/**
 * @file scscf_test.cpp UT for S-CSCF functionality
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


#include <string>
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <boost/lexical_cast.hpp>

#include "pjutils.h"
#include "constants.h"
#include "siptest.hpp"
#include "utils.h"
#include "test_utils.hpp"
#include "analyticslogger.h"
#include "fakecurl.hpp"
#include "fakehssconnection.hpp"
#include "fakexdmconnection.hpp"
#include "test_interposer.hpp"
#include "fakechronosconnection.hpp"
#include "scscfsproutlet.h"
#include "icscfsproutlet.h"
#include "bgcfsproutlet.h"
#include "sproutletappserver.h"
#include "scscfselector.h"
#include "mmtel.h"
#include "sproutletproxy.h"
#include "fakesnmp.hpp"
#include "mock_as_communication_tracker.h"
#include "mock_ralf_processor.h"
#include "acr.h"
#include "testingcommon.h"
#include "mock_subscriber_manager.h"
#include "aor_test_utils.h"
#include "mock_snmp_counter_table.hpp"

using namespace std;
using namespace TestingCommon;
using testing::StrEq;
using testing::ElementsAre;
using testing::MatchesRegex;
using testing::HasSubstr;
using testing::Not;
using testing::_;
using testing::NiceMock;
using testing::HasSubstr;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgReferee;
using ::testing::DoAll;
using ::testing::StrictMock;
using ::testing::AllOf;

// TODO - make this class more consistent with the
// TestingCommon::SubscriptionBuilder class (ie. have function "set_route",
// instead of setting the route when initialising). This work should be done
// when the parent class is reworked.
//
// Subclass which sets the correct Route header for the SCSCF tests.
class SCSCFMessage : public TestingCommon::Message
{
public:
  SCSCFMessage()
  {
    Message::_route = "Route: <sip:sprout.homedomain;service=scscf>";
  };
  ~SCSCFMessage() {};
};

/// ABC for fixtures for SCSCFTest and friends.
class SCSCFTestBase : public SipTest
{
public:
  /// TX data for testing.  Will be cleaned up.  Each message in a
  /// forked flow has its URI stored in _uris, and its txdata stored
  /// in _tdata against that URI.
  vector<string> _uris;
  map<string,pjsip_tx_data*> _tdata;

  /// Set up test case.  Caller must clear host_mapping.
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();

    _chronos_connection = new FakeChronosConnection();
    _local_data_store = new LocalStore();
    _local_aor_store = new AstaireAoRStore(_local_data_store);
    _analytics = new AnalyticsLogger();
    _bgcf_service = new BgcfService(string(UT_DIR).append("/test_stateful_proxy_bgcf.json"));
    _xdm_connection = new FakeXDMConnection();
    _sess_term_comm_tracker = new NiceMock<MockAsCommunicationTracker>();
    _sess_cont_comm_tracker = new NiceMock<MockAsCommunicationTracker>();

    // We only test with a JSONEnumService, not with a DNSEnumService - since
    // it is stateful_proxy.cpp that's under test here, the EnumService
    // implementation doesn't matter.
    _enum_service = new JSONEnumService(string(UT_DIR).append("/test_stateful_proxy_enum.json"));

    _acr_factory = new ACRFactory();
    _fifc_service = new FIFCService(NULL, string(UT_DIR).append("/test_scscf_fifc.xml"));

    // Schedule timers.
    SipTest::poll();
  }

  static void TearDownTestCase()
  {
    // Shut down the transaction module first, before we destroy the
    // objects that might handle any callbacks!
    pjsip_tsx_layer_destroy();
    delete _fifc_service; _fifc_service = NULL;
    delete _acr_factory; _acr_factory = NULL;
    delete _chronos_connection; _chronos_connection = NULL;
    delete _local_aor_store; _local_aor_store = NULL;
    delete _local_data_store; _local_data_store = NULL;
    delete _analytics; _analytics = NULL;
    delete _enum_service; _enum_service = NULL;
    delete _bgcf_service; _bgcf_service = NULL;
    delete _xdm_connection; _xdm_connection = NULL;
    delete _sess_cont_comm_tracker; _sess_cont_comm_tracker = NULL;
    delete _sess_term_comm_tracker; _sess_term_comm_tracker = NULL;
    SipTest::TearDownTestCase();
  }

  SCSCFTestBase()
  {

    _sm = new StrictMock<MockSubscriberManager>();

    _log_traffic = PrintingTestLogger::DEFAULT.isPrinting(); // true to see all traffic
    _local_data_store->flush_all();  // start from a clean slate on each test

    _hss_connection_observer = new MockHSSConnection();
    _hss_connection = new FakeHSSConnection(_hss_connection_observer);

    // Create the BGCF Sproutlet.
    _bgcf_sproutlet = new BGCFSproutlet("bgcf",
                                        5054,
                                        "sip:bgcf.homedomain:5054;transport=tcp",
                                        _bgcf_service,
                                        _enum_service,
                                        _acr_factory,
                                        nullptr,
                                        nullptr,
                                        false);

    // Create the MMTEL AppServer.
    _mmtel = new Mmtel("mmtel", _xdm_connection);
    _mmtel_sproutlet = new SproutletAppServerShim(_mmtel,
                                                  5055,
                                                  "sip:mmtel.homedomain:5058;transport=tcp",
                                                  &SNMP::FAKE_INCOMING_SIP_TRANSACTIONS_TABLE,
                                                  &SNMP::FAKE_OUTGOING_SIP_TRANSACTIONS_TABLE,
                                                  "mmtel.homedomain");

    // We don't care about this function call, but if gtest prints it out as
    // uninteresting mock function call, a memory warning will be issued by
    // valgrind. So put the expectation here to prevent that printing.
    EXPECT_CALL(*_hss_connection_observer, update_registration_state(_, _, _))
      .WillRepeatedly(Return(0));
  }

  ~SCSCFTestBase()
  {
    ::testing::Mock::VerifyAndClearExpectations(_sess_term_comm_tracker);
    ::testing::Mock::VerifyAndClearExpectations(_sess_cont_comm_tracker);

    for (map<string,pjsip_tx_data*>::iterator it = _tdata.begin();
         it != _tdata.end();
         ++it)
    {
      pjsip_tx_data_dec_ref(it->second);
    }

    pjsip_tsx_layer_dump(true);

    // Terminate all transactions
    terminate_all_tsxs(PJSIP_SC_SERVICE_UNAVAILABLE);

    // PJSIP transactions aren't actually destroyed until a zero ms
    // timer fires (presumably to ensure destruction doesn't hold up
    // real work), so poll for that to happen. Otherwise we leak!
    // Allow a good length of time to pass too, in case we have
    // transactions still open. 32s is the default UAS INVITE
    // transaction timeout, so we go higher than that.
    cwtest_advance_time_ms(33000L);
    poll();

    // Stop and restart the layer just in case
    pjsip_tsx_layer_instance()->stop();
    pjsip_tsx_layer_instance()->start();

    // Reset any configuration changes
    URIClassifier::enforce_user_phone = false;
    URIClassifier::enforce_global = false;
    ((SNMP::FakeCounterTable*)_scscf_sproutlet->_routed_by_preloaded_route_tbl)->reset_count();

    delete _sm; _sm = NULL;
    delete _hss_connection; _hss_connection = NULL;
    delete _hss_connection_observer; _hss_connection_observer = NULL;
    delete _proxy; _proxy = NULL;
    delete _mmtel_sproutlet; _mmtel_sproutlet = NULL;
    delete _mmtel; _mmtel = NULL;
    delete _bgcf_sproutlet; _bgcf_sproutlet = NULL;
    delete _scscf_sproutlet; _scscf_sproutlet = NULL;
    delete _icscf_sproutlet; _icscf_sproutlet = NULL;
    delete _scscf_selector; _scscf_selector = NULL;

  }

  /// Send a response back through multiple hops in a dialog. The response is
  /// injected at the downstream end of the dialog (the end that the request
  /// flowed towards. The proxied response is received at each hop, the status
  /// code is checked, and it is then re-injected.
  ///
  /// The outbound message queue must be empty when this function is called.
  ///
  /// @param req         - The response to inject at the downstream end.
  /// @param status_code - The status code of the request. This is used to
  ///                      check that the response it passed through at each
  ///                      hop.
  /// @param num_hops    - The number of hops in the dialog.
  void send_response_back_through_dialog(const std::string& response,
                                         int status_code,
                                         int num_hops)
  {
    std::string curr_response = response;

    for (int ii = 0; ii < num_hops; ++ii)
    {
      inject_msg(curr_response);

      ASSERT_EQ(1, txdata_count());
      RespMatcher(status_code).matches(current_txdata()->msg);

      // Render the received message to a string so we can re-inject it. 64kB
      // should be enough space for this.
      char msg_print_buf[0x10000];
      pj_ssize_t len = pjsip_msg_print(current_txdata()->msg,
                                       msg_print_buf,
                                       sizeof(msg_print_buf));
      curr_response.assign(msg_print_buf, len);

      free_txdata();
    }
  }

protected:
  static LocalStore* _local_data_store;
  static FakeChronosConnection* _chronos_connection;
  static AstaireAoRStore* _local_aor_store;
  static MockSubscriberManager* _sm;
  static AnalyticsLogger* _analytics;
  static FakeHSSConnection* _hss_connection;
  static MockHSSConnection* _hss_connection_observer;
  static FakeXDMConnection* _xdm_connection;
  static BgcfService* _bgcf_service;
  static EnumService* _enum_service;
  static ACRFactory* _acr_factory;
  static FIFCService* _fifc_service;
  BGCFSproutlet* _bgcf_sproutlet;
  SCSCFSproutlet* _scscf_sproutlet;
  Mmtel* _mmtel;
  SproutletAppServerShim* _mmtel_sproutlet;
  static SCSCFSelector* _scscf_selector;
  ICSCFSproutlet* _icscf_sproutlet;
  SproutletProxy* _proxy;
  static MockAsCommunicationTracker* _sess_term_comm_tracker;
  static MockAsCommunicationTracker* _sess_cont_comm_tracker;

  void doTestHeaders(TransportFlow* tpA,
                     bool tpAset,
                     TransportFlow* tpB,
                     bool tpBset,
                     SCSCFMessage& msg,
                     string route,
                     bool expect_100,
                     bool expect_trusted_headers_on_requests,
                     bool expect_trusted_headers_on_responses,
                     bool expect_orig,
                     bool pcpi);
  void doAsOriginated(SCSCFMessage& msg, bool expect_orig);
  void doAsOriginated(const std::string& msg, bool expect_orig);
  void doFourAppServerFlow(std::string record_route_regex, bool app_servers_record_route=false);
  void doSuccessfulFlow(SCSCFMessage& msg,
                        testing::Matcher<string> uri_matcher,
                        list<HeaderMatcher> headers,
                        bool include_ack_and_bye=true,
                        list<HeaderMatcher> rsp_hdrs = list<HeaderMatcher>(),
                        string body_regex = "");
  void doFastFailureFlow(SCSCFMessage& msg, int st_code);
  void doSlowFailureFlow(SCSCFMessage& msg, int st_code, std::string body = "", std::string reason = "");
  void setupForkedFlow(SCSCFMessage& msg);
  // Helper functions to set up subscriber info to be returned to tests.
  void setup_irs_info(HSSConnection::irs_info& irs_info,
                      std::string user,
                      const std::string& domain,
                      bool barred = false,
                      bool tel_uri = false);
  void setup_binding(Bindings& bindings,
                     std::string uri = "sip:6505551234@homedomain",
                     std::string contact = "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob",
                     bool emergency = false);
  void setup_callee_info(HSSConnection::irs_info& irs_info,
                         Bindings& bindings,
                         std::string user = "6505551234",
                         const std::string& domain = "homedomain");
  // Helper functions to add more detailed subscriber info.
  void set_ifcs_from_service_profile(HSSConnection::irs_info& irs_info,
                                     ServiceProfileBuilder& service_profile,
                                     std::string uri);
  void set_ifc(HSSConnection::irs_info& irs_info,
               std::string uri,
               int priority,
               std::vector<std::string> triggers,
               std::string app_serv_name,
               int cond_neg = 0,
               std::string default_handling = "0");
  void put_ifcs_into_irs_info(HSSConnection::irs_info& irs_info,
                              std::string uri,
                              Ifcs& ifcs);
  void add_sp_identity(HSSConnection::irs_info& irs_info,
                       std::string uri,
                       bool barring = false);
  // Helper functions that set up EXPECT_CALLs that return subscriber info to
  // tests.
  void expect_get_subscriber_state(HSSConnection::irs_info& irs_info,
                                   std::string uri,
                                   int times = 1);
  void expect_get_bindings(Bindings& bindings,
                           std::string uri = "sip:6505551234@homedomain");
  void expect_get_callee_info(HSSConnection::irs_info& irs_info,
                              Bindings& bindings,
                              std::string uri = "sip:6505551234@homedomain",
                              int times = 1);
  list<string> doProxyCalculateTargets(int max_targets);
  // We don't want to remove extra info from this route header that we match
  // against, as then we could miss errors where not all the info was passed
  // through (we've had errors in this area before). However, we can't
  // guarantee the order of "lr" and "transport=tcp", so currenly matching
  // against this header is adding fragility to our tests.
  // TODO - Turn this into a function which will match against the full header
  // with either order.
  const std::string BONO_ROUTE_HEADER = "Route: <sip:abcdefgh@bono1.homedomain;transport=tcp;lr;ob>";
  // When fake subscriber info is set, iFCs must be set. An empty iFC object is
  // used, with this placeholder as the key.
  const std::string IFC_PLACEHOLDER = "placeholder";
};

LocalStore* SCSCFTestBase::_local_data_store;
FakeChronosConnection* SCSCFTestBase::_chronos_connection;
AstaireAoRStore* SCSCFTestBase::_local_aor_store;
MockSubscriberManager* SCSCFTestBase::_sm;
AnalyticsLogger* SCSCFTestBase::_analytics;
FakeHSSConnection* SCSCFTestBase::_hss_connection;
MockHSSConnection* SCSCFTestBase::_hss_connection_observer;
FakeXDMConnection* SCSCFTestBase::_xdm_connection;
BgcfService* SCSCFTestBase::_bgcf_service;
EnumService* SCSCFTestBase::_enum_service;
ACRFactory* SCSCFTestBase::_acr_factory;
FIFCService* SCSCFTestBase::_fifc_service;
SCSCFSelector* SCSCFTestBase::_scscf_selector;
MockAsCommunicationTracker* SCSCFTestBase::_sess_term_comm_tracker;
MockAsCommunicationTracker* SCSCFTestBase::_sess_cont_comm_tracker;

// Default test setup, with ICSCF and without remote SDM
class SCSCFTest : public SCSCFTestBase
{
public:
  static void SetUpTestCase()
  {
    SCSCFTestBase::SetUpTestCase();
  }
  static void TearDownTestCase()
  {
    SCSCFTestBase::TearDownTestCase();
  }

  SCSCFTest() : SCSCFTestBase()
  {
    // Create the S-CSCF Sproutlet.
    IFCConfiguration ifc_configuration(false, false, "sip:DUMMY_AS", NULL, NULL);
    _scscf_sproutlet = new SCSCFSproutlet("scscf",
                                          "scscf",
                                          "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                          "sip:127.0.0.1:5058",
                                          "sip:icscf.sprout.homedomain:5059;transport=TCP",
                                          "sip:bgcf@homedomain:5058",
                                          5058,
                                          "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                          "scscf",
                                          "",
                                          _sm,
                                          _enum_service,
                                          _acr_factory,
                                          &SNMP::FAKE_INCOMING_SIP_TRANSACTIONS_TABLE,
                                          &SNMP::FAKE_OUTGOING_SIP_TRANSACTIONS_TABLE,
                                          false,
                                          _fifc_service,
                                          ifc_configuration,
                                          3000, // Session continue timeout - different from default
                                          6000, // Session terminated timeout - different from default
                                          _sess_term_comm_tracker,
                                          _sess_cont_comm_tracker
                                          );
    _scscf_sproutlet->init();

    // Create the I-CSCF Sproutlets.
    _scscf_selector = new SCSCFSelector("sip:scscf.sprout.homedomain",
                                        string(UT_DIR).append("/test_icscf.json"));
    _icscf_sproutlet = new ICSCFSproutlet("icscf",
                                          "sip:bgcf@homedomain:5058",
                                          5059,
                                          "sip:icscf.sprout.homedomain:5059;transport=TCP",
                                          "icscf",
                                          "",
                                          _hss_connection,
                                          _acr_factory,
                                          _scscf_selector,
                                          _enum_service,
                                          &SNMP::FAKE_INCOMING_SIP_TRANSACTIONS_TABLE,
                                          &SNMP::FAKE_OUTGOING_SIP_TRANSACTIONS_TABLE,
                                          false,
                                          5059
                                          );
    _icscf_sproutlet->init();

    // Add common sproutlet to the list for Proxy use
    std::list<Sproutlet*> sproutlets;
    sproutlets.push_back(_scscf_sproutlet);
    sproutlets.push_back(_icscf_sproutlet);
    sproutlets.push_back(_bgcf_sproutlet);
    sproutlets.push_back(_mmtel_sproutlet);

    // Add additional home domain for Proxy use
    std::unordered_set<std::string> additional_home_domains;
    additional_home_domains.insert("sprout.homedomain");
    additional_home_domains.insert("sprout-site2.homedomain");
    additional_home_domains.insert("127.0.0.1");

    // Create the SproutletProxy.
    _proxy = new SproutletProxy(stack_data.endpt,
                                PJSIP_MOD_PRIORITY_UA_PROXY_LAYER+1,
                                "homedomain",
                                additional_home_domains,
                                std::unordered_set<std::string>(),
                                true,
                                sproutlets,
                                std::set<std::string>(),
                                nullptr,
                                nullptr);
  }

  ~SCSCFTest()
  {
  }
};


void SCSCFTestBase::doFourAppServerFlow(std::string record_route_regex, bool app_servers_record_route)
{
  // Expect a call to look up the iFCs for the caller.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  ServiceProfileBuilder service_profile_1 = ServiceProfileBuilder()
    .addIfc(2, {"<Method>INVITE</Method>"}, "sip:4.2.3.4:56788;transport=UDP")
    .addIfc(1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  set_ifcs_from_service_profile(irs_info_1, service_profile_1, "sip:6505551000@homedomain");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Expect calls to look up the iFCs and bindings of the callee.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  ServiceProfileBuilder service_profile_2 = ServiceProfileBuilder()
    .addIfc(1, {"<Method>INVITE</Method>", "<SessionCase>1</SessionCase><!-- terminating-registered -->"}, "sip:5.2.3.4:56787;transport=UDP")
    .addIfc(2, {"<Method>QWERTY_UIOP</Method>"}, "sip:sholes.example.com")
    .addIfc(3, {"<Method>INVITE</Method>"}, "sip:6.2.3.4:56786;transport=UDP");
  set_ifcs_from_service_profile(irs_info_2, service_profile_2, "sip:6505551234@homedomain");
  expect_get_callee_info(irs_info_2, bindings, "sip:6505551234@homedomain", 3);

  EXPECT_CALL(*_sess_cont_comm_tracker, on_success(StrEq("sip:4.2.3.4:56788;transport=UDP")));
  EXPECT_CALL(*_sess_cont_comm_tracker, on_success(StrEq("sip:1.2.3.4:56789;transport=UDP")));
  EXPECT_CALL(*_sess_cont_comm_tracker, on_success(StrEq("sip:5.2.3.4:56787;transport=UDP")));
  EXPECT_CALL(*_sess_cont_comm_tracker, on_success(StrEq("sip:6.2.3.4:56786;transport=UDP")));

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpAS2(TransportFlow::Protocol::UDP, stack_data.scscf_port, "4.2.3.4", 56788);
  TransportFlow tpAS3(TransportFlow::Protocol::UDP, stack_data.scscf_port, "5.2.3.4", 56787);
  TransportFlow tpAS4(TransportFlow::Protocol::UDP, stack_data.scscf_port, "6.2.3.4", 56786);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  pjsip_rr_hdr* as1_rr_hdr = pjsip_rr_hdr_create(stack_data.pool);
  as1_rr_hdr->name_addr.uri = (pjsip_uri*)pjsip_sip_uri_create(stack_data.pool, false);
  ((pjsip_sip_uri*)as1_rr_hdr->name_addr.uri)->host = pj_str("1.2.3.4");

  pjsip_rr_hdr* as2_rr_hdr = pjsip_rr_hdr_create(stack_data.pool);
  as2_rr_hdr->name_addr.uri = (pjsip_uri*)pjsip_sip_uri_create(stack_data.pool, false);
  ((pjsip_sip_uri*)as2_rr_hdr->name_addr.uri)->host = pj_str("4.2.3.4");

  pjsip_rr_hdr* as3_rr_hdr = pjsip_rr_hdr_create(stack_data.pool);
  as3_rr_hdr->name_addr.uri = (pjsip_uri*)pjsip_sip_uri_create(stack_data.pool, false);
  ((pjsip_sip_uri*)as3_rr_hdr->name_addr.uri)->host = pj_str("5.2.3.4");

  pjsip_rr_hdr* as4_rr_hdr = pjsip_rr_hdr_create(stack_data.pool);
  as4_rr_hdr->name_addr.uri = (pjsip_uri*)pjsip_sip_uri_create(stack_data.pool, false);
  ((pjsip_sip_uri*)as4_rr_hdr->name_addr.uri)->host = pj_str("6.2.3.4");

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig;service=scscf>"));

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp1 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp1, &tpAS1);

  // ---------- AS1 turns it around (acting as proxy)
  const pj_str_t STR_ROUTE = pj_str("Route");

  if (app_servers_record_route)
  {
    pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)as1_rr_hdr);
  }

  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS2
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS2.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:4\\.2\\.3\\.4:56788;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig;service=scscf>"));

  // ---------- AS2 sends a 100 Trying to indicate it has received the request.
  string fresp2 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp2, &tpAS2);

  // ---------- AS2 turns it around (acting as proxy)
  if (app_servers_record_route)
  {
    pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)as2_rr_hdr);
  }

  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS2);
  free_txdata();

  // 100 Trying goes back to AS2
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS2.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS3 - From this point on, we're in terminating mode.
  SCOPED_TRACE("INVITE (3)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS3.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));

  // ---------- AS3 sends a 100 Trying to indicate it has received the request.
  string fresp3 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp3, &tpAS3);

  // ---------- AS3 turns it around (acting as proxy)
  if (app_servers_record_route)
  {
    pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)as3_rr_hdr);
  }

  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS3);
  free_txdata();

  // 100 Trying goes back to AS3
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS3.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS4
  SCOPED_TRACE("INVITE (4)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS4.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:6\\.2\\.3\\.4:56786;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));

  // ---------- AS4 sends a 100 Trying to indicate it has received the request.
  string fresp4 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp4, &tpAS4);

  // ---------- AS4 turns it around (acting as proxy)
  if (app_servers_record_route)
  {
    pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)as4_rr_hdr);
  }

  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS4);
  free_txdata();

  // 100 Trying goes back to AS4
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS4.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to final destination (to bono set up in callee's bindings)
  SCOPED_TRACE("INVITE (Z)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  tpCalleeBono.expect_target(current_txdata(), false);

  // ---------- Bono sends a 100 Trying to indicate it has received the request.
  string fresp_bono = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp_bono, &tpBono);

  EXPECT_THAT(get_headers(out, "Record-Route"), testing::MatchesRegex(record_route_regex));

  // Send a 200 OK back down the line to finish the transaction. This is so that
  // AS communication tracking works correctly. There are a total of 5 hops in
  // total.
  pjsip_tx_data* txdata = pop_txdata();

  // Send a 200 ringing back down the chain to finish the transaction. This is a
  // more realistic test of AS communication tracking.
  send_response_back_through_dialog(respond_to_txdata(txdata, 200), 200, 5);

  pjsip_tx_data_dec_ref(txdata); txdata = NULL;
}

// Test flows into Sprout (S-CSCF), in particular for header stripping.
// Check the transport each message is on, and the headers.
// Test a call from Alice to Bob.
void SCSCFTestBase::doTestHeaders(TransportFlow* tpA,  //< Alice's transport.
                                  bool tpAset,         //< Expect all requests to Alice on same transport?
                                  TransportFlow* tpB,  //< Bob's transport.
                                  bool tpBset,         //< Expect all requests to Bob on same transport?
                                  SCSCFMessage& msg,    //< Message to use for testing.
                                  string route,        //< Route header to be used on INVITE
                                  bool expect_100,     //< Will we get a 100 Trying?
                                  bool expect_trusted_headers_on_requests, //< Should P-A-N-I/P-V-N-I be passed on requests?
                                  bool expect_trusted_headers_on_responses, //< Should P-A-N-I/P-V-N-I be passed on responses?
                                  bool expect_orig,    //< Should we expect the INVITE to be marked originating?
                                  bool pcpi)           //< Should we expect a P-Called-Party-ID?
{
  SCOPED_TRACE("doTestHeaders");
  pjsip_msg* out;
  pjsip_tx_data* invite = NULL;
  pjsip_tx_data* prack = NULL;

  // Extra fields to insert in all requests and responses.
  string pani = "P-Access-Network-Info: ietf-carrier-pigeon;rfc=1149";
  string pvni = "P-Visited-Network-Id: other.net, \"Other Network\"";
  string pvani = pani + "\r\n" + pvni;

  if (!msg._extra.empty())
  {
    msg._extra.append("\r\n");
  }

  msg._extra.append(pani);
  msg._extra.append("\r\n");
  msg._extra.append(pvni);

  // ---------- Send INVITE C->X
  SCOPED_TRACE("INVITE");
  msg._method = "INVITE";

  if (route != "")
  {
    msg._route = route;
  }

  inject_msg(msg.get_request(), tpA);
  poll();
  ASSERT_EQ(expect_100 ? 2 : 1, txdata_count());

  if (expect_100)
  {
    // 100 Trying goes back C<-X
    out = current_txdata()->msg;
    RespMatcher(100).matches(out);
    tpA->expect_target(current_txdata(), true);  // Requests always come back on same transport
    msg.convert_routeset(out);

    // Don't bother testing P-Access-Network-Info or P-Visited-Network-Id,
    // because they never get inserted into such messages.
    free_txdata();
  }

  // INVITE passed on X->S
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("INVITE").matches(out));
  tpB->expect_target(current_txdata(), tpBset);

  // Check P-Access-Network-Info and P-Visited-Network-Id.
  EXPECT_EQ(expect_trusted_headers_on_requests ? pani : "",
            get_headers(out, "P-Access-Network-Info")) << "INVITE";
  EXPECT_EQ(expect_trusted_headers_on_requests ? pvni : "",
            get_headers(out, "P-Visited-Network-Id")) << "INVITE";

  // Check originating.
  if (expect_orig)
  {
    EXPECT_THAT(get_headers(out, "Route"), HasSubstr(";orig"));
  }
  else
  {
    EXPECT_THAT(get_headers(out, "Route"), Not(HasSubstr(";orig")));
  }

  // Check P-Called-Party-ID
  EXPECT_EQ(pcpi ? "P-Called-Party-ID: <" + msg._toscheme + ":" + msg._to + "@" + msg._todomain + ">" : "", get_headers(out, "P-Called-Party-ID"));

  invite = pop_txdata();

  // ---------- Send 183 Session Progress back X<-S
  SCOPED_TRACE("183 Session Progress");
  inject_msg(respond_to_txdata(invite, 183, "", pvani), tpB);
  ASSERT_EQ(1, txdata_count());

  // 183 goes back C<-X
  out = current_txdata()->msg;
  RespMatcher(183).matches(out);
  tpA->expect_target(current_txdata(), true);
  msg.convert_routeset(out);
  msg._cseq++;

  // Check P-Access-Network-Info and P-Visited-Network-Id
  EXPECT_EQ(expect_trusted_headers_on_responses ? pani : "",
            get_headers(out, "P-Access-Network-Info")) << "183 Session Progress";
  EXPECT_EQ(expect_trusted_headers_on_responses ? pvni : "",
            get_headers(out, "P-Visited-Network-Id")) << "183 Session Progress";

  free_txdata();

  // Send PRACK C->X
  SCOPED_TRACE("PRACK");
  msg._method = "PRACK";
  msg._in_dialog = true;
  inject_msg(msg.get_request(), tpA);
  poll();
  ASSERT_EQ(1, txdata_count());

  // PRACK passed on X->S
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("PRACK").matches(out));
  tpB->expect_target(current_txdata(), tpBset);

  // Check P-Access-Network-Info and P-Visited-Network-Id.
  EXPECT_EQ(expect_trusted_headers_on_requests ? pani : "",
            get_headers(out, "P-Access-Network-Info")) << "PRACK";
  EXPECT_EQ(expect_trusted_headers_on_requests ? pvni : "",
            get_headers(out, "P-Visited-Network-Id")) << "PRACK";

  prack = pop_txdata();

  // ---------- Send 200 OK back X<-S
  SCOPED_TRACE("200 OK (PRACK)");
  inject_msg(respond_to_txdata(prack, 200, "", pvani), tpB);
  ASSERT_EQ(1, txdata_count());

  // OK goes back C<-X
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpA->expect_target(current_txdata(), true);
  msg.convert_routeset(out);
  msg._cseq++;

  // Check P-Access-Network-Info and P-Visited-Network-Id.
  EXPECT_EQ(expect_trusted_headers_on_responses ? pani : "",
            get_headers(out, "P-Access-Network-Info")) << "200 OK (PRACK)";
  EXPECT_EQ(expect_trusted_headers_on_responses ? pvni : "",
            get_headers(out, "P-Visited-Network-Id")) << "200 OK (PRACK)";

  free_txdata();

  // ---------- Send 200 OK back X<-S
  SCOPED_TRACE("200 OK (INVITE)");
  inject_msg(respond_to_txdata(invite, 200, "", pvani), tpB);
  ASSERT_EQ(1, txdata_count());

  // OK goes back C<-X
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpA->expect_target(current_txdata(), true);
  msg.convert_routeset(out);
  msg._cseq++;

  // Check P-Access-Network-Info and P-Visited-Network-Id.
  EXPECT_EQ(expect_trusted_headers_on_responses ? pani : "",
            get_headers(out, "P-Access-Network-Info")) << "200 OK (INVITE)";
  EXPECT_EQ(expect_trusted_headers_on_responses ? pvni : "",
            get_headers(out, "P-Visited-Network-Id")) << "200 OK (INVITE)";

  free_txdata();

  // ---------- Send ACK C->X
  SCOPED_TRACE("ACK");
  msg._method = "ACK";
  inject_msg(msg.get_request(), tpA);
  poll();
  ASSERT_EQ(1, txdata_count());

  // ACK passed on X->S
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("ACK").matches(out));
  tpB->expect_target(current_txdata(), tpBset);

  // Check P-Access-Network-Info and P-Visited-Network-Id.
  EXPECT_EQ(expect_trusted_headers_on_requests ? pani : "",
            get_headers(out, "P-Access-Network-Info")) << "ACK";
  EXPECT_EQ(expect_trusted_headers_on_requests ? pvni : "",
            get_headers(out, "P-Visited-Network-Id")) << "ACK";

  free_txdata();

  // ---------- Send a retransmission of that 200 OK back X<-S.  Should be processed statelessly.
  SCOPED_TRACE("200 OK (INVITE) (rexmt)");
  inject_msg(respond_to_txdata(invite, 200, "", pvani), tpB);
  pjsip_tx_data_dec_ref(invite);
  invite = NULL;
  ASSERT_EQ(1, txdata_count());

  // OK goes back C<-X
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpA->expect_target(current_txdata(), true);
  msg.convert_routeset(out);
  msg._cseq++;

  // Check P-Access-Network-Info and P-Visited-Network-Id. These will always be stripped,
  // because we handle these retransmissions statelessly and hence don't have any info on
  // trust boundary handling.
  //EXPECT_EQ("", get_headers(out, "P-Access-Network-Info")) << "200 OK (INVITE) (rexmt)";
  //EXPECT_EQ("", get_headers(out, "P-Visited-Network-Id")) << "200 OK (INVITE) (rexmt)";

  free_txdata();

  // ---------- Send a subsequent request. C->X
  SCOPED_TRACE("BYE");
  msg._method = "BYE";
  inject_msg(msg.get_request(), tpA);
  poll();

  // BYE passed on X->S
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("BYE").matches(out));
  tpB->expect_target(current_txdata(), tpBset);

  // Check P-Access-Network-Info and P-Visited-Network-Id.
  EXPECT_EQ(expect_trusted_headers_on_requests ? pani : "",
            get_headers(out, "P-Access-Network-Info")) << "BYE";
  EXPECT_EQ(expect_trusted_headers_on_requests ? pvni : "",
            get_headers(out, "P-Visited-Network-Id")) << "BYE";

  // ---------- Send a reply to that X<-S
  SCOPED_TRACE("200 OK (BYE)");
  inject_msg(respond_to_current_txdata(200, "", pvani), tpB);
  poll();
  ASSERT_EQ(1, txdata_count());

  // Reply passed on C<-X
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpA->expect_target(current_txdata(), true);

  // Check P-Access-Network-Info and P-Visited-Network-Id.
  EXPECT_EQ(expect_trusted_headers_on_responses ? pani : "",
            get_headers(out, "P-Access-Network-Info")) << "200 OK (BYE)";
  EXPECT_EQ(expect_trusted_headers_on_responses ? pvni : "",
            get_headers(out, "P-Visited-Network-Id")) << "200 OK (BYE)";

  free_txdata();

  // ---------- Send INVITE C->X (this is an attempt to establish a second dialog)
  SCOPED_TRACE("INVITE (#2)");
  msg._method = "INVITE";
  msg._in_dialog = false;

  if (route != "")
  {
    msg._route = route;
  }
  msg._unique++;
  inject_msg(msg.get_request(), tpA);
  poll();
  ASSERT_EQ(expect_100 ? 2 : 1, txdata_count());

  if (expect_100)
  {
    // 100 Trying goes back C<-X
    out = current_txdata()->msg;
    RespMatcher(100).matches(out);
    tpA->expect_target(current_txdata(), true);

    // Don't bother testing P-Access-Network-Info or P-Visited-Network-Id, because this is point-to-point.
    free_txdata();
  }

  // INVITE passed on X->S
  SCOPED_TRACE("INVITE (S#2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("INVITE").matches(out));
  tpB->expect_target(current_txdata(), tpBset);

  // Check P-Access-Network-Info and P-Visited-Network-Id.
  EXPECT_EQ(expect_trusted_headers_on_requests ? pani : "",
            get_headers(out, "P-Access-Network-Info")) << "INVITE (#2)";
  EXPECT_EQ(expect_trusted_headers_on_requests ? pvni : "",
            get_headers(out, "P-Visited-Network-Id")) << "INVITE (#2)";

  invite = pop_txdata();

  // ---------- Send 404 Not Found back X<-S
  SCOPED_TRACE("404 Not Found (INVITE #2)");
  inject_msg(respond_to_txdata(invite, 404, "", pvani), tpB);
  poll();
  ASSERT_EQ(2, txdata_count());

  // ACK autogenerated X->S
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("ACK").matches(out));
  tpB->expect_target(current_txdata(), tpBset);

  // Don't check P-Access-Network-Info or P-Visited-Network-Id, because it's point-to-point.

  free_txdata();

  // 404 goes back C<-X
  out = current_txdata()->msg;
  RespMatcher(404).matches(out);
  tpA->expect_target(current_txdata(), true);
  msg.convert_routeset(out);
  msg._cseq++;

  // Check P-Access-Network-Info and P-Visited-Network-Id.
  EXPECT_EQ(expect_trusted_headers_on_responses ? pani : "",
            get_headers(out, "P-Access-Network-Info")) << "404 Not Found (INVITE #2)";
  EXPECT_EQ(expect_trusted_headers_on_responses ? pvni : "",
            get_headers(out, "P-Visited-Network-Id")) << "404 Not Found (INVITE #2)";

  free_txdata();

  // ---------- Send ACK C->X
  SCOPED_TRACE("ACK (#2)");
  msg._method = "ACK";
  msg._in_dialog = true;
  inject_msg(msg.get_request(), tpA);
  poll();
  ASSERT_EQ(0, txdata_count());
  // should be swallowed by core.
}


/// Test a message results in a successful flow. The outgoing INVITE's
/// URI is verified.
void SCSCFTestBase::doSuccessfulFlow(SCSCFMessage& msg,
                                     testing::Matcher<string> uri_matcher,
                                     list<HeaderMatcher> headers,
                                     bool include_ack_and_bye,
                                     list<HeaderMatcher> rsp_headers,
                                     string body_regex)
{
  SCOPED_TRACE("");
  pjsip_msg* out;

  // Send INVITE
  inject_msg(msg.get_request());
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  free_txdata();

  // INVITE passed on
  out = current_txdata()->msg;
  ReqMatcher req("INVITE", "", body_regex);
  ASSERT_NO_FATAL_FAILURE(req.matches(out));

  // Do checks on what gets passed through:
  EXPECT_THAT(req.uri(), uri_matcher);
  for (list<HeaderMatcher>::iterator iter = headers.begin(); iter != headers.end(); ++iter)
  {
    iter->match(out);
  }

  if (body_regex.length() != 0)
  {
    req.body_regex_matches(out);
  }

  // Send 200 OK back
  inject_msg(respond_to_current_txdata(200));
  ASSERT_EQ(1, txdata_count());

  // OK goes back
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  for (list<HeaderMatcher>::iterator iter = rsp_headers.begin();
       iter != rsp_headers.end();
       ++iter)
  {
    iter->match(out);
  }

  msg.convert_routeset(out);
  msg._cseq++;
  free_txdata();

  if (include_ack_and_bye)
  {
    // Send ACK
    msg._method = "ACK";
    msg._in_dialog = true;
    inject_msg(msg.get_request());
    poll();
    ASSERT_EQ(1, txdata_count());
    out = current_txdata()->msg;
    ReqMatcher req2("ACK");
    ASSERT_NO_FATAL_FAILURE(req2.matches(out));
    free_txdata();

    // Send a subsequent request.
    msg._method = "BYE";
    inject_msg(msg.get_request());
    poll();
    ASSERT_EQ(1, txdata_count());
    out = current_txdata()->msg;
    ReqMatcher req3("BYE");
    ASSERT_NO_FATAL_FAILURE(req3.matches(out));

    // Send a reply to that.
    inject_msg(respond_to_current_txdata(200));
    poll();
    ASSERT_EQ(1, txdata_count());
    out = current_txdata()->msg;
    RespMatcher(200).matches(out);

    free_txdata();
  }
}

/// Test a message results in an immediate failure.
void SCSCFTestBase::doFastFailureFlow(SCSCFMessage& msg, int st_code)
{
  SCOPED_TRACE("");

  // Send INVITE
  inject_msg(msg.get_request());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out;

  // error goes back
  out = current_txdata()->msg;
  RespMatcher(st_code).matches(out);
  free_txdata();
}

/// Test a message results in a 100 then a failure.
void SCSCFTestBase::doSlowFailureFlow(SCSCFMessage& msg,
                                      int st_code,
                                      std::string body,
                                      std::string reason)
{
  SCOPED_TRACE("");

  // Send INVITE
  inject_msg(msg.get_request());
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  free_txdata();

  // error goes back
  out = current_txdata()->msg;
  RespMatcher(st_code, body, reason).matches(out);
  free_txdata();
}

// Fill in the irs info object to be returned by the mock subscriber manager.
void SCSCFTestBase::setup_irs_info(HSSConnection::irs_info& irs_info,
                                   std::string user,
                                   const std::string& domain,
                                   bool barred,
                                   bool tel_uri)
{
  std::string uri = "";
  if (tel_uri)
  {
    uri.append("tel:").append(user);
  }
  else
  {
    uri.append("sip:").append(user).append("@").append(domain);
  }

  AssociatedURIs associated_uris = {};
  associated_uris.add_uri(uri, barred);
  irs_info._associated_uris = associated_uris;

  irs_info._regstate = RegDataXMLUtils::STATE_REGISTERED;
  irs_info._prev_regstate = "";

  // Insert an empty iFC object as a placeholder, with the key "placeholder".
  std::map<std::string, Ifcs> service_profiles;
  Ifcs ifcs;
  service_profiles.insert(std::make_pair(IFC_PLACEHOLDER , ifcs));
  irs_info._service_profiles = service_profiles;

  irs_info._aliases.push_back(uri);

  irs_info._ccfs = {"CCF TEST"};
  irs_info._ecfs = {"ECF TEST 1", "ECF TEST 2"};
}

// Add a binding to the bindings object to be returned by the mock subscriber
// manager.
void SCSCFTestBase::setup_binding(Bindings& bindings,
                                  std::string uri,
                                  std::string contact,
                                  bool emergency)
{
  Binding* binding = AoRTestUtils::build_binding(uri,
                                                 time(NULL),
                                                 contact);
  binding->_emergency_registration = emergency;
  bindings.insert(std::make_pair(contact, binding));
}

// Fill in the irs info and bindings objects to contain the info for the
// standard callee. These objects will later be returned by the mock subscriber
// manager.
void SCSCFTestBase::setup_callee_info(HSSConnection::irs_info& irs_info,
                                      Bindings& bindings,
                                      std::string user,
                                      const std::string& domain)
{
  setup_irs_info(irs_info, user, domain);
  std::string uri = "";
  uri.append("sip:").append(user).append("@").append(domain);
  setup_binding(bindings, uri);
}

// Adds the iFCs set in the passed in service profile to the irs info.
void SCSCFTestBase::set_ifcs_from_service_profile(HSSConnection::irs_info& irs_info,
                                                  ServiceProfileBuilder& service_profile,
                                                  std::string uri)
{
  // Create an iFCs object. The easiest way to do this is to use the
  // ServiceProfileBulider.
  Ifcs ifcs = service_profile.return_ifcs();

  put_ifcs_into_irs_info(irs_info, uri, ifcs);
}

// Adds ONLY ONE iFC, whose info is passed in, to the irs_info.
// If multiple iFCs need to be added, set_ifcs_from_service_profiles should be
// used instead.
void SCSCFTestBase::set_ifc(HSSConnection::irs_info& irs_info,
                            std::string uri,
                            int priority,
                            std::vector<std::string> triggers,
                            std::string app_serv_name,
                            int cond_neg,
                            std::string default_handling)
{
  // Create an Ifcs object containing the iFC. The easiest way to do this is to
  // build a service profile and extract it from there - this uses only common
  // testing functions.
  ServiceProfileBuilder service_profile = ServiceProfileBuilder()
    .addIfc(priority, triggers, app_serv_name, cond_neg, default_handling);
  Ifcs ifcs = service_profile.return_ifcs();

  put_ifcs_into_irs_info(irs_info, uri, ifcs);
}

// Puts the iFCs into the irs info.
void SCSCFTestBase::put_ifcs_into_irs_info(HSSConnection::irs_info& irs_info,
                                           std::string uri,
                                           Ifcs& ifcs)
{
  // Insert the Ifcs object into the irs_info, and if a blank iFC is present
  // (used as a placeholder for tests where iFCs aren't required) remove it.
  irs_info._service_profiles.insert(std::make_pair(uri, ifcs));
  irs_info._service_profiles.erase(IFC_PLACEHOLDER);
}

// Add details to the irs_info about an identity that is in the same service
// profile (sp) as the default identity.
void SCSCFTestBase::add_sp_identity(HSSConnection::irs_info& irs_info,
                                    std::string uri,
                                    bool barring)
{
  irs_info._associated_uris.add_uri(uri, barring);
  irs_info._aliases.push_back(uri);
}

// Set up EXPECT_CALL(s) to get the subscriber state for a subscriber.
// The number of times is usually the number of ASs that return the message,
// plus one. This is because there should always be 1 call to get the subscriber
// state (to find the iFCs), and then an additional call for each AS that
// returns the message to the S-CSCF (as a check will take place to see if a
// retarget has happened).
void SCSCFTestBase::expect_get_subscriber_state(HSSConnection::irs_info& irs_info,
                                                std::string uri,
                                                int times)
{
  EXPECT_CALL(*_sm, get_subscriber_state(IrsQueryWithPublicId(uri), _, _))
    .Times(times)
    .WillRepeatedly(DoAll(SetArgReferee<1>(irs_info),
                          Return(HTTP_OK)));
}

// Set up an EXPECT_CALL to get the bindings for a subscriber.
void SCSCFTestBase::expect_get_bindings(Bindings& bindings,
                                        std::string uri)
{
  EXPECT_CALL(*_sm, get_bindings(uri, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(bindings),
                    Return(HTTP_OK)));
}

// Set up the EXPECT_CALLs relating to the standard callee.
// Expect one call to get the bindings, and the specified number of calls to get
// the subscriber state. The number of calls to get the subscriber state is
// usually the number of ASs that return the message, plus one. This is because
// there should always be 1 call to get the subscriber state (to find the iFCs),
// and then an additional call for each AS that returns the message to the
// S-CSCF (as a check will take place to see if a retarget has happened).
void SCSCFTestBase::expect_get_callee_info(HSSConnection::irs_info& irs_info,
                                           Bindings& bindings,
                                           std::string uri,
                                           int times)
{
  expect_get_subscriber_state(irs_info, uri, times);
  expect_get_bindings(bindings, uri);
}


TEST_F(SCSCFTest, TestSimpleMainline)
{
  SCOPED_TRACE("");

  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings);
  expect_get_callee_info(irs_info, bindings);

  SCSCFMessage msg;
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs);

  // This is a terminating call so should not result in a session setup time
  // getting tracked.
  EXPECT_EQ(0, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_audio_session_setup_time_tbl)->_count);
  EXPECT_EQ(0, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_video_session_setup_time_tbl)->_count);

  // It also shouldn't result in any forked INVITEs.
  EXPECT_EQ(0, ((SNMP::FakeCounterTable*)_scscf_sproutlet->_forked_invite_tbl)->_count);
}


// Test route request to Maddr.
TEST_F(SCSCFTest, TestSimpleMainlineMaddr)
{
  SCOPED_TRACE("");

  // Set up callee info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551234", "homedomain");
  expect_get_subscriber_state(irs_info, "sip:6505551234@homedomain");

  SCSCFMessage msg;
  msg._requri = "sip:6505551234@homedomain;maddr=1.2.3.4";
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*maddr.*"), hdrs);
}


TEST_F(SCSCFTest, TestSimpleMainlineRemoteSite)
{
  SCOPED_TRACE("");

  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings);
  expect_get_callee_info(irs_info, bindings);

  SCSCFMessage msg;
  msg._route = "Route: <sip:scscf.sprout-site2.homedomain;transport=tcp;lr>";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Record-Route", "Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-term>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs);
}


// Send a request where the URI is for the same port as a Sproutlet,
// but a different host. We should deal with this sensibly (as opposed
// to e.g. looping forever until we crash).
TEST_F(SCSCFTest, ReqURIMatchesSproutletPort)
{
  SCOPED_TRACE("");
  SCSCFMessage msg;
  msg._requri = "sip:254.253.252.251:5058";
  msg._route = "Route: <sip:sprout.homedomain;transport=tcp;lr;billing-role=charge-term>";
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex("sip:254.253.252.251:5058"), hdrs);
}


// Test flows into Sprout (S-CSCF), in particular for header stripping.
TEST_F(SCSCFTest, TestMainlineHeadersSprout)
{
  SCOPED_TRACE("");

  // Two INVITES are sent in "doTestHeaders", so we expect to call into the mock
  // subscriber manager twice.
  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings);
  // The sproutlet owns, and will free, the bindings. So create a second
  // bindings object to pass back on the second call.
  Bindings bindings_2;
  setup_binding(bindings_2);
  EXPECT_CALL(*_sm, get_subscriber_state(IrsQueryWithPublicId("sip:6505551234@homedomain"), _, _))
    .Times(2)
    .WillRepeatedly(DoAll(SetArgReferee<1>(irs_info),
                          Return(HTTP_OK)));
  EXPECT_CALL(*_sm, get_bindings("sip:6505551234@homedomain", _, _))
    .Times(2)
    .WillOnce(DoAll(SetArgReferee<1>(bindings),
                    Return(HTTP_OK)))
    .WillOnce(DoAll(SetArgReferee<1>(bindings_2),
                    Return(HTTP_OK)));

  // INVITE from anywhere to anywhere.
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345";
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060); // Set up in callee's bindings.
  doTestHeaders(_tp_default, false, &tpCalleeBono, false, msg, "", true, true, true, false, true);
}


// Test the flow where the bindings lookup fails.
// Since no bindings are found, the call should fail with a 480 Temporarily
// Unavailable.
TEST_F(SCSCFTest, GetBindingsFails)
{
  SCOPED_TRACE("");

  // Set up the callee info. The lookup of iFCs is set up to succeed, and the
  // lookup of bindings is set up to fail.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551234", "homedomain");
  expect_get_subscriber_state(irs_info, "sip:6505551234@homedomain");
  EXPECT_CALL(*_sm, get_bindings("sip:6505551234@homedomain", _, _))
    .WillOnce(Return(HTTP_NOT_FOUND));

  SCSCFMessage msg;
  doSlowFailureFlow(msg, 480);
}


TEST_F(SCSCFTest, TestNotRegisteredTo)
{
  SCOPED_TRACE("");

  // Expect a call to the SM to try to find info, but none is returned.
  EXPECT_CALL(*_sm, get_subscriber_state(IrsQueryWithPublicId("sip:6505551234@homedomain"), _, _))
    .WillOnce(Return(HTTP_NOT_FOUND));

  SCSCFMessage msg;
  doSlowFailureFlow(msg, 404);
}


// Test that a call to an unregistered user, where the subscriber state info is
// still found, is rejected.
TEST_F(SCSCFTest, UnregisteredCallee)
{
  // Set up callee info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551234", "homedomain");
  irs_info._regstate = "UNREGISTERED";
  expect_get_subscriber_state(irs_info, "sip:6505551234@homedomain");

  SCSCFMessage msg;
  doSlowFailureFlow(msg, 480);
}


TEST_F(SCSCFTest, TestBadScheme)
{
  SCOPED_TRACE("");
  SCSCFMessage msg;
  msg._toscheme = "sips";
  doFastFailureFlow(msg, 416);  // bad scheme
}


TEST_F(SCSCFTest, TestBarredCaller)
{
  // Tests that a call attempt from a barred caller is rejected with a 403.
  SCOPED_TRACE("");

  // Set up info to be returned about the caller, showing they are barred.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551000", "homedomain", true);
  expect_get_subscriber_state(irs_info, "sip:6505551000@homedomain");

  SCSCFMessage msg;
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  doSlowFailureFlow(msg, 403);
}


TEST_F(SCSCFTest, TestBarredCallee)
{
  // Tests that a call to a barred callee is rejected with a 404.
  SCOPED_TRACE("");

  // Set up info to be returned about the callee, showing they are barred.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551234", "homedomain", true);
  expect_get_subscriber_state(irs_info, "sip:6505551234@homedomain");

  // We look up the bindings before we reject the call due to the callee being
  // barred, so expect a call to get_bindings (but no need to bother to return
  // any useful info).
  EXPECT_CALL(*_sm, get_bindings("sip:6505551234@homedomain", _, _))
    .WillOnce( Return(HTTP_OK));

  SCSCFMessage msg;
  doSlowFailureFlow(msg, 404);
}


TEST_F(SCSCFTest, TestSimpleTelURI)
{
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551000", "homedomain");
  expect_get_subscriber_state(irs_info, "sip:6505551000@homedomain");

  // No callee info needed, as ENUM service resolves tel URI to sip URI that is
  // not in home domain, so is routed externally by the BGCF.

  SCSCFMessage msg;
  msg._toscheme = "tel";
  msg._to = "16505551234";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*16505551234@ut.cw-ngv.com.*"), hdrs, false);

  // Successful originating call.  We should have tracked a single session
  // setup time.
  EXPECT_EQ(1, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_audio_session_setup_time_tbl)->_count);
  EXPECT_EQ(0, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_video_session_setup_time_tbl)->_count);
}


// Test that a successful originating video call results in the correct stats
// being tracked.
TEST_F(SCSCFTest, TestSimpleTelURIVideo)
{
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551000", "homedomain");
  expect_get_subscriber_state(irs_info, "sip:6505551000@homedomain");

  // No callee info needed, as ENUM service resolves tel URI to sip URI that is
  // not in home domain, so is routed externally by the BGCF.

  SCSCFMessage msg;
  msg._toscheme = "tel";
  msg._to = "16505551234";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._body = "\r\nv=0\r\no=Andrew 2890844526 2890844526 IN IP4 10.120.42.3\r\nc=IN IP4 10.120.42.3\r\nt=0 0\r\nm=audio 49170 RTP/AVP 0 8 97\r\na=rtpmap:0 PCMU/8000\r\nm=video 51372 RTP/AVP 31 32\r\na=rtpmap:31 H261/90000\r\n";
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*16505551234@ut.cw-ngv.com.*"), hdrs, false);

  // Successful originating call.  We should have tracked a single session
  // setup time.
  EXPECT_EQ(0, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_audio_session_setup_time_tbl)->_count);
  EXPECT_EQ(1, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_video_session_setup_time_tbl)->_count);
}


TEST_F(SCSCFTest, TestTerminatingTelURI)
{
  // Set the info for the callee, to include the associated tel uri.
  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings);
  add_sp_identity(irs_info, "tel:6505551235", false);
  expect_get_subscriber_state(irs_info, "tel:6505551235"); // Expect iFCs to be looked up with tel URI (since it's the requri).
  expect_get_bindings(bindings);  // Expect bindings to be looked up with sip URI (since it's first that was set in irs_info, making it the default).

  // Send a terminating INVITE for a subscriber with a tel: URI
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain>";
  msg._requri = "tel:6505551235";

  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob"), hdrs, false);
}


// Registered subscriber failed to get associated URI and has no bindings in the
// store.
TEST_F(SCSCFTest, TestEmptyBinding)
{
  // Setup irs_info (for a random uri that is not the one that is called, so
  // that the S-CSCF sproutlet will have failed to get the associated URIs).
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "1234567", "homedomain");
  expect_get_subscriber_state(irs_info, "tel:6505551235");

  // Return empty list of bindings.
  EXPECT_CALL(*_sm, get_bindings("tel:6505551235", _, _))
    .WillOnce(Return(HTTP_OK));

  SCSCFMessage msg;
  msg._requri = "tel:6505551235";
  list<HeaderMatcher> hdrs;

  doSlowFailureFlow(msg, 480);
}


TEST_F(SCSCFTest, TestNoMoreForwards)
{
  SCOPED_TRACE("");
  SCSCFMessage msg;
  msg._forwards = 1;
  doFastFailureFlow(msg, 483); // too many hops
}


TEST_F(SCSCFTest, TestNoMoreForwards2)
{
  SCOPED_TRACE("");
  SCSCFMessage msg;
  msg._forwards = 0;
  doFastFailureFlow(msg, 483); // too many hops
}


TEST_F(SCSCFTest, TestTransportShutdown)
{
  SCOPED_TRACE("");
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject an INVITE request on a transport which is shutting down.  It is safe
  // to call pjsip_transport_shutdown on a TCP transport as the TransportFlow
  // keeps a reference to the transport so it won't actually be destroyed until
  // the TransportFlow is destroyed.
  pjsip_transport_shutdown(tp->transport());

  SCSCFMessage msg;
  msg._method = "INVITE";
  msg._requri = "sip:bob@awaydomain";
  msg._from = "alice";
  msg._to = "bob";
  msg._todomain = "awaydomain";
  msg._via = tp->to_string(false);
  msg._route = "Route: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg.get_request(), tp);

  // Check the 504 Service Unavailable response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(503).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Send an ACK to complete the UAS transaction.
  msg._method = "ACK";
  inject_msg(msg.get_request(), tp);

  delete tp;
}


TEST_F(SCSCFTest, TestStrictRouteThrough)
{
  SCOPED_TRACE("");
  // This message is passing through this proxy; it's not local
  SCSCFMessage msg;
  add_host_mapping("intermediate.com", "10.10.10.1");
  add_host_mapping("destination.com", "10.10.10.2");
  msg._route = "";
  msg._extra = "Route: <sip:nexthop@intermediate.com;transport=tcp>\r\nRoute: <sip:lasthop@destination.com>";
  msg._to = "lasthop";
  msg._todomain = "destination.com";
  msg._requri = "sip:6505551234@nonlocaldomain";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Route", ".*lasthop@destination.com.*", ".*6505551234@nonlocaldomain.*"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*nexthop@intermediate.com.*"), hdrs);
}


TEST_F(SCSCFTest, TestNonLocal)
{
  SCOPED_TRACE("");
  // This message is passing through this proxy; it's not local
  add_host_mapping("destination.com", "10.10.10.2");
  SCSCFMessage msg;
  msg._route = "";
  msg._to = "lasthop";
  msg._todomain = "destination.com";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Route"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*lasthop@destination\\.com.*"), hdrs);

  // Add another test where the nonlocal domain doesn't contain a period. This
  // is for code coverage.
  add_host_mapping("destination", "10.10.10.3");
  SCSCFMessage msg2;
  msg2._route = "";
  msg2._to = "lasthop";
  msg2._todomain = "destination";
  list<HeaderMatcher> hdrs2;
  hdrs2.push_back(HeaderMatcher("Route"));
  doSuccessfulFlow(msg2, testing::MatchesRegex(".*lasthop@destination.*"), hdrs2);
}


TEST_F(SCSCFTest, TestTerminatingPCV)
{
  SCOPED_TRACE("");

  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings);
  expect_get_callee_info(irs_info, bindings);

  // Test that a segfault previously seen when not doing originating
  // handling on a call with a P-Charging-Vector does not reoccur.
  SCSCFMessage msg;
  msg._extra = "P-Charging-Vector: icid-value=3";
  msg._to = "lasthop";
  msg._todomain = "destination.com";
  msg._requri = "sip:6505551234@homedomain";
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*"), hdrs);
}


TEST_F(SCSCFTest, DISABLED_TestLooseRoute)  // @@@KSW not quite - how does this work again?
{
  SCOPED_TRACE("");
  SCSCFMessage msg;
  msg._extra = "Route: <sip:nexthop@anotherdomain;lr>\r\nRoute: <sip:lasthop@destination.com;lr>";
  msg._to = "lasthop";
  msg._todomain = "destination.com";
  msg._requri = "sip:6505551234@homedomain";
  list<HeaderMatcher> hdrs;
//  hdrs.push_back(HeaderMatcher("Route", ".*lasthop@destination.*"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*lasthop@destination.com.*"), hdrs);
}


TEST_F(SCSCFTest, TestExternal)
{
  SCOPED_TRACE("");
  SCSCFMessage msg;
  msg._to = "+15108580271";
  msg._todomain = "ut.cw-ngv.com";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*+15108580271@ut.cw-ngv.com.*"), hdrs);
}


// Test is disabled because there is no Route header, so request is treated as
// terminating request, but domain in RequestURI is not local, so we don't
// provide any services to the user, so therefore shouldn't add a Record-Route.
TEST_F(SCSCFTest, DISABLED_TestExternalRecordRoute)
{
  SCOPED_TRACE("");
  SCSCFMessage msg;
  msg._to = "+15108580271";
  msg._todomain = "ut.cw-ngv.com";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Record-Route", "Record-Route: <sip:sprout.homedomain:5058;transport=TCP;lr;charge-term>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*"), hdrs);
}


TEST_F(SCSCFTest, TestEnumExternalSuccess)
{
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "+16505551000", "homedomain");
  expect_get_subscriber_state(irs_info, "sip:+16505551000@homedomain");

  SCSCFMessage msg;
  msg._to = "+15108580271";
  // We only do ENUM on originating calls
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*+15108580271@ut.cw-ngv.com.*"), hdrs);
}


TEST_F(SCSCFTest, TestNoEnumWhenGRUU)
{
  SCOPED_TRACE("");

  // TODO - It is messy that we need this HSS connection to talk to the I-CSCF
  // in the S-CSCF UTs. This test, and others which do this, should be moved out
  // into a seperate test suite.
  _hss_connection->set_result("/impu/sip%3A%2B15108580271%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  SCSCFMessage msg;
  msg._to = "+15108580271";
  msg._todomain += ";gr=abcd";
  // We only do ENUM on originating calls
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;

  // Set up caller info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "+16505551000", "homedomain");
  expect_get_subscriber_state(irs_info_1, "sip:+16505551000@homedomain");

  // Set up callee info.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings, "+15108580271", "homedomain");
  bindings.begin()->second->_params["+sip.instance"] = "abcd";
  expect_get_callee_info(irs_info_2, bindings, "sip:+15108580271@homedomain");

  // Even though "+15108580271" is configured for ENUM, the presence
  // of a GRUU parameter should indicate to Sprout that this wasn't
  // a string of dialled digits - so we won't do an ENUM lookup and
  // will route to the local subscriber.
  doSuccessfulFlow(msg, testing::MatchesRegex("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob"), hdrs);
}


TEST_F(SCSCFTest, TestGRUUFailure)
{
  // Identical to TestNoEnumWhenGRUU, except that the registered binding in this
  // test has a different instance-id ("abcde" not "abcd"), so the GRUU doesn't
  // match and the call should fail with a 480 error.
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "+16505551000", "homedomain");
  expect_get_subscriber_state(irs_info_1, "sip:+16505551000@homedomain");

  // Set up callee info.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings, "+15108580271", "homedomain");
  bindings.begin()->second->_params["+sip.instance"] = "abcde";
  expect_get_callee_info(irs_info_2, bindings, "sip:+15108580271@homedomain");

   _hss_connection->set_result("/impu/sip%3A%2B15108580271%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  SCSCFMessage msg;
  msg._to = "+15108580271";
  msg._todomain += ";gr=abcd";
  // We only do ENUM on originating calls
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");

  doSlowFailureFlow(msg, 480);
}


// Various ENUM tests - these use the test_stateful_proxy_enum.json file
// TODO - these want tidying up (maybe make the enum service a mock? at least make it so
// there are separate number ranges used in each test).
TEST_F(SCSCFTest, TestEnumExternalSuccessFromFromHeader)
{
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "+15108581234", "homedomain");
  expect_get_subscriber_state(irs_info_1, "sip:+15108581234@homedomain");

  // No callee info needed, as ENUM service resolves tel URI to sip URI that is
  // not in home domain, so is routed externally by the BGCF.

  SCSCFMessage msg;
  msg._to = "+15108580271";
  msg._from = "+15108581234";
  // We only do ENUM on originating calls
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>";

  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*+15108580271@ut.cw-ngv.com.*"), hdrs);
}


TEST_F(SCSCFTest, TestEnumExternalOffNetDialingAllowed)
{
  SCOPED_TRACE("");
  SCSCFMessage msg;

  // Set up caller info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551000", "homedomain");
  expect_get_subscriber_state(irs_info, "sip:6505551000@homedomain");

  // No callee info needed, as ENUM service resolves tel URI to sip URI that is
  // not in home domain, so is routed externally by the BGCF.

  msg._to = "+15108580271";
  // We only do ENUM on originating calls
  msg._route = "Route: <sip:sprout.homedomain;orig>";

  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*+15108580271@ut.cw-ngv.com.*"), hdrs);
}


TEST_F(SCSCFTest, TestEnumUserPhone)
{
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "+16505551000", "homedomain");
  expect_get_subscriber_state(irs_info, "sip:+16505551000@homedomain");

  // No callee info needed, as ENUM service resolves tel URI to sip URI that is
  // not in home domain, so is routed externally by the BGCF.

  URIClassifier::enforce_user_phone = true;
  SCSCFMessage msg;
  msg._to = "+15108580271";
  msg._requri = "sip:+15108580271@homedomain;user=phone";
  // We only do ENUM on originating calls
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*+15108580271@ut.cw-ngv.com.*"), hdrs);
}


TEST_F(SCSCFTest, TestEnumNoUserPhone)
{
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "+16505551000", "homedomain");
  expect_get_subscriber_state(irs_info, "sip:+16505551000@homedomain");

  URIClassifier::enforce_user_phone = true;
  SCSCFMessage msg;
  msg._to = "+15108580271";
  // We only do ENUM on originating calls
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doSlowFailureFlow(msg, 404);
}


TEST_F(SCSCFTest, TestEnumLocalNumber)
{
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "+16505551000", "homedomain");
  expect_get_subscriber_state(irs_info, "sip:+16505551000@homedomain");

  URIClassifier::enforce_global = true;
  SCSCFMessage msg;
  msg._to = "15108580271";
  // We only do ENUM on originating calls
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doSlowFailureFlow(msg, 404);
}


TEST_F(SCSCFTest, TestEnumLocalTelURI)
{
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "+16505551000", "homedomain");
  expect_get_subscriber_state(irs_info, "sip:+16505551000@homedomain");

  URIClassifier::enforce_global = true;
  SCSCFMessage msg;
  msg._to = "16505551234;npdi";
  msg._toscheme = "tel";
  msg._todomain = "";
  // We only do ENUM on originating calls
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  // ENUM fails and wr route to the BGCF, but there are no routes so the call
  // is rejected.
  doSlowFailureFlow(msg, 404, "", "No route to target");
}


TEST_F(SCSCFTest, TestEnumLocalSIPURINumber)
{
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "+16505551000", "homedomain");
  expect_get_subscriber_state(irs_info, "sip:+16505551000@homedomain");

  URIClassifier::enforce_global = true;
  SCSCFMessage msg;
  msg._to = "15108580271;npdi";
  msg._requri = "sip:15108580271;npdi@homedomain;user=phone";
  // We only do ENUM on originating calls
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  // ENUM fails and wr route to the BGCF, but there are no routes so the call
  // is rejected.
  doSlowFailureFlow(msg, 404, "", "No route to target");
}


// Test where the the ENUM lookup returns NP data. The request URI
// is changed, and the request is routed to the BGCF.
TEST_F(SCSCFTest, TestEnumNPData)
{
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "+16505551000", "homedomain");
  expect_get_subscriber_state(irs_info, "sip:+16505551000@homedomain");

  // No callee info needed, as ENUM service resolves tel URI to sip URI that is
  // not in home domain, so is routed externally by the BGCF.

  SCSCFMessage msg;
  msg._to = "+15108580401";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*+15108580401;rn.*+151085804;npdi@homedomain.*"), hdrs);
}


// Test where the request URI represents a number and has NP data. The ENUM
// lookup returns a URI representing a number, so no rewrite is done
TEST_F(SCSCFTest, TestEnumReqURIwithNPData)
{
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "+16505551000", "homedomain");
  expect_get_subscriber_state(irs_info, "sip:+16505551000@homedomain");

  // No callee info needed, as ENUM service resolves tel URI to sip URI that is
  // not in home domain, so is routed externally by the BGCF.

  SCSCFMessage msg;
  msg._to = "+15108580401;npdi;rn=+16";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*15108580401;rn.*+16;npdi@homedomain"), hdrs);
}


// Test where the request URI represents a number and has NP data. The ENUM
// lookup returns a URI representing a number, and override_npdi is on,
// so the request URI is rewritten
TEST_F(SCSCFTest, TestEnumReqURIwithNPDataOverride)
{
  SCOPED_TRACE("");
  _scscf_sproutlet->set_override_npdi(true);

  // Set up caller info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "+16505551000", "homedomain");
  expect_get_subscriber_state(irs_info, "sip:+16505551000@homedomain");

  // No callee info needed, as ENUM service resolves tel URI to sip URI that is
  // not in home domain, so is routed externally by the BGCF.

  SCSCFMessage msg;
  msg._to = "+15108580401;npdi;rn=+16";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*+15108580401;rn.*+151085804;npdi@homedomain.*"), hdrs);
}


// Test where the request URI represents a number and has NP data. The ENUM
// lookup returns a URI that doesn't represent a number so the request URI
// is rewritten
TEST_F(SCSCFTest, TestEnumReqURIwithNPDataToSIP)
{
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "+16505551000", "homedomain");
  expect_get_subscriber_state(irs_info, "sip:+16505551000@homedomain");

  // No callee info needed, as ENUM service resolves tel URI to sip URI that is
  // not in home domain, so is routed externally by the BGCF.

  URIClassifier::enforce_user_phone = true;
  SCSCFMessage msg;
  msg._to = "+15108580272;rn=+16";
  msg._requri = "sip:+15108580272;rn=+16@homedomain;user=phone";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*+15108580272@ut.cw-ngv.com"), hdrs);
}


// Test where the request URI represents a number and has NP data. The ENUM
// lookup returns a URI that doesn't represent a number so the request URI
// is rewritten
TEST_F(SCSCFTest, DISABLED_TestEnumToCIC)
{
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "+16505551000", "homedomain");
  expect_get_subscriber_state(irs_info, "+16505551000");

  // No callee info needed, as ENUM service resolves tel URI to sip URI that is
  // not in home domain, so is routed externally by the BGCF.

  URIClassifier::enforce_user_phone = true;
  SCSCFMessage msg;
  msg._to = "+15108580501";
  msg._requri = "sip:+15108580501@homedomain;user=phone";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*+15108580501;cic=12345@homedomain.*"), hdrs);
}


// Test where the BGCF receives a SIP request URI represents a number and has NP data.
// The ENUM lookup returns a rn which the BGCF routes on.
TEST_F(SCSCFTest, TestEnumNPBGCFSIP)
{
  SCOPED_TRACE("");
  _scscf_sproutlet->set_override_npdi(true);

  // Set up caller info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "+16505551000", "homedomain");
  expect_get_subscriber_state(irs_info, "sip:+16505551000@homedomain");

  // No callee info needed, as ENUM service resolves tel URI to sip URI that is
  // not in home domain, so is routed externally by the BGCF.

  SCSCFMessage msg;
  msg._to = "+15108580401";
  msg._requri = "sip:+15108580401@homedomain;user=phone";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Route", "Route: <sip:10.0.0.1:5060;transport=TCP;lr>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*+15108580401;rn.*+151085804;npdi@homedomain.*"), hdrs);
}


// Test where the BGCF receives a Tel request URI represents a number and has NP data.
// The ENUM lookup returns a rn which the BGCF routes on.
TEST_F(SCSCFTest, TestEnumNPBGCFTel)
{
  SCOPED_TRACE("");
  _scscf_sproutlet->set_override_npdi(true);

  // Set up caller info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "+16505551000", "homedomain");
  expect_get_subscriber_state(irs_info, "sip:+16505551000@homedomain");

  // No callee info needed, as ENUM service resolves tel URI to sip URI that is
  // not in home domain, so is routed externally by the BGCF.

  SCSCFMessage msg;
  msg._to = "+15108580401";
  msg._toscheme = "tel";
  msg._todomain = "";
  msg._requri = "tel:+15108580401";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Route", "Route: <sip:10.0.0.1:5060;transport=TCP;lr>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*+15108580401;rn.*+151085804;npdi@homedomain.*"), hdrs);
}


// We can run with no ENUM service - in this case we expect the Request-URI to
// be unchanged (as there's no lookup which can change it) and for it to just
// be routed normally to the I-CSCF.
TEST_F(SCSCFTest, TestWithoutEnum)
{
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "+16505551000", "homedomain");
  expect_get_subscriber_state(irs_info_1, "sip:+16505551000@homedomain");

  // Set up callee info.
  HSSConnection::irs_info irs_info_2;
  setup_irs_info(irs_info_2, "+15108580271", "homedomain");
  add_sp_identity(irs_info_2, "sip:+15108580271@homedomain");
  Bindings bindings;
  setup_binding(bindings, "tel:+15108580271", "sip:+15108580271@10.114.61.213:5061;transport=tcp;ob");
  expect_get_callee_info(irs_info_2, bindings, "tel:+15108580271");

  _hss_connection->set_result("/impu/tel%3A%2B15108580271/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  // Disable ENUM.
  _scscf_sproutlet->_enum_service = NULL;

  SCSCFMessage msg;
  msg._to = "+15108580271";
  msg._requri = "sip:+15108580271@homedomain;user=phone";

  // We only do ENUM on originating calls
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;

  // Skip the ACK and BYE on this request by setting the last
  // parameter to false, as we're only testing Sprout functionality
  doSuccessfulFlow(msg, testing::MatchesRegex(".*+15108580271@10.114.61.213:5061;transport=tcp;.*"), hdrs);
}

/// Test a forked flow - setup phase.
void SCSCFTestBase::setupForkedFlow(SCSCFMessage& msg)
{
  SCOPED_TRACE("");

  // Set up callee info to include three bindings.
  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings); // Adds bindings for "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob".
  setup_binding(bindings, "sip:6505551234@homedomain", "sip:andunnuvvawun@10.114.61.214:5061;transport=tcp;ob");
  setup_binding(bindings, "sip:6505551234@homedomain", "sip:awwnawmaw@10.114.61.213:5061;transport=tcp;ob");
  expect_get_callee_info(irs_info, bindings);

  pjsip_msg* out;

  // Send INVITE
  inject_msg(msg.get_request());
  ASSERT_EQ(4, txdata_count());

  // 100 Trying goes back
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  free_txdata();

  // Collect INVITEs
  for (int i = 0; i < 3; i++)
  {
    out = current_txdata()->msg;
    ReqMatcher req("INVITE");
    req.matches(out);
    _uris.push_back(req.uri());
    _tdata[req.uri()] = pop_txdata();
  }

  EXPECT_TRUE(_tdata.find("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob") != _tdata.end());
  EXPECT_TRUE(_tdata.find("sip:andunnuvvawun@10.114.61.214:5061;transport=tcp;ob") != _tdata.end());
  EXPECT_TRUE(_tdata.find("sip:awwnawmaw@10.114.61.213:5061;transport=tcp;ob") != _tdata.end());
}


TEST_F(SCSCFTest, TestForkedFlow)
{
  SCOPED_TRACE("");
  pjsip_msg* out;
  SCSCFMessage msg;
  setupForkedFlow(msg);
  ASSERT_EQ(3u, _tdata.size());

  // Send 183 back from one of them
  inject_msg(respond_to_txdata(_tdata[_uris[0]], 183, "early"));

  // 183 goes back
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(183, "early").matches(out);
  free_txdata();

  // Send 100 back from another one of them
  inject_msg(respond_to_txdata(_tdata[_uris[2]], 100));

  // Send 200 OK from another of them
  inject_msg(respond_to_txdata(_tdata[_uris[1]], 200, "bbb"));
  poll();
  ASSERT_EQ(3, txdata_count());

  // OK goes back
  out = current_txdata()->msg;
  RespMatcher(200, "bbb").matches(out);
  free_txdata();

  // Others are cancelled

  // Receive and respond to CANCEL for target 0
  SCOPED_TRACE("");
  out = current_txdata()->msg;
  ReqMatcher c0("CANCEL");
  c0.matches(out);
  EXPECT_THAT(c0.uri(), StrEq(_uris[0]));
  inject_msg(respond_to_current_txdata(200));

  // Receive and respond to CANCEL for target 2
  SCOPED_TRACE("");
  out = current_txdata()->msg;
  ReqMatcher c2("CANCEL");
  c2.matches(out);
  EXPECT_THAT(c2.uri(), StrEq(_uris[2]));
  inject_msg(respond_to_current_txdata(200));

  // Send 487 response from target 0
  SCOPED_TRACE("");
  inject_msg(respond_to_txdata(_tdata[_uris[0]], 487));
  ASSERT_EQ(1, txdata_count());
  // Acknowledges cancel from target 0
  ReqMatcher a0("ACK");
  a0.matches(current_txdata()->msg);
  EXPECT_THAT(a0.uri(), StrEq(_uris[0]));
  free_txdata();

  // Send 487 response from target 2
  SCOPED_TRACE("");
  inject_msg(respond_to_txdata(_tdata[_uris[2]], 487));
  ASSERT_EQ(1, txdata_count());
  // Acknowledges cancel from target 2
  ReqMatcher a2("ACK");
  a2.matches(current_txdata()->msg);
  EXPECT_THAT(a2.uri(), StrEq(_uris[2]));
  free_txdata();

  // All done!
  expect_all_tsx_done();

  // Ensure we count the forked INVITEs
  EXPECT_EQ(2, ((SNMP::FakeCounterTable*)_scscf_sproutlet->_forked_invite_tbl)->_count);
}


TEST_F(SCSCFTest, TestForkedFlow2)
{
  SCOPED_TRACE("");
  pjsip_msg* out;
  SCSCFMessage msg;
  setupForkedFlow(msg);
  ASSERT_EQ(3u, _tdata.size());

  // Send 183 back from one of them
  inject_msg(respond_to_txdata(_tdata[_uris[0]], 183));

  // 183 goes back
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(183).matches(out);
  free_txdata();

  // Send 100 back from one of them
  inject_msg(respond_to_txdata(_tdata[_uris[2]], 100));

  // Send final error from another of them
  inject_msg(respond_to_txdata(_tdata[_uris[1]], 404));

  // Gets acknowledged directly by us
  ASSERT_EQ(1, txdata_count());
  ReqMatcher("ACK").matches(current_txdata()->msg);
  free_txdata();

  // Send final success from first of them
  inject_msg(respond_to_txdata(_tdata[_uris[0]], 200, "abc"));
  poll();

  // Succeeds!
  ASSERT_EQ(2, txdata_count());

  // OK goes back
  out = current_txdata()->msg;
  RespMatcher(200, "abc").matches(out);
  free_txdata();

  // Other is cancelled
  out = current_txdata()->msg;
  ReqMatcher c2("CANCEL");
  c2.matches(out);
  EXPECT_THAT(c2.uri(), StrEq(_uris[2]));
  inject_msg(respond_to_current_txdata(200));
  free_txdata();

  // Send 487 response from target 2
  SCOPED_TRACE("");
  inject_msg(respond_to_txdata(_tdata[_uris[2]], 487));
  ASSERT_EQ(1, txdata_count());
  // Acknowledges cancel from target 2
  ReqMatcher a2("ACK");
  a2.matches(current_txdata()->msg);
  EXPECT_THAT(a2.uri(), StrEq(_uris[2]));
  free_txdata();

  // All done!
  expect_all_tsx_done();

  // Ensure we count the forked INVITEs
  EXPECT_EQ(2, ((SNMP::FakeCounterTable*)_scscf_sproutlet->_forked_invite_tbl)->_count);
}


TEST_F(SCSCFTest, TestForkedFlow3)
{
  SCOPED_TRACE("");
  pjsip_msg* out;
  SCSCFMessage msg;
  setupForkedFlow(msg);
  ASSERT_EQ(3u, _tdata.size());

  // Send 183 back from one of them
  inject_msg(respond_to_txdata(_tdata[_uris[0]], 183));
  // 183 goes back
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(183).matches(out);
  free_txdata();

  // Send final error from another of them
  inject_msg(respond_to_txdata(_tdata[_uris[1]], 404));
  poll();

  // Gets acknowledged directly by us
  ASSERT_EQ(1, txdata_count());
  ReqMatcher("ACK").matches(current_txdata()->msg);
  free_txdata();

  // Send final error from a third
  inject_msg(respond_to_txdata(_tdata[_uris[2]], 503));

  // Gets acknowledged directly by us
  ASSERT_EQ(1, txdata_count());
  ReqMatcher("ACK").matches(current_txdata()->msg);
  free_txdata();

  // Send final failure from first of them
  inject_msg(respond_to_txdata(_tdata[_uris[0]], 301));

  // Gets acknowledged directly by us
  ASSERT_EQ(2, txdata_count());
  ReqMatcher("ACK").matches(current_txdata()->msg);
  free_txdata();

  // "best" failure goes back
  out = current_txdata()->msg;
  RespMatcher(301).matches(out);
  free_txdata();

  // All done!
  expect_all_tsx_done();

  // Ensure we count the forked INVITEs
  EXPECT_EQ(2, ((SNMP::FakeCounterTable*)_scscf_sproutlet->_forked_invite_tbl)->_count);
}


TEST_F(SCSCFTest, TestForkedFlow4)
{
  SCOPED_TRACE("");
  SCSCFMessage msg;
  setupForkedFlow(msg);
  ASSERT_EQ(3u, _tdata.size());

  // Send final error from one of them
  inject_msg(respond_to_txdata(_tdata[_uris[0]], 503));
  // Gets acknowledged directly by us
  ASSERT_EQ(1, txdata_count());
  ReqMatcher("ACK").matches(current_txdata()->msg);
  free_txdata();

  // Send final error from another of them
  inject_msg(respond_to_txdata(_tdata[_uris[1]], 408));

  // Gets acknowledged directly by us
  ASSERT_EQ(1, txdata_count());
  ReqMatcher("ACK").matches(current_txdata()->msg);
  free_txdata();

  // Send a CANCEL from the caller
  msg._method = "CANCEL";
  inject_msg(msg.get_request());

  // CANCEL gets OK'd
  ASSERT_EQ(1, txdata_count());
  RespMatcher(200).matches(current_txdata()->msg);
  free_txdata();

  // No CANCEL sent immediately because target 2 hasn't sent a response.
  ASSERT_EQ(0, txdata_count());

  // Send in a 100 Trying from target 2
  inject_msg(respond_to_txdata(_tdata[_uris[2]], 100));

  // Gets passed through to target 2
  ASSERT_EQ(1, txdata_count());
  ReqMatcher c2("CANCEL");
  c2.matches(current_txdata()->msg);
  EXPECT_THAT(c2.uri(), StrEq(_uris[2]));

  // Respond from target 2 to CANCEL
  inject_msg(respond_to_current_txdata(200));
  // Nothing happens yet
  ASSERT_EQ(0, txdata_count());

  // Respond from target 2 to INVITE
  SCOPED_TRACE("");
  inject_msg(respond_to_txdata(_tdata[_uris[2]], 487));
  ASSERT_EQ(2, txdata_count());

  // Acknowledges cancel from target 2
  ReqMatcher a2("ACK");
  a2.matches(current_txdata()->msg);
  EXPECT_THAT(a2.uri(), StrEq(_uris[2]));
  free_txdata();

  // Finally, pass cancel response back to initial INVITE
  ASSERT_EQ(1, txdata_count());
  RespMatcher(487).matches(current_txdata()->msg);
  free_txdata();

  // All done!
  expect_all_tsx_done();

  // Ensure we count the forked INVITEs
  EXPECT_EQ(2, ((SNMP::FakeCounterTable*)_scscf_sproutlet->_forked_invite_tbl)->_count);
}


// Test SIP Message flows
TEST_F(SCSCFTest, TestSIPMessageSupport)
{
  SCOPED_TRACE("");

  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings);
  expect_get_callee_info(irs_info, bindings);

  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345";
  pjsip_msg* out;
  pjsip_tx_data* message = NULL;

  // Send MESSAGE
  SCOPED_TRACE("MESSAGE");
  msg._method = "MESSAGE";
  inject_msg(msg.get_request(), _tp_default);
  poll();

  // MESSAGE passed on to destination (bono set up in callee's bindings)
  SCOPED_TRACE("MESSAGE (S)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("MESSAGE").matches(out));
  tpCalleeBono.expect_target(current_txdata(), false);

   message = pop_txdata();

   // Send 200 OK back
  SCOPED_TRACE("200 OK (MESSAGE)");
  inject_msg(respond_to_txdata(message, 200), _tp_default);
  ASSERT_EQ(1, txdata_count());

  // OK goes back
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  _tp_default->expect_target(current_txdata(), true);

  free_txdata();
}


// Test that a multipart message can be parsed successfully
TEST_F(SCSCFTest, TestSimpleMultipart)
{
  SCOPED_TRACE("");

  // Set up callee info.
  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings);
  expect_get_callee_info(irs_info, bindings);

  SCSCFMessage msg;
  msg._content_type = "multipart/mixed;boundary=\"boundary1\"";
  msg._body = "\r\n--boundary1\r\nContent-Type: application/sdp\r\nContent-Length: 343\r\n\r\nv=0\r\no=- 3600506724 3600506724 IN IP4 888.888.888.888\r\n" \
              "s=-\r\nc=IN IP4 888.888.888.888\r\nt=0 0\r\nm=message 9 TCP/MSRP *\r\na=path:msrp://888.888.888.888:7777/1391517924073;tcp\r\n" \
              "a=setup:active\r\na=accept-types:message/cpim application/im-iscomposing+xml\r\na=accept-wrapped-types:text/plain message/imdn+xml " \
              "application/rcspushlocation+xml\r\na=sendrecv\r\n\r\n--boundary1\r\nContent-Type: message/cpim\r\nContent-Length: 300\r\n\r\nFrom: " \
              "<sip:anonymous@anonymous.invalid>\r\nTo: <sip:anonymous@anonymous.invalid>\r\nNS: imdn <urn:ietf:params:imdn>\r\nimdn.Message-ID: " \
              "Msg6rn78PUQzC\r\nDateTime: 2014-02-04T12:45:24.000Z\r\nimdn.Disposition-Notification: positive-delivery, display\r\n\r\nContent-type: " \
              "text/plain; charset=utf-8\r\n\r\nsubject\r\n\r\n--boundary1--";

  list<HeaderMatcher> hdrs;
  // Check that the Content-Type manipulation in PJSIP has not inserted multiple
  // Content-Types in the bodyparts
  doSuccessfulFlow(msg,
                   testing::MatchesRegex(".*wuntootreefower.*"),
                   hdrs,
                   true,
                   list<HeaderMatcher>(),
                   ".*--\\S+\r\nContent-Length: 343\r\nContent-Type: application/sdp\r\n\r\n.*");
}


// Test emergency registrations receive calls.
TEST_F(SCSCFTest, TestReceiveCallToEmergencyBinding)
{
  SCOPED_TRACE("");

  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings); // This adds the non emergency binding.
  setup_binding(bindings, "sip:6505551234@homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;sos;ob", true);
  expect_get_callee_info(irs_info, bindings);

  SCSCFMessage msg;
  pjsip_msg* out;

  // Send INVITE
  inject_msg(msg.get_request());
  ASSERT_EQ(3, txdata_count());

  // 100 Trying goes back
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  free_txdata();

  // Collect INVITEs
  for (int i = 0; i < 2; i++)
  {
    out = current_txdata()->msg;
    ReqMatcher req("INVITE");
    req.matches(out);
    _uris.push_back(req.uri());
    _tdata[req.uri()] = pop_txdata();
  }

  EXPECT_TRUE(_tdata.find("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob") != _tdata.end());
  EXPECT_TRUE(_tdata.find("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;sos;ob") != _tdata.end());
}


// Test basic ISC (AS) flow.
TEST_F(SCSCFTest, SimpleISCMainline)
{
  // Set up info about the caller.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  irs_info_1._regstate = "UNREGISTERED";
  set_ifc(irs_info_1, "sip:6505551000@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Setup info about callee.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  expect_get_callee_info(irs_info_2, bindings);

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  EXPECT_CALL(*_sess_cont_comm_tracker, on_success(StrEq("sip:1.2.3.4:56789;transport=UDP")));

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig;service=scscf>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551000@homedomain>;sescase=orig;regstate=unreg"));

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp, &tpAS1);

  // ---------- AS1 turns it around (acting as proxy)
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed to final destination (to bono set up in callee's bindings)
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));
  tpCalleeBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r2.uri());
  EXPECT_EQ(BONO_ROUTE_HEADER, get_headers(out, "Route"));

  // Target sends back 100 Trying
  inject_msg(respond_to_txdata(current_txdata(), 100), &tpBono);

  pjsip_tx_data* txdata = pop_txdata();

  // Send a 200 ringing back down the chain to finish the transaction. This is a
  // more realistic test of AS communication tracking.
  send_response_back_through_dialog(respond_to_txdata(txdata, 200), 200, 2);

  pjsip_tx_data_dec_ref(txdata); txdata = NULL;
}


// Test basic ISC (AS) flow that involves multiple responses to a single
// request.
TEST_F(SCSCFTest, ISCMultipleResponses)
{
  // Set up info about the caller.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  irs_info_1._regstate = "UNREGISTERED";
  set_ifc(irs_info_1, "sip:6505551000@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Setup info about callee.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  expect_get_callee_info(irs_info_2, bindings);

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  // Only expect one call into the AS communication tracker despite receiving
  // multiple responses to the same request.
  EXPECT_CALL(*_sess_cont_comm_tracker, on_success(StrEq("sip:1.2.3.4:56789;transport=UDP")));

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig;service=scscf>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551000@homedomain>;sescase=orig;regstate=unreg"));

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp, &tpAS1);

  // ---------- AS1 turns it around (acting as proxy)
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed to final destination (to bono set up in callee's bindings)
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));
  tpCalleeBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r2.uri());
  EXPECT_EQ(BONO_ROUTE_HEADER, get_headers(out, "Route"));

  // Target sends back 100 Trying
  inject_msg(respond_to_txdata(current_txdata(), 100), &tpBono);

  pjsip_tx_data* txdata = pop_txdata();

  // Send a 180 ringing back down the chain to finish the transaction. This is a
  // more realistic test of AS communication tracking.
  send_response_back_through_dialog(respond_to_txdata(txdata, 180), 180, 2);

  // The 180 counts as the session having been setup from a stats perspective.
  // Check that the stats have been incremented accordingly.
  EXPECT_EQ(1, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_audio_session_setup_time_tbl)->_count);
  EXPECT_EQ(0, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_video_session_setup_time_tbl)->_count);

  // Also send a 200 OK to check that the AS only gets tracked as successful
  // once.
  send_response_back_through_dialog(respond_to_txdata(txdata, 200), 200, 2);

  // Check that 200 OK hasn't resulted in any more session setup stats being
  // accumulated.
  EXPECT_EQ(1, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_audio_session_setup_time_tbl)->_count);
  EXPECT_EQ(0, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_video_session_setup_time_tbl)->_count);

  pjsip_tx_data_dec_ref(txdata); txdata = NULL;
}


// Test that, if we change a SIP URI to an aliased TEL URI, it doesn't count as
// a retarget for originating-cdiv purposes.
TEST_F(SCSCFTest, ISCRetargetWithoutCdiv)
{
  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings);
  add_sp_identity(irs_info, "tel:6505551234");
  ServiceProfileBuilder service_profile = ServiceProfileBuilder()
    .addIfc(1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  set_ifcs_from_service_profile(irs_info, service_profile, "tel:6505551234");
  set_ifcs_from_service_profile(irs_info, service_profile, "sip:6505551234@homedomain");
  expect_get_callee_info(irs_info, bindings, "sip:6505551234@homedomain", 2);

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._route = "Route: <sip:sprout.homedomain>";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  tpAS1.expect_target(current_txdata(), false);

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp, &tpAS1);

  // ---------- AS1 turns it around (acting as proxy)
  const pj_str_t STR_ROUTE = pj_str("Route");
  const pj_str_t STR_NUMBER = pj_str("6505551234");
  pjsip_tel_uri* new_requri = pjsip_tel_uri_create(current_txdata()->pool);
  new_requri->number = STR_NUMBER;
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  out->line.req.uri = (pjsip_uri*)new_requri;
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed to final destination (to bono set up in callee's bindings)
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));
  tpCalleeBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r2.uri());
  EXPECT_EQ(BONO_ROUTE_HEADER, get_headers(out, "Route"));

  free_txdata();
}


// Test basic ISC (AS) flow.
TEST_F(SCSCFTest, SimpleISCTwoRouteHeaders)
{
  // Expect a call to look up the iFCs for the caller.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  set_ifc(irs_info_1, "sip:6505551000@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain;orig>\r\nRoute: <sip:abcde.com>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig;service=scscf>\r\nRoute: <sip:abcde.com>"));

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp, &tpAS1);
  free_txdata();
}


// Test handling of iFC with a malformed AS URI.
TEST_F(SCSCFTest, ISCASURIMalformed)
{
  // Set up info about caller, with a malformed AS URI.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551000", "homedomain");
  set_ifc(irs_info, "sip:6505551000@homedomain", 0, {"<Method>INVITE</Method>"}, "sip::5060");
  expect_get_subscriber_state(irs_info, "sip:6505551000@homedomain");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();

  // INVITE rejected with 502 Bad Gateway response.
  out = current_txdata()->msg;
  RespMatcher(502).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();
}


// Test handling of iFC with a AS Tel URI.
TEST_F(SCSCFTest, ISCASURITel)
{
  // Expect a call to look up the iFCs for the caller.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  set_ifc(irs_info_1, "sip:6505551000@homedomain", 1, {"<Method>INVITE</Method>"}, "tel:1234");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();

  // INVITE rejected with 502 Bad Gateway response.
  out = current_txdata()->msg;
  RespMatcher(502).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();
}


// Test basic ISC (AS) flow with a single "Next" on the originating side.
TEST_F(SCSCFTest, SimpleNextOrigFlow)
{
  // Expect a call to look up the iFCs for the caller.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  ServiceProfileBuilder service_profile = ServiceProfileBuilder()
    .addIfc(0, {"<Method>ETAOIN_SHRDLU</Method>"}, "sip:linotype.example.org")
    .addIfc(1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  set_ifcs_from_service_profile(irs_info_1, service_profile, "sip:6505551000@homedomain");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Expect calls to look up the iFCs and bindings of the callee.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  expect_get_callee_info(irs_info_2, bindings);

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig;service=scscf>"));

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp, &tpAS1);

  // ---------- AS1 turns it around (acting as proxy)
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed to final destination (to bono set up in callee's bindings)
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));
  tpCalleeBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r2.uri());
  EXPECT_EQ(BONO_ROUTE_HEADER, get_headers(out, "Route"));

  free_txdata();
}


// Test basic ISC (AS) rejection flow.
TEST_F(SCSCFTest, SimpleReject)
{
  // Expect a call looking up iFCs for the callee. Assign one iFC to the callee
  // so that an AS is invoked.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551234", "homedomain");
  set_ifc(irs_info, "sip:6505551234@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  expect_get_subscriber_state(irs_info, "sip:6505551234@homedomain");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._requri = "sip:6505551234@homedomain";
  msg._route = "Route: <sip:sprout.homedomain>";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));

  // ---------- AS1 rejects it.
  string fresp = respond_to_txdata(current_txdata(), 404);
  free_txdata();
  inject_msg(fresp, &tpAS1);

  // ACK goes back to AS1
  SCOPED_TRACE("ACK");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("ACK").matches(out));
  free_txdata();

  // 404 response goes back to bono
  SCOPED_TRACE("404");
  out = current_txdata()->msg;
  RespMatcher(404).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  msg._cseq++;
  free_txdata();

  // ---------- Send ACK from bono
  SCOPED_TRACE("ACK");
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpBono);
}


// Test basic ISC (AS) terminating-only flow: call comes from non-local user.
TEST_F(SCSCFTest, SimpleNonLocalReject)
{
  // Set up callee info. There is no need to set up info about the bindings, as
  // the AS will reject the call before the targets are looked up.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551234", "homedomain");
  set_ifc(irs_info, "sip:6505551234@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  expect_get_subscriber_state(irs_info, "sip:6505551234@homedomain");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._fromdomain = "remote-base.mars.int";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));

  // ---------- AS1 rejects it.
  string fresp = respond_to_txdata(current_txdata(), 404);
  free_txdata();
  inject_msg(fresp, &tpAS1);

  // ACK goes back to AS1
  SCOPED_TRACE("ACK");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("ACK").matches(out));
  free_txdata();

  // 404 response goes back to bono
  SCOPED_TRACE("404");
  out = current_txdata()->msg;
  RespMatcher(404).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  msg._cseq++;
  free_txdata();

  // ---------- Send ACK from bono
  SCOPED_TRACE("ACK");
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpBono);
}


// Test basic ISC (AS) final acceptance flow (AS sinks request).
TEST_F(SCSCFTest, SimpleAccept)
{
  // Set up callee info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551234", "homedomain");
  set_ifc(irs_info, "sip:6505551234@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  expect_get_subscriber_state(irs_info, "sip:6505551234@homedomain");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._requri = "sip:6505551234@homedomain";
  msg._route = "Route: <sip:sprout.homedomain>";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));

  // ---------- AS1 accepts it with 200.
  string fresp = respond_to_txdata(current_txdata(), 200);
  free_txdata();
  inject_msg(fresp, &tpAS1);

  // 200 response goes back to bono
  SCOPED_TRACE("OK");
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  msg._cseq++;
  free_txdata();

  // ---------- Send ACK from bono
  SCOPED_TRACE("ACK");
  msg._method = "ACK";
  msg._in_dialog = true;
  inject_msg(msg.get_request(), &tpBono);

  // ACK goes back to AS1
  SCOPED_TRACE("ACK");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("ACK").matches(out));
  free_txdata();
}


// Test basic ISC (AS) redirection flow.
TEST_F(SCSCFTest, SimpleRedirect)
{
  // Set up callee info. There is no need to set up any bindings, as the AS will
  // redirect the call.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551234", "homedomain");
  set_ifc(irs_info, "sip:6505551234@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  expect_get_subscriber_state(irs_info, "sip:6505551234@homedomain");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";
  msg._route = "Route: <sip:sprout.homedomain>";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));

  // ---------- AS1 redirects it to another user on the same server.
  string fresp = respond_to_txdata(current_txdata(), 302, "", "Contact: sip:6505559876@homedomain");
  free_txdata();
  inject_msg(fresp, &tpAS1);

  // ACK goes back to AS1
  SCOPED_TRACE("ACK");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("ACK").matches(out));
  free_txdata();

  // 302 response goes back to bono
  SCOPED_TRACE("Redirect");
  out = current_txdata()->msg;
  RespMatcher(302).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  EXPECT_EQ("Contact: <sip:6505559876@homedomain>", get_headers(out, "Contact"));
  msg.convert_routeset(out);
  msg._cseq++;
  free_txdata();

  // ---------- Send ACK from bono
  SCOPED_TRACE("ACK");
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpBono);
}


// Test DefaultHandling=TERMINATE for non-responsive AS.
TEST_F(SCSCFTest, DefaultHandlingTerminate)
{
  // Set up caller info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551234", "homedomain");
  set_ifc(irs_info, "sip:6505551234@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP", 0, "1");
  expect_get_subscriber_state(irs_info, "sip:6505551234@homedomain");

  EXPECT_CALL(*_sess_term_comm_tracker, on_failure(_, HasSubstr("408")));

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._fromdomain = "remote-base.mars.int";
  msg._requri = "sip:6505551234@homedomain";
  msg._route = "Route: <sip:sprout.homedomain>";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));

  // ---------- AS1 rejects it with a 408 error.
  string fresp = respond_to_txdata(current_txdata(), 408);
  free_txdata();
  inject_msg(fresp, &tpAS1);

  // ACK goes back to AS1
  SCOPED_TRACE("ACK");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("ACK").matches(out));
  free_txdata();

  // 408 response goes back to bono
  SCOPED_TRACE("408");
  out = current_txdata()->msg;
  RespMatcher(408).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  msg._cseq++;
  free_txdata();

  // ---------- Send ACK from bono
  SCOPED_TRACE("ACK");
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpBono);
}


// Test that if an AS is unresponsive (ie. does not respond before it times
// out), and Default Handling is set to Session Terminated, that the call is
// rejected (without waiting for all retries to the AS to time out).
TEST_F(SCSCFTest, DefaultHandlingTerminateTimeout)
{
  // Expect a call looking up the iFCs for the caller. Return an iFC with its
  // default handling set to session terminated.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551000", "homedomain");
  set_ifc(irs_info, "sip:6505551000@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=tcp", 0, "1");
  expect_get_subscriber_state(irs_info, "sip:6505551000@homedomain");

  EXPECT_CALL(*_sess_term_comm_tracker, on_failure(_, HasSubstr("timeout")));

  TransportFlow tpCaller(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::TCP, stack_data.scscf_port, "1.2.3.4", 56789);

  // Caller sends INVITE.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to caller.
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS.
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  free_txdata();

  // Advance time without receiving a response. The application server is
  // bypassed.
  cwtest_advance_time_ms(6001);
  poll();

  // 408 received at caller, without having to advance time again.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(408).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();

  // Caller ACKs error response.
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(0, txdata_count());
}


// Test that after a 408 has been sent in response to an unresponsive AS, a 100
// Trying response from the AS is still handled.
TEST_F(SCSCFTest, DefaultHandlingTerminate100AfterTimeout)
{
  // Expect a call looking up the iFCs for the caller. Return an iFC with its
  // default handling set to session terminated.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551000", "homedomain");
  set_ifc(irs_info, "sip:6505551000@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=tcp", 0, "1");
  expect_get_subscriber_state(irs_info, "sip:6505551000@homedomain");

  EXPECT_CALL(*_sess_term_comm_tracker, on_failure(_, HasSubstr("timeout")));

  TransportFlow tpCaller(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::TCP, stack_data.scscf_port, "1.2.3.4", 56789);

  // Caller sends INVITE.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to caller.
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS.
  // Save off the INVITE, as it is needed later on in the test.
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  pjsip_tx_data* inv_for_as = pop_txdata();

  // Advance time without receiving a response. The application server is
  // bypassed.
  cwtest_advance_time_ms(6001);
  poll();

  // 408 received at caller.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(408).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();

  // Caller ACKs error response.
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(0, txdata_count());

  // Advance some more time.
  cwtest_advance_time_ms(6000);
  poll();

  // Now the AS finally responds with a 100 Trying.
  inject_msg(respond_to_txdata(inv_for_as, 100), &tpAS1);

  // Respond to the AS with a CANCEL, as the timeout error has already been sent
  // to the caller.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  ReqMatcher("CANCEL").matches(out);
  tpAS1.expect_target(current_txdata(), true);

  // AS responds to the CANCEL with a 200 OK.
  inject_msg(respond_to_txdata(current_txdata(), 200), &tpAS1);
  free_txdata();

  // AS sends back a 487 for the cancelled INVITE.
  inject_msg(respond_to_txdata(inv_for_as, 487), &tpAS1);

  // Confirm that sprout ACKs the 487.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  ReqMatcher("ACK").matches(out);
  tpAS1.expect_target(current_txdata(), true);
  free_txdata();

  // Check no other messages are pending.
  ASSERT_EQ(0, txdata_count());
  pjsip_tx_data_dec_ref(inv_for_as); inv_for_as = NULL;
}


// Test that after a 408 has been sent in response to an unresponsive AS, a 100
// Trying response from the AS is still handled (while handling a MESSAGE).
TEST_F(SCSCFTest, DefaultHandlingTerminateMessage100AfterTimeout)
{
  // Expect a call looking up the iFCs for the caller. Return an iFC with its
  // default handling set to session terminated.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551000", "homedomain");
  set_ifc(irs_info, "sip:6505551000@homedomain", 1, {"<Method>MESSAGE</Method>"}, "sip:1.2.3.4:56789;transport=tcp", 0, "1");
  expect_get_subscriber_state(irs_info, "sip:6505551000@homedomain");

  EXPECT_CALL(*_sess_term_comm_tracker, on_failure(_, HasSubstr("timeout")));

  TransportFlow tpUE1(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::TCP, stack_data.scscf_port, "1.2.3.4", 56789);

  // UE1 sends MESSAGE.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "MESSAGE";
  inject_msg(msg.get_request(), &tpUE1);
  poll();
  ASSERT_EQ(1, txdata_count());

  // MESSAGE passed on to AS.
  // Save off the MESSAGE, as it is needed later on in the test.
  pjsip_msg* out = current_txdata()->msg;
  ReqMatcher r1("MESSAGE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  pjsip_tx_data* msg_for_as = pop_txdata();

  // Advance time by just over 3.5 secs, so that a delayed 100 Trying will be
  // returned to UE1.
  cwtest_advance_time_ms(3501);
  poll();

  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpUE1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();

  // Advance time further without receiving a response.
  // The application server is bypassed after 6s, so advance to reach this
  // (remembering we have already advanced 3.5s).
  cwtest_advance_time_ms(2500);
  poll();

  // Check that a 408 is sent to UE1, as the request to the AS has timed out.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(408).matches(out);
  tpUE1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();

  // Advance some more time.
  cwtest_advance_time_ms(6000);
  poll();

  // Now the AS finally responds with a 100 Trying. This doesn't trigger a
  // CANCEL, as it was a response to a MESSAGE.
  inject_msg(respond_to_txdata(msg_for_as, 100), &tpAS1);
  ASSERT_EQ(0, txdata_count());

  // AS sends back a 200 for the MESSAGE.
  inject_msg(respond_to_txdata(msg_for_as, 200), &tpAS1);

  // Check no other messages are pending.
  ASSERT_EQ(0, txdata_count());
  pjsip_tx_data_dec_ref(msg_for_as); msg_for_as = NULL;
}


// Test that after a 408 has been sent in response to an unresponsive AS, a 200
// OK response from the AS is still handled.
TEST_F(SCSCFTest, DefaultHandlingTerminate200AfterTimeout)
{
  // Expect a call looking up the iFCs for the caller. Return an iFC with its
  // default handling set to session terminated.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551000", "homedomain");
  set_ifc(irs_info, "sip:6505551000@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=tcp", 0, "1");
  expect_get_subscriber_state(irs_info, "sip:6505551000@homedomain");

  EXPECT_CALL(*_sess_term_comm_tracker, on_failure(_, HasSubstr("timeout")));

  TransportFlow tpCaller(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::TCP, stack_data.scscf_port, "1.2.3.4", 56789);

  // Caller sends INVITE.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to caller.
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS.
  // Save off the INVITE, as it is needed later on in the test.
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  pjsip_tx_data* inv_for_as = pop_txdata();

  // Advance time without receiving a response. The application server is
  // bypassed.
  cwtest_advance_time_ms(6001);
  poll();

  // 408 received at caller.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(408).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();

  // Caller ACKs error response.
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(0, txdata_count());

  // Advance some more time.
  cwtest_advance_time_ms(6000);
  poll();

  // Now the AS finally responds with a 200 OK.
  // As a 408 response has already been sent upstream, this 200 OK shouldn't be
  // passed on. Also, since the AS is not currently trying, no CANCEL will be
  // sent to the AS either.
  inject_msg(respond_to_txdata(inv_for_as, 200), &tpAS1);

  // Check no other messages are pending.
  ASSERT_EQ(0, txdata_count());
}


// Test that after a 408 has been sent in response to an unresponsive AS, a 4xx
// error response from the AS is still handled.
TEST_F(SCSCFTest, DefaultHandlingTerminate4xxAfterTimeout)
{
  // Expect a call looking up the iFCs for the caller. Return an iFC with its
  // default handling set to session terminated.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551000", "homedomain");
  set_ifc(irs_info, "sip:6505551000@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=tcp", 0, "1");
  expect_get_subscriber_state(irs_info, "sip:6505551000@homedomain");

  EXPECT_CALL(*_sess_term_comm_tracker, on_failure(_, HasSubstr("timeout")));

  TransportFlow tpCaller(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::TCP, stack_data.scscf_port, "1.2.3.4", 56789);

  // Caller sends INVITE.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to caller.
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS.
  // Save off the INVITE, as it is needed later on in the test.
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  pjsip_tx_data* inv_for_as = pop_txdata();

  // Advance time without receiving a response. The application server is
  // bypassed.
  cwtest_advance_time_ms(6001);
  poll();

  // 408 received at caller.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(408).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();

  // Caller ACKs error response.
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(0, txdata_count());

  // Advance some more time.
  cwtest_advance_time_ms(6000);
  poll();

  // Now the AS finally responds with a 403 (a 4xx error code chosen at random).
  inject_msg(respond_to_txdata(inv_for_as, 403), &tpAS1);

  // Confirm sprout responds to the error from the AS with an ACK.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  ReqMatcher("ACK").matches(out);
  tpAS1.expect_target(current_txdata(), true);
  free_txdata();

  // Check error is not forwarded on, as timeout error has already been sent.
  ASSERT_EQ(0, txdata_count());
}


// Test that after a 408 has been sent in response to an unresponsive AS, a 5xx
// error response from the AS is still handled.
TEST_F(SCSCFTest, DefaultHandlingTerminate5xxAfterTimeout)
{
  // Expect a call looking up the iFCs for the caller. Return an iFC with its
  // default handling set to session terminated.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551000", "homedomain");
  set_ifc(irs_info, "sip:6505551000@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=tcp", 0, "1");
  expect_get_subscriber_state(irs_info, "sip:6505551000@homedomain");

  EXPECT_CALL(*_sess_term_comm_tracker, on_failure(_, HasSubstr("timeout")));
  EXPECT_CALL(*_sess_term_comm_tracker, on_failure(_, HasSubstr("501")));

  TransportFlow tpCaller(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::TCP, stack_data.scscf_port, "1.2.3.4", 56789);

  // Caller sends INVITE.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to caller.
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS.
  // Save off the INVITE, as it is needed later on in the test.
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  pjsip_tx_data* inv_for_as = pop_txdata();

  // Advance time without receiving a response. The application server is
  // bypassed.
  cwtest_advance_time_ms(6001);
  poll();

  // 408 received at caller.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(408).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();

  // Caller ACKs error response.
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(0, txdata_count());

  // Advance some more time.
  cwtest_advance_time_ms(6000);
  poll();

  // Now the AS finally responds with a 501 (a 5xx error code chosen at random).
  inject_msg(respond_to_txdata(inv_for_as, 501), &tpAS1);

  // Confirm sprout responds to the error from the AS with an ACK.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  ReqMatcher("ACK").matches(out);
  tpAS1.expect_target(current_txdata(), true);
  free_txdata();

  // Check error is not forwarded on, as timeout error has already been sent.
  ASSERT_EQ(0, txdata_count());
}


// Test that after a 100 Trying is received from an AS, the request isn't timed
// out after 6 secs (set as the default timeout for an AS when Default
// Handling is set to Session Terminated) with a 408, and instead a CANCEL is
// sent after waiting for 3 mins (min timeout for INVITE generating a final
// response).
TEST_F(SCSCFTest, TimeoutExtendedByProofOfLife)
{
  // Expect a call looking up the iFCs for the caller. Return an iFC with its
  // default handling set to session terminated.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551000", "homedomain");
  set_ifc(irs_info, "sip:6505551000@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=tcp", 0, "1");
  expect_get_subscriber_state(irs_info, "sip:6505551000@homedomain");

  TransportFlow tpCaller(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::TCP, stack_data.scscf_port, "1.2.3.4", 56789);

  // Caller sends INVITE.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to caller.
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS.
  // Save off the INVITE, as it is needed later on in the test.
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  pjsip_tx_data* inv_for_as = pop_txdata();

  // AS responds with 100 Trying.
  inject_msg(respond_to_txdata(inv_for_as, 100), &tpAS1);

  // Advance some time (more than 6s, which is the testbed timout for a session
  // terminated AS which hasn't sent any response).
  cwtest_advance_time_ms(6001);
  poll();

  // Check no timeout has been sent upstream.
  ASSERT_EQ(0, txdata_count());

  // Advance 3 mins and 1 millisec so that the INVITE will time out.
  cwtest_advance_time_ms(180001);
  poll();

  // At this point we should have sent a CANCEL to the AS, as the INVITE has
  // timed out.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  ReqMatcher("CANCEL");
  tpAS1.expect_target(current_txdata(), true);
  free_txdata();

  // Advance time for 32 secs and 1 millisec so that the time period in which we
  // will wait for a response to a CANCEL has timed out.
  cwtest_advance_time_ms(32001);
  poll();

  // At this point we should have sent a 487 error upstream, to show the request
  // has been terminated with a CANCEL.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(487).matches(out);
  tpCaller.expect_target(current_txdata(), true);
  free_txdata();

  // Check no other messages pending.
  poll();
  ASSERT_EQ(0, txdata_count());
}


TEST_F(SCSCFTest, DefaultHandlingTerminateDisabled)
{
  // Disable the liveness timer for session terminated ASs.
  _scscf_sproutlet->set_session_terminated_timeout(0);

  // Expect a call looking up the iFCs for the caller. Return an iFC with its
  // default handling set to session terminated.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551000", "homedomain");
  set_ifc(irs_info, "sip:6505551000@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=tcp", 0, "1");
  expect_get_subscriber_state(irs_info, "sip:6505551000@homedomain");

  TransportFlow tpCaller(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::TCP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // Caller sends INVITE
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._requri = "sip:6505551234@homedomain";
  msg._route = "Route: <sip:sprout.homedomain;orig>";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to caller
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  free_txdata();

  // Advance time without receiving a response. Nothing happens straight away.
  cwtest_advance_time_ms(6000);
  poll();
  ASSERT_EQ(0, txdata_count());

  // After another 26s the AS transaction times out and the call fails.
  cwtest_advance_time_ms(26000);
  poll();
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(408).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();

  // Caller ACKs error response.
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(0, txdata_count());
}


// Test DefaultHandling=CONTINUE for non-existent AS (where name does not resolve).
TEST_F(SCSCFTest, DefaultHandlingContinueRecordRouting)
{
  // Expect calls looking up the iFCs and the bindings for the callee. Return an
  // iFC with its default handling set to session continued.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  set_ifc(irs_info_2, "sip:6505551234@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:ne-as:56789;transport=UDP");
  expect_get_callee_info(irs_info_2, bindings);

  EXPECT_CALL(*_sess_cont_comm_tracker, on_failure(_, HasSubstr("No valid address"))).Times(1);
  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);

  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._requri = "sip:6505551234@homedomain";
  msg._route = "Route: <sip:sprout.homedomain";

  stack_data.record_route_on_initiation_of_terminating = true;
  stack_data.record_route_on_completion_of_originating = true;
  stack_data.record_route_on_diversion = false;
  stack_data.record_route_on_every_hop = false;

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  free_txdata();

  // AS name fails to resolve, so INVITE passed on to final destination
  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));

  EXPECT_NE("", get_headers(out, "Record-Route"));

  free_txdata();

  stack_data.record_route_on_initiation_of_terminating = false;
  stack_data.record_route_on_completion_of_originating = false;
  stack_data.record_route_on_diversion = false;
  stack_data.record_route_on_every_hop = false;
}


// Test DefaultHandling=CONTINUE for TCP transport error when contacting AS
TEST_F(SCSCFTest, DefaultHandlingContinueTransportTerminate)
{
  // Expect calls looking up the iFCs and the bindings for the callee. Return an
  // iFC with its default handling set up session continued.
  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings);
  set_ifc(irs_info, "sip:6505551234@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=TCP");
  expect_get_callee_info(irs_info, bindings);

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to caller
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // Contacting right AS, but TCP transport is terminated
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  terminate_tcp_transport(current_txdata()->tp_info.transport);
  poll();
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));
  free_txdata();

  // Without getting a response from AS, INVITE continues to be passed on to
  // final destination (to the bono set up in the callee's bindings)
  SCOPED_TRACE("INVITE (3)");
  out = current_txdata()->msg;
  ReqMatcher r3("INVITE");
  ASSERT_NO_FATAL_FAILURE(r3.matches(out));

  tpCalleeBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r3.uri());
  free_txdata();
}


// Test DefaultHandling=CONTINUE for non-existent AS (where name does not resolve).
TEST_F(SCSCFTest, DefaultHandlingContinueNonExistent)
{
  // Expect calls looking up the iFCs and the bindings for the callee. Return an
  // iFC for a non-existent AS, with its default handling set up session
  // continued.
  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings);
  set_ifc(irs_info, "sip:6505551234@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:ne-as:56789;transport=UDP");
  expect_get_callee_info(irs_info, bindings);

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // AS name fails to resolve, so INVITE passed on to final destination (to bono
  // set up in callee's bindings)
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));
  tpCalleeBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r2.uri());
  free_txdata();
}


// Test DefaultHandling=CONTINUE for non-responsive AS.
TEST_F(SCSCFTest, DefaultHandlingContinueNonResponsive)
{
  // Expect calls looking up the iFCs and the bindings for the callee. Return an
  // iFC with its default handling set to session continued.
  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings);
  set_ifc(irs_info, "sip:6505551234@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  expect_get_callee_info(irs_info, bindings);

  EXPECT_CALL(*_sess_cont_comm_tracker, on_failure(StrEq("sip:1.2.3.4:56789;transport=UDP"), _));

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));

  // ---------- AS1 rejects it with a 408 error.
  string fresp = respond_to_txdata(current_txdata(), 408);
  free_txdata();
  inject_msg(fresp, &tpAS1);

  // ACK goes back to AS1
  SCOPED_TRACE("ACK");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("ACK").matches(out));
  free_txdata();

  // INVITE passed to final destination (to bono set up in callee's bindings)
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));
  tpCalleeBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r2.uri());

  free_txdata();
}


// Test DefaultHandling=CONTINUE for an AS that returns an error immediately.
TEST_F(SCSCFTest, DefaultHandlingContinueImmediateError)
{
  // Expect calls looking up the iFCs and the bindings for the callee. Return an
  // iFC with its default handling set to session continued.
  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings);
  set_ifc(irs_info, "sip:6505551234@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  expect_get_callee_info(irs_info, bindings);

  // This flow counts as an unsuccessful AS communication, as a 100 trying does
  // not cause an AS to be treated as responsive.
  EXPECT_CALL(*_sess_cont_comm_tracker, on_failure(_, HasSubstr("500")));

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._requri = "sip:6505551234@homedomain";
  msg._route = "Route: <sip:sprout.homedomain>";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));

  // ---------- AS1 immediately rejects the request with a 500 response.  This
  // doesn't get returned to the caller, because no 183 has arrived (which would
  // disable the default handling).
  std::string fresp = respond_to_txdata(current_txdata(), 500);
  inject_msg(fresp, &tpAS1);
  free_txdata();

  // ACK goes back to AS1
  ASSERT_EQ(2, txdata_count());
  SCOPED_TRACE("ACK");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("ACK").matches(out));
  free_txdata();

  // INVITE passed to final destination (to bono set up in callee's bindings)
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));
  tpCalleeBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r2.uri());

  // Target sends back 100 Trying
  inject_msg(respond_to_txdata(current_txdata(), 100), &tpBono);
  free_txdata();
}


// Test DefaultHandling=CONTINUE for an AS that returns 100 Trying followed by
// an error.
TEST_F(SCSCFTest, DefaultHandlingContinue100ThenError)
{
  // Expect calls looking up the iFCs and the bindings for the callee. Return an
  // iFC with its default handling set to session continued.
  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings);
  set_ifc(irs_info, "sip:6505551234@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  expect_get_callee_info(irs_info, bindings);

  // This flow counts as an unsuccessful AS communication, as a 100 trying does
  // not cause an AS to be treated as responsive.
  EXPECT_CALL(*_sess_cont_comm_tracker, on_failure(_, _));

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));

  // ---------- AS1 sends a 100 Trying to indicate it is processing the
  // request.  This does NOT disable the default handling.
  //
  // Save off the INVITE TX data so we can build a final response later on.
  string fresp = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp, &tpAS1);

  // ---------- AS1 now rejects the request with a 500 response.  This doesn't
  // get returned to the caller, because no 183 has arrived (which would disable
  // the default handling).
  fresp = respond_to_txdata(current_txdata(), 500);
  inject_msg(fresp, &tpAS1);
  free_txdata();

  // ACK goes back to AS1
  SCOPED_TRACE("ACK");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("ACK").matches(out));
  free_txdata();

  // INVITE passed to final destination (to bono set up in callee's bindings)
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));
  tpCalleeBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r2.uri());

  // Target sends back 100 Trying
  inject_msg(respond_to_txdata(current_txdata(), 100), &tpBono);
  free_txdata();
}


// Test DefaultHandling=CONTINUE for a responsive AS that returns an error.
TEST_F(SCSCFTest, DefaultHandlingContinue1xxThenError)
{
  // Expect calls looking up the iFCs and the bindings for the callee. Return an
  // iFC with its default handling set to session continued.
  // There is no need to set up any bindings, as the AS will reject the call
  // before these are looked up.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551234", "homedomain");
  set_ifc(irs_info, "sip:6505551234@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  expect_get_subscriber_state(irs_info, "sip:6505551234@homedomain");

  // This flow counts as a successful AS communication, as it sent back a 1xx
  // response.
  EXPECT_CALL(*_sess_cont_comm_tracker, on_success(_));

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._requri = "sip:6505551234@homedomain";
  msg._route = "Route: <sip:sprout.homedomain>";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));

  // ---------- AS1 sends a 183 Session Progress to indicate it is processing the
  // request.  This will disable the default handling.
  //
  // Save off the INVITE TX data so we can build a final response later on.
  pjsip_tx_data* invite_tx_data = pop_txdata();
  string fresp = respond_to_txdata(invite_tx_data, 183);
  inject_msg(fresp, &tpAS1);

  // 183 flows back to Bono.
  SCOPED_TRACE("183");
  out = current_txdata()->msg;
  RespMatcher(183).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();

  // ---------- AS1 now rejects the request with a 500 response.  This gets
  // returned to the caller because the 183 indicated the AS is live.
  fresp = respond_to_txdata(invite_tx_data, 500);
  pjsip_tx_data_dec_ref(invite_tx_data); invite_tx_data = NULL;
  inject_msg(fresp, &tpAS1);

  // ACK goes back to AS1
  SCOPED_TRACE("ACK");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("ACK").matches(out));
  free_txdata();

  // 500 response goes back to bono
  SCOPED_TRACE("500");
  out = current_txdata()->msg;
  RespMatcher(500).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // ---------- Send ACK from bono
  SCOPED_TRACE("ACK");
  msg._cseq++;
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpBono);
}


// Test DefaultHandling=CONTINUE for a responsive AS that passes the INVITE
// back to the S-CSCF but then returns an error.
TEST_F(SCSCFTest, DefaultHandlingContinueInviteReturnedThenError)
{
  // Expect calls looking up the iFCs and the bindings for the callee. Return an
  // iFC with its default handling set to session continued.
  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings);
  set_ifc(irs_info, "sip:6505551234@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  expect_get_callee_info(irs_info, bindings, "sip:6505551234@homedomain", 2);

  // This flow is classed as a successful AS flow, as the AS will pass the
  // INVITE back to the S-CSCF which indicates it is responsive.
  EXPECT_CALL(*_sess_cont_comm_tracker, on_success(_));

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._requri = "sip:6505551234@homedomain";
  msg._route = "Route: <sip:sprout.homedomain>";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string resp_100 = respond_to_txdata(current_txdata(), 100);
  inject_msg(resp_100, &tpAS1);

  // We are going to send a 500 response to this request later on in the test
  // case. Build this now, as it means we can mutate the INVITE for sending
  // back to sprout.
  string resp_500 = respond_to_txdata(current_txdata(), 500);

  // ---------- AS1 turns it around (acting as proxy)
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed to final destination (to bono set up in callee's bindings)
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));
  tpCalleeBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r2.uri());
  EXPECT_EQ(BONO_ROUTE_HEADER, get_headers(out, "Route"));

  free_txdata();

  // ---------- AS1 now rejects the request with a 500 response.  The AS is not
  // bypassed as the INVITE it sent back to sprout indicates that it is live.
  inject_msg(resp_500, &tpAS1);

  // ACK goes back to AS1
  SCOPED_TRACE("ACK");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("ACK").matches(out));
  free_txdata();

  // 500 response goes back to bono
  SCOPED_TRACE("500");
  out = current_txdata()->msg;
  RespMatcher(500).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // ---------- Send ACK from bono
  SCOPED_TRACE("ACK");
  msg._cseq++;
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpBono);

  // Check there are no outstanding messages - this confirms sprout did not
  // create a fork to bypass the AS.
  ASSERT_EQ(0, txdata_count());
}


TEST_F(SCSCFTest, DefaultHandlingContinueTimeout)
{
  // Expect calls looking up the iFCs and the bindings for the callee. Return an
  // iFC with its default handling set to session continued.
  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings);
  set_ifc(irs_info, "sip:6505551234@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=tcp");
  expect_get_callee_info(irs_info, bindings);

  EXPECT_CALL(*_sess_cont_comm_tracker, on_failure(_, HasSubstr("timeout")));

  TransportFlow tpCaller(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::TCP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // Caller sends INVITE
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to caller
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  free_txdata();

  // Advance time without receiving a response. The application server is
  // bypassed.
  cwtest_advance_time_ms(3000);

  // INVITE is sent to the callee.
  poll();
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));
  tpBono.expect_target(current_txdata(), true);

  // Callee sends 200 OK.
  inject_msg(respond_to_txdata(current_txdata(), 200, "", ""), &tpBono);
  free_txdata();

  // 200 OK received at caller.
  poll();
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();
}


TEST_F(SCSCFTest, DefaultHandlingContinueDisabled)
{
  // Set the session continue timer to 0 to disable it.
  _scscf_sproutlet->set_session_continued_timeout(0);

  // Expect calls looking up the iFCs and the bindings for the callee. Return an
  // iFC with its default handling set to session continued.
  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings);
  set_ifc(irs_info, "sip:6505551234@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=tcp");
  expect_get_callee_info(irs_info, bindings);

  EXPECT_CALL(*_sess_cont_comm_tracker, on_failure(_, _));

  TransportFlow tpCaller(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::TCP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // Caller sends INVITE
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to caller
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  free_txdata();

  // Advance time without receiving a response. The liveness time is not
  // running which means the AS is not immediately bypassed.
  cwtest_advance_time_ms(3000);
  poll();
  ASSERT_EQ(0, txdata_count());

  // After another 29s the AS transaction times out and the INVITE is sent to
  // the callee.
  cwtest_advance_time_ms(29000);
  poll();

  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));
  tpBono.expect_target(current_txdata(), true);

  // Callee sends 200 OK.
  inject_msg(respond_to_txdata(current_txdata(), 200, "", ""), &tpBono);
  free_txdata();

  // 200 OK received at caller.
  poll();
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();
}


// Test DefaultHandling attribute missing.
TEST_F(SCSCFTest, DefaultHandlingMissing)
{
  // Set up caller info, which includes an iFC which is malformed (it's missing
  // the default handling field).
  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings);
  set_ifc(irs_info, "sip:6505551234@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:ne-as:56789;transport=UDP", 0, "");
  expect_get_callee_info(irs_info, bindings);

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // AS name fails to resolve, so INVITE passed on to final destination (to bono
  // set up in callee's bindings)
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));
  tpCalleeBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r2.uri());
  free_txdata();
}


// Test DefaultHandling attribute malformed.
TEST_F(SCSCFTest, DefaultHandlingMalformed)
{
  // Set up callee info, which includes an iFC with a malformed default handling
  // field (it's not an integer).
  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings);
  set_ifc(irs_info, "sip:6505551234@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:ne-as:56789;transport=UDP", 0, "frog");
  expect_get_callee_info(irs_info, bindings);

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // AS name fails to resolve, so INVITE passed on to final destination (to bono
  // set up in callee's bindings)
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));
  tpCalleeBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r2.uri());
  free_txdata();
}


// Test DefaultHandling=CONTINUE for non-existent AS (where name does not resolve).
//
// This test configures an AS for the originating subscriber, and checks that
// the S-CSCF still record-routes itself correctly when the AS fails and is
// bypassed.
TEST_F(SCSCFTest, DefaultHandlingContinueNonExistentRRTest)
{
  // Set up caller info, which includes an iFC for a non-existent AS.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  set_ifc(irs_info_1, "sip:6505551000@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:ne-as:56789;transport=UDP");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Set up callee info.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  expect_get_callee_info(irs_info_2, bindings);

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._requri = "sip:6505551234@homedomain";
  msg._route = "Route: <sip:sprout.homedomain;orig>";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // AS name fails to resolve, so INVITE passed on to final destination (to bono
  // set up in callee's bindings)
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));
  tpCalleeBono.expect_target(current_txdata(), false);

  // The S-CSCF should record-route itself for both originating and terminating
  // billing.
  EXPECT_THAT(get_headers(out, "Record-Route"),
              MatchesRegex("Record-Route:.*billing-role=charge-term.*"
                           "Record-Route:.*billing-role=charge-orig.*"));
  free_txdata();
}


// Test DefaultHandling=CONTINUE for an unresponsive AS.
//
// This test configures an AS for the originating subscriber, and checks that
// the S-CSCF still record-routes itself correctly when the AS times out and is
// bypassed.
TEST_F(SCSCFTest, DefaultHandlingContinueTimeoutRRTest)
{
  // Set up caller info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  set_ifc(irs_info_1, "sip:6505551000@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=tcp");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Set up callee info.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  expect_get_callee_info(irs_info_2, bindings);

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  EXPECT_CALL(*_sess_cont_comm_tracker, on_failure(_, HasSubstr("timeout")));

  TransportFlow tpCaller(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::TCP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // Caller sends INVITE
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to caller
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  free_txdata();

  // Advance time without receiving a response. The application server is
  // bypassed.
  cwtest_advance_time_ms(3000);

  // INVITE is sent to the callee.
  poll();
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));
  tpBono.expect_target(current_txdata(), true);

  EXPECT_THAT(get_headers(out, "Record-Route"),
              MatchesRegex("Record-Route:.*billing-role=charge-term.*"
                           "Record-Route:.*billing-role=charge-orig.*"));

  // Callee sends 200 OK.
  inject_msg(respond_to_txdata(current_txdata(), 200, "", ""), &tpBono);
  free_txdata();

  // 200 OK received at callee.
  poll();
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();
}


// Test DefaultHandling=CONTINUE for non-existent AS.
//
// This test configures two ASs for the originating subscriber, and checks that
// the S-CSCF still record-routes itself correctly when the first AS fails, is
// bypassed, and the request is routed to the second AS.
TEST_F(SCSCFTest, DefaultHandlingContinueFirstAsFailsRRTest)
{
  // Set up caller info, which includes an iFC for a non-existent AS, and also a
  // real AS.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  ServiceProfileBuilder service_profile = ServiceProfileBuilder()
    .addIfc(1, {"<Method>INVITE</Method>"}, "sip:ne-as:56789;transport=tcp")
    .addIfc(2, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  set_ifcs_from_service_profile(irs_info_1, service_profile, "sip:6505551000@homedomain");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  EXPECT_CALL(*_sess_cont_comm_tracker, on_failure(_, HasSubstr("No valid address")));

  TransportFlow tpCaller(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::TCP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // Caller sends INVITE
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to caller
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // The first AS fails to resolve so the INVITE is passed on to AS2
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  free_txdata();

  // The S-CSCF should have record-routed itself at the start of originating
  // processing, and this should be reflected in the request sent to the second
  // AS.
  EXPECT_THAT(get_headers(out, "Record-Route"),
              MatchesRegex("Record-Route:.*billing-role=charge-orig.*"));
  free_txdata();
}


// Test DefaultHandling=CONTINUE for non-existent AS.
//
// This test configures two ASs for the terminating subscriber, and checks that
// the S-CSCF still record-routes itself correctly when the first AS fails, is
// bypassed, and the request is routed to the second AS.
//
// This test configured record routing at the start of terminating processing,
// so we can check the terminating Record-Route is preserved when bypassing the
// AS.
TEST_F(SCSCFTest, DefaultHandlingContinueFirstTermAsFailsRRTest)
{
  // Setup info for the caller.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Setup info for the callee, which includes two iFCs, one for an non-existent
  // AS and one for a real AS. The default handling of the highest priority iFC
  // is set to continue to allow testing to continue once the first AS fails,
  // however the default handling of the other iFC is set to terminate to
  // prevent cleanup issues at the end of the test.
  HSSConnection::irs_info irs_info_2;
  setup_irs_info(irs_info_2, "6505551234", "homedomain");
  ServiceProfileBuilder service_profile = ServiceProfileBuilder()
    .addIfc(1, {"<Method>INVITE</Method>"}, "sip:ne-as:56789;transport=tcp")
    .addIfc(2, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP", 0, "1");
  set_ifcs_from_service_profile(irs_info_2, service_profile, "sip:6505551234@homedomain");
  expect_get_subscriber_state(irs_info_2, "sip:6505551234@homedomain");

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  EXPECT_CALL(*_sess_cont_comm_tracker, on_failure(_, HasSubstr("No valid address")));

  TransportFlow tpCaller(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::TCP, stack_data.scscf_port, "1.2.3.4", 56789);

  bool old_rr_on_comp_of_orig = stack_data.record_route_on_completion_of_originating;
  bool old_rr_on_init_of_term = stack_data.record_route_on_initiation_of_terminating;
  stack_data.record_route_on_initiation_of_terminating = true;
  stack_data.record_route_on_completion_of_originating = true;

  // Caller sends INVITE
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to caller
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // The first AS fails to resolve so the INVITE is passed on to AS2
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  free_txdata();

  // The S-CSCF should have record-routed itself at the start of originating
  // processing, end of originating, and start of terminating. However:
  // -  We don't bill at the start of terminating processing, so the top route
  //    header should indicate no billing.
  // -  There was only one signaling hop on the originating side, so there
  //    should only be one RR header from originating processing, which should
  //    indicate originating billing).
  EXPECT_THAT(get_headers(out, "Record-Route"),
              MatchesRegex("Record-Route:.*billing-role=charge-none.*"
                           "Record-Route:.*billing-role=charge-orig.*"));
  free_txdata();

  stack_data.record_route_on_initiation_of_terminating = old_rr_on_init_of_term;
  stack_data.record_route_on_completion_of_originating = old_rr_on_comp_of_orig;
}


// Test that if AS1 times out, then AS2 rejects an INVITE, the rejection is
// immediately sent on, without waiting for all retries to AS1 to take place.
// Then, if AS1 finally responds, check the response is handled.
TEST_F(SCSCFTest, DefaultHandlingContinueErrorSentImmediately)
{
  // Set up callee info, to include two iFCs with their default handling set to
  // session continue. There is no need to set up any bindings, as AS2 will
  // reject the call before these are looked up.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551234", "homedomain");
  ServiceProfileBuilder service_profile = ServiceProfileBuilder()
    .addIfc(1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=TCP")
    .addIfc(2, {"<Method>INVITE</Method>"}, "sip:4.2.3.4:56788;transport=TCP");
  set_ifcs_from_service_profile(irs_info, service_profile, "sip:6505551234@homedomain");
  expect_get_subscriber_state(irs_info, "sip:6505551234@homedomain");

  EXPECT_CALL(*_sess_cont_comm_tracker, on_failure(_, HasSubstr("timeout")));

  TransportFlow tpCaller(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::TCP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpAS2(TransportFlow::Protocol::TCP, stack_data.scscf_port, "4.2.3.4", 56788);

  // Caller sends INVITE.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to caller
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // The INVITE is sent onto AS1 (which will reply very slowly).
  //
  // Save off the invite, as it will be needed later.
  out = current_txdata()->msg;
  ReqMatcher("INVITE").matches(out);
  tpAS1.expect_target(current_txdata(), false);
  pjsip_tx_data* invite_1_tx_data = pop_txdata();

  // Advance time by just over 3s (which is the testbed default time to wait for
  // a response from a session continued AS).
  ASSERT_EQ(0, txdata_count());
  cwtest_advance_time_ms(3001);
  poll();

  // Expect the INVITE to have now been passed on to AS2.
  //
  // Save off the invite, as it will be needed later.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  ReqMatcher("INVITE").matches(out);
  tpAS2.expect_target(current_txdata(), false);
  pjsip_tx_data* invite_2_tx_data = pop_txdata();

  // Send in a 183 Session Progress response from AS2 to indicate it is
  // processing the request. This will disable the default handling.
  inject_msg(respond_to_txdata(invite_2_tx_data, 183), &tpAS2);
  poll();

  // Expect the 183 to be returned to the caller without delay.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(183).matches(out);
  tpCaller.expect_target(current_txdata(), true);
  free_txdata();

  // AS2 now rejects the request with a 500 response. This will be returned to
  // the caller, as the 183 indicated that AS2 was alive.
  inject_msg(respond_to_txdata(invite_2_tx_data, 500), &tpAS2);
  ASSERT_EQ(2, txdata_count());

  // Expect an ACK to be sent to AS2.
  out = current_txdata()->msg;
  ReqMatcher("ACK").matches(out);
  tpAS2.expect_target(current_txdata(), false);
  free_txdata();

  // Expect the 500 to be passed back to the caller without delay.
  out = current_txdata()->msg;
  RespMatcher(500).matches(out);
  tpCaller.expect_target(current_txdata(), true);
  free_txdata();

  // Caller ACKs error response.
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpCaller);
  poll();

  ASSERT_EQ(0, txdata_count());

  // Now AS1 finally responds with a 100 Trying.
  inject_msg(respond_to_txdata(invite_1_tx_data, 100), &tpAS1);

  cwtest_advance_time_ms(100);
  poll();

  // Respond to AS1 with a CANCEL, as an error has already been sent upstream to
  // the caller.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  ReqMatcher("CANCEL").matches(out);
  tpAS1.expect_target(current_txdata(), false);
  free_txdata();

  ASSERT_EQ(0, txdata_count());
  pjsip_tx_data_dec_ref(invite_1_tx_data); invite_1_tx_data = NULL;
  pjsip_tx_data_dec_ref(invite_2_tx_data); invite_2_tx_data = NULL;
}


// Test that if AS1 times out, then AS2 rejects an INVITE, and the rejection is
// sent upstream, if AS1 then replies with an error, the error is handled.
TEST_F(SCSCFTest, DefaultHandlingContinueErrorTimeoutThenResp)
{
  // Set up callee info, including two iFCs with default handling set to
  // continue. There is no need to set up bindings, as AS2 will reject the call
  // before these are looked up.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551234", "homedomain");
  ServiceProfileBuilder service_profile = ServiceProfileBuilder()
    .addIfc(1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=TCP")
    .addIfc(2, {"<Method>INVITE</Method>"}, "sip:4.2.3.4:56789;transport=TCP");
  set_ifcs_from_service_profile(irs_info, service_profile, "sip:6505551234@homedomain");
  expect_get_subscriber_state(irs_info, "sip:6505551234@homedomain");

  EXPECT_CALL(*_sess_cont_comm_tracker, on_failure(_, HasSubstr("timeout")));

  TransportFlow tpCaller(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::TCP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpAS2(TransportFlow::Protocol::TCP, stack_data.scscf_port, "4.2.3.4", 56789);

  // Caller sends INVITE.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to caller.
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // The INVITE is sent onto AS1 (which will reply very slowly).
  //
  // Save off the invite, as it will be needed later.
  out = current_txdata()->msg;
  ReqMatcher("INVITE").matches(out);
  tpAS1.expect_target(current_txdata(), false);
  pjsip_tx_data* invite_1_tx_data = pop_txdata();

  // Advance time by just over 3s (which is the testbed default time to wait for
  // a response from a session continued AS).
  ASSERT_EQ(0, txdata_count());
  cwtest_advance_time_ms(3001);
  poll();

  // Expect the INVITE to have now been passed on to AS2.
  //
  // Save off the invite, as it will be needed later.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  ReqMatcher("INVITE").matches(out);
  tpAS2.expect_target(current_txdata(), false);
  pjsip_tx_data* invite_2_tx_data = pop_txdata();

  // Send in a 183 Session Progress response from AS2 to indicate it is
  // processing the request. This will disable the default handling.
  inject_msg(respond_to_txdata(invite_2_tx_data, 183), &tpAS2);
  poll();

  // Expect the 183 to be returned to the caller without delay.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(183).matches(out);
  tpCaller.expect_target(current_txdata(), true);
  free_txdata();

  // AS2 now rejects the request with a 500 response. This will be returned to
  // the caller, as the 183 indicated that AS2 was alive.
  inject_msg(respond_to_txdata(invite_2_tx_data, 500), &tpAS2);
  ASSERT_EQ(2, txdata_count());

  // Expect an ACK to be sent to AS2.
  out = current_txdata()->msg;
  ReqMatcher("ACK").matches(out);
  tpAS2.expect_target(current_txdata(), false);
  free_txdata();

  // Expect the 500 to be passed back to the caller without delay.
  out = current_txdata()->msg;
  RespMatcher(500).matches(out);
  tpCaller.expect_target(current_txdata(), true);
  free_txdata();

  // Caller ACKs error response.
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpCaller);
  poll();

  ASSERT_EQ(0, txdata_count());

  // Now AS1 finally responds with a 403 (an error code chosen at random).
  inject_msg(respond_to_txdata(invite_1_tx_data, 483), &tpAS1);

  // Respond to AS1 with an ACK. Also check the error is not sent upstream, as
  // an error has already been sent.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  ReqMatcher("ACK").matches(out);
  tpAS1.expect_target(current_txdata(), false);
  free_txdata();

  ASSERT_EQ(0, txdata_count());
  pjsip_tx_data_dec_ref(invite_1_tx_data); invite_1_tx_data = NULL;
  pjsip_tx_data_dec_ref(invite_2_tx_data); invite_2_tx_data = NULL;
}


// Test that if AS1 times out, then AS2 rejects an MESSAGE, and the rejection is
// sent upstream, if AS1 then replies with an error, the error is handled.
TEST_F(SCSCFTest, DefaultHandlingContinueMessageErrorTimeoutThenResp)
{
  // Set up callee info, including two iFCs with their default handling set to
  // session continue. There is no need to set up bindings, as AS2 rejects the
  // message before the target is looked up.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551234", "homedomain");
  ServiceProfileBuilder service_profile = ServiceProfileBuilder()
    .addIfc(1, {"<Method>MESSAGE</Method>"}, "sip:1.2.3.4:56789;transport=TCP")
    .addIfc(2, {"<Method>MESSAGE</Method>"}, "sip:4.2.3.4:56789;transport=TCP");
  set_ifcs_from_service_profile(irs_info, service_profile, "sip:6505551234@homedomain");
  expect_get_subscriber_state(irs_info, "sip:6505551234@homedomain");

  EXPECT_CALL(*_sess_cont_comm_tracker, on_failure(_, HasSubstr("timeout")));

  TransportFlow tpUE1(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::TCP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpAS2(TransportFlow::Protocol::TCP, stack_data.scscf_port, "4.2.3.4", 56789);

  // MESSAGE sent from UE1.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "MESSAGE";
  inject_msg(msg.get_request(), &tpUE1);
  poll();
  ASSERT_EQ(1, txdata_count());

  // The MESSAGE is sent onto AS1 (which will reply very slowly).
  //
  // Save off the MESSAGE, as it will be needed later.
  pjsip_msg* out = current_txdata()->msg;
  ReqMatcher("MESSAGE").matches(out);
  tpAS1.expect_target(current_txdata(), false);
  pjsip_tx_data* message_1_tx_data = pop_txdata();

  // Advance time by just over 3s (which is the testbed default time to wait for
  // a response from a session continued AS).
  ASSERT_EQ(0, txdata_count());
  cwtest_advance_time_ms(3001);
  poll();

  // Expect the MESSAGE to have now been passed on to AS2.
  //
  // Save off the MESSAGE, as it will be needed later.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  ReqMatcher("MESSAGE").matches(out);
  tpAS2.expect_target(current_txdata(), false);
  pjsip_tx_data* message_2_tx_data = pop_txdata();

  // Send in a 183 Session Progress response from AS2 to indicate it is
  // processing the request. This will disable the default handling.
  inject_msg(respond_to_txdata(message_2_tx_data, 183), &tpAS2);
  poll();

  // Expect the 183 to be returned to UE1 without delay.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(183).matches(out);
  tpUE1.expect_target(current_txdata(), true);
  free_txdata();

  // AS2 now rejects the request with a 500 response. This will be returned to
  // UE1, as the 183 indicated that AS2 was alive.
  inject_msg(respond_to_txdata(message_2_tx_data, 500), &tpAS2);
  ASSERT_EQ(1, txdata_count());

  // Expect the 500 to be passed back to UE1 without delay.
  out = current_txdata()->msg;
  RespMatcher(500).matches(out);
  tpUE1.expect_target(current_txdata(), true);
  free_txdata();

  ASSERT_EQ(0, txdata_count());

  // Now AS1 finally responds with a 403 (an error code chosen at random).
  inject_msg(respond_to_txdata(message_1_tx_data, 483), &tpAS1);

  // Check the error is not sent upstream, as an error has already been sent.
  ASSERT_EQ(0, txdata_count());
  pjsip_tx_data_dec_ref(message_1_tx_data); message_1_tx_data = NULL;
  pjsip_tx_data_dec_ref(message_2_tx_data); message_2_tx_data = NULL;
}


// Test that when Sprout is configured to Record-Route itself only at
// the start and end of all processing, it does.
TEST_F(SCSCFTest, RecordRoutingTest)
{
  // Expect 2 Record-Routes:
  // - on start of originating handling
  // - AS1's Record-Route
  // - AS2's Record-Route
  // - AS3's Record-Route
  // - AS4's Record-Route
  // - on end of terminating handling

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");
  doFourAppServerFlow("Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-term>\r\n"
                      "Record-Route: <sip:6.2.3.4>\r\n"
                      "Record-Route: <sip:5.2.3.4>\r\n"
                      "Record-Route: <sip:4.2.3.4>\r\n"
                      "Record-Route: <sip:1.2.3.4>\r\n"
                      "Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-orig>", true);
  free_txdata();
}


// Test that when Sprout is configured to Record-Route itself at
// the start and end of terminating and originating processing, it does.
TEST_F(SCSCFTest, RecordRoutingTestStartAndEnd)
{
  stack_data.record_route_on_completion_of_originating = true;
  stack_data.record_route_on_initiation_of_terminating = true;

  // Expect 2 Record-Routes:
  // - on start of originating handling
  // - AS1's Record-Route
  // - AS2's Record-Route
  // - on end of originating handling/on start of terminating handling
  // (collapsed together as they're identical)
  // - AS3's Record-Route
  // - AS4's Record-Route
  // - on end of terminating handling

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  doFourAppServerFlow("Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-term>\r\n"
                      "Record-Route: <sip:6.2.3.4>\r\n"
                      "Record-Route: <sip:5.2.3.4>\r\n"
                      "Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-none>\r\n"
                      "Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-none>\r\n"
                      "Record-Route: <sip:4.2.3.4>\r\n"
                      "Record-Route: <sip:1.2.3.4>\r\n"
                      "Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-orig>", true);
  stack_data.record_route_on_completion_of_originating = false;
  stack_data.record_route_on_initiation_of_terminating = false;
}


// Test that when Sprout is configured to Record-Route itself on each
// hop, it does.
TEST_F(SCSCFTest, RecordRoutingTestEachHop)
{
  // Simulate record-routing model 3, which sets all the record-routing flags.
  stack_data.record_route_on_initiation_of_terminating = true;
  stack_data.record_route_on_completion_of_originating = true;
  stack_data.record_route_on_diversion = true;
  stack_data.record_route_on_every_hop = true;

  // Expect 9 Record-Routes:
  // - between the endpoint and AS1
  // - AS1's Record-Route
  // - between AS1 and AS2
  // - AS2's Record-Route
  // - between AS2 and AS3
  // - AS3's Record-Route
  // - between AS3 and AS4
  // - AS4's Record-Route
  // - between AS4 and the endpoint

  // In reality we'd expect 10 (instead of having one between AS2 and
  // AS3, we'd have two - one for conclusion of originating processing
  // and one for initiation of terminating processing) but we don't
  // split originating and terminating handling like that yet.
  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");
  doFourAppServerFlow("Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-term>\r\n"
                      "Record-Route: <sip:6.2.3.4>\r\n"
                      "Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-none>\r\n"
                      "Record-Route: <sip:5.2.3.4>\r\n"
                      "Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-none>\r\n"
                      "Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-none>\r\n"
                      "Record-Route: <sip:4.2.3.4>\r\n"
                      "Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-none>\r\n"
                      "Record-Route: <sip:1.2.3.4>\r\n"
                      "Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-orig>", true);

  stack_data.record_route_on_initiation_of_terminating = false;
  stack_data.record_route_on_completion_of_originating = false;
  stack_data.record_route_on_diversion = false;
  stack_data.record_route_on_every_hop = false;
}


// Test that Sprout only adds a single Record-Route if none of the Ases
// Record-Route themselves.
TEST_F(SCSCFTest, RecordRoutingTestCollapse)
{
  // Expect 1 Record-Route
  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");
  doFourAppServerFlow("Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-term>\r\n"
                      "Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-orig>", false);
}


// Test that even when Sprout is configured to Record-Route itself on each
// hop, it only adds a single Record-Route if none of the Ases
// Record-Route themselves.
TEST_F(SCSCFTest, RecordRoutingTestCollapseEveryHop)
{
  stack_data.record_route_on_every_hop = true;
  // Expect 1 Record-Route
  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");
  doFourAppServerFlow("Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-term>\r\n"
                      "Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-none>\r\n"
                      "Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-none>\r\n"
                      "Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-none>\r\n"
                      "Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-orig>", false);
  stack_data.record_route_on_every_hop = false;
}

// Test AS-originated flow.
void SCSCFTestBase::doAsOriginated(SCSCFMessage& msg, bool expect_orig)
{
  doAsOriginated(msg.get_request(), expect_orig);
}

void SCSCFTestBase::doAsOriginated(const std::string& msg, bool expect_orig)
{
  // Set up caller info.
  HSSConnection::irs_info irs_info_1;
  if (expect_orig)
  {
    setup_irs_info(irs_info_1, "6505551000", "homedomain");
    set_ifc(irs_info_1, "sip:6505551000@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
    expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");
  }

  // Set up callee info.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  set_ifc(irs_info_2, "sip:6505551234@homedomain", 0, {"<Method>INVITE</Method>"}, "sip:5.2.3.4:56787;transport=UDP");
  expect_get_callee_info(irs_info_2, bindings, "sip:6505551234@homedomain", 2);

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS0(TransportFlow::Protocol::UDP, stack_data.scscf_port, "6.2.3.4", 56786);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpAS2(TransportFlow::Protocol::UDP, stack_data.scscf_port, "5.2.3.4", 56787);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send spontaneous INVITE from AS0.
  inject_msg(msg, &tpAS0);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to AS0
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS0.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();

  ReqMatcher r1("INVITE");
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = NULL;

  if (expect_orig)
  {
    // INVITE passed on to AS1
    SCOPED_TRACE("INVITE (S)");
    out = current_txdata()->msg;
    ASSERT_NO_FATAL_FAILURE(r1.matches(out));

    tpAS1.expect_target(current_txdata(), false);
    EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
    EXPECT_THAT(get_headers(out, "Route"),
                testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig;service=scscf>"));

    // ---------- AS1 sends a 100 Trying to indicate it has received the request.
    string fresp1 = respond_to_txdata(current_txdata(), 100);
    inject_msg(fresp1, &tpAS1);

    // ---------- AS1 turns it around (acting as proxy)
    hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
    if (hdr)
    {
      pj_list_erase(hdr);
    }
    inject_msg(out, &tpAS1);
    free_txdata();

    // 100 Trying goes back to AS1
    out = current_txdata()->msg;
    RespMatcher(100).matches(out);
    tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
    free_txdata();
  }

  // INVITE passed on to AS2
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS2.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp2 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp2, &tpAS1);

  // ---------- AS2 turns it around (acting as proxy)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS2);
  free_txdata();

  // 100 Trying goes back to AS2
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS2.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();

  // INVITE passed on to final destination (to bono set up in callee's bindings)
  SCOPED_TRACE("INVITE (Z)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  tpCalleeBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r1.uri());
  EXPECT_EQ(BONO_ROUTE_HEADER, get_headers(out, "Route"));

  // Inject succesful responses to finish up the flow
  inject_msg(respond_to_current_txdata(200));
  inject_msg(respond_to_current_txdata(200));
  inject_msg(respond_to_current_txdata(200));
}


// Test AS-originated flow - orig.
TEST_F(SCSCFTest, AsOriginatedOrig)
{
  // ---------- Send spontaneous INVITE from AS0, marked as originating-handling-required.
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

//  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";

  SCOPED_TRACE("orig");
  doAsOriginated(msg, true);

  // This is an originating call so we track a session setup time regardless of
  // the fact that it is initiated by an app server.
  EXPECT_EQ(1, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_audio_session_setup_time_tbl)->_count);
  EXPECT_EQ(0, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_video_session_setup_time_tbl)->_count);
}


// Test AS-originated flow - term.
TEST_F(SCSCFTest, AsOriginatedTerm)
{
  // ---------- Send spontaneous INVITE from AS0, marked as terminating-handling-only.
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;

//  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._requri = "sip:6505551234@homedomain";
  msg._route = "Route: <sip:sprout.homedomain>";

  msg._method = "INVITE";

  SCOPED_TRACE("term");
  doAsOriginated(msg, false);
}


// Test call-diversion AS flow.
TEST_F(SCSCFTest, Cdiv)
{
  // Call originally sent to "sip:6505551234@homedomain". Set up its info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551234", "homedomain");
  ServiceProfileBuilder service_profile = ServiceProfileBuilder()
    .addIfc(2, {"<SessionCase>4</SessionCase><!-- originating-cdiv -->", "<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP")
    .addIfc(0, {"<Method>INVITE</Method>", "<SessionCase>1</SessionCase><!-- terminating-registered -->"}, "sip:5.2.3.4:56787;transport=UDP");
  set_ifcs_from_service_profile(irs_info_1, service_profile, "sip:6505551234@homedomain");
  expect_get_subscriber_state(irs_info_1, "sip:6505551234@homedomain", 2);

  // The call is diverted to "sip:6505555678@homedomain". Set up its info.
  HSSConnection::irs_info irs_info_2;
  setup_irs_info(irs_info_2, "6505555678", "homedomain");
  Bindings bindings;
  setup_binding(bindings, "sip:6505555678@homedomain", "sip:andunnuvvawun@10.114.61.214:5061;transport=tcp;ob");
  expect_get_subscriber_state(irs_info_2, "sip:6505555678@homedomain");
  expect_get_bindings(bindings, "sip:6505555678@homedomain");

  _hss_connection->set_result("/impu/sip%3A6505555678%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "5.2.3.4", 56787);
  TransportFlow tpAS2(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpDivertedToCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain>";
  msg._requri = "sip:6505551234@homedomain";
  msg._extra = "P-Charging-Vector: icid-value=3";
  stack_data.record_route_on_diversion = true;

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1 (as terminating AS for Bob)
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551234@homedomain>;sescase=term;regstate=reg"));

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp1 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp1, &tpAS1);

  // ---------- AS1 turns it around (acting as routing B2BUA by changing the target)
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  ((pjsip_sip_uri*)out->line.req.uri)->user = pj_str("6505555678");
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS2 (as originating AS for Bob)
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS2.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505555678@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig;service=scscf>"));

  // As the session case is "Originating_CDIV" we want to include the
  // "orig-div" header field parameter with just a name and no value
  // as specified in 3GPP TS 24.229.
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551234@homedomain>;orig-cdiv"));

  // ---------- AS2 sends a 100 Trying to indicate it has received the request.
  string fresp2 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp2, &tpAS2);

  // ---------- AS2 turns it around (acting as proxy)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS2);
  free_txdata();

  // 100 Trying goes back to AS2
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS2.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to final destination (to bono set up in the diverted to
  // callee's bindings)
  SCOPED_TRACE("INVITE (4)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpDivertedToCalleeBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:andunnuvvawun@10.114.61.214:5061;transport=tcp;ob", r1.uri());
  EXPECT_EQ(BONO_ROUTE_HEADER, get_headers(out, "Route"));

  free_txdata();
  EXPECT_EQ(0, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_audio_session_setup_time_tbl)->_count);
  EXPECT_EQ(0, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_video_session_setup_time_tbl)->_count);
}


// Test call-diversion AS flow where the AS diverts to a different domain.
TEST_F(SCSCFTest, CdivToDifferentDomain)
{
  // Setup info about the callee.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551234", "homedomain");
  ServiceProfileBuilder service_profile = ServiceProfileBuilder()
    .addIfc(2, {"<SessionCase>4</SessionCase><!-- originating-cdiv -->", "<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP")
    .addIfc(0, {"<Method>INVITE</Method>", "<SessionCase>1</SessionCase><!-- terminating-registered -->"}, "sip:5.2.3.4:56787");
  set_ifcs_from_service_profile(irs_info, service_profile, "sip:6505551234@homedomain");
  expect_get_subscriber_state(irs_info, "sip:6505551234@homedomain", 2);

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "5.2.3.4", 56787);
  TransportFlow tpAS2(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1 (as terminating AS for Bob)
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp1 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp1, &tpAS1);

  // ---------- AS1 turns it around (acting as routing B2BUA by changing the target)
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }

  // Re-target the request to a new user. Use the domain "newdomain" as this
  // will be routed off net by the BGCF.
  ((pjsip_sip_uri*)out->line.req.uri)->user = pj_str("newuser");
  ((pjsip_sip_uri*)out->line.req.uri)->host = pj_str("domainvalid");
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS2 (as originating AS for Bob)
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS2.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:newuser@domainvalid", r1.uri());

  // ---------- AS2 sends a 100 Trying to indicate it has received the request.
  string fresp2 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp2, &tpAS2);

  // ---------- AS2 turns it around (acting as proxy)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS2);
  free_txdata();

  // 100 Trying goes back to AS2
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS2.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to final destination
  SCOPED_TRACE("INVITE (4)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:newuser@domainvalid", r1.uri());
  // This route header is determined from the BGCF config.
  EXPECT_EQ("Route: <sip:10.0.0.1:5060;transport=TCP;lr>", get_headers(out, "Route"));
  free_txdata();
}


// Test that ENUM lookups and appropriate URI translation is done before any
// terminating services are applied.
TEST_F(SCSCFTest, BothEndsWithEnumRewrite)
{
  // Set up caller info. Enum lookups should only be done when we do originating
  // and terminating procession, so the caller info must be set to be returned
  // during originating processing.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Set up callee info.
  HSSConnection::irs_info irs_info_2;
  setup_irs_info(irs_info_2, "6505551234", "homedomain");
  // Set default handling to terminate to prevent clean up issues at end of
  // test.
  set_ifc(irs_info_2, "sip:6505551234@homedomain", 0, {"<Method>INVITE</Method>", "<SessionCase>1</SessionCase><!-- terminating-registered -->"}, "sip:5.2.3.4:56787;transport=UDP", 0, "1");
  expect_get_subscriber_state(irs_info_2, "sip:6505551234@homedomain");

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "5.2.3.4", 56787);

  URIClassifier::enforce_global = false;
  URIClassifier::enforce_user_phone = false;

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "1115551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:1115551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1 (as terminating AS for Bob)
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp1 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp1, &tpAS1);

  // These fields of the message will only be filled in correctly if we have
  // done an ENUM lookup before applying terminating services, and correctly
  // recognised that "1115551234" is "6505551234".

  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551234@homedomain>;sescase=term;regstate=reg"));
  free_txdata();
}


// Test that ENUM lookups are not done if we are only doing terminating
// processing.
TEST_F(SCSCFTest, TerminatingWithNoEnumRewrite)
{
  // Set up callee info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "1115551234", "homedomain");
  // Set default handling to terminate to prevent clean up issues at end of
  // test.
  set_ifc(irs_info, "sip:1115551234@homedomain", 0, {"<Method>INVITE</Method>", "<SessionCase>1</SessionCase><!-- terminating-registered -->"}, "sip:5.2.3.4:56787;transport=UDP", 0, "1");
  expect_get_subscriber_state(irs_info, "sip:1115551234@homedomain");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "5.2.3.4", 56787);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "1115551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain>";
  msg._requri = "sip:1115551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1 (as terminating AS for Bob)
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp1 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp1, &tpAS1);

  // These fields of the message will only be filled in correctly if we have
  // not done an ENUM lookup before applying terminating services (as
  // ENUM is only applied when originating)

  EXPECT_EQ("sip:1115551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:1115551234@homedomain>;sescase=term;regstate=reg"));
  free_txdata();
}


// Test call-diversion AS flow, where MMTEL does the diversion.
TEST_F(SCSCFTest, MmtelCdiv)
{
  // Setup info about original callee, which includes one originating and one
  // terminating iFC.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551234", "homedomain");
  ServiceProfileBuilder service_profile = ServiceProfileBuilder()
    .addIfc(2, {"<SessionCase>4</SessionCase><!-- originating-cdiv -->", "<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP")
    .addIfc(0, {"<Method>INVITE</Method>", "<SessionCase>1</SessionCase><!-- terminating-registered -->"}, "sip:mmtel.homedomain");
  set_ifcs_from_service_profile(irs_info_1, service_profile, "sip:6505551234@homedomain");
  // Lookup iFCs on orig and term (but they are cached so only need one lookup
  // here), and lookup if retarget. So overall expect two lookups.
  expect_get_subscriber_state(irs_info_1, "sip:6505551234@homedomain", 2);

  // Setup info about forwarded callee.
  HSSConnection::irs_info irs_info_2;
  setup_irs_info(irs_info_2, "6505555678", "homedomain");
  Bindings bindings;
  setup_binding(bindings, "sip:6505555678@homedomain", "sip:andunnuvvawun@10.114.61.214:5061;transport=tcp;ob");
  expect_get_subscriber_state(irs_info_2, "sip:6505555678@homedomain");
  expect_get_bindings(bindings, "sip:6505555678@homedomain");

  _xdm_connection->put("sip:6505551234@homedomain",
                       R"(<?xml version="1.0" encoding="UTF-8"?>
                          <simservs xmlns="http://uri.etsi.org/ngn/params/xml/simservs/xcap" xmlns:cp="urn:ietf:params:xml:ns:common-policy">
                            <originating-identity-presentation active="false" />
                            <originating-identity-presentation-restriction active="false">
                              <default-behaviour>presentation-restricted</default-behaviour>
                            </originating-identity-presentation-restriction>
                            <communication-diversion active="true">
                              <NoReplyTimer>19</NoReplyTimer>"
                                <cp:ruleset>
                                  <cp:rule id="rule1">
                                    <cp:conditions/>
                                    <cp:actions><forward-to><target>sip:6505555678@homedomain</target></forward-to></cp:actions>
                                  </cp:rule>
                                </cp:ruleset>
                              </communication-diversion>
                            <incoming-communication-barring active="false"/>
                            <outgoing-communication-barring active="false"/>
                          </simservs>)");  // "

  _hss_connection->set_result("/impu/sip%3A6505555678%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS2(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpDivertedToCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(3, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE goes to MMTEL as terminating AS for Bob, and is redirected to 6505555678.
  // A real MMTEL AS is used, so there are some internal messages which are not
  // caught:
  // - the INVITE to the MMTEL from the SCSCF
  // - the 181 from the MMTEL to the SCSCF
  // - the INVITE from the MMTEL to the SCSCF

  // 181 Call is being forwarded goes back to bono
  out = current_txdata()->msg;
  RespMatcher(181).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS2 (as originating AS for Bob)
  SCOPED_TRACE("INVITE (2)");
  ReqMatcher r1("INVITE");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS2.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505555678@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig;service=scscf>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551234@homedomain>;orig-cdiv"));
  EXPECT_THAT(get_headers(out, "History-Info"),
              testing::MatchesRegex("History-Info: <sip:6505551234@homedomain;Reason=SIP%3[bB]cause%3[dD]480%3[bB]text%3[dD]%22Temporarily%20Unavailable%22>;index=1\r\nHistory-Info: <sip:6505555678@homedomain>;index=1.1"));

  // ---------- AS2 sends a 100 Trying to indicate it has received the request.
  string fresp1 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp1, &tpAS2);

  // ---------- AS2 turns it around (acting as proxy)
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS2);
  free_txdata();

  // 100 Trying goes back to AS2
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS2.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to final destination (the bono set up in the diverted-to
  // callee's bindings)
  SCOPED_TRACE("INVITE (4)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpDivertedToCalleeBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:andunnuvvawun@10.114.61.214:5061;transport=tcp;ob", r1.uri());
  EXPECT_EQ(BONO_ROUTE_HEADER, get_headers(out, "Route"));
  EXPECT_THAT(get_headers(out, "History-Info"),
              testing::MatchesRegex("History-Info: <sip:6505551234@homedomain;Reason=SIP%3[bB]cause%3[dD]480%3[bB]text%3[dD]%22Temporarily%20Unavailable%22>;index=1\r\nHistory-Info: <sip:6505555678@homedomain>;index=1.1"));
  free_txdata();
}


TEST_F(SCSCFTest, MmtelDoubleCdiv)
{
  // Set up info about the original callee.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551234", "homedomain");
  set_ifc(irs_info_1, "sip:6505551234@homedomain", 0, {"<Method>INVITE</Method>", "<SessionCase>2</SessionCase><!-- terminating-unregistered -->"}, "sip:mmtel.homedomain");
  irs_info_1._regstate = "UNREGISTERED";
  expect_get_subscriber_state(irs_info_1, "sip:6505551234@homedomain", 2);

  // Set up info about the forwarded callee.
  HSSConnection::irs_info irs_info_2;
  setup_irs_info(irs_info_2, "6505555678", "homedomain");
  ServiceProfileBuilder service_profile = ServiceProfileBuilder()
    .addIfc(2, {"<SessionCase>4</SessionCase><!-- originating-cdiv -->", "<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP")
    .addIfc(0, {"<Method>INVITE</Method>", "<SessionCase>2</SessionCase><!-- terminating-unregistered -->"}, "sip:mmtel.homedomain");
  set_ifcs_from_service_profile(irs_info_2, service_profile, "sip:6505555678@homedomain");
  irs_info_2._regstate = "UNREGISTERED";
  expect_get_subscriber_state(irs_info_2, "sip:6505555678@homedomain", 2);

  // Set up info about the second forwarded callee.
  HSSConnection::irs_info irs_info_3;
  Bindings bindings;
  setup_irs_info(irs_info_3, "6505559012", "homedomain");
  setup_binding(bindings, "sip:6505559012@homedomain", "sip:andunnuvvawun@10.114.61.214:5061;transport=tcp;ob");
  expect_get_callee_info(irs_info_3, bindings, "sip:6505559012@homedomain");

  _xdm_connection->put("sip:6505551234@homedomain",
                       R"(<?xml version="1.0" encoding="UTF-8"?>
                          <simservs xmlns="http://uri.etsi.org/ngn/params/xml/simservs/xcap" xmlns:cp="urn:ietf:params:xml:ns:common-policy">
                            <originating-identity-presentation active="false" />
                            <originating-identity-presentation-restriction active="false">
                              <default-behaviour>presentation-restricted</default-behaviour>
                            </originating-identity-presentation-restriction>
                            <communication-diversion active="true">
                              <NoReplyTimer>19</NoReplyTimer>"
                                <cp:ruleset>
                                  <cp:rule id="rule1">
                                    <cp:conditions/>
                                    <cp:actions><forward-to><target>sip:6505555678@homedomain</target></forward-to></cp:actions>
                                  </cp:rule>
                                </cp:ruleset>
                              </communication-diversion>
                            <incoming-communication-barring active="false"/>
                            <outgoing-communication-barring active="false"/>
                          </simservs>)");  // "

  _xdm_connection->put("sip:6505555678@homedomain",
                       R"(<?xml version="1.0" encoding="UTF-8"?>
                          <simservs xmlns="http://uri.etsi.org/ngn/params/xml/simservs/xcap" xmlns:cp="urn:ietf:params:xml:ns:common-policy">
                            <originating-identity-presentation active="false" />
                            <originating-identity-presentation-restriction active="false">
                              <default-behaviour>presentation-restricted</default-behaviour>
                            </originating-identity-presentation-restriction>
                            <communication-diversion active="true">
                              <NoReplyTimer>19</NoReplyTimer>"
                                <cp:ruleset>
                                  <cp:rule id="rule1">
                                    <cp:conditions/>
                                    <cp:actions><forward-to><target>sip:6505559012@homedomain</target></forward-to></cp:actions>
                                  </cp:rule>
                                </cp:ruleset>
                              </communication-diversion>
                            <incoming-communication-barring active="false"/>
                            <outgoing-communication-barring active="false"/>
                          </simservs>)");  // "

  _hss_connection->set_result("/impu/sip%3A6505555678%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");
  _hss_connection->set_result("/impu/sip%3A6505559012%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS2(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpDivertedToCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(4, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE goes to MMTEL as terminating AS for Bob, and is redirected to 6505555678.
  ReqMatcher r1("INVITE");
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr;

  // MMTEL returns INVITE for 6505555678.

  // 181 Call is being forwarded goes back to bono
  out = current_txdata()->msg;
  RespMatcher(181).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // Originating processing is done for Bob - who has no matching iFCs.
  // Terminating processing is done for 6505555678, and matches an iFC whose AS
  // is the MMTEL, so the INVITE goes to MMTEL.

  // Now INVITE is redirected to 6505559012.
  // MMTEL returns INVITE for 6505559012.

  // 181 Call is being forwarded goes back to bono
  out = current_txdata()->msg;
  RespMatcher(181).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS2 (as originating AS for 6505555678).
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS2.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505559012@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig;service=scscf>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505555678@homedomain>;orig-cdiv"));
  EXPECT_THAT(get_headers(out, "History-Info"),
              testing::MatchesRegex("History-Info: <sip:6505551234@homedomain;Reason=SIP%3[bB]cause%3[dD]480%3[bB]text%3[dD]%22Temporarily%20Unavailable%22>;index=1\r\nHistory-Info: <sip:6505555678@homedomain;Reason=SIP%3[bB]cause%3[dD]480%3[bB]text%3[dD]%22Temporarily%20Unavailable%22>;index=1.1\r\nHistory-Info: <sip:6505559012@homedomain>;index=1.1.1"));

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp1 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp1, &tpAS2);

  // ---------- AS2 turns it around (acting as proxy)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS2);
  free_txdata();

  // 100 Trying goes back to AS2
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS2.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to final destination
  SCOPED_TRACE("INVITE (4)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  // INVITE passed to final destination, which is the bono set up in the
  // bindings of the final callee (who the call was diverted twice to reach)
  tpDivertedToCalleeBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:andunnuvvawun@10.114.61.214:5061;transport=tcp;ob", r1.uri());
  free_txdata();
}


// Test a simple MMTEL flow.
TEST_F(SCSCFTest, MmtelFlow)
{
  // Set up caller info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  set_ifc(irs_info_1, "sip:6505551000@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:mmtel.homedomain");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Set up callee info.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  set_ifc(irs_info_2, "sip:6505551234@homedomain", 0, {"<Method>INVITE</Method>"}, "sip:5.2.3.4:56787;transport=UDP");
  expect_get_callee_info(irs_info_2, bindings, "sip:6505551234@homedomain", 2);

  _xdm_connection->put("sip:6505551000@homedomain",
                       R"(<?xml version="1.0" encoding="UTF-8"?>
                          <simservs xmlns="http://uri.etsi.org/ngn/params/xml/simservs/xcap" xmlns:cp="urn:ietf:params:xml:ns:common-policy">
                            <originating-identity-presentation active="true" />
                            <originating-identity-presentation-restriction active="true">
                              <default-behaviour>presentation-restricted</default-behaviour>
                            </originating-identity-presentation-restriction>
                            <communication-diversion active="false"/>
                            <incoming-communication-barring active="false"/>
                            <outgoing-communication-barring active="false"/>
                          </simservs>)");  // "

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "5.2.3.4", 56787);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono.
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // Call should pass through MMTEL AS, and then proceed. This should
  // add a privacy header.

  // INVITE passed on to AS1.
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));
  EXPECT_EQ("Privacy: id; header; user", get_headers(out, "Privacy"));

  // ---------- AS1 turns it around (acting as proxy)
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1.
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to final destination (to bono set up in callee's
  // bindings).
  SCOPED_TRACE("INVITE (4)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  tpCalleeBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r1.uri());
  EXPECT_EQ(BONO_ROUTE_HEADER, get_headers(out, "Route"));
  EXPECT_EQ("Privacy: id; header; user", get_headers(out, "Privacy"));
  free_txdata();
}


/// Test MMTEL-then-external-AS flows (both orig and term).
//
// Flow:
//
// * 6505551000 calls 6505551234
// * 6505551000 originating:
//     * MMTEL is invoked, applying privacy
//     * external AS1 (1.2.3.4:56789) is invoked
// * 6505551234 terminating:
//     * MMTEL is invoked, applying privacy
//     * external AS2 (5.2.3.4:56787) is invoked
// * call reaches registered contact for 6505551234.
//
TEST_F(SCSCFTest, MmtelThenExternal)
{

  // Set up caller info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  irs_info_1._regstate = "UNREGISTERED";
  ServiceProfileBuilder service_profile_1 = ServiceProfileBuilder()
    .addIfc(1, {"<Method>INVITE</Method>"}, "sip:mmtel.homedomain")
    .addIfc(2, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  set_ifcs_from_service_profile(irs_info_1, service_profile_1, "sip:6505551000@homedomain");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Set up callee info.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  ServiceProfileBuilder service_profile_2 = ServiceProfileBuilder()
    .addIfc(1, {"<Method>INVITE</Method>"}, "sip:mmtel.homedomain")
    .addIfc(2, {"<Method>INVITE</Method>"}, "sip:5.2.3.4:56787;transport=UDP");
  set_ifcs_from_service_profile(irs_info_2, service_profile_2, "sip:6505551234@homedomain");
  expect_get_callee_info(irs_info_2, bindings, "sip:6505551234@homedomain", 3);

  _xdm_connection->put("sip:6505551000@homedomain",
                       R"(<?xml version="1.0" encoding="UTF-8"?>
                          <simservs xmlns="http://uri.etsi.org/ngn/params/xml/simservs/xcap" xmlns:cp="urn:ietf:params:xml:ns:common-policy">
                            <originating-identity-presentation active="true" />
                            <originating-identity-presentation-restriction active="true">
                              <default-behaviour>presentation-restricted</default-behaviour>
                            </originating-identity-presentation-restriction>
                            <communication-diversion active="false"/>
                            <incoming-communication-barring active="false"/>
                            <outgoing-communication-barring active="false"/>
                       </simservs>)");  // "

  _xdm_connection->put("sip:6505551234@homedomain",
                       R"(<?xml version="1.0" encoding="UTF-8"?>
                          <simservs xmlns="http://uri.etsi.org/ngn/params/xml/simservs/xcap" xmlns:cp="urn:ietf:params:xml:ns:common-policy">
                            <originating-identity-presentation active="true" />
                            <originating-identity-presentation-restriction active="true">
                              <default-behaviour>presentation-restricted</default-behaviour>
                            </originating-identity-presentation-restriction>
                            <communication-diversion active="false"/>
                            <incoming-communication-barring active="false"/>
                            <outgoing-communication-barring active="false"/>
                          </simservs>)");  // "

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpAS2(TransportFlow::Protocol::UDP, stack_data.scscf_port, "5.2.3.4", 56787);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // Call should pass through MMTEL AS, and then proceed. This should
  // add a privacy header.

  // INVITE passed on to AS1 (as originating).
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig;service=scscf>"));
  EXPECT_EQ("Privacy: id; header; user", get_headers(out, "Privacy"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551000@homedomain>;sescase=orig;regstate=unreg"));

  // ---------- AS1 turns it around (acting as proxy)
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1.
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // Call should pass through MMTEL AS, and then proceed. This should
  // do nothing.

  // INVITE passed on to AS2 (as terminating).
  SCOPED_TRACE("INVITE (S2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS2.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551234@homedomain>;sescase=term;regstate=reg"));

  // ---------- AS2 turns it around (acting as proxy).
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS2);
  free_txdata();

  // 100 Trying goes back to AS2.
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS2.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed to final destination (to bono set up in callee's bindings).
  SCOPED_TRACE("INVITE (4)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  tpCalleeBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r1.uri());
  EXPECT_EQ("Privacy: id; header; user", get_headers(out, "Privacy"));
  free_txdata();
}


/// Test multiple-MMTEL flow.
// Flow:
//
// * 6505551000 calls 6505551234
// * 6505551000 originating:
//     * MMTEL is invoked, applying privacy
//     * MMTEL is invoked, applying privacy
// * 6505551234 terminating:
//     * MMTEL is invoked, applying privacy
//     * MMTEL is invoked, applying privacy
//     * external AS1 (5.2.3.4:56787) is invoked
// * call reaches registered contact for 6505551234.
//
TEST_F(SCSCFTest, MultipleMmtelFlow)
{
  // Set up caller info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  ServiceProfileBuilder service_profile_1 = ServiceProfileBuilder()
    .addIfc(1, {"<Method>INVITE</Method>"}, "sip:mmtel.homedomain")
    .addIfc(2, {"<Method>INVITE</Method>"}, "sip:mmtel.homedomain");
  set_ifcs_from_service_profile(irs_info_1, service_profile_1, "sip:6505551000@homedomain");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Set up callee info.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  ServiceProfileBuilder service_profile_2 = ServiceProfileBuilder()
    .addIfc(1, {"<Method>INVITE</Method>"}, "sip:mmtel.homedomain")
    .addIfc(2, {"<Method>INVITE</Method>"}, "sip:mmtel.homedomain")
    .addIfc(3, {"<Method>INVITE</Method>"}, "sip:5.2.3.4:56787;transport=UDP");
  set_ifcs_from_service_profile(irs_info_2, service_profile_2, "sip:6505551234@homedomain");
  expect_get_callee_info(irs_info_2, bindings, "sip:6505551234@homedomain", 4);

  _xdm_connection->put("sip:6505551000@homedomain",
                       R"(<?xml version="1.0" encoding="UTF-8"?>
                          <simservs xmlns="http://uri.etsi.org/ngn/params/xml/simservs/xcap" xmlns:cp="urn:ietf:params:xml:ns:common-policy">
                            <originating-identity-presentation active="true" />
                            <originating-identity-presentation-restriction active="true">
                              <default-behaviour>presentation-restricted</default-behaviour>
                            </originating-identity-presentation-restriction>
                            <communication-diversion active="false"/>
                            <incoming-communication-barring active="false"/>
                            <outgoing-communication-barring active="false"/>
                          </simservs>)");  // "

  _xdm_connection->put("sip:6505551234@homedomain",
                       R"(<?xml version="1.0" encoding="UTF-8"?>
                          <simservs xmlns="http://uri.etsi.org/ngn/params/xml/simservs/xcap" xmlns:cp="urn:ietf:params:xml:ns:common-policy">
                            <originating-identity-presentation active="true" />
                            <originating-identity-presentation-restriction active="true">
                              <default-behaviour>presentation-restricted</default-behaviour>
                            </originating-identity-presentation-restriction>
                            <communication-diversion active="false"/>
                            <incoming-communication-barring active="false"/>
                            <outgoing-communication-barring active="false"/>
                          </simservs>)");  // "

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "5.2.3.4", 56787);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // Call should pass through MMTEL AS four times (!), and then
  // proceed. This should add a privacy header.

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));
  EXPECT_EQ("Privacy: id; header; user", get_headers(out, "Privacy"));

  // ---------- AS1 turns it around (acting as proxy)
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed to final destination (to bono set up in callee's bindings)
  SCOPED_TRACE("INVITE (4)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  tpCalleeBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r1.uri());
  EXPECT_EQ("Privacy: id; header; user", get_headers(out, "Privacy"));
  free_txdata();
}


// Test basic ISC (AS) OPTIONS final acceptance flow (AS sinks request).
TEST_F(SCSCFTest, SimpleOptionsAccept)
{
  // Set up caller info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Set up callee info. No need to set up bindings, as the AS sinks the request
  // before it is passed on.
  HSSConnection::irs_info irs_info_2;
  setup_irs_info(irs_info_2, "6505551234", "homedomain");
  set_ifc(irs_info_2, "sip:6505551234@homedomain", 1, {"<Method>OPTIONS</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  expect_get_subscriber_state(irs_info_2, "sip:6505551234@homedomain");

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send OPTIONS
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "OPTIONS";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(1, txdata_count());

  // INVITE passed on to AS1
  SCOPED_TRACE("OPTIONS (S)");
  pjsip_msg* out = current_txdata()->msg;
  ReqMatcher r1("OPTIONS");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));

  // ---------- AS1 accepts it with 200.
  string fresp = respond_to_txdata(current_txdata(), 200);
  free_txdata();
  inject_msg(fresp, &tpAS1);

  // 200 response goes back to bono
  SCOPED_TRACE("OK");
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  msg._cseq++;
  free_txdata();
}


// Test terminating call-diversion AS flow to external URI.
// Repros https://github.com/Metaswitch/sprout/issues/519.
TEST_F(SCSCFTest, TerminatingDiversionExternal)
{
  // Set up caller info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Set up callee info.
  HSSConnection::irs_info irs_info_2;
  setup_irs_info(irs_info_2, "6505501234", "homedomain");
  set_ifc(irs_info_2, "sip:6505501234@homedomain", 1, {"<Method>INVITE</Method>", "<SessionCase>1</SessionCase><!-- terminating-registered -->"}, "sip:1.2.3.4:56789;transport=UDP");
  expect_get_subscriber_state(irs_info_2, "sip:6505501234@homedomain", 2);

  _hss_connection->set_result("/impu/sip%3A6505501234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  TransportFlow tpBono(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpExternal(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.9.8.7", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505501234@homedomain";
  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1 (as terminating AS for Bob)
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505501234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505501234@homedomain>;sescase=term;regstate=reg"));

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp1 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp1, &tpAS);

  // ---------- AS1 turns it around
  // (acting as routing B2BUA by adding a Via, removing the top Route and changing the target)
  const pj_str_t STR_VIA = pj_str("Via");
  pjsip_via_hdr* via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (via_hdr)
  {
    via_hdr->rport_param = via_hdr->sent_by.port;
  }
  via_hdr = pjsip_via_hdr_create(current_txdata()->pool);
  via_hdr->transport = pj_str("FAKE_UDP");
  via_hdr->sent_by.host = pj_str("1.2.3.4");
  via_hdr->sent_by.port = 56789;
  via_hdr->rport_param = 0;
  via_hdr->branch_param = pj_str("z9hG4bK1234567890");
  pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)via_hdr);
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  ((pjsip_sip_uri*)out->line.req.uri)->host = pj_str("ut.cw-ngv.com");
  inject_msg(out, &tpAS);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed externally
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpExternal.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505501234@ut.cw-ngv.com", r1.uri());
  EXPECT_EQ("", get_headers(out, "Route"));

  // ---------- Externally accepted with 200.
  string fresp = respond_to_txdata(current_txdata(), 200);
  free_txdata();
  inject_msg(fresp, &tpExternal);

  // 200 OK goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);

  // ---------- AS1 forwards 200 (stripping via)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  free_txdata();

  // 200 OK goes back to bono
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  EXPECT_EQ(1, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_audio_session_setup_time_tbl)->_count);
  EXPECT_EQ(0, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_video_session_setup_time_tbl)->_count);
}


// Test originating AS handling for request to external URI.  Check that
// originating "user=phone" SIP URIs are looked up using the equivalent Tel URI
TEST_F(SCSCFTest, OriginatingExternal)
{
  // Set up callee info.
  // Call is to "6505501234@ut.cw-ngv.com", but includes
  // "sip:6505551000@homedomain;user=phone" as a P-Asserted-Identity, so lookup
  // should be done on "tel:6505551000".
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551000", "", false, true);
  set_ifc(irs_info, "tel:6505551000", 1, {"<Method>INVITE</Method>", "<SessionCase>0</SessionCase><!-- originating-registered -->"}, "sip:1.2.3.4:56789;transport=UDP");
  expect_get_subscriber_state(irs_info, "tel:6505551000");

  // When the P-Asserted-Identity doesn't include "user=phone", expect the
  // lookup to fail.
  EXPECT_CALL(*_sm, get_subscriber_state(IrsQueryWithPublicId("sip:6505551000@homedomain"), _, _))
    .WillOnce(Return(HTTP_NOT_FOUND));

  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  TransportFlow tpBono(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpExternal(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.9.8.7", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345";
  msg._to = "6505501234@ut.cw-ngv.com";
  msg._extra = "P-Asserted-Identity: Andy <sip:6505551000@homedomain;user=phone>";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505501234@ut.cw-ngv.com";
  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1 (as originating AS for Alice)
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505501234@ut.cw-ngv.com", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig;service=scscf>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <tel:6505551000>;sescase=orig;regstate=reg"));

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp1 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp1, &tpAS);

  // ---------- AS1 turns it around
  // (acting as routing B2BUA by adding a Via, removing the top Route and changing the target)
  const pj_str_t STR_VIA = pj_str("Via");
  pjsip_via_hdr* via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (via_hdr)
  {
    via_hdr->rport_param = via_hdr->sent_by.port;
  }
  via_hdr = pjsip_via_hdr_create(current_txdata()->pool);
  via_hdr->transport = pj_str("FAKE_UDP");
  via_hdr->sent_by.host = pj_str("1.2.3.4");
  via_hdr->sent_by.port = 56789;
  via_hdr->rport_param = 0;
  via_hdr->branch_param = pj_str("z9hG4bK1234567890");
  pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)via_hdr);
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed externally
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpExternal.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505501234@ut.cw-ngv.com", r1.uri());
  EXPECT_EQ("", get_headers(out, "Route"));

  // ---------- Externally accepted with 200.
  string fresp = respond_to_txdata(current_txdata(), 200);
  free_txdata();
  inject_msg(fresp, &tpExternal);

  // 200 OK goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);

  // ---------- AS1 forwards 200 (stripping via)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  free_txdata();

  // 200 OK goes back to bono
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // Finally, clear enforce_user_phone without setting user=phone on the PAI and check that the attempt to resend the INVITE
  // fails (it will attempt the lookup on the SIP URI, not the equivalent Tel URI).  We only do coercion if user=phone
  // is present, regardless of enforce_user_phone.
  URIClassifier::enforce_user_phone = false;

  SCSCFMessage msg2;
  msg2._via = "10.99.88.11:12345";
  msg2._to = "6505501234@ut.cw-ngv.com";
  msg2._extra = "P-Asserted-Identity: Andy <sip:6505551000@homedomain>";
  msg2._todomain = "";
  msg2._route = "Route: <sip:sprout.homedomain;orig>";
  msg2._requri = "sip:6505501234@ut.cw-ngv.com";
  msg2._method = "INVITE";
  inject_msg(msg2.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 and 404 go back to bono
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  free_txdata();

  out = current_txdata()->msg;
  RespMatcher(404).matches(out);
  free_txdata();

  EXPECT_EQ(1, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_audio_session_setup_time_tbl)->_count);
  EXPECT_EQ(0, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_video_session_setup_time_tbl)->_count);
}


// Test local call with both originating and terminating ASs.
TEST_F(SCSCFTest, OriginatingTerminatingAS)
{
  // Set up caller info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  set_ifc(irs_info_1, "sip:6505551000@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Set up callee info.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  set_ifc(irs_info_2, "sip:6505551234@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  expect_get_callee_info(irs_info_2, bindings, "sip:6505551234@homedomain", 2);

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  TransportFlow tpBono(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";
  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1 (as originating AS for 6505551000)
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig;service=scscf>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551000@homedomain>;sescase=orig;regstate=reg"));

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp1 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp1, &tpAS);

  // ---------- AS1 turns it around
  // (acting as routing B2BUA by adding a Via, and removing the top Route.)
  const pj_str_t STR_VIA = pj_str("Via");
  pjsip_via_hdr* via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (via_hdr)
  {
    via_hdr->rport_param = via_hdr->sent_by.port;
  }
  via_hdr = pjsip_via_hdr_create(current_txdata()->pool);
  via_hdr->transport = pj_str("FAKE_UDP");
  via_hdr->sent_by.host = pj_str("1.2.3.4");
  via_hdr->sent_by.port = 56789;
  via_hdr->rport_param = 0;
  via_hdr->branch_param = pj_str("z9hG4bK1234567890");
  pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)via_hdr);
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1 (as terminating AS for 6505551234)
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  r1 = ReqMatcher("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551234@homedomain>;sescase=term;regstate=reg"));

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp2 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp2, &tpAS);

  // ---------- AS1 turns it around
  // (acting as routing B2BUA by adding a Via, and removing the top Route.)
  via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (via_hdr)
  {
    via_hdr->rport_param = via_hdr->sent_by.port;
  }
  via_hdr = pjsip_via_hdr_create(current_txdata()->pool);
  via_hdr->transport = pj_str("FAKE_UDP");
  via_hdr->sent_by.host = pj_str("1.2.3.4");
  via_hdr->sent_by.port = 56789;
  via_hdr->rport_param = 0;
  via_hdr->branch_param = pj_str("z9hG4bK1234567891"); // Must differ from previous branch
  pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)via_hdr);
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed to terminating UE (callee).
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  tpCalleeBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r1.uri());

  string fresp = respond_to_txdata(current_txdata(), 200);
  free_txdata();
  inject_msg(fresp, &tpBono);

  // 200 OK goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);

  // ---------- AS1 forwards 200 (stripping via)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  free_txdata();

  // 200 OK goes back to AS1 (terminating)
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);

  // ---------- AS1 forwards 200 (stripping via)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  free_txdata();

  // 200 OK goes back to bono
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  EXPECT_EQ(1, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_audio_session_setup_time_tbl)->_count);
  EXPECT_EQ(0, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_video_session_setup_time_tbl)->_count);

  // Make sure that we haven't sent a request to homestead with 127.0.0.1 as the
  // domain of the S-CSCF URI.
  // This used to happen when a request was routed to an App Server and back,
  // and resulted in Homestead making a request to the HSS with the wrong S-CSCF
  // URI
  bool found_wrong_uri = false;
  for (FakeHSSConnection::UrlBody body : _hss_connection->_calls)
  {
    found_wrong_uri |= (!(body.second.find("127.0.0.1") == std::string::npos));
  }

  EXPECT_FALSE(found_wrong_uri);
}


// Test local call with both originating and terminating ASs where terminating
// UE doesn't respond.
TEST_F(SCSCFTest, OriginatingTerminatingASTimeout)
{
  // Set up caller info, including one iFC.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  set_ifc(irs_info_1, "sip:6505551000@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=TCP");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Set up callee info, including one iFC.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  set_ifc(irs_info_2, "sip:6505551234@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=TCP");
  expect_get_callee_info(irs_info_2, bindings, "sip:6505551234@homedomain", 2);

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  TransportFlow tpBono(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345";
  msg._branch = "1111111111";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";
  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1 (as originating AS for 6505551000)
  SCOPED_TRACE("INVITE (S)");
  pjsip_tx_data* invite_txdata = pop_txdata();
  out = invite_txdata->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  tpAS.expect_target(invite_txdata, false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=TCP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=TCP;lr;orig;service=scscf>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551000@homedomain>;sescase=orig;regstate=reg"));

  // AS1 sends an immediate 100 Trying
  inject_msg(respond_to_txdata(invite_txdata, 100), &tpAS);

  // ---------- AS1 turns INVITE around
  // (acting as routing B2BUA by adding a Via, and removing the top Route.)
  const pj_str_t STR_VIA = pj_str("Via");
  pjsip_via_hdr* via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (via_hdr)
  {
    via_hdr->rport_param = via_hdr->sent_by.port;
  }
  via_hdr = pjsip_via_hdr_create(invite_txdata->pool);
  via_hdr->transport = pj_str("FAKE_UDP");
  via_hdr->sent_by.host = pj_str("1.2.3.4");
  via_hdr->sent_by.port = 56789;
  via_hdr->rport_param = 0;
  via_hdr->branch_param = pj_str("z9hG4bK2222222222");
  pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)via_hdr);
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1 (as terminating AS for 6505551234)
  SCOPED_TRACE("INVITE (S)");
  invite_txdata = pop_txdata();
  out = invite_txdata->msg;
  r1 = ReqMatcher("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  tpAS.expect_target(invite_txdata, false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=TCP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=TCP;lr;service=scscf>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551234@homedomain>;sescase=term;regstate=reg"));

  // AS1 sends an immediate 100 Trying
  inject_msg(respond_to_txdata(invite_txdata, 100), &tpAS);

  // ---------- AS1 turns INVITE around
  // (acting as routing B2BUA by adding a Via, and removing the top Route.)
  via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (via_hdr)
  {
    via_hdr->rport_param = via_hdr->sent_by.port;
  }
  via_hdr = pjsip_via_hdr_create(invite_txdata->pool);
  via_hdr->transport = pj_str("FAKE_UDP");
  via_hdr->sent_by.host = pj_str("1.2.3.4");
  via_hdr->sent_by.port = 56789;
  via_hdr->rport_param = 0;
  via_hdr->branch_param = pj_str("z9hG4bK3333333333"); // Must differ from previous branch
  pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)via_hdr);
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed to terminating UE
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  // INVITE passed to terminating UE (callee).
  tpCalleeBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r1.uri());

  // Save the request for later.
  pjsip_tx_data* target_rq = pop_txdata();

  // Bono sends an immediate 100 Trying response.
  inject_msg(respond_to_txdata(target_rq, 100), &tpBono);

  // The terminating UE doesn't respond so eventually the transaction will time
  // out.  To force this to happen in the right way, we send a CANCEL chasing
  // the original transaction (which is what Bono will do if the transaction
  // times out).
  msg._method = "CANCEL";
  msg._via = "10.99.88.11:12345";
  msg._branch = "1111111111";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";
  inject_msg(msg.get_request(), &tpBono);

  // CANCEL gets OK'd
  ASSERT_EQ(2, txdata_count());
  RespMatcher(200).matches(current_txdata()->msg);
  free_txdata();

  // The CANCEL is forwarded to AS1 (as originating AS)
  ReqMatcher("CANCEL").matches(current_txdata()->msg);

  // AS1 responds to the CANCEL.
  inject_msg(respond_to_current_txdata(200), &tpAS);
  free_txdata();

  // AS1 forwards the CANCEL back to Sprout.
  msg._branch = "2222222222";
  inject_msg(msg.get_request(), &tpAS);

  // CANCEL gets OK'd
  ASSERT_EQ(2, txdata_count());
  RespMatcher(200).matches(current_txdata()->msg);
  free_txdata();

  // The CANCEL is forwarded to AS1 (as terminating AS)
  ReqMatcher("CANCEL").matches(current_txdata()->msg);

  // AS2 responds to the CANCEL.
  inject_msg(respond_to_current_txdata(200), &tpAS);
  free_txdata();

  // AS1 forwards the CANCEL back to Sprout.
  msg._branch = "3333333333";
  inject_msg(msg.get_request(), &tpAS);

  // CANCEL gets OK'd
  ASSERT_EQ(2, txdata_count());
  RespMatcher(200).matches(current_txdata()->msg);
  free_txdata();

  // The CANCEL is forwarded to the terminating UE
  ReqMatcher("CANCEL").matches(current_txdata()->msg);

  // UE responds to the CANCEL.
  inject_msg(respond_to_current_txdata(200), &tpAS);
  free_txdata();

  // UE sends a 487 response which is ACKed and forwarded to AS1 (as terminating AS)
  inject_msg(respond_to_txdata(target_rq, 487));
  ASSERT_EQ(2, txdata_count());
  ReqMatcher("ACK").matches(current_txdata()->msg);
  free_txdata();
  ASSERT_EQ(1, txdata_count());
  RespMatcher(487).matches(current_txdata()->msg);

  // AS1 ACKs the response and forwards it back to Sprout removing the top Via header.
  msg._method = "ACK";
  msg._branch = "3333333333";
  inject_msg(msg.get_request(), &tpAS);
  out = current_txdata()->msg;
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  free_txdata();

  // Sprout ACKs the response and forwards it to AS1 (as originating AS).
  ASSERT_EQ(2, txdata_count());
  ReqMatcher("ACK").matches(current_txdata()->msg);
  free_txdata();
  ASSERT_EQ(1, txdata_count());
  RespMatcher(487).matches(current_txdata()->msg);

  // AS1 ACKs the response and forwards it back to Sprout removing the top Via header.
  msg._method = "ACK";
  msg._branch = "2222222222";
  inject_msg(msg.get_request(), &tpAS);
  out = current_txdata()->msg;
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  free_txdata();

  // Sprout ACKs the response and forwards it back to the originating UE.
  ASSERT_EQ(2, txdata_count());
  ReqMatcher("ACK").matches(current_txdata()->msg);
  free_txdata();
  ASSERT_EQ(1, txdata_count());
  RespMatcher(487).matches(current_txdata()->msg);
  free_txdata();

  // UE ACKs the response.
  msg._method = "ACK";
  msg._branch = "2222222222";
  inject_msg(msg.get_request(), &tpAS);

  // Session didn't get set up successfully so no session setup time will be
  // tracked.
  EXPECT_EQ(0, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_audio_session_setup_time_tbl)->_count);
  EXPECT_EQ(0, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_video_session_setup_time_tbl)->_count);
}


// Test local MESSAGE request with both originating and terminating ASs where
// the terminating UE doesn't respond.
TEST_F(SCSCFTest, OriginatingTerminatingMessageASTimeout)
{
  // Set up caller info, including one iFC.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  set_ifc(irs_info_1, "sip:6505551000@homedomain", 1, {"<Method>MESSAGE</Method>"}, "sip:1.2.3.4:56789;transport=TCP");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Set up callee info, including one iFC.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  set_ifc(irs_info_2, "sip:6505551234@homedomain", 1, {"<Method>MESSAGE</Method>"}, "sip:1.2.3.4:56789;transport=TCP");
  expect_get_callee_info(irs_info_2, bindings, "sip:6505551234@homedomain", 2);

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS(TransportFlow::Protocol::TCP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send MESSAGE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._method = "MESSAGE";
  msg._via = "10.99.88.11:12345";
  msg._branch = "1111111111";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";
  inject_msg(msg.get_request(), &tpBono);
  poll();

  // MESSAGE passed on to AS1 (as originating AS for 6505551000)
  ASSERT_EQ(1, txdata_count());
  pjsip_tx_data* message_txdata = pop_txdata();
  pjsip_msg* out = message_txdata->msg;
  ReqMatcher r1("MESSAGE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  tpAS.expect_target(message_txdata, false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=TCP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=TCP;lr;orig;service=scscf>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551000@homedomain>;sescase=orig;regstate=reg"));

  // AS1 sends an immediate 100 Trying response.  This isn't realistic as the
  // response should be delayed by 3.5 seconds, but it stops the script
  // having to handle MESSAGE retransmits.
  inject_msg(respond_to_txdata(message_txdata, 100), &tpAS);

  // Advance time by a second so we have good enough control over the order
  // the transactions time out.
  cwtest_advance_time_ms(1000L);

  // ---------- AS1 turns MESSAGE around
  // (acting as routing B2BUA by adding a Via, and removing the top Route.)
  const pj_str_t STR_VIA = pj_str("Via");
  pjsip_via_hdr* via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (via_hdr)
  {
    via_hdr->rport_param = via_hdr->sent_by.port;
  }
  via_hdr = pjsip_via_hdr_create(message_txdata->pool);
  via_hdr->transport = pj_str("TCP");
  via_hdr->sent_by.host = pj_str("1.2.3.4");
  via_hdr->sent_by.port = 56789;
  via_hdr->rport_param = 0;
  via_hdr->branch_param = pj_str("z9hG4bK2222222222");
  pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)via_hdr);
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  pjsip_tx_data_dec_ref(message_txdata);

  // MESSAGE passed on to AS1 (as terminating AS for 6505551234)
  ASSERT_EQ(1, txdata_count());
  message_txdata = pop_txdata();
  out = message_txdata->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  tpAS.expect_target(message_txdata, false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=TCP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=TCP;lr;service=scscf>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551234@homedomain>;sescase=term;regstate=reg"));

  // AS1 sends an immediate 100 Trying response.  This isn't realistic as the
  // response should be delayed by 3.5 seconds, but it stops the script
  // having to handle MESSAGE retransmits.
  inject_msg(respond_to_txdata(message_txdata, 100), &tpAS);

  // Advance time by a second so we have good enough control over the order
  // the transactions time out.
  cwtest_advance_time_ms(1000L);

  // ---------- AS1 turns MESSAGE around
  // (acting as routing B2BUA by adding a Via, and removing the top Route.)
  via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (via_hdr)
  {
    via_hdr->rport_param = via_hdr->sent_by.port;
  }
  via_hdr = pjsip_via_hdr_create(message_txdata->pool);
  via_hdr->transport = pj_str("TCP");
  via_hdr->sent_by.host = pj_str("1.2.3.4");
  via_hdr->sent_by.port = 56789;
  via_hdr->rport_param = 0;
  via_hdr->branch_param = pj_str("z9hG4bK3333333333"); // Must differ from previous branch
  pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)via_hdr);
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  pjsip_tx_data_dec_ref(message_txdata);

  // MESSAGE passed to terminating UE.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  // MESSAGE passed to terminating UE (UE2) - expect the target to be the bono
  // set up in this UEs bindings.
  tpCalleeBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r1.uri());

  // UE sends an immediate 100 Trying response.  This isn't realistic as the
  // response should be delayed by 3.5 seconds, but it stops the script
  // having to handle MESSAGE retransmits.
  inject_msg(respond_to_current_txdata(100), &tpBono);

  // Advance the time so the delayed 100 Trying responses are sent by Sprout
  // (should happen 3.5 seconds after the MESSAGE was first received, so we'll
  // advance to just over that time).
  cwtest_advance_time_ms(3500L);
  poll();
  ASSERT_EQ(3, txdata_count());
  RespMatcher(100).matches(current_txdata()->msg);
  tpBono.expect_target(current_txdata(), true);
  free_txdata();
  ASSERT_EQ(2, txdata_count());
  RespMatcher(100).matches(current_txdata()->msg);
  tpAS.expect_target(current_txdata(), true);
  free_txdata();
  ASSERT_EQ(1, txdata_count());
  RespMatcher(100).matches(current_txdata()->msg);
  tpAS.expect_target(current_txdata(), true);
  free_txdata();

  // Now advance the time so the first transaction times out.  This should
  // happen 64*T1=32 seconds after the initial request.  Since we've already
  // advanced time by just over 5.5 seconds, we just need to advance by
  // another 26.5 seconds.
  cwtest_advance_time_ms(26500L);
  poll();

  // Sprout should send a 408 response on the original transaction.
  ASSERT_EQ(1, txdata_count());
  RespMatcher(408).matches(current_txdata()->msg);
  tpBono.expect_target(current_txdata(), true);
  free_txdata();

  // Advance the time by another second so the second hop transaction times out.
  cwtest_advance_time_ms(1000L);
  poll();

  // Sprout should send a 408 response to AS1.
  ASSERT_EQ(1, txdata_count());
  RespMatcher(408).matches(current_txdata()->msg);
  tpAS.expect_target(current_txdata(), true);
  free_txdata();

  // Advance the time by another second so the third hop transaction times out.
  cwtest_advance_time_ms(1000L);
  poll();

  // Sprout should send a 408 response to AS1.
  ASSERT_EQ(1, txdata_count());
  RespMatcher(408).matches(current_txdata()->msg);
  tpAS.expect_target(current_txdata(), true);
  free_txdata();
}


// Test terminating call-diversion AS flow to external URI, with orig-cdiv enabled too.
TEST_F(SCSCFTest, TerminatingDiversionExternalOrigCdiv)
{
  // Set up caller info, including one iFC.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Set up callee info, including one iFC.
  HSSConnection::irs_info irs_info_2;
  setup_irs_info(irs_info_2, "6505501234", "homedomain");
  set_ifc(irs_info_2, "sip:6505501234@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  expect_get_subscriber_state(irs_info_2, "sip:6505501234@homedomain", 2);

  _hss_connection->set_result("/impu/sip%3A6505501234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  TransportFlow tpBono(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpExternal(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.9.8.7", 5060);
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345";
  msg._to = "6505501234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505501234@homedomain";
  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1 (as terminating AS for Bob)
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505501234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505501234@homedomain>;sescase=term;regstate=reg"));

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp1 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp1, &tpAS);

  // ---------- AS1 turns it around
  // (acting as routing B2BUA by adding a Via, removing the top Route and changing the target)
  const pj_str_t STR_VIA = pj_str("Via");
  pjsip_via_hdr* via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (via_hdr)
  {
    via_hdr->rport_param = via_hdr->sent_by.port;
  }
  via_hdr = pjsip_via_hdr_create(current_txdata()->pool);
  via_hdr->transport = pj_str("FAKE_UDP");
  via_hdr->sent_by.host = pj_str("1.2.3.4");
  via_hdr->sent_by.port = 56789;
  via_hdr->rport_param = 0;
  via_hdr->branch_param = pj_str("z9hG4bK1234567890");
  pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)via_hdr);
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  ((pjsip_sip_uri*)out->line.req.uri)->host = pj_str("ut2.cw-ngv.com");
  inject_msg(out, &tpAS);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1 (as originating-cdiv AS for Bob)
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  r1 = ReqMatcher("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505501234@ut2.cw-ngv.com", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig;service=scscf>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505501234@homedomain>;orig-cdiv"));

  // ---------- AS2 sends a 100 Trying to indicate it has received the request.
  string fresp2 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp2, &tpAS);

  // ---------- AS1 turns it around
  // (acting as routing B2BUA by adding a Via, removing the top Route and changing the target)
  via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (via_hdr)
  {
    via_hdr->rport_param = via_hdr->sent_by.port;
  }
  via_hdr = pjsip_via_hdr_create(current_txdata()->pool);
  via_hdr->transport = pj_str("FAKE_UDP");
  via_hdr->sent_by.host = pj_str("1.2.3.4");
  via_hdr->sent_by.port = 56789;
  via_hdr->rport_param = 0;
  via_hdr->branch_param = pj_str("z9hG4bK1234567891"); // Must differ from previous branch
  pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)via_hdr);
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  ((pjsip_sip_uri*)out->line.req.uri)->host = pj_str("ut.cw-ngv.com");
  inject_msg(out, &tpAS);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed externally
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpExternal.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505501234@ut.cw-ngv.com", r1.uri());
  EXPECT_EQ("", get_headers(out, "Route"));

  // ---------- Externally accepted with 200.
  string fresp = respond_to_txdata(current_txdata(), 200);
  free_txdata();
  inject_msg(fresp, &tpExternal);

  // 200 OK goes back to AS1 (orig-cdiv)
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);

  // ---------- AS1 forwards 200 (stripping via)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  free_txdata();

  // 200 OK goes back to AS1 (terminating)
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);

  // ---------- AS1 forwards 200 (stripping via)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  free_txdata();

  // 200 OK goes back to bono
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  //  We should have tracked the session setup time for just the original session.
  EXPECT_EQ(1, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_audio_session_setup_time_tbl)->_count);
  EXPECT_EQ(0, ((SNMP::FakeEventAccumulatorTable*)_scscf_sproutlet->_video_session_setup_time_tbl)->_count);
}


// This tests if the SCSCF receives an INVITE with a P-Profile-Key header, it
// sends requests to the SM with the correct wildcard entry.
TEST_F(SCSCFTest, TestInvitePProfileKey)
{
  SCOPED_TRACE("");
  std::string wildcard = "sip:650![0-9]+!@homedomain";

  // Set up callee info.
  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings, "6515551000", "homedomain");
  EXPECT_CALL(*_sm, get_subscriber_state(IrsQueryWithWildcard("sip:650![0-9]+!@homedomain"), _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  expect_get_bindings(bindings, "sip:6515551000@homedomain"); // Expect bindings to be looked up with the URI set in the irs_info.

  SCSCFMessage msg;
  msg._route = "Route: <sip:sprout.homedomain>";
  msg._extra = "P-Profile-Key: <" + PJUtils::escape_string_for_uri(wildcard) + ">";
  msg._to = "6515551000";
  msg._requri = "sip:6515551000@homedomain";
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs);
}


TEST_F(SCSCFTest, TestAddSecondTelPAIHdr)
{
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  add_sp_identity(irs_info_1, "tel:6505551000");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Set up callee info.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  expect_get_callee_info(irs_info_2, bindings);

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  SCSCFMessage msg;
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "P-Asserted-Identity: Andy <sip:6505551000@homedomain>";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("P-Asserted-Identity", "P-Asserted-Identity: \"Andy\" <sip:6505551000@homedomain>", "P-Asserted-Identity: \"Andy\" <tel:6505551000>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs);
}


// Checks that a tel URI alias is added to the P-Asserted-Identity header even
// when the username is different from the sip URI.
TEST_F(SCSCFTest, TestAddSecondTelPAIHdrWithAlias)
{
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  add_sp_identity(irs_info_1, "tel:6505551001");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Set up callee info.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  expect_get_callee_info(irs_info_2, bindings);

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  SCSCFMessage msg;
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "P-Asserted-Identity: Andy <sip:6505551000@homedomain>";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("P-Asserted-Identity", "P-Asserted-Identity: \"Andy\" <sip:6505551000@homedomain>", "P-Asserted-Identity: \"Andy\" <tel:6505551001>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs);
}


// Checks if we have multiple aliases and none of them matches the SIP URI
// supplied that we add the first tel URI on the alias list to the
// P-Asserted-Identity header.
TEST_F(SCSCFTest, TestAddSecondTelPAIHdrMultipleAliasesNoMatch)
{
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  add_sp_identity(irs_info_1, "tel:6505551003");
  add_sp_identity(irs_info_1, "tel:6505551002");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Set up callee info.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  expect_get_callee_info(irs_info_2, bindings);

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  SCSCFMessage msg;
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "P-Asserted-Identity: Andy <sip:6505551000@homedomain>";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("P-Asserted-Identity", "P-Asserted-Identity: \"Andy\" <sip:6505551000@homedomain>", "P-Asserted-Identity: \"Andy\" <tel:6505551003>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs);
}


// Checks if we have multiple aliases and one of them matches the SIP URI
// supplied that we add the matching alias even if it's not the first on the
// alias list.
TEST_F(SCSCFTest, TestAddSecondTelPAIHdrMultipleAliases)
{
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  add_sp_identity(irs_info_1, "tel:6505551003");
  add_sp_identity(irs_info_1, "tel:6505551000");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Set up callee info.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  expect_get_callee_info(irs_info_2, bindings);

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  SCSCFMessage msg;
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "P-Asserted-Identity: Andy <sip:6505551000@homedomain>";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("P-Asserted-Identity", "P-Asserted-Identity: \"Andy\" <sip:6505551000@homedomain>", "P-Asserted-Identity: \"Andy\" <tel:6505551000>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs);
}


TEST_F(SCSCFTest, TestAddSecondSIPPAIHdr)
{
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  add_sp_identity(irs_info_1, "tel:6505551000");
  expect_get_subscriber_state(irs_info_1, "tel:6505551000");

  // Set up callee info.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  expect_get_callee_info(irs_info_2, bindings);

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  SCSCFMessage msg;
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "P-Asserted-Identity: Andy <tel:6505551000>";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("P-Asserted-Identity", "P-Asserted-Identity: \"Andy\" <tel:6505551000>", "P-Asserted-Identity: \"Andy\" <sip:6505551000@homedomain;user=phone>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs);
}


// Checks that a matching SIP URI is added to the P-Asserted-Identity header
// even when there is no alias of the original tel URI.
TEST_F(SCSCFTest, TestAddSecondSIPPAIHdrNoSIPUri)
{
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "", false, true);
  expect_get_subscriber_state(irs_info_1, "tel:6505551000");

  // Set up callee info.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  expect_get_callee_info(irs_info_2, bindings);

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  SCSCFMessage msg;
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "P-Asserted-Identity: Andy <tel:6505551000>";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("P-Asserted-Identity", "P-Asserted-Identity: \"Andy\" <tel:6505551000>", "P-Asserted-Identity: \"Andy\" <sip:6505551000@homedomain;user=phone>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs);
}


TEST_F(SCSCFTest, TestTwoPAIHdrsAlready)
{
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  add_sp_identity(irs_info_1, "tel:6505551000");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Set up callee info.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  expect_get_callee_info(irs_info_2, bindings);

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  SCSCFMessage msg;
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "P-Asserted-Identity: Andy <sip:6505551000@homedomain>\nP-Asserted-Identity: Andy <tel:6505551111>";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("P-Asserted-Identity", "P-Asserted-Identity: \"Andy\" <sip:6505551000@homedomain>", "P-Asserted-Identity: \"Andy\" <tel:6505551111>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs);
}


TEST_F(SCSCFTest, TestNoPAIHdrs)
{
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  add_sp_identity(irs_info_1, "tel:6505551000");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Set up callee info.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  expect_get_callee_info(irs_info_2, bindings);

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  SCSCFMessage msg;
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("P-Asserted-Identity"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs);
}


TEST_F(SCSCFTest, TestPAIHdrODIToken)
{
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  add_sp_identity(irs_info_1, "tel:6505551000");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Set up callee info.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  expect_get_callee_info(irs_info_2, bindings);

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  SCSCFMessage msg;
  msg._route = "Route: <sip:odi_dgds89gd8gdshds@127.0.0.1;orig>";
  msg._extra = "P-Asserted-Identity: Andy <sip:6505551000@homedomain>";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("P-Asserted-Identity", "P-Asserted-Identity: \"Andy\" <sip:6505551000@homedomain>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs);
}


TEST_F(SCSCFTest, TestNoSecondPAIHdrTerm)
{
  SCOPED_TRACE("");

  // Set up callee info.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  expect_get_callee_info(irs_info_2, bindings);

  SCSCFMessage msg;
  msg._extra = "P-Asserted-Identity: Andy <sip:6505551000@homedomain>";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("P-Asserted-Identity", "P-Asserted-Identity: \"Andy\" <sip:6505551000@homedomain>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs);
}


/// Test handling of 430 Flow Failed response
TEST_F(SCSCFTest, FlowFailedResponse)
{
  // Set up callee info.
  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_irs_info(irs_info, "6505550231", "homedomain");
  set_ifc(irs_info, "sip:6505550231@homedomain", 1, {"<Method>REGISTER</Method>"}, "sip:1.2.3.4:56789;transport=UDP", 0, "1");
  setup_binding(bindings, "sip:6505550231@homedomain", "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213");
  expect_get_callee_info(irs_info, bindings, "sip:6505550231@homedomain");

  TransportFlow tpBono(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpExternal(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.9.8.7", 5060);
  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345";
  msg._to = "65055502314@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain>";
  msg._requri = "sip:6505550231@homedomain";
  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed externally
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("INVITE").matches(out));
  tpExternal.expect_target(current_txdata(), false);

  // Expect the SCSCF sproutlet to delete the binding after receiving the 430
  // response.
  EXPECT_CALL(*_sm, remove_bindings("sip:6505550231@homedomain", _, _, _, _))
    .WillOnce(Return(HTTP_OK));

  // Send 430 Flow Failed response.
  string fresp = respond_to_current_txdata(430);
  free_txdata();
  inject_msg(fresp);

  // Sprout ACKs the response.
  ASSERT_EQ(2, txdata_count());
  ReqMatcher("ACK").matches(current_txdata()->msg);
  free_txdata();

  // The subscriber manager (which is mocked out in this test) would cover
  // sending a third-party deREGISTER to AS, and deregister to the HSS.

  // Catch the forwarded 430 response.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(430).matches(out);
  free_txdata();

  // UE ACKs the response.
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpBono);
}


/// Test handling of 430 Flow Failed response, where there is an error removing
/// the bindings. This error is caught and processing continues as if it hadn't
/// happened, but the fact that the bindings may still be present is logged.
TEST_F(SCSCFTest, FlowFailedResponseBindingRemovalFails)
{
  // Set up callee info.
  HSSConnection::irs_info irs_info;
  Bindings bindings_1;
  setup_irs_info(irs_info, "6505550231", "homedomain");
  set_ifc(irs_info, "sip:6505550231@homedomain", 1, {"<Method>REGISTER</Method>"}, "sip:1.2.3.4:56789;transport=UDP", 0, "1");
  setup_binding(bindings_1, "sip:6505550231@homedomain", "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213");
  expect_get_callee_info(irs_info, bindings_1, "sip:6505550231@homedomain");

  TransportFlow tpBono(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpExternal(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.9.8.7", 5060);
  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345";
  msg._to = "65055502314@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain>";
  msg._requri = "sip:6505550231@homedomain";
  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed externally
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("INVITE").matches(out));
  tpExternal.expect_target(current_txdata(), false);

  // Expect the SCSCF sproutlet to delete the binding after receiving the 430
  // response. Return a bindings object containing bindings alongside the
  // HTTP_NOT FOUND, to check this memory will still be deleted correctly.
  Bindings bindings_2;
  setup_binding(bindings_2);
  EXPECT_CALL(*_sm, remove_bindings("sip:6505550231@homedomain", _, _, _, _))
    .WillOnce(DoAll(SetArgReferee<3>(bindings_2),
                    Return(HTTP_NOT_FOUND)));

  // Send 430 Flow Failed response.
  string fresp = respond_to_current_txdata(430);
  free_txdata();
  inject_msg(fresp);

  // Sprout ACKs the response.
  ASSERT_EQ(2, txdata_count());
  ReqMatcher("ACK").matches(current_txdata()->msg);
  free_txdata();

  // The subscriber manager (which is mocked out in this test) would cover
  // sending a third-party deREGISTER to AS, and deregister to the HSS.

  // Catch the forwarded 430 response.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(430).matches(out);
  free_txdata();

  // UE ACKs the response.
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpBono);
}


// Check that if an AS supplies a preloaded route when routing back to the
// S-CSCF, we follow the route and record route ourselves. This is needed for
// routing to non-registering PBXs, where the AS preloads the path to the PBX.

// Check that sprout follows a preloaded route when the AS has changed the
// request URI.
TEST_F(SCSCFTest, PreloadedRouteChangedReqUri)
{
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551234", "homedomain");
  set_ifc(irs_info, "sip:6505551234@homedomain", 0, {"<Method>INVITE</Method>", "<SessionCase>1</SessionCase><!-- terminating-registered -->"}, "sip:5.2.3.4:56787;transport=UDP");
  expect_get_subscriber_state(irs_info, "sip:6505551234@homedomain", 2);

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "5.2.3.4", 56787);
  TransportFlow tpPreloadedRoute(TransportFlow::Protocol::TCP, stack_data.scscf_port, "3.3.3.3", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1 (as terminating AS for Bob)
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp1 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp1, &tpAS1);

  // ---------- AS1 sends the request back to the S-CSCF. It changes the
  // request URI and pre-loads a route.
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }

  char preloaded_route[80] = "sip:3.3.3.3:5060;transport=TCP;lr";
  pjsip_route_hdr* hroute = pjsip_route_hdr_create(current_txdata()->pool);
  hroute->name_addr.uri =
    (pjsip_uri*)pjsip_parse_uri(current_txdata()->pool,
                                preloaded_route,
                                strlen(preloaded_route),
                                0);
  pjsip_msg_add_hdr(out, (pjsip_hdr*)hroute);

  ((pjsip_sip_uri*)out->line.req.uri)->user = pj_str("newtarget");
  ((pjsip_sip_uri*)out->line.req.uri)->host = pj_str("2.2.2.2");

  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to final destination (to preloaded route)
  SCOPED_TRACE("INVITE (4)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpPreloadedRoute.expect_target(current_txdata(), false);
  // Sprout has preserved the target and route.
  EXPECT_EQ("sip:newtarget@2.2.2.2", r1.uri());
  EXPECT_EQ(get_headers(out, "Route"),
            "Route: <sip:3.3.3.3:5060;transport=TCP;lr>");
  // Sprout has also record-routed itself.
  EXPECT_THAT(get_headers(out, "Record-Route"),
              MatchesRegex("Record-Route: <sip:scscf.sprout.homedomain:5058;.*billing-role=charge-term.*>"));

  EXPECT_EQ(1, ((SNMP::FakeCounterTable*)_scscf_sproutlet->_routed_by_preloaded_route_tbl)->_count);
  free_txdata();
}


// Check that sprout follows a preloaded route when the AS has NOT changed the
// request URI.
TEST_F(SCSCFTest, PreloadedRoutePreserveReqUri)
{
  // Setup info about the callee.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551234", "homedomain");
  set_ifc(irs_info, "sip:6505551234@homedomain", 0, {"<Method>INVITE</Method>", "<SessionCase>1</SessionCase><!-- terminating-registered -->"}, "sip:5.2.3.4:56787;transport=UDP");
  expect_get_subscriber_state(irs_info, "sip:6505551234@homedomain", 2);

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "5.2.3.4", 56787);
  TransportFlow tpPreloadedRoute(TransportFlow::Protocol::TCP, stack_data.scscf_port, "3.3.3.3", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp1 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp1, &tpAS1);

  // INVITE passed on to AS1 (as terminating AS for Bob)
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());

  // ---------- AS1 sends the request back top the S-CSCF. It preserves the
  // request URI but pre-loads a route.
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }

  char preloaded_route[80] = "sip:3.3.3.3:5060;transport=TCP;lr";
  pjsip_route_hdr* hroute = pjsip_route_hdr_create(current_txdata()->pool);
  hroute->name_addr.uri =
    (pjsip_uri*)pjsip_parse_uri(current_txdata()->pool,
                                preloaded_route,
                                strlen(preloaded_route),
                                0);
  pjsip_msg_add_hdr(out, (pjsip_hdr*)hroute);

  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to final destination (to preloaded route)
  SCOPED_TRACE("INVITE (4)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpPreloadedRoute.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  // Sprout has preserved the target and route.
  EXPECT_EQ(get_headers(out, "Route"),
            "Route: <sip:3.3.3.3:5060;transport=TCP;lr>");
  // Sprout has also record-routed itself.
  EXPECT_THAT(get_headers(out, "Record-Route"),
              MatchesRegex("Record-Route: <sip:scscf.sprout.homedomain:5058;.*billing-role=charge-term.*>"));

  EXPECT_EQ(1, ((SNMP::FakeCounterTable*)_scscf_sproutlet->_routed_by_preloaded_route_tbl)->_count);
  free_txdata();
}


// Check that sprout follows a preloaded route even when there are more ASs in
// the chain.
TEST_F(SCSCFTest, PreloadedRouteNotLastAs)
{
  // Setup info about the callee.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551234", "homedomain");
  ServiceProfileBuilder service_profile = ServiceProfileBuilder()
    .addIfc(0, {"<Method>INVITE</Method>", "<SessionCase>1</SessionCase><!-- terminating-registered -->"}, "sip:5.2.3.4:56787;transport=UDP")
    .addIfc(1, {"<Method>INVITE</Method>", "<SessionCase>1</SessionCase><!-- terminating-registered -->"}, "sip:1.2.3.4:56787;transport=UDP");
  set_ifcs_from_service_profile(irs_info, service_profile, "sip:6505551234@homedomain");
  expect_get_subscriber_state(irs_info, "sip:6505551234@homedomain", 2);

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "5.2.3.4", 56787);
  TransportFlow tpPreloadedRoute(TransportFlow::Protocol::TCP, stack_data.scscf_port, "3.3.3.3", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1 (as terminating AS for Bob)
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp1 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp1, &tpAS1);

  // ---------- AS1 sends the request back top the S-CSCF. It changes the
  // request URI and pre-loads a route.
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }

  char preloaded_route[80] = "sip:3.3.3.3:5060;transport=TCP;lr";
  pjsip_route_hdr* hroute = pjsip_route_hdr_create(current_txdata()->pool);
  hroute->name_addr.uri =
    (pjsip_uri*)pjsip_parse_uri(current_txdata()->pool,
                                preloaded_route,
                                strlen(preloaded_route),
                                0);
  pjsip_msg_add_hdr(out, (pjsip_hdr*)hroute);

  // Re-target the request to a new user. Use the domain "newdomain" as this
  // will be routed off net by the BGCF.
  ((pjsip_sip_uri*)out->line.req.uri)->user = pj_str("newtarget");
  ((pjsip_sip_uri*)out->line.req.uri)->host = pj_str("2.2.2.2");
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to final destination (to preloaded route)
  SCOPED_TRACE("INVITE (4)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpPreloadedRoute.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:newtarget@2.2.2.2", r1.uri());
  // Sprout has preserved the target and route.
  EXPECT_EQ(get_headers(out, "Route"),
            "Route: <sip:3.3.3.3:5060;transport=TCP;lr>");
  // Sprout has also record-routed itself.
  EXPECT_THAT(get_headers(out, "Record-Route"),
              MatchesRegex("Record-Route: <sip:scscf.sprout.homedomain:5058;.*billing-role=charge-term.*>"));

  EXPECT_EQ(1, ((SNMP::FakeCounterTable*)_scscf_sproutlet->_routed_by_preloaded_route_tbl)->_count);
  free_txdata();
}


TEST_F(SCSCFTest, AutomaticRegistration)
{
  SCOPED_TRACE("");

  // Create an originating request that has a proxy-authorization header and
  // requires automatic registration. The To domain is not "homedomain", so no
  // terminating services will be applied, as the BGCF will route off of sprout.
  SCSCFMessage msg;
  msg._to = "newuser";
  msg._todomain = "domainvalid";
  msg._route = "Route: <sip:sprout.homedomain;orig;auto-reg>";
  msg._extra = "Proxy-Authorization: Digest username=\"kermit\", realm=\"homedomain\", uri=\"sip:6505551000@homedomain\", algorithm=MD5";

  // Set caller info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  // The SM should be invoked with a request type of "reg" and with the right
  // private ID.
  EXPECT_CALL(*_sm, get_subscriber_state(AllOf(IrsQueryWithPrivateId("kermit"),
                                               IrsQueryWithReqType(HSSConnection::REG)), _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info_1),
                    Return(HTTP_OK)));

  add_host_mapping("domainvalid", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Route", "Route: <sip:10.0.0.1:5060;transport=TCP;lr>"));
  doSuccessfulFlow(msg, testing::MatchesRegex("sip:newuser@domainvalid"), hdrs);
}


TEST_F(SCSCFTest, AutomaticRegistrationDerivedIMPI)
{
  SCOPED_TRACE("");

  // Create an originating request that requires automatic registration.
  // The To domain is not "homedomain", so no terminating services will be
  // applied, as the BGCF will route off of sprout.
  SCSCFMessage msg;
  msg._to = "newuser";
  msg._todomain = "domainvalid";
  msg._route = "Route: <sip:sprout.homedomain;orig;auto-reg>";

  // Set caller info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  // The SM should be invoked with a request type of "reg" and with the right
  // private ID. No Proxy-Authorization present, so derive the IMPI from the
  // IMPU.
  EXPECT_CALL(*_sm, get_subscriber_state(AllOf(IrsQueryWithPrivateId("6505551000@homedomain"),
                                               IrsQueryWithReqType(HSSConnection::REG)), _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info_1),
                    Return(HTTP_OK)));

  add_host_mapping("domainvalid", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Route", "Route: <sip:10.0.0.1:5060;transport=TCP;lr>"));
  doSuccessfulFlow(msg, testing::MatchesRegex("sip:newuser@domainvalid"), hdrs);
}


TEST_F(SCSCFTest, TestSessionExpires)
{
  SCOPED_TRACE("");

  // Set up callee info.
  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings);
  expect_get_callee_info(irs_info, bindings);

  // Send an INVITE where the client supports session timers. This means that
  // if the server does not support timers, there should still be a
  // Session-Expires header on the response.
  //
  // Most of the session timer logic is tested in
  // `session_expires_helper_test.cpp`. This is just to check that the S-CSCF
  // invokes the logic correctly.
  SCSCFMessage msg;
  msg._extra = "Session-Expires: 600\r\nSupported: timer";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Session-Expires", "Session-Expires:.*"));
  list<HeaderMatcher> rsp_hdrs;
  rsp_hdrs.push_back(HeaderMatcher("Session-Expires", "Session-Expires: .*"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs, true, rsp_hdrs);
}


TEST_F(SCSCFTest, TestSessionExpiresInDialog)
{
  SCOPED_TRACE("");

  // Send an UPDATE in-dialog request to which we should always add RR and SE.
  // Then check that if the UAS strips the SE, that Sprout tells the UAC to be
  // the refresher. This ensures that our response processing is correct.
  SCSCFMessage msg;
  msg._extra = "Supported: timer";
  msg._in_dialog = true;

  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Record-Route"));
  hdrs.push_back(HeaderMatcher("Session-Expires", "Session-Expires:.*"));

  list<HeaderMatcher> rsp_hdrs;
  rsp_hdrs.push_back(HeaderMatcher("Session-Expires", "Session-Expires:.*;refresher=uac"));
  rsp_hdrs.push_back(HeaderMatcher("Record-Route"));

  doSuccessfulFlow(msg, testing::MatchesRegex(".*homedomain.*"), hdrs, true, rsp_hdrs);
}


// The following five tests use logging to check if different billing roles are
// found in in_dialog message. It's a fragile way of testing, but we can't check
// the real effect of billing role in ACR as the ACR response is faked.
TEST_F(SCSCFTest, TestSessionExpiresInDialogBillingTerm)
{
  SCSCFMessage msg;
  msg._in_dialog = true;
  msg._route = "Route: <sip:homedomain;transport=tcp;lr;billing-role=charge-term>";
  list<HeaderMatcher> hdrs;
  CapturingTestLogger log;

  doSuccessfulFlow(msg, testing::MatchesRegex(".*homedomain.*"), hdrs);
  EXPECT_TRUE(log.contains("Charging role is terminating"));
}


TEST_F(SCSCFTest, TestSessionExpiresInDialogBillingOrig)
{
  SCSCFMessage msg;
  msg._in_dialog = true;
  msg._route = "Route: <sip:homedomain;transport=tcp;lr;billing-role=charge-orig>";
  list<HeaderMatcher> hdrs;
  CapturingTestLogger log;

  doSuccessfulFlow(msg, testing::MatchesRegex(".*homedomain.*"), hdrs);
  EXPECT_TRUE(log.contains("Charging role is originating"));
}


TEST_F(SCSCFTest, TestSessionExpiresInDialogBillingNone)
{
  SCSCFMessage msg;
  msg._in_dialog = true;
  msg._route = "Route: <sip:homedomain;transport=tcp;lr;billing-role=charge-none>";
  list<HeaderMatcher> hdrs;
  CapturingTestLogger log;

  doSuccessfulFlow(msg, testing::MatchesRegex(".*homedomain.*"), hdrs);
  EXPECT_TRUE(log.contains("Charging role is none"));
}


TEST_F(SCSCFTest, TestSessionExpiresInDialogBillingUnknown)
{
  SCSCFMessage msg;
  msg._in_dialog = true;
  msg._route = "Route: <sip:homedomain;transport=tcp;lr;billing-role=unknown-string>";
  list<HeaderMatcher> hdrs;
  CapturingTestLogger log;

  doSuccessfulFlow(msg, testing::MatchesRegex(".*homedomain.*"), hdrs);
  EXPECT_TRUE(log.contains("Unknown charging role"));
}


TEST_F(SCSCFTest, TestSessionExpiresInDialogBillingNotFound)
{
  SCSCFMessage msg;
  msg._in_dialog = true;
  msg._route = "Route: <sip:homedomain;transport=tcp;lr>";
  list<HeaderMatcher> hdrs;
  CapturingTestLogger log;

  doSuccessfulFlow(msg, testing::MatchesRegex(".*homedomain.*"), hdrs);
  EXPECT_TRUE(log.contains("No charging role in Route header, assume originating"));
}


TEST_F(SCSCFTest, TestSessionExpiresInDialogRouteHeaderEmpty)
{
  SCSCFMessage msg;
  msg._in_dialog = true;
  msg._route = "";
  list<HeaderMatcher> hdrs;
  CapturingTestLogger log;

  doSuccessfulFlow(msg, testing::MatchesRegex(".*homedomain.*"), hdrs);
  EXPECT_TRUE(log.contains("Cannot determine charging role as no Route header, assume originating"));
}


TEST_F(SCSCFTest, TestSessionExpiresWhenNoRecordRoute)
{
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  ServiceProfileBuilder service_profile = ServiceProfileBuilder()
    .addIfc(2, {"<Method>INVITE</Method>"}, "sip:4.2.3.4:56788;transport=UDP")
    .addIfc(1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  set_ifcs_from_service_profile(irs_info_1, service_profile, "sip:6505551000@homedomain");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpAS2(TransportFlow::Protocol::UDP, stack_data.scscf_port, "4.2.3.4", 56788);

  // Send an INVITE
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";
  msg._method = "INVITE";

  pjsip_msg* out;
  inject_msg(msg.get_request());

  // INVITE passed to AS1
  SCOPED_TRACE("INVITE (1)");
  ASSERT_EQ(2, txdata_count());
  free_txdata();
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  ASSERT_TRUE(!get_headers(out, "Record-Route").empty());
  ASSERT_TRUE(!get_headers(out, "Session-Expires").empty());

  // AS proxies INVITE back.
  const pj_str_t STR_ROUTE = pj_str("Route");
  const pj_str_t STR_REC_ROUTE = pj_str("Record-Route");
  const pj_str_t STR_SESS_EXP = pj_str("Session-Expires");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  pjsip_hdr* rr_hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_REC_ROUTE, NULL);
  pjsip_hdr* se_hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_SESS_EXP, NULL);
  pj_list_erase(rr_hdr);
  pj_list_erase(se_hdr);

  if (hdr)
  {
    pj_list_erase(hdr);
  }

  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS2
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  tpAS2.expect_target(current_txdata(), false);

  // Should not RR between AS's and therefore shouldn't SE
  ASSERT_TRUE(get_headers(out, "Record-Route").empty());
  ASSERT_TRUE(get_headers(out, "Session-Expires").empty());
}


// Test that getting a 503 error from the subscriber manager when looking up
// iFCs results in sprout sending a 504 error.
TEST_F(SCSCFTest, HSSTimeoutOnPutRegData)
{
  // Send originating INVITE
  SCSCFMessage msg;
  msg._route = "Route: <sip:sprout.homedomain;orig>";

  // The SM will return a 503 when looking up the iFCs.
  EXPECT_CALL(*_sm, get_subscriber_state(_, _, _))
    .WillOnce(Return(HTTP_SERVER_UNAVAILABLE));

  inject_msg(msg.get_request());

  // 100 Trying goes out
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  free_txdata();

  // Followed by a 504
  out = current_txdata()->msg;
  EXPECT_EQ(504, out->line.status.code);
  EXPECT_EQ("Server Timeout", str_pj(out->line.status.reason));
}


// Test that a failure to get iFCs due to a 503 error from the subscriber
// manager during Call Diversion results in sprout sending a 504 to the Call
// Diversion AS.
//
// The calls to the subscriber manager, and the returned codes, are:
//  - SM queries HSS for term. iFCs for orig. callee - returns 200 OK
//               -- IMAGINE ISSUE TAKES DOWN HSS --
//  - SM queries the HSS to determine if the call was retargeted - returns 503
//    error. Without anything to prove otherwise, scscf assumes retarget happened
//  - query HSS for orig. iFCs for orig. callee - returns 503
//
TEST_F(SCSCFTest, HSSTimeoutOnCdiv)
{
  // Set up callee info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551234", "homedomain");
  ServiceProfileBuilder service_profile = ServiceProfileBuilder()
    .addIfc(2, {"<SessionCase>4</SessionCase><!-- originating-cdiv -->", "<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP")
    .addIfc(0, {"<Method>INVITE</Method>", "<SessionCase>1</SessionCase><!-- terminating-registered -->"}, "sip:5.2.3.4:56787;transport=UDP");
  set_ifcs_from_service_profile(irs_info, service_profile, "sip:6505551234@homedomain");
  // First call succeeds, second and third calls fail.
  EXPECT_CALL(*_sm, get_subscriber_state(IrsQueryWithPublicId("sip:6505551234@homedomain"), _, _))
    .Times(3)
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)))
    .WillOnce(Return(HTTP_SERVER_UNAVAILABLE))
    .WillOnce(Return(HTTP_SERVER_UNAVAILABLE));

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "5.2.3.4", 56787);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1 (as terminating AS for Bob)
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551234@homedomain>;sescase=term;regstate=reg"));

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp1 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp1, &tpAS1);

  // ---------- AS1 turns it around (acting as routing B2BUA by changing the target)
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  ((pjsip_sip_uri*)out->line.req.uri)->user = pj_str("6505555678");
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // Followed by a 504 (since the iFC lookup set up at the start of the test has
  // returned a 503).
  out = current_txdata()->msg;
  RespMatcher(504).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();
}


// Test that a failure to get iFCs due to a 404 error from the subscriber
// manager during Call Diversion results in sprout sending a 404 to the Call
// Diverstion AS.
//
// The calls to the subscriber manager, and the returned codes, are:
//  - SM queries HSS for term. iFCs for orig. callee - returns 200 OK
//               -- IMAGINE ISSUE TAKES DOWN HSS --
//  - SM queries the HSS to determine if the call was retargeted - returns 404
//    error. Without anything to prove otherwise, scscf assumes retarget happened
//  - query HSS for orig. iFCs for orig. callee - returns 404
//
TEST_F(SCSCFTest, HSSNotFoundOnCdiv)
{
  // Set up callee info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551234", "homedomain");
  ServiceProfileBuilder service_profile = ServiceProfileBuilder()
    .addIfc(2, {"<SessionCase>4</SessionCase><!-- originating-cdiv -->", "<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP")
    .addIfc(0, {"<Method>INVITE</Method>", "<SessionCase>1</SessionCase><!-- terminating-registered -->"}, "sip:5.2.3.4:56787;transport=UDP");
  set_ifcs_from_service_profile(irs_info, service_profile, "sip:6505551234@homedomain");
  // First call succeeds, second and third calls fail.
  EXPECT_CALL(*_sm, get_subscriber_state(IrsQueryWithPublicId("sip:6505551234@homedomain"), _, _))
    .Times(3)
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)))
    .WillOnce(Return(HTTP_NOT_FOUND))
    .WillOnce(Return(HTTP_NOT_FOUND));

  _hss_connection->set_result("/impu/sip%3A6505555678%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "5.2.3.4", 56787);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1 (as terminating AS for Bob)
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;service=scscf>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551234@homedomain>;sescase=term;regstate=reg"));

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp1 = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp1, &tpAS1);

  // ---------- AS1 turns it around (acting as routing B2BUA by changing the target)
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  ((pjsip_sip_uri*)out->line.req.uri)->user = pj_str("6505555678");
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  free_txdata();

  // Followed by a 404 due to the iFC lookup returning an error (set up earlier
  // in the test).
  out = current_txdata()->msg;
  RespMatcher(404).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();
}


TEST_F(SCSCFTest, TestCallerNotBarred)
{
  SCOPED_TRACE("");

  // Set up caller info.
  // The primary IMPU is barred, but this shouldn't stop us making a call since
  // we are calling from one of the other IMPUs.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551001", "homedomain", true);  // This IMPU is barred.
  add_sp_identity(irs_info_1, "sip:6505551000@homedomain");    // This IMPU is unbarred.
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Set up callee info.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  expect_get_callee_info(irs_info_2, bindings);

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  SCSCFMessage msg;
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs);
}


TEST_F(SCSCFTest, TestCalleeNotBarred)
{
  SCOPED_TRACE("");

  // Set up callee info.
  // Include barred primary IMPU ("6505551235"), and another unbarred IMPU
  // ("6505551234").
  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_irs_info(irs_info, "6505551235", "homedomain", true);  // This IMPU is barred.
  add_sp_identity(irs_info, "sip:6505551234@homedomain");    // This IMPU is unbarred.
  setup_binding(bindings, "sip:6505551235@homedomain");
  expect_get_callee_info(irs_info, bindings);

  SCSCFMessage msg;
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs);
}


// Test emergency registrations receive calls when barred.
TEST_F(SCSCFTest, TestEmergencyCalleeNotBarred)
{
  SCOPED_TRACE("");

  // Set up callee info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551234", "homedomain", true); // This IMPU is barred.
  set_ifc(irs_info, "sip:6505551234@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP", 1);
  expect_get_subscriber_state(irs_info, "sip:6505551234@homedomain");
  Bindings bindings;
  setup_binding(bindings, "sip:6505551234@homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;sos;ob", true); // Add an emergency binding.
  // The S-CSCF sproutlet owns the bindings, and will free them. So create a
  // duplicate bindings object to pass back on the second call.
  Bindings bindings_2;
  setup_binding(bindings_2, "sip:6505551234@homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;sos;ob", true);
  // Expect two calls to get bindings, one to check for any emergency
  // registrations after it is realised the served user is barred, and one to
  // find the target to route to.
  EXPECT_CALL(*_sm, get_bindings("sip:6505551234@homedomain", _, _))
    .Times(2)
    .WillOnce(DoAll(SetArgReferee<1>(bindings),
                    Return(HTTP_OK)))
    .WillOnce(DoAll(SetArgReferee<1>(bindings_2),
                    Return(HTTP_OK)));

  SCSCFMessage msg;
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs);
}


// Test only emergency registrations in an implicit registration set receive
// calls to barred IMPUs.
TEST_F(SCSCFTest, TestEmergencyMultipleBindings)
{
  SCOPED_TRACE("");

  // Set up callee info. It includes a barred public id
  // "sip:6505551234@homedomain", and an emergency binding as well.
  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_irs_info(irs_info, "6505551234", "homedomain", true); // This IMPU is barred.
  set_ifc(irs_info, "sip:6505551234@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP", 1);
  setup_binding(bindings, "sip:6505551234@homedomain", "sip:fowertreetoowun@10.114.61.213:5061;transport=tcp;ob");
  setup_binding(bindings, "sip:6505551234@homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;sos;ob", true); // Add an emergency binding.
  expect_get_subscriber_state(irs_info, "sip:6505551234@homedomain");
  // Expect two calls to get bindings, one to check for any emergency
  // registrations after it is realised the served user is barred, and one to
  // find the target to route to.
  // The S-CSCF sproutlet owns the bindings, and will free them. So create a
  // duplicate bindings object to pass back on the second call.
  Bindings bindings_2;
  setup_binding(bindings_2, "sip:6505551234@homedomain", "sip:fowertreetoowun@10.114.61.213:5061;transport=tcp;ob");
  setup_binding(bindings_2, "sip:6505551234@homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;sos;ob", true);
  EXPECT_CALL(*_sm, get_bindings("sip:6505551234@homedomain", _, _))
    .Times(2)
    .WillOnce(DoAll(SetArgReferee<1>(bindings),
                    Return(HTTP_OK)))
    .WillOnce(DoAll(SetArgReferee<1>(bindings_2),
                    Return(HTTP_OK)));

  SCSCFMessage msg;
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*sos.*"), hdrs);
}


// Check that a request with no matching iFCs is rejected on originating side.
TEST_F(SCSCFTest, NoMatchingiFCsRejectOrig)
{
  _scscf_sproutlet->_ifc_configuration._reject_if_no_matching_ifcs = true;

  // Set up caller info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551000", "homedomain");
  set_ifc(irs_info, "sip:6505551000@homedomain", 0, {"<Method>PUBLISH</Method>"}, "sip:DUMMY_AS");
  expect_get_subscriber_state(irs_info, "sip:6505551000@homedomain");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._to = "6505551234@homedomain";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  free_txdata();

  // Request is rejected with a 400.
  out = current_txdata()->msg;
  RespMatcher(400).matches(out);
  tpBono.expect_target(current_txdata(), true);
  free_txdata();
}


// Check that a request with no matching iFCs is rejected on terminating side.
TEST_F(SCSCFTest, NoMatchingiFCsRejectTerm)
{
  _scscf_sproutlet->_ifc_configuration._reject_if_no_matching_ifcs = true;

  // Set up callee info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551234", "homedomain");
  set_ifc(irs_info, "sip:6505551234@homedomain", 0, {"<Method>PUBLISH</Method>"}, "sip:DUMMY_AS");
  expect_get_subscriber_state(irs_info, "sip:6505551234@homedomain");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._to = "6505551234@homedomain";
  msg._route = "Route: <sip:sprout.homedomain>";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  free_txdata();

  // Request is rejected with a 400.
  out = current_txdata()->msg;
  RespMatcher(400).matches(out);
  tpBono.expect_target(current_txdata(), true);
  free_txdata();
}


// Test that we use fallback iFCs if there are no matching iFCs, and that the
// application server flows are as expected.
TEST_F(SCSCFTest, NoMatchingStandardiFCsUseFallbackiFCs)
{
  _scscf_sproutlet->_ifc_configuration._apply_fallback_ifcs = true;

  // Expect a call to look up iFCs for the caller. Set an iFC for the caller,
  // which will not match an INVITE (and has a different address so the test
  // will fail if it is routed to).
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  set_ifc(irs_info_1, "sip:6505551000@homedomain", 0, {"<Method>PUBLISH</Method>"}, "sip:9.8.7.6:54321;transport=UDP");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Expect calls to look up iFCs and bindings for the callee.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  // Fallback iFCs should be applied, so we expect two "get_subscriber_state"
  // calls - one to look up the iFCs originally, and one to check the returned
  // message from the AS (specified in fallback iFCs) hasn't been retargeted.
  expect_get_callee_info(irs_info_2, bindings, "sip:6505551234@homedomain", 2);

   _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.5", 56789);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._to = "6505551234@homedomain";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  free_txdata();

  // INVITE passed on to AS1
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp, &tpAS1);

  // ---------- AS1 turns it around (acting as proxy)
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1
  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));

  tpAS1.expect_target(current_txdata(), false);

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  fresp = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp, &tpAS1);

  // ---------- AS1 turns it around (acting as proxy)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed to final destination (to bono set up in callee's bindings)
  out = current_txdata()->msg;
  ReqMatcher r3("INVITE");
  ASSERT_NO_FATAL_FAILURE(r3.matches(out));
  tpCalleeBono.expect_target(current_txdata(), false);

  // Target sends back 100 Trying
  inject_msg(respond_to_txdata(current_txdata(), 100), &tpBono);
  pjsip_tx_data* txdata = pop_txdata();

  // Send a 200 ringing back down the chain to finish the transaction. This is a
  // more realistic test of AS communication tracking.
  send_response_back_through_dialog(respond_to_txdata(txdata, 200), 200, 2);
  pjsip_tx_data_dec_ref(txdata); txdata = NULL;
}


// Test that we use fallback iFCs if there are no matching iFCs, and that the
// application server flows are as expected. In this case we don't have any
// standard iFCs at all.
TEST_F(SCSCFTest, NoStandardiFCsUseFallbackiFCs)
{
  // Expect call to look up iFCs for the caller.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551000", "homedomain");
  expect_get_subscriber_state(irs_info, "sip:6505551000@homedomain");

  // Expect calls to look up iFCs and bindings for the callee.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings);
  // Fallback iFCs should be applied, so we expect two "get_subscriber_state"
  // calls - one to look up the iFCs originally, and one to check the returned
  // message from the AS (specified in the fallback iFCs) hasn't been retargeted.
  expect_get_callee_info(irs_info_2, bindings, "sip:6505551234@homedomain", 2);

  _scscf_sproutlet->_ifc_configuration._apply_fallback_ifcs = true;

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.5", 56789);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._to = "6505551234@homedomain";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  free_txdata();

  // INVITE passed on to AS1
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp, &tpAS1);

  // ---------- AS1 turns it around (acting as proxy)
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1
  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));

  tpAS1.expect_target(current_txdata(), false);

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  fresp = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp, &tpAS1);

  // ---------- AS1 turns it around (acting as proxy)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed to final destination (to bono set up in callee's bindings)
  out = current_txdata()->msg;
  ReqMatcher r3("INVITE");
  ASSERT_NO_FATAL_FAILURE(r3.matches(out));
  tpCalleeBono.expect_target(current_txdata(), false);

  // Target sends back 100 Trying
  inject_msg(respond_to_txdata(current_txdata(), 100), &tpBono);
  pjsip_tx_data* txdata = pop_txdata();

  // Send a 200 ringing back down the chain to finish the transaction. This is a
  // more realistic test of AS communication tracking.
  send_response_back_through_dialog(respond_to_txdata(txdata, 200), 200, 2);
  pjsip_tx_data_dec_ref(txdata); txdata = NULL;
}


// Test that if a user only has dummy application servers, then no application
// servers are triggered.
TEST_F(SCSCFTest, OnlyDummyApplicationServers)
{
  // Set up callee info, which includes two dummy iFCS - these shouldn't trigger
  // any AS.
  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings);
  ServiceProfileBuilder service_profile = ServiceProfileBuilder()
    .addIfc(0, {"<Method>INVITE</Method>"}, "sip:DUMMY_AS")
    .addIfc(1, {"<Method>INVITE</Method>"}, "sip:DUMMY_AS");
  set_ifcs_from_service_profile(irs_info, service_profile, "sip:6505551234@homedomain");
  expect_get_callee_info(irs_info, bindings);

  SCSCFMessage msg;
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs);
}


// Test that if a user has a mix of real and dummy application servers, only
// the real application servers are triggered.
TEST_F(SCSCFTest, MixedRealAndDummyApplicationServer)
{
    // Expect call to get iFCs for caller.
  HSSConnection::irs_info irs_info_1;
  setup_irs_info(irs_info_1, "6505551000", "homedomain");
  ServiceProfileBuilder service_profile = ServiceProfileBuilder()
    .addIfc(0, {"<Method>INVITE</Method>"}, "sip:DUMMY_AS")
    .addIfc(1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP")
    .addIfc(2, {"<Method>INVITE</Method>"}, "sip:DUMMY_AS");
  set_ifcs_from_service_profile(irs_info_1, service_profile, "sip:6505551000@homedomain");
  expect_get_subscriber_state(irs_info_1, "sip:6505551000@homedomain");

  // Expect calls to get iFCs and bindings for callee.
  HSSConnection::irs_info irs_info_2;
  Bindings bindings;
  setup_callee_info(irs_info_2, bindings, "6505551234", "homedomain");
  expect_get_callee_info(irs_info_2, bindings);

  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");
  EXPECT_CALL(*_sess_cont_comm_tracker, on_success(StrEq("sip:1.2.3.4:56789;transport=UDP")));

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpCalleeBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.6.6.200", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._to = "6505551234@homedomain";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to AS1
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  string fresp = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp, &tpAS1);

  // ---------- AS1 turns it around (acting as proxy)
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  msg.convert_routeset(out);
  free_txdata();

  // INVITE passed on to final destination (to bono set up in callee's bindings)
  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));
  tpCalleeBono.expect_target(current_txdata(), false);

  // Target sends back 100 Trying
  inject_msg(respond_to_txdata(current_txdata(), 100), &tpBono);
  pjsip_tx_data* txdata = pop_txdata();

  // Send a 200 ringing back down the chain to finish the transaction. This is a
  // more realistic test of AS communication tracking.
  send_response_back_through_dialog(respond_to_txdata(txdata, 200), 200, 2);
  pjsip_tx_data_dec_ref(txdata); txdata = NULL;
}


// Test that a MESSAGE containing "urn:service:sos" in the Request URI is
// handled.
//
// The flow here is non-spec.
// Example use case - a user who has an AS set up to bar any calls to them makes
// an emergency call, which goes through the E-CSCF, not the I-CSCF and S-CSCF,
// as it's an emergency call. The user then accidentally hangs up, but the call
// can't be returned since their AS bars it.
// To avoid this, Perimeta sends a MESSAGE to sprout when a user makes an
// emergency call, which contains the uri "urn:service*:sos*". The operator
// should configure an iFC which will match this MESSAGE, so the MESSAGE is
// forwarded to the barring ASs by sprout. This AS will then be aware that the
// user is in an emergency situation, so it can suspend barring, etc. The AS
// should return a 200 OK, which will be returned to Perimeta.
TEST_F(SCSCFTest, SCSCFHandlesUrnUri)
{
  SCOPED_TRACE("");

  pjsip_msg* out;

  TransportFlow tpAS(TransportFlow::Protocol::TCP, stack_data.scscf_port, "1.2.3.4", 56789);

  // Set up the subscription for the caller, to contain an iFC that will be
  // triggered on originating calls, if the RequestURI contains "sos".
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551000", "homedomain");
  set_ifc(irs_info, "sip:6505551000@homedomain", 1, {"<RequestURI>sos</RequestURI>", "<SessionCase>0</SessionCase><!-- originating-registered -->"}, "sip:1.2.3.4:56789;transport=TCP");
  expect_get_subscriber_state(irs_info, "sip:6505551000@homedomain");

  // Create a MESSAGE containing the URI "urn:service:sos".
  Message msg;
  msg._method = "MESSAGE";
  msg._requri = "urn:service:sos";
  msg._full_to_header = "To: <urn:service:sos>";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  std::string p_asserted_id = "P-Asserted-Identity: <sip:";
  p_asserted_id.append(msg._from).append("@").append(msg._fromdomain).append(">");
  msg._extra = p_asserted_id;

  // Send the MESSAGE into the S-CSCF.
  SCOPED_TRACE("MESSAGE");
  inject_msg(msg.get_request(), _tp_default);
  poll();

  // Check the MESSAGE is passed on to the AS (originating AS for 6505551000).
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  ReqMatcher r1("MESSAGE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  tpAS.expect_target(current_txdata(), false);
  EXPECT_EQ("urn:service:sos", r1.uri());
  EXPECT_THAT(get_headers(current_txdata()->msg, "To"),
              testing::MatchesRegex("To: <urn:service:sos>"));

  // In this specific case, the AS should terminate the MESSAGE, and send back a
  // 200 OK.
  SCOPED_TRACE("200 OK (MESSAGE)");
  inject_msg(respond_to_txdata(current_txdata(), 200), &tpAS);
  free_txdata();

  // Check the 200 OK is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  _tp_default->expect_target(current_txdata(), true);
  free_txdata();
}


TEST_F(SCSCFTest, SCSCFHandlesInvalidUri)
{
  // Tests that if the SCSCF receives an originating request with an unrouteable
  // URI after originating processing has finished, it rejects it with a 400
  SCOPED_TRACE("");

  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551000", "homedomain");
  expect_get_subscriber_state(irs_info, "sip:6505551000@homedomain");

  // Create a MESSAGE containing the req-URI "urn:service:sos".
  SCSCFMessage msg;
  msg._method = "MESSAGE";
  msg._requri = "urn:service:sos";
  msg._full_to_header = "To: <urn:service:sos>";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  std::string p_asserted_id = "P-Asserted-Identity: <sip:";
  p_asserted_id.append(msg._from).append("@").append(msg._fromdomain).append(">");
  msg._extra = p_asserted_id;

  // Send the MESSAGE into the S-CSCF.
  SCOPED_TRACE("MESSAGE");
  inject_msg(msg.get_request(), _tp_default);
  poll();

  // Check that we get a 400 error
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(400).matches(out);
  _tp_default->expect_target(current_txdata(), true);
  free_txdata();
}


TEST_F(SCSCFTest, SCSCFHandlesInvalidUriWithoutEnum)
{
  // Tests that if the SCSCF without ENUM configured receives an originating
  // request with an unrouteable URI after originating processing has finished,
  // it rejects it with a 400.
  SCOPED_TRACE("");

  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551000", "homedomain");
  expect_get_subscriber_state(irs_info, "sip:6505551000@homedomain");

  // Disable ENUM
  _scscf_sproutlet->_enum_service = NULL;

  // Create a MESSAGE containing the req-URI "urn:service:sos".
  SCSCFMessage msg;
  msg._method = "MESSAGE";
  msg._requri = "urn:service:sos";
  msg._full_to_header = "To: <urn:service:sos>";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  std::string p_asserted_id = "P-Asserted-Identity: <sip:";
  p_asserted_id.append(msg._from).append("@").append(msg._fromdomain).append(">");
  msg._extra = p_asserted_id;

  // Send the MESSAGE into the S-CSCF.
  SCOPED_TRACE("MESSAGE");
  inject_msg(msg.get_request(), _tp_default);
  poll();

  // Check that we get a 400 error
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(400).matches(out);
  _tp_default->expect_target(current_txdata(), true);
  free_txdata();
}


TEST_F(SCSCFTest, SCSCFHandlesInvalidUriTerm)
{
  // Tests that if the SCSCF receives a terminating request with an unrouteable
  // URI as the next hop, it rejects it with a 400
  SCOPED_TRACE("");

  // Create a MESSAGE containing the URI "urn:service:sos".
  SCSCFMessage msg;
  msg._method = "MESSAGE";
  msg._requri = "urn:service:sos";
  msg._full_to_header = "To: <urn:service:sos>";
  msg._route = "Route: <sip:sprout.homedomain>";
  std::string p_asserted_id = "P-Asserted-Identity: <sip:";
  p_asserted_id.append(msg._from).append("@").append(msg._fromdomain).append(">");
  msg._extra = p_asserted_id;

  // Send the MESSAGE into the S-CSCF.
  SCOPED_TRACE("MESSAGE");
  inject_msg(msg.get_request(), _tp_default);
  poll();

  // Check that we get a 400 error
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(400).matches(out);
  _tp_default->expect_target(current_txdata(), true);
  free_txdata();
}

// Tests that, if we have a request whose Route header matches only on the port,
// the IRS query uses the configured S-CSCF URI as the server name
TEST_F(SCSCFTest, PortMatchedRouteHeaderUsesConfiguredServerName)
{
  // Create an INVITE with a Route header that matches only on the port
  SCSCFMessage msg;
  msg._route = "Route: <sip:homedomain:5058>";

  // Save the IRS query and return NOT_FOUND to prevent further processing
  HSSConnection::irs_query irs_query;
  EXPECT_CALL(*_sm, get_subscriber_state(_, _, _))
    .WillOnce(DoAll(SaveArg<0>(&irs_query),
                    Return(HTTP_NOT_FOUND)));

  // The call will fail
  doSlowFailureFlow(msg, 404);

  // Check that the query was made for the correct subscriber
  EXPECT_EQ("sip:6505551234@homedomain",irs_query._public_id);
  EXPECT_EQ("call", irs_query._req_type);

  // Check that the server name used was the configured S-CSCF URI
  EXPECT_EQ("sip:scscf.sprout.homedomain:5058;transport=TCP", irs_query._server_name);
}

class SCSCFTestWithoutICSCF : public SCSCFTestBase
{
  static void SetUpTestCase()
  {
    SCSCFTestBase::SetUpTestCase();
  }
  static void TearDownTestCase()
  {
    SCSCFTestBase::TearDownTestCase();
  }

  SCSCFTestWithoutICSCF() : SCSCFTestBase()
  {
    // Create the S-CSCF Sproutlet.
    IFCConfiguration ifc_configuration(false, false, "sip:DUMMY_AS", NULL, NULL);
    _scscf_sproutlet = new SCSCFSproutlet("scscf",
                                          "scscf",
                                          "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                          "sip:127.0.0.1:5058",
                                          "",
                                          "sip:bgcf@homedomain:5058",
                                          5058,
                                          "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                          "scscf",
                                          "",
                                          _sm,
                                          _enum_service,
                                          _acr_factory,
                                          &SNMP::FAKE_INCOMING_SIP_TRANSACTIONS_TABLE,
                                          &SNMP::FAKE_OUTGOING_SIP_TRANSACTIONS_TABLE,
                                          false,
                                          _fifc_service,
                                          ifc_configuration,
                                          3000, // Session continue timeout - different from default
                                          6000, // Session terminated timeout - different from default
                                          _sess_term_comm_tracker,
                                          _sess_cont_comm_tracker
                                          );
    _scscf_sproutlet->init();

    // Create the I-CSCF Sproutlets.
    _scscf_selector = new SCSCFSelector("sip:scscf.sprout.homedomain",
                                        string(UT_DIR).append("/test_icscf.json"));
    _icscf_sproutlet = new ICSCFSproutlet("icscf",
                                          "sip:bgcf@homedomain:5058",
                                          5059,
                                          "sip:icscf.sprout.homedomain:5059;transport=TCP",
                                          "icscf",
                                          "",
                                          _hss_connection,
                                          _acr_factory,
                                          _scscf_selector,
                                          _enum_service,
                                          &SNMP::FAKE_INCOMING_SIP_TRANSACTIONS_TABLE,
                                          &SNMP::FAKE_OUTGOING_SIP_TRANSACTIONS_TABLE,
                                          false,
                                          5059
                                          );
    _icscf_sproutlet->init();

    // Add common sproutlet to the list for Proxy use
    std::list<Sproutlet*> sproutlets;
    sproutlets.push_back(_scscf_sproutlet);
    sproutlets.push_back(_bgcf_sproutlet);
    sproutlets.push_back(_mmtel_sproutlet);

    // Add additional home domain for Proxy use
    std::unordered_set<std::string> additional_home_domains;
    additional_home_domains.insert("sprout.homedomain");
    additional_home_domains.insert("sprout-site2.homedomain");
    additional_home_domains.insert("127.0.0.1");

    _proxy = new SproutletProxy(stack_data.endpt,
                                PJSIP_MOD_PRIORITY_UA_PROXY_LAYER+1,
                                "homedomain",
                                additional_home_domains,
                                std::unordered_set<std::string>(),
                                true,
                                sproutlets,
                                std::set<std::string>(),
                                nullptr,
                                nullptr);
  }

  ~SCSCFTestWithoutICSCF()
  {
  }
};


// Test routing directly to the local SCSCF when the ICSCF is disabled.
// This call will fail as there is no data for the callee.
TEST_F(SCSCFTestWithoutICSCF, TestRouteWithoutICSCF)
{
  SCOPED_TRACE("");

  // Set up caller info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "+16505551000", "homedomain");
  expect_get_subscriber_state(irs_info, "sip:+16505551000@homedomain");

  // Expect a call looking for iFCs for the callee - return a 404.
  EXPECT_CALL(*_sm, get_subscriber_state(IrsQueryWithPublicId("sip:+15108580271@homedomain"), _, _))
    .WillOnce(Return(HTTP_NOT_FOUND));

  URIClassifier::enforce_user_phone = true;
  SCSCFMessage msg;
  msg._to = "+15108580271";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";

  list<HeaderMatcher> hdrs;
  // TODO:Route hdr should contain SCSCF URI rather than ICSCF URI, not checked here
  doSlowFailureFlow(msg, 404);
}


class SCSCFTestWithRalf : public SCSCFTestBase
{
  static void SetUpTestCase()
  {
    SCSCFTestBase::SetUpTestCase();
    _ralf_connection = new NiceMock<MockHttpConnection>();
    _ralf_processor = new NiceMock<MockRalfProcessor>(_ralf_connection);
    _ralf_acr_factory = new RalfACRFactory(_ralf_processor, ACR::SCSCF);
  }
  static void TearDownTestCase()
  {
    delete _ralf_acr_factory; _ralf_acr_factory = NULL;
    delete _ralf_processor; _ralf_processor = NULL;
    delete _ralf_connection; _ralf_connection = NULL;
    SCSCFTestBase::TearDownTestCase();
  }

  SCSCFTestWithRalf() : SCSCFTestBase()
  {
    // Create the S-CSCF Sproutlet.
    IFCConfiguration ifc_configuration(false, false, "sip:DUMMY_AS", NULL, NULL);
    _scscf_sproutlet = new SCSCFSproutlet("scscf",
                                          "scscf",
                                          "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                          "sip:127.0.0.1:5058",
                                          "sip:icscf.sprout.homedomain:5059;transport=TCP",
                                          "sip:bgcf@homedomain:5058",
                                          5058,
                                          "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                          "scscf",
                                          "",
                                          _sm,
                                          _enum_service,
                                          _ralf_acr_factory,
                                          &SNMP::FAKE_INCOMING_SIP_TRANSACTIONS_TABLE,
                                          &SNMP::FAKE_OUTGOING_SIP_TRANSACTIONS_TABLE,
                                          false,
                                          _fifc_service,
                                          ifc_configuration,
                                          3000, // Session continue timeout - different from default
                                          6000, // Session terminated timeout - different from default
                                          _sess_term_comm_tracker,
                                          _sess_cont_comm_tracker
                                          );
    _scscf_sproutlet->init();

    // Create the I-CSCF Sproutlets.
    _scscf_selector = new SCSCFSelector("sip:scscf.sprout.homedomain",
                                        string(UT_DIR).append("/test_icscf.json"));
    _icscf_sproutlet = new ICSCFSproutlet("icscf",
                                          "sip:bgcf@homedomain:5058",
                                          5059,
                                          "sip:icscf.sprout.homedomain:5059;transport=TCP",
                                          "icscf",
                                          "",
                                          _hss_connection,
                                          _ralf_acr_factory,
                                          _scscf_selector,
                                          _enum_service,
                                          &SNMP::FAKE_INCOMING_SIP_TRANSACTIONS_TABLE,
                                          &SNMP::FAKE_OUTGOING_SIP_TRANSACTIONS_TABLE,
                                          false,
                                          5059
                                          );
    _icscf_sproutlet->init();

    // Add common sproutlet to the list for Proxy use
    std::list<Sproutlet*> sproutlets;
    sproutlets.push_back(_scscf_sproutlet);
    sproutlets.push_back(_icscf_sproutlet);
    sproutlets.push_back(_bgcf_sproutlet);
    sproutlets.push_back(_mmtel_sproutlet);

    // Add additional home domain for Proxy use
    std::unordered_set<std::string> additional_home_domains;
    additional_home_domains.insert("sprout.homedomain");
    additional_home_domains.insert("sprout-site2.homedomain");
    additional_home_domains.insert("127.0.0.1");

    _proxy = new SproutletProxy(stack_data.endpt,
                                PJSIP_MOD_PRIORITY_UA_PROXY_LAYER+1,
                                "homedomain",
                                additional_home_domains,
                                std::unordered_set<std::string>(),
                                true,
                                sproutlets,
                                std::set<std::string>(),
                                nullptr,
                                nullptr);
  }

  ~SCSCFTestWithRalf()
  {
  }
protected:
  static MockHttpConnection* _ralf_connection;
  static MockRalfProcessor* _ralf_processor;
  static RalfACRFactory* _ralf_acr_factory;

};
MockHttpConnection* SCSCFTestWithRalf::_ralf_connection;
MockRalfProcessor* SCSCFTestWithRalf::_ralf_processor;
RalfACRFactory* SCSCFTestWithRalf::_ralf_acr_factory;


// Test complete mainline call flow and check ralf processor for sending right
// ACR in sequence.
TEST_F(SCSCFTestWithRalf, MainlineBilling)
{
  SCSCFMessage msg;

  // Set up callee info.
  HSSConnection::irs_info irs_info;
  Bindings bindings;
  setup_callee_info(irs_info, bindings);
  expect_get_callee_info(irs_info, bindings);

  list<HeaderMatcher> hdrs;
  CapturingTestLogger log;

  // Save the ralf request being sent out by ralf processor in sequence.
  RalfProcessor::RalfRequest* ralf_request_1;
  RalfProcessor::RalfRequest* ralf_request_2;
  RalfProcessor::RalfRequest* ralf_request_3;
  EXPECT_CALL(*_ralf_processor, send_request_to_ralf(_))
    .WillOnce(SaveArg<0>(&ralf_request_1))
    .WillOnce(SaveArg<0>(&ralf_request_2))
    .WillOnce(SaveArg<0>(&ralf_request_3));

  // Complete call flow with ACK and BYE.
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs);

  // Check Node Function is S-CSCF.
  EXPECT_THAT(ralf_request_1->path,MatchesRegex("/call-id/.*%4010.114.61.213"));
  EXPECT_THAT(ralf_request_1->message,MatchesRegex(".*\"Node-Functionality\":0.*"));

  // First ACR is sent for INVITE and is START_RECORD
  EXPECT_THAT(ralf_request_1->message,MatchesRegex(".*\"SIP-Method\":\"INVITE\".*"));
  EXPECT_THAT(ralf_request_1->message,MatchesRegex(".*\"Accounting-Record-Type\":2.*"));

  // Second ACR is sent for ACK and is EVENT_RECORD
  EXPECT_THAT(ralf_request_2->message,MatchesRegex(".*\"SIP-Method\":\"ACK\".*"));
  EXPECT_THAT(ralf_request_2->message,MatchesRegex(".*\"Accounting-Record-Type\":3.*"));

  // Third request is sent for BYE and has STOP_RECORD
  EXPECT_THAT(ralf_request_3->message,MatchesRegex(".*\"SIP-Method\":\"BYE\".*"));
  EXPECT_THAT(ralf_request_3->message,MatchesRegex(".*\"Accounting-Record-Type\":4.*"));

  delete ralf_request_1; ralf_request_1 = NULL;
  delete ralf_request_2; ralf_request_2 = NULL;
  delete ralf_request_3; ralf_request_3 = NULL;
}


// Test attempted AS chain link after chain has expired, with additional check
// that ralf processor is sending ACR request with right cause code.
TEST_F(SCSCFTestWithRalf, ExpiredChain)
{
  // Set up caller info.
  HSSConnection::irs_info irs_info;
  setup_irs_info(irs_info, "6505551000", "homedomain");
  set_ifc(irs_info, "sip:6505551000@homedomain", 1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  expect_get_subscriber_state(irs_info, "sip:6505551000@homedomain");

  // Set LIA to find callee - this will be needed in "doAsOriginated", which is
  // called later in this test.
  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // Save Ralf request for checking and manual deletion as mock ralf processor
  // will not free up the request autimatically.
  RalfProcessor::RalfRequest* ralf_request;
  RalfProcessor::RalfRequest* ralf_request_1;
  RalfProcessor::RalfRequest* ralf_request_2;
  RalfProcessor::RalfRequest* ralf_request_3;
  RalfProcessor::RalfRequest* ralf_request_4;
  EXPECT_CALL(*_ralf_processor, send_request_to_ralf(_))
    .WillOnce(SaveArg<0>(&ralf_request))
    .WillOnce(SaveArg<0>(&ralf_request_1))
    .WillOnce(SaveArg<0>(&ralf_request_2))
    .WillOnce(SaveArg<0>(&ralf_request_3))
    .WillOnce(SaveArg<0>(&ralf_request_4));

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  SCSCFMessage msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig;service=scscf>"));

  // ---------- AS1 gives final response, ending the transaction.
  string fresp = respond_to_txdata(current_txdata(), 404);
  pjsip_msg* saved = pop_txdata()->msg;
  inject_msg(fresp, &tpAS1);

  // ACK goes back to AS1
  SCOPED_TRACE("ACK");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("ACK").matches(out));
  free_txdata();

  // 404 response goes back to bono
  SCOPED_TRACE("404");
  out = current_txdata()->msg;
  RespMatcher(404).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.convert_routeset(out);
  msg._cseq++;
  free_txdata();

  // ---------- Send ACK from bono
  SCOPED_TRACE("ACK");
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpBono);

  // Allow time to pass, so the initial Sprout UAS transaction moves
  // from Completed to Terminated to Destroyed.  32s is the default
  // timeout. This causes the ODI token to expire.
  cwtest_advance_time_ms(33000L);
  poll();

  // ---------- AS1 attempts to turn the message around (acting as proxy)
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(saved, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }

  char buf[65535];
  pj_ssize_t len = pjsip_msg_print(saved, buf, sizeof(buf));
  doAsOriginated(string(buf, len), true);

  // Check first ralf request.
  EXPECT_THAT(ralf_request->message,MatchesRegex(".*\"Accounting-Record-Type\":1.*")); // EVENT_RECORD
  EXPECT_THAT(ralf_request->message,MatchesRegex(".*\"Role-Of-Node\":0.*"));  // NODE_ROLE_ORIGINATING
  EXPECT_THAT(ralf_request->message,MatchesRegex(".*\"SIP-Method\":\"INVITE\".*"));
  EXPECT_THAT(ralf_request->message,MatchesRegex(".*\"Application-Server\":\"sip:1.2.3.4:56789;transport=UDP\".*"));
  EXPECT_THAT(ralf_request->message,MatchesRegex(".*\"Status-Code\":0.*"));
  EXPECT_THAT(ralf_request->message,MatchesRegex(".*\"Cause-Code\":404.*"));

  delete ralf_request; ralf_request = NULL;
  delete ralf_request_1; ralf_request_1 = NULL;
  delete ralf_request_2; ralf_request_2 = NULL;
  delete ralf_request_3; ralf_request_3 = NULL;
  delete ralf_request_4; ralf_request_4 = NULL;
}

