/**
 * @file Sprout FV tests
 *
 * Copyright (C) Metaswitch Networks 2018
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
#include "mock_snmp_counter_table.hpp"
#include "registration_sender.h"

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

// TECH-DEBT-TODO:
// This class is meant to be a set of FV tests that use real Sprout components
// so far as possible, with the external interfaces being mocked/faked out.
// So far, these tests are not complete, and aren't particularly well structured
// either - we should rework the S-CSCF UTs to be much more UT based, pull a
// bunch of those tests into this suite, and do a proper design/set up proper
// infrastructure for these tests.
// For now, these tests run through a couple of mainline calls. They don't
// really check that much about the calls, just that basically the right flows
// appear to be happening (as verified by looking at Record-/Route headers).
// This is sufficient for now; but we shouldn't really add any more tests to
// this suite without stepping back and doing this properly.
class SCSCFMessage : public TestingCommon::Message
{
public:
  SCSCFMessage()
  {
    Message::_route = "Route: <sip:sprout.homedomain;service=scscf>";
  };
  ~SCSCFMessage() {};
};

/// ABC for fixtures for SproutFVTest and friends.
class SproutFVTest : public SipTest
{
public:
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
    SipTest::SetScscfUri("sip:scscf.sprout.homedomain:5058;transport=TCP");
  }

  void SetUp()
  {
    _log_traffic = PrintingTestLogger::DEFAULT.isPrinting(); // true to see all traffic

    _hss_connection = new FakeHSSConnection();
    _chronos_connection = new FakeChronosConnection();
    _local_data_store = new LocalStore();
    _local_aor_store = new AstaireAoRStore(_local_data_store);
    _s4 = new S4("FV", _chronos_connection, "/timers/", (AoRStore*)_local_aor_store, {});
    _analytics = new AnalyticsLogger();
    _notify_sender = new NotifySender();
    IFCConfiguration ifc_configuration(false, false, "sip:DUMMY_AS", NULL, NULL);
    _fifc_service = new FIFCService(NULL, string(UT_DIR).append("/test_scscf_fifc.xml"));
    _registration_sender = new RegistrationSender(ifc_configuration,
                                                  _fifc_service,
                                                  &SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES,
                                                  true);
    _sm = new SubscriberManager(_s4, _hss_connection, _analytics, _notify_sender, _registration_sender);
    _registration_sender->register_dereg_event_consumer(_sm);
    _bgcf_service = new BgcfService(string(UT_DIR).append("/test_stateful_proxy_bgcf.json"));
    _xdm_connection = new FakeXDMConnection();
    _sess_term_comm_tracker = new NiceMock<MockAsCommunicationTracker>();
    _sess_cont_comm_tracker = new NiceMock<MockAsCommunicationTracker>();
    _enum_service = new JSONEnumService(string(UT_DIR).append("/test_stateful_proxy_enum.json"));
    _acr_factory = new ACRFactory();

    // Create the S-CSCF Sproutlet.
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

    // Schedule timers.
    SipTest::poll();
  }

  static void TearDownTestCase()
  {
    // Shut down the transaction module first, before we destroy the
    // objects that might handle any callbacks!
    pjsip_tsx_layer_destroy();
    SipTest::TearDownTestCase();
  }

  void TearDown()
  {
    ::testing::Mock::VerifyAndClearExpectations(_sess_term_comm_tracker);
    ::testing::Mock::VerifyAndClearExpectations(_sess_cont_comm_tracker);

    delete _fifc_service; _fifc_service = NULL;
    delete _acr_factory; _acr_factory = NULL;
    delete _sm; _sm = NULL;
    delete _s4, _s4 = NULL;
    delete _registration_sender; _registration_sender = NULL;
    delete _notify_sender, _notify_sender = NULL;
    delete _chronos_connection; _chronos_connection = NULL;
    delete _local_aor_store; _local_aor_store = NULL;
    delete _local_data_store; _local_data_store = NULL;
    delete _analytics; _analytics = NULL;
    delete _enum_service; _enum_service = NULL;
    delete _bgcf_service; _bgcf_service = NULL;
    delete _hss_connection; _hss_connection = NULL;
    delete _xdm_connection; _xdm_connection = NULL;
    delete _sess_cont_comm_tracker; _sess_cont_comm_tracker = NULL;
    delete _sess_term_comm_tracker; _sess_term_comm_tracker = NULL;
  }

  ~SproutFVTest()
  {
    pjsip_tsx_layer_dump(true);

    // Terminate all transactions
    std::list<pjsip_transaction*> tsxs = get_all_tsxs();
    for (std::list<pjsip_transaction*>::iterator it2 = tsxs.begin();
         it2 != tsxs.end();
         ++it2)
    {
      pjsip_tsx_terminate(*it2, PJSIP_SC_SERVICE_UNAVAILABLE);
    }

    // PJSIP transactions aren't actually destroyed until a zero ms
    // timer fires (presumably to ensure destruction doesn't hold up
    // real work), so poll for that to happen. Otherwise we leak!
    // Allow a good length of time to pass too, in case we have
    // transactions still open. 32s is the default UAS INVITE
    // transaction timeout, so we go higher than that.
    cwtest_advance_time_ms(33000L);
    poll();

    // Stop and restart the transaction layer just in case
    pjsip_tsx_layer_instance()->stop();
    pjsip_tsx_layer_instance()->start();

    delete _proxy; _proxy = NULL;
    delete _mmtel_sproutlet; _mmtel_sproutlet = NULL;
    delete _mmtel; _mmtel = NULL;
    delete _bgcf_sproutlet; _bgcf_sproutlet = NULL;
    delete _scscf_sproutlet; _scscf_sproutlet = NULL;
    delete _icscf_sproutlet; _icscf_sproutlet = NULL;
    delete _scscf_selector; _scscf_selector = NULL;
  }

  // Three helper functions to check that a flow is correct. These are heavily
  // based on the matching function in scscf_test.
  void doSuccessfulFlow(SCSCFMessage& msg,
                        testing::Matcher<string> uri_matcher,
                        list<HeaderMatcher> headers,
                        list<HeaderMatcher> rsp_hdrs = list<HeaderMatcher>(),
                        string body_regex = "");

  void doFourAppServerFlow(std::string record_route_regex,
                           bool app_servers_record_route=false);

  void send_response_back_through_dialog(const std::string& response,
                                         int status_code,
                                         int num_hops);

protected:
  LocalStore* _local_data_store;
  FakeChronosConnection* _chronos_connection;
  AstaireAoRStore* _local_aor_store;
  RegistrationSender* _registration_sender;
  SubscriberManager* _sm;
  S4* _s4;
  NotifySender* _notify_sender;
  AnalyticsLogger* _analytics;
  FakeHSSConnection* _hss_connection;
  FakeXDMConnection* _xdm_connection;
  BgcfService* _bgcf_service;
  EnumService* _enum_service;
  ACRFactory* _acr_factory;
  FIFCService* _fifc_service;
  BGCFSproutlet* _bgcf_sproutlet;
  SCSCFSproutlet* _scscf_sproutlet;
  Mmtel* _mmtel;
  SproutletAppServerShim* _mmtel_sproutlet;
  SCSCFSelector* _scscf_selector;
  ICSCFSproutlet* _icscf_sproutlet;
  SproutletProxy* _proxy;
  MockAsCommunicationTracker* _sess_term_comm_tracker;
  MockAsCommunicationTracker* _sess_cont_comm_tracker;
};

/// Test a message results in a successful flow. The outgoing INVITE's
/// URI is verified.
void SproutFVTest::doSuccessfulFlow(SCSCFMessage& msg,
                                    testing::Matcher<string> uri_matcher,
                                    list<HeaderMatcher> headers,
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

  free_txdata();
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
void SproutFVTest::send_response_back_through_dialog(const std::string& response,
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

void SproutFVTest::doFourAppServerFlow(std::string record_route_regex, bool app_servers_record_route)
{
  register_uri(_sm, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", false);

  ServiceProfileBuilder service_profile_1 = ServiceProfileBuilder()
    .addIdentity("sip:6505551000@homedomain")
    .addIfc(2, {"<Method>INVITE</Method>"}, "sip:4.2.3.4:56788;transport=UDP")
    .addIfc(1, {"<Method>INVITE</Method>"}, "sip:1.2.3.4:56789;transport=UDP");
  SubscriptionBuilder subscription_1 = SubscriptionBuilder()
    .addServiceProfile(service_profile_1);
  _hss_connection->set_impu_result("sip:6505551000@homedomain",
                                   "call",
                                   RegDataXMLUtils::STATE_REGISTERED,
                                   subscription_1.return_sub());

  ServiceProfileBuilder service_profile_2 = ServiceProfileBuilder()
    .addIdentity("sip:6505551234@homedomain")
    .addIfc(1, {"<Method>INVITE</Method>", "<SessionCase>1</SessionCase><!-- terminating-registered -->"}, "sip:5.2.3.4:56787;transport=UDP")
    .addIfc(2, {"<Method>QWERTY_UIOP</Method>"}, "sip:sholes.example.com")
    .addIfc(3, {"<Method>INVITE</Method>"}, "sip:6.2.3.4:56786;transport=UDP");
  SubscriptionBuilder subscription_2 = SubscriptionBuilder()
    .addServiceProfile(service_profile_2);
  _hss_connection->set_impu_result("sip:6505551234@homedomain",
                                   "call",
                                   RegDataXMLUtils::STATE_REGISTERED,
                                   subscription_2.return_sub());

  EXPECT_CALL(*_sess_cont_comm_tracker, on_success(StrEq("sip:4.2.3.4:56788;transport=UDP")));
  EXPECT_CALL(*_sess_cont_comm_tracker, on_success(StrEq("sip:1.2.3.4:56789;transport=UDP")));
  EXPECT_CALL(*_sess_cont_comm_tracker, on_success(StrEq("sip:5.2.3.4:56787;transport=UDP")));
  EXPECT_CALL(*_sess_cont_comm_tracker, on_success(StrEq("sip:6.2.3.4:56786;transport=UDP")));

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpAS2(TransportFlow::Protocol::UDP, stack_data.scscf_port, "4.2.3.4", 56788);
  TransportFlow tpAS3(TransportFlow::Protocol::UDP, stack_data.scscf_port, "5.2.3.4", 56787);
  TransportFlow tpAS4(TransportFlow::Protocol::UDP, stack_data.scscf_port, "6.2.3.4", 56786);
  TransportFlow tpCallee(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.114.61.213", 5061);

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

  // INVITE passed on to final destination
  SCOPED_TRACE("INVITE (Z)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  // INVITE passed to final destination, so to callee.
  tpCallee.expect_target(current_txdata(), false);

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

// Test an on-net call end-to-end.
TEST_F(SproutFVTest, TestOnNetCall)
{
  register_uri(_sm, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", false);
  register_uri(_sm, _hss_connection, "6505551000", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", false);
  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  SCSCFMessage msg;
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Record-Route", "Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-term>", "Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-orig>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs);

  // Make sure that the HTTP request sent to homestead contains the correct S-CSCF URI.
  EXPECT_TRUE(_hss_connection->url_was_requested("/impu/sip%3A6505551234%40homedomain/reg-data", "{\"reqtype\": \"call\", \"server_name\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}"));
}

// Test an on-net call end-to-end with Tel URIs.
TEST_F(SproutFVTest, TestOnNetCallTelURI)
{
  register_uri(_sm, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", false);
  register_uri(_sm, _hss_connection, "6505551000", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", false);
  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");

  SCSCFMessage msg;
  msg._toscheme = "tel";
  msg._to = "6505551234";
  msg._todomain = "";
  msg._route = "Route: <sip:sprout.homedomain;orig>";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Record-Route", "Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-term>", "Record-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;billing-role=charge-orig>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs);
}

// Test a SUBSCRIBE/NOTIFY flow.
TEST_F(SproutFVTest, TestNotifys)
{
  register_uri(_sm, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", true);
  poll();

  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;

  EXPECT_EQ("NOTIFY", str_pj(out->line.status.reason));
  EXPECT_EQ("Event: reg", get_headers(out, "Event"));

  // Tidy up
  inject_msg(respond_to_current_txdata(200));
}

TEST_F(SproutFVTest, TestApplicationServers)
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
