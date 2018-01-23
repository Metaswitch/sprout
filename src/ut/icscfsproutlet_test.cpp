/**
 * @file icscfproxy_test.cpp UT for I-CSCF proxy class.
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
#include "icscfsproutlet.h"
#include "mock_sas.h"
#include "fakehssconnection.hpp"
#include "test_interposer.hpp"
#include "sproutletproxy.h"
#include "fakesnmp.hpp"
#include "testingcommon.h"

using namespace std;
using testing::StrEq;
using testing::ElementsAre;
using testing::MatchesRegex;
using testing::HasSubstr;
using testing::Not;

int ICSCF_PORT = 5052;

/// ABC for fixtures for ICSCFSproutletTest.
class ICSCFSproutletTestBase : public SipTest
{
public:
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();

    _hss_connection = new FakeHSSConnection();
    _acr_factory = new ACRFactory();
    _scscf_selector = new SCSCFSelector("sip:scscf.homedomain", string(UT_DIR).append("/test_icscf.json"));
    _enum_service = new JSONEnumService(string(UT_DIR).append("/test_enum.json"));
    // Schedule timers.
    SipTest::poll();
  }

  static void TearDownTestCase()
  {
    // Shut down the transaction module first, before we destroy the
    // objects that might handle any callbacks!
    pjsip_tsx_layer_destroy();
    delete _enum_service; _enum_service = NULL;
    delete _acr_factory; _acr_factory = NULL;
    delete _hss_connection; _hss_connection = NULL;
    delete _scscf_selector; _scscf_selector = NULL;
    SipTest::TearDownTestCase();
  }

  ICSCFSproutletTestBase()
  {
    _log_traffic = PrintingTestLogger::DEFAULT.isPrinting(); // true to see all traffic
    _hss_connection->flush_all();

    _icscf_sproutlet = new ICSCFSproutlet("icscf",
                                          "sip:bgcf.homedomain",
                                          ICSCF_PORT,
                                          "sip:icscf.homedomain:5052;transport=tcp",
                                          "icscf",
                                          "",
                                          _hss_connection,
                                          _acr_factory,
                                          _scscf_selector,
                                          _enum_service,
                                          NULL,
                                          NULL,
                                          false,
                                          ICSCF_PORT);
    _icscf_sproutlet->init();
    std::list<Sproutlet*> sproutlets;
    sproutlets.push_back(_icscf_sproutlet);

    _icscf_proxy = new SproutletProxy(stack_data.endpt,
                                      PJSIP_MOD_PRIORITY_UA_PROXY_LAYER,
                                      "homedomain",
                                      std::unordered_set<std::string>(),
                                      sproutlets,
                                      std::set<std::string>());
  }

  ~ICSCFSproutletTestBase()
  {
    pjsip_tsx_layer_dump(true);

    // Terminate all transactions
    list<pjsip_transaction*> tsxs = get_all_tsxs();
    for (list<pjsip_transaction*>::iterator it2 = tsxs.begin();
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

    delete _icscf_proxy; _icscf_proxy = NULL;
    delete _icscf_sproutlet; _icscf_sproutlet = NULL;
  }

  /// Check that we logged an ICID to SAS.
  void check_sas_correlator_icid(std::string value, bool present=true)
  {
    bool found_value = false;
    std::vector<MockSASMessage*> markers = mock_sas_find_marker_multiple(MARKER_ID_IMS_CHARGING_ID);
    for (MockSASMessage* marker : markers)
    {
      EXPECT_EQ(marker->var_params.size(), 1u);
      if (marker->var_params[0] == value)
      {
        found_value = true;
        break;
      }
    }
    EXPECT_EQ(found_value, present);
  }

protected:
  static ACRFactory* _acr_factory;
  static FakeHSSConnection* _hss_connection;
  static SCSCFSelector* _scscf_selector;
  static JSONEnumService* _enum_service;
  ICSCFSproutlet* _icscf_sproutlet;
  SproutletProxy* _icscf_proxy;
};

ACRFactory* ICSCFSproutletTestBase::_acr_factory;
FakeHSSConnection* ICSCFSproutletTestBase::_hss_connection;
SCSCFSelector* ICSCFSproutletTestBase::_scscf_selector;
JSONEnumService* ICSCFSproutletTestBase::_enum_service;

class ICSCFSproutletTest : public ICSCFSproutletTestBase
{
public:
  static void SetUpTestCase()
  {
    ICSCFSproutletTestBase::SetUpTestCase();

    // Set up DNS mappings for some S-CSCFs and a BGCF.
    add_host_mapping("scscf1.homedomain", "10.10.10.1");
    add_host_mapping("scscf2.homedomain", "10.10.10.2");
    add_host_mapping("scscf3.homedomain", "10.10.10.3");
    add_host_mapping("scscf4.homedomain", "10.10.10.4");
    add_host_mapping("scscf5.homedomain", "10.10.10.5");
    add_host_mapping("bgcf.homedomain",   "10.10.11.1");
  }

  static void TearDownTestCase()
  {
    ICSCFSproutletTestBase::TearDownTestCase();
  }

  ICSCFSproutletTest()
  {
  }

  ~ICSCFSproutletTest()
  {
  }

protected:
  // Common test setup for the RouteTermInviteLocalUserPhone tests
  TransportFlow *route_term_invite_local_user_phone_setup()
  {
    // Create a TCP connection to the I-CSCF listening port.
    TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                          ICSCF_PORT,
                                          "1.2.3.4",
                                          49152);

    // Set up the HSS responses for the terminating location query.
    _hss_connection->set_result("/impu/tel%3A16505551234/location",
                                "{\"result-code\": 2001,"
                                " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

    // Inject an INVITE request to a sip URI representing a telephone number with a
    // P-Served-User header.
    TestingCommon::Message msg1;
    msg1._first_hop = true;
    msg1._method = "INVITE";
    msg1._requri = "sip:16505551234@homedomain;user=phone;isub=1234;ext=4321";
    msg1._to = "16505551234";
    msg1._via = tp->to_string(false);
    msg1._extra = "Contact: sip:16505551000@" +
                  tp->to_string(true) +
                  ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
    msg1._extra += "P-Served-User: <sip:16505551000@homedomain>";
    msg1._route = "Route: <sip:homedomain>";
    inject_msg(msg1.get_request(), tp);

    return tp;
  }

  void test_session_establishment_stats(int successes, int failures, int network_successes, int network_failures)
  {
    SNMP::FakeSuccessFailCountTable* session_table = ((SNMP::FakeSuccessFailCountTable*)_icscf_sproutlet->_session_establishment_tbl);
    SNMP::FakeSuccessFailCountTable* session_network_table = ((SNMP::FakeSuccessFailCountTable*)_icscf_sproutlet->_session_establishment_network_tbl);

    EXPECT_EQ(successes + failures, session_table->_attempts);
    EXPECT_EQ(successes, session_table->_successes);
    EXPECT_EQ(failures, session_table->_failures);
    EXPECT_EQ(network_successes + network_failures, session_network_table->_attempts);
    EXPECT_EQ(network_successes, session_network_table->_successes);
    EXPECT_EQ(network_failures, session_network_table->_failures);
  }
};

using TestingCommon::Message;

TEST_F(ICSCFSproutletTest, RouteRegisterSCSCFBlacklisted)
{
  // Tests routing of REGISTER requests when the HSS responds with a blacklisted
  // S-CSCF name.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Add all but one S-CSCF to the blacklist (scscf1.homedomain is not blacklisted).
  _icscf_sproutlet->_blacklisted_scscfs.insert("sip:scscf2.homedomain:5058;transport=TCP");
  _icscf_sproutlet->_blacklisted_scscfs.insert("sip:scscf3.homedomain:5058;transport=TCP");
  _icscf_sproutlet->_blacklisted_scscfs.insert("sip:scscf4.homedomain:5058;transport=TCP");
  _icscf_sproutlet->_blacklisted_scscfs.insert("sip:scscf5.homedomain:5058;transport=TCP");

  // Set up HSS response for user registration where a blacklisted S-CSCF is returned. Also set up the subsequent capabilities query.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
  "{\"result-code\": 2001,"
  " \"scscf\": \"sip:scscf5.homedomain:5058;transport=TCP\"}");
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB",
  "{\"result-code\": 2001,"
  " \"scscf\": \"sip:scscf5.homedomain:5058;transport=TCP\"}");

  // Inject a REGISTER request.
  Message msg2;
  msg2._first_hop = true;
  msg2._method = "REGISTER";
  msg2._requri = "sip:homedomain";
  msg2._to = msg2._from;        // To header contains AoR in REGISTER requests.
  msg2._via = tp->to_string(false);
  msg2._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  inject_msg(msg2.get_request(), tp);

  // REGISTER request should be forwarded to scscf1.homedomain as this is
  // the only S-CSCF that is not blacklisted.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r3("REGISTER");
  r3.matches(tdata->msg);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r4(200);
  r4.matches(tdata->msg);

  free_txdata();
  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");
  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB");

  delete tp;
}

TEST_F(ICSCFSproutletTest, RouteRegisterHSSServerName)
{
  // Tests routing of REGISTER requests when the HSS responds with a server
  // name.  There are two cases tested here - one where the impi is defaulted
  // from the impu and one where the impi is explicit specified in an
  // Authorization header.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the user registration status query using
  // a default private user identity.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

  // Inject a REGISTER request.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "REGISTER";
  msg1._requri = "sip:homedomain";
  msg1._to = msg1._from;        // To header contains AoR in REGISTER requests.
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  inject_msg(msg1.get_request(), tp);

  // REGISTER request should be forwarded to the server named in the HSS
  // response, scscf1.homedomain.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("REGISTER");
  r1.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf1.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route or Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", rr);
  ASSERT_EQ("", route);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r2(200);
  r2.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");

  // Set up the HSS response for the user registration status query using
  // a specified private user identity.
  _hss_connection->set_result("/impi/7132565489%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf2.homedomain:5058;transport=TCP\"}");

  // Inject a REGISTER request.
  Message msg2;
  msg2._first_hop = true;
  msg2._method = "REGISTER";
  msg1._requri = "sip:homedomain";
  msg2._to = msg2._from;        // To header contains AoR in REGISTER requests.
  msg2._via = tp->to_string(false);
  msg2._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg2._extra += "Authorization: Digest username=\"7132565489@homedomain\"";
  inject_msg(msg2.get_request(), tp);

  // REGISTER request should be forwarded to the server named in the HSS
  // response, scscf1.homedomain.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.2", 5058, tdata);
  ReqMatcher r3("REGISTER");
  r3.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf2.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route or Record-Route headers have been added.
  rr = get_headers(tdata->msg, "Record-Route");
  route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", rr);
  ASSERT_EQ("", route);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r4(200);
  r4.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/7132565489%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteRegisterHSSCaps)
{
  // Tests routing of REGISTER requests when the HSS responses with
  // capabilities.  There are two cases tested here - one where the impi
  // is defaulted from the impu and one where the impi is explicit specified
  // in an Authorization header.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the user registration status query using
  // a default private user identity.  The response returns capabilities
  // rather than an S-CSCF name.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [123, 345],"
                              " \"optional-capabilities\": [654]}");

  // Inject a REGISTER request.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "REGISTER";
  msg1._requri = "sip:homedomain";
  msg1._to = msg1._from;        // To header contains AoR in REGISTER requests.
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  inject_msg(msg1.get_request(), tp);

  // REGISTER request should be forwarded to a server matching all the
  // mandatory capabilities, and as many of the optional capabilities as
  // possible.  In this case, the only S-CSCF that matches all mandatory
  // capabilities is scscf1.homedomain.  scscf1.homedomain does not match
  // the optional capabilities.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("REGISTER");
  r1.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf1.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route or Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", rr);
  ASSERT_EQ("", route);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r2(200);
  r2.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");

  // Set up the HSS response for the user registration status query using
  // a default private user identity.  The response returns capabilities
  // rather than an S-CSCF name.
  _hss_connection->set_result("/impi/7132565489%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [123],"
                              " \"optional-capabilities\": [654]}");

  // Inject a REGISTER request.
  Message msg2;
  msg2._first_hop = true;
  msg2._method = "REGISTER";
  msg1._requri = "sip:homedomain";
  msg2._to = msg2._from;        // To header contains AoR in REGISTER requests.
  msg2._via = tp->to_string(false);
  msg2._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg2._extra += "Authorization: Digest username=\"7132565489@homedomain\"";
  inject_msg(msg2.get_request(), tp);

  // REGISTER request should be forwarded to a server matching all the
  // mandatory capabilities, and as many of the optional capabilities as
  // possible.  In this case, both scscf1 and scscf2 match the mandatory
  // capabilities, but only scscf2 matches the optional capabilities as well.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.2", 5058, tdata);
  ReqMatcher r3("REGISTER");
  r3.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf2.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route or Record-Route headers have been added.
  rr = get_headers(tdata->msg, "Record-Route");
  route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", rr);
  ASSERT_EQ("", route);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r4(200);
  r4.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/7132565489%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteEmergencyRegister)
{
  // Tests routing of REGISTER requests when the "sos" flag is set. This test
  // just tests that we correctly add the "sos=true" parameter to the HTTP GET
  // request that we send to Homestead.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the user registration status query using
  // a default private user identity.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG&sos=true",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

  // Inject a REGISTER request.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "REGISTER";
  msg1._requri = "sip:homedomain";
  msg1._to = msg1._from;        // To header contains AoR in REGISTER requests.
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: <sip:6505551000@" +
                tp->to_string(true) +
                ";ob>;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\n" +
                "Contact: <sip:6505551001@" +
                tp->to_string(true) +
                ";ob;sos>;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  inject_msg(msg1.get_request(), tp);

  // REGISTER request should be forwarded to the server named in the HSS
  // response, scscf1.homedomain.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("REGISTER");
  r1.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf1.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route or Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", rr);
  ASSERT_EQ("", route);

  // Check that the contact header still contains the sos parameter.
  string contact = get_headers(tdata->msg, "Contact");
  EXPECT_THAT(contact, HasSubstr("sos"));

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r2(200);
  r2.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG;sos=true");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteRegisterHSSCapsNoMatch)
{
  // Tests routing of REGISTER requests when the HSS responses with
  // capabilities and there are no suitable S-CSCFs.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the user registration status query using
  // a default private user identity.  The response returns capabilities
  // rather than an S-CSCF name.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [765, 123, 345],"
                              " \"optional-capabilities\": [654]}");

  // Inject a REGISTER request.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "REGISTER";
  msg1._requri = "sip:homedomain";
  msg1._to = msg1._from;        // To header contains AoR in REGISTER requests.
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  inject_msg(msg1.get_request(), tp);

  // No S-CSCFs support all the mandatory capabilities, so the REGISTER is
  // rejected.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r1(600);
  r1.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteRegisterICSCFLoop)
{
  // Tests routing of REGISTER requests when the HSS responds with
  // a register that points back to the ICSCF sproutlet.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the user registration status query using
  // a default private user identity.  The response returns capabilities
  // rather than an S-CSCF name.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:homedomain:" + std::to_string(ICSCF_PORT) + ";transport=TCP\"}");

  // Inject a REGISTER request.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "REGISTER";
  msg1._requri = "sip:homedomain";
  msg1._to = msg1._from;        // To header contains AoR in REGISTER requests.
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  inject_msg(msg1.get_request(), tp);

  // S-CSCF return resolves to the local domain and I-CSCF port,s, so the REGISTER is
  // rejected with a "Loop detected" error.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r1(482);
  r1.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteRegisterSCSCFReturnedCAPAB)
{
  // Tests routing of REGISTER requests when the S-CSCF returned by the HSS
  // responds with a retryable error to the REGISTER request.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the user registration status query using
  // a default private user identity.  The first response (specifying
  // auth_type=REG) returns scscf1, the second response (specifying
  // auth_type=CAPAB) returns scscf1 again.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

  // Inject a REGISTER request.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "REGISTER";
  msg1._requri = "sip:homedomain";
  msg1._to = msg1._from;        // To header contains AoR in REGISTER requests.
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  inject_msg(msg1.get_request(), tp);

  // I-CSCF does an initial HSS lookup with auth_type set to REG,
  // which returns S-CSCF scscf1.homedomain.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("REGISTER");
  r1.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf1.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route or Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", rr);
  ASSERT_EQ("", route);

  // Send a 480 Temporarily Unavailable response.
  inject_msg(respond_to_current_txdata(480));

  // I-CSCF does a second HSS look-up, this time with auth_type set to
  // CAPAB. The HSS returns a scscf name, and no capabilities. The name shouldn't
  // be used (as it's already been tried). I-CSCF should select the S-CSCF with
  // the highest priority (as there are no capabilites) which is scscf4.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.4", 5058, tdata);
  ReqMatcher r2("REGISTER");
  r2.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf4.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route or Record-Route headers have been added.
  rr = get_headers(tdata->msg, "Record-Route");
  route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", rr);
  ASSERT_EQ("", route);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r3(200);
  r3.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");
  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB");

  delete tp;
}

TEST_F(ICSCFSproutletTest, RouteRegisterSCSCFReturnedCAPABAndServerName)
{
  // Tests routing of REGISTER requests when the S-CSCF returned by the HSS
  // responds with a retryable error to the REGISTER request.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the user registration status query using
  // a default private user identity.  The first response (specifying
  // auth_type=REG) returns scscf1, the second response (specifying
  // auth_type=CAPAB) returns scscf1 again.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\","
                              " \"mandatory-capabilities\": [765, 123, 345],"
                              " \"optional-capabilities\": [654]}");

  // Inject a REGISTER request.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "REGISTER";
  msg1._requri = "sip:homedomain";
  msg1._to = msg1._from;        // To header contains AoR in REGISTER requests.
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  inject_msg(msg1.get_request(), tp);

  // I-CSCF does an initial HSS lookup with auth_type set to REG,
  // which returns S-CSCF scscf1.homedomain.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("REGISTER");
  r1.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf1.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route or Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", rr);
  ASSERT_EQ("", route);

  // Send a 480 Temporarily Unavailable response.
  inject_msg(respond_to_current_txdata(480));

  // I-CSCF does a second HSS look-up, this time with auth_type set to
  // CAPAB. The HSS returns a scscf name and capabilities. The name shouldn't
  // be used (as it's already been tried). I-CSCF can't select an S-CSCF as
  // there's none with the required capabilities
  // Check the final response is 504.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r2(504);
  r2.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");
  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB");

  delete tp;
}

TEST_F(ICSCFSproutletTest, RouteRegisterHSSRetry)
{
  // Tests routing of REGISTER requests when the S-CSCF returned by the HSS
  // responds with a retryable error to the REGISTER request.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the user registration status query using
  // a default private user identity.  The first response (specifying
  // auth_type=REG) returns scscf1, the second response (specifying
  // auth_type=CAPAB) returns capabilities.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [123],"
                              " \"optional-capabilities\": [345]}");

  // Inject a REGISTER request.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "REGISTER";
  msg1._requri = "sip:homedomain";
  msg1._to = msg1._from;        // To header contains AoR in REGISTER requests.
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  inject_msg(msg1.get_request(), tp);

  // I-CSCF does an initial HSS lookup with auth_type set to REG,
  // which returns S-CSCF scscf1.homedomain.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("REGISTER");
  r1.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf1.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route or Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", rr);
  ASSERT_EQ("", route);

  // Send a 480 Temporarily Unavailable response.
  inject_msg(respond_to_current_txdata(480));

  // I-CSCF does a second HSS look-up, this time with auth_type set to
  // CAPAB.  Both scscf1 and scscf2 match the
  // mandatory capabilities, but only scscf1 matches the optional capabilities.
  // Since the I-CSCF has already tried scscf1 it picks scscf2 this time.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.2", 5058, tdata);
  ReqMatcher r2("REGISTER");
  r2.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf2.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route or Record-Route headers have been added.
  rr = get_headers(tdata->msg, "Record-Route");
  route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", rr);
  ASSERT_EQ("", route);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r3(200);
  r3.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");
  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteRegisterHSSNoRetry)
{
  // Tests routing of REGISTER requests when the S-CSCF returned by the HSS
  // responds with a non-retryable error to the REGISTER request.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the user registration status query using
  // a default private user identity.  The first response (specifying
  // auth_type=REG) returns scscf1, the second response (specifying
  // auth_type=CAPAB) returns capabilities.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

  // Inject a REGISTER request.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "REGISTER";
  msg1._requri = "sip:homedomain";
  msg1._to = msg1._from;        // To header contains AoR in REGISTER requests.
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  inject_msg(msg1.get_request(), tp);

  // I-CSCF does an initial HSS lookup with auth_type set to REG,
  // which returns S-CSCF scscf1.homedomain.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("REGISTER");
  r1.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf1.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route or Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", rr);
  ASSERT_EQ("", route);

  // Send a 401 Not Authorized response.
  inject_msg(respond_to_current_txdata(401));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r2(401);
  r2.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteRegisterHSSMultipleRetry)
{
  // Tests routing of REGISTER requests when the S-CSCF returned by the HSS
  // responds with a retryable error, and the second selected S-CSCF also
  // responds with a retryable error.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the user registration status query using
  // a default private user identity.  The first response (specifying
  // auth_type=REG) returns scscf1, the second response (specifying
  // auth_type=CAPAB) returns capabilities.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [654],"
                              " \"optional-capabilities\": [123]}");

  // Inject a REGISTER request.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "REGISTER";
  msg1._requri = "sip:homedomain";
  msg1._to = msg1._from;        // To header contains AoR in REGISTER requests.
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  inject_msg(msg1.get_request(), tp);

  // I-CSCF does an initial HSS lookup with auth_type set to REG,
  // which returns S-CSCF scscf1.homedomain.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("REGISTER");
  r1.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf1.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route or Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", rr);
  ASSERT_EQ("", route);

  // Send a 480 Temporarily Unavailable response.
  inject_msg(respond_to_current_txdata(480));

  // I-CSCF does a second HSS look-up, this time with auth_type set to
  // CAPAB. scscf2, scscf3 and scscf4 match the
  // mandatory capabilities, but only scscf2 matches the optional capabilities.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.2", 5058, tdata);
  ReqMatcher r2("REGISTER");
  r2.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf2.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route or Record-Route headers have been added.
  rr = get_headers(tdata->msg, "Record-Route");
  route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", rr);
  ASSERT_EQ("", route);

  // Send a 480 Temporarily Unavailable response.
  inject_msg(respond_to_current_txdata(480));

  // I-CSCF does another retry. scscf4 is selected as it has a higher priority than scscf3
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.4", 5058, tdata);
  ReqMatcher r3("REGISTER");
  r3.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf4.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route or Record-Route headers have been added.
  rr = get_headers(tdata->msg, "Record-Route");
  route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", rr);
  ASSERT_EQ("", route);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r4(200);
  r4.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");
  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB");

  delete tp;
}

TEST_F(ICSCFSproutletTest, RouteRegisterHSSMultipleDefaultCapabs)
{
  // Tests routing of REGISTER requests when the S-CSCF returned by the HSS
  // responds with a retryable error, and the CAPAB request to the HSS
  // doesn't return any capabilities (should be treated as empty)
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the user registration status query using
  // a default private user identity.  The first response (specifying
  // auth_type=REG) returns scscf1, the second response (specifying
  // auth_type=CAPAB) returns no capabilities.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB",
                              "{\"result-code\": 2001}");

  // Inject a REGISTER request.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "REGISTER";
  msg1._requri = "sip:homedomain";
  msg1._to = msg1._from;        // To header contains AoR in REGISTER requests.
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  inject_msg(msg1.get_request(), tp);

  // I-CSCF does an initial HSS lookup with auth_type set to REG,
  // which returns S-CSCF scscf1.homedomain.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("REGISTER");
  r1.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf1.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route or Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", rr);
  ASSERT_EQ("", route);

  // Send a 480 Temporarily Unavailable response.
  inject_msg(respond_to_current_txdata(480));

  // I-CSCF does another retry. scscf4 is selected as it is the scscf with the highest
  // priority (there are no mandatory capabilities)
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.4", 5058, tdata);
  ReqMatcher r2("REGISTER");
  r2.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf4.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route or Record-Route headers have been added.
  rr = get_headers(tdata->msg, "Record-Route");
  route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", rr);
  ASSERT_EQ("", route);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r3(200);
  r3.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");
  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteRegisterHSSFail)
{
  // Tests routing of REGISTER requests when the HSS responds to the
  // registration status lookup with an invalid response.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up HSS response for the user registration status query.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=roaming.net&auth-type=REG",
                              "{\"result-code\": \"5004\"}");

  // Inject a REGISTER request.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "REGISTER";
  msg1._requri = "sip:homedomain";
  msg1._to = msg1._from;        // To header contains AoR in REGISTER requests.
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  // Include a P-Visited-Network-ID header.
  msg1._extra += "\r\nP-Visited-Network-ID: roaming.net";
  inject_msg(msg1.get_request(), tp);

  // The user registration status query fails, so the REGISTER is rejected
  // with a 403 Forbidden response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r1(403);
  r1.matches(tdata->msg);

  free_txdata();

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteRegisterHSSBadResponse)
{
  // Tests various cases where the HSS response either fails or is malformed.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Don't set up a HSS response, so the query fail (this simulates an
  // HSS or Homestead timeout).
  _hss_connection->set_rc("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                          HTTP_SERVER_UNAVAILABLE);

  // Inject a REGISTER request.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "REGISTER";
  msg1._requri = "sip:homedomain";
  msg1._to = msg1._from;        // To header contains AoR in REGISTER requests.
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  inject_msg(msg1.get_request(), tp);

  // The user registration status query fails, so the REGISTER is rejected
  // with a 480 Temporarily Unavailable response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r1(480);
  r1.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_rc("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");

  // Return 403 on the request. The registration should fail
  _hss_connection->set_rc("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                          HTTP_FORBIDDEN);

  // Inject a REGISTER request.
  Message msg2;
  msg2._first_hop = true;
  msg2._method = "REGISTER";
  msg2._requri = "sip:homedomain";
  msg2._to = msg2._from;        // To header contains AoR in REGISTER requests.
  msg2._via = tp->to_string(false);
  msg2._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  inject_msg(msg2.get_request(), tp);

  // The REGISTER is rejected with a 403 Forbidden response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r2(403);
  r2.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_rc("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");

  // Set up HSS response for the user registration status query, with a
  // malformed JSON response (missing the final brace).
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [654],"
                              " \"optional-capabilities\": [123]");
  _hss_connection->set_rc("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                          HTTP_OK);

  // Inject a REGISTER request.
  Message msg3;
  msg3._first_hop = true;
  msg3._method = "REGISTER";
  msg3._requri = "sip:homedomain";
  msg3._to = msg3._from;        // To header contains AoR in REGISTER requests.
  msg3._via = tp->to_string(false);
  msg3._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  inject_msg(msg3.get_request(), tp);

  // The HSS response is malformed, so the REGISTER is rejected with a 480 Temporarily Unavailable response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r3(480);
  r3.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");
  _hss_connection->delete_rc("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");

  // Set up HSS response for the user registration status query, with a
  // well structured JSON response, but where the capabilities are not
  // integers.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [\"this\", \"should\", \"be\", \"a\", \"list\", \"of\", \"ints\"],"
                              " \"optional-capabilities\": [123]}");
  _hss_connection->set_rc("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                          HTTP_OK);

  // Inject a REGISTER request.
  Message msg4;
  msg4._first_hop = true;
  msg4._method = "REGISTER";
  msg4._requri = "sip:homedomain";
  msg4._to = msg4._from;        // To header contains AoR in REGISTER requests.
  msg4._via = tp->to_string(false);
  msg4._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  inject_msg(msg4.get_request(), tp);

  // The user registration status query fails, so the REGISTER is rejected
  // with a 480 Temporarily Unavailable response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r4(480);
  r4.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");
  _hss_connection->delete_rc("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteRegisterAllSCSCFsTimeOut)
{
  // Tests routing of REGISTER requests when all the valid S-CSCFs
  // respond with a 480 to the I-CSCF.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the user registration status query using
  // a default private user identity.  The first response (specifying
  // auth_type=REG) returns scscf1, the second response (specifying
  // auth_type=CAPAB) returns scscf1 again.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [123],"
                              " \"optional-capabilities\": [345]}");

  // Inject a REGISTER request.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "REGISTER";
  msg1._requri = "sip:homedomain";
  msg1._to = msg1._from;        // To header contains AoR in REGISTER requests.
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  inject_msg(msg1.get_request(), tp);

  // I-CSCF does an initial HSS lookup with auth_type set to REG,
  // which returns S-CSCF scscf1.homedomain.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("REGISTER");
  r1.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf1.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route or Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", rr);
  ASSERT_EQ("", route);

  // Send a 480 Temporarily Unavailable response.
  inject_msg(respond_to_current_txdata(480));

  // I-CSCF does a second HSS look-up, this time with auth_type set to
  // CAPAB. The HSS returns capabilities. I-CSCF selects scscf2 as it's
  // the only S-CSCF with the mandatory capabilites that hasn't been
  // tried yet
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.2", 5058, tdata);
  ReqMatcher r2("REGISTER");
  r2.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf2.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route or Record-Route headers have been added.
  rr = get_headers(tdata->msg, "Record-Route");
  route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", rr);
  ASSERT_EQ("", route);

  // Send a 480 Temporarily Unavailable response.
  inject_msg(respond_to_current_txdata(480));

  // Check the final response is 504.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r3(504);
  r3.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");
  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB");

  delete tp;
}

TEST_F(ICSCFSproutletTest, RouteRegisterHSSNotFound)
{
  // Tests routing of REGISTER requests when the HSS CAPAB request fails
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the user registration status query using
  // a default private user identity.  The first response (specifying
  // auth_type=REG) returns scscf1, the second response (specifying
  // auth_type=CAPAB) returns a 403.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");
  _hss_connection->set_rc("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB",
                          HTTP_FORBIDDEN);

  // Inject a REGISTER request.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "REGISTER";
  msg1._requri = "sip:homedomain";
  msg1._to = msg1._from;        // To header contains AoR in REGISTER requests.
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  inject_msg(msg1.get_request(), tp);

  // I-CSCF does an initial HSS lookup with auth_type set to REG,
  // which returns S-CSCF scscf1.homedomain.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("REGISTER");
  r1.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf1.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route or Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", rr);
  ASSERT_EQ("", route);

  // Send a 480 Temporarily Unavailable response.
  inject_msg(respond_to_current_txdata(480));

  // I-CSCF does a second HSS look-up, this time with auth_type set to
  // CAPAB. This throws a 403 though. Check the final response is 403.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r2(403);
  r2.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");
  _hss_connection->delete_rc("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB");

  delete tp;
}

TEST_F(ICSCFSproutletTest, RouteOrigInviteHSSServerName)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the originating location query.
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

  // Inject a INVITE request with orig in the Route header, a P-Served-User
  // header and a P-Charging-Vector header. Check the ICID from the PCV is
  // logged to SAS.
  mock_sas_collect_messages(true);
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg1._extra += "P-Served-User: <sip:6505551000@homedomain>\r\n";
  msg1._extra += "P-Charging-Vector: icid-value=4815152542";
  msg1._route = "Route: <sip:homedomain;orig>";
  inject_msg(msg1.get_request(), tp);
  check_sas_correlator_icid("4815152542");
  mock_sas_discard_messages();
  mock_sas_collect_messages(false);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // INVITE request should be forwarded to the server named in the HSS
  // response, scscf1.homedomain.
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf1.homedomain:5058;transport=TCP;lr;orig>", route);

  // Check that there's no P-Profile-Key header
  string ppk = get_headers(tdata->msg, "P-Profile-Key");
  ASSERT_EQ("", ppk);

  // Check that no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  pjsip_tx_data* txdata = pop_txdata();

  // Send a 180 OK response.
  inject_msg(respond_to_txdata(txdata, 180));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r2(180);
  r2.matches(tdata->msg);
  free_txdata();

  // Send a 200 OK response.
  inject_msg(respond_to_txdata(txdata, 200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r3(200);
  r3.matches(tdata->msg);
  free_txdata();

  test_session_establishment_stats(0, 0, 0, 0);

  _hss_connection->delete_result("/impu/sip%3A6505551000%40homedomain/location?originating=true");

  delete tp;
}

// Test that an originating INVITE that recieves a wildcard in the LIA sends a
// P-Profile-Key header when routing the INVITE to the S-CSCF
TEST_F(ICSCFSproutletTest, RouteOrigInviteHSSServerNameWithWildcard)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the originating location query. This uses a SIP
  // URI wildcard with square brackets (which are only valid in wildcards).
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\","
                              " \"wildcard-identity\": \"sip:650![0-9]{2}.*!@homedomain\" }");

  // Inject a INVITE request, and expect a 100 Trying and forwarded INVITE
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._route = "Route: <sip:homedomain;orig>";
  inject_msg(msg1.get_request(), tp);
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  free_txdata();
  tdata = current_txdata();
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check that a P-Profile-Key has been added that uses the wildcard
  string ppk = get_headers(tdata->msg, "P-Profile-Key");
  ASSERT_EQ("P-Profile-Key: <sip:650![0-9]{2}.*!@homedomain>", PJUtils::unescape_string_for_uri(ppk, stack_data.pool));

  test_session_establishment_stats(0, 0, 0, 0);
  _hss_connection->delete_result("/impu/sip%3A6505551000%40homedomain/location?originating=true");
  delete tp;
}

// Test that a terminating INVITE that recieves a wildcard in the LIA sends a
// P-Profile-Key header when routing the INVITE to the S-CSCF
TEST_F(ICSCFSproutletTest, RouteTermInviteHSSServerNameWithWildcard)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the location query. This uses a Tel URI
  // wildcard
  _hss_connection->set_result("/impu/tel%3A%2B16505551234/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\","
                              " \"wildcard-identity\": \"tel:+16!.*!\" }");

  // Inject a INVITE request, and expect a 100 Trying and forwarded INVITE.
  // The SIP URI is translated to a Tel URI during I-CSCF processing.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._route = "Route: <sip:homedomain>";
  msg1._requri = "sip:+16505551234@homedomain";
  msg1._to = "+16505551234";
  inject_msg(msg1.get_request(), tp);
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  free_txdata();
  tdata = current_txdata();
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check that a P-Profile-Key has been added that uses the wildcard
  string ppk = get_headers(tdata->msg, "P-Profile-Key");
  ASSERT_EQ("P-Profile-Key: <tel:+16!.*!>", PJUtils::unescape_string_for_uri(ppk, stack_data.pool));

  test_session_establishment_stats(0, 0, 0, 0);
  _hss_connection->delete_result("/impu/tel%3A%2B16505551234/location");
  delete tp;
}

TEST_F(ICSCFSproutletTest, RouteOrigInviteHSSCaps)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the originating location query.
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [654],"
                              " \"optional-capabilities\": [567]}");

  // Inject a INVITE request with orig in the Route header and a P-Served-User
  // header.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg1._extra += "P-Served-User: <sip:6505551000@homedomain>";
  msg1._route = "Route: <sip:homedomain;orig>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Both scscf3 and scscf4 match all mandatory capabilities, but scscf4 has
  // higher priority.
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.4", 5058, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf4.homedomain:5058;transport=TCP;lr;orig>", route);

  // Check that no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r2(200);
  r2.matches(tdata->msg);
  free_txdata();

  test_session_establishment_stats(0, 0, 0, 0);

  _hss_connection->delete_result("/impu/sip%3A6505551000%40homedomain/location?originating=true");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteOrigInviteHSSCapsNoMatch)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the originating location query.
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [765, 654],"
                              " \"optional-capabilities\": [567]}");

  // Inject a INVITE request with orig in the Route header and a P-Served-User
  // header.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg1._extra += "P-Served-User: <sip:6505551000@homedomain>";
  msg1._route = "Route: <sip:homedomain;orig>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and a final response
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Check the 600 response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r1(600);
  r1.matches(tdata->msg);
  free_txdata();

  test_session_establishment_stats(0, 0, 0, 0);

  _hss_connection->delete_result("/impu/sip%3A6505551000%40homedomain/location?originating=true");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteOrigInviteHSSRetry)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the originating location query.
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true&auth-type=CAPAB",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [654],"
                              " \"optional-capabilities\": [567]}");

  // Inject a INVITE request with orig in the Route header and a P-Served-User
  // header.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg1._extra += "P-Served-User: <sip:6505551000@homedomain>";
  msg1._route = "Route: <sip:homedomain;orig>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // The HSS originally returns S-CSCF scscf1.homedomain.
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf1.homedomain:5058;transport=TCP;lr;orig>", route);

  // Check that no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Kill the TCP connection to the S-CSCF to force a retry.
  terminate_tcp_transport(tdata->tp_info.transport);
  free_txdata();
  cwtest_advance_time_ms(6000);
  poll();

  // The HSS is queried a second time for capabilities.  This time S-CSCF
  // scscf4.homedomain is selected.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.4", 5058, tdata);
  ReqMatcher r3("INVITE");
  r3.matches(tdata->msg);

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf4.homedomain:5058;transport=TCP;lr;orig>", route);

  // Check that no Record-Route headers have been added.
  rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r4(200);
  r4.matches(tdata->msg);
  free_txdata();

  test_session_establishment_stats(0, 0, 0, 0);

  _hss_connection->delete_result("/impu/sip%3A6505551000%40homedomain/location?originating=true");
  _hss_connection->delete_result("/impu/sip%3A6505551000%40homedomain/location?originating=true&auth-type=CAPAB");

  delete tp;
}

TEST_F(ICSCFSproutletTest, RouteOrigInviteHSSRetryWithWildcard)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the originating location query.
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true&auth-type=CAPAB",
                              "{\"result-code\": 2001,"
                              " \"wildcard-identity\": \"sip:650![0-9].*!@homedomain\","
                              " \"mandatory-capabilities\": [654],"
                              " \"optional-capabilities\": [567]}");

  // Inject a INVITE request with orig in the Route header and a P-Served-User
  // header.
  Message msg1;
  msg1._method = "INVITE";
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg1._extra += "P-Served-User: <sip:6505551000@homedomain>";
  msg1._route = "Route: <sip:homedomain;orig>";
  inject_msg(msg1.get_request(), tp);

  // Expecting a 100 Trying and an INVITE. Free the 100 Trying, then kill the
  // TCP connection to the S-CSCF to force a retry.
  ASSERT_EQ(2, txdata_count());
  free_txdata();
  tdata = current_txdata();
  terminate_tcp_transport(tdata->tp_info.transport);
  free_txdata();
  cwtest_advance_time_ms(6000);
  poll();

  // The HSS is queried a second time for capabilities. This time S-CSCF
  // scscf4.homedomain is selected, and the subscriber has a wildcard
  // identity.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.4", 5058, tdata);

  // Check that a P-Profile-Key has been added that uses the wildcard
  string ppk = get_headers(tdata->msg, "P-Profile-Key");
  ASSERT_EQ("P-Profile-Key: <sip:650![0-9].*!@homedomain>", PJUtils::unescape_string_for_uri(ppk, stack_data.pool));

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r1(200);
  r1.matches(tdata->msg);
  free_txdata();

  test_session_establishment_stats(0, 0, 0, 0);

  _hss_connection->delete_result("/impu/sip%3A6505551000%40homedomain/location?originating=true");
  _hss_connection->delete_result("/impu/sip%3A6505551000%40homedomain/location?originating=true&auth-type=CAPAB");

  delete tp;
}

TEST_F(ICSCFSproutletTest, RouteOrigInviteHSSRetryOnceNoMatchingSCSCF)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the originating location query.
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true&auth-type=CAPAB",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [765, 654],"
                              " \"optional-capabilities\": [567]}");

  // Inject a INVITE request with orig in the Route header and a P-Served-User
  // header.
  Message msg1;
  msg1._method = "INVITE";
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg1._extra += "P-Served-User: <sip:6505551000@homedomain>";
  msg1._route = "Route: <sip:homedomain;orig>";
  inject_msg(msg1.get_request(), tp);

  // Expecting a 100 Trying and an INVITE. Free the 100 Trying, then kill the
  // TCP connection to the S-CSCF to force a retry.
  ASSERT_EQ(2, txdata_count());
  free_txdata();
  tdata = current_txdata();
  terminate_tcp_transport(tdata->tp_info.transport);
  free_txdata();
  cwtest_advance_time_ms(6000);
  poll();

  // Looking up the next S-CSCF in the HSS fails though as there are no S-CSCFs
  // that match all the mandatory capabilites. Check the response - it should
  // be a 503 (as that's what we got from the first S-CSCF we tried).
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r2(503);
  r2.matches(tdata->msg);
  free_txdata();

  test_session_establishment_stats(0, 0, 0, 0);

  _hss_connection->delete_result("/impu/sip%3A6505551000%40homedomain/location?originating=true");
  _hss_connection->delete_result("/impu/sip%3A6505551000%40homedomain/location?originating=true&auth-type=CAPAB");

  delete tp;
}

TEST_F(ICSCFSproutletTest, RouteOrigInviteHSSFail)
{
  // Tests originating call when HSS request fails.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Don't set up the HSS response - this will simulate a 404 response
  // Inject a INVITE request with orig in the Route header and a P-Served-User
  // header.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg1._extra += "P-Served-User: <sip:6505551000@homedomain>";
  msg1._route = "Route: <sip:homedomain;orig>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and final 404 responses.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Check the 404 Not Found.
  tdata = current_txdata();
  RespMatcher(404).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Set up the HSS response for the originating location query.
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true",
                              "{\"result-code\": 5004}");

  // Inject a INVITE request with orig in the Route header and a P-Served-User
  // header.
  Message msg2;
  msg2._first_hop = true;
  msg2._method = "INVITE";
  msg2._via = tp->to_string(false);
  msg2._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg2._extra += "P-Served-User: <sip:6505551000@homedomain>";
  msg2._route = "Route: <sip:homedomain;orig>";
  inject_msg(msg2.get_request(), tp);

  // Expecting 100 Trying and final 404 responses.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Check the 404 Not Found.
  tdata = current_txdata();
  RespMatcher(404).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  test_session_establishment_stats(0, 0, 0, 0);

  _hss_connection->delete_result("/impu/sip%3A6505551000%40homedomain/location?originating=true");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteOrigInviteCancel)
{
  // Tests handling of a CANCEL requests after an INVITE has been forwarded.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the originating location query.
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

  // Inject a INVITE request with orig in the Route header and a P-Served-User
  // header.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg1._extra += "P-Served-User: <sip:6505551000@homedomain>";
  msg1._route = "Route: <sip:homedomain;orig>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // INVITE request should be forwarded to the server named in the HSS
  // response, scscf1.homedomain.
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Store the INVITE to build a later response.
  pjsip_tx_data* invite_tdata = pop_txdata();

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf1.homedomain:5058;transport=TCP;lr;orig>", route);

  // Check that no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Build and send a CANCEL chasing the INVITE.
  Message msg2;
  msg2._first_hop = true;
  msg2._method = "CANCEL";
  msg2._via = tp->to_string(false);
  msg2._unique = msg1._unique;    // Make sure branch and call-id are same as the INVITE
  inject_msg(msg2.get_request(), tp);

  // Expect the 200 OK response to the CANCEL, but no forwarded CANCEL as
  // no provisional response has yet been received.
  ASSERT_EQ(1, txdata_count());

  // Check the 200 OK.
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();
  ASSERT_EQ(0, txdata_count());

  // Send a 100 Trying response to the INVITE, triggering the onward CANCEL.
  inject_msg(respond_to_txdata(invite_tdata, 100));

  // Check the CANCEL is forwarded.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r2("CANCEL");
  r2.matches(tdata->msg);

  // Send a 200 OK response to the CANCEL.  This is swallowed by the proxy.
  inject_msg(respond_to_current_txdata(200));
  ASSERT_EQ(0, txdata_count());

  // Now send a 487 response to the INVITE.
  inject_msg(respond_to_txdata(invite_tdata, 487));

  // Catch the ACK to the 487 response
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r3("ACK");
  r3.matches(tdata->msg);
  free_txdata();

  // Check the 487 response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(487).matches(tdata->msg);
  free_txdata();

  test_session_establishment_stats(0, 0, 0, 0);

  _hss_connection->delete_result("/impu/sip%3A6505551000%40homedomain/location?originating=true");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteTermInviteHSSServerName)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the terminating location query.
  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

  // Inject a terminating INVITE request with a P-Served-User header.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg1._extra += "P-Served-User: <sip:6505551000@homedomain>";
  msg1._route = "Route: <sip:homedomain>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // INVITE request should be forwarded to the server named in the HSS
  // response, scscf1.homedomain.
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf1.homedomain:5058;transport=TCP;lr>", route);

  // Check that no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  pjsip_tx_data* txdata = pop_txdata();

  // Send a 180 OK response.
  inject_msg(respond_to_txdata(txdata, 180));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r2(180);
  r2.matches(tdata->msg);
  free_txdata();

  // Check that session establishment stats were correctly updated on the 180.
  test_session_establishment_stats(1, 0, 1, 0);

  // Send a 200 OK response.
  inject_msg(respond_to_txdata(txdata, 200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r3(200);
  r3.matches(tdata->msg);
  free_txdata();

  test_session_establishment_stats(1, 0, 1, 0);

  _hss_connection->delete_result("/impu/sip%3A6505551234%40homedomain/location");

  delete tp;
}

TEST_F(ICSCFSproutletTest, RouteTermInviteCancel)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the terminating location query.
  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

  // Inject a terminating INVITE request with a P-Served-User header.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg1._extra += "P-Served-User: <sip:6505551000@homedomain>";
  msg1._route = "Route: <sip:homedomain>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // INVITE request should be forwarded to the server named in the HSS
  // response, scscf1.homedomain.
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf1.homedomain:5058;transport=TCP;lr>", route);

  // Check that no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Store the INVITE to build a later response.
  pjsip_tx_data* invite_tdata = pop_txdata();

  // Build and send a CANCEL chasing the INVITE.
  Message msg2;
  msg2._first_hop = true;
  msg2._method = "CANCEL";
  msg2._via = tp->to_string(false);
  msg2._unique = msg1._unique;    // Make sure branch and call-id are same as the INVITE
  inject_msg(msg2.get_request(), tp);

  // Expect the 200 OK response to the CANCEL, but no forwarded CANCEL as
  // no provisional response has yet been received.
  ASSERT_EQ(1, txdata_count());

  // Check the 200 OK.
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();
  ASSERT_EQ(0, txdata_count());

  // Send a 100 Trying response to the INVITE, triggering the onward CANCEL.
  inject_msg(respond_to_txdata(invite_tdata, 100));

  // Check the CANCEL is forwarded.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r2("CANCEL");
  r2.matches(tdata->msg);

  // Send a 200 OK response to the CANCEL.  This is swallowed by the proxy.
  inject_msg(respond_to_current_txdata(200));
  ASSERT_EQ(0, txdata_count());

  // Now send a 487 response to the INVITE.
  inject_msg(respond_to_txdata(invite_tdata, 487));

  // Catch the ACK to the 487 response
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r3("ACK");
  r3.matches(tdata->msg);
  free_txdata();

  // Check the 487 response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(487).matches(tdata->msg);
  free_txdata();

  test_session_establishment_stats(0, 1, 1, 0);

  _hss_connection->delete_result("/impu/sip%3A6505551000%40homedomain/location?originating=true");

  delete tp;

}


TEST_F(ICSCFSproutletTest, RouteTermInviteHSSCaps)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the terminating location query.
  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [567],"
                              " \"optional-capabilities\": [789, 567]}");

  // Inject a INVITE request with orig in the Route header and a P-Served-User
  // header.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg1._extra += "P-Served-User: <sip:6505551000@homedomain>";
  msg1._route = "Route: <sip:homedomain>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Both scscf3 and scscf4 match all mandatory characteristics, but only
  // scscf3 matches both optional capabilities.
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.3", 5058, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf3.homedomain:5058;transport=TCP;lr>", route);

  // Check that no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r2(200);
  r2.matches(tdata->msg);
  free_txdata();

  test_session_establishment_stats(1, 0, 1, 0);

  _hss_connection->delete_result("/impu/sip%3A6505551234%40homedomain/location");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteTermInviteNoUnregisteredServices)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the terminating location query.
  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 5003}");

  // Inject a INVITE request
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:homedomain>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and 480 Temporarily Unavailable
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Check the 480.
  tdata = current_txdata();
  RespMatcher(480).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  test_session_establishment_stats(0, 1, 0, 1);

  _hss_connection->delete_result("/impu/sip%3A6505551234%40homedomain/location");

  delete tp;
}



TEST_F(ICSCFSproutletTest, RouteTermInviteHSSRetry)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the terminating location query.
  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");
  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location?auth-type=CAPAB",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [567],"
                              " \"optional-capabilities\": [789, 567]}");

  // Inject a INVITE request with orig in the Route header and a P-Served-User
  // header.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg1._extra += "P-Served-User: <sip:6505551000@homedomain>";
  msg1._route = "Route: <sip:homedomain>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // INVITE request should be forwarded to the server named in the HSS
  // response, scscf1.homedomain.
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf1.homedomain:5058;transport=TCP;lr>", route);

  // Check that no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Kill the TCP connection to the S-CSCF to force a retry.
  terminate_tcp_transport(tdata->tp_info.transport);
  free_txdata();
  cwtest_advance_time_ms(6000);
  poll();

  // I-CSCF does another HSS location query for capabilities.  This time
  // scscf3 is selected.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.3", 5058, tdata);
  ReqMatcher r3("INVITE");
  r3.matches(tdata->msg);

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf3.homedomain:5058;transport=TCP;lr>", route);

  // Check that no Record-Route headers have been added.
  rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Kill the TCP connection to the S-CSCF to force a retry.
  terminate_tcp_transport(tdata->tp_info.transport);
  free_txdata();
  cwtest_advance_time_ms(6000);
  poll();

  // I-CSCF does another HSS location query for capabilities.  This time
  // scscf4 is selected.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.4", 5058, tdata);
  ReqMatcher r5("INVITE");
  r5.matches(tdata->msg);

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf4.homedomain:5058;transport=TCP;lr>", route);

  // Check that no Record-Route headers have been added.
  rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r6(200);
  r6.matches(tdata->msg);
  free_txdata();

  test_session_establishment_stats(1, 0, 1, 0);

  _hss_connection->delete_result("/impu/sip%3A6505551234%40homedomain/location");
  _hss_connection->delete_result("/impu/sip%3A6505551234%40homedomain/location?auth-type=CAPAB");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteTermInviteTelURI)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the terminating location query.
  _hss_connection->set_result("/impu/tel%3A%2B16505551234/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

  // Inject an INVITE request to a tel URI with a P-Served-User header.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._toscheme = "tel";
  msg1._to = "+16505551234;npdi";
  msg1._todomain = "";
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg1._extra += "P-Served-User: <sip:6505551000@homedomain>";
  msg1._route = "Route: <sip:homedomain>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // INVITE request should be forwarded to the server named in the HSS
  // response, scscf1.homedomain.
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf1.homedomain:5058;transport=TCP;lr>", route);

  // Check that no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r2(200);
  r2.matches(tdata->msg);
  free_txdata();

  test_session_establishment_stats(1, 0, 1, 0);

  _hss_connection->delete_result("/impu/sip%3A6505551234%40homedomain/location");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteTermInviteEnum)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the terminating location query.
  _hss_connection->set_result("/impu/sip%3A%2B16505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

  // Inject an INVITE request to a tel URI with a P-Served-User header.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._toscheme = "tel";
  msg1._to = "+16605551234";
  msg1._todomain = "";
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg1._extra += "P-Served-User: <sip:6505551000@homedomain>";
  msg1._route = "Route: <sip:homedomain>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // INVITE request should be forwarded to the server named in the HSS
  // response, scscf1.homedomain.
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf1.homedomain:5058;transport=TCP;lr>", route);

  // Check that no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r2(200);
  r2.matches(tdata->msg);
  free_txdata();

  test_session_establishment_stats(1, 0, 1, 0);

  _hss_connection->delete_result("/impu/sip%3A6505551234%40homedomain/location");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteTermInviteEnumBgcf)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Inject an INVITE request to a tel URI with a P-Served-User header.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._toscheme = "tel";
  msg1._to = "+16607771234";
  msg1._todomain = "";
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg1._extra += "P-Served-User: <sip:6505551000@homedomain>";
  msg1._route = "Route: <sip:homedomain>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // INVITE request should be forwarded to the BGCF.
  tdata = current_txdata();
  expect_target("FAKE_UDP", "0.0.0.0", 0, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:bgcf.homedomain;lr>", route);

  // Check that no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r2(200);
  r2.matches(tdata->msg);
  free_txdata();

  test_session_establishment_stats(1, 0, 1, 0);

  delete tp;
}

// Test the case where the I-CSCF does an ENUM lookup which returns
// NP data. The requ URI should be rewritten to include the NP data,
// and the request should be forwarded to the BGCF
TEST_F(ICSCFSproutletTest, RouteTermInviteEnumNP)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Inject an INVITE request to a tel URI
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._toscheme = "tel";
  msg1._to = "+1690100001";
  msg1._todomain = "";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // INVITE request should be forwarded to the BGCF.
  tdata = current_txdata();
  expect_target("FAKE_UDP", "0.0.0.0", 0, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check the RequestURI has been altered
  ASSERT_EQ("tel:+1690100001;npdi;rn=16901", str_uri(tdata->msg->line.req.uri));

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r2(200);
  r2.matches(tdata->msg);
  free_txdata();

  test_session_establishment_stats(1, 0, 1, 0);

  delete tp;
}

// Test the case where the I-CSCF does an ENUM lookup which returns
// NP data, but already has NP in the req URI. The req URI should not
// be rewritten and the request should be forwarded to the BGCF
TEST_F(ICSCFSproutletTest, RouteTermInviteEnumExistingNP)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Inject an INVITE request to a tel URI
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._toscheme = "tel";
  msg1._to = "+1690100001;rn=+16;npdi";
  msg1._todomain = "";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // INVITE request should be forwarded to the BGCF.
  tdata = current_txdata();
  expect_target("FAKE_UDP", "0.0.0.0", 0, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check the RequestURI hasn't been altered
  ASSERT_EQ("tel:+1690100001;rn=+16;npdi", str_uri(tdata->msg->line.req.uri));

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r2(200);
  r2.matches(tdata->msg);
  free_txdata();

  test_session_establishment_stats(1, 0, 1, 0);

  delete tp;
}

// Test the case where the I-CSCF routes requests to subscribers not in the HSS
// to a transit function, rather than doing an ENUM lookup. When the ENUM
// service is disabled, calls should just go to the BGCF.
TEST_F(ICSCFSproutletTest, RouteTermInviteTransitFunction)
{
  // Disable ENUM.
  _icscf_sproutlet->_enum_service = NULL;

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Inject an INVITE request to a tel URI
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._toscheme = "tel";
  msg1._to = "+1690100001";
  msg1._todomain = "";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // INVITE request should be forwarded to the BGCF.
  tdata = current_txdata();
  expect_target("FAKE_UDP", "0.0.0.0", 0, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:bgcf.homedomain;lr>", route);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r2(200);
  r2.matches(tdata->msg);
  free_txdata();

  test_session_establishment_stats(1, 0, 1, 0);

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteTermInviteUserPhone)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the terminating location query.
  _hss_connection->set_result("/impu/tel%3A%2B16505551234/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

  // Inject an INVITE request to a sip URI representing a telephone number with a
  // P-Served-User header.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:+16505551234@homedomain;user=phone;isub=1234;ext=4321";
  msg1._to = "+16505551234";
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg1._extra += "P-Served-User: <sip:6505551000@homedomain>";
  msg1._route = "Route: <sip:homedomain>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // INVITE request should be forwarded to the server named in the HSS
  // response, scscf1.homedomain.
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf1.homedomain:5058;transport=TCP;lr>", route);

  // Check that no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r2(200);
  r2.matches(tdata->msg);
  free_txdata();

  test_session_establishment_stats(1, 0, 1, 0);

  _hss_connection->delete_result("/impu/sip%3A6505551234%40homedomain/location");

  delete tp;
}

// The following test (similar to RouteTermInviteUserPhone apart from the
// absence of leading "+" characters on the user) verifies that I-CSCF doesn't
// perform a Tel URI conversion if the number is not globally specified (i.e.
// doesn't start with a "+") AND enforce_global_lookups is on.
TEST_F(ICSCFSproutletTest, RouteTermInviteLocalUserPhoneFailure)
{
  pjsip_tx_data* tdata;

  // Turn on enforcement of global-only user=phone to Tel URI lookups in I-CSCF
  URIClassifier::enforce_global = true;

  // Setup common config and submit test INVITE
  TransportFlow* tp = route_term_invite_local_user_phone_setup();

  // Expecting 100 Trying and final 404 responses.  I-CSCF shouldn't perform
  // a TelURI conversion and therefore shouldn't match on the HSS result
  // inserted above.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Check the 404 Not Found.
  tdata = current_txdata();
  RespMatcher(404).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  test_session_establishment_stats(0, 1, 1, 0);

  _hss_connection->delete_result("/impu/tel%3A16505551234/location");

  delete tp;
}

// The following test checks that the user=phone => Tel URI conversion IS
// performed for location lookup for local numbers if enforce_global_lookups
// is OFF
TEST_F(ICSCFSproutletTest, RouteTermInviteLocalUserPhoneSuccess)
{
  pjsip_tx_data* tdata;

  // Turn off enforcement of global-only user=phone to Tel URI lookups in I-CSCF
  URIClassifier::enforce_global = false;

  // Setup common config and submit test INVITE
  TransportFlow* tp = route_term_invite_local_user_phone_setup();

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // INVITE request should be forwarded to the server named in the HSS
  // response, scscf1.homedomain.
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf1.homedomain:5058;transport=TCP;lr>", route);

  // Check that no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r2(200);
  r2.matches(tdata->msg);
  free_txdata();

  test_session_establishment_stats(1, 0, 1, 0);

  _hss_connection->delete_result("/impu/tel%3A16505551234/location");

  delete tp;
}

TEST_F(ICSCFSproutletTest, RouteTermInviteNumericSIPURI)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the terminating location query.
  _hss_connection->set_result("/impu/tel%3A%2B16505551234/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

  // Inject an INVITE request to a sip URI representing a telephone number with a
  // P-Served-User header.
  //
  // Add NP data to the SIP URI - it should be ignored for the purposes of SIP -> Tel URI
  // conversion
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:+16505551234;npdi;rn=567@homedomain";
  msg1._to = "+16505551234";
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg1._extra += "P-Served-User: <sip:6505551000@homedomain>";
  msg1._route = "Route: <sip:homedomain>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // INVITE request should be forwarded to the server named in the HSS
  // response, scscf1.homedomain.
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Verify that the user parameters were carried through the SIP to Tel URI conversion successfully
  ASSERT_EQ("tel:+16505551234;npdi;rn=567", str_uri(tdata->msg->line.req.uri));

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf1.homedomain:5058;transport=TCP;lr>", route);

  // Check that no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r2(200);
  r2.matches(tdata->msg);
  free_txdata();

  test_session_establishment_stats(1, 0, 1, 0);

  _hss_connection->delete_result("/impu/sip%3A6505551234%40homedomain/location");

  delete tp;
}


TEST_F(ICSCFSproutletTest, ProxyAKARegisterChallenge)
{
  // Tests that routing a REGISTER 401 repsonse with an AKA challenge does not
  // change the contents of the www-authenticate header (this was sprout
  // issue 412).

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the user registration status query using
  // a default private user identity.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

  // Inject a REGISTER request.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "REGISTER";
  msg1._requri = "sip:homedomain";
  msg1._to = msg1._from;        // To header contains AoR in REGISTER requests.
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  inject_msg(msg1.get_request(), tp);

  // REGISTER request is forwarded on.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();

  // Reject the REGISTER with a 401 response with a WWW-Authenticate header.
  std::string www_auth = "WWW-Authenticate: Digest  realm=\"os1.richlab.datcon.co.uk\","
                           "nonce=\"u1ZqEvWFsXIqYZ0TwbCQ8/sa60VVnTAw6epZzjfS+30\","
                           "opaque=\"143fe4cd3f27d32b\","
                           "algorithm=AKAv1-MD5,"
                           "qop=\"auth\","
                           "ck=\"d725a54a6097b9db17933e583c7fefb0\","
                           "ik=\"c8d8c92790a214e3877aa9ab4c3fdaf6\"";
  inject_msg(respond_to_current_txdata(401, "", www_auth));

  // Check the response is forwarded back to the source with the same
  // WWW-Authenticate header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  EXPECT_EQ(get_headers(tdata->msg, "WWW-Authenticate"), www_auth);

  // Tidy up.
  free_txdata();
  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");
  delete tp; tp = NULL;
}


TEST_F(ICSCFSproutletTest, RequestErrors)
{
  // Tests various errors on requests.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Inject a INVITE request with a sips: RequestURI
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._toscheme = "sips";
  msg1._from = "alice";
  msg1._to = "+2425551234";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Check the 416 Unsupported URI Scheme response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(416).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Send an ACK to complete the UAS transaction.
  msg1._method = "ACK";
  inject_msg(msg1.get_request(), tp);

  // Inject an INVITE request with Max-Forwards <= 1.
  Message msg2;
  msg2._first_hop = true;
  msg2._method = "INVITE";
  msg2._requri = "sip:bob@awaydomain";
  msg2._from = "alice";
  msg2._to = "bob";
  msg2._todomain = "awaydomain";
  msg2._via = tp->to_string(false);
  msg2._route = "Route: <sip:proxy1.awaydomain;transport=TCP;lr>";
  msg2._forwards = 1;
  inject_msg(msg2.get_request(), tp);

  // Check the 483 Too Many Hops response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(483).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Send an ACK to complete the UAS transaction.
  msg2._method = "ACK";
  inject_msg(msg2.get_request(), tp);

  // This request won't even reach the I-CSCF sproutlet and so won't get
  // counted in our stats.   This probably isn't ideal but we think it is
  // acceptable to live with.
  test_session_establishment_stats(0, 0, 0, 0);

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteOrigInviteBadServerName)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the originating location query.
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"INVALID!\"}");

  // Inject a INVITE request with orig in the Route header and a P-Served-User
  // header.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._via = tp->to_string(false);
  msg1._extra += "P-Served-User: <sip:6505551000@homedomain>";
  msg1._route = "Route: <sip:homedomain;orig>";
  inject_msg(msg1.get_request(), tp);

  // Should have a 100 Trying and a 480 Temporarily Unavailable.
  ASSERT_EQ(2, txdata_count());

  // Deal with the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Deal with the 480 Temporarily Unavailable.
  tdata = current_txdata();
  RespMatcher(480).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  test_session_establishment_stats(0, 0, 0, 0);

  // Now try again, but configure a tel URI.  This should fail in the same way
  // as it's not routable.
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"tel:2015551234\"}");

  msg1._unique += 1; // We want a new call-ID and branch parameter.
  inject_msg(msg1.get_request(), tp);

  // Should have a 100 Trying and a 480 Temporarily Unavailable.
  ASSERT_EQ(2, txdata_count());

  // Deal with the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Deal with the 480 Temporarily Unavailable.
  tdata = current_txdata();
  RespMatcher(480).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  test_session_establishment_stats(0, 0, 0, 0);

  // Finally use a SIPS uri.
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sips:scscf1.homedomain:5058;transport=TCP\"}");

  msg1._unique += 1; // We want a new call-ID and branch parameter.
  inject_msg(msg1.get_request(), tp);

  ASSERT_EQ(2, txdata_count());

  // Deal with the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Deal with the 480 Temporarily Unavailable.
  tdata = current_txdata();
  RespMatcher(480).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  test_session_establishment_stats(0, 0, 0, 0);

  _hss_connection->delete_result("/impu/sip%3A6505551000%40homedomain/location?originating=true");

  delete tp;
}

TEST_F(ICSCFSproutletTest, INVITEWithTwoRouteHeaders)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Inject a INVITE request with orig in the Route header and a P-Served-User
  // header.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:icscf.homedomain;lr>, <sip:scscf1.homedomain:5059;transport=TCP;lr;orig>";
  inject_msg(msg1.get_request(), tp);

  ASSERT_EQ(2, txdata_count());

  // Ignore the 100 Trying
  free_txdata();

  // INVITE request should be forwarded to the server named in the Route header, scscf1.homedomain.
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5059, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check that no additional Route header has been added
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf1.homedomain:5059;transport=TCP;lr;orig>", route);

  // Check that no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r2(200);
  r2.matches(tdata->msg);
  free_txdata();

  test_session_establishment_stats(1, 0, 1, 0);

  delete tp;
}

// Test the case where the I-CSCF receives an ACK. This is not valid and should be dropped.
TEST_F(ICSCFSproutletTest, RouteOutOfDialogAck)
{
  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Inject an ACK request to a local URI
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "ACK";
  msg1._requri = "sip:3196914123@homedomain;transport=UDP";
  inject_msg(msg1.get_request(), tp);

  // Expect it to just be dropped
  ASSERT_EQ(0, txdata_count());
  free_txdata();

  // Allow the transaction to time out so we don't leak PJSIP memory.
  cwtest_advance_time_ms(33000L);
  poll();
  delete tp;
}

// Test the I-CSCF can handle an originating MESSAGE where the Request URI is
// "urn:service:sos".
TEST_F(ICSCFSproutletTest, ICSCFHandlesUrnUriOrig)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the terminating location query.
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true",
                              "{\"result-code\": 2001,"
                              "\"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

  // Inject a SIP MESSAGE.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "MESSAGE";
  msg1._requri = "urn:service:sos";
  msg1._full_to_header = "To: <urn:service:sos>";
  msg1._route = "Route: <sip:homedomain;orig>";
  std::string p_asserted_id = "P-Asserted-Identity: <sip:";
  p_asserted_id.append(msg1._from).append("@").append(msg1._fromdomain).append(">");
  msg1._extra = p_asserted_id;
  inject_msg(msg1.get_request(), tp);

  // Check that the MESSAGE is forwarded as expected.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();

  // Check the method and content of the MESSAGE is correct.
  ReqMatcher r1("MESSAGE");
  r1.matches(tdata->msg);
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  EXPECT_EQ("urn:service:sos", r1.uri());
  EXPECT_THAT(get_headers(current_txdata()->msg, "To"),
              testing::MatchesRegex("To: <urn:service:sos>"));

  // Inject a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the correct response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher r2(200);
  r2.matches(tdata->msg);
  expect_target("TCP", "1.2.3.4", 49152, tdata);

  //Clean up.
  free_txdata();
  _hss_connection->delete_result("/impu/sip%3A6505551000%40homedomain/location?originating=true");
  delete tp;
}

// Test the I-CSCF can handle a terminating MESSAGE where the Request URI is
// "urn:service:sos".
TEST_F(ICSCFSproutletTest, ICSCFHandlesUrnUriTerm)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Inject a SIP MESSAGE.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "MESSAGE";
  msg1._requri = "urn:service:sos";
  msg1._full_to_header = "To: <urn:service:sos>";
  msg1._route = "Route: <sip:homedomain>";
  inject_msg(msg1.get_request(), tp);

  // As the message is terminating the I-CSCF will attempt to route based on
  // the ReqURI - as this in an invalid URI to route on the MESSAGE should
  // be rejected.
  tdata = current_txdata();
  RespMatcher(400).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Clean up.
  delete tp;
}

// Test the I-CSCF can handle an originating message where we can't parse the public ID
TEST_F(ICSCFSproutletTest, ICSCFHandlesOrigInvalid)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Inject a SIP MESSAGE.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "MESSAGE";
  msg1._requri = "urn:service:sos";
  msg1._extra += "P-Served-User: <urn:service:sos>";
  msg1._route = "Route: <sip:homedomain;orig>";
  inject_msg(msg1.get_request(), tp);

  // As the message is originating the I-CSCF will attempt to get the subscriber
  // details based on the P-Served-User - as this an invalid URI to be in the
  // the HSS the MESSAGE should be rejected.
  tdata = current_txdata();
  RespMatcher(400).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Clean up.
  delete tp;
}

// Test the I-CSCF can handle a REGISTER where we can't parse the public ID
TEST_F(ICSCFSproutletTest, ICSCFHandlesRegInvalid)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Inject a SIP MESSAGE.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "REGISTER";
  msg1._requri = "sip:homedomain";
  msg1._full_to_header = "To: <urn:service:sos>";
  msg1._route = "Route: <sip:homedomain>";
  inject_msg(msg1.get_request(), tp);

  // As this is a REGISTER the I-CSCF will attempt to get the subscriber
  // details based on the To header - as this an invalid URI to be in the
  // the HSS the MESSAGE should be rejected.
  tdata = current_txdata();
  RespMatcher(400).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Clean up.
  delete tp;
}

// Test the I-CSCF can handle a message where we can't parse the public ID after an ENUM lookup
TEST_F(ICSCFSproutletTest, ICSCFHandlesEnumInvalid)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "1.2.3.4",
                                        49152);

  // Inject an INVITE request to a tel URI with a P-Served-User header.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "MESSAGE";
  msg1._toscheme = "tel";
  msg1._to = "+1661000000";
  msg1._todomain = "";
  msg1._route = "Route: <sip:homedomain>";
  inject_msg(msg1.get_request(), tp);

  // The ENUM rule means that the MESSAGE should be routed to urn:services:sos
  // - as this is an invalid URI to route on the MESSAGE should be rejected.
  tdata = current_txdata();
  RespMatcher(400).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Clean up.
  delete tp;
}
