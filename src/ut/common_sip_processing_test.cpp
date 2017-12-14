/**
 * @file common_sip_processing_test.cpp
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

#include "pjutils.h"
#include "constants.h"
#include "siptest.hpp"
#include "utils.h"
#include "test_utils.hpp"
#include "test_interposer.hpp"
#include "sproutletproxy.h"
#include "common_sip_processing.h"
#include "counter.h"
#include "fakesnmp.hpp"
#include "testingcommon.h"

using namespace std;

class CommonProcessingTest : public SipTest
{
public:
  int ICSCF_PORT = 5052;

  /// Set up test case.  Caller must clear host_mapping.
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();

    // Schedule timers.
    SipTest::poll();
  }

  static void TearDownTestCase()
  {
    // Shut down the transaction module first, before we destroy the
    // objects that might handle any callbacks!
    SipTest::TearDownTestCase();
  }

  CommonProcessingTest()
  {
    _log_traffic = PrintingTestLogger::DEFAULT.isPrinting();

    // Create a TCP connection to the I-CSCF listening port.
    _tp = new TransportFlow(TransportFlow::Protocol::TCP,
                            ICSCF_PORT,
                            "1.2.3.4",
                            49152);


    // Load monitor with one token in the bucket at startup.
    _lm = new LoadMonitor(0, 1, 0, 0, 0);

    _requests_counter = &SNMP::FAKE_COUNTER_BY_SCOPE_TABLE;
    _overload_counter = &SNMP::FAKE_COUNTER_BY_SCOPE_TABLE;

    _health_checker = new HealthChecker();

    init_common_sip_processing(_requests_counter, _health_checker);
  }

  ~CommonProcessingTest()
  {
    delete(_tp);
    delete(_lm);
    delete(_health_checker);
    unregister_common_processing_module();
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
  }

protected:
  TransportFlow* _tp;
  LoadMonitor* _lm;
  SNMP::CounterByScopeTable* _requests_counter;
  SNMP::CounterByScopeTable* _overload_counter;
  HealthChecker* _health_checker;
};

// Helper PJSIP modules which return a response that goes back through
// common_sip_processing code.

static pj_bool_t always_ok(pjsip_rx_data* rdata)
{
  pjsip_tx_data *tdata;
  pjsip_response_addr res_addr;
  pj_str_t string;
  pj_cstr(&string, "OK"),
  pjsip_endpt_create_tdata(stack_data.endpt, &tdata);
  pjsip_get_response_addr(tdata->pool, rdata, &res_addr);
  pjsip_endpt_create_response(stack_data.endpt,
                              rdata,
                              PJSIP_SC_OK,
                              &string,
                              &tdata);
  pjsip_endpt_send_response(stack_data.endpt, &res_addr, tdata, NULL, NULL);
  return PJ_TRUE;
}

static pj_bool_t always_reject(pjsip_rx_data* rdata)
{
  pjsip_tx_data *tdata;
  pjsip_response_addr res_addr;
  pj_str_t string;
  pj_cstr(&string, "Bad Request"),
  pjsip_endpt_create_tdata(stack_data.endpt, &tdata);
  pjsip_get_response_addr(tdata->pool, rdata, &res_addr);
  pjsip_endpt_create_response(stack_data.endpt,
                              rdata,
                              PJSIP_SC_BAD_REQUEST,
                              &string,
                              &tdata);
  pjsip_endpt_send_response(stack_data.endpt, &res_addr, tdata, NULL, NULL);
  return PJ_TRUE;
}

static pjsip_module mod_ok =
{
  NULL, NULL,                           /* prev, next.          */
  pj_str("mod-ok"),      /* Name.                */
  -1,                                   /* Id                   */
  PJSIP_MOD_PRIORITY_UA_PROXY_LAYER, /* Priority             */
  NULL,                                 /* load()               */
  NULL,                                 /* start()              */
  NULL,                                 /* stop()               */
  NULL,                                 /* unload()             */
  &always_ok,                   /* on_rx_request()      */
  NULL,                   /* on_rx_response()     */
  NULL,                   /* on_tx_request()      */
  NULL,                   /* on_tx_response()     */
  NULL,                                 /* on_tsx_state()       */
};

static pjsip_module mod_reject =
{
  NULL, NULL,                           /* prev, next.          */
  pj_str("mod-reject"),      /* Name.                */
  -1,                                   /* Id                   */
  PJSIP_MOD_PRIORITY_UA_PROXY_LAYER, /* Priority             */
  NULL,                                 /* load()               */
  NULL,                                 /* start()              */
  NULL,                                 /* stop()               */
  NULL,                                 /* unload()             */
  &always_reject,                   /* on_rx_request()      */
  NULL,                   /* on_rx_response()     */
  NULL,                   /* on_tx_request()      */
  NULL,                   /* on_tx_response()     */
  NULL,                                 /* on_tsx_state()       */
};

using TestingCommon::Message;

TEST_F(CommonProcessingTest, OptionsPollPingICSCF)
{
  /// Test OPTIONS request to a local node address (ICSCF) in the following 3 cases:
  /// Case 1. Standard OPTIONS ping
  /// Case 2. "user=phone" URI parameter is incorrectly added to the request URI and
  ///         the URI contains the user part.
  ///         The parameter should be ignored and a 200 OK response received.
  /// Case 3. "user=phone" URI parameter is incorrectly added to the request URI and
  ///         the URI does not contain the user part.
  ///         The parameter should be ignored and a 200 OK response received.

  pjsip_tx_data* tdata;

  //Create a TCP connection to the I-CSCF listening port.  
  delete(_tp);
  _tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        ICSCF_PORT,
                                        "127.0.0.1",
                                        49152);

  // Set up a new Load monitor with enough tokens for each test.
  delete(_lm);
  _lm = new LoadMonitor(0, 3, 0, 0, 0);
  init_common_sip_processing(_requests_counter, _health_checker);

  pjsip_endpt_register_module(stack_data.endpt, &mod_ok);

  /// Case 1.
  // Inject an OPTIONS poll request.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "OPTIONS";
  msg1._requri = std::string("sip:poll-sip@127.0.0.1:") + std::to_string(ICSCF_PORT);
  msg1._via = "127.0.0.1";
  msg1._todomain = std::string("127.0.0.1:") + std::to_string(ICSCF_PORT);
  msg1._to = "poll-sip";
  msg1._fromdomain = "127.0.0.1";
  msg1._from = msg1._to;
  msg1._contentlength = false;
  msg1._extra = "Contact: <sip:127.0.0.1>\nAccept: application/sdp\nContent-Length: 0";
  inject_msg(msg1.get_request(), _tp);

  // Expect a 200 OK response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher r1(200);
  r1.matches(tdata->msg);

  free_txdata();

  /// Case 2.
  // Inject an OPTIONS poll request.
  Message msg2 = msg1;
  msg2._requri += std::string(";user=phone");
  inject_msg(msg2.get_request(), _tp);

  // Expect a 200 OK response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher r2(200);
  r2.matches(tdata->msg);

  free_txdata();

  /// Case 3.
  // Inject an OPTIONS poll request.
  Message msg3 = msg1;
  msg3._requri = std::string("sip:127.0.0.1:") + std::to_string(ICSCF_PORT) + std::string(";user=phone");
  msg3._to = "";
  msg3._from = msg3._to;
  inject_msg(msg3.get_request(), _tp);

  // Expect a 200 OK response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher r3(200);
  r3.matches(tdata->msg);

  free_txdata();

  pjsip_endpt_unregister_module(stack_data.endpt, &mod_ok);
}

TEST_F(CommonProcessingTest, RequestAllowed)
{
  // Tests that, when there is a token in the load monitor's bucket, a
  // request is not rejected.

  // Inject a request.
  Message msg1;
  msg1._first_hop = true;
  inject_msg(msg1.get_request(), _tp);

  // As only the common processing module is loaded (and not anything
  // that will actually handle the request), expect it to just disappear.
  ASSERT_EQ(0, txdata_count());
}

TEST_F(CommonProcessingTest, AckRequestAlwaysAllowed)
{
  // Tests that, even when there is no token in the load monitor's bucket, an
  // ACK request is not rejected.

  // Consume the only token in the bucket.
  _lm->admit_request(0);

  // Inject an ACK request.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "ACK";
  inject_msg(msg1.get_request(), _tp);

  // As only the common processing module is loaded (and not anything
  // that will actually handle the request), expect it to just disappear.
  ASSERT_EQ(0, txdata_count());
}

TEST_F(CommonProcessingTest, BadRequestRejected)
{
  // Tests that a malformed request receives a 400 Bad Request error.
  pjsip_tx_data* tdata;

  // Inject a request with an invalid Contact.
  Message msg1;
  msg1._first_hop = true;
  msg1._extra = "Contact: ;;";
  inject_msg(msg1.get_request(), _tp);

  // Expect a 400 error.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher r1(400);
  r1.matches(tdata->msg);

  free_txdata();
}

TEST_F(CommonProcessingTest, BadAckRequestDropped)
{
  // Tests that a malformed ACK request is dropped, and moreover that this
  // is handled by Sprout code before causing PJSIP errors.
  CapturingTestLogger log;

  // Inject an ACK request with an invalid Contact.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "ACK";
  msg1._extra = "Contact: ;;";
  inject_msg(msg1.get_request(), _tp);

  // Expect it to just vanish.
  ASSERT_EQ(0, txdata_count());

  // And expect no errors from PJSIP
  EXPECT_FALSE(log.contains("pjsip: Assert failed"));
}

TEST_F(CommonProcessingTest, BadResponseDropped)
{
  // Tests that a malformed response is just dropped,
  // rather than receiving a 400 Bad Request error.

  // Inject a response with an invalid Contact.
  Message msg1;
  msg1._first_hop = true;
  msg1._extra = "Contact: ;;";
  inject_msg(msg1.get_response(), _tp);

  // Expect it to just vanish.
  ASSERT_EQ(0, txdata_count());
}

TEST_F(CommonProcessingTest, SupportedHeaderWithCommas)
{
  // Tests that a variety of Supported headers are accepted
  // including ones with trailing commas.
    std::vector<std::string> headers = {
      "Supported: ",
      "Supported: \n ",
      "Supported: timer",
      "Supported: timer\n   ",
      "Supported: \n timer",
      "Supported: timer, path",
      "Supported: timer,\n path",
      "Supported: timer\n ,",
      "Supported: timer,",
      "Supported: timer\n ,",
      "Supported: timer,path, ",
      "Supported: timer, \n path, ",
      "Supported: \n timer,\n path, ",
      "Supported: ,",
      "Supported: ,,,,,,",
      "Supported: ,,,\n ,,,",
  };

  // Set up a new Load monitor with enough tokens for each test.
  delete(_lm);
  _lm = new LoadMonitor(0, headers.size(), 0, 0, 0);
  init_common_sip_processing(_requests_counter, _health_checker);

  pjsip_endpt_register_module(stack_data.endpt, &mod_ok);

  for (std::string h: headers) {
    SCOPED_TRACE(h);
    // Inject a request with the latest header.
    Message msg1;
    msg1._first_hop = true;
    msg1._extra = h;
    inject_msg(msg1.get_request(), _tp);

    // Expect a response from mod_ok.
    ASSERT_EQ(1, txdata_count());

    pjsip_tx_data* tdata = current_txdata();
    RespMatcher r1(200);
    r1.matches(tdata->msg);

    free_txdata();
  }
  pjsip_endpt_unregister_module(stack_data.endpt, &mod_ok);
}

// If:
//  - an exception has already been hit
//  - the health-checker runs a check
//  - and all the requests seen recently have not had a response
// then Sprout should be aborted.
TEST_F(CommonProcessingTest, DeathTest_MissingResponseFailsHealthCheck)
{
  ::testing::FLAGS_gtest_death_test_style = "threadsafe";
  _health_checker->hit_exception();

  // Inject a message.
  Message msg1;
  msg1._first_hop = true;
  inject_msg(msg1.get_request(), _tp);

  // Expect it to just vanish.
  ASSERT_EQ(0, txdata_count());

  ASSERT_DEATH(_health_checker->do_check(), "");
}

// If:
//  - the health-checker runs a check
//  - and all the requests seen recently have not had a response
//  - but an exception has not already been hit
// then Sprout should not be aborted.
TEST_F(CommonProcessingTest, MissingResponseWithoutExceptionPassesHealthCheck)
{
  // Inject a message.
  Message msg1;
  msg1._first_hop = true;
  inject_msg(msg1.get_request(), _tp);

  // Expect it to just vanish.
  ASSERT_EQ(0, txdata_count());

  // This should not crash
  _health_checker->do_check();
}

// If:
//  - an exception has already been hit
//  - the health-checker runs a check
//  - and one of the INVITE requests seen recently had a 200 OK response
// then Sprout should not be aborted.
TEST_F(CommonProcessingTest, Invite200PassesHealthCheck)
{
  _health_checker->hit_exception();

  pjsip_endpt_register_module(stack_data.endpt, &mod_ok);

  // Inject a message.
  Message msg1;
  msg1._first_hop = true;
  inject_msg(msg1.get_request(), _tp);

  // Expect a response from mod_ok.
  ASSERT_EQ(1, txdata_count());

  // This should not crash
  _health_checker->do_check();
  pjsip_endpt_unregister_module(stack_data.endpt, &mod_ok);
}

// If:
//  - an exception has already been hit
//  - the health-checker runs a check
//  - and all of the INVITE requests seen recently had a 400 response
// then Sprout should be aborted.
TEST_F(CommonProcessingTest, DeathTest_Invite400FailsHealthCheck)
{
  ::testing::FLAGS_gtest_death_test_style = "threadsafe";
  _health_checker->hit_exception();

  pjsip_endpt_register_module(stack_data.endpt, &mod_reject);

  // Inject a message.
  Message msg1;
  msg1._first_hop = true;
  inject_msg(msg1.get_request(), _tp);

  // Expect a response from mod_reject.
  ASSERT_EQ(1, txdata_count());

  ASSERT_DEATH(_health_checker->do_check(), "");
  pjsip_endpt_unregister_module(stack_data.endpt, &mod_reject);
}

// If:
//  - an exception has already been hit
//  - the health-checker runs a check
//  - and no INVITE requests have been seen recently
// then Sprout should be aborted.
TEST_F(CommonProcessingTest, DeathTest_Message200FailsHealthCheck)
{
  ::testing::FLAGS_gtest_death_test_style = "threadsafe";
  _health_checker->hit_exception();

  pjsip_endpt_register_module(stack_data.endpt, &mod_ok);

  // Inject a message.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "MESSAGE";
  inject_msg(msg1.get_request(), _tp);

  // Expect a response from mod_ok.
  ASSERT_EQ(1, txdata_count());

  ASSERT_DEATH(_health_checker->do_check(), "");
  pjsip_endpt_unregister_module(stack_data.endpt, &mod_ok);
}

TEST_F(CommonProcessingTest, NoContentLengthDropped)
{
  // Tests that a malformed request with no content length is just dropped

  // Inject a request with no content length header.
  Message msg1;
  msg1._first_hop = true;
  msg1._contentlength = false;
  inject_msg_failure(msg1.get_request(), _tp, -PJSIP_EMISSINGHDR);

  // Expect it to just vanish.
  ASSERT_EQ(0, txdata_count());
}

