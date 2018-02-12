/**
 * @file s4_chronoshandlers_test.cpp
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <curl/curl.h>

#include "mockhttpstack.hpp"
#include "gtest/gtest.h"
#include "siptest.hpp"
#include "s4_chronoshandlers.h"
#include "subscriber_manager.h"
#include "mock_s4.h"
#include "testingcommon.h"

using namespace std;
using namespace TestingCommon;
using ::testing::_;
using ::testing::Return;
using ::testing::InSequence;
using ::testing::SaveArg;

// Test that ChronosAorTimeoutTasks handles request from Chronos about AoR 
// timeout, by sending back response and calling into S4.
class ChronosAoRTimeoutTasksTest : public SipTest
{
public:
  void SetUp()
  {
    stack = new MockHttpStack();
    s4 = new MockS4();
  }

  void TearDown()
  {
    delete config;
    delete req;
    delete stack;
    delete s4; s4 = NULL;
  }

  void build_timeout_request(std::string body, htp_method method)
  {
    req = new MockHttpStack::Request(stack, "/", "timers", "", body, method);
    config = new AoRTimeoutTask::Config(s4);
    handler = new ChronosAoRTimeoutTask(*req, config, 0);
  }

  MockHttpStack::Request* req;
  AoRTimeoutTask::Config* config;
  ChronosAoRTimeoutTask* handler;
  MockS4* s4;
  MockHttpStack* stack;

};

// Mainline test where the request is successfully parsed and handler proceeds
// to call SM. 
TEST_F(ChronosAoRTimeoutTasksTest, MainlineTest)
{
  // Build request from Chronos
  std::string aor_id;
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\"}";
  build_timeout_request(body, htp_method_POST);

  {
    InSequence s;
      // Send back response as soon as the request is successfully parsed
      EXPECT_CALL(*stack, send_reply(_, 200, _));
      EXPECT_CALL(*s4, handle_timer_pop(_, _))
        .WillOnce(SaveArg<0>(&aor_id));
  }
  handler->run();

  EXPECT_EQ(aor_id, "sip:6505550231@homedomain");
}


/// The following tests deal with error cases in parsing the timer pop request.

// Test that an invalid HTTP method fails with HTTP_BADMETHOD
TEST_F(ChronosAoRTimeoutTasksTest, InvalidHTTPMethodTest)
{
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\"}";
  build_timeout_request(body, htp_method_PUT);

  EXPECT_CALL(*stack, send_reply(_, 405, _));

  handler->run();
}

// Test that an invalid JSON body fails in parsing
TEST_F(ChronosAoRTimeoutTasksTest, InvalidJSONTest)
{
  CapturingTestLogger log(5);

  std::string body = "{\"aor_id\" \"aor_id\"}";
  build_timeout_request(body, htp_method_POST);

  EXPECT_CALL(*stack, send_reply(_, 400, _));

  handler->run();

  EXPECT_TRUE(log.contains("Failed to parse opaque data as JSON:"));
}

// Test that a body without an AoR ID fails, logging "Badly formed opaque data"
TEST_F(ChronosAoRTimeoutTasksTest, MissingAorJSONTest)
{
  CapturingTestLogger log(5);

  std::string body = "{}";
  build_timeout_request(body, htp_method_POST);

  EXPECT_CALL(*stack, send_reply(_, 400, _));

  handler->run();

  EXPECT_TRUE(log.contains("Badly formed opaque data (missing aor_id)"));
}


