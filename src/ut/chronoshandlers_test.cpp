/**
 * @file chronoshandlers_test.cpp UT for Chronos Handlers module.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "test_utils.hpp"
#include <curl/curl.h>

#include "mockhttpstack.hpp"
#include "gtest/gtest.h"
#include "basetest.hpp"
#include "siptest.hpp"
#include "test_interposer.hpp"
#include "rapidjson/document.h"
#include "handlers_test.h"
#include "chronoshandlers.h"
#include "s4_chronoshandlers.h"
#include "hssconnection.h"
#include "testingcommon.h"

using namespace std;
using namespace TestingCommon;
using ::testing::_;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::SaveArg;
using ::testing::InSequence;
using ::testing::NiceMock;

class ChronosAoRTimeoutTasksTest : public TestWithMockSdms
{
public:
  void TearDown()
  {
    delete config;
    delete req;

    TestWithMockSdms::TearDown();
  }

  void build_timeout_request(std::string body, htp_method method)
  {
    req = new MockHttpStack::Request(stack, "/", "timers", "", body, method);
    config = new AoRTimeoutTask::Config(sm);
    handler = new ChronosAoRTimeoutTask(*req, config, 0);
  }

  MockHttpStack::Request* req;
  AoRTimeoutTask::Config* config;
  ChronosAoRTimeoutTask* handler;
};

// Test main flow, without a remote store.
TEST_F(ChronosAoRTimeoutTasksTest, MainlineTest)
{
  // Build request
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\"}";
  build_timeout_request(body, htp_method_POST);

  handler->run();
}

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


class ChronosAuthTimeoutTest : public AuthTimeoutTest
{
  MockHttpStack::Request* req;
  AuthTimeoutTask::Config* config;
  ChronosAuthTimeoutTask* handler;

  void TearDown()
  {
    delete config; config = NULL;
    if (req != NULL) delete req; req = NULL;

    AuthTimeoutTest::TearDown();
  }

  void build_timeout_request(std::string body, htp_method method)
  {
    req = new MockHttpStack::Request(&stack, "/", "authentication-timeout", "", body, method);
    config = new AuthTimeoutTask::Config(store, fake_hss);
    handler = new ChronosAuthTimeoutTask(*req, config, 0);
  }
};

// This tests the case where the AV record is still in memcached, but the Chronos timer has popped.
// The subscriber's registration state is updated, and the record is deleted from the AV store.
TEST_F(ChronosAuthTimeoutTest, NonceTimedOut)
{
  fake_hss->set_impu_result("sip:6505550231@homedomain", "dereg-auth-timeout", RegDataXMLUtils::STATE_REGISTERED, "", "?private_id=6505550231%40homedomain");
  ImpiStore::Impi* impi = new ImpiStore::Impi("6505550231@homedomain");
  ImpiStore::DigestAuthChallenge* auth_challenge = new ImpiStore::DigestAuthChallenge("abcdef", "example.com", "auth", "ha1", time(NULL) + 30);
  auth_challenge->_correlator = "abcde";
  auth_challenge->_scscf_uri = "sip:scscf.sprout.homedomain:5058;transport=TCP";
  impi->auth_challenges.push_back(auth_challenge);

  EXPECT_CALL(*store, get_impi("6505550231@homedomain", _, true)).WillOnce(Return(impi));

  std::string body = "{\"impu\": \"sip:6505550231@homedomain\", \"impi\": \"6505550231@homedomain\", \"nonce\": \"abcdef\"}";
  build_timeout_request(body, htp_method_POST);

  EXPECT_CALL(stack, send_reply(_, 200, _));
  handler->run();

  ASSERT_TRUE(fake_hss->url_was_requested("/impu/sip%3A6505550231%40homedomain/reg-data?private_id=6505550231%40homedomain", "{\"reqtype\": \"dereg-auth-timeout\", \"server_name\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}"));
}

TEST_F(ChronosAuthTimeoutTest, NonceTimedOutWithEmptyCorrelator)
{
  fake_hss->set_impu_result("sip:6505550231@homedomain", "dereg-auth-timeout", RegDataXMLUtils::STATE_REGISTERED, "", "?private_id=6505550231%40homedomain");
  ImpiStore::Impi* impi = new ImpiStore::Impi("6505550231@homedomain");
  ImpiStore::DigestAuthChallenge* auth_challenge = new ImpiStore::DigestAuthChallenge("abcdef", "example.com", "auth", "ha1", time(NULL) + 30);
  auth_challenge->_scscf_uri = "sip:scscf.sprout.homedomain:5058;transport=TCP";
  impi->auth_challenges.push_back(auth_challenge);

  EXPECT_CALL(*store, get_impi("6505550231@homedomain", _, true)).WillOnce(Return(impi));

  std::string body = "{\"impu\": \"sip:6505550231@homedomain\", \"impi\": \"6505550231@homedomain\", \"nonce\": \"abcdef\"}";
  build_timeout_request(body, htp_method_POST);

  EXPECT_CALL(stack, send_reply(_, 200, _));
  handler->run();

  ASSERT_TRUE(fake_hss->url_was_requested("/impu/sip%3A6505550231%40homedomain/reg-data?private_id=6505550231%40homedomain", "{\"reqtype\": \"dereg-auth-timeout\", \"server_name\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}"));
}

TEST_F(ChronosAuthTimeoutTest, MainlineTest)
{
  ImpiStore::Impi* impi = new ImpiStore::Impi("test@example.com");
  ImpiStore::DigestAuthChallenge* auth_challenge = new ImpiStore::DigestAuthChallenge("abcdef", "example.com", "auth", "ha1", time(NULL) + 30);
  auth_challenge->_nonce_count++; // Indicates that one successful authentication has occurred
  auth_challenge->_correlator = "abcde";
  impi->auth_challenges.push_back(auth_challenge);

  EXPECT_CALL(*store, get_impi("test@example.com", _, true)).WillOnce(Return(impi));

  std::string body = "{\"impu\": \"sip:test@example.com\", \"impi\": \"test@example.com\", \"nonce\": \"abcdef\"}";
  build_timeout_request(body, htp_method_POST);

  EXPECT_CALL(stack, send_reply(_, 200, _));
  handler->run();

  ASSERT_FALSE(fake_hss->url_was_requested("/impu/sip%3Atest%40example.com/reg-data?private_id=test%40example.com", "{\"reqtype\": \"dereg-auth-timeout\"}"));
}

TEST_F(ChronosAuthTimeoutTest, BadMethod)
{
  std::string body = "{\"impi\": \"test@example.com\", \"nonce\": \"abcdef\"}";
  build_timeout_request(body, htp_method_PUT);

  EXPECT_CALL(stack, send_reply(_, 405, _));
  handler->run();
}

TEST_F(ChronosAuthTimeoutTest, NoIMPU)
{
  std::string body = "{\"impi\": \"test@example.com\", \"nonce\": \"abcdef\"}";
  build_timeout_request(body, htp_method_POST);

  EXPECT_CALL(stack, send_reply(_, 400, _));
  handler->run();
}

TEST_F(ChronosAuthTimeoutTest, CorruptIMPUMissingIMPI)
{
  std::string body = "{\"impi\": \"test@example.com\", \"impu\": \"I am not a URI\", \"nonce\": \"abcdef\"}";
  build_timeout_request(body, htp_method_POST);

  ImpiStore::Impi* impi = NULL;
  EXPECT_CALL(*store, get_impi("test@example.com", _, true)).WillOnce(Return(impi));
  EXPECT_CALL(stack, send_reply(_, 500, _));
  handler->run();
}

TEST_F(ChronosAuthTimeoutTest, NoIMPI)
{
  std::string body = "{\"impu\": \"sip:test@example.com\", \"nonce\": \"abcdef\"}";
  build_timeout_request(body, htp_method_POST);

  EXPECT_CALL(stack, send_reply(_, 400, _));
  handler->run();
}

TEST_F(ChronosAuthTimeoutTest, NoNonce)
{
  std::string body = "{\"impu\": \"sip:test@example.com\", \"impi\": \"test@example.com\"}";
  build_timeout_request(body, htp_method_POST);

  EXPECT_CALL(stack, send_reply(_, 400, _));
  handler->run();
}

TEST_F(ChronosAuthTimeoutTest, BadJSON)
{
  std::string body = "{\"impu\" \"sip:test@example.com\", \"impi\": \"test@example.com\", \"nonce\": \"abcdef\"}";
  build_timeout_request(body, htp_method_POST);

  EXPECT_CALL(stack, send_reply(_, 400, _));
  handler->run();
}
