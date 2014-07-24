/**
 * @file handlers_test.cpp UT for Handlers module.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version, along with the "Special Exception" for use of
 * the program along with SSL, set forth below. This program is distributed
 * in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details. You should have received a copy of the GNU General Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by
 * post at Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 *
 * Special Exception
 * Metaswitch Networks Ltd  grants you permission to copy, modify,
 * propagate, and distribute a work formed by combining OpenSSL with The
 * Software, or a work derivative of such a combination, even if such
 * copying, modification, propagation, or distribution would otherwise
 * violate the terms of the GPL. You must comply with the GPL in all
 * respects for all of the code used other than OpenSSL.
 * "OpenSSL" means OpenSSL toolkit software distributed by the OpenSSL
 * Project and licensed under the OpenSSL Licenses, or a work based on such
 * software and licensed under the OpenSSL Licenses.
 * "OpenSSL Licenses" means the OpenSSL License and Original SSLeay License
 * under which the OpenSSL Project distributes the OpenSSL toolkit software,
 * as those licenses appear in the file LICENSE-OPENSSL.
 */

#include "test_utils.hpp"
#include <curl/curl.h>

#include "mockhttpstack.hpp"
#include "handlers.h"
#include "gtest/gtest.h"
#include "basetest.hpp"
#include "regstore.h"
#include "localstore.h"
#include "fakehssconnection.hpp"
#include "fakechronosconnection.hpp"
#include "test_interposer.hpp"

using namespace std;

class RegistrationTimeoutTasksTest : public BaseTest
{
  FakeChronosConnection* chronos_connection;
  LocalStore* local_data_store;
  RegStore* store;
  FakeHSSConnection* fake_hss;

  MockHttpStack stack;
  MockHttpStack::Request* req;
  RegistrationTimeoutTask::Config* chronos_config;

  RegistrationTimeoutTask* handler;

  void SetUp()
  {
    chronos_connection = new FakeChronosConnection();
    local_data_store = new LocalStore();
    store = new RegStore(local_data_store, chronos_connection);
    fake_hss = new FakeHSSConnection();
    req = new MockHttpStack::Request(&stack, "/", "timers");
    chronos_config = new RegistrationTimeoutTask::Config(store, store, fake_hss);
    handler = new RegistrationTimeoutTask(*req, chronos_config, 0);
  }

  void TearDown()
  {
    delete handler;
    delete chronos_config;
    delete req;
    delete fake_hss;
    delete store; store = NULL;
    delete local_data_store; local_data_store = NULL;
    delete chronos_connection; chronos_connection = NULL;
  }

};

TEST_F(RegistrationTimeoutTasksTest, MainlineTest)
{
  // Get an initial empty AoR record and add a standard binding.
  int now = time(NULL);
  RegStore::AoR* aor_data1 = store->get_aor_data(std::string("sip:6505550231@homedomain"), 0);
  RegStore::AoR::Binding* b1 = aor_data1->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1"));
  b1->_uri = std::string("<sip:6505550231@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 5;
  b1->_priority = 0;
  b1->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_emergency_registration = false;
  b1->_private_id = "6505550231";

  // Add the AoR record to the store.
  store->set_aor_data(std::string("sip:6505550231@homedomain"), aor_data1, true, 0);
  delete aor_data1; aor_data1 = NULL;

  // Advance time so the binding is due for expiry
  cwtest_advance_time_ms(6000);

  // Parse and handle the request
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\", \"binding_id\": \"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1\"}";
  int status = handler->parse_response(body);

  ASSERT_EQ(status, 200);

  handler->handle_response();
}

TEST_F(RegistrationTimeoutTasksTest, InvalidJSONTest)
{
  std::string body = "{\"aor_id\" \"aor_id\", \"binding_id\": \"binding_id\"}";
  int status = handler->parse_response(body);

  ASSERT_EQ(status, 400);
}

TEST_F(RegistrationTimeoutTasksTest, MissingAorJSONTest)
{
  std::string body = "{\"binding_id\": \"binding_id\"}";
  int status = handler->parse_response(body);

  ASSERT_EQ(status, 400);
}

TEST_F(RegistrationTimeoutTasksTest, MissingBindingJSONTest)
{
  std::string body = "{\"aor_id\": \"aor_id\"}";
  int status = handler->parse_response(body);

  ASSERT_EQ(status, 400);
}

class DeregistrationTaskTest : public BaseTest
{
  FakeChronosConnection* chronos_connection;
  LocalStore* local_data_store;
  RegStore* store;
  FakeHSSConnection* fake_hss;

  MockHttpStack stack;
  MockHttpStack::Request* req;
  DeregistrationTask::Config* deregistration_config;

  DeregistrationTask* handler;

  void SetUp()
  {
    chronos_connection = new FakeChronosConnection();
    local_data_store = new LocalStore();
    store = new RegStore(local_data_store, chronos_connection);
    fake_hss = new FakeHSSConnection();
    req = new MockHttpStack::Request(&stack, "/", "registrations");
    deregistration_config = new DeregistrationTask::Config(store, store, fake_hss, NULL);
    handler = new DeregistrationTask(*req, deregistration_config, 0);

    stack_data.scscf_uri = pj_str("sip:all.the.sprouts:5058;transport=TCP");
    // The expiry tests require pjsip, so initialise for this test
    init_pjsip_logging(99, false, "");
    init_pjsip();
  }

  void TearDown()
  {
    delete handler;
    delete deregistration_config;
    delete req;
    delete fake_hss;
    delete store; store = NULL;
    delete local_data_store; local_data_store = NULL;
    delete chronos_connection; chronos_connection = NULL;
    term_pjsip();
  }
};

TEST_F(DeregistrationTaskTest, MainlineTest)
{
  // Get an initial empty AoR record and add a standard binding
  int now = time(NULL);

  RegStore::AoR* aor_data1 = store->get_aor_data(std::string("sip:6505550231@homedomain"), 0);
  RegStore::AoR::Binding* b1 = aor_data1->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1"));
  b1->_uri = std::string("<sip:6505550231@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_emergency_registration = false;
  b1->_private_id = "6505550231";

  // Add the AoR record to the store.
  store->set_aor_data(std::string("sip:6505550231@homedomain"), aor_data1, true, 0);
  delete aor_data1; aor_data1 = NULL;

  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\", \"impi\": \"6505550231\"}]}";
  int status = handler->parse_request(body);
  ASSERT_EQ(status, 200);

  handler->_notify = "true";
  handler->handle_request();
}

TEST_F(DeregistrationTaskTest, AoROnlyTest)
{
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505552001@homedomain\"}]}";
  int status = handler->parse_request(body);
  ASSERT_EQ(status, 200);

  handler->handle_request();
}

TEST_F(DeregistrationTaskTest, AoRPrivateIdPairsTest)
{
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505552001@homedomain\", \"impi\": \"6505552001\"}, {\"primary-impu\": \"sip:6505552002@homedomain\", \"impi\": \"6505552002\"}]}";
  int status = handler->parse_request(body);
  ASSERT_EQ(status, 200);

  handler->handle_request();
}

TEST_F(DeregistrationTaskTest, AoRsOnlyTest)
{
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505552001@homedomain\"}, {\"primary-impu\": \"sip:6505552002\"}]}";
  int status = handler->parse_request(body);
  ASSERT_EQ(status, 200);

  handler->handle_request();
}

TEST_F(DeregistrationTaskTest, InvalidJSONTest)
{
  CapturingTestLogger log;
  std::string body = "{[}";
  int status = handler->parse_request(body);
  EXPECT_TRUE(log.contains("Failed to read data"));
  ASSERT_EQ(status, 400);
}

TEST_F(DeregistrationTaskTest, MissingRegistrationsJSONTest)
{
  CapturingTestLogger log;
  std::string body = "{\"primary-impu\": \"sip:6505552001@homedomain\", \"impi\": \"6505552001\"}}";
  int status = handler->parse_request(body);
  EXPECT_TRUE(log.contains("Registrations not available in JSON"));
  ASSERT_EQ(status, 400);
}

TEST_F(DeregistrationTaskTest, MissingPrimaryIMPUJSONTest)
{
  CapturingTestLogger log;
  std::string body = "{\"registrations\": [{\"primary-imp\": \"sip:6505552001@homedomain\", \"impi\": \"6505552001\"}]}";
  int status = handler->parse_request(body);
  EXPECT_TRUE(log.contains("Invalid JSON - registration doesn't contain primary-impu"));
  ASSERT_EQ(status, 400);
}

class AuthTimeoutTest : public BaseTest
{
  FakeChronosConnection* chronos_connection;
  LocalStore* local_data_store;
  AvStore* store;
  FakeHSSConnection* fake_hss;

  MockHttpStack stack;
  MockHttpStack::Request* req;
  AuthTimeoutTask::Config* chronos_config;

  AuthTimeoutTask* handler;

  void SetUp()
  {
    chronos_connection = new FakeChronosConnection();
    local_data_store = new LocalStore();
    store = new AvStore(local_data_store);
    fake_hss = new FakeHSSConnection();
    req = new MockHttpStack::Request(&stack, "/", "authentication-timeout");
    chronos_config = new AuthTimeoutTask::Config(store, fake_hss);
    handler = new AuthTimeoutTask(*req, chronos_config, 0);
  }

  void TearDown()
  {
    delete handler;
    delete chronos_config;
    delete req;
    delete fake_hss;
    delete store; store = NULL;
    delete local_data_store; local_data_store = NULL;
    delete chronos_connection; chronos_connection = NULL;
  }

};

// This tests the case where the AV record is still in memcached, but the Chronos timer has popped.
// The subscriber's registration state is updated, and the record is deleted from the AV store.
TEST_F(AuthTimeoutTest, NonceTimedOut)
{
  fake_hss->set_impu_result("sip:6505550231@homedomain", "dereg-auth-timeout", HSSConnection::STATE_REGISTERED, "", "?private_id=6505550231%40homedomain");
  Json::Value av(Json::objectValue);
  Json::Value digest(Json::objectValue);
  Json::Value branch("abcde");
  av["digest"] = digest;
  av["branch"] = branch;
  store->set_av("6505550231@homedomain", "abcdef", &av, 0, 0);
  std::string body = "{\"impu\": \"sip:6505550231@homedomain\", \"impi\": \"6505550231@homedomain\", \"nonce\": \"abcdef\"}";
  int status = handler->handle_response(body);

  ASSERT_EQ(status, 200);
  ASSERT_TRUE(fake_hss->url_was_requested("/impu/sip%3A6505550231%40homedomain/reg-data?private_id=6505550231%40homedomain", "{\"reqtype\": \"dereg-auth-timeout\"}"));
}

TEST_F(AuthTimeoutTest, NonceTimedOutWithNoBranch)
{
  fake_hss->set_impu_result("sip:6505550231@homedomain", "dereg-auth-timeout", HSSConnection::STATE_REGISTERED, "", "?private_id=6505550231%40homedomain");
  std::string body = "{\"impu\": \"sip:6505550231@homedomain\", \"impi\": \"6505550231@homedomain\", \"nonce\": \"abcdef\"}";
  int status = 0;
  Json::Value av_nobranch(Json::objectValue);
  Json::Value digest(Json::objectValue);
  av_nobranch["digest"] = digest;

  store->set_av("6505550231@homedomain", "abcdef", &av_nobranch, 0, 0);
  status = handler->handle_response(body);

  ASSERT_EQ(status, 200);
  ASSERT_TRUE(fake_hss->url_was_requested("/impu/sip%3A6505550231%40homedomain/reg-data?private_id=6505550231%40homedomain", "{\"reqtype\": \"dereg-auth-timeout\"}"));
}

TEST_F(AuthTimeoutTest, NonceTimedOutWithEmptyBranch)
{
  fake_hss->set_impu_result("sip:6505550231@homedomain", "dereg-auth-timeout", HSSConnection::STATE_REGISTERED, "", "?private_id=6505550231%40homedomain");
  std::string body = "{\"impu\": \"sip:6505550231@homedomain\", \"impi\": \"6505550231@homedomain\", \"nonce\": \"abcdef\"}";
  int status = 0;
  Json::Value av_emptybranch(Json::objectValue);
  Json::Value digest(Json::objectValue);
  Json::Value branch("");
  av_emptybranch["digest"] = digest;
  av_emptybranch["branch"] = branch;

  store->set_av("6505550231@homedomain", "abcdef", &av_emptybranch, 0, 0);
  status = handler->handle_response(body);

  ASSERT_EQ(status, 200);
  ASSERT_TRUE(fake_hss->url_was_requested("/impu/sip%3A6505550231%40homedomain/reg-data?private_id=6505550231%40homedomain", "{\"reqtype\": \"dereg-auth-timeout\"}"));
}

TEST_F(AuthTimeoutTest, NonceTimedOutWithIntegerBranch)
{
  fake_hss->set_impu_result("sip:6505550231@homedomain", "dereg-auth-timeout", HSSConnection::STATE_REGISTERED, "", "?private_id=6505550231%40homedomain");
  std::string body = "{\"impu\": \"sip:6505550231@homedomain\", \"impi\": \"6505550231@homedomain\", \"nonce\": \"abcdef\"}";
  int status = 0;
  Json::Value av_intbranch(Json::objectValue);
  Json::Value digest(Json::objectValue);
  Json::Value intbranch(6);
  av_intbranch["digest"] = digest;
  av_intbranch["branch"] = intbranch;

  store->set_av("6505550231@homedomain", "abcdef", &av_intbranch, 0, 0);
  status = handler->handle_response(body);

  ASSERT_EQ(status, 200);
  ASSERT_TRUE(fake_hss->url_was_requested("/impu/sip%3A6505550231%40homedomain/reg-data?private_id=6505550231%40homedomain", "{\"reqtype\": \"dereg-auth-timeout\"}"));
}

TEST_F(AuthTimeoutTest, MainlineTest)
{
  std::string body = "{\"impu\": \"sip:test@example.com\", \"impi\": \"test@example.com\", \"nonce\": \"abcdef\"}";
  Json::Value av(Json::objectValue);
  Json::Value digest(Json::objectValue);
  Json::Value branch("abcde");
  av["digest"] = digest;
  av["branch"] = branch;
  av["tombstone"] = Json::Value("true");
  store->set_av("test@example.com", "abcdef", &av, 0, 0);
  int status = handler->handle_response(body);

  ASSERT_EQ(status, 200);
  ASSERT_FALSE(fake_hss->url_was_requested("/impu/sip%3Atest%40example.com/reg-data?private_id=test%40example.com", "{\"reqtype\": \"dereg-auth-timeout\"}"));
}

TEST_F(AuthTimeoutTest, NoIMPU)
{
  std::string body = "{\"impi\": \"test@example.com\", \"nonce\": \"abcdef\"}";
  int status = handler->handle_response(body);

  ASSERT_EQ(status, 400);
}

TEST_F(AuthTimeoutTest, NoIMPI)
{
  std::string body = "{\"impu\": \"sip:test@example.com\", \"nonce\": \"abcdef\"}";
  int status = handler->handle_response(body);

  ASSERT_EQ(status, 400);
}

TEST_F(AuthTimeoutTest, NoNonce)
{
  std::string body = "{\"impu\": \"sip:test@example.com\", \"impi\": \"test@example.com\"}";
  int status = handler->handle_response(body);

  ASSERT_EQ(status, 400);
}

TEST_F(AuthTimeoutTest, BadJSON)
{
  std::string body = "{\"impu\" \"sip:test@example.com\", \"impi\": \"test@example.com\", \"nonce\": \"abcdef\"}";
  int status = handler->handle_response(body);

  ASSERT_EQ(status, 400);
}
