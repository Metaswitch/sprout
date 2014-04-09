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
#include "chronosconnection.h"
#include "localstore.h"
#include "fakehssconnection.hpp"


using namespace std;

class RegistrationTimeoutHandlersTest : public BaseTest
{
  ChronosConnection* chronos_connection;
  LocalStore* local_data_store;
  RegStore* store;
  HSSConnection* fake_hss;

  MockHttpStack stack;
  MockHttpStack::Request* req;
  RegistrationTimeoutHandler::Config* chronos_config;

  RegistrationTimeoutHandler* handler;

  void SetUp()
  {
    chronos_connection = new ChronosConnection("localhost", "localhost:9888");
    local_data_store = new LocalStore();
    store = new RegStore(local_data_store, chronos_connection);
    fake_hss = new FakeHSSConnection();
    req = new MockHttpStack::Request(&stack, "/", "timers");
    chronos_config = new RegistrationTimeoutHandler::Config(store, store, fake_hss);
    handler = new RegistrationTimeoutHandler(*req, chronos_config, 0);
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

TEST_F(RegistrationTimeoutHandlersTest, MainlineTest)
{
  std::string body = "{\"aor_id\": \"aor_id\", \"binding_id\": \"binding_id\"}";
  int status = handler->parse_response(body);

  ASSERT_EQ(status, 200);

  handler->handle_response();
}

TEST_F(RegistrationTimeoutHandlersTest, InvalidJSONTest)
{
  std::string body = "{\"aor_id\" \"aor_id\", \"binding_id\": \"binding_id\"}";
  int status = handler->parse_response(body);

  ASSERT_EQ(status, 400);
}

TEST_F(RegistrationTimeoutHandlersTest, MissingAorJSONTest)
{
  std::string body = "{\"binding_id\": \"binding_id\"}";
  int status = handler->parse_response(body);

  ASSERT_EQ(status, 400);
}

TEST_F(RegistrationTimeoutHandlersTest, MissingBindingJSONTest)
{
  std::string body = "{\"aor_id\": \"aor_id\"}";
  int status = handler->parse_response(body);

  ASSERT_EQ(status, 400);
}

class DeregistrationHandlerTest : public BaseTest
{
  ChronosConnection* chronos_connection;
  LocalStore* local_data_store;
  RegStore* store;
  HSSConnection* fake_hss;

  MockHttpStack stack;
  MockHttpStack::Request* req;
  DeregistrationHandler::Config* deregistration_config;

  DeregistrationHandler* handler;

  void SetUp()
  {
    chronos_connection = new ChronosConnection("localhost", "localhost:9888");
    local_data_store = new LocalStore();
    store = new RegStore(local_data_store, chronos_connection);
    fake_hss = new FakeHSSConnection();
    req = new MockHttpStack::Request(&stack, "/", "registrations");
    deregistration_config = new DeregistrationHandler::Config(store, store, fake_hss, NULL);
    handler = new DeregistrationHandler(*req, deregistration_config, 0);

    stack_data.sprout_cluster_domain = pj_str("all.the.sprouts");
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

TEST_F(DeregistrationHandlerTest, AoRPrivateIdPairTest)
{
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505552001@homedomain\", \"impi\": \"6505552001\"}]}";
  int status = handler->parse_request(body);
  ASSERT_EQ(status, 200);

  handler->handle_request();
}

TEST_F(DeregistrationHandlerTest, AoROnlyTest)
{
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505552001@homedomain\"}]}";
  int status = handler->parse_request(body);
  ASSERT_EQ(status, 200);

  handler->handle_request();
}

TEST_F(DeregistrationHandlerTest, AoRPrivateIdPairsTest)
{
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505552001@homedomain\", \"impi\": \"6505552001\"}, {\"primary-impu\": \"sip:6505552002@homedomain\", \"impi\": \"6505552002\"}]}";
  int status = handler->parse_request(body);
  ASSERT_EQ(status, 200);

  handler->handle_request();
}

TEST_F(DeregistrationHandlerTest, AoRsOnlyTest)
{
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505552001@homedomain\"}, {\"primary-impu\": \"sip:6505552002\"}]}";
  int status = handler->parse_request(body);
  ASSERT_EQ(status, 200);

  handler->handle_request();
}

TEST_F(DeregistrationHandlerTest, InvalidJSONTest)
{
  std::string body = "{[}";
  int status = handler->parse_request(body);
  EXPECT_TRUE(_log.contains("Failed to read data"));
  ASSERT_EQ(status, 400);
}

TEST_F(DeregistrationHandlerTest, MissingRegistrationsJSONTest)
{
  std::string body = "{\"primary-impu\": \"sip:6505552001@homedomain\", \"impi\": \"6505552001\"}}";
  int status = handler->parse_request(body);
  EXPECT_TRUE(_log.contains("Registrations not available in JSON"));
  ASSERT_EQ(status, 400);
}

TEST_F(DeregistrationHandlerTest, MissingPrimaryIMPUJSONTest)
{
  std::string body = "{\"registrations\": [{\"primary-imp\": \"sip:6505552001@homedomain\", \"impi\": \"6505552001\"}]}";
  int status = handler->parse_request(body);
  EXPECT_TRUE(_log.contains("Invalid JSON - registration doesn't contain primary-impu"));
  ASSERT_EQ(status, 400);
}

class AuthTimeoutTest : public BaseTest
{
  ChronosConnection* chronos_connection;
  LocalStore* local_data_store;
  AvStore* store;
  HSSConnection* fake_hss;

  MockHttpStack stack;
  MockHttpStack::Request* req;
  AuthTimeoutHandler::Config* chronos_config;

  AuthTimeoutHandler* handler;

  void SetUp()
  {
    chronos_connection = new ChronosConnection("localhost", "localhost:9888");
    local_data_store = new LocalStore();
    store = new AvStore(local_data_store);
    fake_hss = new FakeHSSConnection();
    req = new MockHttpStack::Request(&stack, "/", "authentication-timeout");
    chronos_config = new AuthTimeoutHandler::Config(store, fake_hss);
    handler = new AuthTimeoutHandler(*req, chronos_config, 0);
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

TEST_F(AuthTimeoutTest, NonceTimedOut)
{
  std::string body = "{\"impu\": \"sip:test@example.com\", \"impi\": \"test@example.com\", \"nonce\": \"abcdef\"}";
  Json::Value json("{}");
  store->set_av("test@example.com", "abcdef", &json, 0);
  int status = handler->handle_response(body);

  ASSERT_EQ(status, 200);
  ASSERT_EQ(NULL, store->get_av("test@example.com", "abcdef", 0));
}

TEST_F(AuthTimeoutTest, MainlineTest)
{
  std::string body = "{\"impu\": \"sip:test@example.com\", \"impi\": \"test@example.com\", \"nonce\": \"abcdef\"}";
  int status = handler->handle_response(body);

  ASSERT_EQ(status, 200);
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
