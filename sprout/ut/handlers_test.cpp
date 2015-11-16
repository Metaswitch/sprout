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
#include "siptest.hpp"
#include "regstore.h"
#include "localstore.h"
#include "fakehssconnection.hpp"
#include "fakechronosconnection.hpp"
#include "test_interposer.hpp"
#include "mock_reg_store.h"
#include "mock_hss_connection.h"

using namespace std;
using ::testing::_;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::SaveArg;
using ::testing::SaveArgPointee;
using ::testing::InSequence;
using ::testing::ByRef;

const std::string HSS_REG_STATE = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                                  "<ClearwaterRegData>"
                                    "<RegistrationState>REGISTERED</RegistrationState>"
                                    "<IMSSubscription>"
                                      "<ServiceProfile>"
                                        "<PublicIdentity>"
                                          "<Identity>sip:6505550001@homedomain</Identity>"
                                        "</PublicIdentity>"
                                      "</ServiceProfile>"
                                    "</IMSSubscription>"
                                  "</ClearwaterRegData>";
const std::string HSS_NOT_REG_STATE = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                                      "<ClearwaterRegData>"
                                        "<RegistrationState>NOT_REGISTERED</RegistrationState>"
                                      "</ClearwaterRegData>";

class RegSubTimeoutTasksTest : public SipTest
{
  MockRegStore* store;
  MockHttpStack* stack;
  MockHSSConnection* mock_hss;
  MockHttpStack::Request* req;
  RegSubTimeoutTask::Config* config;
  RegSubTimeoutTask* handler;

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase(false);
  }

  void SetUp()
  {
    store = new MockRegStore();
    mock_hss = new MockHSSConnection();
    stack = new MockHttpStack();
  }

  void TearDown()
  {
    delete config;
    delete req;
    delete stack;
    delete store; store = NULL;
    delete mock_hss;
  }

  void build_timeout_request(std::string body, htp_method method)
  {
    req = new MockHttpStack::Request(stack, "/", "timers", "", body, method);
    config = new RegSubTimeoutTask::Config(store, mock_hss);
    handler = new RegSubTimeoutTask(*req, config, 0);
  }

  RegStore::AoR* build_aor(std::string aor_id)
  {
    RegStore::AoR* aor = new RegStore::AoR(aor_id);
    int now = time(NULL);
    RegStore::AoR::Binding* b = NULL;
    build_binding(aor, b, now);
    RegStore::AoR::Subscription* s = NULL;
    build_subscription(aor, s, now);
    return aor;
  }

  RegStore::AoR::Binding* build_binding(RegStore::AoR* aor, RegStore::AoR::Binding* b, int now)
  {
    b = aor->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1"));
    b->_uri = std::string("<sip:6505550231@192.91.191.29:59934;transport=tcp;ob>");
    b->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
    b->_cseq = 17038;
    b->_expires = now + 5;
    b->_priority = 0;
    b->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
    b->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
    b->_params["reg-id"] = "1";
    b->_params["+sip.ice"] = "";
    b->_emergency_registration = false;
    b->_private_id = "6505550231";
    return b;
  }

  RegStore::AoR::Subscription* build_subscription(RegStore::AoR* aor, RegStore::AoR::Subscription* s, int now)
  {
    s = aor->get_subscription("1234");
    s->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
    s->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
    s->_from_tag = std::string("4321");
    s->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
    s->_to_tag = std::string("1234");
    s->_cid = std::string("xyzabc@192.91.191.29");
    s->_route_uris.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
    s->_expires = now + 300;
    return s;
  }
};

// Test main flow.
TEST_F(RegSubTimeoutTasksTest, MainlineTest)
{
  // Build request
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\", \"binding_id\": \"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1\"}";
  build_timeout_request(body, htp_method_POST);

  // Set up regstore expectations
  std::string aor_id = "sip:6505550231@homedomain";
  RegStore::AoR* aor = build_aor(aor_id);

  {
    InSequence s;
      EXPECT_CALL(*stack, send_reply(_, 200, _));
      EXPECT_CALL(*store, get_aor_data(aor_id, _, true)).WillOnce(Return(aor));
      EXPECT_CALL(*store, set_aor_data(aor_id, aor, true, _, false, _)).WillOnce(Return(Store::OK));
  }

  handler->run();
}

// Test that an invalid HTTP method fails with HTTP_BADMETHOD
TEST_F(RegSubTimeoutTasksTest, InvalidHTTPMethodTest)
{
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\", \"binding_id\": \"binding_id\"}";
  build_timeout_request(body, htp_method_PUT);

  EXPECT_CALL(*stack, send_reply(_, 405, _));

  handler->run();
}

// Test that an invalid JSON body fails in parsing
TEST_F(RegSubTimeoutTasksTest, InvalidJSONTest)
{
  CapturingTestLogger log(5);

  std::string body = "{\"aor_id\" \"aor_id\", \"binding_id\": \"binding_id\"}";
  build_timeout_request(body, htp_method_POST);

  EXPECT_CALL(*stack, send_reply(_, 400, _));

  handler->run();

  EXPECT_TRUE(log.contains("Failed to parse opaque data as JSON:"));
}

// Test that a body without an AoR ID fails, logging "Badly formed opaque data"
TEST_F(RegSubTimeoutTasksTest, MissingAorJSONTest)
{
  CapturingTestLogger log(5);

  std::string body = "{\"binding_id\": \"binding_id\"}";
  build_timeout_request(body, htp_method_POST);

  EXPECT_CALL(*stack, send_reply(_, 400, _));

  handler->run();

  EXPECT_TRUE(log.contains("Badly formed opaque data (missing aor_id)"));
}

// Test with no bindings
TEST_F(RegSubTimeoutTasksTest, NoBindingsTest)
{
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\", \"subscription_id\": \"subscription_id\", \"binding_id\": \"binding_id\"}";

  build_timeout_request(body, htp_method_POST);
  // Set up regstore expectations
  std::string aor_id = "sip:6505550231@homedomain";
  // Set up AoRs with no bindings
  RegStore::AoR* aor = new RegStore::AoR(aor_id);

  {
    InSequence s;
      EXPECT_CALL(*stack, send_reply(_, 200, _));
      EXPECT_CALL(*store, get_aor_data(aor_id, _, true)).WillOnce(Return(aor));
      EXPECT_CALL(*store, set_aor_data(aor_id, aor, true, _, false, _))
                  .WillOnce(DoAll(SetArgReferee<5>(true), Return(Store::OK)));
      EXPECT_CALL(*mock_hss, update_registration_state(aor_id, "", HSSConnection::DEREG_TIMEOUT, 0));
  }

  handler->run();
}

// Test with no bindings, and a HTTP body not containing a subscription ID
TEST_F(RegSubTimeoutTasksTest, NoBindingsNoSubIDTest)
{
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\", \"subscription_id\": \"subscription_id\"}";

  build_timeout_request(body, htp_method_POST);
  // Set up regstore expectations
  std::string aor_id = "sip:6505550231@homedomain";
  // Set up AoRs with no bindings
  RegStore::AoR* aor = new RegStore::AoR(aor_id);

  {
    InSequence s;
      EXPECT_CALL(*stack, send_reply(_, 200, _));
      EXPECT_CALL(*store, get_aor_data(aor_id, _, true)).WillOnce(Return(aor));
      EXPECT_CALL(*store, set_aor_data(aor_id, aor, true, _, false, _))
                  .WillOnce(DoAll(SetArgReferee<5>(true), Return(Store::OK)));
      EXPECT_CALL(*mock_hss, update_registration_state(aor_id, "", HSSConnection::DEREG_TIMEOUT, 0));
  }

  handler->run();
}

// Test with no bindings, and a HTTP body not containing a subscription ID or binding ID
TEST_F(RegSubTimeoutTasksTest, NoBindingsNoSubIDNoBindingIDTest)
{
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\"}";

  build_timeout_request(body, htp_method_POST);
  // Set up regstore expectations
  std::string aor_id = "sip:6505550231@homedomain";
  // Set up AoRs with no bindings
  RegStore::AoR* aor = new RegStore::AoR(aor_id);

  {
    InSequence s;
      EXPECT_CALL(*stack, send_reply(_, 200, _));
      EXPECT_CALL(*store, get_aor_data(aor_id, _, true)).WillOnce(Return(aor));
      EXPECT_CALL(*store, set_aor_data(aor_id, aor, true, _, false, _))
                  .WillOnce(DoAll(SetArgReferee<5>(true), Return(Store::OK)));
      EXPECT_CALL(*mock_hss, update_registration_state(aor_id, "", HSSConnection::DEREG_TIMEOUT, 0));
  }

  handler->run();
}



// Test with NULL AoRs
TEST_F(RegSubTimeoutTasksTest, NullAoRTest)
{
  CapturingTestLogger log(5);

  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\", \"binding_id\": \"binding_id\"}";
  build_timeout_request(body, htp_method_POST);

  // Set up regstore expectations
  std::string aor_id = "sip:6505550231@homedomain";
  RegStore::AoR* aor = NULL;

  {
    InSequence s;
      EXPECT_CALL(*stack, send_reply(_, 200, _));
      EXPECT_CALL(*store, get_aor_data(aor_id, _, true)).WillOnce(Return(aor));
      EXPECT_CALL(*store, set_aor_data(aor_id, aor, true, _, false, _)).Times(0);
  }

  handler->run();

  EXPECT_TRUE(log.contains("Failed to get AoR binding for"));
}

class RegSubTimeoutTasksMockStoreTest : public SipTest
{
  FakeChronosConnection* chronos_connection;
  MockRegStore* store;
  FakeHSSConnection* fake_hss;

  MockHttpStack stack;
  MockHttpStack::Request* req;
  RegSubTimeoutTask::Config* chronos_config;

  RegSubTimeoutTask* handler;

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase(false);
  }

  void SetUp()
  {
    chronos_connection = new FakeChronosConnection();
    store = new MockRegStore();
    fake_hss = new FakeHSSConnection();
    req = new MockHttpStack::Request(&stack, "/", "timers");
    chronos_config = new RegSubTimeoutTask::Config(store, fake_hss);
    handler = new RegSubTimeoutTask(*req, chronos_config, 0);
  }

  void TearDown()
  {
    delete handler;
    delete chronos_config;
    delete req;
    delete fake_hss;
    delete store; store = NULL;
    delete chronos_connection; chronos_connection = NULL;
  }

};

TEST_F(RegSubTimeoutTasksMockStoreTest, RegStoreWritesFail)
{
  // Set up the RegStore to fail all sets and respond to all gets with not
  // found.
  RegStore::AoR* aor = new RegStore::AoR("sip:6505550231@homedomain");
  EXPECT_CALL(*store, get_aor_data(_, _, _)).WillOnce(Return(aor));
  EXPECT_CALL(*store, set_aor_data(_, _, _, _, _, _)).WillOnce(Return(Store::ERROR));

  // Parse and handle the request
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\", \"binding_id\": \"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1\"}";
  int status = handler->parse_response(body);

  ASSERT_EQ(status, 200);

  handler->handle_response();
}


class DeregistrationTaskTest : public SipTest
{
  MockRegStore* _regstore;
  MockHttpStack* _httpstack;
  FakeHSSConnection* _hss;
  MockHttpStack::Request* _req;
  DeregistrationTask::Config* _cfg;
  DeregistrationTask* _task;

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase(false);
  }

  void SetUp()
  {
    _httpstack = new MockHttpStack();
    _regstore = new MockRegStore();
    _hss = new FakeHSSConnection();
    stack_data.scscf_uri = pj_str("sip:all.the.sprouts:5058;transport=TCP");
  }

  void TearDown()
  {
    delete _req;
    delete _cfg;
    delete _hss;
    delete _regstore;
    delete _httpstack;
  }

  // Build the deregistration request
  void build_dereg_request(std::string body,
                           std::string notify = "true",
                           htp_method method = htp_method_DELETE)
  {
    _req = new MockHttpStack::Request(_httpstack,
         "/registrations?send-notifications=" + notify,
         "",
         "send-notifications=" + notify,
         body,
         method);
    _cfg = new DeregistrationTask::Config(_regstore, _hss, NULL);
    _task = new DeregistrationTask(*_req, _cfg, 0);
  }

  void expect_reg_store_updates(std::vector<std::string> aor_ids,
                                std::vector<RegStore::AoR*> aors)
  {
    for (uint32_t ii = 0; ii < aor_ids.size(); ++ii)
    {
      // Get the information from the local store
      EXPECT_CALL(*_regstore, get_aor_data(aor_ids[ii], _, _)).WillOnce(Return(aors[ii]));

      if (aors[ii] != NULL)
      {
        // Write the information to the local store
        EXPECT_CALL(*_regstore, set_aor_data(aor_ids[ii], _, _, _, _, _)).WillOnce(Return(Store::OK));
      }
    }
  }
};

// Mainline case
TEST_F(DeregistrationTaskTest, MainlineTest)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\", \"impi\": \"6505550231\"}]}";
  build_dereg_request(body);

  // Set up the regstore expectations
  std::string aor_id = "sip:6505550231@homedomain";
  // Get an initial empty AoR record and add a standard binding and subscription
  RegStore::AoR* aor = new RegStore::AoR(aor_id);
  int now = time(NULL);
  RegStore::AoR::Binding* b1 = aor->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1"));
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
  RegStore::AoR::Subscription* s1 = aor->get_subscription("1234");
  s1->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
  s1->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_from_tag = std::string("4321");
  s1->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_to_tag = std::string("1234");
  s1->_cid = std::string("xyzabc@192.91.191.29");
  s1->_route_uris.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  s1->_expires = now + 300;
  std::vector<std::string> aor_ids = {aor_id};
  std::vector<RegStore::AoR*> aors = {aor};
  expect_reg_store_updates(aor_ids, aors);

  // Run the task
  EXPECT_CALL(*_regstore, send_notify(s1, _, b1, _, _));
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();
}

// Test where there are multiple pairs of AoRs and Private IDs and single AoRs
TEST_F(DeregistrationTaskTest, AoRPrivateIdPairsTest)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505552001@homedomain\", \"impi\": \"6505552001\"}, {\"primary-impu\": \"sip:6505552002@homedomain\", \"impi\": \"6505552002\"}, {\"primary-impu\": \"sip:6505552003@homedomain\"}, {\"primary-impu\": \"sip:6505552004@homedomain\"}]}";
  build_dereg_request(body, "false");

  // Set up the regstore expectations
  std::string aor_id_1 = "sip:6505552001@homedomain";
  std::string aor_id_2 = "sip:6505552002@homedomain";
  std::string aor_id_3 = "sip:6505552003@homedomain";
  std::string aor_id_4 = "sip:6505552004@homedomain";
  RegStore::AoR* aor_1 = new RegStore::AoR(aor_id_1);
  RegStore::AoR* aor_2 = new RegStore::AoR(aor_id_2);
  RegStore::AoR* aor_3 = new RegStore::AoR(aor_id_3);
  RegStore::AoR* aor_4 = new RegStore::AoR(aor_id_4);
  std::vector<std::string> aor_ids = {aor_id_1, aor_id_2, aor_id_3, aor_id_4};
  std::vector<RegStore::AoR*> aors = {aor_1, aor_2, aor_3, aor_4};
  expect_reg_store_updates(aor_ids, aors);

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();
}

// Test when the RegStore can't be accessed.
TEST_F(DeregistrationTaskTest, RegStoreFailureTest)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505552001@homedomain\"}]}";
  build_dereg_request(body, "false");

  // Set up the regstore expectations
  std::string aor_id = "sip:6505552001@homedomain";
  RegStore::AoR* aor = NULL;
  std::vector<std::string> aor_ids = {aor_id};
  std::vector<RegStore::AoR*> aors = {aor};
  expect_reg_store_updates(aor_ids, aors);

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 500, _));
  _task->run();
}

// Test that an invalid SIP URI doesn't get sent on third party registers.
TEST_F(DeregistrationTaskTest, InvalidIMPUTest)
{
  _hss->set_result("/impu/notavalidsipuri/reg-data", HSS_NOT_REG_STATE);
  CapturingTestLogger log;

  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"notavalidsipuri\"}]}";
  build_dereg_request(body, "false");

  // Set up the regstore expectations
  std::string aor_id = "notavalidsipuri";
  RegStore::AoR* aor = new RegStore::AoR(aor_id);
  std::vector<std::string> aor_ids = {aor_id};
  std::vector<RegStore::AoR*> aors = {aor};

  expect_reg_store_updates(aor_ids, aors);

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();

  EXPECT_TRUE(log.contains("Unable to create third party registration"));
  _hss->flush_all();
}

// Test that a dereg request that isn't a delete gets rejected.
TEST_F(DeregistrationTaskTest, InvalidMethodTest)
{
  build_dereg_request("", "", htp_method_GET);
  EXPECT_CALL(*_httpstack, send_reply(_, 405, _));
  _task->run();
}

// Test that a dereg request that doesn't have a valid send-notifications param gets rejected.
TEST_F(DeregistrationTaskTest, InvalidParametersTest)
{
  build_dereg_request("", "nottrueorfalse");
  EXPECT_CALL(*_httpstack, send_reply(_, 400, _));
  _task->run();
}

// Test that a dereg request with invalid JSON gets rejected.
TEST_F(DeregistrationTaskTest, InvalidJSONTest)
{
  build_dereg_request("{[}");
  EXPECT_CALL(*_httpstack, send_reply(_, 400, _));
  _task->run();
}

// Test that a dereg request where the JSON is missing the registration element get rejected.
TEST_F(DeregistrationTaskTest, MissingRegistrationsJSONTest)
{
  CapturingTestLogger log;
  build_dereg_request("{\"primary-impu\": \"sip:6505552001@homedomain\", \"impi\": \"6505552001\"}");
  EXPECT_CALL(*_httpstack, send_reply(_, 400, _));
  _task->run();
  EXPECT_TRUE(log.contains("Registrations not available in JSON"));
}

// Test that a dereg request where the JSON is missing the primary impu element get rejected.
TEST_F(DeregistrationTaskTest, MissingPrimaryIMPUJSONTest)
{
  CapturingTestLogger log;
  build_dereg_request("{\"registrations\": [{\"primary-imp\": \"sip:6505552001@homedomain\", \"impi\": \"6505552001\"}]}");
  EXPECT_CALL(*_httpstack, send_reply(_, 400, _));
  _task->run();
  EXPECT_TRUE(log.contains("Invalid JSON - registration doesn't contain primary-impu"));
}


TEST_F(DeregistrationTaskTest, RegStoreWritesFail)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\", \"impi\": \"6505550231\"}]}";
  build_dereg_request(body);

  RegStore::AoR* aor = new RegStore::AoR("sip:6505550231@homedomain");
  EXPECT_CALL(*_regstore, get_aor_data(_, _, _)).WillOnce(Return(aor));
  EXPECT_CALL(*_regstore, set_aor_data(_, _, _, _, _, _)).WillOnce(Return(Store::ERROR));

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 500, _));
  _task->run();
}


class AuthTimeoutTest : public SipTest
{
  FakeChronosConnection* chronos_connection;
  LocalStore* local_data_store;
  AvStore* store;
  FakeHSSConnection* fake_hss;

  MockHttpStack stack;
  MockHttpStack::Request* req;
  AuthTimeoutTask::Config* chronos_config;

  AuthTimeoutTask* handler;

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase(false);
  }

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
  std::string av_str = "{\"digest\":{}, \"branch\":\"abcde\"}";
  rapidjson::Document av;
  av.Parse<0>(av_str.c_str());
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
  std::string av_str = "{\"digest\":{}}";
  rapidjson::Document av_nobranch;
  av_nobranch.Parse<0>(av_str.c_str());

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
  std::string av_str = "{\"digest\":{}, \"branch\":\"\"}";
  rapidjson::Document av_emptybranch;
  av_emptybranch.Parse<0>(av_str.c_str());

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
  std::string av_str = "{\"digest\":{}, \"branch\":6}";
  rapidjson::Document av_intbranch;
  av_intbranch.Parse<0>(av_str.c_str());

  store->set_av("6505550231@homedomain", "abcdef", &av_intbranch, 0, 0);
  status = handler->handle_response(body);

  ASSERT_EQ(status, 200);
  ASSERT_TRUE(fake_hss->url_was_requested("/impu/sip%3A6505550231%40homedomain/reg-data?private_id=6505550231%40homedomain", "{\"reqtype\": \"dereg-auth-timeout\"}"));
}

TEST_F(AuthTimeoutTest, MainlineTest)
{
  std::string body = "{\"impu\": \"sip:test@example.com\", \"impi\": \"test@example.com\", \"nonce\": \"abcdef\"}";
  std::string av_str = "{\"digest\":{}, \"branch\":\"abcde\", \"tombstone\": true}";
  rapidjson::Document av;
  av.Parse<0>(av_str.c_str());
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

TEST_F(AuthTimeoutTest, CorruptIMPU)
{
  std::string body = "{\"impi\": \"test@example.com\", \"impu\": \"I am not a URI\", \"nonce\": \"abcdef\"}";
  int status = handler->handle_response(body);

  ASSERT_EQ(status, 500);
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
