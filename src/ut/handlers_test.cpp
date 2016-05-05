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
#include "localstore.h"
#include "fakehssconnection.hpp"
#include "fakechronosconnection.hpp"
#include "test_interposer.hpp"
#include "mock_subscriber_data_manager.h"
#include "mock_impi_store.h"
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

class AoRTimeoutTasksTest : public SipTest
{
  MockSubscriberDataManager* store;
  MockSubscriberDataManager* remote_store1;
  MockSubscriberDataManager* remote_store2;
  MockHttpStack* stack;
  MockHSSConnection* mock_hss;
  MockHttpStack::Request* req;
  AoRTimeoutTask::Config* config;
  AoRTimeoutTask* handler;

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase(false);
  }

  void SetUp()
  {
    store = new MockSubscriberDataManager();
    remote_store1 = new MockSubscriberDataManager();
    remote_store2 = new MockSubscriberDataManager();
    mock_hss = new MockHSSConnection();
    stack = new MockHttpStack();
  }

  void TearDown()
  {
    delete config;
    delete req;
    delete stack;
    delete remote_store1; remote_store1 = NULL;
    delete remote_store2; remote_store2 = NULL;
    delete store; store = NULL;
    delete mock_hss;
  }

  void build_timeout_request(std::string body, htp_method method)
  {
    req = new MockHttpStack::Request(stack, "/", "timers", "", body, method);
    config = new AoRTimeoutTask::Config(store, {remote_store1, remote_store2}, mock_hss);
    handler = new AoRTimeoutTask(*req, config, 0);
  }

  SubscriberDataManager::AoRPair* build_aor(std::string aor_id)
  {
    SubscriberDataManager::AoR* aor = new SubscriberDataManager::AoR(aor_id);
    int now = time(NULL);
    SubscriberDataManager::AoR::Binding* b = NULL;
    build_binding(aor, b, now);
    SubscriberDataManager::AoR::Subscription* s = NULL;
    build_subscription(aor, s, now);
    SubscriberDataManager::AoR* aor2 = new SubscriberDataManager::AoR(*aor);
    SubscriberDataManager::AoRPair* aor_pair = new SubscriberDataManager::AoRPair(aor, aor2);

    return aor_pair;
  }

  SubscriberDataManager::AoR::Binding* build_binding(SubscriberDataManager::AoR* aor, SubscriberDataManager::AoR::Binding* b, int now)
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

  SubscriberDataManager::AoR::Subscription* build_subscription(SubscriberDataManager::AoR* aor, SubscriberDataManager::AoR::Subscription* s, int now)
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

// Test main flow, without a remote store.
TEST_F(AoRTimeoutTasksTest, MainlineTest)
{
  // Build request
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\", \"binding_id\": \"notavalidID\"}";
  build_timeout_request(body, htp_method_POST);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  SubscriberDataManager::AoRPair* aor = build_aor(aor_id);
  SubscriberDataManager::AoRPair* remote_aor1 = build_aor(aor_id);
  SubscriberDataManager::AoRPair* remote_aor2 = build_aor(aor_id);

  {
    InSequence s;
      EXPECT_CALL(*stack, send_reply(_, 200, _));
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor));
      EXPECT_CALL(*store, set_aor_data(aor_id, aor, _, _, _, _)).WillOnce(Return(Store::OK));
      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _)).WillOnce(Return(remote_aor1));
      EXPECT_CALL(*remote_store1, set_aor_data(aor_id, remote_aor1, _, _, _, _)).WillOnce(Return(Store::OK));
      EXPECT_CALL(*remote_store2, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store2, get_aor_data(aor_id, _)).WillOnce(Return(remote_aor2));
      EXPECT_CALL(*remote_store2, set_aor_data(aor_id, remote_aor2, _, _, _, _)).WillOnce(Return(Store::OK));
  }

  handler->run();
}

// Test that an invalid HTTP method fails with HTTP_BADMETHOD
TEST_F(AoRTimeoutTasksTest, InvalidHTTPMethodTest)
{
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\", \"binding_id\": \"notavalidID\"}";
  build_timeout_request(body, htp_method_PUT);

  EXPECT_CALL(*stack, send_reply(_, 405, _));

  handler->run();
}

// Test that an invalid JSON body fails in parsing
TEST_F(AoRTimeoutTasksTest, InvalidJSONTest)
{
  CapturingTestLogger log(5);

  std::string body = "{\"aor_id\" \"aor_id\", \"binding_id\": \"notavalidID\"}";
  build_timeout_request(body, htp_method_POST);

  EXPECT_CALL(*stack, send_reply(_, 400, _));

  handler->run();

  EXPECT_TRUE(log.contains("Failed to parse opaque data as JSON:"));
}

// Test that a body without an AoR ID fails, logging "Badly formed opaque data"
TEST_F(AoRTimeoutTasksTest, MissingAorJSONTest)
{
  CapturingTestLogger log(5);

  std::string body = "{\"binding_id\": \"notavalidID\"}";
  build_timeout_request(body, htp_method_POST);

  EXPECT_CALL(*stack, send_reply(_, 400, _));

  handler->run();

  EXPECT_TRUE(log.contains("Badly formed opaque data (missing aor_id)"));
}

// Test with a remote AoR with no bindings
TEST_F(AoRTimeoutTasksTest, RemoteAoRNoBindingsTest)
{
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\", \"binding_id\": \"notavalidID\"}";
  build_timeout_request(body, htp_method_POST);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  SubscriberDataManager::AoRPair* aor = build_aor(aor_id);

  // Set up AoRs with no bindings for both remote stores.
  SubscriberDataManager::AoR* remote1_aor1 = new SubscriberDataManager::AoR(aor_id);
  SubscriberDataManager::AoR* remote1_aor2 = new SubscriberDataManager::AoR(*remote1_aor1);
  SubscriberDataManager::AoRPair* remote1_aor_pair = new SubscriberDataManager::AoRPair(remote1_aor1, remote1_aor2);
  SubscriberDataManager::AoR* remote2_aor1 = new SubscriberDataManager::AoR(aor_id);
  SubscriberDataManager::AoR* remote2_aor2 = new SubscriberDataManager::AoR(*remote2_aor1);
  SubscriberDataManager::AoRPair* remote2_aor_pair = new SubscriberDataManager::AoRPair(remote2_aor1, remote2_aor2);

  {
    InSequence s;
      EXPECT_CALL(*stack, send_reply(_, 200, _));
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor));
      EXPECT_CALL(*store, set_aor_data(aor_id, aor, _, _, _, _)).WillOnce(Return(Store::OK));
      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _)).WillOnce(Return(remote1_aor_pair));
      EXPECT_CALL(*remote_store1, set_aor_data(aor_id, remote1_aor_pair, _, _, _, _))
                   .WillOnce(Return(Store::OK));
      EXPECT_CALL(*remote_store2, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store2, get_aor_data(aor_id, _)).WillOnce(Return(remote2_aor_pair));
      EXPECT_CALL(*remote_store2, set_aor_data(aor_id, remote2_aor_pair, _, _, _, _))
                   .WillOnce(Return(Store::OK));
  }

  handler->run();
}

// Test with a remote store, and a local AoR with no bindings
TEST_F(AoRTimeoutTasksTest, LocalAoRNoBindingsTest)
{
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\", \"binding_id\": \"notavalidID\"}";
  build_timeout_request(body, htp_method_POST);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  // Set up local AoR with no bindings
  SubscriberDataManager::AoR* aor = new SubscriberDataManager::AoR(aor_id);
  SubscriberDataManager::AoR* aor2 = new SubscriberDataManager::AoR(*aor);
  SubscriberDataManager::AoRPair* aor_pair = new SubscriberDataManager::AoRPair(aor, aor2);

  SubscriberDataManager::AoRPair* remote1_aor1 = build_aor(aor_id);

  // Set up the remote AoR again, to avoid problem of test process deleting
  // the data of the first one. This is only a problem in the tests, as real
  // use would correctly set the data to the store before deleting the local copy
  SubscriberDataManager::AoRPair* remote1_aor2 = build_aor(aor_id);
  SubscriberDataManager::AoRPair* remote2_aor = build_aor(aor_id);

  {
    InSequence s;
      EXPECT_CALL(*stack, send_reply(_, 200, _));
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor_pair));
      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _)).WillOnce(Return(remote1_aor1));
      EXPECT_CALL(*store, set_aor_data(aor_id, aor_pair, _, _, _, _)).WillOnce(Return(Store::OK));
      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _)).WillOnce(Return(remote1_aor2));
      EXPECT_CALL(*remote_store1, set_aor_data(aor_id, remote1_aor2, _, _, _, _)).WillOnce(Return(Store::OK));
      EXPECT_CALL(*remote_store2, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store2, get_aor_data(aor_id, _)).WillOnce(Return(remote2_aor));
      EXPECT_CALL(*remote_store2, set_aor_data(aor_id, remote2_aor, _, _, _, _)).WillOnce(Return(Store::OK));
  }

  handler->run();
}

// Test with a remote store, and both AoRs with no bindings
TEST_F(AoRTimeoutTasksTest, NoBindingsTest)
{
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\"}";

  build_timeout_request(body, htp_method_POST);
  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  // Set up AoRs with no bindings
  SubscriberDataManager::AoR* aor1 = new SubscriberDataManager::AoR(aor_id);
  SubscriberDataManager::AoR* aor2 = new SubscriberDataManager::AoR(*aor1);
  SubscriberDataManager::AoRPair* aor_pair = new SubscriberDataManager::AoRPair(aor1, aor2);

  SubscriberDataManager::AoR* remote1_aor1 = new SubscriberDataManager::AoR(aor_id);
  SubscriberDataManager::AoR* remote1_aor2 = new SubscriberDataManager::AoR(*remote1_aor1);
  SubscriberDataManager::AoRPair* remote1_aor_pair1 = new SubscriberDataManager::AoRPair(remote1_aor1, remote1_aor2);
  SubscriberDataManager::AoR* remote2_aor1 = new SubscriberDataManager::AoR(aor_id);
  SubscriberDataManager::AoR* remote2_aor2 = new SubscriberDataManager::AoR(*remote2_aor1);
  SubscriberDataManager::AoRPair* remote2_aor_pair1 = new SubscriberDataManager::AoRPair(remote2_aor1, remote2_aor2);

  // Set up the remote AoRs again, to avoid problem of test process deleting
  // the data of the first one. This is only a problem in the tests, as real
  // use would correctly set the data to the store before deleting the local copy
  SubscriberDataManager::AoR* remote1_aor3 = new SubscriberDataManager::AoR(aor_id);
  SubscriberDataManager::AoR* remote1_aor4 = new SubscriberDataManager::AoR(*remote1_aor3);
  SubscriberDataManager::AoRPair* remote1_aor_pair2 = new SubscriberDataManager::AoRPair(remote1_aor3, remote1_aor4);
  SubscriberDataManager::AoR* remote2_aor3 = new SubscriberDataManager::AoR(aor_id);
  SubscriberDataManager::AoR* remote2_aor4 = new SubscriberDataManager::AoR(*remote2_aor3);
  SubscriberDataManager::AoRPair* remote2_aor_pair2 = new SubscriberDataManager::AoRPair(remote2_aor3, remote2_aor4);

  {
    InSequence s;
      EXPECT_CALL(*stack, send_reply(_, 200, _));
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor_pair));
      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _)).WillOnce(Return(remote1_aor_pair1));
      EXPECT_CALL(*remote_store2, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store2, get_aor_data(aor_id, _)).WillOnce(Return(remote2_aor_pair1));
      EXPECT_CALL(*store, set_aor_data(aor_id, aor_pair, _, _, _, _)).WillOnce(DoAll(SetArgReferee<3>(true), Return(Store::OK)));
      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _)).WillOnce(Return(remote1_aor_pair2));
      EXPECT_CALL(*remote_store1, set_aor_data(aor_id, remote1_aor_pair2, _, _, _, _)).WillOnce(DoAll(SetArgReferee<3>(true), Return(Store::OK)));
      EXPECT_CALL(*remote_store2, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store2, get_aor_data(aor_id, _)).WillOnce(Return(remote2_aor_pair2));
      EXPECT_CALL(*remote_store2, set_aor_data(aor_id, remote2_aor_pair2, _, _, _, _)).WillOnce(DoAll(SetArgReferee<3>(true), Return(Store::OK)));
      EXPECT_CALL(*mock_hss, update_registration_state(aor_id, "", HSSConnection::DEREG_TIMEOUT, 0));
  }

  handler->run();
}

// Test with NULL AoRs
TEST_F(AoRTimeoutTasksTest, NullAoRTest)
{
  CapturingTestLogger log(5);

  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\", \"binding_id\": \"notavalidID\"}";
  build_timeout_request(body, htp_method_POST);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  SubscriberDataManager::AoR* aor = NULL;
  SubscriberDataManager::AoRPair* aor_pair = new SubscriberDataManager::AoRPair(aor, aor);
  SubscriberDataManager::AoRPair* remote1_aor_pair = new SubscriberDataManager::AoRPair(aor, aor);
  SubscriberDataManager::AoRPair* remote2_aor_pair = new SubscriberDataManager::AoRPair(aor, aor);

  {
    InSequence s;
      EXPECT_CALL(*stack, send_reply(_, 200, _));
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor_pair));
      EXPECT_CALL(*store, set_aor_data(aor_id, _, _, _, _, _)).Times(0);
      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _)).WillOnce(Return(remote1_aor_pair));
      EXPECT_CALL(*remote_store1, set_aor_data(aor_id, _, _, _, _, _)).Times(0);
      EXPECT_CALL(*remote_store2, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store2, get_aor_data(aor_id, _)).WillOnce(Return(remote2_aor_pair));
      EXPECT_CALL(*remote_store2, set_aor_data(aor_id, _, _, _, _, _)).Times(0);
  }

  handler->run();

  EXPECT_TRUE(log.contains("Failed to get AoR binding for"));
}

class AoRTimeoutTasksMockStoreTest : public SipTest
{
  FakeChronosConnection* chronos_connection;
  MockSubscriberDataManager* store;
  FakeHSSConnection* fake_hss;

  MockHttpStack stack;
  MockHttpStack::Request* req;
  AoRTimeoutTask::Config* chronos_config;

  AoRTimeoutTask* handler;

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase(false);
  }

  void SetUp()
  {
    chronos_connection = new FakeChronosConnection();
    store = new MockSubscriberDataManager();
    fake_hss = new FakeHSSConnection();
    req = new MockHttpStack::Request(&stack, "/", "timers");
    chronos_config = new AoRTimeoutTask::Config(store, {}, fake_hss);
    handler = new AoRTimeoutTask(*req, chronos_config, 0);
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

TEST_F(AoRTimeoutTasksMockStoreTest, SubscriberDataManagerWritesFail)
{
  // Set up the SubscriberDataManager to fail all sets and respond to all gets with not
  // found.
  SubscriberDataManager::AoR* aor = new SubscriberDataManager::AoR("sip:6505550231@homedomain");
  SubscriberDataManager::AoR* aor2 = new SubscriberDataManager::AoR(*aor);
  SubscriberDataManager::AoRPair* aor_pair = new SubscriberDataManager::AoRPair(aor, aor2);
  EXPECT_CALL(*store, get_aor_data(_, _)).WillOnce(Return(aor_pair));
  EXPECT_CALL(*store, set_aor_data(_, _, _, _, _, _)).WillOnce(Return(Store::ERROR));

  // Parse and handle the request
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\", \"binding_id\": \"notavalidID\"}";
  int status = handler->parse_response(body);

  ASSERT_EQ(status, 200);

  handler->handle_response();
}

class DeregistrationTaskTest : public SipTest
{
  MockSubscriberDataManager* _subscriber_data_manager;
  MockImpiStore* _impi_store;
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
    _impi_store = new MockImpiStore();
    _httpstack = new MockHttpStack();
    _subscriber_data_manager = new MockSubscriberDataManager();
    _hss = new FakeHSSConnection();
    stack_data.scscf_uri = pj_str("sip:all.the.sprouts:5058;transport=TCP");
  }

  void TearDown()
  {
    delete _req;
    delete _cfg;
    delete _hss;
    delete _subscriber_data_manager;
    delete _httpstack;
    delete _impi_store; _impi_store = NULL;
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
    _cfg = new DeregistrationTask::Config(_subscriber_data_manager,
                                          {},
                                          _hss,
                                          NULL,
                                          _impi_store);
    _task = new DeregistrationTask(*_req, _cfg, 0);
  }

  void expect_sdm_updates(std::vector<std::string> aor_ids,
                          std::vector<SubscriberDataManager::AoRPair*> aors)
  {
    for (uint32_t ii = 0; ii < aor_ids.size(); ++ii)
    {
      // Get the information from the local store
      EXPECT_CALL(*_subscriber_data_manager, get_aor_data(aor_ids[ii], _)).WillOnce(Return(aors[ii]));

      if (aors[ii] != NULL)
      {
        // Write the information to the local store
        EXPECT_CALL(*_subscriber_data_manager, set_aor_data(aor_ids[ii], _, _, _, _, _)).WillOnce(Return(Store::OK));
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

  // Get an initial empty AoR record and add a standard binding
  std::string aor_id = "sip:6505550231@homedomain";
  SubscriberDataManager::AoR* aor = new SubscriberDataManager::AoR(aor_id);
  int now = time(NULL);
  SubscriberDataManager::AoR::Binding* b1 = aor->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1"));
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

  // Set up the subscriber_data_manager expectations
  SubscriberDataManager::AoR* aor2 = new SubscriberDataManager::AoR(*aor);
  SubscriberDataManager::AoRPair* aor_pair = new SubscriberDataManager::AoRPair(aor, aor2);
  std::vector<std::string> aor_ids = {aor_id};
  std::vector<SubscriberDataManager::AoRPair*> aors = {aor_pair};
  expect_sdm_updates(aor_ids, aors);

  // The IMPI is also deleted.
  ImpiStore::Impi* impi = new ImpiStore::Impi("6505550231");
  EXPECT_CALL(*_impi_store, get_impi("6505550231", _)).WillOnce(Return(impi));
  EXPECT_CALL(*_impi_store, delete_impi(impi, _)).WillOnce(Return(Store::OK));

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();
}

// Test where there are multiple pairs of AoRs and Private IDs and single AoRs
TEST_F(DeregistrationTaskTest, AoRPrivateIdPairsTest)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505552001@homedomain\", \"impi\": \"6505552001\"}, {\"primary-impu\": \"sip:6505552002@homedomain\", \"impi\": \"6505552002\"}, {\"primary-impu\": \"sip:6505552003@homedomain\"}, {\"primary-impu\": \"sip:6505552004@homedomain\"}]}";
  build_dereg_request(body, "false");

  // Set up the subscriber_data_manager expectations
  std::string aor_id_1 = "sip:6505552001@homedomain";
  std::string aor_id_2 = "sip:6505552002@homedomain";
  std::string aor_id_3 = "sip:6505552003@homedomain";
  std::string aor_id_4 = "sip:6505552004@homedomain";
  SubscriberDataManager::AoR* aor_1 = new SubscriberDataManager::AoR(aor_id_1);
  SubscriberDataManager::AoR* aor_11 = new SubscriberDataManager::AoR(*aor_1);
  SubscriberDataManager::AoRPair* aor_pair_1 = new SubscriberDataManager::AoRPair(aor_1, aor_11);
  SubscriberDataManager::AoR* aor_2 = new SubscriberDataManager::AoR(aor_id_2);
  SubscriberDataManager::AoR* aor_22 = new SubscriberDataManager::AoR(*aor_2);
  SubscriberDataManager::AoRPair* aor_pair_2 = new SubscriberDataManager::AoRPair(aor_2, aor_22);
  SubscriberDataManager::AoR* aor_3 = new SubscriberDataManager::AoR(aor_id_3);
  SubscriberDataManager::AoR* aor_33 = new SubscriberDataManager::AoR(*aor_3);
  SubscriberDataManager::AoRPair* aor_pair_3 = new SubscriberDataManager::AoRPair(aor_3, aor_33);
  SubscriberDataManager::AoR* aor_4 = new SubscriberDataManager::AoR(aor_id_4);
  SubscriberDataManager::AoR* aor_44 = new SubscriberDataManager::AoR(*aor_4);
  SubscriberDataManager::AoRPair* aor_pair_4 = new SubscriberDataManager::AoRPair(aor_4, aor_44);
  std::vector<std::string> aor_ids = {aor_id_1, aor_id_2, aor_id_3, aor_id_4};
  std::vector<SubscriberDataManager::AoRPair*> aors = {aor_pair_1, aor_pair_2, aor_pair_3, aor_pair_4};
  expect_sdm_updates(aor_ids, aors);

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();
}

// Test when the SubscriberDataManager can't be accessed.
TEST_F(DeregistrationTaskTest, SubscriberDataManagerFailureTest)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505552001@homedomain\"}]}";
  build_dereg_request(body, "false");

  // Set up the subscriber_data_manager expectations
  std::string aor_id = "sip:6505552001@homedomain";
  SubscriberDataManager::AoRPair* aor_pair = NULL;
  std::vector<std::string> aor_ids = {aor_id};
  std::vector<SubscriberDataManager::AoRPair*> aors = {aor_pair};
  expect_sdm_updates(aor_ids, aors);

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

  // Set up the subscriber_data_manager expectations
  std::string aor_id = "notavalidsipuri";
  SubscriberDataManager::AoR* aor = new SubscriberDataManager::AoR(aor_id);
  SubscriberDataManager::AoR* aor2 = new SubscriberDataManager::AoR(*aor);
  SubscriberDataManager::AoRPair* aor_pair = new SubscriberDataManager::AoRPair(aor, aor2);
  std::vector<std::string> aor_ids = {aor_id};
  std::vector<SubscriberDataManager::AoRPair*> aors = {aor_pair};
  expect_sdm_updates(aor_ids, aors);

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

TEST_F(DeregistrationTaskTest, SubscriberDataManagerWritesFail)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\", \"impi\": \"6505550231\"}]}";
  build_dereg_request(body);

  SubscriberDataManager::AoR* aor = new SubscriberDataManager::AoR("sip:6505550231@homedomain");
  SubscriberDataManager::AoR* aor2 = new SubscriberDataManager::AoR(*aor);
  SubscriberDataManager::AoRPair* aor_pair = new SubscriberDataManager::AoRPair(aor, aor2);

  EXPECT_CALL(*_subscriber_data_manager, get_aor_data(_,  _)).WillOnce(Return(aor_pair));
  EXPECT_CALL(*_subscriber_data_manager, set_aor_data(_, _, _, _, _, _)).WillOnce(Return(Store::ERROR));

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 500, _));
  _task->run();
}

TEST_F(DeregistrationTaskTest, ImpiNotClearedWhenBindingNotDeregistered)
{
  // Build a request that will not deregister any bindings.
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\", \"impi\": \"wrong-impi\"}]}";
  build_dereg_request(body);

  // Create an AoR with a minimal binding.
  std::string aor_id = "sip:6505550231@homedomain";
  SubscriberDataManager::AoR* aor = new SubscriberDataManager::AoR(aor_id);
  int now = time(NULL);
  SubscriberDataManager::AoR::Binding* b1 = aor->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1"));
  b1->_expires = now + 300;
  b1->_emergency_registration = false;
  b1->_private_id = "impi1";

  SubscriberDataManager::AoR* aor2 = new SubscriberDataManager::AoR(*aor);
  SubscriberDataManager::AoRPair* aor_pair = new SubscriberDataManager::AoRPair(aor, aor2);
  std::vector<std::string> aor_ids = {aor_id};
  std::vector<SubscriberDataManager::AoRPair*> aors = {aor_pair};
  expect_sdm_updates(aor_ids, aors);

  // Nothing is deleted from the IMPI store.

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();
}

TEST_F(DeregistrationTaskTest, ImpiClearedWhenBindingUnconditionallyDeregistered)
{
  // Build a request that deregisters all bindings for an IMPU regardless of
  // IMPI.
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\"}]}";
  build_dereg_request(body);

  // Create an AoR with a minimal binding.
  std::string aor_id = "sip:6505550231@homedomain";
  SubscriberDataManager::AoR* aor = new SubscriberDataManager::AoR(aor_id);
  int now = time(NULL);
  SubscriberDataManager::AoR::Binding* b1 = aor->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1"));
  b1->_expires = now + 300;
  b1->_emergency_registration = false;
  b1->_private_id = "impi1";

  SubscriberDataManager::AoR* aor2 = new SubscriberDataManager::AoR(*aor);
  SubscriberDataManager::AoRPair* aor_pair = new SubscriberDataManager::AoRPair(aor, aor2);
  std::vector<std::string> aor_ids = {aor_id};
  std::vector<SubscriberDataManager::AoRPair*> aors = {aor_pair};
  expect_sdm_updates(aor_ids, aors);

  // The corresponding IMPI is also deleted.
  ImpiStore::Impi* impi = new ImpiStore::Impi("impi1");
  EXPECT_CALL(*_impi_store, get_impi("impi1", _)).WillOnce(Return(impi));
  EXPECT_CALL(*_impi_store, delete_impi(impi, _)).WillOnce(Return(Store::OK));

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();
}

TEST_F(DeregistrationTaskTest, ClearMultipleImpis)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\"}, {\"primary-impu\": \"sip:6505550232@homedomain\"}]}";
  build_dereg_request(body);

  int now = time(NULL);

  // Create an AoR with two bindings.
  std::string aor_id = "sip:6505550231@homedomain";
  SubscriberDataManager::AoR* aor = new SubscriberDataManager::AoR(aor_id);

  SubscriberDataManager::AoR::Binding* b1 = aor->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1"));
  b1->_expires = now + 300;
  b1->_emergency_registration = false;
  b1->_private_id = "impi1";

  SubscriberDataManager::AoR::Binding* b2 = aor->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:2"));
  b2->_expires = now + 300;
  b2->_emergency_registration = false;
  b2->_private_id = "impi2";

  SubscriberDataManager::AoR* backup_aor = new SubscriberDataManager::AoR(*aor);
  SubscriberDataManager::AoRPair* aor_pair = new SubscriberDataManager::AoRPair(aor, backup_aor);

  // create another AoR with one binding.
  std::string aor_id2 = "sip:6505550232@homedomain";
  SubscriberDataManager::AoR* aor2 = new SubscriberDataManager::AoR(aor_id2);

  SubscriberDataManager::AoR::Binding* b3 = aor2->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:3"));
  b3->_expires = now + 300;
  b3->_emergency_registration = false;
  b3->_private_id = "impi3";

  SubscriberDataManager::AoR* backup_aor2 = new SubscriberDataManager::AoR(*aor2);
  SubscriberDataManager::AoRPair* aor_pair2 = new SubscriberDataManager::AoRPair(aor2, backup_aor2);

  std::vector<std::string> aor_ids = {aor_id, aor_id2};
  std::vector<SubscriberDataManager::AoRPair*> aors = {aor_pair, aor_pair2};
  expect_sdm_updates(aor_ids, aors);

  // The corresponding IMPIs are also deleted.
  ImpiStore::Impi* impi1 = new ImpiStore::Impi("impi1");
  ImpiStore::Impi* impi2 = new ImpiStore::Impi("impi2");
  ImpiStore::Impi* impi3 = new ImpiStore::Impi("impi3");
  EXPECT_CALL(*_impi_store, get_impi("impi1", _)).WillOnce(Return(impi1));
  EXPECT_CALL(*_impi_store, delete_impi(impi1, _)).WillOnce(Return(Store::OK));
  EXPECT_CALL(*_impi_store, get_impi("impi2", _)).WillOnce(Return(impi2));
  EXPECT_CALL(*_impi_store, delete_impi(impi2, _)).WillOnce(Return(Store::OK));
  EXPECT_CALL(*_impi_store, get_impi("impi3", _)).WillOnce(Return(impi3));
  EXPECT_CALL(*_impi_store, delete_impi(impi3, _)).WillOnce(Return(Store::OK));

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();
}

TEST_F(DeregistrationTaskTest, CannotFindImpiToDelete)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\"}]}";
  build_dereg_request(body);

  // Create an AoR with a minimal binding.
  std::string aor_id = "sip:6505550231@homedomain";
  SubscriberDataManager::AoR* aor = new SubscriberDataManager::AoR(aor_id);
  int now = time(NULL);
  SubscriberDataManager::AoR::Binding* b1 = aor->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1"));
  b1->_expires = now + 300;
  b1->_emergency_registration = false;
  b1->_private_id = "impi1";

  SubscriberDataManager::AoR* aor2 = new SubscriberDataManager::AoR(*aor);
  SubscriberDataManager::AoRPair* aor_pair = new SubscriberDataManager::AoRPair(aor, aor2);
  std::vector<std::string> aor_ids = {aor_id};
  std::vector<SubscriberDataManager::AoRPair*> aors = {aor_pair};
  expect_sdm_updates(aor_ids, aors);

  // Simulate the IMPI not being found in the store. The handler does not go on
  // to try and delete the IMPI.
  ImpiStore::Impi* impi1 = NULL;
  EXPECT_CALL(*_impi_store, get_impi("impi1", _)).WillOnce(Return(impi1));

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();
}

TEST_F(DeregistrationTaskTest, ImpiStoreFailure)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\"}]}";
  build_dereg_request(body);

  // Create an AoR with a minimal binding.
  std::string aor_id = "sip:6505550231@homedomain";
  SubscriberDataManager::AoR* aor = new SubscriberDataManager::AoR(aor_id);
  int now = time(NULL);
  SubscriberDataManager::AoR::Binding* b1 = aor->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1"));
  b1->_expires = now + 300;
  b1->_emergency_registration = false;
  b1->_private_id = "impi1";

  SubscriberDataManager::AoR* aor2 = new SubscriberDataManager::AoR(*aor);
  SubscriberDataManager::AoRPair* aor_pair = new SubscriberDataManager::AoRPair(aor, aor2);
  std::vector<std::string> aor_ids = {aor_id};
  std::vector<SubscriberDataManager::AoRPair*> aors = {aor_pair};
  expect_sdm_updates(aor_ids, aors);

  // Simulate the IMPI store failing when deleting the IMPI. The handler does
  // not retry the delete.
  ImpiStore::Impi* impi1 = new ImpiStore::Impi("impi1");
  EXPECT_CALL(*_impi_store, get_impi("impi1", _)).WillOnce(Return(impi1));
  EXPECT_CALL(*_impi_store, delete_impi(impi1, _)).WillOnce(Return(Store::ERROR));

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();
}

TEST_F(DeregistrationTaskTest, ImpiStoreDataContention)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\"}]}";
  build_dereg_request(body);

  // Create an AoR with a minimal binding.
  std::string aor_id = "sip:6505550231@homedomain";
  SubscriberDataManager::AoR* aor = new SubscriberDataManager::AoR(aor_id);
  int now = time(NULL);
  SubscriberDataManager::AoR::Binding* b1 = aor->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1"));
  b1->_expires = now + 300;
  b1->_emergency_registration = false;
  b1->_private_id = "impi1";

  SubscriberDataManager::AoR* aor2 = new SubscriberDataManager::AoR(*aor);
  SubscriberDataManager::AoRPair* aor_pair = new SubscriberDataManager::AoRPair(aor, aor2);
  std::vector<std::string> aor_ids = {aor_id};
  std::vector<SubscriberDataManager::AoRPair*> aors = {aor_pair};
  expect_sdm_updates(aor_ids, aors);

  // We need to create two IMPIs when we return one on a call to get_impi we
  // lose ownership of it.
  ImpiStore::Impi* impi1 = new ImpiStore::Impi("impi1");
  ImpiStore::Impi* impi1a = new ImpiStore::Impi("impi1");
  {
    // Simulate the IMPI store returning data contention on the first delete.
    // The handler tries again.
    InSequence s;
    EXPECT_CALL(*_impi_store, get_impi("impi1", _)).WillOnce(Return(impi1));
    EXPECT_CALL(*_impi_store, delete_impi(impi1, _)).WillOnce(Return(Store::DATA_CONTENTION));
    EXPECT_CALL(*_impi_store, get_impi("impi1", _)).WillOnce(Return(impi1a));
    EXPECT_CALL(*_impi_store, delete_impi(impi1a, _)).WillOnce(Return(Store::OK));
  }

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();
}


class AuthTimeoutTest : public SipTest
{
  FakeChronosConnection* chronos_connection;
  LocalStore* local_data_store;
  ImpiStore* store;
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
    store = new ImpiStore(local_data_store, ImpiStore::Mode::READ_IMPI_WRITE_IMPI);
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
  ImpiStore::Impi* impi = new ImpiStore::Impi("6505550231@homedomain");
  ImpiStore::DigestAuthChallenge* auth_challenge = new ImpiStore::DigestAuthChallenge("abcdef", "example.com", "auth", "ha1", time(NULL) + 30);
  auth_challenge->correlator = "abcde";
  impi->auth_challenges.push_back(auth_challenge);
  store->set_impi(impi, 0);

  std::string body = "{\"impu\": \"sip:6505550231@homedomain\", \"impi\": \"6505550231@homedomain\", \"nonce\": \"abcdef\"}";
  int status = handler->handle_response(body);

  ASSERT_EQ(status, 200);
  ASSERT_TRUE(fake_hss->url_was_requested("/impu/sip%3A6505550231%40homedomain/reg-data?private_id=6505550231%40homedomain", "{\"reqtype\": \"dereg-auth-timeout\", \"server_name\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}"));

  delete impi; impi = NULL;
}

TEST_F(AuthTimeoutTest, NonceTimedOutWithEmptyCorrelator)
{
  fake_hss->set_impu_result("sip:6505550231@homedomain", "dereg-auth-timeout", HSSConnection::STATE_REGISTERED, "", "?private_id=6505550231%40homedomain");
  ImpiStore::Impi* impi = new ImpiStore::Impi("6505550231@homedomain");
  ImpiStore::DigestAuthChallenge* auth_challenge = new ImpiStore::DigestAuthChallenge("abcdef", "example.com", "auth", "ha1", time(NULL) + 30);
  impi->auth_challenges.push_back(auth_challenge);
  store->set_impi(impi, 0);

  std::string body = "{\"impu\": \"sip:6505550231@homedomain\", \"impi\": \"6505550231@homedomain\", \"nonce\": \"abcdef\"}";
  int status = handler->handle_response(body);

  ASSERT_EQ(status, 200);
  ASSERT_TRUE(fake_hss->url_was_requested("/impu/sip%3A6505550231%40homedomain/reg-data?private_id=6505550231%40homedomain", "{\"reqtype\": \"dereg-auth-timeout\", \"server_name\": \"sip:scscf.sprout.homedomain:5058;transport=TCP\"}"));

  delete impi; impi = NULL;
}

TEST_F(AuthTimeoutTest, MainlineTest)
{
  ImpiStore::Impi* impi = new ImpiStore::Impi("test@example.com");
  ImpiStore::DigestAuthChallenge* auth_challenge = new ImpiStore::DigestAuthChallenge("abcdef", "example.com", "auth", "ha1", time(NULL) + 30);
  auth_challenge->nonce_count++; // Indicates that one successful authentication has occurred
  auth_challenge->correlator = "abcde";
  impi->auth_challenges.push_back(auth_challenge);
  store->set_impi(impi, 0);

  std::string body = "{\"impu\": \"sip:test@example.com\", \"impi\": \"test@example.com\", \"nonce\": \"abcdef\"}";
  int status = handler->handle_response(body);

  ASSERT_EQ(status, 200);
  ASSERT_FALSE(fake_hss->url_was_requested("/impu/sip%3Atest%40example.com/reg-data?private_id=test%40example.com", "{\"reqtype\": \"dereg-auth-timeout\"}"));

  delete impi; impi = NULL;
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
