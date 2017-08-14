/**
 * @file handlers_test.cpp UT for Handlers module.
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
#include "handlers.h"
#include "chronoshandlers.h"
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
#include "rapidjson/document.h"
#include "test_with_mock_sdms.h"

using namespace std;
using ::testing::_;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::SetArgPointee;
using ::testing::SaveArg;
using ::testing::SaveArgPointee;
using ::testing::InSequence;
using ::testing::ByRef;
using ::testing::NiceMock;

class AoRTimeoutTasksTest : public TestWithMockSdms
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
    config = new AoRTimeoutTask::Config(store, {remote_store1, remote_store2}, mock_hss);
    handler = new ChronosAoRTimeoutTask(*req, config, 0);
  }

  MockHttpStack::Request* req;
  AoRTimeoutTask::Config* config;
  ChronosAoRTimeoutTask* handler;
};

// Test main flow, without a remote store.
TEST_F(AoRTimeoutTasksTest, MainlineTest)
{
  // Build request
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\"}";
  build_timeout_request(body, htp_method_POST);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  SubscriberDataManager::AoRPair* aor = build_aor(aor_id);
  SubscriberDataManager::AoRPair* remote_aor1 = build_aor(aor_id);
  SubscriberDataManager::AoRPair* remote_aor2 = build_aor(aor_id);

  // Set up IRS IMPU list to be returned by the mocked get_registration_data call.
  // Add a bunch of random IMPUs to this list - they should all be passed to set_aor_data.
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri("tel:6505550232", false);
  associated_uris.add_uri(aor_id, false);
  associated_uris.add_uri("sip:another_user@another_domain.com", false);

  {
    InSequence s;
      EXPECT_CALL(*stack, send_reply(_, 200, _));
      EXPECT_CALL(*mock_hss, get_registration_data(_, _, _, _, _))
           .WillOnce(DoAll(SetArgReferee<3>(AssociatedURIs(associated_uris)), //IMPUs in IRS
                           Return(HTTP_OK)));
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor));
      EXPECT_CALL(*store, set_aor_data(aor_id, _, aor, _, _)).WillOnce(DoAll(SetArgPointee<1>(AssociatedURIs(associated_uris)),
                                                                             Return(Store::OK)));
      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _)).WillOnce(Return(remote_aor1));
      EXPECT_CALL(*remote_store1, set_aor_data(aor_id, _, remote_aor1, _, _)).WillOnce(DoAll(SetArgPointee<1>(AssociatedURIs(associated_uris)),
                                                                                             Return(Store::OK)));
      EXPECT_CALL(*remote_store2, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store2, get_aor_data(aor_id, _)).WillOnce(Return(remote_aor2));
      EXPECT_CALL(*remote_store2, set_aor_data(aor_id, _, remote_aor2, _, _)).WillOnce(DoAll(SetArgPointee<1>(AssociatedURIs(associated_uris)),
                                                                                             Return(Store::OK)));
  }

  handler->run();
}

// Test that an invalid HTTP method fails with HTTP_BADMETHOD
TEST_F(AoRTimeoutTasksTest, InvalidHTTPMethodTest)
{
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\"}";
  build_timeout_request(body, htp_method_PUT);

  EXPECT_CALL(*stack, send_reply(_, 405, _));

  handler->run();
}

// Test that an invalid JSON body fails in parsing
TEST_F(AoRTimeoutTasksTest, InvalidJSONTest)
{
  CapturingTestLogger log(5);

  std::string body = "{\"aor_id\" \"aor_id\"}";
  build_timeout_request(body, htp_method_POST);

  EXPECT_CALL(*stack, send_reply(_, 400, _));

  handler->run();

  EXPECT_TRUE(log.contains("Failed to parse opaque data as JSON:"));
}

// Test that a body without an AoR ID fails, logging "Badly formed opaque data"
TEST_F(AoRTimeoutTasksTest, MissingAorJSONTest)
{
  CapturingTestLogger log(5);

  std::string body = "{}";
  build_timeout_request(body, htp_method_POST);

  EXPECT_CALL(*stack, send_reply(_, 400, _));

  handler->run();

  EXPECT_TRUE(log.contains("Badly formed opaque data (missing aor_id)"));
}

// Test with a remote AoR with no bindings
TEST_F(AoRTimeoutTasksTest, RemoteAoRNoBindingsTest)
{
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\"}";
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

  // Set up IRS IMPU list to be returned by the mocked get_registration_data calls
  // We'll return an empty list from the mocked get_registration_data.  We should still
  // see our AoR in the irs_impus list passed to set_aor_data.
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri(aor_id, false);

  {
    InSequence s;
      EXPECT_CALL(*stack, send_reply(_, 200, _));
      EXPECT_CALL(*mock_hss, get_registration_data(_, _, _, _, _)).WillOnce(Return(HTTP_OK));
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor));
      EXPECT_CALL(*store, set_aor_data(aor_id, _, aor, _, _)).WillOnce(DoAll(SetArgPointee<1>(AssociatedURIs(associated_uris)),
                                                                             Return(Store::OK)));
      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _)).WillOnce(Return(remote1_aor_pair));
      EXPECT_CALL(*remote_store1, set_aor_data(aor_id, _, remote1_aor_pair, _, _))
                   .WillOnce(DoAll(SetArgPointee<1>(AssociatedURIs(associated_uris)),
                                   Return(Store::OK)));
      EXPECT_CALL(*remote_store2, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store2, get_aor_data(aor_id, _)).WillOnce(Return(remote2_aor_pair));
      EXPECT_CALL(*remote_store2, set_aor_data(aor_id, _, remote2_aor_pair, _, _))
                   .WillOnce(DoAll(SetArgPointee<1>(AssociatedURIs(associated_uris)),
                                   Return(Store::OK)));
  }

  handler->run();
}

// Test with a remote store, and a local AoR with no bindings
TEST_F(AoRTimeoutTasksTest, LocalAoRNoBindingsTest)
{
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\"}";
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

  // Set up IRS IMPU list to be returned by the mocked get_registration_data call
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri(aor_id, false);

  {
    InSequence s;
      EXPECT_CALL(*stack, send_reply(_, 200, _));
      EXPECT_CALL(*mock_hss, get_registration_data(_, _, _, _, _))
           .WillOnce(DoAll(SetArgReferee<3>(AssociatedURIs(associated_uris)), //IMPUs in IRS
                           Return(HTTP_OK)));
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor_pair));
      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _)).WillOnce(Return(remote1_aor1));
      EXPECT_CALL(*store, set_aor_data(aor_id, _, aor_pair, _, _)).WillOnce(DoAll(SetArgPointee<1>(AssociatedURIs(associated_uris)),
                                                                                  Return(Store::OK)));
      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _)).WillOnce(Return(remote1_aor2));
      EXPECT_CALL(*remote_store1, set_aor_data(aor_id, _, remote1_aor2, _, _)).WillOnce(DoAll(SetArgPointee<1>(AssociatedURIs(associated_uris)),
                                                                                              Return(Store::OK)));
      EXPECT_CALL(*remote_store2, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store2, get_aor_data(aor_id, _)).WillOnce(Return(remote2_aor));
      EXPECT_CALL(*remote_store2, set_aor_data(aor_id, _, remote2_aor, _, _)).WillOnce(DoAll(SetArgPointee<1>(AssociatedURIs(associated_uris)),
                                                                                             Return(Store::OK)));
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
  aor1->_scscf_uri = "sip:scscf.sprout.homedomain:5058;transport=TCP";
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

  // Set up IRS IMPU list to be returned by the mocked get_registration_data call
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri(aor_id, false);

  {
    InSequence s;
      EXPECT_CALL(*stack, send_reply(_, 200, _));
      EXPECT_CALL(*mock_hss, get_registration_data(_, _, _, _, _))
           .WillOnce(DoAll(SetArgReferee<3>(AssociatedURIs(associated_uris)), //IMPUs in IRS
                           Return(HTTP_OK)));
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor_pair));
      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _)).WillOnce(Return(remote1_aor_pair1));
      EXPECT_CALL(*remote_store2, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store2, get_aor_data(aor_id, _)).WillOnce(Return(remote2_aor_pair1));
      EXPECT_CALL(*store, set_aor_data(aor_id, _, aor_pair, _, _)).WillOnce(DoAll(SetArgPointee<1>(AssociatedURIs(associated_uris)),
                                                                                  SetArgReferee<4>(true),
                                                                                  Return(Store::OK)));
      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _)).WillOnce(Return(remote1_aor_pair2));
      EXPECT_CALL(*remote_store1, set_aor_data(aor_id, _, remote1_aor_pair2, _, _)).WillOnce(DoAll(SetArgPointee<1>(AssociatedURIs(associated_uris)),
                                                                                                   SetArgReferee<4>(true),
                                                                                                   Return(Store::OK)));
      EXPECT_CALL(*remote_store2, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store2, get_aor_data(aor_id, _)).WillOnce(Return(remote2_aor_pair2));
      EXPECT_CALL(*remote_store2, set_aor_data(aor_id, _, remote2_aor_pair2, _, _)).WillOnce(DoAll(SetArgPointee<1>(AssociatedURIs(associated_uris)),
                                                                                                   SetArgReferee<4>(true),
                                                                                                   Return(Store::OK)));
      EXPECT_CALL(*mock_hss, update_registration_state(aor_id, "", HSSConnection::DEREG_TIMEOUT, "sip:scscf.sprout.homedomain:5058;transport=TCP", 0));
  }

  handler->run();
}

// Test with NULL AoRs
TEST_F(AoRTimeoutTasksTest, NullAoRTest)
{
  CapturingTestLogger log(5);

  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\"}";
  build_timeout_request(body, htp_method_POST);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  SubscriberDataManager::AoR* aor = NULL;
  SubscriberDataManager::AoRPair* aor_pair = new SubscriberDataManager::AoRPair(aor, aor);
  SubscriberDataManager::AoRPair* remote1_aor_pair = new SubscriberDataManager::AoRPair(aor, aor);
  SubscriberDataManager::AoRPair* remote2_aor_pair = new SubscriberDataManager::AoRPair(aor, aor);

  // Set up IRS IMPU list to be returned by the mocked get_registration_data call
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri(aor_id, false);

  {
    InSequence s;
      EXPECT_CALL(*stack, send_reply(_, 200, _));
      EXPECT_CALL(*mock_hss, get_registration_data(_, _, _, _, _))
           .WillOnce(DoAll(SetArgReferee<3>(AssociatedURIs(associated_uris)), //IMPUs in IRS
                           Return(HTTP_OK)));
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor_pair));
      EXPECT_CALL(*store, set_aor_data(aor_id, _, _, _, _)).Times(0);
      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _)).WillOnce(Return(remote1_aor_pair));
      EXPECT_CALL(*remote_store1, set_aor_data(aor_id, _, _, _, _)).Times(0);
      EXPECT_CALL(*remote_store2, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store2, get_aor_data(aor_id, _)).WillOnce(Return(remote2_aor_pair));
      EXPECT_CALL(*remote_store2, set_aor_data(aor_id, _, _, _, _)).Times(0);
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

  ChronosAoRTimeoutTask* handler;

  void SetUp()
  {
    chronos_connection = new FakeChronosConnection();
    store = new MockSubscriberDataManager();
    fake_hss = new FakeHSSConnection();
    req = new MockHttpStack::Request(&stack, "/", "timers");
    chronos_config = new AoRTimeoutTask::Config(store, {}, fake_hss);
    handler = new ChronosAoRTimeoutTask(*req, chronos_config, 0);
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

  // Set up IRS IMPU list to be returned by the mocked get_registration_data call
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri("sip:6505550231@homedomain", false);

  EXPECT_CALL(*store, get_aor_data(_, _)).WillOnce(Return(aor_pair));
  EXPECT_CALL(*store, set_aor_data(_, _, _, _, _)).WillOnce(DoAll(SetArgPointee<1>(AssociatedURIs(associated_uris)),
                                                                  Return(Store::ERROR)));

  // Parse and handle the request
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\"}";
  int status = handler->parse_response(body);

  ASSERT_EQ(status, 200);

  handler->handle_response();
}

class AuthTimeoutTest : public SipTest
{
  FakeChronosConnection* chronos_connection;
  LocalStore* local_data_store;
  ImpiStore* store;
  FakeHSSConnection* fake_hss;

  MockHttpStack stack;
  MockHttpStack::Request* req;
  ChronosAuthTimeoutTask::Config* chronos_config;

  ChronosAuthTimeoutTask* handler;

  void SetUp()
  {
    chronos_connection = new FakeChronosConnection();
    local_data_store = new LocalStore();
    store = new ImpiStore(local_data_store);
    fake_hss = new FakeHSSConnection();
    req = new MockHttpStack::Request(&stack, "/", "authentication-timeout");
    chronos_config = new ChronosAuthTimeoutTask::Config(store, fake_hss);
    handler = new ChronosAuthTimeoutTask(*req, chronos_config, 0);
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
  fake_hss->set_impu_result("sip:6505550231@homedomain", "dereg-auth-timeout", RegDataXMLUtils::STATE_REGISTERED, "", "?private_id=6505550231%40homedomain");
  ImpiStore::Impi* impi = new ImpiStore::Impi("6505550231@homedomain");
  ImpiStore::DigestAuthChallenge* auth_challenge = new ImpiStore::DigestAuthChallenge("abcdef", "example.com", "auth", "ha1", time(NULL) + 30);
  auth_challenge->correlator = "abcde";
  auth_challenge->scscf_uri = "sip:scscf.sprout.homedomain:5058;transport=TCP";
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
  fake_hss->set_impu_result("sip:6505550231@homedomain", "dereg-auth-timeout", RegDataXMLUtils::STATE_REGISTERED, "", "?private_id=6505550231%40homedomain");
  ImpiStore::Impi* impi = new ImpiStore::Impi("6505550231@homedomain");
  ImpiStore::DigestAuthChallenge* auth_challenge = new ImpiStore::DigestAuthChallenge("abcdef", "example.com", "auth", "ha1", time(NULL) + 30);
  auth_challenge->scscf_uri = "sip:scscf.sprout.homedomain:5058;transport=TCP";
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
