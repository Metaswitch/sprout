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

class TestWithMockSdms : public SipTest
{
  MockSubscriberDataManager* store;
  MockSubscriberDataManager* remote_store1;
  MockSubscriberDataManager* remote_store2;
  MockHttpStack* stack;
  MockHSSConnection* mock_hss;

  virtual void SetUp()
  {
    store = new MockSubscriberDataManager();
    remote_store1 = new MockSubscriberDataManager();
    remote_store2 = new MockSubscriberDataManager();
    mock_hss = new MockHSSConnection();
    stack = new MockHttpStack();
  }

  virtual void TearDown()
  {
    delete stack;
    delete remote_store1; remote_store1 = NULL;
    delete remote_store2; remote_store2 = NULL;
    delete store; store = NULL;
    delete mock_hss;
  }

  SubscriberDataManager::AoRPair* build_aor(std::string aor_id,
                                            bool include_subscription = true)
  {
    SubscriberDataManager::AoR* aor = new SubscriberDataManager::AoR(aor_id);
    int now = time(NULL);
    build_binding(aor, now);
    if (include_subscription)
    {
      build_subscription(aor, now);
    }
    aor->_scscf_uri = "sip:scscf.sprout.homedomain:5058;transport=TCP";
    SubscriberDataManager::AoR* aor2 = new SubscriberDataManager::AoR(*aor);
    SubscriberDataManager::AoRPair* aor_pair = new SubscriberDataManager::AoRPair(aor, aor2);

    return aor_pair;
  }

  SubscriberDataManager::AoR::Binding*
    build_binding(SubscriberDataManager::AoR* aor,
                  int now,
                  const std::string& id = "<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1")
  {
    SubscriberDataManager::AoR::Binding* b = aor->get_binding(std::string(id));
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

  SubscriberDataManager::AoR::Subscription*
    build_subscription(SubscriberDataManager::AoR* aor,
                       int now,
                       const std::string& id = "1234")
  {
    SubscriberDataManager::AoR::Subscription* s = aor->get_subscription(id);
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
    handler = new AoRTimeoutTask(*req, config, 0);
  }

  MockHttpStack::Request* req;
  AoRTimeoutTask::Config* config;
  AoRTimeoutTask* handler;
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

  AoRTimeoutTask* handler;

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

class DeregistrationTaskTest : public SipTest
{
  MockSubscriberDataManager* _subscriber_data_manager;
  MockImpiStore* _local_impi_store;
  MockImpiStore* _remote_impi_store;
  MockHttpStack* _httpstack;
  FakeHSSConnection* _hss;
  MockHttpStack::Request* _req;
  DeregistrationTask::Config* _cfg;
  DeregistrationTask* _task;

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
    SipTest::SetScscfUri("sip:all.the.sprout.nodes:5058;transport=TCP");
  }

  void SetUp()
  {
    _local_impi_store = new MockImpiStore();
    _remote_impi_store = new NiceMock<MockImpiStore>();
    _httpstack = new MockHttpStack();
    _subscriber_data_manager = new MockSubscriberDataManager();
    _hss = new FakeHSSConnection();
  }

  void TearDown()
  {
    delete _req;
    delete _cfg;
    delete _hss;
    delete _subscriber_data_manager;
    delete _httpstack;
    delete _local_impi_store; _local_impi_store = NULL;
    delete _remote_impi_store; _remote_impi_store = NULL;
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
     IFCConfiguration ifc_configuration(false, false, "", NULL, NULL);
     _cfg = new DeregistrationTask::Config(_subscriber_data_manager,
                                           {},
                                           _hss,
                                           NULL,
                                           ifc_configuration,
                                           NULL,
                                          _local_impi_store,
                                          {_remote_impi_store});
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
        EXPECT_CALL(*_subscriber_data_manager, set_aor_data(aor_ids[ii], _, _, _, _)).WillOnce(Return(Store::OK));
      }
    }
  }
};

// Mainline case
TEST_F(DeregistrationTaskTest, MainlineTest)
{
  // Set HSS result
  _hss->set_impu_result("sip:6505550231@homedomain", "", RegDataXMLUtils::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "    <Priority>1</Priority>\n"
                              "    <TriggerPoint>\n"
                              "      <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                              "      <SPT>\n"
                              "        <ConditionNegated>0</ConditionNegated>\n"
                              "        <Group>0</Group>\n"
                              "        <Method>REGISTER</Method>\n"
                              "        <Extension></Extension>\n"
                              "      </SPT>\n"
                              "    </TriggerPoint>\n"
                              "    <ApplicationServer>\n"
                              "      <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                              "      <DefaultHandling>1</DefaultHandling>\n"
                              "    </ApplicationServer>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>");

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

  // The IMPI is also deleted from the local and remote stores.
  ImpiStore::Impi* impi = new ImpiStore::Impi("6505550231");
  EXPECT_CALL(*_local_impi_store, get_impi("6505550231", _)).WillOnce(Return(impi));
  EXPECT_CALL(*_local_impi_store, delete_impi(impi, _)).WillOnce(Return(Store::OK));

  impi = new ImpiStore::Impi("6505550231");
  EXPECT_CALL(*_remote_impi_store, get_impi("6505550231", _)).WillOnce(Return(impi));
  EXPECT_CALL(*_remote_impi_store, delete_impi(impi, _)).WillOnce(Return(Store::OK));

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();

  _hss->flush_all();
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
  EXPECT_CALL(*_subscriber_data_manager, set_aor_data(_, _, _, _, _)).WillOnce(Return(Store::ERROR));

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
  EXPECT_CALL(*_local_impi_store, get_impi("impi1", _)).WillOnce(Return(impi));
  EXPECT_CALL(*_local_impi_store, delete_impi(impi, _)).WillOnce(Return(Store::OK));

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();
}

TEST_F(DeregistrationTaskTest, ClearMultipleImpis)
{
  // Set HSS result
  _hss->set_impu_result("sip:6505550231@homedomain", "", RegDataXMLUtils::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "    <Priority>1</Priority>\n"
                              "    <TriggerPoint>\n"
                              "      <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                              "      <SPT>\n"
                              "        <ConditionNegated>0</ConditionNegated>\n"
                              "        <Group>0</Group>\n"
                              "        <Method>REGISTER</Method>\n"
                              "        <Extension></Extension>\n"
                              "      </SPT>\n"
                              "    </TriggerPoint>\n"
                              "    <ApplicationServer>\n"
                              "      <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                              "      <DefaultHandling>1</DefaultHandling>\n"
                              "    </ApplicationServer>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>");
  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

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
  EXPECT_CALL(*_local_impi_store, get_impi("impi1", _)).WillOnce(Return(impi1));
  EXPECT_CALL(*_local_impi_store, delete_impi(impi1, _)).WillOnce(Return(Store::OK));
  EXPECT_CALL(*_local_impi_store, get_impi("impi2", _)).WillOnce(Return(impi2));
  EXPECT_CALL(*_local_impi_store, delete_impi(impi2, _)).WillOnce(Return(Store::OK));
  EXPECT_CALL(*_local_impi_store, get_impi("impi3", _)).WillOnce(Return(impi3));
  EXPECT_CALL(*_local_impi_store, delete_impi(impi3, _)).WillOnce(Return(Store::OK));

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();

  // Expect a 3rd-party deregister to be sent to the AS in the iFCs
  ASSERT_EQ(1, txdata_count());
  // REGISTER passed on to AS
  pjsip_msg* out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS.expect_target(current_txdata(), false);
  inject_msg(respond_to_current_txdata(200));
  free_txdata();

  _hss->flush_all();
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
  EXPECT_CALL(*_local_impi_store, get_impi("impi1", _)).WillOnce(Return(impi1));

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
  EXPECT_CALL(*_local_impi_store, get_impi("impi1", _)).WillOnce(Return(impi1));
  EXPECT_CALL(*_local_impi_store, delete_impi(impi1, _)).WillOnce(Return(Store::ERROR));

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
    EXPECT_CALL(*_local_impi_store, get_impi("impi1", _)).WillOnce(Return(impi1));
    EXPECT_CALL(*_local_impi_store, delete_impi(impi1, _)).WillOnce(Return(Store::DATA_CONTENTION));
    EXPECT_CALL(*_local_impi_store, get_impi("impi1", _)).WillOnce(Return(impi1a));
    EXPECT_CALL(*_local_impi_store, delete_impi(impi1a, _)).WillOnce(Return(Store::OK));
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

  void SetUp()
  {
    chronos_connection = new FakeChronosConnection();
    local_data_store = new LocalStore();
    store = new ImpiStore(local_data_store);
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

//
// Test reading sprout's bindings.
//

class GetBindingsTest : public TestWithMockSdms
{
};

// Test getting an IMPU that does not have any bindings.
TEST_F(GetBindingsTest, NoBindings)
{
  // Build request
  MockHttpStack::Request req(stack, "/impu/sip%3A6505550231%40homedomain/bindings", "");
  GetBindingsTask::Config config(store, {remote_store1});
  GetBindingsTask* task = new GetBindingsTask(req, &config, 0);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  SubscriberDataManager::AoRPair* aor =
    new SubscriberDataManager::AoRPair(new SubscriberDataManager::AoR(aor_id),
                                       new SubscriberDataManager::AoR(aor_id));
  SubscriberDataManager::AoRPair* remote_aor =
    new SubscriberDataManager::AoRPair(new SubscriberDataManager::AoR(aor_id),
                                       new SubscriberDataManager::AoR(aor_id));

  {
    InSequence s;
      // Neither store has any bindings so the backup store is checked.
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor));
      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _)).WillOnce(Return(remote_aor));

      // The handler returns a 404.
      EXPECT_CALL(*stack, send_reply(_, 404, _));
  }

  task->run();
}

// Test getting an IMPU with one binding.
TEST_F(GetBindingsTest, OneBinding)
{
  // Build request
  MockHttpStack::Request req(stack, "/impu/sip%3A6505550231%40homedomain/bindings", "");
  GetBindingsTask::Config config(store, {remote_store1});
  GetBindingsTask* task = new GetBindingsTask(req, &config, 0);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  SubscriberDataManager::AoRPair* aor = build_aor(aor_id);
  std::string id = aor->get_current()->bindings().begin()->first;
  std::string contact = aor->get_current()->bindings().begin()->second->_uri;

  {
    InSequence s;
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor));
      EXPECT_CALL(*stack, send_reply(_, 200, _));
  }

  task->run();

  // Check that the JSON document is correct.
  rapidjson::Document document;
  document.Parse(req.content().c_str());

  // The document should be of the form {"bindings":{...}}
  EXPECT_TRUE(document.IsObject());
  EXPECT_TRUE(document.HasMember("bindings"));
  EXPECT_TRUE(document["bindings"].IsObject());

  // Check there is only one  binding.
  EXPECT_EQ(1, document["bindings"].MemberCount());
  const rapidjson::Value& binding_id = document["bindings"].MemberBegin()->name;
  const rapidjson::Value& binding = document["bindings"].MemberBegin()->value;

  // Check the fields in the binding. Don't check every value. It makes the
  // test unnecessarily verbose.
  EXPECT_TRUE(binding.HasMember("uri"));
  EXPECT_TRUE(binding.HasMember("cid"));
  EXPECT_TRUE(binding.HasMember("cseq"));
  EXPECT_TRUE(binding.HasMember("expires"));
  EXPECT_TRUE(binding.HasMember("priority"));
  EXPECT_TRUE(binding.HasMember("params"));
  EXPECT_TRUE(binding.HasMember("paths"));
  EXPECT_TRUE(binding.HasMember("private_id"));
  EXPECT_TRUE(binding.HasMember("emergency_reg"));

  // Do check the binding ID and URI as a representative test.
  EXPECT_EQ(id, binding_id.GetString());
  EXPECT_EQ(contact, binding["uri"].GetString());
}

// Test getting an IMPU with one binding.
TEST_F(GetBindingsTest, TwoBindings)
{
  int now = time(NULL);

  // Build request
  MockHttpStack::Request req(stack, "/impu/sip%3A6505550231%40homedomain/bindings", "");
  GetBindingsTask::Config config(store, {remote_store1});
  GetBindingsTask* task = new GetBindingsTask(req, &config, 0);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  SubscriberDataManager::AoR* aor = new SubscriberDataManager::AoR(aor_id);
  build_binding(aor, now, "123");
  build_binding(aor, now, "456");
  SubscriberDataManager::AoR* aor2 = new SubscriberDataManager::AoR(*aor);
  SubscriberDataManager::AoRPair* aor_pair = new SubscriberDataManager::AoRPair(aor, aor2);

  {
    InSequence s;
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor_pair));
      EXPECT_CALL(*stack, send_reply(_, 200, _));
  }

  task->run();

  // Check that the JSON document has two bindings.
  rapidjson::Document document;
  document.Parse(req.content().c_str());
  EXPECT_EQ(2, document["bindings"].MemberCount());
  EXPECT_TRUE(document["bindings"].HasMember("123"));
  EXPECT_TRUE(document["bindings"].HasMember("456"));
}

// Test getting an IMPU when the local store is down.
TEST_F(GetBindingsTest, LocalStoreDown)
{
  // Build request
  MockHttpStack::Request req(stack, "/impu/sip%3A6505550231%40homedomain/bindings", "");
  GetBindingsTask::Config config(store, {remote_store1});
  GetBindingsTask* task = new GetBindingsTask(req, &config, 0);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  {
    InSequence s;
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(nullptr));
      EXPECT_CALL(*stack, send_reply(_, 500, _));
  }

  task->run();
}

// Test getting an IMPU with one binding.
TEST_F(GetBindingsTest, BadMethod)
{
  // Build request
  MockHttpStack::Request req(stack,
                             "/impu/sip%3A6505550231%40homedomain/bindings",
                             "",
                             "",
                             "",
                             htp_method_PUT);
  GetBindingsTask::Config config(store, {remote_store1});
  GetBindingsTask* task = new GetBindingsTask(req, &config, 0);

  EXPECT_CALL(*stack, send_reply(_, 405, _));
  task->run();
}

//
// Test fetching sprout's subscriptions.
//

class GetSubscriptionsTest : public TestWithMockSdms
{
};

// Test getting an IMPU that does not have any bindings.
TEST_F(GetSubscriptionsTest, NoSubscriptions)
{
  // Build request
  MockHttpStack::Request req(stack, "/impu/sip%3A6505550231%40homedomain/subscriptions", "");
  GetSubscriptionsTask::Config config(store, {remote_store1});
  GetSubscriptionsTask* task = new GetSubscriptionsTask(req, &config, 0);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  SubscriberDataManager::AoRPair* aor =
    new SubscriberDataManager::AoRPair(new SubscriberDataManager::AoR(aor_id),
                                       new SubscriberDataManager::AoR(aor_id));
  SubscriberDataManager::AoRPair* remote_aor =
    new SubscriberDataManager::AoRPair(new SubscriberDataManager::AoR(aor_id),
                                       new SubscriberDataManager::AoR(aor_id));

  {
    InSequence s;
      // Neither store has any bindings so the backup store is checked.
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor));
      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _)).WillOnce(Return(remote_aor));

      // The handler returns a 404.
      EXPECT_CALL(*stack, send_reply(_, 404, _));
  }

  task->run();
}

// Test getting an IMPU with one binding.
TEST_F(GetSubscriptionsTest, OneSubscription)
{
  // Build request
  MockHttpStack::Request req(stack, "/impu/sip%3A6505550231%40homedomain/subscriptions", "");
  GetSubscriptionsTask::Config config(store, {remote_store1});
  GetSubscriptionsTask* task = new GetSubscriptionsTask(req, &config, 0);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  SubscriberDataManager::AoRPair* aor = build_aor(aor_id);
  std::string id = aor->get_current()->subscriptions().begin()->first;
  std::string uri = aor->get_current()->subscriptions().begin()->second->_req_uri;

  {
    InSequence s;
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor));
      EXPECT_CALL(*stack, send_reply(_, 200, _));
  }

  task->run();

  // Check that the JSON document is correct.
  rapidjson::Document document;
  document.Parse(req.content().c_str());

  // The document should be of the form {"subscriptions":{...}}
  EXPECT_TRUE(document.IsObject());
  EXPECT_TRUE(document.HasMember("subscriptions"));
  EXPECT_TRUE(document["subscriptions"].IsObject());

  // Check there is only one subscription.
  EXPECT_EQ(1, document["subscriptions"].MemberCount());
  const rapidjson::Value& subscription_id = document["subscriptions"].MemberBegin()->name;
  const rapidjson::Value& subscription = document["subscriptions"].MemberBegin()->value;

  // Check the fields in the subscription. Don't check every value. It makes the
  // test unnecessarily verbose.
  EXPECT_TRUE(subscription.HasMember("req_uri"));
  EXPECT_TRUE(subscription.HasMember("from_uri"));
  EXPECT_TRUE(subscription.HasMember("from_tag"));
  EXPECT_TRUE(subscription.HasMember("to_uri"));
  EXPECT_TRUE(subscription.HasMember("to_tag"));
  EXPECT_TRUE(subscription.HasMember("cid"));
  EXPECT_TRUE(subscription.HasMember("routes"));
  EXPECT_TRUE(subscription.HasMember("expires"));

  // Do check the subscription ID and URI as a representative test.
  EXPECT_EQ(id, subscription_id.GetString());
  EXPECT_EQ(uri, subscription["req_uri"].GetString());
}

// Test getting an IMPU with two subscriptions.
TEST_F(GetSubscriptionsTest, TwoSubscriptions)
{
  int now = time(NULL);

  // Build request
  MockHttpStack::Request req(stack, "/impu/sip%3A6505550231%40homedomain/subscriptions", "");
  GetSubscriptionsTask::Config config(store, {remote_store1});
  GetSubscriptionsTask* task = new GetSubscriptionsTask(req, &config, 0);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  SubscriberDataManager::AoR* aor = new SubscriberDataManager::AoR(aor_id);
  build_binding(aor, now, "123");
  build_subscription(aor, now, "456");
  build_subscription(aor, now, "789");
  SubscriberDataManager::AoR* aor2 = new SubscriberDataManager::AoR(*aor);
  SubscriberDataManager::AoRPair* aor_pair = new SubscriberDataManager::AoRPair(aor, aor2);

  {
    InSequence s;
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor_pair));
      EXPECT_CALL(*stack, send_reply(_, 200, _));
  }

  task->run();

  // Check that the JSON document has two bindings.
  rapidjson::Document document;
  document.Parse(req.content().c_str());
  EXPECT_EQ(2, document["subscriptions"].MemberCount());
  EXPECT_TRUE(document["subscriptions"].HasMember("456"));
  EXPECT_TRUE(document["subscriptions"].HasMember("789"));
}

// Test getting an IMPU when the local store is down.
TEST_F(GetSubscriptionsTest, LocalStoreDown)
{
  // Build request
  MockHttpStack::Request req(stack, "/impu/sip%3A6505550231%40homedomain/subscriptions", "");
  GetSubscriptionsTask::Config config(store, {remote_store1});
  GetSubscriptionsTask* task = new GetSubscriptionsTask(req, &config, 0);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  {
    InSequence s;
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(nullptr));
      EXPECT_CALL(*stack, send_reply(_, 500, _));
  }

  task->run();
}

// Test getting an IMPU with one binding.
TEST_F(GetSubscriptionsTest, BadMethod)
{
  // Build request
  MockHttpStack::Request req(stack,
                             "/impu/sip%3A6505550231%40homedomain/subscriptions",
                             "",
                             "",
                             "",
                             htp_method_PUT);
  GetSubscriptionsTask::Config config(store, {remote_store1});
  GetSubscriptionsTask* task = new GetSubscriptionsTask(req, &config, 0);

  EXPECT_CALL(*stack, send_reply(_, 405, _));
  task->run();
}

//
// Tests for deleting sprout's cached data.
//

class DeleteImpuTaskTest : public TestWithMockSdms
{
  MockHttpStack::Request* req;
  DeleteImpuTask::Config* cfg;
  DeleteImpuTask* task;

  static void SetUpTestCase()
  {
    TestWithMockSdms::SetUpTestCase();
    TestWithMockSdms::SetScscfUri("sip:all.the.sprout.nodes:5058;transport=TCP");
  }

  void SetUp()
  {
    TestWithMockSdms::SetUp();
  }

  void TearDown()
  {
    delete req;
    delete cfg;
    TestWithMockSdms::TearDown();
  }

  // Build the deregistration request
  void build_task(const std::string& impu,
                  htp_method method = htp_method_DELETE,
                  bool configure_remote_store = false)
  {
    req = new MockHttpStack::Request(stack,
                                     "/impu/" + impu,
                                     "",
                                     "",
                                     "",
                                     method);
    std::vector<SubscriberDataManager*> remote_stores;
    if (configure_remote_store)
    {
      remote_stores.push_back(remote_store1);
    }

    IFCConfiguration ifc_configuration(false, false, "", NULL, NULL);
    cfg = new DeleteImpuTask::Config(store, remote_stores, mock_hss, NULL, ifc_configuration);
    task = new DeleteImpuTask(*req, cfg, 0);
  }
};

MATCHER(EmptyAoR, "")
{
  return !arg->current_contains_bindings();
}

TEST_F(DeleteImpuTaskTest, Mainline)
{
  std::string impu = "sip:6505550231@homedomain";
  std::string impu_escaped =  "sip%3A6505550231%40homedomain";

  SubscriberDataManager::AoRPair* aor = build_aor(impu, false);
  build_task(impu_escaped);

  {
    InSequence s;
      // Neither store has any bindings so the backup store is checked.
      EXPECT_CALL(*store, get_aor_data(impu, _)).WillOnce(Return(aor));
      EXPECT_CALL(*store, set_aor_data(impu, _, EmptyAoR(), _, _))
        .WillOnce(DoAll(SetArgReferee<4>(true), // All bindings are expired.
                        Return(Store::OK)));
      EXPECT_CALL(*mock_hss, update_registration_state(impu, _, "dereg-admin", "sip:scscf.sprout.homedomain:5058;transport=TCP", _, _, _))
        .WillOnce(Return(200));
      EXPECT_CALL(*stack, send_reply(_, 200, _));
  }

  task->run();
}

TEST_F(DeleteImpuTaskTest, StoreFailure)
{
  std::string impu = "sip:6505550231@homedomain";
  std::string impu_escaped =  "sip%3A6505550231%40homedomain";

  SubscriberDataManager::AoRPair* aor = build_aor(impu, true);
  build_task(impu_escaped);

  {
    InSequence s;
      // Neither store has any bindings so the backup store is checked.
      EXPECT_CALL(*store, get_aor_data(impu, _)).WillOnce(Return(aor));
      EXPECT_CALL(*store, set_aor_data(impu, _, _, _, _))
        .WillOnce(DoAll(SetArgReferee<4>(false), // Fail to expire bindings.
                        Return(Store::ERROR)));
      EXPECT_CALL(*stack, send_reply(_, 500, _));
  }

  task->run();
}

TEST_F(DeleteImpuTaskTest, HomesteadFailsWith404)
{
  std::string impu = "sip:6505550231@homedomain";
  std::string impu_escaped =  "sip%3A6505550231%40homedomain";

  SubscriberDataManager::AoRPair* aor = build_aor(impu, true);
  build_task(impu_escaped);

  {
    InSequence s;
      // Neither store has any bindings so the backup store is checked.
      EXPECT_CALL(*store, get_aor_data(impu, _)).WillOnce(Return(aor));
      EXPECT_CALL(*store, set_aor_data(impu, _, _, _, _))
        .WillOnce(DoAll(SetArgReferee<4>(true), // All bindings expired
                        Return(Store::OK)));
      EXPECT_CALL(*mock_hss, update_registration_state(impu, _, _, "sip:scscf.sprout.homedomain:5058;transport=TCP", _, _, _))
        .WillOnce(Return(404));
      EXPECT_CALL(*stack, send_reply(_, 404, _));
  }

  task->run();
}

TEST_F(DeleteImpuTaskTest, HomesteadFailsWith5xx)
{
  std::string impu = "sip:6505550231@homedomain";
  std::string impu_escaped =  "sip%3A6505550231%40homedomain";

  SubscriberDataManager::AoRPair* aor = build_aor(impu, true);
  build_task(impu_escaped);

  {
    InSequence s;
      // Neither store has any bindings so the backup store is checked.
      EXPECT_CALL(*store, get_aor_data(impu, _)).WillOnce(Return(aor));
      EXPECT_CALL(*store, set_aor_data(impu, _, _, _, _))
        .WillOnce(DoAll(SetArgReferee<4>(true), // All bindings expired
                        Return(Store::OK)));
      EXPECT_CALL(*mock_hss, update_registration_state(impu, _, _, "sip:scscf.sprout.homedomain:5058;transport=TCP", _, _, _))
        .WillOnce(Return(500));
      EXPECT_CALL(*stack, send_reply(_, 502, _));
  }

  task->run();
}

TEST_F(DeleteImpuTaskTest, HomesteadFailsWith4xx)
{
  std::string impu = "sip:6505550231@homedomain";
  std::string impu_escaped =  "sip%3A6505550231%40homedomain";

  SubscriberDataManager::AoRPair* aor = build_aor(impu, true);
  build_task(impu_escaped);

  {
    InSequence s;
      // Neither store has any bindings so the backup store is checked.
      EXPECT_CALL(*store, get_aor_data(impu, _)).WillOnce(Return(aor));
      EXPECT_CALL(*store, set_aor_data(impu, _, _, _, _))
        .WillOnce(DoAll(SetArgReferee<4>(true), // All bindings expired
                        Return(Store::OK)));
      EXPECT_CALL(*mock_hss, update_registration_state(impu, _, _, "sip:scscf.sprout.homedomain:5058;transport=TCP", _, _, _))
        .WillOnce(Return(400));
      EXPECT_CALL(*stack, send_reply(_, 400, _));
  }

  task->run();
}

TEST_F(DeleteImpuTaskTest, WritingToRemoteStores)
{
  std::string impu = "sip:6505550231@homedomain";
  std::string impu_escaped =  "sip%3A6505550231%40homedomain";

  SubscriberDataManager::AoRPair* aor = build_aor(impu);
  SubscriberDataManager::AoRPair* remote_aor = build_aor(impu);
  build_task(impu_escaped, htp_method_DELETE, true);

  {
    InSequence s;
      // Neither store has any bindings so the backup store is checked.
      EXPECT_CALL(*store, get_aor_data(impu, _)).WillOnce(Return(aor));
      EXPECT_CALL(*store, set_aor_data(impu, _, EmptyAoR(), _, _))
        .WillOnce(DoAll(SetArgReferee<4>(true), // All bindings expired
                        Return(Store::OK)));
      EXPECT_CALL(*mock_hss, update_registration_state(impu, _, _, "sip:scscf.sprout.homedomain:5058;transport=TCP", _, _, _))
        .WillOnce(Return(200));

      EXPECT_CALL(*remote_store1, get_aor_data(impu, _)).WillOnce(Return(remote_aor));
      EXPECT_CALL(*remote_store1, set_aor_data(impu, _, EmptyAoR(), _, _))
        .WillOnce(DoAll(SetArgReferee<4>(true), // All bindings expired
                        Return(Store::OK)));

      EXPECT_CALL(*stack, send_reply(_, 200, _));
  }

  task->run();
}

TEST_F(DeleteImpuTaskTest, BadMethod)
{
  std::string impu = "sip:6505550231@homedomain";
  std::string impu_escaped =  "sip%3A6505550231%40homedomain";

  build_task(impu_escaped, htp_method_PUT);
  EXPECT_CALL(*stack, send_reply(_, 405, _));

  task->run();
}

class PushProfileTaskTest : public SipTest
{
  MockSubscriberDataManager* _subscriber_data_manager;
  MockHttpStack* _httpstack;
  FakeHSSConnection* _hss;
  MockHttpStack::Request* _req;
  PushProfileTask::Config* _cfg;
  PushProfileTask* _task;

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
    SipTest::SetScscfUri("sip:all.the.sprout.nodes:5058;transport=TCP");
  }

  void SetUp()
  {
    _httpstack = new MockHttpStack();
    _subscriber_data_manager = new MockSubscriberDataManager();
    _hss = new FakeHSSConnection();
  }

  void TearDown()
  {
    delete _req;
    delete _cfg;
    delete _hss;
    delete _subscriber_data_manager;
    delete _httpstack;
  }

  void build_pushprofile_request(std::string body,
				 std::string default_uri,
                                 htp_method method = htp_method_POST)
  {
    _req = new MockHttpStack::Request(_httpstack,
         "/registrations/" + default_uri,
         "",
         "",
         body,
         method);
     _cfg = new PushProfileTask::Config(_subscriber_data_manager,
                                        {},
                                        _hss);
    _task = new PushProfileTask(*_req, _cfg, 0);
  }
};

// Mainline Case
TEST_F(PushProfileTaskTest, MainlineTest)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string body =          "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                              "  <PublicIdentity><Identity>sip:6505550232@homedomain</Identity><BarringIndicator>1</BarringIndicator></PublicIdentity>\n"
			      "  <PublicIdentity><Identity>sip:6505550233@homedomain</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "    <Priority>1</Priority>\n"
                              "    <TriggerPoint>\n"
                              "      <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                              "      <SPT>\n"
                              "        <ConditionNegated>0</ConditionNegated>\n"
                              "        <Group>0</Group>\n"
                              "        <Method>REGISTER</Method>\n"
                              "        <Extension></Extension>\n"
                              "      </SPT>\n"
                              "    </TriggerPoint>\n"
                              "    <ApplicationServer>\n"
                              "      <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                              "      <DefaultHandling>1</DefaultHandling>\n"
                              "    </ApplicationServer>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>";
  SubscriberDataManager::AoR* aor = new SubscriberDataManager::AoR(default_uri);
  SubscriberDataManager::AoR* aor2 = new SubscriberDataManager::AoR(*aor);
  SubscriberDataManager::AoRPair* aor_pair = new SubscriberDataManager::AoRPair(aor, aor2);
  build_pushprofile_request(body, default_uri);

  EXPECT_CALL(*_subscriber_data_manager, get_aor_data(default_uri, _)).WillOnce(Return(aor_pair));
  EXPECT_CALL(*_subscriber_data_manager, set_aor_data(default_uri, _, aor_pair, _, _)).WillOnce(Return(Store::OK));

  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();
}

// The XML is not valid and therefore not able to be parsed. Sends HTTP_BAD_REQUEST.
TEST_F(PushProfileTaskTest, InvalidMethod)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string body =          "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                              "  <<\n"
                              "</ServiceProfile></IMSSubscription>";
  build_pushprofile_request(body, default_uri, htp_method_GET);

  EXPECT_CALL(*_httpstack, send_reply(_, 405, _));
  _task->run();
}

// The XML is not valid and therefore not able to be parsed. Sends HTTP_BAD_REQUEST.
TEST_F(PushProfileTaskTest, InvalidXML)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string body =          "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
  			      "  <<\n"
                              "</ServiceProfile></IMSSubscription>";
  build_pushprofile_request(body, default_uri);

  EXPECT_CALL(*_httpstack, send_reply(_, 400, _));
  _task->run();
}

// The XML does not contain the relevant Public Identities. Sends HTTP_BAD_REQUEST.
TEST_F(PushProfileTaskTest, MissingPublicIdentityXML)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string body =          "<IMSSubscription><ServiceProfile>\n"
                              "</ServiceProfile></IMSSubscription>";
  build_pushprofile_request(body, default_uri);

  EXPECT_CALL(*_httpstack, send_reply(_, 400, _));
  _task->run();
}

// get_aor_data returns a NULL pointer. Sends HTTP_SERVER_ERROR
TEST_F(PushProfileTaskTest, SubscriberDataManagerFails)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string body =          "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                              "</ServiceProfile></IMSSubscription>";
  SubscriberDataManager::AoRPair* aor_pair;
  aor_pair = NULL;
  build_pushprofile_request(body, default_uri);

  EXPECT_CALL(*_subscriber_data_manager, get_aor_data(default_uri, _)).WillOnce(Return(aor_pair));

  EXPECT_CALL(*_httpstack, send_reply(_, 500, _));
  _task->run();
}

// set_aor_data fails. Sends HTTP_SERVER_ERROR
TEST_F(PushProfileTaskTest, SubscriberDataManagerWriteFails)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string body =          "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                              "</ServiceProfile></IMSSubscription>";
  SubscriberDataManager::AoR* aor = new SubscriberDataManager::AoR(default_uri);
  SubscriberDataManager::AoR* aor2 = new SubscriberDataManager::AoR(*aor);
  SubscriberDataManager::AoRPair* aor_pair = new SubscriberDataManager::AoRPair(aor, aor2);
  build_pushprofile_request(body, default_uri);

  EXPECT_CALL(*_subscriber_data_manager, get_aor_data(default_uri, _)).WillOnce(Return(aor_pair));
  EXPECT_CALL(*_subscriber_data_manager, set_aor_data(default_uri, _, aor_pair, _, _)).WillOnce(Return(Store::ERROR));

  EXPECT_CALL(*_httpstack, send_reply(_, 500, _));
  _task->run();
}


