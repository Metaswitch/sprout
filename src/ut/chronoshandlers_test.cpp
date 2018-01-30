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
    IFCConfiguration ifc_configuration(false, false, "", NULL, NULL);
    req = new MockHttpStack::Request(stack, "/", "timers", "", body, method);
    config = new AoRTimeoutTask::Config(store, 
                                        {remote_store1, remote_store2}, 
                                        mock_hss, 
                                        NULL, 
                                        ifc_configuration);
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

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  AoRPair* aor = build_aor(aor_id);
  AoRPair* remote_aor1 = build_aor(aor_id);
  AoRPair* remote_aor2 = build_aor(aor_id);

  // Set up IRS IMPU list to be returned by the mocked get_registration_data call.
  // Add a bunch of random IMPUs to this list - they should all be passed to set_aor_data.
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri("tel:6505550232", false);
  associated_uris.add_uri(aor_id, false);
  associated_uris.add_uri("sip:another_user@another_domain.com", false);

  HSSConnection::irs_info irs_info;
  irs_info._associated_uris = associated_uris;

  {
    InSequence s;
      EXPECT_CALL(*stack, send_reply(_, 200, _));
      EXPECT_CALL(*mock_hss, get_registration_data(_, _, _))
           .WillOnce(DoAll(SetArgReferee<1>(irs_info), //IMPUs in IRS
                           Return(HTTP_OK)));
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor));
      EXPECT_CALL(*store, set_aor_data(aor_id, SubscriberDataManager::EventTrigger::TIMEOUT, aor, _, _)).WillOnce(Return(Store::OK));

      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _)).WillOnce(Return(remote_aor1));
      EXPECT_CALL(*remote_store1, set_aor_data(aor_id, _, remote_aor1, _, _)).WillOnce(Return(Store::OK));

      EXPECT_CALL(*remote_store2, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store2, get_aor_data(aor_id, _)).WillOnce(Return(remote_aor2));
      EXPECT_CALL(*remote_store2, set_aor_data(aor_id, _, remote_aor2, _, _)).WillOnce(Return(Store::OK));
  }

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

// Test with a remote AoR with no bindings
TEST_F(ChronosAoRTimeoutTasksTest, RemoteAoRNoBindingsTest)
{
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\"}";
  build_timeout_request(body, htp_method_POST);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  AoRPair* aor = build_aor(aor_id);

  // Set up AoRs with no bindings for both remote stores.
  AoR* remote1_aor1 = new AoR(aor_id);
  AoR* remote1_aor2 = new AoR(*remote1_aor1);
  AoRPair* remote1_aor_pair = new AoRPair(remote1_aor1, remote1_aor2);
  AoR* remote2_aor1 = new AoR(aor_id);
  AoR* remote2_aor2 = new AoR(*remote2_aor1);
  AoRPair* remote2_aor_pair = new AoRPair(remote2_aor1, remote2_aor2);

  // Set up IRS IMPU list to be returned by the mocked get_registration_data calls
  // We'll return an empty list from the mocked get_registration_data.  We should still
  // see our AoR in the irs_impus list passed to set_aor_data.
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri(aor_id, false);

  {
    InSequence s;
      EXPECT_CALL(*stack, send_reply(_, 200, _));
      EXPECT_CALL(*mock_hss, get_registration_data(_, _, _)).WillOnce(Return(HTTP_OK));
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor));
      EXPECT_CALL(*store, set_aor_data(aor_id, _, aor, _, _)).WillOnce(Return(Store::OK));

      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _)).WillOnce(Return(remote1_aor_pair));
      EXPECT_CALL(*remote_store1, set_aor_data(aor_id, _, remote1_aor_pair, _, _)).WillOnce(Return(Store::OK));

      EXPECT_CALL(*remote_store2, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store2, get_aor_data(aor_id, _)).WillOnce(Return(remote2_aor_pair));
      EXPECT_CALL(*remote_store2, set_aor_data(aor_id, _, remote2_aor_pair, _, _)).WillOnce(Return(Store::OK));
  }

  handler->run();
}

// Test with a remote store, and a local AoR with no bindings
TEST_F(ChronosAoRTimeoutTasksTest, LocalAoRNoBindingsTest)
{
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\"}";
  build_timeout_request(body, htp_method_POST);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  // Set up local AoR with no bindings
  AoR* aor = new AoR(aor_id);
  AoR* aor2 = new AoR(*aor);
  AoRPair* aor_pair = new AoRPair(aor, aor2);

  AoRPair* remote1_aor1 = build_aor(aor_id);

  // Set up the remote AoR again, to avoid problem of test process deleting
  // the data of the first one. This is only a problem in the tests, as real
  // use would correctly set the data to the store before deleting the local copy
  AoRPair* remote1_aor2 = build_aor(aor_id);
  AoRPair* remote2_aor = build_aor(aor_id);

  // Set up IRS IMPU list to be returned by the mocked get_registration_data call
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri(aor_id, false);

  HSSConnection::irs_info irs_info;
  irs_info._associated_uris = associated_uris;

  {
    InSequence s;
      EXPECT_CALL(*stack, send_reply(_, 200, _));
      EXPECT_CALL(*mock_hss, get_registration_data(_, _, _))
           .WillOnce(DoAll(SetArgReferee<1>(irs_info), //IMPUs in IRS
                           Return(HTTP_OK)));
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor_pair));
      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _)).WillOnce(Return(remote1_aor1));
      EXPECT_CALL(*store, set_aor_data(aor_id, _, aor_pair, _, _)).WillOnce(Return(Store::OK));

      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _)).WillOnce(Return(remote1_aor2));
      EXPECT_CALL(*remote_store1, set_aor_data(aor_id, _, remote1_aor2, _, _)).WillOnce(Return(Store::OK));

      EXPECT_CALL(*remote_store2, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store2, get_aor_data(aor_id, _)).WillOnce(Return(remote2_aor));
      EXPECT_CALL(*remote_store2, set_aor_data(aor_id, _, remote2_aor, _, _)).WillOnce(Return(Store::OK));
  }

  handler->run();
}

// Test with a remote store, and both AoRs with no bindings
TEST_F(ChronosAoRTimeoutTasksTest, NoBindingsTest)
{
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\"}";

  build_timeout_request(body, htp_method_POST);
  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  // Set up AoRs with no bindings
  AoR* aor1 = new AoR(aor_id);
  aor1->_scscf_uri = "sip:scscf.sprout.homedomain:5058;transport=TCP";
  AoR* aor2 = new AoR(*aor1);
  AoRPair* aor_pair = new AoRPair(aor1, aor2);

  AoR* remote1_aor1 = new AoR(aor_id);
  AoR* remote1_aor2 = new AoR(*remote1_aor1);
  AoRPair* remote1_aor_pair1 = new AoRPair(remote1_aor1, remote1_aor2);
  AoR* remote2_aor1 = new AoR(aor_id);
  AoR* remote2_aor2 = new AoR(*remote2_aor1);
  AoRPair* remote2_aor_pair1 = new AoRPair(remote2_aor1, remote2_aor2);

  // Set up the remote AoRs again, to avoid problem of test process deleting
  // the data of the first one. This is only a problem in the tests, as real
  // use would correctly set the data to the store before deleting the local copy
  AoR* remote1_aor3 = new AoR(aor_id);
  AoR* remote1_aor4 = new AoR(*remote1_aor3);
  AoRPair* remote1_aor_pair2 = new AoRPair(remote1_aor3, remote1_aor4);
  AoR* remote2_aor3 = new AoR(aor_id);
  AoR* remote2_aor4 = new AoR(*remote2_aor3);
  AoRPair* remote2_aor_pair2 = new AoRPair(remote2_aor3, remote2_aor4);

  // Set up IRS IMPU list to be returned by the mocked get_registration_data call
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri(aor_id, false);

  HSSConnection::irs_query irs_query;
  HSSConnection::irs_info irs_info;
  irs_info._associated_uris = associated_uris;

  {
    InSequence s;
      EXPECT_CALL(*stack, send_reply(_, 200, _));
      EXPECT_CALL(*mock_hss, get_registration_data(_, _, _))
           .WillOnce(DoAll(SetArgReferee<1>(irs_info), //IMPUs in IRS
                           Return(HTTP_OK)));
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor_pair));
      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _))
        .WillOnce(Return(remote1_aor_pair1));
      EXPECT_CALL(*remote_store2, has_servers())
        .WillOnce(Return(true));
      EXPECT_CALL(*remote_store2, get_aor_data(aor_id, _))
        .WillOnce(Return(remote2_aor_pair1));
      EXPECT_CALL(*store, set_aor_data(aor_id, _, aor_pair, _, _))
        .WillOnce(DoAll(SetArgReferee<4>(true),
                        Return(Store::OK)));

      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _))
        .WillOnce(Return(remote1_aor_pair2));
      EXPECT_CALL(*remote_store1, set_aor_data(aor_id, _, remote1_aor_pair2, _, _))
                  .WillOnce(DoAll(SetArgReferee<4>(true),
                                  Return(Store::OK)));

      EXPECT_CALL(*remote_store2, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store2, get_aor_data(aor_id, _))
        .WillOnce(Return(remote2_aor_pair2));
      EXPECT_CALL(*remote_store2, set_aor_data(aor_id, _, remote2_aor_pair2, _, _))
        .WillOnce(DoAll(SetArgReferee<4>(true),
                        Return(Store::OK)));

      EXPECT_CALL(*mock_hss, update_registration_state(_, _, _))
        .WillOnce(DoAll(SaveArg<0>(&irs_query),
                        Return(200)));
  }

  handler->run();

  ASSERT_EQ(irs_query._public_id, aor_id);
  ASSERT_EQ(irs_query._req_type, HSSConnection::DEREG_TIMEOUT);
  ASSERT_EQ(irs_query._server_name, "sip:scscf.sprout.homedomain:5058;transport=TCP");

}

// Test with NULL AoRs
TEST_F(ChronosAoRTimeoutTasksTest, NullAoRTest)
{
  CapturingTestLogger log(5);

  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\"}";
  build_timeout_request(body, htp_method_POST);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  AoR* aor = NULL;
  AoRPair* aor_pair = new AoRPair(aor, aor);
  AoRPair* remote1_aor_pair = new AoRPair(aor, aor);
  AoRPair* remote2_aor_pair = new AoRPair(aor, aor);

  // Set up IRS IMPU list to be returned by the mocked get_registration_data call
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri(aor_id, false);

  HSSConnection::irs_info irs_info;
  irs_info._associated_uris = associated_uris;

  {
    InSequence s;
      EXPECT_CALL(*stack, send_reply(_, 200, _));
      EXPECT_CALL(*mock_hss, get_registration_data(_, _, _))
           .WillOnce(DoAll(SetArgReferee<1>(irs_info), //IMPUs in IRS
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

class ChronosAoRTimeoutTasksMockStoreTest : public SipTest
{
  MockSubscriberDataManager* store;
  FakeHSSConnection* fake_hss;

  MockHttpStack stack;
  MockHttpStack::Request* req;
  AoRTimeoutTask::Config* config;

  ChronosAoRTimeoutTask* handler;

  void SetUp()
  {
    IFCConfiguration ifc_configuration(false, false, "", NULL, NULL);
    store = new MockSubscriberDataManager();
    fake_hss = new FakeHSSConnection();
    req = new MockHttpStack::Request(&stack, "/", "timers");
    config = new AoRTimeoutTask::Config(store, {}, fake_hss, NULL, ifc_configuration);
    handler = new ChronosAoRTimeoutTask(*req, config, 0);
  }

  void TearDown()
  {
    delete handler;
    delete config;
    delete req;
    delete fake_hss;
    delete store; store = NULL;
  }

};

// Test that deregister is sent to AS when all bindings expired
TEST_F(ChronosAoRTimeoutTasksMockStoreTest, DeregisterAS)
{
  AoR* aor = new AoR("sip:6505550231@homedomain");
  AoR* aor2 = new AoR(*aor);
  AoRPair* aor_pair = new AoRPair(aor, aor2);

  // Set up IRS IMPU list to be returned by the mocked get_registration_data call
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri("sip:6505550231@homedomain", false);

  // Set all bindings expired to true, this should trigger a deregister with AS
  EXPECT_CALL(*store, get_aor_data(_, _)).WillOnce(Return(aor_pair));
  EXPECT_CALL(*store, set_aor_data(_, _, _, _, _))
    .WillOnce(DoAll(SetArgReferee<4>(true),
                    Return(Store::OK)));

  fake_hss->set_impu_result("sip:6505550231@homedomain",
                             "dereg-timeout",
                             RegDataXMLUtils::STATE_REGISTERED,
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

  // Parse and handle the request
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\"}";
  int status = handler->parse_response(body);

  ASSERT_EQ(status, 200);

  handler->handle_response();

  // Expect a 3rd-party deregister to be sent to the AS in the iFCs
  ASSERT_EQ(1, txdata_count());
  // REGISTER passed on to AS
  pjsip_msg* out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  EXPECT_THAT(r1.uri(), testing::MatchesRegex(".*sip:1.2.3.4:56789.*"));

  inject_msg(respond_to_current_txdata(200));
  free_txdata();
}

TEST_F(ChronosAoRTimeoutTasksMockStoreTest, SubscriberDataManagerWritesFail)
{
  // Set up the SubscriberDataManager to fail all sets and respond to all gets with not
  // found.
  AoR* aor = new AoR("sip:6505550231@homedomain");
  AoR* aor2 = new AoR(*aor);
  AoRPair* aor_pair = new AoRPair(aor, aor2);

  // Set up IRS IMPU list to be returned by the mocked get_registration_data call
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri("sip:6505550231@homedomain", false);

  EXPECT_CALL(*store, get_aor_data(_, _)).WillOnce(Return(aor_pair));
  EXPECT_CALL(*store, set_aor_data(_, _, _, _, _)).WillOnce(Return(Store::ERROR));

  // Parse and handle the request
  std::string body = "{\"aor_id\": \"sip:6505550231@homedomain\"}";
  int status = handler->parse_response(body);

  ASSERT_EQ(status, 200);

  handler->handle_response();
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
