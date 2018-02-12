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
#include "mock_impi_store.h"
#include "mock_hss_connection.h"
#include "rapidjson/document.h"
#include "handlers_test.h"
#include "aor_test_utils.h"

using namespace std;
using ::testing::_;
using ::testing::Return;
using ::testing::InSequence;
using ::testing::SetArgReferee;
using ::testing::SaveArg;

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

class DeregistrationTaskTest : public SipTest
{
  MockSubscriberManager* _subscriber_manager;
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
    _remote_impi_store = new MockImpiStore();
    _httpstack = new MockHttpStack();
    _subscriber_manager = new MockSubscriberManager();
    _hss = new FakeHSSConnection();
  }

  void TearDown()
  {
    delete _req;
    delete _cfg;
    delete _hss;
    delete _subscriber_manager;
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
     _cfg = new DeregistrationTask::Config(_subscriber_manager,
                                           NULL,
                                          _local_impi_store,
                                          {_remote_impi_store});
    _task = new DeregistrationTask(*_req, _cfg, 0);
  }

  void expect_sm_updates(const std::string& aor_id,
                         Bindings bindings,
                         std::vector<std::string>& binding_ids)
  {
    EXPECT_CALL(*_subscriber_manager, get_bindings(aor_id, _, _))
      .WillOnce(DoAll(SetArgReferee<1>(bindings), Return(HTTP_OK)));

    EXPECT_CALL(*_subscriber_manager,
                remove_bindings(aor_id, _, SubscriberDataUtils::EventTrigger::HSS, _, _))
          .WillOnce(DoAll(SaveArg<1>(&binding_ids), Return(HTTP_OK)));
  }

  void expect_impi_deletes(std::string private_id, MockImpiStore* impi_store)
  {
    ImpiStore::Impi* impi = new ImpiStore::Impi(private_id);
    EXPECT_CALL(*impi_store, get_impi(private_id, _, false)).WillOnce(Return(impi));
    EXPECT_CALL(*impi_store, delete_impi(impi, _)).WillOnce(Return(Store::OK));
  }

  void expect_gr_impi_deletes(std::string private_id)
  {
    expect_impi_deletes(private_id, _local_impi_store);
    expect_impi_deletes(private_id, _remote_impi_store);
  }
};

// Mainline case
TEST_F(DeregistrationTaskTest, MainlineTest)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\", \"impi\": \"6505550231\"}]}";
  build_dereg_request(body);

  // Set up the subscriber_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  std::string binding_id = "sip:6505550231@homedomain;tcp";
  std::string private_id = "6505550231";

  Binding binding(aor_id);
  binding._uri = binding_id;
  binding._private_id = private_id;
  Bindings bindings;
  bindings[binding_id] = &binding;
  std::vector<std::string> binding_ids;

  expect_sm_updates(aor_id, bindings, binding_ids);

  // The IMPI is also deleted from the local and remote stores.
  expect_gr_impi_deletes(private_id);

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();

  // Check the right binding was being deregistered
  ASSERT_EQ(1u, binding_ids.size());
  EXPECT_EQ(binding_ids[0], binding_id);
}

// Test that a dereg request that isn't an HTTP delete gets rejected.
TEST_F(DeregistrationTaskTest, InvalidMethodTest)
{
  build_dereg_request("", "", htp_method_GET);
  EXPECT_CALL(*_httpstack, send_reply(_, 405, _));
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

// Error case for failing to get bindings from subscriber manager.
TEST_F(DeregistrationTaskTest, SubscriberManagerAccessFail)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505552001@homedomain\"}]}";
  build_dereg_request(body, "false");

  // get_bindings comes back with an error, remove_bindings won't get called
  std::string aor_id = "sip:6505552001@homedomain";
  EXPECT_CALL(*_subscriber_manager,
              get_bindings(aor_id, _, _))
    .WillOnce(Return(HTTP_SERVER_ERROR));

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 500, _));
  _task->run();
}

// Error case for failing to write updated bindings back to subscriber manager.
TEST_F(DeregistrationTaskTest, SubscriberManagerWritesFail)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\", \"impi\": \"6505550231\"}]}";
  build_dereg_request(body);

  // Set up the subscriber_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  std::string private_id = "sip:6505550231";
  Binding binding(aor_id);
  binding._private_id = private_id;

  Bindings bindings;
  bindings[""] = &binding;
  EXPECT_CALL(*_subscriber_manager,
              get_bindings(aor_id, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(bindings),
                    Return(HTTP_OK)));

  EXPECT_CALL(*_subscriber_manager,
              remove_bindings(aor_id, _, SubscriberDataUtils::EventTrigger::HSS, _, _))
    .WillOnce(Return(HTTP_NOT_FOUND));

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 404, _));
  _task->run();
}

// Test deregistering all bindings for an IMPU regardless of IMPI.
TEST_F(DeregistrationTaskTest, ImpiClearedWhenBindingUnconditionallyDeregistered)
{
  // Build a request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\"}]}";
  build_dereg_request(body);

  // Set up the subscriber_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  Binding binding(aor_id);
  binding._private_id = "impi1";
  Bindings bindings;
  bindings[""] = &binding;
  std::vector<std::string> binding_ids;

  expect_sm_updates(aor_id, bindings, binding_ids);

  // The corresponding IMPI is also deleted.
  expect_gr_impi_deletes("impi1");

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();

  // Check the right binding was being deregistered
  ASSERT_EQ(1u, binding_ids.size());
  EXPECT_EQ(binding_ids[0], "");
}

// Test deregistering several IMPIs from different AoR in one request.
TEST_F(DeregistrationTaskTest, ClearMultipleImpis)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\"}, {\"primary-impu\": \"sip:6505550232@homedomain\"}]}";
  build_dereg_request(body);

  // Create an AoR with two bindings.
  std::string aor_id = "sip:6505550231@homedomain";

  Binding binding(aor_id);
  binding._uri = "binding_id";
  binding._private_id = "impi1";
  Binding binding2(aor_id);
  binding2._uri = "binding_id2";
  binding2._private_id = "impi2";
  Bindings bindings;
  bindings["binding_id"] = &binding;
  bindings["binding_id2"] = &binding2;

  // Set up corresponding subscriber_manager expectations
  std::vector<std::string> binding_ids;
  expect_sm_updates(aor_id, bindings, binding_ids);

  // create another AoR with one binding.
  std::string aor_id2 = "sip:6505550232@homedomain";
  Binding binding3(aor_id2);
  binding3._uri = "binding_id3";
  binding3._private_id = "impi3";
  Bindings bindings2;
  bindings2["binding_id3"] = &binding3;

  // Set up corresponding subscriber_manager expectations
  std::vector<std::string> binding_ids_2;
  expect_sm_updates(aor_id2, bindings2, binding_ids_2);

  // The corresponding IMPIs are also deleted.
  expect_gr_impi_deletes("impi1");
  expect_gr_impi_deletes("impi2");
  expect_gr_impi_deletes("impi3");

  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));

  // Run the task
  _task->run();

  // Check the right binding was being deregistered
  ASSERT_EQ(2u, binding_ids.size());
  ASSERT_EQ(1u, binding_ids_2.size());
  EXPECT_EQ(binding_ids[0], "binding_id");
  EXPECT_EQ(binding_ids[1], "binding_id2");
  EXPECT_EQ(binding_ids_2[0], "binding_id3");
}

// Test where IMPI has been removed from AoR but is not found in store.
TEST_F(DeregistrationTaskTest, CannotFindImpiToDelete)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\"}]}";
  build_dereg_request(body);

  // Create an AoR with a minimal binding.
  std::string aor_id = "sip:6505550231@homedomain";
  Binding binding(aor_id);
  binding._private_id = "impi1";
  Bindings bindings;
  bindings[""] = &binding;

  std::vector<std::string> binding_ids;

  expect_sm_updates(aor_id, bindings, binding_ids);

  // Simulate the IMPI not being found in the store. The handler does not go on
  // to try and delete the IMPI.
  ImpiStore::Impi* impi1 = NULL;
  EXPECT_CALL(*_local_impi_store, get_impi("impi1", _, false)).WillOnce(Return(impi1));
  expect_impi_deletes("impi1", _remote_impi_store);

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();
}

// Error case for IMPI store failure when deleting IMPI.
TEST_F(DeregistrationTaskTest, ImpiStoreFailure)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\"}]}";
  build_dereg_request(body);

  // Create an AoR with a minimal binding.
  std::string aor_id = "sip:6505550231@homedomain";
  Binding binding(aor_id);
  binding._private_id = "impi1";
  Bindings bindings;
  bindings[""] = &binding;

  std::vector<std::string> binding_ids;

  expect_sm_updates(aor_id, bindings, binding_ids);

  // Simulate the IMPI store failing when deleting the IMPI. The handler does
  // not retry the delete.
  ImpiStore::Impi* impi1 = new ImpiStore::Impi("impi1");
  EXPECT_CALL(*_local_impi_store, get_impi("impi1", _, false)).WillOnce(Return(impi1));
  EXPECT_CALL(*_local_impi_store, delete_impi(impi1, _)).WillOnce(Return(Store::ERROR));
  expect_impi_deletes("impi1", _remote_impi_store);

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();
}

// Test that handlers will retry when IMPI store returns data contention on
// first delete.
TEST_F(DeregistrationTaskTest, ImpiStoreDataContention)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\"}]}";
  build_dereg_request(body);

  // Create an AoR with a minimal binding.
  std::string aor_id = "sip:6505550231@homedomain";
  Binding binding(aor_id);
  binding._private_id = "impi1";
  Bindings bindings;
  bindings[""] = &binding;

  std::vector<std::string> binding_ids;

  expect_sm_updates(aor_id, bindings, binding_ids);

  // We need to create two IMPIs when we return one on a call to get_impi we
  // lose ownership of it.
  ImpiStore::Impi* impi1 = new ImpiStore::Impi("impi1");
  ImpiStore::Impi* impi1a = new ImpiStore::Impi("impi1");
  {
    // Simulate the IMPI store returning data contention on the first delete.
    // The handler tries again.
    InSequence s;
    EXPECT_CALL(*_local_impi_store, get_impi("impi1", _, false)).WillOnce(Return(impi1));
    EXPECT_CALL(*_local_impi_store, delete_impi(impi1, _)).WillOnce(Return(Store::DATA_CONTENTION));
    EXPECT_CALL(*_local_impi_store, get_impi("impi1", _, false)).WillOnce(Return(impi1a));
    EXPECT_CALL(*_local_impi_store, delete_impi(impi1a, _)).WillOnce(Return(Store::OK));
  }
  expect_impi_deletes("impi1", _remote_impi_store);

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();
}

//
// Test reading sprout's bindings.
//

class GetBindingsTest : public TestWithMockSM
{
};

// Test getting an IMPU that does not have any bindings.
TEST_F(GetBindingsTest, NoBindings)
{
  // Build request
  MockHttpStack::Request req(stack, "/impu/sip%3A6505550231%40homedomain/bindings", "");
  GetBindingsTask::Config config(sm);
  GetBindingsTask* task = new GetBindingsTask(req, &config, 0);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";

  EXPECT_CALL(*sm, get_bindings(aor_id, _, _))
    .WillOnce(Return(HTTP_OK));
  EXPECT_CALL(*stack, send_reply(_, 200, _));

  task->run();
}

// Test getting an IMPU with one binding.
TEST_F(GetBindingsTest, OneBinding)
{
  // Build request
  MockHttpStack::Request req(stack, "/impu/sip%3A6505550231%40homedomain/bindings", "");
  GetBindingsTask::Config config(sm);
  GetBindingsTask* task = new GetBindingsTask(req, &config, 0);

  // Build one binding
  std::string aor_id = "sip:6505550231@homedomain";
  std::string binding_id = "<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1";
  Binding* actual_binding = AoRTestUtils::build_binding(aor_id, time(NULL));
  std::string uri = actual_binding->_uri;
  Bindings bindings;
  bindings[binding_id] = actual_binding;

  // Set up subscriber_manager expectations
  EXPECT_CALL(*sm, get_bindings(aor_id, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(bindings),
                    Return(HTTP_OK)));
  EXPECT_CALL(*stack, send_reply(_, 200, _));

  // Run the task
  task->run();

  // Check that the JSON document is correct.
  rapidjson::Document document;
  document.Parse(req.content().c_str());

  // The document should be of the form {"bindings":{...}}
  EXPECT_TRUE(document.IsObject());
  EXPECT_TRUE(document.HasMember("bindings"));
  EXPECT_TRUE(document["bindings"].IsObject());

  // Check there is only one binding.
  EXPECT_EQ(1, document["bindings"].MemberCount());
  const rapidjson::Value& binding_name = document["bindings"].MemberBegin()->name;
  const rapidjson::Value& binding = document["bindings"].MemberBegin()->value;

  // Check the fields in the binding. Don't check every value. It makes the
  // test unnecessarily verbose.
  EXPECT_TRUE(binding.HasMember("uri"));
  EXPECT_TRUE(binding.HasMember("cid"));
  EXPECT_TRUE(binding.HasMember("cseq"));
  EXPECT_TRUE(binding.HasMember("expires"));
  EXPECT_TRUE(binding.HasMember("priority"));
  EXPECT_TRUE(binding.HasMember("params"));
  EXPECT_TRUE(binding.HasMember("private_id"));
  EXPECT_TRUE(binding.HasMember("emergency_reg"));

  // Do check the binding ID and URI as a representative test.
  EXPECT_EQ(binding_id, binding_name.GetString());
  EXPECT_EQ(uri, binding["uri"].GetString());
}

// Test getting an IMPU with two bindings.
TEST_F(GetBindingsTest, TwoBindings)
{
  // Build request
  MockHttpStack::Request req(stack, "/impu/sip%3A6505550231%40homedomain/bindings", "");
  GetBindingsTask::Config config(sm);
  GetBindingsTask* task = new GetBindingsTask(req, &config, 0);

  // Build two bindings
  std::string aor_id = "sip:6505550231@homedomain";
  Binding* binding_1 = AoRTestUtils::build_binding(aor_id, time(NULL), "123");
  Binding* binding_2 = AoRTestUtils::build_binding(aor_id, time(NULL), "456");
  Bindings bindings;
  bindings["123"] = binding_1;
  bindings["456"] = binding_2;

  // Set up subscriber_data_manager expectations
  EXPECT_CALL(*sm, get_bindings(aor_id, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(bindings),
                    Return(HTTP_OK)));
  EXPECT_CALL(*stack, send_reply(_, 200, _));

  // Run the task
  task->run();

  // Check that the JSON document has two bindings.
  rapidjson::Document document;
  document.Parse(req.content().c_str());
  EXPECT_EQ(2, document["bindings"].MemberCount());
  EXPECT_TRUE(document["bindings"].HasMember("123"));
  EXPECT_TRUE(document["bindings"].HasMember("456"));
}

// Test the flow when subscriber manager returns a server error.
TEST_F(GetBindingsTest, SubscriberManagerFail)
{
  // Build request
  MockHttpStack::Request req(stack, "/impu/sip%3A6505550231%40homedomain/bindings", "");
  GetBindingsTask::Config config(sm);
  GetBindingsTask* task = new GetBindingsTask(req, &config, 0);

  // Expect a server error at subscriber manager
  std::string aor_id = "sip:6505550231@homedomain";
  EXPECT_CALL(*sm, get_bindings(aor_id, _, _))
    .WillOnce(Return(HTTP_SERVER_ERROR));
  EXPECT_CALL(*stack, send_reply(_, 500, _));

  task->run();
}

// Test that a get binding request with PUT method gets rejected.
TEST_F(GetBindingsTest, BadMethod)
{
  // Build request
  MockHttpStack::Request req(stack,
                             "/impu/sip%3A6505550231%40homedomain/bindings",
                             "",
                             "",
                             "",
                             htp_method_PUT);
  GetBindingsTask::Config config(sm);
  GetBindingsTask* task = new GetBindingsTask(req, &config, 0);

  EXPECT_CALL(*stack, send_reply(_, 405, _));
  task->run();
}

//
// Test fetching sprout's subscriptions.
//

class GetSubscriptionsTest : public TestWithMockSM
{
};

// Test getting an IMPU that does not have any subscription.
TEST_F(GetSubscriptionsTest, NoSubscriptions)
{
  // Build request
  MockHttpStack::Request req(stack, "/impu/sip%3A6505550231%40homedomain/subscriptions", "");
  GetSubscriptionsTask::Config config(sm);
  GetSubscriptionsTask* task = new GetSubscriptionsTask(req, &config, 0);

  // Set up subscriber manager expectations
  std::string aor_id = "sip:6505550231@homedomain";

  {
    InSequence s;
      EXPECT_CALL(*sm, get_subscriptions(aor_id, _, _)).WillOnce(Return(HTTP_OK));
      EXPECT_CALL(*stack, send_reply(_, 200, _));
  }

  task->run();
}

// Test getting an IMPU that has one subscription
TEST_F(GetSubscriptionsTest, OneSubscription)
{
  // Build request
  MockHttpStack::Request req(stack, "/impu/sip%3A6505550231%40homedomain/subscriptions", "");
  GetSubscriptionsTask::Config config(sm);
  GetSubscriptionsTask* task = new GetSubscriptionsTask(req, &config, 0);

  // Set up subscriber manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  Subscription* actual_subscription = AoRTestUtils::build_subscription("1234", time(NULL));
  std::string to_tag = actual_subscription->_to_tag;
  std::string uri = actual_subscription->_req_uri;

  Subscriptions subscriptions;
  subscriptions[to_tag] = actual_subscription;

  {
    InSequence s;
      EXPECT_CALL(*sm, get_subscriptions(aor_id, _, _))
        .WillOnce(DoAll(SetArgReferee<1>(subscriptions),
                        Return(HTTP_OK)));
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
  const rapidjson::Value& subscription_name = document["subscriptions"].MemberBegin()->name;
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
  EXPECT_EQ(to_tag, subscription_name.GetString());
  EXPECT_EQ(uri, subscription["req_uri"].GetString());
}

// Test getting an IMPU with two subscriptions.
TEST_F(GetSubscriptionsTest, TwoSubscriptions)
{
  // Build request
  MockHttpStack::Request req(stack, "/impu/sip%3A6505550231%40homedomain/subscriptions", "");
  GetSubscriptionsTask::Config config(sm);
  GetSubscriptionsTask* task = new GetSubscriptionsTask(req, &config, 0);

  // Build two subscriptions
  std::string aor_id = "sip:6505550231@homedomain";
  Subscription* subscription_1 = AoRTestUtils::build_subscription("456", time(NULL));
  Subscription* subscription_2 = AoRTestUtils::build_subscription("789", time(NULL));
  std::string to_tag_1 = subscription_1->_to_tag;
  std::string to_tag_2 = subscription_2->_to_tag;

  Subscriptions subscriptions;
  subscriptions[to_tag_1] = subscription_1;
  subscriptions[to_tag_2] = subscription_2;

  // Set up subscriber manager expectations
  EXPECT_CALL(*sm, get_subscriptions(aor_id, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(subscriptions),
                    Return(HTTP_OK)));
  EXPECT_CALL(*stack, send_reply(_, 200, _));

  // Run the task
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
  GetSubscriptionsTask::Config config(sm);
  GetSubscriptionsTask* task = new GetSubscriptionsTask(req, &config, 0);

  // Set up subscriber manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  Subscriptions subscriptions;
  EXPECT_CALL(*sm, get_subscriptions(aor_id, _, _))
    .WillOnce(Return(HTTP_SERVER_ERROR));
  EXPECT_CALL(*stack, send_reply(_, 500, _));

  task->run();
}

// Test that a get subscription request with PUT method gets rejected.
TEST_F(GetSubscriptionsTest, BadMethod)
{
  // Build request
  MockHttpStack::Request req(stack,
                             "/impu/sip%3A6505550231%40homedomain/subscriptions",
                             "",
                             "",
                             "",
                             htp_method_PUT);
  GetSubscriptionsTask::Config config(sm);
  GetSubscriptionsTask* task = new GetSubscriptionsTask(req, &config, 0);

  EXPECT_CALL(*stack, send_reply(_, 405, _));
  task->run();
}

//
// Tests for deleting sprout's cached data.
//

class DeleteImpuTaskTest : public TestWithMockSM
{
  MockHttpStack::Request* req;
  DeleteImpuTask::Config* cfg;
  DeleteImpuTask* task;

  static void SetUpTestCase()
  {
    TestWithMockSM::SetUpTestCase();
  }

  void SetUp()
  {
    TestWithMockSM::SetUp();
  }

  void TearDown()
  {
    delete req;
    delete cfg;
    TestWithMockSM::TearDown();
  }

  // Build the deregistration request
  void build_task(const std::string& impu,
                  htp_method method = htp_method_DELETE)
  {
    req = new MockHttpStack::Request(stack,
                                     "/impu/" + impu,
                                     "",
                                     "",
                                     "",
                                     method);

    cfg = new DeleteImpuTask::Config(sm);
    task = new DeleteImpuTask(*req, cfg, 0);
  }
};

TEST_F(DeleteImpuTaskTest, Mainline)
{
  std::string impu = "sip:6505550231@homedomain";
  std::string impu_escaped =  "sip%3A6505550231%40homedomain";
  std::string actual_impu;

  build_task(impu_escaped);

  {
    InSequence s;
      EXPECT_CALL(*sm, deregister_subscriber(_, _, _))
        .WillOnce(DoAll(SaveArg<0>(&actual_impu),
                        Return(HTTP_OK)));
      EXPECT_CALL(*stack, send_reply(_, 200, _));
  }

  task->run();

  ASSERT_EQ(impu, actual_impu);
}

// Test a Delete Impu request that encounters store failure 
TEST_F(DeleteImpuTaskTest, StoreFailure)
{
  std::string impu = "sip:6505550231@homedomain";
  std::string impu_escaped =  "sip%3A6505550231%40homedomain";

  build_task(impu_escaped);

  {
    InSequence s;
      EXPECT_CALL(*sm, deregister_subscriber(_, _, _))
        .WillOnce(Return(HTTP_SERVER_ERROR));
      EXPECT_CALL(*stack, send_reply(_, 500, _));
  }

  task->run();
}

// Test that a Delete IMPU request with PUT method gets rejected.
TEST_F(DeleteImpuTaskTest, BadMethod)
{
  std::string impu = "sip:6505550231@homedomain";
  std::string impu_escaped =  "sip%3A6505550231%40homedomain";

  build_task(impu_escaped, htp_method_PUT);
  EXPECT_CALL(*stack, send_reply(_, 405, _));

  task->run();
}


class PushProfileTaskTest : public TestWithMockSM
{
  MockHttpStack::Request* req;
  PushProfileTask::Config* cfg;
  PushProfileTask* task;

  static void SetUpTestCase()
  {
    TestWithMockSM::SetUpTestCase();
  }

  void SetUp()
  {
    TestWithMockSM::SetUp();
  }

  void TearDown()
  {
    delete req;
    delete cfg;
    TestWithMockSM::TearDown();
  }

  // Build the push profile request
  void build_pushprofile_request(std::string body,
                                 std::string default_uri,
                                 htp_method method = htp_method_PUT)
  {
    req = new MockHttpStack::Request(stack,
                                     "/registrations/" + default_uri,
                                     "",
                                     "",
                                     body,
                                     method);

    cfg = new PushProfileTask::Config(sm);
    task = new PushProfileTask(*req, cfg, 0);
  }
};

// Mainline Case. Complicated XML to make sure all components can be handled correctly
TEST_F(PushProfileTaskTest, MainlineTest)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string user_data =     "<IMSSubscription><ServiceProfile>"
                              "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                              "<PublicIdentity><Identity>sip:6505550232@homedomain</Identity><BarringIndication>1</BarringIndication></PublicIdentity>"
                              "<InitialFilterCriteria>"
                              "<Priority>1</Priority>"
                              "<TriggerPoint>"
                              "<ConditionTypeCNF>0</ConditionTypeCNF>"
                              "<SPT>"
                              "<ConditionNegated>0</ConditionNegated>"
                              "<Group>0</Group>"
                              "<Method>REGISTER</Method>"
                              "<Extension></Extension>"
                              "</SPT>"
                              "</TriggerPoint>"
                              "<ApplicationServer>"
                              "<ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>"
                              "<DefaultHandling>1</DefaultHandling>"
                              "</ApplicationServer>"
                              "</InitialFilterCriteria>"
                              "</ServiceProfile></IMSSubscription>";
  std::string body =          "{\"user-data-xml\":\"" + user_data + "\"}";

  build_pushprofile_request(body, default_uri);

  EXPECT_CALL(*sm, update_associated_uris(default_uri, _, _)).WillOnce(Return(HTTP_OK));
  EXPECT_CALL(*stack, send_reply(_, 200, _));
  task->run();
}

// The method is not a put, and therefore is invalid. Sends HTTP_BAD_REQUEST.
TEST_F(PushProfileTaskTest, InvalidMethod)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string user_data =     "<IMSSubscription><ServiceProfile>"
                              "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                              "</ServiceProfile></IMSSubscription>";
  std::string body =          "{\"user-data-xml\":\"" + user_data + "\"}";

  build_pushprofile_request(body, default_uri, htp_method_GET);

  EXPECT_CALL(*stack, send_reply(_, 405, _));
  task->run();
}

// The JSON is not valid, and therefore not able to be parsed. Sends HTTP_BAD_REQUEST.
TEST_F(PushProfileTaskTest, InvalidJSON)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string user_data =     "<IMSSubscription><ServiceProfile>"
                              "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                              "</ServiceProfile></IMSSubscription>";
  std::string body = " {{\"user-data-xml\":\"" + user_data + "\"}";

  build_pushprofile_request(body, default_uri);

  EXPECT_CALL(*stack, send_reply(_, 400, _));
  task->run();
}

// The JSON is valid JSON, but does not contain the xml component as expected Sends HTTP_BAD_REQUEST
TEST_F(PushProfileTaskTest, MissingXMLfromJSON)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string user_data =     "<IMSSubscription><ServiceProfile>"
                              "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                              "</ServiceProfile></IMSSubscription>";
  std::string body = "{\"public-identity\":\""+ default_uri + "\"}";

  build_pushprofile_request(body, default_uri);

  EXPECT_CALL(*stack, send_reply(_, 400, _));
  task->run();
}


// The XML is not valid and therefore not able to be parsed. Sends HTTP_BAD_REQUEST.
TEST_F(PushProfileTaskTest, InvalidXML)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string user_data =     "<IMSSubscription><ServiceProfile>"
                              "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                              "<<"
                              "</ServiceProfile></IMSSubscription>";
  std::string body =          "{\"user-data-xml\":\"" + user_data + "\"}";

  build_pushprofile_request(body, default_uri);

  EXPECT_CALL(*stack, send_reply(_, 400, _));
  task->run();
}

// The XML does not contain any service profiles. Sends HTTP_BAD_REQUEST
TEST_F(PushProfileTaskTest, MissingServiceProfileXML)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string user_data =     "<IMSSubscription>"
                              "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                              "</IMSSubscription>";
  std::string body = "{\"user-data-xml\":\"" + user_data + "\"}";

  build_pushprofile_request(body, default_uri);

  EXPECT_CALL(*stack, send_reply(_, 400, _));
  task->run();
}



// The XML does not contain the relevant Public Identities. Sends HTTP_BAD_REQUEST.
TEST_F(PushProfileTaskTest, MissingPublicIdentityXML)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string user_data =  "<IMSSubscription><ServiceProfile>"
                           "</ServiceProfile></IMSSubscription>";
  std::string body =       "{\"user-data-xml\":\"" + user_data + "\"}";

  build_pushprofile_request(body, default_uri);

  EXPECT_CALL(*stack, send_reply(_, 400, _));
  task->run();
}

// Subscriber manager fails with SERVER ERROR
TEST_F(PushProfileTaskTest, SubscriberManagerFails)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string user_data =     "<IMSSubscription><ServiceProfile>"
                              "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                              "</ServiceProfile></IMSSubscription>";
  std::string body =          "{\"user-data-xml\":\"" + user_data + "\"}";

  build_pushprofile_request(body, default_uri);

  EXPECT_CALL(*sm, update_associated_uris(default_uri, _, _))
    .WillOnce(Return(HTTP_SERVER_ERROR));
  EXPECT_CALL(*stack, send_reply(_, 500, _));
  task->run();
}

