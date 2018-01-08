/**
 * @file subscriber_data_manager_test.cpp
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


#include <string>
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "fakelogger.h"
#include "siptest.hpp"
#include "stack.h"
#include "utils.h"
#include "pjutils.h"
#include "sas.h"
#include "localstore.h"
#include "subscriber_data_manager.h"
#include "astaire_aor_store.h"
#include "test_utils.hpp"
#include "test_interposer.hpp"
#include "fakechronosconnection.hpp"
#include "mock_chronos_connection.h"
#include "mock_store.h"
#include "mock_analytics_logger.h"
#include "analyticslogger.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::AtLeast;
using ::testing::An;

/// Fixture for BasicSubscriberDataManagerTest.
class BasicSubscriberDataManagerTest : public SipTest
{
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
  }

  static void TearDownTestCase()
  {
    SipTest::TearDownTestCase();
  }

  BasicSubscriberDataManagerTest()
  {
    _chronos_connection = new FakeChronosConnection();
    _datastore = new LocalStore();
    _aor_store = new AstaireAoRStore(_datastore);
    _analytics_logger = new MockAnalyticsLogger();
    _store = new SubscriberDataManager(_aor_store,
                                       _chronos_connection,
                                       _analytics_logger,
                                       true);
  }

  virtual ~BasicSubscriberDataManagerTest()
  {
    // PJSIP transactions aren't actually destroyed until a zero ms
    // timer fires (presumably to ensure destruction doesn't hold up
    // real work), so poll for that to happen. Otherwise we leak!
    // Allow a good length of time to pass too, in case we have
    // transactions still open. 32s is the default UAS INVITE
    // transaction timeout, so we go higher than that.
    cwtest_advance_time_ms(33000L);
    poll();

    // Stop and restart the layer just in case
    //pjsip_tsx_layer_instance()->stop();
    //pjsip_tsx_layer_instance()->start();

    delete _store; _store = NULL;
    delete _aor_store; _aor_store = NULL;
    delete _datastore; _datastore = NULL;
    delete _chronos_connection; _chronos_connection = NULL;
    delete _analytics_logger; _analytics_logger = NULL;
  }

  // Fixture variables.  Note that as the fixture is a C++ template, these must
  // be accessed in the individual tests using the this pointer (e.g. use
  // `this->store` rather than `_store`).
  FakeChronosConnection* _chronos_connection;
  LocalStore* _datastore;
  AstaireAoRStore* _aor_store;
  SubscriberDataManager* _store;
  MockAnalyticsLogger* _analytics_logger;
};

TEST_F(BasicSubscriberDataManagerTest, BindingTests)
{
  AoRPair* aor_data1;
  AoR::Binding* b1;
  AssociatedURIs associated_uris = {};

  // Get an initial empty AoR record and add a binding.
  int now = time(NULL);
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  aor_data1->get_current()->_timer_id = "AoRtimer";
  aor_data1->get_current()->_associated_uris = associated_uris;
  EXPECT_EQ(0u, aor_data1->get_current()->bindings().size());
  b1 = aor_data1->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b1->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_private_id = "5102175698@cw-ngv.com";
  b1->_emergency_registration = false;

  // Add the AoR record to the store.
  std::string aor = "5102175698@cw-ngv.com";
  associated_uris.add_uri(aor, false);
  aor_data1->get_current()->_associated_uris = associated_uris;

  EXPECT_CALL(*(this->_analytics_logger),
              registration("5102175698@cw-ngv.com",
                           "urn:uuid:00000000-0000-0000-0000-b4dd32817622:1",
                           "<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>",
                           300)).Times(1);
  bool rc = this->_store->set_aor_data(aor, SubscriberDataManager::EventTrigger::USER, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  // Get the AoR record from the store.
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ("AoRtimer", aor_data1->get_current()->_timer_id);
  EXPECT_EQ(1u, aor_data1->get_current()->bindings().size());
  EXPECT_EQ(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"), aor_data1->get_current()->bindings().begin()->first);
  b1 = aor_data1->get_current()->bindings().begin()->second;
  EXPECT_EQ(std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>"), b1->_uri);
  EXPECT_EQ(std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq"), b1->_cid);
  EXPECT_EQ(17038, b1->_cseq);
  EXPECT_EQ(now + 300, b1->_expires);
  EXPECT_EQ(0, b1->_priority);
  EXPECT_EQ(1u, b1->_path_headers.size());
  EXPECT_EQ(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"), b1->_path_headers.front());
  EXPECT_EQ(3u, b1->_params.size());
  EXPECT_EQ(std::string("\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\""), b1->_params["+sip.instance"]);
  EXPECT_EQ(std::string("1"), b1->_params["reg-id"]);
  EXPECT_EQ(std::string(""), b1->_params["+sip.ice"]);
  EXPECT_EQ(std::string("5102175698@cw-ngv.com"), b1->_private_id);
  EXPECT_FALSE(b1->_emergency_registration);

  // Update AoR record in the store and check it.  Change the expiry time as
  // part of the update and check that we get an analytics log.
  b1->_cseq = 17039;
  now = time(NULL);
  b1->_expires = now + 100;
  EXPECT_CALL(*(this->_analytics_logger),
              registration("5102175698@cw-ngv.com",
                           "urn:uuid:00000000-0000-0000-0000-b4dd32817622:1",
                           "<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>",
                           100)).Times(1);
  rc = this->_store->set_aor_data(aor, SubscriberDataManager::EventTrigger::USER, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ("AoRtimer", aor_data1->get_current()->_timer_id);
  EXPECT_EQ(1u, aor_data1->get_current()->bindings().size());
  EXPECT_EQ(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"), aor_data1->get_current()->bindings().begin()->first);
  b1 = aor_data1->get_current()->bindings().begin()->second;
  EXPECT_EQ(std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>"), b1->_uri);
  EXPECT_EQ(std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq"), b1->_cid);
  EXPECT_EQ(17039, b1->_cseq);
  EXPECT_EQ(now + 100, b1->_expires);
  EXPECT_EQ(0, b1->_priority);
  EXPECT_EQ(1u, b1->_path_uris.size());
  EXPECT_EQ(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"), b1->_path_uris.front());
  EXPECT_EQ(1u, b1->_path_headers.size());
  EXPECT_EQ(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"), b1->_path_headers.front());

  // Update AoR record again in the store and check it, this time using get_binding.
  // Also, don't change the expiry time -- we shouldn't get an analytics log.
  b1->_cseq = 17040;
  rc = this->_store->set_aor_data(aor, SubscriberDataManager::EventTrigger::USER, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ("AoRtimer", aor_data1->get_current()->_timer_id);
  EXPECT_EQ(1u, aor_data1->get_current()->bindings().size());
  b1 = aor_data1->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  EXPECT_EQ(std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>"), b1->_uri);
  EXPECT_EQ(std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq"), b1->_cid);
  EXPECT_EQ(17040, b1->_cseq);
  EXPECT_EQ(now + 100, b1->_expires);
  EXPECT_EQ(0, b1->_priority);
  delete aor_data1; aor_data1 = NULL;

  // Remove a binding.
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ(1u, aor_data1->get_current()->bindings().size());
  aor_data1->get_current()->remove_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  EXPECT_EQ(0u, aor_data1->get_current()->bindings().size());
  EXPECT_CALL(*(this->_analytics_logger),
              registration("5102175698@cw-ngv.com",
                           "urn:uuid:00000000-0000-0000-0000-b4dd32817622:1",
                           "<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>",
                           0)).Times(1);
  rc = this->_store->set_aor_data(aor, SubscriberDataManager::EventTrigger::USER, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ(0u, aor_data1->get_current()->bindings().size());

  delete aor_data1; aor_data1 = NULL;
}

TEST_F(BasicSubscriberDataManagerTest, SubscriptionTests)
{
  CapturingTestLogger log;
  AoRPair* aor_data1;
  AoR::Binding* b1;
  AssociatedURIs associated_uris = {};
  AoR::Subscription* s1;

  // Get an initial empty AoR record and add a binding.
  int now = time(NULL);
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  aor_data1->get_current()->_timer_id = "AoRtimer";
  aor_data1->get_current()->_associated_uris = associated_uris;
  EXPECT_EQ(0u, aor_data1->get_current()->bindings().size());
  b1 = aor_data1->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b1->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_private_id = "5102175698@cw-ngv.com";
  b1->_emergency_registration = false;

  // Add the AoR record to the store.
  std::string aor = "5102175698@cw-ngv.com";
  associated_uris.add_uri(aor, false);
  aor_data1->get_current()->_associated_uris = associated_uris;

  EXPECT_CALL(*(this->_analytics_logger),
              registration("5102175698@cw-ngv.com",
                           "urn:uuid:00000000-0000-0000-0000-b4dd32817622:1",
                           "<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>",
                           300)).Times(1);
  bool rc = this->_store->set_aor_data(aor, SubscriberDataManager::EventTrigger::USER, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  // Get the AoR record from the store.
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ("AoRtimer", aor_data1->get_current()->_timer_id);
  EXPECT_EQ(1u, aor_data1->get_current()->bindings().size());
  EXPECT_EQ(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"), aor_data1->get_current()->bindings().begin()->first);
  b1 = aor_data1->get_current()->bindings().begin()->second;
  EXPECT_EQ(std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>"), b1->_uri);
  EXPECT_EQ(std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq"), b1->_cid);
  EXPECT_EQ(17038, b1->_cseq);
  EXPECT_EQ(now + 300, b1->_expires);
  EXPECT_EQ(0, b1->_priority);

  // Add a subscription to the record.
  s1 = aor_data1->get_current()->get_subscription("1234");
  s1->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
  s1->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_from_tag = std::string("4321");
  s1->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_to_tag = std::string("1234");
  s1->_cid = std::string("xyzabc@192.91.191.29");
  s1->_route_uris.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  s1->_expires = now + 300;

  // Write the record back to the store.
  rc = this->_store->set_aor_data(aor, SubscriberDataManager::EventTrigger::USER, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  EXPECT_TRUE(log.contains("Sending NOTIFY for subscription 1234: Reason(s): - At least one subscription has been created"));

  // Read the record back in and check the subscription is still in place.
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ("AoRtimer", aor_data1->get_current()->_timer_id);
  EXPECT_EQ(1u, aor_data1->get_current()->subscriptions().size());
  EXPECT_EQ(std::string("1234"), aor_data1->get_current()->subscriptions().begin()->first);
  s1 = aor_data1->get_current()->get_subscription(std::string("1234"));
  EXPECT_EQ(std::string("sip:5102175698@192.91.191.29:59934;transport=tcp"), s1->_req_uri);
  EXPECT_EQ(std::string("<sip:5102175698@cw-ngv.com>"), s1->_from_uri);
  EXPECT_EQ(std::string("4321"), s1->_from_tag);
  EXPECT_EQ(std::string("<sip:5102175698@cw-ngv.com>"), s1->_to_uri);
  EXPECT_EQ(std::string("1234"), s1->_to_tag);
  EXPECT_EQ(std::string("xyzabc@192.91.191.29"), s1->_cid);
  EXPECT_EQ(1u, s1->_route_uris.size());
  EXPECT_EQ(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"), s1->_route_uris.front());
  EXPECT_EQ(now + 300, s1->_expires);
  EXPECT_EQ(3, aor_data1->get_current()->_notify_cseq);

  // Remove the subscription.
  aor_data1->get_current()->remove_subscription(std::string("1234"));
  EXPECT_EQ(0u, aor_data1->get_current()->subscriptions().size());

  delete aor_data1; aor_data1 = NULL;
}

TEST_F(BasicSubscriberDataManagerTest, AssociatedURIsTests)
{
  CapturingTestLogger log;
  AoRPair* aor_data1;
  AoR::Binding* b1;
  AoR::Subscription* s1;
  AssociatedURIs associated_uris = {};

  // Get an initial empty AoR record and add a binding and subscription.
  int now = time(NULL);
  aor_data1 = this->_store->get_aor_data(std::string("5102175691@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  aor_data1->get_current()->_timer_id = "AoRtimer";
  aor_data1->get_current()->_associated_uris = associated_uris;
  EXPECT_EQ(0u, aor_data1->get_current()->bindings().size());
  b1 = aor_data1->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  b1->_uri = std::string("<sip:5102175691@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b1->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_private_id = "5102175691@cw-ngv.com";
  b1->_emergency_registration = false;

  s1 = aor_data1->get_current()->get_subscription("1234");
  s1->_req_uri = std::string("sip:5102175691@192.91.191.29:59934;transport=tcp");
  s1->_from_uri = std::string("<sip:5102175691@cw-ngv.com>");
  s1->_from_tag = std::string("4321");
  s1->_to_uri = std::string("<sip:5102175691@cw-ngv.com>");
  s1->_to_tag = std::string("1234");
  s1->_cid = std::string("xyzabc@192.91.191.29");
  s1->_route_uris.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  s1->_expires = now + 300;

  // Add URI
  std::string aor1 = "5102175691@cw-ngv.com";
  associated_uris.add_uri(aor1, false);
  aor_data1->get_current()->_associated_uris = associated_uris;

  // Write AoR record back to store
  EXPECT_CALL(*(this->_analytics_logger),
              registration("5102175691@cw-ngv.com",
                           "urn:uuid:00000000-0000-0000-0000-b4dd32817622:1",
                           "<sip:5102175691@192.91.191.29:59934;transport=tcp;ob>",
                           300)).Times(1);
  bool rc = this->_store->set_aor_data(aor1, SubscriberDataManager::EventTrigger::USER, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  EXPECT_TRUE(log.contains("Sending NOTIFY for subscription 1234: Reason(s): - At least one binding has changed - At least one subscription has been created - The associated URIs have changed"));

  // Get AoR record
  aor_data1 = this->_store->get_aor_data(std::string("5102175691@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ("AoRtimer", aor_data1->get_current()->_timer_id);
  EXPECT_EQ(1u, aor_data1->get_current()->bindings().size());
  EXPECT_EQ(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"), aor_data1->get_current()->bindings().begin()->first);
  b1 = aor_data1->get_current()->bindings().begin()->second;
  EXPECT_EQ(std::string("<sip:5102175691@192.91.191.29:59934;transport=tcp;ob>"), b1->_uri);
  EXPECT_EQ(std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq"), b1->_cid);
  EXPECT_EQ(17038, b1->_cseq);
  EXPECT_EQ(now + 300, b1->_expires);
  EXPECT_EQ(0, b1->_priority);

  // Add some Associated URIs and write back to the store
  std::string aor2 = "5102175692@cw-ngv.com";
  std::string barred1 =  "5102175694@cw-ngv.com";
  std::string wildcard1 = "510*@cw-ngv.com";

  associated_uris.add_uri(aor2, false);
  associated_uris.add_uri(barred1, true);
  associated_uris.add_wildcard_mapping(aor2, wildcard1);

  aor_data1->get_current()->_associated_uris = associated_uris;

  // Write AoR record back to store
  rc = this->_store->set_aor_data(aor1, SubscriberDataManager::EventTrigger::USER, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  // Check that the associated URIs are still there, and a NOTIFY has been sent
  aor_data1 = this->_store->get_aor_data(std::string("5102175691@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);

  AssociatedURIs au = aor_data1->get_current()->_associated_uris;
  std::vector<std::string> list_associated_uris = au.get_all_uris();
  std::vector<std::string> barred_uris = au.get_barred_uris();
  std::map<std::string, std::string> wildcard_map = au.get_wildcard_mapping();

  EXPECT_EQ(3u, list_associated_uris.size());
  EXPECT_EQ(std::string("5102175691@cw-ngv.com"), list_associated_uris[0]);
  EXPECT_EQ(std::string("5102175692@cw-ngv.com"), list_associated_uris[1]);
  EXPECT_EQ(std::string("5102175694@cw-ngv.com"), list_associated_uris[2]);

  EXPECT_EQ(1u, barred_uris.size());
  EXPECT_EQ(std::string("5102175694@cw-ngv.com"), barred_uris[0]);

  EXPECT_EQ(1u, wildcard_map.size());

  EXPECT_TRUE(log.contains("Sending NOTIFY for subscription 1234: Reason(s): - The associated URIs have changed -"));

  // Clear Associated URIs
  au.clear_uris();
  EXPECT_EQ(0u, au.get_all_uris().size());
  EXPECT_EQ(0u, au.get_barred_uris().size());

  delete aor_data1; aor_data1 = NULL;
}

// Test that if a binding is removed due to administrative deregistration then a
// NOTIFY is sent, and if it's removed because it's expired or deregistered by
// the endpoint then a NOTIFY isn't sent.
TEST_F(BasicSubscriberDataManagerTest, NotifyExpiredSubscription)
{
  // We're not testing analytics in this UT, so we don't care about any calls to it.
  EXPECT_CALL(*(this->_analytics_logger), registration(_,_,_,_)).Times(AtLeast(0));

  CapturingTestLogger log;
  AoR::Binding* b0;
  AoR::Binding* b1;
  AoR::Binding* b2;
  AoR::Subscription* s0;
  AoR::Subscription* s1;
  AssociatedURIs associated_uris = {};
  bool all_bindings_expired = false;

  // Get an initial empty AoR record.
  int now = time(NULL);
  AoRPair* aor_data1 = this->_store->get_aor_data(std::string("5102175691@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  aor_data1->get_current()->_timer_id = "AoRtimer";
  aor_data1->get_current()->_associated_uris = associated_uris;
  EXPECT_EQ(0u, aor_data1->get_current()->bindings().size());

  // Add a binding and corresponding subscription.
  // The URI is the same for the binding and the subscription as they're made
  // from the same endpoint.
  b0 = aor_data1->get_current()->get_binding(std::string("urn:uuid:0-0000-0000-0000-b4dd32817622:1"));
  b0->_uri = std::string("sip:5678@5678");
  b0->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b0->_cseq = 17038;
  b0->_expires = now + 300;
  b0->_priority = 0;
  b0->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b0->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b0->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b0->_params["reg-id"] = "1";
  b0->_params["+sip.ice"] = "";
  b0->_private_id = "5102175691@cw-ngv.com";
  b0->_emergency_registration = false;

  s0 = aor_data1->get_current()->get_subscription("5678");
  s0->_req_uri = std::string("sip:5678@5678");
  s0->_from_uri = std::string("<sip:5102175691@cw-ngv.com>");
  s0->_from_tag = std::string("4321");
  s0->_to_uri = std::string("<sip:5102175691@cw-ngv.com>");
  s0->_to_tag = std::string("5678");
  s0->_cid = std::string("xyzabc@192.91.191.29");
  s0->_route_uris.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  s0->_expires = now + 300;

  // Add URI
  std::string aor1 = "5102175691@cw-ngv.com";
  associated_uris.add_uri(aor1, false);
  aor_data1->get_current()->_associated_uris = associated_uris;

  // Add another pair of binding and subscription.
  b1 = aor_data1->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  b1->_uri = std::string("<sip:5102175691@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b1->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_private_id = "5102175691@cw-ngv.com";
  b1->_emergency_registration = false;

  s1 = aor_data1->get_current()->get_subscription("1234");
  s1->_req_uri = std::string("<sip:5102175691@192.91.191.29:59934;transport=tcp;ob>");
  s1->_from_uri = std::string("<sip:5102175691@cw-ngv.com>");
  s1->_from_tag = std::string("4321");
  s1->_to_uri = std::string("<sip:5102175691@cw-ngv.com>");
  s1->_to_tag = std::string("1234");
  s1->_cid = std::string("xyzabc@192.91.191.29");
  s1->_route_uris.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  s1->_expires = now + 300;

  // Add another binding so that when the other two are removed, the AoR is not
  // void.
  b2 = aor_data1->get_current()->get_binding(std::string("urn:uuid:111111-0000-0000-0000-b4dd32817622:1"));
  b2->_uri = std::string("<sip:111111@192.91.191.29:59934;transport=tcp;ob>");
  b2->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b2->_cseq = 17038;
  b2->_expires = now + 300;
  b2->_priority = 0;
  b2->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b2->_path_headers.push_back(std::string("\"Bob\" <sip:leftbinding@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b2->_params["+sip.instance"] = "\"<urn:uuid:111111-0000-0000-0000-b4dd32817622>\"";
  b2->_params["reg-id"] = "1";
  b2->_params["+sip.ice"] = "";
  b2->_private_id = "111111@cw-ngv.com";
  b2->_emergency_registration = false;

  // Write AoR record back to store.
  bool rc = this->_store->set_aor_data(aor1, SubscriberDataManager::EventTrigger::ADMIN, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;
  EXPECT_TRUE(log.contains("Sending NOTIFY for subscription 1234: Reason(s): - At least one binding has changed - At least one subscription has been created -"));

  // Get AoR record, remove first pair of binding and subscription at the same
  // time.
  aor_data1 = this->_store->get_aor_data(aor1, 0);
  ASSERT_TRUE(aor_data1 != NULL);
  aor_data1->get_current()->remove_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  aor_data1->get_current()->remove_subscription(std::string("1234"));

  // Write AoR record back to store with ADMIN. This would simulate the
  // behaviour of admin deregistration via Sprout/HSS.
  rc = this->_store->set_aor_data(aor1, SubscriberDataManager::EventTrigger::ADMIN, aor_data1, 0, all_bindings_expired);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  // Use log to check a NOTIFY has been sent to the removed binding about its
  // deregistration; this makes the test quite fragile, but there isn't a way to
  // check for the NOTIFY itself.
  EXPECT_TRUE(log.contains("Sending NOTIFY for subscription 1234: Reason(s): - At least one binding has changed"));
  EXPECT_TRUE(log.contains("The subscription 1234 has been terminated, send final NOTIFY"));

  // Get AoR record, remove second pair of binding and subscription at the same
  // time.
  aor_data1 = this->_store->get_aor_data(aor1, 0);
  ASSERT_TRUE(aor_data1 != NULL);
  aor_data1->get_current()->remove_binding(std::string("urn:uuid:0-0000-0000-0000-b4dd32817622:1"));
  aor_data1->get_current()->remove_subscription(std::string("5678"));

  // Write AoR record back to store with TIMEOUT. This would simulate the
  // behaviour of an expired binding that subscribed to its own registration.
  rc = this->_store->set_aor_data(aor1, SubscriberDataManager::EventTrigger::TIMEOUT, aor_data1, 0, all_bindings_expired);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  // Use log to check that expiry of an endpoint that subscribe to its own
  // registration state will skip such NOTIFY.
  // This makes the test quite fragile, but there isn't a way to
  // check for the NOTIFY itself.
  EXPECT_TRUE(log.contains("Sending NOTIFY for subscription 1234: Reason(s): - At least one binding has changed"));
  EXPECT_TRUE(log.contains("Skip expired subscription 5678 as the binding sip:5678@5678 has expired"));
}

TEST_F(BasicSubscriberDataManagerTest, CopyTests)
{
  AoRPair* aor_data1;
  AoR::Binding* b1;
  AssociatedURIs associated_uris = {};
  AoR::Subscription* s1;
  int now;

  // Get an initial empty AoR record.
  now = time(NULL);
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  aor_data1->get_current()->_timer_id = "AoRtimer";
  aor_data1->get_current()->_associated_uris = associated_uris;
  EXPECT_EQ(0u, aor_data1->get_current()->bindings().size());
  EXPECT_EQ(0u, aor_data1->get_current()->subscriptions().size());

  // Add a binding to the record.
  b1 = aor_data1->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  EXPECT_EQ(1u, aor_data1->get_current()->bindings().size());
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.homedomain;lr"));
  b1->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.homedomain;lr>;tag=6ht7"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_private_id = "5102175698@cw-ngv.com";
  b1->_emergency_registration = false;

  // Add a subscription to the record.
  s1 = aor_data1->get_current()->get_subscription("1234");
  EXPECT_EQ(1u, aor_data1->get_current()->subscriptions().size());
  s1->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
  s1->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_from_tag = std::string("4321");
  s1->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_to_tag = std::string("1234");
  s1->_cid = std::string("xyzabc@192.91.191.29");
  s1->_route_uris.push_back(std::string("<sip:abcdefgh@bono1.homedomain;lr>"));
  s1->_expires = now + 300;

  // Set the NOTIFY CSeq value to 1.
  aor_data1->get_current()->_notify_cseq = 1;

  // Test AoR copy constructor.
  AoR* copy = new AoR(*aor_data1->get_current());
  EXPECT_EQ("AoRtimer", copy->_timer_id);
  EXPECT_EQ(1u, copy->bindings().size());
  EXPECT_EQ(1u, copy->subscriptions().size());
  EXPECT_EQ(1, copy->_notify_cseq);
  EXPECT_EQ((uint64_t)0, copy->_cas);
  EXPECT_EQ("5102175698@cw-ngv.com", copy->_uri);
  delete copy; copy = NULL;

  // Test AoR assignment.
  copy = new AoR("sip:name@example.com");
  *copy = *aor_data1->get_current();
  EXPECT_EQ("AoRtimer", copy->_timer_id);
  EXPECT_EQ(1u, copy->bindings().size());
  EXPECT_EQ(1u, copy->subscriptions().size());
  EXPECT_EQ(1, copy->_notify_cseq);
  EXPECT_EQ((uint64_t)0, copy->_cas);
  EXPECT_EQ("5102175698@cw-ngv.com", copy->_uri);
  delete copy; copy = NULL;
  delete aor_data1; aor_data1 = NULL;
}

TEST_F(BasicSubscriberDataManagerTest, ExpiryTests)
{
  // The expiry tests require pjsip, so initialise for this test
  CapturingTestLogger log;
  AoRPair* aor_data1;
  AoR::Binding* b1;
  AoR::Binding* b2;
  AoR::Subscription* s1;
  AoR::Subscription* s2;
  AssociatedURIs associated_uris = {};
  bool rc;
  int now;

  // Create an empty AoR record.
  now = time(NULL);
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  aor_data1->get_current()->_timer_id = "AoRtimer";
  aor_data1->get_current()->_associated_uris = associated_uris;
  EXPECT_EQ(0u, aor_data1->get_current()->bindings().size());
  EXPECT_EQ(0u, aor_data1->get_current()->subscriptions().size());

  // Add a couple of bindings, one with expiry in 100 seconds, the next with
  // expiry in 200 seconds.
  b1 = aor_data1->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  EXPECT_EQ(1u, aor_data1->get_current()->bindings().size());
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 100;
  b1->_priority = 0;
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_private_id = "5102175698@cw-ngv.com";
  b1->_emergency_registration = false;
  b2 = aor_data1->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:2"));
  EXPECT_EQ(2u, aor_data1->get_current()->bindings().size());
  b2->_uri = std::string("<sip:5102175698@192.91.191.42:59934;transport=tcp;ob>");
  b2->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b2->_cseq = 17038;
  b2->_expires = now + 200;
  b2->_priority = 0;
  b2->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b2->_params["reg-id"] = "2";
  b2->_params["+sip.ice"] = "";
  b2->_private_id = "5102175699@cw-ngv.com";
  b2->_emergency_registration = false;

  // Add a couple of subscriptions, one with expiry in 150 seconds, the next
  // with expiry in 300 seconds.
  s1 = aor_data1->get_current()->get_subscription("1234");
  EXPECT_EQ(1u, aor_data1->get_current()->subscriptions().size());
  s1->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
  s1->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_from_tag = std::string("4321");
  s1->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_to_tag = std::string("1234");
  s1->_cid = std::string("xyzabc@192.91.191.29");
  s1->_route_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  s1->_expires = now + 150;
  s2 = aor_data1->get_current()->get_subscription("5678");
  EXPECT_EQ(2u, aor_data1->get_current()->subscriptions().size());
  s2->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
  s2->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s2->_from_tag = std::string("8765");
  s2->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s2->_to_tag = std::string("5678");
  s2->_cid = std::string("xyzabc@192.91.191.29");
  s2->_route_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  s2->_expires = now + 300;

  // Write the record to the store.
  std::string aor = "5102175698@cw-ngv.com";
  associated_uris = {};
  associated_uris.add_uri(aor, false);
  aor_data1->get_current()->_associated_uris = associated_uris;

  EXPECT_CALL(*(this->_analytics_logger),
              registration("5102175698@cw-ngv.com",
                           "urn:uuid:00000000-0000-0000-0000-b4dd32817622:2",
                           "<sip:5102175698@192.91.191.42:59934;transport=tcp;ob>",
                           200));
  EXPECT_CALL(*(this->_analytics_logger),
              registration("5102175698@cw-ngv.com",
                           "urn:uuid:00000000-0000-0000-0000-b4dd32817622:1",
                           "<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>",
                           100));
  rc = this->_store->set_aor_data(aor, SubscriberDataManager::EventTrigger::TIMEOUT, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  EXPECT_TRUE(log.contains("Sending NOTIFY for subscription 1234: Reason(s): - At least one binding has changed - At least one subscription has been created - The associated URIs have changed"));

  // Advance the time by 101 seconds and read the record back from the store.
  // The first binding should have expired.
  cwtest_advance_time_ms(101000);
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ(1u, aor_data1->get_current()->bindings().size());
  EXPECT_EQ(2u, aor_data1->get_current()->subscriptions().size());
  delete aor_data1; aor_data1 = NULL;

  // Advance the time by another 50 seconds and read the record back from the
  // store.  The first subscription should have expired.
  cwtest_advance_time_ms(50000);
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ(1u, aor_data1->get_current()->bindings().size());
  EXPECT_EQ(1u, aor_data1->get_current()->subscriptions().size());
  delete aor_data1; aor_data1 = NULL;

  // Advance the time by another 100 seconds and read the record back.
  // The whole record should now be empty - even though the second subscription
  // still has 99 seconds before it expires, all subscriptions implicitly
  // expire when the last binding expires.
  cwtest_advance_time_ms(100000);
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ(0u, aor_data1->get_current()->bindings().size());
  EXPECT_EQ(0u, aor_data1->get_current()->subscriptions().size());
  delete aor_data1; aor_data1 = NULL;
}

/// Fixtures for tests that check bad JSON documents are handled correctly.
class SubscriberDataManagerCorruptDataTest : public ::testing::Test
{
  void SetUp()
  {
    _chronos_connection = new FakeChronosConnection();
    _datastore = new MockStore();
    _aor_store = new AstaireAoRStore(_datastore);
    _analytics_logger = new AnalyticsLogger();

    {
      _store = new SubscriberDataManager(_aor_store,
                                         _chronos_connection,
                                         _analytics_logger,
                                         true);
    }
  }

  void TearDown()
  {
    delete _store; _store = NULL;
    delete _datastore; _datastore = NULL;
    delete _aor_store; _aor_store = NULL;
    delete _chronos_connection; _chronos_connection = NULL;
    delete _analytics_logger; _analytics_logger = NULL;
  }

  FakeChronosConnection* _chronos_connection;
  MockStore* _datastore;
  AstaireAoRStore* _aor_store;
  SubscriberDataManager* _store;
  AnalyticsLogger* _analytics_logger;
};

TEST_F(SubscriberDataManagerCorruptDataTest, BadlyFormedJson)
{
  AoRPair* aor_data1;

  EXPECT_CALL(*_datastore, get_data(_, _, _, _, _, An<Store::Format>()))
    .WillOnce(DoAll(SetArgReferee<2>(std::string("{\"bindings\": {}")),
                    SetArgReferee<3>(1), // CAS
                    Return(Store::OK)));

  aor_data1 = this->_store->get_aor_data(std::string("2010000001@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 == NULL);
  delete aor_data1;
}


TEST_F(SubscriberDataManagerCorruptDataTest, SemanticallyInvalidJson)
{
  AoRPair* aor_data1;

  EXPECT_CALL(*_datastore, get_data(_, _, _, _, _, An<Store::Format>()))
    .WillOnce(DoAll(SetArgReferee<2>(
                    std::string("{\"bindings\": {}, \"subscriptions\" :{}, \"notify_cseq\": \"123\"}")),
                    SetArgReferee<3>(1), // CAS
                    Return(Store::OK)));

  aor_data1 = this->_store->get_aor_data(std::string("2010000001@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 == NULL);
  delete aor_data1;
}


TEST_F(SubscriberDataManagerCorruptDataTest, EmptyJsonObject)
{
  AoRPair* aor_data1;

  EXPECT_CALL(*_datastore, get_data(_, _, _, _, _, An<Store::Format>()))
    .WillOnce(DoAll(SetArgReferee<2>(std::string("{}")),
                    SetArgReferee<3>(1), // CAS
                    Return(Store::OK)));

  aor_data1 = this->_store->get_aor_data(std::string("2010000001@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 == NULL);
  delete aor_data1;
}

/// Test using a Mock Chronos connection that doesn't just swallow requests
class SubscriberDataManagerChronosRequestsTest : public SipTest
{
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
  }

  static void TearDownTestCase()
  {
    SipTest::TearDownTestCase();
  }

  SubscriberDataManagerChronosRequestsTest()
  {
    _chronos_connection = new MockChronosConnection("chronos");
    _datastore = new LocalStore();
    _aor_store = new AstaireAoRStore(_datastore);
    _analytics_logger = new AnalyticsLogger();
    _store = new SubscriberDataManager(_aor_store,
                                       _chronos_connection,
                                       _analytics_logger,
                                       true);
  }

  ~SubscriberDataManagerChronosRequestsTest()
  {
    delete _store; _store = NULL;
    delete _datastore; _datastore = NULL;
    delete _aor_store; _aor_store = NULL;
    delete _chronos_connection; _chronos_connection = NULL;
    delete _analytics_logger; _analytics_logger = NULL;
  }

  MockChronosConnection* _chronos_connection;
  LocalStore* _datastore;
  AstaireAoRStore* _aor_store;
  SubscriberDataManager* _store;
  AnalyticsLogger* _analytics_logger;
};

// Test that adding an AoR to the store generates a chronos POST request, and that
// voiding the AoR (removing all bindings) sends a DELETE request.
TEST_F(SubscriberDataManagerChronosRequestsTest, BasicAoRTimerTest)
{
  AoRPair* aor_data1;
  AoR::Binding* b1;
  AoR::Subscription* s1;
  bool rc;
  int now;

  // Get an initial empty AoR record and add a binding.
  now = time(NULL);
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ(0u, aor_data1->get_current()->bindings().size());
  b1 = aor_data1->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b1->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_private_id = "5102175698@cw-ngv.com";
  b1->_emergency_registration = false;

  // Add a subscription to the record.
  s1 = aor_data1->get_current()->get_subscription("1234");
  s1->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
  s1->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_from_tag = std::string("4321");
  s1->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_to_tag = std::string("1234");
  s1->_cid = std::string("xyzabc@192.91.191.29");
  s1->_route_uris.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  s1->_expires = now + 300;

  // Write the record back to the store.
  EXPECT_CALL(*(this->_chronos_connection), send_post(aor_data1->get_current()->_timer_id, _, _, _, _, _)).
                   WillOnce(DoAll(SetArgReferee<0>("TIMER_ID"),
                                  Return(HTTP_OK)));
  std::string aor = "5102175698@cw-ngv.com";
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri(aor, false);
  aor_data1->get_current()->_associated_uris = associated_uris;

  rc = this->_store->set_aor_data(aor, SubscriberDataManager::EventTrigger::TIMEOUT, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  // Read the record back in and check the timer ID.
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ("TIMER_ID", aor_data1->get_current()->_timer_id);
  EXPECT_EQ(1u, aor_data1->get_current()->bindings().size());
  EXPECT_EQ(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"), aor_data1->get_current()->bindings().begin()->first);
  EXPECT_EQ(1u, aor_data1->get_current()->subscriptions().size());
  EXPECT_EQ(std::string("1234"), aor_data1->get_current()->subscriptions().begin()->first);

  // Remove the binding.
  aor_data1->get_current()->remove_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  EXPECT_EQ(0u, aor_data1->get_current()->bindings().size());

  // Write the record back to the store. Check DELETE request is sent.
  EXPECT_CALL(*(this->_chronos_connection), send_delete(aor_data1->get_current()->_timer_id, _)).Times(1);
  rc = this->_store->set_aor_data(aor, SubscriberDataManager::EventTrigger::TIMEOUT, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;
}

// Test that updating an AoR with extra bindings and subscriptions generates a chronos PUT request.
TEST_F(SubscriberDataManagerChronosRequestsTest, UpdateAoRTimerTest)
{
  AoRPair* aor_data1;
  AoR::Binding* b1;
  std::map<std::string, uint32_t> expected_tags;
  expected_tags["REG"] = 1;
  expected_tags["BIND"] = 0;
  expected_tags["SUB"] = 0;
  bool rc;
  int now;

  // Get an initial empty AoR record and add a binding.
  now = time(NULL);
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ(0u, aor_data1->get_current()->bindings().size());
  b1 = aor_data1->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b1->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_private_id = "5102175698@cw-ngv.com";
  b1->_emergency_registration = false;

  expected_tags["BIND"]++;

  // Write the record back to the store.
  EXPECT_CALL(*(this->_chronos_connection), send_post(_, _, _, _, _, expected_tags)).
                   WillOnce(DoAll(SetArgReferee<0>("TIMER_ID"),
                                  Return(HTTP_OK)));
  std::string aor = "5102175698@cw-ngv.com";
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri(aor, false);
  aor_data1->get_current()->_associated_uris = associated_uris;

  rc = this->_store->set_aor_data(aor, SubscriberDataManager::EventTrigger::USER, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  // Read the record back in and check the timer ID.
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ("TIMER_ID", aor_data1->get_current()->_timer_id);

  // Add a subscription to the record.
  AoR::Subscription* s1;
  s1 = aor_data1->get_current()->get_subscription("1234");
  s1->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
  s1->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_from_tag = std::string("4321");
  s1->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_to_tag = std::string("1234");
  s1->_cid = std::string("xyzabc@192.91.191.29");
  s1->_route_uris.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  s1->_expires = now + 300;

  expected_tags["SUB"]++;

  // Write the record back to the store, expecting a chronos PUT request.
  EXPECT_CALL(*(this->_chronos_connection), send_put(_, _, _, _, _, expected_tags)).
                   WillOnce(Return(HTTP_OK));
  rc = this->_store->set_aor_data(aor, SubscriberDataManager::EventTrigger::USER, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  // Read the record back in and check the timer ID.
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);

  // Add another binding to the record.
  AoR::Binding* b2;
  b2 = aor_data1->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:2"));
  b2->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b2->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b2->_cseq = 17038;
  b2->_expires = now + 300;
  b2->_priority = 0;
  b2->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b2->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b2->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b2->_params["reg-id"] = "1";
  b2->_params["+sip.ice"] = "";
  b2->_private_id = "5102175698@cw-ngv.com";
  b2->_emergency_registration = false;

  expected_tags["BIND"]++;

  // Write the record back to the store, expecting a chronos PUT request.
  EXPECT_CALL(*(this->_chronos_connection), send_put(_, _, _, _, _, expected_tags)).
                   WillOnce(Return(HTTP_OK));
  rc = this->_store->set_aor_data(aor, SubscriberDataManager::EventTrigger::USER, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;
}

// Test that adding and removing an equal number of bindings or subscriptions
// does not generate a chronos request.
TEST_F(SubscriberDataManagerChronosRequestsTest, AoRChangeNoUpdateTimerTest)
{
  AoRPair* aor_data1;
  AoR::Binding* b1;
  AoR::Subscription* s1;
  std::map<std::string, uint32_t> expected_tags;
  expected_tags["REG"] = 1;
  expected_tags["BIND"] = 0;
  expected_tags["SUB"] = 0;
  bool rc;
  int now;

  // Get an initial empty AoR record and add a binding.
  now = time(NULL);
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ(0u, aor_data1->get_current()->bindings().size());
  b1 = aor_data1->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b1->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_private_id = "5102175698@cw-ngv.com";
  b1->_emergency_registration = false;

  expected_tags["BIND"]++;

  // Add a subscription to the record.
  s1 = aor_data1->get_current()->get_subscription("1234");
  s1->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
  s1->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_from_tag = std::string("4321");
  s1->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_to_tag = std::string("1234");
  s1->_cid = std::string("xyzabc@192.91.191.29");
  s1->_route_uris.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  s1->_expires = now + 300;

  expected_tags["SUB"]++;

  // Write the record back to the store.
  EXPECT_CALL(*(this->_chronos_connection), send_post(_, _, _, _, _, expected_tags)).
                   WillOnce(DoAll(SetArgReferee<0>("TIMER_ID"),
                                  Return(HTTP_OK)));
  std::string aor = "5102175698@cw-ngv.com";
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri(aor, false);
  aor_data1->get_current()->_associated_uris = associated_uris;

  rc = this->_store->set_aor_data(aor, SubscriberDataManager::EventTrigger::USER, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  // Read the record back in and check the timer ID.
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ("TIMER_ID", aor_data1->get_current()->_timer_id);

  // Add another binding to the record.
  AoR::Binding* b2;
  b2 = aor_data1->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:2"));
  b2->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b2->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b2->_cseq = 17038;
  b2->_expires = now + 300;
  b2->_priority = 0;
  b2->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b2->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b2->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b2->_params["reg-id"] = "1";
  b2->_params["+sip.ice"] = "";
  b2->_private_id = "5102175698@cw-ngv.com";
  b2->_emergency_registration = false;

  expected_tags["BIND"]++;

  // Add another subscription to the record.
  AoR::Subscription* s2;
  s2 = aor_data1->get_current()->get_subscription("5678");
  s2->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
  s2->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s2->_from_tag = std::string("4321");
  s2->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s2->_to_tag = std::string("1234");
  s2->_cid = std::string("xyzabc@192.91.191.29");
  s2->_route_uris.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  s2->_expires = now + 300;

  expected_tags["SUB"]++;

  // Remove the original binding and subscription.
  aor_data1->get_current()->remove_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  aor_data1->get_current()->remove_subscription(std::string("1234"));
  expected_tags["BIND"]--;  expected_tags["SUB"]--;

  // Write the record back to the store, expecting no chronos PUT request.
  EXPECT_CALL(*(this->_chronos_connection), send_put(_, _, _, _, _, _)).Times(0);
  rc = this->_store->set_aor_data(aor, SubscriberDataManager::EventTrigger::USER, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  // Read the record back in and check the new members were added correctly.
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ(1, aor_data1->get_current()->bindings().size());
  EXPECT_EQ(1, aor_data1->get_current()->subscriptions().size());
  EXPECT_EQ(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:2"), aor_data1->get_current()->bindings().begin()->first);
  EXPECT_EQ(std::string("5678"), aor_data1->get_current()->subscriptions().begin()->first);
  delete aor_data1; aor_data1 = NULL;
}

// Test that changing the soonest expiry time of the AoR members generates a chronos PUT request.
TEST_F(SubscriberDataManagerChronosRequestsTest, AoRNextExpiresUpdateTimerTest)
{
  AoRPair* aor_data1;
  AoR::Binding* b1;
  AoR::Subscription* s1;
  std::map<std::string, uint32_t> expected_tags;
  expected_tags["REG"] = 1;
  expected_tags["BIND"] = 0;
  expected_tags["SUB"] = 0;
  bool rc;
  int now;

  // Get an initial empty AoR record and add a binding.
  now = time(NULL);
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ(0u, aor_data1->get_current()->bindings().size());
  b1 = aor_data1->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b1->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_private_id = "5102175698@cw-ngv.com";
  b1->_emergency_registration = false;

  expected_tags["BIND"]++;

  // Add a subscription to the record.
  s1 = aor_data1->get_current()->get_subscription("1234");
  s1->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
  s1->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_from_tag = std::string("4321");
  s1->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_to_tag = std::string("1234");
  s1->_cid = std::string("xyzabc@192.91.191.29");
  s1->_route_uris.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  s1->_expires = now + 300;

  expected_tags["SUB"]++;

  // Write the record back to the store.
  EXPECT_CALL(*(this->_chronos_connection), send_post(_, (300), _, _, _, expected_tags)).
                   WillOnce(DoAll(SetArgReferee<0>("TIMER_ID"),
                                  Return(HTTP_OK)));
  std::string aor = "5102175698@cw-ngv.com";
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri(aor, false);
  aor_data1->get_current()->_associated_uris = associated_uris;

  rc = this->_store->set_aor_data(aor, SubscriberDataManager::EventTrigger::ADMIN, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  // Read the record back in and check the timer ID.
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ("TIMER_ID", aor_data1->get_current()->_timer_id);

  // Modify the expiry time of the binding to be later. This should not update the timer.
  b1 = aor_data1->get_current()->bindings().begin()->second;
  b1->_expires = now + 500;

  // Write the record back to the store.
  EXPECT_CALL(*(this->_chronos_connection), send_put(_, _, _, _, _, _)).Times(0);
  rc = this->_store->set_aor_data(aor, SubscriberDataManager::EventTrigger::USER, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  // Read the record back in.
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);

  // Modify the expiry time of the binding to be sooner. This should generate an update.
  b1 = aor_data1->get_current()->bindings().begin()->second;
  b1->_expires = now + 200;

  // Write the record back to the store.
  EXPECT_CALL(*(this->_chronos_connection), send_put(_, (200), _, _, _, _)).
                   WillOnce(Return(HTTP_OK));
  rc = this->_store->set_aor_data(aor, SubscriberDataManager::EventTrigger::USER, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  // Read the record back in.
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);

  // Modify the expiry time of the subscription to be sooner. This should also generate an update.
  s1 = aor_data1->get_current()->subscriptions().begin()->second;
  s1->_expires = now + 100;

  // Write the record back to the store.
  EXPECT_CALL(*(this->_chronos_connection), send_put(_, (100), _, _, _, _)).
                   WillOnce(Return(HTTP_OK));
  rc = this->_store->set_aor_data(aor, SubscriberDataManager::EventTrigger::USER, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;
}

// Test that a failed timer POST does not change the timer ID in the AoR.
TEST_F(SubscriberDataManagerChronosRequestsTest, AoRTimerBadRequestNoIDTest)
{
  AoRPair* aor_data1;
  AoR::Binding* b1;
  bool rc;
  int now;

  // Get an initial empty AoR record and add a binding.
  now = time(NULL);
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ(0u, aor_data1->get_current()->bindings().size());
  b1 = aor_data1->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b1->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_private_id = "5102175698@cw-ngv.com";
  b1->_emergency_registration = false;

  // Write the record back to the store.
  EXPECT_CALL(*(this->_chronos_connection), send_post(aor_data1->get_current()->_timer_id, _, _, _, _, _)).
                   WillOnce(DoAll(SetArgReferee<0>("TIMER_ID"),
                                  Return(HTTP_BAD_REQUEST)));
  std::string aor = "5102175698@cw-ngv.com";
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri(aor, false);
  aor_data1->get_current()->_associated_uris = associated_uris;

  rc = this->_store->set_aor_data(aor, SubscriberDataManager::EventTrigger::USER, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  // Read the record back in and check the timer ID was not saved off.
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ("", aor_data1->get_current()->_timer_id);

  delete aor_data1; aor_data1 = NULL;
}

TEST_F(BasicSubscriberDataManagerTest, AoRComparisonCreatedBinding)
{
  std::string aor_id = "5102175698@cw-ngv.com";
  int now = time(NULL);
  AoR* orig_aor = new AoR(aor_id);
  AoR* current_aor = new AoR(aor_id);

  // Add a binding to the current AoR
  std::string b_id = "urn:uuid:00000000-0000-0000-0000-b4dd32817622:1";
  AoR::Binding* b1 = current_aor->get_binding(b_id);
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b1->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_private_id = "5102175698@cw-ngv.com";
  b1->_emergency_registration = false;

  // Create the AoRPair
  AoRPair* aor_pair = new AoRPair(orig_aor, current_aor);

  // Check the 'get_updated_<bindings/subscriptions>' function returns the binding
  AoR::Bindings updated_bindings = aor_pair->get_updated_bindings();
  ASSERT_TRUE(updated_bindings.find( b_id ) != updated_bindings.end());

  delete aor_pair; aor_pair = NULL;
}

TEST_F(BasicSubscriberDataManagerTest, AoRComparisonUpdatedBinding)
{
  std::string aor_id = "5102175698@cw-ngv.com";
  int now = time(NULL);
  AoR* orig_aor = new AoR(aor_id);
  AoR* current_aor = new AoR(aor_id);

  // Add a binding to the original AoR
  std::string b_id = "urn:uuid:00000000-0000-0000-0000-b4dd32817622:1";
  AoR::Binding* b1 = orig_aor->get_binding(b_id);
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b1->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_private_id = "5102175698@cw-ngv.com";
  b1->_emergency_registration = false;

  // Add the same binding, but with an updated expiry, to the current AoR
  AoR::Binding* b2 = current_aor->get_binding(b_id);
  b2->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b2->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b2->_cseq = 17038;
  b2->_expires = now + 600;
  b2->_priority = 0;
  b2->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b2->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b2->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b2->_params["reg-id"] = "1";
  b2->_params["+sip.ice"] = "";
  b2->_private_id = "5102175698@cw-ngv.com";
  b2->_emergency_registration = false;


  // Create the AoRPair
  AoRPair* aor_pair = new AoRPair(orig_aor, current_aor);

  // Check that `get_updated_bindings` returns the updated binding
  AoR::Bindings updated_bindings = aor_pair->get_updated_bindings();
  ASSERT_TRUE(updated_bindings.find( b_id ) != updated_bindings.end());
  EXPECT_EQ((now + 600), updated_bindings[b_id]->_expires);

  delete aor_pair; aor_pair = NULL;
}

TEST_F(BasicSubscriberDataManagerTest, AoRComparisonDeletedBinding)
{
  std::string aor_id = "5102175698@cw-ngv.com";
  int now = time(NULL);
  AoR* orig_aor = new AoR(aor_id);
  AoR* current_aor = new AoR(aor_id);

  // Add a binding to the original AoR only
  std::string b_id = "urn:uuid:00000000-0000-0000-0000-b4dd32817622:1";
  AoR::Binding* b1 = orig_aor->get_binding(b_id);
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b1->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_private_id = "5102175698@cw-ngv.com";
  b1->_emergency_registration = false;

  // Create the AoRPair
  AoRPair* aor_pair = new AoRPair(orig_aor, current_aor);

  // Check that `get_removed_bindings` returns the 'deleted' binding
  AoR::Bindings removed_bindings = aor_pair->get_removed_bindings();
  ASSERT_TRUE(removed_bindings.find( b_id ) != removed_bindings.end());

  delete aor_pair; aor_pair = NULL;
}

TEST_F(BasicSubscriberDataManagerTest, AoRComparisonUnchangedBinding)
{
  std::string aor_id = "5102175698@cw-ngv.com";
  int now = time(NULL);
  AoR* orig_aor = new AoR(aor_id);
  AoR* current_aor = new AoR(aor_id);

  // Add a binding to the original AoR
  std::string b_id = "urn:uuid:00000000-0000-0000-0000-b4dd32817622:1";
  AoR::Binding* b1 = orig_aor->get_binding(b_id);
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b1->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_private_id = "5102175698@cw-ngv.com";
  b1->_emergency_registration = false;

  // Add the same binding to the current AoR
  AoR::Binding* b2 = current_aor->get_binding(b_id);
  b2->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b2->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b2->_cseq = 17038;
  b2->_expires = now + 300;
  b2->_priority = 0;
  b2->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b2->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b2->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b2->_params["reg-id"] = "1";
  b2->_params["+sip.ice"] = "";
  b2->_private_id = "5102175698@cw-ngv.com";
  b2->_emergency_registration = false;

  // Create the AoRPair
  AoRPair* aor_pair = new AoRPair(orig_aor, current_aor);

  // Check that `get_updated_bindings` and `get_removed_bindings` return nothing
  AoR::Bindings updated_bindings = aor_pair->get_updated_bindings();
  ASSERT_TRUE(updated_bindings.find( b_id ) == updated_bindings.end());
  AoR::Bindings removed_bindings = aor_pair->get_removed_bindings();
  ASSERT_TRUE(removed_bindings.find( b_id ) == removed_bindings.end());

  delete aor_pair; aor_pair = NULL;
}

TEST_F(BasicSubscriberDataManagerTest, AoRComparisonCreatedSubscription)
{
  std::string aor_id = "5102175698@cw-ngv.com";
  int now = time(NULL);
  AoR* orig_aor = new AoR(aor_id);
  AoR* current_aor = new AoR(aor_id);

  // Add a binding and subscription to the current AoR
  std::string b_id = "urn:uuid:00000000-0000-0000-0000-b4dd32817622:1";
  AoR::Binding* b1 = current_aor->get_binding(b_id);
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b1->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_private_id = "5102175698@cw-ngv.com";
  b1->_emergency_registration = false;

  std::string s_id = "1234";
  AoR::Subscription* s1 = current_aor->get_subscription(s_id);
  s1->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
  s1->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_from_tag = std::string("4321");
  s1->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_to_tag = std::string("1234");
  s1->_cid = std::string("xyzabc@192.91.191.29");
  s1->_route_uris.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  s1->_expires = now + 300;

  // Create the AoRPair
  AoRPair* aor_pair = new AoRPair(orig_aor, current_aor);

  // Check that `get_updated_subscriptions` returns the new subscription
  AoR::Subscriptions updated_subscriptions = aor_pair->get_updated_subscriptions();
  ASSERT_TRUE(updated_subscriptions.find( s_id ) != updated_subscriptions.end());

  delete aor_pair; aor_pair = NULL;
}

TEST_F(BasicSubscriberDataManagerTest, AoRComparisonUpdatedSubscription)
{
  std::string aor_id = "5102175698@cw-ngv.com";
  int now = time(NULL);
  AoR* orig_aor = new AoR(aor_id);
  AoR* current_aor = new AoR(aor_id);

  // Add a binding and subscription to the original AoR
  std::string b_id = "urn:uuid:00000000-0000-0000-0000-b4dd32817622:1";
  AoR::Binding* b1 = orig_aor->get_binding(b_id);
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b1->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_private_id = "5102175698@cw-ngv.com";
  b1->_emergency_registration = false;

  std::string s_id = "1234";
  AoR::Subscription* s1 = orig_aor->get_subscription(s_id);
  s1->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
  s1->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_from_tag = std::string("4321");
  s1->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_to_tag = std::string("1234");
  s1->_cid = std::string("xyzabc@192.91.191.29");
  s1->_route_uris.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  s1->_expires = now + 300;

  // Add the same binding and subscription to the current AoR, but with updated
  // expiry time on the subscription.
  AoR::Binding* b2 = current_aor->get_binding(b_id);
  b2->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b2->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b2->_cseq = 17038;
  b2->_expires = now + 300;
  b2->_priority = 0;
  b2->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b2->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b2->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b2->_params["reg-id"] = "1";
  b2->_params["+sip.ice"] = "";
  b2->_private_id = "5102175698@cw-ngv.com";
  b2->_emergency_registration = false;

  AoR::Subscription* s2 = current_aor->get_subscription(s_id);
  s2->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
  s2->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s2->_from_tag = std::string("4321");
  s2->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s2->_to_tag = std::string("1234");
  s2->_cid = std::string("xyzabc@192.91.191.29");
  s2->_route_uris.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  s2->_expires = now + 600;

  // Create the AoRPair
  AoRPair* aor_pair = new AoRPair(orig_aor, current_aor);

  // Check that `get_updated_subscriptions` returns the updated subscription
  AoR::Subscriptions updated_subscriptions = aor_pair->get_updated_subscriptions();
  ASSERT_TRUE(updated_subscriptions.find( s_id ) != updated_subscriptions.end());
  EXPECT_EQ((now + 600), updated_subscriptions[s_id]->_expires);

  delete aor_pair; aor_pair = NULL;
}

TEST_F(BasicSubscriberDataManagerTest, AoRComparisonDeletedSubscription)
{
  std::string aor_id = "5102175698@cw-ngv.com";
  int now = time(NULL);
  AoR* orig_aor = new AoR(aor_id);
  AoR* current_aor = new AoR(aor_id);

  // Add a binding and subscription to the original AoR
  std::string b_id = "urn:uuid:00000000-0000-0000-0000-b4dd32817622:1";
  AoR::Binding* b1 = orig_aor->get_binding(b_id);
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b1->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_private_id = "5102175698@cw-ngv.com";
  b1->_emergency_registration = false;

  std::string s_id = "1234";
  AoR::Subscription* s1 = orig_aor->get_subscription(s_id);
  s1->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
  s1->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_from_tag = std::string("4321");
  s1->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_to_tag = std::string("1234");
  s1->_cid = std::string("xyzabc@192.91.191.29");
  s1->_route_uris.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  s1->_expires = now + 300;

  // Add the same binding to the current AoR, but not the subscription
  AoR::Binding* b2 = current_aor->get_binding(b_id);
  b2->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b2->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b2->_cseq = 17038;
  b2->_expires = now + 300;
  b2->_priority = 0;
  b2->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b2->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b2->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b2->_params["reg-id"] = "1";
  b2->_params["+sip.ice"] = "";
  b2->_private_id = "5102175698@cw-ngv.com";
  b2->_emergency_registration = false;

  // Create the AoRPair
  AoRPair* aor_pair = new AoRPair(orig_aor, current_aor);

  // Check that `get_removed_subscriptions` returns the 'deleted' subscription
  AoR::Subscriptions removed_subscriptions = aor_pair->get_removed_subscriptions();
  ASSERT_TRUE(removed_subscriptions.find( s_id ) != removed_subscriptions.end());

  delete aor_pair; aor_pair = NULL;
}

TEST_F(BasicSubscriberDataManagerTest, AoRComparisonUnchangedSubscription)
{
  std::string aor_id = "5102175698@cw-ngv.com";
  int now = time(NULL);
  AoR* orig_aor = new AoR(aor_id);
  AoR* current_aor = new AoR(aor_id);

  // Add a binding and subscription to the original AoR
  std::string b_id = "urn:uuid:00000000-0000-0000-0000-b4dd32817622:1";
  AoR::Binding* b1 = orig_aor->get_binding(b_id);
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b1->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_private_id = "5102175698@cw-ngv.com";
  b1->_emergency_registration = false;

  std::string s_id = "1234";
  AoR::Subscription* s1 = orig_aor->get_subscription(s_id);
  s1->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
  s1->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_from_tag = std::string("4321");
  s1->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_to_tag = std::string("1234");
  s1->_cid = std::string("xyzabc@192.91.191.29");
  s1->_route_uris.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  s1->_expires = now + 300;

  // Add the same binding and subscription to the current AoR
  AoR::Binding* b2 = current_aor->get_binding(b_id);
  b2->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b2->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b2->_cseq = 17038;
  b2->_expires = now + 300;
  b2->_priority = 0;
  b2->_path_uris.push_back(std::string("sip:abcdefgh@bono-1.cw-ngv.com;lr"));
  b2->_path_headers.push_back(std::string("\"Bob\" <sip:abcdefgh@bono-1.cw-ngv.com;lr>;tag=6ht7"));
  b2->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b2->_params["reg-id"] = "1";
  b2->_params["+sip.ice"] = "";
  b2->_private_id = "5102175698@cw-ngv.com";
  b2->_emergency_registration = false;

  AoR::Subscription* s2 = current_aor->get_subscription(s_id);
  s2->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
  s2->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s2->_from_tag = std::string("4321");
  s2->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s2->_to_tag = std::string("1234");
  s2->_cid = std::string("xyzabc@192.91.191.29");
  s2->_route_uris.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  s2->_expires = now + 300;

  // Create the AoRPair
  AoRPair* aor_pair = new AoRPair(orig_aor, current_aor);

  // Check that `get_updated_subscriptions` and `get_removed_subscriptions` returns nothing
  AoR::Subscriptions updated_subscriptions = aor_pair->get_updated_subscriptions();
  ASSERT_TRUE(updated_subscriptions.find( s_id ) == updated_subscriptions.end());
  AoR::Subscriptions removed_subscriptions = aor_pair->get_removed_subscriptions();
  ASSERT_TRUE(removed_subscriptions.find( s_id ) == removed_subscriptions.end());

  delete aor_pair; aor_pair = NULL;
}
