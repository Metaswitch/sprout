/**
 * @file subscriber_data_manager_test.cpp
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


#include <string>
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "siptest.hpp"
#include "stack.h"
#include "utils.h"
#include "pjutils.h"
#include "sas.h"
#include "localstore.h"
#include "subscriber_data_manager.h"
#include "test_utils.hpp"
#include "test_interposer.hpp"
#include "fakechronosconnection.hpp"
#include "mock_chronos_connection.h"
#include "mock_store.h"
#include "mock_analytics_logger.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgReferee;

// These tests use "typed tests" to run the same tests over different
// (de)serializers. For more information see:
// https://code.google.com/p/googletest/wiki/AdvancedGuide#Typed_Tests

/// The types of (de)serializer that we want to test.
typedef ::testing::Types<
  SubscriberDataManager::BinarySerializerDeserializer,
  SubscriberDataManager::JsonSerializerDeserializer
> SerializerDeserializerTypes;

/// Fixture for BasicSubscriberDataManagerTest.  This uses a single SubscriberDataManager, configured to
/// use exactly one (de)serializer.
///
/// The fixture is a template, parameterized over the different types of
/// (de)serializer.
template<class T>
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
    _analytics_logger = new MockAnalyticsLogger();

    SubscriberDataManager::SerializerDeserializer* serializer = new T();
    std::vector<SubscriberDataManager::SerializerDeserializer*> deserializers = {
      new T()
    };

    _store = new SubscriberDataManager(_datastore,
                                       serializer,
                                       deserializers,
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
    delete _datastore; _datastore = NULL;
    delete _chronos_connection; _chronos_connection = NULL;
    delete _analytics_logger; _analytics_logger = NULL;
  }

  // Fixture variables.  Note that as the fixture is a C++ template, these must
  // be accessed in the individual tests using the this pointer (e.g. use
  // `this->store` rather than `_store`).
  FakeChronosConnection* _chronos_connection;
  LocalStore* _datastore;
  SubscriberDataManager* _store;
  MockAnalyticsLogger* _analytics_logger;
};

// BasicSubscriberDataManagerTest is parameterized over these types.
TYPED_TEST_CASE(BasicSubscriberDataManagerTest, SerializerDeserializerTypes);


TYPED_TEST(BasicSubscriberDataManagerTest, BindingTests)
{
  SubscriberDataManager::AoRPair* aor_data1;
  SubscriberDataManager::AoR::Binding* b1;
  bool rc;
  int now;

  // Get an initial empty AoR record and add a binding.
  now = time(NULL);
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  aor_data1->get_current()->_timer_id = "AoRtimer";
  EXPECT_EQ(0u, aor_data1->get_current()->bindings().size());
  b1 = aor_data1->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_timer_id = "shouldbecomeDeprecated";
  b1->_priority = 0;
  b1->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_private_id = "5102175698@cw-ngv.com";
  b1->_emergency_registration = false;

  // Add the AoR record to the store.
  std::vector<std::string> irs_impus;
  irs_impus.push_back("5102175698@cw-ngv.com");
  EXPECT_CALL(*(this->_analytics_logger),
              registration("5102175698@cw-ngv.com",
                           "urn:uuid:00000000-0000-0000-0000-b4dd32817622:1",
                           "<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>",
                           300)).Times(1);
  rc = this->_store->set_aor_data(irs_impus[0], irs_impus, aor_data1, 0);
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
  EXPECT_EQ(std::string("Deprecated"), b1->_timer_id);
  EXPECT_EQ(1u, b1->_path_headers.size());
  EXPECT_EQ(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"), b1->_path_headers.front());
  EXPECT_EQ(3u, b1->_params.size());
  EXPECT_EQ(std::string("\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\""), b1->_params["+sip.instance"]);
  EXPECT_EQ(std::string("1"), b1->_params["reg-id"]);
  EXPECT_EQ(std::string(""), b1->_params["+sip.ice"]);
  EXPECT_EQ(std::string("5102175698@cw-ngv.com"), b1->_private_id);
  EXPECT_EQ(false, b1->_emergency_registration);

  // Update AoR record in the store and check it.
  b1->_cseq = 17039;
  rc = this->_store->set_aor_data(irs_impus[0], irs_impus, aor_data1, 0);
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
  EXPECT_EQ(now + 300, b1->_expires);
  EXPECT_EQ(0, b1->_priority);

  // Update AoR record again in the store and check it, this time using get_binding.
  b1->_cseq = 17040;
  rc = this->_store->set_aor_data(irs_impus[0], irs_impus, aor_data1, 0);
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
  EXPECT_EQ(now + 300, b1->_expires);
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
  rc = this->_store->set_aor_data(irs_impus[0], irs_impus, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ(0u, aor_data1->get_current()->bindings().size());

  delete aor_data1; aor_data1 = NULL;
}


TYPED_TEST(BasicSubscriberDataManagerTest, SubscriptionTests)
{
  SubscriberDataManager::AoRPair* aor_data1;
  SubscriberDataManager::AoR::Binding* b1;
  SubscriberDataManager::AoR::Subscription* s1;
  bool rc;
  int now;

  // Get an initial empty AoR record and add a binding.
  now = time(NULL);
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  aor_data1->get_current()->_timer_id = "AoRtimer";
  EXPECT_EQ(0u, aor_data1->get_current()->bindings().size());
  b1 = aor_data1->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_timer_id = "shouldbecomeDeprecated";
  b1->_priority = 0;
  b1->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_private_id = "5102175698@cw-ngv.com";
  b1->_emergency_registration = false;

  // Add the AoR record to the store.
  std::vector<std::string> irs_impus;
  irs_impus.push_back("5102175698@cw-ngv.com");
  rc = this->_store->set_aor_data(irs_impus[0], irs_impus, aor_data1, 0);
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
  s1->_timer_id = "shouldbecomeDeprecated";

  // Write the record back to the store.
  rc = this->_store->set_aor_data(irs_impus[0], irs_impus, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

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
  EXPECT_EQ("Deprecated", s1->_timer_id);

  // Remove the subscription.
  aor_data1->get_current()->remove_subscription(std::string("1234"));
  EXPECT_EQ(0u, aor_data1->get_current()->subscriptions().size());

  delete aor_data1; aor_data1 = NULL;
}

TYPED_TEST(BasicSubscriberDataManagerTest, CopyTests)
{
  SubscriberDataManager::AoRPair* aor_data1;
  SubscriberDataManager::AoR::Binding* b1;
  SubscriberDataManager::AoR::Subscription* s1;
  int now;

  // Get an initial empty AoR record.
  now = time(NULL);
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  aor_data1->get_current()->_timer_id = "AoRtimer";
  EXPECT_EQ(0u, aor_data1->get_current()->bindings().size());
  EXPECT_EQ(0u, aor_data1->get_current()->subscriptions().size());

  // Add a binding to the record.
  b1 = aor_data1->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  EXPECT_EQ(1u, aor_data1->get_current()->bindings().size());
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_timer_id = "shouldbecomeDeprecated";
  b1->_priority = 0;
  b1->_path_headers.push_back(std::string("<sip:abcdefgh@bono1.homedomain;lr>"));
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
  SubscriberDataManager::AoR* copy = new SubscriberDataManager::AoR(*aor_data1->get_current());
  EXPECT_EQ("AoRtimer", copy->_timer_id);
  EXPECT_EQ(1u, copy->bindings().size());
  EXPECT_EQ(1u, copy->subscriptions().size());
  EXPECT_EQ(1, copy->_notify_cseq);
  EXPECT_EQ((uint64_t)0, copy->_cas);
  EXPECT_EQ("5102175698@cw-ngv.com", copy->_uri);
  delete copy; copy = NULL;

  // Test AoR assignment.
  copy = new SubscriberDataManager::AoR("sip:name@example.com");
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


TYPED_TEST(BasicSubscriberDataManagerTest, ExpiryTests)
{
  // The expiry tests require pjsip, so initialise for this test
  SubscriberDataManager::AoRPair* aor_data1;
  SubscriberDataManager::AoR::Binding* b1;
  SubscriberDataManager::AoR::Binding* b2;
  SubscriberDataManager::AoR::Subscription* s1;
  SubscriberDataManager::AoR::Subscription* s2;
  bool rc;
  int now;

  // Create an empty AoR record.
  now = time(NULL);
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  aor_data1->get_current()->_timer_id = "AoRtimer";
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
  b1->_timer_id = "shouldbecomeDeprecated";
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
  b2->_timer_id = "shouldbecomeDeprecated";
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
  s1->_timer_id = "shouldbecomeDeprecated";
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
  s2->_timer_id = "shouldbecomeDeprecated";

  // Write the record to the store.
  std::vector<std::string> irs_impus;
  irs_impus.push_back("5102175698@cw-ngv.com");
  rc = this->_store->set_aor_data(irs_impus[0], irs_impus, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

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

/// Fixture for testing converting between data formats. Thsi creates two
/// SubscriberDataManagers:
/// 1).  One that only uses one (de)serializer.
/// 2).  One that loads all (de)serializers.
///
/// The fixture is a template, parameterized over the different types of
/// (de)serializer that store 1). uses.
template<class T>
class MultiFormatSubscriberDataManagerTest : public ::testing::Test
{
  void SetUp()
  {
    _chronos_connection = new FakeChronosConnection();
    _datastore = new LocalStore();
    _analytics_logger = new MockAnalyticsLogger();

    {
      SubscriberDataManager::SerializerDeserializer* serializer = new T();
      std::vector<SubscriberDataManager::SerializerDeserializer*> deserializers = {
        new T()
      };

      _single_store = new SubscriberDataManager(_datastore,
                                                serializer,
                                                deserializers,
                                                _chronos_connection,
                                                _analytics_logger,
                                                true);
    }
    {
      SubscriberDataManager::SerializerDeserializer* serializer =
        new SubscriberDataManager::JsonSerializerDeserializer();
      std::vector<SubscriberDataManager::SerializerDeserializer*> deserializers = {
        new SubscriberDataManager::JsonSerializerDeserializer(),
        new SubscriberDataManager::BinarySerializerDeserializer(),
      };

      _multi_store = new SubscriberDataManager(_datastore,
                                               serializer,
                                               deserializers,
                                               _chronos_connection,
                                               _analytics_logger,
                                               true);
    }
  }

  void TearDown()
  {
    delete _multi_store; _multi_store = NULL;
    delete _single_store; _single_store = NULL;
    delete _datastore; _datastore = NULL;
    delete _chronos_connection; _chronos_connection = NULL;
    delete _analytics_logger; _analytics_logger = NULL;
  }

  FakeChronosConnection* _chronos_connection;
  LocalStore* _datastore;
  SubscriberDataManager* _multi_store;
  SubscriberDataManager* _single_store;
  MockAnalyticsLogger* _analytics_logger;
};

// MultiFormatSubscriberDataManagerTest is parameterized over these types.
TYPED_TEST_CASE(MultiFormatSubscriberDataManagerTest, SerializerDeserializerTypes);

TYPED_TEST(MultiFormatSubscriberDataManagerTest, AllFormatsCanBeRead)
{
  SubscriberDataManager::AoRPair* aor_data1;
  SubscriberDataManager::AoR::Binding* b1;
  bool rc;
  int now;

  // Get an initial empty AoR record and add a binding.
  now = time(NULL);
  aor_data1 = this->_single_store->get_aor_data(std::string("2010000001@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  b1 = aor_data1->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817621:1"));
  b1->_uri = std::string("<sip:2010000001@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("cid1");
  b1->_cseq = 1000;
  b1->_expires = now + 300;
  b1->_timer_id = "shouldbecomeDeprecated";
  b1->_priority = 0;
  b1->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817621>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_private_id = "2010000001@cw-ngv.com";
  b1->_emergency_registration = false;

  // Add the AoR record to the store.
  std::vector<std::string> irs_impus;
  irs_impus.push_back("2010000001@cw-ngv.com");
  rc = this->_single_store->set_aor_data(irs_impus[0], irs_impus, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  aor_data1 = this->_multi_store->get_aor_data(std::string("2010000001@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ(1u, aor_data1->get_current()->bindings().size());
  b1 = aor_data1->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817621:1"));
  EXPECT_EQ(std::string("cid1"), b1->_cid);

  EXPECT_EQ(1u, b1->_path_headers.size());
  EXPECT_EQ(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"), b1->_path_headers.front());

  EXPECT_EQ(3u, b1->_params.size());
  EXPECT_EQ(std::string("1"), b1->_params["reg-id"]);
  delete aor_data1; aor_data1 = NULL;
}

/// Fixtures for tests that bad JSON documents are handled correctly, even when
/// mutliple deserializers are loaded.
class SubscriberDataManagerCorruptDataTest : public ::testing::Test
{
  void SetUp()
  {
    _chronos_connection = new FakeChronosConnection();
    _datastore = new MockStore();
    _analytics_logger = new MockAnalyticsLogger();

    {
      SubscriberDataManager::SerializerDeserializer* serializer =
        new SubscriberDataManager::JsonSerializerDeserializer();
      std::vector<SubscriberDataManager::SerializerDeserializer*> deserializers = {
        new SubscriberDataManager::JsonSerializerDeserializer(),
        new SubscriberDataManager::BinarySerializerDeserializer(),
      };

      _store = new SubscriberDataManager(_datastore,
                                         serializer,
                                         deserializers,
                                         _chronos_connection,
                                         _analytics_logger,
                                         true);
    }
  }

  void TearDown()
  {
    delete _store; _store = NULL;
    delete _datastore; _datastore = NULL;
    delete _chronos_connection; _chronos_connection = NULL;
    delete _analytics_logger; _analytics_logger = NULL;
  }

  FakeChronosConnection* _chronos_connection;
  MockStore* _datastore;
  SubscriberDataManager* _store;
  MockAnalyticsLogger* _analytics_logger;
};


TEST_F(SubscriberDataManagerCorruptDataTest, BadlyFormedJson)
{
  SubscriberDataManager::AoRPair* aor_data1;

  EXPECT_CALL(*_datastore, get_data(_, _, _, _, _))
    .WillOnce(DoAll(SetArgReferee<2>(std::string("{\"bindings\": {}")),
                    SetArgReferee<3>(1), // CAS
                    Return(Store::OK)));

  aor_data1 = this->_store->get_aor_data(std::string("2010000001@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 == NULL);
  delete aor_data1;
}


TEST_F(SubscriberDataManagerCorruptDataTest, SemanticallyInvalidJson)
{
  SubscriberDataManager::AoRPair* aor_data1;

  EXPECT_CALL(*_datastore, get_data(_, _, _, _, _))
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
  SubscriberDataManager::AoRPair* aor_data1;

  EXPECT_CALL(*_datastore, get_data(_, _, _, _, _))
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
    _analytics_logger = new MockAnalyticsLogger();

    SubscriberDataManager::SerializerDeserializer* serializer =
      new SubscriberDataManager::JsonSerializerDeserializer();
    std::vector<SubscriberDataManager::SerializerDeserializer*> deserializers = {
      new SubscriberDataManager::JsonSerializerDeserializer(),
    };

    _store = new SubscriberDataManager(_datastore,
                                       serializer,
                                       deserializers,
                                       _chronos_connection,
                                       _analytics_logger,
                                       true);
  }

  ~SubscriberDataManagerChronosRequestsTest()
  {
    delete _store; _store = NULL;
    delete _datastore; _datastore = NULL;
    delete _chronos_connection; _chronos_connection = NULL;
    delete _analytics_logger; _analytics_logger = NULL;
  }

  MockChronosConnection* _chronos_connection;
  LocalStore* _datastore;
  SubscriberDataManager* _store;
  MockAnalyticsLogger* _analytics_logger;
};

// Test that adding an AoR to the store generates a chronos POST request, and that
// voiding the AoR (removing all bindings) sends a DELETE request.
TEST_F(SubscriberDataManagerChronosRequestsTest, BasicAoRTimerTest)
{
  SubscriberDataManager::AoRPair* aor_data1;
  SubscriberDataManager::AoR::Binding* b1;
  SubscriberDataManager::AoR::Subscription* s1;
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
  b1->_timer_id = "shouldbecomeDeprecated";
  b1->_priority = 0;
  b1->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
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
  std::vector<std::string> irs_impus;
  irs_impus.push_back("5102175698@cw-ngv.com");
  rc = this->_store->set_aor_data(irs_impus[0], irs_impus, aor_data1, 0);
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
  rc = this->_store->set_aor_data(irs_impus[0], irs_impus, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;
}

// Test that updating an AoR with extra bindings and subscriptions generates a chronos PUT request.
TEST_F(SubscriberDataManagerChronosRequestsTest, UpdateAoRTimerTest)
{
  SubscriberDataManager::AoRPair* aor_data1;
  SubscriberDataManager::AoR::Binding* b1;
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
  b1->_timer_id = "shouldbecomeDeprecated";
  b1->_priority = 0;
  b1->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
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
  std::vector<std::string> irs_impus;
  irs_impus.push_back("5102175698@cw-ngv.com");
  rc = this->_store->set_aor_data(irs_impus[0], irs_impus, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  // Read the record back in and check the timer ID.
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ("TIMER_ID", aor_data1->get_current()->_timer_id);

  // Add a subscription to the record.
  SubscriberDataManager::AoR::Subscription* s1;
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
  rc = this->_store->set_aor_data(irs_impus[0], irs_impus, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  // Read the record back in and check the timer ID.
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);

  // Add another binding to the record.
  SubscriberDataManager::AoR::Binding* b2;
  b2 = aor_data1->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:2"));
  b2->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b2->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b2->_cseq = 17038;
  b2->_expires = now + 300;
  b2->_timer_id = "shouldbecomeDeprecated";
  b2->_priority = 0;
  b2->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  b2->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b2->_params["reg-id"] = "1";
  b2->_params["+sip.ice"] = "";
  b2->_private_id = "5102175698@cw-ngv.com";
  b2->_emergency_registration = false;

  expected_tags["BIND"]++;

  // Write the record back to the store, expecting a chronos PUT request.
  EXPECT_CALL(*(this->_chronos_connection), send_put(_, _, _, _, _, expected_tags)).
                   WillOnce(Return(HTTP_OK));
  rc = this->_store->set_aor_data(irs_impus[0], irs_impus, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;
}

// Test that adding and removing an equal number of bindings or subscriptions
// does not generate a chronos request.
TEST_F(SubscriberDataManagerChronosRequestsTest, AoRChangeNoUpdateTimerTest)
{
  SubscriberDataManager::AoRPair* aor_data1;
  SubscriberDataManager::AoR::Binding* b1;
  SubscriberDataManager::AoR::Subscription* s1;
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
  b1->_timer_id = "shouldbecomeDeprecated";
  b1->_priority = 0;
  b1->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
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
  std::vector<std::string> irs_impus;
  irs_impus.push_back("5102175698@cw-ngv.com");
  rc = this->_store->set_aor_data(irs_impus[0], irs_impus, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  // Read the record back in and check the timer ID.
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ("TIMER_ID", aor_data1->get_current()->_timer_id);

  // Add another binding to the record.
  SubscriberDataManager::AoR::Binding* b2;
  b2 = aor_data1->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:2"));
  b2->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b2->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b2->_cseq = 17038;
  b2->_expires = now + 300;
  b2->_timer_id = "shouldbecomeDeprecated";
  b2->_priority = 0;
  b2->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  b2->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b2->_params["reg-id"] = "1";
  b2->_params["+sip.ice"] = "";
  b2->_private_id = "5102175698@cw-ngv.com";
  b2->_emergency_registration = false;

  expected_tags["BIND"]++;

  // Add another subscription to the record.
  SubscriberDataManager::AoR::Subscription* s2;
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
  rc = this->_store->set_aor_data(irs_impus[0], irs_impus, aor_data1, 0);
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
  SubscriberDataManager::AoRPair* aor_data1;
  SubscriberDataManager::AoR::Binding* b1;
  SubscriberDataManager::AoR::Subscription* s1;
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
  b1->_timer_id = "shouldbecomeDeprecated";
  b1->_priority = 0;
  b1->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
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
  std::vector<std::string> irs_impus;
  irs_impus.push_back("5102175698@cw-ngv.com");
  rc = this->_store->set_aor_data(irs_impus[0], irs_impus, aor_data1, 0);
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
  rc = this->_store->set_aor_data(irs_impus[0], irs_impus, aor_data1, 0);
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
  rc = this->_store->set_aor_data(irs_impus[0], irs_impus, aor_data1, 0);
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
  rc = this->_store->set_aor_data(irs_impus[0], irs_impus, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;
}

// Test that a failed timer POST does not change the timer ID in the AoR.
TEST_F(SubscriberDataManagerChronosRequestsTest, AoRTimerBadRequestNoIDTest)
{
  SubscriberDataManager::AoRPair* aor_data1;
  SubscriberDataManager::AoR::Binding* b1;
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
  b1->_timer_id = "shouldbecomeDeprecated";
  b1->_priority = 0;
  b1->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_private_id = "5102175698@cw-ngv.com";
  b1->_emergency_registration = false;

  // Write the record back to the store.
  EXPECT_CALL(*(this->_chronos_connection), send_post(aor_data1->get_current()->_timer_id, _, _, _, _, _)).
                   WillOnce(DoAll(SetArgReferee<0>("TIMER_ID"),
                                  Return(HTTP_BAD_REQUEST)));
  std::vector<std::string> irs_impus;
  irs_impus.push_back("5102175698@cw-ngv.com");
  rc = this->_store->set_aor_data(irs_impus[0], irs_impus, aor_data1, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  // Read the record back in and check the timer ID was not saved off.
  aor_data1 = this->_store->get_aor_data(std::string("5102175698@cw-ngv.com"), 0);
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ("", aor_data1->get_current()->_timer_id);

  delete aor_data1; aor_data1 = NULL;
}
