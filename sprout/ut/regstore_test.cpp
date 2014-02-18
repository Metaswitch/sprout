/**
 * @file regstore_test.cpp UT for Sprout registration store.
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
#include <json/reader.h>

#include "stack.h"
#include "utils.h"
#include "sas.h"
#include "localstore.h"
#include "regstore.h"
#include "fakelogger.hpp"
#include "test_utils.hpp"
#include "test_interposer.hpp"
#include "fakechronosconnection.hpp"

using namespace std;

/// Fixture for RegStoreTest.
class RegStoreTest : public ::testing::Test
{
  FakeLogger _log;

  RegStoreTest()
  {
  }

  virtual ~RegStoreTest()
  {
  }
};


TEST_F(RegStoreTest, BindingTests)
{
  RegStore::AoR* aor_data1;
  RegStore::AoR::Binding* b1;
  bool rc;
  int now;

  // Create a RegStore instance backed by a local data store.
  ChronosConnection* chronos_connection = new FakeChronosConnection();
  LocalStore* datastore = new LocalStore();
  RegStore* store = new RegStore(datastore, chronos_connection);

  // Get an initial empty AoR record and add a binding.
  now = time(NULL);
  aor_data1 = store->get_aor_data(std::string("5102175698@cw-ngv.com"));
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ(0u, aor_data1->bindings().size());
  b1 = aor_data1->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_timer_id = "00000000000";
  b1->_priority = 0;
  b1->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  b1->_params.push_back(std::make_pair("+sip.instance", "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\""));
  b1->_params.push_back(std::make_pair("reg-id", "1"));
  b1->_params.push_back(std::make_pair("+sip.ice", ""));

  // Add the AoR record to the store.
  rc = store->set_aor_data(std::string("5102175698@cw-ngv.com"), aor_data1, false);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  // Get the AoR record from the store.
  aor_data1 = store->get_aor_data(std::string("5102175698@cw-ngv.com"));
  EXPECT_EQ(1u, aor_data1->bindings().size());
  EXPECT_EQ(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"), aor_data1->bindings().begin()->first);
  b1 = aor_data1->bindings().begin()->second;
  EXPECT_EQ(std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>"), b1->_uri);
  EXPECT_EQ(std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq"), b1->_cid);
  EXPECT_EQ(17038, b1->_cseq);
  EXPECT_EQ(now + 300, b1->_expires);
  EXPECT_EQ(0, b1->_priority);

  // Update AoR record in the store and check it.
  b1->_cseq = 17039;
  rc = store->set_aor_data(std::string("5102175698@cw-ngv.com"), aor_data1, false);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  aor_data1 = store->get_aor_data(std::string("5102175698@cw-ngv.com"));
  EXPECT_EQ(1u, aor_data1->bindings().size());
  EXPECT_EQ(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"), aor_data1->bindings().begin()->first);
  b1 = aor_data1->bindings().begin()->second;
  EXPECT_EQ(std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>"), b1->_uri);
  EXPECT_EQ(std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq"), b1->_cid);
  EXPECT_EQ(17039, b1->_cseq);
  EXPECT_EQ(now + 300, b1->_expires);
  EXPECT_EQ(0, b1->_priority);

  // Update AoR record again in the store and check it, this time using get_binding.
  b1->_cseq = 17040;
  rc = store->set_aor_data(std::string("5102175698@cw-ngv.com"), aor_data1, false);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  aor_data1 = store->get_aor_data(std::string("5102175698@cw-ngv.com"));
  EXPECT_EQ(1u, aor_data1->bindings().size());
  b1 = aor_data1->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  EXPECT_EQ(std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>"), b1->_uri);
  EXPECT_EQ(std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq"), b1->_cid);
  EXPECT_EQ(17040, b1->_cseq);
  EXPECT_EQ(now + 300, b1->_expires);
  EXPECT_EQ(0, b1->_priority);
  delete aor_data1; aor_data1 = NULL;

  // Remove a binding.
  aor_data1 = store->get_aor_data(std::string("5102175698@cw-ngv.com"));
  EXPECT_EQ(1u, aor_data1->bindings().size());
  aor_data1->remove_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  EXPECT_EQ(0u, aor_data1->bindings().size());
  rc = store->set_aor_data(std::string("5102175698@cw-ngv.com"), aor_data1, false);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;
  
  aor_data1 = store->get_aor_data(std::string("5102175698@cw-ngv.com"));
  EXPECT_EQ(0u, aor_data1->bindings().size());

  delete aor_data1; aor_data1 = NULL;
  delete store; store = NULL;
  delete datastore; datastore = NULL;
  delete chronos_connection; chronos_connection = NULL;
}


TEST_F(RegStoreTest, SubscriptionTests)
{
  RegStore::AoR* aor_data1;
  RegStore::AoR::Binding* b1;
  RegStore::AoR::Subscription* s1;
  bool rc;
  int now;

  // Create a RegStore instance backed by a local data store.
  ChronosConnection* chronos_connection = new FakeChronosConnection();
  LocalStore* datastore = new LocalStore();
  RegStore* store = new RegStore(datastore, chronos_connection);

  // Get an initial empty AoR record and add a binding.
  now = time(NULL);
  aor_data1 = store->get_aor_data(std::string("5102175698@cw-ngv.com"));
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ(0u, aor_data1->bindings().size());
  b1 = aor_data1->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_timer_id = "00000000000";
  b1->_priority = 0;
  b1->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  b1->_params.push_back(std::make_pair("+sip.instance", "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\""));
  b1->_params.push_back(std::make_pair("reg-id", "1"));
  b1->_params.push_back(std::make_pair("+sip.ice", ""));

  // Add the AoR record to the store.
  rc = store->set_aor_data(std::string("5102175698@cw-ngv.com"), aor_data1, false);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  // Get the AoR record from the store.
  aor_data1 = store->get_aor_data(std::string("5102175698@cw-ngv.com"));
  EXPECT_EQ(1u, aor_data1->bindings().size());
  EXPECT_EQ(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"), aor_data1->bindings().begin()->first);
  b1 = aor_data1->bindings().begin()->second;
  EXPECT_EQ(std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>"), b1->_uri);
  EXPECT_EQ(std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq"), b1->_cid);
  EXPECT_EQ(17038, b1->_cseq);
  EXPECT_EQ(now + 300, b1->_expires);
  EXPECT_EQ(0, b1->_priority);

  // Add a subscription to the record.
  s1 = aor_data1->get_subscription("1234");
  s1->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
  s1->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_from_tag = std::string("4321");
  s1->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_to_tag = std::string("1234");
  s1->_cid = std::string("xyzabc@192.91.191.29");
  s1->_route_uris.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  s1->_expires = now + 300;

  // Set the NOTIFY CSeq value to 1.
  aor_data1->_notify_cseq = 1;

  // Write the record back to the store.
  rc = store->set_aor_data(std::string("5102175698@cw-ngv.com"), aor_data1, false);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  // Read the record back in and check the subscription is still in place.
  aor_data1 = store->get_aor_data(std::string("5102175698@cw-ngv.com"));
  EXPECT_EQ(1u, aor_data1->subscriptions().size());
  EXPECT_EQ(std::string("1234"), aor_data1->subscriptions().begin()->first);
  s1 = aor_data1->get_subscription(std::string("1234"));
  EXPECT_EQ(std::string("sip:5102175698@192.91.191.29:59934;transport=tcp"), s1->_req_uri);
  EXPECT_EQ(std::string("<sip:5102175698@cw-ngv.com>"), s1->_from_uri);
  EXPECT_EQ(std::string("4321"), s1->_from_tag);
  EXPECT_EQ(std::string("<sip:5102175698@cw-ngv.com>"), s1->_to_uri);
  EXPECT_EQ(std::string("1234"), s1->_to_tag);
  EXPECT_EQ(std::string("xyzabc@192.91.191.29"), s1->_cid);
  EXPECT_EQ(1u, s1->_route_uris.size());
  EXPECT_EQ(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"), s1->_route_uris.front());
  EXPECT_EQ(now + 300, s1->_expires);
  EXPECT_EQ(1, aor_data1->_notify_cseq);

  // Remove the subscription.
  aor_data1->remove_subscription(std::string("1234"));
  EXPECT_EQ(0u, aor_data1->subscriptions().size());

  delete aor_data1; aor_data1 = NULL;
  delete store; store = NULL;
  delete datastore; datastore = NULL;
  delete chronos_connection; chronos_connection = NULL;
}


TEST_F(RegStoreTest, CopyTests)
{
  RegStore::AoR* aor_data1;
  RegStore::AoR::Binding* b1;
  RegStore::AoR::Subscription* s1;
  int now;

  // Create a RegStore instance backed by a local data store.
  ChronosConnection* chronos_connection = new FakeChronosConnection();
  LocalStore* datastore = new LocalStore();
  RegStore* store = new RegStore(datastore, chronos_connection);

  // Get an initial empty AoR record.
  now = time(NULL);
  aor_data1 = store->get_aor_data(std::string("5102175698@cw-ngv.com"));
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ(0u, aor_data1->bindings().size());
  EXPECT_EQ(0u, aor_data1->subscriptions().size());

  // Add a binding to the record.
  b1 = aor_data1->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  EXPECT_EQ(1u, aor_data1->bindings().size());
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_timer_id = "00000000000";
  b1->_priority = 0;
  b1->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  b1->_params.push_back(std::make_pair("+sip.instance", "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\""));
  b1->_params.push_back(std::make_pair("reg-id", "1"));
  b1->_params.push_back(std::make_pair("+sip.ice", ""));

  // Add a subscription to the record.
  s1 = aor_data1->get_subscription("1234");
  EXPECT_EQ(1u, aor_data1->subscriptions().size());
  s1->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
  s1->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_from_tag = std::string("4321");
  s1->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_to_tag = std::string("1234");
  s1->_cid = std::string("xyzabc@192.91.191.29");
  s1->_route_uris.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  s1->_expires = now + 300;

  // Set the NOTIFY CSeq value to 1.
  aor_data1->_notify_cseq = 1;

  // Test AoR copy constructor.
  RegStore::AoR* copy = new RegStore::AoR(*aor_data1);
  EXPECT_EQ(1u, copy->bindings().size());
  EXPECT_EQ(1u, copy->subscriptions().size());
  delete copy; copy = NULL;

  // Test AoR assignment.
  copy = new RegStore::AoR();
  *copy = *aor_data1;
  EXPECT_EQ(1u, copy->bindings().size());
  EXPECT_EQ(1u, copy->subscriptions().size());
  delete copy; copy = NULL;
  delete aor_data1; aor_data1 = NULL;

  delete store; store = NULL;
  delete datastore; datastore = NULL;
  delete chronos_connection; chronos_connection = NULL;
}

TEST_F(RegStoreTest, ExpiryTests)
{
  // The expiry tests require pjsip, so initialise for this test
  init_pjsip_logging(99, false, "");
  init_pjsip();

  RegStore::AoR* aor_data1;
  RegStore::AoR::Binding* b1;
  RegStore::AoR::Binding* b2;
  RegStore::AoR::Subscription* s1;
  RegStore::AoR::Subscription* s2;
  bool rc;
  int now;

  // Create a RegStore instance backed by a local data store.
  ChronosConnection* chronos_connection = new FakeChronosConnection();
  LocalStore* datastore = new LocalStore();
  RegStore* store = new RegStore(datastore, chronos_connection);

  // Create an empty AoR record.
  now = time(NULL);
  aor_data1 = store->get_aor_data(std::string("5102175698@cw-ngv.com"));
  EXPECT_EQ(0u, aor_data1->bindings().size());
  EXPECT_EQ(0u, aor_data1->subscriptions().size());

  // Add a couple of bindings, one with expiry in 100 seconds, the next with
  // expiry in 200 seconds.
  b1 = aor_data1->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  EXPECT_EQ(1u, aor_data1->bindings().size());
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 100;
  b1->_timer_id = "00000000000";
  b1->_priority = 0;
  b1->_params.push_back(std::make_pair("+sip.instance", "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\""));
  b1->_params.push_back(std::make_pair("reg-id", "1"));
  b1->_params.push_back(std::make_pair("+sip.ice", ""));
  b2 = aor_data1->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:2"));
  EXPECT_EQ(2u, aor_data1->bindings().size());
  b2->_uri = std::string("<sip:5102175698@192.91.191.42:59934;transport=tcp;ob>");
  b2->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b2->_cseq = 17038;
  b2->_expires = now + 200;
  b2->_timer_id = "00000000000";
  b2->_priority = 0;
  b2->_params.push_back(std::make_pair("+sip.instance", "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\""));
  b2->_params.push_back(std::make_pair("reg-id", "2"));
  b2->_params.push_back(std::make_pair("+sip.ice", ""));

  // Add a couple of subscriptions, one with expiry in 150 seconds, the next
  // with expiry in 300 seconds.
  s1 = aor_data1->get_subscription("1234");
  EXPECT_EQ(1u, aor_data1->subscriptions().size());
  s1->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
  s1->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_from_tag = std::string("4321");
  s1->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_to_tag = std::string("1234");
  s1->_cid = std::string("xyzabc@192.91.191.29");
  s1->_route_uris.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  s1->_expires = now + 150;
  s2 = aor_data1->get_subscription("5678");
  EXPECT_EQ(2u, aor_data1->subscriptions().size());
  s2->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
  s2->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s2->_from_tag = std::string("8765");
  s2->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s2->_to_tag = std::string("5678");
  s2->_cid = std::string("xyzabc@192.91.191.29");
  s2->_route_uris.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  s2->_expires = now + 300;

  // Write the record to the store.
  rc = store->set_aor_data(std::string("5102175698@cw-ngv.com"), aor_data1, false);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  // Advance the time by 101 seconds and read the record back from the store.
  // The first binding should have expired.
  cwtest_advance_time_ms(101000);
  aor_data1 = store->get_aor_data(std::string("5102175698@cw-ngv.com"));
  EXPECT_EQ(1u, aor_data1->bindings().size());
  EXPECT_EQ(2u, aor_data1->subscriptions().size());
  delete aor_data1; aor_data1 = NULL;

  // Advance the time by another 50 seconds and read the record back from the
  // store.  The first subscription should have expired.
  cwtest_advance_time_ms(50000);
  aor_data1 = store->get_aor_data(std::string("5102175698@cw-ngv.com"));
  EXPECT_EQ(1u, aor_data1->bindings().size());
  EXPECT_EQ(1u, aor_data1->subscriptions().size());
  delete aor_data1; aor_data1 = NULL;

  // Advance the time by another 100 seconds and read the record back.
  // The whole record should now be empty - even though the second subscription
  // still has 99 seconds before it expires, all subscriptions implicitly
  // expire when the last binding expires.
  cwtest_advance_time_ms(100000);
  aor_data1 = store->get_aor_data(std::string("5102175698@cw-ngv.com"));
  EXPECT_EQ(0u, aor_data1->bindings().size());
  EXPECT_EQ(0u, aor_data1->subscriptions().size());
  delete aor_data1; aor_data1 = NULL;

  delete store; store = NULL;
  delete datastore; datastore = NULL;
  delete chronos_connection; chronos_connection = NULL;
  term_pjsip();
}


