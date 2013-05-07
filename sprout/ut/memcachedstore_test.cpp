/**
 * @file memcachedstore_test.cpp UT for Sprout memcached store.
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

///
///----------------------------------------------------------------------------

#include <string>
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <json/reader.h>

#include "utils.h"
#include "sas.h"
#include "memcachedstore.h"
#include "memcachedstorefactory.h"
#include "localstore.h"
#include "localstorefactory.h"
#include "fakelogger.hpp"
#include "test_utils.hpp"

using namespace std;
using namespace RegData;

/// Fixture for MemcachedStoreTest.
class MemcachedStoreTest : public ::testing::Test
{
  FakeLogger _log;

  MemcachedStoreTest()
  {
  }

  virtual ~MemcachedStoreTest()
  {
  }

  void do_test_simple(Store& store);
};


void do_expect_eq(AoR* aor_data1, AoR* aor_data2)
{
  AoR::Bindings::const_iterator i1;
  AoR::Bindings::const_iterator i2;
  AoR::Binding* b1;
  AoR::Binding* b2;
  std::string s;

  EXPECT_EQ(aor_data1->bindings().size(), aor_data2->bindings().size());
  for (i1 = aor_data1->bindings().begin(), i2 = aor_data2->bindings().begin();
       i1 != aor_data1->bindings().end();
       ++i1, ++i2)
  {
    EXPECT_EQ(i2->first, i1->first);
    b1 = i1->second;
    b2 = i2->second;
    EXPECT_EQ(b1->_uri, b2->_uri);
    EXPECT_EQ(b1->_cid, b2->_cid);
    EXPECT_EQ(b1->_cseq, b2->_cseq);
    EXPECT_EQ(b1->_expires, b2->_expires);
    EXPECT_EQ(b1->_priority, b2->_priority);
    EXPECT_EQ(b1->_params, b2->_params);
    EXPECT_EQ(b1->_path_headers, b2->_path_headers);
  }
}

/// Test serialization - independent of actual server.
TEST_F(MemcachedStoreTest, Serialization)
{
  AoR* aor_data1;
  AoR* aor_data2;
  AoR::Bindings::const_iterator i1;
  AoR::Bindings::const_iterator i2;
  AoR::Binding* b1;
  int now;
  std::string s;

  // Test sequence 1 - test serialization/deserialization.

  // Test 1.1 - serialization/deserialization of single binding.
  now = time(NULL);
  aor_data1 = (AoR*)new MemcachedAoR();
  b1 = aor_data1->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_params.push_back(std::make_pair("+sip.instance", "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\""));
  b1->_params.push_back(std::make_pair("reg-id", "1"));
  b1->_params.push_back(std::make_pair("+sip.ice", ""));
  b1->_path_headers.push_back("<sip:P3.EXAMPLEHOME.COM;lr>");
  b1->_path_headers.push_back("<sip:P1.EXAMPLEVISITED.COM;lr>");
  s = MemcachedStore::serialize_aor((MemcachedAoR*)aor_data1);

  EXPECT_EQ(4ul + 48 + 54 + 33 + 4 + 4 + 4 + 4 + 4 + (9 + 1) + (7 + 2) + (14 + 50) + (28 + 31), s.length());

  aor_data2 = (AoR*)MemcachedStore::deserialize_aor(s);

  SCOPED_TRACE("");
  do_expect_eq(aor_data1, aor_data2);

  // now test copy constructor
  AoR aor_data3(*aor_data2);
  do_expect_eq(aor_data1, &aor_data3);

  delete aor_data1;
  delete aor_data2;

  // Test 1.2 - serialization/deserialization of single binding with whitespace in strings.
  now = time(NULL);
  aor_data1 = (AoR*)new MemcachedAoR();
  b1 = aor_data1->get_binding(std::string("urn:  uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934; transport=tcp; ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91  NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_params.push_back(std::make_pair("+sip.instance", " \"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\""));
  b1->_params.push_back(std::make_pair(" reg-id", "1"));
  b1->_params.push_back(std::make_pair("+sip.ice", ""));
  s = MemcachedStore::serialize_aor((MemcachedAoR*)aor_data1);

  EXPECT_EQ(4ul + 50 + 56 + 35 + 4 + 4 + 4 + 4 + 4 + (9 + 1) + (8 + 2) + (14 + 51), s.length());

  aor_data2 = (AoR*)MemcachedStore::deserialize_aor(s);

  SCOPED_TRACE("");
  do_expect_eq(aor_data1, aor_data2);

  delete aor_data1;
  delete aor_data2;

  // Test 1.3 - serialization/deserialization of multiple bindings.
  now = time(NULL);
  aor_data1 = (AoR*)new MemcachedAoR();
  b1 = aor_data1->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_params.push_back(std::make_pair("+sip.instance", "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\""));
  b1->_params.push_back(std::make_pair("reg-id", "1"));
  b1->_params.push_back(std::make_pair("+sip.ice", ""));
  b1 = aor_data1->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-2867e5552dfc:1"));
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:44226;transport=tcp;ob>");
  b1->_cid = std::string("hgZIoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 2385;
  b1->_expires = now + 183;
  b1->_priority = 0;
  b1->_params.push_back(std::make_pair("+sip.instance", "\"<urn:uuid:00000000-0000-0000-0000-2867e5552dfc>\""));
  b1->_params.push_back(std::make_pair("reg-id", "1"));
  b1->_params.push_back(std::make_pair("+sip.ice", ""));
  s = MemcachedStore::serialize_aor((MemcachedAoR*)aor_data1);

  aor_data2 = (AoR*)MemcachedStore::deserialize_aor(s);

  SCOPED_TRACE("");
  do_expect_eq(aor_data1, aor_data2);

  // Now test assignment operator.
  aor_data3 = *aor_data2;
  do_expect_eq(aor_data1, &aor_data3);

  // Now remove a binding that exists.  It should be removed, but others should still exist.
  aor_data2->remove_binding("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1");
  b1 = aor_data2->get_binding("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1");
  EXPECT_EQ("", b1->_uri);
  b1 = aor_data2->get_binding("urn:uuid:00000000-0000-0000-0000-2867e5552dfc:1");
  EXPECT_EQ("<sip:5102175698@192.91.191.29:44226;transport=tcp;ob>", b1->_uri);

  // Now remove a binding that doesn't exist.  Nothing should happen.
  aor_data2->remove_binding("urn:uuid:00000000-0000-0000-0000-b4dd32817622:3");
  b1 = aor_data2->get_binding("urn:uuid:00000000-0000-0000-0000-2867e5552dfc:1");
  EXPECT_EQ("<sip:5102175698@192.91.191.29:44226;transport=tcp;ob>", b1->_uri);

  delete aor_data1;
  delete aor_data2;
}

/// Test the local fake server.
TEST_F(MemcachedStoreTest, SimpleLocal)
{
  SCOPED_TRACE("local");

  Store* store = create_local_store();
  do_test_simple(*store);
  destroy_local_store(store);
}

/// Test the real memcached server.  Disabled because we don't have a real memcached server to test against at UT time.
TEST_F(MemcachedStoreTest, DISABLED_SimpleMemcached)
{
  SCOPED_TRACE("memcached");
  Store* store;

  // Test 2.1 - create a MemcachedStore instance and connect to a single server.
  std::list<std::string> servers;
  servers.push_back(std::string("localhost:11211"));
  store = create_memcached_store(servers, 10);

  do_test_simple(*store);

  // Test 2.8 - destroy the MemcachedStore instance.
  destroy_memcached_store(store);
}

/// Test the real memcached server.  Alternate version that doesn't expect to work.
TEST_F(MemcachedStoreTest, SimpleMemcachedAlt)
{
  SCOPED_TRACE("memcached");
  Store* store;

  // Test 2.1 - create a MemcachedStore instance and connect to a single server.
  std::list<std::string> servers;
  servers.push_back(std::string("localhost:11209"));
  store = create_memcached_store(servers, 10);

  // Test 2.2 - flush the server.
  store->flush_all();

  // Test 2.3 - get an initial empty AoR record and add a binding.
  AoR* aor_data1 = store->get_aor_data(std::string("5102175698@ngc.thewholeelephant.com"));
  ASSERT_EQ(NULL, aor_data1);

  // Test 2.8 - destroy the MemcachedStore instance.
  destroy_memcached_store(store);
}

/// Test the server.
void MemcachedStoreTest::do_test_simple(Store& store)
{
  AoR* aor_data1;
  AoR::Bindings::const_iterator i1;
  AoR::Bindings::const_iterator i2;
  AoR::Binding* b1;
  bool rc;
  int now;
  std::string s;

  // Test sequence 2 - getting/setting/querying a single registration for a single AoR

  // Test 2.2 - flush the server.
  store.flush_all();

  // Test 2.3 - get an initial empty AoR record and add a binding.
  now = time(NULL);
  aor_data1 = store.get_aor_data(std::string("5102175698@ngc.thewholeelephant.com"));
  ASSERT_TRUE(aor_data1 != NULL);
  EXPECT_EQ(0u, aor_data1->bindings().size());
  b1 = aor_data1->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  b1->_uri = std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_params.push_back(std::make_pair("+sip.instance", "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\""));
  b1->_params.push_back(std::make_pair("reg-id", "1"));
  b1->_params.push_back(std::make_pair("+sip.ice", ""));

  // Test 2.4 - add the AoR record to the server.
  rc = store.set_aor_data(std::string("5102175698@ngc.thewholeelephant.com"), aor_data1);
  EXPECT_TRUE(rc);
  delete aor_data1;

  // Test 2.5 - get the AoR record from the server.
  aor_data1 = store.get_aor_data(std::string("5102175698@ngc.thewholeelephant.com"));
  EXPECT_EQ(1u, aor_data1->bindings().size());
  EXPECT_EQ(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"), aor_data1->bindings().begin()->first);
  b1 = aor_data1->bindings().begin()->second;
  EXPECT_EQ(std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>"), b1->_uri);
  EXPECT_EQ(std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq"), b1->_cid);
  EXPECT_EQ(17038, b1->_cseq);
  EXPECT_EQ(now + 300, b1->_expires);
  EXPECT_EQ(0, b1->_priority);

  // Test 2.6 - update AoR record at the server and check it.
  b1->_cseq = 17039;
  rc = store.set_aor_data(std::string("5102175698@ngc.thewholeelephant.com"), aor_data1);
  EXPECT_TRUE(rc);
  delete aor_data1;
  aor_data1 = store.get_aor_data(std::string("5102175698@ngc.thewholeelephant.com"));
  EXPECT_EQ(1u, aor_data1->bindings().size());
  EXPECT_EQ(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"), aor_data1->bindings().begin()->first);
  b1 = aor_data1->bindings().begin()->second;
  EXPECT_EQ(std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>"), b1->_uri);
  EXPECT_EQ(std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq"), b1->_cid);
  EXPECT_EQ(17039, b1->_cseq);
  EXPECT_EQ(now + 300, b1->_expires);
  EXPECT_EQ(0, b1->_priority);

  // Test 2.7 - update AoR record again at the server and check it, this time using get_binding.
  b1->_cseq = 17040;
  rc = store.set_aor_data(std::string("5102175698@ngc.thewholeelephant.com"), aor_data1);
  EXPECT_TRUE(rc);
  delete aor_data1;
  aor_data1 = store.get_aor_data(std::string("5102175698@ngc.thewholeelephant.com"));
  EXPECT_EQ(1u, aor_data1->bindings().size());
  b1 = aor_data1->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  EXPECT_EQ(std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>"), b1->_uri);
  EXPECT_EQ(std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq"), b1->_cid);
  EXPECT_EQ(17040, b1->_cseq);
  EXPECT_EQ(now + 300, b1->_expires);
  EXPECT_EQ(0, b1->_priority);

  // Now check the maximum expiry is what we think.
  int max_exp = store.expire_bindings(aor_data1, now + 299);
  EXPECT_EQ(1u, aor_data1->bindings().size());
  EXPECT_EQ(now + 300, max_exp);

  // Now expire a binding by pretending the time is in the future.
  max_exp = store.expire_bindings(aor_data1, now + 301);
  EXPECT_EQ(0u, aor_data1->bindings().size());
  EXPECT_EQ(now + 301, max_exp);

  delete aor_data1;
}
