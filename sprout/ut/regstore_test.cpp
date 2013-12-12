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

#include "utils.h"
#include "sas.h"
#include "localstore.h"
#include "regstore.h"
#include "fakelogger.hpp"
#include "test_utils.hpp"

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


TEST_F(RegStoreTest, SimpleTests)
{
  RegStore::AoR* aor_data1;
  RegStore::AoR::Bindings::const_iterator i1;
  RegStore::AoR::Bindings::const_iterator i2;
  RegStore::AoR::Binding* b1;
  bool rc;
  int now;
  std::string s;

  // Test sequence 2 - getting/setting/querying a single registration for a single AoR

  // Test 2.1 - create a RegStore instance backed by a local data store.
  LocalStore* datastore = new LocalStore();
  RegStore* store = new RegStore(datastore);

  // Test 2.2 - get an initial empty AoR record and add a binding.
  now = time(NULL);
  aor_data1 = store->get_aor_data(std::string("5102175698@ngc.thewholeelephant.com"));
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

  // Test 2.3 - add the AoR record to the store.
  rc = store->set_aor_data(std::string("5102175698@ngc.thewholeelephant.com"), aor_data1);
  EXPECT_TRUE(rc);
  delete aor_data1;

  // Test 2.4 - get the AoR record from the store.
  aor_data1 = store->get_aor_data(std::string("5102175698@ngc.thewholeelephant.com"));
  EXPECT_EQ(1u, aor_data1->bindings().size());
  EXPECT_EQ(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"), aor_data1->bindings().begin()->first);
  b1 = aor_data1->bindings().begin()->second;
  EXPECT_EQ(std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>"), b1->_uri);
  EXPECT_EQ(std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq"), b1->_cid);
  EXPECT_EQ(17038, b1->_cseq);
  EXPECT_EQ(now + 300, b1->_expires);
  EXPECT_EQ(0, b1->_priority);

  // Test 2.5 - update AoR record in the store and check it.
  b1->_cseq = 17039;
  rc = store->set_aor_data(std::string("5102175698@ngc.thewholeelephant.com"), aor_data1);
  EXPECT_TRUE(rc);
  delete aor_data1;
  aor_data1 = store->get_aor_data(std::string("5102175698@ngc.thewholeelephant.com"));
  EXPECT_EQ(1u, aor_data1->bindings().size());
  EXPECT_EQ(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"), aor_data1->bindings().begin()->first);
  b1 = aor_data1->bindings().begin()->second;
  EXPECT_EQ(std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>"), b1->_uri);
  EXPECT_EQ(std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq"), b1->_cid);
  EXPECT_EQ(17039, b1->_cseq);
  EXPECT_EQ(now + 300, b1->_expires);
  EXPECT_EQ(0, b1->_priority);

  // Test 2.6 - update AoR record again in the store and check it, this time using get_binding.
  b1->_cseq = 17040;
  rc = store->set_aor_data(std::string("5102175698@ngc.thewholeelephant.com"), aor_data1);
  EXPECT_TRUE(rc);
  delete aor_data1;
  aor_data1 = store->get_aor_data(std::string("5102175698@ngc.thewholeelephant.com"));
  EXPECT_EQ(1u, aor_data1->bindings().size());
  b1 = aor_data1->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  EXPECT_EQ(std::string("<sip:5102175698@192.91.191.29:59934;transport=tcp;ob>"), b1->_uri);
  EXPECT_EQ(std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq"), b1->_cid);
  EXPECT_EQ(17040, b1->_cseq);
  EXPECT_EQ(now + 300, b1->_expires);
  EXPECT_EQ(0, b1->_priority);

  delete aor_data1;

  delete store;
  delete datastore;
}
