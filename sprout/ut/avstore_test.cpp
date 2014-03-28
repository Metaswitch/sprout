/**
 * @file avstore_test.cpp UT for Sprout authentication vector store.
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
#include "avstore.h"
#include "fakelogger.hpp"
#include "test_utils.hpp"
#include "test_interposer.hpp"

using namespace std;

/// Fixture for RegStoreTest.
class AvStoreTest : public ::testing::Test
{
  FakeLogger _log;

  AvStoreTest()
  {
  }

  virtual ~AvStoreTest()
  {
  }
};


TEST_F(AvStoreTest, CreateStore)
{
  LocalStore* local_data_store = new LocalStore();
  AvStore* av_store = new AvStore(local_data_store);

  delete av_store;
  delete local_data_store;
}


TEST_F(AvStoreTest, SimpleWriteRead)
{
  LocalStore* local_data_store = new LocalStore();
  AvStore* av_store = new AvStore(local_data_store);

  // Write an AV to the store.
  std::string impi = "6505551234@cw-ngv.com";
  std::string nonce = "9876543210";
  std::string av = "{\"digest\":{\"realm\": \"cw-ngv.com\",\"qop\": \"auth\",\"ha1\": \"12345678\"}}";

  Json::Reader reader;
  Json::Value* av_json_write = new Json::Value;
  reader.parse(av, *av_json_write);

  av_store->set_av(impi, nonce, av_json_write);

  // Retrieve the AV from the store.
  Json::Value* av_json_read = av_store->get_av(impi, nonce);

  EXPECT_THAT(av_json_read, ::testing::NotNull());
  ASSERT_EQ(0, av_json_read->compare(*av_json_write));

  delete av_json_write;
  delete av_json_read;

  delete av_store;
  delete local_data_store;
}


TEST_F(AvStoreTest, ReadExpired)
{
  LocalStore* local_data_store = new LocalStore();
  AvStore* av_store = new AvStore(local_data_store);

  // Write an AV to the store.
  std::string impi = "6505551234@cw-ngv.com";
  std::string nonce = "9876543210";
  std::string av = "{\"digest\":{\"realm\": \"cw-ngv.com\",\"qop\": \"auth\",\"ha1\": \"12345678\"}}";

  Json::Reader reader;
  Json::Value* av_json_write = new Json::Value;
  reader.parse(av, *av_json_write);

  av_store->set_av(impi, nonce, av_json_write);

  // Advance the time by 39 seconds and read the record.
  cwtest_advance_time_ms(39000);
  Json::Value* av_json_read = av_store->get_av(impi, nonce);

  EXPECT_THAT(av_json_read, ::testing::NotNull());
  ASSERT_EQ(0, av_json_read->compare(*av_json_write));
  delete av_json_read;

  // Advance the time another 2 seconds to expire the record.
  cwtest_advance_time_ms(2000);
  av_json_read = av_store->get_av(impi, nonce);
  ASSERT_EQ(NULL, av_json_read);

  delete av_json_write;

  delete av_store;
  delete local_data_store;
}


TEST_F(AvStoreTest, ReadCorrupt)
{
  LocalStore* local_data_store = new LocalStore();
  AvStore* av_store = new AvStore(local_data_store);

  // Write a corrupt AV directly to the local data store.
  std::string impi = "6505551234@cw-ngv.com";
  std::string nonce = "9876543210";
  std::string av = "{\"digest\":{\"realm\": \"cw-ngv.com\",\"qop\": \"auth\",\"ha1\": \"12345678\"}";

  local_data_store->set_data("av", impi + "\\" + nonce, av, 0, 30);

  // Attempt to retrieve the corrupt AV from the store and get a failure.
  Json::Value* av_json_read = av_store->get_av(impi, nonce);
  ASSERT_EQ(NULL, av_json_read);

  delete av_store;
  delete local_data_store;
}


