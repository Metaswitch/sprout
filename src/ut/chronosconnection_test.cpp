/**
 * @file chronosconnection_test.cpp
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
#include "gtest/gtest.h"

#include "utils.h"
#include "sas.h"
#include "fakehttpresolver.hpp"
#include "chronosconnection.h"
#include "basetest.hpp"
#include "fakecurl.hpp"
#include "sprout_alarmdefinition.h"

using namespace std;

/// Fixture for ChronosConnectionTest.
class ChronosConnectionTest : public BaseTest
{
  FakeHttpResolver _resolver;
  CommunicationMonitor _cm;
  ChronosConnection _chronos;

  ChronosConnectionTest() :
    _resolver("10.42.42.42"),
    _cm(new Alarm("sprout", AlarmDef::SPROUT_CHRONOS_COMM_ERROR, AlarmDef::MAJOR), "sprout", "chronos"),
    _chronos("narcissus", "localhost:9888", &_resolver, &_cm)
  {
    fakecurl_responses.clear();
  }

  virtual ~ChronosConnectionTest()
  {
  }
};

TEST_F(ChronosConnectionTest, SendDelete)
{
  fakecurl_responses["http://10.42.42.42:80/timers/delete_id"] = CURLE_OK;
  HTTPCode status = _chronos.send_delete("delete_id",  0);
  EXPECT_EQ(status, 200);
}

TEST_F(ChronosConnectionTest, SendInvalidDelete)
{
  HTTPCode status = _chronos.send_delete("",  0);
  EXPECT_EQ(status, 405);
}

TEST_F(ChronosConnectionTest, SendPost)
{
  std::list<std::string> headers = {"Location: http://localhost:7253/timers/abcd"};
  fakecurl_responses["http://10.42.42.42:80/timers"] = Response(headers);

  std::string opaque = "{\"aor_id\": \"aor_id\", \"binding_id\": \"binding_id\"}";
  std::string post_identity = "";
  HTTPCode status = _chronos.send_post(post_identity, 300, "/timers", opaque,  0);
  EXPECT_EQ(status, 200);
  EXPECT_EQ(post_identity, "abcd");
}

TEST_F(ChronosConnectionTest, SendPostWithTags)
{
  std::list<std::string> headers = {"Location: http://localhost:7253/timers/abcd"};
  fakecurl_responses["http://10.42.42.42:80/timers"] = Response(headers);

  std::string opaque = "{\"aor_id\": \"aor_id\", \"binding_id\": \"binding_id\"}";
  std::vector<std::string> tags {"TAG1", "TAG2"};
  std::string post_identity = "";
  HTTPCode status = _chronos.send_post(post_identity, 300, "/timers", opaque,  0, tags);
  EXPECT_EQ(status, 200);
  EXPECT_EQ(post_identity, "abcd");
}

TEST_F(ChronosConnectionTest, SendPostWithNoLocationHeader)
{
  std::list<std::string> headers = {"Header: header"};
  fakecurl_responses["http://10.42.42.42:80/timers"] = Response(headers);

  std::string opaque = "{\"aor_id\": \"aor_id\", \"binding_id\": \"binding_id\"}";
  std::string post_identity = "";
  HTTPCode status = _chronos.send_post(post_identity, 300, "/timers", opaque,  0);
  EXPECT_EQ(status, 400);
  EXPECT_EQ(post_identity, "");
}

TEST_F(ChronosConnectionTest, SendPostWithNoHeaders)
{
  std::list<std::string> headers = {""};
  fakecurl_responses["http://10.42.42.42:80/timers"] = Response(headers);

  std::string opaque = "{\"aor_id\": \"aor_id\", \"binding_id\": \"binding_id\"}";
  std::string post_identity = "";
  HTTPCode status = _chronos.send_post(post_identity, 300, "/timers", opaque,  0);
  EXPECT_EQ(status, 400);
  EXPECT_EQ(post_identity, "");
}

TEST_F(ChronosConnectionTest, SendPut)
{
  std::list<std::string> headers = {"Location: http://localhost:7253/timers/efgh"};
  fakecurl_responses["http://10.42.42.42:80/timers/abcd"] = Response(headers);

  // We expect Chronos to change the put identity to the value in the Location
  // header.
  std::string opaque = "{\"aor_id\": \"aor_id\", \"binding_id\": \"binding_id\"}";
  std::string put_identity = "abcd";
  HTTPCode status = _chronos.send_put(put_identity, 300, "/timers", opaque,  0);
  EXPECT_EQ(status, 200);
  EXPECT_EQ(put_identity, "efgh");
}

TEST_F(ChronosConnectionTest, SendPutWithTags)
{
  std::list<std::string> headers = {"Location: http://localhost:7253/timers/efgh"};
  fakecurl_responses["http://10.42.42.42:80/timers/abcd"] = Response(headers);

  // We expect Chronos to change the put identity to the value in the Location
  // header.
  std::string opaque = "{\"aor_id\": \"aor_id\", \"binding_id\": \"binding_id\"}";
  std::vector<std::string> tags = {"TAG1", "TAG2"};
  std::string put_identity = "abcd";
  HTTPCode status = _chronos.send_put(put_identity, 300, "/timers", opaque,  0, tags);
  EXPECT_EQ(status, 200);
  EXPECT_EQ(put_identity, "efgh");
}

TEST_F(ChronosConnectionTest, SendPutWithNoLocationHeader)
{
  std::list<std::string> headers = {"Header: header"};
  fakecurl_responses["http://10.42.42.42:80/timers/abcd"] = Response(headers);

  std::string opaque = "{\"aor_id\": \"aor_id\", \"binding_id\": \"binding_id\"}";
  std::string put_identity = "abcd";
  HTTPCode status = _chronos.send_put(put_identity, 300, "/timers", opaque,  0);
  EXPECT_EQ(status, 400);
  EXPECT_EQ(put_identity, "abcd");
}
