/**
 * @file httpconnection_test.cpp UT for Sprout HttpConnection.
 *
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by post at
 * Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 */

///
///----------------------------------------------------------------------------

#include <string>
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <json/reader.h>

#include "utils.h"
#include "sas.h"
#include "sasevent.h"
#include "httpconnection.h"
#include "basetest.hpp"
#include "fakecurl.hpp"
#include "test_interposer.hpp"
#include "test_utils.hpp"

using namespace std;

/// Fixture for test.
class HttpConnectionTest : public BaseTest
{
  HttpConnection _http;

  HttpConnectionTest() :
    _http("cyrus", true, SASEvent::TX_XDM_GET_BASE, "connected_homers")
  {
    fakecurl_responses.clear();
    fakecurl_responses["http://cyrus/blah/blah/blah"] = "<?xml version=\"1.0\" encoding=\"UTF-8\"><boring>Document</boring>";
    fakecurl_responses["http://cyrus/blah/blah/wot"] = CURLE_REMOTE_FILE_NOT_FOUND;
    fakecurl_responses["http://cyrus/up/up/up"] = "<message>ok, whatever...</message>";
    fakecurl_responses["http://cyrus/up/up/down"] = CURLE_REMOTE_ACCESS_DENIED;
    fakecurl_responses["http://cyrus/down/down/down"] = "<message>WHOOOOSH!!</message>";
    fakecurl_responses["http://cyrus/down/down/up"] = CURLE_RECV_ERROR;
    fakecurl_responses["http://cyrus/down/around"] = Response(CURLE_SEND_ERROR, "<message>Gotcha!</message>");
  }

  virtual ~HttpConnectionTest()
  {
    fakecurl_responses.clear();
    fakecurl_requests.clear();
    cwtest_reset_time();
  }
};


TEST_F(HttpConnectionTest, SimpleKeyAuthGet)
{
  string output;
  bool ret = _http.get("/blah/blah/blah", output, "gandalf", 0);
  EXPECT_TRUE(ret);
  EXPECT_EQ("<?xml version=\"1.0\" encoding=\"UTF-8\"><boring>Document</boring>", output);
  Request& req = fakecurl_requests["http://cyrus/blah/blah/blah"];
  EXPECT_EQ("GET", req._method);
  EXPECT_FALSE(req._httpauth & CURLAUTH_DIGEST) << req._httpauth;
  EXPECT_EQ("", req._username);
  EXPECT_EQ("", req._password);
}

TEST_F(HttpConnectionTest, SimpleGetFailure)
{
  string output;
  bool ret = _http.get("/blah/blah/wot", output, "gandalf", 0);
  EXPECT_FALSE(ret);
}

TEST_F(HttpConnectionTest, SimpleGetRetry)
{
  string output;

  // Warm up the connection.
  bool ret = _http.get("/blah/blah/blah", output, "gandalf", 0);
  EXPECT_TRUE(ret);

  // Get a failure on the connection and retry it.
  ret = _http.get("/down/around", output, "gandalf", 0);
  EXPECT_TRUE(ret);
  EXPECT_EQ("<message>Gotcha!</message>", output);
}

TEST_F(HttpConnectionTest, ConnectionRecycle)
{
  // Warm up.
  string output;
  bool ret = _http.get("/blah/blah/blah", output, "gandalf", 0);
  EXPECT_TRUE(ret);

  // Wait a very short time.
  cwtest_advance_time_ms(10L);

  // Next request should be on same connection (it's possible but very
  // unlikely (~2e-4) that we'll choose to recycle already - let's
  // just take the risk of an occasional spurious test failure).
  ret = _http.get("/up/up/up", output, "legolas", 0);
  EXPECT_TRUE(ret);
  Request& req = fakecurl_requests["http://cyrus/up/up/up"];
  EXPECT_FALSE(req._fresh);

  // Now wait a long time - much longer than the 1-minute average
  // recycle time.
  cwtest_advance_time_ms(10 * 60 * 1000L);

  // Next request should be on a different connection. Again, there's
  // a tiny chance (~5e-5) we'll fail here because we're still using
  // the same connection, but we'll take the risk.
  ret = _http.get("/down/down/down", output, "gimli", 0);
  EXPECT_TRUE(ret);
  Request& req2 = fakecurl_requests["http://cyrus/down/down/down"];
  EXPECT_TRUE(req2._fresh);

  // Should be a single connection to the hardcoded fakecurl IP.
  EXPECT_EQ(1u, _http._serverCount.size());
  EXPECT_EQ(1, _http._serverCount["10.42.42.42"]);
}
