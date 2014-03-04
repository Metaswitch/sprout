/**
 * @file httpconnection_test.cpp UT for Sprout HttpConnection.
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
#include "sasevent.h"
#include "httpconnection.h"
#include "basetest.hpp"
#include "fakecurl.hpp"
#include "test_interposer.hpp"
#include "test_utils.hpp"
#include "load_monitor.h"

using namespace std;

/// Fixture for test.
class HttpConnectionTest : public BaseTest
{
  LoadMonitor _lm;
  LastValueCache _lvc;
  HttpConnection _http;
  HttpConnectionTest() :
    _lm(100000, 20, 10, 10),
    _lvc(num_known_stats, known_statnames, "6666", 10), // Short timeout to avoid shutdown delays.
    _http("cyrus", true, SASEvent::TX_XDM_GET_BASE, "connected_homers", &_lm, &_lvc)
  {
    fakecurl_responses.clear();
    fakecurl_responses["http://cyrus/blah/blah/blah"] = "<?xml version=\"1.0\" encoding=\"UTF-8\"><boring>Document</boring>";
    fakecurl_responses["http://cyrus/blah/blah/wot"] = CURLE_REMOTE_FILE_NOT_FOUND;
    fakecurl_responses["http://cyrus/blah/blah/503"] = CURLE_HTTP_RETURNED_ERROR;
    fakecurl_responses["http://cyrus/up/up/up"] = "<message>ok, whatever...</message>";
    fakecurl_responses["http://cyrus/up/up/down"] = CURLE_REMOTE_ACCESS_DENIED;
    fakecurl_responses["http://cyrus/down/down/down"] = "<message>WHOOOOSH!!</message>";
    fakecurl_responses["http://cyrus/down/down/up"] = CURLE_RECV_ERROR;
    fakecurl_responses["http://cyrus/down/around"] = Response(CURLE_SEND_ERROR, "<message>Gotcha!</message>");
    fakecurl_responses["http://cyrus/delete_id"] = CURLE_OK;
    fakecurl_responses["http://cyrus/put_id"] = CURLE_OK;
    fakecurl_responses["http://cyrus/post_id"] = Response({"Location: test"});
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
  long ret = _http.get("/blah/blah/blah", output, "gandalf", 0);
  EXPECT_EQ(200, ret);
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
  long ret = _http.get("/blah/blah/wot", output, "gandalf", 0);
  EXPECT_EQ(404, ret);
  ret = _http.get("/blah/blah/503", output, "gandalf", 0);
  EXPECT_EQ(503, ret);
}

TEST_F(HttpConnectionTest, SimpleGetRetry)
{
  string output;

  // Warm up the connection.
  long ret = _http.get("/blah/blah/blah", output, "gandalf", 0);
  EXPECT_EQ(200, ret);

  // Get a failure on the connection and retry it.
  ret = _http.get("/down/around", output, "gandalf", 0);
  EXPECT_EQ(200, ret);
  EXPECT_EQ("<message>Gotcha!</message>", output);
}

TEST_F(HttpConnectionTest, ConnectionRecycle)
{
  // Warm up.
  string output;
  long ret = _http.get("/blah/blah/blah", output, "gandalf", 0);
  EXPECT_EQ(200, ret);

  // Wait a very short time.
  cwtest_advance_time_ms(10L);

  // Next request should be on same connection (it's possible but very
  // unlikely (~2e-4) that we'll choose to recycle already - let's
  // just take the risk of an occasional spurious test failure).
  ret = _http.get("/up/up/up", output, "legolas", 0);
  EXPECT_EQ(200, ret);
  Request& req = fakecurl_requests["http://cyrus/up/up/up"];
  EXPECT_FALSE(req._fresh);

  // Now wait a long time - much longer than the 1-minute average
  // recycle time.
  cwtest_advance_time_ms(10 * 60 * 1000L);

  // Next request should be on a different connection. Again, there's
  // a tiny chance (~5e-5) we'll fail here because we're still using
  // the same connection, but we'll take the risk.
  ret = _http.get("/down/down/down", output, "gimli", 0);
  EXPECT_EQ(200, ret);
  Request& req2 = fakecurl_requests["http://cyrus/down/down/down"];
  EXPECT_TRUE(req2._fresh);

  // Should be a single connection to the hardcoded fakecurl IP.
  EXPECT_EQ(1u, _http._server_count.size());
  EXPECT_EQ(1, _http._server_count["10.42.42.42"]);
}

TEST_F(HttpConnectionTest, SimplePost)
{
  std::map<std::string, std::string> head;
  long ret = _http.send_post("/post_id", "", head, 0);
  EXPECT_EQ(200, ret);
}

TEST_F(HttpConnectionTest, SimplePut)
{
  long ret = _http.send_put("/put_id", "", 0);
  EXPECT_EQ(200, ret);
}

TEST_F(HttpConnectionTest, SimpleDelete)
{
  long ret = _http.send_delete("/delete_id", 0);
  EXPECT_EQ(200, ret);
}
