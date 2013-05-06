/**
 * @file xdmconnection_test.cpp UT for Sprout XDM connection and underlying
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

/// HttpConnection.
///
///----------------------------------------------------------------------------

#include <string>
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <json/reader.h>

#include "utils.h"
#include "sas.h"
#include "httpconnection.h"
#include "xdmconnection.h"
#include "basetest.hpp"
#include "fakecurl.hpp"
#include "fakelogger.hpp"
#include "test_utils.hpp"

using namespace std;

/// Fixture for XdmConnectionTest.
class XdmConnectionTest : public BaseTest
{
  XDMConnection _xdm;

  XdmConnectionTest() :
    _xdm("cyrus")
  {
    fakecurl_responses.clear();
    fakecurl_responses["http://cyrus/org.etsi.ngn.simservs/users/gand%2Falf/simservs.xml"] = "<?xml version=\"1.0\" encoding=\"UTF-8\"><boring>Still</boring>";
    fakecurl_responses["http://cyrus/org.etsi.ngn.simservs/users/gand%2Falf2/simservs.xml"] = "yadda";
    fakecurl_responses["http://cyrus/org.etsi.ngn.simservs/users/gand%2Falf3/simservs.xml"] = "wherizzit?";
  }

  virtual ~XdmConnectionTest()
  {
    fakecurl_responses.clear();
    fakecurl_requests.clear();
  }
};


// Now test the higher-level methods.

TEST_F(XdmConnectionTest, SimServsGet)
{
  string output;
  bool ret = _xdm.get_simservs("gand/alf", output, "friend_and_enter", 0);
  EXPECT_TRUE(ret);
  EXPECT_EQ("<?xml version=\"1.0\" encoding=\"UTF-8\"><boring>Still</boring>", output);
  Request& req = fakecurl_requests["http://cyrus/org.etsi.ngn.simservs/users/gand%2Falf/simservs.xml"];
  EXPECT_EQ("GET", req._method);
  EXPECT_FALSE(req._httpauth & CURLAUTH_DIGEST) << req._httpauth;
  EXPECT_EQ("", req._username);
  EXPECT_EQ("", req._password);
  EXPECT_CONTAINED("X-XCAP-Asserted-Identity: gand/alf", req._headers);
}

