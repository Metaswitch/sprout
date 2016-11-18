/**
 * @file xdmconnection_test.cpp UT for Sprout XDM connection and underlying
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

/// HttpConnection.
///
///----------------------------------------------------------------------------

#include <string>
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "utils.h"
#include "sas.h"
#include "fakehttpresolver.hpp"
#include "httpconnection.h"
#include "xdmconnection.h"
#include "basetest.hpp"
#include "fakecurl.hpp"
#include "fakesnmp.hpp"
#include "test_utils.hpp"

using namespace std;

/// Fixture for XdmConnectionTest.
class XdmConnectionTest : public BaseTest
{
  FakeHttpResolver _resolver;
  XDMConnection _xdm;

  XdmConnectionTest() :
    _resolver("10.42.42.42"),
    _xdm("cyrus", &_resolver, NULL, &SNMP::FAKE_IP_COUNT_TABLE, &SNMP::FAKE_EVENT_ACCUMULATOR_TABLE)
  {
    fakecurl_responses.clear();
    fakecurl_responses["http://10.42.42.42:80/org.etsi.ngn.simservs/users/gand%2Falf/simservs.xml"] = "<?xml version=\"1.0\" encoding=\"UTF-8\"><boring>Still</boring>";
    fakecurl_responses["http://10.42.42.42:80/org.etsi.ngn.simservs/users/gand%2Falf2/simservs.xml"] = "yadda";
    fakecurl_responses["http://10.42.42.42:80/org.etsi.ngn.simservs/users/gand%2Falf3/simservs.xml"] = "wherizzit?";
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
  Request& req = fakecurl_requests["http://cyrus:80/org.etsi.ngn.simservs/users/gand%2Falf/simservs.xml"];
  EXPECT_EQ("GET", req._method);
  EXPECT_FALSE(req._httpauth & CURLAUTH_DIGEST) << req._httpauth;
  EXPECT_EQ("", req._username);
  EXPECT_EQ("", req._password);
  EXPECT_CONTAINED("X-XCAP-Asserted-Identity: gand/alf", req._headers);
}

