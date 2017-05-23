/**
 * @file xdmconnection_test.cpp UT for Sprout XDM connection and underlying
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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

