/**
 * @file aschain_test.cpp UT for Sprout AsChain module
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
#include "gtest/gtest.h"

#include "utils.h"
#include "siptest.hpp"
#include "fakelogger.hpp"

#include "ifchandler.h"
#include "aschain.h"

using namespace std;

/// Fixture for AsChainTest
class AsChainTest : public SipTest
{
public:
  FakeLogger _log;

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
  }

  static void TearDownTestCase()
  {
    SipTest::TearDownTestCase();
  }

  AsChainTest() : SipTest(NULL)
  {
  }

  ~AsChainTest()
  {
  }
};

TEST_F(AsChainTest, ServedUser)
{
  string str("INVITE sip:5755550099@homedomain SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.64.90.97:50693;rport;branch=z9hG4bKPjPtKqxhkZnvVKI2LUEWoZVFjFaqo.cOzf;alias\n"
             "Max-Forwards: 69\n"
             "From: <sip:5755550018@homedomain>;tag=13919SIPpTag0011234\n"
             "To: <sip:5755550099@homedomain>\n"
             "Contact: <sip:5755550018@10.16.62.109:58309;transport=TCP;ob>\n"
             "Call-ID: 1-13919@10.151.20.48\n"
             "CSeq: 4 INVITE\n"
             "Route: <sip:testnode;transport=TCP;lr;orig>\n"
             "Content-Length: 0\n\n");
  pjsip_rx_data* rdata = build_rxdata(str);
  parse_rxdata(rdata);

  EXPECT_EQ("sip:5755550018@homedomain", IfcHandler::served_user_from_msg(SessionCase::Originating, rdata->msg_info.msg));
  EXPECT_EQ("sip:5755550018@homedomain", IfcHandler::served_user_from_msg(SessionCase::OriginatingCdiv, rdata->msg_info.msg));
  EXPECT_EQ("sip:5755550099@homedomain", IfcHandler::served_user_from_msg(SessionCase::Terminating, rdata->msg_info.msg));
}


