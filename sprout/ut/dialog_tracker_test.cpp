/**
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
#include <boost/algorithm/string/replace.hpp>
#include <boost/lexical_cast.hpp>

#include "stack.h"
#include "utils.h"
#include "siptest.hpp"
#include "dialog_tracker.hpp"
#include "fakelogger.hpp"

using namespace std;

/// Fixture for IfcHandlerTest
class DialogTrackerTest : public SipTest
{
public:
  FakeLogger _log;
  static DialogTracker* _dialog_tracker;
  static FlowTable* _ft;

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
    _ft = new FlowTable();
    _dialog_tracker = new DialogTracker(_ft);
  }

  static void TearDownTestCase()
  {
    delete _dialog_tracker;
    _dialog_tracker = NULL;
    delete _ft;
    _ft = NULL;

    SipTest::TearDownTestCase();
  }

  DialogTrackerTest() : SipTest(NULL)
  {
  }

  ~DialogTrackerTest()
  {
  }
};

FlowTable* DialogTrackerTest::_ft;
DialogTracker* DialogTrackerTest::_dialog_tracker;

TEST_F(DialogTrackerTest, VerySimple)
{
/*
  string str0("INVITE $1 SIP/2.0\n"
              "Via: SIP/2.0/TCP 10.64.90.97:50693;rport;branch=z9hG4bKPjPtKqxhkZnvVKI2LUEWoZVFjFaqo.cOzf;alias\n"
              "Max-Forwards: 69\n"
              "From: <sip:5755550018@homedomain>;tag=13919SIPpTag0011234\n"
              "To: <sip:5755550099@homedomain>\n"
              "Contact: <sip:5755550018@10.16.62.109:58309;transport=TCP;ob>\n"
              "Call-ID: 1-13919@10.151.20.48\n"
              "CSeq: 4 INVITE\n"
              "Route: <sip:testnode;transport=TCP;lr;orig>\n"
              "Content-Length: 0\n$2\n");
  string str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", "sip:5755550099@homedomain"), "$2", "");
  pjsip_rx_data* rdata = build_rxdata(str);
  parse_rxdata(rdata);
*/
  EXPECT_EQ(1, 1);

}
