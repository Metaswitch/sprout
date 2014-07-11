/**
 * @file options_test.cpp UT for Sprout options module.
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
#include "gtest/gtest.h"

#include "siptest.hpp"
#include "utils.h"
#include "analyticslogger.h"
#include "options.h"

using namespace std;

/// Fixture for OptionsTest.
class OptionsTest : public SipTest
{
public:
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
    pj_status_t ret = init_options();
    ASSERT_EQ(PJ_SUCCESS, ret);
  }

  static void TearDownTestCase()
  {
    destroy_options();
    SipTest::TearDownTestCase();
  }

  OptionsTest() : SipTest(&mod_options)
  {
  }

  ~OptionsTest()
  {
  }
};

namespace Options
{
class Message
{
public:
  string _method;
  string _user;
  string _domain;
  string _route;

  Message() :
    _method("OPTIONS"),
    _user("6505550231"),
    _domain("127.0.0.1"),
    _route("")
  {
  }

  string get();
};
}

string Options::Message::get()
{
  char buf[16384];

  int n = snprintf(buf, sizeof(buf),
                   "%1$s sip:%3$s SIP/2.0\r\n"
                   "Via: SIP/2.0/TCP 10.83.18.38:36530;rport;branch=z9hG4bKPjmo1aimuq33BAI4rjhgQgBr4sY5e9kSPI\r\n"
                   "Via: SIP/2.0/TCP 10.114.61.213:5061;received=23.20.193.43;branch=z9hG4bK+7f6b263a983ef39b0bbda2135ee454871+sip+1+a64de9f6\r\n"
                   "From: <sip:%2$s@%3$s>;tag=10.114.61.213+1+8c8b232a+5fb751cf\r\n"
                   "Supported: outbound, path\r\n"
                   "To: <sip:%2$s@%3$s>\r\n"
                   "%4$s"
                   "Max-Forwards: 68\r\n"
                   "Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqsUOO4ohntC@10.114.61.213\r\n"
                   "CSeq: 16567 %1$s\r\n"
                   "User-Agent: Accession 2.0.0.0\r\n"
                   "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n"
                   "Content-Length: 0\r\n\r\n",
                   /*  1 */ _method.c_str(),
                   /*  2 */ _user.c_str(),
                   /*  3 */ _domain.c_str(),
                   /*  4 */ _route.empty() ? "" : string(_route).append("\r\n").c_str()
    );

  EXPECT_LT(n, (int)sizeof(buf));

  string ret(buf, n);
  // cout << ret <<endl;
  return ret;
}

using Options::Message;

TEST_F(OptionsTest, NotOptions)
{
  Message msg;
  msg._method = "INVITE";
  pj_bool_t ret = inject_msg_direct(msg.get());
  EXPECT_EQ(PJ_FALSE, ret);
}

TEST_F(OptionsTest, NotOurs)
{
  Message msg;
  msg._domain = "not-us.example.org";
  pj_bool_t ret = inject_msg_direct(msg.get());
  EXPECT_EQ(PJ_FALSE, ret);
}

TEST_F(OptionsTest, HomeDomain)
{
  Message msg;
  msg._domain = "homedomain";
  pj_bool_t ret = inject_msg_direct(msg.get());
  EXPECT_EQ(PJ_FALSE, ret);
}

TEST_F(OptionsTest, LocalHost)
{
  Message msg;
  msg._domain = "localhost";
  pj_bool_t ret = inject_msg_direct(msg.get());
  EXPECT_EQ(PJ_FALSE, ret);
}

TEST_F(OptionsTest, RouteHeader)
{
  Message msg;
  msg._route = "Route: <sip:notthehomedomain;transport=UDP;lr>";
  pj_bool_t ret = inject_msg_direct(msg.get());
  EXPECT_EQ(PJ_FALSE, ret);
}

TEST_F(OptionsTest, RouteHeaderMatchingLocalDomain)
{
  Message msg;
  msg._route = "Route: <sip:homedomain;transport=UDP;lr>";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  free_txdata();
}

TEST_F(OptionsTest, MultipleRouteHeaders)
{
  Message msg;
  msg._route = "Route: <sip:homedomain;transport=UDP;lr>\r\nRoute: <sip:homedomain2;transport=UDP;lr>";
  pj_bool_t ret = inject_msg_direct(msg.get());
  EXPECT_EQ(PJ_FALSE, ret);
}

/// Simple correct example
TEST_F(OptionsTest, SimpleMainline)
{
  Message msg;
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  // cout << PjMsg(out) << endl;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  // Nothing very interesting in the response, so nothing to test for.
  free_txdata();
}

