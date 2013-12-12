/**
 * @file authentication_test.cpp UT for Sprout authentication module.
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
#include "localstore.h"
#include "avstore.h"
#include "hssconnection.h"
#include "authentication.h"
#include "fakelogger.hpp"
#include "fakehssconnection.hpp"
#include "fakecurl.hpp"

using namespace std;

/// Fixture for AuthenticationTest.
class AuthenticationTest : public SipTest
{
public:
  FakeLogger _log;

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();

    _local_data_store = new LocalStore();
    _av_store = new AvStore(_local_data_store);
    _hss_connection = new FakeHSSConnection();
    _analytics = new AnalyticsLogger("foo");
    delete _analytics->_logger;
    _analytics->_logger = NULL;
    pj_status_t ret = init_authentication("ut.cw-ngv.com", _av_store, _hss_connection, _analytics);
    ASSERT_EQ(PJ_SUCCESS, ret);
  }

  static void TearDownTestCase()
  {
    destroy_authentication();
    delete _hss_connection;
    delete _analytics;
    delete _av_store;
    delete _local_data_store;

    SipTest::TearDownTestCase();
  }

  AuthenticationTest() : SipTest(&mod_auth)
  {
    _analytics->_logger = &_log;
  }

  ~AuthenticationTest()
  {
    _analytics->_logger = NULL;
  }

protected:
  static LocalStore* _local_data_store;
  static AvStore* _av_store;
  static FakeHSSConnection* _hss_connection;
  static AnalyticsLogger* _analytics;
};

LocalStore* AuthenticationTest::_local_data_store;
AvStore* AuthenticationTest::_av_store;
FakeHSSConnection* AuthenticationTest::_hss_connection;
AnalyticsLogger* AuthenticationTest::_analytics;

class AuthenticationMessage
{
public:
  string _method;
  string _user;
  string _domain;
  bool _auth_hdr;
  string _auth_user;
  string _auth_realm;
  string _nonce;
  string _uri;
  string _response;
  string _algorithm;
  string _opaque;
  string _integ_prot;

  AuthenticationMessage(std::string method) :
    _method(method),
    _user("6505550001"),
    _domain("ut.cw-ngv.com"),
    _auth_hdr(true),
    _auth_user("6505550001@ut.cw-ngv.com"),
    _auth_realm("ut.cw-ngv.com"),
    _nonce(""),
    _uri("sip:ut.cw-ngv.com"),
    _response("8deeadd5f2d912be142530786bc0ccab"),
    _algorithm("md5"),
    _opaque(""),
    _integ_prot("")
  {
  }

  string get();
};

string AuthenticationMessage::get()
{
  char buf[16384];

  int n = snprintf(buf, sizeof(buf),
                   "%1$s sip:%3$s SIP/2.0\r\n"
                   "Via: SIP/2.0/TCP 10.83.18.38:36530;rport;branch=z9hG4bKPjmo1aimuq33BAI4rjhgQgBr4sY5e9kSPI\r\n"
                   "Via: SIP/2.0/TCP 10.114.61.213:5061;received=23.20.193.43;branch=z9hG4bK+7f6b263a983ef39b0bbda2135ee454871+sip+1+a64de9f6\r\n"
                   "Max-Forwards: 68\r\n"
                   "Supported: outbound, path\r\n"
                   "To: <sip:%2$s@%3$s>\r\n"
                   "From: <sip:%2$s@%3$s>;tag=fc614d9c\r\n"
                   "Call-ID: OWZiOGFkZDQ4MGI1OTljNjlkZDkwNTdlMTE0NmUyOTY.\r\n"
                   "CSeq: 1 %1$s\r\n"
                   "Expires: 300\r\n"
                   "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO\r\n"
                   "User-Agent: X-Lite release 5.0.0 stamp 67284\r\n"
                   "Contact: <sip:%2$s@uac.example.com:5060;rinstance=f0b20987985b61df;transport=TCP>\r\n"
                   "Route: <sip:sprout.ut.cw-ngv.com;transport=tcp;lr>\r\n"
                   "%4$s"
                   "Content-Length: 0\r\n"
                   "\r\n",
                   /*  1 */ _method.c_str(),
                   /*  2 */ _user.c_str(),
                   /*  3 */ _domain.c_str(),
                   /*  4 */ _auth_hdr ?
                              string("Authorization: Digest ")
                                .append((!_auth_user.empty()) ? string("username=\"").append(_auth_user).append("\", ") : "")
                                .append((!_auth_realm.empty()) ? string("realm=\"").append(_auth_realm).append("\", ") : "")
                                .append((!_nonce.empty()) ? string("nonce=\"").append(_nonce).append("\", ") : "")
                                .append((!_uri.empty()) ? string("uri=\"").append(_uri).append("\", ") : "")
                                .append((!_response.empty()) ? string("response=\"").append(_response).append("\", ") : "")
                                .append((!_opaque.empty()) ? string("opaque=\"").append(_opaque).append("\", ") : "")
                                .append((!_integ_prot.empty()) ? string("integrity-protected=\"").append(_integ_prot).append("\", ") : "")
                                .append((!_algorithm.empty()) ? string("algorithm=").append(_algorithm) : "")
                                .append("\r\n").c_str() :
                              ""
    );

  EXPECT_LT(n, (int)sizeof(buf));

  string ret(buf, n);
  //cout << ret <<endl;
  return ret;
}


TEST_F(AuthenticationTest, NoAuthorizationNonReg)
{
  // Test that Sprout accepts non-REGISTER requests with no authorization header.
  AuthenticationMessage msg("INVITE");
  msg._auth_hdr = false;
  pj_bool_t ret = inject_msg_direct(msg.get());
  EXPECT_EQ(PJ_FALSE, ret);
}

