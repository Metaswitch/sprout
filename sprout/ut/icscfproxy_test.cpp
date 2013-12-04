/**
 * @file icscfproxy_test.cpp UT for I-CSCF proxy class.
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
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <boost/lexical_cast.hpp>

#include "pjutils.h"
#include "constants.h"
#include "siptest.hpp"
#include "utils.h"
#include "test_utils.hpp"
#include "analyticslogger.h"
#include "icscfproxy.h"
#include "fakelogger.hpp"
#include "fakehssconnection.hpp"
#include "test_interposer.hpp"

using namespace std;
using testing::StrEq;
using testing::ElementsAre;
using testing::MatchesRegex;
using testing::HasSubstr;
using testing::Not;

/// ABC for fixtures for ICSCFProxyTest.
class ICSCFProxyTestBase : public SipTest
{
public:
  FakeLogger _log;

  /// TX data for testing.  Will be cleaned up.  Each message in a
  /// forked flow has its URI stored in _uris, and its txdata stored
  /// in _tdata against that URI.

  /// Set up test case.  Caller must clear host_mapping.
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase(false);

    _analytics = new AnalyticsLogger("foo");
    delete _analytics->_logger;
    _analytics->_logger = NULL;

    _scscf_selector = new SCSCFSelector();
    _hss_connection = new FakeHSSConnection();

    _icscf_proxy = new ICSCFProxy(stack_data.endpt,
                                  5056,
                                  PJSIP_MOD_PRIORITY_UA_PROXY_LAYER+1,
                                  _hss_connection,
                                  _scscf_selector,
                                  _analytics);

    // Schedule timers.
    SipTest::poll();
  }

  static void TearDownTestCase()
  {
    // Shut down the transaction module first, before we destroy the
    // objects that might handle any callbacks!
    pjsip_tsx_layer_destroy();
    delete _icscf_proxy; _icscf_proxy = NULL;
    delete _analytics; _analytics = NULL;
    delete _hss_connection; _hss_connection = NULL;
    delete _scscf_selector; _scscf_selector = NULL;
    SipTest::TearDownTestCase();
  }

  ICSCFProxyTestBase()
  {
    Log::setLoggingLevel(99);
    _log_traffic = FakeLogger::isNoisy(); // true to see all traffic
    _analytics->_logger = &_log;
    _hss_connection->flush_all();
  }

  ~ICSCFProxyTestBase()
  {
    pjsip_tsx_layer_dump(true);

    // Terminate all transactions
    list<pjsip_transaction*> tsxs = get_all_tsxs();
    for (list<pjsip_transaction*>::iterator it2 = tsxs.begin();
         it2 != tsxs.end();
         ++it2)
    {
      pjsip_tsx_terminate(*it2, PJSIP_SC_SERVICE_UNAVAILABLE);
    }

    // PJSIP transactions aren't actually destroyed until a zero ms
    // timer fires (presumably to ensure destruction doesn't hold up
    // real work), so poll for that to happen. Otherwise we leak!
    // Allow a good length of time to pass too, in case we have
    // transactions still open. 32s is the default UAS INVITE
    // transaction timeout, so we go higher than that.
    cwtest_advance_time_ms(33000L);
    poll();
    // Stop and restart the transaction layer just in case
    pjsip_tsx_layer_instance()->stop();
    pjsip_tsx_layer_instance()->start();

    _analytics->_logger = NULL;
  }

  class Message
  {
  public:
    string _method;
    string _requri; //< overrides toscheme:to@todomain
    string _toscheme;
    string _status;
    string _from;
    string _fromdomain;
    string _to;
    string _todomain;
    string _content_type;
    string _body;
    string _extra;
    int _forwards;
    int _unique; //< unique to this dialog; inserted into Call-ID
    string _via;
    string _route;
    int _cseq;

    Message() :
      _method("INVITE"),
      _toscheme("sip"),
      _status("200 OK"),
      _from("6505551000"),
      _fromdomain("homedomain"),
      _to("6505551234"),
      _todomain("homedomain"),
      _content_type("application/sdp"),
      _forwards(68),
      _via("10.83.18.38:36530"),
      _cseq(16567)
    {
      static int unique = 1042;
      _unique = unique;
      unique += 10; // leave room for manual increments
    }

    void set_route(pjsip_msg* msg)
    {
      string route = get_headers(msg, "Record-Route");
      if (route != "")
      {
        // Convert to a Route set by replacing all instances of Record-Route: with Route:
        for (size_t n = 0; (n = route.find("Record-Route:", n)) != string::npos;)
        {
          route.replace(n, 13, "Route:");
        }
      }
      _route = route;
    }

    string get_request()
    {
      char buf[16384];

      // The remote target.
      string target = string(_toscheme).append(":").append(_to);
      if (!_todomain.empty())
      {
        target.append("@").append(_todomain);
      }

      string requri = target;
      string route = _route.empty() ? "" : _route.append("\r\n");

      int n = snprintf(buf, sizeof(buf),
                       "%1$s %9$s SIP/2.0\r\n"
                       "Via: SIP/2.0/TCP %12$s;rport;branch=z9hG4bKPjmo1aimuq33BAI4rjhgQgBr4sY%11$04dSPI\r\n"
                       "From: <sip:%2$s@%3$s>;tag=10.114.61.213+1+8c8b232a+5fb751cf\r\n"
                       "To: <%10$s>\r\n"
                       "Max-Forwards: %8$d\r\n"
                       "Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs%11$04dohntC@10.114.61.213\r\n"
                       "CSeq: %14$d %1$s\r\n"
                       "User-Agent: Accession 2.0.0.0\r\n"
                       "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n"
                       "%4$s"
                       "%7$s"
                       "%13$s"
                       "Content-Length: %5$d\r\n"
                       "\r\n"
                       "%6$s",
                       /*  1 */ _method.c_str(),
                       /*  2 */ _from.c_str(),
                       /*  3 */ _fromdomain.c_str(),
                       /*  4 */ _content_type.empty() ? "" : string("Content-Type: ").append(_content_type).append("\r\n").c_str(),
                       /*  5 */ (int)_body.length(),
                       /*  6 */ _body.c_str(),
                       /*  7 */ _extra.empty() ? "" : string(_extra).append("\r\n").c_str(),
                       /*  8 */ _forwards,
                       /*  9 */ _requri.empty() ? requri.c_str() : _requri.c_str(),
                       /* 10 */ target.c_str(),
                       /* 11 */ _unique,
                       /* 12 */ _via.c_str(),
                       /* 13 */ route.c_str(),
                       /* 14 */ _cseq
        );

      EXPECT_LT(n, (int)sizeof(buf));

      string ret(buf, n);
      // cout << ret <<endl;
      return ret;
    }

    string get_response()
    {
      char buf[16384];

      int n = snprintf(buf, sizeof(buf),
                       "SIP/2.0 %9$s\r\n"
                       "Via: SIP/2.0/TCP %13$s;rport;branch=z9hG4bKPjmo1aimuq33BAI4rjhgQgBr4sY%11$04dSPI\r\n"
                       "From: <sip:%2$s@%3$s>;tag=10.114.61.213+1+8c8b232a+5fb751cf\r\n"
                       "To: <sip:%7$s%8$s>\r\n"
                       "Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs%11$04dohntC@10.114.61.213\r\n"
                       "CSeq: %12$d %1$s\r\n"
                       "User-Agent: Accession 2.0.0.0\r\n"
                       "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n"
                       "%4$s"
                       "%10$s"
                       "Content-Length: %5$d\r\n"
                       "\r\n"
                       "%6$s",
                       /*  1 */ _method.c_str(),
                       /*  2 */ _from.c_str(),
                       /*  3 */ _fromdomain.c_str(),
                       /*  4 */ _content_type.empty() ? "" : string("Content-Type: ").append(_content_type).append("\r\n").c_str(),
                       /*  5 */ (int)_body.length(),
                       /*  6 */ _body.c_str(),
                       /*  7 */ _to.c_str(),
                       /*  8 */ _todomain.empty() ? "" : string("@").append(_todomain).c_str(),
                       /*  9 */ _status.c_str(),
                       /* 10 */ _extra.empty() ? "" : string(_extra).append("\r\n").c_str(),
                       /* 11 */ _unique,
                       /* 12 */ _cseq,
                       /* 13 */ _via.c_str()
        );

      EXPECT_LT(n, (int)sizeof(buf));

      string ret(buf, n);
      // cout << ret <<endl;
      return ret;
    }
  };


protected:
  static AnalyticsLogger* _analytics;
  static FakeHSSConnection* _hss_connection;
  static SCSCFSelector* _scscf_selector;
  static ICSCFProxy* _icscf_proxy;

};

AnalyticsLogger* ICSCFProxyTestBase::_analytics;
FakeHSSConnection* ICSCFProxyTestBase::_hss_connection;
SCSCFSelector* ICSCFProxyTestBase::_scscf_selector;
ICSCFProxy* ICSCFProxyTestBase::_icscf_proxy;


class ICSCFProxyTest : public ICSCFProxyTestBase
{
public:
  static void SetUpTestCase()
  {
    // Set up DNS mappings for some S-CSCFs.
    cwtest_clear_host_mapping();
    cwtest_add_host_mapping("scscf1.homedomain", "10.10.10.1");
    cwtest_add_host_mapping("scscf2.homedomain", "10.10.10.2");
    cwtest_add_host_mapping("scscf3.homedomain", "10.10.10.3");
    cwtest_add_host_mapping("scscf4.homedomain", "10.10.10.4");
    cwtest_add_host_mapping("scscf5.homedomain", "10.10.10.5");

    ICSCFProxyTestBase::SetUpTestCase();
  }

  static void TearDownTestCase()
  {
    ICSCFProxyTestBase::TearDownTestCase();
  }

  ICSCFProxyTest()
  {
  }

  ~ICSCFProxyTest()
  {
  }

protected:
};



TEST_F(ICSCFProxyTest, RouteRegisterHSSServerName)
{
  // Tests routing of REGISTER requests when the HSS responses with a server
  // name.  There are two cases tested here - one where the impi is defaulted
  // from the impu and one where the impi is explicit specified in an
  // Authorization header.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        5056,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the user registration status query using
  // a default private user identity.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&auth-type=REGISTRATION",
                              "{\"result-code\": \"DIAMETER_SUCCESS\", \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

  // Inject a REGISTER request.
  Message msg1;
  msg1._method = "REGISTER";
  msg1._requri = "sip:homedomain";
  msg1._to = msg1._from;        // To header contains AoR in REGISTER requests.
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  inject_msg(msg1.get_request(), tp);

  // REGISTER request should be forwarded to the server named in the HSS
  // response, scscf1.homedomain.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("REGISTER");
  r1.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf1.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route or Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", rr);
  ASSERT_EQ("", route);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r2(200);
  r2.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&auth-type=REGISTRATION");

  // Set up the HSS response for the user registration status query using
  // a specified private user identity.
  _hss_connection->set_result("/impi/7132565489%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&auth-type=REGISTRATION",
                              "{\"result-code\": \"DIAMETER_SUCCESS\", \"scscf\": \"sip:scscf2.homedomain:5058;transport=TCP\"}");

  // Inject a REGISTER request.
  Message msg2;
  msg2._method = "REGISTER";
  msg1._requri = "sip:homedomain";
  msg2._to = msg2._from;        // To header contains AoR in REGISTER requests.
  msg2._via = tp->to_string(false);
  msg2._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg2._extra += "Authorization: Digest username=\"7132565489@homedomain\"";
  inject_msg(msg2.get_request(), tp);

  // REGISTER request should be forwarded to the server named in the HSS
  // response, scscf1.homedomain.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.2", 5058, tdata);
  ReqMatcher r3("REGISTER");
  r3.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf2.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route or Record-Route headers have been added.
  rr = get_headers(tdata->msg, "Record-Route");
  route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", rr);
  ASSERT_EQ("", route);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r4(200);
  r4.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/7132565489%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&auth-type=REGISTRATION");

  delete tp;
}


TEST_F(ICSCFProxyTest, RouteOrigInviteHSSServerName)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        5056,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the originating location query.
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true",
                              "{\"result-code\": \"DIAMETER_SUCCESS\", \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

  // Inject a INVITE request with orig in the Route header and a P-Served-User
  // header.
  Message msg1;
  msg1._method = "INVITE";
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg1._extra += "P-Served-User: <sip:6505551000@homedomain>";
  msg1._route = "Route: <sip:homedomain;orig>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // INVITE request should be forwarded to the server named in the HSS
  // response, scscf1.homedomain.
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf1.homedomain:5058;transport=TCP;lr;orig>", route);

  // Check that no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r2(200);
  r2.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impu/sip%3A6505551000%40homedomain/location?originating=true");

  delete tp;
}


TEST_F(ICSCFProxyTest, RouteTermInviteHSSServerName)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        5056,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the originating location query.
  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": \"DIAMETER_SUCCESS\", \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

  // Inject a INVITE request with orig in the Route header and a P-Served-User
  // header.
  Message msg1;
  msg1._method = "INVITE";
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg1._extra += "P-Served-User: <sip:6505551000@homedomain>";
  msg1._route = "Route: <sip:homedomain>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // INVITE request should be forwarded to the server named in the HSS
  // response, scscf1.homedomain.
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf1.homedomain:5058;transport=TCP;lr>", route);

  // Check that no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r2(200);
  r2.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impu/sip%3A6505551234%40homedomain/location");

  delete tp;
}


