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
#include "icscfsproutlet.h"
#include "fakehssconnection.hpp"
#include "test_interposer.hpp"
#include "sproutletproxy.h"

using namespace std;
using testing::StrEq;
using testing::ElementsAre;
using testing::MatchesRegex;
using testing::HasSubstr;
using testing::Not;

/// ABC for fixtures for ICSCFSproutletTest.
class ICSCFSproutletTestBase : public SipTest
{
public:
  /// TX data for testing.  Will be cleaned up.  Each message in a
  /// forked flow has its URI stored in _uris, and its txdata stored
  /// in _tdata against that URI.

  /// Set up test case.  Caller must clear host_mapping.
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase(false);

    _hss_connection = new FakeHSSConnection();
    _acr_factory = new ACRFactory();
    _scscf_selector = new SCSCFSelector(string(UT_DIR).append("/test_icscf.json"));
    _enum_service = new JSONEnumService(string(UT_DIR).append("/test_enum.json"));

    _icscf_sproutlet = new ICSCFSproutlet("sip:bgcf.homedomain",
                                          stack_data.icscf_port,
                                          _hss_connection,
                                          _acr_factory,
                                          _scscf_selector,
                                          _enum_service,
                                          true,
                                          false,
                                          false);
    _icscf_sproutlet->init();
    std::list<Sproutlet*> sproutlets;
    sproutlets.push_back(_icscf_sproutlet);

    _icscf_proxy = new SproutletProxy(stack_data.endpt,
                                      PJSIP_MOD_PRIORITY_UA_PROXY_LAYER,
                                      "sip:homedomain:" + std::to_string(stack_data.icscf_port),
                                      std::unordered_set<std::string>(),
                                      sproutlets,
                                      std::set<std::string>());

    // Schedule timers.
    SipTest::poll();
  }

  static void TearDownTestCase()
  {
    // Shut down the transaction module first, before we destroy the
    // objects that might handle any callbacks!
    pjsip_tsx_layer_destroy();
    delete _icscf_proxy; _icscf_proxy = NULL;
    delete _icscf_sproutlet; _icscf_sproutlet = NULL;
    delete _enum_service; _enum_service = NULL;
    delete _acr_factory; _acr_factory = NULL;
    delete _hss_connection; _hss_connection = NULL;
    delete _scscf_selector; _scscf_selector = NULL;
    SipTest::TearDownTestCase();
  }

  ICSCFSproutletTestBase()
  {
    _log_traffic = PrintingTestLogger::DEFAULT.isPrinting(); // true to see all traffic
    _hss_connection->flush_all();
  }

  ~ICSCFSproutletTestBase()
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
      string route = _route.empty() ? "" : _route + "\r\n";

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
  static ACRFactory* _acr_factory;
  static FakeHSSConnection* _hss_connection;
  static SCSCFSelector* _scscf_selector;
  static JSONEnumService* _enum_service;
  static ICSCFSproutlet* _icscf_sproutlet;
  static SproutletProxy* _icscf_proxy;

};

ACRFactory* ICSCFSproutletTestBase::_acr_factory;
FakeHSSConnection* ICSCFSproutletTestBase::_hss_connection;
SCSCFSelector* ICSCFSproutletTestBase::_scscf_selector;
JSONEnumService* ICSCFSproutletTestBase::_enum_service;
ICSCFSproutlet* ICSCFSproutletTestBase::_icscf_sproutlet;
SproutletProxy* ICSCFSproutletTestBase::_icscf_proxy;


class ICSCFSproutletTest : public ICSCFSproutletTestBase
{
public:
  static void SetUpTestCase()
  {
    ICSCFSproutletTestBase::SetUpTestCase();

    // Set up DNS mappings for some S-CSCFs and a BGCF.
    add_host_mapping("scscf1.homedomain", "10.10.10.1");
    add_host_mapping("scscf2.homedomain", "10.10.10.2");
    add_host_mapping("scscf3.homedomain", "10.10.10.3");
    add_host_mapping("scscf4.homedomain", "10.10.10.4");
    add_host_mapping("scscf5.homedomain", "10.10.10.5");
    add_host_mapping("bgcf.homedomain",   "10.10.11.1");
  }

  static void TearDownTestCase()
  {
    ICSCFSproutletTestBase::TearDownTestCase();
  }

  ICSCFSproutletTest()
  {
  }

  ~ICSCFSproutletTest()
  {
  }

protected:
  // Common test setup for the RouteTermInviteLocalUserPhone tests
  TransportFlow *RouteTermInviteLocalUserPhoneSetup()
  {
    // Create a TCP connection to the I-CSCF listening port.
    TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                          stack_data.icscf_port,
                                          "1.2.3.4",
                                          49152);

    // Set up the HSS responses for the terminating location query.
    _hss_connection->set_result("/impu/tel%3A16505551234/location",
                                "{\"result-code\": 2001,"
                                " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

    // Inject an INVITE request to a sip URI representing a telephone number with a
    // P-Served-User header.
    Message msg1;
    msg1._method = "INVITE";
    msg1._requri = "sip:16505551234@homedomain;user=phone;isub=1234;ext=4321";
    msg1._to = "16505551234";
    msg1._via = tp->to_string(false);
    msg1._extra = "Contact: sip:16505551000@" +
                  tp->to_string(true) +
                  ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
    msg1._extra += "P-Served-User: <sip:16505551000@homedomain>";
    msg1._route = "Route: <sip:homedomain>";
    inject_msg(msg1.get_request(), tp);

    return tp;
  }

};



TEST_F(ICSCFSproutletTest, RouteRegisterHSSServerName)
{
  // Tests routing of REGISTER requests when the HSS responses with a server
  // name.  There are two cases tested here - one where the impi is defaulted
  // from the impu and one where the impi is explicit specified in an
  // Authorization header.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the user registration status query using
  // a default private user identity.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

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

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");

  // Set up the HSS response for the user registration status query using
  // a specified private user identity.
  _hss_connection->set_result("/impi/7132565489%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf2.homedomain:5058;transport=TCP\"}");

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

  _hss_connection->delete_result("/impi/7132565489%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteRegisterHSSCaps)
{
  // Tests routing of REGISTER requests when the HSS responses with
  // capabilities.  There are two cases tested here - one where the impi
  // is defaulted from the impu and one where the impi is explicit specified
  // in an Authorization header.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the user registration status query using
  // a default private user identity.  The response returns capabilities
  // rather than an S-CSCF name.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [123, 345],"
                              " \"optional-capabilities\": [654]}");

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

  // REGISTER request should be forwarded to a server matching all the
  // mandatory capabilities, and as many of the optional capabilities as
  // possible.  In this case, the only S-CSCF that matches all mandatory
  // capabilities is scscf1.homedomain.  scscf1.homedomain does not match
  // the optional capabilities.
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

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");

  // Set up the HSS response for the user registration status query using
  // a default private user identity.  The response returns capabilities
  // rather than an S-CSCF name.
  _hss_connection->set_result("/impi/7132565489%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [123],"
                              " \"optional-capabilities\": [654]}");

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

  // REGISTER request should be forwarded to a server matching all the
  // mandatory capabilities, and as many of the optional capabilities as
  // possible.  In this case, both scscf1 and scscf2 match the mandatory
  // capabilities, but only scscf2 matches the optional capabilities as well.
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

  _hss_connection->delete_result("/impi/7132565489%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteRegisterHSSCapsNoMatch)
{
  // Tests routing of REGISTER requests when the HSS responses with
  // capabilities and there are no suitable S-CSCFs.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the user registration status query using
  // a default private user identity.  The response returns capabilities
  // rather than an S-CSCF name.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [765, 123, 345],"
                              " \"optional-capabilities\": [654]}");

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

  // No S-CSCFs support all the mandatory capabilities, so the REGISTER is
  // rejected.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r1(600);
  r1.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteRegisterICSCFLoop)
{
  // Tests routing of REGISTER requests when the HSS responds with
  // a register that points back to the ICSCF sproutlet.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the user registration status query using
  // a default private user identity.  The response returns capabilities
  // rather than an S-CSCF name.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:homedomain:" + std::to_string(stack_data.icscf_port) + ";transport=TCP\"}");

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

  // S-CSCF return resolves to the local domain and I-CSCF port,s, so the REGISTER is
  // rejected with a "Loop detected" error.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r1(482);
  r1.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteRegisterSCSCFReturnedCAPAB)
{
  // Tests routing of REGISTER requests when the S-CSCF returned by the HSS
  // responds with a retryable error to the REGISTER request.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the user registration status query using
  // a default private user identity.  The first response (specifying
  // auth_type=REG) returns scscf1, the second response (specifying
  // auth_type=CAPAB) returns scscf1 again.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

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

  // I-CSCF does an initial HSS lookup with auth_type set to REG,
  // which returns S-CSCF scscf1.homedomain.
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

  // Send a 480 Temporarily Unavailable response.
  inject_msg(respond_to_current_txdata(480));

  // I-CSCF does a second HSS look-up, this time with auth_type set to
  // CAPAB. The HSS returns a scscf name, and no capabilities. The name shouldn't
  // be used (as it's already been tried). I-CSCF should select the S-CSCF with
  // the highest priority (as there are no capabilites) which is scscf4.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.4", 5058, tdata);
  ReqMatcher r2("REGISTER");
  r2.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf4.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

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
  RespMatcher r3(200);
  r3.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");
  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB");

  delete tp;
}

TEST_F(ICSCFSproutletTest, RouteRegisterSCSCFReturnedCAPABAndServerName)
{
  // Tests routing of REGISTER requests when the S-CSCF returned by the HSS
  // responds with a retryable error to the REGISTER request.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the user registration status query using
  // a default private user identity.  The first response (specifying
  // auth_type=REG) returns scscf1, the second response (specifying
  // auth_type=CAPAB) returns scscf1 again.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\","
                              " \"mandatory-capabilities\": [765, 123, 345],"
                              " \"optional-capabilities\": [654]}");

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

  // I-CSCF does an initial HSS lookup with auth_type set to REG,
  // which returns S-CSCF scscf1.homedomain.
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

  // Send a 480 Temporarily Unavailable response.
  inject_msg(respond_to_current_txdata(480));

  // I-CSCF does a second HSS look-up, this time with auth_type set to
  // CAPAB. The HSS returns a scscf name and capabilities. The name shouldn't
  // be used (as it's already been tried). I-CSCF can't select an S-CSCF as
  // there's none with the required capabilities
  // Check the final response is 504.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r2(504);
  r2.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");
  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB");

  delete tp;
}

TEST_F(ICSCFSproutletTest, RouteRegisterHSSRetry)
{
  // Tests routing of REGISTER requests when the S-CSCF returned by the HSS
  // responds with a retryable error to the REGISTER request.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the user registration status query using
  // a default private user identity.  The first response (specifying
  // auth_type=REG) returns scscf1, the second response (specifying
  // auth_type=CAPAB) returns capabilities.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [123],"
                              " \"optional-capabilities\": [345]}");

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

  // I-CSCF does an initial HSS lookup with auth_type set to REG,
  // which returns S-CSCF scscf1.homedomain.
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

  // Send a 480 Temporarily Unavailable response.
  inject_msg(respond_to_current_txdata(480));

  // I-CSCF does a second HSS look-up, this time with auth_type set to
  // CAPAB.  Both scscf1 and scscf2 match the
  // mandatory capabilities, but only scscf1 matches the optional capabilities.
  // Since the I-CSCF has already tried scscf1 it picks scscf2 this time.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.2", 5058, tdata);
  ReqMatcher r2("REGISTER");
  r2.matches(tdata->msg);

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
  RespMatcher r3(200);
  r3.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");
  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteRegisterHSSNoRetry)
{
  // Tests routing of REGISTER requests when the S-CSCF returned by the HSS
  // responds with a non-retryable error to the REGISTER request.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the user registration status query using
  // a default private user identity.  The first response (specifying
  // auth_type=REG) returns scscf1, the second response (specifying
  // auth_type=CAPAB) returns capabilities.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

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

  // I-CSCF does an initial HSS lookup with auth_type set to REG,
  // which returns S-CSCF scscf1.homedomain.
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

  // Send a 401 Not Authorized response.
  inject_msg(respond_to_current_txdata(401));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r2(401);
  r2.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteRegisterHSSMultipleRetry)
{
  // Tests routing of REGISTER requests when the S-CSCF returned by the HSS
  // responds with a retryable error, and the second selected S-CSCF also
  // responds with a retryable error.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the user registration status query using
  // a default private user identity.  The first response (specifying
  // auth_type=REG) returns scscf1, the second response (specifying
  // auth_type=CAPAB) returns capabilities.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [654],"
                              " \"optional-capabilities\": [123]}");

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

  // I-CSCF does an initial HSS lookup with auth_type set to REG,
  // which returns S-CSCF scscf1.homedomain.
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

  // Send a 480 Temporarily Unavailable response.
  inject_msg(respond_to_current_txdata(480));

  // I-CSCF does a second HSS look-up, this time with auth_type set to
  // CAPAB. scscf2, scscf3 and scscf4 match the
  // mandatory capabilities, but only scscf2 matches the optional capabilities.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.2", 5058, tdata);
  ReqMatcher r2("REGISTER");
  r2.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf2.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route or Record-Route headers have been added.
  rr = get_headers(tdata->msg, "Record-Route");
  route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", rr);
  ASSERT_EQ("", route);

  // Send a 480 Temporarily Unavailable response.
  inject_msg(respond_to_current_txdata(480));

  // I-CSCF does another retry. scscf4 is selected as it has a higher priority than scscf3
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.4", 5058, tdata);
  ReqMatcher r3("REGISTER");
  r3.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf4.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

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

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");
  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB");

  delete tp;
}

TEST_F(ICSCFSproutletTest, RouteRegisterHSSMultipleDefaultCapabs)
{
  // Tests routing of REGISTER requests when the S-CSCF returned by the HSS
  // responds with a retryable error, and the CAPAB request to the HSS
  // doesn't return any capabilities (should be treated as empty)
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the user registration status query using
  // a default private user identity.  The first response (specifying
  // auth_type=REG) returns scscf1, the second response (specifying
  // auth_type=CAPAB) returns no capabilities.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB",
                              "{\"result-code\": 2001}");

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

  // I-CSCF does an initial HSS lookup with auth_type set to REG,
  // which returns S-CSCF scscf1.homedomain.
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

  // Send a 480 Temporarily Unavailable response.
  inject_msg(respond_to_current_txdata(480));

  // I-CSCF does another retry. scscf4 is selected as it is the scscf with the highest
  // priority (there are no mandatory capabilities)
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.4", 5058, tdata);
  ReqMatcher r2("REGISTER");
  r2.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf4.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

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
  RespMatcher r3(200);
  r3.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");
  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteRegisterHSSFail)
{
  // Tests routing of REGISTER requests when the HSS responds to the
  // registration status lookup with an invalid response.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up HSS response for the user registration status query.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=roaming.net&auth-type=REG",
                              "{\"result-code\": \"5004\"}");

  // Inject a REGISTER request.
  Message msg1;
  msg1._method = "REGISTER";
  msg1._requri = "sip:homedomain";
  msg1._to = msg1._from;        // To header contains AoR in REGISTER requests.
  msg1._via = tp->to_string(false);
  msg1._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  // Include a P-Visited-Network-ID header.
  msg1._extra += "\r\nP-Visited-Network-ID: roaming.net";
  inject_msg(msg1.get_request(), tp);

  // The user registration status query fails, so the REGISTER is rejected
  // with a 403 Forbidden response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r1(403);
  r1.matches(tdata->msg);

  free_txdata();

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteRegisterHSSBadResponse)
{
  // Tests various cases where the HSS response either fails or is malformed.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Don't set up a HSS response, so the query fail (this simulates an
  // HSS or Homestead timeout).
  _hss_connection->set_rc("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                          HTTP_SERVER_UNAVAILABLE);

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

  // The user registration status query fails, so the REGISTER is rejected
  // with a 480 Temporarily Unavailable response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r1(480);
  r1.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_rc("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");

  // Return 403 on the request. The registration should fail
  _hss_connection->set_rc("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                          HTTP_FORBIDDEN);

  // Inject a REGISTER request.
  Message msg2;
  msg2._method = "REGISTER";
  msg2._requri = "sip:homedomain";
  msg2._to = msg2._from;        // To header contains AoR in REGISTER requests.
  msg2._via = tp->to_string(false);
  msg2._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  inject_msg(msg2.get_request(), tp);

  // The REGISTER is rejected with a 403 Forbidden response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r2(403);
  r2.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_rc("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");

  // Set up HSS response for the user registration status query, with a
  // malformed JSON response (missing the final brace).
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [654],"
                              " \"optional-capabilities\": [123]");
  _hss_connection->set_rc("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                          HTTP_OK);

  // Inject a REGISTER request.
  Message msg3;
  msg3._method = "REGISTER";
  msg3._requri = "sip:homedomain";
  msg3._to = msg3._from;        // To header contains AoR in REGISTER requests.
  msg3._via = tp->to_string(false);
  msg3._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  inject_msg(msg3.get_request(), tp);

  // The HSS response is malformed, so the REGISTER is rejected with a 480 Temporarily Unavailable response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r3(480);
  r3.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");
  _hss_connection->delete_rc("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");

  // Set up HSS response for the user registration status query, with a
  // well structured JSON response, but where the capabilities are not
  // integers.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [\"this\", \"should\", \"be\", \"a\", \"list\", \"of\", \"ints\"],"
                              " \"optional-capabilities\": [123]}");
  _hss_connection->set_rc("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                          HTTP_OK);

  // Inject a REGISTER request.
  Message msg4;
  msg4._method = "REGISTER";
  msg4._requri = "sip:homedomain";
  msg4._to = msg4._from;        // To header contains AoR in REGISTER requests.
  msg4._via = tp->to_string(false);
  msg4._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"";
  inject_msg(msg4.get_request(), tp);

  // The user registration status query fails, so the REGISTER is rejected
  // with a 480 Temporarily Unavailable response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "1.2.3.4", 49152, tdata);
  RespMatcher r4(480);
  r4.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");
  _hss_connection->delete_rc("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteRegisterAllSCSCFsTimeOut)
{
  // Tests routing of REGISTER requests when all the valid S-CSCFs
  // respond with a 480 to the I-CSCF.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the user registration status query using
  // a default private user identity.  The first response (specifying
  // auth_type=REG) returns scscf1, the second response (specifying
  // auth_type=CAPAB) returns scscf1 again.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [123],"
                              " \"optional-capabilities\": [345]}");

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

  // I-CSCF does an initial HSS lookup with auth_type set to REG,
  // which returns S-CSCF scscf1.homedomain.
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

  // Send a 480 Temporarily Unavailable response.
  inject_msg(respond_to_current_txdata(480));

  // I-CSCF does a second HSS look-up, this time with auth_type set to
  // CAPAB. The HSS returns capabilities. I-CSCF selects scscf2 as it's
  // the only S-CSCF with the mandatory capabilites that hasn't been
  // tried yet
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.2", 5058, tdata);
  ReqMatcher r2("REGISTER");
  r2.matches(tdata->msg);

  // Check the RequestURI has been altered to direct the message appropriately.
  ASSERT_EQ("sip:scscf2.homedomain:5058;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route or Record-Route headers have been added.
  rr = get_headers(tdata->msg, "Record-Route");
  route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", rr);
  ASSERT_EQ("", route);

  // Send a 480 Temporarily Unavailable response.
  inject_msg(respond_to_current_txdata(480));

  // Check the final response is 504.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r3(504);
  r3.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");
  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB");

  delete tp;
}

TEST_F(ICSCFSproutletTest, RouteRegisterHSSNotFound)
{
  // Tests routing of REGISTER requests when the HSS CAPAB request fails
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the user registration status query using
  // a default private user identity.  The first response (specifying
  // auth_type=REG) returns scscf1, the second response (specifying
  // auth_type=CAPAB) returns a 403.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");
  _hss_connection->set_rc("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB",
                          HTTP_FORBIDDEN);

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

  // I-CSCF does an initial HSS lookup with auth_type set to REG,
  // which returns S-CSCF scscf1.homedomain.
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

  // Send a 480 Temporarily Unavailable response.
  inject_msg(respond_to_current_txdata(480));

  // I-CSCF does a second HSS look-up, this time with auth_type set to
  // CAPAB. This throws a 403 though. Check the final response is 403.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r2(403);
  r2.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");
  _hss_connection->delete_rc("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=CAPAB");

  delete tp;
}

TEST_F(ICSCFSproutletTest, RouteOrigInviteHSSServerName)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the originating location query.
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

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


TEST_F(ICSCFSproutletTest, RouteOrigInviteHSSCaps)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the originating location query.
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [654],"
                              " \"optional-capabilities\": [567]}");

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

  // Both scscf3 and scscf4 match all mandatory capabilities, but scscf4 has
  // higher priority.
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.4", 5058, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf4.homedomain:5058;transport=TCP;lr;orig>", route);

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


TEST_F(ICSCFSproutletTest, RouteOrigInviteHSSCapsNoMatch)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the originating location query.
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [765, 654],"
                              " \"optional-capabilities\": [567]}");

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

  // Expecting 100 Trying and a final response
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Check the 600 response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r1(600);
  r1.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impu/sip%3A6505551000%40homedomain/location?originating=true");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteOrigInviteHSSRetry)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the originating location query.
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true&auth-type=CAPAB",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [654],"
                              " \"optional-capabilities\": [567]}");

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

  // The HSS originally returns S-CSCF scscf1.homedomain.
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

  // Kill the TCP connection to the S-CSCF to force a retry.
  terminate_tcp_transport(tdata->tp_info.transport);
  free_txdata();
  cwtest_advance_time_ms(6000);
  poll();

  // The HSS is queried a second time for capabilities.  This time S-CSCF
  // scscf4.homedomain is selected.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.4", 5058, tdata);
  ReqMatcher r3("INVITE");
  r3.matches(tdata->msg);

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf4.homedomain:5058;transport=TCP;lr;orig>", route);

  // Check that no Record-Route headers have been added.
  rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r4(200);
  r4.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impu/sip%3A6505551000%40homedomain/location?originating=true");
  _hss_connection->delete_result("/impu/sip%3A6505551000%40homedomain/location?originating=true&auth-type=CAPAB");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteOrigInviteHSSFail)
{
  // Tests originating call when HSS request fails.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Don't set up the HSS response - this will simulate a 404 response
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

  // Expecting 100 Trying and final 404 responses.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Check the 404 Not Found.
  tdata = current_txdata();
  RespMatcher(404).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Set up the HSS response for the originating location query.
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true",
                              "{\"result-code\": 5004}");

  // Inject a INVITE request with orig in the Route header and a P-Served-User
  // header.
  Message msg2;
  msg2._method = "INVITE";
  msg2._via = tp->to_string(false);
  msg2._extra = "Contact: sip:6505551000@" +
                tp->to_string(true) +
                ";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  msg2._extra += "P-Served-User: <sip:6505551000@homedomain>";
  msg2._route = "Route: <sip:homedomain;orig>";
  inject_msg(msg2.get_request(), tp);

  // Expecting 100 Trying and final 404 responses.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Check the 404 Not Found.
  tdata = current_txdata();
  RespMatcher(404).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  _hss_connection->delete_result("/impu/sip%3A6505551000%40homedomain/location?originating=true");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteOrigInviteCancel)
{
  // Tests handling of a CANCEL requests after an INVITE has been forwarded.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the originating location query.
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

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
  tp->expect_target(tdata);
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // INVITE request should be forwarded to the server named in the HSS
  // response, scscf1.homedomain.
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Store the INVITE to build a later response.
  pjsip_tx_data* invite_tdata = pop_txdata();

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf1.homedomain:5058;transport=TCP;lr;orig>", route);

  // Check that no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Build and send a CANCEL chasing the INVITE.
  Message msg2;
  msg2._method = "CANCEL";
  msg2._via = tp->to_string(false);
  msg2._unique = msg1._unique;    // Make sure branch and call-id are same as the INVITE
  inject_msg(msg2.get_request(), tp);

  // Expect the 200 OK response to the CANCEL, but no forwarded CANCEL as
  // no provisional response has yet been received.
  ASSERT_EQ(1, txdata_count());

  // Check the 200 OK.
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();
  ASSERT_EQ(0, txdata_count());

  // Send a 100 Trying response to the INVITE, triggering the onward CANCEL.
  inject_msg(respond_to_txdata(invite_tdata, 100));

  // Check the CANCEL is forwarded.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r2("CANCEL");
  r2.matches(tdata->msg);

  // Send a 200 OK response to the CANCEL.  This is swallowed by the proxy.
  inject_msg(respond_to_current_txdata(200));
  ASSERT_EQ(0, txdata_count());

  // Now send a 487 response to the INVITE.
  inject_msg(respond_to_txdata(invite_tdata, 487));

  // Catch the ACK to the 487 response
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5058, tdata);
  ReqMatcher r3("ACK");
  r3.matches(tdata->msg);
  free_txdata();

  // Check the 487 response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(487).matches(tdata->msg);
  free_txdata();

  _hss_connection->delete_result("/impu/sip%3A6505551000%40homedomain/location?originating=true");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteTermInviteHSSServerName)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the terminating location query.
  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

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


TEST_F(ICSCFSproutletTest, RouteTermInviteHSSCaps)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the terminating location query.
  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [567],"
                              " \"optional-capabilities\": [789, 567]}");

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

  // Both scscf3 and scscf4 match all mandatory characteristics, but only
  // scscf3 matches both optional capabilities.
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.3", 5058, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf3.homedomain:5058;transport=TCP;lr>", route);

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


TEST_F(ICSCFSproutletTest, RouteTermInviteNoUnregisteredServices)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the terminating location query.
  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 5003}");

  // Inject a INVITE request
  Message msg1;
  msg1._method = "INVITE";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:homedomain>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and 480 Temporarily Unavailable
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Check the 480.
  tdata = current_txdata();
  RespMatcher(480).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  _hss_connection->delete_result("/impu/sip%3A6505551234%40homedomain/location");

  delete tp;
}



TEST_F(ICSCFSproutletTest, RouteTermInviteHSSRetry)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the terminating location query.
  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");
  _hss_connection->set_result("/impu/sip%3A6505551234%40homedomain/location?auth-type=CAPAB",
                              "{\"result-code\": 2001,"
                              " \"mandatory-capabilities\": [567],"
                              " \"optional-capabilities\": [789, 567]}");

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

  // Kill the TCP connection to the S-CSCF to force a retry.
  terminate_tcp_transport(tdata->tp_info.transport);
  free_txdata();
  cwtest_advance_time_ms(6000);
  poll();

  // I-CSCF does another HSS location query for capabilities.  This time
  // scscf3 is selected.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.3", 5058, tdata);
  ReqMatcher r3("INVITE");
  r3.matches(tdata->msg);

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf3.homedomain:5058;transport=TCP;lr>", route);

  // Check that no Record-Route headers have been added.
  rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Kill the TCP connection to the S-CSCF to force a retry.
  terminate_tcp_transport(tdata->tp_info.transport);
  free_txdata();
  cwtest_advance_time_ms(6000);
  poll();

  // I-CSCF does another HSS location query for capabilities.  This time
  // scscf4 is selected.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.4", 5058, tdata);
  ReqMatcher r5("INVITE");
  r5.matches(tdata->msg);

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:scscf4.homedomain:5058;transport=TCP;lr>", route);

  // Check that no Record-Route headers have been added.
  rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r6(200);
  r6.matches(tdata->msg);

  free_txdata();

  _hss_connection->delete_result("/impu/sip%3A6505551234%40homedomain/location");
  _hss_connection->delete_result("/impu/sip%3A6505551234%40homedomain/location?auth-type=CAPAB");

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteTermInviteTelURI)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the terminating location query.
  _hss_connection->set_result("/impu/tel%3A%2B16505551234/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

  // Inject an INVITE request to a tel URI with a P-Served-User header.
  Message msg1;
  msg1._method = "INVITE";
  msg1._toscheme = "tel";
  msg1._to = "+16505551234;npdi";
  msg1._todomain = "";
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


TEST_F(ICSCFSproutletTest, RouteTermInviteEnum)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the terminating location query.
  _hss_connection->set_result("/impu/sip%3A%2B16505551234%40homedomain/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

  // Inject an INVITE request to a tel URI with a P-Served-User header.
  Message msg1;
  msg1._method = "INVITE";
  msg1._toscheme = "tel";
  msg1._to = "+16605551234";
  msg1._todomain = "";
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


TEST_F(ICSCFSproutletTest, RouteTermInviteEnumBgcf)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject an INVITE request to a tel URI with a P-Served-User header.
  Message msg1;
  msg1._method = "INVITE";
  msg1._toscheme = "tel";
  msg1._to = "+16607771234";
  msg1._todomain = "";
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

  // INVITE request should be forwarded to the BGCF.
  tdata = current_txdata();
  expect_target("FAKE_UDP", "0.0.0.0", 0, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check that a Route header has been added routing the INVITE to the
  // selected S-CSCF.  This must include the orig parameter.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:bgcf.homedomain;lr>", route);

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
  delete tp;
}

// Test the case where the I-CSCF does an ENUM lookup which returns
// NP data. The requ URI should be rewritten to include the NP data,
// and the request should be forwarded to the BGCF
TEST_F(ICSCFSproutletTest, RouteTermInviteEnumNP)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject an INVITE request to a tel URI
  Message msg1;
  msg1._method = "INVITE";
  msg1._toscheme = "tel";
  msg1._to = "+1690100001";
  msg1._todomain = "";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // INVITE request should be forwarded to the BGCF.
  tdata = current_txdata();
  expect_target("FAKE_UDP", "0.0.0.0", 0, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check the RequestURI has been altered
  ASSERT_EQ("tel:+1690100001;npdi;rn=16901", str_uri(tdata->msg->line.req.uri));

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r2(200);
  r2.matches(tdata->msg);

  free_txdata();
  delete tp;
}

// Test the case where the I-CSCF does an ENUM lookup which returns
// NP data, but already has NP in the req URI. The req URI should not
// be rewritten and the request should be forwarded to the BGCF
TEST_F(ICSCFSproutletTest, RouteTermInviteEnumExistingNP)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject an INVITE request to a tel URI
  Message msg1;
  msg1._method = "INVITE";
  msg1._toscheme = "tel";
  msg1._to = "+1690100001;npdi";
  msg1._todomain = "";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // INVITE request should be forwarded to the BGCF.
  tdata = current_txdata();
  expect_target("FAKE_UDP", "0.0.0.0", 0, tdata);
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check the RequestURI hasn't been altered
  ASSERT_EQ("tel:+1690100001;npdi", str_uri(tdata->msg->line.req.uri));

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher r2(200);
  r2.matches(tdata->msg);

  free_txdata();
  delete tp;
}

TEST_F(ICSCFSproutletTest, RouteTermInviteUserPhone)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the terminating location query.
  _hss_connection->set_result("/impu/tel%3A%2B16505551234/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

  // Inject an INVITE request to a sip URI representing a telephone number with a
  // P-Served-User header.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:+16505551234@homedomain;user=phone;isub=1234;ext=4321";
  msg1._to = "+16505551234";
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

// The following test (similar to RouteTermInviteUserPhone apart from the
// absence of leading "+" characters on the user) verifies that I-CSCF doesn't
// perform a Tel URI conversion if the number is not globally specified (i.e.
// doesn't start with a "+") AND enforce_global_lookups is on.
TEST_F(ICSCFSproutletTest, RouteTermInviteLocalUserPhoneFailure)
{
  pjsip_tx_data* tdata;

  // Turn on enforcement of global-only user=phone to Tel URI lookups in I-CSCF
  _icscf_sproutlet->set_global_only_lookups_enforced(true);

  // Setup common config and submit test INVITE
  TransportFlow* tp = RouteTermInviteLocalUserPhoneSetup();

  // Expecting 100 Trying and final 404 responses.  I-CSCF shouldn't perform
  // a TelURI conversion and therefore shouldn't match on the HSS result
  // inserted above.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Check the 404 Not Found.
  tdata = current_txdata();
  RespMatcher(404).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  _hss_connection->delete_result("/impu/tel%3A16505551234/location");

  delete tp;
}

// The following test checks that the user=phone => Tel URI conversion IS
// performed for location lookup for local numbers if enforce_global_lookups
// is OFF
TEST_F(ICSCFSproutletTest, RouteTermInviteLocalUserPhoneSuccess)
{
  pjsip_tx_data* tdata;

  // Turn off enforcement of global-only user=phone to Tel URI lookups in I-CSCF
  _icscf_sproutlet->set_global_only_lookups_enforced(false);

  // Setup common config and submit test INVITE
  TransportFlow* tp = RouteTermInviteLocalUserPhoneSetup();

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

  _hss_connection->delete_result("/impu/tel%3A16505551234/location");

  delete tp;
}

TEST_F(ICSCFSproutletTest, RouteTermInviteNumericSIPURI)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS responses for the terminating location query.
  _hss_connection->set_result("/impu/tel%3A%2B16505551234/location",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

  // Inject an INVITE request to a sip URI representing a telephone number with a
  // P-Served-User header.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:+16505551234@homedomain";
  msg1._to = "+16505551234";
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


TEST_F(ICSCFSproutletTest, ProxyAKARegisterChallenge)
{
  // Tests that routing a REGISTER 401 repsonse with an AKA challenge does not
  // change the contents of the www-authenticate header (this was sprout
  // issue 412).

  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the user registration status query using
  // a default private user identity.
  _hss_connection->set_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sip:scscf1.homedomain:5058;transport=TCP\"}");

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

  // REGISTER request is forwarded on.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();

  // Reject the REGISTER with a 401 response with a WWW-Authenticate header.
  std::string www_auth = "WWW-Authenticate: Digest  realm=\"os1.richlab.datcon.co.uk\","
                           "nonce=\"u1ZqEvWFsXIqYZ0TwbCQ8/sa60VVnTAw6epZzjfS+30\","
                           "opaque=\"143fe4cd3f27d32b\","
                           "algorithm=AKAv1-MD5,"
                           "qop=\"auth\","
                           "ck=\"d725a54a6097b9db17933e583c7fefb0\","
                           "ik=\"c8d8c92790a214e3877aa9ab4c3fdaf6\"";
  inject_msg(respond_to_current_txdata(401, "", www_auth));

  // Check the response is forwarded back to the source with the same
  // WWW-Authenticate header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  EXPECT_EQ(get_headers(tdata->msg, "WWW-Authenticate"), www_auth);

  // Tidy up.
  free_txdata();
  _hss_connection->delete_result("/impi/6505551000%40homedomain/registration-status?impu=sip%3A6505551000%40homedomain&visited-network=homedomain&auth-type=REG");
  delete tp; tp = NULL;
}


TEST_F(ICSCFSproutletTest, RequestErrors)
{
  // Tests various errors on requests.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a INVITE request with a sips: RequestURI
  Message msg1;
  msg1._method = "INVITE";
  msg1._toscheme = "sips";
  msg1._from = "alice";
  msg1._to = "+2425551234";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Check the 416 Unsupported URI Scheme response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(416).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Send an ACK to complete the UAS transaction.
  msg1._method = "ACK";
  inject_msg(msg1.get_request(), tp);

  // Inject an INVITE request with Max-Forwards <= 1.
  Message msg2;
  msg2._method = "INVITE";
  msg2._requri = "sip:bob@awaydomain";
  msg2._from = "alice";
  msg2._to = "bob";
  msg2._todomain = "awaydomain";
  msg2._via = tp->to_string(false);
  msg2._route = "Route: <sip:proxy1.awaydomain;transport=TCP;lr>";
  msg2._forwards = 1;
  inject_msg(msg2.get_request(), tp);

  // Check the 483 Too Many Hops response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(483).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Send an ACK to complete the UAS transaction.
  msg2._method = "ACK";
  inject_msg(msg2.get_request(), tp);

  delete tp;
}


TEST_F(ICSCFSproutletTest, RouteOrigInviteBadServerName)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Set up the HSS response for the originating location query.
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"INVALID!\"}");

  // Inject a INVITE request with orig in the Route header and a P-Served-User
  // header.
  Message msg1;
  msg1._method = "INVITE";
  msg1._via = tp->to_string(false);
  msg1._extra += "P-Served-User: <sip:6505551000@homedomain>";
  msg1._route = "Route: <sip:homedomain;orig>";
  inject_msg(msg1.get_request(), tp);

  // Should have a 100 Trying and a 480 Temporarily Unavailable.
  ASSERT_EQ(2, txdata_count());

  // Deal with the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Deal with the 480 Temporarily Unavailable.
  tdata = current_txdata();
  RespMatcher(480).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Now try again, but configure a tel URI.  This should fail in the same way
  // as it's not routable.
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"tel:2015551234\"}");

  msg1._unique += 1; // We want a new call-ID and branch parameter.
  inject_msg(msg1.get_request(), tp);

  // Should have a 100 Trying and a 480 Temporarily Unavailable.
  ASSERT_EQ(2, txdata_count());

  // Deal with the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Deal with the 480 Temporarily Unavailable.
  tdata = current_txdata();
  RespMatcher(480).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Finally use a SIPS uri.
  _hss_connection->set_result("/impu/sip%3A6505551000%40homedomain/location?originating=true",
                              "{\"result-code\": 2001,"
                              " \"scscf\": \"sips:scscf1.homedomain:5058;transport=TCP\"}");

  msg1._unique += 1; // We want a new call-ID and branch parameter.
  inject_msg(msg1.get_request(), tp);

  ASSERT_EQ(2, txdata_count());

  // Deal with the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Deal with the 480 Temporarily Unavailable.
  tdata = current_txdata();
  RespMatcher(480).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  _hss_connection->delete_result("/impu/sip%3A6505551000%40homedomain/location?originating=true");

  delete tp;
}

// Test the case where the I-CSCF receives an ACK. This is not valid and should be dropped.
TEST_F(ICSCFSproutletTest, RouteOutOfDialogAck)
{
  // Create a TCP connection to the I-CSCF listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.icscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject an ACK request to a local URI
  Message msg1;
  msg1._method = "ACK";
  msg1._requri = "sip:3196914123@homedomain;transport=UDP";
  inject_msg(msg1.get_request(), tp);

  // Expect it to just be dropped
  ASSERT_EQ(0, txdata_count());
  free_txdata(); 
  delete tp; 
}


