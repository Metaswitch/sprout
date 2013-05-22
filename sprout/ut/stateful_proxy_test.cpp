/**
 * @file stateful_proxy_test.cpp UT for Sprout stateful proxy module.
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
#include <valgrind/valgrind.h>
#include <boost/lexical_cast.hpp>

#include "pjutils.h"
#include "siptest.hpp"
#include "utils.h"
#include "test_utils.hpp"
#include "localstorefactory.h"
#include "analyticslogger.h"
#include "stateful_proxy.h"
#include "fakelogger.hpp"
#include "fakehssconnection.hpp"
#include "fakexdmconnection.hpp"
#include "test_interposer.hpp"

using namespace std;
using testing::StrEq;
using testing::ElementsAre;
using testing::MatchesRegex;
using testing::HasSubstr;
using testing::Not;

namespace SP
{
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
    bool _first_hop;
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
      _first_hop(false),
      _via("10.83.18.38:36530"),
      _cseq(16567)
    {
      static int unique = 1042;
      _unique = unique;
      unique += 10; // leave room for manual increments
    }

    string get_request();
    string get_response();

    void set_route(pjsip_msg* msg);
  };
}

/// Helper to print list to ostream.
class DumpList
{
public:
  DumpList(const string& title, list<string> list) :
    _title(title), _list(list)
  {
  }
  friend std::ostream& operator<<(std::ostream& os, const DumpList& that);
private:
  string _title;
  list<string> _list;
};

std::ostream& operator<<(std::ostream& os, const DumpList& that)
{
  os << that._title << endl;
  for (list<string>::const_iterator iter = that._list.begin(); iter != that._list.end(); ++iter)
  {
    os << "  " << *iter << endl;
  }
  return os;
}

class HeaderMatcher
{
public:
  HeaderMatcher(string header) :
    _header(header)
  {
  }

  HeaderMatcher(string header, string regex1) :
    _header(header)
  {
    _regexes.push_back(regex1);
  }

  HeaderMatcher(string header, string regex1, string regex2) :
    _header(header)
  {
    _regexes.push_back(regex1);
    _regexes.push_back(regex2);
  }

  void match(pjsip_msg* msg)
  {
    pj_str_t name_str = { const_cast<char*>(_header.data()), _header.length() };
    pjsip_hdr* hdr = NULL;
    list<string> values;

    while (NULL != (hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(msg, &name_str, hdr)))
    {
      char buf[1024];
      int n = pjsip_hdr_print_on(hdr, buf, sizeof(buf));
      EXPECT_LT(n, (int)sizeof(buf));
      values.push_back(string(buf,n));
      hdr = hdr->next;
    }

    ASSERT_EQ(_regexes.size(), values.size()) << DumpList("Expected", _regexes) << DumpList("Actual", values);
    list<string>::iterator itv = values.begin();
    list<string>::iterator itr = _regexes.begin();

    for (unsigned i = 0; i < _regexes.size(); i++)
    {
      EXPECT_THAT(*itv, testing::MatchesRegex(*itr));
      ++itv;
      ++itr;
    }
  }

private:
  string _header;
  list<string> _regexes;
};


/// ABC for fixtures for StatefulProxyTest and friends.
class StatefulProxyTestBase : public SipTest
{
public:
  FakeLogger _log;

  /// TX data for testing.  Will be cleaned up.  Each message in a
  /// forked flow has its URI stored in _uris, and its txdata stored
  /// in _tdata against that URI.
  vector<string> _uris;
  map<string,pjsip_tx_data*> _tdata;

  /// Set up test case.  Caller must clear host_mapping.
  static void SetUpTestCase(const string& edge_upstream_proxy,
                            const string& ibcf_trusted_hosts,
                            bool hss)
  {
    SipTest::SetUpTestCase(false);

    _store = RegData::create_local_store();
    _analytics = new AnalyticsLogger("foo");
    delete _analytics->_logger;
    _analytics->_logger = NULL;
    _call_services = NULL;
    if (hss)
    {
      _hss_connection = new FakeHSSConnection();
      _xdm_connection = new FakeXDMConnection();
      _ifc_handler = new IfcHandler(_hss_connection, _store);
      _call_services = new CallServices(_xdm_connection);
    }
    // We only test with a JSONEnumService, not with a DNSEnumService - since
    // it is stateful_proxy.cpp that's under test here, the EnumService
    // implementation doesn't matter.
    _enum_service = new JSONEnumService(string(UT_DIR).append("/test_stateful_proxy_enum.json"));
    _bgcf_service = new BgcfService(string(UT_DIR).append("/test_stateful_proxy_bgcf.json"));
    _edge_upstream_proxy = edge_upstream_proxy;
    _ibcf_trusted_hosts = ibcf_trusted_hosts;
    pj_status_t ret = init_stateful_proxy(_store,
                                          _call_services,
                                          _ifc_handler,
                                          !_edge_upstream_proxy.empty(),
                                          _edge_upstream_proxy.c_str(),
                                          10,
                                          86400,
                                          !_ibcf_trusted_hosts.empty(),
                                          _ibcf_trusted_hosts.c_str(),
                                          _analytics,
                                          _enum_service,
                                          _bgcf_service);
    ASSERT_EQ(PJ_SUCCESS, ret) << PjStatus(ret);

    // Schedule timers.
    SipTest::poll();
  }

  static void TearDownTestCase()
  {
    // Shut down the transaction module first, before we destroy the
    // objects that might handle any callbacks!
    pjsip_tsx_layer_destroy();
    destroy_stateful_proxy();
    RegData::destroy_local_store(_store);
    delete _analytics; _analytics = NULL;
    delete _call_services; _call_services = NULL;
    delete _ifc_handler; _ifc_handler = NULL;
    delete _hss_connection; _hss_connection = NULL;
    delete _xdm_connection; _xdm_connection = NULL;
    delete _enum_service; _enum_service = NULL;
    delete _bgcf_service; _bgcf_service = NULL;
    SipTest::TearDownTestCase();
  }

  StatefulProxyTestBase()
  {
    Log::setLoggingLevel(99);
    _log_traffic = FakeLogger::isNoisy(); // true to see all traffic
    _analytics->_logger = &_log;
    _store->flush_all();  // start from a clean slate on each test
    if (_hss_connection)
    {
      _hss_connection->flush_all();
    }
    if (_xdm_connection)
    {
      _xdm_connection->flush_all();
    }
  }

  ~StatefulProxyTestBase()
  {
    for (map<string,pjsip_tx_data*>::iterator it = _tdata.begin();
         it != _tdata.end();
         ++it)
    {
      pjsip_tx_data_dec_ref(it->second);
    }

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
    poll();

    // Stop and restart the layer just in case
    pjsip_tsx_layer_instance()->stop();
    pjsip_tsx_layer_instance()->start();

    _analytics->_logger = NULL;
  }

protected:
  static RegData::Store* _store;
  static AnalyticsLogger* _analytics;
  static FakeHSSConnection* _hss_connection;
  static FakeXDMConnection* _xdm_connection;
  static CallServices* _call_services;
  static IfcHandler* _ifc_handler;
  static EnumService* _enum_service;
  static BgcfService* _bgcf_service;
  static string _edge_upstream_proxy;
  static string _ibcf_trusted_hosts;

  void doTestHeaders(TransportFlow* tpA,
                     bool tpAset,
                     TransportFlow* tpB,
                     bool tpBset,
                     SP::Message& msg,
                     bool expect_100,
                     bool pani_AB,
                     bool pani_BA,
                     bool expect_orig);
};

RegData::Store* StatefulProxyTestBase::_store;
AnalyticsLogger* StatefulProxyTestBase::_analytics;
FakeHSSConnection* StatefulProxyTestBase::_hss_connection;
FakeXDMConnection* StatefulProxyTestBase::_xdm_connection;
CallServices* StatefulProxyTestBase::_call_services;
IfcHandler* StatefulProxyTestBase::_ifc_handler;
EnumService* StatefulProxyTestBase::_enum_service;
BgcfService* StatefulProxyTestBase::_bgcf_service;
string StatefulProxyTestBase::_edge_upstream_proxy;
string StatefulProxyTestBase::_ibcf_trusted_hosts;

class StatefulProxyTest : public StatefulProxyTestBase
{
public:
  static void SetUpTestCase()
  {
    cwtest_clear_host_mapping();
    StatefulProxyTestBase::SetUpTestCase("", "", false);
  }

  static void TearDownTestCase()
  {
    StatefulProxyTestBase::TearDownTestCase();
  }

  StatefulProxyTest()
  {
  }

  ~StatefulProxyTest()
  {
  }

protected:
  void doSuccessfulFlow(SP::Message& msg, testing::Matcher<string> uri_matcher, list<HeaderMatcher> headers);
  void doFastFailureFlow(SP::Message& msg, int st_code);
  void doSlowFailureFlow(SP::Message& msg, int st_code);
  void setupForkedFlow(SP::Message& msg);
  list<string> doProxyCalculateTargets(int max_targets);
};

class StatefulEdgeProxyTest : public StatefulProxyTestBase
{
public:
  static void SetUpTestCase()
  {
    cwtest_clear_host_mapping();
    cwtest_add_host_mapping("upstreamnode", "10.6.6.8");
    StatefulProxyTestBase::SetUpTestCase("upstreamnode", "", false);
  }

  static void TearDownTestCase()
  {
    StatefulProxyTestBase::TearDownTestCase();
  }

  StatefulEdgeProxyTest()
  {
  }

  ~StatefulEdgeProxyTest()
  {
  }

protected:
  void doRegisterEdge(TransportFlow* xiTp, string& xoToken, string& xoBareToken, bool firstHop = false, string supported = "outbound, path", bool expectPath = true, string via = "");
  SP::Message doInviteEdge(string token);
};

class StatefulTrunkProxyTest : public StatefulProxyTestBase
{
public:
  static void SetUpTestCase()
  {
    cwtest_clear_host_mapping();
    cwtest_add_host_mapping("upstreamnode", "10.6.6.8");
    cwtest_add_host_mapping("trunknode", "10.7.7.10");
    cwtest_add_host_mapping("trunknode2", "10.7.7.11");
    StatefulProxyTestBase::SetUpTestCase("upstreamnode", "trunknode,trunknode2", false);
  }

  static void TearDownTestCase()
  {
    StatefulProxyTestBase::TearDownTestCase();
  }

  StatefulTrunkProxyTest()
  {
  }

  ~StatefulTrunkProxyTest()
  {
  }

protected:
};

class IscTest : public StatefulProxyTestBase
{
public:
  static void SetUpTestCase()
  {
    cwtest_clear_host_mapping();
    StatefulProxyTestBase::SetUpTestCase("", "", true);
  }

  static void TearDownTestCase()
  {
    StatefulProxyTestBase::TearDownTestCase();
  }

  IscTest()
  {
  }

  ~IscTest()
  {
  }

  void doAsOriginated(SP::Message& msg, bool expect_orig);
};

void SP::Message::set_route(pjsip_msg* msg)
{
  string route = get_headers(msg, "Record-Route");
  if (route != "")
  {
    route.erase(0, strlen("Record-Route: <"));
    route.erase(route.find(">"));
    _route = route;
  }
}

string SP::Message::get_request()
{
  char buf[16384];

  string attodomain;
  if (!_todomain.empty())
  {
    attodomain.append("@").append(_todomain);
  }

  // The remote target.
  string target = string(_toscheme).append(":").append(_to).append(attodomain);

  // If there's no route, the target goes in the request
  // URI. Otherwise it goes in the Route:, and the route goes in the
  // request URI.
  string requri = _route.empty() ? target : _route;
  string route = _route.empty() ? "" : string("Route: ").append(target).append("\r\n");

  int n = snprintf(buf, sizeof(buf),
                   "%1$s %9$s SIP/2.0\r\n"
                   "Via: SIP/2.0/TCP %13$s;rport;branch=z9hG4bKPjmo1aimuq33BAI4rjhgQgBr4sY%11$04dSPI\r\n"
                   "%12$s"
                   "From: <sip:%2$s@%3$s>;tag=10.114.61.213+1+8c8b232a+5fb751cf\r\n"
                   "To: <%10$s>\r\n"
                   "Max-Forwards: %8$d\r\n"
                   "Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs%11$04dohntC@10.114.61.213\r\n"
                   "CSeq: %15$d %1$s\r\n"
                   "User-Agent: Accession 2.0.0.0\r\n"
                   "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n"
                   "%4$s"
                   "%7$s"
                   "%14$s"
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
                   /* 12 */ _first_hop ? "" : "Via: SIP/2.0/TCP 10.114.61.213:5061;received=23.20.193.43;branch=z9hG4bK+7f6b263a983ef39b0bbda2135ee454871+sip+1+a64de9f6\r\n",
                   /* 13 */ _via.c_str(),
                   /* 14 */ route.c_str(),
                   /* 15 */ _cseq
    );

  EXPECT_LT(n, (int)sizeof(buf));

  string ret(buf, n);
  // cout << ret <<endl;
  return ret;
}

string SP::Message::get_response()
{
  char buf[16384];

  int n = snprintf(buf, sizeof(buf),
                   "SIP/2.0 %9$s\r\n"
                   "Via: SIP/2.0/TCP %14$s;rport;branch=z9hG4bKPjmo1aimuq33BAI4rjhgQgBr4sY%11$04dSPI\r\n"
                   "%12$s"
                   "From: <sip:%2$s@%3$s>;tag=10.114.61.213+1+8c8b232a+5fb751cf\r\n"
                   "To: <sip:%7$s%8$s>\r\n"
                   "Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs%11$04dohntC@10.114.61.213\r\n"
                   "CSeq: %13$d %1$s\r\n"
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
                   /* 12 */ _first_hop ? "" : "Via: SIP/2.0/TCP 10.114.61.213:5061;received=23.20.193.43;branch=z9hG4bK+7f6b263a983ef39b0bbda2135ee454871+sip+1+a64de9f6\r\n",
                   /* 13 */ _cseq,
                   /* 14 */ _via.c_str()
    );

  EXPECT_LT(n, (int)sizeof(buf));

  string ret(buf, n);
  // cout << ret <<endl;
  return ret;
}

using SP::Message;


// Test flows into Sprout (S-CSCF), in particular for header stripping.
// Check the transport each message is on, and the headers.
// Test a call from Alice to Bob.
void StatefulProxyTestBase::doTestHeaders(TransportFlow* tpA,  //< Alice's transport.
                                          bool tpAset,         //< Expect all requests to Alice on same transport?
                                          TransportFlow* tpB,  //< Bob's transport.
                                          bool tpBset,         //< Expect all requests to Bob on same transport?
                                          SP::Message& msg,    //< Message to use for testing.
                                          bool expect_100,     //< Will we get a 100 Trying?
                                          bool pani_AB,        //< Should P-A-N-I be passed on requests?
                                          bool pani_BA,        //< Should P-A-N-I be passed on responses?
                                          bool expect_orig)    //< Should we expect the INVITE to be marked originating?
{
  SCOPED_TRACE("doTestHeaders");
  pjsip_msg* out;
  pjsip_tx_data* invite = NULL;

  // Extra fields to insert in all requests and responses.
  string extra = "P-Access-Network-Info: ietf-carrier-pigeon;rfc=1149";
  if (!msg._extra.empty())
  {
    msg._extra.append("\r\n");
  }
  msg._extra.append(extra);

  // ---------- Send INVITE C->X
  SCOPED_TRACE("INVITE");
  msg._method = "INVITE";
  inject_msg(msg.get_request(), tpA);
  poll();
  ASSERT_EQ(expect_100 ? 2 : 1, txdata_count());

  if (expect_100)
  {
    // 100 Trying goes back C<-X
    out = current_txdata()->msg;
    RespMatcher(100).matches(out);
    tpA->expect_target(current_txdata(), true);  // Requests always come back on same transport
    msg.set_route(out);

    // Don't bother testing P-Access-Network-Info, because it never gets inserted into such messages.
    free_txdata();
  }

  // INVITE passed on X->S
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("INVITE").matches(out));
  tpB->expect_target(current_txdata(), tpBset);

  // Check P-Access-Network-Info.
  EXPECT_EQ(pani_AB ? extra : "", get_headers(out, "P-Access-Network-Info")) << "INVITE";

  // Check originating.
  if (expect_orig)
  {
    EXPECT_THAT(get_headers(out, "Route"), HasSubstr(";orig"));
  }
  else
  {
    EXPECT_THAT(get_headers(out, "Route"), Not(HasSubstr(";orig")));
  }

  invite = pop_txdata();

  // ---------- Send 183 Session Progress back X<-S
  SCOPED_TRACE("183 Session Progress");
  inject_msg(respond_to_txdata(invite, 183, "", extra), tpB);
  ASSERT_EQ(1, txdata_count());

  // 183 goes back C<-X
  out = current_txdata()->msg;
  RespMatcher(183).matches(out);
  tpA->expect_target(current_txdata(), true);
  msg.set_route(out);
  msg._cseq++;

  // Check P-Access-Network-Info.
  EXPECT_EQ(pani_BA ? extra : "", get_headers(out, "P-Access-Network-Info")) << "183 Session Progress";

  free_txdata();

  // ---------- Send 200 OK back X<-S
  SCOPED_TRACE("200 OK (INVITE)");
  inject_msg(respond_to_txdata(invite, 200, "", extra), tpB);
  ASSERT_EQ(1, txdata_count());

  // OK goes back C<-X
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpA->expect_target(current_txdata(), true);
  msg.set_route(out);
  msg._cseq++;

  // Check P-Access-Network-Info.
  EXPECT_EQ(pani_BA ? extra : "", get_headers(out, "P-Access-Network-Info")) << "200 OK (INVITE)";

  free_txdata();

  // ---------- Send ACK C->X
  SCOPED_TRACE("ACK");
  msg._method = "ACK";
  inject_msg(msg.get_request(), tpA);
  poll();
  ASSERT_EQ(1, txdata_count());

  // ACK passed on X->S
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("ACK").matches(out));
  tpB->expect_target(current_txdata(), tpBset);

  // Check P-Access-Network-Info.
  EXPECT_EQ(pani_AB ? extra : "", get_headers(out, "P-Access-Network-Info")) << "ACK";

  free_txdata();

  // ---------- Send a retransmission of that 200 OK back X<-S.  Should be processed statelessly.
  SCOPED_TRACE("200 OK (INVITE) (rexmt)");
  inject_msg(respond_to_txdata(invite, 200, "", extra), tpB);
  pjsip_tx_data_dec_ref(invite);
  invite = NULL;
  ASSERT_EQ(1, txdata_count());

  // OK goes back C<-X
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  //@@@DISABLED - see bug 132. tpA->expect_target(current_txdata(), true);
  msg.set_route(out);
  msg._cseq++;

  // Check P-Access-Network-Info.  This will always be stripped,
  // because we handle these retransmissions statelessly and hence
  // don't have any info on trust boundary handling.
  EXPECT_EQ("", get_headers(out, "P-Access-Network-Info")) << "200 OK (INVITE) (rexmt)";

  free_txdata();

  // ---------- Send a reINVITE in the reverse direction. X<-S

  // ---------- Send a subsequent request. C->X
  SCOPED_TRACE("BYE");
  msg._method = "BYE";
  inject_msg(msg.get_request(), tpA);
  poll();

  // BYE passed on X->S
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("BYE").matches(out));
  tpB->expect_target(current_txdata(), tpBset);

  // Check P-Access-Network-Info.
  EXPECT_EQ(pani_AB ? extra : "", get_headers(out, "P-Access-Network-Info")) << "BYE";

  // ---------- Send a reply to that X<-S
  SCOPED_TRACE("200 OK (BYE)");
  inject_msg(respond_to_current_txdata(200, "", extra), tpB);
  poll();
  ASSERT_EQ(1, txdata_count());

  // Reply passed on C<-X
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpA->expect_target(current_txdata(), true);

  // Check P-Access-Network-Info.
  EXPECT_EQ(pani_BA ? extra : "", get_headers(out, "P-Access-Network-Info")) << "200 OK (BYE)";

  free_txdata();

  // ---------- Send INVITE C->X (this is an attempt to establish a second dialog)
  SCOPED_TRACE("INVITE (#2)");
  msg._method = "INVITE";
  msg._unique++;
  inject_msg(msg.get_request(), tpA);
  poll();
  ASSERT_EQ(expect_100 ? 2 : 1, txdata_count());

  if (expect_100)
  {
    // 100 Trying goes back C<-X
    out = current_txdata()->msg;
    RespMatcher(100).matches(out);
    tpA->expect_target(current_txdata(), true);

    // Don't bother testing P-Access-Network-Info, because this is point-to-point.
    free_txdata();
  }

  // INVITE passed on X->S
  SCOPED_TRACE("INVITE (S#2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("INVITE").matches(out));
  tpB->expect_target(current_txdata(), tpBset);

  // Check P-Access-Network-Info.
  EXPECT_EQ(pani_AB ? extra : "", get_headers(out, "P-Access-Network-Info")) << "INVITE (#2)";

  invite = pop_txdata();

  // ---------- Send 404 Not Found back X<-S
  SCOPED_TRACE("404 Not Found (INVITE #2)");
  inject_msg(respond_to_txdata(invite, 404, "", extra), tpB);
  poll();
  ASSERT_EQ(2, txdata_count());

  // ACK autogenerated X->S
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("ACK").matches(out));
  tpB->expect_target(current_txdata(), tpBset);

  // Don't check P-Access-Network-Info, because it's point-to-point.

  free_txdata();

  // 404 goes back C<-X
  out = current_txdata()->msg;
  RespMatcher(404).matches(out);
  tpA->expect_target(current_txdata(), true);
  msg.set_route(out);
  msg._cseq++;

  // Check P-Access-Network-Info.
  EXPECT_EQ(pani_BA ? extra : "", get_headers(out, "P-Access-Network-Info")) << "404 Not Found (INVITE #2)";

  free_txdata();

  // ---------- Send ACK C->X
  SCOPED_TRACE("ACK (#2)");
  msg._method = "ACK";
  inject_msg(msg.get_request(), tpA);
  poll();
  ASSERT_EQ(0, txdata_count());
  // should be swallowed by core.
}


/// Test a message results in a successful flow. The outgoing INVITE's
/// URI is verified.
void StatefulProxyTest::doSuccessfulFlow(Message& msg,
                                         testing::Matcher<string> uri_matcher,
                                         list<HeaderMatcher> headers)
{
  SCOPED_TRACE("");
  pjsip_msg* out;

  // Send INVITE
  inject_msg(msg.get_request());
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  free_txdata();

  // INVITE passed on
  out = current_txdata()->msg;
  ReqMatcher req("INVITE");
  ASSERT_NO_FATAL_FAILURE(req.matches(out));

  // Do checks on what gets passed through:
  EXPECT_THAT(req.uri(), uri_matcher);
  for (list<HeaderMatcher>::iterator iter = headers.begin(); iter != headers.end(); ++iter)
  {
    iter->match(out);
  }

  // Send 200 OK back
  inject_msg(respond_to_current_txdata(200));
  ASSERT_EQ(1, txdata_count());

  // OK goes back
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  msg.set_route(out);
  msg._cseq++;
  free_txdata();

  // Send ACK
  msg._method = "ACK";
  inject_msg(msg.get_request());
  poll();
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  ReqMatcher req2("ACK");
  ASSERT_NO_FATAL_FAILURE(req2.matches(out));
  free_txdata();

  // Send a subsequent request.
  msg._method = "BYE";
  inject_msg(msg.get_request());
  poll();
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  ReqMatcher req3("BYE");
  ASSERT_NO_FATAL_FAILURE(req3.matches(out));

  // Send a reply to that.
  inject_msg(respond_to_current_txdata(200));
  poll();
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);

  free_txdata();
}

/// Test a message results in an immediate failure.
void StatefulProxyTest::doFastFailureFlow(Message& msg, int st_code)
{
  SCOPED_TRACE("");

  // Send INVITE
  inject_msg(msg.get_request());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out;

  // error goes back
  out = current_txdata()->msg;
  RespMatcher(st_code).matches(out);
  free_txdata();
}

/// Test a message results in a 100 then a failure.
void StatefulProxyTest::doSlowFailureFlow(Message& msg, int st_code)
{
  SCOPED_TRACE("");

  // Send INVITE
  inject_msg(msg.get_request());
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  free_txdata();

  // error goes back
  out = current_txdata()->msg;
  RespMatcher(st_code).matches(out);
  free_txdata();
}

TEST_F(StatefulProxyTest, TestSimpleMainline)
{
  SCOPED_TRACE("");
  register_uri(_store, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  Message msg;
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs);
}

// Test flows into Sprout (S-CSCF), in particular for header stripping.
TEST_F(StatefulProxyTest, TestMainlineHeadersSprout)
{
  SCOPED_TRACE("");
  register_uri(_store, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");

  // INVITE from anywhere to anywhere.
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345";
  doTestHeaders(_tp_default, false, _tp_default, false, msg, true, true, true, false);
}

TEST_F(StatefulProxyTest, TestNotRegisteredTo)
{
  SCOPED_TRACE("");
  Message msg;
  doSlowFailureFlow(msg, 404);
}

TEST_F(StatefulProxyTest, TestBadScheme)
{
  SCOPED_TRACE("");
  register_uri(_store, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  Message msg;
  msg._toscheme = "tel";
  msg._to = "+16505551234";
  msg._todomain = "";
  doFastFailureFlow(msg, 416);  // bad scheme
}

TEST_F(StatefulProxyTest, TestNoMoreForwards)
{
  SCOPED_TRACE("");
  register_uri(_store, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  Message msg;
  msg._forwards = 1;
  doFastFailureFlow(msg, 483); // too many hops
}

TEST_F(StatefulProxyTest, TestNoMoreForwards2)
{
  SCOPED_TRACE("");
  register_uri(_store, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  Message msg;
  msg._forwards = 0;
  doFastFailureFlow(msg, 483); // too many hops
}

/// This proxy really doesn't support anything - beware!
TEST_F(StatefulProxyTest, TestProxyRequire)
{
  SCOPED_TRACE("");
  register_uri(_store, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  Message msg;
  msg._extra = "Proxy-Require: privacy";
  doFastFailureFlow(msg, 420);  // bad extension
}

TEST_F(StatefulProxyTest, TestStrictRouteThrough)
{
  SCOPED_TRACE("");
  // This message is passing through this proxy; it's not local
  Message msg;
  msg._extra = "Route: <sip:nexthop@intermediate.com;transport=tcp>\r\nRoute: <sip:lasthop@destination.com>";
  msg._to = "lasthop";
  msg._todomain = "destination.com";
  msg._requri = "sip:6505551234@nonlocaldomain";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Route", ".*lasthop@destination.com.*", ".*6505551234@nonlocaldomain.*"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*nexthop@intermediate.com.*"), hdrs);
}

TEST_F(StatefulProxyTest, TestNonLocal)
{
  SCOPED_TRACE("");
  // This message is passing through this proxy; it's not local
  Message msg;
  msg._to = "lasthop";
  msg._todomain = "destination.com";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Route"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*lasthop@destination\\.com.*"), hdrs);
}

TEST_F(StatefulProxyTest, DISABLED_TestLooseRoute)  // @@@KSW not quite - how does this work again?
{
  SCOPED_TRACE("");
  Message msg;
  msg._extra = "Route: <sip:nexthop@anotherdomain;lr>\r\nRoute: <sip:lasthop@destination.com;lr>";
  msg._to = "lasthop";
  msg._todomain = "destination.com";
  msg._requri = "sip:6505551234@homedomain";
  list<HeaderMatcher> hdrs;
//  hdrs.push_back(HeaderMatcher("Route", ".*lasthop@destination.*"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*lasthop@destination.com.*"), hdrs);
}

TEST_F(StatefulProxyTest, TestExternal)
{
  SCOPED_TRACE("");
  Message msg;
  msg._to = "+15108580271";
  msg._todomain = "ut.cw-ngv.com";
  cwtest_add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*+15108580271@ut.cw-ngv.com.*"), hdrs);
}

/// Test a forked flow - setup phase.
void StatefulProxyTest::setupForkedFlow(SP::Message& msg)
{
  SCOPED_TRACE("");
  register_uri(_store, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  register_uri(_store, "6505551234", "homedomain", "sip:andunnuvvawun@10.114.61.214:5061;transport=tcp;ob");
  register_uri(_store, "6505551234", "homedomain", "sip:awwnawmaw@10.114.61.213:5061;transport=tcp;ob");
  pjsip_msg* out;

  // Send INVITE
  inject_msg(msg.get_request());
  ASSERT_EQ(4, txdata_count());

  // 100 Trying goes back
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  free_txdata();

  // Collect INVITEs
  for (int i = 0; i < 3; i++)
  {
    out = current_txdata()->msg;
    ReqMatcher req("INVITE");
    req.matches(out);
    _uris.push_back(req.uri());
    _tdata[req.uri()] = pop_txdata();
  }

  EXPECT_TRUE(_tdata.find("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob") != _tdata.end());
  EXPECT_TRUE(_tdata.find("sip:andunnuvvawun@10.114.61.214:5061;transport=tcp;ob") != _tdata.end());
  EXPECT_TRUE(_tdata.find("sip:awwnawmaw@10.114.61.213:5061;transport=tcp;ob") != _tdata.end());
}

TEST_F(StatefulProxyTest, TestForkedFlow)
{
  SCOPED_TRACE("");
  pjsip_msg* out;
  Message msg;
  setupForkedFlow(msg);

  // Send 183 back from one of them
  inject_msg(respond_to_txdata(_tdata[_uris[0]], 183, "early"));

  // Nothing happens yet!
  ASSERT_EQ(0, txdata_count());

  // Send 200 OK from another of them
  inject_msg(respond_to_txdata(_tdata[_uris[1]], 200, "bbb"));
  poll();
  ASSERT_EQ(3, txdata_count());

  // OK goes back
  out = current_txdata()->msg;
  RespMatcher(200, "bbb").matches(out);
  free_txdata();

  // Others are cancelled

  // Receive and respond to CANCEL for target 0
  SCOPED_TRACE("");
  out = current_txdata()->msg;
  ReqMatcher c0("CANCEL");
  c0.matches(out);
  EXPECT_THAT(c0.uri(), StrEq(_uris[0]));
  inject_msg(respond_to_current_txdata(200));

  // Receive and respond to CANCEL for target 2
  SCOPED_TRACE("");
  out = current_txdata()->msg;
  ReqMatcher c2("CANCEL");
  c2.matches(out);
  EXPECT_THAT(c2.uri(), StrEq(_uris[2]));
  inject_msg(respond_to_current_txdata(200));

  // Send 487 response from target 0
  SCOPED_TRACE("");
  inject_msg(respond_to_txdata(_tdata[_uris[0]], 487));
  ASSERT_EQ(1, txdata_count());
  // Acknowledges cancel from target 0
  ReqMatcher a0("ACK");
  a0.matches(current_txdata()->msg);
  EXPECT_THAT(a0.uri(), StrEq(_uris[0]));
  free_txdata();

  // Send 487 response from target 2
  SCOPED_TRACE("");
  inject_msg(respond_to_txdata(_tdata[_uris[2]], 487));
  ASSERT_EQ(1, txdata_count());
  // Acknowledges cancel from target 2
  ReqMatcher a2("ACK");
  a2.matches(current_txdata()->msg);
  EXPECT_THAT(a2.uri(), StrEq(_uris[2]));
  free_txdata();

  // All done!
  expect_all_tsx_done();
}

TEST_F(StatefulProxyTest, TestForkedFlow2)
{
  SCOPED_TRACE("");
  pjsip_msg* out;
  Message msg;
  setupForkedFlow(msg);

  // Send 183 back from one of them
  inject_msg(respond_to_txdata(_tdata[_uris[0]], 183));
  // Nothing happens yet!
  ASSERT_EQ(0, txdata_count());

  // Send final error from another of them
  inject_msg(respond_to_txdata(_tdata[_uris[1]], 404));

  // Gets acknowledged directly by us
  ASSERT_EQ(1, txdata_count());
  ReqMatcher("ACK").matches(current_txdata()->msg);
  free_txdata();

  // Send final success from first of them
  inject_msg(respond_to_txdata(_tdata[_uris[0]], 200, "abc"));
  poll();

  // Succeeds!
  ASSERT_EQ(2, txdata_count());

  // OK goes back
  out = current_txdata()->msg;
  RespMatcher(200, "abc").matches(out);
  free_txdata();

  // Other is cancelled
  out = current_txdata()->msg;
  ReqMatcher c2("CANCEL");
  c2.matches(out);
  EXPECT_THAT(c2.uri(), StrEq(_uris[2]));
  inject_msg(respond_to_current_txdata(200));
  free_txdata();

  // Send 487 response from target 2
  SCOPED_TRACE("");
  inject_msg(respond_to_txdata(_tdata[_uris[2]], 487));
  ASSERT_EQ(1, txdata_count());
  // Acknowledges cancel from target 2
  ReqMatcher a2("ACK");
  a2.matches(current_txdata()->msg);
  EXPECT_THAT(a2.uri(), StrEq(_uris[2]));
  free_txdata();

  // All done!
  expect_all_tsx_done();
}

TEST_F(StatefulProxyTest, TestForkedFlow3)
{
  SCOPED_TRACE("");
  pjsip_msg* out;
  Message msg;
  setupForkedFlow(msg);

  // Send 183 back from one of them
  inject_msg(respond_to_txdata(_tdata[_uris[0]], 183));
  // Nothing happens yet!
  ASSERT_EQ(0, txdata_count());

  // Send final error from another of them
  inject_msg(respond_to_txdata(_tdata[_uris[1]], 404));

  // Gets acknowledged directly by us
  ASSERT_EQ(1, txdata_count());
  ReqMatcher("ACK").matches(current_txdata()->msg);
  free_txdata();

  // Send final error from a third
  inject_msg(respond_to_txdata(_tdata[_uris[2]], 503));

  // Gets acknowledged directly by us
  ASSERT_EQ(1, txdata_count());
  ReqMatcher("ACK").matches(current_txdata()->msg);
  free_txdata();

  // Send final failure from first of them
  inject_msg(respond_to_txdata(_tdata[_uris[0]], 301));

  // Gets acknowledged directly by us
  ASSERT_EQ(2, txdata_count());
  ReqMatcher("ACK").matches(current_txdata()->msg);
  free_txdata();

  // "best" failure goes back
  out = current_txdata()->msg;
  RespMatcher(301).matches(out);
  free_txdata();

  // All done!
  expect_all_tsx_done();
}

TEST_F(StatefulProxyTest, TestForkedFlow4)
{
  SCOPED_TRACE("");
  Message msg;
  setupForkedFlow(msg);

  // Send final error from one of them
  inject_msg(respond_to_txdata(_tdata[_uris[0]], 503));
  // Gets acknowledged directly by us
  ASSERT_EQ(1, txdata_count());
  ReqMatcher("ACK").matches(current_txdata()->msg);
  free_txdata();

  // Send final error from another of them
  inject_msg(respond_to_txdata(_tdata[_uris[1]], 408));

  // Gets acknowledged directly by us
  ASSERT_EQ(1, txdata_count());
  ReqMatcher("ACK").matches(current_txdata()->msg);
  free_txdata();

  // Send a CANCEL from the caller
  msg._method = "CANCEL";
  inject_msg(msg.get_request());

  // CANCEL gets OK'd
  ASSERT_EQ(2, txdata_count());
  RespMatcher(200).matches(current_txdata()->msg);
  free_txdata();

  // Gets passed through to target 2
  ReqMatcher c2("CANCEL");
  c2.matches(current_txdata()->msg);
  EXPECT_THAT(c2.uri(), StrEq(_uris[2]));

  // Respond from target 2 to CANCEL
  inject_msg(respond_to_current_txdata(200));
  // Nothing happens yet
  ASSERT_EQ(0, txdata_count());

  // Respond from target 2 to INVITE
  SCOPED_TRACE("");
  inject_msg(respond_to_txdata(_tdata[_uris[2]], 487));
  ASSERT_EQ(2, txdata_count());

  // Acknowledges cancel from target 2
  ReqMatcher a2("ACK");
  a2.matches(current_txdata()->msg);
  EXPECT_THAT(a2.uri(), StrEq(_uris[2]));
  free_txdata();

  // Finally, pass cancel response back to initial INVITE
  ASSERT_EQ(1, txdata_count());
  RespMatcher(487).matches(current_txdata()->msg);
  free_txdata();

  // All done!
  expect_all_tsx_done();
}

list<string> StatefulProxyTest::doProxyCalculateTargets(int max_targets)
{
  SCOPED_TRACE("");
  register_uri(_store, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", 3600);
  register_uri(_store, "6505551234", "homedomain", "sip:andunnuvvawun@10.114.61.214:5061;transport=tcp;ob", 3500);
  register_uri(_store, "6505551234", "homedomain", "sip:awwnawmaw@10.114.61.213:5061;transport=tcp;ob", 3200);
  register_uri(_store, "6505551234", "homedomain", "sip:bah@10.114.61.213:5061;transport=tcp;ob", 3300);
  register_uri(_store, "6505551234", "homedomain", "sip:humbug@10.114.61.213:5061;transport=tcp;ob", 3400);

  Message msg;
  pjsip_rx_data* rdata = build_rxdata(msg.get_request());
  parse_rxdata(rdata);

  target_list targets;
  proxy_calculate_targets(rdata->msg_info.msg, stack_data.pool, &TrustBoundary::TRUSTED, targets, max_targets);

  list<string> ret;
  for (target_list::const_iterator i = targets.begin();
       i != targets.end();
       ++i)
  {
    EXPECT_EQ((pj_bool_t)true, i->from_store);
    EXPECT_EQ("sip:6505551234@homedomain", i->aor);
    EXPECT_EQ(i->binding_id, str_uri(i->uri));
    EXPECT_TRUE(i->paths.empty());
    ret.push_back(i->binding_id);
  }

  return ret;
}

TEST_F(StatefulProxyTest, TestProxyCalcTargets1)
{
  SCOPED_TRACE("");
  list<string> actual = doProxyCalculateTargets(3);
  EXPECT_THAT(actual, ElementsAre("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob",
                                  "sip:andunnuvvawun@10.114.61.214:5061;transport=tcp;ob",
                                  "sip:humbug@10.114.61.213:5061;transport=tcp;ob"));
}

TEST_F(StatefulProxyTest, TestProxyCalcTargets2)
{
  SCOPED_TRACE("");
  list<string> actual = doProxyCalculateTargets(5);
  EXPECT_THAT(actual, ElementsAre("sip:andunnuvvawun@10.114.61.214:5061;transport=tcp;ob",
                                  "sip:awwnawmaw@10.114.61.213:5061;transport=tcp;ob",
                                  "sip:bah@10.114.61.213:5061;transport=tcp;ob",
                                  "sip:humbug@10.114.61.213:5061;transport=tcp;ob",
                                  "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob"));
}

/// Register a client with the edge proxy, returning the flow token.
void StatefulEdgeProxyTest::doRegisterEdge(TransportFlow* xiTp,  //^ transport to register on
                                           string& xoToken, //^ out: token (parsed from Path)
                                           string& xoBareToken, //^ out: bare token (parsed from Path)
                                           bool firstHop,  //^ is this the first hop? If not, there was a previous hop to get here.
                                           string supported, //^ Supported: header value, or empty if none
                                           bool expectPath, //^ do we expect a Path: response? If false, don't parse token
                                           string via) //^ addr:port to use for top Via, or empty for the real one from xiTp
{
  SCOPED_TRACE("");

  // Register a client with the edge proxy.
  Message msg;
  msg._method = "REGISTER";
  msg._first_hop = firstHop;
  msg._via = via.empty() ? xiTp->to_string(false) : via;
  msg._extra = "Contact: sip:wuntootreefower@";
  msg._extra.append(xiTp->to_string(true)).append(";ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"");
  if (!supported.empty())
  {
    msg._extra.append("\r\n").append("Supported: ").append(supported);
  }
  inject_msg(msg.get_request(), xiTp);
  ASSERT_EQ(1, txdata_count());

  // Check that we generate a flow token and pass it through. We don't
  // check the value of the flow token (it's opaque) - just its
  // effect.

  // Is the right kind and method.
  ReqMatcher r1("REGISTER");
  pjsip_tx_data* tdata = current_txdata();
  r1.matches(tdata->msg);

  // Path is correct.
  string actual = get_headers(tdata->msg, "Path");
  EXPECT_EQ(expectPath, !actual.empty());
  if (actual.empty())
  {
    xoToken = "";
    xoBareToken = "";
  }
  else
  {
    xoToken = actual.substr(6);
    string expect = "";
    expect.append(msg._toscheme)
      .append(":.*@")
      .append(str_pj(stack_data.local_host))
      .append(":")
      .append(boost::lexical_cast<string>(stack_data.trusted_port))
      .append(";transport=TCP")
      .append(";lr")
      .append(firstHop ? ";ob" : "");
    EXPECT_THAT(xoToken, MatchesRegex(expect));

    // Get the bare token as just the user@host part of the URI.
    xoBareToken = xoToken.substr(0, xoToken.find(':', xoToken.find(':')));
  }

  // No integrity marking.
  actual = get_headers(tdata->msg, "Authorization");
  EXPECT_EQ("", actual);

  // Goes to the right place.
  expect_target("TCP", "10.6.6.8", stack_data.trusted_port, tdata);

  // Pass response back through.
  string r;
  if (!xoToken.empty())
  {
    r = "Path: ";
    r.append(xoToken);
  }
  inject_msg(respond_to_current_txdata(200, "", r));
  ASSERT_EQ(1, txdata_count());

  // Is the right kind and method.
  RespMatcher r2(200);
  tdata = current_txdata();
  r2.matches(tdata->msg);

  // Is the correct transport.
  xiTp->expect_target(tdata);

  free_txdata();
}

/// Inject an outbound message from upstream to the client.
Message StatefulEdgeProxyTest::doInviteEdge(string token)
{
  Message msg;
  msg._method = "INVITE";
  msg._to = "6505551000";
  msg._from = "6505551234";
  msg._extra = "Route: ";
  msg._extra.append(token);
  msg._requri = "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob";
  inject_msg(msg.get_request());
  return msg;
}

TEST_F(StatefulEdgeProxyTest, TestEdgeRegisterFW)
{
  SCOPED_TRACE("");

  // Register client.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        TransportFlow::Trust::UNTRUSTED,
                                        "1.2.3.4",
                                        49152);
  string token;
  string baretoken;
  doRegisterEdge(tp, token, baretoken);

  // Do two invites - the first time, the token is created; the second
  // time, we reuse the existing token.
  for (int i = 1; i <= 2; i++)
  {
    SCOPED_TRACE(i);

    // Now try to call the edge-proxied client.  We set the Route header
    // appropriately, and check that the message goes out the registered
    // transport.
    Message msg = doInviteEdge(token);
    ASSERT_EQ(1, txdata_count());
    pjsip_tx_data* tdata = current_txdata();

    // Is the right kind and method.
    ReqMatcher r2("INVITE");
    r2.matches(tdata->msg);

    // Goes to the right place (straight to the registered client).
    tp->expect_target(tdata);

    // Path not added.
    string actual = get_headers(tdata->msg, "Path");
    EXPECT_EQ("", actual);

    // RFC5626 s5.3.1 says the route header should be stripped.
    actual = get_headers(tdata->msg, "Route");
    EXPECT_EQ("", actual);

    // Route header value appears in Record-Route
    actual = get_headers(tdata->msg, "Record-Route");
    EXPECT_THAT(actual, HasSubstr(baretoken));
    EXPECT_THAT(actual, HasSubstr(":" + to_string<int>(tp->local_port(), std::dec)));
    EXPECT_THAT(actual, HasSubstr(";lr"));
    EXPECT_THAT(actual, Not(HasSubstr(";ob")));

    free_txdata();

    // Test a CANCEL chasing the INVITE.
    msg._method = "CANCEL";
    inject_msg(msg.get_request());
    ASSERT_EQ(2, txdata_count());

    // Is the right kind and method.
    tdata = current_txdata();
    RespMatcher r3(200);
    r3.matches(tdata->msg);

    // Goes to the right place (back to the injector)
    _tp_default->expect_target(tdata);
    free_txdata();

    // Is the right kind and method.
    tdata = current_txdata();
    ReqMatcher r4("CANCEL");
    r4.matches(tdata->msg);

    // Goes to the right place (straight to the registered client).
    tp->expect_target(tdata);
    free_txdata();
  }

  delete tp;
}

TEST_F(StatefulEdgeProxyTest, TestEdgeRegisterFWUDP)
{
  SCOPED_TRACE("");

  // Register client.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::UDP,
                                        TransportFlow::Trust::UNTRUSTED,
                                        "1.2.3.4",
                                        5060);
  string token;
  string baretoken;
  doRegisterEdge(tp, token, baretoken);

  // Do two invites - the first time, the token is created; the second
  // time, we reuse the existing token.
  for (int i = 1; i <= 2; i++)
  {
    SCOPED_TRACE(i);

    // Now try to call the edge-proxied client.  We set the Route header
    // appropriately, and check that the message goes out the registered
    // transport.
    Message msg = doInviteEdge(token);
    ASSERT_EQ(1, txdata_count());
    pjsip_tx_data* tdata = current_txdata();

    // Is the right kind and method.
    ReqMatcher r2("INVITE");
    r2.matches(tdata->msg);

    // Goes to the right place (straight to the registered client).
    tp->expect_target(tdata);

    // Path not added.
    string actual = get_headers(tdata->msg, "Path");
    EXPECT_EQ("", actual);

    // RFC5626 s5.3.1 says the route header should be stripped.
    actual = get_headers(tdata->msg, "Route");
    EXPECT_EQ("", actual);

    // Route header value appears in Record-Route
    actual = get_headers(tdata->msg, "Record-Route");
    EXPECT_THAT(actual, HasSubstr(baretoken));
    EXPECT_THAT(actual, HasSubstr(";lr"));
    EXPECT_THAT(actual, Not(HasSubstr(";ob")));

    free_txdata();

    // Test a CANCEL chasing the INVITE.
    msg._method = "CANCEL";
    inject_msg(msg.get_request());
    ASSERT_EQ(2, txdata_count());

    // Is the right kind and method.
    tdata = current_txdata();
    RespMatcher r3(200);
    r3.matches(tdata->msg);

    // Goes to the right place (back to the injector)
    _tp_default->expect_target(tdata);
    free_txdata();

    // Is the right kind and method.
    tdata = current_txdata();
    ReqMatcher r4("CANCEL");
    r4.matches(tdata->msg);

    // Goes to the right place (straight to the registered client).
    tp->expect_target(tdata);
    free_txdata();
  }

  delete tp;
}

TEST_F(StatefulEdgeProxyTest, TestEdgeCorruptToken)
{
  SCOPED_TRACE("");

  // Register client.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        TransportFlow::Trust::UNTRUSTED,
                                        "1.2.3.4",
                                        49152);
  string token;
  string baretoken;
  doRegisterEdge(tp, token, baretoken);

  // For sanity, check the real token works as expected.
  doInviteEdge(token);
  ASSERT_EQ(1, txdata_count());
  ReqMatcher r1("INVITE");
  r1.matches(current_txdata()->msg);
  tp->expect_target(current_txdata());
  free_txdata();

  // Now try to call the edge-proxied client.  We set the Route header
  // with a corrupt token, and check we get the appropriate error per
  // RFC5626. Actually RFC5626 asserts we should get 403 in cases like
  // this where the flow has been tampered with, and 430 when we just
  // don't know the flow. This module doesn't distinguish the two,
  // so we test a tampered token because it's easier to construct.
  list<string> tokens;

  // A simple tampered token
  string tampered(token);
  tampered[6]++;
  tokens.push_back(tampered);

  // Not base 64 (this actually gets decoded as if it is, so doesn't
  // exercise a different path, but we leave it in anyway).
  tokens.push_back("sip:Not&valid&base64)@testnode:5060;lr");

  // Too short
  string tooshort(token);
  tooshort.erase(6,4);
  tokens.push_back(tooshort);

  // Too short
  string toolong(token);
  toolong.insert(6, "AAAA");
  tokens.push_back(toolong);

  for (list<string>::iterator iter = tokens.begin(); iter != tokens.end(); ++iter)
  {
    SCOPED_TRACE(*iter);

    doInviteEdge(*iter);
    ASSERT_EQ(1, txdata_count());

    // Is the right kind and method.
    RespMatcher r2(430);
    r2.matches(current_txdata()->msg);

    // Goes to the right place: to sprout, not the client.
    _tp_default->expect_target(current_txdata());

    free_txdata();
  }

  // Close the transport (waiting for deferred processing and swallowing error message), and try again.
  delete tp;
  poll();
  ASSERT_EQ(1, txdata_count());
  free_txdata();

  doInviteEdge(token);
  ASSERT_EQ(1, txdata_count());

  // Is the right kind and method.
  RespMatcher r2(430);
  r2.matches(current_txdata()->msg);

  // Goes to the right place: to sprout, not the client.
  _tp_default->expect_target(current_txdata());

  free_txdata();
}

TEST_F(StatefulEdgeProxyTest, TestEdgeFirstHopDetection)
{
  SCOPED_TRACE("");
  TransportFlow* tp;
  string token;
  string baretoken;

  // Client 1: Declares outbound support, not behind NAT. Should get path.
  tp = new TransportFlow(TransportFlow::Protocol::TCP,
                         TransportFlow::Trust::UNTRUSTED,
                         "10.83.18.38",
                         49152);
  doRegisterEdge(tp, token, baretoken, true, "outbound, path", true, "");
  delete tp;

  // Client 2: Declares outbound support, behind NAT. Should get path.
  tp = new TransportFlow(TransportFlow::Protocol::TCP,
                         TransportFlow::Trust::UNTRUSTED,
                         "10.83.18.39",
                         49152);
  doRegisterEdge(tp, token, baretoken, true, "outbound, path", true, "10.22.3.4:9999");
  delete tp;

  // Client 3: Doesn't declare outbound support (no attr), not behind NAT. Shouldn't get path.
  // RETIRED - since sto131 we add Path to all REGISTERs from clients outside trusted zone.
  //tp = new TransportFlow("TCP", "10.83.18.40", 36530);
  //doRegisterEdge(tp, token, baretoken, true, "path", false, "");
  //delete tp;

  // Client 4: Doesn't declare outbound support (no attr), behind NAT. Should get path anyway.
  tp = new TransportFlow(TransportFlow::Protocol::TCP,
                         TransportFlow::Trust::UNTRUSTED,
                         "10.83.18.41",
                         49152);
  doRegisterEdge(tp, token, baretoken, true, "path", true, "10.22.3.5:8888");
  delete tp;

  // Client 5: Doesn't declare outbound support (no header), not behind NAT. Shouldn't get path.
  // RETIRED - since sto131 we add Path to all REGISTERs from clients outside trusted zone.
  //tp = new TransportFlow("TCP", "10.83.18.40", 36530);
  //doRegisterEdge(tp, token, baretoken, true, "", false, "");
  //delete tp;

  // Client 6: Doesn't declare outbound support (no header), behind NAT. Should get path anyway.
  tp = new TransportFlow(TransportFlow::Protocol::TCP,
                         TransportFlow::Trust::UNTRUSTED,
                         "10.83.18.41",
                         49152);
  doRegisterEdge(tp, token, baretoken, true, "", true, "10.22.3.5:8888");
  delete tp;
}

TEST_F(StatefulEdgeProxyTest, TestEdgeFirstHop)
{
  SCOPED_TRACE("");

  // Register client.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP, TransportFlow::Trust::UNTRUSTED, "10.83.18.38", 36530);
  string token;
  string baretoken;
  doRegisterEdge(tp, token, baretoken, true);

  // This is first hop, so should be marked
  EXPECT_THAT(token, HasSubstr(";ob"));

  // Now try to call the edge-proxied client.  We set the Route header
  // appropriately, and check that the message goes out the registered
  // transport.
  Message msg = doInviteEdge(token);
  ASSERT_EQ(1, txdata_count());
  pjsip_tx_data* tdata = current_txdata();

  // Is the right kind and method.
  ReqMatcher r2("INVITE");
  r2.matches(tdata->msg);

  // Goes to the right place (straight to the registered client).
  tp->expect_target(tdata);

  // Path not added.
  string actual = get_headers(tdata->msg, "Path");
  EXPECT_EQ("", actual);

  // RFC5626 s5.3.1 says the route header should be stripped.
  actual = get_headers(tdata->msg, "Route");
  EXPECT_EQ("", actual);

  // Route header value appears in Record-Route
  actual = get_headers(tdata->msg, "Record-Route");
  EXPECT_THAT(actual, HasSubstr(baretoken));
  EXPECT_THAT(actual, HasSubstr(";lr"));
  EXPECT_THAT(actual, Not(HasSubstr(";ob")));

  free_txdata();

  // Now try a message from the client to the R.O.W.
  Message msg2;
  msg2._method = "INVITE";
  msg2._first_hop = true;
  inject_msg(msg2.get_request(), tp);

  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();

  // Is the right kind and method.
  ReqMatcher r3("INVITE");
  r3.matches(tdata->msg);

  // Goes to the right place (upstream).
  expect_target("TCP", "10.6.6.8", stack_data.trusted_port, tdata);

  // Record-Route is added so it will come back the right way.
  actual = get_headers(tdata->msg, "Record-Route");
  EXPECT_THAT(actual, HasSubstr(baretoken));
  EXPECT_THAT(actual, HasSubstr(";lr"));
  EXPECT_THAT(actual, Not(HasSubstr(";ob")));

  // Boring route header.
  actual = get_headers(tdata->msg, "Route");
  EXPECT_THAT(actual, HasSubstr("sip:upstreamnode:" + to_string<int>(stack_data.trusted_port, std::dec) + ";transport=TCP"));

  // No path header.
  actual = get_headers(tdata->msg, "Path");
  EXPECT_EQ("", actual);

  free_txdata();

  // Now try a message from the client to the R.O.W., but getting the
  // destination domain wrong (specifying this host, rather than the
  // home domain). Edge proxy should silently correct this.
  msg2._unique++;
  msg2._todomain = "testnode";
  inject_msg(msg2.get_request(), tp);

  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();

  // Is the right kind and method.
  ReqMatcher r4("INVITE");
  r4.matches(tdata->msg);

  // Goes to the right place (upstream).
  expect_target("TCP", "10.6.6.8", stack_data.trusted_port, tdata);

  // Request URI is what it was, but coerced to correct domain.
  EXPECT_EQ("sip:6505551234@homedomain", r4.uri());

  // Record-Route is added so it will come back the right way.
  actual = get_headers(tdata->msg, "Record-Route");
  EXPECT_THAT(actual, HasSubstr(baretoken));
  EXPECT_THAT(actual, HasSubstr(";lr"));
  EXPECT_THAT(actual, Not(HasSubstr(";ob")));

  // Boring route header.
  actual = get_headers(tdata->msg, "Route");
  EXPECT_THAT(actual, HasSubstr("sip:upstreamnode:" + to_string<int>(stack_data.trusted_port, std::dec) + ";transport=TCP"));

  // No path header.
  actual = get_headers(tdata->msg, "Path");
  EXPECT_EQ("", actual);

  free_txdata();

  delete tp;
}

// Test flows out of Bono (P-CSCF), first hop, in particular for header stripping.
TEST_F(StatefulEdgeProxyTest, TestMainlineHeadersBonoFirstOut)
{
  SCOPED_TRACE("");

  // Register client.
  TransportFlow tp(TransportFlow::Protocol::TCP, TransportFlow::Trust::UNTRUSTED, "10.83.18.38", 36530);
  string token;
  string baretoken;
  doRegisterEdge(&tp, token, baretoken, true);

  // INVITE from Sprout (or elsewhere) via bono to client
  Message msg;
  msg._extra = string("Route: ").append(token);
  msg._todomain = "10.83.18.38:36530;transport=tcp";
  msg._via = "10.99.88.11:12345";
  // Strip PANI outbound - leaving the trust zone.
  doTestHeaders(_tp_default, false, &tp, true, msg, false, false, true, false);
}

// Test flows into Bono (P-CSCF), first hop, in particular for header stripping.
TEST_F(StatefulEdgeProxyTest, TestMainlineHeadersBonoFirstIn)
{
  SCOPED_TRACE("");

  // Register client.
  TransportFlow tp(TransportFlow::Protocol::TCP, TransportFlow::Trust::UNTRUSTED, "10.83.18.37", 36531);
  string token;
  string baretoken;
  doRegisterEdge(&tp, token, baretoken, true);

  // INVITE from client via bono to Sprout, first hop
  Message msg;
  msg._first_hop = true;
  msg._via = "10.83.18.37:36531;transport=tcp";
  // Strip PANI in outbound direction - leaving the trust zone.
  // This is originating; mark it so.
  doTestHeaders(&tp, true, _tp_default, false, msg, false, true, false, true);
}

// Test flows out of Bono (P-CSCF), not first hop, in particular for header stripping.
TEST_F(StatefulEdgeProxyTest, TestMainlineHeadersBonoProxyOut)
{
  SCOPED_TRACE("");

  // Register client.
  TransportFlow tp(TransportFlow::Protocol::TCP, TransportFlow::Trust::UNTRUSTED, "10.83.18.38", 36530);
  string token;
  string baretoken;
  doRegisterEdge(&tp, token, baretoken, false);

  // INVITE from Sprout (or elsewhere) via bono to client
  Message msg;
  msg._extra = string("Route: ").append(token);
  msg._todomain = "10.83.18.38:36530;transport=tcp";
  msg._via = "10.99.88.11:12345";
  // Don't care which transport we come back on, as long as it goes to
  // the right address.
  // Strip PANI outbound - leaving the trust zone.
  doTestHeaders(_tp_default, false, &tp, false, msg, false, false, true, false);
}

// Test flows into Bono (P-CSCF), not first hop, in particular for header stripping.
TEST_F(StatefulEdgeProxyTest, TestMainlineHeadersBonoProxyIn)
{
  SCOPED_TRACE("");

  // Register client.
  TransportFlow tp(TransportFlow::Protocol::TCP, TransportFlow::Trust::UNTRUSTED, "10.83.18.37", 36531);
  string token;
  string baretoken;
  doRegisterEdge(&tp, token, baretoken, false);

  // INVITE from client via bono to Sprout, not first hop
  Message msg;
  msg._via = "10.83.18.37:36531;transport=tcp";
  // Don't care which transport we come back on, as long as it goes to
  // the right address.
  // Strip PANI in outbound direction - leaving the trust zone.
  // This is originating; mark it so.
  doTestHeaders(&tp, false, _tp_default, false, msg, false, true, false, true);
}


// Test flows into IBCF, in particular for header stripping.
TEST_F(StatefulTrunkProxyTest, TestMainlineHeadersIbcfTrustedIn)
{
  SCOPED_TRACE("");

  // Set up default message.
  Message msg;
  msg._to = "6505551000";
  msg._from = "+12125551212";
  msg._fromdomain = "foreign-domain.example.com";
  msg._via = "10.7.7.10:36530;transport=tcp";

  // Get a connection from the trusted host.
  TransportFlow tp(TransportFlow::Protocol::TCP, TransportFlow::Trust::UNTRUSTED, "10.7.7.10", 36530);

  // INVITE from the "trusted" (but outside the trust zone) trunk to Sprout.
  // Stripped in both directions.
  // This cannot be originating, because it's IBCF! It's a foreign domain.
  doTestHeaders(&tp, true, _tp_default, false, msg, false, false, false, false);
}

// Test flows out of IBCF, in particular for header stripping.
TEST_F(StatefulTrunkProxyTest, TestMainlineHeadersIbcfTrustedOut)
{
  SCOPED_TRACE("");

  // Set up default message.
  Message msg;
  msg._to = "+12125551212";
  msg._todomain = "10.7.7.10:36530;transport=tcp";
  msg._from = "6505551000";
  msg._fromdomain = "trunknode";
  msg._via = "10.99.88.11:12345";

  // Get a connection from the trusted host.
  TransportFlow tp(TransportFlow::Protocol::TCP, TransportFlow::Trust::UNTRUSTED, "10.7.7.10", 36530);

  // INVITE from Sprout to the "trusted" (but outside the trust zone) trunk.
  // Stripped in both directions.
  doTestHeaders(_tp_default, false, &tp, true, msg, false, false, false, false);
}

// Check configured trusted host is respected
TEST_F(StatefulTrunkProxyTest, TestIbcfTrusted1)
{
  SCOPED_TRACE("");

  // Set up default message.
  Message msg;
  msg._method = "INVITE";
  msg._to = "6505551000";
  msg._from = "+12125551212";
  msg._fromdomain = "foreign-domain.example.com";

  TransportFlow* tp;
  pjsip_tx_data* tdata;
  ReqMatcher r1("INVITE");
  string actual;

  // Get a connection from the trusted host.
  tp = new TransportFlow(TransportFlow::Protocol::TCP, TransportFlow::Trust::UNTRUSTED, "10.7.7.10", 36530);

  // Send an INVITE from the trusted host.
  msg._unique++;
  inject_msg(msg.get_request(), tp);

  // Check it's the right kind and method, and goes to the right place.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  r1.matches(tdata->msg);
  expect_target("TCP", "10.6.6.8", stack_data.trusted_port, tdata);  // to Sprout

  // Check it is marked authorized and integrity-protected. This
  // particular header is a bit weird; feel free to relax the test if
  // you understand what's going on.
  actual = get_headers(tdata->msg, "Authorization");
  EXPECT_EQ("Authorization: Digest username=\"sip:6505551000@homedomain\", nonce=\"\", response=\"\",integrity-protected=\"yes\"", actual);

  // Send a reply.
  inject_msg(respond_to_current_txdata(200));
  poll();
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();

  free_txdata();
  delete tp;
}

// Check that both configured trusted hosts are respected.
TEST_F(StatefulTrunkProxyTest, TestIbcfTrusted2)
{
  SCOPED_TRACE("");

  // Set up default message.
  Message msg;
  msg._method = "INVITE";
  msg._to = "6505551000";
  msg._from = "+12125551212";
  msg._fromdomain = "foreign-domain.example.com";

  TransportFlow* tp;
  pjsip_tx_data* tdata;
  ReqMatcher r1("INVITE");
  string actual;

  // Get a connection from the other trusted host.
  tp = new TransportFlow(TransportFlow::Protocol::TCP, TransportFlow::Trust::UNTRUSTED, "10.7.7.11", 36533);

  // Send an INVITE from the trusted host.
  msg._unique++;
  inject_msg(msg.get_request(), tp);

  // Check it's the right kind and method, and goes to the right place.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  r1.matches(tdata->msg);
  expect_target("TCP", "10.6.6.8", stack_data.trusted_port, tdata);  // to Sprout

  free_txdata();
  delete tp;
}

// Check that ;orig on IBCF trunk is illegal.
TEST_F(StatefulTrunkProxyTest, TestIbcfOrig)
{
  SCOPED_TRACE("");

  // Set up default message.
  Message msg;
  msg._method = "INVITE";
  msg._to = "testnode;orig";
  msg._todomain = "";
  msg._route = "sip:6505551000@homedomain";
  msg._from = "+12125551212";
  msg._fromdomain = "foreign-domain.example.com";

  TransportFlow* tp;
  pjsip_tx_data* tdata;
  RespMatcher r1(403);
  string actual;

  // Get a connection from the other trusted host.
  tp = new TransportFlow(TransportFlow::Protocol::TCP, TransportFlow::Trust::UNTRUSTED, "10.7.7.11", 36533);

  // Send an INVITE from the trusted host.
  msg._unique++;
  inject_msg(msg.get_request(), tp);

  // Check it's the right kind and method, and goes to the right place.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  r1.matches(tdata->msg);
  tp->expect_target(tdata, true);  // to source

  free_txdata();
  delete tp;
}

TEST_F(StatefulTrunkProxyTest, TestIbcfUntrusted)
{
  SCOPED_TRACE("");

  // Set up default message.
  Message msg;
  msg._method = "INVITE";
  msg._to = "6505551000";
  msg._from = "+12125551212";
  msg._fromdomain = "foreign-domain.example.com";

  TransportFlow* tp;
  pjsip_tx_data* tdata;
  ReqMatcher r1("INVITE");
  string actual;

  // Get a connection from some other random (untrusted) host.
  tp = new TransportFlow(TransportFlow::Protocol::TCP, TransportFlow::Trust::UNTRUSTED, "10.83.18.39", 36530);

  // Send the same INVITE from the random host.
  msg._unique++;
  inject_msg(msg.get_request(), tp);

  // Check it's the right kind and method, and goes to the right place.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  r1.matches(tdata->msg);
  expect_target("TCP", "10.6.6.8", stack_data.trusted_port, tdata);  // to Sprout

  // Check it is *not* authorized.
  actual = get_headers(tdata->msg, "Authorization");
  EXPECT_EQ("", actual);

  free_txdata();
  delete tp;
}

// Test basic ISC (AS) flow.
TEST_F(IscTest, SimpleMainline)
{
  register_uri(_store, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_user_ifc("sip:6505551000@homedomain",
                                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                                "<ServiceProfile>\n"
                                "  <InitialFilterCriteria>\n"
                                "    <Priority>1</Priority>\n"
                                "    <TriggerPoint>\n"
                                "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                                "    <SPT>\n"
                                "      <ConditionNegated>0</ConditionNegated>\n"
                                "      <Group>0</Group>\n"
                                "      <Method>INVITE</Method>\n"
                                "      <Extension></Extension>\n"
                                "    </SPT>\n"
                                "  </TriggerPoint>\n"
                                "  <ApplicationServer>\n"
                                "    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                                "    <DefaultHandling>0</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile>");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, TransportFlow::Trust::UNTRUSTED, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, TransportFlow::Trust::TRUSTED, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain;orig";
  msg._todomain = "";
  msg._route = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@testnode:5058;transport=UDP;lr>"));

  // ---------- AS1 turns it around (acting as proxy)
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to final destination
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));

  tpBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r2.uri());
  EXPECT_EQ("", get_headers(out, "Route"));

  free_txdata();
}


// Test basic ISC (AS) rejection flow.
TEST_F(IscTest, SimpleReject)
{
  register_uri(_store, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_user_ifc("sip:6505551234@homedomain",
                                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                                "<ServiceProfile>\n"
                                "  <InitialFilterCriteria>\n"
                                "    <Priority>1</Priority>\n"
                                "    <TriggerPoint>\n"
                                "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                                "    <SPT>\n"
                                "      <ConditionNegated>0</ConditionNegated>\n"
                                "      <Group>0</Group>\n"
                                "      <Method>INVITE</Method>\n"
                                "      <Extension></Extension>\n"
                                "    </SPT>\n"
                                "  </TriggerPoint>\n"
                                "  <ApplicationServer>\n"
                                "    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                                "    <DefaultHandling>0</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile>");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, TransportFlow::Trust::UNTRUSTED, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, TransportFlow::Trust::TRUSTED, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain;orig";
  msg._todomain = "";
  msg._route = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@testnode:5058;transport=UDP;lr>"));

  // ---------- AS1 rejects it.
  string fresp = respond_to_txdata(current_txdata(), 404);
  free_txdata();
  inject_msg(fresp, &tpAS1);

  // ACK goes back to AS1
  SCOPED_TRACE("ACK");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("ACK").matches(out));
  free_txdata();

  // 404 response goes back to bono
  SCOPED_TRACE("404");
  out = current_txdata()->msg;
  RespMatcher(404).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  msg._cseq++;
  free_txdata();

  // ---------- Send ACK from bono
  SCOPED_TRACE("ACK");
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpBono);
}


// Test basic ISC (AS) final acceptance flow (AS sinks request).
TEST_F(IscTest, SimpleAccept)
{
  register_uri(_store, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_user_ifc("sip:6505551234@homedomain",
                                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                                "<ServiceProfile>\n"
                                "  <InitialFilterCriteria>\n"
                                "    <Priority>1</Priority>\n"
                                "    <TriggerPoint>\n"
                                "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                                "    <SPT>\n"
                                "      <ConditionNegated>0</ConditionNegated>\n"
                                "      <Group>0</Group>\n"
                                "      <Method>INVITE</Method>\n"
                                "      <Extension></Extension>\n"
                                "    </SPT>\n"
                                "  </TriggerPoint>\n"
                                "  <ApplicationServer>\n"
                                "    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                                "    <DefaultHandling>0</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile>");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, TransportFlow::Trust::UNTRUSTED, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, TransportFlow::Trust::TRUSTED, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain;orig";
  msg._todomain = "";
  msg._route = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@testnode:5058;transport=UDP;lr>"));

  // ---------- AS1 accepts it with 200.
  string fresp = respond_to_txdata(current_txdata(), 200);
  free_txdata();
  inject_msg(fresp, &tpAS1);

  // 200 response goes back to bono
  SCOPED_TRACE("OK");
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  msg._cseq++;
  free_txdata();

  // ---------- Send ACK from bono
  SCOPED_TRACE("ACK");
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpBono);

  // ACK goes back to AS1
  SCOPED_TRACE("ACK");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("ACK").matches(out));
  free_txdata();
}


// Test basic ISC (AS) redirection flow.
TEST_F(IscTest, SimpleRedirect)
{
  register_uri(_store, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_user_ifc("sip:6505551234@homedomain",
                                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                                "<ServiceProfile>\n"
                                "  <InitialFilterCriteria>\n"
                                "    <Priority>1</Priority>\n"
                                "    <TriggerPoint>\n"
                                "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                                "    <SPT>\n"
                                "      <ConditionNegated>0</ConditionNegated>\n"
                                "      <Group>0</Group>\n"
                                "      <Method>INVITE</Method>\n"
                                "      <Extension></Extension>\n"
                                "    </SPT>\n"
                                "  </TriggerPoint>\n"
                                "  <ApplicationServer>\n"
                                "    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                                "    <DefaultHandling>0</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile>");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, TransportFlow::Trust::UNTRUSTED, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, TransportFlow::Trust::TRUSTED, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain;orig";
  msg._todomain = "";
  msg._route = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@testnode:5058;transport=UDP;lr>"));

  // ---------- AS1 redirects it to another user on the same server.
  string fresp = respond_to_txdata(current_txdata(), 302, "", "Contact: sip:6505559876@homedomain");
  free_txdata();
  inject_msg(fresp, &tpAS1);

  // ACK goes back to AS1
  SCOPED_TRACE("ACK");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("ACK").matches(out));
  free_txdata();

  // 302 response goes back to bono
  SCOPED_TRACE("Redirect");
  out = current_txdata()->msg;
  RespMatcher(302).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  EXPECT_EQ("Contact: <sip:6505559876@homedomain>", get_headers(out, "Contact"));
  msg.set_route(out);
  msg._cseq++;
  free_txdata();

  // ---------- Send ACK from bono
  SCOPED_TRACE("ACK");
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpBono);
}


// Test more interesting ISC (AS) flow.
TEST_F(IscTest, InterestingAs)
{
  register_uri(_store, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_user_ifc("sip:6505551000@homedomain",
                                R"(<?xml version="1.0" encoding="UTF-8"?>
                                <ServiceProfile>
                                  <InitialFilterCriteria>
                                    <Priority>2</Priority>
                                    <TriggerPoint>
                                    <ConditionTypeCNF>0</ConditionTypeCNF>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <Method>INVITE</Method>
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:4.2.3.4:56788;transport=UDP</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                  <InitialFilterCriteria>
                                    <Priority>1</Priority>
                                    <TriggerPoint>
                                    <ConditionTypeCNF>0</ConditionTypeCNF>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <Method>INVITE</Method>
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                </ServiceProfile>)");
  _hss_connection->set_user_ifc("sip:6505551234@homedomain",
                                R"(<?xml version="1.0" encoding="UTF-8"?>
                                <ServiceProfile>
                                  <InitialFilterCriteria>
                                    <Priority>0</Priority>
                                    <TriggerPoint>
                                    <ConditionTypeCNF>0</ConditionTypeCNF>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <Method>INVITE</Method>
                                      <Extension></Extension>
                                    </SPT>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <SessionCase>1</SessionCase>  <!-- terminating-registered -->
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:5.2.3.4:56787;transport=UDP</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                  <InitialFilterCriteria>
                                    <Priority>1</Priority>
                                    <TriggerPoint>
                                    <ConditionTypeCNF>0</ConditionTypeCNF>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <Method>INVITE</Method>
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:6.2.3.4:56786;transport=UDP</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                </ServiceProfile>)");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, TransportFlow::Trust::UNTRUSTED, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, TransportFlow::Trust::TRUSTED, "1.2.3.4", 56789);
  TransportFlow tpAS2(TransportFlow::Protocol::UDP, TransportFlow::Trust::TRUSTED, "4.2.3.4", 56788);
  TransportFlow tpAS3(TransportFlow::Protocol::UDP, TransportFlow::Trust::TRUSTED, "5.2.3.4", 56787);
  TransportFlow tpAS4(TransportFlow::Protocol::UDP, TransportFlow::Trust::TRUSTED, "6.2.3.4", 56786);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain;orig";
  msg._todomain = "";
  msg._route = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@testnode:5058;transport=UDP;lr>"));

  // ---------- AS1 turns it around (acting as proxy)
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to AS2
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS2.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:4\\.2\\.3\\.4:56788;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@testnode:5058;transport=UDP;lr>"));

  // ---------- AS2 turns it around (acting as proxy)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS2);
  free_txdata();

  // 100 Trying goes back to AS2
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS2.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to AS3
  SCOPED_TRACE("INVITE (3)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS3.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@testnode:5058;transport=UDP;lr>"));

  // ---------- AS3 turns it around (acting as proxy)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS3);
  free_txdata();

  // 100 Trying goes back to AS3
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS3.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to AS4
  SCOPED_TRACE("INVITE (4)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS4.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:6\\.2\\.3\\.4:56786;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@testnode:5058;transport=UDP;lr>"));

  // ---------- AS4 turns it around (acting as proxy)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS4);
  free_txdata();

  // 100 Trying goes back to AS4
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS4.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to final destination
  SCOPED_TRACE("INVITE (Z)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r1.uri());
  EXPECT_EQ("", get_headers(out, "Route"));

  free_txdata();
}


// Test AS-originated flow - orig.
void IscTest::doAsOriginated(Message& msg, bool expect_orig)
{
  register_uri(_store, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_user_ifc("sip:6505551000@homedomain",
                                R"(<?xml version="1.0" encoding="UTF-8"?>
                                <ServiceProfile>
                                  <InitialFilterCriteria>
                                    <Priority>1</Priority>
                                    <TriggerPoint>
                                    <ConditionTypeCNF>0</ConditionTypeCNF>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <Method>INVITE</Method>
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                </ServiceProfile>)");
  _hss_connection->set_user_ifc("sip:6505551234@homedomain",
                                R"(<?xml version="1.0" encoding="UTF-8"?>
                                <ServiceProfile>
                                  <InitialFilterCriteria>
                                    <Priority>0</Priority>
                                    <TriggerPoint>
                                    <ConditionTypeCNF>0</ConditionTypeCNF>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <Method>INVITE</Method>
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:5.2.3.4:56787;transport=UDP</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                </ServiceProfile>)");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, TransportFlow::Trust::UNTRUSTED, "10.99.88.11", 12345);
  TransportFlow tpAS0(TransportFlow::Protocol::UDP, TransportFlow::Trust::TRUSTED, "6.2.3.4", 56786);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, TransportFlow::Trust::TRUSTED, "1.2.3.4", 56789);
  TransportFlow tpAS2(TransportFlow::Protocol::UDP, TransportFlow::Trust::TRUSTED, "5.2.3.4", 56787);

  // ---------- Send spontaneous INVITE from AS0.
  inject_msg(msg.get_request(), &tpAS0);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to AS0
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS0.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  ReqMatcher r1("INVITE");
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = NULL;

  if (expect_orig)
  {
    // INVITE passed on to AS1
    SCOPED_TRACE("INVITE (S)");
    out = current_txdata()->msg;
    ASSERT_NO_FATAL_FAILURE(r1.matches(out));

    tpAS1.expect_target(current_txdata(), false);
    EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
    EXPECT_THAT(get_headers(out, "Route"),
                testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@testnode:5058;transport=UDP;lr>"));

    // ---------- AS1 turns it around (acting as proxy)
    hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
    if (hdr)
    {
      pj_list_erase(hdr);
    }
    inject_msg(out, &tpAS1);
    free_txdata();

    // 100 Trying goes back to AS1
    out = current_txdata()->msg;
    RespMatcher(100).matches(out);
    tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
    msg.set_route(out);
    free_txdata();
  }

  // INVITE passed on to AS2
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS2.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@testnode:5058;transport=UDP;lr>"));

  // ---------- AS2 turns it around (acting as proxy)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS2);
  free_txdata();

  // 100 Trying goes back to AS2
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS2.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to final destination
  SCOPED_TRACE("INVITE (Z)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r1.uri());
  EXPECT_EQ("", get_headers(out, "Route"));

  free_txdata();
}


// Test AS-originated flow - orig.
TEST_F(IscTest, AsOriginatedOrig)
{
  // ---------- Send spontaneous INVITE from AS0, marked as originating-handling-required.
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
//  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain;orig";
  msg._todomain = "";
  msg._route = "sip:6505551234@homedomain";

  msg._method = "INVITE";

  SCOPED_TRACE("orig");
  doAsOriginated(msg, true);
}


// Test AS-originated flow - term.
TEST_F(IscTest, AsOriginatedTerm)
{
  // ---------- Send spontaneous INVITE from AS0, marked as terminating-handling-only.
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
//  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "sip:6505551234@homedomain";

  msg._method = "INVITE";

  SCOPED_TRACE("term");
  doAsOriginated(msg, false);
}


// Test call-diversion AS flow.
TEST_F(IscTest, Cdiv)
{
  register_uri(_store, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  register_uri(_store, "6505555678", "homedomain", "sip:andunnuvvawun@10.114.61.214:5061;transport=tcp;ob");
  _hss_connection->set_user_ifc("sip:6505551234@homedomain",
                                R"(<?xml version="1.0" encoding="UTF-8"?>
                                <ServiceProfile>
                                  <InitialFilterCriteria>
                                    <Priority>2</Priority>
                                    <TriggerPoint>
                                    <ConditionTypeCNF>0</ConditionTypeCNF>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <SessionCase>4</SessionCase>  <!-- originating-cdiv -->
                                      <Extension></Extension>
                                    </SPT>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <Method>INVITE</Method>
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                  <InitialFilterCriteria>
                                    <Priority>0</Priority>
                                    <TriggerPoint>
                                    <ConditionTypeCNF>0</ConditionTypeCNF>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <Method>INVITE</Method>
                                      <Extension></Extension>
                                    </SPT>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <SessionCase>1</SessionCase>  <!-- terminating-registered -->
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:5.2.3.4:56787;transport=UDP</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                </ServiceProfile>)");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, TransportFlow::Trust::UNTRUSTED, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, TransportFlow::Trust::TRUSTED, "5.2.3.4", 56787);
  TransportFlow tpAS2(TransportFlow::Protocol::UDP, TransportFlow::Trust::TRUSTED, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain;orig";
  msg._todomain = "";
  msg._route = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to AS1 (as terminating AS for Bob)
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@testnode:5058;transport=UDP;lr>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551234@homedomain>;sescase=term;regstate=reg"));

  // ---------- AS1 turns it around (acting as routing B2BUA by changing the target)
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  ((pjsip_sip_uri*)out->line.req.uri)->user = pj_str("6505555678");
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to AS2 (as originating AS for Bob)
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS2.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505555678@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@testnode:5058;transport=UDP;lr>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551234@homedomain>;sescase=orig-cdiv"));

  // ---------- AS2 turns it around (acting as proxy)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS2);
  free_txdata();

  // 100 Trying goes back to AS2
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS2.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to final destination
  SCOPED_TRACE("INVITE (4)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:andunnuvvawun@10.114.61.214:5061;transport=tcp;ob", r1.uri());
  EXPECT_EQ("", get_headers(out, "Route"));

  free_txdata();
}


// Test attempted AS chain link after chain has expired.
TEST_F(IscTest, ExpiredChain)
{
  if (RUNNING_ON_VALGRIND)
  {
    // This test doesn't work with Valgrind, presumably due to some
    // interaction with the clock_gettime call interposing we do at
    // cwtest_advance_time_ms below.
    return;
  }

  register_uri(_store, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_user_ifc("sip:6505551000@homedomain",
                                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                                "<ServiceProfile>\n"
                                "  <InitialFilterCriteria>\n"
                                "    <Priority>1</Priority>\n"
                                "    <TriggerPoint>\n"
                                "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                                "    <SPT>\n"
                                "      <ConditionNegated>0</ConditionNegated>\n"
                                "      <Group>0</Group>\n"
                                "      <Method>INVITE</Method>\n"
                                "      <Extension></Extension>\n"
                                "    </SPT>\n"
                                "  </TriggerPoint>\n"
                                "  <ApplicationServer>\n"
                                "    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                                "    <DefaultHandling>0</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile>");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, TransportFlow::Trust::UNTRUSTED, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, TransportFlow::Trust::TRUSTED, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain;orig";
  msg._todomain = "";
  msg._route = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@testnode:5058;transport=UDP;lr>"));

  // ---------- AS1 gives final response, ending the transaction.
  string fresp = respond_to_txdata(current_txdata(), 404);
  pjsip_msg* saved = pop_txdata()->msg;
  inject_msg(fresp, &tpAS1);

  // ACK goes back to AS1
  SCOPED_TRACE("ACK");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("ACK").matches(out));
  free_txdata();

  // 404 response goes back to bono
  SCOPED_TRACE("404");
  out = current_txdata()->msg;
  RespMatcher(404).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  msg._cseq++;
  free_txdata();

  // ---------- Send ACK from bono
  SCOPED_TRACE("ACK");
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpBono);

  // Allow time to pass, so the initial Sprout UAS transaction moves
  // from Completed to Terminated to Destroyed.  32s is the default
  // timeout. This causes the ODI token to expire.
  cwtest_advance_time_ms(33000L);
  poll();

  // ---------- AS1 attempts to turn the message around (acting as proxy)
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(saved, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(saved, &tpAS1);

  // 400 error goes back to AS1
  SCOPED_TRACE("400");
  out = current_txdata()->msg;
  RespMatcher(400).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();
}


// Test a simple MMTEL flow.
TEST_F(IscTest, MmtelFlow)
{
  register_uri(_store, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_user_ifc("sip:6505551000@homedomain",
                                R"(<?xml version="1.0" encoding="UTF-8"?>
                                <ServiceProfile>
                                  <InitialFilterCriteria>
                                    <Priority>1</Priority>
                                    <TriggerPoint>
                                    <ConditionTypeCNF>0</ConditionTypeCNF>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <Method>INVITE</Method>
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:mmtel.homedomain</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                </ServiceProfile>)");
  _xdm_connection->put("sip:6505551000@homedomain",
                       R"(<?xml version="1.0" encoding="UTF-8"?>
                          <simservs xmlns="http://uri.etsi.org/ngn/params/xml/simservs/xcap" xmlns:cp="urn:ietf:params:xml:ns:common-policy">
                            <originating-identity-presentation active="true" />
                            <originating-identity-presentation-restriction active="true">
                              <default-behaviour>presentation-restricted</default-behaviour>
                            </originating-identity-presentation-restriction>
                            <communication-diversion active="false"/>
                            <incoming-communication-barring active="false"/>
                            <outgoing-communication-barring active="false"/>
                          </simservs>)");  // "
  _hss_connection->set_user_ifc("sip:6505551234@homedomain",
                                R"(<?xml version="1.0" encoding="UTF-8"?>
                                <ServiceProfile>
                                  <InitialFilterCriteria>
                                    <Priority>0</Priority>
                                    <TriggerPoint>
                                    <ConditionTypeCNF>0</ConditionTypeCNF>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <Method>INVITE</Method>
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:5.2.3.4:56787;transport=UDP</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                </ServiceProfile>)");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, TransportFlow::Trust::UNTRUSTED, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, TransportFlow::Trust::TRUSTED, "5.2.3.4", 56787);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain;orig";
  msg._todomain = "";
  msg._route = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // Call should pass through MMTEL AS, and then proceed. This should
  // add a privacy header.

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@testnode:5058;transport=UDP;lr>"));
  EXPECT_EQ("Privacy: id, header, user", get_headers(out, "Privacy"));

  // ---------- AS1 turns it around (acting as proxy)
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to final destination
  SCOPED_TRACE("INVITE (4)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r1.uri());
  EXPECT_EQ("", get_headers(out, "Route"));
  EXPECT_EQ("Privacy: id, header, user", get_headers(out, "Privacy"));

  free_txdata();
}


// Test MMTEL-then-external-AS flows (both orig and term).
TEST_F(IscTest, DISABLED_MmtelThenExternal)  // @@@KSW MMTEL-then-external-AS not working yet.
{
  register_uri(_store, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_user_ifc("sip:6505551000@homedomain",
                                R"(<?xml version="1.0" encoding="UTF-8"?>
                                <ServiceProfile>
                                  <InitialFilterCriteria>
                                    <Priority>1</Priority>
                                    <TriggerPoint>
                                    <ConditionTypeCNF>0</ConditionTypeCNF>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <Method>INVITE</Method>
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:mmtel.homedomain</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                  <InitialFilterCriteria>
                                    <Priority>2</Priority>
                                    <TriggerPoint>
                                    <ConditionTypeCNF>0</ConditionTypeCNF>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <Method>INVITE</Method>
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                </ServiceProfile>)");
  _xdm_connection->put("sip:6505551000@homedomain",
                       R"(<?xml version="1.0" encoding="UTF-8"?>
                          <simservs xmlns="http://uri.etsi.org/ngn/params/xml/simservs/xcap" xmlns:cp="urn:ietf:params:xml:ns:common-policy">
                            <originating-identity-presentation active="true" />
                            <originating-identity-presentation-restriction active="true">
                              <default-behaviour>presentation-restricted</default-behaviour>
                            </originating-identity-presentation-restriction>
                            <communication-diversion active="false"/>
                            <incoming-communication-barring active="false"/>
                            <outgoing-communication-barring active="false"/>
                          </simservs>)");  // "
  _hss_connection->set_user_ifc("sip:6505551234@homedomain",
                                R"(<?xml version="1.0" encoding="UTF-8"?>
                                <ServiceProfile>
                                  <InitialFilterCriteria>
                                    <Priority>1</Priority>
                                    <TriggerPoint>
                                    <ConditionTypeCNF>0</ConditionTypeCNF>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <Method>INVITE</Method>
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:mmtel.homedomain</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                  <InitialFilterCriteria>
                                    <Priority>2</Priority>
                                    <TriggerPoint>
                                    <ConditionTypeCNF>0</ConditionTypeCNF>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <Method>INVITE</Method>
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:5.2.3.4:56787;transport=UDP</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                </ServiceProfile>)");
  _xdm_connection->put("sip:65055511234@homedomain",
                       R"(<?xml version="1.0" encoding="UTF-8"?>
                          <simservs xmlns="http://uri.etsi.org/ngn/params/xml/simservs/xcap" xmlns:cp="urn:ietf:params:xml:ns:common-policy">
                            <originating-identity-presentation active="true" />
                            <originating-identity-presentation-restriction active="true">
                              <default-behaviour>presentation-restricted</default-behaviour>
                            </originating-identity-presentation-restriction>
                            <communication-diversion active="false"/>
                            <incoming-communication-barring active="false"/>
                            <outgoing-communication-barring active="false"/>
                          </simservs>)");  // "

  TransportFlow tpBono(TransportFlow::Protocol::TCP, TransportFlow::Trust::UNTRUSTED, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, TransportFlow::Trust::TRUSTED, "1.2.3.4", 56789);
  TransportFlow tpAS2(TransportFlow::Protocol::UDP, TransportFlow::Trust::TRUSTED, "5.2.3.4", 56787);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain;orig";
  msg._todomain = "";
  msg._route = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // Call should pass through MMTEL AS, and then proceed. This should
  // add a privacy header.

  // INVITE passed on to AS1 (as originating).
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@testnode:5058;transport=UDP;lr>"));
  EXPECT_EQ("Privacy: id, header, user", get_headers(out, "Privacy"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551000@homedomain>;sescase=orig;regstate=unreg"));

  // ---------- AS1 turns it around (acting as proxy)
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // Call should pass through MMTEL AS, and then proceed. This should
  // do nothing.

  // INVITE passed on to AS2 (as terminating).
  SCOPED_TRACE("INVITE (S2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS2.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@testnode:5058;transport=UDP;lr>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551234@homedomain>;sescase=term;regstate=reg"));

  // ---------- AS2 turns it around (acting as proxy)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS2);
  free_txdata();

  // 100 Trying goes back to AS2
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS2.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to final destination
  SCOPED_TRACE("INVITE (4)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r1.uri());
  EXPECT_EQ("", get_headers(out, "Route"));
  EXPECT_EQ("Privacy: id, header, user", get_headers(out, "Privacy"));

  free_txdata();
}


// Test multiple-MMTEL flow.
TEST_F(IscTest, DISABLED_MultipleMmtelFlow)  // @@@KSW MMTEL-then-external-AS not working yet.

{
  register_uri(_store, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_user_ifc("sip:6505551000@homedomain",
                                R"(<?xml version="1.0" encoding="UTF-8"?>
                                <ServiceProfile>
                                  <InitialFilterCriteria>
                                    <Priority>1</Priority>
                                    <TriggerPoint>
                                    <ConditionTypeCNF>0</ConditionTypeCNF>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <Method>INVITE</Method>
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:mmtel.homedomain</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                  <InitialFilterCriteria>
                                    <Priority>2</Priority>
                                    <TriggerPoint>
                                    <ConditionTypeCNF>0</ConditionTypeCNF>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <Method>INVITE</Method>
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:mmtel.homedomain</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                </ServiceProfile>)");
  _xdm_connection->put("sip:6505551000@homedomain",
                       R"(<?xml version="1.0" encoding="UTF-8"?>
                          <simservs xmlns="http://uri.etsi.org/ngn/params/xml/simservs/xcap" xmlns:cp="urn:ietf:params:xml:ns:common-policy">
                            <originating-identity-presentation active="true" />
                            <originating-identity-presentation-restriction active="true">
                              <default-behaviour>presentation-restricted</default-behaviour>
                            </originating-identity-presentation-restriction>
                            <communication-diversion active="false"/>
                            <incoming-communication-barring active="false"/>
                            <outgoing-communication-barring active="false"/>
                          </simservs>)");  // "
  _hss_connection->set_user_ifc("sip:6505551234@homedomain",
                                R"(<?xml version="1.0" encoding="UTF-8"?>
                                <ServiceProfile>
                                  <InitialFilterCriteria>
                                    <Priority>1</Priority>
                                    <TriggerPoint>
                                    <ConditionTypeCNF>0</ConditionTypeCNF>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <Method>INVITE</Method>
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:mmtel.homedomain</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                  <InitialFilterCriteria>
                                    <Priority>2</Priority>
                                    <TriggerPoint>
                                    <ConditionTypeCNF>0</ConditionTypeCNF>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <Method>INVITE</Method>
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:mmtel.homedomain</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                  <InitialFilterCriteria>
                                    <Priority>3</Priority>
                                    <TriggerPoint>
                                    <ConditionTypeCNF>0</ConditionTypeCNF>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <Method>INVITE</Method>
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:5.2.3.4:56787;transport=UDP</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                </ServiceProfile>)");
  _xdm_connection->put("sip:6505551234@homedomain",
                       R"(<?xml version="1.0" encoding="UTF-8"?>
                          <simservs xmlns="http://uri.etsi.org/ngn/params/xml/simservs/xcap" xmlns:cp="urn:ietf:params:xml:ns:common-policy">
                            <originating-identity-presentation active="true" />
                            <originating-identity-presentation-restriction active="true">
                              <default-behaviour>presentation-restricted</default-behaviour>
                            </originating-identity-presentation-restriction>
                            <communication-diversion active="false"/>
                            <incoming-communication-barring active="false"/>
                            <outgoing-communication-barring active="false"/>
                          </simservs>)");  // "

  TransportFlow tpBono(TransportFlow::Protocol::TCP, TransportFlow::Trust::UNTRUSTED, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, TransportFlow::Trust::TRUSTED, "5.2.3.4", 56787);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain;orig";
  msg._todomain = "";
  msg._route = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // Call should pass through MMTEL AS four times (!), and then
  // proceed. This should add a privacy header.

  // INVITE passed on to AS1
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@testnode:5058;transport=UDP;lr>"));
  EXPECT_EQ("Privacy: id, header, user", get_headers(out, "Privacy"));

  // ---------- AS1 turns it around (acting as proxy)
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS1);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS1.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to final destination
  SCOPED_TRACE("INVITE (4)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r1.uri());
  EXPECT_EQ("", get_headers(out, "Route"));
  EXPECT_EQ("Privacy: id, header, user", get_headers(out, "Privacy"));

  free_txdata();
}

// @@@ WS stuff

// @@@ integrity-protected handling (includes find_flow_data); relationship to auth

// @@@ minor things:
// @@@ multiple route headers, single route headers, no route header
// @@@ strict route
// @@@ maddr routes
// @@@ use bgcf route

// @@@ sprouty stuff: badly-formed contact URI etc around 1096ff
// @@@ SC comparison: equal, terminated
// @@@ translate non-SIP URI, other problems aroudn 1200
// ... will-to-live issues encountered

// @@@ Extend doTestHeaders to send a request (e.g., reINVITE) in the opposite
//     direction. Needs a separate message in the same dialog.
// @@@ Extend doTestHeaders to examine REGISTER flows.
// @@@ Extend doTestHeaders to examine CANCEL flows.
// @@@ Extend doTestHeaders to examine ISC flows.

// @@@ Make tests run faster. E.g., terminate needs a shutdown kick so
// we don't wait 100ms for it.

// TODO: Test that an outbound call to a phone that has registered
// through an edge proxy specifies the correct Route header (so it
// goes to the right bono, and passes the right token).  (This is a
// sprout test, not a bono test). (Is like the forked-flow tests
// above, just with a more elaborate registration).
