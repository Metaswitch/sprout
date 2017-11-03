/**
 * @file bono_test.cpp UT for Bono.
 *
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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
#include "bono.h"
#include "fakecurl.hpp"
#include "fakehssconnection.hpp"
#include "fakexdmconnection.hpp"
#include "test_interposer.hpp"
#include "fakechronosconnection.hpp"
#include "testingcommon.h"

using namespace std;
using testing::StrEq;
using testing::ElementsAre;
using testing::MatchesRegex;
using testing::HasSubstr;
using testing::Not;


/// ABC for fixtures for StatefulProxyTest and friends.
class StatefulProxyTestBase : public SipTest
{
public:
  static QuiescingManager _quiescing_manager;


  /// TX data for testing.  Will be cleaned up.  Each message in a
  /// forked flow has its URI stored in _uris, and its txdata stored
  /// in _tdata against that URI.
  vector<string> _uris;
  map<string,pjsip_tx_data*> _tdata;

  /// Set up test case.  Caller must clear host_mapping.
  static void SetUpTestCase(const string& edge_upstream_proxy,
                            const string& ibcf_trusted_hosts,
                            const string& pbx_hosts,
                            const string& pbx_service_routes,
                            bool ifcs,
                            bool icscf_enabled = false,
                            bool scscf_enabled = false,
                            const string& icscf_uri_str = "",
                            bool emerg_reg_enabled = false)
  {
    SipTest::SetUpTestCase();

    // Bono does not currently support SIP Graylisting, so this creates a SIP
    // Resolver without graylisting
    SipTest::SIPResolverNoGraylist();

    _analytics = new AnalyticsLogger();
    _edge_upstream_proxy = edge_upstream_proxy;
    _ibcf_trusted_hosts = ibcf_trusted_hosts;
    _icscf_uri_str = icscf_uri_str;
    _icscf = icscf_enabled;
    _scscf = scscf_enabled;
    _emerg_reg = emerg_reg_enabled;
    _acr_factory = new ACRFactory();
    pj_status_t ret = init_stateful_proxy(!_edge_upstream_proxy.empty(),
                                          _edge_upstream_proxy.c_str(),
                                          stack_data.pcscf_trusted_port,
                                          10,
                                          86400,
                                          !_ibcf_trusted_hosts.empty(),
                                          _ibcf_trusted_hosts.c_str(),
                                          pbx_hosts.c_str(),
                                          pbx_service_routes,
                                          _analytics,
                                          _acr_factory,
                                          _icscf_uri_str,
                                          &_quiescing_manager,
                                          _icscf,
                                          _scscf,
                                          _emerg_reg);
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
    delete _acr_factory; _acr_factory = NULL;
    delete _analytics; _analytics = NULL;
    SipTest::TearDownTestCase();
  }

  StatefulProxyTestBase()
  {
    _log_traffic = PrintingTestLogger::DEFAULT.isPrinting(); // true to see all traffic
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
    // Allow a good length of time to pass too, in case we have
    // transactions still open. 32s is the default UAS INVITE
    // transaction timeout, so we go higher than that.
    cwtest_advance_time_ms(33000L);
    poll();

    // Stop and restart the layer just in case
    pjsip_tsx_layer_instance()->stop();
    pjsip_tsx_layer_instance()->start();

  }

protected:
  static AnalyticsLogger* _analytics;
  static ACRFactory* _acr_factory;
  static string _edge_upstream_proxy;
  static string _ibcf_trusted_hosts;
  static string _icscf_uri_str;
  static bool _icscf;
  static bool _scscf;
  static bool _emerg_reg;

  void doTestHeaders(TransportFlow* tpA,
                     bool tpAset,
                     TransportFlow* tpB,
                     bool tpBset,
                     TestingCommon::Message& msg,
                     string route,
                     bool expect_100,
                     bool expect_trusted_headers_on_requests,
                     bool expect_trusted_headers_on_responses,
                     bool expect_orig,
                     bool pcpi);
};

AnalyticsLogger* StatefulProxyTestBase::_analytics;
ACRFactory* StatefulProxyTestBase::_acr_factory;
string StatefulProxyTestBase::_edge_upstream_proxy;
string StatefulProxyTestBase::_ibcf_trusted_hosts;
string StatefulProxyTestBase::_icscf_uri_str;
bool StatefulProxyTestBase::_icscf;
bool StatefulProxyTestBase::_scscf;
bool StatefulProxyTestBase::_emerg_reg;
QuiescingManager StatefulProxyTestBase::_quiescing_manager;

class StatefulEdgeProxyTest : public StatefulProxyTestBase
{
public:
  static void SetUpTestCase()
  {
    StatefulProxyTestBase::SetUpTestCase("upstreamnode", "", "", "", false);
    add_host_mapping("upstreamnode", "10.6.6.8");
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
  void doRegisterEdge(TransportFlow* xiTp,
                      string& xoToken,
                      string& xoBareToken,
                      int expiry = 300,
                      string response = "",
                      string integrity = "",
                      string extraRspHeaders = "",
                      bool firstHop = false,
                      string supported = "outbound, path",
                      bool expectPath = true,
                      string via = "");
  TestingCommon::Message doInviteEdge(string token);
};

class StatefulEdgeProxyAcceptRegisterTest : public StatefulProxyTestBase
{
public:
  static void SetUpTestCase()
  {
    StatefulProxyTestBase::SetUpTestCase("upstreamnode", "", "", "", false, false, false, "", true);
    add_host_mapping("upstreamnode", "10.6.6.8");
  }

  static void TearDownTestCase()
  {
    StatefulProxyTestBase::TearDownTestCase();
  }

  StatefulEdgeProxyAcceptRegisterTest()
  {
  }

  ~StatefulEdgeProxyAcceptRegisterTest()
  {
  }

protected:
};

class StatefulEdgeProxyPBXTest : public StatefulProxyTestBase
{
public:
  static void SetUpTestCase()
  {
    StatefulProxyTestBase::SetUpTestCase("upstreamnode",
                                         "",
                                         "1.2.3.4",
                                         "sip:scscfnode:5054;lr;transport=tcp;orig;auto-reg",
                                         false);
    add_host_mapping("scscfnode", "10.6.6.8");
  }

  static void TearDownTestCase()
  {
    StatefulProxyTestBase::TearDownTestCase();
  }

  StatefulEdgeProxyPBXTest()
  {
  }

  ~StatefulEdgeProxyPBXTest()
  {
  }

protected:
};


class StatefulTrunkProxyTest : public StatefulProxyTestBase
{
public:
  static void SetUpTestCase()
  {
    add_host_mapping("upstreamnode", "10.6.6.8");
    add_host_mapping("trunknode", "10.7.7.10");
    add_host_mapping("trunknode2", "10.7.7.11");
    StatefulProxyTestBase::SetUpTestCase("upstreamnode", "10.7.7.10,10.7.7.11", "", "", false);
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

using TestingCommon::Message;

// Test flows into Sprout (S-CSCF), in particular for header stripping.
// Check the transport each message is on, and the headers.
// Test a call from Alice to Bob.
void StatefulProxyTestBase::doTestHeaders(TransportFlow* tpA,  //< Alice's transport.
                                          bool tpAset,         //< Expect all requests to Alice on same transport?
                                          TransportFlow* tpB,  //< Bob's transport.
                                          bool tpBset,         //< Expect all requests to Bob on same transport?
                                          Message& msg,        //< Message to use for testing.
                                          string route,        //< Route header to be used on INVITE
                                          bool expect_100,     //< Will we get a 100 Trying?
                                          bool expect_trusted_headers_on_requests, //< Should P-A-N-I/P-V-N-I be passed on requests?
                                          bool expect_trusted_headers_on_responses, //< Should P-A-N-I/P-V-N-I be passed on responses?
                                          bool expect_orig,    //< Should we expect the INVITE to be marked originating?
                                          bool pcpi)           //< Should we expect a P-Called-Party-ID?
{
  SCOPED_TRACE("doTestHeaders");
  pjsip_msg* out;
  pjsip_tx_data* invite = NULL;
  pjsip_tx_data* prack = NULL;

  // Extra fields to insert in all requests and responses.
  string pani = "P-Access-Network-Info: ietf-carrier-pigeon;rfc=1149";
  string pvni = "P-Visited-Network-Id: other.net, \"Other Network\"";
  string pvani = pani + "\r\n" + pvni;

  if (!msg._extra.empty())
  {
    msg._extra.append("\r\n");
  }

  msg._extra.append(pani);
  msg._extra.append("\r\n");
  msg._extra.append(pvni);

  // ---------- Send INVITE C->X
  SCOPED_TRACE("INVITE");
  msg._method = "INVITE";
  msg._route = route;
  inject_msg(msg.get_request(), tpA);
  poll();
  ASSERT_EQ(expect_100 ? 2 : 1, txdata_count());

  if (expect_100)
  {
    // 100 Trying goes back C<-X
    out = current_txdata()->msg;
    RespMatcher(100).matches(out);
    tpA->expect_target(current_txdata(), true);  // Requests always come back on same transport
    msg.convert_routeset(out);

    // Don't bother testing P-Access-Network-Info or P-Visited-Network-Id,
    // because they never get inserted into such messages.
    free_txdata();
  }

  // INVITE passed on X->S
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("INVITE").matches(out));
  tpB->expect_target(current_txdata(), tpBset);

  // Check P-Access-Network-Info and P-Visited-Network-Id.
  EXPECT_EQ(expect_trusted_headers_on_requests ? pani : "",
            get_headers(out, "P-Access-Network-Info")) << "INVITE";
  EXPECT_EQ(expect_trusted_headers_on_requests ? pvni : "",
            get_headers(out, "P-Visited-Network-Id")) << "INVITE";

  // Check originating.
  if (expect_orig)
  {
    EXPECT_THAT(get_headers(out, "Route"), HasSubstr(";orig"));
  }
  else
  {
    EXPECT_THAT(get_headers(out, "Route"), Not(HasSubstr(";orig")));
  }

  // Check P-Called-Party-ID
  EXPECT_EQ(pcpi ? "P-Called-Party-ID: <" + msg._toscheme + ":" + msg._to + "@" + msg._todomain + ">" : "", get_headers(out, "P-Called-Party-ID"));

  invite = pop_txdata();

  // ---------- Send 183 Session Progress back X<-S
  SCOPED_TRACE("183 Session Progress");
  inject_msg(respond_to_txdata(invite, 183, "", pvani), tpB);
  ASSERT_EQ(1, txdata_count());

  // 183 goes back C<-X
  out = current_txdata()->msg;
  RespMatcher(183).matches(out);
  tpA->expect_target(current_txdata(), true);
  msg.convert_routeset(out);
  msg._cseq++;

  // Check P-Access-Network-Info and P-Visited-Network-Id
  EXPECT_EQ(expect_trusted_headers_on_responses ? pani : "",
            get_headers(out, "P-Access-Network-Info")) << "183 Session Progress";
  EXPECT_EQ(expect_trusted_headers_on_responses ? pvni : "",
            get_headers(out, "P-Visited-Network-Id")) << "183 Session Progress";

  free_txdata();

  // Send PRACK C->X
  SCOPED_TRACE("PRACK");
  msg._method = "PRACK";
  inject_msg(msg.get_request(), tpA);
  poll();
  ASSERT_EQ(1, txdata_count());

  // PRACK passed on X->S
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("PRACK").matches(out));
  tpB->expect_target(current_txdata(), tpBset);

  // Check P-Access-Network-Info and P-Visited-Network-Id.
  EXPECT_EQ(expect_trusted_headers_on_requests ? pani : "",
            get_headers(out, "P-Access-Network-Info")) << "PRACK";
  EXPECT_EQ(expect_trusted_headers_on_requests ? pvni : "",
            get_headers(out, "P-Visited-Network-Id")) << "PRACK";

  prack = pop_txdata();

  // ---------- Send 200 OK back X<-S
  SCOPED_TRACE("200 OK (PRACK)");
  inject_msg(respond_to_txdata(prack, 200, "", pvani), tpB);
  ASSERT_EQ(1, txdata_count());

  // OK goes back C<-X
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpA->expect_target(current_txdata(), true);
  msg.convert_routeset(out);
  msg._cseq++;

  // Check P-Access-Network-Info and P-Visited-Network-Id.
  EXPECT_EQ(expect_trusted_headers_on_responses ? pani : "",
            get_headers(out, "P-Access-Network-Info")) << "200 OK (PRACK)";
  EXPECT_EQ(expect_trusted_headers_on_responses ? pvni : "",
            get_headers(out, "P-Visited-Network-Id")) << "200 OK (PRACK)";

  free_txdata();

  // ---------- Send 200 OK back X<-S
  SCOPED_TRACE("200 OK (INVITE)");
  inject_msg(respond_to_txdata(invite, 200, "", pvani), tpB);
  ASSERT_EQ(1, txdata_count());

  // OK goes back C<-X
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpA->expect_target(current_txdata(), true);
  msg.convert_routeset(out);
  msg._cseq++;

  // Check P-Access-Network-Info and P-Visited-Network-Id.
  EXPECT_EQ(expect_trusted_headers_on_responses ? pani : "",
            get_headers(out, "P-Access-Network-Info")) << "200 OK (INVITE)";
  EXPECT_EQ(expect_trusted_headers_on_responses ? pvni : "",
            get_headers(out, "P-Visited-Network-Id")) << "200 OK (INVITE)";

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

  // Check P-Access-Network-Info and P-Visited-Network-Id.
  EXPECT_EQ(expect_trusted_headers_on_requests ? pani : "",
            get_headers(out, "P-Access-Network-Info")) << "ACK";
  EXPECT_EQ(expect_trusted_headers_on_requests ? pvni : "",
            get_headers(out, "P-Visited-Network-Id")) << "ACK";

  free_txdata();

  // ---------- Send a retransmission of that 200 OK back X<-S.  Should be processed statelessly.
  SCOPED_TRACE("200 OK (INVITE) (rexmt)");
  inject_msg(respond_to_txdata(invite, 200, "", pvani), tpB);
  pjsip_tx_data_dec_ref(invite);
  invite = NULL;
  ASSERT_EQ(1, txdata_count());

  // OK goes back C<-X
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpA->expect_target(current_txdata(), true);
  msg.convert_routeset(out);
  msg._cseq++;

  // Check P-Access-Network-Info and P-Visited-Network-Id. These will always be stripped,
  // because we handle these retransmissions statelessly and hence don't have any info on
  // trust boundary handling.
  EXPECT_EQ("", get_headers(out, "P-Access-Network-Info")) << "200 OK (INVITE) (rexmt)";
  EXPECT_EQ("", get_headers(out, "P-Visited-Network-Id")) << "200 OK (INVITE) (rexmt)";

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

  // Check P-Access-Network-Info and P-Visited-Network-Id.
  EXPECT_EQ(expect_trusted_headers_on_requests ? pani : "",
            get_headers(out, "P-Access-Network-Info")) << "BYE";
  EXPECT_EQ(expect_trusted_headers_on_requests ? pvni : "",
            get_headers(out, "P-Visited-Network-Id")) << "BYE";

  // ---------- Send a reply to that X<-S
  SCOPED_TRACE("200 OK (BYE)");
  inject_msg(respond_to_current_txdata(200, "", pvani), tpB);
  poll();
  ASSERT_EQ(1, txdata_count());

  // Reply passed on C<-X
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpA->expect_target(current_txdata(), true);

  // Check P-Access-Network-Info and P-Visited-Network-Id.
  EXPECT_EQ(expect_trusted_headers_on_responses ? pani : "",
            get_headers(out, "P-Access-Network-Info")) << "200 OK (BYE)";
  EXPECT_EQ(expect_trusted_headers_on_responses ? pvni : "",
            get_headers(out, "P-Visited-Network-Id")) << "200 OK (BYE)";

  free_txdata();

  // ---------- Send INVITE C->X (this is an attempt to establish a second dialog)
  SCOPED_TRACE("INVITE (#2)");
  msg._method = "INVITE";
  msg._route = route;
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

    // Don't bother testing P-Access-Network-Info or P-Visited-Network-Id, because this is point-to-point.
    free_txdata();
  }

  // INVITE passed on X->S
  SCOPED_TRACE("INVITE (S#2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("INVITE").matches(out));
  tpB->expect_target(current_txdata(), tpBset);

  // Check P-Access-Network-Info and P-Visited-Network-Id.
  EXPECT_EQ(expect_trusted_headers_on_requests ? pani : "",
            get_headers(out, "P-Access-Network-Info")) << "INVITE (#2)";
  EXPECT_EQ(expect_trusted_headers_on_requests ? pvni : "",
            get_headers(out, "P-Visited-Network-Id")) << "INVITE (#2)";

  invite = pop_txdata();

  // ---------- Send 404 Not Found back X<-S
  SCOPED_TRACE("404 Not Found (INVITE #2)");
  inject_msg(respond_to_txdata(invite, 404, "", pvani), tpB);
  poll();
  ASSERT_EQ(2, txdata_count());

  // ACK autogenerated X->S
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("ACK").matches(out));
  tpB->expect_target(current_txdata(), tpBset);

  // Don't check P-Access-Network-Info or P-Visited-Network-Id, because it's point-to-point.

  free_txdata();

  // 404 goes back C<-X
  out = current_txdata()->msg;
  RespMatcher(404).matches(out);
  tpA->expect_target(current_txdata(), true);
  msg.convert_routeset(out);
  msg._cseq++;

  // Check P-Access-Network-Info and P-Visited-Network-Id.
  EXPECT_EQ(expect_trusted_headers_on_responses ? pani : "",
            get_headers(out, "P-Access-Network-Info")) << "404 Not Found (INVITE #2)";
  EXPECT_EQ(expect_trusted_headers_on_responses ? pvni : "",
            get_headers(out, "P-Visited-Network-Id")) << "404 Not Found (INVITE #2)";

  free_txdata();

  // ---------- Send ACK C->X
  SCOPED_TRACE("ACK (#2)");
  msg._method = "ACK";
  inject_msg(msg.get_request(), tpA);
  poll();
  ASSERT_EQ(0, txdata_count());
  // should be swallowed by core.
}

/// Register a client with the edge proxy, returning the flow token.
void StatefulEdgeProxyTest::doRegisterEdge(TransportFlow* xiTp,  //^ transport to register on
                                           string& xoToken, //^ out: token (parsed from Path)
                                           string& xoBareToken, //^ out: bare token (parsed from Path)
                                           int expires, //^ expiry period
                                           string response, //^ response string to be included in authorization header
                                           string integrity, //^ expected integrity marking in authorization header
                                           string extraRspHeaders, //^ extra headers to be included in response
                                           bool firstHop,  //^ is this the first hop? If not, there was a previous hop to get here.
                                           string supported, //^ Supported: header value, or empty if none
                                           bool expectPath, //^ do we expect a Path: response? If false, don't parse token
                                           string via) //^ addr:port to use for top Via, or empty for the real one from xiTp
{
  SCOPED_TRACE("");

  // Register a client with the edge proxy.
  Message msg;
  msg._method = "REGISTER";
  msg._to = msg._from;        // To header contains AoR in REGISTER requests.
  msg._first_hop = firstHop;
  msg._via = via.empty() ? xiTp->to_string(false) : via;
  msg._extra = "Contact: sip:wuntootreefower@";
  msg._extra.append(xiTp->to_string(true)).append(";ob;expires=").append(to_string<int>(expires, std::dec)).append(";+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"");
  if (!response.empty())
  {
    msg._extra.append("\r\nAuthorization: Digest username=\"6505551000@homedomain\", nonce=\"\", response=\"").append(response).append("\"");
  }
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
    string expect = "<";
    expect.append(msg._toscheme)
      .append(":.*@")
      .append(str_pj(stack_data.local_host))
      .append(":")
      .append(boost::lexical_cast<string>(stack_data.pcscf_trusted_port))
      .append(";transport=TCP")
      .append(";lr")
      .append(firstHop ? ";ob>" : ">");
    EXPECT_THAT(xoToken, MatchesRegex(expect));

    // Get the bare token as just the user part of the URI.
    xoBareToken = xoToken.substr(xoToken.find(':')+1);
    xoBareToken = xoBareToken.substr(0, xoBareToken.find('@'));
  }

  // Check integrity=? marking.
  if (!integrity.empty())
  {
    actual = get_headers(tdata->msg, "Authorization");
    EXPECT_THAT(actual, MatchesRegex("^Authorization: Digest .*"));
    EXPECT_THAT(actual, MatchesRegex(".*username=\"6505551000@homedomain\".*"));
    EXPECT_THAT(actual, MatchesRegex(".*response=\"" + response + "\".*"));
    EXPECT_THAT(actual, MatchesRegex(".*integrity-protected=" + integrity + ".*"));
  }

  // Check P-Charging headers are added correctly
  actual = get_headers(tdata->msg, "P-Charging-Function-Addresses");
  EXPECT_EQ("P-Charging-Function-Addresses: ccf=cdfdomain", actual);
  actual = get_headers(tdata->msg, "P-Visited-Network-ID");
  EXPECT_EQ("P-Visited-Network-ID: homedomain", actual);
  actual = get_headers(tdata->msg, "P-Charging-Vector");
  std::string call_id = get_headers(tdata->msg, "Call-ID");
  call_id.erase(std::remove(call_id.begin(), call_id.end(), '@'), call_id.end());
  call_id.erase(std::remove(call_id.begin(), call_id.end(), '"'), call_id.end());
  EXPECT_EQ("P-Charging-Vector: icid-value=\"" + call_id.substr(9) + "\";icid-generated-at=127.0.0.1", actual);

  // Goes to the right place.
  expect_target("TCP", "10.6.6.8", stack_data.pcscf_trusted_port, tdata);

  // Pass response back through.
  string r;
  if (!xoToken.empty())
  {
    r = "Path: ";
    r.append(xoToken).append("\n");
  }
  // Must include a contact header otherwise the flow won't be marked as authenticated.
  r.append("Contact: sip:wuntootreefower@").append(xiTp->to_string(true)).append(";ob;expires=").append(to_string<int>(expires, std::dec)).append(";+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"");

  // Add any extra response headers.
  r.append(extraRspHeaders);

  // Pass the response back.
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
  msg._route = "Route: ";
  msg._route.append(token);
  msg._requri = "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob";
  inject_msg(msg.get_request());
  return msg;
}

TEST_F(StatefulEdgeProxyTest, TestEdgeRegisterQuiesced)
{
  SCOPED_TRACE("");

  _quiescing_manager.quiesce();

  // Register client.
  TransportFlow* xiTp = new TransportFlow(TransportFlow::Protocol::TCP,
                                          stack_data.pcscf_untrusted_port,
                                          "1.2.3.4",
                                          49152);
  // Register a client with the edge proxy.
  Message msg;
  int expires = 300;
  msg._method = "REGISTER";
  msg._to = msg._from;        // To header contains AoR in REGISTER requests.
  msg._first_hop = true;
  msg._via = xiTp->to_string(false);
  msg._extra = "Contact: sip:wuntootreefower@";
  msg._extra.append(xiTp->to_string(true)).append(";ob;expires=").append(to_string<int>(expires, std::dec)).append(";+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"");
  inject_msg(msg.get_request(), xiTp);
  ASSERT_EQ(1, txdata_count());

  // Check that we get a 305 Use Proxy response when sending a
  // REGISTER on a flow with no dialogs when we are quiesced.
  RespMatcher r1(305);
  pjsip_tx_data* tdata = current_txdata();
  r1.matches(tdata->msg);

  _quiescing_manager.unquiesce();

  delete xiTp;
}

TEST_F(StatefulEdgeProxyTest, TestEdgeRegisterFWTCP)
{
  SCOPED_TRACE("");

  // Register client.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.pcscf_untrusted_port,
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
                                        stack_data.pcscf_untrusted_port,
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

TEST_F(StatefulEdgeProxyTest, TestPreferredAssertedIdentities)
{
  SCOPED_TRACE("");
  Message msg;
  pjsip_tx_data* tdata;
  pjsip_msg* out;
  string actual;

  // Register client.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.pcscf_untrusted_port,
                                        "1.2.3.4",
                                        49150);

  // Register a client, with four associated URIs.
  SCOPED_TRACE("");
  string token;
  string baretoken;
  doRegisterEdge(tp, token, baretoken, 300, "1234123412341234", "ip-assoc-pending",
                 "\nP-Associated-URI: <sip:6505551000@homedomain>, <sip:+16505551000@homedomain>, \"Fred\" <sip:1000@homedomain>\nP-Associated-URI: <tel:+16505551000>");

  // Send an INVITE from the client specifying one of the valid identities in
  // a P-Preferred-Identity header.
  SCOPED_TRACE("");
  msg._method = "INVITE";
  msg._requri = "sip:6505551234@homedomain:5061;transport=tcp;ob";
  msg._to = "6505551234";
  msg._from = "6505551000";
  msg._extra = "Route: ";
  msg._extra.append(token);
  msg._extra.append("\r\nP-Preferred-Identity: <sip:+16505551000@homedomain>");
  msg._extra.append("\r\nSupported: timer");
  inject_msg(msg.get_request(), tp);

  // Check that the message is forwarded as expected.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();

  // Is the right kind and method.
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Goes to the right place (upstream).
  expect_target("TCP", "10.6.6.8", stack_data.pcscf_trusted_port, tdata);

  // Route header refers to upstream and indicates it is an originating request.
  actual = get_headers(tdata->msg, "Route");
  EXPECT_EQ("Route: <sip:" + _edge_upstream_proxy + ":" + to_string<int>(stack_data.pcscf_trusted_port, std::dec) + ";transport=TCP;lr;orig>", actual);

  // Edge proxy must double record route for transition to trust zone.
  actual = get_headers(tdata->msg, "Record-Route");
  EXPECT_EQ("Record-Route: <sip:127.0.0.1:" + to_string<int>(stack_data.pcscf_trusted_port, std::dec) + ";transport=TCP;lr>\r\n" +
            "Record-Route: <sip:" + baretoken + "@127.0.0.1:" + to_string<int>(stack_data.pcscf_untrusted_port, std::dec) + ";transport=TCP;lr>", actual);

  // P-Preferred-Identity header has been converted to P-Asserted-Identity.
  actual = get_headers(tdata->msg, "P-Asserted-Identity");
  EXPECT_EQ("P-Asserted-Identity: <sip:+16505551000@homedomain>", actual);

  // Send 200 OK to close our transaction.
  inject_msg(respond_to_current_txdata(200));
  poll();
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  EXPECT_NE(get_headers(out, "Session-Expires"), "");
  free_txdata();

  // Send an INVITE from the client with no P-Preferred-Identity header.
  SCOPED_TRACE("");
  msg._method = "INVITE";
  msg._requri = "sip:6505551234@homedomain:5061;transport=tcp;ob";
  msg._to = "6505551234";
  msg._from = "6505551000";
  msg._extra = "Route: ";
  msg._extra.append(token);
  inject_msg(msg.get_request(), tp);

  // Check that the message is forwarded as expected.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();

  // Is the right kind and method.
  r1.matches(tdata->msg);

  // Goes to the right place (upstream).
  expect_target("TCP", "10.6.6.8", stack_data.pcscf_trusted_port, tdata);

  // Route header refers to upstream and indicates it is an originating request.
  actual = get_headers(tdata->msg, "Route");
  EXPECT_EQ("Route: <sip:" + _edge_upstream_proxy + ":" + to_string<int>(stack_data.pcscf_trusted_port, std::dec) + ";transport=TCP;lr;orig>", actual);

  // Edge proxy must double record route for transition to trust zone.
  actual = get_headers(tdata->msg, "Record-Route");
  EXPECT_EQ("Record-Route: <sip:127.0.0.1:" + to_string<int>(stack_data.pcscf_trusted_port, std::dec) + ";transport=TCP;lr>\r\n" +
            "Record-Route: <sip:" + baretoken + "@127.0.0.1:" + to_string<int>(stack_data.pcscf_untrusted_port, std::dec) + ";transport=TCP;lr>", actual);

  // A P-Asserted-Identity header has been added with the default identity.
  actual = get_headers(tdata->msg, "P-Asserted-Identity");
  EXPECT_EQ("P-Asserted-Identity: <sip:6505551000@homedomain>", actual);

  // Send 200 OK to close our transaction.
  inject_msg(respond_to_current_txdata(200));
  poll();
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  free_txdata();

  // Send an INVITE from the client with two P-Preferred-Identitys.
  SCOPED_TRACE("");
  msg._method = "INVITE";
  msg._requri = "sip:6505551234@homedomain:5061;transport=tcp;ob";
  msg._to = "6505551234";
  msg._from = "6505551000";
  msg._extra = "Route: ";
  msg._extra.append(token);
  msg._extra.append("\r\nP-Preferred-Identity: <sip:+16505551000@homedomain>, <tel:+16505551000>");
  inject_msg(msg.get_request(), tp);

  // Check that the message is forwarded as expected.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();

  // Is the right kind and method.
  r1.matches(tdata->msg);

  // Goes to the right place (upstream).
  expect_target("TCP", "10.6.6.8", stack_data.pcscf_trusted_port, tdata);

  // Route header refers to upstream and indicates it is an originating request.
  actual = get_headers(tdata->msg, "Route");
  EXPECT_EQ("Route: <sip:" + _edge_upstream_proxy + ":" + to_string<int>(stack_data.pcscf_trusted_port, std::dec) + ";transport=TCP;lr;orig>", actual);

  // Edge proxy must double record route for transition to trust zone.
  actual = get_headers(tdata->msg, "Record-Route");
  EXPECT_EQ("Record-Route: <sip:127.0.0.1:" + to_string<int>(stack_data.pcscf_trusted_port, std::dec) + ";transport=TCP;lr>\r\n" +
            "Record-Route: <sip:" + baretoken + "@127.0.0.1:" + to_string<int>(stack_data.pcscf_untrusted_port, std::dec) + ";transport=TCP;lr>", actual);

  // P-Asserted-Identity headers have been added with both identities.
  actual = get_headers(tdata->msg, "P-Asserted-Identity");
  EXPECT_EQ("P-Asserted-Identity: <sip:+16505551000@homedomain>\r\nP-Asserted-Identity: <tel:+16505551000>", actual);

  // Send 200 OK to close our transaction.
  inject_msg(respond_to_current_txdata(200));
  poll();
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  free_txdata();

  // Send an INVITE from the client with an unauthorized P-Preferred-Identity.
  SCOPED_TRACE("");
  msg._method = "INVITE";
  msg._requri = "sip:6505551234@homedomain:5061;transport=tcp;ob";
  msg._to = "6505551234";
  msg._from = "6505551000";
  msg._extra = "Route: ";
  msg._extra.append(token);
  msg._extra.append("\r\nP-Preferred-Identity: <sip:+16505551001@homedomain>");
  inject_msg(msg.get_request(), tp);

  // Is the right kind and method.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(403).matches(tdata->msg);

  // Goes to the right place (back to the injector)
  tp->expect_target(tdata);
  free_txdata();

  // Send an INVITE from the client with two sip: P-Preferred-Identitys.
  SCOPED_TRACE("");
  msg._method = "INVITE";
  msg._requri = "sip:6505551234@homedomain:5061;transport=tcp;ob";
  msg._to = "6505551234";
  msg._from = "6505551000";
  msg._extra = "Route: ";
  msg._extra.append(token);
  msg._extra.append("\r\nP-Preferred-Identity: <sip:+16505551000@homedomain>, <sip:6505551000@homedomain>");
  inject_msg(msg.get_request(), tp);

  // Is the right kind and method.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(403).matches(tdata->msg);

  // Goes to the right place (back to the injector)
  tp->expect_target(tdata);
  free_txdata();

  // Refresh the registration.
  SCOPED_TRACE("");
  doRegisterEdge(tp, token, baretoken, 300, "", "ip-assoc-yes",
                 "\nP-Associated-URI: <sip:6505551000@homedomain>, <sip:+16505551000@homedomain>, \"Fred\" <sip:1000@homedomain>\nP-Associated-URI: <tel:+16505551000>");

  // Check that authorization is still in place by sending an INVITE from the client with no P-Preferred-Identity header.
  SCOPED_TRACE("");
  msg._method = "INVITE";
  msg._requri = "sip:6505551234@homedomain:5061;transport=tcp;ob";
  msg._to = "6505551234";
  msg._from = "6505551000";
  msg._extra = "Route: ";
  msg._extra.append(token);
  inject_msg(msg.get_request(), tp);

  // Check that the message is forwarded as expected.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();

  // Is the right kind and method.
  r1.matches(tdata->msg);

  // Goes to the right place (upstream).
  expect_target("TCP", "10.6.6.8", stack_data.pcscf_trusted_port, tdata);

  // Route header refers to upstream and indicates it is an originating request.
  actual = get_headers(tdata->msg, "Route");
  EXPECT_EQ("Route: <sip:" + _edge_upstream_proxy + ":" + to_string<int>(stack_data.pcscf_trusted_port, std::dec) + ";transport=TCP;lr;orig>", actual);

  // Edge proxy must double record route for transition to trust zone.
  actual = get_headers(tdata->msg, "Record-Route");
  EXPECT_EQ("Record-Route: <sip:127.0.0.1:" + to_string<int>(stack_data.pcscf_trusted_port, std::dec) + ";transport=TCP;lr>\r\n" +
            "Record-Route: <sip:" + baretoken + "@127.0.0.1:" + to_string<int>(stack_data.pcscf_untrusted_port, std::dec) + ";transport=TCP;lr>", actual);

  // A P-Asserted-Identity header has been added with the default identity.
  actual = get_headers(tdata->msg, "P-Asserted-Identity");
  EXPECT_EQ("P-Asserted-Identity: <sip:6505551000@homedomain>", actual);

  // Send 200 OK to close our transaction.
  inject_msg(respond_to_current_txdata(200));
  poll();
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  free_txdata();

  // Expire the registration.
  SCOPED_TRACE("");
  doRegisterEdge(tp, token, baretoken, 0, "", "ip-assoc-yes",
                 "\nP-Associated-URI: <sip:6505551000@homedomain>, <sip:+16505551000@homedomain>, \"Fred\" <sip:1000@homedomain>\nP-Associated-URI: <tel:+16505551000>");

  // Check that authorization is gone by sending an INVITE from the client with no P-Preferred-Identity header.
  SCOPED_TRACE("");
  msg._method = "INVITE";
  msg._requri = "sip:6505551234@homedomain:5061;transport=tcp;ob";
  msg._to = "6505551234";
  msg._from = "6505551000";
  msg._extra = "Route: ";
  msg._extra.append(token);
  inject_msg(msg.get_request(), tp);

  // Is the right kind and method.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(403).matches(tdata->msg);

  // Goes to the right place (back to the injector)
  tp->expect_target(tdata);
  free_txdata();

  delete tp;
}

TEST_F(StatefulEdgeProxyTest, TestEdgeDeregister)
{
  SCOPED_TRACE("");

  //Deregister client which hasn't registered yet
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.pcscf_untrusted_port,
                                        "1.2.3.4",
                                        49152);
  string token;
  string baretoken;
  doRegisterEdge(tp, token, baretoken, 0);

  delete tp;
}

TEST_F(StatefulEdgeProxyTest, TestEdgeCorruptToken)
{
  SCOPED_TRACE("");

  // Register client.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.pcscf_untrusted_port,
                                        "1.2.3.4",
                                        49152);
  string token;
  string baretoken;
  doRegisterEdge(tp, token, baretoken);

  // For sanity, check the real token works as expected.
  SCOPED_TRACE("Works as expected");
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
  // 'Z'++ is '[', which PJSIP rejects as invalid when used in a From
  // header, so use 'Z'-- instead. Similarly for 'z'.
  if ((tampered[6] != 'Z') && (tampered[6] != 'z'))
  {
    tampered[6]++;
  }
  else
  {
    tampered[6]--;
  }
  tokens.push_back(tampered);

  // Not base 64 (this actually gets decoded as if it is, so doesn't
  // exercise a different path, but we leave it in anyway).
  tokens.push_back("sip:Not&valid&base64)@127.0.0.1:5060;lr");

  // Too short
  string tooshort(token);
  tooshort.erase(6,4);
  tokens.push_back(tooshort);

  // Too short
  string toolong(token);
  toolong.insert(6, "AAAA");
  tokens.push_back(toolong);

  SCOPED_TRACE("Corrupt tokens");

  for (list<string>::iterator iter = tokens.begin(); iter != tokens.end(); ++iter)
  {
    SCOPED_TRACE(*iter);

    doInviteEdge(*iter);
    ASSERT_EQ(1, txdata_count());

    // Is the right kind and method.
    RespMatcher r2(430, "", "Flow failed");
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

  SCOPED_TRACE("New transport");

  doInviteEdge(token);
  ASSERT_EQ(1, txdata_count());

  // Is the right kind and method.
  RespMatcher r2(430, "", "Flow failed");
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
                         stack_data.pcscf_untrusted_port,
                         "10.83.18.38",
                         49152);
  doRegisterEdge(tp, token, baretoken, 300, "", "", "", true, "outbound, path", true, "");
  delete tp;

  // Client 2: Declares outbound support, behind NAT. Should get path.
  tp = new TransportFlow(TransportFlow::Protocol::TCP,
                         stack_data.pcscf_untrusted_port,
                         "10.83.18.39",
                         49152);
  doRegisterEdge(tp, token, baretoken, 300, "", "", "", true, "outbound, path", true, "10.22.3.4:9999");
  delete tp;

  // Client 3: Doesn't declare outbound support (no attr), not behind NAT. Shouldn't get path.
  // RETIRED - since sto131 we add Path to all REGISTERs from clients outside trusted zone.
  //tp = new TransportFlow("TCP", "10.83.18.40", 36530);
  //doRegisterEdge(tp, token, baretoken, 300, "no", "", true, "path", false, "");
  //delete tp;

  // Client 4: Doesn't declare outbound support (no attr), behind NAT. Should get path anyway.
  tp = new TransportFlow(TransportFlow::Protocol::TCP,
                         stack_data.pcscf_untrusted_port,
                         "10.83.18.41",
                         49152);
  doRegisterEdge(tp, token, baretoken, 300, "", "", "", true, "path", true, "10.22.3.5:8888");
  delete tp;

  // Client 5: Doesn't declare outbound support (no header), not behind NAT. Shouldn't get path.
  // RETIRED - since sto131 we add Path to all REGISTERs from clients outside trusted zone.
  //tp = new TransportFlow("TCP", "10.83.18.40", 36530);
  //doRegisterEdge(tp, token, baretoken, 300, "no", "", true, "", false, "");
  //delete tp;

  // Client 6: Doesn't declare outbound support (no header), behind NAT. Should get path anyway.
  tp = new TransportFlow(TransportFlow::Protocol::TCP,
                         stack_data.pcscf_untrusted_port,
                         "10.83.18.41",
                         49152);
  doRegisterEdge(tp, token, baretoken, 300, "", "", "", true, "", true, "10.22.3.5:8888");
  delete tp;
}

TEST_F(StatefulEdgeProxyTest, TestEdgeFirstHop)
{
  SCOPED_TRACE("");

  // Register client.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP, stack_data.pcscf_untrusted_port, "10.83.18.38", 36530);
  string token;
  string baretoken;
  doRegisterEdge(tp, token, baretoken, 300, "", "", "", true);

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
  // Include a parameter in the From URI to check that this is correctly stripped
  // out for authentication checks.
  Message msg2;
  msg2._method = "INVITE";
  msg2._fromdomain += ";user=phone";
  msg2._first_hop = true;
  inject_msg(msg2.get_request(), tp);

  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();

  // Is the right kind and method.
  ReqMatcher r3("INVITE");
  r3.matches(tdata->msg);

  // Goes to the right place (upstream).
  expect_target("TCP", "10.6.6.8", stack_data.pcscf_trusted_port, tdata);

  // Record-Route is added so it will come back the right way.
  actual = get_headers(tdata->msg, "Record-Route");
  EXPECT_THAT(actual, HasSubstr(baretoken));
  EXPECT_THAT(actual, HasSubstr(";lr"));
  EXPECT_THAT(actual, Not(HasSubstr(";ob")));

  // Boring route header.
  actual = get_headers(tdata->msg, "Route");
  EXPECT_THAT(actual, HasSubstr("sip:upstreamnode:" + to_string<int>(stack_data.pcscf_trusted_port, std::dec) + ";transport=TCP"));

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
  TransportFlow tp(TransportFlow::Protocol::TCP, stack_data.pcscf_untrusted_port, "10.83.18.38", 36530);
  string token;
  string baretoken;
  doRegisterEdge(&tp, token, baretoken, 300, "", "", "", true);

  // INVITE from Sprout (or elsewhere) via bono to client
  Message msg;
  msg._todomain = "10.83.18.38:36530;transport=tcp";
  msg._via = "10.99.88.11:12345";
  string route = string("Route: ").append(token);

  // Strip PANI outbound - leaving the trust zone.
  doTestHeaders(_tp_default, false, &tp, true, msg, route, false, false, true, false, false);
}

// Test flows into Bono (P-CSCF), first hop, in particular for header stripping.
TEST_F(StatefulEdgeProxyTest, TestMainlineHeadersBonoFirstIn)
{
  SCOPED_TRACE("");

  // Register client.
  TransportFlow tp(TransportFlow::Protocol::TCP, stack_data.pcscf_untrusted_port, "10.83.18.37", 36531);
  string token;
  string baretoken;
  doRegisterEdge(&tp, token, baretoken, 300, "", "", "", true);

  // INVITE from client via bono to Sprout, first hop
  Message msg;
  msg._first_hop = true;
  msg._via = "10.83.18.37:36531;transport=tcp";

  // Strip PANI in outbound direction - leaving the trust zone.
  // This is originating; mark it so.
  doTestHeaders(&tp, true, _tp_default, false, msg, "", false, true, false, true, false);
}

// Test flows out of Bono (P-CSCF), not first hop, in particular for header stripping.
TEST_F(StatefulEdgeProxyTest, TestMainlineHeadersBonoProxyOut)
{
  SCOPED_TRACE("");

  // Register client.
  TransportFlow tp(TransportFlow::Protocol::TCP, stack_data.pcscf_untrusted_port, "10.83.18.38", 36530);
  string token;
  string baretoken;
  doRegisterEdge(&tp, token, baretoken);

  // INVITE from Sprout (or elsewhere) via bono to client
  Message msg;
  msg._todomain = "10.83.18.38:36530;transport=tcp";
  msg._via = "10.99.88.11:12345";
  string route = string("Route: ").append(token);

  // Don't care which transport we come back on, as long as it goes to
  // the right address.
  // Strip PANI outbound - leaving the trust zone.
  doTestHeaders(_tp_default, false, &tp, false, msg, route, false, false, true, false, false);
}

// Test flows into Bono (P-CSCF), not first hop, in particular for header stripping.
TEST_F(StatefulEdgeProxyTest, TestMainlineHeadersBonoProxyIn)
{
  SCOPED_TRACE("");

  // Register client.
  TransportFlow tp(TransportFlow::Protocol::TCP, stack_data.pcscf_untrusted_port, "10.83.18.37", 36531);
  string token;
  string baretoken;
  doRegisterEdge(&tp, token, baretoken);

  // INVITE from client via bono to Sprout, not first hop
  Message msg;
  msg._via = "10.83.18.37:36531;transport=tcp";
  // Don't care which transport we come back on, as long as it goes to
  // the right address.
  // Strip PANI in outbound direction - leaving the trust zone.
  // This is originating; mark it so.
  doTestHeaders(&tp, false, _tp_default, false, msg, "", false, true, false, true, false);
}

// Test that Bono routes requests appropriately if the RequestURI contains a
// loopback address.
TEST_F(StatefulEdgeProxyTest, TestLoopbackReqUri)
{
  SCOPED_TRACE("");

  // Register a client.
  TransportFlow tp(TransportFlow::Protocol::TCP, stack_data.pcscf_untrusted_port, "10.83.18.37", 36531);
  string token;
  string baretoken;
  doRegisterEdge(&tp, token, baretoken);

  // Send an ACK from the client with four route headers - client=>bono=>bono=>client,
  // with loopback address in RequestURI.
  SCOPED_TRACE("");
  Message msg;
  msg._method = "ACK";
  msg._requri = "sip:6505551234@127.0.0.1;transport=tcp";
  msg._to = "6505551234";
  msg._from = "6505551000";
  msg._route = "Route: <sip:" + baretoken + "@127.0.0.1:" + to_string<int>(stack_data.pcscf_untrusted_port, std::dec) + ";transport=TCP;lr>\r\n";
  msg._route += "Route: <sip:bono1.homedomain:" + to_string<int>(stack_data.pcscf_trusted_port, std::dec) + ";transport=TCP;lr>\r\n";
  msg._route += "Route: <sip:bono1.homedomain:" + to_string<int>(stack_data.pcscf_trusted_port, std::dec) + ";transport=TCP;lr>\r\n";
  msg._route += "Route: <sip:123456@127.0.0.1:" + to_string<int>(stack_data.pcscf_untrusted_port, std::dec) + ";transport=TCP;lr>";
  msg._in_dialog = true;
  inject_msg(msg.get_request(), &tp);

  // Check that the message is forwarded as expected.
  ASSERT_EQ(1, txdata_count());
  pjsip_tx_data* tdata = current_txdata();

  // Is the right kind and method.
  ReqMatcher r1("ACK");
  r1.matches(tdata->msg);

  // Goes to the right place (bono1, which is mapped to 10.6.6.200).
  expect_target("TCP", "10.6.6.200", stack_data.pcscf_trusted_port, tdata);

  free_txdata();
}

// Test that Bono routes all initial requests to Sprout.
TEST_F(StatefulEdgeProxyTest, TestAlwaysRouteUpstream)
{
  SCOPED_TRACE("");

  // Register a client.
  TransportFlow tp(TransportFlow::Protocol::TCP, stack_data.pcscf_untrusted_port, "10.83.18.37", 36531);
  string token;
  string baretoken;
  doRegisterEdge(&tp, token, baretoken);

  // Send a MESSAGE from the client. Use a different domain in the Request-URI.
  SCOPED_TRACE("");
  Message msg;
  msg._method = "MESSAGE";
  msg._requri = "sip:1234@someotherdomain";
  msg._to = "6505551234";
  msg._from = "6505551000";
  msg._in_dialog = false;
  inject_msg(msg.get_request(), &tp);

  // Check that the message is forwarded as expected.
  ASSERT_EQ(1, txdata_count());
  pjsip_tx_data* tdata = current_txdata();

  // Is the right kind and method.
  ReqMatcher r1("MESSAGE");
  r1.matches(tdata->msg);

  // Goes to the configured upstream proxy ("upstreamnode", "10.6.6.8")
  expect_target("TCP", "10.6.6.8", stack_data.pcscf_trusted_port, tdata);

  free_txdata();
}

// Test that Bono routes all initial requests to Sprout.
TEST_F(StatefulEdgeProxyTest, TestAlwaysRouteUpstreamTel)
{
  SCOPED_TRACE("");

  // Register a client.
  TransportFlow tp(TransportFlow::Protocol::TCP, stack_data.pcscf_untrusted_port, "10.83.18.37", 36531);
  string token;
  string baretoken;
  doRegisterEdge(&tp, token, baretoken);

  // Send a MESSAGE from the client. Use a tel: URI in the Request-URI
  // to ensure that no SIP routing interferes.
  SCOPED_TRACE("");
  Message msg;
  msg._method = "MESSAGE";
  msg._requri = "tel:1234";
  msg._to = "6505551234";
  msg._from = "6505551000";
  msg._in_dialog = false;
  inject_msg(msg.get_request(), &tp);

  // Check that the message is forwarded as expected.
  ASSERT_EQ(1, txdata_count());
  pjsip_tx_data* tdata = current_txdata();

  // Is the right kind and method.
  ReqMatcher r1("MESSAGE");
  r1.matches(tdata->msg);

  // Goes to the configured upstream proxy ("upstreamnode", "10.6.6.8")
  expect_target("TCP", "10.6.6.8", stack_data.pcscf_trusted_port, tdata);

  free_txdata();
}

// Test flows into Bono (P-CSCF), first hop with Route header.
TEST_F(StatefulEdgeProxyTest, TestMainlineBonoRouteIn)
{
  SCOPED_TRACE("");

  // Register client.
  TransportFlow tp(TransportFlow::Protocol::TCP, stack_data.pcscf_untrusted_port, "10.83.18.37", 36531);
  string token;
  string baretoken;
  doRegisterEdge(&tp, token, baretoken, 300, "", "", "", true);

  Message msg;
  msg._first_hop = true;
  msg._via = "10.83.18.37:36531;transport=tcp";
  msg._extra = "Route: <sip:upstreamnode;lr;orig>";
  list<HeaderMatcher> hdrs;
  // Strip PANI in outbound direction - leaving the trust zone.
  // This is originating; mark it so.
  doTestHeaders(&tp, true, _tp_default, false, msg, "", false, true, false, true, false);
}

// Test flows into Bono (P-CSCF) of emergency register.
TEST_F(StatefulEdgeProxyTest, TestBonoEmergencyRejectRegister)
{
  SCOPED_TRACE("");

  TransportFlow tp(TransportFlow::Protocol::TCP, stack_data.pcscf_untrusted_port, "10.83.18.37", 36531);

  // Attempt to emergency register a client with the edge proxy.
  Message msg;
  msg._method = "REGISTER";
  msg._to = msg._from;
  msg._via = tp.to_string(false);
  msg._extra = "Contact: <sip:wuntootreefower@";
  msg._extra.append(tp.to_string(true)).append(";sos;ob>;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"");

  inject_msg(msg.get_request(), &tp);

  // REGISTER rejected with a 503
  ASSERT_EQ(1, txdata_count());
  pjsip_tx_data* tdata = current_txdata();
  RespMatcher(503).matches(tdata->msg);
  free_txdata();
}

// Test flows into Bono (P-CSCF) of emergency register.
TEST_F(StatefulEdgeProxyAcceptRegisterTest, TestBonoEmergencyAcceptRegister)
{
  SCOPED_TRACE("");

  TransportFlow tp(TransportFlow::Protocol::TCP, stack_data.pcscf_untrusted_port, "10.83.18.37", 36531);

  // Attempt to emergency register a client with the edge proxy.
  Message msg;
  msg._method = "REGISTER";
  msg._to = msg._from;
  msg._via = tp.to_string(false);
  msg._extra = "Contact: <sip:wuntootreefower@";
  msg._extra.append(tp.to_string(true)).append(";sos;ob>;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"");

  inject_msg(msg.get_request(), &tp);

  // REGISTER rejected with a 503
  ASSERT_EQ(1, txdata_count());


  // Check that we generate a flow token and pass it through. We don't
  // check the value of the flow token (it's opaque) - just its
  // effect.

  // Is the right kind and method.
  ReqMatcher r1("REGISTER");
  pjsip_tx_data* tdata = current_txdata();
  r1.matches(tdata->msg);

  free_txdata();
}

// Test flows into Bono (P-CSCF) of non-registering PBX.
TEST_F(StatefulEdgeProxyPBXTest, AcceptInvite)
{
  SCOPED_TRACE("");

  TransportFlow tp(TransportFlow::Protocol::TCP, stack_data.pcscf_untrusted_port, "1.2.3.4", 36531);
  pjsip_msg* out;

  Message msg;
  msg._method = "INVITE";

  inject_msg(msg.get_request(), &tp);
  poll();
  ASSERT_EQ(1, txdata_count());

  // INVITE should be passed to Sprout despite the lack of a REGISTER
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("INVITE").matches(out));

  // Goes to the configured service route ("scscfnode", "10.6.6.8", port 5054)
  expect_target("TCP", "10.6.6.8", 5054, current_txdata());

  // Check that a Proxy-Authorization header gets added.
  std::string actual = get_headers(out, "Proxy-Authorization");
  EXPECT_THAT(actual, MatchesRegex("^Proxy-Authorization: Digest .*"));
  EXPECT_THAT(actual, MatchesRegex(".*response=\"\".*"));
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
  TransportFlow tp(TransportFlow::Protocol::TCP, stack_data.pcscf_untrusted_port, "10.7.7.10", 36530);

  // INVITE from the "trusted" (but outside the trust zone) trunk to Sprout.
  // Stripped in both directions.
  // This cannot be originating, because it's IBCF! It's a foreign domain.
  doTestHeaders(&tp, true, _tp_default, false, msg, "", false, false, false, false, false);
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
  TransportFlow tp(TransportFlow::Protocol::TCP, stack_data.pcscf_untrusted_port, "10.7.7.10", 36530);

  // INVITE from Sprout to the "trusted" (but outside the trust zone) trunk.
  // Stripped in both directions.
  doTestHeaders(_tp_default, false, &tp, true, msg, "", false, false, false, false, false);
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
  tp = new TransportFlow(TransportFlow::Protocol::TCP, stack_data.pcscf_untrusted_port, "10.7.7.10", 36530);

  // Send an INVITE from the trusted host.
  msg._unique++;
  inject_msg(msg.get_request(), tp);

  // Check it's the right kind and method, and goes to the right place.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  r1.matches(tdata->msg);
  expect_target("TCP", "10.6.6.8", stack_data.pcscf_trusted_port, tdata);  // to Sprout

  // Check there is no Authorization header added.
  actual = get_headers(tdata->msg, "Authorization");
  EXPECT_EQ("", actual);

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
  tp = new TransportFlow(TransportFlow::Protocol::TCP, stack_data.pcscf_untrusted_port, "10.7.7.11", 36533);

  // Send an INVITE from the trusted host.
  msg._unique++;
  inject_msg(msg.get_request(), tp);

  // Check it's the right kind and method, and goes to the right place.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  r1.matches(tdata->msg);
  expect_target("TCP", "10.6.6.8", stack_data.pcscf_trusted_port, tdata);  // to Sprout

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
  msg._to = "127.0.0.1";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._todomain = "homedomain";
  msg._requri = "sip:6505551000@homedomain";
  msg._from = "+12125551212";
  msg._fromdomain = "foreign-domain.example.com";

  TransportFlow* tp;
  pjsip_tx_data* tdata;
  string actual;

  // Get a connection from the other trusted host.
  tp = new TransportFlow(TransportFlow::Protocol::TCP, stack_data.pcscf_untrusted_port, "10.7.7.11", 36533);

  // Send an INVITE from the trusted host.
  msg._unique++;
  inject_msg(msg.get_request(), tp);

  // Check it's the right kind and method, and goes to the right place.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher r1(403);
  r1.matches(tdata->msg);
  tp->expect_target(tdata, true);  // to source

  free_txdata();
  delete tp;
}

// Check that ;orig on P-CSCF trunk is legal and gets passed through
// on the upstream Route header.
TEST_F(StatefulTrunkProxyTest, TestPcscfOrig)
{
  SCOPED_TRACE("");

  // Set up default message.
  Message msg;
  msg._method = "INVITE";
  msg._to = "127.0.0.1";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._todomain = "homedomain";
  msg._requri = "sip:6505551000@homedomain";
  msg._from = "+12125551212";
  msg._fromdomain = "foreign-domain.example.com";

  TransportFlow* tp;
  pjsip_tx_data* tdata;
  string actual;

  // Get a connection from the trusted host.
  tp = new TransportFlow(TransportFlow::Protocol::TCP, stack_data.pcscf_trusted_port, "10.17.17.111", 36533);

  // Send an INVITE from the trusted host.
  msg._unique++;
  inject_msg(msg.get_request(), tp);

  // Check it's the right kind and method, and goes to the right place.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher r1("INVITE");
  r1.matches(tdata->msg);

  // Check that the orig parameter is copied onto the Route header
  // Bono passes upstream.
  actual = get_headers(tdata->msg, "Route");
  EXPECT_THAT(actual, testing::MatchesRegex(".*;orig.*"));

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
  string actual;

  // Get a connection from some other random (untrusted) host.
  tp = new TransportFlow(TransportFlow::Protocol::TCP, stack_data.pcscf_untrusted_port, "10.83.18.39", 36530);

  // Send the same INVITE from the random host.
  msg._unique++;
  inject_msg(msg.get_request(), tp);

  // Check it is rejected with a 403 Forbidden response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher r1(403);
  r1.matches(tdata->msg);
  tp->expect_target(tdata, true);  // to source

  free_txdata();
  delete tp;
}

TEST_F(StatefulEdgeProxyTest, TestSessionExpires)
{
  SCOPED_TRACE("");
  Message msg;
  pjsip_msg* out;
  string actual;

  // Register client.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.pcscf_untrusted_port,
                                        "1.2.3.4",
                                        49150);
  string token;
  string baretoken;
  doRegisterEdge(tp, token, baretoken, 300, "1234123412341234", "ip-assoc-pending");

  // Send an INVITE where the client supports session timers. This means that
  // if the server does not support timers, there should still be a
  // Session-Expires header on the response.
  //
  // Most of the session timer logic is tested in
  // `session_expires_helper_test.cpp`. This is just to check that Bono invokes
  // the logic correctly.
  SCOPED_TRACE("");
  msg._extra = "Route: ";
  msg._extra.append(token);
  msg._extra.append("\r\nSupported: timer");
  inject_msg(msg.get_request(), tp);

  // Check that the message is forwarded as expected.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  r1.matches(out);

  // Check the request has a Session-Expires.
  EXPECT_NE(get_headers(out, "Session-Expires"), "");

  // Send 200 OK to close our transaction.
  inject_msg(respond_to_current_txdata(200));
  poll();
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);

  // Check the response has a Session-Expires.
  EXPECT_NE(get_headers(out, "Session-Expires"), "");
  free_txdata();

  delete tp; tp = NULL;
}
