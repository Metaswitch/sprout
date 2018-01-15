/**
 * @file bgcf_test.cpp
 *
 * Copyright (C) Metaswitch Networks 2017
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
#include "test_interposer.hpp"
#include "bgcfsproutlet.h"
#include "sproutletappserver.h"
#include "sproutletproxy.h"
#include "fakesnmp.hpp"
#include "mock_snmp_counter_table.hpp"

using namespace std;
using testing::StrEq;
using testing::ElementsAre;
using testing::MatchesRegex;
using testing::HasSubstr;
using testing::Not;

namespace SP
{
  class BGCFMessage
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
    string _branch;
    int _cseq;
    bool _in_dialog;
    string _route;

    BGCFMessage() :
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
      _branch(""),
      _cseq(16567),
      _in_dialog(false),
      _route("Route: <sip:bgcf.homedomain;orig>")
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

      // If there's no route, the target goes in the request
      // URI. Otherwise it goes in the Route:, and the route goes in the
      // request URI.
      string requri = target;
      string route = _route;
      route = route.empty() ? "" : route.append("\r\n");

      // Default branch parameter if it's not supplied.
      std::string branch = _branch.empty() ? "Pjmo1aimuq33BAI4rjhgQgBr4sY" + std::to_string(_unique) : _branch;

      int n = snprintf(buf, sizeof(buf),
                       "%1$s %9$s SIP/2.0\r\n"
                       "Via: SIP/2.0/TCP %13$s;rport;branch=z9hG4bK%15$s\r\n"
                       "%12$s"
                       "From: <sip:%2$s@%3$s>;tag=10.114.61.213+1+8c8b232a+5fb751cf\r\n"
                       "To: <%10$s>%16$s\r\n"
                       "Max-Forwards: %8$d\r\n"
                       "Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs%11$04dohntC@10.114.61.213\r\n"
                       "CSeq: %14$d %1$s\r\n"
                       "User-Agent: Accession 2.0.0.0\r\n"
                       "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n"
                       "%4$s"
                       "%7$s"
                       "%17$s"
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
                       /* 14 */ _cseq,
                       /* 15 */ branch.c_str(),
                       /* 16 */ (_in_dialog) ? ";tag=10.114.61.213+1+8c8b232a+5fb751cf" : "",
                       /* 17 */ route.c_str()
        );

      EXPECT_LT(n, (int)sizeof(buf));

      string ret(buf, n);
      return ret;
    }
  };
}

/// ABC for fixtures for BGCFTest and friends.
class BGCFTest : public SipTest
{
public:
  /// Set up test case.  Caller must clear host_mapping.
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();

    // BGCF selector built with test_bgcf_sproutlet_bgcf.json. This has a
    // wildcard domain, so the BGCF tests will always route to something
    _bgcf_service = new BgcfService(string(UT_DIR).append("/test_bgcf_sproutlet_bgcf.json"));

    // We only test with a JSONEnumService, not with a DNSEnumService - since
    // it is stateful_proxy.cpp that's under test here, the EnumService
    // implementation doesn't matter.
    _enum_service = new JSONEnumService(string(UT_DIR).append("/test_bgcf_sproutlet_enum.json"));
    _acr_factory = new ACRFactory();

    // Create the BGCF Sproutlet.
    _bgcf_sproutlet = new BGCFSproutlet("bgcf",
                                        5054,
                                        "sip:bgcf.homedomain:5058;transport=tcp",
                                        _bgcf_service,
                                        _enum_service,
                                        _acr_factory,
                                        nullptr,
                                        nullptr,
                                        false);

    // Create the SproutletProxy.
    std::list<Sproutlet*> sproutlets;
    sproutlets.push_back(_bgcf_sproutlet);
    std::unordered_set<std::string> aliases;
    aliases.insert("127.0.0.1");
    _mock_counter_table = new MockSnmpCounterTable();
    _proxy = new SproutletProxy(stack_data.endpt,
                                PJSIP_MOD_PRIORITY_UA_PROXY_LAYER+1,
                                "homedomain",
                                aliases,
                                std::unordered_set<std::string>(),
                                sproutlets,
                                std::set<std::string>(),
                                _mock_counter_table);

    // Schedule timers.
    SipTest::poll();
  }

  static void TearDownTestCase()
  {
    // Shut down the transaction module first, before we destroy the
    // objects that might handle any callbacks!
    pjsip_tsx_layer_destroy();
    delete _proxy; _proxy = NULL;
    delete _mock_counter_table; _mock_counter_table = NULL;
    delete _bgcf_sproutlet; _bgcf_sproutlet = NULL;
    delete _acr_factory; _acr_factory = NULL;
    delete _enum_service; _enum_service = NULL;
    delete _bgcf_service; _bgcf_service = NULL;
    SipTest::TearDownTestCase();
  }

  BGCFTest()
  {
    _log_traffic = PrintingTestLogger::DEFAULT.isPrinting(); // true to see all traffic
  }

  ~BGCFTest()
  {
    pjsip_tsx_layer_dump(true);

    // Terminate all transactions
    terminate_all_tsxs(PJSIP_SC_SERVICE_UNAVAILABLE);

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

    // Reset any configuration changes
    URIClassifier::enforce_user_phone = false;
    URIClassifier::enforce_global = false;
  }

protected:
  static BgcfService* _bgcf_service;
  static EnumService* _enum_service;
  static ACRFactory* _acr_factory;
  static BGCFSproutlet* _bgcf_sproutlet;
  static MockSnmpCounterTable* _mock_counter_table;
  static SproutletProxy* _proxy;

  void doSuccessfulFlow(SP::BGCFMessage& msg,
                        testing::Matcher<string> uri_matcher,
                        std::list<HeaderMatcher> hdr_matchers);
  void doFailureFlow(SP::BGCFMessage& msg, int st_code);
};

BgcfService* BGCFTest::_bgcf_service;
EnumService* BGCFTest::_enum_service;
ACRFactory* BGCFTest::_acr_factory;
BGCFSproutlet* BGCFTest::_bgcf_sproutlet;
MockSnmpCounterTable* BGCFTest::_mock_counter_table;
SproutletProxy* BGCFTest::_proxy;

using SP::BGCFMessage;

/// Test a message results in a successful flow. The outgoing INVITE's
/// URI is verified and any requested headers are verified as well
void BGCFTest::doSuccessfulFlow(BGCFMessage& msg,
                                testing::Matcher<string> uri_matcher,
                                std::list<HeaderMatcher> hdr_matchers)
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
  for (list<HeaderMatcher>::iterator iter = hdr_matchers.begin(); iter != hdr_matchers.end(); ++iter)
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
}

/// Test a message results in an immediate failure.
void BGCFTest::doFailureFlow(BGCFMessage& msg, int st_code)
{
  SCOPED_TRACE("");

  // Send INVITE
  inject_msg(msg.get_request());
  ASSERT_EQ(2, txdata_count());

  // We get the 100 Trying from the SproutletProxy, so check this first
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  free_txdata();

  // Now check the error
  out = current_txdata()->msg;
  RespMatcher(st_code).matches(out);
  free_txdata();
}

// Test that a simple Tel URI is picked up by the number route
TEST_F(BGCFTest, TestSimpleTelURIMatched)
{
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  SCOPED_TRACE("");
  BGCFMessage msg;
  msg._toscheme = "tel";
  msg._to = "+16505551234";
  msg._todomain = "";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Route", ".*10.0.0.1:5060.*"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*16505551234$"), hdrs);
}

// Tests that a sip: URI with user=phone and no routing number parameter matches
// on the number route
TEST_F(BGCFTest, TestSipPhoneNumberUriMatched)
{
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  SCOPED_TRACE("");
  BGCFMessage msg;
  msg._requri = "sip:+16505551234@notamatchingdomain;user=phone";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Route", ".*10.0.0.1:5060.*"));
  doSuccessfulFlow(msg, testing::MatchesRegex("sip:[+]16505551234@notamatchingdomain;user=phone"), hdrs);
}

// Tests that a SIP URI representing a phone number that doesn't match a number
// route is picked up by the wildcard domain
TEST_F(BGCFTest, TestSipPhoneNumberUriNotMatched)
{
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  SCOPED_TRACE("");
  BGCFMessage msg;
  msg._requri = "sip:16505551234@notamatchingdomain;user=phone";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Route", ".*10.0.0.2:5060.*"));
  doSuccessfulFlow(msg, testing::MatchesRegex("sip:16505551234@notamatchingdomain;user=phone"), hdrs);
}

// Test that a simple Tel URI that doesn't match a route is picked up by the
// wildcard domain
TEST_F(BGCFTest, TestSimpleTelURIUnmatched)
{
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  SCOPED_TRACE("");
  BGCFMessage msg;
  msg._toscheme = "tel";
  msg._to = "16505551234";
  msg._todomain = "";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Route", ".*10.0.0.2:5060.*"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*16505551234$"), hdrs);
}

// Test that Tel URI with a routing number that matches a number route is picked
// up by that route
TEST_F(BGCFTest, TestTelURINPMatched)
{
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  SCOPED_TRACE("");
  BGCFMessage msg;
  msg._toscheme = "tel";
  msg._to = "16505551234;npdi;rn=+16505551234";
  msg._todomain = "";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Route", ".*10.0.0.1:5060.*"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*16505551234$"), hdrs);
}

// Test that Tel URI with a routing number that doesn't match  a number route is
// picked up by the wildcard domain route
TEST_F(BGCFTest, TestTelURINPNotMatched)
{
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  SCOPED_TRACE("");
  BGCFMessage msg;
  msg._toscheme = "tel";
  msg._to = "+16505551234;npdi;rn=16505551234";
  msg._todomain = "";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Route", ".*10.0.0.2:5060.*"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*16505551234$"), hdrs);
}

TEST_F(BGCFTest, TestValidBGCFRoute)
{
  SCOPED_TRACE("");
  BGCFMessage msg;
  msg._to = "bgcf";
  msg._todomain = "domainvalid";
  add_host_mapping("domainvalid", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Route", "Route: <sip:10.0.0.1:5060;transport=TCP;lr>"));
  doSuccessfulFlow(msg, testing::MatchesRegex("sip:bgcf@domainvalid"), hdrs);
}

TEST_F(BGCFTest, TestValidBGCFRouteNameAddr)
{
  SCOPED_TRACE("");
  BGCFMessage msg;
  msg._to = "bgcf";
  msg._todomain = "domainanglebracket";
  add_host_mapping("domainanglebracket", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Route", "Route: <sip:10.0.0.1:5060;transport=TCP;lr>"));
  doSuccessfulFlow(msg, testing::MatchesRegex("sip:bgcf@domainanglebracket"), hdrs);
}

TEST_F(BGCFTest, TestInvalidBGCFRoute)
{
  SCOPED_TRACE("");
  BGCFMessage msg;
  msg._to = "bgcf";
  msg._todomain = "domainnotasipuri";
  add_host_mapping("domainnotasipuri", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doFailureFlow(msg, 500);
}

TEST_F(BGCFTest, TestInvalidBGCFRouteNameAddr)
{
  SCOPED_TRACE("");
  BGCFMessage msg;
  msg._to = "bgcf";
  msg._todomain = "domainnotasipurianglebracket";
  add_host_mapping("domainnotasipurianglebracket", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doFailureFlow(msg, 500);
}

TEST_F(BGCFTest, TestInvalidBGCFRouteNameAddrMix)
{
  SCOPED_TRACE("");
  BGCFMessage msg;
  msg._to = "bgcf";
  msg._todomain = "domainnotasipurianglebracketmix";
  add_host_mapping("domainnotasipurianglebracketmix", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doFailureFlow(msg, 500);
}

// If the BGCF receives a request with pre-loaded Route headers, it should
// remove them before applying its own routes.
TEST_F(BGCFTest, OverrideRoutes)
{
  SCOPED_TRACE("");
  BGCFMessage msg;
  msg._to = "12345";
  msg._todomain = "domainvalid";
  msg._route = "Route: <sip:bgcf.homedomain>\nRoute: <sip:1.2.3.4;lr>";
  add_host_mapping("domainvalid", "10.9.8.7");
  list<HeaderMatcher> hdrs;

  // Check that the preloaded 1.2.3.4 route has now gone.
  hdrs.push_back(HeaderMatcher("Route", "Route: <sip:10.0.0.1:5060;transport=TCP;lr>"));
  doSuccessfulFlow(msg, testing::MatchesRegex("sip:12345@domainvalid"), hdrs);
}
