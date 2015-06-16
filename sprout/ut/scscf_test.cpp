/**
 * @file scscf_test.cpp UT for S-CSCF functionality
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
#include "fakecurl.hpp"
#include "fakehssconnection.hpp"
#include "fakexdmconnection.hpp"
#include "test_interposer.hpp"
#include "fakechronosconnection.hpp"
#include "scscfsproutlet.h"
#include "icscfsproutlet.h"
#include "bgcfsproutlet.h"
#include "sproutletappserver.h"
#include "mmtel.h"
#include "sproutletproxy.h"

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
    string _branch;
    string _route;
    int _cseq;
    bool _in_dialog;

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
      _branch(""),
      _cseq(16567),
      _in_dialog(false)
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
      //string requri = _route.empty() ? target : _route;
      //string route = _route.empty() ? "" : string("Route: ").append(target).append("\r\n");
      string requri = target;
      string route = _route;
      route = route.empty() ? "" : route.append("\r\n");

      // Default branch parameter if it's not supplied.
      std::string branch = _branch.empty() ? "Pjmo1aimuq33BAI4rjhgQgBr4sY" + std::to_string(_unique) : _branch;

      int n = snprintf(buf, sizeof(buf),
                       "%1$s %9$s SIP/2.0\r\n"
                       "Via: SIP/2.0/TCP %13$s;rport;branch=z9hG4bK%16$s\r\n"
                       "%12$s"
                       "From: <sip:%2$s@%3$s>;tag=10.114.61.213+1+8c8b232a+5fb751cf\r\n"
                       "To: <%10$s>%17$s\r\n"
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
                       /* 15 */ _cseq,
                       /* 16 */ branch.c_str(),
                       /* 17 */ (_in_dialog) ? ";tag=10.114.61.213+1+8c8b232a+5fb751cf" : ""
        );

      EXPECT_LT(n, (int)sizeof(buf));

      string ret(buf, n);
      // cout << ret <<endl;
      return ret;
    }

    string get_response()
    {
      char buf[16384];

      // Default branch parameter if it's not supplied.
      std::string branch = _branch.empty() ? "Pjmo1aimuq33BAI4rjhgQgBr4sY" + std::to_string(_unique) : _branch;

      int n = snprintf(buf, sizeof(buf),
                       "SIP/2.0 %9$s\r\n"
                       "Via: SIP/2.0/TCP %14$s;rport;branch=z9hG4bK%15$s\r\n"
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
                       /* 14 */ _via.c_str(),
                       /* 15 */ branch.c_str()
        );

      EXPECT_LT(n, (int)sizeof(buf));

      string ret(buf, n);
      // cout << ret <<endl;
      return ret;
    }
  };
}

/// Helper to print list to ostream.
class SCSCFDumpList
{
public:
  SCSCFDumpList(const string& title, list<string> list) :
    _title(title), _list(list)
  {
  }
  friend std::ostream& operator<<(std::ostream& os, const SCSCFDumpList& that);
private:
  string _title;
  list<string> _list;
};

std::ostream& operator<<(std::ostream& os, const SCSCFDumpList& that)
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

    ASSERT_EQ(_regexes.size(), values.size()) << SCSCFDumpList("Expected", _regexes) << SCSCFDumpList("Actual", values);
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


/// ABC for fixtures for SCSCFTest and friends.
class SCSCFTest : public SipTest
{
public:
  /// TX data for testing.  Will be cleaned up.  Each message in a
  /// forked flow has its URI stored in _uris, and its txdata stored
  /// in _tdata against that URI.
  vector<string> _uris;
  map<string,pjsip_tx_data*> _tdata;

  /// Set up test case.  Caller must clear host_mapping.
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase(false);

    _chronos_connection = new FakeChronosConnection();
    _local_data_store = new LocalStore();
    _store = new RegStore((Store*)_local_data_store, _chronos_connection);
    _analytics = new AnalyticsLogger(&PrintingTestLogger::DEFAULT);
    _hss_connection = new FakeHSSConnection();
    _scscf_selector = new SCSCFSelector(string(UT_DIR).append("/test_stateful_proxy_scscf.json"));
    _bgcf_service = new BgcfService(string(UT_DIR).append("/test_stateful_proxy_bgcf.json"));
    _xdm_connection = new FakeXDMConnection();

    // We only test with a JSONEnumService, not with a DNSEnumService - since
    // it is stateful_proxy.cpp that's under test here, the EnumService
    // implementation doesn't matter.
    _enum_service = new JSONEnumService(string(UT_DIR).append("/test_stateful_proxy_enum.json"));

    _acr_factory = new ACRFactory();

    // Create the S-CSCF Sproutlet.
    _scscf_sproutlet = new SCSCFSproutlet("sip:homedomain:5058",
                                          "sip:127.0.0.1:5058",
                                          "",
                                          "sip:bgcf.homedomain:5058",
                                          5058,
                                          _store,
                                          NULL,
                                          _hss_connection,
                                          _enum_service,
                                          _acr_factory,
                                          false,
                                          false,
                                          false,
                                          3000, // Session continue timeout - different from default
                                          6000  // Session terminated timeout - different from default
                                          );
    _scscf_sproutlet->init();

    // Create the BGCF Sproutlet.
    _bgcf_sproutlet = new BGCFSproutlet(0,
                                        _bgcf_service,
                                        _enum_service,
                                        _acr_factory,
                                        false,
                                        false,
                                        false);

    // Create the MMTEL AppServer.
    _mmtel = new Mmtel("mmtel", _xdm_connection);
    _mmtel_sproutlet = new SproutletAppServerShim(_mmtel, "mmtel.homedomain");

    // Create the SproutletProxy.
    std::list<Sproutlet*> sproutlets;
    sproutlets.push_back(_scscf_sproutlet);
    sproutlets.push_back(_bgcf_sproutlet);
    sproutlets.push_back(_mmtel_sproutlet);
    std::unordered_set<std::string> aliases;
    aliases.insert("127.0.0.1");
    _proxy = new SproutletProxy(stack_data.endpt,
                                PJSIP_MOD_PRIORITY_UA_PROXY_LAYER+1,
                                "sip:homedomain:5058",
                                aliases,
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
    delete _proxy; _proxy = NULL;
    delete _mmtel_sproutlet; _mmtel_sproutlet = NULL;
    delete _mmtel; _mmtel = NULL;
    delete _bgcf_sproutlet; _bgcf_sproutlet = NULL;
    delete _scscf_sproutlet; _scscf_sproutlet = NULL;
    delete _scscf_selector; _scscf_selector = NULL;
    delete _acr_factory; _acr_factory = NULL;
    delete _store; _store = NULL;
    delete _chronos_connection; _chronos_connection = NULL;
    delete _local_data_store; _local_data_store = NULL;
    delete _analytics; _analytics = NULL;
    delete _hss_connection; _hss_connection = NULL;
    delete _enum_service; _enum_service = NULL;
    delete _bgcf_service; _bgcf_service = NULL;
    delete _xdm_connection; _xdm_connection = NULL;
    SipTest::TearDownTestCase();
  }

  SCSCFTest()
  {
    _log_traffic = PrintingTestLogger::DEFAULT.isPrinting(); // true to see all traffic
    _local_data_store->flush_all();  // start from a clean slate on each test
    if (_hss_connection)
    {
      _hss_connection->flush_all();
    }
  }

  ~SCSCFTest()
  {
    for (map<string,pjsip_tx_data*>::iterator it = _tdata.begin();
         it != _tdata.end();
         ++it)
    {
      pjsip_tx_data_dec_ref(it->second);
    }

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
    _scscf_sproutlet->set_global_only_lookups(false);
    _scscf_sproutlet->set_enforce_user_phone(false);
    _scscf_sproutlet->set_override_npdi(false);
    _scscf_sproutlet->set_session_continued_timeout(3000);
    _scscf_sproutlet->set_session_terminated_timeout(6000);
  }

protected:
  static LocalStore* _local_data_store;
  static FakeChronosConnection* _chronos_connection;
  static RegStore* _store;
  static AnalyticsLogger* _analytics;
  static FakeHSSConnection* _hss_connection;
  static FakeXDMConnection* _xdm_connection;
  static BgcfService* _bgcf_service;
  static EnumService* _enum_service;
  static ACRFactory* _acr_factory;
  static SCSCFSelector* _scscf_selector;
  static SCSCFSproutlet* _scscf_sproutlet;
  static BGCFSproutlet* _bgcf_sproutlet;
  static Mmtel* _mmtel;
  static SproutletAppServerShim* _mmtel_sproutlet;
  static SproutletProxy* _proxy;

  void doTestHeaders(TransportFlow* tpA,
                     bool tpAset,
                     TransportFlow* tpB,
                     bool tpBset,
                     SP::Message& msg,
                     string route,
                     bool expect_100,
                     bool expect_trusted_headers_on_requests,
                     bool expect_trusted_headers_on_responses,
                     bool expect_orig,
                     bool pcpi);
  void doAsOriginated(SP::Message& msg, bool expect_orig);
  void doAsOriginated(const std::string& msg, bool expect_orig);
  void doFourAppServerFlow(std::string record_route_regex, bool app_servers_record_route=false);
  void doSuccessfulFlow(SP::Message& msg, testing::Matcher<string> uri_matcher, list<HeaderMatcher> headers, bool include_ack_and_bye=true, bool session_expires=false);
  void doFastFailureFlow(SP::Message& msg, int st_code);
  void doSlowFailureFlow(SP::Message& msg, int st_code, std::string body = "", std::string reason = "");
  void setupForkedFlow(SP::Message& msg);
  list<string> doProxyCalculateTargets(int max_targets);
};

LocalStore* SCSCFTest::_local_data_store;
FakeChronosConnection* SCSCFTest::_chronos_connection;
RegStore* SCSCFTest::_store;
AnalyticsLogger* SCSCFTest::_analytics;
FakeHSSConnection* SCSCFTest::_hss_connection;
FakeXDMConnection* SCSCFTest::_xdm_connection;
BgcfService* SCSCFTest::_bgcf_service;
EnumService* SCSCFTest::_enum_service;
ACRFactory* SCSCFTest::_acr_factory;
SCSCFSelector* SCSCFTest::_scscf_selector;
SCSCFSproutlet* SCSCFTest::_scscf_sproutlet;
BGCFSproutlet* SCSCFTest::_bgcf_sproutlet;
Mmtel* SCSCFTest::_mmtel;
SproutletAppServerShim* SCSCFTest::_mmtel_sproutlet;
SproutletProxy* SCSCFTest::_proxy;

using SP::Message;

void SCSCFTest::doFourAppServerFlow(std::string record_route_regex, bool app_servers_record_route)
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                R"(<IMSSubscription><ServiceProfile>
                                <PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>
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
                                </ServiceProfile></IMSSubscription>)");
  _hss_connection->set_impu_result("sip:6505551234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                R"(<IMSSubscription><ServiceProfile>
                                <PublicIdentity><Identity>sip:6505551234@homedomain</Identity></PublicIdentity>
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
                                    <Priority>2</Priority>
                                    <TriggerPoint>
                                    <ConditionTypeCNF>0</ConditionTypeCNF>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <Method>QWERTY_UIOP</Method>
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:sholes.example.com</ServerName>
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
                                    <ServerName>sip:6.2.3.4:56786;transport=UDP</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                </ServiceProfile></IMSSubscription>)");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpAS2(TransportFlow::Protocol::UDP, stack_data.scscf_port, "4.2.3.4", 56788);
  TransportFlow tpAS3(TransportFlow::Protocol::UDP, stack_data.scscf_port, "5.2.3.4", 56787);
  TransportFlow tpAS4(TransportFlow::Protocol::UDP, stack_data.scscf_port, "6.2.3.4", 56786);

  pjsip_rr_hdr* as1_rr_hdr = pjsip_rr_hdr_create(stack_data.pool);
  as1_rr_hdr->name_addr.uri = (pjsip_uri*)pjsip_sip_uri_create(stack_data.pool, false);
  ((pjsip_sip_uri*)as1_rr_hdr->name_addr.uri)->host = pj_str("1.2.3.4");

  pjsip_rr_hdr* as2_rr_hdr = pjsip_rr_hdr_create(stack_data.pool);
  as2_rr_hdr->name_addr.uri = (pjsip_uri*)pjsip_sip_uri_create(stack_data.pool, false);
  ((pjsip_sip_uri*)as2_rr_hdr->name_addr.uri)->host = pj_str("4.2.3.4");

  pjsip_rr_hdr* as3_rr_hdr = pjsip_rr_hdr_create(stack_data.pool);
  as3_rr_hdr->name_addr.uri = (pjsip_uri*)pjsip_sip_uri_create(stack_data.pool, false);
  ((pjsip_sip_uri*)as3_rr_hdr->name_addr.uri)->host = pj_str("5.2.3.4");

  pjsip_rr_hdr* as4_rr_hdr = pjsip_rr_hdr_create(stack_data.pool);
  as4_rr_hdr->name_addr.uri = (pjsip_uri*)pjsip_sip_uri_create(stack_data.pool, false);
  ((pjsip_sip_uri*)as4_rr_hdr->name_addr.uri)->host = pj_str("6.2.3.4");

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

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
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig>"));

  // ---------- AS1 turns it around (acting as proxy)
  const pj_str_t STR_ROUTE = pj_str("Route");

  if (app_servers_record_route)
  {
    pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)as1_rr_hdr);
  }

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
              testing::MatchesRegex("Route: <sip:4\\.2\\.3\\.4:56788;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig>"));

  // ---------- AS2 turns it around (acting as proxy)
  if (app_servers_record_route)
  {
    pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)as2_rr_hdr);
  }

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

  // INVITE passed on to AS3 - From this point on, we're in terminating mode.
  SCOPED_TRACE("INVITE (3)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS3.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr>"));

  // ---------- AS3 turns it around (acting as proxy)
  if (app_servers_record_route)
  {
    pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)as3_rr_hdr);
  }

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
              testing::MatchesRegex("Route: <sip:6\\.2\\.3\\.4:56786;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr>"));

  // ---------- AS4 turns it around (acting as proxy)
  if (app_servers_record_route)
  {
    pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)as4_rr_hdr);
  }

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

  EXPECT_THAT(get_headers(out, "Record-Route"), testing::MatchesRegex(record_route_regex));

  free_txdata();
}

// Test flows into Sprout (S-CSCF), in particular for header stripping.
// Check the transport each message is on, and the headers.
// Test a call from Alice to Bob.
void SCSCFTest::doTestHeaders(TransportFlow* tpA,  //< Alice's transport.
                              bool tpAset,         //< Expect all requests to Alice on same transport?
                              TransportFlow* tpB,  //< Bob's transport.
                              bool tpBset,         //< Expect all requests to Bob on same transport?
                              SP::Message& msg,    //< Message to use for testing.
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
    msg.set_route(out);

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
  msg.set_route(out);
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
  msg.set_route(out);
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
  msg.set_route(out);
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
  msg.set_route(out);
  msg._cseq++;

  // Check P-Access-Network-Info and P-Visited-Network-Id. These will always be stripped,
  // because we handle these retransmissions statelessly and hence don't have any info on
  // trust boundary handling.
  //EXPECT_EQ("", get_headers(out, "P-Access-Network-Info")) << "200 OK (INVITE) (rexmt)";
  //EXPECT_EQ("", get_headers(out, "P-Visited-Network-Id")) << "200 OK (INVITE) (rexmt)";

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
  msg.set_route(out);
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


/// Test a message results in a successful flow. The outgoing INVITE's
/// URI is verified.
void SCSCFTest::doSuccessfulFlow(Message& msg,
                                 testing::Matcher<string> uri_matcher,
                                 list<HeaderMatcher> headers,
                                 bool include_ack_and_bye,
                                 bool session_expires)
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

  if (session_expires)
  {
    // In general proxied messages should have Session-Expires headers added,
    // except if we are simply forwarding without applying any services.
    std::string session_expires = get_headers(out, "Session-Expires");
    EXPECT_EQ("Session-Expires: 600", session_expires);
  }

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

  // If we're testing Sprout functionality, we want to exclude the ACK
  // and BYE requests, as Sprout wouldn't see them in normal circumstances.
  if (include_ack_and_bye)
  {
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
}

/// Test a message results in an immediate failure.
void SCSCFTest::doFastFailureFlow(Message& msg, int st_code)
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
void SCSCFTest::doSlowFailureFlow(Message& msg,
                                  int st_code,
                                  std::string body,
                                  std::string reason)
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
  RespMatcher(st_code, body, reason).matches(out);
  free_txdata();
}

TEST_F(SCSCFTest, TestSimpleMainline)
{
  SCOPED_TRACE("");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  Message msg;
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs);
}

// Send a request where the URI is for the same port as a Sproutlet,
// but a different host. We should deal with this sensibly (as opposed
// to e.g. looping forever until we crash).
TEST_F(SCSCFTest, ReqURIMatchesSproutletPort)
{
  SCOPED_TRACE("");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  Message msg;
  msg._requri = "sip:254.253.252.251:5058";
  msg._route = "Route: <sip:homedomain;transport=tcp;lr;service=scscf;billing-role=charge-term>";
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex("sip:254.253.252.251:5058"), hdrs, false);
}

// Test flows into Sprout (S-CSCF), in particular for header stripping.
TEST_F(SCSCFTest, TestMainlineHeadersSprout)
{
  SCOPED_TRACE("");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");

  // INVITE from anywhere to anywhere.
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345";
  doTestHeaders(_tp_default, false, _tp_default, false, msg, "", true, true, true, false, true);
}

TEST_F(SCSCFTest, TestNotRegisteredTo)
{
  SCOPED_TRACE("");
  Message msg;
  doSlowFailureFlow(msg, 404);
}

TEST_F(SCSCFTest, TestBadScheme)
{
  SCOPED_TRACE("");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  Message msg;
  msg._toscheme = "sips";
  doFastFailureFlow(msg, 416);  // bad scheme
}

TEST_F(SCSCFTest, TestSimpleTelURI)
{
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  SCOPED_TRACE("");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");
  Message msg;
  msg._toscheme = "tel";
  msg._to = "16505551234";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._todomain = "";
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*16505551234@ut.cw-ngv.com.*"), hdrs, false);
}

TEST_F(SCSCFTest, TestNoMoreForwards)
{
  SCOPED_TRACE("");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  Message msg;
  msg._forwards = 1;
  doFastFailureFlow(msg, 483); // too many hops
}

TEST_F(SCSCFTest, TestNoMoreForwards2)
{
  SCOPED_TRACE("");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  Message msg;
  msg._forwards = 0;
  doFastFailureFlow(msg, 483); // too many hops
}

TEST_F(SCSCFTest, TestTransportShutdown)
{
  SCOPED_TRACE("");
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject an INVITE request on a transport which is shutting down.  It is safe
  // to call pjsip_transport_shutdown on a TCP transport as the TransportFlow
  // keeps a reference to the transport so it won't actually be destroyed until
  // the TransportFlow is destroyed.
  pjsip_transport_shutdown(tp->transport());

  Message msg;
  msg._method = "INVITE";
  msg._requri = "sip:bob@awaydomain";
  msg._from = "alice";
  msg._to = "bob";
  msg._todomain = "awaydomain";
  msg._via = tp->to_string(false);
  msg._route = "Route: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg.get_request(), tp);

  // Check the 504 Service Unavailable response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(503).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Send an ACK to complete the UAS transaction.
  msg._method = "ACK";
  inject_msg(msg.get_request(), tp);

  delete tp;
}

TEST_F(SCSCFTest, TestStrictRouteThrough)
{
  SCOPED_TRACE("");
  // This message is passing through this proxy; it's not local
  Message msg;
  add_host_mapping("intermediate.com", "10.10.10.1");
  add_host_mapping("destination.com", "10.10.10.2");
  msg._extra = "Route: <sip:nexthop@intermediate.com;transport=tcp>\r\nRoute: <sip:lasthop@destination.com>";
  msg._to = "lasthop";
  msg._todomain = "destination.com";
  msg._requri = "sip:6505551234@nonlocaldomain";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Route", ".*lasthop@destination.com.*", ".*6505551234@nonlocaldomain.*"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*nexthop@intermediate.com.*"), hdrs, false, false);
}

TEST_F(SCSCFTest, TestMultipleRouteHeaders)
{
  SCOPED_TRACE("");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  Message msg;
  msg._extra = "Route: <sip:homedomain:5058;transport=tcp;lr>\r\nRoute: <sip:homedomain:5054;lr>";
  list<HeaderMatcher> hdrs;
  // Expect only the top Route header to be stripped, as is necessary
  // for Sprout and Bono to be colocated

  hdrs.push_back(HeaderMatcher("Route", "Route: <sip:homedomain:5054;lr>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*"), hdrs);
}


TEST_F(SCSCFTest, TestNonLocal)
{
  SCOPED_TRACE("");
  // This message is passing through this proxy; it's not local
  add_host_mapping("destination.com", "10.10.10.2");
  Message msg;
  msg._to = "lasthop";
  msg._todomain = "destination.com";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Route"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*lasthop@destination\\.com.*"), hdrs);
}

TEST_F(SCSCFTest, TestTerminatingPCV)
{
  SCOPED_TRACE("");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");

  // Test that a segfault previously seen when not doing originating
  // handling on a call with a P-Charging-Vector does not reoccur.
  Message msg;
  msg._extra = "P-Charging-Vector: icid-value=3";
  msg._to = "lasthop";
  msg._todomain = "destination.com";
  msg._requri = "sip:6505551234@homedomain";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Route"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*"), hdrs);
}

TEST_F(SCSCFTest, DISABLED_TestLooseRoute)  // @@@KSW not quite - how does this work again?
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

TEST_F(SCSCFTest, TestExternal)
{
  SCOPED_TRACE("");
  Message msg;
  msg._to = "+15108580271";
  msg._todomain = "ut.cw-ngv.com";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*+15108580271@ut.cw-ngv.com.*"), hdrs);
}

// Test is disabled because there is no Route header, so request is treated as
// terminating request, but domain in RequestURI is not local, so we don't
// provide any services to the user, so therefore shouldn't add a Record-Route.
TEST_F(SCSCFTest, DISABLED_TestExternalRecordRoute)
{
  SCOPED_TRACE("");
  Message msg;
  msg._to = "+15108580271";
  msg._todomain = "ut.cw-ngv.com";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Record-Route", "Record-Route: <sip:sprout.homedomain:5058;transport=TCP;lr;charge-term>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*"), hdrs);
}

TEST_F(SCSCFTest, TestEnumExternalSuccess)
{
  SCOPED_TRACE("");
  _hss_connection->set_impu_result("sip:+16505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");

  Message msg;
  msg._to = "+15108580271";
  // We only do ENUM on originating calls
  msg._route = "Route: <sip:homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  // Skip the ACK and BYE on this request by setting the last
  // parameter to false, as we're only testing Sprout functionality
  doSuccessfulFlow(msg, testing::MatchesRegex(".*+15108580271@ut.cw-ngv.com.*"), hdrs, false);
}

TEST_F(SCSCFTest, TestNoEnumWhenGRUU)
{
  SCOPED_TRACE("");
  _hss_connection->set_impu_result("sip:+16505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");
  register_uri(_store, _hss_connection, "+15108580271", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", 30, "abcd");

  Message msg;
  msg._to = "+15108580271";
  msg._todomain += ";gr=abcd";
  // We only do ENUM on originating calls
  msg._route = "Route: <sip:homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;

  // Even though "+15108580271" is configured for ENUM, the presence
  // of a GRUU parameter should indicate to Sprout that this wasn't
  // a string of dialled digits - so we won't do an ENUM lookup and
  // will route to the local subscriber.
  doSuccessfulFlow(msg, testing::MatchesRegex("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob"), hdrs, false);
}

TEST_F(SCSCFTest, TestGRUUFailure)
{
  // Identical to TestNoEnumWhenGRUU, except that the registered
  // binding in this test has a different instance-id ("abcde" nor
  // "abcd"), so the GRUU doesn't match and the call should fail with
  // a 480 error.
  SCOPED_TRACE("");
  _hss_connection->set_impu_result("sip:+16505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");
  register_uri(_store, _hss_connection, "+15108580271", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", 30, "abcde");

  Message msg;
  msg._to = "+15108580271";
  msg._todomain += ";gr=abcd";
  // We only do ENUM on originating calls
  msg._route = "Route: <sip:homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");

  doSlowFailureFlow(msg, 480);
}

// Various ENUM tests - these use the test_stateful_proxy_enum.json file
// TODO - these want tidying up (maybe make the enum service a mock? at least make it so
// there are separate number ranges used in each test).
TEST_F(SCSCFTest, TestEnumExternalSuccessFromFromHeader)
{
  SCOPED_TRACE("");
  Message msg;
  _hss_connection->set_impu_result("sip:+15108581234@homedomain", "call", HSSConnection::STATE_REGISTERED, "");

  msg._to = "+15108580271";
  msg._from = "+15108581234";
  // We only do ENUM on originating calls
  msg._route = "Route: <sip:homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>";

  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  // Skip the ACK and BYE on this request by setting the last
  // parameter to false, as we're only testing Sprout functionality
  doSuccessfulFlow(msg, testing::MatchesRegex(".*+15108580271@ut.cw-ngv.com.*"), hdrs, false);
}

TEST_F(SCSCFTest, TestEnumExternalOffNetDialingAllowed)
{
  SCOPED_TRACE("");
  Message msg;
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");

  msg._to = "+15108580271";
  // We only do ENUM on originating calls
  msg._route = "Route: <sip:homedomain;orig>";

  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  // Skip the ACK and BYE on this request by setting the last
  // parameter to false, as we're only testing Sprout functionality
  doSuccessfulFlow(msg, testing::MatchesRegex(".*+15108580271@ut.cw-ngv.com.*"), hdrs, false);
}

TEST_F(SCSCFTest, TestEnumUserPhone)
{
  SCOPED_TRACE("");
  _hss_connection->set_impu_result("sip:+16505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");

  _scscf_sproutlet->set_enforce_user_phone(true);
  Message msg;
  msg._to = "+15108580271";
  msg._requri = "sip:+15108580271@homedomain;user=phone";
  // We only do ENUM on originating calls
  msg._route = "Route: <sip:homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  // Skip the ACK and BYE on this request by setting the last
  // parameter to false, as we're only testing Sprout functionality
  doSuccessfulFlow(msg, testing::MatchesRegex(".*+15108580271@ut.cw-ngv.com.*"), hdrs, false);
}

TEST_F(SCSCFTest, TestEnumNoUserPhone)
{
  SCOPED_TRACE("");
  _hss_connection->set_impu_result("sip:+16505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");

  _scscf_sproutlet->set_enforce_user_phone(true);
  Message msg;
  msg._to = "+15108580271";
  // We only do ENUM on originating calls
  msg._route = "Route: <sip:homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doSlowFailureFlow(msg, 404);
}

TEST_F(SCSCFTest, TestEnumLocalNumber)
{
  SCOPED_TRACE("");
  _hss_connection->set_impu_result("sip:+16505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");

  _scscf_sproutlet->set_global_only_lookups(true);
  Message msg;
  msg._to = "15108580271";
  // We only do ENUM on originating calls
  msg._route = "Route: <sip:homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doSlowFailureFlow(msg, 404);
}

TEST_F(SCSCFTest, TestEnumLocalTelURI)
{
  SCOPED_TRACE("");
  _hss_connection->set_impu_result("sip:+16505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");

  _scscf_sproutlet->set_global_only_lookups(true);
  Message msg;
  msg._to = "16505551234;npdi";
  msg._toscheme = "tel";
  msg._todomain = "";
  // We only do ENUM on originating calls
  msg._route = "Route: <sip:homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  // ENUM fails and wr route to the BGCF, but there are no routes so the call
  // is rejected.
  doSlowFailureFlow(msg, 404, "", "No route to target");
}

TEST_F(SCSCFTest, TestEnumLocalSIPURINumber)
{
  SCOPED_TRACE("");
  _hss_connection->set_impu_result("sip:+16505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");

  _scscf_sproutlet->set_global_only_lookups(true);
  Message msg;
  msg._to = "15108580271;npdi";
  msg._requri = "sip:15108580271;npdi@homedomain;user=phone";
  // We only do ENUM on originating calls
  msg._route = "Route: <sip:homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  // ENUM fails and we route to the BGCF, but there are no routes so the call
  // is rejected.
  doSlowFailureFlow(msg, 404, "", "No route to target");
}

// Test where the the ENUM lookup returns NP data. The request URI
// is changed, and the request is routed to the BGCF.
TEST_F(SCSCFTest, TestEnumNPData)
{
  SCOPED_TRACE("");
  _hss_connection->set_impu_result("sip:+16505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");

  Message msg;
  msg._to = "+15108580401";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*+15108580401;rn.*+151085804;npdi@homedomain.*"), hdrs, false);
}

// Test where the request URI represents a number and has NP data. The ENUM
// lookup returns a URI representing a number, so no rewrite is done
TEST_F(SCSCFTest, TestEnumReqURIwithNPData)
{
  SCOPED_TRACE("");
  _hss_connection->set_impu_result("sip:+16505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");

  Message msg;
  msg._to = "+15108580301;npdi";
  msg._requri = "sip:+15108580301;npdi@homedomain;user=phone";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  // ENUM fails and we route to the BGCF, but there are no routes so the call
  // is rejected. (This is unfortunately the same behaviour as we'd get if a rewrite was done, so
  // we're relying on code coverage metrics to confirm that this function works.) 
  doSlowFailureFlow(msg, 404, "", "No route to target");
}

// Test where the request URI represents a number and has NP data. The ENUM
// lookup returns a URI representing a number, and override_npdi is on,
// so the request URI is rewritten
TEST_F(SCSCFTest, TestEnumReqURIwithNPDataOverride)
{
  SCOPED_TRACE("");
  _hss_connection->set_impu_result("sip:+16505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");

  _scscf_sproutlet->set_override_npdi(true);
  Message msg;
  msg._to = "+15108580301;npdi";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*+15108580301;npdi@ut.cw-ngv.com.*"), hdrs, false);
}

// Test where the request URI represents a number and has NP data. The ENUM
// lookup returns a URI that doesn't represent a number so the request URI
// is rewritten
TEST_F(SCSCFTest, TestEnumReqURIwithNPDataToSIP)
{
  SCOPED_TRACE("");
  _hss_connection->set_impu_result("sip:+16505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");

  _scscf_sproutlet->set_enforce_user_phone(true);
  Message msg;
  msg._to = "+15108580301;npdi";
  msg._requri = "sip:+15108580301;npdi@homedomain;user=phone";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*+15108580301;npdi@ut.cw-ngv.com.*"), hdrs, false);
}

// Test where the BGCF receives a SIP request URI represents a number and has NP data.
// The ENUM lookup returns a rn which the BGCF routes on.
TEST_F(SCSCFTest, TestEnumNPBGCFSIP)
{
  SCOPED_TRACE("");
  _hss_connection->set_impu_result("sip:+16505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");
  _scscf_sproutlet->set_override_npdi(true);

  Message msg;
  msg._to = "+15108580401";
  msg._requri = "sip:+15108580401@homedomain;user=phone";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Route", "Route: <sip:10.0.0.1:5060;transport=TCP;lr>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*+15108580401;rn.*+151085804;npdi@homedomain.*"), hdrs, false);
}

// Test where the BGCF receives a Tel request URI represents a number and has NP data.
// The ENUM lookup returns a rn which the BGCF routes on.
TEST_F(SCSCFTest, TestEnumNPBGCFTel)
{
  SCOPED_TRACE("");
  _hss_connection->set_impu_result("sip:+16505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");
  _scscf_sproutlet->set_override_npdi(true);

  Message msg;
  msg._to = "+15108580401";
  msg._toscheme = "tel";
  msg._todomain = "";
  msg._requri = "tel:+15108580401";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._extra = "Record-Route: <sip:homedomain>\nP-Asserted-Identity: <sip:+16505551000@homedomain>";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Route", "Route: <sip:10.0.0.1:5060;transport=TCP;lr>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*+15108580401;rn.*+151085804;npdi@homedomain.*"), hdrs, false);
}

// Test where the BGCF does an ENUM lookup which returns an invalid rule. This
// test uses two ENUM rules. The first one is invoked by the S-CSCF before
// routing to the BGCF. The BGCF does the second lookup. At this point an
// invalid rule is returned and we reply with a 404 ENUM failure.
TEST_F(SCSCFTest, TestBGCFInvalidEnumRule)
{
  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  SCOPED_TRACE("");
  register_uri(_store, _hss_connection, "6505551239", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");
  Message msg;
  msg._toscheme = "tel";
  msg._to = "16505551239";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._todomain = "";
  list<HeaderMatcher> hdrs;
  doSlowFailureFlow(msg, 404, "", "ENUM failure");
}

TEST_F(SCSCFTest, TestValidBGCFRoute)
{
  SCOPED_TRACE("");
  Message msg;
  msg._to = "bgcf";
  msg._todomain = "domainvalid";
  add_host_mapping("domainvalid", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Route", "Route: <sip:10.0.0.1:5060;transport=TCP;lr>"));
  doSuccessfulFlow(msg, testing::MatchesRegex("sip:bgcf@domainvalid"), hdrs);
}

TEST_F(SCSCFTest, TestValidBGCFRouteNameAddr)
{
  SCOPED_TRACE("");
  Message msg;
  msg._to = "bgcf";
  msg._todomain = "domainanglebracket";
  add_host_mapping("domainanglebracket", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Route", "Route: <sip:10.0.0.1:5060;transport=TCP;lr>"));
  doSuccessfulFlow(msg, testing::MatchesRegex("sip:bgcf@domainanglebracket"), hdrs);
}

TEST_F(SCSCFTest, TestInvalidBGCFRoute)
{
  SCOPED_TRACE("");
  Message msg;
  msg._to = "bgcf";
  msg._todomain = "domainnotasipuri";
  add_host_mapping("domainnotasipuri", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doSlowFailureFlow(msg, 500);
}

TEST_F(SCSCFTest, TestInvalidBGCFRouteNameAddr)
{
  SCOPED_TRACE("");
  Message msg;
  msg._to = "bgcf";
  msg._todomain = "domainnotasipurianglebracket";
  add_host_mapping("domainnotasipurianglebracket", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doSlowFailureFlow(msg, 500);
}

TEST_F(SCSCFTest, TestInvalidBGCFRouteNameAddrMix)
{
  SCOPED_TRACE("");
  Message msg;
  msg._to = "bgcf";
  msg._todomain = "domainnotasipurianglebracketmix";
  add_host_mapping("domainnotasipurianglebracketmix", "10.9.8.7");
  list<HeaderMatcher> hdrs;
  doSlowFailureFlow(msg, 500);
}

/// Test a forked flow - setup phase.
void SCSCFTest::setupForkedFlow(SP::Message& msg)
{
  SCOPED_TRACE("");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:andunnuvvawun@10.114.61.214:5061;transport=tcp;ob");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:awwnawmaw@10.114.61.213:5061;transport=tcp;ob");
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

TEST_F(SCSCFTest, TestForkedFlow)
{
  SCOPED_TRACE("");
  pjsip_msg* out;
  Message msg;
  setupForkedFlow(msg);
  ASSERT_EQ(3u, _tdata.size());

  // Send 183 back from one of them
  inject_msg(respond_to_txdata(_tdata[_uris[0]], 183, "early"));

  // 183 goes back
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(183, "early").matches(out);
  free_txdata();

  // Send 100 back from another one of them
  inject_msg(respond_to_txdata(_tdata[_uris[2]], 100));

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

TEST_F(SCSCFTest, TestForkedFlow2)
{
  SCOPED_TRACE("");
  pjsip_msg* out;
  Message msg;
  setupForkedFlow(msg);
  ASSERT_EQ(3u, _tdata.size());

  // Send 183 back from one of them
  inject_msg(respond_to_txdata(_tdata[_uris[0]], 183));

  // 183 goes back
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(183).matches(out);
  free_txdata();

  // Send 100 back from one of them
  inject_msg(respond_to_txdata(_tdata[_uris[2]], 100));

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

TEST_F(SCSCFTest, TestForkedFlow3)
{
  SCOPED_TRACE("");
  pjsip_msg* out;
  Message msg;
  setupForkedFlow(msg);
  ASSERT_EQ(3u, _tdata.size());

  // Send 183 back from one of them
  inject_msg(respond_to_txdata(_tdata[_uris[0]], 183));
  // 183 goes back
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(183).matches(out);
  free_txdata();

  // Send final error from another of them
  inject_msg(respond_to_txdata(_tdata[_uris[1]], 404));
  poll();

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

TEST_F(SCSCFTest, TestForkedFlow4)
{
  SCOPED_TRACE("");
  Message msg;
  setupForkedFlow(msg);
  ASSERT_EQ(3u, _tdata.size());

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
  ASSERT_EQ(1, txdata_count());
  RespMatcher(200).matches(current_txdata()->msg);
  free_txdata();

  // No CANCEL sent immediately because target 2 hasn't sent a response.
  ASSERT_EQ(0, txdata_count());

  // Send in a 100 Trying from target 2
  inject_msg(respond_to_txdata(_tdata[_uris[2]], 100));

  // Gets passed through to target 2
  ASSERT_EQ(1, txdata_count());
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

// Test SIP Message flows
TEST_F(SCSCFTest, TestSIPMessageSupport)
{
  SCOPED_TRACE("");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");

  Message msg;
  msg._via = "10.99.88.11:12345";
  pjsip_msg* out;
  pjsip_tx_data* message = NULL;

  // Send MESSAGE
  SCOPED_TRACE("MESSAGE");
  msg._method = "MESSAGE";
  inject_msg(msg.get_request(), _tp_default);
  poll();

  // MESSAGE passed on
  SCOPED_TRACE("MESSAGE (S)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("MESSAGE").matches(out));
  _tp_default->expect_target(current_txdata(), false);

   message = pop_txdata();

   // Send 200 OK back
  SCOPED_TRACE("200 OK (MESSAGE)");
  inject_msg(respond_to_txdata(message, 200), _tp_default);
  ASSERT_EQ(1, txdata_count());

  // OK goes back
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  _tp_default->expect_target(current_txdata(), true);

  free_txdata();
}

// Test that a multipart message can be parsed successfully
TEST_F(SCSCFTest, TestSimpleMultipart)
{
  SCOPED_TRACE("");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  Message msg;
  msg._content_type = "multipart/mixed;boundary=\"boundary1\"";
  msg._body = "\r\n--boundary1\r\nContent-Type: application/sdp\r\nContent-Length: 343\r\n\r\nv=0\r\no=- 3600506724 3600506724 IN IP4 888.888.888.888\r\n" \
              "s=-\r\nc=IN IP4 888.888.888.888\r\nt=0 0\r\nm=message 9 TCP/MSRP *\r\na=path:msrp://888.888.888.888:7777/1391517924073;tcp\r\n" \
              "a=setup:active\r\na=accept-types:message/cpim application/im-iscomposing+xml\r\na=accept-wrapped-types:text/plain message/imdn+xml " \
              "application/rcspushlocation+xml\r\na=sendrecv\r\n\r\n--boundary1\r\nContent-Type: message/cpim\r\nContent-Length: 300\r\n\r\nFrom: " \
              "<sip:anonymous@anonymous.invalid>\r\nTo: <sip:anonymous@anonymous.invalid>\r\nNS: imdn <urn:ietf:params:imdn>\r\nimdn.Message-ID: " \
              "Msg6rn78PUQzC\r\nDateTime: 2014-02-04T12:45:24.000Z\r\nimdn.Disposition-Notification: positive-delivery, display\r\n\r\nContent-type: " \
              "text/plain; charset=utf-8\r\n\r\nsubject\r\n\r\n--boundary1--";

  list<HeaderMatcher> hdrs;
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs);
}

// Test emergency registrations receive calls.
TEST_F(SCSCFTest, TestReceiveCallToEmergencyBinding)
{
  SCOPED_TRACE("");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;sos;ob");
  Message msg;

  pjsip_msg* out;

  // Send INVITE
  inject_msg(msg.get_request());
  ASSERT_EQ(3, txdata_count());

  // 100 Trying goes back
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  free_txdata();

  // Collect INVITEs
  for (int i = 0; i < 2; i++)
  {
    out = current_txdata()->msg;
    ReqMatcher req("INVITE");
    req.matches(out);
    _uris.push_back(req.uri());
    _tdata[req.uri()] = pop_txdata();
  }

  EXPECT_TRUE(_tdata.find("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob") != _tdata.end());
  EXPECT_TRUE(_tdata.find("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;sos;ob") != _tdata.end());
}

// Test basic ISC (AS) flow.
TEST_F(SCSCFTest, SimpleISCMainline)
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", "UNREGISTERED",
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>"
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
                                "</ServiceProfile></IMSSubscription>");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";

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
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig>"));
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

// Test handling of IFC with a malformed AS URI.
TEST_F(SCSCFTest, ISCASURIMalformed)
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", "UNREGISTERED",
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>"
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
                                "    <ServerName>sip::5060</ServerName>\n"
                                "    <DefaultHandling>0</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile></IMSSubscription>");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();

  // INVITE rejected with 502 Bad Gateway response.
  out = current_txdata()->msg;
  RespMatcher(502).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();
}

// Test handling of IFC with a AS Tel URI.
TEST_F(SCSCFTest, ISCASURITel)
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", "UNREGISTERED",
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>"
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
                                "    <ServerName>tel:1234</ServerName>\n"
                                "    <DefaultHandling>0</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile></IMSSubscription>");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();

  // INVITE rejected with 502 Bad Gateway response.
  out = current_txdata()->msg;
  RespMatcher(502).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();
}

// Test basic ISC (AS) flow with a single "Next" on the originating side.
TEST_F(SCSCFTest, SimpleNextOrigFlow)
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>"
                                "  <InitialFilterCriteria>\n"
                                "    <Priority>0</Priority>\n"
                                "    <TriggerPoint>\n"
                                "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                                "    <SPT>\n"
                                "      <ConditionNegated>0</ConditionNegated>\n"
                                "      <Group>0</Group>\n"
                                "      <Method>ETAOIN_SHRDLU</Method>\n"
                                "      <Extension></Extension>\n"
                                "    </SPT>\n"
                                "  </TriggerPoint>\n"
                                "  <ApplicationServer>\n"
                                "    <ServerName>sip:linotype.example.org</ServerName>\n"
                                "    <DefaultHandling>0</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
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
                                "</ServiceProfile></IMSSubscription>");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

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
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig>"));

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
TEST_F(SCSCFTest, SimpleReject)
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505551234@homedomain</Identity></PublicIdentity>"
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
                                   "</ServiceProfile></IMSSubscription>");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";
  msg._route = "Route: <sip:homedomain;orig>";

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
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr>"));

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


// Test basic ISC (AS) terminating-only flow: call comes from non-local user.
TEST_F(SCSCFTest, SimpleNonLocalReject)
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505551234@homedomain</Identity></PublicIdentity>"
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
                                "</ServiceProfile></IMSSubscription>");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._fromdomain = "remote-base.mars.int";
  msg._requri = "sip:6505551234@homedomain";

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
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr>"));

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
TEST_F(SCSCFTest, SimpleAccept)
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505551234@homedomain</Identity></PublicIdentity>"
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
                                "</ServiceProfile></IMSSubscription>");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";
  msg._route = "Route: <sip:homedomain;orig>";

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
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr>"));

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
TEST_F(SCSCFTest, SimpleRedirect)
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505551234@homedomain</Identity></PublicIdentity>"
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
                                "</ServiceProfile></IMSSubscription>");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";
  msg._route = "Route: <sip:homedomain;orig>";

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
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr>"));

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


// Test DefaultHandling=TERMINATE for non-responsive AS.
TEST_F(SCSCFTest, DefaultHandlingTerminate)
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505551234@homedomain</Identity></PublicIdentity>"
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
                                "    <DefaultHandling>1</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile></IMSSubscription>");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._fromdomain = "remote-base.mars.int";
  msg._requri = "sip:6505551234@homedomain";
  msg._route = "Route: <sip:homedomain>";

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
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr>"));

  // ---------- AS1 rejects it with a 408 error.
  string fresp = respond_to_txdata(current_txdata(), 408);
  free_txdata();
  inject_msg(fresp, &tpAS1);

  // ACK goes back to AS1
  SCOPED_TRACE("ACK");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("ACK").matches(out));
  free_txdata();

  // 408 response goes back to bono
  SCOPED_TRACE("408");
  out = current_txdata()->msg;
  RespMatcher(408).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  msg._cseq++;
  free_txdata();

  // ---------- Send ACK from bono
  SCOPED_TRACE("ACK");
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpBono);
}


// Disabled because terminated default handling is broken at the moment.
TEST_F(SCSCFTest, DISABLED_DefaultHandlingTerminateTimeout)
{
  // Register an endpoint to act as the callee.
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");

  // Set up an application server for the caller. It's default handling is set
  // to session continue.
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", "UNREGISTERED",
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>"
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
                                "    <ServerName>sip:1.2.3.4:56789;transport=tcp</ServerName>\n"
                                "    <DefaultHandling>1</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile></IMSSubscription>");

  TransportFlow tpCaller(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::TCP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpCallee(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.114.61.213", 5061);

  // Caller sends INVITE
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to caller
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to AS
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  free_txdata();

  // Advance time without receiving a response. The application server is
  // bypassed.
  cwtest_advance_time_ms(6000);

  // 408 received at callee.
  poll();
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(408).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();

  // Caller ACKs error response.
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(1, txdata_count());
}


// Disabled because terminated default handling is broken at the moment.
TEST_F(SCSCFTest, DefaultHandlingTerminateDisabled)
{
  // Disable the liveness timer for session terminated ASs.
  _scscf_sproutlet->set_session_terminated_timeout(0);

  // Register an endpoint to act as the callee.
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");

  // Set up an application server for the caller. It's default handling is set
  // to session continue.
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", "UNREGISTERED",
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>"
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
                                "    <ServerName>sip:1.2.3.4:56789;transport=tcp</ServerName>\n"
                                "    <DefaultHandling>1</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile></IMSSubscription>");

  TransportFlow tpCaller(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::TCP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpCallee(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.114.61.213", 5061);

  // Caller sends INVITE
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to caller
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to AS
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  free_txdata();

  // Advance time without receiving a response. Nothing happens straight away.
  cwtest_advance_time_ms(6000);
  poll();
  ASSERT_EQ(0, txdata_count());

  // After another 26s the AS transaction times out and the call fails.
  cwtest_advance_time_ms(26000);
  poll();
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(408).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();

  // Caller ACKs error response.
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(0, txdata_count());
}


// Test DefaultHandling=CONTINUE for non-existent AS (where name does not resolve).
TEST_F(SCSCFTest, DefaultHandlingContinueNonExistent)
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  register_uri(_store, _hss_connection, "6505551000", "homedomain", "sip:who@example.net");
  _hss_connection->set_impu_result("sip:6505551234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505551234@homedomain</Identity></PublicIdentity>"
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
                                "    <ServerName>sip:ne-as:56789;transport=UDP</ServerName>\n"
                                "    <DefaultHandling>0</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile></IMSSubscription>");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";
  msg._route = "Route: <sip:homedomain;orig>";

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

  // AS name fails to resolve, so INVITE passed on to final destination
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));

  tpBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r2.uri());
  EXPECT_EQ("", get_headers(out, "Route"));

  free_txdata();
}


// Test DefaultHandling=CONTINUE for non-responsive AS.
TEST_F(SCSCFTest, DefaultHandlingContinueNonResponsive)
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  register_uri(_store, _hss_connection, "6505551000", "homedomain", "sip:who@example.net");
  _hss_connection->set_impu_result("sip:6505551234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505551234@homedomain</Identity></PublicIdentity>"
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
                                "</ServiceProfile></IMSSubscription>");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";
  msg._route = "Route: <sip:homedomain;orig>";

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
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr>"));

  // ---------- AS1 rejects it with a 408 error.
  string fresp = respond_to_txdata(current_txdata(), 408);
  free_txdata();
  inject_msg(fresp, &tpAS1);

  // ACK goes back to AS1
  SCOPED_TRACE("ACK");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("ACK").matches(out));
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


// Test DefaultHandling=CONTINUE for a responsive AS that returns an error.
TEST_F(SCSCFTest, DefaultHandlingContinueResponsiveError)
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
    _hss_connection->set_impu_result("sip:6505551234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505551234@homedomain</Identity></PublicIdentity>"
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
                                "</ServiceProfile></IMSSubscription>");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";
  msg._route = "Route: <sip:homedomain;orig>";

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
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr>"));

  // ---------- AS1 sends a 100 Trying to indicate it has received the request.
  // This will disable the default handling.
  string fresp = respond_to_txdata(current_txdata(), 100);
  inject_msg(fresp, &tpAS1);

  // ---------- AS1 now rejects the request with a 500 response.  This gets
  // returned to the caller because the 100 Trying indicated the AS is live.
  fresp = respond_to_txdata(current_txdata(), 500);
  free_txdata();
  inject_msg(fresp, &tpAS1);

  // ACK goes back to AS1
  SCOPED_TRACE("ACK");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("ACK").matches(out));
  free_txdata();

  // 500 response goes back to bono
  SCOPED_TRACE("500");
  out = current_txdata()->msg;
  RespMatcher(500).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  msg._cseq++;
  free_txdata();

  // ---------- Send ACK from bono
  SCOPED_TRACE("ACK");
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpBono);
}


TEST_F(SCSCFTest, DefaultHandlingContinueTimeout)
{
  // Register an endpoint to act as the callee.
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");

  // Set up an application server for the caller. It's default handling is set
  // to session continue.
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", "UNREGISTERED",
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>"
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
                                "    <ServerName>sip:1.2.3.4:56789;transport=tcp</ServerName>\n"
                                "    <DefaultHandling>0</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile></IMSSubscription>");

  TransportFlow tpCaller(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::TCP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpCallee(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.114.61.213", 5061);

  // Caller sends INVITE
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to caller
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to AS
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  free_txdata();

  // Advance time without receiving a response. The application server is
  // bypassed.
  cwtest_advance_time_ms(3000);

  // INVITE is sent to the callee.
  poll();
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));
  tpCallee.expect_target(current_txdata(), true);

  // Callee sends 200 OK.
  inject_msg(respond_to_txdata(current_txdata(), 200, "", ""), &tpCallee);
  free_txdata();

  // 200 OK received at callee.
  poll();
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();
}

TEST_F(SCSCFTest, DefaultHandlingContinueDisabled)
{
  // Set the session continue timer to 0 to disable it.
  _scscf_sproutlet->set_session_continued_timeout(0);

  // Register an endpoint to act as the callee.
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");

  // Set up an application server for the caller. It's default handling is set
  // to session continue.
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", "UNREGISTERED",
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>"
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
                                "    <ServerName>sip:1.2.3.4:56789;transport=tcp</ServerName>\n"
                                "    <DefaultHandling>0</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile></IMSSubscription>");

  TransportFlow tpCaller(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::TCP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpCallee(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.114.61.213", 5061);

  // Caller sends INVITE
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpCaller);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to caller
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to AS
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  free_txdata();

  // Advance time without receiving a response. The liveness time is not
  // running which means the AS is not immediately bypassed.
  cwtest_advance_time_ms(3000);
  poll();
  ASSERT_EQ(0, txdata_count());

  // After another 29s the AS transaction times out and the INVITE is sent to
  // the callee.
  cwtest_advance_time_ms(29000);
  poll();

  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));
  tpCallee.expect_target(current_txdata(), true);

  // Callee sends 200 OK.
  inject_msg(respond_to_txdata(current_txdata(), 200, "", ""), &tpCallee);
  free_txdata();

  // 200 OK received at callee.
  poll();
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpCaller.expect_target(current_txdata(), true);  // Requests always come back on same transport
  free_txdata();
}


// Test DefaultHandling attribute missing.
TEST_F(SCSCFTest, DefaultHandlingMissing)
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  register_uri(_store, _hss_connection, "6505551000", "homedomain", "sip:who@example.net");
  _hss_connection->set_impu_result("sip:6505551234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505551234@homedomain</Identity></PublicIdentity>"
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
                                "    <ServerName>sip:ne-as:56789;transport=UDP</ServerName>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile></IMSSubscription>");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";
  msg._route = "Route: <sip:homedomain;orig>";

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

  // AS name fails to resolve, so INVITE passed on to final destination
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));

  tpBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r2.uri());
  EXPECT_EQ("", get_headers(out, "Route"));

  free_txdata();
}


// Test DefaultHandling attribute malformed.
TEST_F(SCSCFTest, DefaultHandlingMalformed)
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  register_uri(_store, _hss_connection, "6505551000", "homedomain", "sip:who@example.net");
  _hss_connection->set_impu_result("sip:6505551234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505551234@homedomain</Identity></PublicIdentity>"
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
                                "    <ServerName>sip:ne-as:56789;transport=UDP</ServerName>\n"
                                "    <DefaultHandling>frog</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile></IMSSubscription>");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";
  msg._route = "Route: <sip:homedomain;orig>";

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

  // AS name fails to resolve, so INVITE passed on to final destination
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ReqMatcher r2("INVITE");
  ASSERT_NO_FATAL_FAILURE(r2.matches(out));

  tpBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r2.uri());
  EXPECT_EQ("", get_headers(out, "Route"));

  free_txdata();
}


// Test more interesting ISC (AS) flow.
TEST_F(SCSCFTest, InterestingAs)
{
}

// Test that when Sprout is configured to Record-Route itself only at
// the start and end of all processing, it does.
TEST_F(SCSCFTest, RecordRoutingTest)
{
  // Expect 2 Record-Routes:
  // - on start of originating handling
  // - AS1's Record-Route
  // - AS2's Record-Route
  // - AS3's Record-Route
  // - AS4's Record-Route
  // - on end of terminating handling

  doFourAppServerFlow("Record-Route: <sip:homedomain:5058;lr;service=scscf;billing-role=charge-term>\r\n"
                      "Record-Route: <sip:6.2.3.4>\r\n"
                      "Record-Route: <sip:5.2.3.4>\r\n"
                      "Record-Route: <sip:4.2.3.4>\r\n"
                      "Record-Route: <sip:1.2.3.4>\r\n"
                      "Record-Route: <sip:homedomain:5058;lr;service=scscf;billing-role=charge-orig>", true);
  free_txdata();
}

// Test that when Sprout is configured to Record-Route itself at
// the start and end of terminating and originating processing, it does.
TEST_F(SCSCFTest, RecordRoutingTestStartAndEnd)
{
  stack_data.record_route_on_completion_of_originating = true;
  stack_data.record_route_on_initiation_of_terminating = true;

  // Expect 2 Record-Routes:
  // - on start of originating handling
  // - AS1's Record-Route
  // - AS2's Record-Route
  // - on end of originating handling/on start of terminating handling
  // (collapsed together as they're identical)
  // - AS3's Record-Route
  // - AS4's Record-Route
  // - on end of terminating handling

  doFourAppServerFlow("Record-Route: <sip:homedomain:5058;lr;service=scscf;billing-role=charge-term>\r\n"
                      "Record-Route: <sip:6.2.3.4>\r\n"
                      "Record-Route: <sip:5.2.3.4>\r\n"
                      "Record-Route: <sip:homedomain:5058;lr;service=scscf;billing-role=charge-term>\r\n"
                      "Record-Route: <sip:homedomain:5058;lr;service=scscf;billing-role=charge-orig>\r\n"
                      "Record-Route: <sip:4.2.3.4>\r\n"
                      "Record-Route: <sip:1.2.3.4>\r\n"
                      "Record-Route: <sip:homedomain:5058;lr;service=scscf;billing-role=charge-orig>", true);
  stack_data.record_route_on_completion_of_originating = false;
  stack_data.record_route_on_initiation_of_terminating = false;
}


// Test that when Sprout is configured to Record-Route itself on each
// hop, it does.
TEST_F(SCSCFTest, RecordRoutingTestEachHop)
{
  // Simulate record-routing model 3, which sets all the record-routing flags.
  stack_data.record_route_on_initiation_of_terminating = true;
  stack_data.record_route_on_completion_of_originating = true;
  stack_data.record_route_on_diversion = true;
  stack_data.record_route_on_every_hop = true;

  // Expect 9 Record-Routes:
  // - between the endpoint and AS1
  // - AS1's Record-Route
  // - between AS1 and AS2
  // - AS2's Record-Route
  // - between AS2 and AS3
  // - AS3's Record-Route
  // - between AS3 and AS4
  // - AS4's Record-Route
  // - between AS4 and the endpoint

  // In reality we'd expect 10 (instead of having one between AS2 and
  // AS3, we'd have two - one for conclusion of originating processing
  // and one for initiation of terminating processing) but we don't
  // split originating and terminating handling like that yet.
  doFourAppServerFlow("Record-Route: <sip:homedomain:5058;lr;service=scscf;billing-role=charge-term>\r\n"
                      "Record-Route: <sip:6.2.3.4>\r\n"
                      "Record-Route: <sip:homedomain:5058;lr;service=scscf;billing-role=charge-term>\r\n"
                      "Record-Route: <sip:5.2.3.4>\r\n"
                      "Record-Route: <sip:homedomain:5058;lr;service=scscf;billing-role=charge-term>\r\n"
                      "Record-Route: <sip:homedomain:5058;lr;service=scscf;billing-role=charge-orig>\r\n"
                      "Record-Route: <sip:4.2.3.4>\r\n"
                      "Record-Route: <sip:homedomain:5058;lr;service=scscf;billing-role=charge-orig>\r\n"
                      "Record-Route: <sip:1.2.3.4>\r\n"
                      "Record-Route: <sip:homedomain:5058;lr;service=scscf;billing-role=charge-orig>", true);

  stack_data.record_route_on_initiation_of_terminating = false;
  stack_data.record_route_on_completion_of_originating = false;
  stack_data.record_route_on_diversion = false;
  stack_data.record_route_on_every_hop = false;
}

// Test that Sprout only adds a single Record-Route if none of the Ases
// Record-Route themselves.
TEST_F(SCSCFTest, RecordRoutingTestCollapse)
{
  // Expect 1 Record-Route
  doFourAppServerFlow("Record-Route: <sip:homedomain:5058;lr;service=scscf;billing-role=charge-term>\r\n"
                      "Record-Route: <sip:homedomain:5058;lr;service=scscf;billing-role=charge-orig>", false);
}

// Test that even when Sprout is configured to Record-Route itself on each
// hop, it only adds a single Record-Route if none of the Ases
// Record-Route themselves.
TEST_F(SCSCFTest, RecordRoutingTestCollapseEveryHop)
{
  stack_data.record_route_on_every_hop = true;
  // Expect 1 Record-Route
  doFourAppServerFlow("Record-Route: <sip:homedomain:5058;lr;service=scscf;billing-role=charge-term>\r\n"
                      "Record-Route: <sip:homedomain:5058;lr;service=scscf;billing-role=charge-term>\r\n"
                      "Record-Route: <sip:homedomain:5058;lr;service=scscf;billing-role=charge-orig>\r\n"
                      "Record-Route: <sip:homedomain:5058;lr;service=scscf;billing-role=charge-orig>\r\n"
                      "Record-Route: <sip:homedomain:5058;lr;service=scscf;billing-role=charge-orig>", false);
  stack_data.record_route_on_every_hop = false;
}

// Test AS-originated flow.
void SCSCFTest::doAsOriginated(Message& msg, bool expect_orig)
{
  doAsOriginated(msg.get_request(), expect_orig);
}

void SCSCFTest::doAsOriginated(const std::string& msg, bool expect_orig)
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                "<IMSSubscription><ServiceProfile>"
                                "<PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>"
                                  "<InitialFilterCriteria>"
                                    "<Priority>1</Priority>"
                                    "<TriggerPoint>"
                                    "<ConditionTypeCNF>0</ConditionTypeCNF>"
                                    "<SPT>"
                                      "<ConditionNegated>0</ConditionNegated>"
                                      "<Group>0</Group>"
                                      "<Method>INVITE</Method>"
                                      "<Extension></Extension>"
                                    "</SPT>"
                                  "</TriggerPoint>"
                                  "<ApplicationServer>"
                                    "<ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>"
                                    "<DefaultHandling>0</DefaultHandling>"
                                  "</ApplicationServer>"
                                  "</InitialFilterCriteria>"
                                "</ServiceProfile></IMSSubscription>");
  _hss_connection->set_impu_result("sip:6505551234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                "<IMSSubscription><ServiceProfile>"
                                "<PublicIdentity><Identity>sip:6505551234@homedomain</Identity></PublicIdentity>"
                                  "<InitialFilterCriteria>"
                                    "<Priority>0</Priority>"
                                    "<TriggerPoint>"
                                    "<ConditionTypeCNF>0</ConditionTypeCNF>"
                                    "<SPT>"
                                      "<ConditionNegated>0</ConditionNegated>"
                                      "<Group>0</Group>"
                                      "<Method>INVITE</Method>"
                                      "<Extension></Extension>"
                                    "</SPT>"
                                  "</TriggerPoint>"
                                  "<ApplicationServer>"
                                    "<ServerName>sip:5.2.3.4:56787;transport=UDP</ServerName>"
                                    "<DefaultHandling>0</DefaultHandling>"
                                  "</ApplicationServer>"
                                  "</InitialFilterCriteria>"
                                "</ServiceProfile></IMSSubscription>");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS0(TransportFlow::Protocol::UDP, stack_data.scscf_port, "6.2.3.4", 56786);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpAS2(TransportFlow::Protocol::UDP, stack_data.scscf_port, "5.2.3.4", 56787);

  // ---------- Send spontaneous INVITE from AS0.
  inject_msg(msg, &tpAS0);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to AS0
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS0.expect_target(current_txdata(), true);  // Requests always come back on same transport
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
                testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig>"));

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
    free_txdata();
  }

  // INVITE passed on to AS2
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS2.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr>"));

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
TEST_F(SCSCFTest, AsOriginatedOrig)
{
  // ---------- Send spontaneous INVITE from AS0, marked as originating-handling-required.
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
//  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";

  SCOPED_TRACE("orig");
  doAsOriginated(msg, true);
}


// Test AS-originated flow - term.
TEST_F(SCSCFTest, AsOriginatedTerm)
{
  // ---------- Send spontaneous INVITE from AS0, marked as terminating-handling-only.
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
//  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._requri = "sip:6505551234@homedomain";
  msg._route = "Route: <sip:homedomain>";

  msg._method = "INVITE";

  SCOPED_TRACE("term");
  doAsOriginated(msg, false);
}


// Test call-diversion AS flow.
TEST_F(SCSCFTest, Cdiv)
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  register_uri(_store, _hss_connection, "6505551000", "homedomain", "sip:wuntootree@10.14.61.213:5061;transport=tcp;ob");
  register_uri(_store, _hss_connection, "6505555678", "homedomain", "sip:andunnuvvawun@10.114.61.214:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                R"(<IMSSubscription><ServiceProfile>
                                <PublicIdentity><Identity>sip:6505551234@homedomain</Identity></PublicIdentity>
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
                                </ServiceProfile></IMSSubscription>)");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "5.2.3.4", 56787);
  TransportFlow tpAS2(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

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
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr>"));
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
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig>"));
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

// Test that ENUM lookups and appropriate URI translation is done before any terminating services are applied.
TEST_F(SCSCFTest, BothEndsWithEnumRewrite)
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
    _hss_connection->set_impu_result("sip:6505551234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                               R"(<IMSSubscription><ServiceProfile>
                                  <PublicIdentity><Identity>sip:6505551234@homedomain</Identity></PublicIdentity>
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
                                </ServiceProfile></IMSSubscription>)");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "5.2.3.4", 56787);

  _scscf_sproutlet->set_enforce_user_phone(false);
  _scscf_sproutlet->set_global_only_lookups(false);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "1115551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._requri = "sip:1115551234@homedomain";

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

  // These fields of the message will only be filled in correctly if we have
  // done an ENUM lookup before applying terminating services, and correctly
  // recognised that "1115551234" is "6505551234".

  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551234@homedomain>;sescase=term;regstate=reg"));

  free_txdata();
}

// Test that ENUM lookups are not done if we are only doing
// terminating processing.
TEST_F(SCSCFTest, TerminatingWithNoEnumRewrite)
{
  register_uri(_store, _hss_connection, "1115551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
    _hss_connection->set_impu_result("sip:1115551234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                R"(<IMSSubscription><ServiceProfile>
                                  <PublicIdentity><Identity>sip:1115551234@homedomain</Identity></PublicIdentity>
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
                                </ServiceProfile></IMSSubscription>)");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "5.2.3.4", 56787);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "1115551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:homedomain>";
  msg._requri = "sip:1115551234@homedomain";

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

  // These fields of the message will only be filled in correctly if we have
  // not done an ENUM lookup before applying terminating services (as
  // ENUM is only applied when originating)

  EXPECT_EQ("sip:1115551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:1115551234@homedomain>;sescase=term;regstate=reg"));

  free_txdata();
}


// Test call-diversion AS flow, where MMTEL does the diversion.
TEST_F(SCSCFTest, MmtelCdiv)
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  register_uri(_store, _hss_connection, "6505555678", "homedomain", "sip:andunnuvvawun@10.114.61.214:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                R"(<IMSSubscription><ServiceProfile>
                                <PublicIdentity><Identity>sip:6505551234@homedomain</Identity></PublicIdentity>
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
                                    <ServerName>sip:mmtel.homedomain</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                </ServiceProfile></IMSSubscription>)");
  _xdm_connection->put("sip:6505551234@homedomain",
                       R"(<?xml version="1.0" encoding="UTF-8"?>
                          <simservs xmlns="http://uri.etsi.org/ngn/params/xml/simservs/xcap" xmlns:cp="urn:ietf:params:xml:ns:common-policy">
                            <originating-identity-presentation active="false" />
                            <originating-identity-presentation-restriction active="false">
                              <default-behaviour>presentation-restricted</default-behaviour>
                            </originating-identity-presentation-restriction>
                            <communication-diversion active="true">
                              <NoReplyTimer>19</NoReplyTimer>"
                                <cp:ruleset>
                                  <cp:rule id="rule1">
                                    <cp:conditions/>
                                    <cp:actions><forward-to><target>sip:6505555678@homedomain</target></forward-to></cp:actions>
                                  </cp:rule>
                                </cp:ruleset>
                              </communication-diversion>
                            <incoming-communication-barring active="false"/>
                            <outgoing-communication-barring active="false"/>
                          </simservs>)");  // "
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS2(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(3, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE goes to MMTEL as terminating AS for Bob, and is redirected to 6505555678.
  ReqMatcher r1("INVITE");
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr;

  // 181 Call is being forwarded goes back to bono
  out = current_txdata()->msg;
  RespMatcher(181).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to AS2 (as originating AS for Bob)
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS2.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505555678@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551234@homedomain>;sescase=orig-cdiv"));
  EXPECT_THAT(get_headers(out, "History-Info"),
              testing::MatchesRegex("History-Info: <sip:6505551234@homedomain;text=Temporarily%20Unavailable;cause=480;Reason=SIP>;index=1\r\nHistory-Info: <sip:6505555678@homedomain>;index=1.1"));

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
  EXPECT_THAT(get_headers(out, "History-Info"),
              testing::MatchesRegex("History-Info: <sip:6505551234@homedomain;text=Temporarily%20Unavailable;cause=480;Reason=SIP>;index=1\r\nHistory-Info: <sip:6505555678@homedomain>;index=1.1"));

  free_txdata();
}


// Test call-diversion AS flow, where MMTEL does the diversion - twice.
TEST_F(SCSCFTest, MmtelDoubleCdiv)
{
  register_uri(_store, _hss_connection, "6505559012", "homedomain", "sip:andunnuvvawun@10.114.61.214:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551234@homedomain", "call", "UNREGISTERED",
                                R"(<IMSSubscription><ServiceProfile>
                                <PublicIdentity><Identity>sip:6505551234@homedomain</Identity></PublicIdentity>
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
                                      <SessionCase>2</SessionCase>  <!-- terminating-unregistered -->
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:mmtel.homedomain</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                </ServiceProfile></IMSSubscription>)");
  _xdm_connection->put("sip:6505551234@homedomain",
                       R"(<?xml version="1.0" encoding="UTF-8"?>
                          <simservs xmlns="http://uri.etsi.org/ngn/params/xml/simservs/xcap" xmlns:cp="urn:ietf:params:xml:ns:common-policy">
                            <originating-identity-presentation active="false" />
                            <originating-identity-presentation-restriction active="false">
                              <default-behaviour>presentation-restricted</default-behaviour>
                            </originating-identity-presentation-restriction>
                            <communication-diversion active="true">
                              <NoReplyTimer>19</NoReplyTimer>"
                                <cp:ruleset>
                                  <cp:rule id="rule1">
                                    <cp:conditions/>
                                    <cp:actions><forward-to><target>sip:6505555678@homedomain</target></forward-to></cp:actions>
                                  </cp:rule>
                                </cp:ruleset>
                              </communication-diversion>
                            <incoming-communication-barring active="false"/>
                            <outgoing-communication-barring active="false"/>
                          </simservs>)");  // "
  _hss_connection->set_impu_result("sip:6505555678@homedomain", "call", "UNREGISTERED",
                                R"(<IMSSubscription><ServiceProfile>
                                <PublicIdentity><Identity>sip:6505555678@homedomain</Identity></PublicIdentity>
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
                                      <SessionCase>2</SessionCase>  <!-- terminating-unregistered -->
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:mmtel.homedomain</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                </ServiceProfile></IMSSubscription>)");
  _xdm_connection->put("sip:6505555678@homedomain",
                       R"(<?xml version="1.0" encoding="UTF-8"?>
                          <simservs xmlns="http://uri.etsi.org/ngn/params/xml/simservs/xcap" xmlns:cp="urn:ietf:params:xml:ns:common-policy">
                            <originating-identity-presentation active="false" />
                            <originating-identity-presentation-restriction active="false">
                              <default-behaviour>presentation-restricted</default-behaviour>
                            </originating-identity-presentation-restriction>
                            <communication-diversion active="true">
                              <NoReplyTimer>19</NoReplyTimer>"
                                <cp:ruleset>
                                  <cp:rule id="rule1">
                                    <cp:conditions/>
                                    <cp:actions><forward-to><target>sip:6505559012@homedomain</target></forward-to></cp:actions>
                                  </cp:rule>
                                </cp:ruleset>
                              </communication-diversion>
                            <incoming-communication-barring active="false"/>
                            <outgoing-communication-barring active="false"/>
                          </simservs>)");  // "
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS2(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(4, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE goes to MMTEL as terminating AS for Bob, and is redirected to 6505555678.
  ReqMatcher r1("INVITE");
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr;

  // 181 Call is being forwarded goes back to bono
  out = current_txdata()->msg;
  RespMatcher(181).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // Now INVITE is redirected to 6505559012

  // 181 Call is being forwarded goes back to bono
  out = current_txdata()->msg;
  RespMatcher(181).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to AS2 (as originating AS for Bob)
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS2.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505559012@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505555678@homedomain>;sescase=orig-cdiv"));
  EXPECT_THAT(get_headers(out, "History-Info"),
              testing::MatchesRegex("History-Info: <sip:6505551234@homedomain;text=Temporarily%20Unavailable;cause=480;Reason=SIP>;index=1\r\nHistory-Info: <sip:6505555678@homedomain;text=Temporarily%20Unavailable;cause=480;Reason=SIP>;index=1.1\r\nHistory-Info: <sip:6505559012@homedomain>;index=1.1.1"));

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
TEST_F(SCSCFTest, ExpiredChain)
{
  register_uri(_store, _hss_connection, "6505551000", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                "<IMSSubscription><ServiceProfile>"
                                "<PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>"
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
                                "</ServiceProfile></IMSSubscription>");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

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
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig>"));

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

  char buf[65535];
  pj_ssize_t len = pjsip_msg_print(saved, buf, sizeof(buf));
  doAsOriginated(string(buf, len), true);
}

#if 0
// Test a simple MMTEL flow.
TEST_F(SCSCFTest, MmtelFlow)
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                R"(<IMSSubscription><ServiceProfile>
                                <PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>
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
                                </ServiceProfile></IMSSubscription>)");
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
  _hss_connection->set_impu_result("sip:6505551234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                R"(<IMSSubscription><ServiceProfile>
                                <PublicIdentity><Identity>sip:6505551234@homedomain</Identity></PublicIdentity>
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
                                </ServiceProfile></IMSSubscription>)");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "5.2.3.4", 56787);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

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
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr>"));
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


/// Test MMTEL-then-external-AS flows (both orig and term).
//
// Flow:
//
// * 6505551000 calls 6505551234
// * 6505551000 originating:
//     * MMTEL is invoked, applying privacy
//     * external AS1 (1.2.3.4:56789) is invoked
// * 6505551234 terminating:
//     * MMTEL is invoked, applying privacy
//     * external AS2 (5.2.3.4:56787) is invoked
// * call reaches registered contact for 6505551234.
//
TEST_F(SCSCFTest, MmtelThenExternal)
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", "UNREGISTERED",
                                R"(<IMSSubscription><ServiceProfile>
                                <PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>
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
                                </ServiceProfile></IMSSubscription>)");
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
    _hss_connection->set_impu_result("sip:6505551234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                R"(<IMSSubscription><ServiceProfile>
                                <PublicIdentity><Identity>sip:6505551234@homedomain</Identity></PublicIdentity>
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
                                </ServiceProfile></IMSSubscription>)");
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

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpAS2(TransportFlow::Protocol::UDP, stack_data.scscf_port, "5.2.3.4", 56787);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

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
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig>"));
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
  // @@@KSW Work around https://github.com/Metaswitch/sprout/issues/43
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_PRIVACY, NULL);
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
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr>"));
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
  // @@@KSW Work around https://github.com/Metaswitch/sprout/issues/43: omit: EXPECT_EQ("Privacy: id, header, user", get_headers(out, "Privacy"));

  free_txdata();
}


/// Test multiple-MMTEL flow.
// Flow:
//
// * 6505551000 calls 6505551234
// * 6505551000 originating:
//     * MMTEL is invoked, applying privacy
//     * MMTEL is invoked, applying privacy
// * 6505551234 terminating:
//     * MMTEL is invoked, applying privacy
//     * MMTEL is invoked, applying privacy
//     * external AS1 (5.2.3.4:56787) is invoked
// * call reaches registered contact for 6505551234.
//
TEST_F(SCSCFTest, DISABLED_MultipleMmtelFlow)  // @@@KSW not working: https://github.com/Metaswitch/sprout/issues/44
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                R"(<IMSSubscription><ServiceProfile>
                                <PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>
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
                                </ServiceProfile></IMSSubscription>)");
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
  _hss_connection->set_impu_result("sip:6505551234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                R"(<IMSSubscription><ServiceProfile>
                                <PublicIdentity><Identity>sip:6505551234@homedomain</Identity></PublicIdentity>
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
                                </ServiceProfile></IMSSubscription>)");
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

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "5.2.3.4", 56787);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

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
              testing::MatchesRegex("Route: <sip:5\\.2\\.3\\.4:56787;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr>"));
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
#endif


// Test basic ISC (AS) OPTIONS final acceptance flow (AS sinks request).
TEST_F(SCSCFTest, SimpleOptionsAccept)
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505551234@homedomain</Identity></PublicIdentity>"
                                "  <InitialFilterCriteria>\n"
                                "    <Priority>1</Priority>\n"
                                "    <TriggerPoint>\n"
                                "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                                "    <SPT>\n"
                                "      <ConditionNegated>0</ConditionNegated>\n"
                                "      <Group>0</Group>\n"
                                "      <Method>OPTIONS</Method>\n"
                                "      <Extension></Extension>\n"
                                "    </SPT>\n"
                                "  </TriggerPoint>\n"
                                "  <ApplicationServer>\n"
                                "    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                                "    <DefaultHandling>0</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile></IMSSubscription>");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");

  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS1(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send OPTIONS
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345;transport=TCP";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";

  msg._method = "OPTIONS";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(1, txdata_count());

  // INVITE passed on to AS1
  SCOPED_TRACE("OPTIONS (S)");
  pjsip_msg* out = current_txdata()->msg;
  ReqMatcher r1("OPTIONS");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS1.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr>"));

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
}


// Test terminating call-diversion AS flow to external URI.
// Repros https://github.com/Metaswitch/sprout/issues/519.
TEST_F(SCSCFTest, TerminatingDiversionExternal)
{
  register_uri(_store, _hss_connection, "6505501234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505501234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                R"(<IMSSubscription><ServiceProfile>
                                <PublicIdentity><Identity>sip:6505501234@homedomain</Identity></PublicIdentity>
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
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <SessionCase>1</SessionCase>  <!-- terminating-registered -->
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                </ServiceProfile></IMSSubscription>)");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");

  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  TransportFlow tpBono(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpExternal(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.9.8.7", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345";
  msg._to = "6505501234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._requri = "sip:6505501234@homedomain";
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

  tpAS.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505501234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505501234@homedomain>;sescase=term;regstate=reg"));

  // ---------- AS1 turns it around
  // (acting as routing B2BUA by adding a Via, removing the top Route and changing the target)
  const pj_str_t STR_VIA = pj_str("Via");
  pjsip_via_hdr* via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (via_hdr)
  {
    via_hdr->rport_param = via_hdr->sent_by.port;
  }
  via_hdr = pjsip_via_hdr_create(current_txdata()->pool);
  via_hdr->transport = pj_str("FAKE_UDP");
  via_hdr->sent_by.host = pj_str("1.2.3.4");
  via_hdr->sent_by.port = 56789;
  via_hdr->rport_param = 0;
  via_hdr->branch_param = pj_str("z9hG4bK1234567890");
  pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)via_hdr);
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  ((pjsip_sip_uri*)out->line.req.uri)->host = pj_str("ut.cw-ngv.com");
  inject_msg(out, &tpAS);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed externally
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpExternal.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505501234@ut.cw-ngv.com", r1.uri());
  EXPECT_EQ("", get_headers(out, "Route"));

  // ---------- Externally accepted with 200.
  string fresp = respond_to_txdata(current_txdata(), 200);
  free_txdata();
  inject_msg(fresp, &tpExternal);

  // 200 OK goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);

  // ---------- AS1 forwards 200 (stripping via)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  free_txdata();

  // 200 OK goes back to bono
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();
}


// Test originating AS handling for request to external URI.
TEST_F(SCSCFTest, OriginatingExternal)
{
  register_uri(_store, _hss_connection, "6505501234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                R"(<IMSSubscription><ServiceProfile>
                                <PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>
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
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <SessionCase>0</SessionCase>  <!-- originating-registered -->
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                </ServiceProfile></IMSSubscription>)");
  _hss_connection->set_impu_result("sip:6505501234@homedomain", "call", HSSConnection::STATE_REGISTERED, "");

  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");
  TransportFlow tpBono(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpExternal(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.9.8.7", 5060);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345";
  msg._to = "6505501234@ut.cw-ngv.com";
  msg._todomain = "";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._requri = "sip:6505501234@ut.cw-ngv.com";
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

  // INVITE passed on to AS1 (as originating AS for Alice)
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505501234@ut.cw-ngv.com", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551000@homedomain>;sescase=orig;regstate=reg"));

  // ---------- AS1 turns it around
  // (acting as routing B2BUA by adding a Via, removing the top Route and changing the target)
  const pj_str_t STR_VIA = pj_str("Via");
  pjsip_via_hdr* via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (via_hdr)
  {
    via_hdr->rport_param = via_hdr->sent_by.port;
  }
  via_hdr = pjsip_via_hdr_create(current_txdata()->pool);
  via_hdr->transport = pj_str("FAKE_UDP");
  via_hdr->sent_by.host = pj_str("1.2.3.4");
  via_hdr->sent_by.port = 56789;
  via_hdr->rport_param = 0;
  via_hdr->branch_param = pj_str("z9hG4bK1234567890");
  pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)via_hdr);
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed externally
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpExternal.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505501234@ut.cw-ngv.com", r1.uri());
  EXPECT_EQ("", get_headers(out, "Route"));

  // ---------- Externally accepted with 200.
  string fresp = respond_to_txdata(current_txdata(), 200);
  free_txdata();
  inject_msg(fresp, &tpExternal);

  // 200 OK goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);

  // ---------- AS1 forwards 200 (stripping via)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  free_txdata();

  // 200 OK goes back to bono
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();
}


// Test local call with both originating and terminating ASs.
TEST_F(SCSCFTest, OriginatingTerminatingAS)
{
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                R"(<IMSSubscription><ServiceProfile>
                                <PublicIdentity><Identity>sip:6505551234@homedomain</Identity></PublicIdentity>
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
                                </ServiceProfile></IMSSubscription>)");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                R"(<IMSSubscription><ServiceProfile>
                                <PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>
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
                                </ServiceProfile></IMSSubscription>)");

  TransportFlow tpBono(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";
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

  // INVITE passed on to AS1 (as originating AS for 6505551000)
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551000@homedomain>;sescase=orig;regstate=reg"));

  // ---------- AS1 turns it around
  // (acting as routing B2BUA by adding a Via, and removing the top Route.)
  const pj_str_t STR_VIA = pj_str("Via");
  pjsip_via_hdr* via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (via_hdr)
  {
    via_hdr->rport_param = via_hdr->sent_by.port;
  }
  via_hdr = pjsip_via_hdr_create(current_txdata()->pool);
  via_hdr->transport = pj_str("FAKE_UDP");
  via_hdr->sent_by.host = pj_str("1.2.3.4");
  via_hdr->sent_by.port = 56789;
  via_hdr->rport_param = 0;
  via_hdr->branch_param = pj_str("z9hG4bK1234567890");
  pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)via_hdr);
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to AS1 (as terminating AS for 6505551234)
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  r1 = ReqMatcher("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551234@homedomain>;sescase=term;regstate=reg"));

  // ---------- AS1 turns it around
  // (acting as routing B2BUA by adding a Via, and removing the top Route.)
  via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (via_hdr)
  {
    via_hdr->rport_param = via_hdr->sent_by.port;
  }
  via_hdr = pjsip_via_hdr_create(current_txdata()->pool);
  via_hdr->transport = pj_str("FAKE_UDP");
  via_hdr->sent_by.host = pj_str("1.2.3.4");
  via_hdr->sent_by.port = 56789;
  via_hdr->rport_param = 0;
  via_hdr->branch_param = pj_str("z9hG4bK1234567891"); // Must differ from previous branch
  pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)via_hdr);
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed to terminating UE
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r1.uri());
  EXPECT_EQ("", get_headers(out, "Route"));

  string fresp = respond_to_txdata(current_txdata(), 200);
  free_txdata();
  inject_msg(fresp, &tpBono);

  // 200 OK goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);

  // ---------- AS1 forwards 200 (stripping via)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  free_txdata();

  // 200 OK goes back to AS1 (terminating)
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);

  // ---------- AS1 forwards 200 (stripping via)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  free_txdata();

  // 200 OK goes back to bono
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();
}


// Test local call with both originating and terminating ASs where terminating UE doesn't respond.
TEST_F(SCSCFTest, OriginatingTerminatingASTimeout)
{
  TransportFlow tpBono(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                R"(<IMSSubscription><ServiceProfile>
                                <PublicIdentity><Identity>sip:6505551234@homedomain</Identity></PublicIdentity>
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
                                    <ServerName>sip:1.2.3.4:56789;transport=TCP</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                </ServiceProfile></IMSSubscription>)");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                R"(<IMSSubscription><ServiceProfile>
                                <PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>
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
                                    <ServerName>sip:1.2.3.4:56789;transport=TCP</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                </ServiceProfile></IMSSubscription>)");

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345";
  msg._branch = "1111111111";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";
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

  // INVITE passed on to AS1 (as originating AS for 6505551000)
  SCOPED_TRACE("INVITE (S)");
  pjsip_tx_data* invite_txdata = pop_txdata();
  out = invite_txdata->msg;
  ReqMatcher r1("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  tpAS.expect_target(invite_txdata, false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=TCP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=TCP;lr;orig>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551000@homedomain>;sescase=orig;regstate=reg"));

  // AS1 sends an immediate 100 Trying
  inject_msg(respond_to_txdata(invite_txdata, 100), &tpAS);

  // ---------- AS1 turns INVITE around
  // (acting as routing B2BUA by adding a Via, and removing the top Route.)
  const pj_str_t STR_VIA = pj_str("Via");
  pjsip_via_hdr* via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (via_hdr)
  {
    via_hdr->rport_param = via_hdr->sent_by.port;
  }
  via_hdr = pjsip_via_hdr_create(invite_txdata->pool);
  via_hdr->transport = pj_str("FAKE_UDP");
  via_hdr->sent_by.host = pj_str("1.2.3.4");
  via_hdr->sent_by.port = 56789;
  via_hdr->rport_param = 0;
  via_hdr->branch_param = pj_str("z9hG4bK2222222222");
  pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)via_hdr);
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to AS1 (as terminating AS for 6505551234)
  SCOPED_TRACE("INVITE (S)");
  invite_txdata = pop_txdata();
  out = invite_txdata->msg;
  r1 = ReqMatcher("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  tpAS.expect_target(invite_txdata, false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=TCP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=TCP;lr>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551234@homedomain>;sescase=term;regstate=reg"));

  // AS1 sends an immediate 100 Trying
  inject_msg(respond_to_txdata(invite_txdata, 100), &tpAS);

  // ---------- AS1 turns INVITE around
  // (acting as routing B2BUA by adding a Via, and removing the top Route.)
  via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (via_hdr)
  {
    via_hdr->rport_param = via_hdr->sent_by.port;
  }
  via_hdr = pjsip_via_hdr_create(invite_txdata->pool);
  via_hdr->transport = pj_str("FAKE_UDP");
  via_hdr->sent_by.host = pj_str("1.2.3.4");
  via_hdr->sent_by.port = 56789;
  via_hdr->rport_param = 0;
  via_hdr->branch_param = pj_str("z9hG4bK3333333333"); // Must differ from previous branch
  pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)via_hdr);
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed to terminating UE
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  tpBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r1.uri());
  EXPECT_EQ("", get_headers(out, "Route"));

  // Save the request for later.
  pjsip_tx_data* target_rq = pop_txdata();

  // Bono sends an immediate 100 Trying response.
  inject_msg(respond_to_txdata(target_rq, 100), &tpBono);

  // The terminating UE doesn't respond so eventually the transaction will time
  // out.  To force this to happen in the right way, we send a CANCEL chasing
  // the original transaction (which is what Bono will do if the transaction
  // times out).
  msg._method = "CANCEL";
  msg._via = "10.99.88.11:12345";
  msg._branch = "1111111111";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";
  inject_msg(msg.get_request(), &tpBono);

  // CANCEL gets OK'd
  ASSERT_EQ(2, txdata_count());
  RespMatcher(200).matches(current_txdata()->msg);
  free_txdata();

  // The CANCEL is forwarded to AS1 (as originating AS)
  ReqMatcher("CANCEL").matches(current_txdata()->msg);

  // AS1 responds to the CANCEL.
  inject_msg(respond_to_current_txdata(200), &tpAS);
  free_txdata();

  // AS1 forwards the CANCEL back to Sprout.
  msg._branch = "2222222222";
  inject_msg(msg.get_request(), &tpAS);

  // CANCEL gets OK'd
  ASSERT_EQ(2, txdata_count());
  RespMatcher(200).matches(current_txdata()->msg);
  free_txdata();

  // The CANCEL is forwarded to AS1 (as terminating AS)
  ReqMatcher("CANCEL").matches(current_txdata()->msg);

  // AS2 responds to the CANCEL.
  inject_msg(respond_to_current_txdata(200), &tpAS);
  free_txdata();

  // AS1 forwards the CANCEL back to Sprout.
  msg._branch = "3333333333";
  inject_msg(msg.get_request(), &tpAS);

  // CANCEL gets OK'd
  ASSERT_EQ(2, txdata_count());
  RespMatcher(200).matches(current_txdata()->msg);
  free_txdata();

  // The CANCEL is forwarded to the terminating UE
  ReqMatcher("CANCEL").matches(current_txdata()->msg);

  // UE responds to the CANCEL.
  inject_msg(respond_to_current_txdata(200), &tpAS);
  free_txdata();

  // UE sends a 487 response which is ACKed and forwarded to AS1 (as terminating AS)
  inject_msg(respond_to_txdata(target_rq, 487));
  ASSERT_EQ(2, txdata_count());
  ReqMatcher("ACK").matches(current_txdata()->msg);
  free_txdata();
  ASSERT_EQ(1, txdata_count());
  RespMatcher(487).matches(current_txdata()->msg);

  // AS1 ACKs the response and forwards it back to Sprout removing the top Via header.
  msg._method = "ACK";
  msg._branch = "3333333333";
  inject_msg(msg.get_request(), &tpAS);
  out = current_txdata()->msg;
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  free_txdata();

  // Sprout ACKs the response and forwards it to AS1 (as originating AS).
  ASSERT_EQ(2, txdata_count());
  ReqMatcher("ACK").matches(current_txdata()->msg);
  free_txdata();
  ASSERT_EQ(1, txdata_count());
  RespMatcher(487).matches(current_txdata()->msg);

  // AS1 ACKs the response and forwards it back to Sprout removing the top Via header.
  msg._method = "ACK";
  msg._branch = "2222222222";
  inject_msg(msg.get_request(), &tpAS);
  out = current_txdata()->msg;
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  free_txdata();

  // Sprout ACKs the response and forwards it back to the originating UE.
  ASSERT_EQ(2, txdata_count());
  ReqMatcher("ACK").matches(current_txdata()->msg);
  free_txdata();
  ASSERT_EQ(1, txdata_count());
  RespMatcher(487).matches(current_txdata()->msg);
  free_txdata();

  // UE ACKs the response.
  msg._method = "ACK";
  msg._branch = "2222222222";
  inject_msg(msg.get_request(), &tpAS);
}


// Test local MESSAGE request with both originating and terminating ASs where terminating UE doesn't respond.
TEST_F(SCSCFTest, OriginatingTerminatingMessageASTimeout)
{
  TransportFlow tpBono(TransportFlow::Protocol::TCP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS(TransportFlow::Protocol::TCP, stack_data.scscf_port, "1.2.3.4", 56789);

  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                R"(<IMSSubscription><ServiceProfile>
                                <PublicIdentity><Identity>sip:6505551234@homedomain</Identity></PublicIdentity>
                                  <InitialFilterCriteria>
                                    <Priority>1</Priority>
                                    <TriggerPoint>
                                    <ConditionTypeCNF>0</ConditionTypeCNF>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <Method>MESSAGE</Method>
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:1.2.3.4:56789;transport=TCP</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                </ServiceProfile></IMSSubscription>)");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                R"(<IMSSubscription><ServiceProfile>
                                <PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>
                                  <InitialFilterCriteria>
                                    <Priority>1</Priority>
                                    <TriggerPoint>
                                    <ConditionTypeCNF>0</ConditionTypeCNF>
                                    <SPT>
                                      <ConditionNegated>0</ConditionNegated>
                                      <Group>0</Group>
                                      <Method>MESSAGE</Method>
                                      <Extension></Extension>
                                    </SPT>
                                  </TriggerPoint>
                                  <ApplicationServer>
                                    <ServerName>sip:1.2.3.4:56789;transport=TCP</ServerName>
                                    <DefaultHandling>0</DefaultHandling>
                                  </ApplicationServer>
                                  </InitialFilterCriteria>
                                </ServiceProfile></IMSSubscription>)");

  // ---------- Send MESSAGE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._method = "MESSAGE";
  msg._via = "10.99.88.11:12345";
  msg._branch = "1111111111";
  msg._to = "6505551234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._requri = "sip:6505551234@homedomain";
  inject_msg(msg.get_request(), &tpBono);
  poll();

  // MESSAGE passed on to AS1 (as originating AS for 6505551000)
  ASSERT_EQ(1, txdata_count());
  pjsip_tx_data* message_txdata = pop_txdata();
  pjsip_msg* out = message_txdata->msg;
  ReqMatcher r1("MESSAGE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  tpAS.expect_target(message_txdata, false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=TCP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=TCP;lr;orig>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551000@homedomain>;sescase=orig;regstate=reg"));

  // AS1 sends an immediate 100 Trying response.  This isn't realistic as the
  // response should be delayed by 3.5 seconds, but it stops the script
  // having to handle MESSAGE retransmits.
  inject_msg(respond_to_txdata(message_txdata, 100), &tpAS);

  // Advance time by a second so we have good enough control over the order
  // the transactions time out.
  cwtest_advance_time_ms(1000L);

  // ---------- AS1 turns MESSAGE around
  // (acting as routing B2BUA by adding a Via, and removing the top Route.)
  const pj_str_t STR_VIA = pj_str("Via");
  pjsip_via_hdr* via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (via_hdr)
  {
    via_hdr->rport_param = via_hdr->sent_by.port;
  }
  via_hdr = pjsip_via_hdr_create(message_txdata->pool);
  via_hdr->transport = pj_str("TCP");
  via_hdr->sent_by.host = pj_str("1.2.3.4");
  via_hdr->sent_by.port = 56789;
  via_hdr->rport_param = 0;
  via_hdr->branch_param = pj_str("z9hG4bK2222222222");
  pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)via_hdr);
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  pjsip_tx_data_dec_ref(message_txdata);

  // MESSAGE passed on to AS1 (as terminating AS for 6505551234)
  ASSERT_EQ(1, txdata_count());
  message_txdata = pop_txdata();
  out = message_txdata->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  tpAS.expect_target(message_txdata, false);
  EXPECT_EQ("sip:6505551234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=TCP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=TCP;lr>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505551234@homedomain>;sescase=term;regstate=reg"));

  // AS1 sends an immediate 100 Trying response.  This isn't realistic as the
  // response should be delayed by 3.5 seconds, but it stops the script
  // having to handle MESSAGE retransmits.
  inject_msg(respond_to_txdata(message_txdata, 100), &tpAS);

  // Advance time by a second so we have good enough control over the order
  // the transactions time out.
  cwtest_advance_time_ms(1000L);

  // ---------- AS1 turns MESSAGE around
  // (acting as routing B2BUA by adding a Via, and removing the top Route.)
  via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (via_hdr)
  {
    via_hdr->rport_param = via_hdr->sent_by.port;
  }
  via_hdr = pjsip_via_hdr_create(message_txdata->pool);
  via_hdr->transport = pj_str("TCP");
  via_hdr->sent_by.host = pj_str("1.2.3.4");
  via_hdr->sent_by.port = 56789;
  via_hdr->rport_param = 0;
  via_hdr->branch_param = pj_str("z9hG4bK3333333333"); // Must differ from previous branch
  pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)via_hdr);
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  pjsip_tx_data_dec_ref(message_txdata);

  // MESSAGE passed to terminating UE
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  tpBono.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob", r1.uri());
  EXPECT_EQ("", get_headers(out, "Route"));

  // UE sends an immediate 100 Trying response.  This isn't realistic as the
  // response should be delayed by 3.5 seconds, but it stops the script
  // having to handle MESSAGE retransmits.
  inject_msg(respond_to_current_txdata(100), &tpBono);

  // Advance the time so the delayed 100 Trying responses are sent by Sprout
  // (should happen 3.5 seconds after the MESSAGE was first received, so we'll
  // advance to just over that time).
  cwtest_advance_time_ms(3500L);
  poll();
  ASSERT_EQ(3, txdata_count());
  RespMatcher(100).matches(current_txdata()->msg);
  tpBono.expect_target(current_txdata(), true);
  free_txdata();
  ASSERT_EQ(2, txdata_count());
  RespMatcher(100).matches(current_txdata()->msg);
  tpAS.expect_target(current_txdata(), true);
  free_txdata();
  ASSERT_EQ(1, txdata_count());
  RespMatcher(100).matches(current_txdata()->msg);
  tpAS.expect_target(current_txdata(), true);
  free_txdata();

  // Now advance the time so the first transaction times out.  This should
  // happen 64*T1=32 seconds after the initial request.  Since we've already
  // advanced time by just over 5.5 seconds, we just need to advance by
  // another 26.5 seconds.
  cwtest_advance_time_ms(26500L);
  poll();

  // Sprout should send a 408 response on the original transaction.
  ASSERT_EQ(1, txdata_count());
  RespMatcher(408).matches(current_txdata()->msg);
  tpBono.expect_target(current_txdata(), true);
  free_txdata();

  // Advance the time by another second so the second hop transaction times out.
  cwtest_advance_time_ms(1000L);
  poll();

  // Sprout should send a 408 response to AS1.
  ASSERT_EQ(1, txdata_count());
  RespMatcher(408).matches(current_txdata()->msg);
  tpAS.expect_target(current_txdata(), true);
  free_txdata();

  // Advance the time by another second so the third hop transaction times out.
  cwtest_advance_time_ms(1000L);
  poll();

  // Sprout should send a 408 response to AS1.
  ASSERT_EQ(1, txdata_count());
  RespMatcher(408).matches(current_txdata()->msg);
  tpAS.expect_target(current_txdata(), true);
  free_txdata();
}


// Test terminating call-diversion AS flow to external URI, with orig-cdiv enabled too.
TEST_F(SCSCFTest, TerminatingDiversionExternalOrigCdiv)
{
  TransportFlow tpBono(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.99.88.11", 12345);
  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  TransportFlow tpExternal(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.9.8.7", 5060);

  register_uri(_store, _hss_connection, "6505501234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505501234@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                R"(<IMSSubscription><ServiceProfile>
                                <PublicIdentity><Identity>sip:6505501234@homedomain</Identity></PublicIdentity>
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
                                </ServiceProfile></IMSSubscription>)");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");

  add_host_mapping("ut.cw-ngv.com", "10.9.8.7");

  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345";
  msg._to = "6505501234@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._requri = "sip:6505501234@homedomain";
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

  tpAS.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505501234@homedomain", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505501234@homedomain>;sescase=term;regstate=reg"));

  // ---------- AS1 turns it around
  // (acting as routing B2BUA by adding a Via, removing the top Route and changing the target)
  const pj_str_t STR_VIA = pj_str("Via");
  pjsip_via_hdr* via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (via_hdr)
  {
    via_hdr->rport_param = via_hdr->sent_by.port;
  }
  via_hdr = pjsip_via_hdr_create(current_txdata()->pool);
  via_hdr->transport = pj_str("FAKE_UDP");
  via_hdr->sent_by.host = pj_str("1.2.3.4");
  via_hdr->sent_by.port = 56789;
  via_hdr->rport_param = 0;
  via_hdr->branch_param = pj_str("z9hG4bK1234567890");
  pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)via_hdr);
  const pj_str_t STR_ROUTE = pj_str("Route");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  ((pjsip_sip_uri*)out->line.req.uri)->host = pj_str("ut2.cw-ngv.com");
  inject_msg(out, &tpAS);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed on to AS1 (as originating-cdiv AS for Bob)
  SCOPED_TRACE("INVITE (S)");
  out = current_txdata()->msg;
  r1 = ReqMatcher("INVITE");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505501234@ut2.cw-ngv.com", r1.uri());
  EXPECT_THAT(get_headers(out, "Route"),
              testing::MatchesRegex("Route: <sip:1\\.2\\.3\\.4:56789;transport=UDP;lr>\r\nRoute: <sip:odi_[+/A-Za-z0-9]+@127.0.0.1:5058;transport=UDP;lr;orig>"));
  EXPECT_THAT(get_headers(out, "P-Served-User"),
              testing::MatchesRegex("P-Served-User: <sip:6505501234@homedomain>;sescase=orig-cdiv"));

  // ---------- AS1 turns it around
  // (acting as routing B2BUA by adding a Via, removing the top Route and changing the target)
  via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (via_hdr)
  {
    via_hdr->rport_param = via_hdr->sent_by.port;
  }
  via_hdr = pjsip_via_hdr_create(current_txdata()->pool);
  via_hdr->transport = pj_str("FAKE_UDP");
  via_hdr->sent_by.host = pj_str("1.2.3.4");
  via_hdr->sent_by.port = 56789;
  via_hdr->rport_param = 0;
  via_hdr->branch_param = pj_str("z9hG4bK1234567891"); // Must differ from previous branch
  pjsip_msg_insert_first_hdr(out, (pjsip_hdr*)via_hdr);
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_ROUTE, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  ((pjsip_sip_uri*)out->line.req.uri)->host = pj_str("ut.cw-ngv.com");
  inject_msg(out, &tpAS);
  free_txdata();

  // 100 Trying goes back to AS1
  out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();

  // INVITE passed externally
  SCOPED_TRACE("INVITE (2)");
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpExternal.expect_target(current_txdata(), false);
  EXPECT_EQ("sip:6505501234@ut.cw-ngv.com", r1.uri());
  EXPECT_EQ("", get_headers(out, "Route"));

  // ---------- Externally accepted with 200.
  string fresp = respond_to_txdata(current_txdata(), 200);
  free_txdata();
  inject_msg(fresp, &tpExternal);

  // 200 OK goes back to AS1 (orig-cdiv)
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);

  // ---------- AS1 forwards 200 (stripping via)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  free_txdata();

  // 200 OK goes back to AS1 (terminating)
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpAS.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);

  // ---------- AS1 forwards 200 (stripping via)
  hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(out, &STR_VIA, NULL);
  if (hdr)
  {
    pj_list_erase(hdr);
  }
  inject_msg(out, &tpAS);
  free_txdata();

  // 200 OK goes back to bono
  out = current_txdata()->msg;
  RespMatcher(200).matches(out);
  tpBono.expect_target(current_txdata(), true);  // Requests always come back on same transport
  msg.set_route(out);
  free_txdata();
}

TEST_F(SCSCFTest, TestAddSecondTelPAIHdr)
{
  SCOPED_TRACE("");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                   "<IMSSubscription><ServiceProfile>\n"
                                   "<PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>"
                                   "<PublicIdentity><Identity>tel:6505551000</Identity></PublicIdentity>"
                                   "  <InitialFilterCriteria>\n"
                                   "  </InitialFilterCriteria>\n"
                                   "</ServiceProfile></IMSSubscription>");
  Message msg;
  msg._route = "Route: <sip:homedomain;orig>";
  msg._extra = "P-Asserted-Identity: Andy <sip:6505551000@homedomain>";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("P-Asserted-Identity", "P-Asserted-Identity: \"Andy\" <sip:6505551000@homedomain>", "P-Asserted-Identity: \"Andy\" <tel:6505551000>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs, false);
}

TEST_F(SCSCFTest, TestAddSecondSIPPAIHdr)
{
  SCOPED_TRACE("");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("tel:6505551000", "call", HSSConnection::STATE_REGISTERED,
                                   "<IMSSubscription><ServiceProfile>\n"
                                   "<PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>"
                                   "<PublicIdentity><Identity>tel:6505551000</Identity></PublicIdentity>"
                                   "  <InitialFilterCriteria>\n"
                                   "  </InitialFilterCriteria>\n"
                                   "</ServiceProfile></IMSSubscription>");
  Message msg;
  msg._route = "Route: <sip:homedomain;orig>";
  msg._extra = "P-Asserted-Identity: Andy <tel:6505551000>";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("P-Asserted-Identity", "P-Asserted-Identity: \"Andy\" <tel:6505551000>", "P-Asserted-Identity: \"Andy\" <sip:6505551000@homedomain;user=phone>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs, false);
}

TEST_F(SCSCFTest, TestTwoPAIHdrsAlready)
{
  SCOPED_TRACE("");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                   "<IMSSubscription><ServiceProfile>\n"
                                   "<PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>"
                                   "<PublicIdentity><Identity>tel:6505551000</Identity></PublicIdentity>"
                                   "  <InitialFilterCriteria>\n"
                                   "  </InitialFilterCriteria>\n"
                                   "</ServiceProfile></IMSSubscription>");
  Message msg;
  msg._route = "Route: <sip:homedomain;orig>";
  msg._extra = "P-Asserted-Identity: Andy <sip:6505551000@homedomain>\nP-Asserted-Identity: Andy <tel:6505551111>";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("P-Asserted-Identity", "P-Asserted-Identity: \"Andy\" <sip:6505551000@homedomain>", "P-Asserted-Identity: \"Andy\" <tel:6505551111>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs, false);
}

TEST_F(SCSCFTest, TestNoPAIHdrs)
{
  SCOPED_TRACE("");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                   "<IMSSubscription><ServiceProfile>\n"
                                   "<PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>"
                                   "<PublicIdentity><Identity>tel:6505551000</Identity></PublicIdentity>"
                                   "  <InitialFilterCriteria>\n"
                                   "  </InitialFilterCriteria>\n"
                                   "</ServiceProfile></IMSSubscription>");
  Message msg;
  msg._route = "Route: <sip:homedomain;orig>";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("P-Asserted-Identity"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs, false);
}

TEST_F(SCSCFTest, TestPAIHdrODIToken)
{
  SCOPED_TRACE("");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                   "<IMSSubscription><ServiceProfile>\n"
                                   "<PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>"
                                   "<PublicIdentity><Identity>tel:6505551000</Identity></PublicIdentity>"
                                   "  <InitialFilterCriteria>\n"
                                   "  </InitialFilterCriteria>\n"
                                   "</ServiceProfile></IMSSubscription>");
  Message msg;
  msg._route = "Route: <sip:odi_dgds89gd8gdshds@127.0.0.1;orig>";
  msg._extra = "P-Asserted-Identity: Andy <sip:6505551000@homedomain>";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("P-Asserted-Identity", "P-Asserted-Identity: \"Andy\" <sip:6505551000@homedomain>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs, false);
}

TEST_F(SCSCFTest, TestNoSecondPAIHdrTerm)
{
  SCOPED_TRACE("");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED,
                                   "<IMSSubscription><ServiceProfile>\n"
                                   "<PublicIdentity><Identity>sip:6505551000@homedomain</Identity></PublicIdentity>"
                                   "<PublicIdentity><Identity>tel:6505551000</Identity></PublicIdentity>"
                                   "  <InitialFilterCriteria>\n"
                                   "  </InitialFilterCriteria>\n"
                                   "</ServiceProfile></IMSSubscription>");
  Message msg;
  msg._extra = "P-Asserted-Identity: Andy <sip:6505551000@homedomain>";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("P-Asserted-Identity", "P-Asserted-Identity: \"Andy\" <sip:6505551000@homedomain>"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs, false);
}

// Test that the Session-Expires header is correctly altered by the Min-SE
// header
TEST_F(SCSCFTest, TestMinSEOverride)
{
  SCOPED_TRACE("");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");
  Message msg;
  msg._extra = "Session-Expires: 600\nMin-SE: 800";
  list<HeaderMatcher> hdrs;
  hdrs.push_back(HeaderMatcher("Session-Expires", "Session-Expires: 800"));
  doSuccessfulFlow(msg, testing::MatchesRegex(".*wuntootreefower.*"), hdrs, false);
}

// Test that a request where the Min-SE header is too large is rejected
TEST_F(SCSCFTest, TestMinSETooLarge)
{
  SCOPED_TRACE("");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");
  Message msg;
  msg._extra = "Session-Expires: 600\nMin-SE: 1000";
  doSlowFailureFlow(msg, 480);
}

// Test that a request where the Session-Expiry header is too large is rejected
TEST_F(SCSCFTest, TestSessionExpiresTooLarge)
{
  SCOPED_TRACE("");
  register_uri(_store, _hss_connection, "6505551234", "homedomain", "sip:wuntootreefower@10.114.61.213:5061;transport=tcp;ob");
  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");
  Message msg;
  msg._extra = "Session-Expires: 1000";
  doSlowFailureFlow(msg, 480);
}

/// Test handling of 430 Flow Failed response
TEST_F(SCSCFTest, FlowFailedResponse)
{
  TransportFlow tpBono(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.99.88.11", 12345);
  //TransportFlow tpExternal(TransportFlow::Protocol::UDP, stack_data.scscf_port, "10.9.8.7", 5060);
  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  std::string user = "sip:6505550231@homedomain";
  register_uri(_store, _hss_connection, "6505550231", "homedomain", "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213", 30);

  _hss_connection->set_impu_result("sip:6505551000@homedomain", "call", HSSConnection::STATE_REGISTERED, "");
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "dereg-timeout", HSSConnection::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "    <Priority>1</Priority>\n"
                              "    <TriggerPoint>\n"
                              "      <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                              "      <SPT>\n"
                              "        <ConditionNegated>0</ConditionNegated>\n"
                              "        <Group>0</Group>\n"
                              "        <Method>REGISTER</Method>\n"
                              "        <Extension></Extension>\n"
                              "      </SPT>\n"
                              "    </TriggerPoint>\n"
                              "    <ApplicationServer>\n"
                              "      <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                              "      <DefaultHandling>1</DefaultHandling>\n"
                              "    </ApplicationServer>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>");


  // ---------- Send INVITE
  // We're within the trust boundary, so no stripping should occur.
  Message msg;
  msg._via = "10.99.88.11:12345";
  msg._to = "65055502314@homedomain";
  msg._todomain = "";
  msg._route = "Route: <sip:homedomain;orig>";
  msg._requri = "sip:6505550231@homedomain";
  msg._method = "INVITE";
  inject_msg(msg.get_request(), &tpBono);
  poll();
  ASSERT_EQ(2, txdata_count());

  // 100 Trying goes back to bono
  pjsip_msg* out = current_txdata()->msg;
  RespMatcher(100).matches(out);
  tpBono.expect_target(current_txdata(), true);
  msg.set_route(out);
  free_txdata();

  // INVITE passed externally
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("INVITE").matches(out));

  // Send 430 Flow Failed response.
  string fresp = respond_to_current_txdata(430);
  free_txdata();
  inject_msg(fresp);

  // Sprout ACKs the response.
  ASSERT_EQ(3, txdata_count());
  ReqMatcher("ACK").matches(current_txdata()->msg);
  free_txdata();

  // Sprout deletes the binding.
  RegStore::AoR* aor_data = _store->get_aor_data(user, 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(0u, aor_data->_bindings.size());
  delete aor_data; aor_data = NULL;

  // Because there are no remaining bindings, Sprout sends a deregister to the
  // HSS and a third-party deREGISTER to the AS.
  ASSERT_EQ(2, txdata_count());
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(ReqMatcher("REGISTER").matches(out));
  EXPECT_EQ(NULL, out->body);

  // Send a 200 OK response from the AS.
  fresp = respond_to_current_txdata(200);
  //free_txdata();
  inject_msg(fresp, &tpAS);

  // Catch the forwarded 430 response.
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  RespMatcher(430).matches(out);
  free_txdata();

  // UE ACKs the response.
  msg._method = "ACK";
  inject_msg(msg.get_request(), &tpBono);
}
