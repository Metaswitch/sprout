/**
 * @file basicproxy_test.cpp UT for BasicProxy class.
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
#include "icscfproxy.h"
#include "fakelogger.hpp"
#include "fakehssconnection.hpp"
#include "faketransport_tcp.hpp"
#include "test_interposer.hpp"

using namespace std;
using testing::StrEq;
using testing::ElementsAre;
using testing::MatchesRegex;
using testing::HasSubstr;
using testing::Not;

/// To fully test the BasicProxy class we need to override some of the
/// methods to force execution of function such as forking and retries.
class BasicProxyUT : public BasicProxy
{
public:
  class TestTarget
  {
  public:
    TestTarget(const std::string& uri) :
      _uri(uri),
      _paths(),
      _transport(NULL)
    {
    }

    TestTarget(const std::list<std::string>& paths) :
      _uri(),
      _paths(paths),
      _transport(NULL)
    {
    }

    TestTarget(const std::string& uri, const std::list<std::string>& paths) :
      _uri(uri),
      _paths(paths),
      _transport(NULL)
    {
    }

    TestTarget(pjsip_transport* transport) :
      _uri(),
      _paths(),
      _transport(transport)
    {
    }

    TestTarget(const std::string& uri, pjsip_transport* transport) :
      _uri(uri),
      _paths(),
      _transport(transport)
    {
    }

    TestTarget(const std::list<std::string>& paths, pjsip_transport* transport) :
      _uri(),
      _paths(paths),
      _transport(transport)
    {
    }

    TestTarget(const std::string& uri, const std::list<std::string>& paths, pjsip_transport* transport) :
      _uri(uri),
      _paths(paths),
      _transport(transport)
    {
    }

  private:
    std::string _uri;
    std::list<std::string> _paths;
    pjsip_transport* _transport;

    friend class BasicProxyUT;
  };

  BasicProxyUT(pjsip_endpoint* endpt, int priority) :
    BasicProxy(endpt, "UTProxy", NULL, priority, false)
  {
  }

  void add_test_target(const std::string& aor, const std::string& uri)
  {
    _test_targets[aor].push_back(TestTarget(uri));
  }

  void add_test_target(const std::string& aor, const std::list<std::string>& paths)
  {
    _test_targets[aor].push_back(TestTarget(paths));
  }

  void add_test_target(const std::string& aor, const std::string& uri, const std::list<std::string>& paths)
  {
    _test_targets[aor].push_back(TestTarget(uri, paths));
  }

  void add_test_target(const std::string& aor, pjsip_transport* transport)
  {
    _test_targets[aor].push_back(TestTarget(transport));
  }

  void add_test_target(const std::string& aor, const std::string& uri, pjsip_transport* transport)
  {
    _test_targets[aor].push_back(TestTarget(uri, transport));
  }

  void add_test_target(const std::string& aor, const std::list<std::string>& paths, pjsip_transport* transport)
  {
    _test_targets[aor].push_back(TestTarget(paths, transport));
  }

  void add_test_target(const std::string& aor, const std::string& uri, const std::list<std::string>& paths, pjsip_transport* transport)
  {
    _test_targets[aor].push_back(TestTarget(uri, paths, transport));
  }

  void remove_test_targets(const std::string& aor)
  {
    _test_targets.erase(aor);
  }

  std::list<TestTarget> find_test_targets(const std::string& aor)
  {
    std::map<std::string, std::list<TestTarget> >::const_iterator i = _test_targets.find(aor);
    if (i == _test_targets.end())
    {
      LOG_DEBUG("Failed to find test targets for AOR %s", aor.c_str());
      return std::list<TestTarget>();
    }

    return i->second;
  }

protected:
  /// Create UAS transaction objects.
  BasicProxy::UASTsx* create_uas_tsx()
  {
    return (BasicProxy::UASTsx*)new UASTsx(this);
  }

private:
  class UASTsx : public BasicProxy::UASTsx
  {
    UASTsx(BasicProxyUT* proxy) :
      BasicProxy::UASTsx((BasicProxy*)proxy)
    {
    }

  protected:
    virtual int calculate_targets()
    {
      // Invoke the standard function first.
      int status_code = BasicProxy::UASTsx::calculate_targets();

      if (status_code == PJSIP_SC_NOT_FOUND)
      {
        // No targets set up by default function, so see if any have been
        // manually configured in the test case
        LOG_DEBUG("Check for test targets");
        std::string aor = PJUtils::aor_from_uri((pjsip_sip_uri*)_req->msg->line.req.uri);
        std::list<BasicProxyUT::TestTarget> test_targets = ((BasicProxyUT*)_proxy)->find_test_targets(aor);
        LOG_DEBUG("Found %d targets for %s", test_targets.size(), aor.c_str());

        // Add the targets to the transaction.
        while (!test_targets.empty())
        {
          TestTarget& tt = test_targets.front();
          BasicProxy::Target* target = new BasicProxy::Target;
          if (tt._uri != "")
          {
            target->uri = PJUtils::uri_from_string(tt._uri, _req->pool);
          }
          for (std::list<std::string>::const_iterator i = tt._paths.begin();
               i != tt._paths.end();
               ++i)
          {
            target->paths.push_back(PJUtils::uri_from_string(*i, _req->pool));
          }
          if (tt._transport != NULL)
          {
            target->transport = tt._transport;
            pjsip_transport_add_ref(target->transport);
          }

          add_target(target);
          test_targets.pop_front();

          // Found at least one target.
          status_code = PJSIP_SC_OK;
        }
      }

      return status_code;
    }
  };

  /// Map holding targets programmed by the tests.
  std::map<std::string, std::list<BasicProxyUT::TestTarget> > _test_targets;

};


/// ABC for fixtures for BasicProxyTest.
class BasicProxyTestBase : public SipTest
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

    _basic_proxy = new BasicProxyUT(stack_data.endpt,
                                    PJSIP_MOD_PRIORITY_UA_PROXY_LAYER+1);

    // Schedule timers.
    SipTest::poll();
  }

  static void TearDownTestCase()
  {
    // Shut down the transaction module first, before we destroy the
    // objects that might handle any callbacks!
    pjsip_tsx_layer_destroy();
    delete _basic_proxy; _basic_proxy = NULL;
    SipTest::TearDownTestCase();
  }

  BasicProxyTestBase()
  {
    Log::setLoggingLevel(-1); // cover out-of-range log levels
    Log::setLoggingLevel(99);
    _log_traffic = FakeLogger::isNoisy(); // true to see all traffic
  }

  ~BasicProxyTestBase()
  {
    // Give any transactions in progress a chance to complete.
    poll();

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
    string _fromscheme;
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
      _fromscheme("pres"),
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
      string target = _toscheme + ":" + _to;
      if (!_todomain.empty())
      {
        target += "@" + _todomain;
      }

      string from = _fromscheme + ":" + _from;
      string requri = _requri.empty() ? target : _requri;
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
                       /*  2 */ from.c_str(),
                       /*  3 */ _fromdomain.c_str(),
                       /*  4 */ _content_type.empty() ? "" : string("Content-Type: ").append(_content_type).append("\r\n").c_str(),
                       /*  5 */ (int)_body.length(),
                       /*  6 */ _body.c_str(),
                       /*  7 */ _extra.empty() ? "" : string(_extra).append("\r\n").c_str(),
                       /*  8 */ _forwards,
                       /*  9 */ requri.c_str(),
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

      string to = _toscheme + ":" + _to;
      if (!_todomain.empty())
      {
        to += "@" + _todomain;
      }

      string from = _fromscheme + ":" + _from;
      string route = _route.empty() ? "" : _route + "\r\n";

      int n = snprintf(buf, sizeof(buf),
                       "SIP/2.0 %8$s\r\n"
                       "Via: SIP/2.0/TCP %12$s;rport;branch=z9hG4bKPjmo1aimuq33BAI4rjhgQgBr4sY%10$04dSPI\r\n"
                       "From: <sip:%2$s@%3$s>;tag=10.114.61.213+1+8c8b232a+5fb751cf\r\n"
                       "To: <sip:%7$s>\r\n"
                       "Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs%10$04dohntC@10.114.61.213\r\n"
                       "CSeq: %11$d %1$s\r\n"
                       "User-Agent: Accession 2.0.0.0\r\n"
                       "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n"
                       "%4$s"
                       "%9$s"
                       "Content-Length: %5$d\r\n"
                       "\r\n"
                       "%6$s",
                       /*  1 */ _method.c_str(),
                       /*  2 */ from.c_str(),
                       /*  3 */ _fromdomain.c_str(),
                       /*  4 */ _content_type.empty() ? "" : string("Content-Type: ").append(_content_type).append("\r\n").c_str(),
                       /*  5 */ (int)_body.length(),
                       /*  6 */ _body.c_str(),
                       /*  7 */ to.c_str(),
                       /*  8 */ _status.c_str(),
                       /*  9 */ _extra.empty() ? "" : string(_extra).append("\r\n").c_str(),
                       /* 10 */ _unique,
                       /* 11 */ _cseq,
                       /* 12 */ _via.c_str()
        );

      EXPECT_LT(n, (int)sizeof(buf));

      string ret(buf, n);
      // cout << ret <<endl;
      return ret;
    }
  };

protected:
  static BasicProxyUT* _basic_proxy;

};

BasicProxyUT* BasicProxyTestBase::_basic_proxy;


class BasicProxyTest : public BasicProxyTestBase
{
public:
  static void SetUpTestCase()
  {
    // Set up DNS mappings for destinations.
    cwtest_clear_host_mapping();
    cwtest_add_host_mapping("proxy1.homedomain", "10.10.10.1");
    cwtest_add_host_mapping("proxy2.homedomain", "10.10.10.2");
    cwtest_add_host_mapping("node1.homedomain", "10.10.18.1");
    cwtest_add_host_mapping("node2.homedomain", "10.10.18.2");
    cwtest_add_host_mapping("node3.homedomain", "10.10.18.2");
    cwtest_add_host_mapping("node4.homedomain", "10.10.18.2");

    cwtest_add_host_mapping("proxy1.awaydomain", "10.10.20.1");
    cwtest_add_host_mapping("proxy2.awaydomain", "10.10.20.2");
    cwtest_add_host_mapping("node1.awaydomain", "10.10.28.1");
    cwtest_add_host_mapping("node2.awaydomain", "10.10.28.2");

    BasicProxyTestBase::SetUpTestCase();
  }

  static void TearDownTestCase()
  {
    BasicProxyTestBase::TearDownTestCase();
  }

  BasicProxyTest()
  {
  }

  ~BasicProxyTest()
  {
  }

protected:
};



TEST_F(BasicProxyTest, RouteOnRouteHeaders)
{
  // Tests routing of requests on normal loose routing Route headers.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header not referencing this node or the
  // home domain.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check the RequestURI has not been altered.
  ASSERT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));

  // Check the Route header has not been removed.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>", route);

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  // Inject a request with two Route headers, the first refering to the
  // home domain and the second refering to an external domain.
  Message msg2;
  msg2._method = "INVITE";
  msg2._requri = "sip:bob@awaydomain";
  msg2._from = "alice";
  msg2._to = "bob";
  msg2._todomain = "awaydomain";
  msg2._via = tp->to_string(false);
  msg2._route = "Route: <sip:local_ip;transport=TCP;lr>\r\nRoute: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg2.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Request is forwarded to the node in the second Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check the RequestURI has not been altered.
  ASSERT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));

  // Check the first Route header has been removed, but the second remains.
  route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>", route);

  // Check no Record-Route headers have been added.
  rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  delete tp;
}


TEST_F(BasicProxyTest, RouteOnRequestURIDomain)
{
  // Tests routing of requests to an external RequestURI.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with no Route headers and a RequestURI with an external
  // node.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@proxy1.awaydomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Request is forwarded to the node in RequestURI.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check the RequestURI has not been altered.
  ASSERT_EQ("sip:bob@proxy1.awaydomain;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route headers have been added.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", route);

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  delete tp;
}


TEST_F(BasicProxyTest, RouteToHomeURINoPathTransport)
{
  // Tests routing of requests to a home domain RequestURI.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Add a test target for bob@homedomain, with just a URI in the target.
  _basic_proxy->add_test_target("sip:bob@homedomain", "sip:bob@node1.homedomain;transport=TCP");

  // Inject a request with a Route header referring to this node and a
  // RequestURI with a URI in the home domain.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:local_ip;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // The proxy resolves the requestURI to the test target bob@node1.homedomain.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.18.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check the RequestURI has been altered.
  ASSERT_EQ("sip:bob@node1.homedomain;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check the Route header has been removed.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", route);

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  _basic_proxy->remove_test_targets("sip:bob@homedomain");

  delete tp;
}


TEST_F(BasicProxyTest, RouteToHomeURIWithPath)
{
  // Tests routing of requests to a home domain RequestURI inserting
  // appropriate Route headers from a stored path.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Add a test target for bob@homedomain, with a URI plus a path with a
  // single proxy.
  _basic_proxy->add_test_target("sip:bob@homedomain",
                                "sip:bob@node1.homedomain;transport=TCP",
                                std::list<std::string>(1, "sip:proxy1.homedomain;transport=TCP;lr"));

  // Inject a request with a Route header referring to this node and a
  // RequestURI with a URI in the home domain.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:local_ip;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // The proxy resolves the requestURI to the test target bob@node1.homedomain
  // with path via proxy1.homedomain.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check the RequestURI has been altered.
  ASSERT_EQ("sip:bob@node1.homedomain;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check the Route header has been removed and a new one added for the path.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:proxy1.homedomain;transport=TCP;lr>", route);

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  _basic_proxy->remove_test_targets("sip:bob@homedomain");

  delete tp;
}


TEST_F(BasicProxyTest, RouteToHomeURIWithTransport)
{
  // Tests routing of requests to a home domain RequestURI forcing use of
  // a particular transport.

  pjsip_tx_data* tdata;

  // Create a two TCP connections to the listening port.
  TransportFlow* tp1 = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);
  TransportFlow* tp2 = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "5.6.7.8",
                                        49322);

  // Add a test target for bob@homedomain, with a URI plus transport tp2
  // single proxy.
  _basic_proxy->add_test_target("sip:bob@homedomain",
                                "sip:bob@node1.homedomain;transport=TCP",
                                tp2->transport());

  // Inject a request with a Route header referring to this node and a
  // RequestURI with a URI in the home domain.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp1->to_string(false);
  msg1._route = "Route: <sip:local_ip;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp1);

  // Expecting 100 Trying and forwarded INVITE

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp1->expect_target(tdata);
  free_txdata();

  // The proxy resolves the requestURI to the test target bob@node1.homedomain
  // using transport tp2.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp2->expect_target(tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check the RequestURI has been altered.
  ASSERT_EQ("sip:bob@node1.homedomain;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check the Route header has been removed.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("", route);

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200), tp2);

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp1->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  _basic_proxy->remove_test_targets("sip:bob@homedomain");

  delete tp1;
  delete tp2;
}


TEST_F(BasicProxyTest, RouteToHomeURITransportCancel)
{
  // Tests cancelling a requests to a home domain RequestURI forcing use of
  // a particular transport.

  pjsip_tx_data* tdata;

  // Create a two TCP connections to the listening port.
  TransportFlow* tp1 = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);
  TransportFlow* tp2 = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "5.6.7.8",
                                        49322);

  // Add a test target for bob@homedomain, with a URI plus transport tp2
  // single proxy.
  _basic_proxy->add_test_target("sip:bob@homedomain",
                                "sip:bob@node1.homedomain;transport=TCP",
                                tp2->transport());

  // Inject a request with a Route header referring to this node and a
  // RequestURI with a URI in the home domain.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp1->to_string(false);
  msg1._route = "Route: <sip:local_ip;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp1);

  // Expecting 100 Trying and forwarded INVITE

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp1->expect_target(tdata);
  free_txdata();

  // The proxy resolves the requestURI to the test target bob@node1.homedomain
  // using transport tp2.
  ASSERT_EQ(1, txdata_count());
  pjsip_tx_data* tdata1 = pop_txdata();
  tp2->expect_target(tdata1);
  ReqMatcher("INVITE").matches(tdata1->msg);
  ASSERT_EQ("sip:bob@node1.homedomain;transport=TCP", str_uri(tdata1->msg->line.req.uri));
  ASSERT_EQ("", get_headers(tdata1->msg, "Route"));
  ASSERT_EQ("", get_headers(tdata1->msg, "Record-Route"));

  // Send 100 Trying from the downstream node.
  inject_msg(respond_to_txdata(tdata1, 100));
  ASSERT_EQ(0, txdata_count());

  // Send a CANCEL from the originator.
  Message msg2;
  msg2._method = "CANCEL";
  msg2._requri = "sip:bob@homedomain;transport=TCP";
  msg2._from = "alice";
  msg2._to = "bob";
  msg2._todomain = "awaydomain";
  msg2._via = tp1->to_string(false);
  msg2._unique = msg1._unique;    // Make sure branch and call-id are same as the INVITE
  inject_msg(msg2.get_request(), tp1);

  // Expect both a 200 OK response to the CANCEL and a CANCELs on the
  // outstanding forked transactions.
  ASSERT_EQ(2, txdata_count());

  // Check the 200 OK.
  tdata = current_txdata();
  tp1->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  // Check the CANCEL is forwarded.
  tdata = current_txdata();
  tp2->expect_target(tdata);
  ReqMatcher("CANCEL").matches(tdata->msg);
  inject_msg(respond_to_current_txdata(200));

  // Send 487 response to the original INVITE.  Check that this is ACKed
  // and forwarded.
  inject_msg(respond_to_txdata(tdata1, 487));
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  tp2->expect_target(tdata);
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // A 487 response is now forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp1->expect_target(tdata);
  RespMatcher(487).matches(tdata->msg);
  free_txdata();

  // Send an ACK to complete the UAS transaction.
  msg1._method = "ACK";
  inject_msg(msg1.get_request(), tp1);

  _basic_proxy->remove_test_targets("sip:bob@homedomain");

  delete tp1;
  delete tp2;
}


TEST_F(BasicProxyTest, ForkedRequestSuccess)
{
  // Tests forking of request to a home domain RequestURI.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Add three test targets for bob@homedomain, all with a URI plus a path with a
  // single proxy.
  _basic_proxy->add_test_target("sip:bob@homedomain",
                                "sip:bob@node1.homedomain;transport=TCP",
                                std::list<std::string>(1, "sip:proxy1.homedomain;transport=TCP;lr"));
  _basic_proxy->add_test_target("sip:bob@homedomain",
                                "sip:bob@node2.homedomain;transport=TCP",
                                std::list<std::string>(1, "sip:proxy1.homedomain;transport=TCP;lr"));
  _basic_proxy->add_test_target("sip:bob@homedomain",
                                "sip:bob@node3.homedomain;transport=TCP",
                                std::list<std::string>(1, "sip:proxy2.homedomain;transport=TCP;lr"));
  _basic_proxy->add_test_target("sip:bob@homedomain",
                                "sip:bob@node4.homedomain;transport=TCP",
                                std::list<std::string>(1, "sip:proxy2.homedomain;transport=TCP;lr"));
  _basic_proxy->add_test_target("sip:bob@homedomain",
                                "sip:bob@node5.homedomain;transport=TCP",
                                std::list<std::string>(1, "sip:proxy2.homedomain;transport=TCP;lr"));

  // Inject a request with a Route header referring to this node and a
  // RequestURI with a URI in the home domain.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:local_ip;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and five forwarded INVITEs
  ASSERT_EQ(6, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Catch the request forked to node1.homedomain via proxy1.homedomain.
  pjsip_tx_data* tdata1 = pop_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata1);
  ReqMatcher("INVITE").matches(tdata1->msg);
  ASSERT_EQ("sip:bob@node1.homedomain;transport=TCP",
            str_uri(tdata1->msg->line.req.uri));
  ASSERT_EQ("Route: <sip:proxy1.homedomain;transport=TCP;lr>",
            get_headers(tdata1->msg, "Route"));

  // Catch the request forked to node2.homedomain via proxy1.homedomain.
  pjsip_tx_data* tdata2 = pop_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata2);
  ReqMatcher("INVITE").matches(tdata2->msg);
  ASSERT_EQ("sip:bob@node2.homedomain;transport=TCP",
            str_uri(tdata2->msg->line.req.uri));
  ASSERT_EQ("Route: <sip:proxy1.homedomain;transport=TCP;lr>",
            get_headers(tdata2->msg, "Route"));

  // Catch the request forked to node3.homedomain via proxy2.homedomain.
  pjsip_tx_data* tdata3 = pop_txdata();
  expect_target("TCP", "10.10.10.2", 5060, tdata3);
  ReqMatcher("INVITE").matches(tdata3->msg);
  ASSERT_EQ("sip:bob@node3.homedomain;transport=TCP",
            str_uri(tdata3->msg->line.req.uri));
  ASSERT_EQ("Route: <sip:proxy2.homedomain;transport=TCP;lr>",
            get_headers(tdata3->msg, "Route"));

  // Catch the request forked to node4.homedomain via proxy2.homedomain.
  pjsip_tx_data* tdata4 = pop_txdata();
  expect_target("TCP", "10.10.10.2", 5060, tdata4);
  ReqMatcher("INVITE").matches(tdata4->msg);
  ASSERT_EQ("sip:bob@node4.homedomain;transport=TCP",
            str_uri(tdata4->msg->line.req.uri));
  ASSERT_EQ("Route: <sip:proxy2.homedomain;transport=TCP;lr>",
            get_headers(tdata4->msg, "Route"));

  // Catch the request forked to node5.homedomain via proxy2.homedomain.
  pjsip_tx_data* tdata5 = pop_txdata();
  expect_target("TCP", "10.10.10.2", 5060, tdata5);
  ReqMatcher("INVITE").matches(tdata5->msg);
  ASSERT_EQ("sip:bob@node5.homedomain;transport=TCP",
            str_uri(tdata5->msg->line.req.uri));
  ASSERT_EQ("Route: <sip:proxy2.homedomain;transport=TCP;lr>",
            get_headers(tdata5->msg, "Route"));

  // Send 100 Trying responses from all five nodes, and check they are
  // absorbed.
  inject_msg(respond_to_txdata(tdata1, 100));
  ASSERT_EQ(0, txdata_count());
  inject_msg(respond_to_txdata(tdata2, 100));
  ASSERT_EQ(0, txdata_count());
  inject_msg(respond_to_txdata(tdata3, 100));
  ASSERT_EQ(0, txdata_count());
  inject_msg(respond_to_txdata(tdata4, 100));
  ASSERT_EQ(0, txdata_count());
  inject_msg(respond_to_txdata(tdata5, 100));
  ASSERT_EQ(0, txdata_count());

  // Send 180 Ringing response from node 2, and check this is passed to the
  // source.
  inject_msg(respond_to_txdata(tdata2, 180));
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(180).matches(tdata->msg);
  free_txdata();

  // Send a 480 response from the first target, and check the proxy absorbs
  // this while waiting for a better offer.
  inject_msg(respond_to_txdata(tdata1, 480));
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // Send a 480 response from the fourth target, and check the proxy absorbs
  // this while waiting for a better offer.
  inject_msg(respond_to_txdata(tdata4, 480));
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // Send a 408 response from the fifth target, and check the proxy absorbs
  // this while waiting for a better offer.
  inject_msg(respond_to_txdata(tdata5, 408));
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // Send a 200 OK response from the second target.
  inject_msg(respond_to_txdata(tdata2, 200));

  // Check the 200 OK is forwarded immediately to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  // Now wait for the UAS transaction to terminate, which will cancel
  // the outstanding forked transaction.
  poll();

  // Catch the CANCEL for the outstanding forked transaction.
  EXPECT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.2", 5060, tdata);
  ReqMatcher("CANCEL").matches(tdata->msg);

  // Send a 200 OK to the CANCEL.
  inject_msg(respond_to_current_txdata(200));
  ASSERT_EQ(0, txdata_count());

  // Send a 487 response from node3.homedomain in response to the CANCEL.
  // Check that this is ACKed, but otherwise absorbed by the proxy.
  inject_msg(respond_to_txdata(tdata3, 487));
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  _basic_proxy->remove_test_targets("sip:bob@homedomain");

  delete tp;
}


TEST_F(BasicProxyTest, ForkedRequestFail)
{
  // Tests forking of request to a home domain RequestURI where all
  // downstream transactions fail.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Add two test targets for bob@homedomain, both with a URI plus a path with a
  // single proxy.
  _basic_proxy->add_test_target("sip:bob@homedomain",
                                "sip:bob@node1.homedomain;transport=TCP",
                                std::list<std::string>(1, "sip:proxy1.homedomain;transport=TCP;lr"));
  _basic_proxy->add_test_target("sip:bob@homedomain",
                                "sip:bob@node2.homedomain;transport=TCP",
                                std::list<std::string>(1, "sip:proxy2.homedomain;transport=TCP;lr"));
  _basic_proxy->add_test_target("sip:bob@homedomain",
                                "sip:bob@node3.homedomain;transport=TCP",
                                std::list<std::string>(1, "sip:proxy2.homedomain;transport=TCP;lr"));

  // Inject a request with a Route header referring to this node and a
  // RequestURI with a URI in the home domain.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:local_ip;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and three forwarded INVITEs
  ASSERT_EQ(4, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Catch the request forked to node1.homedomain via proxy1.homedomain.
  pjsip_tx_data* tdata1 = pop_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata1);
  ReqMatcher("INVITE").matches(tdata1->msg);
  ASSERT_EQ("sip:bob@node1.homedomain;transport=TCP",
            str_uri(tdata1->msg->line.req.uri));
  ASSERT_EQ("Route: <sip:proxy1.homedomain;transport=TCP;lr>",
            get_headers(tdata1->msg, "Route"));

  // Catch the request forked to node2.homedomain via proxy2.homedomain.
  pjsip_tx_data* tdata2 = pop_txdata();
  expect_target("TCP", "10.10.10.2", 5060, tdata2);
  ReqMatcher("INVITE").matches(tdata2->msg);
  ASSERT_EQ("sip:bob@node2.homedomain;transport=TCP",
            str_uri(tdata2->msg->line.req.uri));
  ASSERT_EQ("Route: <sip:proxy2.homedomain;transport=TCP;lr>",
            get_headers(tdata2->msg, "Route"));

  // Catch the request forked to node2.homedomain via proxy2.homedomain.
  pjsip_tx_data* tdata3 = pop_txdata();
  expect_target("TCP", "10.10.10.2", 5060, tdata3);
  ReqMatcher("INVITE").matches(tdata3->msg);
  ASSERT_EQ("sip:bob@node3.homedomain;transport=TCP",
            str_uri(tdata3->msg->line.req.uri));
  ASSERT_EQ("Route: <sip:proxy2.homedomain;transport=TCP;lr>",
            get_headers(tdata3->msg, "Route"));

  // Send 100 Trying responses from all three nodes, and check they are absorbed.
  inject_msg(respond_to_txdata(tdata1, 100));
  ASSERT_EQ(0, txdata_count());
  inject_msg(respond_to_txdata(tdata2, 100));
  ASSERT_EQ(0, txdata_count());
  inject_msg(respond_to_txdata(tdata3, 100));
  ASSERT_EQ(0, txdata_count());

  // Send a 480 response from the first target, and check the proxy absorbs
  // this while waiting for a better offer.
  inject_msg(respond_to_txdata(tdata1, 480));
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // Send a 488 Not Acceptable Here reponse from the second target.
  inject_msg(respond_to_txdata(tdata2, 488));
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // Send a 404 Not Found reponse from the third target.
  inject_msg(respond_to_txdata(tdata3, 404));
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // The proxy sends the best response (the 404) to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(404).matches(tdata->msg);
  free_txdata();

  // Send an ACK to complete the UAS transaction.
  msg1._method = "ACK";
  inject_msg(msg1.get_request(), tp);

  _basic_proxy->remove_test_targets("sip:bob@homedomain");

  delete tp;
}


TEST_F(BasicProxyTest, ForkedRequestConnFail)
{
  // Tests forking of request to a home domain RequestURI where the
  // downstream transactions fail because of a connection failure.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Add two test targets for bob@homedomain, both with a URI plus a path with a
  // single proxy.
  _basic_proxy->add_test_target("sip:bob@homedomain",
                                "sip:bob@node1.homedomain;transport=TCP",
                                std::list<std::string>(1, "sip:proxy1.homedomain;transport=TCP;lr"));
  _basic_proxy->add_test_target("sip:bob@homedomain",
                                "sip:bob@node2.homedomain;transport=TCP",
                                std::list<std::string>(1, "sip:proxy1.homedomain;transport=TCP;lr"));

  // Inject a request with a Route header referring to this node and a
  // RequestURI with a URI in the home domain.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:local_ip;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and three forwarded INVITEs
  ASSERT_EQ(3, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Catch the request forked to node1.homedomain via proxy1.homedomain.
  pjsip_tx_data* tdata1 = pop_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata1);
  ReqMatcher("INVITE").matches(tdata1->msg);
  ASSERT_EQ("sip:bob@node1.homedomain;transport=TCP",
            str_uri(tdata1->msg->line.req.uri));
  ASSERT_EQ("Route: <sip:proxy1.homedomain;transport=TCP;lr>",
            get_headers(tdata1->msg, "Route"));

  // Catch the request forked to node2.homedomain via proxy2.homedomain.
  pjsip_tx_data* tdata2 = pop_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata2);
  ReqMatcher("INVITE").matches(tdata2->msg);
  ASSERT_EQ("sip:bob@node2.homedomain;transport=TCP",
            str_uri(tdata2->msg->line.req.uri));
  ASSERT_EQ("Route: <sip:proxy1.homedomain;transport=TCP;lr>",
            get_headers(tdata2->msg, "Route"));

  // Send 100 Trying responses from both nodes, and check they are absorbed.
  inject_msg(respond_to_txdata(tdata1, 100));
  ASSERT_EQ(0, txdata_count());
  inject_msg(respond_to_txdata(tdata2, 100));
  ASSERT_EQ(0, txdata_count());

  // proxy1.homedomain fails causing both transactions to fail.
  ASSERT_EQ(tdata1->tp_info.transport, tdata2->tp_info.transport);
  fake_tcp_init_shutdown((fake_tcp_transport*)tdata1->tp_info.transport, PJ_EEOF);
  poll();

  // The proxy sends the best response (a 408) to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(408).matches(tdata->msg);
  free_txdata();

  // Send an ACK to complete the UAS transaction.
  msg1._method = "ACK";
  inject_msg(msg1.get_request(), tp);

  _basic_proxy->remove_test_targets("sip:bob@homedomain");

  delete tp;
}


TEST_F(BasicProxyTest, ForkedRequestCancel)
{
  // Tests CANCELing a forked of request to a home domain RequestURI.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Add three test targets for bob@homedomain, all with a URI plus a path with a
  // single proxy.
  _basic_proxy->add_test_target("sip:bob@homedomain",
                                "sip:bob@node1.homedomain;transport=TCP",
                                std::list<std::string>(1, "sip:proxy1.homedomain;transport=TCP;lr"));
  _basic_proxy->add_test_target("sip:bob@homedomain",
                                "sip:bob@node2.homedomain;transport=TCP",
                                std::list<std::string>(1, "sip:proxy1.homedomain;transport=TCP;lr"));
  _basic_proxy->add_test_target("sip:bob@homedomain",
                                "sip:bob@node3.homedomain;transport=TCP",
                                std::list<std::string>(1, "sip:proxy2.homedomain;transport=TCP;lr"));

  // Inject a request with a Route header referring to this node and a
  // RequestURI with a URI in the home domain.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:local_ip;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and three forwarded INVITEs
  ASSERT_EQ(4, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Catch the request forked to node1.homedomain via proxy1.homedomain.
  pjsip_tx_data* tdata1 = pop_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata1);
  ReqMatcher("INVITE").matches(tdata1->msg);
  ASSERT_EQ("sip:bob@node1.homedomain;transport=TCP",
            str_uri(tdata1->msg->line.req.uri));
  ASSERT_EQ("Route: <sip:proxy1.homedomain;transport=TCP;lr>",
            get_headers(tdata1->msg, "Route"));

  // Catch the request forked to node2.homedomain via proxy1.homedomain.
  pjsip_tx_data* tdata2 = pop_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata2);
  ReqMatcher("INVITE").matches(tdata2->msg);
  ASSERT_EQ("sip:bob@node2.homedomain;transport=TCP",
            str_uri(tdata2->msg->line.req.uri));
  ASSERT_EQ("Route: <sip:proxy1.homedomain;transport=TCP;lr>",
            get_headers(tdata2->msg, "Route"));

  // Catch the request forked to node3.homedomain via proxy2.homedomain.
  pjsip_tx_data* tdata3 = pop_txdata();
  expect_target("TCP", "10.10.10.2", 5060, tdata3);
  ReqMatcher("INVITE").matches(tdata3->msg);
  ASSERT_EQ("sip:bob@node3.homedomain;transport=TCP",
            str_uri(tdata3->msg->line.req.uri));
  ASSERT_EQ("Route: <sip:proxy2.homedomain;transport=TCP;lr>",
            get_headers(tdata3->msg, "Route"));

  // Send 100 Trying responses from all three nodes, and check they are
  // absorbed.
  inject_msg(respond_to_txdata(tdata1, 100));
  ASSERT_EQ(0, txdata_count());
  inject_msg(respond_to_txdata(tdata2, 100));
  ASSERT_EQ(0, txdata_count());
  inject_msg(respond_to_txdata(tdata3, 100));
  ASSERT_EQ(0, txdata_count());

  // Send a 480 response from the first target, and check the proxy absorbs
  // this while waiting for a better offer.
  inject_msg(respond_to_txdata(tdata1, 480));
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // Send a CANCEL from the originator.
  Message msg2;
  msg2._method = "CANCEL";
  msg2._requri = "sip:bob@homedomain;transport=TCP";
  msg2._from = "alice";
  msg2._to = "bob";
  msg2._todomain = "awaydomain";
  msg2._via = tp->to_string(false);
  msg2._unique = msg1._unique;    // Make sure branch and call-id are same as the INVITE
  inject_msg(msg2.get_request(), tp);

  // Expect both a 200 OK response to the CANCEL and CANCELs on the two
  // outstanding forked transactions.
  ASSERT_EQ(3, txdata_count());

  // Check the 200 OK.
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Check the CANCEL is forwarded to node2.homedomain via proxy1.homedomain
  // and send a 200 OK response (which is absorbed by the proxy).
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata);
  ReqMatcher("CANCEL").matches(tdata->msg);
  inject_msg(respond_to_current_txdata(200));

  // Check the CANCEL is forwarded to node3.homedomain via proxy2.homedomain
  // and send a 200 OK response (which is absorbed by the proxy).
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.2", 5060, tdata);
  ReqMatcher("CANCEL").matches(tdata->msg);
  inject_msg(respond_to_current_txdata(200));
  ASSERT_EQ(0, txdata_count());

  // Send 487 response from node2.homedomain.  Check that this is ACKed
  // and absorbed.
  inject_msg(respond_to_txdata(tdata2, 487));
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata);
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // Send 480 response from node3.homedomain (this crossed with the CANCEL).
  // Check that this is ACKed.
  inject_msg(respond_to_txdata(tdata3, 480));
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.2", 5060, tdata);
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // A 487 response is now forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(487).matches(tdata->msg);
  free_txdata();

  // Send an ACK to complete the UAS transaction.
  msg1._method = "ACK";
  inject_msg(msg1.get_request(), tp);

  _basic_proxy->remove_test_targets("sip:bob@homedomain");

  delete tp;
}


TEST_F(BasicProxyTest, RouteToHomeURINotFound)
{
  // Tests routing of requests to a home domain RequestURI which isn't found.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header referring to this node and a
  // RequestURI with a URI in the home domain.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:local_ip;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and a 404 Not Found response.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Check the 404 Not Found.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(404).matches(tdata->msg);
  free_txdata();

  delete tp;
}


TEST_F(BasicProxyTest, StrictRouterUpstream)
{
  // Tests routing of requests when upstream and/or downstream proxies are
  // "strict routers".

  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with this node in the RequestURI and Route headers
  // indicating the onward Route.  This is the expected request if the
  // upstream proxy is a strict router.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:local_ip";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy1.awaydomain;transport=TCP;lr>\r\nRoute: <sip:bob@awaydomain>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check the RequestURI has been rewritten to the URI from the final Route header.
  ASSERT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));

  // Check the last Route header has been removed.
  ASSERT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>",
            get_headers(tdata->msg, "Route"));

  // Check no Record-Route headers have been added.
  ASSERT_EQ("", get_headers(tdata->msg, "Record-Route"));

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  // Inject a request with this node in the RequestURI and no Route headers
  // indicating an onward Route.  This is the expected request if the
  // upstream proxy is a strict router.
  Message msg2;
  msg2._method = "INVITE";
  msg2._requri = "sip:local_ip";
  msg2._from = "alice";
  msg2._to = "bob";
  msg2._todomain = "awaydomain";
  msg2._via = tp->to_string(false);
  //msg2._route = "Route: <sip:proxy1.awaydomain;transport=TCP;lr>\r\nRoute: <sip:bob@awaydomain>";
  inject_msg(msg2.get_request(), tp);

  // Expecting 100 Trying and then a 404 response.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Check the 404 response.
  tdata = current_txdata();
  RespMatcher(404).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Send an ACK to complete the UAS transaction.
  msg1._method = "ACK";
  inject_msg(msg1.get_request(), tp);

  delete tp;
}


TEST_F(BasicProxyTest, StrictRouterDownstream)
{
  // Tests routing of requests when upstream and/or downstream proxies are
  // "strict routers".

  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with this node in the first Route header and another
  // domain in the second Route headers, with no lr parameter in the second
  // Route header.  This is the form of request expected if the downstream
  // proxy is a strict router.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:local_ip;transport=TCP;lr>\r\nRoute: <sip:proxy1.awaydomain;transport=TCP>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Request is forwarded to the node in the second Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check the RequestURI has been rewritten with the URI from the second Route
  // header.
  ASSERT_EQ("sip:proxy1.awaydomain;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check the first Route header has been removed and the second Route header
  // rewritten with the RequestURI
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:bob@awaydomain>", route);

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  delete tp;
}


TEST_F(BasicProxyTest, StatelessForwardResponse)
{
  // Tests stateless forwarding of responses (this can happen to 200 OK
  // response retries if the ACK is delayed).

  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header not referencing this node or the
  // home domain.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check the RequestURI has not been altered.
  ASSERT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));

  // Check the Route header has not been removed.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>", route);

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Save the forwarded INVITE so we can generate multiple responses.
  pjsip_tx_data* invite_tdata = pop_txdata();

  // Send a 200 OK response.
  inject_msg(respond_to_txdata(invite_tdata, 200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  // Leave some time for the transactions to be destroyed.
  poll();

  // Resend the 200 OK response.
  inject_msg(respond_to_txdata(invite_tdata, 200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  delete tp;
}


TEST_F(BasicProxyTest, StatelessForwardACK)
{
  // Tests stateless forwarding of ACK.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header not referencing this node or the
  // home domain.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check the RequestURI has not been altered.
  ASSERT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));

  // Check the Route header has not been removed.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>", route);

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  // Send an ACK with Route headers traversing the proxy.  (This wouldn't
  // normally happen since the BasicProxy does not RecordRoute itself.)
  Message msg2;
  msg2._method = "ACK";
  msg2._requri = "sip:bob@awaydomain";
  msg2._from = "alice";
  msg2._to = "bob";
  msg2._todomain = "awaydomain";
  msg2._via = tp->to_string(false);
  msg2._route = "Route: <sip:local_ip;transport=TCP;lr>\r\nRoute: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg2.get_request(), tp);

  // Request is forwarded to the node in the second Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("ACK").matches(tdata->msg);

  // Check the RequestURI has not been altered.
  ASSERT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));

  // Check the top Route header has been removed.
  route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>", route);

  // Check no Record-Route headers have been added.
  rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  delete tp;
}


TEST_F(BasicProxyTest, LateCancel)
{
  // Tests CANCELing a request after the request has completed.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Add three test targets for bob@homedomain, all with a URI plus a path with a
  // single proxy.
  _basic_proxy->add_test_target("sip:bob@homedomain",
                                "sip:bob@node1.homedomain;transport=TCP",
                                std::list<std::string>(1, "sip:proxy1.homedomain;transport=TCP;lr"));

  // Inject a request with a Route header referring to this node and a
  // RequestURI with a URI in the home domain.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:local_ip;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and the forwarded INVITEs
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Catch the request forwarded to node1.homedomain via proxy1.homedomain.
  pjsip_tx_data* tdata1 = pop_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata1);
  ReqMatcher("INVITE").matches(tdata1->msg);
  ASSERT_EQ("sip:bob@node1.homedomain;transport=TCP",
            str_uri(tdata1->msg->line.req.uri));
  ASSERT_EQ("Route: <sip:proxy1.homedomain;transport=TCP;lr>",
            get_headers(tdata1->msg, "Route"));

  // Send 100 Trying responses from the downstream nodes, and check it is
  // absorbed.
  inject_msg(respond_to_txdata(tdata1, 100));
  ASSERT_EQ(0, txdata_count());

  // Send a 200 OK response from the second target.
  inject_msg(respond_to_txdata(tdata1, 200));

  // Check the 200 OK is forwarded immediately to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  // Now wait for the UAS transaction to terminate, which will cancel
  // the outstanding forked transaction.
  poll();

  // Send a CANCEL from the originator.
  Message msg2;
  msg2._method = "CANCEL";
  msg2._requri = "sip:bob@homedomain;transport=TCP";
  msg2._from = "alice";
  msg2._to = "bob";
  msg2._todomain = "awaydomain";
  msg2._via = tp->to_string(false);
  msg2._unique = msg1._unique;    // Make sure branch and call-id are same as the INVITE
  inject_msg(msg2.get_request(), tp);

  // Check that the CANCEL is rejected with 481 response since original
  // transaction has ended.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(481).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  _basic_proxy->remove_test_targets("sip:bob@homedomain");

  delete tp;
}


TEST_F(BasicProxyTest, RequestErrors)
{
  // Tests various errors on requests.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a INVITE request with a tel: RequestURI
  Message msg1;
  msg1._method = "INVITE";
  msg1._toscheme = "tel";
  msg1._from = "alice";
  msg1._to = "+2425551234";
  msg1._todomain = "";
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


TEST_F(BasicProxyTest, ResponseErrors)
{
  // Tests various errors on stateless responses.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header not referencing this node or the
  // home domain.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check the RequestURI has not been altered.
  ASSERT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));

  // Check the Route header has not been removed.
  string route = get_headers(tdata->msg, "Route");
  ASSERT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>", route);

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  ASSERT_EQ("", rr);

  // Save the forwarded INVITE so we can generate multiple responses.
  pjsip_tx_data* invite_tdata = pop_txdata();

  // Send a 200 OK response.
  inject_msg(respond_to_txdata(invite_tdata, 200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  // Leave some time for the transactions to be destroyed.
  poll();

  // Resend the 200 OK response, but remove the second Via header, so the
  // proxy cannot stateless forward it.
  pjsip_tx_data* rsp_tdata = create_response(invite_tdata, 200, NULL);
  pjsip_via_hdr* via = (pjsip_via_hdr*)pjsip_msg_find_hdr(rsp_tdata->msg,
                                                          PJSIP_H_VIA,
                                                          NULL);
  via = (pjsip_via_hdr*)pjsip_msg_find_hdr(rsp_tdata->msg,
                                           PJSIP_H_VIA,
                                           via->next);
  pj_list_erase(via);
  char buf[16384];
  pjsip_msg_print(rsp_tdata->msg, buf, sizeof(buf));
  pjsip_tx_data_dec_ref(rsp_tdata);
  inject_msg(std::string(buf));
  ASSERT_EQ(0, txdata_count());

  // Resend the 200 OK response, but remove the received parameter from the
  // second Via header.  The proxy can recover this by using the sent-by
  // address instead.
  rsp_tdata = create_response(invite_tdata, 200, NULL);
  via = (pjsip_via_hdr*)pjsip_msg_find_hdr(rsp_tdata->msg,
                                                          PJSIP_H_VIA,
                                                          NULL);
  via = (pjsip_via_hdr*)pjsip_msg_find_hdr(rsp_tdata->msg,
                                           PJSIP_H_VIA,
                                           via->next);
  via->recvd_param.slen = 0;
  pjsip_msg_print(rsp_tdata->msg, buf, sizeof(buf));
  pjsip_tx_data_dec_ref(rsp_tdata);
  inject_msg(std::string(buf));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  // Resend the 200 OK response, but remove the rport parameter from the
  // second Via header.  The proxy can recover this by using the sent-by
  // port instead.
  rsp_tdata = create_response(invite_tdata, 200, NULL);
  via = (pjsip_via_hdr*)pjsip_msg_find_hdr(rsp_tdata->msg,
                                                          PJSIP_H_VIA,
                                                          NULL);
  via = (pjsip_via_hdr*)pjsip_msg_find_hdr(rsp_tdata->msg,
                                           PJSIP_H_VIA,
                                           via->next);
  via->rport_param = 0;
  pjsip_msg_print(rsp_tdata->msg, buf, sizeof(buf));
  pjsip_tx_data_dec_ref(rsp_tdata);
  inject_msg(std::string(buf));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  delete tp;
}

