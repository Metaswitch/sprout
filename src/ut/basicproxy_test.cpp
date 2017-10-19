/**
 * @file basicproxy_test.cpp UT for BasicProxy class.
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
#include "basicproxy.h"
#include "test_utils.hpp"
#include "fakehssconnection.hpp"
#include "faketransport_tcp.hpp"
#include "test_interposer.hpp"
#include "testingcommon.h"

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
    BasicProxy(endpt,
               "UTProxy",
               priority,
               false,
               std::set<std::string>({"stateless-proxy.awaydomain"}))
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
      TRC_DEBUG("Failed to find test targets for AOR %s", aor.c_str());
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
        // manually configured in the test case.
        TRC_DEBUG("Check for test targets");
        std::string aor = PJUtils::public_id_from_uri(_req->msg->line.req.uri);
        std::list<BasicProxyUT::TestTarget> test_targets = ((BasicProxyUT*)_proxy)->find_test_targets(aor);
        TRC_DEBUG("Found %d targets for %s", test_targets.size(), aor.c_str());

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
  /// TX data for testing.  Will be cleaned up.  Each message in a
  /// forked flow has its URI stored in _uris, and its txdata stored
  /// in _tdata against that URI.

  /// Set up test case.  Caller must clear host_mapping.
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();

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
    _log_traffic = PrintingTestLogger::DEFAULT.isPrinting(); // true to see all traffic
  }

  ~BasicProxyTestBase()
  {
    // Give any transactions in progress a chance to complete.
    poll();

    pjsip_tsx_layer_dump(true);

    // Terminate all transactions.
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

    // Stop and restart the transaction layer just in case.
    pjsip_tsx_layer_instance()->stop();
    pjsip_tsx_layer_instance()->start();
  }

protected:
  static BasicProxyUT* _basic_proxy;

};

BasicProxyUT* BasicProxyTestBase::_basic_proxy;


class BasicProxyTest : public BasicProxyTestBase
{
public:
  static void SetUpTestCase()
  {
    BasicProxyTestBase::SetUpTestCase();

    // Set up DNS mappings for destinations.
    add_host_mapping("proxy1.homedomain", "10.10.10.1");
    add_host_mapping("proxy2.homedomain", "10.10.10.2");
    add_host_mapping("node1.homedomain", "10.10.18.1");
    add_host_mapping("node2.homedomain", "10.10.18.2");
    add_host_mapping("node2.homedomain", "10.10.18.3");
    add_host_mapping("node2.homedomain", "10.10.18.4");

    add_host_mapping("proxy1.awaydomain", "10.10.20.1");
    add_host_mapping("proxy2.awaydomain", "10.10.20.2");
    add_host_mapping("node1.awaydomain", "10.10.28.1");
    add_host_mapping("node2.awaydomain", "10.10.28.2");
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

using TestingCommon::Message;

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
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check the RequestURI has not been altered.
  EXPECT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));

  // Check the Route header has not been removed.
  string route = get_headers(tdata->msg, "Route");
  EXPECT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>", route);

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  EXPECT_EQ("", rr);

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
  msg2._first_hop = true;
  msg2._method = "INVITE";
  msg2._requri = "sip:bob@awaydomain";
  msg2._from = "alice";
  msg2._to = "bob";
  msg2._todomain = "awaydomain";
  msg2._via = tp->to_string(false);
  msg2._route = "Route: <sip:127.0.0.1;transport=TCP;lr>\r\nRoute: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg2.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Request is forwarded to the node in the second Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check the RequestURI has not been altered.
  EXPECT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));

  // Check the first Route header has been removed, but the second remains.
  route = get_headers(tdata->msg, "Route");
  EXPECT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>", route);

  // Check no Record-Route headers have been added.
  rr = get_headers(tdata->msg, "Record-Route");
  EXPECT_EQ("", rr);

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

TEST_F(BasicProxyTest, RouteOnRouteHeadersWithTelURI)
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
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "tel:1231231231";
  msg1._from = "alice";
  msg1._to = "1231231231";
  msg1._todomain = "";
  msg1._toscheme = "tel";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <tel:1231231231>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check the RequestURI has not been altered.
  EXPECT_EQ("tel:1231231231", str_uri(tdata->msg->line.req.uri));

  // Check the Route header has not been removed.
  string route = get_headers(tdata->msg, "Route");
  EXPECT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>", route);
  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  EXPECT_EQ("", rr);

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
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@proxy1.awaydomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Request is forwarded to the node in RequestURI.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check the RequestURI has not been altered.
  EXPECT_EQ("sip:bob@proxy1.awaydomain;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check no Route headers have been added.
  string route = get_headers(tdata->msg, "Route");
  EXPECT_EQ("", route);

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  EXPECT_EQ("", rr);

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
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:127.0.0.1;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // The proxy resolves the requestURI to the test target bob@node1.homedomain.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.18.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check the RequestURI has been altered.
  EXPECT_EQ("sip:bob@node1.homedomain;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check the Route header has been removed.
  string route = get_headers(tdata->msg, "Route");
  EXPECT_EQ("", route);

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  EXPECT_EQ("", rr);

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
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:127.0.0.1;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // The proxy resolves the requestURI to the test target bob@node1.homedomain
  // with path via proxy1.homedomain.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check the RequestURI has been altered.
  EXPECT_EQ("sip:bob@node1.homedomain;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check the Route header has been removed and a new one added for the path.
  string route = get_headers(tdata->msg, "Route");
  EXPECT_EQ("Route: <sip:proxy1.homedomain;transport=TCP;lr>", route);

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  EXPECT_EQ("", rr);

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
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp1->to_string(false);
  msg1._route = "Route: <sip:127.0.0.1;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp1);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp1->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // The proxy resolves the requestURI to the test target bob@node1.homedomain
  // using transport tp2.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp2->expect_target(tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check the RequestURI has been altered.
  EXPECT_EQ("sip:bob@node1.homedomain;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check the Route header has been removed.
  string route = get_headers(tdata->msg, "Route");
  EXPECT_EQ("", route);

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  EXPECT_EQ("", rr);

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
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp1->to_string(false);
  msg1._route = "Route: <sip:127.0.0.1;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp1);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp1->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // The proxy resolves the requestURI to the test target bob@node1.homedomain
  // using transport tp2.
  ASSERT_EQ(1, txdata_count());
  pjsip_tx_data* tdata1 = pop_txdata();
  tp2->expect_target(tdata1);
  ReqMatcher("INVITE").matches(tdata1->msg);
  EXPECT_EQ("sip:bob@node1.homedomain;transport=TCP", str_uri(tdata1->msg->line.req.uri));
  EXPECT_EQ("", get_headers(tdata1->msg, "Route"));
  EXPECT_EQ("", get_headers(tdata1->msg, "Record-Route"));

  // Send 100 Trying from the downstream node.
  inject_msg(respond_to_txdata(tdata1, 100));
  ASSERT_EQ(0, txdata_count());

  // Send a CANCEL from the originator.
  Message msg2;
  msg2._first_hop = true;
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
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:127.0.0.1;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and five forwarded INVITEs.
  ASSERT_EQ(6, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Catch the request forked to node1.homedomain via proxy1.homedomain.
  pjsip_tx_data* tdata1 = pop_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata1);
  ReqMatcher("INVITE").matches(tdata1->msg);
  EXPECT_EQ("sip:bob@node1.homedomain;transport=TCP",
            str_uri(tdata1->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy1.homedomain;transport=TCP;lr>",
            get_headers(tdata1->msg, "Route"));

  // Catch the request forked to node2.homedomain via proxy1.homedomain.
  pjsip_tx_data* tdata2 = pop_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata2);
  ReqMatcher("INVITE").matches(tdata2->msg);
  EXPECT_EQ("sip:bob@node2.homedomain;transport=TCP",
            str_uri(tdata2->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy1.homedomain;transport=TCP;lr>",
            get_headers(tdata2->msg, "Route"));

  // Catch the request forked to node3.homedomain via proxy2.homedomain.
  pjsip_tx_data* tdata3 = pop_txdata();
  expect_target("TCP", "10.10.10.2", 5060, tdata3);
  ReqMatcher("INVITE").matches(tdata3->msg);
  EXPECT_EQ("sip:bob@node3.homedomain;transport=TCP",
            str_uri(tdata3->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy2.homedomain;transport=TCP;lr>",
            get_headers(tdata3->msg, "Route"));

  // Catch the request forked to node4.homedomain via proxy2.homedomain.
  pjsip_tx_data* tdata4 = pop_txdata();
  expect_target("TCP", "10.10.10.2", 5060, tdata4);
  ReqMatcher("INVITE").matches(tdata4->msg);
  EXPECT_EQ("sip:bob@node4.homedomain;transport=TCP",
            str_uri(tdata4->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy2.homedomain;transport=TCP;lr>",
            get_headers(tdata4->msg, "Route"));

  // Catch the request forked to node5.homedomain via proxy2.homedomain.
  pjsip_tx_data* tdata5 = pop_txdata();
  expect_target("TCP", "10.10.10.2", 5060, tdata5);
  ReqMatcher("INVITE").matches(tdata5->msg);
  EXPECT_EQ("sip:bob@node5.homedomain;transport=TCP",
            str_uri(tdata5->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy2.homedomain;transport=TCP;lr>",
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
  ASSERT_EQ(1, txdata_count());
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

  // Add four test targets for bob@homedomain, all with a URI plus a path with a
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
  _basic_proxy->add_test_target("sip:bob@homedomain",
                                "sip:bob@node4.homedomain;transport=TCP",
                                std::list<std::string>(1, "sip:proxy2.homedomain;transport=TCP;lr"));

  // Inject a request with a Route header referring to this node and a
  // RequestURI with a URI in the home domain.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:127.0.0.1;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and four forwarded INVITEs.
  ASSERT_EQ(5, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Catch the request forked to node1.homedomain via proxy1.homedomain.
  pjsip_tx_data* tdata1 = pop_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata1);
  ReqMatcher("INVITE").matches(tdata1->msg);
  EXPECT_EQ("sip:bob@node1.homedomain;transport=TCP",
            str_uri(tdata1->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy1.homedomain;transport=TCP;lr>",
            get_headers(tdata1->msg, "Route"));

  // Catch the request forked to node2.homedomain via proxy2.homedomain.
  pjsip_tx_data* tdata2 = pop_txdata();
  expect_target("TCP", "10.10.10.2", 5060, tdata2);
  ReqMatcher("INVITE").matches(tdata2->msg);
  EXPECT_EQ("sip:bob@node2.homedomain;transport=TCP",
            str_uri(tdata2->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy2.homedomain;transport=TCP;lr>",
            get_headers(tdata2->msg, "Route"));

  // Catch the request forked to node2.homedomain via proxy2.homedomain.
  pjsip_tx_data* tdata3 = pop_txdata();
  expect_target("TCP", "10.10.10.2", 5060, tdata3);
  ReqMatcher("INVITE").matches(tdata3->msg);
  EXPECT_EQ("sip:bob@node3.homedomain;transport=TCP",
            str_uri(tdata3->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy2.homedomain;transport=TCP;lr>",
            get_headers(tdata3->msg, "Route"));

  // Catch the request forked to node3.homedomain via proxy2.homedomain.
  pjsip_tx_data* tdata4 = pop_txdata();
  expect_target("TCP", "10.10.10.2", 5060, tdata4);
  ReqMatcher("INVITE").matches(tdata4->msg);
  EXPECT_EQ("sip:bob@node4.homedomain;transport=TCP",
            str_uri(tdata4->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy2.homedomain;transport=TCP;lr>",
            get_headers(tdata4->msg, "Route"));

  // Send 100 Trying responses from all four nodes, and check they are absorbed.
  inject_msg(respond_to_txdata(tdata1, 100));
  ASSERT_EQ(0, txdata_count());
  inject_msg(respond_to_txdata(tdata2, 100));
  ASSERT_EQ(0, txdata_count());
  inject_msg(respond_to_txdata(tdata3, 100));
  ASSERT_EQ(0, txdata_count());
  inject_msg(respond_to_txdata(tdata4, 100));
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
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // Send a 604 Not Found reponse from the fourth target.
  inject_msg(respond_to_txdata(tdata4, 604));
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // The proxy sends the best response (the 604) to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(604).matches(tdata->msg);
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
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:127.0.0.1;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and three forwarded INVITEs.
  ASSERT_EQ(3, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Catch the request forked to node1.homedomain via proxy1.homedomain.
  pjsip_tx_data* tdata1 = pop_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata1);
  ReqMatcher("INVITE").matches(tdata1->msg);
  EXPECT_EQ("sip:bob@node1.homedomain;transport=TCP",
            str_uri(tdata1->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy1.homedomain;transport=TCP;lr>",
            get_headers(tdata1->msg, "Route"));

  // Catch the request forked to node2.homedomain via proxy2.homedomain.
  pjsip_tx_data* tdata2 = pop_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata2);
  ReqMatcher("INVITE").matches(tdata2->msg);
  EXPECT_EQ("sip:bob@node2.homedomain;transport=TCP",
            str_uri(tdata2->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy1.homedomain;transport=TCP;lr>",
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
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:127.0.0.1;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and three forwarded INVITEs.
  ASSERT_EQ(4, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Catch the request forked to node1.homedomain via proxy1.homedomain.
  pjsip_tx_data* tdata1 = pop_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata1);
  ReqMatcher("INVITE").matches(tdata1->msg);
  EXPECT_EQ("sip:bob@node1.homedomain;transport=TCP",
            str_uri(tdata1->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy1.homedomain;transport=TCP;lr>",
            get_headers(tdata1->msg, "Route"));

  // Catch the request forked to node2.homedomain via proxy1.homedomain.
  pjsip_tx_data* tdata2 = pop_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata2);
  ReqMatcher("INVITE").matches(tdata2->msg);
  EXPECT_EQ("sip:bob@node2.homedomain;transport=TCP",
            str_uri(tdata2->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy1.homedomain;transport=TCP;lr>",
            get_headers(tdata2->msg, "Route"));

  // Catch the request forked to node3.homedomain via proxy2.homedomain.
  pjsip_tx_data* tdata3 = pop_txdata();
  expect_target("TCP", "10.10.10.2", 5060, tdata3);
  ReqMatcher("INVITE").matches(tdata3->msg);
  EXPECT_EQ("sip:bob@node3.homedomain;transport=TCP",
            str_uri(tdata3->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy2.homedomain;transport=TCP;lr>",
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
  msg2._first_hop = true;
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


TEST_F(BasicProxyTest, ForkedRequest6xx)
{
  // Tests forking of request to a home domain RequestURI where one
  // downstream transaction fails with 6xx and we cancel all the others.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Add three test targets for bob@homedomain, both with a URI plus a path with a
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
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:127.0.0.1;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and three forwarded INVITEs.
  ASSERT_EQ(4, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Catch the request forked to node1.homedomain via proxy1.homedomain.
  pjsip_tx_data* tdata1 = pop_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata1);
  ReqMatcher("INVITE").matches(tdata1->msg);
  EXPECT_EQ("sip:bob@node1.homedomain;transport=TCP",
            str_uri(tdata1->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy1.homedomain;transport=TCP;lr>",
            get_headers(tdata1->msg, "Route"));

  // Catch the request forked to node2.homedomain via proxy2.homedomain.
  pjsip_tx_data* tdata2 = pop_txdata();
  expect_target("TCP", "10.10.10.2", 5060, tdata2);
  ReqMatcher("INVITE").matches(tdata2->msg);
  EXPECT_EQ("sip:bob@node2.homedomain;transport=TCP",
            str_uri(tdata2->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy2.homedomain;transport=TCP;lr>",
            get_headers(tdata2->msg, "Route"));

  // Catch the request forked to node3.homedomain via proxy2.homedomain.
  pjsip_tx_data* tdata3 = pop_txdata();
  expect_target("TCP", "10.10.10.2", 5060, tdata3);
  ReqMatcher("INVITE").matches(tdata3->msg);
  EXPECT_EQ("sip:bob@node3.homedomain;transport=TCP",
            str_uri(tdata3->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy2.homedomain;transport=TCP;lr>",
            get_headers(tdata3->msg, "Route"));

  // Send 100 Trying responses from all three nodes, and check they are absorbed.
  inject_msg(respond_to_txdata(tdata1, 100));
  ASSERT_EQ(0, txdata_count());
  inject_msg(respond_to_txdata(tdata2, 100));
  ASSERT_EQ(0, txdata_count());
  inject_msg(respond_to_txdata(tdata3, 100));
  ASSERT_EQ(0, txdata_count());

  // Send a 600 response from the first target and expect an ACK.
  inject_msg(respond_to_txdata(tdata1, 600));
  ASSERT_EQ(3, txdata_count());
  tdata = current_txdata();
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // Also expect CANCEL at node2.homedomain.  Send a 200 OK.
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.2", 5060, tdata);
  ReqMatcher("CANCEL").matches(tdata->msg);
  inject_msg(respond_to_current_txdata(200));

  // Also expect CANCEL at node3.homedomain.  Send a 200 OK.
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.2", 5060, tdata);
  ReqMatcher("CANCEL").matches(tdata->msg);
  inject_msg(respond_to_current_txdata(200));

  // Send 487 response from node2.homedomain.  Check that this is ACKed.
  inject_msg(respond_to_txdata(tdata2, 487));
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.2", 5060, tdata);
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // Send 604 response from node3.homedomain.  Check that this is ACKed.
  inject_msg(respond_to_txdata(tdata3, 604));
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.2", 5060, tdata);
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // The proxy sends the best response (the 600) to the source.
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(600).matches(tdata->msg);
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
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:127.0.0.1;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and a 404 Not Found response.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
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
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:127.0.0.1";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy1.awaydomain;transport=TCP;lr>\r\nRoute: <sip:bob@awaydomain>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check the RequestURI has been rewritten to the URI from the final Route header.
  EXPECT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));

  // Check the last Route header has been removed.
  EXPECT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>",
            get_headers(tdata->msg, "Route"));

  // Check no Record-Route headers have been added.
  EXPECT_EQ("", get_headers(tdata->msg, "Record-Route"));

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
  msg2._first_hop = true;
  msg2._method = "INVITE";
  msg2._requri = "sip:127.0.0.1";
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
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
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
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:127.0.0.1;transport=TCP;lr>\r\nRoute: <sip:proxy1.awaydomain;transport=TCP>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Request is forwarded to the node in the second Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check the RequestURI has been rewritten with the URI from the second Route
  // header.
  EXPECT_EQ("sip:proxy1.awaydomain;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check the first Route header has been removed and the second Route header
  // rewritten with the RequestURI.
  string route = get_headers(tdata->msg, "Route");
  EXPECT_EQ("Route: <sip:bob@awaydomain>", route);

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  EXPECT_EQ("", rr);

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


TEST_F(BasicProxyTest, StrictRouterTelUri)
{
  // Tests routing of TEL URI requests when downstream proxy is a "strict
  // router".

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
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "tel:+1234";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:127.0.0.1;transport=TCP;lr>\r\nRoute: <sip:proxy1.awaydomain;transport=TCP>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

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
  EXPECT_EQ("sip:proxy1.awaydomain;transport=TCP", str_uri(tdata->msg->line.req.uri));

  // Check the first Route header has been removed and the second Route header
  // rewritten with the RequestURI.
  string route = get_headers(tdata->msg, "Route");
  EXPECT_EQ("Route: <tel:+1234>", route);

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  EXPECT_EQ("", rr);

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
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check the RequestURI has not been altered.
  EXPECT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));

  // Check the Route header has not been removed.
  string route = get_headers(tdata->msg, "Route");
  EXPECT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>", route);

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  EXPECT_EQ("", rr);

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
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check the RequestURI has not been altered.
  EXPECT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));

  // Check the Route header has not been removed.
  string route = get_headers(tdata->msg, "Route");
  EXPECT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>", route);

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  EXPECT_EQ("", rr);

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
  msg2._first_hop = true;
  msg2._method = "ACK";
  msg2._requri = "sip:bob@awaydomain";
  msg2._from = "alice";
  msg2._to = "bob";
  msg2._todomain = "awaydomain";
  msg2._via = tp->to_string(false);
  msg2._route = "Route: <sip:127.0.0.1;transport=TCP;lr>\r\nRoute: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg2.get_request(), tp);

  // Request is forwarded to the node in the second Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("ACK").matches(tdata->msg);

  // Check the RequestURI has not been altered.
  EXPECT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));

  // Check the top Route header has been removed.
  route = get_headers(tdata->msg, "Route");
  EXPECT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>", route);

  // Check no Record-Route headers have been added.
  rr = get_headers(tdata->msg, "Record-Route");
  EXPECT_EQ("", rr);

  delete tp;
}


TEST_F(BasicProxyTest, StatelessForwardLargeACK)
{
  // Tests stateless forwarding of a large ACK where the onward hop is
  // over UDP.  This tests that switching to TCP works.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Send an ACK with Route headers traversing the proxy, with a large message
  // body.  The second Route header specifies UDP transport.
  Message msg;
  msg._first_hop = true;
  msg._method = "ACK";
  msg._requri = "sip:bob@awaydomain";
  msg._from = "alice";
  msg._to = "bob";
  msg._todomain = "awaydomain";
  msg._via = tp->to_string(false);
  msg._route = "Route: <sip:127.0.0.1;transport=TCP;lr>\r\nRoute: <sip:proxy1.awaydomain;transport=UDP;lr>";
  msg._body = std::string(1300, '!');
  inject_msg(msg.get_request(), tp);

  // Request is forwarded to the node in the second Route header, over TCP
  // not UDP.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // Create a UDP flow and force this as a target for bob@homedomain.
  TransportFlow* tp2 = new TransportFlow(TransportFlow::Protocol::UDP,
                                        stack_data.scscf_port,
                                        "5.6.7.8",
                                        49322);
  _basic_proxy->add_test_target("sip:bob@homedomain",
                                "sip:bob@5.6.7.8:49322;transport=UDP",
                                tp2->transport());

  // Send an ACK with no Route headers directed at bob@homedomain, with a
  // large message body.
  msg._method = "ACK";
  msg._requri = "sip:bob@homedomain";
  msg._from = "alice";
  msg._to = "bob";
  msg._todomain = "homedomain";
  msg._via = tp->to_string(false);
  msg._body = std::string(1300, '!');
  inject_msg(msg.get_request(), tp);

  // Request is forwarded to the UDP flow, not switched to TCP.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp2->expect_target(tdata);
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  _basic_proxy->remove_test_targets("sip:bob@homedomain");

  delete tp2;
  delete tp;

}


TEST_F(BasicProxyTest, StatelessForwardLargeACKNoUplift)
{
  // Tests stateless forwarding of a large ACK where the onward hop is
  // over UDP.  We've disabled UDP-to-TCP uplift so this now tests that
  // switching to TCP doesn't happen.
  pjsip_tx_data* tdata;

  // Set the disable TCP switch option in PJSIP so that uplift does not
  // happen.
  pjsip_cfg_t* pjsip_config = pjsip_cfg();
  pjsip_config->endpt.disable_tcp_switch = true;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Send an ACK with Route headers traversing the proxy, with a large message
  // body.  The second Route header specifies UDP transport.
  Message msg;
  msg._first_hop = true;
  msg._method = "ACK";
  msg._requri = "sip:bob@awaydomain";
  msg._from = "alice";
  msg._to = "bob";
  msg._todomain = "awaydomain";
  msg._via = tp->to_string(false);
  msg._route = "Route: <sip:127.0.0.1;transport=TCP;lr>\r\nRoute: <sip:proxy1.awaydomain;transport=UDP;lr>";
  msg._body = std::string(1300, '!');
  inject_msg(msg.get_request(), tp);

  // Request is forwarded to the node in the second Route header, over UDP
  // not TCP.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("FAKE_UDP", "0.0.0.0", 0, tdata);
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // Create a UDP flow and force this as a target for bob@homedomain.
  TransportFlow* tp2 = new TransportFlow(TransportFlow::Protocol::UDP,
                                        stack_data.scscf_port,
                                        "5.6.7.8",
                                        49322);
  _basic_proxy->add_test_target("sip:bob@homedomain",
                                "sip:bob@5.6.7.8:49322;transport=UDP",
                                tp2->transport());

  // Send an ACK with no Route headers directed at bob@homedomain, with a
  // large message body.
  msg._method = "ACK";
  msg._requri = "sip:bob@homedomain";
  msg._from = "alice";
  msg._to = "bob";
  msg._todomain = "homedomain";
  msg._via = tp->to_string(false);
  msg._body = std::string(1300, '!');
  inject_msg(msg.get_request(), tp);

  // Request is forwarded to the UDP flow, not switched to TCP.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp2->expect_target(tdata);
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  _basic_proxy->remove_test_targets("sip:bob@homedomain");

  delete tp2;
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
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:127.0.0.1;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and the forwarded INVITEs.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Catch the request forwarded to node1.homedomain via proxy1.homedomain.
  pjsip_tx_data* tdata1 = pop_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata1);
  ReqMatcher("INVITE").matches(tdata1->msg);
  EXPECT_EQ("sip:bob@node1.homedomain;transport=TCP",
            str_uri(tdata1->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy1.homedomain;transport=TCP;lr>",
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
  msg2._first_hop = true;
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

  // Inject a INVITE request with a tel: RequestURI.
  Message msg1;
  msg1._first_hop = true;
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
  msg2._first_hop = true;
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

  // Inject an INVITE request on a transport which is shutting down.  It is safe
  // to call pjsip_transport_shutdown on a TCP transport as the TransportFlow
  // keeps a reference to the transport so it won't actually be destroyed until
  // the TransportFlow is destroyed.
  pjsip_transport_shutdown(tp->transport());

  Message msg3;
  msg3._first_hop = true;
  msg3._method = "INVITE";
  msg3._requri = "sip:bob@awaydomain";
  msg3._from = "alice";
  msg3._to = "bob";
  msg3._todomain = "awaydomain";
  msg3._via = tp->to_string(false);
  msg3._route = "Route: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg3.get_request(), tp);

  // Check the 504 Service Unavailable response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(503).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Send an ACK to complete the UAS transaction.
  msg3._method = "ACK";
  inject_msg(msg3.get_request(), tp);

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
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check the RequestURI has not been altered.
  EXPECT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));

  // Check the Route header has not been removed.
  string route = get_headers(tdata->msg, "Route");
  EXPECT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>", route);

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  EXPECT_EQ("", rr);

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

  // Resend the 200 OK response, but change the CSEQ method to REGISTER, so the
  // proxy will not stateless forward it.
  rsp_tdata = create_response(invite_tdata, 200, NULL);
  pjsip_cseq_hdr* cseq = (pjsip_cseq_hdr*)pjsip_msg_find_hdr(rsp_tdata->msg,
                                                             PJSIP_H_CSEQ,
                                                             NULL);
  cseq->method.id = PJSIP_REGISTER_METHOD;
  cseq->method.name = pj_str("REGISTER");

  pjsip_msg_print(rsp_tdata->msg, buf, sizeof(buf));
  pjsip_tx_data_dec_ref(rsp_tdata);
  inject_msg(std::string(buf));
  ASSERT_EQ(0, txdata_count());

  delete tp;
}


TEST_F(BasicProxyTest, DnsResolutionFailure)
{
  // Tests handling of request when the DNS resolution of the next hop fails.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header not referencing this node or the
  // home domain, and with a domain name in the top route which is not
  // configured in DNS.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy-x.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying followed by 408 Request Timeout response.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(100).matches(tdata->msg);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Check the 408 Request Timeout.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(408).matches(tdata->msg);
  free_txdata();

  delete tp;
}


TEST_F(BasicProxyTest, DontRetryOnTimeout)
{
  // Tests a server timing out a transaction and _not_ retrying.
  // Long-term, we should retry, but we need to shorten the transaction
  // timeout for this to make sense - 32s without alerting is too long!

  pjsip_tx_data* tdata;

  // Add a host mapping for proxy-x.awaydomain to four IP addresses.
  add_host_mapping("proxy-x.awaydomain", "10.10.10.100,10.10.10.101,10.10.10.102,10.10.10.103");

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header not referencing this node or the
  // home domain.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy-x.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check that it was sent to one of the server addresses.
  EXPECT_STREQ("TCP", tdata->tp_info.transport->type_name) << "Wrong transport type";
  EXPECT_EQ(5060, tdata->tp_info.transport->remote_name.port) << "Wrong transport port";
  string server1 = str_pj(tdata->tp_info.transport->remote_name.host);
  if ((server1 != "10.10.10.100") &&
      (server1 != "10.10.10.101") &&
      (server1 != "10.10.10.102") &&
      (server1 != "10.10.10.103"))
  {
    ADD_FAILURE_AT(__FILE__, __LINE__) << "Unexpected server address " << server1;
  }

  // Check the RequestURI, Route and Record-Route headers.
  EXPECT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy-x.awaydomain;transport=TCP;lr>",
            get_headers(tdata->msg, "Route"));
  EXPECT_EQ("", get_headers(tdata->msg, "Record-Route"));

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  EXPECT_EQ("", rr);

  free_txdata();

  // This server doesn't respond, so advance time to trigger the timeout.
  cwtest_advance_time_ms(33000);
  poll();

  // Check a 408 timeout response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(408).matches(tdata->msg);
  free_txdata();

  delete tp;
}


TEST_F(BasicProxyTest, RetryOnTransportError)
{
  // Tests retrying to an alternate server on a transport error.

  pjsip_tx_data* tdata;

  // Add a host mapping for proxy-x.awaydomain to four IP addresses.
  add_host_mapping("proxy-x.awaydomain", "10.10.10.100,10.10.10.101,10.10.10.102,10.10.10.103");

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header not referencing this node or the
  // home domain.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy-x.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check that it was sent to one of the server addresses.
  EXPECT_STREQ("TCP", tdata->tp_info.transport->type_name) << "Wrong transport type";
  EXPECT_EQ(5060, tdata->tp_info.transport->remote_name.port) << "Wrong transport port";
  string server1 = str_pj(tdata->tp_info.transport->remote_name.host);
  if ((server1 != "10.10.10.100") &&
      (server1 != "10.10.10.101") &&
      (server1 != "10.10.10.102") &&
      (server1 != "10.10.10.103"))
  {
    ADD_FAILURE_AT(__FILE__, __LINE__) << "Unexpected server address " << server1;
  }

  // Check the RequestURI, Route and Record-Route headers.
  EXPECT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy-x.awaydomain;transport=TCP;lr>",
            get_headers(tdata->msg, "Route"));
  EXPECT_EQ("", get_headers(tdata->msg, "Record-Route"));

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  EXPECT_EQ("", rr);

  // Kill the transport the request was sent on.
  fake_tcp_init_shutdown((fake_tcp_transport*)tdata->tp_info.transport, PJ_EEOF);
  free_txdata();
  poll();

  // Check that the request has been redirected to another server.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check that it was sent to one of the server addresses.
  EXPECT_STREQ("TCP", tdata->tp_info.transport->type_name) << "Wrong transport type";
  EXPECT_EQ(5060, tdata->tp_info.transport->remote_name.port) << "Wrong transport port";
  string server2 = str_pj(tdata->tp_info.transport->remote_name.host);
  EXPECT_STRNE(server2.c_str(), server1.c_str()) << "Request retried to same server";
  if ((server2 != "10.10.10.100") &&
      (server2 != "10.10.10.101") &&
      (server2 != "10.10.10.102") &&
      (server2 != "10.10.10.103"))
  {
    ADD_FAILURE_AT(__FILE__, __LINE__) << "Unexpected server address " << server2;
  }

  // Check the RequestURI, Route and Record-Route headers.
  EXPECT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy-x.awaydomain;transport=TCP;lr>",
            get_headers(tdata->msg, "Route"));
  EXPECT_EQ("", get_headers(tdata->msg, "Record-Route"));

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

TEST_F(BasicProxyTest, StopsRetryingAfterManyFailures)
{
  // Tests that if all servers fail the request stops retrying after 5 retries.
  // (5 is currently the default set in PJ Utils)

  pjsip_tx_data* tdata;

  // Add a host mapping for proxy-x.awaydomain to six IP addresses.
  add_host_mapping("proxy-x.awaydomain",
                   "10.10.10.100,10.10.10.101,10.10.10.102,10.10.10.103,10.10.10.104,10.10.10.105,10.10.10.106,10.10.10.107,10.10.10.108,10.10.10.109");

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.5",
                                        49152);

  // Inject a request with a Route header not referencing this node or the
  // home domain.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy-x.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("INVITE").matches(tdata->msg);

  // Try to send the request 5 times, and have the request fail after each
  // attempt due to a transport error. Verify that after 5 failed attempts the
  // request stops being retried, despite there being addresses left to try.
  for (int ii = 0; ii < 5; ++ii)
  {
    // Check that it was sent to one of the server addresses.
    EXPECT_STREQ("TCP", tdata->tp_info.transport->type_name) << "Wrong transport type";
    EXPECT_EQ(5060, tdata->tp_info.transport->remote_name.port) << "Wrong transport port";
    string server1 = str_pj(tdata->tp_info.transport->remote_name.host);
    EXPECT_THAT(server1, MatchesRegex("10.10.10.10[0-9]")) << "Unexpected server address " << server1;

    // Kill the transport the request was sent on.
    fake_tcp_init_shutdown((fake_tcp_transport*)tdata->tp_info.transport, PJ_EEOF);
    free_txdata();
    poll();

    if (ii < 4)
    {
      // There are attempts left, so check that the request has been redirected
      // to another server.
      ASSERT_EQ(1, txdata_count());
      tdata = current_txdata();
      ReqMatcher("INVITE").matches(tdata->msg);
    }
  }

  // The 5th retry just failed, so check that the request is not retried,
  // and instead it fails and this failure of the request is reported.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(408).matches(tdata->msg); // Response is a 408 Timeout.

  free_txdata();

  delete tp;
}


TEST_F(BasicProxyTest, StopsRetryingIfFewAddresses)
{
  // Tests that if there are fewer than 5 addresses, the BasicProxy stops
  // retrying once it rusn out of targets and reports that the request has
  // failed.

  pjsip_tx_data* tdata;

  // Add a host mapping for proxy-x.awaydomain to six IP addresses.
  add_host_mapping("proxy-x.awaydomain",
                   "10.10.10.100,10.10.10.101,10.10.10.102,10.10.10.103");

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.5",
                                        49152);

  // Inject a request with a Route header not referencing this node or the
  // home domain.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy-x.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("INVITE").matches(tdata->msg);

  // Try to send the request 4 times, and have the request fail after each
  // attempt due to a transport error. Verify that after there stops being any
  // addresses left to try, the request fails and this is reported.
  for (int ii = 0; ii < 4; ++ii)
  {
    // Check that it was sent to one of the server addresses.
    EXPECT_STREQ("TCP", tdata->tp_info.transport->type_name) << "Wrong transport type";
    EXPECT_EQ(5060, tdata->tp_info.transport->remote_name.port) << "Wrong transport port";
    string server1 = str_pj(tdata->tp_info.transport->remote_name.host);
    EXPECT_THAT(server1, MatchesRegex("10.10.10.10[0-3]")) << "Unexpected server address " << server1;

    // Kill the transport the request was sent on.
    fake_tcp_init_shutdown((fake_tcp_transport*)tdata->tp_info.transport, PJ_EEOF);
    free_txdata();
    poll();

    if (ii < 3)
    {
      // There are addresses left, so check that the request has been redirected
      // to another server.
      ASSERT_EQ(1, txdata_count());
      tdata = current_txdata();
      ReqMatcher("INVITE").matches(tdata->msg);
    }
  }

  // There are no addresses left, so check that the request is not retried
  // again, and its failure is reported.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(408).matches(tdata->msg); // Response is a 408 Timeout.

  free_txdata();

  delete tp;
}


TEST_F(BasicProxyTest, RetryOn5xx)
{
  // Tests retrying to an alternate server on a 5xx response.

  pjsip_tx_data* tdata;

  // Add a host mapping for proxy-x.awaydomain to four IP addresses.
  add_host_mapping("proxy-x.awaydomain", "10.10.10.100,10.10.10.101,10.10.10.102,10.10.10.103");

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header not referencing this node or the
  // home domain.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy-x.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check that it was sent to one of the server addresses.
  EXPECT_STREQ("TCP", tdata->tp_info.transport->type_name) << "Wrong transport type";
  EXPECT_EQ(5060, tdata->tp_info.transport->remote_name.port) << "Wrong transport port";
  string server1 = str_pj(tdata->tp_info.transport->remote_name.host);
  if ((server1 != "10.10.10.100") &&
      (server1 != "10.10.10.101") &&
      (server1 != "10.10.10.102") &&
      (server1 != "10.10.10.103"))
  {
    ADD_FAILURE_AT(__FILE__, __LINE__) << "Unexpected server address " << server1;
  }

  // Check the RequestURI, Route and Record-Route headers.
  EXPECT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy-x.awaydomain;transport=TCP;lr>",
            get_headers(tdata->msg, "Route"));
  EXPECT_EQ("", get_headers(tdata->msg, "Record-Route"));

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  EXPECT_EQ("", rr);

  // Send a 503 response to the request and catch the ACK.
  inject_msg(respond_to_current_txdata(503));
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // Check that the request has been redirected to another server.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check that it was sent to one of the server addresses.
  EXPECT_STREQ("TCP", tdata->tp_info.transport->type_name) << "Wrong transport type";
  EXPECT_EQ(5060, tdata->tp_info.transport->remote_name.port) << "Wrong transport port";
  string server2 = str_pj(tdata->tp_info.transport->remote_name.host);
  EXPECT_STRNE(server2.c_str(), server1.c_str()) << "Request retried to same server";
  if ((server2 != "10.10.10.100") &&
      (server2 != "10.10.10.101") &&
      (server2 != "10.10.10.102") &&
      (server2 != "10.10.10.103"))
  {
    ADD_FAILURE_AT(__FILE__, __LINE__) << "Unexpected server address " << server2;
  }

  // Check the RequestURI, Route and Record-Route headers.
  EXPECT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy-x.awaydomain;transport=TCP;lr>",
            get_headers(tdata->msg, "Route"));
  EXPECT_EQ("", get_headers(tdata->msg, "Record-Route"));

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


TEST_F(BasicProxyTest, RetryFailed)
{
  // Tests retrying to an alternate server on a 5xx response, which also responds
  // with a 5xx response.

  pjsip_tx_data* tdata;

  // Add a host mapping for proxy-x.awaydomain to two IP addresses.
  add_host_mapping("proxy-x.awaydomain", "10.10.10.100,10.10.10.101");

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header not referencing this node or the
  // home domain.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy-x.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check that it was sent to one of the server addresses.
  EXPECT_STREQ("TCP", tdata->tp_info.transport->type_name) << "Wrong transport type";
  EXPECT_EQ(5060, tdata->tp_info.transport->remote_name.port) << "Wrong transport port";
  string server1 = str_pj(tdata->tp_info.transport->remote_name.host);
  if ((server1 != "10.10.10.100") &&
      (server1 != "10.10.10.101"))
  {
    ADD_FAILURE_AT(__FILE__, __LINE__) << "Unexpected server address " << server1;
  }

  // Check the RequestURI, Route and Record-Route headers.
  EXPECT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy-x.awaydomain;transport=TCP;lr>",
            get_headers(tdata->msg, "Route"));
  EXPECT_EQ("", get_headers(tdata->msg, "Record-Route"));

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  EXPECT_EQ("", rr);

  // Send a 503 response to the request and catch the ACK.
  inject_msg(respond_to_current_txdata(503));
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // Check that the request has been redirected to another server.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check that it was sent to one of the server addresses.
  EXPECT_STREQ("TCP", tdata->tp_info.transport->type_name) << "Wrong transport type";
  EXPECT_EQ(5060, tdata->tp_info.transport->remote_name.port) << "Wrong transport port";
  string server2 = str_pj(tdata->tp_info.transport->remote_name.host);
  EXPECT_STRNE(server2.c_str(), server1.c_str()) << "Request retried to same server";
  if ((server2 != "10.10.10.100") &&
      (server2 != "10.10.10.101"))
  {
    ADD_FAILURE_AT(__FILE__, __LINE__) << "Unexpected server address " << server2;
  }

  // Check the RequestURI, Route and Record-Route headers.
  EXPECT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy-x.awaydomain;transport=TCP;lr>",
            get_headers(tdata->msg, "Route"));
  EXPECT_EQ("", get_headers(tdata->msg, "Record-Route"));

  // Send a 503 response to the request and catch the ACK.
  inject_msg(respond_to_current_txdata(503));
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // Check the 503 response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(503).matches(tdata->msg);
  free_txdata();

  // Send an ACK to complete the UAS transaction.
  msg1._method = "ACK";
  inject_msg(msg1.get_request(), tp);

  delete tp;
}


TEST_F(BasicProxyTest, NonInvite100Trying)
{
  // Tests 100 Trying for non-INVITEs.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header not referencing this node or the
  // home domain.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "REGISTER";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Check the forwarded REGISTER.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("REGISTER").matches(tdata->msg);

  // Check the RequestURI has not been altered.
  EXPECT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));

  // Check the Route header has not been removed.
  string route = get_headers(tdata->msg, "Route");
  EXPECT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>", route);

  // Check no Record-Route headers have been added.
  string rr = get_headers(tdata->msg, "Record-Route");
  EXPECT_EQ("", rr);
  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  Message msg2;
  msg2._first_hop = true;
  msg2._method = "REGISTER";
  msg2._requri = "sip:bob@awaydomain";
  msg2._from = "alice";
  msg2._to = "bob";
  msg2._todomain = "awaydomain";
  msg2._via = tp->to_string(false);
  msg2._route = "Route: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg2.get_request(), tp);

  // Check the forwarded REGISTER.
  ASSERT_EQ(1, txdata_count());
  pjsip_tx_data* tdata1 = pop_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata1);
  ReqMatcher("REGISTER").matches(tdata1->msg);

  // Check the RequestURI has not been altered.
  EXPECT_EQ("sip:bob@awaydomain", str_uri(tdata1->msg->line.req.uri));

  // Check the Route header has not been removed.
  route = get_headers(tdata1->msg, "Route");
  EXPECT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>", route);

  // Check no Record-Route headers have been added.
  rr = get_headers(tdata1->msg, "Record-Route");
  EXPECT_EQ("", rr);

  // Advance time, and check the 100 Trying was created.
  cwtest_advance_time_ms(4000);
  poll();

  ASSERT_EQ(1, txdata_count());
  pjsip_tx_data* tdata2 = current_txdata();
  RespMatcher(100).matches(tdata2->msg);
  tp->expect_target(tdata2);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata2->msg, "To")); // No tag
  free_txdata();

  // Send a 200 OK response.
  inject_msg(respond_to_txdata(tdata1, 200, ""));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata2 = current_txdata();
  tp->expect_target(tdata2);
  RespMatcher(200).matches(tdata2->msg);
  free_txdata();

  delete tp;
}


TEST_F(BasicProxyTest, ContentHeaders)
{
  // Tests handling of Content-Length and Content-Type headers (mainly to
  // verify fixes to problems that resulted in multiple Content-Length and
  // Content-Type headers.

  pjsip_tx_data* tdata;
  char buf[1000];
  int len;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Send an ACK with Route headers traversing the proxy, with no message body
  // and check it comes out the other side with only one Content-Length
  // header and no Content-Type header.
  Message msg;
  msg._first_hop = true;
  msg._method = "ACK";
  msg._requri = "sip:bob@awaydomain";
  msg._from = "alice";
  msg._to = "bob";
  msg._todomain = "awaydomain";
  msg._via = tp->to_string(false);
  msg._route = "Route: <sip:127.0.0.1;transport=TCP;lr>\r\nRoute: <sip:proxy1.awaydomain;transport=TCP;lr>";
  msg._content_type = "";
  inject_msg(msg.get_request(), tp);

  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();

  // To force the problem to show up we need to print the message to a buffer
  // and parse it back.  Arguably we should do this for every message in the UTs.
  len = pjsip_msg_print(tdata->msg, buf, sizeof(buf));
  tdata->msg = pjsip_parse_msg(tdata->pool, buf, len, NULL);
  EXPECT_EQ("Content-Length: 0", get_headers(tdata->msg, "Content-Length"));
  EXPECT_EQ("", get_headers(tdata->msg, "Content-Type"));
  free_txdata();

  // Send an ACK with Route headers traversing the proxy, with no message body
  // and a Content-Type header, and check it comes out the other side with
  // only one Content-Length header (with length zero) and the Content-Type
  // header intact.
  msg._method = "ACK";
  msg._requri = "sip:bob@awaydomain";
  msg._from = "alice";
  msg._to = "bob";
  msg._todomain = "awaydomain";
  msg._via = tp->to_string(false);
  msg._route = "Route: <sip:127.0.0.1;transport=TCP;lr>\r\nRoute: <sip:proxy1.awaydomain;transport=TCP;lr>";
  msg._content_type = "text/html";
  inject_msg(msg.get_request(), tp);

  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  len = pjsip_msg_print(tdata->msg, buf, sizeof(buf));
  tdata->msg = pjsip_parse_msg(tdata->pool, buf, len, NULL);
  EXPECT_EQ("Content-Length: 0", get_headers(tdata->msg, "Content-Length"));
  EXPECT_EQ("Content-Type: text/html", get_headers(tdata->msg, "Content-Type"));
  free_txdata();

  // Send an ACK with Route headers traversing the proxy, with a message body
  // and a Content-Type header, and check it comes out the other side with
  // only one Content-Length header (with the right length) and the Content-Type
  // header intact.
  msg._method = "ACK";
  msg._requri = "sip:bob@awaydomain";
  msg._from = "alice";
  msg._to = "bob";
  msg._todomain = "awaydomain";
  msg._via = tp->to_string(false);
  msg._route = "Route: <sip:127.0.0.1;transport=TCP;lr>\r\nRoute: <sip:proxy1.awaydomain;transport=TCP;lr>";
  msg._content_type = "application/sdp";
  msg._body = "v=0\r\no=alice 53655765 2353687637 IN IP4 pc33.atlanta.com\r\ns=-\r\nt=0 0\r\nc=IN IP4 pc33.atlanta.com\r\nm=audio 3456 RTP/AVP 0 1 3 99\r\na=rtpmap:0 PCMU/8000\r\n\r\n";
  inject_msg(msg.get_request(), tp);

  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  len = pjsip_msg_print(tdata->msg, buf, sizeof(buf));
  tdata->msg = pjsip_parse_msg(tdata->pool, buf, len, NULL);
  EXPECT_EQ("Content-Length: 152", get_headers(tdata->msg, "Content-Length"));
  EXPECT_EQ("Content-Type: application/sdp", get_headers(tdata->msg, "Content-Type"));
  free_txdata();

  delete tp;
}


TEST_F(BasicProxyTest, InviteTimerCExpiryCancelled)
{
  // Tests expiry of Timer C on an INVITE transaction.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Add a test target for bob@homedomain.
  _basic_proxy->add_test_target("sip:bob@homedomain",
                                "sip:bob@node1.homedomain;transport=TCP",
                                std::list<std::string>(1, "sip:proxy1.homedomain;transport=TCP;lr"));

  // Inject a request with a Route header referring to this node and a
  // RequestURI with a URI in the home domain.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:127.0.0.1;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and a forwarded INVITE.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Catch the request forwarded to node1.homedomain via proxy1.homedomain.
  pjsip_tx_data* tdata1 = pop_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata1);
  ReqMatcher("INVITE").matches(tdata1->msg);
  EXPECT_EQ("sip:bob@node1.homedomain;transport=TCP",
            str_uri(tdata1->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy1.homedomain;transport=TCP;lr>",
            get_headers(tdata1->msg, "Route"));

  // Send a 100 Trying.
  inject_msg(respond_to_txdata(tdata1, 100));
  ASSERT_EQ(0, txdata_count());

  // The transaction timers are no longer running, but Timer C is running, so
  // advance time so that timer C expires.
  cwtest_advance_time_ms(180000);
  poll();

  // Expect a CANCEL on the outstanding transaction and send a 200 OK response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata);
  ReqMatcher("CANCEL").matches(tdata->msg);
  inject_msg(respond_to_current_txdata(200));

  // Send a 487 response to the original INVITE transaction and check this
  // is ACKed and passed through.
  inject_msg(respond_to_txdata(tdata1, 487));
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();
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

TEST_F(BasicProxyTest, InviteTimerCExpiryRace)
{
  // Tests expiry of Timer C on an INVITE transaction where the CANCEL loses
  // the race with a final response from the downstream node.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Add a test target for bob@homedomain.
  _basic_proxy->add_test_target("sip:bob@homedomain",
                                "sip:bob@node1.homedomain;transport=TCP",
                                std::list<std::string>(1, "sip:proxy1.homedomain;transport=TCP;lr"));

  // Inject a request with a Route header referring to this node and a
  // RequestURI with a URI in the home domain.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:127.0.0.1;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and a forwarded INVITE.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Catch the request forwarded to node1.homedomain via proxy1.homedomain.
  pjsip_tx_data* tdata1 = pop_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata1);
  ReqMatcher("INVITE").matches(tdata1->msg);
  EXPECT_EQ("sip:bob@node1.homedomain;transport=TCP",
            str_uri(tdata1->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy1.homedomain;transport=TCP;lr>",
            get_headers(tdata1->msg, "Route"));

  // Send a 100 Trying.
  inject_msg(respond_to_txdata(tdata1, 100));
  ASSERT_EQ(0, txdata_count());

  // The transaction timers are no longer running, but Timer C is running, so
  // advance time so that timer C expires.
  cwtest_advance_time_ms(180000);
  poll();

  // Expect a CANCEL on the outstanding transaction, but don't respond immediately.
  ASSERT_EQ(1, txdata_count());
  pjsip_tx_data* cancel = pop_txdata();
  expect_target("TCP", "10.10.10.1", 5060, cancel);
  ReqMatcher("CANCEL").matches(cancel->msg);

  // Send a 408 response to the original INVITE transaction and check this
  // is ACKed and passed through.
  inject_msg(respond_to_txdata(tdata1, 408));
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(408).matches(tdata->msg);
  free_txdata();

  // Send an ACK to complete the UAS transaction.
  msg1._method = "ACK";
  inject_msg(msg1.get_request(), tp);

  // Delay briefly to allow the INVITE transactions to be completed and destroyed.
  cwtest_advance_time_ms(1000);
  poll();

  // Send in a late CANCEL failure response, and check that this is absorbed.
  inject_msg(respond_to_txdata(cancel, 481));
  ASSERT_EQ(0, txdata_count());

  _basic_proxy->remove_test_targets("sip:bob@homedomain");

  delete tp;
}


TEST_F(BasicProxyTest, InviteTimerCExpiryCancelTimeout)
{
  // Tests expiry of Timer C on an INVITE transaction where the CANCEL
  // times out.

  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Add a test target for bob@homedomain.
  _basic_proxy->add_test_target("sip:bob@homedomain",
                                "sip:bob@node1.homedomain;transport=TCP",
                                std::list<std::string>(1, "sip:proxy1.homedomain;transport=TCP;lr"));

  // Inject a request with a Route header referring to this node and a
  // RequestURI with a URI in the home domain.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:127.0.0.1;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and a forwarded INVITE.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Catch the request forwarded to node1.homedomain via proxy1.homedomain.
  pjsip_tx_data* tdata1 = pop_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata1);
  ReqMatcher("INVITE").matches(tdata1->msg);
  EXPECT_EQ("sip:bob@node1.homedomain;transport=TCP",
            str_uri(tdata1->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy1.homedomain;transport=TCP;lr>",
            get_headers(tdata1->msg, "Route"));

  // Send a 100 Trying.
  inject_msg(respond_to_txdata(tdata1, 100));
  ASSERT_EQ(0, txdata_count());

  // The transaction timers are no longer running, but Timer C is running, so
  // advance time so that timer C expires.
  cwtest_advance_time_ms(180000);
  poll();

  // Expect a CANCEL on the outstanding transaction, but don't respond immediately.
  ASSERT_EQ(1, txdata_count());
  pjsip_tx_data* cancel = pop_txdata();
  expect_target("TCP", "10.10.10.1", 5060, cancel);
  ReqMatcher("CANCEL").matches(cancel->msg);

  // Advance time so the CANCEL transaction times out.
  cwtest_advance_time_ms(32000);
  poll();

  // Receive a 487 response to the original INVITE transaction.
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


// Check that a target is blacklisted if a transaction to it times out.
TEST_F(BasicProxyTest, BlacklistOnTimeout)
{
  pjsip_tx_data* tdata;

  // Set up SRV records so that proxy-x has a higher priority than proxy-y,
  // meaning x will always be chosen in preference to y unless x is
  // blacklisted.
  std::vector<DnsRRecord*> srv_records;
  srv_records.push_back(new DnsSrvRecord("_sip._tcp.proxy.awaydomain",
                                         36000000,
                                         1,
                                         100,
                                         5060,
                                         "proxy-x.awaydomain"));
  srv_records.push_back(new DnsSrvRecord("_sip._tcp.proxy.awaydomain",
                                         36000000,
                                         2,
                                         100,
                                         5060,
                                         "proxy-y.awaydomain"));
  _dnsresolver.add_to_cache("_sip._tcp.proxy.awaydomain", ns_t_srv, srv_records);

  add_host_mapping("proxy-x.awaydomain", "10.10.10.100");
  add_host_mapping("proxy-y.awaydomain", "10.10.10.101");

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header not referencing this node or the
  // home domain.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check that it was sent to the first server.
  EXPECT_STREQ("TCP", tdata->tp_info.transport->type_name) << "Wrong transport type";
  EXPECT_EQ(5060, tdata->tp_info.transport->remote_name.port) << "Wrong transport port";
  string server1 = str_pj(tdata->tp_info.transport->remote_name.host);
  EXPECT_EQ(server1, "10.10.10.100");
  free_txdata();

  // This server doesn't respond, so advance time to trigger the timeout.
  cwtest_advance_time_ms(33000);
  poll();

  // Check a 408 Timeout response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(408).matches(tdata->msg);
  free_txdata();

  // Now inject another INVITE.
  msg1._unique++;
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check that it was sent to the second server (the first is blacklisted).
  EXPECT_STREQ("TCP", tdata->tp_info.transport->type_name) << "Wrong transport type";
  EXPECT_EQ(5060, tdata->tp_info.transport->remote_name.port) << "Wrong transport port";
  server1 = str_pj(tdata->tp_info.transport->remote_name.host);
  EXPECT_EQ(server1, "10.10.10.101");

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


// Checks that if there is a successful call to a graylisted target it moves to
// the whitelist.
TEST_F(BasicProxyTest, GraylistToWhitelistOnCallSuccess)
{
  pjsip_tx_data* tdata;

  // Set up SRV records so that proxy-x has a higher priority than proxy-y,
  // meaning x will always be chosen in preference to y unless x is
  // blacklisted.
  std::vector<DnsRRecord*> srv_records;
  srv_records.push_back(new DnsSrvRecord("_sip._tcp.proxy.awaydomain",
                                         36000000,
                                         1,
                                         100,
                                         5060,
                                         "proxy-x.awaydomain"));
  srv_records.push_back(new DnsSrvRecord("_sip._tcp.proxy.awaydomain",
                                         36000000,
                                         2,
                                         100,
                                         5060,
                                         "proxy-y.awaydomain"));
  _dnsresolver.add_to_cache("_sip._tcp.proxy.awaydomain", ns_t_srv, srv_records);

  add_host_mapping("proxy-x.awaydomain", "10.10.10.100");
  add_host_mapping("proxy-y.awaydomain", "10.10.10.101");

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
  msg1._route = "Route: <sip:proxy.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check that it was sent to the first server.
  EXPECT_STREQ("TCP", tdata->tp_info.transport->type_name) << "Wrong transport type";
  EXPECT_EQ(5060, tdata->tp_info.transport->remote_name.port) << "Wrong transport port";
  string server1 = str_pj(tdata->tp_info.transport->remote_name.host);
  EXPECT_EQ(server1, "10.10.10.100");
  free_txdata();

  // This server doesn't respond, so advance time to trigger the timeout.
  cwtest_advance_time_ms(33000);
  poll();

  // Check a 408 Timeout response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(408).matches(tdata->msg);
  free_txdata();

  // Wait for the server to move onto the graylist.
  cwtest_advance_time_ms(33000);
  poll();

  // Now inject another INVITE.
  msg1._unique++;
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check that it was sent to the first server, since that server is graylisted
  // and so is being probed by this request. The fact that an INVITE message was
  // successfully sent means that success is reported on that server, moving it
  // to the whitelist.
  EXPECT_STREQ("TCP", tdata->tp_info.transport->type_name) << "Wrong transport type";
  EXPECT_EQ(5060, tdata->tp_info.transport->remote_name.port) << "Wrong transport port";
  server1 = str_pj(tdata->tp_info.transport->remote_name.host);
  EXPECT_EQ(server1, "10.10.10.100");

  // Send a 200 OK response for the request.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  // Now inject another INVITE.
  msg1._unique++;
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check that it was sent to the first server, since it has been moved back to
  // the whitelist following its successful probing.
  EXPECT_STREQ("TCP", tdata->tp_info.transport->type_name) << "Wrong transport type";
  EXPECT_EQ(5060, tdata->tp_info.transport->remote_name.port) << "Wrong transport port";
  server1 = str_pj(tdata->tp_info.transport->remote_name.host);
  EXPECT_EQ(server1, "10.10.10.100");

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


// Test that a failed graylist probe does not ungraylist the target.
TEST_F(BasicProxyTest, FailedProbeDoesNotUngraylist)
{
  pjsip_tx_data* tdata;

  // Set up SRV records so that proxy-x has a higher priority than proxy-y.
  std::vector<DnsRRecord*> srv_records;
  srv_records.push_back(new DnsSrvRecord("_sip._tcp.proxy.awaydomain",
                                         36000000,
                                         1,
                                         100,
                                         5060,
                                         "proxy-x.awaydomain"));
  srv_records.push_back(new DnsSrvRecord("_sip._tcp.proxy.awaydomain",
                                         36000000,
                                         2,
                                         100,
                                         5060,
                                         "proxy-y.awaydomain"));
  _dnsresolver.add_to_cache("_sip._tcp.proxy.awaydomain", ns_t_srv, srv_records);

  add_host_mapping("proxy-x.awaydomain", "10.10.10.100");
  add_host_mapping("proxy-y.awaydomain", "10.10.10.101");

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
  msg1._route = "Route: <sip:proxy.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check that it was sent to the first server.
  EXPECT_STREQ("TCP", tdata->tp_info.transport->type_name) << "Wrong transport type";
  EXPECT_EQ(5060, tdata->tp_info.transport->remote_name.port) << "Wrong transport port";
  string server1 = str_pj(tdata->tp_info.transport->remote_name.host);
  EXPECT_EQ(server1, "10.10.10.100");
  free_txdata();

  // This server doesn't respond, so advance time to trigger the timeout.
  cwtest_advance_time_ms(33000);
  poll();

  // Check a 408 Timeout response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(408).matches(tdata->msg);
  free_txdata();

  // Wait for the server to move onto the graylist.
  cwtest_advance_time_ms(33000);
  poll();

  // Now inject another INVITE.
  msg1._unique++;
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check that it was sent to the first server, since that server is graylisted
  // and so is being probed by this request. The fact that an INVITE message was
  // successfully sent means that success is reported on that server, moving it
  // to the whitelist.
  EXPECT_STREQ("TCP", tdata->tp_info.transport->type_name) << "Wrong transport type";
  EXPECT_EQ(5060, tdata->tp_info.transport->remote_name.port) << "Wrong transport port";
  server1 = str_pj(tdata->tp_info.transport->remote_name.host);
  EXPECT_EQ(server1, "10.10.10.100");
  free_txdata();

  // Now inject a third INVITE. This should go to the second server as the first
  // is being probed.
  msg1._unique++;
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check that it was sent to the first server, since that server is graylisted
  // and so is being probed by this request. The fact that an INVITE message was
  // successfully sent means that success is reported on that server, moving it
  // to the whitelist.
  EXPECT_STREQ("TCP", tdata->tp_info.transport->type_name) << "Wrong transport type";
  EXPECT_EQ(5060, tdata->tp_info.transport->remote_name.port) << "Wrong transport port";
  server1 = str_pj(tdata->tp_info.transport->remote_name.host);
  EXPECT_EQ(server1, "10.10.10.101");

  // Send a 200 OK response for the request.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  // This server doesn't respond, so advance time to trigger the timeout.
  cwtest_advance_time_ms(33000);
  poll();

  // Check a 408 Timeout response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(408).matches(tdata->msg);
  free_txdata();

  delete tp;
}


// Test that an ACK does not blacklist a target (due to not getting a response).
TEST_F(BasicProxyTest, AckDoesNotBlacklist)
{
  pjsip_tx_data* tdata;

  // Set up SRV records so that proxy-x has a higher priority than proxy-y.
  std::vector<DnsRRecord*> srv_records;
  srv_records.push_back(new DnsSrvRecord("_sip._tcp.proxy.awaydomain",
                                         36000000,
                                         1,
                                         100,
                                         5060,
                                         "proxy-x.awaydomain"));
  srv_records.push_back(new DnsSrvRecord("_sip._tcp.proxy.awaydomain",
                                         36000000,
                                         2,
                                         100,
                                         5060,
                                         "proxy-y.awaydomain"));
  _dnsresolver.add_to_cache("_sip._tcp.proxy.awaydomain", ns_t_srv, srv_records);

  add_host_mapping("proxy-x.awaydomain", "10.10.10.100");
  add_host_mapping("proxy-y.awaydomain", "10.10.10.101");

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header not referencing this node or the
  // home domain.
  Message msg1;
  msg1._method = "ACK";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("ACK").matches(tdata->msg);

  // Check that it was sent to the first server.
  EXPECT_STREQ("TCP", tdata->tp_info.transport->type_name) << "Wrong transport type";
  EXPECT_EQ(5060, tdata->tp_info.transport->remote_name.port) << "Wrong transport port";
  string server1 = str_pj(tdata->tp_info.transport->remote_name.host);
  EXPECT_EQ(server1, "10.10.10.100");
  free_txdata();

  // Now inject an INVITE.
  msg1._unique++;
  msg1._method = "INVITE";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check that it was sent to the first server, which should not have been
  // blacklisted by being sent an ACK.
  EXPECT_STREQ("TCP", tdata->tp_info.transport->type_name) << "Wrong transport type";
  EXPECT_EQ(5060, tdata->tp_info.transport->remote_name.port) << "Wrong transport port";
  server1 = str_pj(tdata->tp_info.transport->remote_name.host);
  EXPECT_EQ(server1, "10.10.10.100");

  // Send a 200 OK response for the request.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  delete tp;
}


// Check that a stateless proxy is NOT blacklisted if a transaction to it times
// out.
TEST_F(BasicProxyTest, StatelessProxyNoBlacklistOnTimeout)
{
  pjsip_tx_data* tdata;

  // Set up SRV records so that proxy-x has a higher priority than proxy-y,
  // meaning x will always be chosen in preference to y unless x is
  // blacklisted.
  //
  // Note that "stateless-proxy.awaydomain" is configured in the test fixture
  // as being a stateless proxy.
  std::vector<DnsRRecord*> srv_records;
  srv_records.push_back(new DnsSrvRecord("_sip._tcp.stateless-proxy.awaydomain",
                                         36000000,
                                         1,
                                         100,
                                         5060,
                                         "stateless-proxy-x.awaydomain"));
  srv_records.push_back(new DnsSrvRecord("_sip._tcp.stateless-proxy.awaydomain",
                                         36000000,
                                         2,
                                         100,
                                         5060,
                                         "stateless-proxy-y.awaydomain"));
  _dnsresolver.add_to_cache("_sip._tcp.stateless-proxy.awaydomain", ns_t_srv, srv_records);

  add_host_mapping("stateless-proxy-x.awaydomain", "10.10.10.100");
  add_host_mapping("stateless-proxy-y.awaydomain", "10.10.10.101");

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header not referencing this node or the
  // home domain.
  Message msg1;
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:stateless-proxy.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check that it was sent to the first server.
  EXPECT_STREQ("TCP", tdata->tp_info.transport->type_name) << "Wrong transport type";
  EXPECT_EQ(5060, tdata->tp_info.transport->remote_name.port) << "Wrong transport port";
  string server1 = str_pj(tdata->tp_info.transport->remote_name.host);
  EXPECT_EQ(server1, "10.10.10.100");
  free_txdata();

  // This server doesn't respond, so advance time to trigger the timeout.
  cwtest_advance_time_ms(33000);
  poll();

  // Check a 408 Timeout response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(408).matches(tdata->msg);
  free_txdata();

  // Now inject another INVITE.
  msg1._unique++;
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.

  // Check the 100 Trying.
  ASSERT_EQ(2, txdata_count());
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Request is forwarded to the node in the top Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  ReqMatcher("INVITE").matches(tdata->msg);

  // Check that it was sent to the first server (which is not blacklisted
  // because it is a stateless proxy).
  EXPECT_STREQ("TCP", tdata->tp_info.transport->type_name) << "Wrong transport type";
  EXPECT_EQ(5060, tdata->tp_info.transport->remote_name.port) << "Wrong transport port";
  server1 = str_pj(tdata->tp_info.transport->remote_name.host);
  EXPECT_EQ(server1, "10.10.10.100");

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

TEST_F(BasicProxyTest, TransportFailureWithCancelPending)
{
  // Tests transport failure while a CANCEL is outstanding.

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
  msg1._first_hop = true;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@homedomain;transport=TCP";
  msg1._from = "alice";
  msg1._to = "bob";
  msg1._todomain = "awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:127.0.0.1;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and the forwarded INVITEs.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  pjsip_tx_data* tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Catch the request forwarded to node1.homedomain via proxy1.homedomain.
  pjsip_tx_data* tdata1 = pop_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata1);
  ReqMatcher("INVITE").matches(tdata1->msg);
  EXPECT_EQ("sip:bob@node1.homedomain;transport=TCP",
            str_uri(tdata1->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy1.homedomain;transport=TCP;lr>",
            get_headers(tdata1->msg, "Route"));

  // Send 100 Trying responses from the downstream nodes, and check it is
  // absorbed.
  inject_msg(respond_to_txdata(tdata1, 100));
  ASSERT_EQ(0, txdata_count());

  // Send a CANCEL from the originator.
  msg1._method = "CANCEL";
  inject_msg(msg1.get_request(), tp);

  // Expect both a 200 OK response to the CANCEL and CANCEL on the outbound transaction.
  ASSERT_EQ(2, txdata_count());

  // Check the 200 OK.
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);

  // Kill the transport on this side of the call.
  fake_tcp_init_shutdown((fake_tcp_transport*)tdata->tp_info.transport, PJ_EEOF);
  free_txdata();
  poll();

  // Check the CANCEL is forwarded.
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata);
  ReqMatcher("CANCEL").matches(tdata->msg);
  inject_msg(respond_to_current_txdata(200));

  // Send 487 response to the original INVITE.  Check that this is ACKed.
  inject_msg(respond_to_txdata(tdata1, 487));
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.10.1", 5060, tdata);
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // That's it.
  ASSERT_EQ(0, txdata_count());

  _basic_proxy->remove_test_targets("sip:bob@homedomain");

  delete tp;
}
