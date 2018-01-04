/**
 * @file session_expires_helper_test.cpp Tests for the session expires helper.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "gmock/gmock.h"
#include "siptest.hpp"
#include "test_interposer.hpp"
#include "sproutletproxy.h"
#include "session_expires_helper.h"

using namespace std;
using testing::MatchesRegex;


// A test sproutlet transaction whose sole purpose is to perform session-expires
// processing.
class SessionExpiresHelperTsx : public SproutletTsx
{
public:
  SessionExpiresHelperTsx(Sproutlet* sproutlet) :
    SproutletTsx(sproutlet),
    _se_helper(600)
  {
  }

  void on_rx_initial_request(pjsip_msg* req)
  {
    _se_helper.process_request(req, get_pool(req), trail());
    send_request(req);
  }

  void on_rx_in_dialog_request(pjsip_msg* req)
  {
    _se_helper.process_request(req, get_pool(req), trail());
    send_request(req);
  }

  void on_rx_response(pjsip_msg* rsp, int fork_id)
  {
    _se_helper.process_response(rsp, get_pool(rsp), trail());
    send_response(rsp);
  }

private:
  SessionExpiresHelper _se_helper;
};


// A Sproutlet to create the above transaction.
class SessionExpiresHelperSproutlet : public Sproutlet
{
public:
  SessionExpiresHelperSproutlet(const std::string& service_name,
                  int port,
                  const std::string& service_host) :
    Sproutlet(service_name, port, service_host)
  {}

  SproutletTsx* get_tsx(SproutletHelper* helper,
                        const std::string& alias,
                        pjsip_msg* req,
                        pjsip_sip_uri*& next_hop,
                        pj_pool_t* pool,
                        SAS::TrailId trail)
  {
    return (SessionExpiresHelperTsx*)new SessionExpiresHelperTsx(this);
  }
};


class SessionExpiresHelperTest : public SipTest
{
public:
  /// Set up test case.
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();

    // Set up DNS mappings for destinations.
    add_host_mapping("proxy1.homedomain", "10.10.10.1");
    add_host_mapping("proxy2.homedomain", "10.10.10.2");

    // Create the Test Sproutlets.
    _sproutlets.push_back(new SessionExpiresHelperSproutlet("se", 0, ""));

    // Create the Sproutlet proxy.
    _proxy = new SproutletProxy(stack_data.endpt,
                                PJSIP_MOD_PRIORITY_UA_PROXY_LAYER+1,
                                "proxy1.homedomain",
                                std::unordered_set<std::string>(),
                                std::unordered_set<std::string>(), // TJW2 TODO
                                _sproutlets,
                                std::set<std::string>());

    // Schedule timers.
    SipTest::poll();
  }

  static void TearDownTestCase()
  {
    // Shut down the transaction module first, before we destroy the
    // objects that might handle any callbacks!
    pjsip_tsx_layer_destroy();

    delete _proxy;

    for (std::list<Sproutlet*>::iterator i = _sproutlets.begin();
         i != _sproutlets.end();
         ++i)
    {
      delete (*i);
    }

    SipTest::TearDownTestCase();
  }

  SessionExpiresHelperTest()
  {
    _log_traffic = PrintingTestLogger::DEFAULT.isPrinting(); // true to see all traffic

    _tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                           stack_data.scscf_port,
                                           "1.2.3.4",
                                           49152);

  }

  ~SessionExpiresHelperTest()
  {
    delete _tp; _tp = NULL;

    // Give any transactions in progress a chance to complete.
    poll();

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

    // Stop and restart the transaction layer just in case
    pjsip_tsx_layer_instance()->stop();
    pjsip_tsx_layer_instance()->start();
  }

  class Message
  {
  public:
    string _method;
    string _se;
    string _min_se;
    string _from_tag;
    string _to_tag;
    string _body;
    string _extra;
    int _unique;
    int _cseq;
    bool _uac_supports_timer;

    Message() :
      _method("INVITE"),
      _from_tag("10.114.61.213+1+8c8b232a+5fb751cf"),
      _to_tag(""),
      _cseq(16567),
      _uac_supports_timer(false)
    {
      static int unique = 1042;
      _unique = unique;
      unique += 10; // leave room for manual increments
    }

    string get_request()
    {
      char buf[16384];

      string from = "sip:alice@homedomain";
      if (!_from_tag.empty())
      {
        from += ";tag=" + _from_tag;
      }
      string to = "sip:bob@homedomain";
      if (!_to_tag.empty())
      {
        to += ";tag=" + _to_tag;
      }

      int n = snprintf(buf, sizeof(buf),
                       "%1$s sip:bob@homedomain SIP/2.0\r\n"
                       "Via: SIP/2.0/TCP 10.83.18.38:36530;rport;branch=z9hG4bKPjmo1aimuq33BAI4rjhgQgBr4sY%7$04dSPI\r\n"
                       "From: %2$s\r\n"
                       "To: %3$s\r\n"
                       "Max-Forwards: 68\r\n"
                       "Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs%7$04dohntC@10.114.61.213\r\n"
                       "CSeq: %8$d %1$s\r\n"
                       "User-Agent: Accession 2.0.0.0\r\n"
                       "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n"
                       "Content-Type: application/sdp\r\n"
                       "Route: sip:se.proxy1.homedomain;lr\r\nRoute: sip:proxy2.homedomain;lr\r\n"
                       "%6$s"
                       "%9$s"
                       "%10$s"
                       "%11$s"
                       "Content-Length: %4$d\r\n"
                       "\r\n"
                       "%5$s",
                       /*  1 */ _method.c_str(),
                       /*  2 */ from.c_str(),
                       /*  3 */ to.c_str(),
                       /*  4 */ (int)_body.length(),
                       /*  5 */ _body.c_str(),
                       /*  6 */ _extra.empty() ? "" : string(_extra).append("\r\n").c_str(),
                       /*  7 */ _unique,
                       /*  8 */ _cseq,
                       /*  9 */ _se.empty() ? "" : (_se + "\r\n").c_str(),
                       /* 10 */ _min_se.empty() ? "" : (_min_se + "\r\n").c_str(),
                       /* 11 */ _uac_supports_timer ? "Supported: timer\r\n" : ""
        );

      EXPECT_LT(n, (int)sizeof(buf));

      string ret(buf, n);
      // cout << ret <<endl;
      return ret;
    }
  };

  // Utility method to send a request, optionally receive a 100 Trying, and
  // receive a proxied request. This function does not free the proxied request.
  // The caller may check it, and is responsible for freeing it.
  void do_request_flow(Message* msg, bool expect_100 = true)
  {
    inject_msg(msg->get_request(), _tp);

    if (expect_100)
    {
      ASSERT_EQ(2, txdata_count());
      RespMatcher(100).matches(current_txdata()->msg);
      free_txdata();
    }

    ASSERT_EQ(1, txdata_count());
  }

  // Build a response (based on the current txdata) and receive a proxied
  // response (optionally freeing it). This function does not free the proxied
  // response. The caller may check it, and is responsible for freeing it.
  void do_response_flow(int st_code = 200,
                        const std::string& headers = "")
  {
    inject_msg(respond_to_txdata(current_txdata(), st_code, "", headers));
    free_txdata();

    ASSERT_EQ(1, txdata_count());
  }

protected:
  TransportFlow* _tp;
  static SproutletProxy* _proxy;
  static std::list<Sproutlet*> _sproutlets;
};

SproutletProxy* SessionExpiresHelperTest::_proxy;
std::list<Sproutlet*> SessionExpiresHelperTest::_sproutlets;


// No session expires header present - the helper adds one.
TEST_F(SessionExpiresHelperTest, NoExistingSE)
{
  Message msg1;
  do_request_flow(&msg1);

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600");

  do_response_flow();
  free_txdata();
}


// The helper reduces an existing session-expiry if the existing value is too
// high.
TEST_F(SessionExpiresHelperTest, HighExistingSE)
{
  Message msg1;
  msg1._se = "Session-Expires: 900";
  do_request_flow(&msg1);

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600");

  do_response_flow();
  free_txdata();
}


// The helper leaves an existing session-expires alone if it is lower then the
// target.
TEST_F(SessionExpiresHelperTest, LowExistingSE)
{
  Message msg1;
  msg1._se = "Session-Expires: 450";
  do_request_flow(&msg1);

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 450");

  do_response_flow();
  free_txdata();
}


// If there is a min-SE lower than the target, the helper sets its target value
// for the session-expires.
TEST_F(SessionExpiresHelperTest, LowMinSE) { Message msg1; msg1._min_se =
  "Min-SE: 100"; do_request_flow(&msg1);

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600");

  do_response_flow(); free_txdata(); }


// If there is a min-SE higher than the target, the helper sets the
// session-expires to the min-SE.
TEST_F(SessionExpiresHelperTest, HighMinSE)
{
  Message msg1;
  msg1._min_se = "Min-SE: 1000";
  do_request_flow(&msg1);

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 1000");

  do_response_flow();
  free_txdata();
}


// If neither UA supports session timers, the response should not have a
// session-expires.
TEST_F(SessionExpiresHelperTest, ClientServerDoNotSupportTimer)
{
  Message msg1;
  do_request_flow(&msg1);

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600");

  do_response_flow();

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"), "");

  free_txdata();
}


// If the server does support timers, the response has a session-expires even
// if the client did not support timers.
TEST_F(SessionExpiresHelperTest, ServerDoesSupportTimer)
{
  Message msg1;
  do_request_flow(&msg1);

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600");

  do_response_flow(200, "Session-Expires: 500;refresher=uas");

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 500;refresher=uas");

  free_txdata();
}


// If both UAs support timers, the response has a session-expires.
TEST_F(SessionExpiresHelperTest, BothUAsSupporttimer)
{
  Message msg1;
  msg1._uac_supports_timer = true;
  do_request_flow(&msg1);

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600");

  do_response_flow(200, "Session-Expires: 500;refresher=uas");

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 500;refresher=uas");

  free_txdata();
}

//
// Scenarios where the client supports session timers but the server does not.
// These check that regardless of the session-expires or min-SE on the received
// request, the value put on the response matches the value on the *sent*
// request.
//

TEST_F(SessionExpiresHelperTest, ClientSupportsTimerSESetFreely)
{
  Message msg1;
  msg1._uac_supports_timer = true;
  do_request_flow(&msg1);

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600");

  do_response_flow();

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600;refresher=uac");

  free_txdata();
}


TEST_F(SessionExpiresHelperTest, ClientSupportsTimerSEModified)
{
  Message msg1;
  msg1._uac_supports_timer = true;
  msg1._se = "Session-Expires: 800";
  do_request_flow(&msg1);

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600");

  do_response_flow();

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600;refresher=uac");
  EXPECT_THAT(get_headers(current_txdata()->msg, "Require"),
              MatchesRegex("Require:.*[ ,]timer($|[ ,])"));

  free_txdata();
}


TEST_F(SessionExpiresHelperTest, ClientSupportsTimerSELeftAlone)
{
  Message msg1;
  msg1._uac_supports_timer = true;
  msg1._se = "Session-Expires: 450";
  do_request_flow(&msg1);

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 450");

  do_response_flow();

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 450;refresher=uac");

  free_txdata();
}


TEST_F(SessionExpiresHelperTest, ClientSupportsTimerSESetToMinSE)
{
  Message msg1;
  msg1._uac_supports_timer = true;
  msg1._min_se = "Min-SE: 1000";
  do_request_flow(&msg1);

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 1000");

  do_response_flow();

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 1000;refresher=uac");

  free_txdata();
}


// Session expires processing also happens on UPDATEs.
TEST_F(SessionExpiresHelperTest, ProcessingHappensOnUpdate)
{
  Message msg1;
  msg1._method = "UPDATE";
  msg1._to_tag = "12345";
  msg1._uac_supports_timer = true;
  do_request_flow(&msg1, false);

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600");

  do_response_flow();

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600;refresher=uac");

  free_txdata();
}


// There is no session expires processing on other methods.
TEST_F(SessionExpiresHelperTest, NoProcessingOnNonInviteOrUpdate)
{
  Message msg1;
  msg1._method = "SUBSCRIBE";
  do_request_flow(&msg1, false);

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"), "");

  do_response_flow();

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"), "");

  free_txdata();
}


// No processing on error responses.
TEST_F(SessionExpiresHelperTest, NoProcessingOnErrorResponse)
{
  Message msg1;
  do_request_flow(&msg1);

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600");

  inject_msg(respond_to_txdata(current_txdata(), 400));
  free_txdata();

  ASSERT_EQ(2, txdata_count());

  ReqMatcher ack_matcher("ACK");
  ack_matcher.matches(current_txdata()->msg);
  free_txdata();

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"), "");
  free_txdata();

  msg1._method = "ACK";
  inject_msg(msg1.get_request(), _tp);
}
