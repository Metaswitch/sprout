/**
 * @file session_expires_helper_test.cpp Tests for the session expires helper.
 *
 * project clearwater - ims in the cloud
 * copyright (c) 2015  metaswitch networks ltd
 *
 * this program is free software: you can redistribute it and/or modify it
 * under the terms of the gnu general public license as published by the
 * free software foundation, either version 3 of the license, or (at your
 * option) any later version, along with the "special exception" for use of
 * the program along with ssl, set forth below. this program is distributed
 * in the hope that it will be useful, but without any warranty;
 * without even the implied warranty of merchantability or fitness for
 * a particular purpose.  see the gnu general public license for more
 * details. you should have received a copy of the gnu general public
 * license along with this program.  if not, see
 * <http://www.gnu.org/licenses/>.
 *
 * the author can be reached by email at clearwater@metaswitch.com or by
 * post at metaswitch networks ltd, 100 church st, enfield en2 6bq, uk
 *
 * special exception
 * metaswitch networks ltd  grants you permission to copy, modify,
 * propagate, and distribute a work formed by combining openssl with the
 * software, or a work derivative of such a combination, even if such
 * copying, modification, propagation, or distribution would otherwise
 * violate the terms of the gpl. you must comply with the gpl in all
 * respects for all of the code used other than openssl.
 * "openssl" means openssl toolkit software distributed by the openssl
 * project and licensed under the openssl licenses, or a work based on such
 * software and licensed under the openssl licenses.
 * "openssl licenses" means the openssl license and original ssleay license
 * under which the openssl project distributes the openssl toolkit software,
 * as those licenses appear in the file license-openssl.
 */

#include "gmock/gmock.h"
#include "siptest.hpp"
#include "test_interposer.hpp"
#include "sproutletproxy.h"
#include "session_expires_helper.h"

using namespace std;
using testing::MatchesRegex;


class SessionExpiresHelperTsx : public SproutletTsx
{
public:
  SessionExpiresHelperTsx(SproutletTsxHelper* helper) :
    SproutletTsx(helper),
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


class SessionExpiresHelperSproutlet : public Sproutlet
{
public:
  SessionExpiresHelperSproutlet(const std::string& service_name,
                  int port,
                  const std::string& service_host) :
    Sproutlet(service_name, port, service_host)
  {}

  SproutletTsx* get_tsx(SproutletTsxHelper* helper,
                        const std::string& alias,
                        pjsip_msg* req)
  {
    return (SessionExpiresHelperTsx*)new SessionExpiresHelperTsx(helper);
  }
};


class SessionExpiresHelperTest : public SipTest
{
public:
  /// Set up test case.
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase(false);

    // Set up DNS mappings for destinations.
    add_host_mapping("proxy1.homedomain", "10.10.10.1");
    add_host_mapping("proxy2.homedomain", "10.10.10.2");

    // Create the Test Sproutlets.
    _sproutlets.push_back(new SessionExpiresHelperSproutlet("se", 0, ""));

    // Create the Sproutlet proxy.
    _proxy = new SproutletProxy(stack_data.endpt,
                                PJSIP_MOD_PRIORITY_UA_PROXY_LAYER+1,
                                "sip:proxy1.homedomain",
                                std::unordered_set<std::string>(),
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
    string _requri;
    string _status;
    string _from;
    string _to;
    string _from_tag;
    string _to_tag;
    string _content_type;
    string _body;
    string _extra;
    int _forwards;
    int _unique;
    string _via;
    string _route;
    int _cseq;
    bool _uac_supports_timer;

    Message() :
      _method("INVITE"),
      _requri("sip:bob@homedomain"),
      _status("200 OK"),
      _from("sip:alice@homedomain"),
      _to("sip:bob@homedomain"),
      _from_tag("10.114.61.213+1+8c8b232a+5fb751cf"),
      _to_tag(""),
      _content_type("application/sdp"),
      _forwards(68),
      _via("10.83.18.38:36530"),
      _route("Route: sip:se.proxy1.homedomain;lr\r\nRoute: sip:proxy2.homedomain;lr"),
      _cseq(16567),
      _uac_supports_timer(false)
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

      string route = _route.empty() ? "" : _route + "\r\n";

      string from = _from;
      if (!_from_tag.empty())
      {
        from += ";tag=" + _from_tag;
      }
      string to = _to;
      if (!_to_tag.empty())
      {
        to += ";tag=" + _to_tag;
      }

      int n = snprintf(buf, sizeof(buf),
                       "%1$s %9$s SIP/2.0\r\n"
                       "Via: SIP/2.0/TCP %11$s;rport;branch=z9hG4bKPjmo1aimuq33BAI4rjhgQgBr4sY%10$04dSPI\r\n"
                       "From: %2$s\r\n"
                       "To: %3$s\r\n"
                       "Max-Forwards: %8$d\r\n"
                       "Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs%10$04dohntC@10.114.61.213\r\n"
                       "CSeq: %13$d %1$s\r\n"
                       "User-Agent: Accession 2.0.0.0\r\n"
                       "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n"
                       "%4$s"
                       "%7$s"
                       "%12$s"
                       "%14$s"
                       "%15$s"
                       "%16$s"
                       "Content-Length: %5$d\r\n"
                       "\r\n"
                       "%6$s",
                       /*  1 */ _method.c_str(),
                       /*  2 */ from.c_str(),
                       /*  3 */ to.c_str(),
                       /*  4 */ _content_type.empty() ? "" : string("Content-Type: ").append(_content_type).append("\r\n").c_str(),
                       /*  5 */ (int)_body.length(),
                       /*  6 */ _body.c_str(),
                       /*  7 */ _extra.empty() ? "" : string(_extra).append("\r\n").c_str(),
                       /*  8 */ _forwards,
                       /*  9 */ _requri.c_str(),
                       /* 10 */ _unique,
                       /* 11 */ _via.c_str(),
                       /* 12 */ route.c_str(),
                       /* 13 */ _cseq,
                       /* 14 */ _se.empty() ? "" : (_se + "\r\n").c_str(),
                       /* 15 */ _min_se.empty() ? "" : (_min_se + "\r\n").c_str(),
                       /* 16 */ _uac_supports_timer ? "Supported: timer\r\n" : ""
        );

      EXPECT_LT(n, (int)sizeof(buf));

      string ret(buf, n);
      // cout << ret <<endl;
      return ret;
    }

    string get_response()
    {
      char buf[16384];

      string route = _route.empty() ? "" : _route + "\r\n";

      string from = _from;
      if (!_from_tag.empty())
      {
        from += ";tag=" + _from_tag;
      }
      string to = _to;
      if (!_to_tag.empty())
      {
        to += ";tag=" + _to_tag;
      }

      int n = snprintf(buf, sizeof(buf),
                       "SIP/2.0 %7$s\r\n"
                       "Via: SIP/2.0/TCP %11$s;rport;branch=z9hG4bKPjmo1aimuq33BAI4rjhgQgBr4sY%9$04dSPI\r\n"
                       "From: %2$s\r\n"
                       "To: %3$s\r\n"
                       "Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs%9$04dohntC@10.114.61.213\r\n"
                       "CSeq: %10$d %1$s\r\n"
                       "User-Agent: Accession 2.0.0.0\r\n"
                       "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n"
                       "%4$s"
                       "%8$s"
                       "Content-Length: %5$d\r\n"
                       "\r\n"
                       "%6$s",
                       /*  1 */ _method.c_str(),
                       /*  2 */ from.c_str(),
                       /*  3 */ to.c_str(),
                       /*  4 */ _content_type.empty() ? "" : string("Content-Type: ").append(_content_type).append("\r\n").c_str(),
                       /*  5 */ (int)_body.length(),
                       /*  6 */ _body.c_str(),
                       /*  7 */ _status.c_str(),
                       /*  8 */ _extra.empty() ? "" : string(_extra).append("\r\n").c_str(),
                       /*  9 */ _unique,
                       /* 10 */ _cseq,
                       /* 11 */ _via.c_str()
        );

      EXPECT_LT(n, (int)sizeof(buf));

      string ret(buf, n);
      // cout << ret <<endl;
      return ret;
    }
  };

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

  void do_response_flow(bool free_rsp = true,
                                 int st_code = 200,
                                 const std::string& headers = "")
  {
    inject_msg(respond_to_txdata(current_txdata(), st_code, "", headers));
    free_txdata();

    ASSERT_EQ(1, txdata_count());

    if (free_rsp)
    {
      free_txdata();
    }
  }

protected:
  TransportFlow* _tp;
  static SproutletProxy* _proxy;
  static std::list<Sproutlet*> _sproutlets;
};

SproutletProxy* SessionExpiresHelperTest::_proxy;
std::list<Sproutlet*> SessionExpiresHelperTest::_sproutlets;


TEST_F(SessionExpiresHelperTest, NoExistingSE)
{
  // Send INVITE and catch 100 Trying and proxied INVITE
  Message msg1;
  do_request_flow(&msg1);

  // The request should have a Session-Expires header.
  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600");

  do_response_flow();
}


TEST_F(SessionExpiresHelperTest, HighExistingSE)
{
  // Send INVITE and catch 100 Trying and proxied INVITE
  Message msg1;
  msg1._se = "Session-Expires: 900";
  do_request_flow(&msg1);

  // The request should have a Session-Expires header.
  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600");

  do_response_flow();
}


TEST_F(SessionExpiresHelperTest, LowExistingSE)
{
  // Send INVITE and catch 100 Trying and proxied INVITE
  Message msg1;
  msg1._se = "Session-Expires: 450";
  do_request_flow(&msg1);

  // The request should have a Session-Expires header.
  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 450");

  do_response_flow();
}


TEST_F(SessionExpiresHelperTest, LowMinSE)
{
  // Send INVITE and catch 100 Trying and proxied INVITE
  Message msg1;
  msg1._min_se = "Min-SE: 100";
  do_request_flow(&msg1);

  // The request should have a Session-Expires header.
  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600");

  do_response_flow();
}


TEST_F(SessionExpiresHelperTest, HighMinSE)
{
  // Send INVITE and catch 100 Trying and proxied INVITE
  Message msg1;
  msg1._min_se = "Min-SE: 1000";
  do_request_flow(&msg1);

  // The request should have a Session-Expires header.
  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 1000");

  do_response_flow();
}


TEST_F(SessionExpiresHelperTest, ServerDoesNotSupportTimer)
{
  // Send INVITE and catch 100 Trying and proxied INVITE
  Message msg1;
  do_request_flow(&msg1);

  // The request should have a Session-Expires header.
  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600");

  do_response_flow(false);

  // The response should not have a session expires.
  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"), "");

  free_txdata();
}


TEST_F(SessionExpiresHelperTest, ServerDoesSupportTimer)
{
  // Send INVITE and catch 100 Trying and proxied INVITE
  Message msg1;
  do_request_flow(&msg1);

  // The request should have a Session-Expires header.
  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600");

  do_response_flow(false, 200, "Session-Expires: 500;refresher=uas");

  // The response should not have a session expires.
  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 500;refresher=uas");

  free_txdata();
}


TEST_F(SessionExpiresHelperTest, BothUAsSupporttimer)
{
  // Send INVITE and catch 100 Trying and proxied INVITE
  Message msg1;
  msg1._uac_supports_timer = true;
  do_request_flow(&msg1);

  // The request should have a Session-Expires header.
  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600");

  do_response_flow(false, 200, "Session-Expires: 500;refresher=uas");

  // The response should not have a session expires.
  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 500;refresher=uas");

  free_txdata();
}


TEST_F(SessionExpiresHelperTest, ClientSupportsTimerSESetFreely)
{
  // Send INVITE and catch 100 Trying and proxied INVITE
  Message msg1;
  msg1._uac_supports_timer = true;
  do_request_flow(&msg1);

  // The request should have a Session-Expires header.
  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600");

  do_response_flow(false);

  // The response should not have a session expires.
  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600;refresher=uac");

  free_txdata();
}


TEST_F(SessionExpiresHelperTest, ClientSupportsTimerSEModified)
{
  // Send INVITE and catch 100 Trying and proxied INVITE
  Message msg1;
  msg1._uac_supports_timer = true;
  msg1._se = "Session-Expires: 800";
  do_request_flow(&msg1);

  // The request should have a Session-Expires header.
  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600");

  do_response_flow(false);

  // The response should not have a session expires.
  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600;refresher=uac");
  EXPECT_THAT(get_headers(current_txdata()->msg, "Require"),
              MatchesRegex("Require:.*[ ,]timer($|[ ,])"));

  free_txdata();
}


TEST_F(SessionExpiresHelperTest, ClientSupportsTimerSELeftAlone)
{
  // Send INVITE and catch 100 Trying and proxied INVITE
  Message msg1;
  msg1._uac_supports_timer = true;
  msg1._se = "Session-Expires: 450";
  do_request_flow(&msg1);

  // The request should have a Session-Expires header.
  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 450");

  do_response_flow(false);

  // The response should not have a session expires.
  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 450;refresher=uac");

  free_txdata();
}


TEST_F(SessionExpiresHelperTest, ClientSupportsTimerSESetToMinSE)
{
  // Send INVITE and catch 100 Trying and proxied INVITE
  Message msg1;
  msg1._uac_supports_timer = true;
  msg1._min_se = "Min-SE: 1000";
  do_request_flow(&msg1);

  // The request should have a Session-Expires header.
  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 1000");

  do_response_flow(false);

  // The response should not have a session expires.
  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 1000;refresher=uac");

  free_txdata();
}


TEST_F(SessionExpiresHelperTest, NoProcessingOnNonInviteDialog)
{
  // Send INVITE and catch 100 Trying and proxied INVITE
  Message msg1;
  msg1._method = "SUBSCRIBE";
  do_request_flow(&msg1, false);

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"), "");

  do_response_flow(false);

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"), "");

  free_txdata();
}


TEST_F(SessionExpiresHelperTest, ProcessingHappensOnUpdate)
{
  // Send INVITE and catch 100 Trying and proxied INVITE
  Message msg1;
  msg1._method = "UPDATE";
  msg1._to_tag = "12345";
  msg1._uac_supports_timer = true;
  do_request_flow(&msg1, false);

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600");

  do_response_flow(false);

  EXPECT_EQ(get_headers(current_txdata()->msg, "Session-Expires"),
            "Session-Expires: 600;refresher=uac");

  free_txdata();
}


TEST_F(SessionExpiresHelperTest, NoProcessingOnErrorResponse)
{
  // Send INVITE and catch 100 Trying and proxied INVITE
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
