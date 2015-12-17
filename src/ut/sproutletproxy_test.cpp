/**
 * @file sproutletproxy_test.cpp  SproutletProxy unit tests.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2014  Metaswitch Networks Ltd
 *
 * Parts of this module were derived from GPL licensed PJSIP sample code
 * with the following copyrights.
 *   Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 *   Copyright (C) 2003-2008 Benny Prijono <benny@prijono.org>
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

#include "gmock/gmock.h"
#include "siptest.hpp"
#include "test_interposer.hpp"
#include "sproutletproxy.h"
#include "pjutils.h"

#include <mutex>

using namespace std;
using testing::InSequence;
using testing::DoAll;
using testing::Invoke;
using testing::Return;
using testing::WithArg;
using testing::_;

#define NUM_FORKS 3

const pj_str_t STR_UT_TSX_ID_HDR = pj_str((char*)"X-UT-TsxId");

template <class T>
class FakeSproutlet : public Sproutlet
{
public:
  FakeSproutlet(const std::string& service_name, int port, const std::string& service_host) :
    Sproutlet(service_name, port, service_host)
  {
    _aliases.push_back("alias");
  }

  SproutletTsx* get_tsx(SproutletTsxHelper* helper, const std::string& alias, pjsip_msg* req)
  {
    return (SproutletTsx*)new T(helper);
  }

  const std::list<std::string> aliases() const
  {
    return _aliases;
  }

private:

  std::list<std::string> _aliases;
};

template <int S>
class FakeSproutletTsxReject : public SproutletTsx
{
public:
  FakeSproutletTsxReject(SproutletTsxHelper* helper) :
    SproutletTsx(helper)
  {
  }

  void on_rx_initial_request(pjsip_msg* req)
  {
    pjsip_msg* rsp = create_response(req, S);
    free_msg(req);
    send_response(rsp);
  }
};

template <bool RR>
class FakeSproutletTsxForwarder : public SproutletTsx
{
public:
  FakeSproutletTsxForwarder(SproutletTsxHelper* helper) :
    SproutletTsx(helper)
  {
  }

  void on_rx_initial_request(pjsip_msg* req)
  {
    if (RR)
    {
      pj_pool_t* pool = get_pool(req);
      pjsip_sip_uri* uri = get_reflexive_uri(pool);
      pjsip_route_hdr* rr = pjsip_rr_hdr_create(pool);
      rr->name_addr.uri = (pjsip_uri*)uri;

      // Add a parameter
      pjsip_param* param = PJ_POOL_ALLOC_T(pool, pjsip_param);
      pj_strdup2(pool, &param->name, "hello");
      pj_strdup2(pool, &param->value, "world");
      pj_list_insert_before(&uri->other_param, param);

      pjsip_msg_insert_first_hdr(req, (pjsip_hdr*)rr);
    }
    send_request(req);
  }

  void on_rx_in_dialog_request(pjsip_msg* req)
  {
    const pjsip_route_hdr* route = route_hdr();
    pj_str_t param_name = pj_str((char*)"hello");
    pjsip_sip_uri* uri = (pjsip_sip_uri*)route->name_addr.uri;

    EXPECT_TRUE(is_uri_reflexive((pjsip_uri*)uri));

    // Check the parameter
    pjsip_param* param = pjsip_param_find(&uri->other_param,
                                          &param_name);
    ASSERT_NE((pjsip_param*)NULL, param);
    std::string param_value(param->value.ptr, param->value.slen);
    EXPECT_EQ(param_value, "world");

    send_request(req);
  }

  void on_rx_response(pjsip_msg* rsp, int fork_id)
  {
    send_response(rsp);
  }
};

class FakeSproutletTsxDownstreamRequest : public SproutletTsx
{
public:
  FakeSproutletTsxDownstreamRequest(SproutletTsxHelper* helper) :
    SproutletTsx(helper)
  {
  }

  void on_rx_initial_request(pjsip_msg* req)
  {
    pjsip_msg* ds_req = create_request();
    free_msg(ds_req);
    send_request(req);
  }

  void on_rx_in_dialog_request(pjsip_msg* req)
  {
    send_request(req);
  }

  void on_rx_response(pjsip_msg* rsp, int fork_id)
  {
    send_response(rsp);
  }
};
template <int N>
class FakeSproutletTsxForker : public SproutletTsx
{
public:
  FakeSproutletTsxForker(SproutletTsxHelper* helper) :
    SproutletTsx(helper)
  {
  }

  void on_rx_initial_request(pjsip_msg* req)
  {
    if ((!pj_strcmp2(&req->line.req.method.name, "INVITE")) ||
        (!pj_strcmp2(&req->line.req.method.name, "MESSAGE")))
    {
      // Fork INVITE and MESSAGE requests.
      for (int ii = NUM_FORKS - 1; ii >= 0; --ii)
      {
        pjsip_msg* clone = clone_request(req);
        pj_pool_t* pool = get_pool(clone);
        pjsip_sip_uri* uri = (pjsip_sip_uri*)pjsip_uri_get_uri(clone->line.req.uri);
        std::string user = std::string(uri->user.ptr, uri->user.slen) + "-" + std::to_string(ii);
        pj_strdup2(pool, &uri->user, user.c_str());
        uri->port = 5060;
        pj_strdup2(pool, &uri->transport_param, "TCP");
        send_request(clone);
      }
      free_msg(req);
    }
    else
    {
      // Simply forward other requests.
      send_request(req);
    }
  }

  void on_rx_response(pjsip_msg* rsp, int fork_id)
  {
    send_response(rsp);
  }
};

template <int T>
class FakeSproutletTsxDelayRedirect : public SproutletTsx
{
  FakeSproutletTsxDelayRedirect(SproutletTsxHelper* helper) :
    SproutletTsx(helper),
    _tid(0),
    _fork_id(-1)
  {
  }

  void on_rx_initial_request(pjsip_msg* req)
  {
    _fork_id = send_request(req);

    // Start a timer for the specified timer duration.
    schedule_timer(NULL, _tid, T * 1000);
  }

  void on_rx_response(pjsip_msg* rsp, int fork_id)
  {
    if ((rsp->line.status.code >= PJSIP_SC_OK) &&
        (_tid != 0) && (timer_running(_tid)))
    {
      // Received final response, and timer is still running, so stop it now.
      cancel_timer(_tid);
      _tid = 0;
      _fork_id = -1;
    }
    send_response(rsp);
  }

  void on_timer_expiry(void* context)
  {
    if (_tid != 0)
    {
      _tid = 0;

      // Cancel the pending fork.
      cancel_fork(_fork_id);
      _fork_id = -1;

      // Redirect the request.
      pjsip_msg* req = original_request();
      pj_pool_t* pool = get_pool(req);
      pjsip_sip_uri* uri = (pjsip_sip_uri*)req->line.req.uri;
      pj_strdup2(pool, &uri->user, "bob2");
      send_request(req);
    }
  }

  TimerID _tid;
  int _fork_id;
};

class FakeSproutletTsxBad : public SproutletTsx
{
  FakeSproutletTsxBad(SproutletTsxHelper* helper) :
    SproutletTsx(helper)
  {
  }

  void on_rx_initial_request(pjsip_msg* req)
  {
    // Attempt to clone a bad message
    pjsip_msg* clone = clone_request((pjsip_msg*)1);
    EXPECT_EQ(NULL, clone);

    // Attempt to build a response from a bad message.
    pjsip_msg* rsp = create_response((pjsip_msg*)2, PJSIP_SC_NOT_FOUND);
    EXPECT_EQ(NULL, rsp);

    // Attempt to get the pool for a bad message.
    pj_pool_t* pool = get_pool((pjsip_msg*)3);
    EXPECT_EQ(NULL, pool);

    // Attempt to get msg_info for a bad message.
    const char* info = msg_info((pjsip_msg*)4);
    EXPECT_EQ(0, strcmp(info, ""));

    // Attempt to free a bad message.
    pjsip_msg* msg = (pjsip_msg*)5;
    free_msg(msg);
    EXPECT_EQ((pjsip_msg*)5, msg);

    // Attempt to send an invalid request.
    int fork_id = send_request(msg);
    EXPECT_EQ(-1, fork_id);
    EXPECT_EQ((pjsip_msg*)5, msg);

    // Attempt to send an invalid response.
    send_response(msg);
    EXPECT_EQ((pjsip_msg*)5, msg);

    // Attempt to send a response as a request.
    rsp = create_response(req, PJSIP_SC_OK);
    fork_id = send_request(rsp);
    EXPECT_EQ(-1, fork_id);

    // Attempt to send a request as a response.
    send_response(req);

    // Query fork state on an unknown fork.
    ForkState fstate = fork_state(2);
    EXPECT_EQ(PJSIP_TSX_STATE_NULL, fstate.tsx_state);
    EXPECT_EQ(NONE, fstate.error_state);

    send_response(rsp);
  }
};

class FakeSproutletTsxB2BUA : public SproutletTsx
{
public:
  FakeSproutletTsxB2BUA(SproutletTsxHelper* helper) :
    SproutletTsx(helper)
  {
  }

  void on_rx_initial_request(pjsip_msg* req)
  {
    _method = req->line.req.method.id;
    if (_method == PJSIP_INVITE_METHOD)
    {
      // Respond locally to the INVITE with a 200 OK and forward it on.
      pjsip_msg* rsp = create_response(req, PJSIP_SC_OK);
      send_response(rsp);
      send_request(req);
    }
    else if (_method == PJSIP_ACK_METHOD)
    {
      // Swallow the ACK locally, as we will generate one when the 200 OK
      // arrives.
      free_msg(req);
    }
    else
    {
      // Forward all other requests unchanged.
      send_request(req);
    }
  }

  void on_rx_response(pjsip_msg* rsp, int fork_id)
  {
    if ((_method == PJSIP_INVITE_METHOD) &&
        (rsp->line.status.code >= PJSIP_SC_OK))
    {
      // This is a final response, so build and send an ACK for this
      // response, irrespective of the status code.
      TRC_DEBUG("Process INVITE final response");
      pjsip_msg* ack = original_request();
      pjsip_method_set(&ack->line.req.method, PJSIP_ACK_METHOD);

      pjsip_hdr* next = NULL;
      for (pjsip_hdr* hdr = ack->hdr.next;
           (hdr != NULL) && (hdr != &ack->hdr);
           hdr = next)
      {
        next = hdr->next;
        TRC_DEBUG("%.*s header", hdr->name.slen, hdr->name.ptr);

        switch (hdr->type)
        {
          case PJSIP_H_FROM:
          case PJSIP_H_CALL_ID:
          case PJSIP_H_REQUIRE:
          case PJSIP_H_ROUTE:
            // Leave header in the ACK.
            TRC_DEBUG("Leave header in ACK");
            break;

          case PJSIP_H_TO:
            // Leave header in the ACK, but copy tag from the response.
            if (PJSIP_MSG_TO_HDR(rsp) != NULL)
            {
              TRC_DEBUG("Copy To tag from response");
              pj_strdup(get_pool(ack),
                        &(((pjsip_to_hdr*)hdr)->tag),
                        &(PJSIP_MSG_TO_HDR(rsp)->tag));
            }
            TRC_DEBUG("Leave header in ACK");
            break;

          case PJSIP_H_CSEQ:
            // Update the method to ACK.
            TRC_DEBUG("Update method in CSeq");
            pjsip_method_set(&((pjsip_cseq_hdr*)hdr)->method, PJSIP_ACK_METHOD);
            break;

          default:
            // Remove header from the ACK.
            TRC_DEBUG("Remove header");
            pj_list_erase(hdr);
            break;
        }
      }
      ack->body = NULL;
      send_request(ack);

      // Assume OK response, so can drop it.  (If we want to support failure
      // responses we'd need to send a BYE upstream.
      free_msg(rsp);
    }
    else
    {
      send_response(rsp);
    }
  }

private:
  pjsip_method_e _method;
};

template <int T>
class FakeSproutletTsxDelayAfterRsp : public SproutletTsx
{
  FakeSproutletTsxDelayAfterRsp(SproutletTsxHelper* helper) :
    SproutletTsx(helper),
    _tsx_from_tag(),
    _tid(0)
  {
  }

  ~FakeSproutletTsxDelayAfterRsp()
  {
    deleted(_tsx_from_tag);
  }

  void on_rx_initial_request(pjsip_msg* req)
  {
    TRC_DEBUG("Initial request.  Forward on.");
    pjsip_from_hdr* from_hdr = PJSIP_MSG_FROM_HDR(req);
    if (from_hdr != NULL)
    {
      _tsx_from_tag = PJUtils::pj_str_to_string(&from_hdr->tag);
      created(_tsx_from_tag);
    }
    pjsip_msg* rsp = create_response(req, PJSIP_SC_OK);
    send_response(rsp);
    schedule_timer(NULL, _tid, T * 1000);
    free_msg(req);
  }

  void on_rx_response(pjsip_msg* rsp, int fork_id)
  {
    TRC_DEBUG("Response.  Ignore.");

    // Swallow this response
    free_msg(rsp);
  }

  void on_timer_expiry(void* context)
  {
    TRC_DEBUG("Timer expiry (%ld)", _tid);
    if (_tid != 0)
    {
      // Check concurrent cancellation of timer doesn't break
      cancel_timer(_tid);

      _tid = 0;
    }
  }

  std::string _tsx_from_tag;
  TimerID _tid;

  static std::set<std::string> _live_tsxs;
  static std::mutex _live_tsxs_mutex;

  static void created(std::string& tsx_from_tag)
  {
    if (!tsx_from_tag.empty())
    {
      _live_tsxs_mutex.lock();
      _live_tsxs.insert(tsx_from_tag);
      _live_tsxs_mutex.unlock();
    }
  }

  static void deleted(std::string& tsx_from_tag)
  {
    if (!tsx_from_tag.empty())
    {
      _live_tsxs_mutex.lock();
      _live_tsxs.erase(tsx_from_tag);
      _live_tsxs_mutex.unlock();
    }
  }

  static bool is_live(const std::string& tsx_from_tag)
  {
    bool live;
    _live_tsxs_mutex.lock();
    live = _live_tsxs.count(tsx_from_tag) > 0;
    _live_tsxs_mutex.unlock();
    return live;
  }
};

template<int T> std::set<std::string> FakeSproutletTsxDelayAfterRsp<T>::_live_tsxs;
template<int T> std::mutex FakeSproutletTsxDelayAfterRsp<T>::_live_tsxs_mutex;

template <int T>
class FakeSproutletTsxDelayAfterFwd : public SproutletTsx
{
  FakeSproutletTsxDelayAfterFwd(SproutletTsxHelper* helper) :
    SproutletTsx(helper),
    _tid(0),
    _response(0)
  {
  }

  void on_rx_initial_request(pjsip_msg* req)
  {
    TRC_DEBUG("Initial request.  Forward on.");
    _second_request = clone_request(req);
    pjsip_msg* rsp = create_response(req, PJSIP_SC_OK);
    send_response(rsp);
    send_request(req);
  }

  void on_rx_response(pjsip_msg* rsp, int fork_id)
  {
    ++_response;
    TRC_DEBUG("Response %d", _response);

    // Swallow this response
    free_msg(rsp);

    if (_response == 1)
    {
      // Start a timer for the specified timer duration.  This timer
      // should be the only thing keeping the SproutletWrapper and
      // UASTsx alive for its duration.
      schedule_timer(NULL, _tid, T * 1000);
    }
  }

  void on_timer_expiry(void* context)
  {
    TRC_DEBUG("Timer expiry (%ld)", _tid);
    if (_tid != 0)
    {
      // Check concurrent cancellation of timer doesn't break
      cancel_timer(_tid);

      _tid = 0;

      // Send another request.
      send_request(_second_request);
    }
  }

  TimerID _tid;
  int _response;
  pjsip_msg* _second_request;
};

class SproutletProxyTest : public SipTest
{
public:
  /// Set up test case.
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase(false);

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

    // Create the Test Sproutlets.
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxForwarder<false> >("fwd", 0, ""));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxForwarder<true> >("fwdrr", 0, ""));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxDownstreamRequest>("dsreq", 0, ""));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxForker<NUM_FORKS> >("forker", 0, ""));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxDelayRedirect<1> >("delayredirect", 0, ""));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxBad >("bad", 0, ""));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxB2BUA >("b2bua", 0, ""));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxDelayAfterRsp<1> >("delayafterrsp", 0, ""));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxDelayAfterFwd<1> >("delayafterfwd", 0, ""));

    // Create a host alias.
    std::unordered_set<std::string> host_aliases;
    host_aliases.insert("proxy1.homedomain-alias");

    // Create the Sproutlet proxy.
    _proxy = new SproutletProxy(stack_data.endpt,
                                PJSIP_MOD_PRIORITY_UA_PROXY_LAYER+1,
                                "sip:proxy1.homedomain",
                                host_aliases,
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

  SproutletProxyTest()
  {
    _log_traffic = PrintingTestLogger::DEFAULT.isPrinting(); // true to see all traffic
  }

  ~SproutletProxyTest()
  {
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

    Message() :
      _method("INVITE"),
      _status("200 OK"),
      _from("sip:6505551000@homedomain"),
      _to("sip:6505551234@homedomain"),
      _from_tag("10.114.61.213+1+8c8b232a+5fb751cf"),
      _to_tag(""),
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
                       /* 13 */ _cseq
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

protected:

  static SproutletProxy* _proxy;
  static std::list<Sproutlet*> _sproutlets;
};

SproutletProxy* SproutletProxyTest::_proxy;
std::list<Sproutlet*> SproutletProxyTest::_sproutlets;

TEST_F(SproutletProxyTest, NullSproutlet)
{
  // Tests standard routing of a request that doesn't match any Sproutlets.
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
  msg1._from = "sip:alice@homedomain";
  msg1._to = "sip:bob@awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
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
  msg2._method = "INVITE";
  msg2._requri = "sip:bob@awaydomain";
  msg2._from = "sip:alice@homedomain";
  msg2._to = "sip:bob@awaydomain";
  msg2._via = tp->to_string(false);
  msg2._route = "Route: <sip:proxy1.homedomain;transport=TCP;lr>\r\nRoute: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg2.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE

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

  // All done!
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, DownstreamRequestSproutlet)
{
  // Tests standard routing of a request that doesn't match any Sproutlets.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with two Route headers, the first refering to the
  // home domain and the second refering to an external domain.
  Message msg;
  msg._method = "INVITE";
  msg._requri = "sip:bob@awaydomain";
  msg._from = "sip:alice@homedomain";
  msg._to = "sip:bob@awaydomain";
  msg._via = tp->to_string(false);
  msg._route = "Route: <sip:proxy1.homedomain;transport=TCP;service=dsreq;lr>\r\nRoute: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE

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

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  // All done!
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, SimpleSproutletForwarder)
{
  // Tests standard routing of a request through a Sproutlet that simply
  // forwards requests and responses and doesn't Record-Route itself.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with two Route headers - the first referencing the
  // forwarder Sproutlet and the second referencing an external node.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "sip:alice@homedomain";
  msg1._to = "sip:bob@awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:fwd.proxy1.homedomain;transport=TCP;lr>\r\nRoute: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
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

  // Check the first Route header has been removed.
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

  // All done!
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, SimpleSproutletForwarderRR)
{
  // Tests standard routing of a request through a Sproutlet that simply
  // forwards requests and responses and Record-Routes itself.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with two Route headers - the first referencing the
  // forwarder Sproutlet and the second referencing an external node.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "sip:alice@homedomain";
  msg1._to = "sip:bob@awaydomain";
  msg1._via = tp->to_string(false) + "1";
  msg1._route = "Route: <sip:fwdrr.proxy1.homedomain;transport=TCP;lr>\r\nRoute: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
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

  // Check the first Route header has been removed.
  EXPECT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>",
            get_headers(tdata->msg, "Route"));

  // Check a Record-Route header has been added.
  EXPECT_EQ("Record-Route: <sip:proxy1.homedomain;lr;service=fwdrr;hello=world>",
            get_headers(tdata->msg, "Record-Route"));

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  // Send an ACK with the appropriate Route headers and RequestURI.
  //
  // Use aliases in the Record-Route headers to ensure we still route properly.
  Message msg2;
  msg2._method = "ACK";
  msg2._requri = "sip:bob@awaydomain";
  msg2._from = "sip:alice@homedomain";
  msg2._to = "sip:bob@awaydomain";
  msg2._to_tag = "abcdefg";
  msg2._via = tp->to_string(false) + "2";
  msg2._route = "Route: <sip:proxy1.homedomain-alias;lr;service=alias;hello=world>\r\nRoute: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg2.get_request(), tp);

  // Check the ACK is forwarded.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("ACK").matches(tdata->msg);
  EXPECT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>",
            get_headers(tdata->msg, "Route"));
  EXPECT_EQ("",
            get_headers(tdata->msg, "Record-Route"));
  free_txdata();

  // Send a BYE with the appropriate Route headers and RequestURI.
  Message msg3;
  msg3._method = "BYE";
  msg3._requri = "sip:bob@awaydomain";
  msg3._from = "sip:alice@homedomain";
  msg3._to = "sip:bob@awaydomain";
  msg3._to_tag = "abcdefg";
  msg3._via = tp->to_string(false) + "3";
  msg3._route = "Route: <sip:proxy1.homedomain;lr;service=fwdrr/1>\r\nRoute: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg3.get_request(), tp);

  // Check the BYE is forwarded.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("BYE").matches(tdata->msg);
  EXPECT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>",
            get_headers(tdata->msg, "Route"));
  EXPECT_EQ("",
            get_headers(tdata->msg, "Record-Route"));

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // Check the response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  // All done!
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, SimpleSproutletForker)
{
  // Tests standard routing of a request through a Sproutlet that simply
  // forks requests and aggregates responses using the default policy.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header referencing the forking Sproutlet.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@proxy1.awaydomain";
  msg1._from = "sip:alice@homedomain";
  msg1._to = "sip:bob@awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:forker.proxy1.homedomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(NUM_FORKS + 1, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Request is forked to NUM_FORKS different users at the host in the RequestURI.
  ASSERT_EQ(NUM_FORKS, txdata_count());

  // Check the forked requests - RequestURI should be updated, Route header should
  // be stripped and no Record-Route headers added - and send 100 Trying
  // responses.
  std::vector<pjsip_tx_data*> req;
  for (int ii = 0; ii < NUM_FORKS; ++ii)
  {
    int idx = NUM_FORKS - ii - 1;
    req.push_back(pop_txdata());
    expect_target("TCP", "10.10.20.1", 5060, req[ii]);
    ReqMatcher("INVITE").matches(req[ii]->msg);
    EXPECT_EQ("sip:bob-" + std::to_string(idx) + "@proxy1.awaydomain:5060;transport=TCP",
              str_uri(req[ii]->msg->line.req.uri));
    EXPECT_EQ("", get_headers(req[ii]->msg, "Route"));
    EXPECT_EQ("", get_headers(req[ii]->msg, "Record-Route"));
    inject_msg(respond_to_txdata(req[ii], 100));
  }

  // Send 180 Ringing responses on each fork and check they are passed
  // through unchanged.
  for (int ii = 0; ii < NUM_FORKS; ++ii)
  {
    inject_msg(respond_to_txdata(req[ii], 180));
    ASSERT_EQ(1, txdata_count());
    tdata = current_txdata();
    RespMatcher(180).matches(tdata->msg);
    tp->expect_target(tdata);
    free_txdata();
  }

  // Send a 200 OK response from one of the forks and check that the others
  // are cancelled.
  inject_msg(respond_to_txdata(req[0], 200));
  ASSERT_EQ(NUM_FORKS, txdata_count());

  // Check the 200 OK.
  tdata = current_txdata();
  RespMatcher(200).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  for (int ii = 1; ii < NUM_FORKS; ++ii)
  {
    int idx = NUM_FORKS - ii - 1;
    tdata = current_txdata();
    expect_target("TCP", "10.10.20.1", 5060, tdata);
    ReqMatcher("CANCEL").matches(tdata->msg);
    EXPECT_EQ("sip:bob-" + std::to_string(idx) + "@proxy1.awaydomain:5060;transport=TCP",
              str_uri(tdata->msg->line.req.uri));
    EXPECT_EQ("", get_headers(tdata->msg, "Route"));
    EXPECT_EQ("", get_headers(tdata->msg, "Record-Route"));
    inject_msg(respond_to_txdata(tdata, 200));
    free_txdata();
  }

  for (int ii = 1; ii < NUM_FORKS; ++ii)
  {
    inject_msg(respond_to_txdata(req[ii], 487));
    ASSERT_EQ(1, txdata_count());
    tdata = current_txdata();
    expect_target("TCP", "10.10.20.1", 5060, tdata);
    ReqMatcher("ACK").matches(tdata->msg);
    free_txdata();
  }

  // All done!
  req.clear();
  ASSERT_EQ(0, txdata_count());

  // Repeat the same sequence with a MESSAGE request.
  Message msg2;
  msg2._method = "MESSAGE";
  msg2._requri = "sip:bob@proxy1.awaydomain";
  msg2._from = "sip:alice@homedomain";
  msg2._to = "sip:bob@awaydomain";
  msg2._via = tp->to_string(false);
  msg2._route = "Route: <sip:forker.proxy1.homedomain;transport=TCP;lr>";
  inject_msg(msg2.get_request(), tp);

  // Request is forked to NUM_FORKS different users at the host in the RequestURI.
  ASSERT_EQ(NUM_FORKS, txdata_count());

  // Check the forked requests - RequestURI should be updated, Route header should
  // be stripped and no Record-Route headers added.
  for (int ii = 0; ii < NUM_FORKS; ++ii)
  {
    int idx = NUM_FORKS - ii - 1;
    req.push_back(pop_txdata());
    expect_target("TCP", "10.10.20.1", 5060, req[ii]);
    ReqMatcher("MESSAGE").matches(req[ii]->msg);
    EXPECT_EQ("sip:bob-" + std::to_string(idx) + "@proxy1.awaydomain:5060;transport=TCP",
              str_uri(req[ii]->msg->line.req.uri));
    EXPECT_EQ("", get_headers(req[ii]->msg, "Route"));
    EXPECT_EQ("", get_headers(req[ii]->msg, "Record-Route"));
  }

  // Send a 486 Busy Here response from fork one and check that this isn't
  // forwarded.
  inject_msg(respond_to_txdata(req[0], 486));
  ASSERT_EQ(0, txdata_count());

  // Send a 200 OK response from one of the forks and check that this is
  // forwarded immediately.
  // are cancelled.
  inject_msg(respond_to_txdata(req[1], 200));
  ASSERT_EQ(1, txdata_count());

  // Check the 200 OK.
  tdata = current_txdata();
  RespMatcher(200).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // The other forks are cancelled internally, but since this wasn't an INVITE
  // transaction, no CANCELs are sent.
  ASSERT_EQ(0, txdata_count());

  // Send in responses on the other forks and check these are absorbed.
  for (int ii = 2; ii < NUM_FORKS; ++ii)
  {
    inject_msg(respond_to_txdata(req[ii], 404));
    ASSERT_EQ(0, txdata_count());
  }

  // All done!
  req.clear();
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, CancelForking)
{
  // Tests CANCEL processing of a request sent via a forking Sproutlet.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header referencing the forking Sproutlet.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@proxy1.awaydomain";
  msg1._from = "sip:alice@homedomain";
  msg1._to = "sip:bob@awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:forker.proxy1.homedomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(NUM_FORKS + 1, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Request is forked to NUM_FORKS different users at the host in the RequestURI.
  ASSERT_EQ(NUM_FORKS, txdata_count());

  // Check the forked requests - RequestURI should be updated, Route header should
  // be stripped and no Record-Route headers added - and send 100 Trying
  // responses.
  std::vector<pjsip_tx_data*> req;
  for (int ii = 0; ii < NUM_FORKS; ++ii)
  {
    int idx = NUM_FORKS - ii - 1;
    req.push_back(pop_txdata());
    expect_target("TCP", "10.10.20.1", 5060, req[ii]);
    ReqMatcher("INVITE").matches(req[ii]->msg);
    EXPECT_EQ("sip:bob-" + std::to_string(idx) + "@proxy1.awaydomain:5060;transport=TCP",
              str_uri(req[ii]->msg->line.req.uri));
    EXPECT_EQ("", get_headers(req[ii]->msg, "Route"));
    EXPECT_EQ("", get_headers(req[ii]->msg, "Record-Route"));
    inject_msg(respond_to_txdata(req[ii], 100));
  }

  // Send 180 Ringing responses on each fork and check they are passed
  // through unchanged.
  for (int ii = 0; ii < NUM_FORKS; ++ii)
  {
    inject_msg(respond_to_txdata(req[ii], 180));
    ASSERT_EQ(1, txdata_count());
    tdata = current_txdata();
    RespMatcher(180).matches(tdata->msg);
    tp->expect_target(tdata);
    free_txdata();
  }

  // Receive a 408 timeout response on the first fork, and check it is absorbed.
  inject_msg(respond_to_txdata(req[0], 408));
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // Send a CANCEL for the original INVITE.
  msg1._method = "CANCEL";
  inject_msg(msg1.get_request(), tp);

  // Expect a 200 OK response to the CANCEL and CANCELs on the remaining forks.
  ASSERT_EQ(NUM_FORKS, txdata_count());

  tdata = current_txdata();
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  for (int ii = 1; ii < NUM_FORKS; ++ii)
  {
    int idx = NUM_FORKS - ii - 1;
    tdata = current_txdata();
    expect_target("TCP", "10.10.20.1", 5060, tdata);
    ReqMatcher("CANCEL").matches(tdata->msg);
    EXPECT_EQ("sip:bob-" + std::to_string(idx) + "@proxy1.awaydomain:5060;transport=TCP",
              str_uri(tdata->msg->line.req.uri));
    EXPECT_EQ("", get_headers(tdata->msg, "Route"));
    EXPECT_EQ("", get_headers(tdata->msg, "Record-Route"));
    inject_msg(respond_to_txdata(tdata, 200));
    free_txdata();
  }

  // Send in 487 responses for all but the last fork.
  for (int ii = 1; ii < NUM_FORKS - 1; ++ii)
  {
    inject_msg(respond_to_txdata(req[ii], 487));
    tdata = current_txdata();
    expect_target("TCP", "10.10.20.1", 5060, tdata);
    ReqMatcher("ACK").matches(tdata->msg);
    free_txdata();
  }

  // Send in a 486 response for the last fork.
  inject_msg(respond_to_txdata(req[NUM_FORKS - 1], 486));
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // Catch the final 487 response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(487).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // All done!
  req.clear();
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, SproutletDelayRedirect)
{
  // Tests timers with a delayed redirect flow.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with two Route headers - the first referencing the
  // redirect Sproutlet and the second referencing an external node.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "sip:alice@homedomain";
  msg1._to = "sip:bob@awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:delayredirect.proxy1.homedomain;transport=TCP;lr>\r\nRoute: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
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
  EXPECT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>",
            get_headers(tdata->msg, "Route"));
  EXPECT_EQ("", get_headers(tdata->msg, "Record-Route"));
  pjsip_tx_data* old_invite = pop_txdata();
  inject_msg(respond_to_txdata(old_invite, 100));

  // Delay for 1.1 seconds.
  cwtest_advance_time_ms(1100);
  poll();

  // Expect a redirected INVITE and a CANCEL for the previous INVITE.
  ASSERT_EQ(2, txdata_count());

  // Check the CANCEL for the old fork.
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("CANCEL").matches(tdata->msg);
  EXPECT_EQ("sip:bob@awaydomain",
            str_uri(tdata->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>",
            get_headers(tdata->msg, "Route"));
  EXPECT_EQ("", get_headers(tdata->msg, "Record-Route"));
  inject_msg(respond_to_txdata(tdata, 200));
  free_txdata();

  // Check the redirected INVITE.
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);
  EXPECT_EQ("sip:bob2@awaydomain", str_uri(tdata->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>",
            get_headers(tdata->msg, "Route"));
  EXPECT_EQ("", get_headers(tdata->msg, "Record-Route"));
  pjsip_tx_data* new_invite = pop_txdata();

  // Send a 487 response to the original INVITE and check it isn't forwarded.
  inject_msg(respond_to_txdata(old_invite, 487));
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // Send a 200 OK response to the Redirected INVITE.
  inject_msg(respond_to_txdata(new_invite, 200));

  // Check the 200 OK response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  // All done!
  ASSERT_EQ(0, txdata_count());

  // Second time around we do the same with a MESSAGE and have the response
  // come in before the redirect timer expires.
  Message msg2;
  msg2._method = "MESSAGE";
  msg2._requri = "sip:bob@awaydomain";
  msg2._from = "sip:alice@homedomain";
  msg2._to = "sip:bob@awaydomain";
  msg2._via = tp->to_string(false);
  msg2._route = "Route: <sip:delayredirect.proxy1.homedomain;transport=TCP;lr>\r\nRoute: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg2.get_request(), tp);

  // Request is forwarded to the node in the second Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("MESSAGE").matches(tdata->msg);
  EXPECT_EQ("sip:bob@awaydomain", str_uri(tdata->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:proxy1.awaydomain;transport=TCP;lr>",
            get_headers(tdata->msg, "Route"));
  EXPECT_EQ("", get_headers(tdata->msg, "Record-Route"));

  // Send a 200 OK response to the MESSAGE.  This will stop the redirect
  // timer.
  inject_msg(respond_to_current_txdata(200));

  // Check the 200 OK response is forwarded back to the source.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  // All done!
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, SproutletB2BUA)
{
  // Tests passing a request through a B2BUA Sproutlet.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a top Route header referencing the B2BUA Sproutlet
  // and a second Route header referencing the forwarding Sproutlet.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@proxy1.awaydomain:5060;transport=TCP";
  msg1._from = "sip:alice@homedomain";
  msg1._to = "sip:bob@awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:b2bua.proxy1.homedomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying, 200 OK and forwarded INVITE.
  ASSERT_EQ(3, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Check the 200 OK.
  tdata = current_txdata();
  RespMatcher(200).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Check the forwarded INVITE.
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);
  EXPECT_EQ("sip:bob@proxy1.awaydomain:5060;transport=TCP", str_uri(tdata->msg->line.req.uri));
  EXPECT_EQ("", get_headers(tdata->msg, "Route"));
  EXPECT_EQ("", get_headers(tdata->msg, "Record-Route"));

  // Send an ACK in to the 200 OK.
  Message msg2;
  msg2._method = "ACK";
  msg2._requri = "sip:bob@proxy1.awaydomain:5060;transport=TCP";
  msg2._from = "sip:alice@homedomain";
  msg2._to = "sip:bob@awaydomain";
  msg2._via = tp->to_string(false);
  msg2._route = "Route: <sip:b2bua.proxy1.homedomain;transport=TCP;lr>";
  inject_msg(msg2.get_request(), tp);

  // Send a 200 OK response to the INVITE.
  inject_msg(respond_to_current_txdata(200));

  // Check the ACK.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("ACK").matches(tdata->msg);
  EXPECT_EQ("sip:bob@proxy1.awaydomain:5060;transport=TCP", str_uri(tdata->msg->line.req.uri));
  EXPECT_EQ("", get_headers(tdata->msg, "Route"));
  EXPECT_EQ("", get_headers(tdata->msg, "Record-Route"));
  free_txdata();

  // All done!
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, SproutletErrors)
{
  // Tests error handling in SproutletProxy.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with one Route header referencing the bad Sproutlet.
  Message msg1;
  msg1._method = "MESSAGE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "sip:alice@homedomain";
  msg1._to = "sip:bob@awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:bad@proxy1.homedomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 200 OK response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  // All done!
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, UnrecognisedSproutlet)
{
  // Tests SproutletProxy handling of requests to an unrecognised sproutlet.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header referencing a made-up Sproutlet.
  Message msg1;
  msg1._method = "MESSAGE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "sip:alice@homedomain";
  msg1._to = "sip:bob@awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:unrecognised@proxy1.homedomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // SproutletProxy would route based on ReqURI and route to awaydomain.
  // This fails DNS lookup so the request is rejected with a 503.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(503).matches(tdata->msg);
  free_txdata();

  // Inject a request with no Route header.
  Message msg2;
  msg2._method = "MESSAGE";
  msg2._requri = "sip:bob@awaydomain";
  msg2._from = "sip:alice@homedomain";
  msg2._to = "sip:bob@awaydomain";
  msg2._via = tp->to_string(false);
  inject_msg(msg2.get_request(), tp);

  // SproutletProxy doesn't find a Route header, so can't select a suitable
  // Sproutlet, so rejects the request.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(500).matches(tdata->msg);
  free_txdata();

  // All done!
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, UASError)
{
  // Tests handling of errors on the UAS side of a Sproutlet transaction.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header referencing the forking Sproutlet.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@proxy1.awaydomain";
  msg1._from = "sip:alice@homedomain";
  msg1._to = "sip:bob@awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:forker.proxy1.homedomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE
  ASSERT_EQ(NUM_FORKS + 1, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Request is forked to NUM_FORKS different users at the host in the RequestURI.
  ASSERT_EQ(NUM_FORKS, txdata_count());

  // Check the forked requests - RequestURI should be updated, Route header should
  // be stripped and no Record-Route headers added - and send 100 Trying
  // responses.
  std::vector<pjsip_tx_data*> req;
  for (int ii = 0; ii < NUM_FORKS; ++ii)
  {
    int idx = NUM_FORKS - ii - 1;
    req.push_back(pop_txdata());
    expect_target("TCP", "10.10.20.1", 5060, req[ii]);
    ReqMatcher("INVITE").matches(req[ii]->msg);
    EXPECT_EQ("sip:bob-" + std::to_string(idx) + "@proxy1.awaydomain:5060;transport=TCP",
              str_uri(req[ii]->msg->line.req.uri));
    EXPECT_EQ("", get_headers(req[ii]->msg, "Route"));
    EXPECT_EQ("", get_headers(req[ii]->msg, "Record-Route"));
    inject_msg(respond_to_txdata(req[ii], 100));
  }

  // Send 180 Ringing responses on each fork and check they are passed
  // through unchanged.
  for (int ii = 0; ii < NUM_FORKS; ++ii)
  {
    inject_msg(respond_to_txdata(req[ii], 180));
    ASSERT_EQ(1, txdata_count());
    tdata = current_txdata();
    RespMatcher(180).matches(tdata->msg);
    tp->expect_target(tdata);
    free_txdata();
  }

  // Advance the time so the UAS transaction times out.
  //cwtest_advance_time_ms(40000L);
  //poll();

  // Terminate the incoming transport to force a transport error on the UAS
  // transaction.
  delete tp;
  poll();

  ASSERT_EQ(NUM_FORKS, txdata_count());

  for (int ii = NUM_FORKS - 1; ii >= 0; --ii)
  {
    tdata = current_txdata();
    expect_target("TCP", "10.10.20.1", 5060, tdata);
    ReqMatcher("CANCEL").matches(tdata->msg);
    EXPECT_EQ("sip:bob-" + std::to_string(ii) + "@proxy1.awaydomain:5060;transport=TCP",
              str_uri(tdata->msg->line.req.uri));
    EXPECT_EQ("", get_headers(tdata->msg, "Route"));
    EXPECT_EQ("", get_headers(tdata->msg, "Record-Route"));
    inject_msg(respond_to_txdata(tdata, 200));
    free_txdata();
  }

  for (int ii = 0; ii < NUM_FORKS; ++ii)
  {
    inject_msg(respond_to_txdata(req[ii], 487));
    tdata = current_txdata();
    expect_target("TCP", "10.10.20.1", 5060, tdata);
    ReqMatcher("ACK").matches(tdata->msg);
    free_txdata();
  }

  // All done!
  req.clear();
  ASSERT_EQ(0, txdata_count());
}

TEST_F(SproutletProxyTest, SproutletChain)
{
  // Tests passing a request through a chain of sproutlets.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a top Route header referencing the forking Sproutlet
  // and a second Route header referencing the forwarding Sproutlet.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@proxy1.awaydomain";
  msg1._from = "sip:alice@homedomain";
  msg1._to = "sip:bob@awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:forker.proxy1.homedomain;transport=TCP;lr>\r\nRoute: <sip:fwd.proxy1.homedomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITEs.
  ASSERT_EQ(NUM_FORKS + 1, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Request is forked to NUM_FORKS different users at the host in the RequestURI.
  ASSERT_EQ(NUM_FORKS, txdata_count());

  // Check the forked requests - RequestURI should be updated, Route headers should
  // be stripped and no Record-Route headers added - and send 100 Trying
  // responses.
  std::vector<pjsip_tx_data*> req;
  for (int ii = 0; ii < NUM_FORKS; ++ii)
  {
    int idx = NUM_FORKS - ii - 1;
    req.push_back(pop_txdata());
    expect_target("TCP", "10.10.20.1", 5060, req[ii]);
    ReqMatcher("INVITE").matches(req[ii]->msg);
    EXPECT_EQ("sip:bob-" + std::to_string(idx) + "@proxy1.awaydomain:5060;transport=TCP",
              str_uri(req[ii]->msg->line.req.uri));
    EXPECT_EQ("", get_headers(req[ii]->msg, "Route"));
    EXPECT_EQ("", get_headers(req[ii]->msg, "Record-Route"));
    inject_msg(respond_to_txdata(req[ii], 100));
  }

  // Send 180 Ringing responses on each fork and check they are passed
  // through unchanged.
  for (int ii = 0; ii < NUM_FORKS; ++ii)
  {
    inject_msg(respond_to_txdata(req[ii], 180));
    ASSERT_EQ(1, txdata_count());
    tdata = current_txdata();
    RespMatcher(180).matches(tdata->msg);
    tp->expect_target(tdata);
    free_txdata();
  }

  // Send a 486 Busy Here response from fork zero and check that this is ACKed
  // but not forwarded.
  inject_msg(respond_to_txdata(req[0], 486));
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("ACK").matches(tdata->msg);
  free_txdata();

  // Send a 200 OK response from one of the forks and check that the others
  // are cancelled.
  inject_msg(respond_to_txdata(req[1], 200));
  ASSERT_EQ(NUM_FORKS - 1, txdata_count());

  // Check the 200 OK.
  tdata = current_txdata();
  RespMatcher(200).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  for (int ii = 2; ii < NUM_FORKS; ++ii)
  {
    int idx = NUM_FORKS - ii - 1;
    tdata = current_txdata();
    expect_target("TCP", "10.10.20.1", 5060, tdata);
    ReqMatcher("CANCEL").matches(tdata->msg);
    EXPECT_EQ("sip:bob-" + std::to_string(idx) + "@proxy1.awaydomain:5060;transport=TCP",
              str_uri(tdata->msg->line.req.uri));
    EXPECT_EQ("", get_headers(tdata->msg, "Route"));
    EXPECT_EQ("", get_headers(tdata->msg, "Record-Route"));
    inject_msg(respond_to_txdata(tdata, 200));
    free_txdata();
  }

  for (int ii = 2; ii < NUM_FORKS; ++ii)
  {
    inject_msg(respond_to_txdata(req[ii], 487));
    ASSERT_EQ(1, txdata_count());
    tdata = current_txdata();
    expect_target("TCP", "10.10.20.1", 5060, tdata);
    ReqMatcher("ACK").matches(tdata->msg);
    free_txdata();
  }

  // Send an ACK through the same chain of Sproutlets.
  Message msg2;
  msg2._method = "ACK";
  msg2._requri = "sip:bob-1@proxy1.awaydomain:5060;transport=TCP";
  msg2._from = "sip:alice@homedomain";
  msg2._to = "sip:bob@awaydomain";
  msg2._via = tp->to_string(false);
  msg2._route = "Route: <sip:forker.proxy1.homedomain;transport=TCP;lr>\r\nRoute: <sip:fwd.proxy1.homedomain;transport=TCP;lr>";
  inject_msg(msg2.get_request(), tp);

  // Check the ACK is forwarded.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("ACK").matches(tdata->msg);
  EXPECT_EQ("sip:bob-1@proxy1.awaydomain:5060;transport=TCP", str_uri(tdata->msg->line.req.uri));
  EXPECT_EQ("",
            get_headers(tdata->msg, "Route"));
  EXPECT_EQ("",
            get_headers(tdata->msg, "Record-Route"));
  free_txdata();

  // All done!
  req.clear();
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, LoopDetection)
{
  // Test loop detection of requests passing through a chain of sproutlets.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a INVITE with a two Route headers referencing the forwarding Sproutlet,
  // but with Max-Forwards set to one.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@proxy1.awaydomain";
  msg1._from = "sip:alice@homedomain";
  msg1._to = "sip:bob@awaydomain";
  msg1._via = tp->to_string(false) + "1111";
  msg1._route = "Route: <sip:fwd.proxy1.homedomain;transport=TCP;lr>\r\nRoute: <sip:fwd.proxy1.homedomain;transport=TCP;lr>";
  msg1._forwards = 2;
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying followed by 483 Too Many Hops response.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Check the 486 Loop Detected.
  tdata = current_txdata();
  RespMatcher(483).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Inject an ACK with a two Route headers referencing the forwarding Sproutlet,
  // but with Max-Forwards set to one.
  Message msg2;
  msg2._method = "ACK";
  msg2._requri = "sip:bob@proxy1.awaydomain";
  msg2._from = "sip:alice@homedomain";
  msg2._to = "sip:bob@awaydomain";
  msg2._via = tp->to_string(false) + "2222";
  msg2._route = "Route: <sip:fwd.proxy1.homedomain;transport=TCP;lr>\r\nRoute: <sip:fwd.proxy1.homedomain;transport=TCP;lr>";
  msg2._forwards = 2;
  inject_msg(msg2.get_request(), tp);

  // The ACK should be discarded.
  ASSERT_EQ(0, txdata_count());

  // All done!
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, DelayAfterReponse)
{
  // Tests lifetime of a sproutlet that runs a timer after it responds
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with two Route headers - the first referencing the
  // forwarder Sproutlet and the second referencing an external node.
  // Use the address of this message as a unique From tag.
  Message msg1;
  std::string tsx_from_tag = std::to_string((intptr_t)&msg1);
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "sip:alice@homedomain";
  msg1._from_tag = tsx_from_tag;
  msg1._to = "sip:bob@awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:delayafterrsp.proxy1.homedomain;transport=TCP;lr>\r\nRoute: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and 200 OK
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  free_txdata();

  // Check the 200 OK.
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  // No outstanding messages.
  ASSERT_EQ(0, txdata_count());

  // SproutletTsx is live
  ASSERT_TRUE(FakeSproutletTsxDelayAfterRsp<1>::is_live(tsx_from_tag));

  // Advance time to allow the timer to run out and the Tsx to suicide
  cwtest_advance_time_ms(1100L);
  poll();

  // SproutletTsx timer has expired and now the Tsx is gone.
  ASSERT_FALSE(FakeSproutletTsxDelayAfterRsp<1>::is_live(tsx_from_tag));

  // All done!
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, DelayAfterForward)
{
  // Tests lifetime of a sproutlet that runs a timer after it responds
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with two Route headers - the first referencing the
  // forwarder Sproutlet and the second referencing an external node.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@awaydomain";
  msg1._from = "sip:alice@homedomain";
  msg1._to = "sip:bob@awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:delayafterfwd.proxy1.homedomain;transport=TCP;lr>\r\nRoute: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying, 200 OK and forwarded INVITE.
  ASSERT_EQ(3, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  free_txdata();

  // Check the 200 OK.
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(200).matches(tdata->msg);
  free_txdata();

  // Request is forwarded to the node in the second Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // No outstanding messages.
  ASSERT_EQ(0, txdata_count());

  // Advance time to allow the delayed action to occur.
  cwtest_advance_time_ms(1100L);
  poll();

  // Request is forwarded to the node in the second Route header.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  expect_target("TCP", "10.10.20.1", 5060, tdata);
  ReqMatcher("INVITE").matches(tdata->msg);

  // Send a 200 OK response.
  inject_msg(respond_to_current_txdata(200));

  // All done!
  ASSERT_EQ(0, txdata_count());

  delete tp;
}
