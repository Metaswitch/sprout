/**
 * @file sproutletproxy_test.cpp  SproutletProxy unit tests.
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
#include "compositesproutlet.h"
#include "custom_headers.h"
#include "pjutils.h"
#include "pjsip.h"
#include "pjsip_simple.h"
#include "boost/algorithm/string_regex.hpp"

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
  FakeSproutlet(const std::string& service_name,
                int port,
                const std::string& uri,
                const std::string& service_host,
                std::string alias = "",
                SNMP::FakeSuccessFailCountByRequestTypeTable* fake_inc_tbl = NULL,
                SNMP::FakeSuccessFailCountByRequestTypeTable* fake_out_tbl = NULL,
                const std::string& network_function="",
                const std::string& next_hop="") :
    Sproutlet(service_name, port, uri, service_host, { alias }, fake_inc_tbl, fake_out_tbl, network_function),
    _next_hop(next_hop)
  {
  }

  SproutletTsx* get_tsx(SproutletHelper* helper, const std::string& alias, pjsip_msg* req, pjsip_sip_uri*& next_hop, pj_pool_t* pool, SAS::TrailId trail)
  {
    return (SproutletTsx*)new T(this);
  }

  const std::string _next_hop;
};

template <class T>
class UninterestedSproutlet : public Sproutlet
{
public:
  UninterestedSproutlet(const std::string& service_name,
                        int port,
                        const std::string& uri,
                        const std::string& service_host,
                        std::string alias = "",
                        SNMP::FakeSuccessFailCountByRequestTypeTable* fake_inc_tbl = NULL,
                        SNMP::FakeSuccessFailCountByRequestTypeTable* fake_out_tbl = NULL,
                        const std::string& network_function="",
                        const std::string& next_hop="next-hop") :
    Sproutlet(service_name, port, uri, service_host, { alias }, fake_inc_tbl, fake_out_tbl, network_function),
    _next_hop(next_hop)
  {
  }

  SproutletTsx* get_tsx(SproutletHelper* helper, const std::string& alias, pjsip_msg* req, pjsip_sip_uri*& next_hop, pj_pool_t* pool, SAS::TrailId trail)
  {
    pjsip_sip_uri* base_uri = helper->get_routing_uri(req, this);
    next_hop = helper->next_hop_uri(_next_hop,
                                    base_uri,
                                    pool);
    return NULL;
  }

  const std::string _next_hop;
};

template <int S>
class FakeSproutletTsxReject : public SproutletTsx
{
public:
  FakeSproutletTsxReject(Sproutlet* sproutlet) :
    SproutletTsx(sproutlet)
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
  FakeSproutletTsxForwarder(Sproutlet* sproutlet) :
    SproutletTsx(sproutlet)
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
  FakeSproutletTsxDownstreamRequest(Sproutlet* sproutlet) :
    SproutletTsx(sproutlet)
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
  FakeSproutletTsxForker(Sproutlet* sproutlet) :
    SproutletTsx(sproutlet)
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
  FakeSproutletTsxDelayRedirect(Sproutlet* sproutlet) :
    SproutletTsx(sproutlet),
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
  FakeSproutletTsxBad(Sproutlet* sproutlet) :
    SproutletTsx(sproutlet)
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
  FakeSproutletTsxB2BUA(Sproutlet* sproutlet) :
    SproutletTsx(sproutlet)
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
  FakeSproutletTsxDelayAfterRsp(Sproutlet* sproutlet) :
    SproutletTsx(sproutlet),
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
  FakeSproutletTsxDelayAfterFwd(Sproutlet* sproutlet) :
    SproutletTsx(sproutlet),
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

class FakeSproutletTsxDummySCSCF : public SproutletTsx
{
public:
  FakeSproutletTsxDummySCSCF(Sproutlet* sproutlet) :
    SproutletTsx(sproutlet)
  {
  }

  void on_rx_initial_request(pjsip_msg* req)
  {
    pjsip_msg* rsp = create_response(req, PJSIP_SC_NOT_FOUND);
    free_msg(req);
    send_response(rsp);
  }
};

class FakeSproutletReusesTransport : public SproutletTsx
{
public:
  FakeSproutletReusesTransport(Sproutlet* sproutlet) :
    SproutletTsx(sproutlet)
  {
  }

  void on_rx_initial_request(pjsip_msg* req)
  {
    copy_original_transport(req);
    send_request(req);
  }
};

class FakeSproutletTsxNextHop : public CompositeSproutletTsx
{
public:
  FakeSproutletTsxNextHop(Sproutlet* sproutlet) :
   CompositeSproutletTsx(sproutlet, static_cast<FakeSproutlet<FakeSproutletTsxNextHop>*>(sproutlet)->_next_hop)
  {
  }
};

class FakeSproutletURIForwarder : public CompositeSproutletTsx
{
public:
  FakeSproutletURIForwarder(Sproutlet* sproutlet) :
   CompositeSproutletTsx(sproutlet, static_cast<FakeSproutlet<FakeSproutletURIForwarder>*>(sproutlet)->_next_hop)
  {
  }

  void on_rx_initial_request(pjsip_msg* req)
  {
    // Regardless of what we receive, forward the request on using a Route
    // header to route the message to the specified (external) URI.  This is
    // used to test Tel URIs, which are not themselves routable.
    string forwarding_uri = "sip:bob@proxy1.awaydomain:5060;transport=TCP";
    TRC_DEBUG("Forwarding to URI: %s", forwarding_uri.c_str());
    pj_pool_t* pool = get_pool(req);
    pjsip_route_hdr* route = pjsip_route_hdr_create(pool);
    route->name_addr.uri = PJUtils::uri_from_string(forwarding_uri, pool, PJ_FALSE);
    pjsip_msg_insert_first_hdr(req, (pjsip_hdr*)route);

    // Add a foo header so we can check that this sproutlet actually received
    // the message.
    pj_str_t foo = pj_str((char*)"Foo");
    pjsip_route_hdr* foo_hdr = identity_hdr_create(pool, foo);
    foo_hdr->name_addr.uri = PJUtils::uri_from_string("sip:bar@baz", pool, PJ_FALSE);
    pjsip_msg_add_hdr(req, (pjsip_hdr*)foo_hdr);

    send_request(req);
  }
};

class FakeSproutletRestrict : public FakeSproutletTsxNextHop
{
public:
  FakeSproutletRestrict(Sproutlet* sproutlet) :
   FakeSproutletTsxNextHop(sproutlet)
  {
  }

  void on_rx_initial_request(pjsip_msg* req)
  {
    int allowed_state = BaseResolver::ALL_LISTS;

    string hdr_state = get_headers(req, "X-Host-State");

    if (!hdr_state.empty())
    {
      allowed_state = std::stoi(hdr_state.substr(14));
    }

    TRC_DEBUG("Forward on with allowed state restriction: %d", allowed_state);
    send_request(req, allowed_state);
  }

  void on_rx_response(pjsip_msg* rsp, int fork_id)
  {
    TRC_DEBUG("Got %d response", rsp->line.status.code);

    ForkState state = fork_state(fork_id);
    if (state.error_state != ForkErrorState::NONE)
    {
      // The downstream sproutlet hit an error.  Encode this by adding the
      // error value to 700, to produce a unique status code to send upstream.
      // This is just to allow the UTs to check on the error state result, we
      // wouldn't expect real sproutlets to expose this internal error state.
      TRC_DEBUG("Got error state: %d", state.error_state);
      free_msg(rsp);
      pjsip_msg* err_rsp =
        create_response(original_request(),
                        (pjsip_status_code)(700 + state.error_state));
      send_response(err_rsp);
    }
    else
    {
      // Pass the response upstream
      TRC_DEBUG("No error state");
      send_response(rsp);
    }
  }
};

class FakeSproutletBoundary : public FakeSproutletTsxNextHop
{
public:
  FakeSproutletBoundary(Sproutlet* sproutlet) :
   FakeSproutletTsxNextHop(sproutlet)
  {
  }

  void on_rx_initial_request(pjsip_msg* req)
  {
    // Unconditionally restrict downstream attempts so that no addresses are
    // acceptable.  This information must not be passed across network function
    // boundaries, so should be ignored.
    TRC_DEBUG("Forward on - no addrs allowed");
    int allowed_state = 0;
    send_request(req, allowed_state);
  }

  void on_rx_response(pjsip_msg* rsp, int fork_id)
  {
    // There should be no error state passed back up to us from the next
    // network function (such state should not cross network function
    // boundaries).
    TRC_DEBUG("Got %d response - check error", rsp->line.status.code);

    ForkState state = fork_state(fork_id);
    if (state.error_state != ForkErrorState::NONE)
    {
      // We've been passed an error across a network boundary - fail the test.
      FAIL() << "Error passed across network function boundary";
    }

    send_response(rsp);
  }
};

class FakeSproutletForkErrors : public FakeSproutletTsxNextHop
{
public:
  FakeSproutletForkErrors(Sproutlet* sproutlet) :
   FakeSproutletTsxNextHop(sproutlet)
  {
  }

  void on_rx_initial_request(pjsip_msg* req)
  {
    // Send two downstream requests, which we expect to fail in two separate
    // ways.
    TRC_DEBUG("Fork INVITE downstream");
    send_request(req, 0);

    pjsip_msg* orig_req = original_request();
    send_request(orig_req, BaseResolver::ALL_LISTS);
  }
};

class FakeSproutletForkCheck : public FakeSproutletTsxNextHop
{
public:
  FakeSproutletForkCheck(Sproutlet* sproutlet) :
   FakeSproutletTsxNextHop(sproutlet)
  {
  }

  void on_rx_response(pjsip_msg* rsp, int fork_id)
  {
    // As the downstream forks fail in two different ways, we should get an
    // error state of NONE, as we can't usefully combine them.
    TRC_DEBUG("Got %d response - check error state", rsp->line.status.code);

    ForkState state = fork_state(fork_id);
    if (state.error_state != ForkErrorState::NONE)
    {
      // We've been passed error state, when we expected none.
      FAIL() << "Error state incorrectly passed upstream";
    }

    send_response(rsp);
  }
};

class SproutletProxyTest : public SipTest
{
public:
  /// Set up test case.
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();

    // Set up DNS mappings for destinations.
    add_host_mapping("proxy1.homedomain", "10.10.10.1");
    add_host_mapping("proxy2.homedomain", "10.10.10.2");
    add_host_mapping("node1.homedomain", "10.10.18.1");
    add_host_mapping("node2.homedomain", "10.10.18.2");
    add_host_mapping("node2.homedomain", "10.10.18.3");
    add_host_mapping("node2.homedomain", "10.10.18.4");
    add_host_mapping("scscf.proxy1.homedomain", "10.10.19.1");
    add_host_mapping("proxy1.awaydomain", "10.10.20.1");
    add_host_mapping("proxy2.awaydomain", "10.10.20.2");
    add_host_mapping("node1.awaydomain", "10.10.28.1");
    add_host_mapping("node2.awaydomain", "10.10.28.2");

    // Create the Test Sproutlets.
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxForwarder<false> >("fwd", 0, "sip:fwd.homedomain;transport=tcp", ""));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxForwarder<true> >("fwdrr", 0, "sip:fwdrr.proxy1.homedomain;transport=tcp", "", "alias"));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxDownstreamRequest>("dsreq", 0, "sip:dsreq.homedomain;transport=tcp", ""));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxForker<NUM_FORKS> >("forker", 0, "sip:forker.homedomain;transport=tcp", ""));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxDelayRedirect<1> >("delayredirect", 0, "sip:delayredirect.homedomain;transport=tcp", ""));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxBad >("bad", 0, "sip:bad.homedomain;transport=tcp", ""));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxB2BUA >("b2bua", 0, "sip:b2bua.homedomain;transport=tcp", ""));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxDelayAfterRsp<1> >("delayafterrsp", 0, "sip:delayafterrsp.homedomain;transport=tcp", ""));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxDelayAfterFwd<1> >("delayafterfwd", 0, "sip:delayafterfwd.homedomain;transport=tcp", ""));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxDummySCSCF>("scscf", 44444, "sip:scscf.homedomain:44444;transport=tcp", "scscf"));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletReusesTransport>("transport", 0, "sip:transport.homedomain;transport=tcp", ""));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxForwarder<false> >("fwdwithstats", 0, "sip:fwdwithstats.homedomain;transport=tcp", "", "", &SNMP::FAKE_INCOMING_SIP_TRANSACTIONS_TABLE, &SNMP::FAKE_OUTGOING_SIP_TRANSACTIONS_TABLE));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxNextHop>("loop1", 0, "sip:loop1.homedomain;transport=tcp", "", "", NULL, NULL, "loop-nf", "loop2"));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxNextHop>("loop2", 0, "sip:loop2.homedomain;transport=tcp", "", "", NULL, NULL, "loop-nf", "loop1"));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxNextHop>("composite1", 0, "sip:cmp1.homedomain;transport=tcp", "", "", NULL, NULL, "cmp-nf", "composite2"));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxNextHop>("composite2", 0, "sip:cmp2.homedomain;transport=tcp", "", "", NULL, NULL, "cmp-nf", "fwd"));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxNextHop>("repeat1", 0, "sip:rep1.homedomain;transport=tcp", "", "", NULL, NULL, "repeat", "repeat2"));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxNextHop>("repeat2", 0, "sip:rep2.homedomain;transport=tcp", "", "", NULL, NULL, "repeat", "repeat"));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxNextHop>("repeat", 0, "sip:rep.homedomain;transport=tcp", "", "", NULL, NULL, "repeat", "repeat3"));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxNextHop>("repeat3", 0, "sip:rep3.homedomain;transport=tcp", "", "", NULL, NULL, "repeat", ""));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletRestrict>("restrict", 0, "sip:restrict.homedomain;transport=tcp", "", "", NULL, NULL, "state-nf", "downstream"));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxForwarder<false>>("downstream", 0, "sip:downstream.homedomain;transport=tcp", "", "", NULL, NULL, "state-nf", ""));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletBoundary>("boundary", 0, "sip:boundary.homedomain;transport=tcp", "", "", NULL, NULL, "boundary-nf", "restrict"));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletForkErrors>("forkcheck", 0, "sip:forkcheck.homedomain;transport=tcp", "", "", NULL, NULL, "fork-nf", "forkerr"));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletForkErrors>("forkerr", 0, "sip:forkerr.homedomain;transport=tcp", "", "", NULL, NULL, "fork-nf", ""));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletTsxNextHop>("teltest1", 44555, "sip:teltest1.homedomain;transport=tcp", "", "", NULL, NULL, "teltest-nf", "teltest2"));
    _sproutlets.push_back(new FakeSproutlet<FakeSproutletURIForwarder>("teltest2", 0, "sip:teltest2.homedomain;transport=tcp", "", "", NULL, NULL, "teltest-nf", ""));
    _sproutlets.push_back(new UninterestedSproutlet<FakeSproutletTsxNextHop>("teltest3", 44666, "sip:teltest3.homedomain;transport=tcp", "", "", NULL, NULL, "teltest-nf", "teltest2"));

    // Create a host alias.
    std::unordered_set<std::string> host_aliases;
    host_aliases.insert("proxy1.homedomain-alias");

    // We need to add this one for a UT.
    host_aliases.insert("scscf.proxy1.homedomain");

    // Create the Sproutlet proxy.
    _proxy = new SproutletProxy(stack_data.endpt,
                                PJSIP_MOD_PRIORITY_UA_PROXY_LAYER+1,
                                "proxy1.homedomain",
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

  std::string match_sproutlet_from_uri(pjsip_uri* uri)
  {
    std::string service_name;
    std::string unused_alias, unused_local_hostname;
    SproutletProxy::SPROUTLET_SELECTION_TYPES unused_selection_type = SproutletProxy::SPROUTLET_SELECTION_TYPES::NONE_SELECTED;
    Sproutlet* sproutlet = _proxy->match_sproutlet_from_uri(uri,
                                                            unused_alias,
                                                            unused_local_hostname,
                                                            unused_selection_type);
    if (sproutlet != NULL)
    {
      service_name = sproutlet->service_name();
    }

    return service_name;
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
    string _forwards;
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
      _forwards("68"),
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
                       "%8$s"
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
                       /*  8 */ _forwards.empty() ? "" : string("Max-Forwards: ").append(_forwards).append("\r\n").c_str(),
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
  EXPECT_EQ("Record-Route: <sip:fwdrr.proxy1.homedomain;transport=tcp;lr;hello=world>",
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

TEST_F(SproutletProxyTest, ForkErrorTimeout)
{
  // Tests handling of a request timeout.
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
  msg1._route = "Route: <sip:fwdwithstats.proxy1.homedomain;transport=TCP;lr>\r\nRoute: <sip:proxy1.awaydomain;transport=TCP;lr>";
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

  // We won't be responding to this one, so free the data.
  free_txdata();

  // Advance time to trigger a timeout.
  cwtest_advance_time_ms(33000L);
  poll();

  // Expect a 408 response to be sent by the sproutlet.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  tp->expect_target(tdata);
  RespMatcher(408).matches(tdata->msg);
  free_txdata();

  // All done!
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

TEST_F(SproutletProxyTest, CompositeNetworkFunction)
{
  // Tests passing a request through a Network Function composed of multiple
  // sproutlets.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header referencing the first Sproutlet in
  // the composite newtork function.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@proxy1.awaydomain:5060;transport=TCP";
  msg1._from = "sip:alice@homedomain";
  msg1._to = "sip:bob@awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:composite1.proxy1.homedomain;transport=TCP;lr>";
  msg1._forwards = "100";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITEs.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Check the INVITE and send a 100 Trying.
  // We sent in an initial Max-Forwards count of 100.  We've been through three
  // sproutlets, but two of them were part of the same Network Function, so we
  // expect the counter to have gone down by two (not three).
  pjsip_tx_data* req = pop_txdata();
  expect_target("TCP", "10.10.20.1", 5060, req);
  ReqMatcher("INVITE").matches(req->msg);
  EXPECT_EQ("sip:bob@proxy1.awaydomain:5060;transport=TCP",
            str_uri(req->msg->line.req.uri));
  EXPECT_EQ("Max-Forwards: 98", get_headers(req->msg, "Max-Forwards"));
  EXPECT_EQ("", get_headers(req->msg, "Route"));
  vector<string> via_hdrs;
  string via_str = get_headers(req->msg, "Via");
  boost::algorithm::split_regex(via_hdrs, via_str, boost::regex("\r\n"));
  EXPECT_EQ(3, via_hdrs.size());
  EXPECT_THAT(via_hdrs[1], MatchesRegex("Via: SIP/2.0/TCP cmp-nf.sprout.homedomain.*"));

  inject_msg(respond_to_txdata(req, 100));

  // Send a 200 OK response.
  inject_msg(respond_to_txdata(req, 200));
  ASSERT_EQ(1, txdata_count());

  // Check the 200 OK.
  tdata = current_txdata();
  RespMatcher(200).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Send an ACK
  Message msg2;
  msg2._method = "ACK";
  msg2._requri = "sip:bob@proxy1.awaydomain:5060;transport=TCP";
  msg2._from = "sip:alice@homedomain";
  msg2._to = "sip:bob@awaydomain";
  msg2._via = tp->to_string(false);
  msg2._route = "Route: <sip:composite1.proxy1.homedomain;transport=TCP;lr>";
  inject_msg(msg2.get_request(), tp);

  // Check the ACK is forwarded.
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

TEST_F(SproutletProxyTest, CompositeNetworkFunctionTelURI)
{
  // Tests passing a request through a Network Function composed of multiple
  // sproutlets, when the request is routed by port (as there are no Route
  // headers, and the Request URI is not a routable SIP URI - e.g. it is a Tel
  // URI).
  pjsip_tx_data* tdata;

  // Create a TCP transport that will deliver inbound messages on the port
  // 44555.  This port is owned by the teltest1 sproutlet, which forwards on to
  // the teltest2 sproutlet, even though it doesn't have a routable SIP URI to
  // hand.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        44555,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with no Route header, and a Tel URI.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "tel:8088341234";
  msg1._from = "sip:alice@homedomain";
  msg1._to = "sip:bob@awaydomain";
  msg1._via = tp->to_string(false);
  msg1._forwards = "100";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITEs.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Check the INVITE contains the Foo header added by teltest2 and send a
  // 100 Trying.
  pjsip_tx_data* req = pop_txdata();
  expect_target("TCP", "10.10.20.1", 5060, req);
  ReqMatcher("INVITE").matches(req->msg);
  EXPECT_EQ("Foo: <sip:bar@baz>", get_headers(req->msg, "Foo"));
  inject_msg(respond_to_txdata(req, 100));

  // Send a 200 OK response.
  inject_msg(respond_to_txdata(req, 200));
  ASSERT_EQ(1, txdata_count());

  // Check the 200 OK.
  tdata = current_txdata();
  RespMatcher(200).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // All done!
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, CompositeNetworkFunctionTelURI2)
{
  // Tests passing a request through a Network Function composed of multiple
  // sproutlets, when the request is routed by port (as there are no Route
  // headers, the Request URI is not a routable SIP URI - e.g. it is a Tel
  // URI), and the first sproutlet is not interested in handling the request.
  pjsip_tx_data* tdata;

  // Create a TCP transport that will deliver inbound messages on the port
  // 44666.  This port is owned by the teltest3 sproutlet, which forwards on to
  // the teltest2 sproutlet, even though it doesn't have a routable SIP URI to
  // hand.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        44666,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with no Route header, and a Tel URI.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "tel:8088341234";
  msg1._from = "sip:alice@homedomain";
  msg1._to = "sip:bob@awaydomain";
  msg1._via = tp->to_string(false);
  msg1._forwards = "100";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITEs.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Check the INVITE contains the Foo header added by teltest2 and send a
  // 100 Trying.
  pjsip_tx_data* req = pop_txdata();
  expect_target("TCP", "10.10.20.1", 5060, req);
  ReqMatcher("INVITE").matches(req->msg);
  EXPECT_EQ("Foo: <sip:bar@baz>", get_headers(req->msg, "Foo"));
  inject_msg(respond_to_txdata(req, 100));

  // Send a 200 OK response.
  inject_msg(respond_to_txdata(req, 200));
  ASSERT_EQ(1, txdata_count());

  // Check the 200 OK.
  tdata = current_txdata();
  RespMatcher(200).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // All done!
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, CompositeNetworkFunctionReqURI)
{
  // Tests passing a request through a Network Function composed of multiple
  // sproutlets, when the request is routed by the request URI.
  pjsip_tx_data* tdata;

  // Create a TCP transport that will deliver inbound messages on. The port is
  // random to make sure that we don't match a Sproutlet based on the port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        43498,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with no Route header, and a Tel URI.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@teltest1.proxy1.homedomain:5060;transport=TCP";
  msg1._from = "sip:alice@homedomain";
  msg1._to = "sip:bob@awaydomain";
  msg1._via = tp->to_string(false);
  msg1._forwards = "100";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITEs.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Check the INVITE contains the Foo header added by teltest2 and send a
  // 100 Trying.
  pjsip_tx_data* req = pop_txdata();
  expect_target("TCP", "10.10.20.1", 5060, req);
  ReqMatcher("INVITE").matches(req->msg);
  EXPECT_EQ("Foo: <sip:bar@baz>", get_headers(req->msg, "Foo"));
  inject_msg(respond_to_txdata(req, 100));

  // Send a 200 OK response.
  inject_msg(respond_to_txdata(req, 200));
  ASSERT_EQ(1, txdata_count());

  // Check the 200 OK.
  tdata = current_txdata();
  RespMatcher(200).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // All done!
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, CompositeNetworkFunctionReqURI2)
{
  // Tests passing a request through a Network Function composed of multiple
  // sproutlets, when the request is routed by the request URI, and the first
  // sproutlet is not interested in handling the request.
  pjsip_tx_data* tdata;

  // Create a TCP transport that will deliver inbound messages on. The port is
  // random to make sure that we don't match a Sproutlet based on the port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        43498,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with no Route header, and a Tel URI.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@teltest3.proxy1.homedomain:5060;transport=TCP";
  msg1._from = "sip:alice@homedomain";
  msg1._to = "sip:bob@awaydomain";
  msg1._via = tp->to_string(false);
  msg1._forwards = "100";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITEs.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Check the INVITE contains the Foo header added by teltest2 and send a
  // 100 Trying.
  pjsip_tx_data* req = pop_txdata();
  expect_target("TCP", "10.10.20.1", 5060, req);
  ReqMatcher("INVITE").matches(req->msg);
  EXPECT_EQ("Foo: <sip:bar@baz>", get_headers(req->msg, "Foo"));
  inject_msg(respond_to_txdata(req, 100));

  // Send a 200 OK response.
  inject_msg(respond_to_txdata(req, 200));
  ASSERT_EQ(1, txdata_count());

  // Check the 200 OK.
  tdata = current_txdata();
  RespMatcher(200).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // All done!
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, CompositeNetworkFunctionNonLocalReqURI)
{
  // Tests passing a request through a Network Function composed of multiple
  // sproutlets, when the request is routed by port (but the message contains
  // a non-local SIP URI in the request line), and the first sproutlet is not
  // interested in handling the request.
  pjsip_tx_data* tdata;

  // Create a TCP transport that will deliver inbound messages on the port
  // 44666.  This port is owned by the teltest3 sproutlet, which forwards on to
  // the teltest2 sproutlet, even though it doesn't have a routable SIP URI to
  // hand.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        44666,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with no Route header, and a Tel URI.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@notalocaluri:5060;transport=TCP";
  msg1._from = "sip:alice@homedomain";
  msg1._to = "sip:bob@awaydomain";
  msg1._via = tp->to_string(false);
  msg1._forwards = "100";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITEs.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Check the INVITE contains the Foo header added by teltest2 and send a
  // 100 Trying.
  pjsip_tx_data* req = pop_txdata();
  expect_target("TCP", "10.10.20.1", 5060, req);
  ReqMatcher("INVITE").matches(req->msg);
  EXPECT_EQ("Foo: <sip:bar@baz>", get_headers(req->msg, "Foo"));
  inject_msg(respond_to_txdata(req, 100));

  // Send a 200 OK response.
  inject_msg(respond_to_txdata(req, 200));
  ASSERT_EQ(1, txdata_count());

  // Check the 200 OK.
  tdata = current_txdata();
  RespMatcher(200).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // All done!
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, RepeatedNetworkFunction)
{
  // Tests passing a request through two network functions with the same name.
  // We should still be able to detect the boundary between them, and add the
  // internal Via header.  For testing purposes, we've mocked this up by having
  // two separate network functions which report the same name.  In real
  // situations it will be two instances of the same network function, which
  // the call is routed through in complex ways.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header referencing the first Sproutlet in
  // the first instance of the network function.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@proxy1.awaydomain:5060;transport=TCP";
  msg1._from = "sip:alice@homedomain";
  msg1._to = "sip:bob@awaydomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:repeat1.proxy1.homedomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITEs.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Check the INVITE and send a 100 Trying.  There should be three Via headers
  // on the INVITE that coms out the other side (from top, to bottom):
  //  - One from exiting the SPN
  //  - One from the internal network function boundary
  //  - One from the original sender
  pjsip_tx_data* req = pop_txdata();
  expect_target("TCP", "10.10.20.1", 5060, req);
  ReqMatcher("INVITE").matches(req->msg);
  EXPECT_EQ("sip:bob@proxy1.awaydomain:5060;transport=TCP",
            str_uri(req->msg->line.req.uri));
  EXPECT_EQ("", get_headers(req->msg, "Route"));
  vector<string> via_hdrs;
  string via_str = get_headers(req->msg, "Via");
  boost::algorithm::split_regex(via_hdrs, via_str, boost::regex("\r\n"));
  EXPECT_EQ(3, via_hdrs.size());
  EXPECT_THAT(via_hdrs[1], MatchesRegex("Via: SIP/2.0/TCP repeat.sprout.homedomain.*"));

  inject_msg(respond_to_txdata(req, 100));

  // Send a 200 OK response.
  inject_msg(respond_to_txdata(req, 200));
  ASSERT_EQ(1, txdata_count());

  // Check the 200 OK.  It should contain just a single Via header (belonging
  // to the original sender).
  tdata = current_txdata();
  RespMatcher(200).matches(tdata->msg);
  via_hdrs.clear();
  via_str = get_headers(tdata->msg, "Via");
  boost::algorithm::split_regex(via_hdrs, via_str, boost::regex("\r\n"));
  EXPECT_EQ(1, via_hdrs.size());
  EXPECT_THAT(via_hdrs[0], MatchesRegex("Via: SIP/2.0/TCP 1.2.3.4.*"));
  tp->expect_target(tdata);
  free_txdata();

  // All done!
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, LoopDetectionMaxForwards)
{
  // Test loop detection of requests passing through a chain of sproutlets.
  // We use two sproutlets that return different Network Function names,
  // otherwise they'll be treated as a single entity, and only decrement the
  // Max-Forwards count once.
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
  msg1._route = "Route: <sip:fwd.proxy1.homedomain;transport=TCP;lr>\r\nRoute: <sip:fwdrr.proxy1.homedomain;transport=TCP;lr>";
  msg1._forwards = "2";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying followed by 483 Too Many Hops response.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Check the 483 Loop Detected.
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
  msg2._route = "Route: <sip:fwd.proxy1.homedomain;transport=TCP;lr>\r\nRoute: <sip:fwdrr.proxy1.homedomain;transport=TCP;lr>";
  msg2._forwards = "2";
  inject_msg(msg2.get_request(), tp);

  // The ACK should be discarded.
  ASSERT_EQ(0, txdata_count());

  // All done!
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, LoopDetectionSproutletDepth)
{
  // Test loop detection when a request is sent around in a loop between
  // sproutlets that are all part of the same Network Function.  In such cases,
  // Max-Forwards won't help us, as it will only be decremented once by the
  // Network Function, rather than once per sproutlet.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a INVITE with a Route header identifying the entry Sproutlet.  Omit
  // the Max-Forwards header to avoid that ending the loop for us.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@proxy1.awaydomain";
  msg1._from = "sip:alice@homedomain";
  msg1._to = "sip:bob@awaydomain";
  msg1._via = tp->to_string(false) + "1111";
  msg1._route = "Route: <sip:loop1.proxy1.homedomain;transport=TCP;lr>";
  msg1._forwards = "";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying followed by 483 Too Many Hops response.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
  free_txdata();

  // Check the 483 Loop Detected.
  tdata = current_txdata();
  RespMatcher(483).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Inject an ACK.
  Message msg2;
  msg2._method = "ACK";
  msg2._requri = "sip:bob@proxy1.awaydomain";
  msg2._from = "sip:alice@homedomain";
  msg2._to = "sip:bob@awaydomain";
  msg2._via = tp->to_string(false) + "2222";
  msg2._route = "Route: <sip:loop1.proxy1.homedomain;transport=TCP;lr>";
  msg2._forwards = "";
  inject_msg(msg2.get_request(), tp);

  // The ACK should be discarded.
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, RestrictHostStateNone)
{
  // Tests passing a request through a Network Function that restricts the
  // allowed host state of request targets, and having a downstream sproutlet
  // fail to meet those restrictions.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header referencing the first restricting
  // Sproutlet.  Include the internal UT header X-Host-State to indicate that
  // the restrict sproutlet should not allow any address types.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@proxy1.awaydomain:5060;transport=TCP";
  msg1._route = "Route: <sip:restrict.proxy1.homedomain;transport=TCP;lr>";
  msg1._extra = "X-Host-State: 0";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and error response from restrict sproutlet.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Check the error response.  The restrict sproutlet makes up an error code
  // by adding 700 to the index of the error state that it encountered.
  int err_code = 700 + (int)ForkErrorState::NO_ADDRESSES;
  tdata = current_txdata();
  RespMatcher(err_code).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // All done!
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, RestrictHostStateTimeout)
{
  // Tests passing a request through a Network Function that restricts the
  // allowed host state of request targets, and having a downstream sproutlet
  // fail to meet those restrictions.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header referencing the first restricting
  // Sproutlet.  Include the internal UT header X-Host-State to indicate that
  // the restrict sproutlet can use only whitelisted addresses.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@proxy1.awaydomain:5060;transport=TCP";
  msg1._route = "Route: <sip:restrict.proxy1.homedomain;transport=TCP;lr>";
  msg1._extra = "X-Host-State: " + BaseResolver::WHITELISTED;
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and forwarded INVITE.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Check the INVITE, but don't send any trying response (we're being
  // unresponsive to trigger a timeout).
  pjsip_tx_data* req = pop_txdata();
  expect_target("TCP", "10.10.20.1", 5060, req);
  ReqMatcher("INVITE").matches(req->msg);

  // Advance time to make the call timeout
  cwtest_advance_time_ms(33000L);
  poll();

  // Check the error response.  The restrict sproutlet makes up an error code
  // by adding 700 to the index of the error state that it encountered.
  ASSERT_EQ(1, txdata_count());
  int err_code = 700 + (int)ForkErrorState::TIMEOUT;
  tdata = current_txdata();
  RespMatcher(err_code).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // All done!
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, RestrictHostBoundaryLimit)
{
  // Tests passing a request through a Network Function that restricts the
  // allowed host state of request targets, and having that restriction
  // discarded at the newtork function boundary.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header referencing the first network
  // function.  This will restrict the allowed type to "no addresses", which
  // the downstream sproutlet will ignore, because it is part of a separate
  // network function.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@proxy1.awaydomain:5060;transport=TCP";
  msg1._route = "Route: <sip:boundary.proxy1.homedomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and error response from restrict sproutlet.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // Check the INVITE, but don't send any trying response (we're being
  // unresponsive to trigger a timeout).
  pjsip_tx_data* req = pop_txdata();
  expect_target("TCP", "10.10.20.1", 5060, req);
  ReqMatcher("INVITE").matches(req->msg);

  // Advance time to make the call timeout
  cwtest_advance_time_ms(33000L);
  poll();

  // Check the error response.  The restrict sproutlet makes up an error code
  // by adding 700 to the index of the error state that it encountered.  The
  // boundary sproutlet will have verified that the error state wasn't also
  // passed upstream.
  ASSERT_EQ(1, txdata_count());
  int err_code = 700 + (int)ForkErrorState::TIMEOUT;
  tdata = current_txdata();
  RespMatcher(err_code).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // All done!
  ASSERT_EQ(0, txdata_count());

  delete tp;
}

TEST_F(SproutletProxyTest, RestrictHostForkError)
{
  // Tests hitting multiple error states on multiple forks.
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        stack_data.scscf_port,
                                        "1.2.3.4",
                                        49152);

  // Inject a request with a Route header referencing the first network
  // function.  This will restrict the allowed type to "no addresses", which
  // the downstream sproutlet will ignore, because it is part of a separate
  // network function.
  Message msg1;
  msg1._method = "INVITE";
  msg1._requri = "sip:bob@proxy1.awaydomain:5060;transport=TCP";
  msg1._route = "Route: <sip:forkcheck.proxy1.homedomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting 100 Trying and error response from restrict sproutlet.
  ASSERT_EQ(2, txdata_count());

  // Check the 100 Trying.
  tdata = current_txdata();
  RespMatcher(100).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

  // One fork will be rejected at the transport layer (because no host state
  // is acceptable).  The other will result in an INVITE, which we ignore, as
  // we're being unresponsive.
  pjsip_tx_data* req = pop_txdata();
  expect_target("TCP", "10.10.20.1", 5060, req);
  ReqMatcher("INVITE").matches(req->msg);

  // Advance time to make the call timeout
  cwtest_advance_time_ms(33000L);
  poll();

  // Check that we got the expected SIP response code.  The forkcheck sproutlet
  // will have verified that it didn't get a single fork error result (as the
  // forks didn't agree).
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(503).matches(tdata->msg);
  tp->expect_target(tdata);
  free_txdata();

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

// Tests standard routing of a subscription request to ensure it is
// routed via the sproutlet interface.
TEST_F(SproutletProxyTest, LocalNonSubscribe)
{
  pjsip_tx_data* tdata;

  // Create a TCP connection to the listening port.
  TransportFlow* tp = new TransportFlow(TransportFlow::Protocol::TCP,
                                        44444,
                                        "1.2.3.4",
                                        49152);

  // Inject a SUBSCRIBE request that wouldn't be absorbed by the subscription
  // module (this should be handled by the S-CSCF)
  Message msg1;
  msg1._method = "SUBSCRIBE";
  msg1._requri = "sip:bob@homedomain";
  msg1._from = "sip:alice@homedomain";
  msg1._to = "sip:bob@homedomain";
  msg1._via = tp->to_string(false);
  msg1._route = "Route: <sip:fwd.proxy1.homedomain;transport=TCP;lr>\r\nRoute: <sip:scscf@proxy1.homedomain;transport=TCP;lr>\r\nRoute: <sip:proxy1.awaydomain;transport=TCP;lr>";
  inject_msg(msg1.get_request(), tp);

  // Expecting the forwarded SUBSCRIBE
  ASSERT_EQ(1, txdata_count());

  // Check the 404 result (the fake sproutlet always returns a 404)
  tdata = current_txdata();
  RespMatcher(404).matches(tdata->msg);

  delete tp;
}

// Tests that sproutlet target selection works.
TEST_F(SproutletProxyTest, SproutletSelection)
{
  // The order of precedence for matching is:
  // - service parameter
  // - domain part
  // - user part
  // - port
  //
  // Check that this holds when we have conflicting information in the three
  // parts.
  std::string service_name;
  std::string uri_str = "sip:b2bua@scscf.proxy1.homedomain:44444;service=fwd";
  pjsip_sip_uri* uri = (pjsip_sip_uri*)PJUtils::uri_from_string(uri_str, stack_data.pool, PJ_FALSE);

  // Shoud match fwd.
  service_name = match_sproutlet_from_uri((pjsip_uri*)uri);
  ASSERT_EQ("fwd", service_name);

  uri_str = "sip:b2bua@scscf.proxy1.homedomain:44444";
  uri = (pjsip_sip_uri*)PJUtils::uri_from_string(uri_str, stack_data.pool, PJ_FALSE);

  // Should match scscf.
  service_name = match_sproutlet_from_uri((pjsip_uri*)uri);
  ASSERT_EQ("scscf", service_name);

  uri_str = "sip:b2bua@proxy1.homedomain:44444";
  uri = (pjsip_sip_uri*)PJUtils::uri_from_string(uri_str, stack_data.pool, PJ_FALSE);

  // Should match b2bua.
  service_name = match_sproutlet_from_uri((pjsip_uri*)uri);
  ASSERT_EQ("b2bua", service_name);
}

// Tests that it's not possible to register more than one Sproutlet for the
// same service name or port.
TEST_F(SproutletProxyTest, ConflictingSproutlets)
{
  // Check that we fail to register a sproutlet that already exists.
  // This is because the service name, alias and port are already taken.
  Sproutlet* sproutlet = new FakeSproutlet<FakeSproutletTsxDummySCSCF>("scscf", 44444, "sip:scscf.homedomain:44444;transport=tcp", "scscf", "alias");
  ASSERT_EQ(_proxy->register_sproutlet(sproutlet), false);

  delete sproutlet;
}

TEST_F(SproutletProxyTest, SproutletCopiesOriginalTransport)
{
  // Tests standard routing of a request through a Sproutlet that simply
  // forwards requests and responses and doesn't Record-Route itself - and
  // that reuses the original transport for onwards messages.
  pjsip_tx_data* tdata;

  // Create two TCP connections to the listening port.
  TransportFlow* tp1 = new TransportFlow(TransportFlow::Protocol::TCP,
                                         stack_data.scscf_port,
                                         "10.10.28.1",   // node1.awaydomain
                                         49152);
  TransportFlow* tp2 = new TransportFlow(TransportFlow::Protocol::TCP,
                                         stack_data.scscf_port,
                                         "10.10.28.1",   // node1.awaydomain
                                         54321);

  // We're going to show that whichever transport we use to send in an INVITE
  // is reused on the outgoing side.
  for (int ii = 0; ii < 2; ii++)
  {
    // Use one, or the other, of our transport flows.
    TransportFlow* tp = (ii == 0) ? tp1 : tp2;

    // Inject a request with two Route headers - the first referencing the
    // transport-copying Sproutlet and the second going back to the sender.
    Message msg1;
    msg1._method = "INVITE";
    msg1._requri = "sip:bob@awaydomain";
    msg1._from = "sip:alice@homedomain";
    msg1._to = "sip:bob@awaydomain";
    msg1._via = tp->to_string(false);
    msg1._route = "Route: <sip:transport.proxy1.homedomain;transport=TCP;lr>\r\nRoute: <sip:node1.awaydomain;transport=TCP;lr>";
    inject_msg(msg1.get_request(), tp);

    // Expecting 100 Trying and forwarded INVITE
    ASSERT_EQ(2, txdata_count());

    // Check the 100 Trying.
    tdata = current_txdata();
    RespMatcher(100).matches(tdata->msg);
    tp->expect_target(tdata);
    EXPECT_EQ("To: <sip:bob@awaydomain>", get_headers(tdata->msg, "To")); // No tag
    free_txdata();

    // Request is forwarded to the node in the second Route header, reusing the
    // incoming transport
    ASSERT_EQ(1, txdata_count());
    tdata = current_txdata();
    tp->expect_target(tdata, true);
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
  }

  delete tp1;
  delete tp2;
}
