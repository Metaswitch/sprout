/**
 * @file bono.cpp P-CSCF/IBCF implementation
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

///
/// = Structure =
///
/// init_stateful_proxy and destroy_stateful_proxy do the obvious.
///
/// The main entry points during operation are: proxy_on_rx_request,
/// proxy_on_rx_response, tu_on_tsx_state.
///
/// proxy_on_rx_request invokes one of the following:
/// * handle_incoming_non_cancel
/// * uas_data->handle_outgoing_non_cancel
/// * cancel logic directly in proxy_on_rx_request.
///
/// proxy_on_rx_response forwards the response upstream appropriately
/// based on the headers.
///
/// tu_on_tsx_state passes transaction state change message to
/// UASTransaction::on_tsx_state or UACTransaction::on_tsx_state as
/// appropriate.  These cause appropriate state updates.
///
/// handle_incoming_non_cancel does the following, in order:
/// * proxy_verify_request
/// * clone request as response
/// * optionally, do proxy_process_access_routing
/// * do proxy_process_routing
/// * create a UAS transaction object
/// * pass to uas_data->handle_incoming_non_cancel
///
/// UASTransaction::handle_incoming_non_cancel does:
/// * 100 if necessary
/// * originating call services hook if appropriate.
///
/// UASTransaction::handle_outgoing_non_cancel does:
/// * URI translation
/// * terminating call services hook if appropriate
/// * find targets
/// * add headers
/// * UASTransaction::init_uac_transactions
///
/// UASTransaction::init_uac_transactions takes a list of targets and
/// does:
/// * create transaction
/// * create UAC transaction object
/// * UAC::send_request on each
///
/// UAC sends out requests, and passes responses up to
/// UAS::on_new_client_response.
///
/// UAS::on_new_client_response handles appropriately, including
/// handling forked transactions, and forwards upstream as necessary.

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
#include "pjsip-simple/evsub.h"
}

// Common STL includes.
#include <cassert>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <queue>
#include <string>

#include "log.h"
#include "utils.h"
#include "pjutils.h"
#include "stack.h"
#include "sproutsasevent.h"
#include "analyticslogger.h"
#include "bono.h"
#include "constants.h"
#include "enumservice.h"
#include "bgcfservice.h"
#include "sip_connection_pool.h"
#include "flowtable.h"
#include "trustboundary.h"
#include "sessioncase.h"
#include "ifchandler.h"
#include "hssconnection.h"
#include "aschain.h"
#include "registration_utils.h"
#include "custom_headers.h"
#include "dialog_tracker.hpp"
#include "quiescing_manager.h"
#include "scscfselector.h"
#include "contact_filtering.h"
#include "uri_classifier.h"

static AnalyticsLogger* analytics_logger;
static ACRFactory* cscf_acr_factory;

static bool edge_proxy;
static pjsip_uri* upstream_proxy;
static SIPConnectionPool* upstream_conn_pool = NULL;

static SNMP::IPCountTable* sprout_ip_tbl = NULL;
static SNMP::U32Scalar* flow_count = NULL;

static FlowTable* flow_table;
static DialogTracker* dialog_tracker;
static pjsip_uri* icscf_uri = NULL;

static bool ibcf = false;
static bool icscf = false;
static bool scscf = false;
static bool allow_emergency_reg = false;

PJUtils::host_list_t trusted_hosts(&PJUtils::compare_pj_sockaddr);
PJUtils::host_list_t pbx_hosts(&PJUtils::compare_pj_sockaddr);
std::string pbx_service_route;

//
// mod_stateful_proxy is the module to receive SIP request and
// response message that is outside any transaction context.
//
static pj_bool_t proxy_on_rx_request(pjsip_rx_data *rdata );
static pj_bool_t proxy_on_rx_response(pjsip_rx_data *rdata );

void set_target_on_tdata(const struct Target& target, pjsip_tx_data* tdata);

static pjsip_module mod_stateful_proxy =
{
  NULL, NULL,                         // prev, next
  pj_str("mod-stateful-proxy"),       // Name
  -1,                                 // Id
  PJSIP_MOD_PRIORITY_UA_PROXY_LAYER+3,// Priority
  NULL,                               // load()
  NULL,                               // start()
  NULL,                               // stop()
  NULL,                               // unload()
  &proxy_on_rx_request,               // on_rx_request()
  &proxy_on_rx_response,              // on_rx_response()
  NULL,                               // on_tx_request()
  NULL,                               // on_tx_response()
  NULL,                               // on_tsx_state()
};


//
// mod_tu (tu=Transaction User) is the module to receive notification
// from transaction when the transaction state has changed.
//
static void tu_on_tsx_state(pjsip_transaction *tsx, pjsip_event *event);

static pjsip_module mod_tu =
{
  NULL, NULL,                         // prev, next.
  pj_str("mod-transaction-user"),     // Name.
  -1,                                 // Id
  PJSIP_MOD_PRIORITY_APPLICATION,     // Priority
  NULL,                               // load()
  NULL,                               // start()
  NULL,                               // stop()
  NULL,                               // unload()
  NULL,                               // on_rx_request()
  NULL,                               // on_rx_response()
  NULL,                               // on_tx_request()
  NULL,                               // on_tx_response()
  &tu_on_tsx_state,                   // on_tsx_state()
};

// High-level functions.
static void process_tsx_request(pjsip_rx_data* rdata);
static void process_cancel_request(pjsip_rx_data* rdata);
static int proxy_verify_request(pjsip_rx_data *rdata);
static void reject_request(pjsip_rx_data* rdata, int status_code);
#ifndef UNIT_TEST
static
#endif
int proxy_process_access_routing(pjsip_rx_data *rdata,
                                 pjsip_tx_data *tdata,
                                 TrustBoundary **trust,
                                 Target **target);
static bool ibcf_trusted_peer(const pj_sockaddr& addr);
static bool is_pbx(const pj_sockaddr& addr);
static pj_status_t proxy_process_routing(pjsip_tx_data *tdata);
static pj_bool_t proxy_trusted_source(pjsip_rx_data* rdata);


// Helper functions.
static int compare_sip_sc(int sc1, int sc2);
static pj_status_t add_path(pjsip_tx_data* tdata,
                            const Flow* flow_data,
                            const pjsip_rx_data* rdata);
static ACR::NodeRole acr_node_role(pjsip_msg *req);


// Utility class that automatically flushes a trail ID when it goes out of
// scope (unless the user decides it isn't required). This is useful when a
// function has multiple exit points that should all cause the trail to be
// flushed.
class TrailFlusher
{
public:
  TrailFlusher(SAS::TrailId trail) : _trail(trail), _flush_required(true) {}

  void set_flush_required(bool required) { _flush_required = required; }

  ~TrailFlusher()
  {
    if (_flush_required)
    {
      SAS::Marker flush_marker(_trail, MARKED_ID_FLUSH);
      SAS::report_marker(flush_marker);
    }
  }

private:
  SAS::TrailId _trail;
  bool _flush_required;
};

///@{
// MAIN ENTRY POINTS

// Callback to be called to handle new incoming requests.  Subsequent
// responses/requests will be handled by UA[SC]Transaction methods.
static pj_bool_t proxy_on_rx_request(pjsip_rx_data *rdata)
{
  TRC_DEBUG("Proxy RX request");

  // SAS log the start of processing by this module
  SAS::Event event(get_trail(rdata), SASEvent::BEGIN_STATEFUL_PROXY_REQ, 0);
  SAS::report_event(event);

  if (rdata->msg_info.msg->line.req.method.id != PJSIP_CANCEL_METHOD)
  {
    // Request is a normal transaction request.
    process_tsx_request(rdata);
  }
  else
  {
    // Request is a CANCEL.
    process_cancel_request(rdata);
  }

  return PJ_TRUE;
}


// Callback to be called to handle incoming response outside
// any transactions. This happens for example when 2xx/OK
// for INVITE is received and transaction will be destroyed
// immediately, so we need to forward the subsequent 2xx/OK
// retransmission statelessly.
static pj_bool_t proxy_on_rx_response(pjsip_rx_data *rdata)
{
  pjsip_tx_data *tdata;
  pjsip_response_addr res_addr;
  pjsip_via_hdr *hvia;
  pj_status_t status;

  // SAS log the start of processing by this module
  SAS::Event event(get_trail(rdata), SASEvent::BEGIN_STATEFUL_PROXY_RSP, 0);
  SAS::report_event(event);

  // Only forward responses to INVITES
  if (rdata->msg_info.cseq->method.id == PJSIP_INVITE_METHOD)
  {
    // Create response to be forwarded upstream (Via will be stripped here)
    status = PJUtils::create_response_fwd(stack_data.endpt, rdata, 0, &tdata);
    if (status != PJ_SUCCESS)
    {
      TRC_ERROR("Error creating response, %s",
                PJUtils::pj_status_to_string(status).c_str());
      return PJ_TRUE;
    }

    // Get topmost Via header
    hvia = (pjsip_via_hdr*) pjsip_msg_find_hdr(tdata->msg, PJSIP_H_VIA, NULL);
    if (hvia == NULL)
    {
      // Invalid response! Just drop it
      pjsip_tx_data_dec_ref(tdata);
      return PJ_TRUE;
    }

    // Calculate the address to forward the response
    pj_bzero(&res_addr, sizeof(res_addr));
    res_addr.dst_host.type = pjsip_transport_get_type_from_name(&hvia->transport);
    res_addr.dst_host.flag =
    pjsip_transport_get_flag_from_type(res_addr.dst_host.type);

    // Destination address is Via's received param
    res_addr.dst_host.addr.host = hvia->recvd_param;
    if (res_addr.dst_host.addr.host.slen == 0)
    {
      // Someone has messed up our Via header!
      res_addr.dst_host.addr.host = hvia->sent_by.host;
    }

    // Destination port is the rport
    if (hvia->rport_param != 0 && hvia->rport_param != -1)
    {
      res_addr.dst_host.addr.port = hvia->rport_param;
    }

    if (res_addr.dst_host.addr.port == 0)
    {
      // Ugh, original sender didn't put rport!
      // At best, can only send the response to the port in Via.
      res_addr.dst_host.addr.port = hvia->sent_by.port;
    }

    // We don't know the transaction, so be pessimistic and strip
    // everything.
    TrustBoundary::process_stateless_message(tdata);

    // Forward response
    status = pjsip_endpt_send_response(stack_data.endpt, &res_addr, tdata,
                                       NULL, NULL);
    if (status != PJ_SUCCESS)
    {
      TRC_ERROR("Error forwarding response, %s",
                PJUtils::pj_status_to_string(status).c_str());
      return PJ_TRUE;
    }
  }

  return PJ_TRUE;
}


// Callback to be called to handle transaction state changed.
static void tu_on_tsx_state(pjsip_transaction *tsx, pjsip_event *event)
{
  TRC_DEBUG("%s - tu_on_tsx_state %s, %s %s state=%s",
            tsx->obj_name,
            pjsip_role_name(tsx->role),
            pjsip_event_str(event->type),
            pjsip_event_str(event->body.tsx_state.type),
            pjsip_tsx_state_str(tsx->state));

  if (tsx->role == PJSIP_ROLE_UAS)
  {
    UASTransaction* uas_data = UASTransaction::get_from_tsx(tsx);
    if (uas_data != NULL)
    {
      uas_data->on_tsx_state(event);
    }
  }
  else
  {
    UACTransaction* uac_data = UACTransaction::get_from_tsx(tsx);
    if (uac_data != NULL)
    {
      uac_data->on_tsx_state(event);
    }
  }
}

///@}

///@{
// HIGH LEVEL PROCESSING

/// Process a received transaction request (that is, a non-CANCEL).
///
void process_tsx_request(pjsip_rx_data* rdata)
{
  pj_status_t status;
  pjsip_tx_data* tdata;
  UASTransaction* uas_data;
  ServingState serving_state;
  TrustBoundary* trust = &TrustBoundary::TRUSTED;
  Target *target = NULL;
  ACR* acr = NULL;
  ACR* downstream_acr = NULL;
  TrailFlusher trail_flusher(get_trail(rdata));

  // Verify incoming request.
  int status_code = proxy_verify_request(rdata);
  if (status_code != PJSIP_SC_OK)
  {
    reject_request(rdata, status_code);
    return;
  }

  // Request looks sane, so clone the request to create transmit data.
  tdata = PJUtils::clone_msg(stack_data.endpt, rdata);
  if (tdata == NULL)
  {
    TRC_ERROR("Failed to clone request to forward");
    reject_request(rdata, PJSIP_SC_INTERNAL_SERVER_ERROR);
    return;
  }

  assert(edge_proxy);
  // Process access proxy routing.  This also does IBCF function if enabled.
  status_code = proxy_process_access_routing(rdata, tdata, &trust, &target);
  if (status_code != PJSIP_SC_OK)
  {
    // Request failed routing checks, so reject it.
    reject_request(rdata, status_code);

    // Delete the request since we're not forwarding it
    pjsip_tx_data_dec_ref(tdata);
    delete target; target = NULL;
    return;
  }
  assert(target);

  acr = cscf_acr_factory->get_acr(get_trail(rdata),
                                  ACR::CALLING_PARTY,
                                  acr_node_role(rdata->msg_info.msg));
  acr->set_default_ccf(PJUtils::pj_str_to_string(&stack_data.cdf_domain));

  // Do standard processing of Route headers.
  status = proxy_process_routing(tdata);

  if (status != PJ_SUCCESS)
  {
    TRC_ERROR("Error processing route, %s",
              PJUtils::pj_status_to_string(status).c_str());

    delete target; target = NULL;
    delete acr; acr = NULL;
    delete downstream_acr; downstream_acr = NULL;
    return;
  }

  // Pass the received request to the ACR.
  acr->rx_request(rdata->msg_info.msg, rdata->pkt_info.timestamp);

  // We now know various details of this transaction:
  TRC_DEBUG("Trust mode %s, serving state %s",
            trust->to_string().c_str(),
            serving_state.to_string().c_str());

  // If this is an ACK request, forward statelessly.
  // This happens if the proxy records route and this ACK
  // is sent for 2xx response. An ACK that is sent for non-2xx
  // final response will be absorbed by transaction layer, and
  // it will not be received by on_rx_request() callback.
  if (tdata->msg->line.req.method.id == PJSIP_ACK_METHOD)
  {
    // Report a SIP call ID marker on the trail to make sure it gets
    // associated with the INVITE transaction at SAS.  There's no need to
    // report the branch IDs as they won't be used for correlation.
    TRC_DEBUG("Statelessly forwarding ACK");

    trust->process_request(tdata);

    // About to send the request to notify the ACR. Also, if we have a
    // downstream ACR, simulate it being received and sent by that ACR.
    acr->tx_request(tdata->msg);

    if (downstream_acr != NULL)
    {
      downstream_acr->rx_request(tdata->msg);
      downstream_acr->tx_request(tdata->msg);
    }

    if (target != NULL)
    {
      // Target has already been selected for the request, so set it up on the
      // request.
      tdata->msg->line.req.uri = target->uri;

      // If the target is routing to the upstream device (we're acting as an access
      // proxy), strip any extra loose routes on the message to prevent accidental
      // double routing.
      if (target->upstream_route)
      {
        TRC_DEBUG("Stripping loose routes from proxied message");

        // Tight loop to strip all route headers.
        while (pjsip_msg_find_remove_hdr(tdata->msg,
                                         PJSIP_H_ROUTE,
                                         NULL) != NULL)
        {
          // Tight loop.
        };
      }

      if (target->transport != NULL)
      {
        // The target includes a selected transport, so set it here.
        pjsip_tpselector tp_selector;
        tp_selector.type = PJSIP_TPSELECTOR_TRANSPORT;
        tp_selector.u.transport = target->transport;
        pjsip_tx_data_set_transport(tdata, &tp_selector);

        tdata->dest_info.addr.count = 1;
        tdata->dest_info.addr.entry[0].type =
                           (pjsip_transport_type_e)target->transport->key.type;
        pj_memcpy(&tdata->dest_info.addr.entry[0].addr,
                  &target->remote_addr,
                  sizeof(pj_sockaddr));
        tdata->dest_info.addr.entry[0].addr_len =
             (tdata->dest_info.addr.entry[0].addr.addr.sa_family == pj_AF_INET()) ?
             sizeof(pj_sockaddr_in) : sizeof(pj_sockaddr_in6);
        tdata->dest_info.cur_addr = 0;

        // Remove the reference to the transport added when it was chosen.
        pjsip_transport_dec_ref(target->transport);
      }
    }

    // Add a via header for ACKs (this is handled in init_uac_transactions
    // for other methods)
    PJUtils::add_top_via(tdata);

    status = PJUtils::send_request_stateless(tdata);

    if (status != PJ_SUCCESS)
    {
      TRC_ERROR("Error forwarding request, %s",
                PJUtils::pj_status_to_string(status).c_str());
    }

    // Send Rf messages and clean up the ACRs.
    acr->send();
    delete acr; acr = NULL;

    if (downstream_acr)
    {
      downstream_acr->send();
      delete downstream_acr; downstream_acr = NULL;
    }

    delete target; target = NULL;
    return;
  }

  // Create the transaction.  This implicitly enters its context, so we're
  // safe to operate on it (and have to exit its context below).
  status = UASTransaction::create(rdata, tdata, trust, acr, &uas_data);

  // The UAS transaction is responsible for flushing the trail when it is
  // terminated.
  trail_flusher.set_flush_required(false);

  if (status != PJ_SUCCESS)
  {
    TRC_ERROR("Failed to create UAS transaction, %s",
              PJUtils::pj_status_to_string(status).c_str());

    // Delete the request since we're not forwarding it
    pjsip_tx_data_dec_ref(tdata);
    reject_request(rdata, PJSIP_SC_INTERNAL_SERVER_ERROR);
    delete acr; acr = NULL;
    delete downstream_acr; downstream_acr = NULL;
    delete target; target = NULL;
    return;
  }

  // UASTrancation has taken ownership of the ACR.
  acr = NULL;

  assert(target);
  uas_data->access_proxy_handle_non_cancel(target);

  uas_data->exit_context();

  delete acr; acr = NULL;
  delete downstream_acr; downstream_acr = NULL;
}


/// Process a received CANCEL request
///
void process_cancel_request(pjsip_rx_data* rdata)
{
  pjsip_transaction *invite_uas;
  pj_str_t key;
  TrailFlusher trail_flusher(get_trail(rdata));

  // Find the UAS INVITE transaction
  pjsip_tsx_create_key(rdata->tp_info.pool, &key, PJSIP_UAS_ROLE,
                       pjsip_get_invite_method(), rdata);
  invite_uas = pjsip_tsx_layer_find_tsx(&key, PJ_TRUE);
  if (!invite_uas)
  {
    // Invite transaction not found, respond to CANCEL with 481
    reject_request(rdata, PJSIP_SC_CALL_TSX_DOES_NOT_EXIST);
    return;
  }

  assert(edge_proxy);
  if (!proxy_trusted_source(rdata))
  {
    // The CANCEL request has not come from a trusted source, so reject it
    // (can't challenge a CANCEL).
    reject_request(rdata, PJSIP_SC_FORBIDDEN);
    return;
  }

  // Respond 200 OK to CANCEL.  Must do this statefully.
  pjsip_transaction* tsx;
  pj_status_t status = pjsip_tsx_create_uas(NULL, rdata, &tsx);
  if (status != PJ_SUCCESS)
  {
    reject_request(rdata, PJSIP_SC_INTERNAL_SERVER_ERROR);
    return;
  }

  // Set the SAS trail on the CANCEL transaction so the response gets correlated
  set_trail(tsx, get_trail(rdata));

  // Feed the CANCEL request to the transaction.
  pjsip_tsx_recv_msg(tsx, rdata);

  // Send the 200 OK statefully.
  PJUtils::respond_stateful(stack_data.endpt, tsx, rdata, 200, NULL, NULL, NULL);

  // Send CANCEL to cancel the UAC transactions.
  // The UAS INVITE transaction will get final response when
  // we receive final response from the UAC INVITE transaction.
  TRC_DEBUG("%s - Cancel for UAS transaction", invite_uas->obj_name);
  UASTransaction *uas_data = UASTransaction::get_from_tsx(invite_uas);
  uas_data->cancel_pending_uac_tsx(0, false);

  // Create and send an ACR for the CANCEL request.
  ACR* acr = cscf_acr_factory->get_acr(get_trail(rdata),
                                       ACR::CALLING_PARTY,
                                       acr_node_role(rdata->msg_info.msg));
  acr->set_default_ccf(PJUtils::pj_str_to_string(&stack_data.cdf_domain));
  acr->rx_request(rdata->msg_info.msg, rdata->pkt_info.timestamp);
  acr->send();
  delete acr;

  // Unlock UAS tsx because it is locked in find_tsx()
  pj_grp_lock_release(invite_uas->grp_lock);
}


// Proxy utility to verify incoming requests.
// Return the SIP status code if verification failed.
static int proxy_verify_request(pjsip_rx_data *rdata)
{
  const pj_str_t STR_PROXY_REQUIRE = pj_str("Proxy-Require");

  // RFC 3261 Section 16.3 Request Validation

  // Before an element can proxy a request, it MUST verify the message's
  // validity.  A valid message must pass the following checks:
  //
  // 1. Reasonable Syntax
  // 2. URI scheme
  // 3. Max-Forwards
  // 4. (Optional) Loop Detection
  // 5. Proxy-Require
  // 6. Proxy-Authorization

  // 1. Reasonable Syntax.
  // This would have been checked by transport layer.

  // 2. URI scheme.
  // We support "sip:", "tel:" and "urn:" URI schemes in this simple proxy.
  if (!(PJSIP_URI_SCHEME_IS_SIP(rdata->msg_info.msg->line.req.uri) ||
        PJSIP_URI_SCHEME_IS_TEL(rdata->msg_info.msg->line.req.uri) ||
        PJSIP_URI_SCHEME_IS_URN(rdata->msg_info.msg->line.req.uri)))
  {
    return PJSIP_SC_UNSUPPORTED_URI_SCHEME;
  }

  // 3. Max-Forwards.
  // Send error if Max-Forwards is 1 or lower.
  if (rdata->msg_info.max_fwd && rdata->msg_info.max_fwd->ivalue <= 1)
  {
    return PJSIP_SC_TOO_MANY_HOPS;
  }

  // 4. (Optional) Loop Detection.
  // Nah, we don't do that with this simple proxy.

  // 5. Proxy-Require
  if (pjsip_msg_find_hdr_by_name(rdata->msg_info.msg, &STR_PROXY_REQUIRE,
                                 NULL) != NULL)
  {
    return PJSIP_SC_BAD_EXTENSION;
  }

  // 6. Proxy-Authorization.
  // Nah, we don't require any authorization with this sample.

  // Check that non-ACK request has not been received on a shutting down
  // transport.  If it has then we won't be able to send a transaction
  // response, so it is better to reject immediately.
  if ((rdata->msg_info.msg->line.req.method.id != PJSIP_ACK_METHOD) &&
      (rdata->tp_info.transport != NULL) &&
      (rdata->tp_info.transport->is_shutdown))
  {
    return PJSIP_SC_SERVICE_UNAVAILABLE;
  }

  return PJSIP_SC_OK;
}

/// Rejects a request statelessly.
static void reject_request(pjsip_rx_data* rdata, int status_code)
{
  // Log start and end markers. These are needed for the failed request to
  // appear in SAS.
  SAS::Marker start_marker(get_trail(rdata), MARKER_ID_START, 1u);
  SAS::report_marker(start_marker);
  SAS::Marker end_marker(get_trail(rdata), MARKER_ID_END, 1u);
  SAS::report_marker(end_marker);

  pj_status_t status;

  ACR* acr = cscf_acr_factory->get_acr(get_trail(rdata),
                                       ACR::CALLING_PARTY,
                                       acr_node_role(rdata->msg_info.msg));
  acr->set_default_ccf(PJUtils::pj_str_to_string(&stack_data.cdf_domain));
  acr->rx_request(rdata->msg_info.msg, rdata->pkt_info.timestamp);

  if (rdata->msg_info.msg->line.req.method.id != PJSIP_ACK_METHOD)
  {
    // Not an ACK, so we should send a response.
    TRC_INFO("Reject %.*s request with %d status code",
             rdata->msg_info.msg->line.req.method.name.slen,
             rdata->msg_info.msg->line.req.method.name.ptr, status_code);
    pjsip_tx_data* tdata;

    // Use default status text except for cases where PJSIP doesn't know
    // about the status code.
    const pj_str_t* status_text = NULL;
    if (status_code == SIP_STATUS_FLOW_FAILED)
    {
      status_text = &SIP_REASON_FLOW_FAILED;
    }

    status = PJUtils::create_response(stack_data.endpt, rdata, status_code, status_text, &tdata);
    if (status == PJ_SUCCESS)
    {
      // Pass the response to the ACR.
      acr->tx_response(tdata->msg);

      status = pjsip_endpt_send_response2(stack_data.endpt, rdata, tdata, NULL, NULL);
      if (status != PJ_SUCCESS)
      {
        // LCOV_EXCL_START
        pjsip_tx_data_dec_ref(tdata);
        // LCOV_EXCL_STOP
      }
    }
  }

  // Send the ACR and delete it.
  acr->send();
  delete acr;
}

static SIPPeerType determine_source(pjsip_transport* transport, pj_sockaddr addr)
{
  if (transport == NULL)
  {
    TRC_DEBUG("determine_source called with a NULL pjsip_transport");
    return SIP_PEER_UNKNOWN;
  }
  if (transport->local_name.port == stack_data.pcscf_trusted_port)
  {
    // Request received on trusted port.
    TRC_DEBUG("Request received on trusted port %d", transport->local_name.port);
    return SIP_PEER_TRUSTED_PORT;
  }

  TRC_DEBUG("Request received on non-trusted port %d", transport->local_name.port);

  // Request received on untrusted port, so see if it came over a trunk.
  if ((ibcf) &&
      (ibcf_trusted_peer(addr)))
  {
    TRC_DEBUG("Request received on configured SIP trunk");
    return SIP_PEER_CONFIGURED_TRUNK;
  }

  if (is_pbx(addr))
  {
    return SIP_PEER_NONREGISTERING_PBX;
  }

  return SIP_PEER_CLIENT;
}

/// Checks whether the request was received from a trusted source.
static pj_bool_t proxy_trusted_source(pjsip_rx_data* rdata)
{
  SIPPeerType source = determine_source(rdata->tp_info.transport, rdata->pkt_info.src_addr);
  pj_bool_t trusted = PJ_FALSE;

  if ((source == SIP_PEER_TRUSTED_PORT) ||
      (source == SIP_PEER_CONFIGURED_TRUNK))
  {
    trusted = PJ_TRUE;
  }
  else if (source == SIP_PEER_CLIENT)
  {
    Flow* src_flow = flow_table->find_flow(rdata->tp_info.transport,
                                           &rdata->pkt_info.src_addr);
    if (src_flow != NULL)
    {
      // Request received on a known flow, so check it is
      // authenticated.
      pjsip_from_hdr *from_hdr = PJSIP_MSG_FROM_HDR(rdata->msg_info.msg);
      if (src_flow->asserted_identity((pjsip_uri*)pjsip_uri_get_uri(from_hdr->uri)).length() > 0)
      {
        TRC_DEBUG("Request received on authenticated client flow.");
        trusted = PJ_TRUE;
      }
      src_flow->dec_ref();
    }
  }
  return trusted;
}

/// Checks for double Record-Routing and removes superfluous Route header to
/// avoid request spirals.
void proxy_handle_double_rr(pjsip_tx_data* tdata)
{
  pjsip_route_hdr* r1 = NULL;
  pjsip_route_hdr* r2 = NULL;

  if ((PJUtils::is_top_route_local(tdata->msg, &r1)) &&
      (PJUtils::is_next_route_local(tdata->msg, r1, &r2)))
  {
    // The top two Route headers were both added by this node, so check for
    // different transports or ports.  We don't act on all Route header pairs
    // that look like a spiral, only ones that look like the result of
    // double Record-Routing, and we only do that if the transport and/or port
    // are different.
    TRC_DEBUG("Top two route headers added by this node, checking transports and ports");
    pjsip_sip_uri* uri1 = (pjsip_sip_uri*)r1->name_addr.uri;
    pjsip_sip_uri* uri2 = (pjsip_sip_uri*)r2->name_addr.uri;
    if ((uri1->port != uri2->port) ||
        (pj_stricmp(&uri1->transport_param, &uri2->transport_param) != 0))
    {
      // Possible double record routing.  If one of the route headers doesn't
      // have a flow token it can safely be removed.
      TRC_DEBUG("Host names are the same and transports are different");
      if (uri1->user.slen == 0)
      {
        TRC_DEBUG("Remove top route header");
        pj_list_erase(r1);
      }
      else if (uri2->user.slen == 0)
      {
        TRC_DEBUG("Remove second route header");
        pj_list_erase(r2);
      }
    }
  }
}


/// Find and remove P-Preferred-Identity headers from the message.
static void extract_preferred_identities(pjsip_tx_data* tdata, std::vector<pjsip_uri*>& identities)
{
  pjsip_routing_hdr* p_preferred_id;
  p_preferred_id = (pjsip_routing_hdr*)
                       pjsip_msg_find_hdr_by_name(tdata->msg,
                                                  &STR_P_PREFERRED_IDENTITY,
                                                  NULL);

  while (p_preferred_id != NULL)
  {
    identities.push_back((pjsip_uri*)&p_preferred_id->name_addr);

    void* next_hdr = p_preferred_id->next;

    pj_list_erase(p_preferred_id);

    p_preferred_id = (pjsip_routing_hdr*)pjsip_msg_find_hdr_by_name(tdata->msg, &STR_P_PREFERRED_IDENTITY, next_hdr);
  }
}


/// Create a simple target routing the call to Sprout.
static void proxy_route_upstream(pjsip_rx_data* rdata,
                                 pjsip_tx_data* tdata,
                                 Flow* src_flow,
                                 TrustBoundary **trust,
                                 Target** target,
                                 const std::string& configured_service_route = "")
{
  // Forward it to the upstream proxy to deal with.  We do this by creating
  // a target with the existing request URI and a path to the upstream
  // proxy and stripping any loose routes that might have been added by the
  // UA.
  *target = new Target();
  Target* target_p = *target;
  target_p->upstream_route = PJ_TRUE;
  URIClass uri_class = URIClassifier::classify_uri(tdata->msg->line.req.uri);

  // Some trunks will send incoming requests directed at the IBCF node,
  // rather than determining the correct domain for the subscriber first.
  // In this case, we'll re-write the ReqURI to the default home domain.
  if ((*trust == &TrustBoundary::INBOUND_TRUNK) &&
      uri_class == NODE_LOCAL_SIP_URI)
  {
    // Change host/domain in target to use default home domain.
    target_p->uri = (pjsip_uri*)pjsip_uri_clone(tdata->pool,
                                                tdata->msg->line.req.uri);
    ((pjsip_sip_uri*)target_p->uri)->host = stack_data.default_home_domain;
  }
  else
  {
    // Use request URI unchanged.
    target_p->uri = (pjsip_uri*)tdata->msg->line.req.uri;
  }

  std::string service_route = configured_service_route;

  if ((service_route == "") && (src_flow != NULL))
  {
    // See if we have a service route for the served user of the request.
    TRC_DEBUG("Request received on authentication flow - check for Service-Route");
    pjsip_uri* served_user = PJUtils::orig_served_user(tdata->msg, tdata->pool, 0);
    if (served_user != NULL)
    {
      std::string user = PJUtils::public_id_from_uri(served_user);
      service_route = src_flow->service_route(user);
      TRC_VERBOSE("Found Service-Route for served user %s - %s",
                  user.c_str(), service_route.c_str());
    }
  }

  pjsip_sip_uri* upstream_uri;

  if (service_route != "")
  {
    // We have a service route, so add it as a Route header.
    upstream_uri = (pjsip_sip_uri*)PJUtils::uri_from_string(service_route, tdata->pool, false);
  }
  else
  {
    // Route to default upstream proxy.
    upstream_uri = (pjsip_sip_uri*)pjsip_uri_clone(tdata->pool, upstream_proxy);

    // Maybe mark it as originating, so Sprout knows to
    // apply originating handling.
    //
    // In theory, on the access side, the UE ought to have
    // done this itself - see 3GPP TS 24.229 s5.1.1.2.1 200-OK d and
    // s5.1.2A.1.1 "The UE shall build a proper preloaded Route header"
    //
    // When working on the IBCF side, the provided route will not have
    // orig set, so we won't set in on the route upstream ether.
    //
    // When working as a load-balancer for a third-party P-CSCF, trust the
    // orig parameter of the top-most Route header.
    pjsip_param* orig_param = NULL;
    pjsip_routing_hdr* route_hdr;

    // Check the rdata here, as the Route header may have been stripped
    // from the cloned tdata.
    if (PJUtils::is_top_route_local(rdata->msg_info.msg, &route_hdr))
    {
      pjsip_sip_uri* uri = (pjsip_sip_uri*)route_hdr->name_addr.uri;
      orig_param = pjsip_param_find(&uri->other_param, &STR_ORIG);
    }

    if (orig_param ||
        (*trust == &TrustBoundary::INBOUND_EDGE_CLIENT))
    {
      TRC_DEBUG("Mark originating");
      pjsip_param *orig_param = PJ_POOL_ALLOC_T(tdata->pool, pjsip_param);
      pj_strdup(tdata->pool, &orig_param->name, &STR_ORIG);
      pj_strdup2(tdata->pool, &orig_param->value, "");
      pj_list_insert_after(&upstream_uri->other_param, orig_param);
    }

    // Select a transport for the request.
    if (upstream_conn_pool != NULL)
    {
      target_p->transport = upstream_conn_pool->get_connection();
      if (target_p->transport != NULL)
      {
        pj_memcpy(&target_p->remote_addr,
                  &target_p->transport->key.rem_addr,
                  sizeof(pj_sockaddr));
      }
    }
  }

  TRC_INFO("Route request to upstream proxy %s",
           PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR, (pjsip_uri*)upstream_uri).c_str());

  pjsip_route_hdr* hdr = pjsip_route_hdr_create(tdata->pool);
  hdr->name_addr.uri = (pjsip_uri*)upstream_uri;
  target_p->paths.push_back(hdr);
}


/// Perform access-proxy-specific routing.
#ifndef UNIT_TEST
static
#endif
int proxy_process_access_routing(pjsip_rx_data *rdata,
                                 pjsip_tx_data *tdata,
                                 TrustBoundary **trust,
                                 Target **target)
{
  pj_status_t status;
  Flow* src_flow = NULL;
  Flow* tgt_flow = NULL;
  SIPPeerType source_type = determine_source(rdata->tp_info.transport,
                                             rdata->pkt_info.src_addr);
  TRC_DEBUG("Perform access proxy routing for %.*s request",
            tdata->msg->line.req.method.name.slen, tdata->msg->line.req.method.name.ptr);

  if (tdata->msg->line.req.method.id == PJSIP_REGISTER_METHOD)
  {
    bool is_emergency_reg = false;

    pjsip_contact_hdr* contact_hdr = (pjsip_contact_hdr*)
                  pjsip_msg_find_hdr(tdata->msg, PJSIP_H_CONTACT, NULL);

    while ((contact_hdr != NULL) && (!is_emergency_reg))
    {
      is_emergency_reg = PJUtils::is_emergency_registration(contact_hdr);
      contact_hdr = (pjsip_contact_hdr*) pjsip_msg_find_hdr(tdata->msg,
                                                            PJSIP_H_CONTACT,
                                                            contact_hdr->next);
    }

    if (!allow_emergency_reg && is_emergency_reg)
    {
      TRC_DEBUG("Rejecting emergency REGISTER request");
      return PJSIP_SC_SERVICE_UNAVAILABLE;
    }

    if (source_type == SIP_PEER_TRUSTED_PORT)
    {
      TRC_WARNING("Rejecting REGISTER request received from within the trust domain");
      return PJSIP_SC_METHOD_NOT_ALLOWED;
    }

    if (source_type == SIP_PEER_CONFIGURED_TRUNK)
    {
      TRC_WARNING("Rejecting REGISTER request received over SIP trunk");
      return PJSIP_SC_METHOD_NOT_ALLOWED;
    }

    // The REGISTER came from outside the trust domain and not over a SIP
    // trunk, so we must act as the access proxy for the node.
    TRC_DEBUG("Message requires outbound support");

    // Find or create a flow object to represent this flow.
    src_flow = flow_table->find_create_flow(rdata->tp_info.transport,
                                              &rdata->pkt_info.src_addr);

    if (src_flow == NULL)
    {
      TRC_ERROR("Failed to create flow data record");
      return PJSIP_SC_INTERNAL_SERVER_ERROR; // LCOV_EXCL_LINE find_create_flow failure cases are all excluded already
    }

    TRC_DEBUG("Found or created flow data record, token = %s", src_flow->token().c_str());

    // Reject the REGISTER with a 305 if Bono is trying to quiesce and
    // there are no active dialogs on this flow.
    if (src_flow->should_quiesce())
    {
      TRC_DEBUG("REGISTER request received on a quiescing flow - responding with 305");
      src_flow->dec_ref();
      return PJSIP_SC_USE_PROXY;
    }

    // Touch the flow to make sure it doesn't time out while we are waiting
    // for the REGISTER response from upstream.
    src_flow->touch();

    pjsip_to_hdr *to_hdr = PJSIP_MSG_TO_HDR(rdata->msg_info.msg);
    if (!src_flow->asserted_identity((pjsip_uri*)pjsip_uri_get_uri(to_hdr->uri)).empty())
    {
      // The message was received on a client flow that has already been
      // authenticated, so add "integrity-protected=ip-assoc-yes" to flag this
      // to the S-CSCF.
      PJUtils::add_integrity_protected_indication(tdata,
                                                  PJUtils::Integrity::IP_ASSOC_YES);
    }
    else
    {
      // The message wasn't received on an authenticated client flow.  Add
      // "integrity-protected=ip-assoc-pending" if the request contains a
      // response to a challenge, otherwise don't add an integrity protected
      // indicator at all (adding "integrity-protected=no" would be interpreted
      // by the S-CSCF as a request to use AKA authentication).
      pjsip_authorization_hdr* auth_hdr = (pjsip_authorization_hdr*)
               pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_AUTHORIZATION, NULL);

      if ((auth_hdr != NULL) &&
          (auth_hdr->credential.digest.response.slen != 0))
      {
        PJUtils::add_integrity_protected_indication(tdata,
                                                    PJUtils::Integrity::IP_ASSOC_PENDING);
      }
    }

    PJUtils::add_pvni(tdata, &stack_data.default_home_domain);

    // Add a path header so we get included in the egress call flow.  If we're not
    // acting as access proxy, we'll add the bono cluster instead.
    status = add_path(tdata, src_flow, rdata);
    if (status != PJ_SUCCESS)
    {
      if (src_flow)
      {
        src_flow->dec_ref();
      }
      return status; // LCOV_EXCL_LINE No failure cases exist.
    }

    if (src_flow)
    {
      // Remove the reference to the source flow since we have finished with it.
      src_flow->dec_ref();
    }

    // Message from client. Allow client to provide data, but don't let it discover internal data.
    *trust = &TrustBoundary::INBOUND_EDGE_CLIENT;

    // Until we support routing, all REGISTER requests should be sent to the upstream sprout
    // for processing.
    proxy_route_upstream(rdata, tdata, NULL, trust, target);

    // Do standard route header processing for the request.  This may
    // remove the top route header if it corresponds to this node.
    proxy_process_routing(tdata);
  }
  else
  {
    // Check for double Record-Routing and remove extra Route header.
    proxy_handle_double_rr(tdata);

    // Work out whether the message has come from an implicitly trusted
    // source (that is, from within the trust zone, or over a known SIP
    // trunk), or a source we can now trust because it has been authenticated
    // (that is, a client flow).
    bool trusted = false;

    if (source_type != SIP_PEER_TRUSTED_PORT)
    {
      // Message received on untrusted port, so see if it came over a trunk
      // or on a known client flow.
      TRC_DEBUG("Message received on non-trusted port %d", rdata->tp_info.transport->local_name.port);
      if (source_type == SIP_PEER_CONFIGURED_TRUNK)
      {
        TRC_DEBUG("Message received on configured SIP trunk");
        trusted = true;
        *trust = &TrustBoundary::INBOUND_TRUNK;

        pjsip_route_hdr* route_hdr;
        if ((PJUtils::is_top_route_local(tdata->msg, &route_hdr)) &&
            (pjsip_param_find(&(((pjsip_sip_uri*)route_hdr->name_addr.uri)->other_param), &STR_ORIG)))
        {
          // Topmost route header points to us/Sprout and requests originating
          // handling, but this is not a known client. This is forbidden.
          //
          // This covers 3GPP TS 24.229 s5.10.3.2, except that we
          // implement a whitelist (only known Bono clients can pass this)
          // rather than a blacklist (IBCF clients are forbidden).
          //
          // All connections to our IBCF are untrusted (we don't implement
          // any trusted ones) in the sense of s5.10.3.2, so this always
          // applies and we never implement the step 4 and 5 behaviour of
          // copying the ;orig parameter to the outgoing Route.
          //
          // We are slightly overloading TrustBoundary here - how to
          // improve this is FFS.
          TRC_WARNING("Request for originating handling but not from known client");
          return PJSIP_SC_FORBIDDEN;
        }
      }
      else if (source_type == SIP_PEER_NONREGISTERING_PBX)
      {
        TRC_DEBUG("Message received on configured SIP nonregistering PBX");
        trusted = true;
        *trust = &TrustBoundary::INBOUND_EDGE_CLIENT;

        bool initial_request = (rdata->msg_info.to->tag.slen == 0);
        if (initial_request)
        {
          // Initial requests (ones without a To tag) always go upstream
          // to Sprout
          TRC_DEBUG("Routing initial request from PBX to upstream Sprout");
          PJUtils::add_proxy_auth_for_pbx(tdata);
          proxy_route_upstream(rdata, tdata, NULL, trust, target, pbx_service_route);
        }
      }
      else
      {
        src_flow = flow_table->find_flow(rdata->tp_info.transport,
                                         &rdata->pkt_info.src_addr);
        if (src_flow != NULL)
        {
          // Message on a known client flow.
          TRC_DEBUG("Message received on known client flow");

          // Get all the preferred identities from the message and remove
          // the P-Preferred-Identity headers.
          std::vector<pjsip_uri*> identities;
          extract_preferred_identities(tdata, identities);

          if (identities.size() > 2)
          {
            // Cannot have more than two preferred identities.
            TRC_DEBUG("Request has more than two P-Preferred-Identitys, rejecting");
            src_flow->dec_ref();
            return PJSIP_SC_FORBIDDEN;
          }
          else if (identities.size() == 0)
          {
            // No identities specified, so check there is valid default identity
            // and use it for the P-Asserted-Identity.
            TRC_DEBUG("Request has no P-Preferred-Identity headers, so check for default identity on flow");
            std::string aid = src_flow->default_identity();

            if (aid.length() > 0)
            {
              *trust = &TrustBoundary::INBOUND_EDGE_CLIENT;
              trusted = true;
              PJUtils::add_asserted_identity(tdata, aid);
            }
          }
          else if (identities.size() == 1)
          {
            // Only one preferred identity specified.
            TRC_DEBUG("Request has one P-Preferred-Identity");
            if ((!PJSIP_URI_SCHEME_IS_SIP(identities[0])) &&
                (!PJSIP_URI_SCHEME_IS_TEL(identities[0])))
            {
              // Preferred identity must be sip, sips or tel URI.
              TRC_DEBUG("Invalid URI scheme in P-Preferred-Identity, rejecting");
              src_flow->dec_ref();
              return PJSIP_SC_FORBIDDEN;
            }

            // Check the preferred identity is authorized and get the corresponding
            // asserted identity.
            std::string aid = src_flow->asserted_identity(identities[0]);

            if (aid.length() > 0)
            {
              *trust = &TrustBoundary::INBOUND_EDGE_CLIENT;
              trusted = true;
              PJUtils::add_asserted_identity(tdata, aid);
            }
          }
          else if (identities.size() == 2)
          {
            // Two preferred identities specified.
            TRC_DEBUG("Request has two P-Preferred-Identitys");
            if (!(((PJSIP_URI_SCHEME_IS_SIP(identities[0])) &&
                   (PJSIP_URI_SCHEME_IS_TEL(identities[1]))) ||
                  ((PJSIP_URI_SCHEME_IS_TEL(identities[0])) &&
                   (PJSIP_URI_SCHEME_IS_SIP(identities[1])))))
            {
              // One identity must be sip or sips URI and the other must be
              // tel URI
              TRC_DEBUG("Invalid combination of URI schemes in P-Preferred-Identitys, rejecting");
              src_flow->dec_ref();
              return PJSIP_SC_FORBIDDEN;
            }

            // Check both preferred identities are authorized and get the
            // corresponding asserted identities.
            std::string aid1 = src_flow->asserted_identity(identities[0]);
            std::string aid2 = src_flow->asserted_identity(identities[1]);

            if ((aid1.length() > 0) && (aid2.length() > 0))
            {
              *trust = &TrustBoundary::INBOUND_EDGE_CLIENT;
              trusted = true;
              PJUtils::add_asserted_identity(tdata, aid1);
              PJUtils::add_asserted_identity(tdata, aid2);
            }
          }

          bool initial_request = (rdata->msg_info.to->tag.slen == 0);
          if (initial_request)
          {
            // Initial requests (ones without a To tag) always go upstream
            // to Sprout
            TRC_DEBUG("Routing initial request from client to upstream Sprout");
            proxy_route_upstream(rdata, tdata, src_flow, trust, target);
          }
        }
      }
    }
    else
    {
      // Message received on a trusted port.
      TRC_DEBUG("Message received on trusted port");
      trusted = true;

      // See if the message is destined for a client.
      pjsip_route_hdr* route_hdr;
      if ((PJUtils::is_top_route_local(tdata->msg, &route_hdr)) &&
          (((pjsip_sip_uri*)route_hdr->name_addr.uri)->user.slen > 0))
      {
        // The user part is present, it should hold our token, so validate the
        // token.
        pjsip_sip_uri* sip_path_uri = (pjsip_sip_uri*)route_hdr->name_addr.uri;
        TRC_DEBUG("Flow identifier in Route header = %.*s", sip_path_uri->user.slen, sip_path_uri->user.ptr);
        tgt_flow = flow_table->find_flow(PJUtils::pj_str_to_string(&sip_path_uri->user));

        if (tgt_flow == NULL)
        {
          // We couldn't find the flow referenced in the
          // flow token, tell upstream that the flow failed.
          // Note: RFC 5626 specs that we should send a FORBIDDEN
          // if the token was invalid (as opposed to for a flow
          // that we don't have).  The authentication module
          // should handle that.
          TRC_ERROR("Route header flow identifier failed to correlate");
          return SIP_STATUS_FLOW_FAILED;
        }

        // This must be a request for a client, so make sure it is routed
        // over the appropriate flow.
        TRC_DEBUG("Inbound request for client with flow identifier in Route header");
        *target = new Target();
        (*target)->uri = (pjsip_uri*)pjsip_uri_clone(tdata->pool, tdata->msg->line.req.uri);
        (*target)->transport = tgt_flow->transport();
        pj_memcpy(&((*target)->remote_addr), tgt_flow->remote_addr(), sizeof(pj_sockaddr));
        pjsip_transport_add_ref((*target)->transport);

        *trust = &TrustBoundary::OUTBOUND_EDGE_CLIENT;
      }
    }

    if (!trusted)
    {
      // Request is not from a trusted source, so reject or discard it.
      TRC_INFO("Rejecting request from untrusted source");
      if (src_flow != NULL)
      {
        src_flow->dec_ref();
      }
      return PJSIP_SC_FORBIDDEN;
    }

    // Do standard route header processing for the request.  This may
    // remove the top route header if it corresponds to this node.
    proxy_process_routing(tdata);

    if (*target == NULL)
    {
      TRC_DEBUG("No target found yet");

      // Check if we have any Route headers.  If so, we'll follow them.  If not,
      // we get to choose where to route to, so route upstream to sprout.
      void* top_route = pjsip_msg_find_hdr(tdata->msg, PJSIP_H_ROUTE, NULL);
      URIClass uri_class = URIClassifier::classify_uri(tdata->msg->line.req.uri);
      if ((top_route == NULL) &&
          (uri_class != OFFNET_SIP_URI))
      {
        // Route the request upstream to Sprout.
        proxy_route_upstream(rdata, tdata, src_flow, trust, target);
      }
      else
      {
        // We have a Route header, or this is not local (e.g. if we're an IBCF) so follow standard SIP routing
        *target = new Target();
        (*target)->uri = (pjsip_uri*)pjsip_uri_clone(tdata->pool, tdata->msg->line.req.uri);
      }

      // Work out the next hop target for the message.  This will either be the
      // URI in the top route header, or the request URI.
      pjsip_uri* next_hop = PJUtils::next_hop(tdata->msg);

      if ((ibcf) &&
          (tgt_flow == NULL) &&
          (PJSIP_URI_SCHEME_IS_SIP(next_hop)))
      {

        // Check if the message is destined for a SIP trunk
        TRC_DEBUG("Check whether destination %.*s is a SIP trunk",
                  ((pjsip_sip_uri*)next_hop)->host.slen, ((pjsip_sip_uri*)next_hop)->host.ptr);
        pj_sockaddr dest;
        if (pj_sockaddr_parse(pj_AF_UNSPEC(), 0, &((pjsip_sip_uri*)next_hop)->host, &dest) == PJ_SUCCESS)
        {
          // Target host name is an IP address, so check against the IBCF trusted
          // peers.
          TRC_DEBUG("Parsed destination as an IP address, so check against trusted peers list");
          if (ibcf_trusted_peer(dest))
          {
            TRC_DEBUG("Destination is a SIP trunk");
            *trust = &TrustBoundary::OUTBOUND_TRUNK;
          }
          else
          {
            // Also check against the PBX peers.
            TRC_DEBUG("Parsed destination as an IP address, and not a trusted peer, so check against PBX list");
            if (is_pbx(dest))
            {
              TRC_DEBUG("Destination is a SIP PBX");
              *trust = &TrustBoundary::OUTBOUND_EDGE_CLIENT;
            }
          }
        }
      }
    }

    // Add suitable Record-Route header(s).
    TRC_DEBUG("Add record route header(s)");
    if (src_flow != NULL)
    {
      // Message is from a client, so add separate Record-Route headers for
      // the ingress and egress hops.
      TRC_DEBUG("Message received from client - double Record-Route");
      PJUtils::add_record_route(tdata, src_flow->transport()->type_name, src_flow->transport()->local_name.port, src_flow->token().c_str(), stack_data.public_host);
      PJUtils::add_record_route(tdata, "TCP", stack_data.pcscf_trusted_port, NULL, stack_data.local_host);
    }
    else if (tgt_flow != NULL)
    {
      // Message is destined for a client, so add separate Record-Route headers
      // for the ingress and egress hops.
      TRC_DEBUG("Message destined for client - double Record-Route");
      PJUtils::add_record_route(tdata, "TCP", stack_data.pcscf_trusted_port, NULL, stack_data.local_host);
      PJUtils::add_record_route(tdata, tgt_flow->transport()->type_name, tgt_flow->transport()->local_name.port, tgt_flow->token().c_str(), stack_data.public_host);
    }
    else if (((ibcf) && (*trust == &TrustBoundary::INBOUND_TRUNK)) ||
             (*trust == &TrustBoundary::INBOUND_EDGE_CLIENT))
    {
      // Received message on a trunk, so add separate Record-Route headers for
      // the ingress and egress hops.
      PJUtils::add_record_route(tdata, rdata->tp_info.transport->type_name, rdata->tp_info.transport->local_name.port, NULL, stack_data.public_host);
      PJUtils::add_record_route(tdata, "TCP", stack_data.pcscf_trusted_port, NULL, stack_data.local_host);
    }
    else if (((ibcf) && (*trust == &TrustBoundary::OUTBOUND_TRUNK)) ||
             (*trust == &TrustBoundary::OUTBOUND_EDGE_CLIENT))
    {
      // Message destined for trunk, so add separate Record-Route headers for
      // the ingress and egress hops.
      PJUtils::add_record_route(tdata, "TCP", stack_data.pcscf_trusted_port, NULL, stack_data.local_host);
      PJUtils::add_record_route(tdata, "TCP", stack_data.pcscf_untrusted_port, NULL, stack_data.public_host);   // @TODO - transport type?
    }

    // Decrement references on flows as we have finished with them.
    if (tgt_flow != NULL)
    {
      tgt_flow->dec_ref();
    }

    if (src_flow != NULL)
    {
      src_flow->dec_ref();
    }
  }

  return PJSIP_SC_OK;
}


/// Determine whether a source or destination IP address corresponds to
/// a configured trusted PBX.  "Trusted" here simply means that it's
/// known, not that we trust any headers it sets.
static bool is_pbx(const pj_sockaddr& addr)
{
  // Check whether the source IP address of the message is in the list of
  // trusted hosts.  Zero out the source port before doing the search.
  pj_sockaddr sockaddr;
  pj_sockaddr_cp(&sockaddr, &addr);
  pj_sockaddr_set_port(&sockaddr, 0);
  PJUtils::host_list_t::const_iterator i = pbx_hosts.find(sockaddr);

  return (i != pbx_hosts.end());
}


/// Determine whether a source or destination IP address corresponds to
/// a configured trusted peer.  "Trusted" here simply means that it's
/// known, not that we trust any headers it sets.
static bool ibcf_trusted_peer(const pj_sockaddr& addr)
{
  // Check whether the source IP address of the message is in the list of
  // trusted hosts.  Zero out the source port before doing the search.
  pj_sockaddr sockaddr;
  pj_sockaddr_cp(&sockaddr, &addr);
  pj_sockaddr_set_port(&sockaddr, 0);
  PJUtils::host_list_t::const_iterator i = trusted_hosts.find(sockaddr);

  return (i != trusted_hosts.end());
}


// Process route information in the request
static pj_status_t proxy_process_routing(pjsip_tx_data *tdata)
{
  pjsip_uri *target;
  pjsip_route_hdr *hroute;

  // RFC 3261 Section 16.4 Route Information Preprocessing

  target = tdata->msg->line.req.uri;
  URIClass uri_class = URIClassifier::classify_uri(target);

  // The proxy MUST inspect the Request-URI of the request.  If the
  // Request-URI of the request contains a value this proxy previously
  // placed into a Record-Route header field (see Section 16.6 item 4),
  // the proxy MUST replace the Request-URI in the request with the last
  // value from the Route header field, and remove that value from the
  // Route header field.  The proxy MUST then proceed as if it received
  // this modified request.
  if (uri_class == NODE_LOCAL_SIP_URI)
  {
    pjsip_route_hdr *r;
    pjsip_sip_uri *uri;

    // Find the first Route header
    r = hroute = (pjsip_route_hdr*)pjsip_msg_find_hdr(tdata->msg, PJSIP_H_ROUTE, NULL);
    if (r == NULL)
    {
      // No Route header. This request is destined for this proxy.
      return PJ_SUCCESS;
    }

    // Find the last Route header
    while ( (r=(pjsip_route_hdr*)pjsip_msg_find_hdr(tdata->msg,
                                                    PJSIP_H_ROUTE,
                                                    r->next)) != NULL )
    {
      hroute = r;
    }

    // If the last Route header doesn't have ";lr" parameter, then
    // this is a strict-routed request indeed, and we follow the steps
    // in processing strict-route requests above.
    //
    // But if it does contain ";lr" parameter, skip the strict-route
    // processing.
    uri = (pjsip_sip_uri*)pjsip_uri_get_uri(&hroute->name_addr);
    if (uri->lr_param == 0)
    {
      // Yes this is strict route, so:
      // - replace req URI with the URI in Route header,
      // - remove the Route header,
      // - proceed as if it received this modified request.
      tdata->msg->line.req.uri = hroute->name_addr.uri;
      pj_list_erase(hroute);
    }
  }

  // maddr handling for source routing is considered deprecated, so we don't
  // support it.  (See RFC 3261/19.1.1 - recommendation is to use Route headers
  // if requests must traverse a fixed set of proxies.)

  // If the first value in the Route header field indicates this proxy or
  // home domain, the proxy MUST remove that value from the request.
  // We remove consecutive Route headers that point to us so we don't spiral.'
  if (PJUtils::is_top_route_local(tdata->msg, &hroute))
  {
    TRC_DEBUG("Top Route header is local - erasing");
    pj_list_erase(hroute);
  }

  return PJ_SUCCESS;
}

/// For a given message, calculate the role the message is requesting the
/// node carry out.
static ACR::NodeRole acr_node_role(pjsip_msg *req)
{
  ACR::NodeRole role;

  // Determine whether this an originating or terminating request by looking for
  // the `orig` parameter in the top route header.  REGISTERs, are neither, but
  // originating makes most sense as they only correspond to the user that
  // generates them.
  pjsip_route_hdr* route_hdr = (pjsip_route_hdr*)
                                   pjsip_msg_find_hdr(req, PJSIP_H_ROUTE, NULL);

  if ((route_hdr != NULL) &&
      (pjsip_param_find(&((pjsip_sip_uri*)route_hdr->name_addr.uri)->other_param,
                        &STR_ORIG) != NULL))
  {
    role = ACR::NODE_ROLE_ORIGINATING;
  }
  else if (req->line.req.method.id == PJSIP_REGISTER_METHOD)
  {
    role = ACR::NODE_ROLE_ORIGINATING;
  }
  else
  {
    role = ACR::NODE_ROLE_TERMINATING;
  }

  return role;
}

///@}

void UASTransaction::cancel_trying_timer()
{
  pthread_mutex_lock(&_trying_timer_lock);

  if (_trying_timer.id == TRYING_TIMER)
  {
    // The deferred trying timer is running, so cancel it.
    _trying_timer.id = 0;
    pjsip_endpt_cancel_timer(stack_data.endpt, &_trying_timer);
  }

  pthread_mutex_unlock(&_trying_timer_lock);
}

///@{
// IN-TRANSACTION PROCESSING

static void proxy_process_register_response(pjsip_rx_data* rdata)
{
  // Check to see if the REGISTER response contains a Path header.  If so
  // this is a signal that the registrar accepted the REGISTER and so
  // authenticated the client.
  pjsip_routing_hdr* path_hdr = (pjsip_routing_hdr*)
              pjsip_msg_find_hdr_by_name(rdata->msg_info.msg, &STR_PATH, NULL);
  if (path_hdr != NULL)
  {
    // The response has a Path header in it, so extract the URI so we can
    // check for a flow token.
    pjsip_sip_uri* path_uri = (pjsip_sip_uri*)path_hdr->name_addr.uri;

    if ((path_uri != NULL) &&
        (path_uri->user.slen > 0))
    {
      // The Path header has a flow token, so see if this maps to a known
      // active flow.
      std::string flow_token = PJUtils::pj_str_to_string(&path_uri->user);
      Flow* flow_data = flow_table->find_flow(flow_token);

      if (flow_data != NULL)
      {
        // The response correlates to an active flow.  Check the contact
        // headers and expiry header to find when the last contacts will
        // expire.
        //
        // If a binding does not specify an expiry time then assume it expires
        // in 5 minutes (300s).  This should never happens as it means the
        // registrar is misbehaving, but we defensively assume a short expiry
        // time as this is more secure.
        int max_expires;
        PJUtils::get_max_expires(rdata->msg_info.msg, 300, max_expires);
        TRC_DEBUG("Maximum contact expiry is %d", max_expires);

        // Find the Service-Route header so we can record this with each
        // authorized identity.
        std::string service_route;
        pjsip_route_hdr* h_sr = (pjsip_route_hdr*)
                               pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                          &STR_SERVICE_ROUTE,
                                                          NULL);

        if (h_sr != NULL)
        {
          service_route = PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                                 h_sr->name_addr.uri);
        }

        // Go through the list of URIs covered by this registration setting
        // them on the flow.  This is either the list in the P-Associated-URI
        // header, if supplied, or the URI in the To header.
        pjsip_route_hdr* p_assoc_uri = (pjsip_route_hdr*)
                             pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                        &STR_P_ASSOCIATED_URI,
                                                        NULL);
        if (p_assoc_uri != NULL)
        {
          // Use P-Associated-URIs list as list of authenticated URIs.
          TRC_DEBUG("Found P-Associated-URI header");
          bool is_default = true;
          while (p_assoc_uri != NULL)
          {
            flow_data->set_identity((pjsip_uri*)&p_assoc_uri->name_addr,
                                    service_route,
                                    is_default,
                                    max_expires);
            p_assoc_uri = (pjsip_route_hdr*)
                              pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                         &STR_P_ASSOCIATED_URI,
                                                         p_assoc_uri->next);
            is_default = false;
          }
        }
        else
        {
          // Use URI in To header as authenticated URIs.
          TRC_DEBUG("No P-Associated-URI, use URI in To header.");
          flow_data->set_identity(PJSIP_MSG_TO_HDR(rdata->msg_info.msg)->uri,
                                  service_route,
                                  true,
                                  max_expires);
        }

        // Decrement the reference to the flow data
        flow_data->dec_ref();
      }
      else
      {
        // Failed to correlate the token in the Path header to an active flow.
        // This can happen if, for example, the connection to the client
        // failed, but it is unusual, so log at info level rather than as an
        // error or warning.
        TRC_INFO("Failed to correlate REGISTER response Path token %s to a flow", flow_token.c_str());
      }
    }
  }
}

///@}

// UAS Transaction constructor
UASTransaction::UASTransaction(pjsip_transaction* tsx,
                               pjsip_rx_data* rdata,
                               pjsip_tx_data* tdata,
                               TrustBoundary* trust,
                               ACR* acr) :
  _tsx(tsx),
  _num_targets(0),
  _pending_targets(0),
  _ringing(PJ_FALSE),
  _req(tdata),
  _best_rsp(NULL),
  _trust(trust),
  _pending_destroy(false),
  _context_count(0),
  _upstream_acr(acr),
  _downstream_acr(acr),
  _in_dialog(false),
  _se_helper(stack_data.default_session_expires)
{
  TRC_DEBUG("UASTransaction constructor (%p)", this);
  TRC_DEBUG("ACR (%p)", acr);

  for (int ii = 0; ii < MAX_FORKING; ++ii)
  {
    _uac_data[ii] = NULL;
  }

  // Reference the transaction's group lock.
  _lock = tsx->grp_lock;
  pj_grp_lock_add_ref(tsx->grp_lock);

  // Set the trail identifier for the transaction using the trail ID on
  // the original message.
  set_trail(_tsx, get_trail(rdata));

  // Feed the request to the UAS transaction to drive its state
  // out of NULL state.
  pjsip_tsx_recv_msg(_tsx, rdata);

  // Create a 408 response to use if none of the targets responds.
  pjsip_endpt_create_response(stack_data.endpt, rdata,
                              PJSIP_SC_REQUEST_TIMEOUT, NULL, &_best_rsp);

  // Do any start of transaction logging operations.
  log_on_tsx_start(rdata);

  _tsx->mod_data[mod_tu.id] = this;

  // initialise deferred trying timer
  pthread_mutex_init(&_trying_timer_lock, NULL);
  pj_timer_entry_init(&_trying_timer, 0, (void*)this, &trying_timer_callback);
  _trying_timer.id = 0;

  // Record whether or not this is an in-dialog request.  This is needed
  // to determine whether or not to send interim ACRs on provisional
  // responses.
  _in_dialog = (rdata->msg_info.msg->line.req.method.id != PJSIP_BYE_METHOD) &&
               (rdata->msg_info.to->tag.slen != 0);
}

/// UASTransaction destructor.  On entry, the group lock must be held.  On
/// exit, it will have been released (and possibly destroyed).
UASTransaction::~UASTransaction()
{
  TRC_DEBUG("UASTransaction destructor (%p)", this);

  pj_assert(_context_count == 0);

  if (_tsx != NULL)
  {
    _tsx->mod_data[mod_tu.id] = NULL;
  }

  if (method() == PJSIP_INVITE_METHOD)
  {
    // INVITE transaction has been terminated.  If there are any
    // pending UAC transactions they should be cancelled.
    cancel_pending_uac_tsx(0, true);
  }

  cancel_trying_timer();
  pthread_mutex_destroy(&_trying_timer_lock);

  // Disconnect all UAC transactions from the UAS transaction.
  TRC_DEBUG("Disconnect UAC transactions from UAS transaction");
  for (int ii = 0; ii < _num_targets; ++ii)
  {
    UACTransaction* uac_data = _uac_data[ii];
    if (uac_data != NULL)
    {
      dissociate(uac_data);
    }
  }

  TRC_DEBUG("Upstream ACR = %p, Downstream ACR = %p", _upstream_acr, _downstream_acr);

  // This transaction is still in control of the ACR, so send it now.
  if (_downstream_acr != _upstream_acr)
  {
    // The downstream ACR is not the same as the upstream one, so send the
    // message and destroy the object.
    _downstream_acr->send();
    delete _downstream_acr;
  }

  // Send the ACR for the upstream side.
  _upstream_acr->send();
  delete _upstream_acr;
  _upstream_acr = NULL;
  _downstream_acr = NULL;

  if (_req != NULL)
  {
    TRC_DEBUG("Free original request (%p)", _req);
    pjsip_tx_data_dec_ref(_req);
    _req = NULL;
  }

  if (_best_rsp != NULL)
  {
    // The pre-built response hasn't been used, so free it.
    TRC_DEBUG("Free un-used best response");
    pjsip_tx_data_dec_ref(_best_rsp);
    _best_rsp = NULL;
  }

  pj_grp_lock_release(_lock);
  pj_grp_lock_dec_ref(_lock);

  TRC_DEBUG("UASTransaction destructor completed");
}

// Creates a PJSIP transaction and a corresponding UASTransaction.  On
// success, we will be in the transaction's context.
//
// This should all be done in the UASTransaction constructor, but creating a
// PJSIP transaction can fail, and it's hard to fail a constructor.
//
// @returns status code indicating whether the operation was successful.
pj_status_t UASTransaction::create(pjsip_rx_data* rdata,
                                   pjsip_tx_data* tdata,
                                   TrustBoundary* trust,
                                   ACR* acr,
                                   UASTransaction** uas_data_ptr)
{
  // Create a group lock, and take it.  This avoids the transaction being
  // destroyed before we even get our hands on it.
  pj_grp_lock_t* lock;
  pj_status_t status = pj_grp_lock_create(stack_data.pool, NULL, &lock);
  if (status != PJ_SUCCESS)
  {
    return status;
  }
  pj_grp_lock_add_ref(lock);
  pj_grp_lock_acquire(lock);

  // Create a transaction for the UAS side.  We do this before looking
  // up targets because calculating targets may involve interacting
  // with an external database, and we need the transaction in place
  // early to ensure CANCEL gets handled correctly.
  pjsip_transaction* uas_tsx;
  status = pjsip_tsx_create_uas2(&mod_tu, rdata, lock, &uas_tsx);
  if (status != PJ_SUCCESS)
  {
    pj_grp_lock_release(lock);
    pj_grp_lock_dec_ref(lock);
    return status;
  }

  // Allocate UAS data to keep track of the transaction.
  *uas_data_ptr = new UASTransaction(uas_tsx, rdata, tdata, trust, acr);

  // Enter the transaction's context, and then release our copy of the
  // group lock.
  (*uas_data_ptr)->enter_context();
  pj_grp_lock_release(lock);
  pj_grp_lock_dec_ref(lock);

  return PJ_SUCCESS;
}

// Gets a UASTransaction from a PJSIP transaction, if one exists.
//
// @returns a UASTransaction or null.
UASTransaction* UASTransaction::get_from_tsx(pjsip_transaction* tsx)
{
  // Check that the PJSIP transaction is the correct role, and then return
  // any attached data as a UASTransaction.
  return (tsx->role == PJSIP_ROLE_UAS) ? (UASTransaction *)tsx->mod_data[mod_tu.id] : NULL;
}

// Handle a non-CANCEL message as an access proxy.
void UASTransaction::access_proxy_handle_non_cancel(Target* target)
{
  assert(edge_proxy);

  // Strip any untrusted headers as required, so we don't pass them on.
  _trust->process_request(_req);

  // Perform common outgoing processing.
  handle_outgoing_non_cancel(target);

  delete target;
}

// Handle the outgoing half of a non-CANCEL message.
void UASTransaction::handle_outgoing_non_cancel(Target* target)
{
  // Calculate targets
  TargetList targets;
  assert(target != NULL);
  // Already have a target, so use it.
  targets.push_back(*target);

  _se_helper.process_request(_req->msg, _req->pool, trail());

  // Now set up the data structures and transactions required to
  // process the request.
  pj_status_t status = init_uac_transactions(targets);

  if (status != PJ_SUCCESS)
  {
    // Send 500/Internal Server Error to UAS transaction */
    TRC_ERROR("Failed to allocate UAC transaction for UAS transaction");
    send_response(PJSIP_SC_INTERNAL_SERVER_ERROR);
    return;
  }
}

// Handles a response to an associated UACTransaction.
void UASTransaction::on_new_client_response(UACTransaction* uac_data, pjsip_rx_data *rdata)
{
  if (_tsx != NULL)
  {
    enter_context();

    // Pass the received response to the downstream ACR.
    _downstream_acr->rx_response(rdata->msg_info.msg, rdata->pkt_info.timestamp);

    pjsip_tx_data *tdata;
    pj_status_t status;
    int status_code = rdata->msg_info.msg->line.status.code;

    assert(edge_proxy);
    if ((method() == PJSIP_REGISTER_METHOD) &&
        (status_code == 200))
    {
      // Pass the REGISTER response to the access proxy code to see if
      // the associated client flow has been authenticated.
      proxy_process_register_response(rdata);
    }

    status = PJUtils::create_response_fwd(stack_data.endpt, rdata, 0, &tdata);
    if (status != PJ_SUCCESS)
    {
      TRC_ERROR("Error creating response, %s",
                PJUtils::pj_status_to_string(status).c_str());
      exit_context();
      return;
    }

    _se_helper.process_response(tdata->msg, tdata->pool, trail());

    // Strip any untrusted headers as required, so we don't pass them on.
    _trust->process_response(tdata);

    if (_downstream_acr != _upstream_acr)
    {
      // The downstream and upstream legs are in different Rf contexts, so
      // pass the received response (after trust boundary changes) to the
      // downstream ACR as a transmitted response and to the upstream ACR as
      // a received response.
      _downstream_acr->tx_response(tdata->msg);

      if ((_in_dialog) &&
          (status_code > 100) &&
          (status_code < 199))
      {
        // This is a provisional response to a mid-dialog message, so we
        // should send an ACR now.
        _downstream_acr->send();

        // Don't delete the ACR as we will send another on any subsequent
        // provisional responses, and also when the transaction completes.
      }

      _upstream_acr->rx_response(tdata->msg);
    }

    if (_num_targets > 1)
    {
      if ((status_code > 100) &&
          (status_code < 199))
      {
        // Forward all provisional responses.
        TRC_DEBUG("%s - Forward 1xx response", uac_data->name());

        // Pass the response to the upstream ACR for reporting.
        _upstream_acr->tx_response(tdata->msg);

        if (_in_dialog)
        {
          // This is a provisional response to a mid-dialog message, so we
          // should send an ACR now.
          _upstream_acr->send();

          // Don't delete the ACR as we will send another on any subsequent
          // provisional responses, and also when the transaction completes.
        }

        // Forward response with the UAS transaction
        pjsip_tsx_send_msg(_tsx, tdata);
      }
      else if (status_code == 200)
      {
        // 200 OK.
        TRC_DEBUG("%s - Forward 200 OK response", name());

        // Forward response with the UAS transaction
        pjsip_tsx_send_msg(_tsx, tdata);

        // Disconnect the UAC data from the UAS data so no further
        // events get passed between the two.
        dissociate(uac_data);

        if (method() == PJSIP_INVITE_METHOD)
        {
          // Terminate the UAS transaction (this needs to be done
          // manually for INVITE 200 OK response, otherwise the
          // transaction layer will wait for an ACK.  This will also
          // cause all other pending UAC transactions to be cancelled.
          TRC_DEBUG("%s - Terminate UAS INVITE transaction (forking case)", name());
          pjsip_tsx_terminate(_tsx, 200);
        }
      }
      else
      {
        // Final, non-OK response.  Is this the "best" response
        // received so far?
        TRC_DEBUG("%s - 3xx/4xx/5xx/6xx response", uac_data->name());
        if ((_best_rsp == NULL) ||
            (compare_sip_sc(status_code, _best_rsp->msg->line.status.code) > 0))
        {
          TRC_DEBUG("%s - Best 3xx/4xx/5xx/6xx response so far", uac_data->name());

          if (_best_rsp != NULL)
          {
            pjsip_tx_data_dec_ref(_best_rsp);
          }

          _best_rsp = tdata;
        }
        else
        {
          pjsip_tx_data_dec_ref(tdata);
        }

        // Disconnect the UAC data from the UAS data so no further
        // events get passed between the two.
        dissociate(uac_data);

        if (--_pending_targets == 0)
        {
          // Received responses on every UAC transaction, so check terminating
          // call services and then send the best response on the UAS
          // transaction.
          TRC_DEBUG("%s - All UAC responded", name());
          handle_final_response();
        }
      }
    }
    else
    {
      // Non-forked transaction.  Create response to be forwarded upstream
      // (Via will be stripped here)
      if (rdata->msg_info.msg->line.status.code < 200)
      {
        // Forward provisional response with the UAS transaction.
        TRC_DEBUG("%s - Forward provisional response on UAS transaction", uac_data->name());
        pjsip_tsx_send_msg(_tsx, tdata);
      }
      else
      {
        // Forward final response.  Disconnect the UAC data from
        // the UAS data so no further events get passed between the two.
        TRC_DEBUG("%s - Final response, so disconnect UAS and UAC transactions", uac_data->name());
        if (_best_rsp != NULL)
        {
          pjsip_tx_data_dec_ref(_best_rsp);
        }
        _best_rsp = tdata;
        _pending_targets--;
        dissociate(uac_data);
        handle_final_response();
      }
    }

    exit_context();
  }
}

// Notification that a client transaction is not responding.
void UASTransaction::on_client_not_responding(UACTransaction* uac_data)
{
  if (_tsx != NULL)
  {
    enter_context();

   if (_num_targets > 1)
    {
      // UAC transaction has timed out or hit a transport error.  If
      // we've not received a response from on any other UAC
      // transactions then keep this as the best response.
      TRC_DEBUG("%s - Forked request", uac_data->name());

      if (--_pending_targets == 0)
      {
        // Received responses on every UAC transaction, so
        // send the best response on the UAS transaction.
        TRC_DEBUG("%s - No more pending responses, so send response on UAC tsx", name());
        handle_final_response();
      }
    }
    else
    {
      // UAC transaction has timed out or hit a transport error for
      // non-forked request.  Send a 408 on the UAS transaction.
      TRC_DEBUG("%s - Not forked request", uac_data->name());
      --_pending_targets;
      handle_final_response();
    }

    // Disconnect the UAC data from the UAS data so no further
    // events get passed between the two.
    TRC_DEBUG("%s - Disconnect UAS tsx from UAC tsx", uac_data->name());
    dissociate(uac_data);

    exit_context();
  }
}

// Notification that the underlying PJSIP transaction has changed state.
//
// After calling this, the caller must not assume that the UASTransaction still
// exists - if the PJSIP transaction is being destroyed, this method will
// destroy the UASTransaction.
void UASTransaction::on_tsx_state(pjsip_event* event)
{
  enter_context();

  if (_tsx->state == PJSIP_TSX_STATE_COMPLETED)
  {
    // UAS transaction has completed, so do any transaction completion
    // log activities

    // This has to be conditional on a completed state, else
    // _tsx->transport might not be set.
    assert(edge_proxy);
    SIPPeerType stype  = determine_source(_tsx->transport, _tsx->addr);
    bool is_client = (stype == SIP_PEER_CLIENT);
    dialog_tracker->on_uas_tsx_complete(_req, _tsx, event, is_client);

    log_on_tsx_complete();
  }

  if (_tsx->state == PJSIP_TSX_STATE_DESTROYED)
  {
    TRC_DEBUG("%s - UAS tsx destroyed", _tsx->obj_name);
    if (method() == PJSIP_INVITE_METHOD)
    {
      // INVITE transaction has been terminated.  If there are any
      // pending UAC transactions they should be cancelled.
      cancel_pending_uac_tsx(0, true);
    }
    _tsx->mod_data[mod_tu.id] = NULL;
    _tsx = NULL;
    _pending_destroy = true;
  }

  exit_context();
}

// Handles the best final response, once all final responses have been received
// from all forked INVITEs.
// @Returns whether or not the send was a success.
pj_status_t UASTransaction::handle_final_response()
{
  pj_status_t rc = PJ_SUCCESS;
  if (_tsx != NULL)
  {
    pjsip_tx_data *best_rsp = _best_rsp;
    int st_code = best_rsp->msg->line.status.code;

    // Pass the final response to the upstream ACR.
    _upstream_acr->tx_response(best_rsp->msg);

    // Send the best response back on the UAS transaction.
    _best_rsp = NULL;
    set_trail(best_rsp, trail());
    rc = pjsip_tsx_send_msg(_tsx, best_rsp);

    if ((method() == PJSIP_INVITE_METHOD) &&
        (st_code == 200))
    {
      // Terminate the UAS transaction (this needs to be done
      // manually for INVITE 200 OK response, otherwise the
      // transaction layer will wait for an ACK).  This will also
      // cause all other pending UAC transactions to be cancelled.
      TRC_DEBUG("%s - Terminate UAS INVITE transaction (non-forking case)",
          _tsx->obj_name);
      pjsip_tsx_terminate(_tsx, 200);
    }

  }
  return rc;
}

// Sends a response using the buffer saved off for the best response.
// @Returns whether or not the send was a success.
pj_status_t UASTransaction::send_response(int st_code, const pj_str_t* st_text)
{
  // cancel any outstanding deferred trying responses
  if ((st_code >= 100) && (st_code < 200))
  {
    // Build a provisional response.
    pjsip_tx_data* prov_rsp = PJUtils::clone_tdata(_best_rsp);
    prov_rsp->msg->line.status.code = st_code;
    prov_rsp->msg->line.status.reason = (st_text != NULL) ? *st_text : *pjsip_get_status_text(st_code);

    // If this is a 100 Trying response, we need to clear the To tag.  This was
    // filled in when we created _best_rsp as a final response, but isn't valid
    // on a 100 Trying response.
    if (st_code == 100)
    {
      PJSIP_MSG_TO_HDR(prov_rsp->msg)->tag.slen = 0;
    }

    // Send the response.
    pjsip_tx_data_invalidate_msg(prov_rsp);
    set_trail(prov_rsp, trail());
    _upstream_acr->tx_response(prov_rsp->msg);
    return pjsip_tsx_send_msg(_tsx, prov_rsp);
  }
  else
  {
    _best_rsp->msg->line.status.code = st_code;
    _best_rsp->msg->line.status.reason = (st_text != NULL) ? *st_text : *pjsip_get_status_text(st_code);
    pjsip_tx_data_invalidate_msg(_best_rsp);
    return handle_final_response();
  }
}

// Enters this transaction's context.  While in the transaction's
// context, processing on this and associated transactions will be
// single-threaded and the transaction will not be destroyed.  Whenever
// enter_context is called, exit_context must be called before the end of the
// method.
void UASTransaction::enter_context()
{
  // Take the group lock.
  pj_grp_lock_acquire(_lock);

  // If the transaction is pending destroy, the context count must be greater
  // than 0.  Otherwise, the transaction should have already been destroyed (so
  // entering its context again is unsafe).
  assert((!_pending_destroy) || (_context_count > 0));

  _context_count++;
}

// Exits this transaction's context.  On return from this method, the caller
// must not assume that the transaction still exists.
void UASTransaction::exit_context()
{
  // If the transaction is pending destroy, the context count must be greater
  // than 0.  Otherwise, the transaction should have already been destroyed (so
  // entering its context again is unsafe).
  assert(_context_count > 0);

  _context_count--;
  if ((_context_count == 0) && (_pending_destroy))
  {
    // Deleting the transaction implicitly releases the group lock.
    delete this;
  }
  else
  {
    // Release the group lock.
    pj_grp_lock_release(_lock);
  }
}

// Generate analytics logs relating to a new transaction starting.
void UASTransaction::log_on_tsx_start(const pjsip_rx_data* rdata)
{
  // Store analytics data from request starting transaction.
  _analytics.from = (rdata->msg_info.from != NULL) ? (pjsip_from_hdr*)pjsip_hdr_clone(_tsx->pool, rdata->msg_info.from) : NULL;
  _analytics.to = (rdata->msg_info.to != NULL) ? (pjsip_to_hdr*)pjsip_hdr_clone(_tsx->pool, rdata->msg_info.to) : NULL;
  _analytics.cid = (rdata->msg_info.cid != NULL) ? (pjsip_cid_hdr*)pjsip_hdr_clone(_tsx->pool, rdata->msg_info.cid) : NULL;

  // Report SAS markers for the transaction.
  TRC_DEBUG("Report SAS start marker - trail (%llx)", trail());
  SAS::Marker start_marker(trail(), MARKER_ID_START, 1u);
  SAS::report_marker(start_marker);
}

// Generate analytics logs relating to a transaction completing.
void UASTransaction::log_on_tsx_complete()
{
  // Report SAS markers for the transaction.
  TRC_DEBUG("Report SAS end marker - trail (%llx)", trail());
  SAS::Marker end_marker(trail(), MARKER_ID_END, 1u);
  SAS::report_marker(end_marker);

  if (analytics_logger != NULL)
  {
    // Generate analytics inputs based on the end result of the UAS
    // transaction.
    if ((method() == PJSIP_INVITE_METHOD) &&
        (_analytics.to != NULL) &&
        (_analytics.to->tag.slen == 0))
    {
      // INVITE transaction with no To tag in original request, so must
      // be a call set-up.
      if ((_tsx->status_code >= 200) && (_tsx->status_code <= 299))
      {
        // 2xx response, so call connected successfully.
        analytics_logger->call_connected(PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, (pjsip_uri*)pjsip_uri_get_uri(_analytics.from->uri)),
                                         PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, (pjsip_uri*)pjsip_uri_get_uri(_analytics.to->uri)),
                                         PJUtils::pj_str_to_string(&_analytics.cid->id));
      }
      else if (_tsx->status_code >= 400)
      {
        // non-2xx/non-3xx final response, so call failed to connect.
        analytics_logger->call_not_connected(PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, (pjsip_uri*)pjsip_uri_get_uri(_analytics.from->uri)),
                                             PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, (pjsip_uri*)pjsip_uri_get_uri(_analytics.to->uri)),
                                             PJUtils::pj_str_to_string(&_analytics.cid->id),
                                             _tsx->status_code);
      }
      // @TODO - what about 3xx redirect responses?
    }
    else if (method() == PJSIP_BYE_METHOD)
    {
      // BYE transaction, so consider this to be a normal disconnection
      // irrespective of the result of the transaction.
      analytics_logger->call_disconnected(PJUtils::pj_str_to_string(&_analytics.cid->id), 0);
    }
    else if (_tsx->status_code >= 400)
    {
      // Non-INVITE/Non-BYE transaction has failed - consider this to
      // always be a call disconnect.
      analytics_logger->call_disconnected(PJUtils::pj_str_to_string(&_analytics.cid->id), _tsx->status_code);
    }
  }
}

// Initializes UAC transactions to each of the specified targets.
//
// @returns a status code indicating whether or not the operation succeeded.
pj_status_t UASTransaction::init_uac_transactions(TargetList& targets)
{
  pj_status_t status = PJ_EUNKNOWN;
  pjsip_transaction *uac_tsx;
  UACTransaction *uac_data;
  pjsip_tx_data *uac_tdata;

  if (_tsx != NULL)
  {
    // Initialise the UAC data structures for each target.
    int ii = 0;
    for (TargetList::const_iterator it = targets.begin();
         it != targets.end();
         ++it)
    {
      // First UAC transaction can use existing tdata, others must clone.
      TRC_DEBUG("Allocating transaction and data for target %d", ii);
      uac_tdata = PJUtils::clone_tdata(_req);
      PJUtils::add_top_via(uac_tdata);

      // Copy the targets onto the tdata as Route headers at this
      // point - if the Request-URI is a tel: URI, PJSIP will refuse
      // to create the transaction unless Route headers are present.
      set_target_on_tdata(*it, uac_tdata);


      if (uac_tdata == NULL)
      {
        status = PJ_ENOMEM;
        TRC_ERROR("Failed to clone request for forked transaction, %s",
                  PJUtils::pj_status_to_string(status).c_str());
        break;
      }

      status = pjsip_tsx_create_uac2(&mod_tu, uac_tdata, _lock, &uac_tsx);
      if (status != PJ_SUCCESS)
      {
        TRC_ERROR("Failed to create UAC transaction, %s",
                  PJUtils::pj_status_to_string(status).c_str());
        break;
      }

      // Add the trail from the UAS transaction to the UAC transaction.
      TRC_DEBUG("Adding trail identifier %ld to UAC transaction", trail());
      set_trail(uac_tsx, trail());

      // Attach data to the UAC transaction.
      uac_data = new UACTransaction(this, ii, uac_tsx, uac_tdata);
      _uac_data[ii] = uac_data;
      ii++;
    }

    if (status == PJ_SUCCESS)
    {
      // Allocated all the structures, so now set the targets for transaction
      // (this is done as a separate loop to avoid modifying the message
      // before it is cloned).
      ii = 0;
      for (TargetList::const_iterator it = targets.begin();
           it != targets.end();
           ++it)
      {
        TRC_DEBUG("Updating request URI and route for target %d", ii);
        uac_data = _uac_data[ii];
        uac_data->set_target(*it);
        ++ii;
      }
    }

    if (status == PJ_SUCCESS)
    {
      // All the data structures, transactions and transmit data have
      // been created, so start sending messages.
      _num_targets = targets.size();
      _pending_targets = _num_targets;

      // Forward the client requests.
      for (ii = 0; ii < _num_targets; ++ii)
      {
        UACTransaction* uac_data = _uac_data[ii];
        uac_data->send_request();
      }
    }
    else
    {
      // Clean up any transactions and tx data allocated.
      for (ii = 0; ii < (int)targets.size(); ++ii)
      {
        uac_data = _uac_data[ii];
        if (uac_data != NULL)
        {
          // UAC data should be freed up when UAC transaction terminates
          delete uac_data;
          _uac_data[ii] = NULL;
        }
      }
    }
  }

  return status;
}

// Cancels all pending UAC transactions associated with this UAS transaction.
void UASTransaction::cancel_pending_uac_tsx(int st_code, bool dissociate_uac)
{
  enter_context();

  // Send CANCEL on all pending UAC transactions forked from this UAS
  // transaction.  This is invoked either because the UAS transaction
  // received a CANCEL, or one of the UAC transactions received a 200 OK or
  // 6xx response.
  int ii;
  UACTransaction *uac_data;

  TRC_DEBUG("%s - Cancel %d pending UAC transactions",
            name(), _pending_targets);

  for (ii = 0; ii < _num_targets; ++ii)
  {
    uac_data = _uac_data[ii];
    TRC_DEBUG("%s - Check target %d, UAC data = %p, UAC tsx = %p",
              name(),
              ii,
              uac_data,
              (uac_data != NULL) ? uac_data->_tsx : NULL);
    if (uac_data != NULL)
    {
      // Found a UAC transaction that is still active, so send a CANCEL.
      uac_data->cancel_pending_tsx(st_code);

      // Normal behaviour (that is, on receipt of a CANCEL on the UAS
      // transaction), is to leave the UAC transaction connected to the UAS
      // transaction so the 487 response gets passed through.  However, in
      // cases where the CANCEL is initiated on this node (for example,
      // because the UAS transaction has already failed, or in call forwarding
      // scenarios) we dissociate immediately so the 487 response gets
      // swallowed on this node
      if (dissociate_uac)
      {
        dissociate(uac_data);
      }
    }
  }

  exit_context();
}

// Disassociates the specified UAC transaction from this UAS transaction, and
// vice-versa.
//
// This must be called before destroying either transaction.
void UASTransaction::dissociate(UACTransaction* uac_data)
{
  TRC_DEBUG("Dissociate UAC transaction %p (%d)", uac_data, uac_data->_target);
  uac_data->_uas_data = NULL;
  _uac_data[uac_data->_target] = NULL;
}

// UAC Transaction constructor
UACTransaction::UACTransaction(UASTransaction* uas_data,
                               int target,
                               pjsip_transaction* tsx,
                               pjsip_tx_data *tdata) :
  _uas_data(uas_data),
  _target(target),
  _tsx(tsx),
  _tdata(tdata),
  _from_store(false),
  _aor(),
  _binding_id(),
  _servers(),
  _current_server(0),
  _pending_destroy(false),
  _context_count(0)
{
  // Add a reference to the request so we can be sure it remains valid for retries.
  pjsip_tx_data_add_ref(_tdata);

  // Reference the transaction's group lock.
  _lock = tsx->grp_lock;
  pj_grp_lock_add_ref(tsx->grp_lock);

  _tsx->mod_data[mod_tu.id] = this;

  // Initialise the liveness timer.
  pj_timer_entry_init(&_liveness_timer, 0, (void*)this, &liveness_timer_callback);
}

/// UACTransaction destructor.  On entry, the group lock must be held.  On
/// exit, it will have been released (and possibly destroyed).
UACTransaction::~UACTransaction()
{
  pj_assert(_context_count == 0);

  if (_tsx != NULL)
  {
    _tsx->mod_data[mod_tu.id] = NULL;
  }

  if (_uas_data != NULL)
  {
    _uas_data->dissociate(this);
  }

  if (_tdata != NULL)
  {
    pjsip_tx_data_dec_ref(_tdata);
    _tdata = NULL;
  }

  if (_liveness_timer.id == LIVENESS_TIMER)
  {
    // The liveness timer is running, so cancel it.
    _liveness_timer.id = 0;
    pjsip_endpt_cancel_timer(stack_data.endpt, &_liveness_timer);
  }

  if ((_tsx != NULL) &&
      (_tsx->state != PJSIP_TSX_STATE_TERMINATED) &&
      (_tsx->state != PJSIP_TSX_STATE_DESTROYED))
  {
    pjsip_tsx_terminate(_tsx, PJSIP_SC_INTERNAL_SERVER_ERROR);
  }

  _tsx = NULL;

  pj_grp_lock_release(_lock);
  pj_grp_lock_dec_ref(_lock);
}

// Gets a UACTransaction from a PJSIP transaction, if one exists.
//
// @returns a UACTransaction or null.
UACTransaction* UACTransaction::get_from_tsx(pjsip_transaction* tsx)
{
  // Check that the PJSIP transaction is the correct role, and then return
  // any attached data as a UACTransaction.
  return (tsx->role == PJSIP_ROLE_UAC) ? (UACTransaction *)tsx->mod_data[mod_tu.id] : NULL;
}

// Modifies a tdata's Request-URI and Route headers to match the given Target object.
void set_target_on_tdata(const struct Target& target, pjsip_tx_data* tdata)
{
  if (target.from_store)
  {
    // This target came from the registration store.  Before we overwrite the
    // URI, extract its AOR and write it to the P-Called-Party-ID header.
    static const pj_str_t called_party_id_hdr_name = pj_str("P-Called-Party-ID");
    pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(tdata->msg, &called_party_id_hdr_name, NULL);
    if (hdr)
    {
      pj_list_erase(hdr);
    }
    std::string name_addr_str("<" + PJUtils::public_id_from_uri(tdata->msg->line.req.uri) + ">");
    pj_str_t called_party_id;
    pj_strdup2(tdata->pool,
               &called_party_id,
               name_addr_str.c_str());
    hdr = (pjsip_hdr*)pjsip_generic_string_hdr_create(tdata->pool,
                                                      &called_party_id_hdr_name,
                                                      &called_party_id);
    pjsip_msg_add_hdr(tdata->msg, hdr);
  }

  // Write the target in to the request.  Need to clone the URI to make
  // sure it comes from the right pool.
  tdata->msg->line.req.uri = (pjsip_uri*)pjsip_uri_clone(tdata->pool, target.uri);

  // If the target is routing to the upstream device (we're acting as an access
  // proxy), strip any extra loose routes on the message to prevent accidental
  // double routing.
  if (target.upstream_route)
  {
    TRC_DEBUG("Stripping loose routes from proxied message");

    // Tight loop to strip all route headers.
    while (pjsip_msg_find_remove_hdr(tdata->msg,
                                     PJSIP_H_ROUTE,
                                     NULL) != NULL)
    {
      TRC_DEBUG("Stripped a Route header from proxied message");
    };
  }

  // Add all the paths as a sequence of Route headers.
  for (std::list<pjsip_route_hdr*>::const_iterator pit = target.paths.begin();
       pit != target.paths.end();
       ++pit)
  {
    // We may have a nameaddr here rather than a URI - if so,
    // pjsip_uri_get_uri will return the internal URI. Otherwise, it
    // will just return the URI.
    pjsip_sip_uri* uri = (pjsip_sip_uri*)(*pit)->name_addr.uri;

    TRC_DEBUG("Adding a Route header to sip:%.*s%s%.*s:%d;transport=%.*s",
              uri->user.slen, uri->user.ptr,
              (uri->user.slen != 0) ? "@" : "",
              uri->host.slen, uri->host.ptr,
              uri->port,
              uri->transport_param.slen,
              uri->transport_param.ptr);


    //pjsip_route_hdr* route_hdr = pjsip_route_hdr_create(tdata->pool);
    //route_hdr->name_addr.uri = (pjsip_uri*)pjsip_uri_clone(tdata->pool, uri);
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)pjsip_hdr_clone(tdata->pool, *pit));
  }
}

// Set the target for this UAC transaction.
//
void UACTransaction::set_target(const struct Target& target)
{
  enter_context();

  // Store the liveness timeout.
  _liveness_timeout = target.liveness_timeout;

  if (target.from_store)
  {
    // This target came from the registration store, store the lookup keys.
    TRC_DEBUG("Target came from store, storing AoR = %s, binding_id = %s",
              target.aor.c_str(), target.binding_id.c_str());
    _from_store = PJ_TRUE;
    pj_strdup2(_tsx->pool, &_aor, target.aor.c_str());
    pj_strdup2(_tsx->pool, &_binding_id, target.binding_id.c_str());
  }

  if (target.transport != NULL)
  {
    // The target includes a selected transport, so set it here.
    pjsip_tpselector tp_selector;
    tp_selector.type = PJSIP_TPSELECTOR_TRANSPORT;
    tp_selector.u.transport = target.transport;
    pjsip_tx_data_set_transport(_tdata, &tp_selector);

    _tdata->dest_info.addr.count = 1;
    _tdata->dest_info.addr.entry[0].type = (pjsip_transport_type_e)target.transport->key.type;
    pj_memcpy(&_tdata->dest_info.addr.entry[0].addr, &target.remote_addr, sizeof(pj_sockaddr));
    _tdata->dest_info.addr.entry[0].addr_len =
         (_tdata->dest_info.addr.entry[0].addr.addr.sa_family == pj_AF_INET()) ?
         sizeof(pj_sockaddr_in) : sizeof(pj_sockaddr_in6);
    _tdata->dest_info.cur_addr = 0;

    // Remove the reference to the transport added when it was chosen.
    pjsip_transport_dec_ref(target.transport);
  }
  else
  {
    // Resolve the next hop destination for this request to a set of servers.
    TRC_DEBUG("Resolve next hop destination");
    PJUtils::resolve_next_hop(_tdata, 0, _servers, BaseResolver::ALL_LISTS, trail());
  }

  exit_context();
}

// Sends the initial request on this UAC transaction.
void UACTransaction::send_request()
{
  pj_status_t status = PJ_SUCCESS;

  enter_context();

  if (_tdata->tp_sel.type == PJSIP_TPSELECTOR_TRANSPORT)
  {
    // The transport has already been selected for this request, so
    // add it to the transaction otherwise it will get overwritten.
    TRC_DEBUG("Transport %s (%s) pre-selected for transaction",
              _tdata->tp_sel.u.transport->obj_name,
              _tdata->tp_sel.u.transport->info);
    pjsip_tsx_set_transport(_tsx, &_tdata->tp_sel);
  }
  else if (_current_server < (int)_servers.size())
  {
    // We have resolved servers to try, so set up the destination information
    // in the request.
    PJUtils::set_dest_info(_tdata, _servers[_current_server]);
  }
  else
  {
    // The resolver is enabled, but we failed to get any valid destination
    // servers, so fail the transaction.
    status = PJ_ENOTFOUND;
  }

  if (status == PJ_SUCCESS)
  {
    TRC_DEBUG("Sending request for %s", PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, _tdata->msg->line.req.uri).c_str());
    _uas_data->_downstream_acr->tx_request(_tdata->msg);
    status = pjsip_tsx_send_msg(_tsx, _tdata);
  }

  if (status != PJ_SUCCESS)
  {
    // Failed to send the request.  This is an unexpected error rather than
    // an indication that the selected destination is down, so we do not
    // attempt a retry and do not blacklist the selected destination.
    TRC_DEBUG("Failed to send request (%d %s)",
              status, PJUtils::pj_status_to_string(status).c_str());
    pjsip_tx_data_dec_ref(_tdata);

    // The UAC transaction will have been destroyed when it failed to send
    // the request, so there's no need to destroy it.  However, we do need to
    // tell the UAS transaction.
    if (_uas_data != NULL)
    {
      _uas_data->on_client_not_responding(this);
    }
  }
  else
  {
    // Sent the request successfully.
    if (_liveness_timeout != 0)
    {
      _liveness_timer.id = LIVENESS_TIMER;
      pj_time_val delay = {_liveness_timeout, 0};
      pjsip_endpt_schedule_timer(stack_data.endpt, &_liveness_timer, &delay);
    }
  }

  exit_context();
}

// Cancels the pending transaction, using the specified status code in the
// Reason header.
void UACTransaction::cancel_pending_tsx(int st_code)
{
  enter_context();
  if (_tsx != NULL)
  {
    TRC_DEBUG("Found transaction %s status=%d", name(), _tsx->status_code);
    if (_tsx->status_code < 200)
    {
      // See issue 1232.
      pjsip_tx_data* cancel = PJUtils::create_cancel(stack_data.endpt,
                                                     _tsx->last_tx,
                                                     _tsx->status_code);

      if (trail() == 0)
      {
        TRC_ERROR("Sending CANCEL request with no SAS trail");
      }

      set_trail(cancel, trail());

      if (_tsx->transport != NULL)
      {
        // The transaction being cancelled has already selected a transport,
        // so make sure the CANCEL uses this transport as well.
        pjsip_tpselector tp_selector;
        tp_selector.type = PJSIP_TPSELECTOR_TRANSPORT;
        tp_selector.u.transport = _tsx->transport;
        pjsip_tx_data_set_transport(cancel, &tp_selector);
      }

      // Send CANCEL request using stateful sender.  The CANCEL should
      // always chase the INVITE transaction, so don't retry any alternate
      // targets.
      TRC_DEBUG("Sending CANCEL request");
      pj_status_t status = PJUtils::send_request(cancel, 1);

      // We used to deregister the user here if we had
      // SIP_STATUS_FLOW_FAILED, but this is inappropriate - only one
      // of their bindings has failed, but they may be registered
      // elsewhere. If this was the last binding, Chronos will
      // eventually time it out and cause a deregistration.

      if (status != PJ_SUCCESS)
      {
        TRC_ERROR("Error sending CANCEL, %s", PJUtils::pj_status_to_string(status).c_str());
      }
    }
  }
  exit_context();
}

// Notification that the underlying PJSIP transaction has changed state.
//
// After calling this, the caller must not assume that the UACTransaction still
// exists - if the PJSIP transaction is being destroyed, this method will
// destroy the UACTransaction.
void UACTransaction::on_tsx_state(pjsip_event* event)
{
  enter_context();

  // Handle incoming responses (provided the UAS transaction hasn't
  // terminated or been cancelled.
  TRC_DEBUG("%s - uac_data = %p, uas_data = %p", name(), this, _uas_data);

  // Check that the event is on the current UAC transaction (we may have
  // created a new one for a retry) and is still connected to the UAS
  // transaction.
  if ((event->body.tsx_state.tsx == _tsx) && (_uas_data != NULL))
  {
    bool retrying = false;

    if (!_servers.empty())
    {
      // Check to see if the destination server has failed so we can blacklist
      // it and retry to an alternative if possible.
      if ((event->body.tsx_state.tsx->state == PJSIP_TSX_STATE_TERMINATED) &&
          ((event->body.tsx_state.type == PJSIP_EVENT_TIMER) ||
           (event->body.tsx_state.type == PJSIP_EVENT_TRANSPORT_ERROR)))
      {
        // Either failed to connect to the selected server, or failed or get
        // a response, so blacklist it.
        TRC_DEBUG("Failed to connected to server, so add to blacklist");
        PJUtils::blacklist(_servers[_current_server]);

        // Attempt a retry.
        retrying = retry_request();
      }
      else if ((event->body.tsx_state.tsx->state == PJSIP_TSX_STATE_COMPLETED) &&
               (_tsx->status_code == PJSIP_SC_SERVICE_UNAVAILABLE))
      {
        // The server returned a 503 error.  We don't blacklist in this case
        // as it may indicated a transient overload condition, but we can
        // retry to an alternate server if one is available.
        retrying = retry_request();
      }
    }

    if (!retrying)
    {
      if (event->body.tsx_state.type == PJSIP_EVENT_RX_MSG)
      {
        TRC_DEBUG("%s - RX_MSG on active UAC transaction", name());
        if (_liveness_timer.id == LIVENESS_TIMER)
        {
          // The liveness timer is running on this transaction, so cancel it.
          _liveness_timer.id = 0;
          pjsip_endpt_cancel_timer(stack_data.endpt, &_liveness_timer);
        }

        if (_uas_data != NULL) {
          pjsip_rx_data* rdata = event->body.tsx_state.src.rdata;
          _uas_data->on_new_client_response(this, rdata);
        }
      }

      // If UAC transaction is terminated because of a timeout, treat this as
      // a 504 error.
      if ((event->body.tsx_state.tsx->state == PJSIP_TSX_STATE_TERMINATED) &&
          (_uas_data != NULL))
      {
        // UAC transaction has terminated while still connected to the UAS
        // transaction.
        TRC_DEBUG("%s - UAC tsx terminated while still connected to UAS tsx",
                  _tsx->obj_name);
        if (event->body.tsx_state.type == PJSIP_EVENT_TRANSPORT_ERROR)
        {
          TRC_DEBUG("Timeout or transport error");
          SAS::Event sas_event(trail(), SASEvent::TRANSPORT_FAILURE, 0);
          SAS::report_event(sas_event);
          _uas_data->on_client_not_responding(this);
        }
        else if (event->body.tsx_state.type == PJSIP_EVENT_TIMER)
        {
          TRC_DEBUG("Timeout error");
          SAS::Event sas_event(trail(), SASEvent::TIMEOUT_FAILURE, 0);
          SAS::report_event(sas_event);
          _uas_data->on_client_not_responding(this);
        }
        else
        {
          _uas_data->dissociate(this);
        }
      }
    }
  }

  if ((event->body.tsx_state.tsx == _tsx) &&
      (_tsx->state == PJSIP_TSX_STATE_DESTROYED))
  {
    TRC_DEBUG("%s - UAC tsx destroyed", _tsx->obj_name);
    _tsx->mod_data[mod_tu.id] = NULL;
    _tsx = NULL;
    _pending_destroy = true;
  }

  exit_context();
}


// Attempt to retry the request to an alternate server.
bool UACTransaction::retry_request()
{
  bool retrying = false;
  _current_server++;
  if (_current_server < (int)_servers.size())
  {
    // More servers to try.  As per RFC3263, retries to an alternate server
    // have to be a completely new transaction, presumably to avoid any
    // possibility of mis-correlating a late response from the original server.
    // We therefore have to allocate a new branch ID and transaction for the
    // retry and connect it to this object.  We'll leave the old transaction
    // connected to this object while PJSIP closes it down, but ignore any
    // future events from it.
    TRC_DEBUG("Attempt to retry request to alternate server");
    pjsip_transaction* retry_tsx;
    PJUtils::generate_new_branch_id(_tdata);
    pj_status_t status = pjsip_tsx_create_uac2(&mod_tu,
                                               _tdata,
                                               _lock,
                                               &retry_tsx);

    if (status == PJ_SUCCESS)
    {
      // Set up the PJSIP transaction user module data to refer to the associated
      // UACTsx object
      TRC_DEBUG("Created transaction for retry, so send request");
      pjsip_transaction* original_tsx = _tsx;
      _tsx = retry_tsx;
      original_tsx->mod_data[mod_tu.id] = NULL;
      _tsx->mod_data[mod_tu.id] = this;

      // Add the trail from the UAS transaction to the UAC transaction.
      set_trail(_tsx, _uas_data->trail());

      // Increment the reference count of the request as we are passing
      // it to a new transaction.
      pjsip_tx_data_add_ref(_tdata);

      // Copy across the destination information for a retry and try to
      // resend the request.
      PJUtils::set_dest_info(_tdata, _servers[_current_server]);
      status = pjsip_tsx_send_msg(_tsx, _tdata);

      if (status == PJ_SUCCESS)
      {
        // Successfully sent the retry.
        retrying = true;
      }
      else
      {
        // Failed to send, so revert to the original transaction to see it
        // through to the end.  Must decrement the reference count on the
        // request as pjsip_tsx_send_msg won't do it if it fails.
        pjsip_tx_data_dec_ref(_tdata);
        _tsx->mod_data[mod_tu.id] = NULL;
        _tsx = original_tsx;
        _tsx->mod_data[mod_tu.id] = this;
      }
    }
  }

  return retrying;
}


/// Handle the liveness timer expiring on this transaction.
void UACTransaction::liveness_timer_expired()
{
  enter_context();

  if ((_tsx->state == PJSIP_TSX_STATE_NULL) ||
      (_tsx->state == PJSIP_TSX_STATE_CALLING))
  {
    // The transaction is still in NULL or CALLING state, so we've not
    // received any response (provisional or final) from the downstream UAS.
    // Terminate the transaction and send a timeout response upstream.
    pjsip_tsx_terminate(_tsx, PJSIP_SC_REQUEST_TIMEOUT);
  }

  exit_context();
}


/// Static method called by PJSIP when a liveness timer expires.  The instance
/// is stored in the user_data field of the timer entry.
void UACTransaction::liveness_timer_callback(pj_timer_heap_t *timer_heap, struct pj_timer_entry *entry)
{
  if (entry->id == LIVENESS_TIMER)
  {
    ((UACTransaction*)entry->user_data)->liveness_timer_expired();
  }
}

/// Handle the trying timer expiring on this transaction.
void UASTransaction::trying_timer_expired()
{
  enter_context();
  pthread_mutex_lock(&_trying_timer_lock);

  if ((_trying_timer.id == TRYING_TIMER) &&
      (_tsx->state == PJSIP_TSX_STATE_TRYING))
  {
    // Transaction is still in Trying state, so send a 100 Trying response
    // now.
    send_response(100);
    _trying_timer.id = 0;
  }

  pthread_mutex_unlock(&_trying_timer_lock);
  exit_context();
}

/// Static method called by PJSIP when a trying timer expires.  The instance
/// is stored in the user_data field of the timer entry.
void UASTransaction::trying_timer_callback(pj_timer_heap_t *timer_heap, struct pj_timer_entry *entry)
{
  if (entry->id == TRYING_TIMER)
  {
    ((UASTransaction*)entry->user_data)->trying_timer_expired();
  }
}

// Enters this transaction's context.  While in the transaction's
// context, processing on this and associated transactions will be
// single-threaded and the transaction will not be destroyed.  Whenever
// enter_context is called, exit_context must be called before the end of the
// method.
void UACTransaction::enter_context()
{
  // Take the group lock.
  pj_grp_lock_acquire(_lock);

  // If the transaction is pending destroy, the context count must be greater
  // than 0.  Otherwise, the transaction should have already been destroyed (so
  // entering its context again is unsafe).
  assert((!_pending_destroy) || (_context_count > 0));

  _context_count++;
}

// Exits this transaction's context.  On return from this method, the caller
// must not assume that the transaction still exists.
void UACTransaction::exit_context()
{
  // If the transaction is pending destroy, the context count must be greater
  // than 0.  Otherwise, the transaction should have already been destroyed (so
  // entering its context again is unsafe).
  assert(_context_count > 0);

  _context_count--;
  if ((_context_count == 0) && (_pending_destroy))
  {
    // Deleting the transaction implicitly releases the group lock.
    delete this;
  }
  else
  {
    // Release the group lock.
    pj_grp_lock_release(_lock);
  }
}


///@{
// MODULE LIFECYCLE

pj_status_t init_stateful_proxy(pj_bool_t enable_edge_proxy,
                                const std::string& upstream_proxy_arg,
                                int upstream_proxy_port,
                                int upstream_proxy_connections,
                                int upstream_proxy_recycle,
                                pj_bool_t enable_ibcf,
                                const std::string& ibcf_trusted_hosts,
                                const std::string& pbx_host_str,
                                const std::string& pbx_service_route_arg,
                                AnalyticsLogger* analytics,
                                ACRFactory* cscf_rfacr_factory,
                                const std::string& icscf_uri_str,
                                QuiescingManager* quiescing_manager,
                                bool icscf_enabled,
                                bool scscf_enabled,
                                bool emerg_reg_accepted)
{
  analytics_logger = analytics;
  icscf = icscf_enabled;
  scscf = scscf_enabled;
  allow_emergency_reg = emerg_reg_accepted;
  cscf_acr_factory = cscf_rfacr_factory;
  edge_proxy = enable_edge_proxy;

  assert(edge_proxy);

  // Create a URI for the upstream proxy to use in Route headers.
  upstream_proxy = (pjsip_uri*)pjsip_sip_uri_create(stack_data.pool, PJ_FALSE);
  ((pjsip_sip_uri*)upstream_proxy)->host = pj_strdup3(stack_data.pool, upstream_proxy_arg.c_str());
  ((pjsip_sip_uri*)upstream_proxy)->port = upstream_proxy_port;
  ((pjsip_sip_uri*)upstream_proxy)->transport_param = pj_str("TCP");
  ((pjsip_sip_uri*)upstream_proxy)->lr_param = 1;

  // Create a flow table object to manage the client flow records
  // and handle access proxy quiescing.
  flow_count = new SNMP::U32Scalar("bono_connected_clients",
                                   ".1.2.826.0.1.1578918.9.2.1");
  flow_table = new FlowTable(quiescing_manager, flow_count);
  quiescing_manager->register_flows_handler(flow_table);

  // Create a dialog tracker to count dialogs on each flow
  dialog_tracker = new DialogTracker(flow_table);

  // Create a connection pool to the upstream proxy.
  if (upstream_proxy_connections > 0)
  {
    pjsip_host_port pool_target;
    pool_target.host = pj_strdup3(stack_data.pool, upstream_proxy_arg.c_str());
    pool_target.port = upstream_proxy_port;
    sprout_ip_tbl = SNMP::IPCountTable::create("bono_connected_sprouts",
                                               ".1.2.826.0.1.1578918.9.2.3.1");
    upstream_conn_pool = new SIPConnectionPool(&pool_target,
        upstream_proxy_connections,
        upstream_proxy_recycle,
        stack_data.pool,
        stack_data.endpt,
        stack_data.pcscf_trusted_tcp_factory,
        sprout_ip_tbl);
    upstream_conn_pool->init();
  }

  ibcf = enable_ibcf;
  if (ibcf)
  {
    TRC_STATUS("Create list of trusted hosts");
    std::list<std::string> hosts;
    Utils::split_string(ibcf_trusted_hosts, ',', hosts, 0, true);
    for (std::list<std::string>::const_iterator i = hosts.begin();
        i != hosts.end();
        ++i)
    {
      pj_str_t host;
      pj_cstr(&host, (*i).c_str());
      pj_sockaddr sockaddr;
      pj_status_t status = pj_sockaddr_parse(pj_AF_UNSPEC(), 0, &host, &sockaddr);
      if (status != PJ_SUCCESS)
      {
        TRC_ERROR("Badly formatted trusted host %.*s", host.slen, host.ptr);
        return status;
      }
      char buf[100];
      TRC_STATUS("Adding host %s to list", pj_sockaddr_print(&sockaddr, buf, sizeof(buf), 1));
      trusted_hosts.insert(std::make_pair(sockaddr, true));
    }
  }

  TRC_STATUS("Create list of PBXes");
  std::list<std::string> hosts;
  Utils::split_string(pbx_host_str, ',', hosts, 0, true);
  for (std::list<std::string>::const_iterator i = hosts.begin();
       i != hosts.end();
       ++i)
  {
    pj_str_t host;
    pj_cstr(&host, (*i).c_str());
    pj_sockaddr sockaddr;
    pj_status_t status = pj_sockaddr_parse(pj_AF_UNSPEC(), 0, &host, &sockaddr);
    if (status != PJ_SUCCESS)
    {
      TRC_ERROR("Badly formatted PBX IP %.*s", host.slen, host.ptr);
      return status;
    }
    char buf[100];
    TRC_STATUS("Adding PBX %s to list", pj_sockaddr_print(&sockaddr, buf, sizeof(buf), 1));
    pbx_hosts.insert(std::make_pair(sockaddr, true));
  }

  // If present, check the PBX service route is valid.
  pbx_service_route = pbx_service_route_arg;
  if (pbx_service_route != "")
  {
    if (PJUtils::uri_from_string(pbx_service_route, stack_data.pool, PJ_FALSE) == NULL)
    {
      TRC_ERROR("PBX service route (%s) is invalid", pbx_service_route.c_str());
      return -1;
    }
  }

  if (!icscf_uri_str.empty())
  {
    // Got an I-CSCF - parse it.
    icscf_uri = PJUtils::uri_from_string(icscf_uri_str, stack_data.pool, PJ_FALSE);
    if (PJSIP_URI_SCHEME_IS_SIP(icscf_uri))
    {
      // Got a SIP URI - force loose-routing.
      ((pjsip_sip_uri*)icscf_uri)->lr_param = 1;
    }
  }

  pj_status_t status = pjsip_endpt_register_module(stack_data.endpt, &mod_stateful_proxy);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

  status = pjsip_endpt_register_module(stack_data.endpt, &mod_tu);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

  return PJ_SUCCESS;
}

void destroy_stateful_proxy()
{
  assert(edge_proxy);
  // Destroy the upstream connection pool.  This will quiesce all the TCP
  // connections.
  delete upstream_conn_pool; upstream_conn_pool = NULL;
  delete sprout_ip_tbl; sprout_ip_tbl = NULL;

  // Destroy the flow table.
  delete flow_count;
  flow_count = NULL;
  delete flow_table;
  flow_table = NULL;

  delete dialog_tracker;
  dialog_tracker = NULL;

  // Set back static values to defaults (for UTs)
  icscf_uri = NULL;
  ibcf = false;
  icscf = false;
  scscf = false;
  allow_emergency_reg = false;

  pjsip_endpt_unregister_module(stack_data.endpt, &mod_stateful_proxy);
  pjsip_endpt_unregister_module(stack_data.endpt, &mod_tu);
}


///@}

///@{
// HELPERS

// Compare two status codes from the perspective of which is the best to
// return to the originator of a forked transaction.  This will only ever
// be called for 3xx/4xx/5xx/6xx response codes.
//
// @returns +1 if sc1 is better than sc2
//          0 if sc1 and sc2 are identical (or equally as good)
//          -1 if sc2 is better than sc1
//
static int compare_sip_sc(int sc1, int sc2)
{
  // Order is: (best) 487, 300, 301, ..., 698, 699, 408 (worst).
  if (sc1 == sc2)
  {
    // Status codes are equal.
    return 0;
  }
  else if (sc1 == PJSIP_SC_REQUEST_TIMEOUT)
  {
    // A timeout response is never better than anything else.
    return -1;
  }
  else if (sc2 == PJSIP_SC_REQUEST_TIMEOUT)
  {
    // A non-timeout response is always better than a timeout.
    return 1;
  }
  else if (sc2 == PJSIP_SC_REQUEST_TERMINATED)
  {
    // Request terminated is always better than anything else because
    // this should only happen if transaction is CANCELLED by originator
    // and this will be the expected response.
    return -1;
  }
  else if (sc1 == PJSIP_SC_REQUEST_TERMINATED)
  {
    return 1;
  }
  // Default behaviour is to favour the lowest number.
  else if (sc1 < sc2)
  {
    return 1;
  }
  else
  {
    return -1;
  }
}

/// Adds a Path header when functioning as an edge proxy.
///
/// We're the edge-proxy and thus supplying outbound support for the client.
/// The path header consists of a SIP URI with our host and a user portion that
/// identifies the client flow.
static pj_status_t add_path(pjsip_tx_data* tdata,
                            const Flow* flow_data,
                            const pjsip_rx_data* rdata)
{
  // Determine if the connection is secured (so we use the correct scheme in the
  // generated Path header).
  pjsip_to_hdr* to_hdr = rdata->msg_info.to;
  pj_bool_t secure = (to_hdr != NULL) ? PJSIP_URI_SCHEME_IS_SIPS(to_hdr->uri) : false;

  pjsip_sip_uri* path_uri = pjsip_sip_uri_create(tdata->pool, secure);
  path_uri->port = stack_data.pcscf_trusted_port;
  path_uri->transport_param = pj_str("TCP");
  path_uri->lr_param = 1;

  // Specify this particular node, as only we can find the client.
  path_uri->host = stack_data.local_host;

  // Add the flow token and "ob" parameter.
  pj_strdup2(tdata->pool, &path_uri->user, flow_data->token().c_str());

  if (PJUtils::is_first_hop(rdata->msg_info.msg))
  {
    // We own the outbound flow to the UAC.  We must indicate that by adding
    // the ob parameter.
    pjsip_param *ob_node = PJ_POOL_ALLOC_T(tdata->pool, pjsip_param);
    pj_strdup2(tdata->pool, &ob_node->name, "ob");
    pj_strdup2(tdata->pool, &ob_node->value, "");
    pj_list_insert_after(&path_uri->other_param, ob_node);
  }

  // Add the path header.
  pjsip_routing_hdr* path_hdr = identity_hdr_create(tdata->pool, STR_PATH);
  path_hdr->name_addr.uri = (pjsip_uri*)path_uri;
  pjsip_msg_insert_first_hdr(tdata->msg, (pjsip_hdr*)path_hdr);

  return PJ_SUCCESS;
}


///@}
