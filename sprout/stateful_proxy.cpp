/**
 * @file stateful_proxy.cpp Stateful proxy implementation
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
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
/// * optionally, do proxy_process_edge_routing
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
#include "sasevent.h"
#include "analyticslogger.h"
#include "regdata.h"
#include "stateful_proxy.h"
#include "callservices.h"
#include "constants.h"
#include "enumservice.h"
#include "bgcfservice.h"
#include "connection_pool.h"
#include "flowtable.h"
#include "trustboundary.h"
#include "sessioncase.h"
#include "ifchandler.h"
#include "aschain.h"
#include "registration_utils.h"

static RegData::Store* store;

static CallServices* call_services_handler;
static IfcHandler* ifc_handler;

static AnalyticsLogger* analytics_logger;

static EnumService *enum_service;
static BgcfService *bgcf_service;

static bool edge_proxy;
static pjsip_uri* upstream_proxy;
static ConnectionPool* upstream_conn_pool;
static FlowTable* flow_table;
static AsChainTable* as_chain_table;

static bool ibcf = false;

PJUtils::host_list_t trusted_hosts(&PJUtils::compare_pj_sockaddr);

//
// mod_stateful_proxy is the module to receive SIP request and
// response message that is outside any transaction context.
//
static pj_bool_t proxy_on_rx_request(pjsip_rx_data *rdata );
static pj_bool_t proxy_on_rx_response(pjsip_rx_data *rdata );

static pjsip_module mod_stateful_proxy =
{
  NULL, NULL,                         // prev, next
  pj_str("mod-stateful-proxy"),       // Name
  -1,                                 // Id
  PJSIP_MOD_PRIORITY_UA_PROXY_LAYER+1,// Priority
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
static pj_status_t proxy_verify_request(pjsip_rx_data *rdata);
#ifndef UNIT_TEST
static
#endif
pj_status_t proxy_process_edge_routing(pjsip_rx_data *rdata,
                                       pjsip_tx_data *tdata,
                                       TrustBoundary **trust);
static bool ibcf_trusted_peer(const pj_sockaddr& addr);
static pj_status_t proxy_process_routing(pjsip_tx_data *tdata);


// Helper functions.
static int compare_sip_sc(int sc1, int sc2);
static pj_bool_t is_uri_routeable(const pjsip_uri* uri);
static pj_bool_t is_user_numeric(const std::string& user);
static pj_status_t add_path(pjsip_tx_data* tdata,
                            const Flow* flow_data,
                            const pjsip_rx_data* rdata);


///@{
// MAIN ENTRY POINTS

// Callback to be called to handle new incoming requests.  Subsequent
// responses/requests will be handled by UA[SC]Transaction methods.
static pj_bool_t proxy_on_rx_request(pjsip_rx_data *rdata)
{
  LOG_DEBUG("Proxy RX request");

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

  // Create response to be forwarded upstream (Via will be stripped here)
  status = PJUtils::create_response_fwd(stack_data.endpt, rdata, 0, &tdata);
  if (status != PJ_SUCCESS)
  {
    LOG_ERROR("Error creating response, %s",
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
  res_addr.dst_host.type = PJSIP_TRANSPORT_UDP;
  res_addr.dst_host.flag =
    pjsip_transport_get_flag_from_type(PJSIP_TRANSPORT_UDP);

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

  // Report a SIP call ID marker on the trail to make sure it gets
  // associated with the INVITE transaction at SAS.
  if (rdata->msg_info.cid != NULL)
  {
    SAS::Marker cid(get_trail(rdata), SASMarker::SIP_CALL_ID, 3u);
    cid.add_var_param(rdata->msg_info.cid->id.slen, rdata->msg_info.cid->id.ptr);
    SAS::report_marker(cid, SAS::Marker::Scope::TrailGroup);
  }

  // We don't know the transaction, so be pessimistic and strip
  // everything.
  TrustBoundary::process_stateless_message(tdata);

  // Forward response
  status = pjsip_endpt_send_response(stack_data.endpt, &res_addr, tdata,
                                     NULL, NULL);
  if (status != PJ_SUCCESS)
  {
    LOG_ERROR("Error forwarding response, %s",
              PJUtils::pj_status_to_string(status).c_str());
    return PJ_TRUE;
  }

  return PJ_TRUE;
}


// Callback to be called to handle transaction state changed.
static void tu_on_tsx_state(pjsip_transaction *tsx, pjsip_event *event)
{
  LOG_DEBUG("%s - tu_on_tsx_state %s, %s %s state=%s",
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
  target* target = NULL;
  TrustBoundary* trust = &TrustBoundary::TRUSTED;

  // Verify incoming request.
  status = proxy_verify_request(rdata);
  if (status != PJ_SUCCESS)
  {
    LOG_ERROR("RX invalid request, %s",
              PJUtils::pj_status_to_string(status).c_str());
    return;
  }

  // Request looks sane, so clone the request to create transmit data.
  status = PJUtils::create_request_fwd(stack_data.endpt, rdata, NULL, NULL, 0, &tdata);
  if (status != PJ_SUCCESS)
  {
    LOG_ERROR("Failed to clone request to forward");
    PJUtils::respond_stateless(stack_data.endpt, rdata,
                               PJSIP_SC_INTERNAL_SERVER_ERROR,
                               NULL, NULL, NULL);
    return;
  }

  if (edge_proxy)
  {
    // Process edge proxy routing.  This also does IBCF function if enabled.
    status = proxy_process_edge_routing(rdata, tdata, &trust);
    if (status != PJ_SUCCESS)
    {
      // Delete the request since we're not forwarding it
      pjsip_tx_data_dec_ref(tdata);
      return;
    }
  }
  else
  {
    // Process route information for routing proxy.
    pjsip_route_hdr* hroute = (pjsip_route_hdr*)pjsip_msg_find_hdr(tdata->msg, PJSIP_H_ROUTE, NULL);
    if ((hroute) &&
        ((PJUtils::is_home_domain(hroute->name_addr.uri)) ||
         (PJUtils::is_uri_local(hroute->name_addr.uri))))
    {
      // This is our own Route header, containing a SIP URI.  Check for an
      // ODI token.  We need to determine the session case: is
      // this an originating request or not - see 3GPP TS 24.229
      // s5.4.3.1, s5.4.1.2.2F and the behaviour of
      // proxy_calculate_targets as an edge proxy.
      pjsip_sip_uri* uri = (pjsip_sip_uri*)hroute->name_addr.uri;
      pjsip_param* orig_param = pjsip_param_find(&uri->other_param, &STR_ORIG);
      const SessionCase* session_case = (orig_param != NULL) ? &SessionCase::Originating : &SessionCase::Terminating;

      AsChainLink original_dialog;
      if (pj_strncmp(&uri->user, &STR_ODI_PREFIX, STR_ODI_PREFIX.slen) == 0)
      {
        // This is one of our original dialog identifier (ODI) tokens.
        // See 3GPP TS 24.229 s5.4.3.4.
        std::string odi_token = std::string(uri->user.ptr + STR_ODI_PREFIX.slen,
                                            uri->user.slen - STR_ODI_PREFIX.slen);
        original_dialog = as_chain_table->lookup(odi_token);

        if (original_dialog.is_set())
        {
          LOG_INFO("Original dialog for %.*s found: %s",
                   uri->user.slen, uri->user.ptr,
                   original_dialog.to_string().c_str());
          session_case = &original_dialog.session_case();

          // This message forms part of the AsChain trail.
          set_trail(rdata, original_dialog.trail());
        }
        else
        {
          // We're in the middle of an AS chain, but we've lost our
          // reference to the rest of the chain. We must not carry on
          // - fail the request with a suitable error code.
          LOG_ERROR("Original dialog lookup for %.*s not found",
                    uri->user.slen, uri->user.ptr);
          pjsip_tx_data_dec_ref(tdata);
          PJUtils::respond_stateless(stack_data.endpt, rdata,
                                     PJSIP_SC_BAD_REQUEST, NULL,
                                     NULL, NULL);
          return;
        }
      }

      LOG_DEBUG("Got our Route header, session case %s, OD=%s",
                session_case->to_string().c_str(),
                original_dialog.to_string().c_str());
      serving_state = ServingState(session_case, original_dialog);
    }

    // Do standard processing of Route headers.
    status = proxy_process_routing(tdata);

    if (status != PJ_SUCCESS)
    {
      LOG_ERROR("Error processing route, %s",
                PJUtils::pj_status_to_string(status).c_str());
      return;
    }
  }

  // We now know various details of this transaction:
  LOG_DEBUG("Trust mode %s, serving state %s",
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
    // associated with the INVITE transaction at SAS.
    if (rdata->msg_info.cid != NULL)
    {
      SAS::Marker cid(get_trail(rdata), SASMarker::SIP_CALL_ID, 2u);
      cid.add_var_param(rdata->msg_info.cid->id.slen, rdata->msg_info.cid->id.ptr);
      SAS::report_marker(cid, SAS::Marker::Scope::TrailGroup);
    }

    trust->process_request(tdata);
    status = pjsip_endpt_send_request_stateless(stack_data.endpt, tdata,
                                                NULL, NULL);
    if (status != PJ_SUCCESS)
    {
      LOG_ERROR("Error forwarding request, %s",
                PJUtils::pj_status_to_string(status).c_str());
    }

    return;
  }

  status = UASTransaction::create(rdata, tdata, trust, &uas_data);
  if (status != PJ_SUCCESS)
  {
    LOG_ERROR("Failed to create UAS transaction, %s",
              PJUtils::pj_status_to_string(status).c_str());

    // Delete the request since we're not forwarding it
    pjsip_tx_data_dec_ref(tdata);
    PJUtils::respond_stateless(stack_data.endpt, rdata,
                               PJSIP_SC_INTERNAL_SERVER_ERROR, NULL,
                               NULL, NULL);
    return;
  }

  // Perform common initial processing.
  uas_data->enter_context();
  AsChainLink as_chain_link = uas_data->handle_incoming_non_cancel(rdata, tdata, serving_state);

  AsChainLink::Disposition disposition = AsChainLink::Disposition::Next;

  if ((!edge_proxy) &&
      ((PJUtils::is_home_domain(tdata->msg->line.req.uri)) ||
       (PJUtils::is_uri_local(tdata->msg->line.req.uri))))
  {
    // Do services and translation processing for requests targeted at this
    // node/home domain.

    // Do incoming (originating) half.
    disposition = uas_data->handle_originating(as_chain_link, rdata, tdata, &target);

    if (disposition == AsChainLink::Disposition::Next)
    {
      // Do outgoing (terminating) half.
      LOG_DEBUG("Terminating half");
      disposition = uas_data->handle_terminating(as_chain_link, tdata, &target);
    }
  }

  uas_data->exit_context();

  if (disposition != AsChainLink::Disposition::Stop)
  {
    // Perform common outgoing processing.
    uas_data->handle_outgoing_non_cancel(tdata, target);
  }

  delete target;
}


/// Process a received CANCEL request
///
void process_cancel_request(pjsip_rx_data* rdata)
{
  // This is CANCEL request
  pjsip_transaction *invite_uas;
  pj_str_t key;

  // Find the UAS INVITE transaction
  pjsip_tsx_create_key(rdata->tp_info.pool, &key, PJSIP_UAS_ROLE,
                       pjsip_get_invite_method(), rdata);
  invite_uas = pjsip_tsx_layer_find_tsx(&key, PJ_TRUE);
  if (!invite_uas)
  {
    // Invite transaction not found, respond to CANCEL with 481
    PJUtils::respond_stateless(stack_data.endpt, rdata, 481, NULL,
                               NULL, NULL);
    return;
  }

  // Respond 200 OK to CANCEL.  Must do this statefully.
  pjsip_transaction* tsx;
  pj_status_t status = pjsip_tsx_create_uas(NULL, rdata, &tsx);
  if (status != PJ_SUCCESS)
  {
    PJUtils::respond_stateless(stack_data.endpt, rdata,
                               PJSIP_SC_INTERNAL_SERVER_ERROR,
                               NULL, NULL, NULL);
    return;
  }

  // Feed the CANCEL request to the transaction.
  pjsip_tsx_recv_msg(tsx, rdata);

  // Send the 200 OK statefully.
  PJUtils::respond_stateful(stack_data.endpt, tsx, rdata, 200, NULL, NULL, NULL);

  pj_bool_t integrity_protected = PJ_FALSE;

  if (edge_proxy)
  {
    // Check whether the CANCEL has arrived on an integrity protected
    // connection.  The CANCEL isn't rejected if it hasn't because it may
    // have come from a Sprout node anyway - but we need to know whether
    // to mark the ongoing CANCELs as integrity protected.
    Flow* flow_data = flow_table->find_flow(rdata->tp_info.transport,
                                            &rdata->pkt_info.src_addr);

    if ((flow_data != NULL) && (flow_data->authenticated()))
    {
      integrity_protected = PJ_TRUE;
    }
  }

  // Send CANCEL to cancel the UAC transactions.
  // The UAS INVITE transaction will get final response when
  // we receive final response from the UAC INVITE transaction.
  LOG_DEBUG("%s - Cancel for UAS transaction", invite_uas->obj_name);
  UASTransaction *uas_data = UASTransaction::get_from_tsx(invite_uas);
  uas_data->cancel_pending_uac_tsx(0, integrity_protected);

  // Unlock UAS tsx because it is locked in find_tsx()
  pj_grp_lock_release(invite_uas->grp_lock);
}


// Proxy utility to verify incoming requests.
// Return non-zero if verification failed.
static pj_status_t proxy_verify_request(pjsip_rx_data *rdata)
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
  // We only want to support "sip:" URI scheme for this simple proxy.
  if (!PJSIP_URI_SCHEME_IS_SIP(rdata->msg_info.msg->line.req.uri))
  {
    PJUtils::respond_stateless(stack_data.endpt, rdata,
                               PJSIP_SC_UNSUPPORTED_URI_SCHEME, NULL,
                               NULL, NULL);
    return PJSIP_ERRNO_FROM_SIP_STATUS(PJSIP_SC_UNSUPPORTED_URI_SCHEME);
  }

  // 3. Max-Forwards.
  // Send error if Max-Forwards is 1 or lower.
  if (rdata->msg_info.max_fwd && rdata->msg_info.max_fwd->ivalue <= 1)
  {
    PJUtils::respond_stateless(stack_data.endpt, rdata,
                               PJSIP_SC_TOO_MANY_HOPS, NULL,
                               NULL, NULL);
    return PJSIP_ERRNO_FROM_SIP_STATUS(PJSIP_SC_TOO_MANY_HOPS);
  }

  // 4. (Optional) Loop Detection.
  // Nah, we don't do that with this simple proxy.

  // 5. Proxy-Require
  if (pjsip_msg_find_hdr_by_name(rdata->msg_info.msg, &STR_PROXY_REQUIRE,
                                 NULL) != NULL)
  {
    PJUtils::respond_stateless(stack_data.endpt, rdata,
                               PJSIP_SC_BAD_EXTENSION, NULL,
                               NULL, NULL);
    return PJSIP_ERRNO_FROM_SIP_STATUS(PJSIP_SC_BAD_EXTENSION);
  }

  // 6. Proxy-Authorization.
  // Nah, we don't require any authorization with this sample.

  return PJ_SUCCESS;
}


/// Perform edge-proxy-specific routing.
#ifndef UNIT_TEST
static
#endif
pj_status_t proxy_process_edge_routing(pjsip_rx_data *rdata,
                                       pjsip_tx_data *tdata,
                                       TrustBoundary **trust)
{
  pj_status_t status;
  Flow* src_flow = NULL;
  Flow* tgt_flow = NULL;


  LOG_DEBUG("Perform edge proxy routing for %.*s request",
            tdata->msg->line.req.method.name.slen, tdata->msg->line.req.method.name.ptr);

  if (tdata->msg->line.req.method.id == PJSIP_REGISTER_METHOD)
  {
    // Received a REGISTER request.  Check if we should act as the edge proxy
    // for the request.
    if (rdata->tp_info.transport->local_name.port == stack_data.trusted_port)
    {
      // Reject REGISTER request received from within the trust domain.
      LOG_DEBUG("Reject REGISTER received on trusted port");
      PJUtils::respond_stateless(stack_data.endpt,
                                 rdata,
                                 PJSIP_SC_METHOD_NOT_ALLOWED,
                                 NULL, NULL, NULL);
      return PJ_ENOTFOUND;
    }

    if ((ibcf) &&
        (ibcf_trusted_peer(rdata->pkt_info.src_addr)))
    {
      LOG_WARNING("Rejecting REGISTER request received over SIP trunk");
      PJUtils::respond_stateless(stack_data.endpt,
                                 rdata,
                                 PJSIP_SC_METHOD_NOT_ALLOWED,
                                 NULL, NULL, NULL);
      return PJ_ENOTFOUND;
    }

    // The REGISTER came from outside the trust domain and not over a SIP
    // trunk, so we must act as the edge proxy for the node.  (Previously
    // we would only act as edge proxy for nodes that requested it with
    // the outbound flag, or we detected were behind a NAT - now we have a
    // well-defined trust zone we have to do it for all nodes outside
    // the trust node.)
    LOG_DEBUG("Message requires outbound support");

    // Find or create a flow object to represent this flow.
    src_flow = flow_table->find_create_flow(rdata->tp_info.transport,
                                            &rdata->pkt_info.src_addr);

    if (src_flow == NULL)
    {
      LOG_ERROR("Failed to create flow data record");
      return PJ_ENOMEM; // LCOV_EXCL_LINE find_create_flow failure cases are all excluded already
    }

    LOG_DEBUG("Found or created flow data record, token = %s", src_flow->token().c_str());

    status = add_path(tdata, src_flow, rdata);
    if (status != PJ_SUCCESS)
    {
      return status; // LCOV_EXCL_LINE No failure cases exist.
    }

    // Treat the REGISTER request as a keepalive.  In theory we should
    // support STUN keepalives from clients, but only outbound aware
    // clients will support STUN keepalive so we don't rely on this.
    src_flow->keepalive();

    if (src_flow->authenticated())
    {
      // The message was received on a client flow that has already been
      // authenticated, so add an integrity-protected indication.
      PJUtils::add_integrity_protected_indication(tdata);
    }

    // Remove the reference to the source flow since we have finished with it
    src_flow->dec_ref();

    // Message from client. Allow client to provide data, but don't let it discover internal data.
    *trust = &TrustBoundary::INBOUND_EDGE_CLIENT;

    // Do standard route header processing for the request.  This may
    // remove the top route header if it corresponds to this node.
    proxy_process_routing(tdata);
  }
  else
  {
    // Non-register request.  First check for double-record routing and remove
    // extra Route header.
    pjsip_route_hdr* r1 = (pjsip_route_hdr*)pjsip_msg_find_hdr(tdata->msg, PJSIP_H_ROUTE, NULL);

    if ((r1) &&
        (PJSIP_URI_SCHEME_IS_SIP(r1->name_addr.uri)) &&
        (PJUtils::is_uri_local(r1->name_addr.uri)))
    {
      // The top route header was added by this node.  Check for cases
      // of double Record Routing and remove the extra Route header.
      LOG_DEBUG("Check for double Record-Routing");
      pjsip_route_hdr* r2 = (pjsip_route_hdr*)pjsip_msg_find_hdr(tdata->msg, PJSIP_H_ROUTE, r1->next);

      if ((r2) &&
          (PJSIP_URI_SCHEME_IS_SIP(r2->name_addr.uri)) &&
          (PJUtils::is_uri_local(r2->name_addr.uri)))
      {
        // Second route header was also added by this node, so check for
        // different transports or ports.
        pjsip_sip_uri* uri1 = (pjsip_sip_uri*)r1->name_addr.uri;
        pjsip_sip_uri* uri2 = (pjsip_sip_uri*)r2->name_addr.uri;
        if ((uri1->port != uri2->port) ||
            (pj_stricmp(&uri1->transport_param, &uri2->transport_param) != 0))
        {
          // Possible double record routing.  If one of the route headers doesn't
          // have a flow token it can safely be removed.
          LOG_DEBUG("Host names are the same and transports are different");
          if (uri1->user.slen == 0)
          {
            LOG_DEBUG("Remove top route header");
            pj_list_erase(r1);
          }
          else if (uri2->user.slen == 0)
          {
            LOG_DEBUG("Remove second route header");
            pj_list_erase(r2);
          }
        }
      }
    }

    // Work out whether the message has come from an implicitly trusted
    // source (that is, from within the trust zone, or over a known SIP
    // trunk), or a source we can now trust because it has been authenticated
    // (that is, a client flow).
    bool trusted = false;

    if (rdata->tp_info.transport->local_name.port != stack_data.trusted_port)
    {
      // Message received on untrusted port, so see if it came over a trunk
      // or on a known client flow.
      LOG_DEBUG("Message received on non-trusted port %d", rdata->tp_info.transport->local_name.port);
      if ((ibcf) &&
          (ibcf_trusted_peer(rdata->pkt_info.src_addr)))
      {
        LOG_DEBUG("Message received on configured SIP trunk");
        trusted = true;
        *trust = &TrustBoundary::INBOUND_TRUNK;
        PJUtils::add_integrity_protected_indication(tdata);
      }
      else
      {
        src_flow = flow_table->find_flow(rdata->tp_info.transport,
                                         &rdata->pkt_info.src_addr);
        if (src_flow != NULL)
        {
          // Message on a known client flow.
          LOG_DEBUG("Message received on known client flow");
          *trust = &TrustBoundary::INBOUND_EDGE_CLIENT;

          if (src_flow->authenticated())
          {
            // Client has been authenticated, so we can trust it for the
            // purposes of routing SIP messages and don't need to challenge
            // again.
            trusted = true;
            PJUtils::add_integrity_protected_indication(tdata);
          }
        }
        else
        {
          // Message was not received on a known flow, so treat it as an
          // unknown client for the purposes of header stripping.
          LOG_DEBUG("Message received from unknown client");
          *trust = &TrustBoundary::UNKNOWN_EDGE_CLIENT;
        }
      }
    }
    else
    {
      // Message received on a trusted port.
      LOG_DEBUG("Message received on trusted port");
      trusted = true;

      // See if the message is destined for a client.
      pjsip_route_hdr* route_hdr = (pjsip_route_hdr*)pjsip_msg_find_hdr(tdata->msg, PJSIP_H_ROUTE, NULL);

      if ((route_hdr) &&
          (PJSIP_URI_SCHEME_IS_SIP(route_hdr->name_addr.uri)) &&
          (PJUtils::is_uri_local(route_hdr->name_addr.uri)) &&
          (((pjsip_sip_uri*)route_hdr->name_addr.uri)->user.slen > 0))
      {
        // The user part is present, it should hold our token, so validate the
        // token.
        pjsip_sip_uri* sip_path_uri = (pjsip_sip_uri*)route_hdr->name_addr.uri;
        LOG_DEBUG("Flow identifier in Route header = %.*s", sip_path_uri->user.slen, sip_path_uri->user.ptr);
        tgt_flow = flow_table->find_flow(PJUtils::pj_str_to_string(&sip_path_uri->user));

        if (tgt_flow == NULL)
        {
          // We couldn't find the flow referenced in the
          // flow token, tell upstream that the flow failed.
          // Note: RFC 5626 specs that we should send a FORBIDDEN
          // if the token was invalid (as opposed to for a flow
          // that we don't have).  The authentication module
          // should handle that.
          LOG_ERROR("Route header flow identifier failed to correlate");
          if (rdata->msg_info.msg->line.req.method.id != PJSIP_ACK_METHOD)
          {
            PJUtils::respond_stateless(stack_data.endpt, rdata,
                                       SIP_STATUS_FLOW_FAILED,
                                       &SIP_REASON_FLOW_FAILED,
                                       NULL, NULL);
          }
          return PJ_ENOTFOUND;
        }

        // This must be a request for a client, so make sure it is routed
        // over the appropriate flow.
        LOG_DEBUG("Inbound request for client with flow identifier in Route header");
        pjsip_tpselector tp_selector;
        tp_selector.type = PJSIP_TPSELECTOR_TRANSPORT;
        tp_selector.u.transport = tgt_flow->transport();
        pjsip_tx_data_set_transport(tdata, &tp_selector);

        tdata->dest_info.addr.count = 1;
        tdata->dest_info.addr.entry[0].type = (pjsip_transport_type_e)tgt_flow->transport()->key.type;
        pj_memcpy(&tdata->dest_info.addr.entry[0].addr, tgt_flow->remote_addr(), sizeof(pj_sockaddr));
        tdata->dest_info.addr.entry[0].addr_len =
             (tdata->dest_info.addr.entry[0].addr.addr.sa_family == pj_AF_INET()) ?
             sizeof(pj_sockaddr_in) : sizeof(pj_sockaddr_in6);
        tdata->dest_info.cur_addr = 0;

        *trust = &TrustBoundary::OUTBOUND_EDGE_CLIENT;

        // If there is an authorization header remove it.
        pjsip_msg_find_remove_hdr(tdata->msg, PJSIP_H_AUTHORIZATION, NULL);
      }
    }

    pjsip_route_hdr* route_hdr = (pjsip_route_hdr*)pjsip_msg_find_hdr(tdata->msg, PJSIP_H_ROUTE, NULL);
    if (route_hdr &&
        (PJSIP_URI_SCHEME_IS_SIP(route_hdr->name_addr.uri)) &&
        (PJUtils::is_home_domain(route_hdr->name_addr.uri) ||
         PJUtils::is_uri_local(route_hdr->name_addr.uri)) &&
        pjsip_param_find(&reinterpret_cast<pjsip_sip_uri*>(pjsip_uri_get_uri(route_hdr->name_addr.uri))->other_param,
                         &STR_ORIG) &&
        (*trust != &TrustBoundary::INBOUND_EDGE_CLIENT))
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
      LOG_WARNING("Request for originating handling but not from known client");
      PJUtils::respond_stateless(stack_data.endpt,
                                 rdata,
                                 PJSIP_SC_FORBIDDEN,
                                 NULL, NULL, NULL);
      return PJ_ENOTFOUND;
    }

    // Do standard route header processing for the request.  This may
    // remove the top route header if it corresponds to this node.
    proxy_process_routing(tdata);

    // Work out the target for the message.  This will either be the URI in
    // the top route header, or the request URI.
    route_hdr = (pjsip_route_hdr*)pjsip_msg_find_hdr(tdata->msg, PJSIP_H_ROUTE, NULL);
    LOG_DEBUG("Destination is %s", (route_hdr != NULL) ? "top route header" : "Request-URI");
    pjsip_uri* target = (route_hdr != NULL) ? route_hdr->name_addr.uri : tdata->msg->line.req.uri;

    if ((!trusted) &&
        (!PJUtils::is_home_domain((pjsip_uri*)target)) &&
        (!PJUtils::is_uri_local((pjsip_uri*)target)))
    {
      // Message is from an untrusted source and destination is not Sprout, so
      // reject it.
      if (tdata->msg->line.req.method.id != PJSIP_ACK_METHOD)
      {
        LOG_WARNING("Rejecting message from untrusted source not directed to Sprout");
        PJUtils::respond_stateless(stack_data.endpt,
                                   rdata,
                                   PJSIP_SC_FORBIDDEN,
                                   NULL, NULL, NULL);
      }
      else
      {
        LOG_WARNING("Discard ACK from untrusted source no directed to Sprout");
      }
      return PJ_ENOTFOUND;
    }

    if ((ibcf) &&
        (tgt_flow == NULL) &&
        (PJSIP_URI_SCHEME_IS_SIP(target)))
    {
      // Check if the message is destined for a SIP trunk
      LOG_DEBUG("Check whether destination %.*s is a SIP trunk",
                ((pjsip_sip_uri*)target)->host.slen, ((pjsip_sip_uri*)target)->host.ptr);
      pj_sockaddr dest;
      if (pj_sockaddr_parse(pj_AF_UNSPEC(), 0, &((pjsip_sip_uri*)target)->host, &dest) == PJ_SUCCESS)
      {
        // Target host name is an IP address, so check against the IBCF trusted
        // peers.
        LOG_DEBUG("Parsed destination as an IP address, so check against trusted peers list");
        if (ibcf_trusted_peer(dest))
        {
          LOG_DEBUG("Destination is a SIP trunk");
          *trust = &TrustBoundary::OUTBOUND_TRUNK;
          pjsip_msg_find_remove_hdr(tdata->msg, PJSIP_H_AUTHORIZATION, NULL);
        }
      }
    }

    // Add suitable Record-Route header(s).
    LOG_DEBUG("Add record route header(s)");
    if (src_flow != NULL)
    {
      // Message is from a client, so add separate Record-Route headers for
      // the ingress and egress hops.
      LOG_DEBUG("Message received from client - double Record-Route");
      PJUtils::add_record_route(tdata, src_flow->transport()->type_name, src_flow->transport()->local_name.port, src_flow->token().c_str());
      PJUtils::add_record_route(tdata, "TCP", stack_data.trusted_port, NULL);
    }
    else if (tgt_flow != NULL)
    {
      // Message is destined for a client, so add separate Record-Route headers
      // for the ingress and egress hops.
      LOG_DEBUG("Message destined for client - double Record-Route");
      PJUtils::add_record_route(tdata, "TCP", stack_data.trusted_port, NULL);
      PJUtils::add_record_route(tdata, tgt_flow->transport()->type_name, tgt_flow->transport()->local_name.port, tgt_flow->token().c_str());
    }
    else if ((ibcf) && (*trust == &TrustBoundary::INBOUND_TRUNK))
    {
      // Received message on a trunk, so add separate Record-Route headers for
      // the ingress and egress hops.
      PJUtils::add_record_route(tdata, rdata->tp_info.transport->type_name, rdata->tp_info.transport->local_name.port, NULL);
      PJUtils::add_record_route(tdata, "TCP", stack_data.trusted_port, NULL);
    }
    else if ((ibcf) && (*trust == &TrustBoundary::OUTBOUND_TRUNK))
    {
      // Message destined for trunk, so add separate Record-Route headers for
      // the ingress and egress hops.
      PJUtils::add_record_route(tdata, "TCP", stack_data.trusted_port, NULL);
      PJUtils::add_record_route(tdata, "TCP", stack_data.untrusted_port, NULL);   // @TODO - transport type?
    }
    else
    {
      // Just do a single Record-Route.
      LOG_DEBUG("Single Record-Route");
      PJUtils::add_record_route(tdata, "TCP", stack_data.trusted_port, NULL);
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

  return PJ_SUCCESS;
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
  pjsip_sip_uri *target;
  pjsip_route_hdr *hroute;

  // RFC 3261 Section 16.4 Route Information Preprocessing

  target = (pjsip_sip_uri*) tdata->msg->line.req.uri;

  // The proxy MUST inspect the Request-URI of the request.  If the
  // Request-URI of the request contains a value this proxy previously
  // placed into a Record-Route header field (see Section 16.6 item 4),
  // the proxy MUST replace the Request-URI in the request with the last
  // value from the Route header field, and remove that value from the
  // Route header field.  The proxy MUST then proceed as if it received
  // this modified request.
  if (PJUtils::is_uri_local((pjsip_uri*)target))
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
      target = (pjsip_sip_uri*) tdata->msg->line.req.uri;
      pj_list_erase(hroute);
    }
  }

  // maddr handling for source routing is considered deprecated, so we don't
  // support it.  (See RFC 3261/19.1.1 - recommendation is to use Route headers
  // if requests must traverse a fixed set of proxies.)

  // If the first value in the Route header field indicates this proxy or
  // home domain, the proxy MUST remove that value from the request.
  hroute = (pjsip_route_hdr*)pjsip_msg_find_hdr(tdata->msg, PJSIP_H_ROUTE, NULL);
  if ((hroute) &&
      ((PJUtils::is_home_domain(hroute->name_addr.uri)) ||
       (PJUtils::is_uri_local(hroute->name_addr.uri))))
  {
    pj_list_erase(hroute);
  }

  return PJ_SUCCESS;
}

///@}

///@{
// IN-TRANSACTION PROCESSING

/// Calculate a list of targets for the message.
#ifndef UNIT_TEST
static
#endif
void proxy_calculate_targets(pjsip_msg* msg,
                             pj_pool_t* pool,
                             const TrustBoundary* trust,
                             target_list& targets,
                             int max_targets)
{
  // RFC 3261 Section 16.5 Determining Request Targets

  pjsip_sip_uri* req_uri = (pjsip_sip_uri*)msg->line.req.uri;

  // If the Request-URI of the request contains an maddr parameter, the
  // Request-URI MUST be placed into the target set as the only target
  // URI, and the proxy MUST proceed to Section 16.6.
  if (req_uri->maddr_param.slen)
  {
    LOG_INFO("Route request to maddr %.*s", req_uri->maddr_param.slen, req_uri->maddr_param.ptr);
    target target;
    target.from_store = PJ_FALSE;
    target.uri = (pjsip_uri*)req_uri;
    target.transport = NULL;
    targets.push_back(target);
    return;
  }

  // If the domain of the Request-URI indicates a domain this element is
  // not responsible for, the Request-URI MUST be placed into the target
  // set as the only target, and the element MUST proceed to the task of
  // Request Forwarding (Section 16.6).
  if ((!PJUtils::is_home_domain((pjsip_uri*)req_uri)) &&
      (!PJUtils::is_uri_local((pjsip_uri*)req_uri)))
  {
    LOG_INFO("Route request to domain %.*s", req_uri->host.slen, req_uri->host.ptr);
    target target;
    target.from_store = PJ_FALSE;
    target.uri = (pjsip_uri*)req_uri;
    target.transport = NULL;

    if ((bgcf_service) &&
        (PJSIP_URI_SCHEME_IS_SIP(req_uri)))
    {
      // See if we have a configured route to the destination.
      std::string domain = PJUtils::pj_str_to_string(&((pjsip_sip_uri*)req_uri)->host);
      std::string bgcf_route = bgcf_service->get_route(domain);

      if (!bgcf_route.empty())
      {
        // BGCF configuration has a route to this destination, so translate to
        // a URI.
        pjsip_sip_uri* route_uri = pjsip_sip_uri_create(pool, false);
        pj_strdup2(pool, &route_uri->host, bgcf_route.c_str());
        route_uri->port = stack_data.trusted_port;
        route_uri->transport_param = pj_str("TCP");
        route_uri->lr_param = 1;
        target.paths.push_back((pjsip_uri*)route_uri);
      }
    }

    targets.push_back(target);
    return;
  }

  if (edge_proxy)
  {
    // We're an edge proxy and there wasn't a defined route in the message,
    // forward it to the upstream proxy to deal with.  We do this by adding
    // a target with the existing request URI and a path to the upstream
    // proxy.  If the request URI is a SIP URI with a domain/host that is not
    // the home domain, change it to use the home domain.
    LOG_INFO("Route request to upstream proxy %.*s",
             ((pjsip_sip_uri*)upstream_proxy)->host.slen,
             ((pjsip_sip_uri*)upstream_proxy)->host.ptr);
    target target;
    target.from_store = PJ_FALSE;
    if ((PJSIP_URI_SCHEME_IS_SIP(req_uri)) &&
        (!PJUtils::is_home_domain((pjsip_uri*)req_uri)))
    {
      // Change host/domain in target to use home domain.
      target.uri = (pjsip_uri*)pjsip_uri_clone(pool, req_uri);
      ((pjsip_sip_uri*)target.uri)->host = stack_data.home_domain;
    }
    else
    {
      // Use request URI unchanged.
      target.uri = (pjsip_uri*)req_uri;
    }

    // Route upstream.
    pjsip_sip_uri* upstream_uri = (pjsip_sip_uri*)pjsip_uri_clone(pool, upstream_proxy);
    if (trust == &TrustBoundary::INBOUND_EDGE_CLIENT)
    {
      // Mark it as originating, so Sprout knows to
      // apply originating handling.  In theory the UE ought to have
      // done this itself - see 3GPP TS 24.229 s5.1.1.2.1 200-OK d and
      // s5.1.2A.1.1 "The UE shall build a proper preloaded Route header" c
      // - but if we're here it didn't, so we do the work for it.
      LOG_DEBUG("Mark originating");
      pjsip_param *orig_param = PJ_POOL_ALLOC_T(pool, pjsip_param);
      pj_strdup(pool, &orig_param->name, &STR_ORIG);
      pj_strdup2(pool, &orig_param->value, "");
      pj_list_insert_after(&upstream_uri->other_param, orig_param);
    }
    target.paths.push_back((pjsip_uri*)upstream_uri);

    // Select a transport for the request.
    target.transport = upstream_conn_pool->get_connection();

    targets.push_back(target);
    return;
  }

  // If the target set for the request has not been predetermined as
  // described above, this implies that the element is responsible for the
  // domain in the Request-URI, and the element MAY use whatever mechanism
  // it desires to determine where to send the request.
  if (store)
  {
    // Look up the target in the registration data store.
    std::string aor = PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, (pjsip_uri*)req_uri);
    LOG_INFO("Look up targets in registration store: %s", aor.c_str());
    RegData::AoR* aor_data = store->get_aor_data(aor);

    // Pick up to max_targets bindings to attempt to contact.  Since
    // some of these may be stale, and we don't want stale bindings to
    // push live bindings out, we sort by expiry time and pick those
    // with the most distant expiry times.  See bug 45.
    std::list<RegData::AoR::Bindings::value_type> target_bindings;
    if (aor_data != NULL)
    {
      const RegData::AoR::Bindings& bindings = aor_data->bindings();
      if ((int)bindings.size() <= max_targets)
      {
        for (RegData::AoR::Bindings::const_iterator i = bindings.begin();
             i != bindings.end();
             ++i)
        {
          target_bindings.push_back(*i);
        }
      }
      else
      {
        std::multimap<int, RegData::AoR::Bindings::value_type> ordered;
        for (RegData::AoR::Bindings::const_iterator i = bindings.begin();
             i != bindings.end();
             ++i)
        {
          std::pair<int, RegData::AoR::Bindings::value_type> p = std::make_pair(i->second->_expires, *i);
          ordered.insert(p);
        }

        int num_contacts = 0;
        for (std::multimap<int, RegData::AoR::Bindings::value_type>::const_reverse_iterator i = ordered.rbegin();
             num_contacts < max_targets;
             ++i)
        {
          target_bindings.push_back(i->second);
          num_contacts++;
        }
      }
    }

    for (std::list<RegData::AoR::Bindings::value_type>::const_iterator i = target_bindings.begin();
         i != target_bindings.end();
         ++i)
    {
      RegData::AoR::Binding* binding = i->second;
      LOG_DEBUG("Target = %s", binding->_uri.c_str());
      bool useable_contact = true;
      target target;
      target.from_store = PJ_TRUE;
      target.aor = aor;
      target.binding_id = i->first;
      target.uri = PJUtils::uri_from_string(binding->_uri, pool);
      target.transport = NULL;
      if (target.uri == NULL)
      {
        LOG_WARNING("Ignoring badly formed contact URI %s for target %s",
                    binding->_uri.c_str(), aor.c_str());
        useable_contact = false;
      }
      else
      {
        for (std::list<std::string>::const_iterator j = binding->_path_headers.begin();
             j != binding->_path_headers.end();
             ++j)
        {
          pjsip_uri* path = PJUtils::uri_from_string(*j, pool);
          if (path != NULL)
          {
            target.paths.push_back(PJUtils::uri_from_string(*j, pool));
          }
          else
          {
            LOG_WARNING("Ignoring contact %s for target %s because of badly formed path header %s",
                        binding->_uri.c_str(), aor.c_str(), (*j).c_str());
            useable_contact = false;
            break;
          }
        }
      }

      if (useable_contact)
      {
        targets.push_back(target);
      }
    }

    delete aor_data;
  }
}


/// Attempt ENUM lookup if appropriate.
static pj_status_t translate_request_uri(pjsip_tx_data* tdata, SAS::TrailId trail)
{
  pj_status_t status = PJ_SUCCESS;
  std::string uri;

  if (PJSIP_URI_SCHEME_IS_SIP(tdata->msg->line.req.uri))
  {
    std::string user = PJUtils::pj_str_to_string(&((pjsip_sip_uri*)tdata->msg->line.req.uri)->user);
    if (is_user_numeric(user))
    {
      uri = enum_service->lookup_uri_from_user(user, trail);
    }
  }
  else
  {
    std::string user = PJUtils::pj_str_to_string(&((pjsip_other_uri*)tdata->msg->line.req.uri)->content);
    uri = enum_service->lookup_uri_from_user(user, trail);
  }

  if (!uri.empty())
  {
    pjsip_uri* req_uri = (pjsip_uri*)PJUtils::uri_from_string(uri, tdata->pool);
    if (req_uri != NULL)
    {
      LOG_DEBUG("Update request URI to %s", uri.c_str());
      tdata->msg->line.req.uri = req_uri;
    }
    else
    {
      LOG_WARNING("Badly formed URI %s from ENUM translation", uri.c_str());
      status = PJ_EINVAL;
    }
  }

  return status;
}


static void proxy_process_register_response(pjsip_rx_data* rdata)
{
  // Check to see if the REGISTER response contains a Path header.  If so
  // this is a signal that the registrar accepted the REGISTER and so
  // authenticated the client.
  pjsip_generic_string_hdr* path_hdr = (pjsip_generic_string_hdr*)
              pjsip_msg_find_hdr_by_name(rdata->msg_info.msg, &STR_PATH, NULL);
  if (path_hdr != NULL)
  {
    // The response has a Path header in it, so parse this to a URI so we can
    // check for a flow token.  Extract the field to a null terminated string
    // first since we can't guarantee it is null terminated in the message,
    // and pjsip_parse_uri requires a null terminated string.
    pj_str_t hvalue;
    pj_strdup_with_null(rdata->tp_info.pool, &hvalue, &path_hdr->hvalue);
    pjsip_sip_uri* path_uri = (pjsip_sip_uri*)
                                      pjsip_parse_uri(rdata->tp_info.pool,
                                                      hvalue.ptr,
                                                      hvalue.slen,
                                                      0);

    if ((path_uri != NULL) &&
        (path_uri->user.slen > 0))
    {
      // The Path header has a flow token, so see if this maps to a known
      // active flow.
      Flow* flow_data = flow_table->find_flow(PJUtils::pj_str_to_string(&path_uri->user));

      if (flow_data != NULL)
      {
        // The response correlates to an active flow.
        if (pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_CONTACT, NULL) != NULL)
        {
          // There are active contacts, so consider the flow authenticated.
          LOG_INFO("Mark client flow as authenticated");
          flow_data->set_authenticated();
        }
        else
        {
          // The are no active contacts, so the client is effectively
          // unregistered.  Clear the authenticated flag, so the next
          // REGISTER is challenged.
          //LOG_INFO("Mark client flow as un-authenticated");
          //flow_data->set_unauthenticated();
        }

        // Decrement the reference to the flow data
        flow_data->dec_ref();
      }
    }
  }
}

///@}

// UAS Transaction constructor
UASTransaction::UASTransaction(pjsip_transaction* tsx,
                               pjsip_rx_data* rdata,
                               pjsip_tx_data* tdata,
                               TrustBoundary* trust) :
                                                         _tsx(tsx),
                                                         _num_targets(0),
                                                         _pending_targets(0),
                                                         _ringing(PJ_FALSE),
                                                         _req(tdata),
                                                         _best_rsp(NULL),
                                                         _trust(trust),
                                                         _proxy(NULL),
                                                         _pending_destroy(false),
                                                         _context_count(0)
{
  for (int ii = 0; ii < MAX_FORKING; ++ii)
  {
    _uac_data[ii] = NULL;
  }

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
}

UASTransaction::~UASTransaction()
{
  LOG_DEBUG("UASTransaction destructor");

  pj_assert(_context_count == 0);

  if (_tsx != NULL)
  {
  _tsx->mod_data[mod_tu.id] = NULL;
  }

  if (method() == PJSIP_INVITE_METHOD)
  {
    // INVITE transaction has been terminated.  If there are any
    // pending UAC transactions they should be cancelled.
    cancel_pending_uac_tsx(0, PJ_TRUE);
  }

  // Disconnect all UAC transactions from the UAS transaction.
  LOG_DEBUG("Disconnect UAC transactions from UAS transaction");
  for (int ii = 0; ii < _num_targets; ++ii)
  {
    UACTransaction* uac_data = _uac_data[ii];
    if (uac_data != NULL)
    {
      dissociate(uac_data);
    }
  }

  if (_req != NULL)
  {
    LOG_DEBUG("Free original request");
    pjsip_tx_data_dec_ref(_req);
    _req = NULL;
  }

  if (_best_rsp != NULL)
  {
    // The pre-built response hasn't been used, so free it.
    LOG_DEBUG("Free un-used best response");
    pjsip_tx_data_dec_ref(_best_rsp);
    _best_rsp = NULL;
  }

  if (_proxy != NULL)
  {
    // The proxy is still around, so free it.
    LOG_DEBUG("Free proxy");
    delete _proxy;
    _proxy = NULL;
  }

  for (std::list<AsChain*>::iterator it = _victims.begin();
       it != _victims.end();
       ++it)
  {
    LOG_DEBUG("Delete AsChain");
    delete *it;
  }
  _victims.clear();

  LOG_DEBUG("UASTransaction destructor completed");
}

// Creates a PJSIP transaction and a corresponding UASTransaction.
//
// This should all be done in the UASTransaction constructor, but creating a
// PJSIP transaction can fail, and it's hard to fail a constructor.
//
// @returns status code indicating whether the operation was successful.
pj_status_t UASTransaction::create(pjsip_rx_data* rdata,
                                   pjsip_tx_data* tdata,
                                   TrustBoundary* trust,
                                   UASTransaction** uas_data_ptr)
{
  // Create a transaction for the UAS side.  We do this before looking
  // up targets because calculating targets may involve interacting
  // with an external database, and we need the transaction in place
  // early to ensure CANCEL gets handled correctly.
  pjsip_transaction* uas_tsx;
  pj_status_t status = pjsip_tsx_create_uas(&mod_tu, rdata, &uas_tsx);
  if (status != PJ_SUCCESS)
  {
    return status;
  }

  // Allocate UAS data to keep track of the transaction.
  *uas_data_ptr = new UASTransaction(uas_tsx, rdata, tdata, trust);

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


// Handle the incoming half of a non-CANCEL message.
AsChainLink UASTransaction::handle_incoming_non_cancel(pjsip_rx_data* rdata,
                                                        pjsip_tx_data* tdata,
                                                        const ServingState& serving_state)
{
  if ((!edge_proxy) &&
      (method() == PJSIP_INVITE_METHOD))
  {
    // If running in routing proxy mode send the 100 Trying response before
    // applying services and routing the request as both may involve
    // interacting with external databases.  When running in edge proxy
    // mode we hold off sending the 100 Trying until we've received one from
    // upstream so we can be sure we could route a subsequent CANCEL to the
    // right place.
    PJUtils::respond_stateful(stack_data.endpt, _tsx, rdata, 100, NULL, NULL, NULL);
  }

  // Strip any untrusted headers as required, so we don't pass them on.
  _trust->process_request(tdata);

  AsChainLink as_chain_link;

  if (serving_state.is_set())
  {
    if (serving_state.original_dialog().is_set())
    {
      // Pick up existing AS chain.
      as_chain_link = serving_state.original_dialog();

      if ((serving_state.session_case() == SessionCase::Terminating) &&
          !as_chain_link.matches_target(rdata))
      {
        // AS is retargeting per 3GPP TS 24.229 s5.4.3.3 step 3,
        // so create new AS chain.
        LOG_INFO("Request-URI has changed, retargeting");
        as_chain_link = create_as_chain(SessionCase::OriginatingCdiv,
                                        rdata);
      }
    }
    else
    {
      // No existing AS chain - create new.
      as_chain_link = create_as_chain(serving_state.session_case(),
                                      rdata);
    }

    if (serving_state.session_case().is_originating() &&
        ((!as_chain_link.is_set()) ||
         (as_chain_link.complete())))
    {
      // We've completed the originating half: switch to terminating
      // and look up again.  The served user changes here.
      LOG_DEBUG("Originating AS chain complete, move to terminating chain (1)");
      as_chain_link = move_to_terminating_chain(rdata, tdata);
    }
  }

  return as_chain_link;
}


// Perform originating handling.
// @Returns whether processing should stop, continue, or skip to the end.
AsChainLink::Disposition UASTransaction::handle_originating(AsChainLink& as_chain_link,
                                                        pjsip_rx_data* rdata,
                                                        pjsip_tx_data* tdata,
                                                        // OUT: target, if disposition is Skip
                                                        target** target)
{
  if (!(as_chain_link.is_set() && as_chain_link.session_case().is_originating()))
  {
    // No chain or not an originating (or orig-cdiv) session case.  Skip.
    return AsChainLink::Disposition::Next;
  }

  // Apply originating call services to the message
  LOG_DEBUG("Applying originating services");
  AsChainLink::Disposition disposition;
  disposition = as_chain_link.on_initial_request(call_services_handler, this, rdata->msg_info.msg, tdata, target);

  if (disposition == AsChainLink::Disposition::Next)
  {
    // @@@KSW We've done built-in services, but might need to proceed - what to do?
    // We've completed the originating half: switch to terminating
    // and look up iFCs again.  The served user changes here.
    // @@@KSW fix this up to loop if necessary
    LOG_DEBUG("Originating AS chain complete, move to terminating chain (2)");
    as_chain_link = move_to_terminating_chain(rdata, tdata);
  }

  LOG_INFO("Originating services disposition %d", (int)disposition);
  return disposition;
}


/// Move from originating to terminating handling.
AsChainLink UASTransaction::move_to_terminating_chain(pjsip_rx_data* rdata,
                                                      pjsip_tx_data* tdata)
{
  AsChainLink as_chain_link;

  // These headers name the originating user, so should not survive
  // the changearound to the terminating chain.
  PJUtils::delete_header(rdata->msg_info.msg, &STR_P_SERVED_USER);
  PJUtils::delete_header(tdata->msg, &STR_P_SERVED_USER);

  // Create new terminating chain.
  as_chain_link = create_as_chain(SessionCase::Terminating,
                                  rdata);

  return as_chain_link;
}

// Perform terminating handling.
// @Returns whether processing should stop, continue, or skip to the end.
AsChainLink::Disposition UASTransaction::handle_terminating(AsChainLink& as_chain_link,
                                                        pjsip_tx_data* tdata,
                                                        // OUT: target, if disposition is Skip
                                                        target** target)
{
  pj_status_t status;

  if (!edge_proxy &&
      (enum_service) &&
      (PJUtils::is_home_domain(tdata->msg->line.req.uri)) &&
      (!is_uri_routeable(tdata->msg->line.req.uri)))
  {
    // Request is targeted at this domain but URI is not currently
    // routeable, so translate it to a routeable URI.
    LOG_DEBUG("Translating URI");
    status = translate_request_uri(_req, trail());

    if (status != PJ_SUCCESS)
    {
      // An error occurred during URI translation.  This doesn't happen if
      // there is no match, only if there is a match but there is an error
      // performing the defined mapping.  We therefore reject the request
      // with the not found status code and a specific reason phrase.
      send_response(PJSIP_SC_NOT_FOUND, &SIP_REASON_ENUM_FAILED);
      return AsChainLink::Disposition::Stop;
    }

    if ((!PJUtils::is_home_domain(tdata->msg->line.req.uri)) &&
        (!PJUtils::is_e164((pjsip_uri*)pjsip_uri_get_uri(PJSIP_MSG_FROM_HDR(tdata->msg)->uri))))
    {
      // The URI has been translated to an off-net domain, but the user does
      // not have a valid E.164 number that can be used to make off-net calls.
      // Reject the call with a not found response code, which is about the
      // most suitable for this case.
      LOG_INFO("Rejecting off-net call from user without E.164 address");
      send_response(PJSIP_SC_NOT_FOUND, &SIP_REASON_OFFNET_DISALLOWED);
      return AsChainLink::Disposition::Stop;
    }
  }

  AsChainLink::Disposition disposition = AsChainLink::Disposition::Next;

  if (as_chain_link.is_set() && as_chain_link.session_case().is_terminating())
  {
    // Apply terminating call services to the message
    LOG_DEBUG("Apply terminating services");
    disposition = as_chain_link.on_initial_request(call_services_handler, this, tdata->msg, tdata, target);
    // On return from on_initial_request, our _proxy pointer
    // may be NULL.  Don't use it without checking first.

    // @@@KSW may be Next, in which case we might need to do more.
  }

  LOG_INFO("Terminating services disposition %d", (int)disposition);
  return disposition;
}

// Handle the outgoing half of a non-CANCEL message.
void UASTransaction::handle_outgoing_non_cancel(pjsip_tx_data* tdata, target* target)
{
  // Calculate targets
  target_list targets;
  if (target != NULL)
  {
    // Already have a target, so use it.
    targets.push_back(*target);
  }
  else
  {
    // Find targets.
    proxy_calculate_targets(tdata->msg, tdata->pool, _trust, targets, MAX_FORKING);
  }

  if (targets.size() == 0)
  {
    // No targets found, so reject with a 404 error - reuse the best_rsp
    // message.
    LOG_INFO("Reject request with 404");
    send_response(PJSIP_SC_NOT_FOUND);

    return;
  }

  // Now set up the data structures and transactions required to
  // process the request.
  pj_status_t status = init_uac_transactions(tdata, targets);

  if (status != PJ_SUCCESS)
  {
    // Send 500/Internal Server Error to UAS transaction */
    LOG_ERROR("Failed to allocate UAC transaction for UAS transaction");
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

  pjsip_tx_data *tdata;
  pj_status_t status;
  int status_code = rdata->msg_info.msg->line.status.code;

  if ((!edge_proxy) &&
      (method() == PJSIP_INVITE_METHOD) &&
      (status_code == 100))
  {
    // In routing proxy mode, don't forward 100 response for INVITE as it has
    // already been sent.
      LOG_DEBUG("%s - Discard 100/INVITE response", uac_data->name());
    return;
  }

  if ((edge_proxy) &&
      (method() == PJSIP_REGISTER_METHOD) &&
      (status_code == 200))
  {
    // Pass the REGISTER response to the edge proxy code to see if
    // the associated client flow has been authenticated.
    proxy_process_register_response(rdata);
  }

  status = PJUtils::create_response_fwd(stack_data.endpt, rdata, 0,
                                          &tdata);
  if (status != PJ_SUCCESS)
  {
    LOG_ERROR("Error creating response, %s",
              PJUtils::pj_status_to_string(status).c_str());
    return;
  }

  // Strip any untrusted headers as required, so we don't pass them on.
  _trust->process_response(tdata);

  if ((_proxy != NULL) &&
      (!_proxy->on_response(tdata->msg)))
  {
    // Proxy has taken control.  Stop processing now.
    pjsip_tx_data_dec_ref(tdata);
    return;
  }

  if (_num_targets > 1)
  {
    // Do special response filtering for forked transactions.
    if ((method() == PJSIP_INVITE_METHOD) &&
        (status_code == 180) &&
        (!_ringing))
    {
        LOG_DEBUG("%s - 180/INVITE Ringing response", uac_data->name());
      // We special case the first ringing response to an INVITE,
      // sending a ringing response to the originating UAC, but
      // pretending the response is from a UAS co-resident with the
      // proxy.
      pjsip_fromto_hdr *to;

      _ringing = PJ_TRUE;

      // Change the tag in the To header.
      to = (pjsip_fromto_hdr* )pjsip_msg_find_hdr(tdata->msg,
                                                  PJSIP_H_TO, NULL);
      if (to == NULL)
      {
        LOG_ERROR("No To header in INVITE response", 0);
        return;
      }

      to->tag = pj_str("xyz");

      // Contact header???

      // Forward response with the UAS transaction
      pjsip_tsx_send_msg(_tsx, tdata);
    }
    else if ((method() == PJSIP_INVITE_METHOD) &&
             (status_code > 100) &&
             (status_code < 199))
    {
      // Discard all other provisional responses to INVITE
      // transactions.
        LOG_DEBUG("%s - Discard 1xx/INVITE response", uac_data->name());
      pjsip_tx_data_dec_ref(tdata);
    }
    else if ((status_code > 100) &&
             (status_code < 199))
    {
      // Forward all provisional responses to non-INVITE transactions.
        LOG_DEBUG("%s - Forward 1xx/non-INVITE response", uac_data->name());

      // Forward response with the UAS transaction
      pjsip_tsx_send_msg(_tsx, tdata);
    }
    else if (status_code == 200)
    {
      // 200 OK.
        LOG_DEBUG("%s - Forward 200 OK response", name());

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
          LOG_DEBUG("%s - Terminate UAS INVITE transaction (forking case)", name());
        pjsip_tsx_terminate(_tsx, 200);
      }
    }
    else
    {
      // Final, non-OK response.  Is this the "best" response
      // received so far?
        LOG_DEBUG("%s - 3xx/4xx/5xx/6xx response", uac_data->name());
      pj_grp_lock_acquire(_tsx->grp_lock);
      if ((_best_rsp == NULL) ||
          (compare_sip_sc(status_code, _best_rsp->msg->line.status.code) > 0))
      {
          LOG_DEBUG("%s - Best 3xx/4xx/5xx/6xx response so far", uac_data->name());

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
          LOG_DEBUG("%s - All UAC responded", name());
        pj_grp_lock_release(_tsx->grp_lock);
        handle_final_response();
      }
      else
      {
        pj_grp_lock_release(_tsx->grp_lock);
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
        LOG_DEBUG("%s - Forward provisional response on UAS transaction", uac_data->name());
      pjsip_tsx_send_msg(_tsx, tdata);
    }
    else
    {
      // Forward final response.  Disconnect the UAC data from
      // the UAS data so no further events get passed between the two.
        LOG_DEBUG("%s - Final response, so disconnect UAS and UAC transactions", uac_data->name());
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
      LOG_DEBUG("%s - Forked request", uac_data->name());
    pj_grp_lock_acquire(_tsx->grp_lock);

    if (--_pending_targets == 0)
    {
      // Received responses on every UAC transaction, so
      // send the best response on the UAS transaction.
        LOG_DEBUG("%s - No more pending responses, so send response on UAC tsx", name());
      pj_grp_lock_release(_tsx->grp_lock);
      handle_final_response();
    }
    else
    {
      pj_grp_lock_release(_tsx->grp_lock);
    }
  }
  else
  {
    // UAC transaction has timed out or hit a transport error for
    // non-forked request.  Send a 408 on the UAS transaction.
      LOG_DEBUG("%s - Not forked request", uac_data->name());
    --_pending_targets;
    handle_final_response();
  }

  // Disconnect the UAC data from the UAS data so no further
  // events get passed between the two.
    LOG_DEBUG("%s - Disconnect UAS tsx from UAC tsx", uac_data->name());
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
    log_on_tsx_complete();
  }

  if (_tsx->state == PJSIP_TSX_STATE_DESTROYED)
  {
    LOG_DEBUG("%s - UAS tsx destroyed", _tsx->obj_name);
    if (method() == PJSIP_INVITE_METHOD)
    {
      // INVITE transaction has been terminated.  If there are any
      // pending UAC transactions they should be cancelled.
      cancel_pending_uac_tsx(0, PJ_TRUE);
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
  if ((_tsx != NULL) &&
      ((_proxy == NULL) ||
       (_proxy->on_final_response(_best_rsp))))
  {
    pjsip_tx_data *best_rsp = _best_rsp;
    int st_code = best_rsp->msg->line.status.code;
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
      LOG_DEBUG("%s - Terminate UAS INVITE transaction (non-forking case)",
                _tsx->obj_name);
      pjsip_tsx_terminate(_tsx, 200);
    }
  }
  return rc;
}


/// Register a proxy to handle future responses.  Ownership passes to
/// this transaction; it will be deleted when this transaction is
/// deleted.
void UASTransaction::register_proxy(CallServices::Terminating* proxy)
{
  pj_assert(_proxy == NULL);
  _proxy = proxy;
}


// Sends a response using the buffer saved off for the best response.
// @Returns whether or not the send was a success.
pj_status_t UASTransaction::send_response(int st_code, const pj_str_t* st_text)
{
  if ((st_code >= 100) && (st_code < 200))
  {
    pjsip_tx_data* prov_rsp = PJUtils::clone_tdata(_best_rsp);
    prov_rsp->msg->line.status.code = st_code;
    prov_rsp->msg->line.status.reason = (st_text != NULL) ? *st_text : *pjsip_get_status_text(st_code);
    set_trail(prov_rsp, trail());
    return pjsip_tsx_send_msg(_tsx, prov_rsp);
  }
  else
  {
    _best_rsp->msg->line.status.code = st_code;
    _best_rsp->msg->line.status.reason = (st_text != NULL) ? *st_text : *pjsip_get_status_text(st_code);
    return handle_final_response();
  }
}

// Redirects the call to the specified target, for the reason specified in the
// status code.
//
// @returns whether the call should continue as it was.
bool UASTransaction::redirect(std::string target, int code)
{
  pjsip_uri* target_uri = PJUtils::uri_from_string(target, _req->pool);

  if (target_uri == NULL)
  {
    // Target URI was badly formed, so continue processing the call without
    // the redirect.
    return true;
  }

  return redirect_int(target_uri, code);
}

// Enters this transaction's context.  While in the transaction's
// context, it will not be destroyed.  Whenever enter_context is called,
// exit_context must be called before the end of the method.
void UASTransaction::enter_context()
{
  // If the transaction is pending destroy, the context count must be greater
  // than 0.  Otherwise, the transaction should have already been destroyed (so
  // entering its context again is unsafe).
  pj_assert((!_pending_destroy) || (_context_count > 0));

  _context_count++;
}

// Exits this transaction's context.  On return from this method, the caller
// must not assume that the transaction still exists.
void UASTransaction::exit_context()
{
  // If the transaction is pending destroy, the context count must be greater
  // than 0.  Otherwise, the transaction should have already been destroyed (so
  // entering its context again is unsafe).
  pj_assert(_context_count > 0);

  _context_count--;
  if ((_context_count == 0) && (_pending_destroy))
  {
    delete this;
  }
}

// Redirects the call to the specified target, for the reason specified in the
// status code.
//
// @returns whether the call should continue as it was (always false).
bool UASTransaction::redirect(pjsip_uri* target, int code)
{
  return redirect_int((pjsip_uri*)pjsip_uri_clone(_req->pool, target), code);
}

// Generate analytics logs relating to a new transaction starting.
void UASTransaction::log_on_tsx_start(const pjsip_rx_data* rdata)
{
  // Store analytics data from request starting transaction.
  _analytics.from = (rdata->msg_info.from != NULL) ? (pjsip_from_hdr*)pjsip_hdr_clone(_tsx->pool, rdata->msg_info.from) : NULL;
  _analytics.to = (rdata->msg_info.to != NULL) ? (pjsip_to_hdr*)pjsip_hdr_clone(_tsx->pool, rdata->msg_info.to) : NULL;
  _analytics.cid = (rdata->msg_info.cid != NULL) ? (pjsip_cid_hdr*)pjsip_hdr_clone(_tsx->pool, rdata->msg_info.cid) : NULL;

  // Report SAS markers for the transaction.
  LOG_DEBUG("Report SAS start marker - trail (%llx)", trail());
  SAS::Marker start_marker(trail(), SASMarker::INIT_TIME, 1u);
  SAS::report_marker(start_marker);

  if (_analytics.from)
  {
    SAS::Marker calling_dn(trail(), SASMarker::CALLING_DN, 1u);
    pjsip_sip_uri* calling_uri = (pjsip_sip_uri*)pjsip_uri_get_uri(_analytics.from->uri);
    calling_dn.add_var_param(calling_uri->user.slen, calling_uri->user.ptr);
    SAS::report_marker(calling_dn);
  }

  if (_analytics.to)
  {
    SAS::Marker called_dn(trail(), SASMarker::CALLED_DN, 1u);
    pjsip_sip_uri* called_uri = (pjsip_sip_uri*)pjsip_uri_get_uri(_analytics.to->uri);
    called_dn.add_var_param(called_uri->user.slen, called_uri->user.ptr);
    SAS::report_marker(called_dn);
  }

  if (_analytics.cid)
  {
    SAS::Marker cid(trail(), SASMarker::SIP_CALL_ID, 1u);
    cid.add_var_param(_analytics.cid->id.slen, _analytics.cid->id.ptr);
    SAS::report_marker(cid, SAS::Marker::TrailGroup);
  }
}

// Generate analytics logs relating to a transaction completing.
void UASTransaction::log_on_tsx_complete()
{
  // Report SAS markers for the transaction.
  LOG_DEBUG("Report SAS end marker - trail (%llx)", trail());
  SAS::Marker end_marker(trail(), SASMarker::END_TIME, 1u);
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
pj_status_t UASTransaction::init_uac_transactions(pjsip_tx_data* tdata,
                                                  target_list& targets)
{
  pj_status_t status = PJ_EUNKNOWN;
  pjsip_transaction *uac_tsx;
  UACTransaction *uac_data;
  pjsip_tx_data *uac_tdata;

  if (_tsx != NULL)
  {
    // Initialise the UAC data structures for each target.
    int ii = 0;
    for (target_list::const_iterator it = targets.begin();
         it != targets.end();
         ++it)
    {
      // First UAC transaction can use existing tdata, others must clone.
      LOG_DEBUG("Allocating transaction and data for target %d", ii);
      uac_tdata = PJUtils::clone_tdata(tdata);

      if (uac_tdata == NULL)
      {
        status = PJ_ENOMEM;
        LOG_ERROR("Failed to clone request for forked transaction, %s",
                  PJUtils::pj_status_to_string(status).c_str());
        break;
      }

      status = pjsip_tsx_create_uac2(&mod_tu, uac_tdata, _tsx->grp_lock, &uac_tsx);
      if (status != PJ_SUCCESS)
      {
        LOG_ERROR("Failed to create UAC transaction, %s",
                  PJUtils::pj_status_to_string(status).c_str());
        break;
      }

      // Add the trail from the UAS transaction to the UAC transaction.
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
      for (target_list::const_iterator it = targets.begin();
           it != targets.end();
           ++it)
      {
        LOG_DEBUG("Updating request URI and route for target %d", ii);
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
void UASTransaction::cancel_pending_uac_tsx(int st_code, pj_bool_t integrity_protected)
{
  enter_context();

  // Send CANCEL on all pending UAC transactions forked from this UAS
  // transaction.  This is invoked either because the UAS transaction
  // received a CANCEL, or one of the UAC transactions received a 200 OK or
  // 6xx response.
  int ii;
  UACTransaction *uac_data;

  LOG_DEBUG("%s - Cancel %d pending UAC transactions",
            name(), _pending_targets);

  for (ii = 0; ii < _num_targets; ++ii)
  {
    uac_data = _uac_data[ii];
    LOG_DEBUG("%s - Check target %d, UAC data = %p, UAC tsx = %p",
              name(),
              ii,
              uac_data,
              (uac_data != NULL) ? uac_data->_tsx : NULL);
    if (uac_data != NULL)
    {
      // Found a UAC transaction that is still active, so send a CANCEL.
      uac_data->cancel_pending_tsx(st_code, integrity_protected);

      // Leave the UAC transaction connected to the UAS transaction so the
      // 487 response gets passed through.
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
  uac_data->_uas_data = NULL;
  _uac_data[uac_data->_target] = NULL;
}

// Redirects the call to the specified target, for the reason specified in the
// status code.
//
// This internal version of the method does not clone the provided URI, so it
// must have been allocated from a suitable pool.
//
// @returns whether the call should continue as it was (always false).
bool UASTransaction::redirect_int(pjsip_uri* target, int code)
{
  static const pj_str_t STR_HISTORY_INFO = pj_str("History-Info");
  static const pj_str_t STR_REASON = pj_str("Reason");
  static const pj_str_t STR_SIP = pj_str("SIP");
  static const pj_str_t STR_CAUSE = pj_str("cause");
  static const pj_str_t STR_TEXT = pj_str("text");
  static const int MAX_HISTORY_INFOS = 5;

  // Default the code to 480 Temporarily Unavailable.
  code = (code != 0) ? code : PJSIP_SC_TEMPORARILY_UNAVAILABLE;

  // Clear out any proxy.  Once we've done a redirect (or failed a
  // redirect), we can't apply further call services for the original
  // callee.
  if (_proxy != NULL)
  {
    delete _proxy;
    _proxy = NULL;
  }

  // Count the number of existing History-Info headers.
  int num_history_infos = 0;
  pjsip_history_info_hdr* prev_history_info_hdr = NULL;
  for (pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(_req->msg, &STR_HISTORY_INFO, NULL);
       hdr != NULL;
       hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(_req->msg, &STR_HISTORY_INFO, hdr->next))
  {
    ++num_history_infos;
    prev_history_info_hdr = (pjsip_history_info_hdr*)hdr;
  }

  // If we haven't already had too many redirections (i.e. History-Info
  // headers), do the redirect.
  if (num_history_infos < MAX_HISTORY_INFOS)
  {
    // Cancel pending UAC transactions and notify the originator.
    cancel_pending_uac_tsx(code, PJ_TRUE);
    send_response(PJSIP_SC_CALL_BEING_FORWARDED);

    // Set up the new target URI.
    _req->msg->line.req.uri = target;

    // Create a History-Info header.
    pjsip_history_info_hdr* history_info_hdr = pjsip_history_info_hdr_create(_req->pool);

    // Clone the URI and set up its parameters.
    pjsip_uri* history_info_uri = (pjsip_uri*)pjsip_uri_clone(_req->pool, (pjsip_uri*)pjsip_uri_get_uri(target));
    if (PJSIP_URI_SCHEME_IS_SIP(history_info_uri))
    {
      // Set up the Reason parameter - this is always "SIP".
      pjsip_sip_uri* history_info_sip_uri = (pjsip_sip_uri*)history_info_uri;
      pjsip_param *param = PJ_POOL_ALLOC_T(_req->pool, pjsip_param);
      param->name = STR_REASON;
      param->value = STR_SIP;
      pj_list_insert_before(&history_info_sip_uri->header_param, param);

      // Now add the cause parameter.
      param = PJ_POOL_ALLOC_T(_req->pool, pjsip_param);
      param->name = STR_CAUSE;
      char cause_text[4];
      sprintf(cause_text, "%u", code);
      pj_strdup2(_req->pool, &param->value, cause_text);
      pj_list_insert_before(&history_info_sip_uri->header_param, param);

      // Finally add the text parameter.
      param = PJ_POOL_ALLOC_T(_req->pool, pjsip_param);
      param->name = STR_TEXT;
      param->value = *pjsip_get_status_text(code);
      pj_list_insert_before(&history_info_sip_uri->header_param, param);
    }
    pjsip_name_addr* history_info_name_addr_uri = pjsip_name_addr_create(_req->pool);
    history_info_name_addr_uri->uri = history_info_uri;
    history_info_hdr->uri = (pjsip_uri*)history_info_name_addr_uri;

    // Set up the index parameter.  This is "1" if it is the first request and
    // the previous value suffixed with ".1" if not.
    if (prev_history_info_hdr == NULL)
    {
      history_info_hdr->index = pj_str("1");
    }
    else
    {
      history_info_hdr->index.slen = prev_history_info_hdr->index.slen + 2;
      history_info_hdr->index.ptr = (char*)pj_pool_alloc(_req->pool, history_info_hdr->index.slen);
      pj_memcpy(history_info_hdr->index.ptr, prev_history_info_hdr->index.ptr, prev_history_info_hdr->index.slen);
      pj_memcpy(history_info_hdr->index.ptr + prev_history_info_hdr->index.slen, ".1", 2);
    }
    // Add the History-Info header to the request.
    pjsip_msg_add_hdr(_req->msg, (pjsip_hdr*)history_info_hdr);

    // Kick off outgoing processing for the new request.
    handle_outgoing_non_cancel(_req, NULL);
  }
  else
  {
    send_response(code);
  }

  return false;
}


// UAC Transaction constructor
UACTransaction::UACTransaction(UASTransaction* uas_data,
                               int target,
                               pjsip_transaction* tsx,
                               pjsip_tx_data *tdata) : _uas_data(uas_data),
                                                       _target(target),
                                                       _tsx(tsx),
                                                       _tdata(tdata),
                                                       _from_store(false),
                                                       _aor(),
                                                       _binding_id(),
                                                       _pending_destroy(false),
                                                       _context_count(0)
{
  _tsx->mod_data[mod_tu.id] = this;
}

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

  if ((_tsx != NULL) &&
      (_tsx->state != PJSIP_TSX_STATE_TERMINATED) &&
      (_tsx->state != PJSIP_TSX_STATE_DESTROYED))
  {
    pjsip_tsx_terminate(_tsx, PJSIP_SC_INTERNAL_SERVER_ERROR);
  }

  _tsx = NULL;
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

// Set the target for this UAC transaction.
//
void UACTransaction::set_target(const struct target& target)
{
  enter_context();

  // Write the target in to the request.  Need to clone the URI to make
  // sure it comes from the right pool.
  _tdata->msg->line.req.uri = (pjsip_uri*)pjsip_uri_clone(_tdata->pool, target.uri);

  for (std::list<pjsip_uri*>::const_iterator pit = target.paths.begin();
       pit != target.paths.end();
       ++pit)
  {
    // We've got a path that should be added as a Route header.
    LOG_DEBUG("Adding a Route header to sip:%.*s%s%.*s",
              ((pjsip_sip_uri*)*pit)->user.slen, ((pjsip_sip_uri*)*pit)->user.ptr,
              (((pjsip_sip_uri*)*pit)->user.slen != 0) ? "@" : "",
              ((pjsip_sip_uri*)*pit)->host.slen, ((pjsip_sip_uri*)*pit)->host.ptr);
    pjsip_route_hdr* route_hdr = pjsip_route_hdr_create(_tdata->pool);
    route_hdr->name_addr.uri = (pjsip_uri*)pjsip_uri_clone(_tdata->pool, *pit);
    pjsip_msg_add_hdr(_tdata->msg, (pjsip_hdr*)route_hdr);

    // We no longer set the transport in the route header as it has no effect
    // and the transport should already be set in the path URI.
    //LOG_DEBUG("Explictly setting transport to TCP in Route header");
    //pj_list_init(&route_hdr->other_param);
    //pjsip_param *transport_param = PJ_POOL_ALLOC_T(_tdata->pool, pjsip_param);
    //pj_strdup2(_tdata->pool, &transport_param->name, "transport");
    //pj_strdup2(_tdata->pool, &transport_param->value, "tcp");
    //pj_list_insert_before(&route_hdr->other_param, transport_param);
  }

  if (target.from_store)
  {
    // This target came from the registration store, store the lookup keys.
    LOG_DEBUG("Target came from store, storing AoR = %s, binding_id = %s",
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

    // Remove the reference to the transport added when it was chosen.
    pjsip_transport_dec_ref(target.transport);
  }

  exit_context();
}

// Sends the initial request on this UAC transaction.
void UACTransaction::send_request()
{
  enter_context();

  if (_tdata->tp_sel.type == PJSIP_TPSELECTOR_TRANSPORT)
  {
    // The transport has already been selected for this request, so
    // add it to the transaction otherwise it will get overwritten.
    LOG_DEBUG("Transport %s (%s) pre-selected for transaction",
              _tdata->tp_sel.u.transport->obj_name,
              _tdata->tp_sel.u.transport->info);
    pjsip_tsx_set_transport(_tsx, &_tdata->tp_sel);
  }
  LOG_DEBUG("Sending request for %s", PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, _tdata->msg->line.req.uri).c_str());
  pj_status_t status = pjsip_tsx_send_msg(_tsx, _tdata);
  if (status != PJ_SUCCESS)
  {
    // Failed to send the request.
    pjsip_tx_data_dec_ref(_tdata);

    // The UAC transaction will have been destroyed when it failed to send
    // the request, so there's no need to destroy it.
  }
  _tdata = NULL;

  exit_context();
}

// Cancels the pending transaction, using the specified status code in the
// Reason header.
void UACTransaction::cancel_pending_tsx(int st_code, pj_bool_t integrity_protected)
{
  if (_tsx != NULL)
  {
    enter_context();

    LOG_DEBUG("Found transaction %s status=%d", name(), _tsx->status_code);
    pj_grp_lock_acquire(_tsx->grp_lock);
    if (_tsx->status_code < 200)
    {
      pjsip_tx_data *cancel;
      pjsip_endpt_create_cancel(stack_data.endpt, _tsx->last_tx, &cancel);
      if (st_code != 0)
      {
        char reason_val_str[96];
        const pj_str_t* st_text = pjsip_get_status_text(st_code);
        sprintf(reason_val_str, "SIP ;cause=%d ;text=\"%.*s\"", st_code, (int)st_text->slen, st_text->ptr);
        pj_str_t reason_name = pj_str("Reason");
        pj_str_t reason_val = pj_str(reason_val_str);
        pjsip_hdr* reason_hdr = (pjsip_hdr*)pjsip_generic_string_hdr_create(cancel->pool, &reason_name, &reason_val);
        pjsip_msg_add_hdr(cancel->msg, reason_hdr);
      }
      if ((edge_proxy) && (integrity_protected))
      {
        // Add integrity protected indication to the request so Sprout will
        // accept it.
        PJUtils::add_integrity_protected_indication(cancel);
      }
      set_trail(cancel, trail());

      if (_tsx->tp_sel.type == PJSIP_TPSELECTOR_TRANSPORT)
      {
        // The transaction being cancelled was forced to a particular transport,
        // so make sure the CANCEL uses this transport as well.
        pjsip_tx_data_set_transport(cancel, &_tsx->tp_sel);
      }

      LOG_DEBUG("Sending CANCEL request");
      pj_status_t status = pjsip_endpt_send_request(stack_data.endpt, cancel, -1, NULL, NULL);
      if (status != PJ_SUCCESS)
      {
        LOG_ERROR("Error sending CANCEL, %s", PJUtils::pj_status_to_string(status).c_str());
      }
    }
    pj_grp_lock_release(_tsx->grp_lock);

    exit_context();
  }
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
  LOG_DEBUG("%s - uac_data = %p, uas_data = %p", name(), this, _uas_data);
  if ((_uas_data != NULL) &&
      (event->body.tsx_state.type == PJSIP_EVENT_RX_MSG))
  {
    LOG_DEBUG("%s - RX_MSG on active UAC transaction", name());
    pjsip_rx_data* rdata = event->body.tsx_state.src.rdata;
    _uas_data->on_new_client_response(this, rdata);

    if (rdata->msg_info.msg->line.status.code == SIP_STATUS_FLOW_FAILED &&
        _from_store)
    {
      // We're the auth proxy and the flow we used failed, delete the
      // record of the flow.
      std::string aor = PJUtils::pj_str_to_string(&_aor);
      std::string binding_id = PJUtils::pj_str_to_string(&_binding_id);
      RegistrationUtils::network_initiated_deregistration(ifc_handler, store, aor, binding_id);
    }
  }

  // If UAC transaction is terminated because of a timeout, treat this as
  // a 504 error.
  if ((_tsx->state == PJSIP_TSX_STATE_TERMINATED) &&
      (_uas_data != NULL))
  {
    // UAC transaction has terminated while still connected to the UAS
    // transaction.
    LOG_DEBUG("%s - UAC tsx terminated while still connected to UAS tsx",
              _tsx->obj_name);
    if ((event->body.tsx_state.type == PJSIP_EVENT_TIMER) ||
        (event->body.tsx_state.type == PJSIP_EVENT_TRANSPORT_ERROR))
    {
      _uas_data->on_client_not_responding(this);
    }
    else
    {
      _uas_data->dissociate(this);
    }
  }

  if (_tsx->state == PJSIP_TSX_STATE_DESTROYED)
  {
    LOG_DEBUG("%s - UAC tsx destroyed", _tsx->obj_name);
    _tsx->mod_data[mod_tu.id] = NULL;
    _tsx = NULL;
    _pending_destroy = true;
  }

  exit_context();
}

// Enters this transaction's context.  While in the transaction's
// context, it will not be destroyed.  Whenever enter_context is called,
// exit_context must be called before the end of the method.
void UACTransaction::enter_context()
{
  // If the transaction is pending destroy, the context count must be greater
  // than 0.  Otherwise, the transaction should have already been destroyed (so
  // entering its context again is unsafe).
  pj_assert((!_pending_destroy) || (_context_count > 0));

  _context_count++;
}

// Exits this transaction's context.  On return from this method, the caller
// must not assume that the transaction still exists.
void UACTransaction::exit_context()
{
  // If the transaction is pending destroy, the context count must be greater
  // than 0.  Otherwise, the transaction should have already been destroyed (so
  // entering its context again is unsafe).
  pj_assert(_context_count > 0);

  _context_count--;
  if ((_context_count == 0) && (_pending_destroy))
  {
    delete this;
  }
}


///@{
// MODULE LIFECYCLE

pj_status_t init_stateful_proxy(RegData::Store* registrar_store,
                                CallServices* call_services,
                                IfcHandler* ifc_handler_in,
                                pj_bool_t enable_edge_proxy,
                                const std::string& edge_upstream_proxy,
                                int edge_upstream_proxy_connections,
                                int edge_upstream_proxy_recycle,
                                pj_bool_t enable_ibcf,
                                const std::string& ibcf_trusted_hosts,
                                AnalyticsLogger* analytics,
                                EnumService *enumService,
                                BgcfService *bgcfService)
{
  pj_status_t status;

  analytics_logger = analytics;
  store = registrar_store;

  call_services_handler = call_services;
  ifc_handler = ifc_handler_in;

  edge_proxy = enable_edge_proxy;
  if (edge_proxy)
  {
    // Create a URI for the upstream proxy to use in Route headers.
    upstream_proxy = (pjsip_uri*)pjsip_sip_uri_create(stack_data.pool, PJ_FALSE);
    ((pjsip_sip_uri*)upstream_proxy)->host = pj_strdup3(stack_data.pool, edge_upstream_proxy.c_str());
    ((pjsip_sip_uri*)upstream_proxy)->port = stack_data.trusted_port;
    ((pjsip_sip_uri*)upstream_proxy)->transport_param = pj_str("TCP");
    ((pjsip_sip_uri*)upstream_proxy)->lr_param = 1;

    // Create a flow table object to manage the client flow records.
    flow_table = new FlowTable;

    // Create a connection pool to the upstream proxy.
    pjsip_host_port pool_target;
    pool_target.host = pj_strdup3(stack_data.pool, edge_upstream_proxy.c_str());
    pool_target.port = stack_data.trusted_port;
    upstream_conn_pool = new ConnectionPool(&pool_target,
                                            edge_upstream_proxy_connections,
                                            edge_upstream_proxy_recycle,
                                            stack_data.pool,
                                            stack_data.endpt,
                                            stack_data.tcp_factory);
    upstream_conn_pool->init();

    ibcf = enable_ibcf;
    if (ibcf)
    {
      LOG_STATUS("Create list of trusted hosts");
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
          LOG_ERROR("Badly formatted trusted host %.*s", host.slen, host.ptr);
          return status;
        }
        char buf[100];
        LOG_STATUS("Adding host %s to list", pj_sockaddr_print(&sockaddr, buf, sizeof(buf), 1));
        trusted_hosts.insert(std::make_pair(sockaddr, true));
      }
    }
  }
  else
  {
    // Routing proxy (Sprout).

    as_chain_table = new AsChainTable;
  }

  enum_service = enumService;
  bgcf_service = bgcfService;

  status = pjsip_endpt_register_module(stack_data.endpt, &mod_stateful_proxy);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

  status = pjsip_endpt_register_module(stack_data.endpt, &mod_tu);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

  return PJ_SUCCESS;
}


void destroy_stateful_proxy()
{
  if (edge_proxy)
  {
    // Destroy the upstream connection pool.  This will quiesce all the TCP
    // connections.
    delete upstream_conn_pool; upstream_conn_pool = NULL;

    // Destroy the flow table.
    delete flow_table; flow_table = NULL;
  }
  else
  {
    delete as_chain_table; as_chain_table = NULL;
  }

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


// TODO: this will always return false until we have a better way to check
//       if a uri is routable
static pj_bool_t is_uri_routeable(const pjsip_uri* uri)
{
  return PJ_FALSE;
}


/// Determines whether a user string is purely numeric (maybe with a leading +).
// @returns PJ_TRUE if so, PJ_FALSE if not.
static pj_bool_t is_user_numeric(const std::string& user)
{
  for (size_t i = 0; i < user.size(); i++)
  {
    if ((!isdigit(user[i])) &&
        ((user[i] != '+') || (i != 0)))
    {
      return PJ_FALSE;
    }
  }
  return PJ_TRUE;
}

/// Adds a Path header when functioning as an edge proxy.
///
/// The path header consists of a SIP URI with our host and a user portion that
/// identifies the client flow.
static pj_status_t add_path(pjsip_tx_data* tdata,
                            const Flow* flow_data,
                            const pjsip_rx_data* rdata)
{
  pjsip_to_hdr* to_hdr = rdata->msg_info.to;
  pj_bool_t secure = (to_hdr != NULL) ? PJSIP_URI_SCHEME_IS_SIPS(to_hdr->uri) : false;

  // Create a path URI with our host name and port, and the flow token in
  // the user field.
  pjsip_sip_uri* path_uri = pjsip_sip_uri_create(tdata->pool, secure);
  pj_strdup2(tdata->pool, &path_uri->user, flow_data->token().c_str());
  path_uri->host = stack_data.local_host;
  path_uri->port = stack_data.trusted_port;
  path_uri->transport_param = pj_str("TCP");
  path_uri->lr_param = 1;

  if (PJUtils::is_first_hop(rdata->msg_info.msg))
  {
    // We own the outbound flow to the UAC.  We must indicate that by adding
    // the ob parameter.
    pjsip_param *ob_node = PJ_POOL_ALLOC_T(tdata->pool, pjsip_param);
    pj_strdup2(tdata->pool, &ob_node->name, "ob");
    pj_strdup2(tdata->pool, &ob_node->value, "");
    pj_list_insert_after(&path_uri->other_param, ob_node);
  }

  // Render the URI as a string.
  char buf[500];
  int len = pjsip_uri_print(PJSIP_URI_IN_ROUTING_HDR, path_uri, buf, sizeof(buf));
  pj_str_t path = {buf, len};

  // Add the path header.
  pjsip_hdr* path_hdr = (pjsip_hdr*)
               pjsip_generic_string_hdr_create(tdata->pool, &STR_PATH, &path);
  pjsip_msg_insert_first_hdr(tdata->msg, path_hdr);

  return PJ_SUCCESS;
}


/// Determine if the given user is registered in the registration data
/// store.
bool is_user_registered(std::string served_user)
{
  bool is_registered = false;

  if (store)
  {
    std::string aor = served_user;
    RegData::AoR* aor_data = store->get_aor_data(aor);
    is_registered = (aor_data != NULL) &&
      (aor_data->bindings().size() != 0u);
    delete aor_data; aor_data = NULL;
    LOG_DEBUG("User %s is %sregistered", aor.c_str(), is_registered ? "" : "un");
  }

  return is_registered;
}


/// Factory method: create AsChain by looking up iFCs.
AsChainLink UASTransaction::create_as_chain(const SessionCase& session_case,
                                            pjsip_rx_data* rdata)
{
  if (ifc_handler == NULL)
  {
    // LCOV_EXCL_START No easy way to hit.
    LOG_INFO("No IFC handler");
    return AsChainLink();
    // LCOV_EXCL_STOP
  }

  std::string served_user = ifc_handler->served_user_from_msg(session_case,
                                                              rdata);

  std::vector<AsInvocation> application_servers;
  bool is_registered = false;

  if (!served_user.empty())
  {
    is_registered = is_user_registered(served_user);

    ifc_handler->lookup_ifcs(session_case,
                             served_user,
                             is_registered,
                             rdata->msg_info.msg,
                             trail(),
                             application_servers);
  }

  AsChain* ret = new AsChain(as_chain_table,
                             session_case,
                             served_user,
                             is_registered,
                             trail(),
                             application_servers);
  _victims.push_back(ret);

  return AsChainLink(ret, 0u);
}

///@}

