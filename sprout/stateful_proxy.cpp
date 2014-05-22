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
#include "regstore.h"
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
#include "hssconnection.h"
#include "aschain.h"
#include "registration_utils.h"
#include "custom_headers.h"
#include "dialog_tracker.hpp"
#include "quiescing_manager.h"
#include "scscfselector.h"

static RegStore* store;
static RegStore* remote_store;

static CallServices* call_services_handler;
static IfcHandler* ifc_handler;

static AnalyticsLogger* analytics_logger;

static EnumService *enum_service;
static bool user_phone = false;
static bool global_only_lookups = false;
static BgcfService *bgcf_service;
static SCSCFSelector *scscf_selector;

static ACRFactory* cscf_acr_factory;
static ACRFactory* bgcf_acr_factory;
static ACRFactory* icscf_acr_factory;

static bool edge_proxy;
static pjsip_uri* upstream_proxy;
static ConnectionPool* upstream_conn_pool = NULL;
static FlowTable* flow_table;
static DialogTracker* dialog_tracker;
static AsChainTable* as_chain_table;
static HSSConnection* hss;
static pjsip_uri* icscf_uri = NULL;

static bool ibcf = false;
static bool icscf = false;
static bool scscf = false;
static bool allow_emergency_reg = false;

// Pre-built Record-Route header added to requests handled by the S-CSCF.
static pjsip_rr_hdr* scscf_rr;

// S-CSCF domain name.
static pj_str_t scscf_domain_name;


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
static pj_status_t proxy_process_routing(pjsip_tx_data *tdata);
static pj_bool_t proxy_trusted_source(pjsip_rx_data* rdata);


// Helper functions.
static int compare_sip_sc(int sc1, int sc2);
static pj_bool_t is_uri_routeable(const pjsip_uri* uri);
static pj_bool_t is_user_numeric(const std::string& user);
static pj_bool_t is_user_global(const std::string& user);
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

  // Only forward responses to INVITES
  if (rdata->msg_info.cseq->method.id == PJSIP_INVITE_METHOD)
  {
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

    // Report SIP call and branch ID markers on the trail to make sure it gets
    // associated with the INVITE transaction at SAS.
    PJUtils::mark_sas_call_branch_ids(get_trail(rdata), rdata->msg_info.cid, rdata->msg_info.msg);

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
  TrustBoundary* trust = &TrustBoundary::TRUSTED;
  Target *target = NULL;
  ACR* acr = NULL;

  // Verify incoming request.
  int status_code = proxy_verify_request(rdata);
  if (status_code != PJSIP_SC_OK)
  {
    reject_request(rdata, status_code);
    return;
  }

  // Request looks sane, so clone the request to create transmit data.
  status = PJUtils::create_request_fwd(stack_data.endpt, rdata, NULL, NULL, 0, &tdata);
  if (status != PJ_SUCCESS)
  {
    LOG_ERROR("Failed to clone request to forward");
    reject_request(rdata, PJSIP_SC_INTERNAL_SERVER_ERROR);
    return;
  }

  if (edge_proxy)
  {
    // Process access proxy routing.  This also does IBCF function if enabled.
    status_code = proxy_process_access_routing(rdata, tdata, &trust, &target);
    if (status_code != PJSIP_SC_OK)
    {
      // Request failed routing checks, so reject it.
      reject_request(rdata, status_code);

      // Delete the request since we're not forwarding it
      pjsip_tx_data_dec_ref(tdata);
      delete target;
      target = NULL;
      return;
    }
  }
  else
  {
    // Process route information for routing proxy.
    pjsip_route_hdr* hroute = rdata->msg_info.route;

    if ((hroute != NULL) &&
        ((PJUtils::is_home_domain(hroute->name_addr.uri)) ||
         (PJUtils::is_uri_local(hroute->name_addr.uri))))
    {
      // This is our own Route header, containing a SIP URI.  Check for an
      // ODI token.  We need to determine the session case: is
      // this an originating request or not - see 3GPP TS 24.229
      // s5.4.3.1, s5.4.1.2.2F and the behaviour of
      // proxy_calculate_targets as an access proxy.
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
          acr = original_dialog.acr();
          LOG_DEBUG("Retrieved ACR %p for existing AS chain", acr);
        }
        else
        {
          // We're in the middle of an AS chain, but we've lost our
          // reference to the rest of the chain. We must not carry on
          // - fail the request with a suitable error code.
          LOG_ERROR("Original dialog lookup for %.*s not found",
                    uri->user.slen, uri->user.ptr);
          pjsip_tx_data_dec_ref(tdata);
          reject_request(rdata, PJSIP_SC_BAD_REQUEST);
          return;
        }
      }

      LOG_DEBUG("Got our Route header, session case %s, OD=%s",
                session_case->to_string().c_str(),
                original_dialog.to_string().c_str());
      serving_state = ServingState(session_case, original_dialog);
    }
    else if (hroute == NULL)
    {
      // No Route header on the request.  This probably shouldn't happen, but
      // if it does we will treat it as a terminating request.
      LOG_DEBUG("No Route header, so treat as terminating request");
      serving_state = ServingState(&SessionCase::Terminating, AsChainLink());
    }

    // Do standard processing of Route headers.
    status = proxy_process_routing(tdata);

    if (status != PJ_SUCCESS)
    {
      LOG_ERROR("Error processing route, %s",
                PJUtils::pj_status_to_string(status).c_str());

      delete target;
      target = NULL;
      return;
    }
  }

  if (acr == NULL)
  {
    // We haven't found an existing ACR for this transaction, so create a new
    // one.
    LOG_DEBUG("Create new ACR for this transaction");
    acr = cscf_acr_factory->get_acr(get_trail(rdata), CALLING_PARTY);
  }

  // Pass the received request to the ACR.
  acr->rx_request(rdata->msg_info.msg, rdata->pkt_info.timestamp);

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
    // Any calculated target is going to be ignored, so clean up.
    delete target;
    target = NULL;

    // Report a SIP call ID marker on the trail to make sure it gets
    // associated with the INVITE transaction at SAS.  There's no need to
    // report the branch IDs as they won't be used for correlation.
    LOG_DEBUG("Statelessly forwarding ACK");
    PJUtils::mark_sas_call_branch_ids(get_trail(rdata), rdata->msg_info.cid, NULL);

    trust->process_request(tdata);

    acr->tx_request(tdata->msg);

    status = PJUtils::send_request_stateless(tdata);

    if (status != PJ_SUCCESS)
    {
      LOG_ERROR("Error forwarding request, %s",
                PJUtils::pj_status_to_string(status).c_str());
    }
    acr->send_message();
    delete acr;

    return;
  }

  // Create the transaction.  This implicitly enters its context, so we're
  // safe to operate on it (and have to exit its context below).
  status = UASTransaction::create(rdata, tdata, trust, acr, &uas_data);
  if (status != PJ_SUCCESS)
  {
    LOG_ERROR("Failed to create UAS transaction, %s",
              PJUtils::pj_status_to_string(status).c_str());

    // Delete the request since we're not forwarding it
    pjsip_tx_data_dec_ref(tdata);
    reject_request(rdata, PJSIP_SC_INTERNAL_SERVER_ERROR);
    delete acr;
    delete target;
    target = NULL;
    return;
  }

  if (!edge_proxy)
  {
    if (uas_data->method() == PJSIP_INVITE_METHOD)
    {
      // If running in routing proxy mode send the 100 Trying response before
      // applying services and routing the request as both may involve
      // interacting with external databases.  When running in access proxy
      // mode we hold off sending the 100 Trying until we've received one from
      // upstream so we can be sure we could route a subsequent CANCEL to the
      // right place.
      uas_data->send_trying(rdata);
    }
    else
    {
      // capture the rdata for deferral and schedule trying timer
      pjsip_rx_data_clone(rdata, 0, &(uas_data->_defer_rdata));
      uas_data->_trying_timer.id = uas_data->TRYING_TIMER;
      pj_time_val delay = {(PJSIP_T2_TIMEOUT - PJSIP_T1_TIMEOUT) / 1000,
                           (PJSIP_T2_TIMEOUT - PJSIP_T1_TIMEOUT) % 1000 };
      pjsip_endpt_schedule_timer(stack_data.endpt, &(uas_data->_trying_timer), &delay);
    }
  }

  // Perform common initial processing.  This will delete the
  // target if specified.
  uas_data->handle_non_cancel(serving_state, target);

  uas_data->exit_context();
}


/// Process a received CANCEL request
///
void process_cancel_request(pjsip_rx_data* rdata)
{
  pjsip_transaction *invite_uas;
  pj_str_t key;

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

  if ((edge_proxy) && (!proxy_trusted_source(rdata)))
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
  LOG_DEBUG("%s - Cancel for UAS transaction", invite_uas->obj_name);
  UASTransaction *uas_data = UASTransaction::get_from_tsx(invite_uas);
  uas_data->cancel_pending_uac_tsx(0, false);

  // Create and send an ACR for the CANCEL request.
  ACR* acr = cscf_acr_factory->get_acr(get_trail(rdata), CALLING_PARTY);
  acr->rx_request(rdata->msg_info.msg, rdata->pkt_info.timestamp);
  acr->send_message();
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
  // We support "sip:" and "tel:" URI schemes in this simple proxy.
  if (!(PJSIP_URI_SCHEME_IS_SIP(rdata->msg_info.msg->line.req.uri) ||
        PJSIP_URI_SCHEME_IS_TEL(rdata->msg_info.msg->line.req.uri)))
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
  pj_status_t status;

  ACR* acr = cscf_acr_factory->get_acr(get_trail(rdata), CALLING_PARTY);
  acr->rx_request(rdata->msg_info.msg, rdata->pkt_info.timestamp);

  if (rdata->msg_info.msg->line.req.method.id != PJSIP_ACK_METHOD)
  {
    // Not an ACK, so we should send a response.
    LOG_ERROR("Reject %.*s request with %d status code",
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
  acr->send_message();
  delete acr;
}

static SIPPeerType determine_source(pjsip_transport* transport, pj_sockaddr addr)
{
  if (transport == NULL)
  {
    LOG_DEBUG("determine_source called with a NULL pjsip_transport");
    return SIP_PEER_UNKNOWN;
  }
  if (transport->local_name.port == stack_data.pcscf_trusted_port)
  {
    // Request received on trusted port.
    LOG_DEBUG("Request received on trusted port %d", transport->local_name.port);
    return SIP_PEER_TRUSTED_PORT;
  }

  LOG_DEBUG("Request received on non-trusted port %d", transport->local_name.port);

  // Request received on untrusted port, so see if it came over a trunk.
  if ((ibcf) &&
      (ibcf_trusted_peer(addr)))
  {
    LOG_DEBUG("Request received on configured SIP trunk");
    return SIP_PEER_CONFIGURED_TRUNK;
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
        LOG_DEBUG("Request received on authenticated client flow.");
        trusted = PJ_TRUE;
      }
      src_flow->dec_ref();
    }
  }
  return trusted;
}

void UASTransaction::routing_proxy_record_route()
{
  pjsip_rr_hdr* top_rr = (pjsip_rr_hdr*)
                   pjsip_msg_find_hdr(_req->msg, PJSIP_H_RECORD_ROUTE, NULL);

  if ((top_rr == NULL) ||
      (pjsip_uri_cmp(PJSIP_URI_IN_ROUTING_HDR,
                     top_rr->name_addr.uri,
                     scscf_rr->name_addr.uri) != PJ_SUCCESS))
  {
    // The S-CSCF URI is not in the top Record-Route header, so add the
    // pre-built header.  It is not safe to do this with the pre-built header
    // from the global pool because the chaining data structures in the
    // header may get overwritten, but it is safe to do a shallow clone.
    pjsip_hdr* clone = (pjsip_hdr*)pjsip_hdr_shallow_clone(_req->pool, scscf_rr);
    pjsip_msg_insert_first_hdr(_req->msg, clone);
  }
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
    LOG_DEBUG("Top two route headers added by this node, checking transports and ports");
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
                                 TrustBoundary **trust,
                                 Target** target)
{
  // Forward it to the upstream proxy to deal with.  We do this by creating
  // a target with the existing request URI and a path to the upstream
  // proxy and stripping any loose routes that might have been added by the
  // UA.
  LOG_INFO("Route request to upstream proxy %.*s",
      ((pjsip_sip_uri*)upstream_proxy)->host.slen,
      ((pjsip_sip_uri*)upstream_proxy)->host.ptr);
  *target = new Target();
  Target* target_p = *target;
  target_p->upstream_route = PJ_TRUE;

  // Some trunks will send incoming requests directed at the IBCF node,
  // rather than determining the correct domain for the subscriber first.
  // In this case, we'll re-write the ReqURI to the default home domain.
  if ((*trust == &TrustBoundary::INBOUND_TRUNK) &&
      (PJSIP_URI_SCHEME_IS_SIP(tdata->msg->line.req.uri)) &&
      (PJUtils::is_uri_local((pjsip_uri*)tdata->msg->line.req.uri)))
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

  // Route upstream.
  pjsip_routing_hdr* route_hdr;
  pjsip_sip_uri* upstream_uri = (pjsip_sip_uri*)pjsip_uri_clone(tdata->pool,
                                                                upstream_proxy);

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
    LOG_DEBUG("Mark originating");
    pjsip_param *orig_param = PJ_POOL_ALLOC_T(tdata->pool, pjsip_param);
    pj_strdup(tdata->pool, &orig_param->name, &STR_ORIG);
    pj_strdup2(tdata->pool, &orig_param->value, "");
    pj_list_insert_after(&upstream_uri->other_param, orig_param);
  }

  // Select a transport for the request.
  if (upstream_conn_pool != NULL)
  {
    target_p->transport = upstream_conn_pool->get_connection();
  }

  target_p->paths.push_back((pjsip_uri*)upstream_uri);
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
  LOG_DEBUG("Perform access proxy routing for %.*s request",
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
      LOG_DEBUG("Rejecting emergency REGISTER request");
      return PJSIP_SC_SERVICE_UNAVAILABLE;
    }

    if (source_type == SIP_PEER_TRUSTED_PORT)
    {
      LOG_WARNING("Rejecting REGISTER request received from within the trust domain");
      return PJSIP_SC_METHOD_NOT_ALLOWED;
    }

    if (source_type == SIP_PEER_CONFIGURED_TRUNK)
    {
      LOG_WARNING("Rejecting REGISTER request received over SIP trunk");
      return PJSIP_SC_METHOD_NOT_ALLOWED;
    }

    // The REGISTER came from outside the trust domain and not over a SIP
    // trunk, so we must act as the access proxy for the node.
    LOG_DEBUG("Message requires outbound support");

    // Find or create a flow object to represent this flow.
    src_flow = flow_table->find_create_flow(rdata->tp_info.transport,
                                              &rdata->pkt_info.src_addr);

    if (src_flow == NULL)
    {
      LOG_ERROR("Failed to create flow data record");
      return PJSIP_SC_INTERNAL_SERVER_ERROR; // LCOV_EXCL_LINE find_create_flow failure cases are all excluded already
    }

    LOG_DEBUG("Found or created flow data record, token = %s", src_flow->token().c_str());

    // Reject the REGISTER with a 305 if Bono is trying to quiesce and
    // there are no active dialogs on this flow.
    if (src_flow->should_quiesce())
    {
      LOG_DEBUG("REGISTER request received on a quiescing flow - responding with 305");
      src_flow->dec_ref();
      return PJSIP_SC_USE_PROXY;
    }

    // Touch the flow to make sure it doesn't time out while we are waiting
    // for the REGISTER response from upstream.
    src_flow->touch();

    // Add an integrity-protected indicator if the message was received on a
    // client flow that has already been authenticated.  We don't add
    // integrity-protected=no otherwise as this would be interpreted by the
    // S-CSCF as a request to use AKA authentication.
    pjsip_to_hdr *to_hdr = PJSIP_MSG_TO_HDR(rdata->msg_info.msg);
    if (!src_flow->asserted_identity((pjsip_uri*)pjsip_uri_get_uri(to_hdr->uri)).empty())
    {
      PJUtils::add_integrity_protected_indication(tdata,
                                                  PJUtils::Integrity::IP_ASSOC_YES);
    }

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
    proxy_route_upstream(rdata, tdata, trust, target);

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
      LOG_DEBUG("Message received on non-trusted port %d", rdata->tp_info.transport->local_name.port);
      if (source_type == SIP_PEER_CONFIGURED_TRUNK)
      {
        LOG_DEBUG("Message received on configured SIP trunk");
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
          LOG_WARNING("Request for originating handling but not from known client");
          return PJSIP_SC_FORBIDDEN;
        }
      }
      else
      {
        src_flow = flow_table->find_flow(rdata->tp_info.transport,
                                         &rdata->pkt_info.src_addr);
        if (src_flow != NULL)
        {
          // Message on a known client flow.
          LOG_DEBUG("Message received on known client flow");

          // Get all the preferred identities from the message and remove
          // the P-Preferred-Identity headers.
          std::vector<pjsip_uri*> identities;
          extract_preferred_identities(tdata, identities);

          if (identities.size() > 2)
          {
            // Cannot have more than two preferred identities.
            LOG_DEBUG("Request has more than two P-Preferred-Identitys, rejecting");
            src_flow->dec_ref();
            return PJSIP_SC_FORBIDDEN;
          }
          else if (identities.size() == 0)
          {
            // No identities specified, so check there is valid default identity
            // and use it for the P-Asserted-Identity.
            LOG_DEBUG("Request has no P-Preferred-Identity headers, so check for default identity on flow");
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
            LOG_DEBUG("Request has one P-Preferred-Identity");
            if ((!PJSIP_URI_SCHEME_IS_SIP(identities[0])) &&
                (!PJSIP_URI_SCHEME_IS_TEL(identities[0])))
            {
              // Preferred identity must be sip, sips or tel URI.
              LOG_DEBUG("Invalid URI scheme in P-Preferred-Identity, rejecting");
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
            LOG_DEBUG("Request has two P-Preferred-Identitys");
            if (!(((PJSIP_URI_SCHEME_IS_SIP(identities[0])) &&
                   (PJSIP_URI_SCHEME_IS_TEL(identities[1]))) ||
                  ((PJSIP_URI_SCHEME_IS_TEL(identities[0])) &&
                   (PJSIP_URI_SCHEME_IS_SIP(identities[1])))))
            {
              // One identity must be sip or sips URI and the other must be
              // tel URI
              LOG_DEBUG("Invalid combination of URI schemes in P-Preferred-Identitys, rejecting");
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
        }
      }
    }
    else
    {
      // Message received on a trusted port.
      LOG_DEBUG("Message received on trusted port");
      trusted = true;

      // See if the message is destined for a client.
      pjsip_route_hdr* route_hdr;
      if ((PJUtils::is_top_route_local(tdata->msg, &route_hdr)) &&
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
          return SIP_STATUS_FLOW_FAILED;
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

    if (!trusted)
    {
      // Request is not from a trusted source, so reject or discard it.
      LOG_WARNING("Rejecting request from untrusted source");
      if (src_flow != NULL)
      {
        src_flow->dec_ref();
      }
      return PJSIP_SC_FORBIDDEN;
    }

    // Do standard route header processing for the request.  This may
    // remove the top route header if it corresponds to this node.
    proxy_process_routing(tdata);

    // Check if we have any Route headers.  If so, we'll follow them.  If not,
    // we get to choose where to route to, so route upstream to sprout.
    void* top_route = pjsip_msg_find_hdr(tdata->msg, PJSIP_H_ROUTE, NULL);
    if (top_route)
    {
      // We already have Route headers, so just build a target that mirrors
      // the current request URI.
      *target = new Target();
      (*target)->uri = (pjsip_uri*)pjsip_uri_clone(tdata->pool, tdata->msg->line.req.uri);
    }
    else if (PJUtils::is_home_domain(tdata->msg->line.req.uri) ||
             PJUtils::is_uri_local(tdata->msg->line.req.uri))
    {
      // Route the request upstream to Sprout.
      proxy_route_upstream(rdata, tdata, trust, target);
    }

    // Work out the next hop target for the message.  This will either be the
    // URI in the top route header, or the request URI.
    pjsip_uri* next_hop = PJUtils::next_hop(tdata->msg);

    if ((ibcf) &&
        (tgt_flow == NULL) &&
        (PJSIP_URI_SCHEME_IS_SIP(next_hop)))
    {
      // Check if the message is destined for a SIP trunk
      LOG_DEBUG("Check whether destination %.*s is a SIP trunk",
                ((pjsip_sip_uri*)next_hop)->host.slen, ((pjsip_sip_uri*)next_hop)->host.ptr);
      pj_sockaddr dest;
      if (pj_sockaddr_parse(pj_AF_UNSPEC(), 0, &((pjsip_sip_uri*)next_hop)->host, &dest) == PJ_SUCCESS)
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
      PJUtils::add_record_route(tdata, src_flow->transport()->type_name, src_flow->transport()->local_name.port, src_flow->token().c_str(), stack_data.public_host);
      PJUtils::add_record_route(tdata, "TCP", stack_data.pcscf_trusted_port, NULL, stack_data.local_host);
    }
    else if (tgt_flow != NULL)
    {
      // Message is destined for a client, so add separate Record-Route headers
      // for the ingress and egress hops.
      LOG_DEBUG("Message destined for client - double Record-Route");
      PJUtils::add_record_route(tdata, "TCP", stack_data.pcscf_trusted_port, NULL, stack_data.local_host);
      PJUtils::add_record_route(tdata, tgt_flow->transport()->type_name, tgt_flow->transport()->local_name.port, tgt_flow->token().c_str(), stack_data.public_host);
    }
    else if ((ibcf) && (*trust == &TrustBoundary::INBOUND_TRUNK))
    {
      // Received message on a trunk, so add separate Record-Route headers for
      // the ingress and egress hops.
      PJUtils::add_record_route(tdata, rdata->tp_info.transport->type_name, rdata->tp_info.transport->local_name.port, NULL, stack_data.public_host);
      PJUtils::add_record_route(tdata, "TCP", stack_data.pcscf_trusted_port, NULL, stack_data.local_host);
    }
    else if ((ibcf) && (*trust == &TrustBoundary::OUTBOUND_TRUNK))
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
      target = tdata->msg->line.req.uri;
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
    LOG_DEBUG("Top Route header is local - erasing");
    pj_list_erase(hroute);
  }

  return PJ_SUCCESS;
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
    pjsip_rx_data_free_cloned(_defer_rdata);
  }

  pthread_mutex_unlock(&_trying_timer_lock);
}

// Gets the subscriber's associated URIs and iFCs for each URI from
// the HSS. Returns true on success, false on failure.

// The info parameter is only filled in correctly if this function
// returns true,
bool UASTransaction::get_data_from_hss(std::string public_id, HSSCallInformation& info, SAS::TrailId trail)
{
  std::map<std::string, HSSCallInformation>::iterator data = cached_hss_data.find(public_id);
  bool rc = false;
  if (data != cached_hss_data.end())
  {
    info = data->second;
    rc = true;
  }
  else
  {
    std::vector<std::string> uris;
    std::map<std::string, Ifcs> ifc_map;
    std::string regstate;
    long http_code = hss->update_registration_state(public_id, "", HSSConnection::CALL, regstate, ifc_map, uris, trail);
    bool registered = (regstate == HSSConnection::STATE_REGISTERED);
    info = {registered, ifc_map[public_id], uris};
    if (http_code == 200)
    {
      cached_hss_data[public_id] = info;
      rc = true;
    }
  }
  return rc;
}

// Look up the registration state for the given public ID, using the
// per-transaction cache if possible (and caching them and the iFC otherwise).
bool UASTransaction::is_user_registered(std::string public_id)
{
  HSSCallInformation data;
  bool success = get_data_from_hss(public_id, data, trail());
  if (success)
  {
    return data.registered;
  }
  else
  {
    LOG_ERROR("Connection to Homestead failed, treating user as unregistered");
    return false;
  }
}

// Look up the associated URIs for the given public ID, using the cache if possible (and caching them and the iFC otherwise).
// The uris parameter is only filled in correctly if this function
// returns true,
bool UASTransaction::get_associated_uris(std::string public_id, std::vector<std::string>& uris, SAS::TrailId trail)
{
  HSSCallInformation data;
  bool success = get_data_from_hss(public_id, data, trail);
  if (success)
  {
    uris = data.uris;
  }
  return success;
}

// Look up the Ifcs for the given public ID, using the cache if possible (and caching them and the associated URIs otherwise).
// The ifcs parameter is only filled in correctly if this function
// returns true,
bool UASTransaction::lookup_ifcs(std::string public_id, Ifcs& ifcs, SAS::TrailId trail)
{
  HSSCallInformation data;
  bool success = get_data_from_hss(public_id, data, trail);
  if (success)
  {
    ifcs = data.ifcs;
  }
  return success;
}

///@{
// IN-TRANSACTION PROCESSING

/// Calculate a list of targets for the message.
void UASTransaction::proxy_calculate_targets(pjsip_msg* msg,
                                             pj_pool_t* pool,
                                             const TrustBoundary* trust,
                                             TargetList& targets,
                                             int max_targets,
                                             SAS::TrailId trail)
{
  bool sip_uri = false;
  bool tel_uri = false;

  // RFC 3261 Section 16.5 Determining Request Targets

  pjsip_uri* req_uri = (pjsip_uri*)msg->line.req.uri;

  if (PJSIP_URI_SCHEME_IS_SIP(msg->line.req.uri))
  {
    sip_uri = true;
  }
  else if (PJSIP_URI_SCHEME_IS_TEL(msg->line.req.uri))
  {
    tel_uri = true;
  }

  // If the Request-URI of the request contains an maddr parameter, the
  // Request-URI MUST be placed into the target set as the only target
  // URI, and the proxy MUST proceed to Section 16.6.
  if (sip_uri && ((pjsip_sip_uri*)req_uri)->maddr_param.slen)
  {
    LOG_INFO("Route request to maddr %.*s",
             ((pjsip_sip_uri*)req_uri)->maddr_param.slen,
             ((pjsip_sip_uri*)req_uri)->maddr_param.ptr);
    Target target;
    target.uri = req_uri;
    targets.push_back(target);
    return;
  }

  // If the domain of the Request-URI indicates a domain this element is
  // not responsible for, the Request-URI MUST be placed into the target
  // set as the only target, and the element MUST proceed to the task of
  // Request Forwarding (Section 16.6).
  if ((!PJUtils::is_home_domain(req_uri)) &&
      (!PJUtils::is_uri_local(req_uri)))
  {
    if (sip_uri)
    {
      LOG_INFO("Route request to domain %.*s",
               ((pjsip_sip_uri*)req_uri)->host.slen,
               ((pjsip_sip_uri*)req_uri)->host.ptr);
    }

    Target target;
    target.uri = req_uri;

    if ((bgcf_service) &&
        (sip_uri || tel_uri))
    {
      // See if we have a configured route to the destination.
      std::string domain;
      if (sip_uri)
      {
        domain = PJUtils::pj_str_to_string(&((pjsip_sip_uri*)req_uri)->host);
      }
      std::vector<std::string> bgcf_route = bgcf_service->get_route(domain, trail);

      if (!bgcf_route.empty())
      {
        for (std::vector<std::string>::const_iterator ii = bgcf_route.begin(); ii != bgcf_route.end(); ++ii)
        {
          pjsip_uri* route_uri = PJUtils::uri_from_string(*ii, pool);

          if (route_uri != NULL && PJSIP_URI_SCHEME_IS_SIP(route_uri))
          {
            target.paths.push_back(route_uri);
          }
          else
          {
            // One of the routes is an invalid SIP URI. Stop processing the entry
            // and clear the target
            target.paths.clear();
          }
        }

        // We have added a BGCF generated route to the request, so we should
        // switch ACR context for the downstream leg.
        _bgcf_acr = bgcf_acr_factory->get_acr(trail, CALLING_PARTY);
        if (_downstream_acr != _upstream_acr)
        {
          // We've already set up a different downstream ACR to the upstream ACR
          // so free it off.
          delete _downstream_acr;
        }
        _downstream_acr = _bgcf_acr;

        // Pass the request to the downstream ACR as if it is being received.
        _downstream_acr->rx_request(msg);
      }
    }

    targets.push_back(target);

    return;
  }

  // If the target set for the request has not been predetermined as
  // described above, this implies that the element is responsible for the
  // domain in the Request-URI, and the element MAY use whatever mechanism
  // it desires to determine where to send the request.
  //
  // is_user_registered() checks on Homestead to see whether the user
  // is registered - if not, we don't need to use the memcached store
  // to look up their bindings.
  std::string public_id;
  if (sip_uri)
  {
    public_id = PJUtils::aor_from_uri((pjsip_sip_uri*)req_uri);
  }

  if ((sip_uri) && (store) && (hss) && is_user_registered(public_id))
  {
    // Determine the canonical public ID, and look up the set of associated
    // URIs on the HSS.
    std::vector<std::string> uris;
    bool success = get_associated_uris(public_id, uris, trail);

    std::string aor;
    if (success && (uris.size() > 0))
    {
      // Take the first associated URI as the AOR.
      aor = uris.front();
    }
    else
    {
      // Failed to get the associated URIs from Homestead.  We'll try to
      // do the registration look-up with the specified target URI - this may
      // fail, but we'll never misroute the call.
      LOG_WARNING("Invalid Homestead response - a user is registered but has no list of associated URIs");
      aor = public_id;
    }

    // Look up the target in the registration data store.
    LOG_INFO("Look up targets in registration store: %s", aor.c_str());
    RegStore::AoR* aor_data = store->get_aor_data(aor, trail);

    // If we didn't get bindings from the local store and we have a remote
    // store, try the remote.
    if ((remote_store != NULL) &&
        ((aor_data == NULL) ||
         (aor_data->bindings().empty())))
    {
      delete aor_data;
      aor_data = remote_store->get_aor_data(aor, trail);
    }

    // Pick up to max_targets bindings to attempt to contact.  Since
    // some of these may be stale, and we don't want stale bindings to
    // push live bindings out, we sort by expiry time and pick those
    // with the most distant expiry times.  See bug 45.
    std::list<RegStore::AoR::Bindings::value_type> target_bindings;
    if (aor_data != NULL)
    {
      const RegStore::AoR::Bindings& bindings = aor_data->bindings();
      if ((int)bindings.size() <= max_targets)
      {
        for (RegStore::AoR::Bindings::const_iterator i = bindings.begin();
             i != bindings.end();
             ++i)
        {
          target_bindings.push_back(*i);
        }
      }
      else
      {
        std::multimap<int, RegStore::AoR::Bindings::value_type> ordered;
        for (RegStore::AoR::Bindings::const_iterator i = bindings.begin();
             i != bindings.end();
             ++i)
        {
          std::pair<int, RegStore::AoR::Bindings::value_type> p = std::make_pair(i->second->_expires, *i);
          ordered.insert(p);
        }

        int num_contacts = 0;
        for (std::multimap<int, RegStore::AoR::Bindings::value_type>::const_reverse_iterator i = ordered.rbegin();
             num_contacts < max_targets;
             ++i)
        {
          target_bindings.push_back(i->second);
          num_contacts++;
        }
      }
    }

    for (std::list<RegStore::AoR::Bindings::value_type>::const_iterator i = target_bindings.begin();
         i != target_bindings.end();
         ++i)
    {
      RegStore::AoR::Binding* binding = i->second;
      LOG_DEBUG("Target = %s", binding->_uri.c_str());
      bool useable_contact = true;
      Target target;
      target.from_store = PJ_TRUE;
      target.aor = aor;
      target.binding_id = i->first;
      target.uri = PJUtils::uri_from_string(binding->_uri, pool);
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
            target.paths.push_back(path);
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

    if (targets.empty())
    {
      LOG_ERROR("Failed to find any valid bindings for %s in registration store", aor.c_str());
    }

    delete aor_data;
  }
}


/// Attempt ENUM lookup if appropriate.
static pj_status_t translate_request_uri(pjsip_tx_data* tdata, SAS::TrailId trail)
{
  pj_status_t status = PJ_SUCCESS;
  std::string user;
  bool tel_uri = false;
  bool sip_uri = false;
  std::string uri;

  // Determine whether we have a SIP URI or a tel URI
  if (PJSIP_URI_SCHEME_IS_SIP(tdata->msg->line.req.uri))
  {
    user = PJUtils::pj_str_to_string(&((pjsip_sip_uri*)tdata->msg->line.req.uri)->user);
    sip_uri = true;
  }
  else if (PJSIP_URI_SCHEME_IS_TEL(tdata->msg->line.req.uri))
  {
    user = PJUtils::public_id_from_uri((pjsip_uri*)tdata->msg->line.req.uri);
    tel_uri = true;
  }

  // Check whether we have a global number or whether we allow
  // ENUM lookups for local numbers
  if (is_user_global(user) || !global_only_lookups)
  {
    // Perform an ENUM lookup if we have a tel URI, or if we have
    // a SIP URI which is being treated as a phone number
    if (tel_uri ||
        (sip_uri &&
         (!user_phone || PJUtils::is_sip_uri_phone_number((pjsip_sip_uri*)tdata->msg->line.req.uri)) &&
         is_user_numeric(user)))
    {
      LOG_DEBUG("Performing ENUM lookup for user %s", user.c_str());
      uri = enum_service->lookup_uri_from_user(user, trail);
    }
  }
  else if (tel_uri ||
           (sip_uri && PJUtils::is_sip_uri_phone_number((pjsip_sip_uri*)tdata->msg->line.req.uri)))
  {
    LOG_WARNING("Unable to resolve URI phone number %s using ENUM", user.c_str());
    status = PJ_EUNKNOWN;
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
        int max_expires = PJUtils::max_expires(rdata->msg_info.msg, 300);
        LOG_DEBUG("Maximum contact expiry is %d", max_expires);

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
          LOG_DEBUG("Found P-Associated-URI header");
          bool is_default = true;
          while (p_assoc_uri != NULL)
          {
            flow_data->set_identity((pjsip_uri*)&p_assoc_uri->name_addr, is_default, max_expires);
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
          LOG_DEBUG("No P-Associated-URI, use URI in To header.");
          flow_data->set_identity(PJSIP_MSG_TO_HDR(rdata->msg_info.msg)->uri, true, max_expires);
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
        LOG_INFO("Failed to correlate REGISTER response Path token %s to a flow", flow_token.c_str());
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
  _proxy(NULL),
  _pending_destroy(false),
  _context_count(0),
  _as_chain_link(),
  _as_chain_linked(false),
  _victims(),
  _upstream_acr(acr),
  _downstream_acr(acr),
  _in_dialog(false),
  _icscf_router(NULL),
  _icscf_acr(NULL),
  _bgcf_acr(NULL)
{
  LOG_DEBUG("UASTransaction constructor (%p)", this);
  LOG_DEBUG("ACR (%p)", acr);

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
  LOG_DEBUG("UASTransaction destructor (%p)", this);

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
  LOG_DEBUG("Disconnect UAC transactions from UAS transaction");
  for (int ii = 0; ii < _num_targets; ++ii)
  {
    UACTransaction* uac_data = _uac_data[ii];
    if (uac_data != NULL)
    {
      dissociate(uac_data);
    }
  }

  if (_icscf_acr != NULL)
  {
    // I-CSCF ACR has been created for this transaction, so send the message
    // and delete the ACR.
    _icscf_acr->send_message();

    if (_downstream_acr == _icscf_acr)
    {
      // Downstream ACR was referencing the I-CSCF ACR, so reset it back to
      // the same as the upstream ACR so it doesn't get reported or freed twice.
      _downstream_acr = _upstream_acr;
    }

    delete _icscf_acr;
    _icscf_acr = NULL;
  }

  if (_bgcf_acr != NULL)
  {
    // BGCF ACR has been created for this transaction, so send the message
    // and delete the ACR.
    _bgcf_acr->send_message();

    if (_downstream_acr == _bgcf_acr)
    {
      // Downstream ACR was referencing the BGCF ACR, so reset it back to
      // the same as the upstream ACR so it doesn't get reported or freed twice.
      _downstream_acr = _upstream_acr;
    }

    delete _bgcf_acr;
    _bgcf_acr = NULL;
  }

  if (!_as_chain_linked)
  {
    // This transaction has not been linked to any AS chains, so is still
    // in control of the ACR, so send it now.
    if (_downstream_acr != _upstream_acr)
    {
      // The downstream ACR is not the same as the upstream one, so send the
      // message and destroy the object.
      _downstream_acr->send_message();
      delete _downstream_acr;
    }

    // Send the ACR for the upstream side.
    _upstream_acr->send_message();
    delete _upstream_acr;
    _upstream_acr = NULL;
    _downstream_acr = NULL;
  }

  if (_icscf_router != NULL)
  {
    delete _icscf_router;
    _icscf_router = NULL;
  }

  if (_req != NULL)
  {
    LOG_DEBUG("Free original request (%p)", _req);
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

  if (_as_chain_link.is_set())
  {
    _as_chain_link.release();
  }

  // Request destruction of any AsChains scheduled for destruction
  // along with this transaction. They are not actually deleted until
  // any concurrent threads have finished using them.
  for (std::list<AsChain*>::iterator it = _victims.begin();
       it != _victims.end();
       ++it)
  {
    (*it)->request_destroy();
  }
  _victims.clear();

  pj_grp_lock_release(_lock);
  pj_grp_lock_dec_ref(_lock);

  LOG_DEBUG("UASTransaction destructor completed");
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

/// Handle a non-CANCEL message.
void UASTransaction::handle_non_cancel(const ServingState& serving_state, Target *target)
{
  AsChainLink::Disposition disposition = AsChainLink::Disposition::Complete;
  pj_status_t status;

  // Strip any untrusted headers as required, so we don't pass them on.
  _trust->process_request(_req);

  // If we're a routing proxy, perform AS handling to pick the next hop.
  if (!target && !edge_proxy && serving_state.is_set())
  {
    // The serving state has been set up, so perform AS handling.
    if (stack_data.record_route_on_every_hop)
    {
      LOG_DEBUG("Single Record-Route - configured to do this on every hop");
      routing_proxy_record_route();
    }

    // Pick up the AS chain from the ODI, or do the iFC lookups
    // necessary to create a new AS chain. If creating a new AS
    // chain, and configured to Record-Route on initiation of
    // originating or terminating (but not on every hop), also Record-Routes.
    bool rc = find_as_chain(serving_state);

    if (!rc)
    {
      LOG_INFO("Reject request with 404 due to failed iFC lookup");
      send_response(PJSIP_SC_NOT_FOUND);
      // target is not set, so just return
      return;
    }

    if (_as_chain_link.is_set() &&
        _as_chain_link.session_case().is_originating())
    {
      LOG_DEBUG("Performing originating call processing");

      // Do originating handling (including AS handling and setting
      // orig-ioi).
      disposition = handle_originating(&target);

      if (disposition == AsChainLink::Disposition::Complete)
      {
        // Processing at end of originating handling

        if (stack_data.record_route_on_completion_of_originating)
        {
          LOG_DEBUG("Single Record-Route - end of originating handling");
          routing_proxy_record_route();
        }

        if ((enum_service) &&
            ((PJUtils::is_home_domain(_req->msg->line.req.uri)) || (PJSIP_URI_SCHEME_IS_TEL(_req->msg->line.req.uri))) &&
            (!is_uri_routeable(_req->msg->line.req.uri)))
        {
          // We've finished originating handling, and the request is
          // targeted at this domain, but the URI is not currently
          // routeable, so do an ENUM lookup to translate it to a
          // routeable URI.

          // This may mean it is no longer targeted at
          // this domain, so we need to recheck this below before
          // starting terminating handling.
          LOG_DEBUG("Translating URI");
          status = translate_request_uri(_req, trail());

          if (status != PJ_SUCCESS)
          {
            // An error occurred during URI translation.  This doesn't happen if
            // there is no match, only if the URI is invalid or there is a match
            // but there is an error performing the defined mapping.  We therefore
            // reject the request.
            disposition = AsChainLink::Disposition::Stop;

            if (status == PJ_EUNKNOWN)
            {
              send_response(PJSIP_SC_ADDRESS_INCOMPLETE, &SIP_REASON_ADDR_INCOMPLETE);
            }
            else
            {
              send_response(PJSIP_SC_NOT_FOUND, &SIP_REASON_ENUM_FAILED);
            }
          }
        }
      }
    }

    if ((_as_chain_link.is_set()) &&
        (_as_chain_link.session_case().is_originating()) &&
        (disposition == AsChainLink::Disposition::Complete) &&
        (PJUtils::is_home_domain(_req->msg->line.req.uri)) &&
        (icscf_uri))
    {
      // We've completed the originating half, the destination is local and
      // we have an external I-CSCF configured.  Route the call there.
      LOG_INFO("Invoking I-CSCF %s",
               PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR, icscf_uri).c_str());

      // Release any existing AS chain to avoid leaking it.
      _as_chain_link.release();

      // Start defining the new target.
      delete target;
      target = new Target;

      // Set the I-CSCF URI as the topmost route header.
      target->paths.push_back((pjsip_uri*)pjsip_uri_clone(_req->pool, icscf_uri));

      // The Request-URI should remain unchanged
      target->uri = _req->msg->line.req.uri;
    }
    else if ((_as_chain_link.is_set()) &&
             (_as_chain_link.session_case().is_originating()) &&
             (disposition == AsChainLink::Disposition::Complete) &&
             (PJUtils::is_home_domain(_req->msg->line.req.uri)) &&
             (icscf))
    {
      // We've completed the originating half, the destination is local and
      // I-CSCF function is enabled.  In this case we should do the LIR lookup
      // ourselves rather than invoking an external I-CSCF.
      LOG_INFO("Sprout has I-CSCF function enabled");

      // Logically we are transitioning from S-CSCF context to I-CSCF
      // context, so pass the request to the upstream ACR as if it is
      // being transmitted.
      _upstream_acr->tx_request(_req->msg);

      // Allocate an I-CSCF ACR.
      _icscf_acr = icscf_acr_factory->get_acr(trail(), CALLING_PARTY);
      _icscf_acr->rx_request(_req->msg);

      // Create an I-CSCF router for the LIR query.
      std::string public_id = PJUtils::aor_from_uri((pjsip_sip_uri*)_req->msg->line.req.uri);
      _icscf_router = (ICSCFRouter*)new ICSCFLIRouter(hss,
                                                      scscf_selector,
                                                      trail(),
                                                      _icscf_acr,
                                                      public_id,
                                                      false);

      pjsip_sip_uri* scscf_uri = NULL;
      int status_code;

      if (_icscf_router != NULL)
      {
        // Select a S-CSCF to route the call and convert it to a URI.
        std::string server_name;
        status_code = _icscf_router->get_scscf(server_name);

        if (status_code == PJSIP_SC_OK)
        {
          scscf_uri = (pjsip_sip_uri*)PJUtils::uri_from_string(server_name,
                                                               _req->pool,
                                                               PJ_FALSE);
          if ((scscf_uri == NULL) ||
              (!PJSIP_URI_SCHEME_IS_SIP(scscf_uri)))
          {
            // Server name was invalid, so act as if no suitable S-CSCF was
            // found.
            LOG_DEBUG("Server name is invalid");
            status_code = PJSIP_SC_NOT_FOUND;
          }
        }
      }
      else
      {
        // Failed to create an ICSCF router, so reject the request with
        // 500.
        status_code = PJSIP_SC_INTERNAL_SERVER_ERROR;
      }

      if (status_code != PJSIP_SC_OK)
      {
        // The I-CSCF look-up failed to find a suitable S-CSCF for the
        // terminating subscriber, so reject the request.
        LOG_DEBUG("No valid S-CSCFs found");

        // Pass the error response to the I-CSCF ACR and send the ACR.
        _best_rsp->msg->line.status.code = status_code;
        _best_rsp->msg->line.status.reason = *pjsip_get_status_text(status_code);
        _icscf_acr->tx_response(_best_rsp->msg);
        _icscf_acr->send_message();
        delete _icscf_acr;
        _icscf_acr = NULL;

        send_response(PJSIP_SC_NOT_FOUND);
        delete target;
        return;
      }

      // Check whether the returned S-CSCF is this S-CSCF.  Check the host
      // name and the port returned on the LIR, but ignore transport and
      // other URI parameters.
      if ((pj_stricmp(&scscf_uri->host, &scscf_domain_name) == 0) &&
          (scscf_uri->port == stack_data.scscf_port))
      {
        // The terminating user is on this S-CSCF, so continue processing
        // locally by switching to the terminating AS chain.

        // We're switching back out of I-CSCF context, so pass the request
        // to the ACR as if we are transmitting it.
        _icscf_acr->tx_request(_req->msg);

        bool success = move_to_terminating_chain();
        if (!success)
        {
          LOG_INFO("Reject request with 404 due to failed move to terminating chain");
          send_response(PJSIP_SC_NOT_FOUND);
          delete target;
          return;
        }
      }
      else
      {
        // The S-CSCF is different, so route the call there.
         _as_chain_link.release();

        if (_icscf_acr != NULL)
        {
          // In this case we need to reference the I-CSCF as the downstream
          // ACR for this transaction, and keep a reference to it as an
          // I-CSCF ACR in case we do any further routing look-ups.
          _downstream_acr = _icscf_acr;
        }

        delete target;
        target = new Target;

        scscf_uri->lr_param = 1;
        target->paths.push_back((pjsip_uri*)
                         pjsip_uri_clone(_req->pool, (pjsip_uri*)scscf_uri));

        // The Request-URI should remain unchanged
        target->uri = _req->msg->line.req.uri;
      }
    }
    else if (disposition == AsChainLink::Disposition::Complete &&
             (PJUtils::is_home_domain(_req->msg->line.req.uri)) &&
             !(_as_chain_link.is_set() && _as_chain_link.session_case().is_terminating()))
    {
      // We've completed the originating half (or we're not doing
      // originating handling for this call), we're handling the
      // terminating half (i.e. it hasn't been ENUMed to go
      // elsewhere), and we don't yet have a terminating chain.

      // Logically we are transitioning from originating S-CSCF context to
      // terminating S-CSCF context, so pass the request to the upstream
      // ACR as if it is being transmitted.
      _upstream_acr->tx_request(_req->msg);

      // Switch to terminating session state, set the served user to
      // the callee, and look up iFCs again.
      LOG_DEBUG("Originating AS chain complete, move to terminating chain");
      bool success = move_to_terminating_chain();
      if (!success)
      {
        LOG_INFO("Reject request with 404 due to failed move to terminating chain");
        send_response(PJSIP_SC_NOT_FOUND);
        delete target;
        return;
      }
    }
    else if ((disposition == AsChainLink::Disposition::Complete) &&
             !_as_chain_link.is_set() &&
             !PJUtils::is_home_domain(_req->msg->line.req.uri))
    {
      LOG_DEBUG("Record-Route for the BGCF case");
      routing_proxy_record_route();
    }

    if (_as_chain_link.is_set() &&
        _as_chain_link.session_case().is_terminating())
    {
      // Do terminating handling (including AS handling and setting
      // orig-ioi).

      LOG_DEBUG("Terminating half");
      disposition = handle_terminating(&target);

      if (disposition == AsChainLink::Disposition::Complete)
      {
        // Processing at end of terminating handling

        if (stack_data.record_route_on_completion_of_terminating)
        {
          routing_proxy_record_route();
          LOG_DEBUG("Single Record-Route - end of terminating handling");
        }
      }
    }
  }

  if (disposition != AsChainLink::Disposition::Stop)
  {
    // Perform common outgoing processing.
    handle_outgoing_non_cancel(target);
  }

  delete target;
}


// Find the AS chain for this transaction, or create a new one.
bool UASTransaction::find_as_chain(const ServingState& serving_state)
{
  LOG_DEBUG("Looking for AS chain for incoming transaction request, serving state = %s", serving_state.to_string().c_str());
  bool success = true;

  std::string served_user;
  Ifcs ifcs;

  if (serving_state.original_dialog().is_set())
  {
    // Pick up existing AS chain.
    _as_chain_link = serving_state.original_dialog();
    LOG_DEBUG("Picking up original AS chain");
    success = true;

    if ((serving_state.session_case() == SessionCase::Terminating) &&
        (!_as_chain_link.matches_target(_req)))
    {
      // AS is retargeting per 3GPP TS 24.229 s5.4.3.3 step 3, so
      // create new AS chain with session case orig-cdiv and the
      // terminating user as served user.
      LOG_INFO("Request-URI has changed, retargeting");

      // We might not be the terminating server any more, so we
      // should blank out the term_ioi parameter. If we are still
      // the terminating server, we'll fill it back in when we go
      // through handle_terminating.

      // Note that there's no need to change orig_ioi - we don't
      // actually become the originating server when we do this redirect.
      pjsip_p_c_v_hdr* pcv = (pjsip_p_c_v_hdr*)
        pjsip_msg_find_hdr_by_name(_req->msg, &STR_P_C_V, NULL);
      if (pcv)
      {
        LOG_DEBUG("Blanking out term_ioi parameter due to redirect");
        pcv->term_ioi = pj_str("");
      }

      served_user = _as_chain_link.served_user();

      _as_chain_link.release();
      success = lookup_ifcs(served_user, ifcs, trail());
      if (success)
      {
        LOG_DEBUG("Creating originating CDIV AS chain");
        _as_chain_link = create_as_chain(SessionCase::OriginatingCdiv, ifcs, served_user);
        if (stack_data.record_route_on_diversion)
        {
          LOG_DEBUG("Single Record-Route - originating Cdiv");
          routing_proxy_record_route();
        }
      }
    }
  }
  else
  {
    // No existing AS chain - create new.
    served_user = ifc_handler->served_user_from_msg(serving_state.session_case(), _req->msg, _req->pool);
    if (!served_user.empty())
    {
      LOG_DEBUG("Looking up iFCs for %s for new AS chain", served_user.c_str());
      success = lookup_ifcs(served_user, ifcs, trail());
      if (success)
      {
        LOG_DEBUG("Successfully looked up iFCs");
        _as_chain_link = create_as_chain(serving_state.session_case(), ifcs, served_user);
      }

      if (serving_state.session_case() == SessionCase::Terminating)
      {
        common_start_of_terminating_processing();
      }
      else if (serving_state.session_case() == SessionCase::Originating)
      {
        // Processing at start of originating handling (not including CDiv)
        if (stack_data.record_route_on_initiation_of_originating)
        {
          LOG_DEBUG("Single Record-Route - initiation of originating handling");
          routing_proxy_record_route();
        }
      }
    }
  }

  if (_as_chain_link.is_set())
  {
    // Flag that the transaction has been linked to an AS chain.
    _as_chain_linked = true;
  }

  return success;
}


/// Perform originating handling.
//
// @returns whether processing should `Stop`, `Skip` to the end, or
// continue to next chain because the current chain is
// `Complete`. Never returns `Next`.
AsChainLink::Disposition UASTransaction::handle_originating(Target** target) // OUT: target, if disposition is Skip
{
  // These are effectively the preconditions of this function - that
  // it is only called when we know we are providing originating
  // services for a user.

  if (!(_as_chain_link.is_set() && _as_chain_link.session_case().is_originating()))
  {
    LOG_WARNING("In handle_originating despite not having an originating session case");
    return AsChainLink::Disposition::Complete;
  }

  if (_as_chain_link.served_user().empty())
  {
    LOG_WARNING("In handle_originating despite not having a served user specified");
    return AsChainLink::Disposition::Complete;
  }

  // Add ourselves as orig-IOI.
  pjsip_p_c_v_hdr* pcv = (pjsip_p_c_v_hdr*)
    pjsip_msg_find_hdr_by_name(_req->msg, &STR_P_C_V, NULL);
  if (pcv)
  {
    pcv->orig_ioi = PJUtils::domain_from_uri(_as_chain_link.served_user(), _req->pool);
  }

  // Apply originating call services to the message
  LOG_DEBUG("Applying originating services");
  AsChainLink::Disposition disposition;
  for (;;)
  {
    disposition = _as_chain_link.on_initial_request(call_services_handler, this, _req, target);

    if (disposition == AsChainLink::Disposition::Next)
    {
      _as_chain_link = _as_chain_link.next();
      LOG_DEBUG("Done internal step - advance link to %s and go around again", _as_chain_link.to_string().c_str());
    }
    else
    {
      break;
    }
  }

  LOG_INFO("Originating services disposition %d", (int)disposition);
  return disposition;
}

// We can start terminating processing either in find_as_chain or
// move_to_terminating_chain. This function contains processing common
// to both.
void UASTransaction::common_start_of_terminating_processing()
{
  if (stack_data.record_route_on_initiation_of_terminating)
  {
    LOG_DEBUG("Single Record-Route - initiation of terminating handling");
    routing_proxy_record_route();
  }
}

/// Move from originating to terminating handling.
bool UASTransaction::move_to_terminating_chain()
{
  // Create new terminating chain.
  _as_chain_link.release();
  std::string served_user = ifc_handler->served_user_from_msg(SessionCase::Terminating, _req->msg, _req->pool);

  LOG_DEBUG("Looking up iFCs for served user %s", served_user.c_str());
  // If we got a served user, look it up.  We won't get a served user if we've recognized that they're remote.

  bool success = true;
  if (!served_user.empty())
  {
    Ifcs ifcs;
    success = lookup_ifcs(served_user, ifcs, trail());

    if (success)
    {
      // Switch Rf context to the S-CSCF terminating side processing, by
      // passing the request to the upstream ACR as if it is being transmitted,
      // then creating a new downstream ACR for the terminating side and passing
      // the request to it as if it has been received.
      _upstream_acr->tx_request(_req->msg);
      _downstream_acr = cscf_acr_factory->get_acr(trail(), CALLING_PARTY);
      _downstream_acr->rx_request(_req->msg);

      // These headers name the originating user, so should not survive
      // the changearound to the terminating chain.
      PJUtils::remove_hdr(_req->msg, &STR_P_SERVED_USER);

      // Create the terminating chain.
      _as_chain_link = create_as_chain(SessionCase::Terminating, ifcs, served_user);
      _as_chain_linked = true;
      common_start_of_terminating_processing();
    }
  }
  return success;
}

// Perform terminating handling.
//
// @returns whether processing should `Stop`, `Skip` to the end, or
// is now `Complete`. Never returns `Next`.
AsChainLink::Disposition UASTransaction::handle_terminating(Target** target) // OUT: target, if disposition is Skip
{
  // These are effectively the preconditions of this function - that
  // it is only called when we know we are providing terminating
  // services for a user, and the target is in our domain.
  if (!(_as_chain_link.is_set() && _as_chain_link.session_case().is_terminating()))
  {
    LOG_WARNING("In handle_terminating despite not having a terminating session case");
    return AsChainLink::Disposition::Complete;
  }

  if (_as_chain_link.served_user().empty())
  {
    LOG_WARNING("In handle_terminating despite not having a served user specified");
    return AsChainLink::Disposition::Complete;
  }

  if (!PJUtils::is_home_domain(_req->msg->line.req.uri))
  {
    LOG_WARNING("In handle_terminating despite the request not being targeted at our domain");
    return AsChainLink::Disposition::Complete;
  }

  // If the newly translated ReqURI indicates that we're the host of the
  // target user, include ourselves as the terminating operator for
  // billing.
  pjsip_p_c_v_hdr* pcv = (pjsip_p_c_v_hdr*)
    pjsip_msg_find_hdr_by_name(_req->msg, &STR_P_C_V, NULL);
  if (pcv)
  {
    pcv->term_ioi = PJUtils::domain_from_uri(_as_chain_link.served_user(), _req->pool);
  }

  // Apply terminating call services to the message
  LOG_DEBUG("Apply terminating services");
  AsChainLink::Disposition disposition;
  for (;;)
  {
    disposition = _as_chain_link.on_initial_request(call_services_handler, this, _req, target);
    // On return from on_initial_request, our _proxy pointer may be
    // NULL.  Don't use it without checking first.

    if (disposition == AsChainLink::Disposition::Next)
    {
      _as_chain_link = _as_chain_link.next();
      LOG_DEBUG("Done internal step - advance link to %s and go around again", _as_chain_link.to_string().c_str());
    }
    else
    {
      break;
    }
  }

  LOG_INFO("Terminating services disposition %d", (int)disposition);
  return disposition;
}

// Handle the outgoing half of a non-CANCEL message.
void UASTransaction::handle_outgoing_non_cancel(Target* target)
{
  // Calculate targets
  TargetList targets;
  if (target != NULL)
  {
    // Already have a target, so use it.
    targets.push_back(*target);
  }
  else
  {
    // Find targets.
    proxy_calculate_targets(_req->msg, _req->pool, _trust, targets, MAX_FORKING, trail());
  }

  if (targets.size() == 0)
  {
    // No targets found, so reject with a 480 error.
    // There will only be no targets when the terminating user isn't
    // registered or has no valid bindings.
    LOG_INFO("Reject request with 480");
    send_response(PJSIP_SC_TEMPORARILY_UNAVAILABLE);

    return;
  }

  // Ensure that Session-Expires is added to the message to enable the session
  // timer on the UEs.
  pjsip_session_expires_hdr* session_expires =
    (pjsip_session_expires_hdr*)pjsip_msg_find_hdr_by_name(_req->msg,
                                                           &STR_SESSION_EXPIRES,
                                                           NULL);
  if (session_expires == NULL)
  {
    session_expires = pjsip_session_expires_hdr_create(_req->pool);
    pjsip_msg_add_hdr(_req->msg, (pjsip_hdr*)session_expires);
  }
  session_expires->expires = stack_data.default_session_expires;

  // Now set up the data structures and transactions required to
  // process the request.
  pj_status_t status = init_uac_transactions(targets);

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

    // Pass the received response to the downstream ACR.
    _downstream_acr->rx_response(rdata->msg_info.msg, rdata->pkt_info.timestamp);

    pjsip_tx_data *tdata;
    pj_status_t status;
    int status_code = rdata->msg_info.msg->line.status.code;

    if ((!edge_proxy) &&
        (_as_chain_link.is_set()))
    {
      // Pass the response to the AS chain.
      _as_chain_link.on_response(rdata);
    }

    if ((!edge_proxy) &&
        (method() == PJSIP_INVITE_METHOD) &&
        (status_code == 100))
    {
      // In routing proxy mode, don't forward 100 response for INVITE as it has
      // already been sent.
      LOG_DEBUG("%s - Discard 100/INVITE response", uac_data->name());

      exit_context();
      return;
    }

    if ((edge_proxy) &&
        (method() == PJSIP_REGISTER_METHOD) &&
        (status_code == 200))
    {
      // Pass the REGISTER response to the access proxy code to see if
      // the associated client flow has been authenticated.
      proxy_process_register_response(rdata);
    }

    status = PJUtils::create_response_fwd(stack_data.endpt, rdata, 0, &tdata);
    if (status != PJ_SUCCESS)
    {
      LOG_ERROR("Error creating response, %s",
                PJUtils::pj_status_to_string(status).c_str());
      exit_context();
      return;
    }

    // Strip any untrusted headers as required, so we don't pass them on.
    _trust->process_response(tdata);

    if ((_proxy != NULL) &&
        (!_proxy->on_response(tdata->msg)))
    {
      // Proxy has taken control.  Stop processing now.
      pjsip_tx_data_dec_ref(tdata);
      exit_context();
      return;
    }

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
        _downstream_acr->send_message();

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
        LOG_DEBUG("%s - Forward 1xx response", uac_data->name());

        // Pass the response to the upstream ACR for reporting.
        _upstream_acr->tx_response(tdata->msg);

        if (_in_dialog)
        {
          // This is a provisional response to a mid-dialog message, so we
          // should send an ACR now.
          _upstream_acr->send_message();

          // Don't delete the ACR as we will send another on any subsequent
          // provisional responses, and also when the transaction completes.
        }

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

    if ((!edge_proxy) &&
        (_as_chain_link.is_set()))
    {
      // Pass the response to the AS chain.
      _as_chain_link.on_not_responding();
    }

    if (_num_targets > 1)
    {
      // UAC transaction has timed out or hit a transport error.  If
      // we've not received a response from on any other UAC
      // transactions then keep this as the best response.
      LOG_DEBUG("%s - Forked request", uac_data->name());

      if (--_pending_targets == 0)
      {
        // Received responses on every UAC transaction, so
        // send the best response on the UAS transaction.
        LOG_DEBUG("%s - No more pending responses, so send response on UAC tsx", name());
        handle_final_response();
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

    // This has to be conditional on a completed state, else
    // _tsx->transport might not be set.
    if (edge_proxy)
    {
      SIPPeerType stype  = determine_source(_tsx->transport, _tsx->addr);
      bool is_client = (stype == SIP_PEER_CLIENT);
      dialog_tracker->on_uas_tsx_complete(_req, _tsx, event, is_client);
    }

    log_on_tsx_complete();
  }

  if (_tsx->state == PJSIP_TSX_STATE_DESTROYED)
  {
    LOG_DEBUG("%s - UAS tsx destroyed", _tsx->obj_name);
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
  if ((_tsx != NULL) &&
      ((_proxy == NULL) ||
       (_proxy->on_final_response(_best_rsp))))
  {
    pjsip_tx_data *best_rsp = _best_rsp;
    int st_code = best_rsp->msg->line.status.code;

    if (((st_code == PJSIP_SC_REQUEST_TIMEOUT) ||
         (PJSIP_IS_STATUS_IN_CLASS(st_code, 500))) &&
        (_as_chain_link.is_set()) &&
        (_as_chain_link.continue_session()) &&
        (!_as_chain_link.complete()))
    {
      // The AS either timed out or returned a 5xx error, and the conditions
      // for continuing the session with the next application server have been
      // met.
      LOG_DEBUG("Trigger default_handling=CONTINUE processing");

      // Reset the best response to a 408 response to use if none of the targets responds.
      _best_rsp->msg->line.status.code = PJSIP_SC_REQUEST_TIMEOUT;

      // Redirect the dialog to the next AS in the chain.
      ServingState serving_state(&_as_chain_link.session_case(),
                                 _as_chain_link.next());
      handle_non_cancel(serving_state, NULL);
    }
    else
    {
      if ((_icscf_acr != NULL) &&
          (_icscf_acr != _downstream_acr))
      {
        // Report the final response to the I-CSCF ACR.
        _icscf_acr->rx_response(best_rsp->msg);
        _icscf_acr->tx_response(best_rsp->msg);
      }

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
        LOG_DEBUG("%s - Terminate UAS INVITE transaction (non-forking case)",
                  _tsx->obj_name);
        pjsip_tsx_terminate(_tsx, 200);
      }
    }
  }
  return rc;
}


/// Register a proxy to handle future responses received from our
// child UAC transaction or generated internally.  Ownership passes
// to this transaction; it will be deleted when this transaction is
// deleted.
void UASTransaction::register_proxy(CallServices::Terminating* proxy)
{
  pj_assert(_proxy == NULL);
  _proxy = proxy;
}


// Sends a 100 Trying response to the given rdata, in this transaction.
// @Returns whether or not the send was a success.
pj_status_t UASTransaction::send_trying(pjsip_rx_data* rdata)
{
  return PJUtils::respond_stateful(stack_data.endpt, _tsx, rdata, 100, NULL, NULL, NULL);
}


// Sends a response using the buffer saved off for the best response.
// @Returns whether or not the send was a success.
pj_status_t UASTransaction::send_response(int st_code, const pj_str_t* st_text)
{
  // cancel any outstanding deferred trying responses
  cancel_trying_timer();

  if ((st_code >= 100) && (st_code < 200))
  {
    pjsip_tx_data* prov_rsp = PJUtils::clone_tdata(_best_rsp);
    prov_rsp->msg->line.status.code = st_code;
    prov_rsp->msg->line.status.reason = (st_text != NULL) ? *st_text : *pjsip_get_status_text(st_code);
    set_trail(prov_rsp, trail());
    _upstream_acr->tx_response(prov_rsp->msg);
    return pjsip_tsx_send_msg(_tsx, prov_rsp);
  }
  else
  {
    _best_rsp->msg->line.status.code = st_code;
    _best_rsp->msg->line.status.reason = (st_text != NULL) ? *st_text : *pjsip_get_status_text(st_code);
    return handle_final_response();
  }
}

/// Redirects the call to the specified target, for the reason specified in the
// status code.
//
// If a proxy is set, it is deleted by this method.  Beware!
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
    // Deleting the transaction implicitly releases the group lock.
    delete this;
  }
  else
  {
    // Release the group lock.
    pj_grp_lock_release(_lock);
  }
}

/// Redirects the call to the specified target, for the reason specified in the
// status code.
//
// If a proxy is set, it is deleted by this method.  Beware!
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
  SAS::Marker start_marker(trail(), MARKER_ID_START, 1u);
  SAS::report_marker(start_marker);

  if (_analytics.from)
  {
    SAS::Marker calling_dn(trail(), MARKER_ID_CALLING_DN, 1u);
    pjsip_sip_uri* calling_uri = (pjsip_sip_uri*)pjsip_uri_get_uri(_analytics.from->uri);
    calling_dn.add_var_param(calling_uri->user.slen, calling_uri->user.ptr);
    SAS::report_marker(calling_dn);
  }

  if (_analytics.to)
  {
    SAS::Marker called_dn(trail(), MARKER_ID_CALLED_DN, 1u);
    pjsip_sip_uri* called_uri = (pjsip_sip_uri*)pjsip_uri_get_uri(_analytics.to->uri);
    called_dn.add_var_param(called_uri->user.slen, called_uri->user.ptr);
    SAS::report_marker(called_dn);
  }

  PJUtils::mark_sas_call_branch_ids(get_trail(rdata), _analytics.cid, rdata->msg_info.msg);
}

// Generate analytics logs relating to a transaction completing.
void UASTransaction::log_on_tsx_complete()
{
  // Report SAS markers for the transaction.
  LOG_DEBUG("Report SAS end marker - trail (%llx)", trail());
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
      LOG_DEBUG("Allocating transaction and data for target %d", ii);
      uac_tdata = PJUtils::clone_tdata(_req);

      if (uac_tdata == NULL)
      {
        status = PJ_ENOMEM;
        LOG_ERROR("Failed to clone request for forked transaction, %s",
                  PJUtils::pj_status_to_string(status).c_str());
        break;
      }

      status = pjsip_tsx_create_uac2(&mod_tu, uac_tdata, _lock, &uac_tsx);
      if (status != PJ_SUCCESS)
      {
        LOG_ERROR("Failed to create UAC transaction, %s",
                  PJUtils::pj_status_to_string(status).c_str());
        break;
      }

      // Add the trail from the UAS transaction to the UAC transaction.
      LOG_DEBUG("Adding trail identifier %ld to UAC transaction", trail());
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
void UASTransaction::cancel_pending_uac_tsx(int st_code, bool dissociate_uac)
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
  LOG_DEBUG("Dissociate UAC transaction %p (%d)", uac_data, uac_data->_target);
  uac_data->_uas_data = NULL;
  _uac_data[uac_data->_target] = NULL;
}

/// Redirects the call to the specified target, for the reason specified in the
// status code.
//
// This internal version of the method does not clone the provided URI, so it
// must have been allocated from a suitable pool.
//
// If a proxy is set, it is deleted by this method.  Beware!
//
// @returns whether the call should continue as it was (always false).
bool UASTransaction::redirect_int(pjsip_uri* target, int code)
{
  static const pj_str_t STR_HISTORY_INFO = pj_str("History-Info");
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
    cancel_pending_uac_tsx(code, true);
    send_response(PJSIP_SC_CALL_BEING_FORWARDED);

    // Add a Diversion header with the original request URI and the reason
    // for the diversion.
    std::string div = PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, _req->msg->line.req.uri);
    div += ";reason=";
    div += (code == PJSIP_SC_BUSY_HERE) ? "user-busy" :
           (code == PJSIP_SC_TEMPORARILY_UNAVAILABLE) ? "no-answer" :
           (code == PJSIP_SC_NOT_FOUND) ? "out-of-service" :
           (code == 0) ? "unconditional" :
           "unknown";
    pj_str_t sdiv;
    pjsip_generic_string_hdr* diversion =
                    pjsip_generic_string_hdr_create(_req->pool,
                                                    &STR_DIVERSION,
                                                    pj_cstr(&sdiv, div.c_str()));
    pjsip_msg_add_hdr(_req->msg, (pjsip_hdr*)diversion);

    // Create or update a History-Info header for the old target.
    if (prev_history_info_hdr == NULL)
    {
      prev_history_info_hdr = create_history_info_hdr(_req->msg->line.req.uri);
      prev_history_info_hdr->index = pj_str("1");
      pjsip_msg_add_hdr(_req->msg, (pjsip_hdr*)prev_history_info_hdr);
    }

    update_history_info_reason(((pjsip_name_addr*)(prev_history_info_hdr->uri))->uri, code);

    // Set up the new target URI.
    _req->msg->line.req.uri = target;

    // Create a History-Info header for the new target.
    pjsip_history_info_hdr* history_info_hdr = create_history_info_hdr(target);

    // Set up the index parameter.  This is the previous value suffixed with ".1".
    history_info_hdr->index.slen = prev_history_info_hdr->index.slen + 2;
    history_info_hdr->index.ptr = (char*)pj_pool_alloc(_req->pool, history_info_hdr->index.slen);
    pj_memcpy(history_info_hdr->index.ptr, prev_history_info_hdr->index.ptr, prev_history_info_hdr->index.slen);
    pj_memcpy(history_info_hdr->index.ptr + prev_history_info_hdr->index.slen, ".1", 2);

    pjsip_msg_add_hdr(_req->msg, (pjsip_hdr*)history_info_hdr);

    // Kick off outgoing processing for the new request.  Continue the
    // existing AsChain. This will trigger orig-cdiv handling.
    handle_non_cancel(ServingState(&SessionCase::Terminating, _as_chain_link), NULL);
  }
  else
  {
    send_response(code);
  }

  return false;
}


pjsip_history_info_hdr* UASTransaction::create_history_info_hdr(pjsip_uri* target)
{
  // Create a History-Info header.
  pjsip_history_info_hdr* history_info_hdr = pjsip_history_info_hdr_create(_req->pool);

  // Clone the URI and set up its parameters.
  pjsip_uri* history_info_uri = (pjsip_uri*)pjsip_uri_clone(_req->pool, (pjsip_uri*)pjsip_uri_get_uri(target));
  pjsip_name_addr* history_info_name_addr_uri = pjsip_name_addr_create(_req->pool);
  history_info_name_addr_uri->uri = history_info_uri;
  history_info_hdr->uri = (pjsip_uri*)history_info_name_addr_uri;

  return history_info_hdr;
}


void UASTransaction::update_history_info_reason(pjsip_uri* history_info_uri, int code)
{
  static const pj_str_t STR_REASON = pj_str("Reason");
  static const pj_str_t STR_SIP = pj_str("SIP");
  static const pj_str_t STR_CAUSE = pj_str("cause");
  static const pj_str_t STR_TEXT = pj_str("text");

  if (PJSIP_URI_SCHEME_IS_SIP(history_info_uri))
  {
    // Set up the Reason parameter - this is always "SIP".
    pjsip_sip_uri* history_info_sip_uri = (pjsip_sip_uri*)history_info_uri;
    if (pj_list_empty(&history_info_sip_uri->other_param))
    {
      pjsip_param *param = PJ_POOL_ALLOC_T(_req->pool, pjsip_param);
      param->name = STR_REASON;
      param->value = STR_SIP;

      pj_list_insert_after(&history_info_sip_uri->other_param, (pj_list_type*)param);

      // Now add the cause parameter.
      param = PJ_POOL_ALLOC_T(_req->pool, pjsip_param);
      param->name = STR_CAUSE;
      char cause_text[4];
      sprintf(cause_text, "%u", code);
      pj_strdup2(_req->pool, &param->value, cause_text);
      pj_list_insert_after(&history_info_sip_uri->other_param, param);

      // Finally add the text parameter.
      param = PJ_POOL_ALLOC_T(_req->pool, pjsip_param);
      param->name = STR_TEXT;
      param->value = *pjsip_get_status_text(code);
      pj_list_insert_after(&history_info_sip_uri->other_param, param);
    }
  }
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

// Set the target for this UAC transaction.
//
void UACTransaction::set_target(const struct Target& target)
{
  enter_context();

  if (target.from_store)
  {
    // This target came from the registration store.  Before we overwrite the
    // URI, extract its AOR and write it to the P-Called-Party-ID header.
    static const pj_str_t called_party_id_hdr_name = pj_str("P-Called-Party-ID");
    pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(_tdata->msg, &called_party_id_hdr_name, NULL);
    if (hdr)
    {
      pj_list_erase(hdr);
    }
    std::string name_addr_str("<" + PJUtils::aor_from_uri((pjsip_sip_uri*)_tdata->msg->line.req.uri) + ">");
    pj_str_t called_party_id;
    pj_strdup2(_tdata->pool,
               &called_party_id,
               name_addr_str.c_str());
    hdr = (pjsip_hdr*)pjsip_generic_string_hdr_create(_tdata->pool,
                                                      &called_party_id_hdr_name,
                                                      &called_party_id);
    pjsip_msg_add_hdr(_tdata->msg, hdr);
  }

  // Write the target in to the request.  Need to clone the URI to make
  // sure it comes from the right pool.
  _tdata->msg->line.req.uri = (pjsip_uri*)pjsip_uri_clone(_tdata->pool, target.uri);

  // If the target is routing to the upstream device (we're acting as an access
  // proxy), strip any extra loose routes on the message to prevent accidental
  // double routing.
  if (target.upstream_route)
  {
    LOG_DEBUG("Stripping loose routes from proxied message");

    // Tight loop to strip all route headers.
    while (pjsip_msg_find_remove_hdr(_tdata->msg,
                                     PJSIP_H_ROUTE,
                                     NULL) != NULL)
    {
      // Tight loop.
    };
  }

  // Store the liveness timeout.
  _liveness_timeout = target.liveness_timeout;

  // Add all the paths as a sequence of Route headers.
  for (std::list<pjsip_uri*>::const_iterator pit = target.paths.begin();
       pit != target.paths.end();
       ++pit)
  {
    // We may have a nameaddr here rather than a URI - if so,
    // pjsip_uri_get_uri will return the internal URI. Otherwise, it
    // will just return the URI.
    pjsip_sip_uri* uri = (pjsip_sip_uri*)pjsip_uri_get_uri(*pit);

    LOG_DEBUG("Adding a Route header to sip:%.*s%s%.*s:%d;transport=%.*s",
              uri->user.slen, uri->user.ptr,
              (uri->user.slen != 0) ? "@" : "",
              uri->host.slen, uri->host.ptr,
              uri->port,
              uri->transport_param.slen,
              uri->transport_param.ptr);
    pjsip_route_hdr* route_hdr = pjsip_route_hdr_create(_tdata->pool);
    route_hdr->name_addr.uri = (pjsip_uri*)pjsip_uri_clone(_tdata->pool, uri);
    pjsip_msg_add_hdr(_tdata->msg, (pjsip_hdr*)route_hdr);
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

    _tdata->dest_info.addr.count = 1;
    _tdata->dest_info.addr.entry[0].type = (pjsip_transport_type_e)target.transport->key.type;
    pj_memcpy(&_tdata->dest_info.addr.entry[0].addr, &target.transport->key.rem_addr, sizeof(pj_sockaddr));
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
    LOG_DEBUG("Resolve next hop destination");
    PJUtils::resolve_next_hop(_tdata, 0, _servers, trail());
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
    LOG_DEBUG("Transport %s (%s) pre-selected for transaction",
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
    LOG_DEBUG("Sending request for %s", PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, _tdata->msg->line.req.uri).c_str());
    _uas_data->_downstream_acr->tx_request(_tdata->msg);
    status = pjsip_tsx_send_msg(_tsx, _tdata);
  }

  if (status != PJ_SUCCESS)
  {
    // Failed to send the request.  This is an unexpected error rather than
    // an indication that the selected destination is down, so we do not
    // attempt a retry and do not blacklist the selected destination.
    LOG_DEBUG("Failed to send request (%d %s)",
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
    LOG_DEBUG("Found transaction %s status=%d", name(), _tsx->status_code);
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
      LOG_DEBUG("Sending CANCEL request");
      pj_status_t status = PJUtils::send_request(cancel, 1);

      // We used to deregister the user here if we had
      // SIP_STATUS_FLOW_FAILED, but this is inappropriate - only one
      // of their bindings has failed, but they may be registered
      // elsewhere. If this was the last binding, Chronos will
      // eventually time it out and cause a deregistration.

      if (status != PJ_SUCCESS)
      {
        LOG_ERROR("Error sending CANCEL, %s", PJUtils::pj_status_to_string(status).c_str());
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
  LOG_DEBUG("%s - uac_data = %p, uas_data = %p", name(), this, _uas_data);

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
        LOG_DEBUG("Failed to connected to server, so add to blacklist");
        PJUtils::blacklist_server(_servers[_current_server]);

        // Attempt a retry.
        retrying = retry_request();
      }
      else if ((event->body.tsx_state.tsx->state == PJSIP_TSX_STATE_COMPLETED) &&
               (PJSIP_IS_STATUS_IN_CLASS(_tsx->status_code, 500)))
      {
        // The server returned a 5xx error.  We don't blacklist in this case
        // as it may indicated a transient overload condition, but we can
        // retry to an alternate server if one is available.
        retrying = retry_request();
      }
    }

    if (!retrying)
    {
      if (event->body.tsx_state.type == PJSIP_EVENT_RX_MSG)
      {
        LOG_DEBUG("%s - RX_MSG on active UAC transaction", name());
        if (_liveness_timer.id == LIVENESS_TIMER)
        {
          // The liveness timer is running on this transaction, so cancel it.
          _liveness_timer.id = 0;
          pjsip_endpt_cancel_timer(stack_data.endpt, &_liveness_timer);
        }

        pjsip_rx_data* rdata = event->body.tsx_state.src.rdata;
        _uas_data->on_new_client_response(this, rdata);
      }

      // If UAC transaction is terminated because of a timeout, treat this as
      // a 504 error.
      if ((event->body.tsx_state.tsx->state == PJSIP_TSX_STATE_TERMINATED) &&
          (_uas_data != NULL))
      {
        // UAC transaction has terminated while still connected to the UAS
        // transaction.
        LOG_DEBUG("%s - UAC tsx terminated while still connected to UAS tsx",
                  _tsx->obj_name);
        if ((event->body.tsx_state.type == PJSIP_EVENT_TIMER) ||
            (event->body.tsx_state.type == PJSIP_EVENT_TRANSPORT_ERROR))
        {
          LOG_DEBUG("Timeout or transport error");
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
    LOG_DEBUG("%s - UAC tsx destroyed", _tsx->obj_name);
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
    LOG_DEBUG("Attempt to retry request to alternate server");
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
      LOG_DEBUG("Created transaction for retry, so send request");
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
        // through to the end.
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

  // verify that the timer has not been cancelled halfway through expiry
  if (_trying_timer.id == TRYING_TIMER)
  {
    send_trying(_defer_rdata);
    _trying_timer.id = 0;
    pjsip_rx_data_free_cloned(_defer_rdata);
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

pj_status_t init_stateful_proxy(RegStore* registrar_store,
                                RegStore* remote_reg_store,
                                CallServices* call_services,
                                IfcHandler* ifc_handler_in,
                                pj_bool_t enable_edge_proxy,
                                const std::string& upstream_proxy_arg,
                                int upstream_proxy_port,
                                int upstream_proxy_connections,
                                int upstream_proxy_recycle,
                                pj_bool_t enable_ibcf,
                                const std::string& ibcf_trusted_hosts,
                                AnalyticsLogger* analytics,
                                EnumService *enumService,
                                bool enforce_user_phone,
                                bool enforce_global_only_lookups,
                                BgcfService *bgcfService,
                                HSSConnection* hss_connection,
                                ACRFactory* cscf_rfacr_factory,
                                ACRFactory* bgcf_rfacr_factory,
                                ACRFactory* icscf_rfacr_factory,
                                const std::string& icscf_uri_str,
                                QuiescingManager* quiescing_manager,
                                SCSCFSelector *scscfSelector,
                                bool icscf_enabled,
                                bool scscf_enabled,
                                bool emerg_reg_accepted)
{
  pj_status_t status;

  analytics_logger = analytics;
  store = registrar_store;
  remote_store = remote_reg_store;

  call_services_handler = call_services;
  ifc_handler = ifc_handler_in;

  icscf = icscf_enabled;
  scscf = scscf_enabled;
  allow_emergency_reg = emerg_reg_accepted;

  cscf_acr_factory = cscf_rfacr_factory;
  bgcf_acr_factory = bgcf_rfacr_factory;
  icscf_acr_factory = icscf_rfacr_factory;

  edge_proxy = enable_edge_proxy;
  if (edge_proxy)
  {
    // Create a URI for the upstream proxy to use in Route headers.
    upstream_proxy = (pjsip_uri*)pjsip_sip_uri_create(stack_data.pool, PJ_FALSE);
    ((pjsip_sip_uri*)upstream_proxy)->host = pj_strdup3(stack_data.pool, upstream_proxy_arg.c_str());
    ((pjsip_sip_uri*)upstream_proxy)->port = upstream_proxy_port;
    ((pjsip_sip_uri*)upstream_proxy)->transport_param = pj_str("TCP");
    ((pjsip_sip_uri*)upstream_proxy)->lr_param = 1;

    // Create a flow table object to manage the client flow records
    // and handle access proxy quiescing.
    flow_table = new FlowTable(quiescing_manager, stack_data.stats_aggregator);
    quiescing_manager->register_flows_handler(flow_table);


    // Create a dialog tracker to count dialogs on each flow
    dialog_tracker = new DialogTracker(flow_table);

    // Create a connection pool to the upstream proxy.
    if (upstream_proxy_connections > 0)
    {
      pjsip_host_port pool_target;
      pool_target.host = pj_strdup3(stack_data.pool, upstream_proxy_arg.c_str());
      pool_target.port = upstream_proxy_port;
      upstream_conn_pool = new ConnectionPool(&pool_target,
                                              upstream_proxy_connections,
                                              upstream_proxy_recycle,
                                              stack_data.pool,
                                              stack_data.endpt,
                                              stack_data.pcscf_trusted_tcp_factory,
                                              stack_data.stats_aggregator);
      upstream_conn_pool->init();
    }

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
    // Routing proxy (Sprout - S-CSCF and I-CSCF).
    as_chain_table = new AsChainTable;

    // Build a Record-Route header with the S-CSCF URI
    scscf_rr = pjsip_rr_hdr_create(stack_data.pool);
    scscf_rr->name_addr.uri = (pjsip_uri*)pjsip_parse_uri(stack_data.pool,
                                                          stack_data.scscf_uri.ptr,
                                                          stack_data.scscf_uri.slen,
                                                          0);
    ((pjsip_sip_uri*)scscf_rr->name_addr.uri)->lr_param = PJ_TRUE;

    // Extract the S-CSCF domain name which is used to determine whether
    // the S-CSCF name returned in an I-CSCF LIR is targeted at this Sprout
    // cluster.
    scscf_domain_name = ((pjsip_sip_uri*)scscf_rr->name_addr.uri)->host;
  }

  enum_service = enumService;
  user_phone = enforce_user_phone;
  global_only_lookups = enforce_global_only_lookups;
  bgcf_service = bgcfService;
  hss = hss_connection;
  scscf_selector = scscfSelector;

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

  status = pjsip_endpt_register_module(stack_data.endpt, &mod_stateful_proxy);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

  status = pjsip_endpt_register_module(stack_data.endpt, &mod_tu);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

  return PJ_SUCCESS;
}

#ifdef UNIT_TEST
// These setter functions are for unit test purposes only
void set_user_phone(bool enforce_user_phone)
{
  user_phone = enforce_user_phone;
}

void set_global_only_lookups(bool enforce_global_only_lookups)
{
  global_only_lookups = enforce_global_only_lookups;
}
#endif

void destroy_stateful_proxy()
{
  if (edge_proxy)
  {
    // Destroy the upstream connection pool.  This will quiesce all the TCP
    // connections.
    delete upstream_conn_pool; upstream_conn_pool = NULL;

    // Destroy the flow table.
    delete flow_table;
    flow_table = NULL;

    delete dialog_tracker;
    dialog_tracker = NULL;
  }
  else
  {
    delete as_chain_table;
    as_chain_table = NULL;
  }

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

// Determines whether a user string represents a global number.
//
// @returns PJ_TRUE if so, PJ_FALSE if not.
static pj_bool_t is_user_global(const std::string& user)
{
  if (user.size() > 0 && user[0] == '+')
  {
    return PJ_TRUE;
  }
  return PJ_FALSE;
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


/// Factory method: create AsChain by looking up iFCs.
AsChainLink UASTransaction::create_as_chain(const SessionCase& session_case,
                                            Ifcs ifcs,
                                            std::string served_user)
{
  if (served_user.empty())
  {
    LOG_WARNING("create_as_chain called with an empty served_user");
  }
  bool is_registered = is_user_registered(served_user);

  // Select the ACR to use for the AS Chain.  For originating chains and
  // terminating chains we use the upstream and downstream ACRs respectivly.
  // For the originating-cdiv case we create a new ACR copied from the
  // downstream ACR.
  ACR* acr = NULL;
  if (session_case == SessionCase::Originating)
  {
    // Originating chain, so use upstream ACR.
    acr = _upstream_acr;
  }
  else if (session_case == SessionCase::Terminating)
  {
    // Terminating chain, so use downstream ACR.
    acr = _downstream_acr;
  }
  else if (session_case == SessionCase::OriginatingCdiv)
  {
    // Originating-cdiv chain, so create a copy of the downstream ACR.
    acr = new ACR(*_downstream_acr);
  }

  // Create the AsChain, and schedule its destruction.  AsChain
  // lifetime is tied to the lifetime of the creating transaction.
  //
  // Rationale:
  //
  // Consider two successive Sprout UAS transactions Ai and Ai+1 in
  // the chain. Sprout creates Ai+1 in response to it receiving the Ai
  // ODI token from the AS.
  //
  // (1) Ai+1 can only be created if the ODI is valid at the point
  // Sprout receives the transaction-creating message.
  //
  // (2) Before the point Sprout creates Ai+1, the ODI’s lifetime
  // cannot be dependent on Ai+1, but only on Ai (and previous
  // transactions).
  //
  // (3) Hence at the point Ai+1 is created, Ai must still be live.
  //
  // (4) This applies transitively, so the lifetime of A0 bounds the
  // lifetime of Aj for all j.
  //
  // This means that there’s a constraint on B2BUA AS behaviour: it
  // must not give a final response to the inbound transaction before
  // receiving a final response from the outbound transaction.
  //
  // While this constraint is not stated explicitly in 24.229, there
  // is no other sensible lifetime for the ODI token. The alternative
  // would allow B2BUAs that gave a final response to the caller, and
  // then at some arbitrary time later did some action that continued
  // the original AS chain, which is nonsensical.

  AsChainLink ret = AsChainLink::create_as_chain(as_chain_table,
                                                 session_case,
                                                 served_user,
                                                 is_registered,
                                                 trail(),
                                                 ifcs,
                                                 acr);
  _victims.push_back(ret.as_chain());
  LOG_DEBUG("UASTransaction %p linked to AsChain %s", this, ret.to_string().c_str());
  return ret;
}

///@}
