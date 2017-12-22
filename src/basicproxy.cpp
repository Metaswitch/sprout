/**
 * @file basicproxy.cpp  BasicProxy class implementation
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
#include "pjsip-simple/evsub.h"
}

#include <vector>


#include "log.h"
#include "utils.h"
#include "pjutils.h"
#include "stack.h"
#include "sproutsasevent.h"
#include "constants.h"
#include "basicproxy.h"
#include "uri_classifier.h"


BasicProxy::BasicProxy(pjsip_endpoint* endpt,
                       std::string name,
                       int priority,
                       bool delay_trying,
                       const std::set<std::string>& stateless_proxies) :
  _mod_proxy(this, endpt, name, priority, PJMODULE_MASK_PROXY),
  _mod_tu(this, endpt, name + "-tu", priority, PJMODULE_MASK_TU),
  _delay_trying(delay_trying),
  _endpt(endpt),
  _stateless_proxies(stateless_proxies)
{
}


BasicProxy::~BasicProxy()
{
}


// Callback to be called to handle incoming request outside of a
// existing transaction context.
pj_bool_t BasicProxy::on_rx_request(pjsip_rx_data* rdata)
{
  if (rdata->msg_info.msg->line.req.method.id != PJSIP_CANCEL_METHOD)
  {
    // Request is a normal transaction request.
    TRC_DEBUG("Process %.*s request",
              rdata->msg_info.msg->line.req.method.name.slen,
              rdata->msg_info.msg->line.req.method.name.ptr);
    on_tsx_request(rdata);
  }
  else
  {
    // Request is a CANCEL.
    TRC_DEBUG("Process CANCEL request");
    on_cancel_request(rdata);
  }

  return PJ_TRUE;
}


// Callback to be called to handle incoming response outside
// any transactions. This happens for example when 2xx/OK
// for INVITE is received and transaction will be destroyed
// immediately, so we need to forward the subsequent 2xx/OK
// retransmission statelessly.
pj_bool_t BasicProxy::on_rx_response(pjsip_rx_data *rdata)
{
  pjsip_tx_data *tdata;
  pjsip_response_addr res_addr;
  pjsip_via_hdr *hvia;
  pj_status_t status;

  TRC_DEBUG("Statelessly forwarding late response");

  // Only forward responses to INVITES.
  if (rdata->msg_info.cseq->method.id == PJSIP_INVITE_METHOD)
  {
    // Create response to be forwarded upstream (Via will be stripped here)
    status = PJUtils::create_response_fwd(stack_data.endpt, rdata, 0, &tdata);
    if (status != PJ_SUCCESS)
    {
      // LCOV_EXCL_START
      TRC_ERROR("Error creating response, %s",
                PJUtils::pj_status_to_string(status).c_str());
      return PJ_TRUE;
      // LCOV_EXCL_STOP
    }

    // Get topmost Via header.
    hvia = (pjsip_via_hdr*)pjsip_msg_find_hdr(tdata->msg, PJSIP_H_VIA, NULL);
    if (hvia == NULL)
    {
      // Invalid response! Just drop it.
      pjsip_tx_data_dec_ref(tdata);
      return PJ_TRUE;
    }

    // Calculate the address to forward the response.
    pj_bzero(&res_addr, sizeof(res_addr));
    res_addr.dst_host.type = pjsip_transport_get_type_from_name(&hvia->transport);
    res_addr.dst_host.flag =
                     pjsip_transport_get_flag_from_type(res_addr.dst_host.type);

    // Destination address is Via's received param.
    res_addr.dst_host.addr.host = hvia->recvd_param;
    if (res_addr.dst_host.addr.host.slen == 0)
    {
      // Someone has messed up our Via header!
      res_addr.dst_host.addr.host = hvia->sent_by.host;
    }

    // Destination port is the rport.
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

    // Forward response.
    status = pjsip_endpt_send_response(stack_data.endpt, &res_addr, tdata, NULL, NULL);

    if (status != PJ_SUCCESS)
    {
      // LCOV_EXCL_START
      TRC_ERROR("Error forwarding response, %s",
                PJUtils::pj_status_to_string(status).c_str());
      return PJ_TRUE;
      // LCOV_EXCL_STOP
    }
  }

  return PJ_TRUE;
}


// Callback to be called to handle transmitted request.
// LCOV_EXCL_START - only needed to prevent linker error.
pj_status_t BasicProxy::on_tx_request(pjsip_tx_data* tdata)
{
  return PJ_SUCCESS;
}
// LCOV_EXCL_STOP


// Callback to be called to handle transmitted response.
// LCOV_EXCL_START - only needed to prevent linker error.
pj_status_t BasicProxy::on_tx_response(pjsip_tx_data* tdata)
{
  return PJ_SUCCESS;
}
// LCOV_EXCL_STOP


// Callback to be called to handle transaction state changed.
void BasicProxy::on_tsx_state(pjsip_transaction* tsx, pjsip_event* event)
{
  TRC_DEBUG("%s - tu_on_tsx_state %s, %s %s state=%s",
            tsx->obj_name,
            pjsip_role_name(tsx->role),
            pjsip_event_str(event->type),
            pjsip_event_str(event->body.tsx_state.type),
            pjsip_tsx_state_str(tsx->state));

  if (tsx->role == PJSIP_ROLE_UAS)
  {
    UASTsx* uas_tsx = (UASTsx*)get_from_transaction(tsx);
    if (uas_tsx != NULL)
    {
      uas_tsx->on_tsx_state(event);
    }
  }
  else
  {
    UACTsx* uac_tsx = (UACTsx*)get_from_transaction(tsx);
    if (uac_tsx != NULL)
    {
      uac_tsx->on_tsx_state(event);
    }
  }
}


/// Binds a UASTsx or UACTsx object to a PJSIP transaction.
void BasicProxy::bind_transaction(void* uas_uac_tsx, pjsip_transaction* tsx)
{
  tsx->mod_data[_mod_tu.id()] = uas_uac_tsx;
}


/// Unbinds a UASTsx or UACTsx object from a PJSIP transaction.
void BasicProxy::unbind_transaction(pjsip_transaction* tsx)
{
  tsx->mod_data[_mod_tu.id()] = NULL;
}


/// Gets the UASTsx or UACTsx object bound to a PJSIP transaction.
void* BasicProxy::get_from_transaction(pjsip_transaction* tsx)
{
  return tsx->mod_data[_mod_tu.id()];
}


/// Process a transaction (that is, non-CANCEL) request.
void BasicProxy::on_tsx_request(pjsip_rx_data* rdata)
{
  // Verify incoming request.
  int status_code = verify_request(rdata);
  if (status_code != PJSIP_SC_OK)
  {
    reject_request(rdata, status_code);
    return;
  }

  // Request looks sane, so create and initialize an object to handle the
  // request.
  UASTsx* uas_tsx = create_uas_tsx();
  pj_status_t status = (uas_tsx != NULL) ? uas_tsx->init(rdata) : PJ_ENOMEM;

  if (status != PJ_SUCCESS)
  {
    // LCOV_EXCL_START
    TRC_ERROR("Failed to create BasicProxy UAS transaction object, %s",
              PJUtils::pj_status_to_string(status).c_str());
    reject_request(rdata, PJSIP_SC_INTERNAL_SERVER_ERROR);
    delete uas_tsx;
    return;
    // LCOV_EXCL_STOP
  }

  // Process the request.
  uas_tsx->process_tsx_request(rdata);

  // Initializing the transaction entered its context, so exit now.
  uas_tsx->exit_context();
}


/// Process a received CANCEL request.
void BasicProxy::on_cancel_request(pjsip_rx_data* rdata)
{
  pjsip_transaction *invite_uas;
  pj_str_t key;

  // Find the UAS INVITE transaction.
  pjsip_tsx_create_key(rdata->tp_info.pool, &key, PJSIP_UAS_ROLE,
                       pjsip_get_invite_method(), rdata);
  invite_uas = pjsip_tsx_layer_find_tsx(&key, PJ_TRUE);
  if (!invite_uas)
  {
    // Invite transaction not found, respond to CANCEL with 481
    reject_request(rdata, PJSIP_SC_CALL_TSX_DOES_NOT_EXIST);
    return;
  }

  UASTsx *uas_tsx = (UASTsx*)get_from_transaction(invite_uas);

  if (uas_tsx == NULL)
  {
    // LCOV_EXCL_START
    //
    // The PJSIP transaction exists but there is no UASTsx associated with it.
    // The only case where this happens is a window condition where
    // - the PJSIP transaction is already in state destroyed because we have
    //   sent a final response
    // - we've been told about this via on_tsx_state and so have unbound the
    //   UASTsx
    // - PJSIP just hasn't yet freed up the actual Tsx.
    // Given that we will already have sent a final response to the INVITE we
    // should treat this as though the INVITE has already been destroyed.
    reject_request(rdata, PJSIP_SC_CALL_TSX_DOES_NOT_EXIST);

    // Unlock UAS tsx because it is locked in find_tsx()
    pj_grp_lock_release(invite_uas->grp_lock);

    return;
    // LCOV_EXCL_STOP
  }

  // Respond 200 OK to CANCEL.  Must do this statefully.
  pjsip_transaction* cancel_tsx;
  pj_status_t status = pjsip_tsx_create_uas(NULL, rdata, &cancel_tsx);
  if (status != PJ_SUCCESS)
  {
    // LCOV_EXCL_START
    reject_request(rdata, PJSIP_SC_INTERNAL_SERVER_ERROR);

    // Unlock UAS tsx because it is locked in find_tsx()
    pj_grp_lock_release(invite_uas->grp_lock);

    return;
    // LCOV_EXCL_STOP
  }

  // Set the SAS trail on the CANCEL transaction.
  set_trail(cancel_tsx, get_trail(rdata));

  // Feed the CANCEL request to the transaction.
  pjsip_tsx_recv_msg(cancel_tsx, rdata);

  // Send the 200 OK statefully.
  PJUtils::respond_stateful(stack_data.endpt, cancel_tsx, rdata, 200, NULL, NULL, NULL);

  // Send CANCEL to cancel the UAC transactions.
  // The UAS INVITE transaction will get final response when
  // we receive final response from the UAC INVITE transaction.
  uas_tsx->process_cancel_request(rdata, "CANCEL request received from peer");

  // Unlock UAS tsx because it is locked in find_tsx()
  pj_grp_lock_release(invite_uas->grp_lock);
}


/// Proxy utility to verify incoming requests.
// Return non-zero if verification failed.
int BasicProxy::verify_request(pjsip_rx_data *rdata)
{
  // RFC 3261 Section 16.3 Request Validation.

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
  if ((rdata->msg_info.max_fwd) &&
      (rdata->msg_info.max_fwd->ivalue <= 1))
  {
    return PJSIP_SC_TOO_MANY_HOPS;
  }

  // 4. (Optional) Loop Detection.  Not checked in the BasicProxy.

  // 5. Proxy-Require.  This isn't checked in the BasicProxy, inheriting
  // classes may implement checks on this.

  // 6. Proxy-Authorization.  Not checked in the BasicProxy.

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
void BasicProxy::reject_request(pjsip_rx_data* rdata, int status_code)
{
  if (rdata->msg_info.msg->line.req.method.id != PJSIP_ACK_METHOD)
  {
    TRC_DEBUG("Rejecting %.*s request with %d status code",
              rdata->msg_info.msg->line.req.method.name.slen,
              rdata->msg_info.msg->line.req.method.name.ptr,
              status_code);
    PJUtils::respond_stateless(stack_data.endpt,
                               rdata,
                               status_code,
                               NULL,
                               NULL,
                               NULL);
  }
}


/// Creates a UASTsx object.
// LCOV_EXCL_START - Overriden in UT.
BasicProxy::UASTsx* BasicProxy::create_uas_tsx()
{
  return new UASTsx(this);
}
// LCOV_EXCL_STOP


/// UAS Transaction constructor.
BasicProxy::UASTsx::UASTsx(BasicProxy* proxy) :
  _proxy(proxy),
  _req(NULL),
  _original_transport(NULL),
  _tsx(NULL),
  _lock(NULL),
  _trail(0),
  _targets(),
  _uac_tsx(),
  _pending_sends(0),
  _pending_responses(0),
  _final_rsp(NULL),
  _pending_destroy(false),
  _context_count(0)
{
  // Don't do any set-up that could fail in here - do that in the init method.
}


void BasicProxy::UASTsx::unbind_from_pjsip_tsx()
{
  // We expect to only be called on the PJSIP transport thread, and our data
  // race/locking safety is based on this assumption. Raise an error log if
  // this is not the case.
  CHECK_PJ_TRANSPORT_THREAD();

  if (_tsx != NULL)
  {
    // Unbind from the PJSIP transaction.
    _proxy->unbind_transaction(_tsx);
    _tsx = NULL;

    // The trying timer should only be running when we have a PJSIP transaction,
    // so cancel it if it is running.
    if (_trying_timer.id == TRYING_TIMER)
    {
      _trying_timer.id = 0;
      pjsip_endpt_cancel_timer(stack_data.endpt, &_trying_timer);
    }
  }
}


BasicProxy::UASTsx::~UASTsx()
{
  TRC_DEBUG("BasicProxy::UASTsx destructor (%p)", this);

  pj_assert(_context_count == 0);

  if (_tsx != NULL)
  {
    // LCOV_EXCL_START
    //
    // This branch should never be hit as the UASTSx should only be destroyed
    // when there is no underlying PJSIP transaction.  However if we do hit this
    // branch we try to unbind the UASTsx from PJSIP, otherwise we're almost
    // guaranteed to reference the UASTsx after it's been deleted.
    unbind_from_pjsip_tsx();
    // LCOV_EXCL_STOP
  }

  // Disconnect all UAC transactions from the UAS transaction.
  TRC_DEBUG("Disconnect UAC transactions from UAS transaction");
  for (size_t ii = 0; ii < _uac_tsx.size(); ++ii)
  {
    UACTsx* uac_tsx = _uac_tsx[ii];
    if (uac_tsx != NULL)
    {
      // LCOV_EXCL_START
      dissociate(uac_tsx);
      // LCOV_EXCL_STOP
    }
  }

  if (_original_transport != NULL)
  {
    TRC_DEBUG("Free original transport");
    pjsip_transport_dec_ref(_original_transport);
    _original_transport = NULL;
  }

  if (_req != NULL)
  {
    TRC_DEBUG("Free original request");
    pjsip_tx_data_dec_ref(_req);
    _req = NULL;
  }

  if (_final_rsp != NULL)
  {
    // The pre-built response hasn't been used, so free it.
    // LCOV_EXCL_START
    TRC_DEBUG("Free un-used best response");
    pjsip_tx_data_dec_ref(_final_rsp);
    _final_rsp = NULL;
    // LCOV_EXCL_STOP
  }

  // Delete any unactioned targets.
  while (!_targets.empty())
  {
    // LCOV_EXCL_START
    delete _targets.front();
    _targets.pop_front();
    // LCOV_EXCL_STOP
  }

  if (_lock != NULL)
  {
    pj_grp_lock_release(_lock);
    pj_grp_lock_dec_ref(_lock);
  }

  TRC_DEBUG("BasicProxy::UASTsx destructor completed");
}


/// Initializes the UASTsx object to handle proxying of the request.
pj_status_t BasicProxy::UASTsx::init(pjsip_rx_data* rdata)
{
  _trail = get_trail(rdata);

  // initialise deferred trying timer.
  pj_timer_entry_init(&_trying_timer, 0, (void*)this, &trying_timer_callback);
  _trying_timer.id = 0;

  // Do any start of transaction logging operations.
  on_tsx_start(rdata);

  _req = PJUtils::clone_msg(stack_data.endpt, rdata);
  if (_req == NULL)
  {
    // LCOV_EXCL_START - no UT for forcing PJSIP errors.
    TRC_ERROR("Failed to clone received request");
    on_tsx_complete();
    _pending_destroy = true;
    return PJ_ENOMEM;
    // LCOV_EXCL_STOP
  }

  _original_transport = rdata->tp_info.transport;
  if (_original_transport != NULL)
  {
    pjsip_transport_add_ref(_original_transport);
  }

  if (rdata->msg_info.msg->line.req.method.id != PJSIP_ACK_METHOD)
  {
    // Not an ACK message, so create a PJSIP UAS transaction for the request.
    pj_status_t status = create_pjsip_transaction(rdata);

    if (status != PJ_SUCCESS)
    {
      // Failed to create the PJSIP transaction for a stateful request.
      // LCOV_EXCL_START
      on_tsx_complete();
      _pending_destroy = true;
      return status;
      // LCOV_EXCL_STOP
    }

    // Feed the request to the UAS transaction to drive its state
    // out of NULL state.
    pjsip_tsx_recv_msg(_tsx, rdata);

    // Create a 408 response to use if none of the targets responds.
    pjsip_endpt_create_response(stack_data.endpt,
                                rdata,
                                PJSIP_SC_REQUEST_TIMEOUT,
                                NULL,
                                &_final_rsp);

    // If delay_trying is enabled, then don't send a 100 Trying now.
    if ((rdata->msg_info.msg->line.req.method.id == PJSIP_INVITE_METHOD) &&
        (!_proxy->_delay_trying))
    {
      // If the request is an INVITE then send the 100 Trying straight away.
      TRC_DEBUG("Send immediate 100 Trying response");
      send_response(100);
    }
    else if (!_proxy->_delay_trying)
    {
      // Send the 100 Trying after 3.5 secs if a final response hasn't been
      // sent.
      _trying_timer.id = TRYING_TIMER;
      pj_time_val delay = {(PJSIP_T2_TIMEOUT - PJSIP_T1_TIMEOUT) / 1000,
                           (PJSIP_T2_TIMEOUT - PJSIP_T1_TIMEOUT) % 1000 };
      pjsip_endpt_schedule_timer(stack_data.endpt, &(_trying_timer), &delay);
    }
  }
  else
  {
    // ACK will be forwarded statelessly, so we don't need a PJSIP transaction.
    // Enter the context of this object so the context count gets incremented.
    enter_context();
  }

  return PJ_SUCCESS;
}


/// Handle the incoming half of a transaction request.
void BasicProxy::UASTsx::process_tsx_request(pjsip_rx_data* rdata)
{
  // Process routing headers.
  int status_code = process_routing();

  if ((status_code == PJSIP_SC_OK) &&
      (_targets.size() == 0))
  {
    // We don't have any targets yet, so calculate them now.
    status_code = calculate_targets();
    if (status_code != PJSIP_SC_OK)
    {
      TRC_DEBUG("Calculate targets failed with %d status code", status_code);
      send_response(status_code);
    }
    else if (_targets.size() == 0)
    {
      // No targets found, so reject with a 404 status code.  Should never
      // happen as calculate_targets should return a status code if it
      // doesn't add any targets.
      // LCOV_EXCL_START - Should never happen.
      TRC_INFO("Reject request with 404");
      status_code = PJSIP_SC_NOT_FOUND;
      // LCOV_EXCL_STOP
    }
  }

  if (status_code == PJSIP_SC_OK)
  {
    // Now set up the data structures and transactions required to
    // process the request and send it.
    pj_status_t status = forward_to_targets();

    if (status != PJ_SUCCESS)
    {
      // Send 500/Internal Server Error to UAS transaction
      // LCOV_EXCL_START
      TRC_ERROR("Failed to allocate UAC transaction for UAS transaction");
      status_code = PJSIP_SC_INTERNAL_SERVER_ERROR;
      // LCOV_EXCL_STOP
    }
  }

  if (_tsx == NULL)
  {
    // ACK request, so no response to wait for.
    TRC_DEBUG("ACK transaction is complete");
    on_tsx_complete();
    _pending_destroy = true;
  }
  else if (status_code != PJSIP_SC_OK)
  {
    // Failed to forward the request, so send a response with the appropriate
    // status code.
    send_response(status_code);
  }
}


/// Handle a received CANCEL request.
void BasicProxy::UASTsx::process_cancel_request(pjsip_rx_data* rdata, const std::string& reason)
{
  TRC_DEBUG("%s - Cancel for UAS transaction", name());

  enter_context();

  // Send CANCEL to cancel the UAC transactions.
  // The UAS INVITE transaction will get final response when
  // we receive final response from the UAC INVITE transaction.
  cancel_pending_uac_tsx(0, reason, false);

  exit_context();
}


/// Process route information in the request.
int BasicProxy::UASTsx::process_routing()
{
  pjsip_msg* msg = _req->msg;
  pjsip_sip_uri* req_uri = (pjsip_sip_uri*)msg->line.req.uri;
  URIClass uri_class = URIClassifier::classify_uri(msg->line.req.uri);
  pjsip_route_hdr* hroute;

  // RFC 3261 Section 16.4 Route Information Preprocessing.


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

    // Find the first Route header.
    r = hroute = (pjsip_route_hdr*)pjsip_msg_find_hdr(msg,
                                                      PJSIP_H_ROUTE,
                                                      NULL);
    if (r == NULL)
    {
      // No Route header. This request is destined for this proxy.
      return PJSIP_SC_OK;
    }

    // Find the last Route header.
    while ((r = (pjsip_route_hdr*)pjsip_msg_find_hdr(msg,
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
      msg->line.req.uri = hroute->name_addr.uri;
      req_uri = (pjsip_sip_uri*)msg->line.req.uri;
      pj_list_erase(hroute);
    }
  }

  // maddr handling for source routing is considered deprecated, so we don't
  // support it.  (See RFC 3261/19.1.1 - recommendation is to use Route headers
  // if requests must traverse a fixed set of proxies.)

  // Route on the top route header if present.
  hroute = (pjsip_route_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_ROUTE, NULL);
  if (hroute != NULL)
  {
    URIClass hroute_uri_class = URIClassifier::classify_uri(hroute->name_addr.uri);
    if ((hroute_uri_class != NODE_LOCAL_SIP_URI) &&
        (hroute_uri_class != HOME_DOMAIN_SIP_URI))
    {
      // The top route header is not this node or the local domain so set up
      // a target containing just the Request URI so the requesst will be
      // routed to the next node in the route set.
      TRC_DEBUG("Route to next hop in route set");
      Target* target = new Target;
      target->uri = (pjsip_uri*)req_uri;
      add_target(target);
    }
    else
    {
      // The top route header indicates this proxy or home domain, so
      // MUST remove that value from the request.
      TRC_DEBUG("Remove top Route header referencing this node/domain");
      pj_list_erase(hroute);
    }
  }

  return PJSIP_SC_OK;
}


/// Create a PJSIP UAS transaction for handling stateful request proxying.
pj_status_t BasicProxy::UASTsx::create_pjsip_transaction(pjsip_rx_data* rdata)
{
  // Create a group lock, and take it.  This avoids the transaction being
  // destroyed before we even get our hands on it.  It is okay to use our
  // global pool here as PJSIP creates its own pool for the lock, using the
  // same factory as the supplied pool.
  pj_status_t status = pj_grp_lock_create(stack_data.pool, NULL, &_lock);
  if (status != PJ_SUCCESS)
  {
    // LCOV_EXCL_START
    TRC_DEBUG("Failed to create group lock for transaction");
    return status;
    // LCOV_EXCL_STOP
  }
  pj_grp_lock_add_ref(_lock);
  pj_grp_lock_acquire(_lock);

  // Create a transaction for the UAS side.  We do this before looking
  // up targets because calculating targets may involve interacting
  // with an external database, and we need the transaction in place
  // early to ensure CANCEL gets handled correctly.
  status = pjsip_tsx_create_uas2(_proxy->_mod_tu.module(),
                                 rdata,
                                 _lock,
                                 &_tsx);
  if (status != PJ_SUCCESS)
  {
    // LCOV_EXCL_START
    pj_grp_lock_release(_lock);
    pj_grp_lock_dec_ref(_lock);
    _lock = NULL;
    return status;
    // LCOV_EXCL_STOP
  }

  // Bind this object to the PJSIP transaction.
  _proxy->bind_transaction(this, _tsx);

  // Enter the transaction's context, and then release our copy of the
  // group lock, but don't decrement the reference count as we need to leave
  // a reference corresponding to this UASTsx structure.
  enter_context();
  pj_grp_lock_release(_lock);

  // Set the trail identifier for the transaction using the trail ID on
  // the original message.
  set_trail(_tsx, _trail);

  return PJ_SUCCESS;
}


/// Calculate a list of targets for the message.
int BasicProxy::UASTsx::calculate_targets()
{
  pjsip_msg* msg = _req->msg;

  // RFC 3261 Section 16.5 Determining Request Targets.

  pjsip_sip_uri* req_uri = (pjsip_sip_uri*)msg->line.req.uri;

  // maddr handling is deprecated in favour of using Route headers to Route
  // requests, so is not supported.

  // If the domain of the Request-URI indicates a domain this element is
  // not responsible for, the Request-URI MUST be placed into the target
  // set as the only target, and the element MUST proceed to the task of
  // Request Forwarding (Section 16.6).
  URIClass uri_class = URIClassifier::classify_uri(msg->line.req.uri);

  if ((uri_class != NODE_LOCAL_SIP_URI) &&
      (uri_class != HOME_DOMAIN_SIP_URI))
  {
    TRC_INFO("Route request to domain %.*s",
             req_uri->host.slen, req_uri->host.ptr);
    Target* target = new Target;
    add_target(target);
    return PJSIP_SC_OK;
  }

  return PJSIP_SC_NOT_FOUND;
}


/// Adds a target to the target list for this transaction.
void BasicProxy::UASTsx::add_target(BasicProxy::Target* target)
{
  _targets.push_back(target);
}


/// Initializes UAC transactions to each of the specified targets and
/// forwards the request.
///
/// @returns a status code indicating whether or not the operation succeeded.
pj_status_t BasicProxy::UASTsx::forward_to_targets()
{
  pj_status_t status = PJ_EUNKNOWN;

  // Initialise the UAC data structures for each new target.
  _pending_sends = _targets.size();

  while (!_targets.empty())
  {
    TRC_DEBUG("Allocating transaction and data for target");
    pjsip_tx_data* uac_tdata = PJUtils::clone_tdata(_req);

    if (uac_tdata == NULL)
    {
      // LCOV_EXCL_START
      status = PJ_ENOMEM;
      TRC_ERROR("Failed to clone request for forked transaction, %s",
                PJUtils::pj_status_to_string(status).c_str());
      break;
      // LCOV_EXCL_STOP
    }

    // Set the target information in the request.
    Target* target = _targets.front();
    _targets.pop_front();
    set_req_target(uac_tdata, target);
    delete target;

    // Forward the request.
    size_t index;
    --_pending_sends;
    ++_pending_responses;
    TRC_DEBUG("Sending request, pending %d sends and %d responses",
              _pending_sends, _pending_responses);
    status = forward_request(uac_tdata, index);
    if (status != PJ_SUCCESS)
    {
      // @TODO - handle errors better!!
      // LCOV_EXCL_START
      break;
      // LCOV_EXCL_STOP
    }
  }

  return status;
}


/// Set the target for this request.
void BasicProxy::UASTsx::set_req_target(pjsip_tx_data* tdata,
                                        BasicProxy::Target* target)
{
  TRC_DEBUG("Set target for request");

  if (target->uri != NULL)
  {
    // Target has a URI, so write this in to the request URI in the request.
    // Need to clone the URI to make sure it comes from the right pool.
    TRC_DEBUG("Update Request-URI to %s",
              PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, target->uri).c_str());
    tdata->msg->line.req.uri =
                        (pjsip_uri*)pjsip_uri_clone(tdata->pool, target->uri);
  }

  for (std::list<pjsip_uri*>::const_iterator pit = target->paths.begin();
       pit != target->paths.end();
       ++pit)
  {
    // We've got a path that should be added as a Route header.
    TRC_DEBUG("Adding a Route header to sip:%.*s%s%.*s",
              ((pjsip_sip_uri*)*pit)->user.slen, ((pjsip_sip_uri*)*pit)->user.ptr,
              (((pjsip_sip_uri*)*pit)->user.slen != 0) ? "@" : "",
              ((pjsip_sip_uri*)*pit)->host.slen, ((pjsip_sip_uri*)*pit)->host.ptr);
    pjsip_route_hdr* route_hdr = pjsip_route_hdr_create(tdata->pool);
    route_hdr->name_addr.uri = (pjsip_uri*)pjsip_uri_clone(tdata->pool, *pit);
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)route_hdr);
  }

  if (target->transport != NULL)
  {
    // The target includes a selected transport, so set the transport on
    // the request.
    TRC_DEBUG("Force request to use selected transport %.*s:%d to %.*s:%d",
              target->transport->local_name.host.slen,
              target->transport->local_name.host.ptr,
              target->transport->local_name.port,
              target->transport->remote_name.host.slen,
              target->transport->remote_name.host.ptr,
              target->transport->remote_name.port);
    pjsip_tpselector tp_selector;
    tp_selector.type = PJSIP_TPSELECTOR_TRANSPORT;
    tp_selector.u.transport = target->transport;
    pjsip_tx_data_set_transport(tdata, &tp_selector);

    tdata->dest_info.addr.count = 1;
    tdata->dest_info.addr.entry[0].type = (pjsip_transport_type_e)target->transport->key.type;
    pj_memcpy(&tdata->dest_info.addr.entry[0].addr, &target->transport->key.rem_addr, sizeof(pj_sockaddr));
    tdata->dest_info.addr.entry[0].addr_len =
         (tdata->dest_info.addr.entry[0].addr.addr.sa_family == pj_AF_INET()) ?
         sizeof(pj_sockaddr_in) : sizeof(pj_sockaddr_in6);
    tdata->dest_info.cur_addr = 0;

    // Remove the reference to the transport added when it was chosen.
    pjsip_transport_dec_ref(target->transport);
  }
}

/// Allocates and initializes a new UACTsx for the request.
pj_status_t BasicProxy::UASTsx::allocate_uac(pjsip_tx_data* tdata,
                                             size_t& index,
                                             int allowed_host_state)
{
  // Create and initialize the UAC transaction.
  index = _uac_tsx.size();
  UACTsx* uac_tsx = create_uac_tsx(index);
  pj_status_t status = (uac_tsx != NULL) ? uac_tsx->init(tdata, allowed_host_state) : PJ_ENOMEM;

  if (status != PJ_SUCCESS)
  {
    // LCOV_EXCL_START
    TRC_ERROR("Failed to create/initialize UAC transaction, %s",
              PJUtils::pj_status_to_string(status).c_str());
    delete uac_tsx;
    // LCOV_EXCL_STOP
  }
  else
  {
    // Add the UAC transaction to the vector.
    _uac_tsx.push_back(uac_tsx);
  }

  return status;
}


/// Forwards a request creating a UACTsx to handle the downstream hop.
pj_status_t BasicProxy::UASTsx::forward_request(pjsip_tx_data* tdata,
                                                size_t& index)
{
  pj_status_t status = allocate_uac(tdata, index, BaseResolver::ALL_LISTS);

  if (status == PJ_SUCCESS)
  {
    _uac_tsx[index]->send_request();
  }
  return status;
}


/// Handles a response to an associated UACTsx.
void BasicProxy::UASTsx::on_new_client_response(UACTsx* uac_tsx,
                                                pjsip_tx_data *tdata)
{
  if (_tsx != NULL)
  {
    enter_context();

    int status_code = tdata->msg->line.status.code;

    if ((status_code == 100) &&
        (!_proxy->_delay_trying))
    {
      // Delay trying is disabled, so we will already have sent a locally
      // generated 100 Trying response, so don't forward this one.
      TRC_DEBUG("%s - Discard 100/INVITE response", uac_tsx->name());
      pjsip_tx_data_dec_ref(tdata);
      exit_context();
      return;
    }

    if ((status_code > 100) &&
        (status_code < 199) &&
        (_tsx->method.id == PJSIP_INVITE_METHOD))
    {
      // Forward all provisional responses to INVITEs.
      TRC_DEBUG("%s - Forward 1xx response", uac_tsx->name());

      // Forward response with the UAS transaction.
      on_tx_response(tdata);
      pj_status_t status = pjsip_tsx_send_msg(_tsx, tdata);
      if (status != PJ_SUCCESS)
      {
        // LCOV_EXCL_START
        TRC_INFO("Failed to forward 1xx response: %s",
                 PJUtils::pj_status_to_string(status).c_str());
        pjsip_tx_data_dec_ref(tdata);
        // LCOV_EXCL_STOP
      }
    }
    else if (PJSIP_IS_STATUS_IN_CLASS(status_code, 200))
    {
      // 2xx.
      TRC_DEBUG("%s - Forward 2xx response", name());

      // Send this response immediately as a final response.
      if (_final_rsp != NULL)
      {
        pjsip_tx_data_dec_ref(_final_rsp);
      }
      _final_rsp = tdata;
      --_pending_responses;
      dissociate(uac_tsx);
      on_final_response();
    }
    else
    {
      // Final, non-OK response.  Is this the "best" response
      // received so far?
      TRC_DEBUG("%s - 3xx/4xx/5xx/6xx response", uac_tsx->name());
      if ((_final_rsp == NULL) ||
          (compare_sip_sc(status_code, _final_rsp->msg->line.status.code) > 0))
      {
        TRC_DEBUG("%s - Best 3xx/4xx/5xx/6xx response so far", uac_tsx->name());

        if (_final_rsp != NULL)
        {
          pjsip_tx_data_dec_ref(_final_rsp);
        }

        _final_rsp = tdata;
      }
      else
      {
        pjsip_tx_data_dec_ref(tdata);
      }

      // Disconnect the UAC data from the UAS data so no further
      // events get passed between the two.
      dissociate(uac_tsx);

      --_pending_responses;

      if (_pending_sends + _pending_responses == 0)
      {
        // Received responses on every UAC transaction, so check terminating
        // call services and then send the best response on the UAS
        // transaction.
        TRC_DEBUG("%s - All UAC responded", name());
        on_final_response();
      }
      else if ((_tsx->method.id == PJSIP_INVITE_METHOD) &&
               (PJSIP_IS_STATUS_IN_CLASS(status_code, 600)))
      {
        // From RFC 3261, section 16.7, point 5:
        // > If a 6xx response is received, it is not immediately forwarded,
        // > but the stateful proxy SHOULD cancel all client pending
        // > transactions as described in Section 10, and it MUST NOT create
        // > any new branches in this context.

        // Cancel any pending transactions, but don't dissociate so that we wait
        // for all transactions to complete before forwarding the response.
        cancel_pending_uac_tsx(status_code, "6xx response received", false);
      }
    }

    exit_context();
  }
  // LCOV_EXCL_START
  else
  {
    pjsip_tx_data_dec_ref(tdata);
  }
  // LCOV_EXCL_STOP
}


/// Notification that a client transaction is not responding.
void BasicProxy::UASTsx::on_client_not_responding(UACTsx* uac_tsx,
                                                  ForkErrorState fork_error,
                                                  const std::string& reason)
{
  if (_tsx != NULL)
  {
    enter_context();

    // UAC transaction has timed out or hit a transport error.  If
    // we've not received a response from a client on any other UAC
    // transactions then keep this as the best response.
    TRC_DEBUG("%s - client transaction not responding (%s)",
              uac_tsx->name(),
              reason.c_str());

    SAS::Event client_not_responding(trail(), SASEvent::UAC_TSX_FAILED_NO_RESPONSE, 0);
    client_not_responding.add_var_param(reason);
    SAS::report_event(client_not_responding);

    if (--_pending_responses == 0)
    {
      // Received responses on every UAC transaction, so
      // send the best response on the UAS transaction.
      TRC_DEBUG("%s - No more pending responses, so send response on UAC tsx", name());
      on_final_response();
    }

    // Disconnect the UAC data from the UAS data so no further
    // events get passed between the two.
    TRC_DEBUG("%s - Disconnect UAS tsx from UAC tsx", uac_tsx->name());
    dissociate(uac_tsx);

    exit_context();
  }
}


/// Notification that the underlying PJSIP transaction has changed state.
///
/// After calling this, the caller must not assume that the UASTsx still
/// exists - if the PJSIP transaction is being destroyed, this method will
/// destroy the UASTsx.
void BasicProxy::UASTsx::on_tsx_state(pjsip_event* event)
{
  enter_context();

  if (_tsx->state == PJSIP_TSX_STATE_COMPLETED)
  {
    // UAS transaction has completed, so do any transaction completion
    // activities.
    on_tsx_complete();
  }

  if (_tsx->state == PJSIP_TSX_STATE_DESTROYED)
  {
    TRC_DEBUG("%s - UAS tsx destroyed", _tsx->obj_name);
    if (_tsx->method.id == PJSIP_INVITE_METHOD)
    {
      // INVITE transaction has been terminated.  If there are any
      // pending UAC transactions they should be cancelled.
      cancel_pending_uac_tsx(0, pjsip_event_str(event->body.tsx_state.type), true);
    }
    unbind_from_pjsip_tsx();
    _pending_destroy = true;
  }

  exit_context();
}


/// Handles the best final response, once all final responses have been received
/// from all forked INVITEs.
void BasicProxy::UASTsx::on_final_response()
{
  if (_tsx != NULL)
  {
    pjsip_tx_data* rsp = _final_rsp;
    _final_rsp = NULL;
    int st_code = rsp->msg->line.status.code;
    set_trail(rsp, trail());
    pjsip_tx_data_invalidate_msg(rsp);
    on_tx_response(rsp);
    pj_status_t status = pjsip_tsx_send_msg(_tsx, rsp);
    if (status != PJ_SUCCESS)
    {
      // LCOV_EXCL_START
      TRC_INFO("Failed to send final response: %s",
               PJUtils::pj_status_to_string(status).c_str());
      pjsip_tx_data_dec_ref(rsp);
      // LCOV_EXCL_STOP
    }

    if ((_tsx->method.id == PJSIP_INVITE_METHOD) &&
        (st_code == 200))
    {
      // Terminate the UAS transaction (this needs to be done
      // manually for INVITE 200 OK response, otherwise the
      // transaction layer will wait for an ACK).  This will also
      // cause all other pending UAC transactions to be cancelled.
      TRC_DEBUG("%s - Terminate UAS INVITE transaction", _tsx->obj_name);
      pjsip_tsx_terminate(_tsx, 200);
    }
  }
}


/// Sends a response using the buffer saved off for the final response.
void BasicProxy::UASTsx::send_response(int st_code, const pj_str_t* st_text)
{
  if (_tsx != NULL)
  {
    if ((st_code >= 100) && (st_code < 200))
    {
      // Build and send a provisional response building it from scratch using
      // the original request.
      pjsip_tx_data* prov_rsp;
      pj_status_t status = PJUtils::create_response(stack_data.endpt,
                                                    _req,
                                                    st_code,
                                                    st_text,
                                                    &prov_rsp);
      if (status == PJ_SUCCESS)
      {
        set_trail(prov_rsp, trail());
        on_tx_response(prov_rsp);
        pj_status_t status = pjsip_tsx_send_msg(_tsx, prov_rsp);
        if (status != PJ_SUCCESS)
        {
          // LCOV_EXCL_START
          TRC_INFO("Failed to send provisional response: %s",
                   PJUtils::pj_status_to_string(status).c_str());

          // pjsip_tsx_send_msg doesn't decrease the ref count on the tdata on
          // failure
          pjsip_tx_data_dec_ref(prov_rsp);
          // LCOV_EXCL_STOP
        }
      }
    }
    else if (_final_rsp != NULL)
    {
      // Send a final response.
      _final_rsp->msg->line.status.code = st_code;
      _final_rsp->msg->line.status.reason =
                (st_text != NULL) ? *st_text : *pjsip_get_status_text(st_code);
      on_final_response();
    }
  }
}


/// Called when a response is transmitted on this transaction.
void BasicProxy::UASTsx::on_tx_response(pjsip_tx_data* tdata)
{
}


/// Called when a request is transmitted on an associated downstream client
/// transaction.
void BasicProxy::UASTsx::on_tx_client_request(pjsip_tx_data* tdata, UACTsx* uac_tsx)
{
}


/// Perform actions on a new transaction starting.
void BasicProxy::UASTsx::on_tsx_start(const pjsip_rx_data* rdata)
{
  // Report SAS markers for the transaction.
  TRC_DEBUG("Report SAS start marker - trail (%llx)", trail());
  SAS::Marker start_marker(trail(), MARKER_ID_START, 1u);
  SAS::report_marker(start_marker);
}


/// Perform actions on a transaction completing.
void BasicProxy::UASTsx::on_tsx_complete()
{
  // Report SAS markers for the transaction.
  TRC_DEBUG("Report SAS end marker - trail (%llx)", trail());
  SAS::Marker end_marker(trail(), MARKER_ID_END, 1u);
  SAS::report_marker(end_marker);
}


/// Cancels all pending UAC transactions associated with this UAS transaction.
void BasicProxy::UASTsx::cancel_pending_uac_tsx(int st_code,
                                                const std::string& reason,
                                                bool dissociate_uac)
{
  // Send CANCEL on all pending UAC transactions forked from this UAS
  // transaction.  This is invoked either because the UAS transaction
  // received a CANCEL, or one of the UAC transactions received a 200 OK or
  // 6xx response.
  UACTsx *uac_tsx;

  TRC_DEBUG("%s - Cancel %d pending UAC transactions",
            name(), _pending_responses);

  for (size_t ii = 0; ii < _uac_tsx.size(); ++ii)
  {
    uac_tsx = _uac_tsx[ii];
    TRC_DEBUG("%s - Check target %d, UAC data = %p, UAC tsx = %p",
              name(),
              ii,
              uac_tsx,
              (uac_tsx != NULL) ? uac_tsx->_tsx : NULL);

    if (uac_tsx != NULL)
    {
      // Found a UAC transaction that is still active, so send a CANCEL.
      // Normal behaviour (that is, on receipt of a CANCEL on the UAS
      // transaction), is to leave the UAC transaction connected to the UAS
      // transaction so the 487 response gets passed through.  However, in
      // cases where the CANCEL is initiated on this node (for example,
      // because the UAS transaction has already failed, or in call forwarding
      // scenarios) we dissociate immediately so the 487 response gets
      // swallowed on this node.
      if (dissociate_uac)
      {
        dissociate(uac_tsx);
      }

      uac_tsx->cancel_pending_tsx(st_code, reason);
    }
  }
}


/// Compare two status codes from the perspective of which is the best to
/// return to the originator of a forked transaction.  This will only ever
/// be called for 3xx/4xx/5xx/6xx response codes.
///
/// @returns +1 if sc1 is better than sc2
///          0 if sc1 and sc2 are identical (or equally as good)
///          -1 if sc2 is better than sc1
///
int BasicProxy::UASTsx::compare_sip_sc(int sc1, int sc2)
{
  // See RFC 3261, section 16.7, point 6 for full logic for choosing the best response.
  // We also priortize 487 over any 300-599 status code to ensure that after a CANCEL we
  // get a 487 unless we get a definitive (6xx) response.
  //
  // Our order is:
  // (best) 600, ..., 699, 487, 300, ..., 407, 409, ..., 486, 488, ..., 599, 408 (worst).
  TRC_DEBUG("Compare new status code %d with stored status code %d", sc1, sc2);
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
  else if (PJSIP_IS_STATUS_IN_CLASS(sc1, 600))
  {
    if (PJSIP_IS_STATUS_IN_CLASS(sc2, 600))
    {
      // Both 6xx series - compare directly.
      return (sc1 < sc2) ? 1 : -1;
    }
    else
    {
      // sc1 is 6xx but sc2 is not - sc1 is better.
      return 1;
    }
  }
  else if (PJSIP_IS_STATUS_IN_CLASS(sc2, 600))
  {
    // sc2 is 6xx and we know sc1 is not - sc2 is better.
    return -1;
  }
  // After 6xx, 487 takes precedence over anything else.
  else if (sc1 == PJSIP_SC_REQUEST_TERMINATED)
  {
    return 1;
  }
  else if (sc2 == PJSIP_SC_REQUEST_TERMINATED)
  {
    return -1;
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


/// Disassociates the specified UAC transaction from this UAS transaction, and
/// vice-versa.  Must be called before destroying either transaction.
void BasicProxy::UASTsx::dissociate(UACTsx* uac_tsx)
{
  TRC_DEBUG("Dissociate UAC transaction %p for target %d", uac_tsx, uac_tsx->_index);
  uac_tsx->_uas_tsx = NULL;
  if (_uac_tsx.size() > (size_t)uac_tsx->_index)
  {
    _uac_tsx[uac_tsx->_index] = NULL;
  }
}


/// Creates a UACTsx object to send the request to a selected target.
BasicProxy::UACTsx* BasicProxy::UASTsx::create_uac_tsx(size_t index)
{
  return new UACTsx(_proxy, this, index);
}


/// Enters this transaction's context.  While in the transaction's
/// context, it will not be destroyed.  Whenever enter_context is called,
/// exit_context must be called before the end of the method.
void BasicProxy::UASTsx::enter_context()
{
  if (_lock != NULL)
  {
    // Take the group lock.
    pj_grp_lock_acquire(_lock);
  }

  // If the transaction is pending destroy, the context count must be greater
  // than 0.  Otherwise, the transaction should have already been destroyed (so
  // entering its context again is unsafe).
  pj_assert((!_pending_destroy) || (_context_count > 0));

  _context_count++;
}


/// Exits this transaction's context.  On return from this method, the caller
/// must not assume that the transaction still exists.
void BasicProxy::UASTsx::exit_context()
{
  // If the transaction is pending destroy, the context count must be greater
  // than 0.  Otherwise, the transaction should have already been destroyed (so
  // entering its context again is unsafe).
  pj_assert(_context_count > 0);

  _context_count--;
  if ((_context_count == 0) && (_pending_destroy))
  {
    TRC_DEBUG("Transaction (%p) suiciding");
    delete this;
  }
  else if (_lock != NULL)
  {
    // Release the group lock.
    pj_grp_lock_release(_lock);
  }
}


/// Handle the trying timer expiring on this transaction.
void BasicProxy::UASTsx::trying_timer_expired()
{
  enter_context();

  // We expect to only be called on the PJSIP transport thread, and our data
  // race/locking safety is based on this assumption. Raise an error log if
  // this is not the case.
  CHECK_PJ_TRANSPORT_THREAD();

  TRC_DEBUG("Trying timer expired for %s, transaction state = %s",
            name(),
            (_tsx != NULL) ? pjsip_tsx_state_str(_tsx->state) : "Unknown");

  if ((_trying_timer.id == TRYING_TIMER) &&
      (_tsx != NULL) &&
      (_tsx->state == PJSIP_TSX_STATE_TRYING))
  {
    // Transaction is still in Trying state, so send a 100 Trying response
    // now.
    TRC_DEBUG("Send delayed 100 Trying response");
    send_response(100);
    _trying_timer.id = 0;
  }

  exit_context();
}


/// Static method called by PJSIP when a trying timer expires.  The instance
/// is stored in the user_data field of the timer entry.
void BasicProxy::UASTsx::trying_timer_callback(pj_timer_heap_t *timer_heap, struct pj_timer_entry *entry)
{
  if (entry->id == TRYING_TIMER)
  {
    ((BasicProxy::UASTsx*)entry->user_data)->trying_timer_expired();
  }
}


/// UACTsx constructor
BasicProxy::UACTsx::UACTsx(BasicProxy* proxy,
                           UASTsx* uas_tsx,
                           size_t index) :
  _proxy(proxy),
  _uas_tsx(uas_tsx),
  _lock(NULL),
  _index(index),
  _tsx(NULL),
  _tdata(NULL),
  _servers_iter(NULL),
  _current_server(),
  _cancel_tsx(NULL),
  _timer_c(),
  _trail(0),
  _pending_destroy(false),
  _context_count(0),
  _stateless_proxy(false),
  _num_attempts_left(PJUtils::DEFAULT_RETRIES)
{
  // Don't put any initialization that can fail here, implement in init()
  // instead.
  pj_timer_entry_init(&_timer_c, 0, this, timer_expired);
}


/// UACTsx destructor
BasicProxy::UACTsx::~UACTsx()
{
  TRC_DEBUG("BasicProxy::UACTsx destructor (%p)", this);
  pj_assert(_context_count == 0);

  stop_timer_c();

  if (_tsx != NULL)
  {
    _proxy->unbind_transaction(_tsx);                         //LCOV_EXCL_LINE
  }

  if (_cancel_tsx != NULL)
  {
    _proxy->unbind_transaction(_cancel_tsx);                  //LCOV_EXCL_LINE
  }

  if (_uas_tsx != NULL)
  {
    _uas_tsx->dissociate(this);                               //LCOV_EXCL_LINE
  }

  if (_tdata != NULL)
  {
    pjsip_tx_data_dec_ref(_tdata);
    _tdata = NULL;
  }

  if ((_tsx != NULL) &&
      (_tsx->state != PJSIP_TSX_STATE_TERMINATED) &&          //LCOV_EXCL_LINE
      (_tsx->state != PJSIP_TSX_STATE_DESTROYED))             //LCOV_EXCL_LINE
  {
    pjsip_tsx_terminate(_tsx, PJSIP_SC_INTERNAL_SERVER_ERROR);//LCOV_EXCL_LINE
  }

  _tsx = NULL;
  _cancel_tsx = NULL;

  if (_lock != NULL)
  {
    pj_grp_lock_release(_lock);
    pj_grp_lock_dec_ref(_lock);
  }

  delete _servers_iter; _servers_iter = nullptr;
}


/// Initializes a UAC transaction.
pj_status_t BasicProxy::UACTsx::init(pjsip_tx_data* tdata,
                                     int allowed_host_state)
{
  pj_status_t status;

  _trail = _uas_tsx->trail();

  // Add a new top Via header to the request.  This must be done before creating
  // the PJSIP UAC transaction as otherwise response correlation won't work.
  PJUtils::add_top_via(tdata);

  if (tdata->msg->line.req.method.id != PJSIP_ACK_METHOD)
  {
    // Use the lock associated with the PJSIP UAS transaction.
    _lock = _uas_tsx->_lock;
    pj_grp_lock_add_ref(_lock);

    // Create a PJSIP UAC transaction for the request and bind it to this
    // object.
    status = pjsip_tsx_create_uac2(_proxy->_mod_tu.module(),
                                   tdata,
                                   _lock,
                                   &_tsx);
    if (status != PJ_SUCCESS)
    {
      //LCOV_EXCL_START
      TRC_DEBUG("Failed to create PJSIP UAC transaction");
      return status;
      //LCOV_EXCL_STOP
    }

    // Set up the PJSIP transaction user module data to refer to the associated
    // UACTsx object
    _proxy->bind_transaction(this, _tsx);

    // Add the SAS trail to the UAC transaction.
    set_trail(_tsx, _trail);
    TRC_DEBUG("Added trail identifier %ld to UAC transaction", get_trail(_tsx));
  }

  // Store the request and add a reference to the request so we can be sure it
  // remains valid for retries and building timeout responses.
  _tdata = tdata;
  pjsip_tx_data_add_ref(_tdata);

  if (tdata->tp_sel.type != PJSIP_TPSELECTOR_TRANSPORT)
  {
    // Resolve the next hop destination for this request to a set of target
    // servers (IP address/port/transport tuples). The maximum number of times
    // to attempt the call is stored in _num_attempts.
    _servers_iter = PJUtils::resolve_next_hop_iter(tdata, allowed_host_state, trail());
  }

  // Work out whether this UAC transaction is to a stateless proxy.
  pjsip_sip_uri* next_hop_uri = (pjsip_sip_uri*)PJUtils::next_hop(tdata->msg);
  std::string next_hop = std::string(next_hop_uri->host.ptr,
                                     next_hop_uri->host.slen);
  _stateless_proxy = (_proxy->_stateless_proxies.find(next_hop) !=
                      _proxy->_stateless_proxies.end());
  TRC_DEBUG("Next hop %s %s a stateless proxy",
            next_hop.c_str(),
            _stateless_proxy ? "is" : "is not");

  return PJ_SUCCESS;
}


/// Sends the initial request on this UAC transaction.
void BasicProxy::UACTsx::send_request()
{
  enter_context();

  pj_status_t status = PJ_SUCCESS;

  TRC_DEBUG("Sending request for %s",
            PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, _tdata->msg->line.req.uri).c_str());

  if (_tdata->tp_sel.type == PJSIP_TPSELECTOR_TRANSPORT)
  {
    // The transport has already been selected for this request, so
    // add it to the transaction otherwise it will get overwritten.
    TRC_DEBUG("Transport %s (%s) pre-selected for transaction",
              _tdata->tp_sel.u.transport->obj_name,
              _tdata->tp_sel.u.transport->info);
    pjsip_tsx_set_transport(_tsx, &_tdata->tp_sel);
  }
  else
  {
    // Get the next server from the address iterator.
    if (get_next_server())
    {
      // We have resolved servers to try, so set up the destination information
      // in the request.
      PJUtils::set_dest_info(_tdata, _current_server.address());
    }
    else
    {
      // We failed to get any valid destination servers, so fail the transaction.
      status = PJ_ENOTFOUND;
    }
  }

  if (status == PJ_SUCCESS)
  {
    // Notify the UASTsx the request is being sent and send it.
    _uas_tsx->on_tx_client_request(_tdata, this);

    if (_tdata->msg->line.req.method.id == PJSIP_ACK_METHOD)
    {
      // Forward ACK request statelessly and immediately mark the UACTsx for
      // destruction.
      status = PJUtils::send_request_stateless(_tdata);
      _pending_destroy = true;
    }
    else
    {
      // Send non-ACK request statefully.
      status = pjsip_tsx_send_msg(_tsx, _tdata);

      if ((status == PJ_SUCCESS) &&
          (_tdata->msg->line.req.method.id == PJSIP_INVITE_METHOD))
      {
        start_timer_c();
      }
      else if (status != PJ_SUCCESS)
      {
        // LCOV_EXCL_START
        TRC_INFO("Failed to send stateful request: %s",
                 PJUtils::pj_status_to_string(status).c_str());

        // If we failed to send the message, the ref count on _tdata will not
        // have been decreased, and we will have triggered a call into
        // on_tsx_state already.
        // That will have decided to retry the request if appropriate, and
        // increased the ref count on _tdata so we should decrease it here.
        pjsip_tx_data_dec_ref(_tdata);
        // LCOV_EXCL_STOP
      }

      // We do not want to take any other actions on a failure returned from
      // pjsip_tsx_send_msg, as it will have also triggered a call into
      // on_tsx_state. In the event of failure, this will, or already has
      // cause us to call into retry_request; we do not want to call into
      // on_client_not_responding below, so always return success.
      status = PJ_SUCCESS;
    }
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
    if ((_uas_tsx != NULL) &&
        (_tdata->msg->line.req.method.id != PJSIP_ACK_METHOD))
    {
      // Remove the top Via from the request before reporting the error in
      // case the request is used to build an error response.
      PJUtils::remove_top_via(_tdata);

      ForkErrorState fork_error;
      std::string reason;

      if (_current_server.is_set())
      {
        // LCOV_EXCL_START - don't expect failure to send messages in UT
        fork_error = ForkErrorState::TRANSPORT_ERROR;
        reason = "Unexpected failure to send request to peer";
        // LCOV_EXCL_STOP
      }
      else
      {
        fork_error = ForkErrorState::NO_ADDRESSES;
        reason = "No address for peer";
      }

      _uas_tsx->on_client_not_responding(this, fork_error, reason);
    }

    _pending_destroy = true;
  }

  exit_context();
}


/// Cancels the pending transaction, using the specified status code in the
/// Reason header.
void BasicProxy::UACTsx::cancel_pending_tsx(int st_code, const std::string& reason)
{
  if (_tsx != NULL)
  {
    enter_context();

    TRC_DEBUG("Found transaction %s status=%d", name(), _tsx->status_code);
    if (_tsx->status_code < 200)
    {
      if (_tdata->msg->line.req.method.id == PJSIP_INVITE_METHOD)
      {
        TRC_DEBUG("Sending CANCEL request");

        // See issue 1232.
        pjsip_tx_data *cancel = PJUtils::create_cancel(stack_data.endpt,
                                                       _tsx->last_tx,
                                                       st_code);
        set_trail(cancel, _trail);

        SAS::Event cancel_tsx_event(_trail, SASEvent::CANCELLING_TSX, 0);

        if (reason.size() != 0)
        {
          cancel_tsx_event.add_var_param(reason);
        }
        else
        {
          cancel_tsx_event.add_var_param("(no reason available)");
        }

        SAS::report_event(cancel_tsx_event);

        // Create a PJSIP UAC transaction on which to send the CANCEL, and
        // make sure this is using the same group lock.
        pj_status_t status = pjsip_tsx_create_uac2(_proxy->_mod_tu.module(),
                                                   cancel,
                                                   _lock,
                                                   &_cancel_tsx);
        if (status == PJ_SUCCESS)
        {
          // Set up the PJSIP transaction user module data on the cancel
          // transaction to refer to this UACTsx object.
          _proxy->bind_transaction(this, _cancel_tsx);
          set_trail(_cancel_tsx, _trail);

          if (_tsx->transport != NULL)
          {
            // The transaction being cancelled has already selected a transport,
            // so make sure the CANCEL uses this transport as well.
            pjsip_tpselector tp_selector;
            tp_selector.type = PJSIP_TPSELECTOR_TRANSPORT;
            tp_selector.u.transport = _tsx->transport;
            pjsip_tsx_set_transport(_cancel_tsx, &tp_selector);
          }

          // Send the CANCEL on the new transaction.
          status = pjsip_tsx_send_msg(_cancel_tsx, cancel);
          if (status != PJ_SUCCESS)
          {
            //LCOV_EXCL_START
            pjsip_tx_data_dec_ref(cancel);
            //LCOV_EXCL_STOP
          }
        }

        // There are some known but hard-to-hit ways for this to fail - we
        // only log at INFO level for these:
        //
        // - EEXISTS can be hit if we've already sent out the CANCEL and then
        //   see a transport failure on the incoming side of the call - that
        //   brings us through this path for a second time.
        //
        // - EINVALIDOP can be hit if the transport on which we're trying to
        //   send the CANCEL is unavailable.
        if ((status == PJ_EEXISTS) || (status == PJ_EINVALIDOP))
        {
          TRC_INFO("Error sending CANCEL, %s",
                   PJUtils::pj_status_to_string(status).c_str());
        }
        else if (status != PJ_SUCCESS)
        {
          //LCOV_EXCL_START
          TRC_ERROR("Error sending CANCEL, %s",
                    PJUtils::pj_status_to_string(status).c_str());
          //LCOV_EXCL_STOP
        }
      }
      else
      {
        // Non-INVITE transaction, so terminate the transaction immediately.
        //LCOV_EXCL_START
        TRC_DEBUG("Terminate transaction immediately");
        pjsip_tsx_terminate(_tsx, st_code);
        //LCOV_EXCL_STOP
      }
    }

    exit_context();
  }
}


/// Notification that the underlying PJSIP transaction has changed state.
///
/// After calling this, the caller must not assume that the UACTsx still
/// exists - if the PJSIP transaction is being destroyed, this method will
/// destroy the UACTsx.
void BasicProxy::UACTsx::on_tsx_state(pjsip_event* event)
{
  std::string reason;

  enter_context();

  // Handle incoming responses (provided the UAS transaction hasn't
  // terminated or been cancelled).
  TRC_DEBUG("%s - uac_tsx = %p, uas_tsx = %p", name(), this, _uas_tsx);

  // Check that the event is on the current UAC transaction (we may have
  // created a new one for a retry) and is still connected to the UAS
  // transaction.
  if ((event->body.tsx_state.tsx == _tsx) && (_uas_tsx != NULL))
  {
    TRC_DEBUG("%s event on current UAC transaction",
              pjsip_event_str(event->body.tsx_state.type));
    bool retrying = false;

    if ((_timer_c.id == TIMER_C) &&
        ((_tsx->state == PJSIP_TSX_STATE_COMPLETED) ||
         (_tsx->state == PJSIP_TSX_STATE_TERMINATED)))
    {
      // Transaction has completed or terminated with Timer C running, so
      // cancel the timer.
      stop_timer_c();
    }

    if (_current_server.is_set())
    {
      // Check to see if the destination server has failed so we can blacklist
      // it and retry to an alternative if possible.
      if ((_tsx->state == PJSIP_TSX_STATE_TERMINATED) &&
          (event->body.tsx_state.type == PJSIP_EVENT_TRANSPORT_ERROR))
      {
        // Failed to connect to the selected server, or failed so blacklist it.
        TRC_DEBUG("Failed to connected to server so add to blacklist");
        _current_server.failed();

        // Attempt a retry.
        retrying = retry_request();
      }
      else if ((_tsx->state == PJSIP_TSX_STATE_TERMINATED) &&
               (event->body.tsx_state.type == PJSIP_EVENT_TIMER))
      {
        // SIP transaction timed out.
        TRC_DEBUG("Request to server timed-out");

        if (!_stateless_proxy)
        {
          // The next hop is NOT a stateful proxy so if it hasn't responded then
          // it should be blacklisted.  We don't blacklist stateless proxies to
          // avoid blacklisting them due to an unresponsive server further
          // downstream.
          TRC_DEBUG("Next hop is NOT a stateless-proxy - blacklist");
          _current_server.failed();
        }

        // Don't retry - if we've waited for a SIP transaction to time out,
        // the upstream transaction has probably failed anyway.  Not retrying
        // also avoids us sending an INVITE with a chasing CANCEL when an AS
        // is unresponsive (see
        // https://github.com/Metaswitch/sprout/issues/1095).
      }
      else if ((_tsx->state == PJSIP_TSX_STATE_COMPLETED) &&
               (_tsx->status_code == PJSIP_SC_SERVICE_UNAVAILABLE))
      {
        // The server returned a 503 error.  We don't blacklist in this case
        // as it may indicated a transient overload condition, but we can
        // retry to an alternate server if one is available.
        TRC_DEBUG("Server returned a 503 error");
       _current_server.succeeded();
        retrying = retry_request();
      }
      else if (event->body.tsx_state.type == PJSIP_EVENT_RX_MSG)
      {
        TRC_DEBUG("Server sent a response");
        _current_server.succeeded();
      }
    }

    if (!retrying)
    {
      if (event->body.tsx_state.type == PJSIP_EVENT_RX_MSG)
      {
        TRC_DEBUG("%s - RX_MSG on active UAC transaction", name());
        if (_uas_tsx != NULL)
        {
          pjsip_tx_data* tdata;
          pj_status_t status = PJUtils::create_response_fwd(stack_data.endpt,
                                                            event->body.tsx_state.src.rdata,
                                                            0,
                                                            &tdata);
          if (status != PJ_SUCCESS)
          {
            // LCOV_EXCL_START
            TRC_ERROR("Error creating response, %s",
                      PJUtils::pj_status_to_string(status).c_str());
            // LCOV_EXCL_STOP
          }
          else
          {
            _uas_tsx->on_new_client_response(this, tdata);
          }
        }
      }

      // If UAC transaction is terminated because of a timeout, treat this as
      // a 504 error.
      if ((_tsx->state == PJSIP_TSX_STATE_TERMINATED) &&
          (_uas_tsx != NULL))
      {
        // UAC transaction has terminated while still connected to the UAS
        // transaction.
        TRC_DEBUG("%s - UAC tsx terminated while still connected to UAS tsx",
                  _tsx->obj_name);
        ForkErrorState fork_error = ForkErrorState::NONE;

        if (event->body.tsx_state.type == PJSIP_EVENT_TRANSPORT_ERROR)
        {
          TRC_DEBUG("Timeout or transport error");
          SAS::Event sas_event(trail(), SASEvent::TRANSPORT_FAILURE, 0);
          SAS::report_event(sas_event);

          fork_error = ForkErrorState::TRANSPORT_ERROR;
          reason = "Transport failure";
        }
        // LCOV_EXCL_START - no timeouts in UT.
        else if (event->body.tsx_state.type == PJSIP_EVENT_TIMER)
        {
          TRC_DEBUG("Timeout error");
          SAS::Event sas_event(trail(), SASEvent::TIMEOUT_FAILURE, 0);
          SAS::report_event(sas_event);

          fork_error = ForkErrorState::TIMEOUT;
          reason = "Timeout";
        }
        // LCOV_EXCL_STOP - no timeouts in UT.

        // Report the error to the UASTsx.  Remove the top Via header from the
        // request first in case it is used to generate an error response.
        PJUtils::remove_top_via(_tdata);

        _uas_tsx->on_client_not_responding(this,
                                           fork_error,
                                           reason);
      }
    }
  }
  else if ((event->body.tsx_state.tsx == _cancel_tsx) &&
           (_tsx != NULL) &&
           (_uas_tsx != NULL))
  {
    TRC_DEBUG("%s event on CANCEL transaction",
              pjsip_event_str(event->body.tsx_state.type));
    if ((event->body.tsx_state.type == PJSIP_EVENT_RX_MSG) &&
        (event->body.tsx_state.src.rdata->msg_info.msg->line.status.code == PJSIP_SC_OK))
    {
      // 200 OK response to the CANCEL request, so everything is good.  We need
      // to unlink the CANCEL PJSIP transaction as we're not interested in
      // subsequent events.
      TRC_DEBUG("200 OK response to CANCEL");
      _proxy->unbind_transaction(_cancel_tsx);
      _cancel_tsx = NULL;
    }
    else if ((event->body.tsx_state.type == PJSIP_EVENT_TRANSPORT_ERROR) ||
             (event->body.tsx_state.type == PJSIP_EVENT_TIMER) ||
             (event->body.tsx_state.type == PJSIP_EVENT_RX_MSG))
    {
      TRC_INFO("CANCEL failed, transaction in state %s",
               pjsip_tsx_state_str(_tsx->state));
      if ((_tsx->state != PJSIP_TSX_STATE_COMPLETED) &&
          (_tsx->state != PJSIP_TSX_STATE_TERMINATED))
      {
        // CANCEL failed for a transaction which is still active, so terminate
        // the transaction immediately and send a 487 response upstream.
        //pjsip_tsx_terminate(_tsx, PJSIP_SC_REQUEST_TERMINATED);
        pjsip_tx_data* rsp;
        pj_status_t status = PJUtils::create_response(stack_data.endpt,
                                                      _tdata,
                                                      PJSIP_SC_REQUEST_TERMINATED,
                                                      NULL,
                                                      &rsp);
        if (status == PJ_SUCCESS)
        {
          // Remove the top Via header (we must do this as we built the response
          // from a request where we've added an extra Via).
          pjsip_msg_find_remove_hdr(rsp->msg, PJSIP_H_VIA, NULL);
          _uas_tsx->on_new_client_response(this, rsp);
        }
      }
    }
  }

  if ((event->body.tsx_state.tsx == _tsx) &&
      (_tsx != NULL) &&
      (_tsx->state == PJSIP_TSX_STATE_DESTROYED))
  {
    TRC_DEBUG("%s - UAC tsx destroyed", _tsx->obj_name);
    _proxy->unbind_transaction(_tsx);
    _tsx = NULL;
    _pending_destroy = true;
  }

  exit_context();
}


/// Attempt to retry the request to an alternate server.
bool BasicProxy::UACTsx::retry_request()
{
  bool retrying = false;

  // Stores the next server in _current_server. Returns false if no servers are
  // left, or if the maximum number of retry attempts have been made.
  if (get_next_server())
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

    // In congestion cases, the old tdata might still be held by PjSIP's
    // transport layer waiting to be sent.  Therefore it's not safe to re-send
    // the same tdata, so we should clone it first.
    // LCOV_EXCL_START - No congestion in UTs.
    if (_tdata->is_pending)
    {
      pjsip_tx_data* old_tdata = _tdata;
      _tdata = PJUtils::clone_tdata(_tdata);

      // We no longer care about the old tdata.
      pjsip_tx_data_dec_ref(old_tdata);
    }
    // LCOV_EXCL_STOP

    PJUtils::generate_new_branch_id(_tdata);
    pj_status_t status = pjsip_tsx_create_uac2(_proxy->_mod_tu.module(),
                                               _tdata,
                                               _lock,
                                               &retry_tsx);

    if (status == PJ_SUCCESS)
    {
      // Set up the PJSIP transaction user module data to refer to the associated
      // UACTsx object.
      TRC_DEBUG("Created transaction for retry, so send request");
      _proxy->unbind_transaction(_tsx);
      pjsip_transaction* original_tsx = _tsx;
      _tsx = retry_tsx;
      _proxy->bind_transaction(this, _tsx);

      // Add the trail from the UAS transaction to the UAC transaction.
      set_trail(_tsx, _uas_tsx->trail());

      // Increment the reference count of the request as we are passing
      // it to a new transaction.
      pjsip_tx_data_add_ref(_tdata);

      // Copy across the destination information for a retry and try to
      // resend the request.
      PJUtils::set_dest_info(_tdata, _current_server.address());
      status = pjsip_tsx_send_msg(_tsx, _tdata);

      if (status == PJ_SUCCESS)
      {
        // Successfully sent the retry.
        TRC_INFO("Retrying request to alternate target");
        retrying = true;

        if (_tdata->msg->line.req.method.id == PJSIP_INVITE_METHOD)
        {
          // Start Timer C again.
          start_timer_c();
        }
      }
      else
      {
        // Failed to send, so revert to the original transaction to see it
        // through to the end.  Must decrement the reference count on the
        // request as pjsip_tsx_send_msg won't do it if it fails.
        // LCOV_EXCL_START
        TRC_INFO("Failed to send retry: %s",
                 PJUtils::pj_status_to_string(status).c_str());
        pjsip_tx_data_dec_ref(_tdata);
        _proxy->unbind_transaction(_tsx);
        _tsx = original_tsx;
        _proxy->bind_transaction(this, _tsx);
        // LCOV_EXCL_STOP
      }
    }
  }

  return retrying;
}


/// Enters this transaction's context.  While in the transaction's
/// context, it will not be destroyed.  Whenever enter_context is called,
/// exit_context must be called before the end of the method.
void BasicProxy::UACTsx::enter_context()
{
  if (_lock != NULL)
  {
    // Take the group lock.
    pj_grp_lock_acquire(_lock);
  }

  // If the transaction is pending destroy, the context count must be greater
  // than 0.  Otherwise, the transaction should have already been destroyed (so
  // entering its context again is unsafe).
  pj_assert((!_pending_destroy) || (_context_count > 0));

  _context_count++;
}


/// Exits this transaction's context.  On return from this method, the caller
/// must not assume that the transaction still exists.
void BasicProxy::UACTsx::exit_context()
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
  else if (_lock != NULL)
  {
    // Release the group lock.
    pj_grp_lock_release(_lock);
  }
}


/// Start Timer C on the transaction.
void BasicProxy::UACTsx::start_timer_c()
{
  TRC_DEBUG("Starting timer C");
  _timer_c.id = TIMER_C;
  pj_time_val delay = {180, 0};
  pjsip_endpt_schedule_timer(stack_data.endpt, &_timer_c, &delay);
}


/// Stop Timer C on the transaction.
void BasicProxy::UACTsx::stop_timer_c()
{
  if (_timer_c.id == TIMER_C)
  {
    TRC_DEBUG("Stopping timer C");
    pjsip_endpt_cancel_timer(stack_data.endpt, &_timer_c);
    _timer_c.id = 0;
  }
}


/// Called when timer C expires.
void BasicProxy::UACTsx::timer_c_expired()
{
  _timer_c.id = 0;
  if (_tsx != NULL)
  {
    TRC_DEBUG("Timer C expired");
    if ((_tsx->method.id == PJSIP_INVITE_METHOD) &&
        (_tsx->state == PJSIP_TSX_STATE_PROCEEDING))
    {
      // INVITE transaction in proceeding state, so send a CANCEL request.
      // request.
      TRC_INFO("Timer C expired, %.*s transaction in %s state, sending CANCEL",
               _tsx->method.name.slen, _tsx->method.name.ptr,
               pjsip_tsx_state_str(_tsx->state));
      cancel_pending_tsx(408, "Timer C expired");
    }
    //LCOV_EXCL_START - RFC3261 says that Timer C can expire for a non-INVITE
    // transaction, or an INVITE transaction in calling state, but it
    // seems to be impossible to hit because Timer F will expire on the
    // transaction well before Timer C expires.
    else if ((_tsx->state == PJSIP_TSX_STATE_TRYING) ||
             (_tsx->state == PJSIP_TSX_STATE_CALLING) ||
             (_tsx->state == PJSIP_TSX_STATE_PROCEEDING))
    {
      // Either a non-INVITE transaction, or an INVITE transaction which
      // hasn't yet received a 100 Trying response, so terminate the
      // transaction and report this target as non-responsive.  Remove
      // the top Via header from the request in case it is used to generate
      // an error response.
      TRC_INFO("Timer C expired, %.*s transaction in %s state, aborting",
               _tsx->method.name.slen, _tsx->method.name.ptr,
               pjsip_tsx_state_str(_tsx->state));
      pjsip_tsx_terminate(_tsx, PJSIP_SC_REQUEST_TIMEOUT);
      PJUtils::remove_top_via(_tdata);

      _uas_tsx->on_client_not_responding(this,
                                         ForkErrorState::TIMEOUT,
                                         "Timer C expired");
    }
    //LCOV_EXCL_STOP
  }
}


/// Static function called when a timer expires.
void BasicProxy::UACTsx::timer_expired(pj_timer_heap_t *timer_heap,
                                       struct pj_timer_entry *entry)
{
  if (entry->id == TIMER_C)
  {
    ((BasicProxy::UACTsx*)entry->user_data)->timer_c_expired();
  }
}

/// Helper function to store the next server in _current_server. Returns false
/// if there are no servers left, or the maximum number of attempts have been
/// made.
bool BasicProxy::UACTsx::get_next_server()
{
  if (_num_attempts_left > 0)
  {
    // Decrement the number of attempts left.
    --_num_attempts_left;

    // Stores the next server in _current_server and increments _servers_iter.
    // next returns true if there was another server to return.
    AddrInfo addr;
    if (_servers_iter->next(addr))
    {
      // Work out whether to blacklist this address by default (i.e. if the
      // UACTsx gives up on it without explicitly determining its health. We
      // blacklist by default if:
      //
      // -  The request has a transaction associated with it, meaning that the
      //    request is not an ACK request. ACKs do not have a response so there
      //    is no clear indication that it has succeeded.
      //
      // -  The address is a stateful proxy. For stateful proxies, the most
      //    likely thing is that the host has failed in some weird way that the
      //    UACTsx doesn't cope with, so the best thing to do is blacklist the
      //    host.  State*less* proxies are only blacklisted on transport
      //    failures. These are easy to spot, so it is unlikely the UACTsx
      //    didn't spot this, and the best thing to do is mark the host as
      //    successful.
      bool blacklist_by_default = (_tsx != nullptr) && !_stateless_proxy;
      _current_server.set(addr, blacklist_by_default);

      if (Log::enabled(Log::DEBUG_LEVEL))
      {
        std::string host_str = addr.to_string();
        TRC_DEBUG("Selected host %s (%s be blacklisted by default)",
                  host_str.c_str(), blacklist_by_default ? "will" : "will not");
      }

      return true;
    }
    else
    {
      return false;
    }
  }
  else
  {
    // Maximum number of attempts have been made.
    return false;
  }
}

//
// Methods for BasicProxy::UACTsx::Target
//

BasicProxy::UACTsx::Target::Target() :
  _addr(), _is_set(false), _health_known(false), _blacklist_by_default(false)
{}

BasicProxy::UACTsx::Target::~Target()
{
  unset();
}

void BasicProxy::UACTsx::Target::set(AddrInfo& addr, bool blacklist_by_default)
{
  // A new address is being set, so unset the current one.
  unset();

  _addr = addr;
  _is_set = true;
  _health_known = false;
  _blacklist_by_default = blacklist_by_default;
}

bool BasicProxy::UACTsx::Target::is_set() { return _is_set; }
const AddrInfo& BasicProxy::UACTsx::Target::address() { return _addr; }

void BasicProxy::UACTsx::Target::failed()
{
  if (_is_set && !_health_known)
  {
    PJUtils::blacklist(_addr);
    _health_known = true;
  }
}

void BasicProxy::UACTsx::Target::succeeded()
{
  if (_is_set && !_health_known)
  {
    PJUtils::success(_addr);
    _health_known = true;
  }
}

void BasicProxy::UACTsx::Target::unset()
{
  if (_is_set && !_health_known)
  {
    // We have a target already and we don't know its health (because the caller
    // hasn't told us). However we need to call success or blacklist on the
    // address.
    if (_blacklist_by_default)
    {
      PJUtils::blacklist(_addr);
    }
    else
    {
      PJUtils::success(_addr);
    }
  }
}
