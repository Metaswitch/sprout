/**
 * @file sproutletproxy.cpp  Sproutlet controlling proxy class implementation
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


extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}


#include "log.h"
#include "pjutils.h"
#include "sproutsasevent.h"
#include "sproutletproxy.h"


/// Constructor.
SproutletProxy::SproutletProxy(pjsip_endpoint* endpt,
                               int priority,
                               const std::string& uri,
                               const std::list<Sproutlet*>& sproutlets) :
  BasicProxy(endpt, "mod-sproutlet-controller", priority, false),
  _sproutlets()
{
  /// Store the URI of this SproutletProxy - this is used for Record-Routing.
  _uri = PJUtils::uri_from_string(uri, stack_data.pool, false);

  /// Build a map from service-name to Sproutlet object.
  for (std::list<Sproutlet*>::const_iterator i = sproutlets.begin();
       i != sproutlets.end();
       ++i) 
  {
    _sproutlets[(*i)->service_name()] = (*i);
  }
}


/// Destructor.
SproutletProxy::~SproutletProxy()
{
}


/// Utility method to create a UASTsx object for incoming requests.
BasicProxy::UASTsx* SproutletProxy::create_uas_tsx()
{
  return (BasicProxy::UASTsx*)new SproutletProxy::UASTsx(this);
}


/// Utility method to find the appropriate Sproutlet to handle a request.
std::list<Sproutlet*> SproutletProxy::target_sproutlets(pjsip_msg* msg)
{
  std::list<Sproutlet*> sproutlets;
#if 0

  bool in_dialog = (PJSIP_MSG_TO_HDR(msg)->tag.slen > 0);

  pjsip_route_hdr* hroute = (pjsip_route_hdr*)
                                  pjsip_msg_find_hdr(msg, PJSIP_H_ROUTE, NULL);

  if ((hroute != NULL) && (pjsip_uri_compare(hroute->name_add.uri, _uri))) 
  {
    // The Route header references this node, so we should apply services.

  }
#else
  sproutlets.push_back(_sproutlets.begin()->second);
#endif
  return sproutlets;
}


void SproutletProxy::add_record_route(pjsip_tx_data* tdata,
                                      const std::string& service_name,
                                      const std::string& dialog_id)
{
  // Add a Record-Route header.
  // @TODO - for full implementation must only add one Record-Route and add
  // parameters for others.
  LOG_DEBUG("Add Record-Route %s:%s", service_name.c_str(), dialog_id.c_str());

  pjsip_sip_uri* rr_uri = (pjsip_sip_uri*)pjsip_uri_clone(tdata->pool, _uri);
  rr_uri->lr_param = 1;

  // Construct a parameter encoding the service name and dialog identifier,
  // and add it to the URI.
  std::string pname = service_name + ":" + dialog_id;
  pjsip_param *p = PJ_POOL_ALLOC_T(tdata->pool, pjsip_param);
  pj_strdup2(tdata->pool, &p->name, pname.c_str());
  pj_list_insert_before(&rr_uri->other_param, p);

  // Construct and add the Record-Route header.
  pjsip_rr_hdr* hrr = pjsip_rr_hdr_create(tdata->pool);
  hrr->name_addr.uri = (pjsip_uri*)rr_uri;
  pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)hrr);
}


SproutletProxy::UASTsx::UASTsx(BasicProxy* proxy) :
  BasicProxy::UASTsx(proxy),
  _in_dialog(false)
{
}


SproutletProxy::UASTsx::~UASTsx()
{
}


/// Initialise the UAS transaction object.
pj_status_t SproutletProxy::UASTsx::init(pjsip_rx_data* rdata)
{
  // Do the BasicProxy initialization first.
  pj_status_t status = BasicProxy::UASTsx::init(rdata);

  if (status == PJ_SUCCESS) 
  {
    // Locate the target Sproutlet for the request, and create the helper and
    // the Sproutlet transaction.
    std::list<Sproutlet*> sproutlets =
                       ((SproutletProxy*)_proxy)->target_sproutlets(_req->msg);
    Sproutlet* sproutlet = sproutlets.front();
    LOG_DEBUG("Initializing SproutletProxy transaction for %s",
              sproutlet->service_name().c_str());
    _service_name = sproutlet->service_name();
    _helper = new SproutletProxyTsxHelper(_req, trail());
    _sproutlet = sproutlet->get_tsx(_helper, _req->msg);

    if (_sproutlet == NULL) 
    {
      // The Sproutlet has decided it doesn't want to handle the message, so
      // just use a default Sproutlet that passes the request through.
      _sproutlet = new SproutletTsx(_helper);
    }
  }
                                                       
  return status;
}


/// Handle the incoming half of a transaction request.
void SproutletProxy::UASTsx::process_tsx_request()
{
  // Pass the request to the Sproutlet at the root of the tree.
  pjsip_tx_data* req = _req;
  _req = NULL;
  if (!_in_dialog) 
  {
    LOG_DEBUG("Pass initial request to Sproutlet");
    _sproutlet->on_rx_initial_request(req->msg);
  }
  else
  {
    LOG_DEBUG("Pass in dialog request to Sproutlet");
    _sproutlet->on_rx_in_dialog_request(req->msg);
  }

  // Now query the helper and process any follow-on actions.
  process_actions(_helper);
}


/// Handle a received CANCEL request.
void SproutletProxy::UASTsx::process_cancel_request(pjsip_rx_data* rdata)
{
  // Pass the CANCEL to the Sproutlet at the root of the tree.
  _sproutlet->on_rx_cancel(PJSIP_SC_REQUEST_TERMINATED, rdata->msg_info.msg);

  // Send CANCEL to cancel the UAC transactions.
  // The UAS INVITE transaction will get final response when
  // we receive final response from the UAC INVITE transaction.
  cancel_pending_uac_tsx(0, false);

  // @TODO - will need to process CANCELs through the tree of Sproutlet's
  // when we support arbitrary Sproutlet topologies.
}


/// Handles a response to an associated UACTsx.
void SproutletProxy::UASTsx::on_new_client_response(UACTsx* uac_tsx,
                                                    pjsip_tx_data *tdata)
{
  enter_context();

  _helper->register_tdata(tdata);
  _sproutlet->on_rx_response(tdata->msg, _uac_2_fork[uac_tsx->index()]);

  if (tdata->msg->line.status.code >= PJSIP_SC_OK) 
  {
    // This is a final response, so dissociate the UAC transaction.
    dissociate(uac_tsx);
  }

  process_actions(_helper);

  exit_context();
}


/// Called when a response is transmitted on this transaction.
void SproutletProxy::UASTsx::on_tx_response(pjsip_tx_data* tdata)
{
  enter_context();

  if ((_sproutlet != NULL) &&
      (tdata->msg->line.status.code != PJSIP_SC_TRYING))
  {
    _sproutlet->on_tx_response(tdata->msg);
  }

  exit_context();
}


/// Called when a request is transmitted on an associated client transaction.
/// Handles interactions with the ACR for the request if one is allocated.
void SproutletProxy::UASTsx::on_tx_client_request(pjsip_tx_data* tdata, UACTsx* uac_tsx)
{
  enter_context();

  _sproutlet->on_tx_request(tdata->msg, _uac_2_fork[uac_tsx->index()]);

  exit_context();
}


/// Notification that the underlying PJSIP UAS transaction has changed state.
///
/// After calling this, the caller must not assume that the UASTsx still
/// exists - if the PJSIP transaction is being destroyed, this method will
/// destroy the UASTsx.
void SproutletProxy::UASTsx::on_tsx_state(pjsip_event* event)
{
  enter_context();

  if ((_tsx->state == PJSIP_TSX_STATE_TERMINATED) &&
      ((event->body.tsx_state.type == PJSIP_EVENT_TIMER) ||
       (event->body.tsx_state.type == PJSIP_EVENT_TRANSPORT_ERROR)))
  {
    // Notify the root Sproutlet of the error.
    _sproutlet->on_rx_cancel(PJSIP_SC_REQUEST_TIMEOUT, NULL);
    if (_tsx->method.id == PJSIP_INVITE_METHOD)
    {
      // INVITE transaction has been terminated.  If there are any
      // pending UAC transactions they should be cancelled.
      cancel_pending_uac_tsx(0, true);
    }
  }

  BasicProxy::UASTsx::on_tsx_state(event);

  exit_context();
}


/// Process actions required by a Sproutlet
void SproutletProxy::UASTsx::process_actions(SproutletProxyTsxHelper* helper)
{
  // First handle any responses generated or forwarded by the Sproutlet.
  LOG_DEBUG("Processing actions from sproutlet");
  std::list<pjsip_tx_data*> rsps;
  helper->responses(rsps);
  LOG_DEBUG("%d responses", rsps.size());
  while (!rsps.empty()) 
  {
    pjsip_tx_data* tdata = rsps.front();
    LOG_DEBUG("Process response %p", tdata);
    rsps.pop_front();
    process_response(tdata);
  }

  // Now handle any requests forwarded/generated by the Sproutlet.
  std::string dialog_id;
  bool record_route = helper->record_route_requested(dialog_id);
  std::unordered_map<int, pjsip_tx_data*> reqs;
  helper->requests(reqs);
  LOG_DEBUG("%d requests", reqs.size());
  _pending_sends = reqs.size();
  for (std::unordered_map<int, pjsip_tx_data*>::const_iterator i = reqs.begin();
       i != reqs.end();
       ++i) 
  {
    --_pending_sends;
    ++_pending_responses;

    pjsip_tx_data* tdata = i->second;
    LOG_DEBUG("Processing request %p, fork = %d", tdata, i->first);

    if (record_route) 
    {
      // The Sproutlet has requested that we Record-Route on this dialog, so
      // add a Record-Route header.
      ((SproutletProxy*)_proxy)->add_record_route(tdata, _service_name, dialog_id);
    }

    // Store the fork ID corresponding to the UAC transaction so we can route
    // responses appropriately.
    // @TODO - this is a bit of a hack because we need the fork mapping set up
    // before calling forward_request.
    int index = _uac_tsx.size();
    if (_uac_2_fork.size() <= (size_t)index) 
    {
      _uac_2_fork.resize(index + 1);
    }
    _uac_2_fork[_uac_tsx.size()] = i->first;

    // Forward the request, remembering the UAC index.
    pj_status_t status = forward_request(i->second, index);

    if (status != PJ_SUCCESS) 
    {
      // @TODO
    }

  }
}


void SproutletProxy::UASTsx::process_response(pjsip_tx_data* tdata)
{
  int status_code = tdata->msg->line.status.code;

  if (status_code == 100)
  {
    // We will already have sent a locally generated 100 Trying response, so
    // don't forward this one.
    LOG_DEBUG("Discard 100/INVITE response");
    pjsip_tx_data_dec_ref(tdata);
    return;
  }

  if ((status_code > 100) &&
      (status_code < 199) &&
      (_tsx->method.id == PJSIP_INVITE_METHOD))
  {
    // Forward all provisional responses to INVITEs.
    LOG_DEBUG("Forward 1xx response");

    // Forward response with the UAS transaction
    on_tx_response(tdata);
    pjsip_tsx_send_msg(_tsx, tdata);
  }
  else if (status_code == 200)
  {
    // 200 OK.
    LOG_DEBUG("Forward 200 OK response");

    // Send this response immediately as a final response.
    if (_best_rsp != NULL)
    {
      pjsip_tx_data_dec_ref(_best_rsp);
    }
    _best_rsp = tdata;
    --_pending_responses;
    on_final_response();
  }
  else
  {
    // Final, non-OK response.  Is this the "best" response
    // received so far?
    LOG_DEBUG("3xx/4xx/5xx/6xx response");
    if ((_best_rsp == NULL) ||
        (compare_sip_sc(status_code, _best_rsp->msg->line.status.code) > 0))
    {
      LOG_DEBUG("Best 3xx/4xx/5xx/6xx response so far");

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

    --_pending_responses;
    if (_pending_sends + _pending_responses == 0)
    {
      // Received responses on every UAC transaction, so check terminating
      // call services and then send the best response on the UAS
      // transaction.
      LOG_DEBUG("All UAC responded");
      on_final_response();
    }
  }
}

//
// SproutletTsxHelper methods.
//

SproutletProxyTsxHelper::SproutletProxyTsxHelper(pjsip_tx_data* inbound_request,
                                                 SAS::TrailId trail_id) :
  _dialog_id(""),
  _record_routed(false),
  _final_response_sent(false),
  _unique_id(0),
  _trail_id(trail_id)
{
  register_tdata(inbound_request);
}

SproutletProxyTsxHelper::~SproutletProxyTsxHelper()
{
  assert(_clones.empty());
  assert(_requests.empty());
  assert(_responses.empty());
}

bool SproutletProxyTsxHelper::record_route_requested(std::string& dialog_id)
{
  if (_record_routed)
  {
    dialog_id = _dialog_id;
    return true;
  }
  else
  {
    return false;
  }
}

void SproutletProxyTsxHelper::requests(std::unordered_map<int, pjsip_tx_data*>& requests)
{
  requests = _requests;
  _requests.clear();
}

void SproutletProxyTsxHelper::responses(std::list<pjsip_tx_data*>& responses)
{
  responses = _responses;
  _responses.clear();
}


void SproutletProxyTsxHelper::register_tdata(pjsip_tx_data* tdata)
{
  LOG_DEBUG("Adding message %p => txdata %p mapping",
            tdata->msg, tdata);
  _clones[tdata->msg] = tdata;
}

//
// SproutletTsxHelper overloads.
//

void SproutletProxyTsxHelper::add_to_dialog(const std::string& dialog_id)
{
  if (_record_routed)
  {
    LOG_WARNING("A sproutlet has attempted to add itself to the dialog multiple times, only the last dialog_id will be used");
  }

  _record_routed = true;
  _dialog_id = dialog_id;
}

const std::string& SproutletProxyTsxHelper::dialog_id() const
{
  return _dialog_id;
}

pjsip_msg* SproutletProxyTsxHelper::clone_request(pjsip_msg* req)
{
  // Get the old tdata from the map of clones
  Clones::iterator it = _clones.find(req);
  if (it == _clones.end())
  {
    LOG_WARNING("Sproutlet attempted to clone an unrecognised request");
    return NULL;
  }

  // Clone the tdata and put it back into the map
  pjsip_tx_data* new_tdata = PJUtils::clone_tdata(it->second);
  register_tdata(new_tdata);

  return new_tdata->msg;
}

pjsip_msg* SproutletProxyTsxHelper::create_response(pjsip_msg* req,
                                                    pjsip_status_code status_code,
                                                    const std::string& status_text)
{
  // Get the request's tdata from the map of clones
  Clones::iterator it = _clones.find(req);
  if (it == _clones.end())
  {
    LOG_WARNING("Sproutlet attempted to create a response from an unrecognised request");
    return NULL;
  }

  // Create a response from the tdata and add it to the map.
  pjsip_tx_data* new_tdata;

  pj_status_t status = PJUtils::create_response(stack_data.endpt,
                                                it->second,
                                                status_code,
                                                status_text,
                                                &new_tdata);

  if (status == PJ_SUCCESS) 
  {
    register_tdata(new_tdata);
    return new_tdata->msg;
  }

  return NULL;
}

int SproutletProxyTsxHelper::send_request(pjsip_msg*& req)
{
  LOG_DEBUG("Sproutlet send_request %p", req);

  // Check that this actually is a request
  if (req->type != PJSIP_REQUEST_MSG)
  {
    LOG_ERROR("Sproutlet attempted to forward a response as a request");
    return -1;
  }

  // Get the tdata from the map of clones
  Clones::iterator it = _clones.find(req);
  if (it == _clones.end())
  {
    LOG_ERROR("Sproutlet attempted to forward an unrecognised request");
    return -1;
  }

  // If we've already forwarded a final response, we should not forward a
  // request too.
  if (req->line.status.code >= PJSIP_SC_OK)
  {
    _final_response_sent = true;
    if (!_requests.empty())
    {
      LOG_ERROR("Sproutlet sent a final response as well as forwarding downstream");
    }
  }

  // We've found the tdata, move it to _requests under a new unique ID.
  int fork_id = _unique_id++;
  _requests[fork_id] = it->second;
  LOG_DEBUG("Added request %d (tdata=%p) to output with fork id %d",
            _requests.size(), it->second, fork_id);

  // Move the clone out of the clones list.
  _clones.erase(req);

  // Finish up
  req = NULL;
  return fork_id;
}

void SproutletProxyTsxHelper::send_response(pjsip_msg*& rsp)
{
  // Check that this actually is a response
  if (rsp->type != PJSIP_RESPONSE_MSG)
  {
    LOG_ERROR("Sproutlet attempted to forward a request as a response");
    return;
  }

  // Get the tdata from the map of clones
  Clones::iterator it = _clones.find(rsp);
  if (it == _clones.end())
  {
    LOG_ERROR("Sproutlet attempted to clone an unrecognised request");
    return;
  }

  // If this is a final response, we should not have a request forwarded too.
  if (rsp->line.status.code >= PJSIP_SC_OK)
  {
    _final_response_sent = true;
    if (!_requests.empty())
    {
      LOG_ERROR("Sproutlet sent a final response as well as forwarding downstream");
    }
  }

  // We've found the tdata, move it to _responses.
  _responses.push_back(it->second);

  // Move the clone out of the clones list.
  _clones.erase(rsp);

  // Finish up
  rsp = NULL;
}

void SproutletProxyTsxHelper::free_msg(pjsip_msg*& msg)
{
  // Get the tdata from the map of clones
  Clones::iterator it = _clones.find(msg);
  if (it == _clones.end())
  {
    LOG_ERROR("Sproutlet attempted to free an unrecognised message");
    return;
  }

  pjsip_tx_data_dec_ref(it->second);

  _clones.erase(msg);

  // Finish up
  msg = NULL;
}

pj_pool_t* SproutletProxyTsxHelper::get_pool(const pjsip_msg* msg)
{
  // Get the tdata from the map of clones
  Clones::iterator it = _clones.find(msg);
  if (it == _clones.end())
  {
    LOG_ERROR("Sproutlet attempted to get the pool for an unrecognised message");
    return NULL;
  }

  return it->second->pool;
}

SAS::TrailId SproutletProxyTsxHelper::trail() const
{
  return _trail_id;
}
