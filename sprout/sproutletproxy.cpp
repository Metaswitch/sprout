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
  _uri(NULL),
  _service_map(),
  _port_map()
{
  /// Store the URI of this SproutletProxy - this is used for Record-Routing.
  LOG_DEBUG("Supplied Record-Route URI = %s", uri.c_str());
  _uri = (pjsip_sip_uri*)PJUtils::uri_from_string(uri, stack_data.pool, false);

  /// Build maps from service name and port number to Sproutlet object.
  for (std::list<Sproutlet*>::const_iterator i = sproutlets.begin();
       i != sproutlets.end();
       ++i) 
  {
    _service_map[(*i)->service_name()] = *i;

    if ((*i)->port() != 0) 
    {
      _port_map[(*i)->port()] = *i;
    }
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
Sproutlet* SproutletProxy::target_sproutlet(pjsip_msg* msg, int port)
{
  Sproutlet* sproutlet = NULL;
  std::string id;

  // Find and parse the top Route header.
  pjsip_route_hdr* route = (pjsip_route_hdr*)
                                  pjsip_msg_find_hdr(msg, PJSIP_H_ROUTE, NULL);

  if ((route != NULL) &&
      (PJSIP_URI_SCHEME_IS_SIP(route->name_addr.uri)))
  {
    pjsip_sip_uri* uri = (pjsip_sip_uri*)route->name_addr.uri;
    id = service_id(uri);
    if (port == 0) 
    {
      // No port was specified, so use the URI port instead.
      port = uri->port;
    }
  }

  if (!id.empty()) 
  {
    // There was a service identifier encoded in the Route URI.
    std::map<std::string, Sproutlet*>::iterator i =
                                           _service_map.find(service_name(id));

    if (i != _service_map.end()) 
    {
      sproutlet = i->second;
    }
  }
  else if (port != 0)
  {
    // No service identifier in the Route URI, so check for a default service
    // for the port.
    std::map<int, Sproutlet*>::iterator i = _port_map.find(port);
    if (i != _port_map.end()) 
    {
      sproutlet = i->second;
    }
  }

  return sproutlet;
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
  pjsip_param *p = PJ_POOL_ALLOC_T(tdata->pool, pjsip_param);
  pj_strdup2(tdata->pool, &p->name, service_name.c_str());
  pj_strdup2(tdata->pool, &p->value, dialog_id.c_str());
  pj_list_insert_before(&rr_uri->other_param, p);

  // Construct and add the Record-Route header.
  pjsip_rr_hdr* hrr = pjsip_rr_hdr_create(tdata->pool);
  hrr->name_addr.uri = (pjsip_uri*)rr_uri;
  pjsip_msg_insert_first_hdr(tdata->msg, (pjsip_hdr*)hrr);
}


/// Extracts the first service identifier encoded in the URI (if any).
/// Service identifiers can be encoded in the host or user part of the URI.
/// If encoded in the host, the service identifier can only contain a service
/// name.  If encoded in the user part, the service identifier can also
/// have a concatenated service index, separated by a '-'.  If multiple
/// service identifiers are included in the user part, they are separated by
/// '&' characters.
std::string SproutletProxy::service_id(pjsip_sip_uri* uri)
{
  std::string id;

  if (!pj_stricmp(&uri->host, &_uri->host)) 
  {
    // The URI domain is the same as the local URI domain, so look for 
    // service names in the user portion of the URI.
    if (uri->user.slen > 0) 
    {
      // Scan for a separator
      char* sep = pj_strchr(&uri->user, '&');
      if (sep != NULL) 
      {
        // Found a separator, so service name is the string up to the 
        // separator.
        id = std::string(uri->user.ptr, (sep - uri->user.ptr));
      }
      else
      {
        // No separator, so service name is the full username.
        id = std::string(uri->user.ptr, uri->user.slen);
      }
    }
  }
  else
  {
    // The URI domain is not identical to the local URI domain, so check
    // for the service name as the first part of the domain.
    char* sep = pj_strchr(&uri->host, '.');
    if (sep != NULL) 
    {
      // Extract the root of the domain and check it is the same as the
      // local URI domain.
      pj_str_t root_host;
      root_host.ptr = sep + 1;
      root_host.slen = uri->host.slen - (sep + 1 - uri->host.ptr);
      if (!pj_stricmp(&root_host, &_uri->host)) 
      {
        // The root of the URI domain matches, so the service name is
        // the portion at the front.
        id = std::string(uri->host.ptr, (sep - uri->host.ptr));
      }
    }
  }

  return id;
}


/// Extracts the service name from a service identifier.
std::string SproutletProxy::service_name(const std::string& service_id)
{
  size_t sep = service_id.find_first_of('-');
  if (sep != std::string::npos) 
  {
    return service_id.substr(0, sep);
  }
  else
  {
    return service_id;
  }
}


SproutletProxy::UASTsx::UASTsx(BasicProxy* proxy) :
  BasicProxy::UASTsx(proxy),
  _record_routed(false),
  _root(NULL),
  _dmap_sproutlet(),
  _dmap_uac(),
  _umap()                   
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
    Sproutlet* sproutlet =
                   target_sproutlet(_req->msg,
                                    rdata->tp_info.transport->local_name.port);
    LOG_DEBUG("Initializing SproutletProxy transaction for %s",
              sproutlet->service_name().c_str());
    _root = new TsxHelper(this, sproutlet, _req, trail());
  }
                                                       
  return status;
}


/// Handle the incoming half of a transaction request.
void SproutletProxy::UASTsx::process_tsx_request(pjsip_rx_data* rdata)
{
  // Pass the request to the Sproutlet at the root of the tree.
  _root->rx_request(_req);
}


/// Handle a received CANCEL request.
void SproutletProxy::UASTsx::process_cancel_request(pjsip_rx_data* rdata)
{
  // Pass the CANCEL to the Sproutlet at the root of the tree.
  pjsip_tx_data* tdata = PJUtils::clone_msg(stack_data.endpt, rdata);
  _root->rx_cancel(tdata);
}


/// Handles a response to an associated UACTsx.
void SproutletProxy::UASTsx::on_new_client_response(UACTsx* uac_tsx,
                                                    pjsip_tx_data *rsp)
{
  enter_context();

  if (rsp->msg->line.status.code >= PJSIP_SC_OK) 
  {
    // This is a final response, so dissociate the UAC transaction.
    dissociate(uac_tsx);
  }

  UMap::iterator i = _umap.find((void*)uac_tsx);

  if (i != _umap.end()) 
  {
    // Pass the response to the upstream Sproutlet on the appropriate fork.
    TsxHelper* upstream_helper = i->second.first;
    int upstream_fork = i->second.second;

    if (rsp->msg->line.status.code >= PJSIP_SC_OK) 
    {
      // Final response, so break the linkage between the UAC transaction and
      // the Sproutlets.
      _dmap_uac.erase(i->second);
      _umap.erase(i);
    }
    upstream_helper->rx_response(rsp, upstream_fork);
  }
  else
  {
    pjsip_tx_data_dec_ref(rsp);
  }

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
    _root->rx_error(PJSIP_SC_REQUEST_TIMEOUT);
  }

  BasicProxy::UASTsx::on_tsx_state(event);

  exit_context();
}


Sproutlet* SproutletProxy::UASTsx::target_sproutlet(pjsip_msg* msg, int port)
{
  return ((SproutletProxy*)_proxy)->target_sproutlet(msg, port);
}


void SproutletProxy::UASTsx::add_record_route(pjsip_tx_data* tdata,
                                              const std::string& service_name,
                                              const std::string& dialog_id)
{
  ((SproutletProxy*)_proxy)->add_record_route(tdata, service_name, dialog_id);
}


void SproutletProxy::UASTsx::tx_sproutlet_request(TsxHelper* helper,
                                                  int fork_id,
                                                  pjsip_tx_data* req)
{
  Sproutlet* sproutlet = target_sproutlet(req->msg, 0);

  if (sproutlet != NULL) 
  {
    // Found a local Sproutlet to handle the request, so create a helper.
    TsxHelper* downstream_helper = new TsxHelper(this, sproutlet, req, trail());

    if (downstream_helper != NULL) 
    {
      // Set up the mappings.
      _dmap_sproutlet[std::make_pair(helper, fork_id)] = downstream_helper;
      _umap[(void*)downstream_helper] = std::make_pair(helper, fork_id);

      // Pass the request to the downstream helper.
      downstream_helper->rx_request(req);
    }
    else
    {
      // @TODO
    }
  }
  else
  {
    // No local Sproutlet, so route the request externally.
    size_t index;
    pj_status_t status = allocate_uac(req, index);

    if (status == PJ_SUCCESS) 
    {
      // Successfully set up UAC transaction, so set up the mappings and
      // send the request.
      _dmap_uac[std::make_pair(helper, fork_id)] = _uac_tsx[index];
      _umap[(void*)_uac_tsx[index]] = std::make_pair(helper, fork_id);

      // Send the request.
      _uac_tsx[index]->send_request();
    }
    else
    {
      // @TODO
    }
  }
}


void SproutletProxy::UASTsx::tx_sproutlet_response(TsxHelper* helper,
                                                   pjsip_tx_data* rsp)
{
  if (helper == _root) 
  {
    // This is the root sproutlet in the tree, so send the response on the
    // UAS transaction.
    if (_final_rsp != NULL) 
    {
      pjsip_tx_data_dec_ref(_final_rsp);
    }
    _final_rsp = rsp;
    on_final_response();
  }
  else
  {
    // Find the upstream Sproutlet/fork for this helper.
    UMap::iterator i = _umap.find((void*)helper); 
    if (i != _umap.end()) 
    {
      // Found the upstream Sproutlet/fork, so pass the request.
      TsxHelper* upstream_helper = i->second.first;
      int upstream_fork = i->second.second;

      if (rsp->msg->line.status.code >= PJSIP_SC_OK) 
      {
        // Final response, so break the linkage between the Sproutlets.
        _dmap_sproutlet.erase(i->second);
        _umap.erase(i);
      }
      upstream_helper->rx_response(rsp, upstream_fork);
    }
    else
    {
      // Failed to find the upstream Sproutlet, so discard the response.
      pjsip_tx_data_dec_ref(rsp);
    }
  }
}


void SproutletProxy::UASTsx::tx_sproutlet_cancel(TsxHelper* helper,
                                                 int fork_id,
                                                 pjsip_tx_data* cancel)
{
  DMap<TsxHelper*>::iterator i = _dmap_sproutlet.find(std::make_pair(helper, fork_id));

  if (i != _dmap_sproutlet.end()) 
  {
    // Pass the CANCEL request to the downstream Sproutlet.
    TsxHelper* downstream_helper = i->second;
    downstream_helper->rx_cancel(cancel);
  }
  else
  {
    DMap<UACTsx*>::iterator j = _dmap_uac.find(std::make_pair(helper, fork_id));
    if (j != _dmap_uac.end()) 
    {
      // CANCEL the downstream UAC transaction.
      UACTsx* uac_tsx = j->second;
      uac_tsx->cancel_pending_tsx(0);
    }

    // Free the CANCEL request.
    pjsip_tx_data_dec_ref(cancel);
  }
}


//
// UASTsx::TsxHelper methods.
//

SproutletProxy::UASTsx::TsxHelper::TsxHelper(SproutletProxy::UASTsx* proxy_tsx,
                                             Sproutlet* sproutlet,
                                             pjsip_tx_data* req,
                                             SAS::TrailId trail_id) :
  _proxy_tsx(proxy_tsx),
  _sproutlet(NULL),
  _service_name(""),
  _packets(),
  _send_requests(),
  _send_responses(),
  _dialog_id(""),
  _record_routed(false),
  _pending_sends(0),
  _pending_responses(0),
  _best_rsp(NULL),
  _complete(false),
  _forks(),
  _trail_id(trail_id)
{
  // Call the Sproutlet to get a SproutletTsx object.
  _sproutlet = sproutlet->get_tsx(this, req->msg);
  _service_name = sproutlet->service_name();
  if (_sproutlet == NULL) 
  {
    // The Sproutlet doesn't want to handle this request, so create a default
    // SproutletTsx to handle it.
    _sproutlet = new SproutletTsx(this);
  }

  // Set up the dialog identifier, either by extracting it from the Route header
  // (on an in-dialog request), or by creating a default.
  if (PJSIP_MSG_TO_HDR(req->msg)->tag.slen == 0) 
  {
    // Initial request, create default.
    // @TODO
  }
  else
  {
    // In-dialog request, so pull from top Route header.
    LOG_DEBUG("In-dialog request");
    pjsip_route_hdr* hr = (pjsip_route_hdr*)
                            pjsip_msg_find_hdr(req->msg, PJSIP_H_ROUTE, NULL);
    if ((hr != NULL) &&
        (PJSIP_URI_SCHEME_IS_SIP(hr->name_addr.uri)))
    {
      pjsip_sip_uri* uri = (pjsip_sip_uri*)hr->name_addr.uri;
      pj_str_t sname;
      sname.slen = _service_name.length();
      sname.ptr = (char*)_service_name.data();
      pjsip_param* p = pjsip_param_find(&uri->other_param, &sname);
      if (p != NULL) 
      {
        // Found the appropriate parameter, so extract the dialog identifier.
        _dialog_id = PJUtils::pj_str_to_string(&p->value);
        LOG_DEBUG("Found dialog identifier %s", _dialog_id.c_str());
      }
    }
  }
}

SproutletProxy::UASTsx::TsxHelper::~TsxHelper()
{
  assert(_packets.empty());
  assert(_send_requests.empty());
  assert(_send_responses.empty());
}

//
// UASTsx::TsxHelper overloads.
//

void SproutletProxy::UASTsx::TsxHelper::add_to_dialog(const std::string& dialog_id)
{
  if (_record_routed)
  {
    LOG_WARNING("A sproutlet has attempted to add itself to the dialog multiple times, only the last dialog_id will be used");
  }

  _record_routed = true;
  _dialog_id = dialog_id;
}

const std::string& SproutletProxy::UASTsx::TsxHelper::dialog_id() const
{
  return _dialog_id;
}

pjsip_msg* SproutletProxy::UASTsx::TsxHelper::clone_request(pjsip_msg* req)
{
  // Get the old tdata from the map of clones
  Packets::iterator it = _packets.find(req);
  if (it == _packets.end())
  {
    LOG_WARNING("Sproutlet attempted to clone an unrecognised request");
    return NULL;
  }

  // Clone the tdata and put it back into the map
  pjsip_tx_data* new_tdata = PJUtils::clone_msg(stack_data.endpt, it->second);

  if (new_tdata == NULL) 
  {
    LOG_ERROR("Failed to clone request for Sproutlet %s", _service_name.c_str());
    return NULL;
  }

  register_tdata(new_tdata);

  return new_tdata->msg;
}

pjsip_msg* SproutletProxy::UASTsx::TsxHelper::create_response(pjsip_msg* req,
                                                              pjsip_status_code status_code,
                                                              const std::string& status_text)
{
  // Get the request's tdata from the map of clones
  Packets::iterator it = _packets.find(req);
  if (it == _packets.end())
  {
    LOG_WARNING("Sproutlet attempted to create a response from an unrecognised request");
    return NULL;
  }

  // Create a response from the tdata and add it to the map.
  pjsip_tx_data* new_tdata;

  pj_str_t status_text_str;
  pj_cstr(&status_text_str, status_text.c_str());
  pj_status_t status = PJUtils::create_response(stack_data.endpt,
                                                it->second,
                                                status_code,
                                                (status_text_str.slen > 0) ? &status_text_str : NULL,
                                                &new_tdata);

  if (status == PJ_SUCCESS) 
  {
    register_tdata(new_tdata);
    return new_tdata->msg;
  }

  return NULL;
}

int SproutletProxy::UASTsx::TsxHelper::send_request(pjsip_msg*& req)
{
  LOG_DEBUG("Sproutlet send_request %p", req);

  // Check that this actually is a request
  if (req->type != PJSIP_REQUEST_MSG)
  {
    LOG_ERROR("Sproutlet attempted to forward a response as a request");
    return -1;
  }

  // Get the tdata from the map of clones
  Packets::iterator it = _packets.find(req);
  if (it == _packets.end())
  {
    LOG_ERROR("Sproutlet attempted to forward an unrecognised request");
    return -1;
  }

  // We've found the tdata, move it to _send_requests under a new unique ID.
  int fork_id = _forks.size();
  _forks.resize(fork_id + 1);
  _forks[fork_id].state = PJSIP_TSX_STATE_NULL;
  _forks[fork_id].pending_cancel = false;
  _send_requests[fork_id] = it->second;
  LOG_DEBUG("Added request %d (tdata=%p) to output with fork id %d",
            _send_requests.size(), it->second, fork_id);

  // Move the clone out of the clones list.
  _packets.erase(req);

  // Finish up
  req = NULL;
  return fork_id;
}

void SproutletProxy::UASTsx::TsxHelper::send_response(pjsip_msg*& rsp)
{
  // Check that this actually is a response
  if (rsp->type != PJSIP_RESPONSE_MSG)
  {
    LOG_ERROR("Sproutlet attempted to forward a request as a response");
    return;
  }

  // Get the tdata from the map of clones
  Packets::iterator it = _packets.find(rsp);
  if (it == _packets.end())
  {
    LOG_ERROR("Sproutlet attempted to clone an unrecognised request");
    return;
  }

  // We've found the tdata, move it to _send_responses.
  _send_responses.push_back(it->second);

  // Move the clone out of the clones list.
  _packets.erase(rsp);

  // Finish up
  rsp = NULL;
}

void SproutletProxy::UASTsx::TsxHelper::cancel_fork(int fork_id, int reason)
{
  if ((_forks.size() > (size_t)fork_id) &&
      ((_forks[fork_id].state == PJSIP_TSX_STATE_CALLING) ||
       (_forks[fork_id].state == PJSIP_TSX_STATE_PROCEEDING)) &&
      (_forks[fork_id].req->msg->line.req.method.id == PJSIP_INVITE_METHOD))          
  {
    // The fork is still pending a final response to an INVITE request, so
    // we can CANCEL it.
    LOG_DEBUG("Cancelling fork %d, reason = %d", fork_id, reason);
    _forks[fork_id].pending_cancel = true;
    _forks[fork_id].cancel_reason = reason;
  }
}

void SproutletProxy::UASTsx::TsxHelper::cancel_pending_forks(int reason)
{
  for (size_t ii = 0; ii < _forks.size(); ++ii) 
  {
    if (((_forks[ii].state == PJSIP_TSX_STATE_CALLING) ||
         (_forks[ii].state == PJSIP_TSX_STATE_PROCEEDING)) &&
        (_forks[ii].req->msg->line.req.method.id == PJSIP_INVITE_METHOD)) 
    {
      // The fork is still pending a final response to an INVITE request, so
      // we can CANCEL it.
      LOG_DEBUG("Cancelling fork %d, reason = %d", ii, reason);
      _forks[ii].pending_cancel = true;
      _forks[ii].cancel_reason = reason;
    }
  }
}

void SproutletProxy::UASTsx::TsxHelper::free_msg(pjsip_msg*& msg)
{
  // Get the tdata from the map of clones
  Packets::iterator it = _packets.find(msg);
  if (it == _packets.end())
  {
    LOG_ERROR("Sproutlet attempted to free an unrecognised message");
    return;
  }

  pjsip_tx_data_dec_ref(it->second);

  _packets.erase(msg);

  // Finish up
  msg = NULL;
}

pj_pool_t* SproutletProxy::UASTsx::TsxHelper::get_pool(const pjsip_msg* msg)
{
  // Get the tdata from the map of clones
  Packets::iterator it = _packets.find(msg);
  if (it == _packets.end())
  {
    LOG_ERROR("Sproutlet attempted to get the pool for an unrecognised message");
    return NULL;
  }

  return it->second->pool;
}

bool SproutletProxy::UASTsx::TsxHelper::schedule_timer(int id,
                                                       void* context,
                                                       int duration)
{
  return false;
}

void SproutletProxy::UASTsx::TsxHelper::cancel_timer(int id)
{
}

bool SproutletProxy::UASTsx::TsxHelper::timer_running(int id)
{
  return false;
}

SAS::TrailId SproutletProxy::UASTsx::TsxHelper::trail() const
{
  return _trail_id;
}

void SproutletProxy::UASTsx::TsxHelper::rx_request(pjsip_tx_data* req)
{
  // Keep an immutable reference to the request.
  _req = req;
  pjsip_tx_data_add_ref(_req);

  // Clone the request to get a mutable copy to pass to the Sproutlet.
  pjsip_tx_data* clone = PJUtils::clone_msg(stack_data.endpt, req);
  if (clone == NULL) 
  {
    // @TODO
  }

  register_tdata(clone);
  if (PJSIP_MSG_TO_HDR(clone->msg)->tag.slen == 0) 
  {
    LOG_DEBUG("Pass initial request to Sproutlet");
    _sproutlet->on_rx_initial_request(clone->msg);
  }
  else
  {
    LOG_DEBUG("Pass in dialog request to Sproutlet");
    _sproutlet->on_rx_in_dialog_request(clone->msg);
  }
  process_actions();

}

void SproutletProxy::UASTsx::TsxHelper::rx_response(pjsip_tx_data* rsp, int fork_id)
{
  register_tdata(rsp);
  if ((PJSIP_IS_STATUS_IN_CLASS(rsp->msg->line.status.code, 100)) &&
      (_forks[fork_id].state == PJSIP_TSX_STATE_CALLING))
  {
    // Provisional response on fork still in calling state, so move to 
    // proceeding state.
    LOG_DEBUG("Received provisional response on fork %d", fork_id);
    _forks[fork_id].state = PJSIP_TSX_STATE_PROCEEDING;
  }
  else if (rsp->msg->line.status.code >= PJSIP_SC_OK) 
  {
    // Final response, so mark the fork as completed and decrement the number
    // of pending responses.
    _forks[fork_id].state = PJSIP_TSX_STATE_COMPLETED;
    LOG_DEBUG("Received final response on fork %d, status = %d",
              fork_id, _forks[fork_id]);
    --_pending_responses;

    // Decrement the reference on the request sent on this fork.
    pjsip_tx_data_dec_ref(_forks[fork_id].req);
  }
  _sproutlet->on_rx_response(rsp->msg, fork_id);
  process_actions();
}

void SproutletProxy::UASTsx::TsxHelper::rx_cancel(pjsip_tx_data* cancel)
{
  LOG_DEBUG("Received CANCEL request");
  _sproutlet->on_rx_cancel(PJSIP_SC_REQUEST_TERMINATED,
                           cancel->msg);
  pjsip_tx_data_dec_ref(cancel);
  cancel_pending_forks();
  process_actions();
}

void SproutletProxy::UASTsx::TsxHelper::rx_error(int status_code)
{
  _sproutlet->on_rx_cancel(status_code, NULL);
  process_actions();
}

void SproutletProxy::UASTsx::TsxHelper::register_tdata(pjsip_tx_data* tdata)
{
  LOG_DEBUG("Adding message %p => txdata %p mapping",
            tdata->msg, tdata);
  _packets[tdata->msg] = tdata;
}

/// Process actions required by a Sproutlet
void SproutletProxy::UASTsx::TsxHelper::process_actions()
{
  LOG_DEBUG("Processing actions from sproutlet - %d responses, %d requests",
            _send_responses.size(), _send_requests.size());

  // First increment the pending sends count by the number of requests waiting
  // to be sent.  This must happen first to avoid the response aggregation
  // code incorrectly triggering on the count of error responses.
  _pending_sends += _send_requests.size();

  // Now handle any responses generated or forwarded by the Sproutlet.
  while (!_send_responses.empty())
  {
    pjsip_tx_data* tdata = _send_responses.front();
    _send_responses.pop_front();
    aggregate_response(tdata);
  }

  if ((!_complete) &&
      (_best_rsp != NULL) &&
      (_pending_sends + _pending_responses == 0))
  {
    // There are no pending responses and no new forked requests waiting to
    // be sent, and the Sproutlet has sent at least one final response, so
    // send this best response upstream.
    LOG_DEBUG("All UAC responded");
    tx_response(_best_rsp);
  }

  if (!_complete) 
  {
    // The Sproutlet transaction hasn't completed, so handle any requests
    // forwarded/generated by the Sproutlet.
    for (std::unordered_map<int, pjsip_tx_data*>::const_iterator i = _send_requests.begin();
         i != _send_requests.end();
         ++i) 
    {
      pjsip_tx_data* tdata = i->second;
      LOG_DEBUG("Processing request %p, fork = %d", tdata, i->first);

      if (_record_routed) 
      {
        // The Sproutlet has requested that we Record-Route on this dialog, so
        // add a Record-Route header.
        _proxy_tsx->add_record_route(tdata, _service_name, _dialog_id);
      }

      tx_request(tdata, i->first);
    }
    _send_requests.clear();
  }

  for (size_t ii = 0; ii < _forks.size(); ++ii) 
  {
    LOG_DEBUG("Fork %d status = %d", ii, _forks[ii]);
    if ((_forks[ii].pending_cancel) &&
        (_forks[ii].state == PJSIP_TSX_STATE_PROCEEDING))
    {
      // Fork has been marked as pending cancel and we have received a 
      // provisional response, so can send the CANCEL.
      LOG_DEBUG("Send CANCEL for fork %d", ii);
      tx_cancel(ii);
    }
  }
}

void SproutletProxy::UASTsx::TsxHelper::aggregate_response(pjsip_tx_data* rsp)
{
  int status_code = rsp->msg->line.status.code;
  LOG_DEBUG("Aggregating response with status code %d", status_code);

  if (_complete) 
  {
    // We've already sent a final response upstream (a 200 OK) so discard
    // this discard.
    LOG_DEBUG("Discard stale response");
    pjsip_tx_data_dec_ref(rsp);
    return;
  }

  if (status_code == 100)
  {
    // We will already have sent a locally generated 100 Trying response, so
    // don't forward this one.
    LOG_DEBUG("Discard 100/INVITE response");
    pjsip_tx_data_dec_ref(rsp);
    return;
  }

  if ((status_code > 100) &&
      (status_code < 199))
  {
    // Forward all provisional responses to INVITEs.
    LOG_DEBUG("Forward 1xx response");
    tx_response(rsp);
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
    _best_rsp = rsp;

    tx_response(_best_rsp);
  }
  else
  {
    // Final, non-OK response.  Is this the "best" response received so far?
    LOG_DEBUG("3xx/4xx/5xx/6xx response");
    if ((_best_rsp == NULL) ||
        (compare_sip_sc(status_code, _best_rsp->msg->line.status.code) > 0))
    {
      LOG_DEBUG("Best 3xx/4xx/5xx/6xx response so far");

      if (_best_rsp != NULL)
      {
        pjsip_tx_data_dec_ref(_best_rsp);
      }

      _best_rsp = rsp;
    }
    else
    {
      LOG_DEBUG("Discard response - we already have a better one");
      pjsip_tx_data_dec_ref(rsp);
    }
  }
}

void SproutletProxy::UASTsx::TsxHelper::tx_request(pjsip_tx_data* req, int fork_id)
{
  // Set the state of this fork to CALLING (strictly speaking this should
  // be TRYING for non-INVITE transaction, but we only need to track this
  // state for determining when we can legally send CANCEL requests using
  // CALLING in all cases is fine).
  _forks[fork_id].state = PJSIP_TSX_STATE_CALLING;
  LOG_DEBUG("Transmitting request on fork_id %d, state = %d",
            fork_id, pjsip_tsx_state_str(_forks[fork_id].state));
  --_pending_sends;
  ++_pending_responses;

  // Store a reference to the request and increment the reference count.
  _forks[fork_id].req = req;

  // Notify the sproutlet that the request is being sent downstream.
  _sproutlet->on_tx_request(req->msg, fork_id);

  // Forward the request downstream.
  _proxy_tsx->tx_sproutlet_request(this, fork_id, req);
}

void SproutletProxy::UASTsx::TsxHelper::tx_response(pjsip_tx_data* rsp)
{
  // Notify the sproutlet that the response is being sent upstream.
  _sproutlet->on_tx_response(rsp->msg);

  if (rsp->msg->line.status.code >= PJSIP_SC_OK) 
  {
    pjsip_tx_data_dec_ref(_req);
    _complete = true;
  }

  // Forward the response upstream.
  _proxy_tsx->tx_sproutlet_response(this, rsp);
}

void SproutletProxy::UASTsx::TsxHelper::tx_cancel(int fork_id)
{
  // Build a CANCEL request from the original request sent on this fork.
  pjsip_tx_data* cancel = PJUtils::create_cancel(stack_data.endpt,
                                                 _forks[fork_id].req,
                                                 _forks[fork_id].cancel_reason);
  _proxy_tsx->tx_sproutlet_cancel(this, fork_id, cancel);
  _forks[fork_id].pending_cancel = false;
}

/// Compare two status codes from the perspective of which is the best to
/// return to the originator of a forked transaction.  This will only ever
/// be called for 3xx/4xx/5xx/6xx response codes.
///
/// @returns +1 if sc1 is better than sc2
///          0 if sc1 and sc2 are identical (or equally as good)
///          -1 if sc2 is better than sc1
///
int SproutletProxy::UASTsx::TsxHelper::compare_sip_sc(int sc1, int sc2)
{
  // Order is: (best) 487, 300, 301, ..., 698, 699, 408 (worst).
  LOG_DEBUG("Compare new status code %d with stored status code %d", sc1, sc2);
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


