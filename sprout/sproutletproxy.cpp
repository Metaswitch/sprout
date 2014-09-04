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

#include <sstream>

#include "log.h"
#include "pjutils.h"
#include "sproutsasevent.h"
#include "sproutletproxy.h"


const pj_str_t SproutletProxy::STR_SERVICE = {"service", 7};

const ForkState NULL_FORK_STATE = {PJSIP_TSX_STATE_NULL, NONE};

/// Constructor.
SproutletProxy::SproutletProxy(pjsip_endpoint* endpt,
                               int priority,
                               const std::string& uri,
                               const std::list<Sproutlet*>& sproutlets) :
  BasicProxy(endpt, "mod-sproutlet-controller", priority, false),
  _uri(NULL),
  _service_name_map(),
  _service_host_map(),
  _port_map()
{
  /// Store the URI of this SproutletProxy - this is used for Record-Routing.
  LOG_DEBUG("Supplied Record-Route URI = %s", uri.c_str());
  _uri = (pjsip_sip_uri*)PJUtils::uri_from_string(uri, stack_data.pool, false);

  /// Build maps from service name, service hostname and port number to
  /// Sproutlet object.
  for (std::list<Sproutlet*>::const_iterator i = sproutlets.begin();
       i != sproutlets.end();
       ++i)
  {
    std::string service_name = (*i)->service_name();
    std::string service_host = (*i)->service_host();
    if (service_host.empty())
    {
      service_host = service_name + "." +
                                  std::string(_uri->host.ptr, _uri->host.slen);
    }

    LOG_DEBUG("Add service name map %s", service_name.c_str());
    _service_name_map[service_name] = *i;

    LOG_DEBUG("Add service host map %s", service_host.c_str());
    _service_host_map[service_host] = *i;

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


void SproutletProxy::on_timer_pop(pj_timer_heap_t* th,
                                  pj_timer_entry* tentry)
{
  SproutletTimerCallbackData* tdata = (SproutletTimerCallbackData*)tentry->user_data;
  LOG_DEBUG("Sproutlet timer popped, id = %ld", (TimerID)tdata);
  tdata->proxy->on_timer_pop(tdata->uas_tsx,
                             tdata->sproutlet_wrapper,
                             tdata->context);
  delete tentry;
  delete tdata;
}


/// Utility method to create a UASTsx object for incoming requests.
BasicProxy::UASTsx* SproutletProxy::create_uas_tsx()
{
  return (BasicProxy::UASTsx*)new SproutletProxy::UASTsx(this);
}


/// Utility method to find the appropriate Sproutlet to handle a request.
Sproutlet* SproutletProxy::target_sproutlet(pjsip_msg* req, int port)
{
  LOG_DEBUG("Find target Sproutlet for request");

  Sproutlet* sproutlet = NULL;
  std::string id;

  // Find and parse the top Route header.
  pjsip_route_hdr* route = (pjsip_route_hdr*)
                                  pjsip_msg_find_hdr(req, PJSIP_H_ROUTE, NULL);

  if ((route != NULL) &&
      (PJSIP_URI_SCHEME_IS_SIP(route->name_addr.uri)))
  {
    LOG_DEBUG("Found top Route header: %s ", PJUtils::hdr_to_string(route).c_str());
    pjsip_sip_uri* uri = (pjsip_sip_uri*)route->name_addr.uri;

    if (PJSIP_MSG_TO_HDR(req)->tag.slen == 0)
    {
      // For initial requests, the service can be encoded in the URI host name
      // or the URI user name.
      LOG_DEBUG("Initial request");
      sproutlet = service_from_host(uri);

      if (sproutlet == NULL)
      {
        sproutlet = service_from_user(uri);
      }
    }
    else
    {
      // For in-dialog requests, the services (and dialog identifiers) are
      // encoded in a URI parameter.
      LOG_DEBUG("In-dialog request");
      sproutlet = service_from_params(uri);
    }

    if (port == 0)
    {
      // No port was specified, so use the URI port instead.
      port = uri->port;
    }
  }

  if ((sproutlet == NULL) &&
      (port != 0))
  {
    // No service identifier in the Route URI, so check for a default service
    // for the port.  We can only do this if there is either no route header
    // or the URI in the Route header corresponds to our hostname.
    LOG_DEBUG("No Sproutlet found using service name or host");
    if ((route == NULL) ||
        (is_uri_local(route->name_addr.uri)))
    {
      LOG_DEBUG("Find default service for port %d", port);
      std::map<int, Sproutlet*>::iterator i = _port_map.find(port);
      if (i != _port_map.end())
      {
        sproutlet = i->second;
      }
    }
  }

  return sproutlet;
}

/// Finds the Sproutlet corresponding to the service encoded in the host
/// portion of the URI.
Sproutlet* SproutletProxy::service_from_host(pjsip_sip_uri* uri)
{
  Sproutlet* sproutlet = NULL;
  LOG_DEBUG("Look for Sproutlet host mapping for %.*s", uri->host.slen, uri->host.ptr);

  std::string service_host = std::string(uri->host.ptr, uri->host.slen);

  std::map<std::string, Sproutlet*>::iterator i = _service_host_map.find(service_host);

  if (i != _service_host_map.end())
  {
    sproutlet = i->second;
  }

  return sproutlet;
}

/// Finds the Sproutlet corresponding to the first service encoded in the user
/// portion of the URI.  If multiple services are specified they are separated
/// by the & character.
Sproutlet* SproutletProxy::service_from_user(pjsip_sip_uri* uri)
{
  Sproutlet* sproutlet = NULL;

  if ((is_uri_local(uri)) && (uri->user.slen > 0))
  {
    // The URI domain is the same as the local URI domain, so look for
    // service names in the user portion of the URI.
    LOG_DEBUG("Look for Sproutlet service mapping for user %.*s",
              uri->user.slen, uri->user.ptr);

    // Scan for a separator.
    char* sep = pj_strchr(&uri->user, '&');
    std::string service;
    if (sep != NULL)
    {
      // Found a separator, so service name is the string up to the
      // separator.
      //LCOV_EXCL_START - not currently supported
      service = std::string(uri->user.ptr, (sep - uri->user.ptr));
      //LCOV_EXCL_STOP
    }
    else
    {
      // No separator, so service name is the full user name.
      service = std::string(uri->user.ptr, uri->user.slen);
    }
    std::map<std::string, Sproutlet*>::iterator i =
                                             _service_name_map.find(service);

    if (i != _service_name_map.end())
    {
      LOG_DEBUG("Found service name %s", service.c_str());
      sproutlet = i->second;
    }
  }

  return sproutlet;
}

/// Finds the Sproutlet corresponding to the first service encoded in the
/// URI parameters.  The list of services (and accompanying dialog identifiers)
/// is encoded in a single parameter, separated by & characters.
Sproutlet* SproutletProxy::service_from_params(pjsip_sip_uri* uri)
{
  Sproutlet* sproutlet = NULL;

  // Find the services parameter in the URI.
  LOG_DEBUG("Look for Sproutlet service parameter");
  pjsip_param* p = pjsip_param_find(&uri->other_param, &STR_SERVICE);

  if (p != NULL)
  {
    // Get the first service in the list.
    LOG_DEBUG("Found services - %.*s", p->value.slen, p->value.ptr);
    pj_str_t service_str = p->value;

    // Scan for a separator between services.
    char* sep = pj_strchr(&service_str, '&');
    if (sep != NULL)
    {
      // Found a separator, so service is the string up to the
      // separator.
      //LCOV_EXCL_START - not currently supported
      service_str.slen = sep - service_str.ptr;
      //LCOV_EXCL_STOP
    }

    // Now scan for the separator between the service name and the dialog
    // identifier.
    sep = pj_strchr(&service_str, '/');

    if (sep != NULL)
    {
      service_str.slen = sep - service_str.ptr;
    }

    std::string service = std::string(service_str.ptr, service_str.slen);
    LOG_DEBUG("Found service name %s", service.c_str());
    std::map<std::string, Sproutlet*>::iterator i =
                                             _service_name_map.find(service);
    if (i != _service_name_map.end())
    {
      sproutlet = i->second;
    }
  }

  return sproutlet;
}

#if 0
/// Adds a Record-Route header for this node if one has not already been
/// added, and encoded the specified service and dialog identifier in the
/// header.
void SproutletProxy::add_record_route(pjsip_tx_data* tdata,
                                      const std::string& service_name,
                                      const std::string& dialog_id)
{
  LOG_DEBUG("Add Record-Route %s:%s", service_name.c_str(), dialog_id.c_str());

  pjsip_rr_hdr* hrr = (pjsip_rr_hdr*)
                    pjsip_msg_find_hdr(tdata->msg, PJSIP_H_RECORD_ROUTE, NULL);

  if ((hrr == NULL) ||
      (!is_uri_local(hrr->name_addr.uri)))
  {
    // Construct and add the Record-Route header.
    LOG_DEBUG("Add new Record-Route header");
    pjsip_sip_uri* rr_uri = (pjsip_sip_uri*)pjsip_uri_clone(tdata->pool, _uri);
    rr_uri->lr_param = 1;
    hrr = pjsip_rr_hdr_create(tdata->pool);
    hrr->name_addr.uri = (pjsip_uri*)rr_uri;
    pjsip_msg_insert_first_hdr(tdata->msg, (pjsip_hdr*)hrr);
  }

  pjsip_sip_uri* uri = (pjsip_sip_uri*)hrr->name_addr.uri;
  pjsip_param* p = pjsip_param_find(&uri->other_param, &STR_SERVICE);
  std::string services;

  if (p == NULL)
  {
    // No services parameter has been added, so add one now.
    LOG_DEBUG("Add services parameter");
    p = PJ_POOL_ALLOC_T(tdata->pool, pjsip_param);
    pj_strdup(tdata->pool, &p->name, &STR_SERVICE);
    pj_list_insert_before(&uri->other_param, p);
  }
  else
  {
    // Existing services parameter, so extract existing parameter.
    services = std::string(p->value.ptr, p->value.slen);
    LOG_DEBUG("Existing services parameter = %s", services.c_str());
  }

  // Add the service name and dialog identifier to the parameter.
  if (!services.empty())
  {
    services += '&';
  }
  services += service_name + '/' + dialog_id;
  pj_strdup2(tdata->pool, &p->value, services.c_str());
  LOG_DEBUG("%s", PJUtils::hdr_to_string(hrr).c_str());
}
#else
/// Adds a Record-Route header for this node encoding the specified service
/// and dialog identifier in the header.
void SproutletProxy::add_record_route(pjsip_tx_data* tdata,
                                      const std::string& service_name,
                                      const std::string& dialog_id)
{
  LOG_DEBUG("Add Record-Route %s:%s", service_name.c_str(), dialog_id.c_str());

  // Construct and add the Record-Route header.
  LOG_DEBUG("Add new Record-Route header");
  pjsip_sip_uri* uri = (pjsip_sip_uri*)pjsip_uri_clone(tdata->pool, _uri);
  uri->lr_param = 1;
  pjsip_route_hdr* hrr = pjsip_rr_hdr_create(tdata->pool);
  hrr->name_addr.uri = (pjsip_uri*)uri;
  pjsip_msg_insert_first_hdr(tdata->msg, (pjsip_hdr*)hrr);

  LOG_DEBUG("Add services parameter");
  pjsip_param* p = PJ_POOL_ALLOC_T(tdata->pool, pjsip_param);
  pj_strdup(tdata->pool, &p->name, &STR_SERVICE);
  pj_list_insert_before(&uri->other_param, p);
  std::string services = service_name + '/' + dialog_id;
  pj_strdup2(tdata->pool, &p->value, services.c_str());
  LOG_DEBUG("%s", PJUtils::hdr_to_string(hrr).c_str());
}
#endif


bool SproutletProxy::is_uri_local(pjsip_uri* uri)
{
  if (PJSIP_URI_SCHEME_IS_SIP(uri))
  {
    return is_uri_local((pjsip_sip_uri*)uri);
  }
  //LCOV_EXCL_START
  return false;
  //LCOV_EXCL_STOP
}


bool SproutletProxy::is_uri_local(pjsip_sip_uri* uri)
{
  pjsip_sip_uri* sip_uri = (pjsip_sip_uri*)uri;
  return is_host_local(&sip_uri->host);
}


bool SproutletProxy::is_host_local(pj_str_t* host)
{
  if (!pj_stricmp(host, &_uri->host))
  {
    return true;
  }
  return false;
}

bool SproutletProxy::schedule_timer(SproutletProxy::UASTsx* uas_tsx,
                                    SproutletWrapper* sproutlet_wrapper,
                                    void* context,
                                    TimerID& id,
                                    int duration)
{
  pj_timer_entry* tentry = new pj_timer_entry();
  memset(tentry, 0, sizeof(*tentry));

  SproutletTimerCallbackData* tdata = new SproutletTimerCallbackData;
  tdata->uas_tsx = uas_tsx;
  tdata->sproutlet_wrapper = sproutlet_wrapper;
  tdata->context = context;
  tentry->user_data = tdata;

  tentry->cb = SproutletProxy::on_timer_pop;

  id = (TimerID)tentry;

  pj_time_val tval;
  tval.sec = duration / 1000;
  tval.msec = duration % 1000;

  pj_status_t rc = pjsip_endpt_schedule_timer(_endpt, tentry, &tval);

  LOG_DEBUG("Started Sproutlet timer, id = %ld, duration = %d.%.3d",
            id, tval.sec, tval.msec);
  return (rc == 0);
}


void SproutletProxy::cancel_timer(TimerID id)
{
  pj_timer_entry* tentry = (pj_timer_entry*)id;
  pjsip_endpt_cancel_timer(_endpt, tentry);
  SproutletTimerCallbackData* tdata = (SproutletTimerCallbackData*)tentry->user_data;
  delete tdata;
  delete tentry;
  LOG_DEBUG("Cancelled Sproutlet timer, id = %ld", id);
}


bool SproutletProxy::timer_running(TimerID id)
{
  pj_timer_entry* tentry = (pj_timer_entry*)id;
  return pj_timer_entry_running(tentry);
}


void SproutletProxy::on_timer_pop(SproutletProxy::UASTsx* uas_tsx,
                                  SproutletWrapper* sproutlet_wrapper,
                                  void* context)
{
  uas_tsx->process_timer_pop(sproutlet_wrapper,
                             context);
}

SproutletProxy::UASTsx::UASTsx(SproutletProxy* proxy) :
  BasicProxy::UASTsx(proxy),
  _root(NULL),
  _dmap_sproutlet(),
  _dmap_uac(),
  _umap(),
  _pending_req_q(),
  _sproutlet_proxy(proxy)
{
  LOG_VERBOSE("Sproutlet Proxy transaction (%p) created", this);
}


SproutletProxy::UASTsx::~UASTsx()
{
  LOG_VERBOSE("Sproutlet Proxy transaction (%p) destroyed", this);
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
    _root = new SproutletWrapper(_sproutlet_proxy,
                                 this,
                                 sproutlet,
                                 _req,
                                 trail());
  }

  return status;
}


/// Handle the incoming half of a transaction request.
void SproutletProxy::UASTsx::process_tsx_request(pjsip_rx_data* rdata)
{
  // Pass the request to the Sproutlet at the root of the tree.
  pjsip_tx_data_add_ref(_req);
  _root->rx_request(_req);

  // Schedule any requests generated by the Sproutlet.
  schedule_requests();

  if (_tsx == NULL)
  {
    // ACK request, so no response to wait for.
    LOG_DEBUG("ACK transaction is complete");
    _root = NULL;
    on_tsx_complete();
    _pending_destroy = true;
  }
}


/// Handle a received CANCEL request.
void SproutletProxy::UASTsx::process_cancel_request(pjsip_rx_data* rdata)
{
  // We may receive a CANCEL after sending a final response, so check that
  // the root Sproutlet is still connected.
  if (_root != NULL)
  {
    // Pass the CANCEL to the Sproutlet at the root of the tree.
    pjsip_tx_data* tdata = PJUtils::clone_msg(stack_data.endpt, rdata);
    _root->rx_cancel(tdata);

    // Schedule any requests generated by the Sproutlet.
    schedule_requests();
  }
}


/// Handle a timer expiring.
void SproutletProxy::UASTsx::process_timer_pop(SproutletWrapper* sproutlet_wrapper,
                                               void* context)
{
  enter_context();
  sproutlet_wrapper->on_timer_pop(context);
  schedule_requests();
  exit_context();
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
    SproutletWrapper* upstream_sproutlet = i->second.first;
    int upstream_fork = i->second.second;

    if (rsp->msg->line.status.code >= PJSIP_SC_OK)
    {
      // Final response, so break the linkage between the UAC transaction and
      // the Sproutlets.
      _dmap_uac.erase(i->second);
      _umap.erase(i);

      // Check to see if we can destroy the UASTsx.
      check_destroy();
    }
    upstream_sproutlet->rx_response(rsp, upstream_fork);

    // Schedule any requests generated by the Sproutlet.
    schedule_requests();
  }
  else
  {
    //LCOV_EXCL_START
    LOG_DEBUG("Discard response %s (%s)", pjsip_tx_data_get_info(rsp), rsp->obj_name);
    pjsip_tx_data_dec_ref(rsp);
    //LCOV_EXCL_STOP
  }

  exit_context();
}


/// Handles a response to an associated UACTsx.
void SproutletProxy::UASTsx::on_client_not_responding(UACTsx* uac_tsx,
                                                      pjsip_event_id_e event)
{
  enter_context();

  // This is equivalent to a final response, so dissociate the UAC transaction.
  dissociate(uac_tsx);

  UMap::iterator i = _umap.find((void*)uac_tsx);

  if (i != _umap.end())
  {
    // Pass the error to the upstream Sproutlet on the appropriate fork.
    SproutletWrapper* upstream_sproutlet = i->second.first;
    int upstream_fork = i->second.second;

    // Final response, so break the linkage between the UAC transaction and
    // the Sproutlets.
    _dmap_uac.erase(i->second);
    _umap.erase(i);

    // Check to see if we can destroy the UASTsx.
    check_destroy();

    upstream_sproutlet->rx_fork_error(event, upstream_fork);

    // Schedule any requests generated by the Sproutlet.
    schedule_requests();
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

  if (_tsx->state == PJSIP_TSX_STATE_TERMINATED)
  {
    // UAS transaction has completed, so do any transaction completion
    // activities.
    on_tsx_complete();
  }

  if ((_root != NULL) &&
      (_tsx->state == PJSIP_TSX_STATE_TERMINATED) &&
      ((event->body.tsx_state.type == PJSIP_EVENT_TIMER) ||
       (event->body.tsx_state.type == PJSIP_EVENT_TRANSPORT_ERROR)))
  {
    // Notify the root Sproutlet of the error.
    LOG_DEBUG("Pass error to Sproutlet %p", _root);
    _root->rx_error(PJSIP_SC_REQUEST_TIMEOUT);

    // Schedule any requests generated by the Sproutlet.
    schedule_requests();

    // The root Sproutlet may suicide at any time now, so don't send anything
    // else to it.
    _root = NULL;
  }

  if (_tsx->state == PJSIP_TSX_STATE_DESTROYED)
  {
    LOG_DEBUG("%s - UAS tsx destroyed", _tsx->obj_name);
    _proxy->unbind_transaction(_tsx);
    _tsx = NULL;

    // Check to see if we can destroy the UASTsx.
    check_destroy();
  }

  exit_context();
}


Sproutlet* SproutletProxy::UASTsx::target_sproutlet(pjsip_msg* msg, int port)
{
  return _sproutlet_proxy->target_sproutlet(msg, port);
}


void SproutletProxy::UASTsx::add_record_route(pjsip_tx_data* tdata,
                                              const std::string& service_name,
                                              const std::string& dialog_id)
{
  _sproutlet_proxy->add_record_route(tdata, service_name, dialog_id);
}


void SproutletProxy::UASTsx::tx_request(SproutletWrapper* upstream,
                                        int fork_id,
                                        pjsip_tx_data* req)
{
  // Add the request to the back of the pending request queue.
  PendingRequest pr;
  pr.req = req;
  pr.upstream = std::make_pair(upstream, fork_id);
  _pending_req_q.push(pr);
}


void SproutletProxy::UASTsx::schedule_requests()
{
  while (!_pending_req_q.empty())
  {
    PendingRequest req = _pending_req_q.front();
    _pending_req_q.pop();

    Sproutlet* sproutlet = target_sproutlet(req.req->msg, 0);

    if (sproutlet != NULL)
    {
      // Found a local Sproutlet to handle the request, so create a
      // SproutletWrapper.
      SproutletWrapper* downstream = new SproutletWrapper(_sproutlet_proxy,
                                                          this,
                                                          sproutlet,
                                                          req.req,
                                                          trail());

      // Set up the mappings.
      _dmap_sproutlet[req.upstream] = downstream;
      _umap[(void*)downstream] = req.upstream;

      if (req.req->msg->line.req.method.id == PJSIP_INVITE_METHOD)
      {
        // Send an immediate 100 Trying response to the upstream
        // Sproutlet.
        pjsip_tx_data* trying;
        pj_status_t status = PJUtils::create_response(stack_data.endpt,
                                                      req.req,
                                                      PJSIP_SC_TRYING,
                                                      NULL,
                                                      &trying);
        if (status == PJ_SUCCESS)
        {
          req.upstream.first->rx_response(trying, req.upstream.second);
        }
      }

      // Pass the request to the downstream sproutlet.
      downstream->rx_request(req.req);
    }
    else
    {
      // No local Sproutlet, so route the request externally.
      size_t index;
      PJUtils::add_top_via(req.req);
      pj_status_t status = allocate_uac(req.req, index);

      if (status == PJ_SUCCESS)
      {
        // Successfully set up UAC transaction, so set up the mappings and
        // send the request.
        _dmap_uac[req.upstream] = _uac_tsx[index];
        _umap[(void*)_uac_tsx[index]] = req.upstream;

        // Send the request.
        _uac_tsx[index]->send_request();
      }
      else
      {
        // @TODO
      }
    }
  }
}


bool SproutletProxy::UASTsx::schedule_timer(SproutletWrapper* tsx,
                                            void* context,
                                            TimerID& id,
                                            int duration)
{
  return _sproutlet_proxy->schedule_timer(this,
                                          tsx,
                                          context,
                                          id,
                                          duration);
}

void SproutletProxy::UASTsx::cancel_timer(TimerID id)
{
  _sproutlet_proxy->cancel_timer(id);
}


bool SproutletProxy::UASTsx::timer_running(TimerID id)
{
  return _sproutlet_proxy->timer_running(id);
}


void SproutletProxy::UASTsx::tx_response(SproutletWrapper* downstream,
                                         pjsip_tx_data* rsp)
{
  if (downstream == _root)
  {
    // This is the root sproutlet in the tree, so send the response on the
    // UAS transaction.
    if (_tsx != NULL)
    {
      int st_code = rsp->msg->line.status.code;
      set_trail(rsp, trail());
      on_tx_response(rsp);
      pjsip_tsx_send_msg(_tsx, rsp);

      if (st_code >= PJSIP_SC_OK)
      {
        // Final response, so disconnect root Sproutlet.
        _root = NULL;
      }

      if ((_tsx->method.id == PJSIP_INVITE_METHOD) &&
          (PJSIP_IS_STATUS_IN_CLASS(st_code, 200)))
      {
        // Terminate the UAS transaction (this needs to be done
        // manually for INVITE 2xx response, otherwise the
        // transaction layer will wait for an ACK).  This will also
        // cause all other pending UAC transactions to be cancelled.
        LOG_DEBUG("%s - Terminate UAS INVITE transaction", _tsx->obj_name);
        pjsip_tsx_terminate(_tsx, st_code);
      }
    }
  }
  else
  {
    // Find the upstream Sproutlet/fork for this sproutlet.
    UMap::iterator i = _umap.find((void*)downstream);
    if (i != _umap.end())
    {
      // Found the upstream Sproutlet/fork, so pass the request.
      SproutletWrapper* upstream = i->second.first;
      int fork_id = i->second.second;

      if (rsp->msg->line.status.code >= PJSIP_SC_OK)
      {
        // Final response, so break the linkage between the Sproutlets.
        _dmap_sproutlet.erase(i->second);
        _umap.erase(i);

        // Check to see if the UASTsx can be destroyed.
        check_destroy();
      }
      upstream->rx_response(rsp, fork_id);
    }
    else
    {
      // Failed to find the upstream Sproutlet, so discard the response.
      //LCOV_EXCL_START
      LOG_DEBUG("Discard response %s (%s)", pjsip_tx_data_get_info(rsp), rsp->obj_name);
      pjsip_tx_data_dec_ref(rsp);
      //LCOV_EXCL_STOP
    }
  }
}


void SproutletProxy::UASTsx::tx_cancel(SproutletWrapper* upstream,
                                       int fork_id,
                                       pjsip_tx_data* cancel)
{
  LOG_DEBUG("Process CANCEL from %s on fork %d",
            upstream->service_name().c_str(), fork_id);
  DMap<SproutletWrapper*>::iterator i =
                       _dmap_sproutlet.find(std::make_pair(upstream, fork_id));

  if (i != _dmap_sproutlet.end())
  {
    // Pass the CANCEL request to the downstream Sproutlet.
    SproutletWrapper* downstream = i->second;
    LOG_DEBUG("Route CANCEL to %s", downstream->service_name().c_str());
    downstream->rx_cancel(cancel);
  }
  else
  {
    DMap<UACTsx*>::iterator j = _dmap_uac.find(std::make_pair(upstream, fork_id));
    if (j != _dmap_uac.end())
    {
      // CANCEL the downstream UAC transaction.
      LOG_DEBUG("Route CANCEL to downstream UAC transaction");
      UACTsx* uac_tsx = j->second;
      uac_tsx->cancel_pending_tsx(0);
    }

    // Free the CANCEL request.
    LOG_DEBUG("Free CANCEL request (%s)", cancel->obj_name);
    pjsip_tx_data_dec_ref(cancel);
  }
}


/// Checks to see if the UASTsx can be destroyed.  It is only safe to destroy
/// the UASTsx when all the Sproutlet's have completed their processing, which
/// only occurs when all the linkages are broken.
void SproutletProxy::UASTsx::check_destroy()
{
  if ((_dmap_uac.empty()) &&
      (_dmap_sproutlet.empty()) &&
      (_umap.empty()) &&
      (_tsx == NULL))
  {
    // UAS transaction has been destroyed and all Sproutlets are complete.
    _pending_destroy = true;
  }
}


//
// UASTsx::SproutletWrapper methods.
//

SproutletWrapper::SproutletWrapper(SproutletProxy* proxy,
                                   SproutletProxy::UASTsx* proxy_tsx,
                                   Sproutlet* sproutlet,
                                   pjsip_tx_data* req,
                                   SAS::TrailId trail_id) :
  _proxy(proxy),
  _proxy_tsx(proxy_tsx),
  _sproutlet(NULL),
  _service_name(""),
  _service_host(""),
  _id(""),
  _packets(),
  _send_requests(),
  _send_responses(),
  _in_dialog(false),
  _dialog_id(""),
  _record_routed(false),
  _pending_sends(0),
  _pending_responses(0),
  _best_rsp(NULL),
  _complete(false),
  _forks(),
  _trail_id(trail_id)
{
  if (sproutlet != NULL)
  {
    // Offer the Sproutlet the chance to handle this transaction.
    _sproutlet = sproutlet->get_tsx(this, req->msg);
    _service_name = sproutlet->service_name();
    _service_host = sproutlet->service_host();
  }
  else
  {
    // No Sproutlet specified, so we'll use a default "no-op" Sproutlet.
    _service_name = "noop";
  }

  if (_sproutlet == NULL)
  {
    // The Sproutlet doesn't want to handle this request, so create a default
    // SproutletTsx to handle it.
    _sproutlet = new SproutletTsx(this);
  }

  // Construct a unique identifier for this Sproutlet.
  std::ostringstream id;
  id << _service_name << "-" << (const void*)_sproutlet;
  _id = id.str();
  LOG_VERBOSE("Created Sproutlet %s for %s",
              _id.c_str(), pjsip_tx_data_get_info(req));

  _in_dialog = (PJSIP_MSG_TO_HDR(req->msg)->tag.slen > 0);

  if (_in_dialog)
  {
    // In-dialog request, so pull dialog identifier from top Route header.
    LOG_DEBUG("In-dialog request");
    pjsip_route_hdr* hr = (pjsip_route_hdr*)
                             pjsip_msg_find_hdr(req->msg, PJSIP_H_ROUTE, NULL);
    if ((hr != NULL) &&
        (PJSIP_URI_SCHEME_IS_SIP(hr->name_addr.uri)))
    {
      pjsip_sip_uri* uri = (pjsip_sip_uri*)hr->name_addr.uri;
      pjsip_param* p =
             pjsip_param_find(&uri->other_param, &SproutletProxy::STR_SERVICE);
      if (p != NULL)
      {
        // Found the service parameter, so extract the dialog identifier from
        // the first service.
        pj_str_t service_str = p->value;

        // Remove all subsequent services.
        char* sep = pj_strchr(&service_str, '&');
        service_str.slen = (sep != NULL) ?
                                    (sep - service_str.ptr) : service_str.slen;

        // Find the dialog identifier if it is encoded.
        sep = pj_strchr(&service_str, '/');
        if (sep != NULL)
        {
          _dialog_id = std::string(sep + 1,
                                   service_str.slen - (sep + 1 - service_str.ptr));
        }
      }
    }
    LOG_DEBUG("Dialog identifier = %s", _dialog_id.c_str());
  }
}

SproutletWrapper::~SproutletWrapper()
{
  // Destroy the SproutletTsx.
  LOG_DEBUG("Destroying SproutletWrapper %p", this);
  if (_sproutlet != NULL)
  {
    delete _sproutlet;
  }

  if (_req != NULL)
  {
    LOG_DEBUG("Free original request %s (%s)",
              pjsip_tx_data_get_info(_req), _req->obj_name);
    pjsip_tx_data_dec_ref(_req);
  }

  if (!_packets.empty())
  {
    LOG_WARNING("Sproutlet %s leaked %d messages - reclaiming", _id.c_str(), _packets.size());
    for (Packets::iterator it = _packets.begin(); it != _packets.end(); ++it)
    {
      LOG_WARNING("  Leaked message - %s", pjsip_tx_data_get_info(it->second));
      pjsip_tx_data_dec_ref(it->second);
    }
  }
}

const std::string& SproutletWrapper::service_name() const
{
  return _service_name;
}

//
// UASTsx::SproutletWrapper overloads.
//

void SproutletWrapper::add_to_dialog(const std::string& dialog_id)
{
  if (_record_routed)
  {
    LOG_WARNING("A sproutlet has attempted to add itself to the dialog multiple times, only the last dialog_id will be used");
  }

  _record_routed = true;
  _dialog_id = dialog_id;
}

const std::string& SproutletWrapper::dialog_id() const
{
  return _dialog_id;
}

/// Returns a mutable clone of the original request suitable for forwarding
/// or as the basis for constructing a response.
pjsip_msg* SproutletWrapper::original_request()
{
  pjsip_tx_data* clone = PJUtils::clone_msg(stack_data.endpt, _req);

  if (clone == NULL)
  {
    //LCOV_EXCL_START
    LOG_ERROR("Failed to clone original request for Sproutlet %s", _service_name.c_str());
    return NULL;
    //LCOV_EXCL_STOP
  }

  // Remove the top Route header from the request if it refers to this node or
  // this Sproutlet.  The Sproutlet can inspect the route_hdr API if required
  // using the route_hdr() API, but cannot manipulate it.
  pjsip_route_hdr* hr = (pjsip_route_hdr*)
                           pjsip_msg_find_hdr(clone->msg, PJSIP_H_ROUTE, NULL);
  if ((hr != NULL) &&
      (is_uri_local(hr->name_addr.uri)))
  {
    LOG_DEBUG("Remove top Route header %s", PJUtils::hdr_to_string(hr).c_str());
    pj_list_erase(hr);
  }

  register_tdata(clone);

  return clone->msg;
}

/// Returns a brief message summary.
const char* SproutletWrapper::msg_info(pjsip_msg* msg)
{
  Packets::const_iterator it = _packets.find(msg);
  if (it != _packets.end())
  {
    return pjsip_tx_data_get_info(it->second);
  }
  return "";
}

/// Returns the top Route header from the original request.
const pjsip_route_hdr* SproutletWrapper::route_hdr() const
{
  if (_req != NULL)
  {
    pjsip_route_hdr* hr = (pjsip_route_hdr*)
                            pjsip_msg_find_hdr(_req->msg, PJSIP_H_ROUTE, NULL);
    if ((hr != NULL) &&
        (is_uri_local(hr->name_addr.uri)))
    {
      return hr;
    }
  }

  return NULL;
}

pjsip_msg* SproutletWrapper::clone_request(pjsip_msg* req)
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
    //LCOV_EXCL_START
    LOG_ERROR("Failed to clone request for Sproutlet %s", _service_name.c_str());
    return NULL;
    //LCOV_EXCL_STOP
  }

  register_tdata(new_tdata);

  return new_tdata->msg;
}

pjsip_msg* SproutletWrapper::create_response(pjsip_msg* req,
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

  //LCOV_EXCL_START
  return NULL;
  //LCOV_EXCL_STOP
}

int SproutletWrapper::send_request(pjsip_msg*& req)
{
  LOG_DEBUG("Sproutlet send_request %p", req);

  // Get the tdata from the map of clones
  Packets::iterator it = _packets.find(req);
  if (it == _packets.end())
  {
    LOG_ERROR("Sproutlet attempted to forward an unrecognised request");
    return -1;
  }

  // Check that this actually is a request
  if (req->type != PJSIP_REQUEST_MSG)
  {
    LOG_ERROR("Sproutlet attempted to forward a response as a request");
    return -1;
  }

  // We've found the tdata, move it to _send_requests under a new unique ID.
  int fork_id = _forks.size();
  _forks.resize(fork_id + 1);
  _forks[fork_id].state.tsx_state = PJSIP_TSX_STATE_NULL;
  _forks[fork_id].state.error_state = NONE;
  _forks[fork_id].pending_cancel = false;
  _send_requests[fork_id] = it->second;
  LOG_VERBOSE("%s sending %s on fork %d",
              _id.c_str(), pjsip_tx_data_get_info(it->second), fork_id);

  // Move the clone out of the clones list.
  _packets.erase(req);

  // Finish up
  req = NULL;
  return fork_id;
}

void SproutletWrapper::send_response(pjsip_msg*& rsp)
{
  // Get the tdata from the map of clones
  Packets::iterator it = _packets.find(rsp);
  if (it == _packets.end())
  {
    LOG_ERROR("Sproutlet attempted to send an unrecognised response");
    return;
  }

  // Check that this actually is a response
  if (rsp->type != PJSIP_RESPONSE_MSG)
  {
    LOG_ERROR("Sproutlet attempted to forward a request as a response");
    return;
  }

  LOG_VERBOSE("%s sending %s", _id.c_str(), pjsip_tx_data_get_info(it->second));

  // We've found the tdata, move it to _send_responses.
  _send_responses.push_back(it->second);

  // Move the clone out of the clones list.
  _packets.erase(rsp);

  // Finish up
  rsp = NULL;
}

void SproutletWrapper::cancel_fork(int fork_id, int reason)
{
  LOG_DEBUG("Request to cancel fork %d, reason = %d", fork_id, reason);
  if ((_forks.size() > (size_t)fork_id) &&
      (_forks[fork_id].state.tsx_state != PJSIP_TSX_STATE_TERMINATED))
  {
    if (_forks[fork_id].req->msg->line.req.method.id == PJSIP_INVITE_METHOD)
    {
      // The fork is still pending a final response to an INVITE request, so
      // we can CANCEL it.
      LOG_VERBOSE("%s cancelling fork %d, reason = %d",
                  _id.c_str(), fork_id, reason);
      _forks[fork_id].pending_cancel = true;
      _forks[fork_id].cancel_reason = reason;
    }
  }
}

void SproutletWrapper::cancel_pending_forks(int reason)
{
  for (size_t ii = 0; ii < _forks.size(); ++ii)
  {
    if (_forks[ii].state.tsx_state != PJSIP_TSX_STATE_TERMINATED)
    {
      if (_forks[ii].req->msg->line.req.method.id == PJSIP_INVITE_METHOD)
      {
        // The fork is still pending a final response to an INVITE request, so
        // we can CANCEL it.
        LOG_VERBOSE("%s cancelling fork %d, reason = %d", _id.c_str(), ii, reason);
        _forks[ii].pending_cancel = true;
        _forks[ii].cancel_reason = reason;
      }
    }
  }
}

const ForkState& SproutletWrapper::fork_state(int fork_id)
{
  if (fork_id < (int)_forks.size())
  {
    // Fork exists, so read out state.
    return _forks[fork_id].state;
  }
  else
  {
    // Fork doesn't exist, so return defaults.
    return NULL_FORK_STATE;
  }
}

void SproutletWrapper::free_msg(pjsip_msg*& msg)
{
  // Get the tdata from the map of clones
  Packets::iterator it = _packets.find(msg);
  if (it == _packets.end())
  {
    LOG_ERROR("Sproutlet attempted to free an unrecognised message");
    return;
  }

  pjsip_tx_data* tdata = it->second;

  deregister_tdata(tdata);

  LOG_DEBUG("Free message %s", tdata->obj_name);
  pjsip_tx_data_dec_ref(tdata);

  // Finish up
  msg = NULL;
}

pj_pool_t* SproutletWrapper::get_pool(const pjsip_msg* msg)
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

bool SproutletWrapper::schedule_timer(void* context, TimerID& id, int duration)
{
  return _proxy_tsx->schedule_timer(this, context, id, duration);
}

void SproutletWrapper::cancel_timer(TimerID id)
{
  _proxy_tsx->cancel_timer(id);
}

bool SproutletWrapper::timer_running(TimerID id)
{
  return _proxy_tsx->timer_running(id);
}

SAS::TrailId SproutletWrapper::trail() const
{
  return _trail_id;
}

void SproutletWrapper::rx_request(pjsip_tx_data* req)
{
  // Keep an immutable reference to the request.
  _req = req;

  // Clone the request to get a mutable copy to pass to the Sproutlet.
  pjsip_msg* clone = original_request();
  if (clone == NULL)
  {
    // @TODO
  }

  if (PJSIP_MSG_TO_HDR(clone)->tag.slen == 0)
  {
    LOG_VERBOSE("%s pass initial request %s to Sproutlet",
                _id.c_str(), msg_info(clone));
    _sproutlet->on_rx_initial_request(clone);
  }
  else
  {
    LOG_VERBOSE("%s pass in dialog request %s to Sproutlet",
                _id.c_str(), msg_info(clone));
    _sproutlet->on_rx_in_dialog_request(clone);
  }
  process_actions();
}

void SproutletWrapper::rx_response(pjsip_tx_data* rsp, int fork_id)
{
  register_tdata(rsp);
  if ((PJSIP_IS_STATUS_IN_CLASS(rsp->msg->line.status.code, 100)) &&
      (_forks[fork_id].state.tsx_state == PJSIP_TSX_STATE_CALLING))
  {
    // Provisional response on fork still in calling state, so move to
    // proceeding state.
    _forks[fork_id].state.tsx_state = PJSIP_TSX_STATE_PROCEEDING;
    LOG_VERBOSE("%s received provisional response %s on fork %d, state = %s",
                _id.c_str(), pjsip_tx_data_get_info(rsp),
                fork_id, pjsip_tsx_state_str(_forks[fork_id].state.tsx_state));
  }
  else if (rsp->msg->line.status.code >= PJSIP_SC_OK)
  {
    // Final response, so mark the fork as completed and decrement the number
    // of pending responses.
    _forks[fork_id].state.tsx_state = PJSIP_TSX_STATE_TERMINATED;
    pjsip_tx_data_dec_ref(_forks[fork_id].req);
    _forks[fork_id].req = NULL;
    LOG_VERBOSE("%s received final response %s on fork %d, state = %s",
                _id.c_str(), pjsip_tx_data_get_info(rsp),
                fork_id, pjsip_tsx_state_str(_forks[fork_id].state.tsx_state));
    --_pending_responses;
  }
  _sproutlet->on_rx_response(rsp->msg, fork_id);
  process_actions();
}

void SproutletWrapper::rx_cancel(pjsip_tx_data* cancel)
{
  LOG_VERBOSE("%s received CANCEL request", _id.c_str());
  _sproutlet->on_rx_cancel(PJSIP_SC_REQUEST_TERMINATED,
                           cancel->msg);
  pjsip_tx_data_dec_ref(cancel);
  cancel_pending_forks();
  process_actions();
}

void SproutletWrapper::rx_error(int status_code)
{
  LOG_VERBOSE("%s received error %d", _id.c_str(), status_code);
  _sproutlet->on_rx_cancel(status_code, NULL);
  cancel_pending_forks();

  // Consider the transaction to be complete as no final response should be
  // sent upstream.
  _complete = true;
  process_actions();
}

void SproutletWrapper::rx_fork_error(pjsip_event_id_e event, int fork_id)
{
  LOG_VERBOSE("%s received error %s on fork %d, state = %s",
              _id.c_str(), pjsip_event_str(event),
              fork_id, pjsip_tsx_state_str(_forks[fork_id].state.tsx_state));

  if (_forks[fork_id].state.tsx_state != PJSIP_TSX_STATE_TERMINATED)
  {
    // This fork has not already been terminated, so record the error in the
    // fork state.
    if (event == PJSIP_EVENT_TIMER)
    {
      _forks[fork_id].state.error_state = TIMEOUT;
    }
    else if (event == PJSIP_EVENT_TRANSPORT_ERROR)
    {
      _forks[fork_id].state.error_state = TRANSPORT_ERROR;
    }

    // Create a response for the error.
    int status_code = (event == PJSIP_EVENT_TIMER) ?
                             PJSIP_SC_REQUEST_TIMEOUT :
                             PJSIP_SC_SERVICE_UNAVAILABLE;
    pjsip_tx_data* rsp;
    pj_status_t status = PJUtils::create_response(stack_data.endpt,
                                                  _forks[fork_id].req,
                                                  status_code,
                                                  NULL,
                                                  &rsp);

    // This counts as a final response, so mark the fork as terminated and
    // decrement the number of pending responses.
    _forks[fork_id].state.tsx_state = PJSIP_TSX_STATE_TERMINATED;
    pjsip_tx_data_dec_ref(_forks[fork_id].req);
    _forks[fork_id].req = NULL;
    --_pending_responses;

    if (status == PJ_SUCCESS) 
    {
      // Pass the response to the application.
      register_tdata(rsp);
      _sproutlet->on_rx_response(rsp->msg, fork_id);
      process_actions();
    }
  }
}

void SproutletWrapper::on_timer_pop(void* context)
{
  LOG_DEBUG("Timer has popped");
  _sproutlet->on_timer_expiry(context);
  process_actions();
}

void SproutletWrapper::register_tdata(pjsip_tx_data* tdata)
{
  LOG_DEBUG("Adding message %p => txdata %p mapping",
            tdata->msg, tdata);
  _packets[tdata->msg] = tdata;
}

void SproutletWrapper::deregister_tdata(pjsip_tx_data* tdata)
{
  LOG_DEBUG("Removing message %p => txdata %p mapping",
            tdata->msg, tdata);
  _packets.erase(tdata->msg);
}

/// Process actions required by a Sproutlet
void SproutletWrapper::process_actions()
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
    while (!_send_requests.empty())
    {
      std::unordered_map<int, pjsip_tx_data*>::iterator i = _send_requests.begin();
      int fork_id = i->first;
      pjsip_tx_data* tdata = i->second;
      _send_requests.erase(i);

      LOG_DEBUG("Processing request %p, fork = %d", tdata, fork_id);

      if (_record_routed)
      {
        // The Sproutlet has requested that we Record-Route on this dialog, so
        // add a Record-Route header.
        _proxy_tsx->add_record_route(tdata, _service_name, _dialog_id);
      }

      tx_request(tdata, fork_id);
    }
  }

  for (size_t ii = 0; ii < _forks.size(); ++ii)
  {
    if (_forks[ii].pending_cancel)
    {
      LOG_VERBOSE("%s fork %d pending CANCEL, state = %s",
                  _id.c_str(), ii, pjsip_tsx_state_str(_forks[ii].state.tsx_state));

      if (_forks[ii].state.tsx_state == PJSIP_TSX_STATE_PROCEEDING)
      {
        // Fork has been marked as pending cancel and we have received a
        // provisional response, so can send the CANCEL.
        LOG_DEBUG("Send CANCEL for fork %d", ii);
        tx_cancel(ii);
      }
    }
  }

  if ((_complete) &&
      (_pending_responses == 0))
  {
    // Sproutlet has sent a final response and has no downstream forks
    // waiting a response, so should destroy itself.
    LOG_VERBOSE("%s suiciding", _id.c_str());
    delete this;
  }
}

void SproutletWrapper::aggregate_response(pjsip_tx_data* rsp)
{
  int status_code = rsp->msg->line.status.code;
  LOG_DEBUG("Aggregating response with status code %d", status_code);

  if (_complete)
  {
    // We've already sent a final response upstream (a 200 OK) so discard
    // this response.
    LOG_DEBUG("Discard stale response %s (%s)",
              pjsip_tx_data_get_info(rsp), rsp->obj_name);
    deregister_tdata(rsp);
    pjsip_tx_data_dec_ref(rsp);
    return;
  }

  if (status_code == 100)
  {
    // We will already have sent a locally generated 100 Trying response, so
    // don't forward this one.
    LOG_DEBUG("Discard 100/INVITE response (%s)", rsp->obj_name);
    deregister_tdata(rsp);
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
  else if (PJSIP_IS_STATUS_IN_CLASS(status_code, 200))
  {
    // 2xx response.
    LOG_DEBUG("Forward 2xx response");

    // Send this response immediately as a final response.
    if (_best_rsp != NULL)
    {
      LOG_DEBUG("Discard previous best response %s (%s)",
                pjsip_tx_data_get_info(_best_rsp), _best_rsp->obj_name);
      deregister_tdata(_best_rsp);
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
        LOG_DEBUG("Discard previous best response %s (%s)",
                  pjsip_tx_data_get_info(_best_rsp), _best_rsp->obj_name);
        deregister_tdata(_best_rsp);
        pjsip_tx_data_dec_ref(_best_rsp);
      }

      _best_rsp = rsp;
    }
    else
    {
      LOG_DEBUG("Discard response %s (%s) - we already have a better one",
                pjsip_tx_data_get_info(rsp), rsp->obj_name);
      deregister_tdata(rsp);
      pjsip_tx_data_dec_ref(rsp);
    }
  }
}

void SproutletWrapper::tx_request(pjsip_tx_data* req, int fork_id)
{
  LOG_DEBUG("%s transmitting request on fork %d", _id.c_str(), fork_id);
  --_pending_sends;

  if (req->msg->line.req.method.id != PJSIP_ACK_METHOD)
  {
    // Set the state of this fork to CALLING (strictly speaking this should
    // be TRYING for non-INVITE transaction, but we only need to track this
    // state for determining when we can legally send CANCEL requests so using
    // CALLING in all cases is fine).
    _forks[fork_id].state.tsx_state = PJSIP_TSX_STATE_CALLING;
    ++_pending_responses;

    // Store a reference to the request.
    LOG_DEBUG("%s store reference to non-ACK request %s on fork %d",
              _id.c_str(), pjsip_tx_data_get_info(req), fork_id);
    pjsip_tx_data_add_ref(req);
    _forks[fork_id].req = req;
  }
  else
  {
    // ACK request, so no response expected.
    _forks[fork_id].state.tsx_state = PJSIP_TSX_STATE_TERMINATED;

    // We can consider the processing of this Sproutlet to be complete now.
    _complete = true;
  }

  // Notify the sproutlet that the request is being sent downstream.
  _sproutlet->on_tx_request(req->msg, fork_id);

  // Forward the request downstream.
  deregister_tdata(req);
  _proxy_tsx->tx_request(this, fork_id, req);
}

void SproutletWrapper::tx_response(pjsip_tx_data* rsp)
{
  // Notify the sproutlet that the response is being sent upstream.
  _sproutlet->on_tx_response(rsp->msg);

  if (rsp->msg->line.status.code >= PJSIP_SC_OK)
  {
    _complete = true;
    cancel_pending_forks();
  }

  // Forward the response upstream.
  deregister_tdata(rsp);
  _proxy_tsx->tx_response(this, rsp);
}

void SproutletWrapper::tx_cancel(int fork_id)
{
  // Build a CANCEL request from the original request sent on this fork.
  pjsip_tx_data* cancel = PJUtils::create_cancel(stack_data.endpt,
                                                 _forks[fork_id].req,
                                                 _forks[fork_id].cancel_reason);
  _proxy_tsx->tx_cancel(this, fork_id, cancel);
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
int SproutletWrapper::compare_sip_sc(int sc1, int sc2)
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

/// Checks whether the specified URI is "owned" by this system.  The URI is
/// considered local if the domain is either equal to the base URI domain, or
/// the service name prepended to the base URI domain.
bool SproutletWrapper::is_uri_local(pjsip_uri* uri) const
{
  if (_proxy->is_uri_local(uri))
  {
    return true;
  }
  else if (PJSIP_URI_SCHEME_IS_SIP(uri))
  {
    pjsip_sip_uri* sip_uri = (pjsip_sip_uri*)uri;
    pj_str_t host = sip_uri->host;

    if (!_service_host.empty())
    {
      if (!pj_stricmp2(&host, _service_host.c_str()))
      {
        return true;
      }
    }
    else
    {
      char* sep = pj_strchr(&host, '.');
      if (sep != NULL)
      {
        host.slen = sep - host.ptr;
        if (!pj_stricmp2(&host, _service_name.c_str()))
        {
          // The first part of the domain is the service name, so check that
          // the rest of the URI is local.
          host.ptr = sep + 1;
          host.slen = sip_uri->host.slen - (sep + 1 - sip_uri->host.ptr);
          if (_proxy->is_host_local(&host))
          {
            return true;
          }
        }
      }
    }
  }

  return _proxy->is_uri_local(uri);
}


