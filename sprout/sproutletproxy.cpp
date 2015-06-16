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
#include <pjsip-simple/evsub.h>
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
                               const std::string& root_uri,
                               const std::unordered_set<std::string>& host_aliases,
                               const std::list<Sproutlet*>& sproutlets,
                               const std::set<std::string> stateless_proxies) :
  BasicProxy(endpt,
             "mod-sproutlet-controller",
             priority,
             false,
             stateless_proxies),
  _root_uri(NULL),
  _host_aliases(host_aliases),
  _sproutlets(sproutlets)
{
  /// Store the URI of this SproutletProxy - this is used for Record-Routing.
  LOG_DEBUG("Root Record-Route URI = %s", root_uri.c_str());
  _root_uri = (pjsip_sip_uri*)PJUtils::uri_from_string(root_uri, stack_data.pool, false);
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
Sproutlet* SproutletProxy::target_sproutlet(pjsip_msg* req,
                                            int port,
                                            std::string& alias)
{
  LOG_DEBUG("Find target Sproutlet for request");

  Sproutlet* sproutlet = NULL;
  std::string id;

  // Find and parse the top Route header.
  pjsip_route_hdr* route = (pjsip_route_hdr*)
                                  pjsip_msg_find_hdr(req, PJSIP_H_ROUTE, NULL);


  pjsip_sip_uri* uri = NULL;
  if (route == NULL)
  {
    // TODO: Once the registrar and subscription managers are Sproutlets, this should
    // consider the ReqURI regardess of the method.
    if ((pjsip_method_cmp(&req->line.req.method, &pjsip_register_method) != 0) &&
        (pjsip_method_cmp(&req->line.req.method, pjsip_get_subscribe_method()) != 0) &&
        (PJSIP_URI_SCHEME_IS_SIP(req->line.req.uri)))
    {
      uri = (pjsip_sip_uri*)req->line.req.uri;
    }
  }
  else
  {
    if (PJSIP_URI_SCHEME_IS_SIP(route->name_addr.uri))
    {
      uri = (pjsip_sip_uri*)route->name_addr.uri;
    }
  }

  if (uri != NULL)
  {
    LOG_DEBUG("Found next routable URI: %s",
              PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                     (pjsip_uri*)uri).c_str());

    for (std::list<Sproutlet*>::iterator it = _sproutlets.begin();
         it != _sproutlets.end();
         ++it)
    {
      if (does_uri_match_sproutlet((pjsip_uri*)uri, *it, alias))
      {
        sproutlet = *it;
        break;
      }
    }

    if ((port == 0) &&
        (PJSIP_URI_SCHEME_IS_SIP(uri)) &&
        (is_host_local(&((pjsip_sip_uri*)uri)->host)))
    {
      // No port was specified by the caller, and the URI is local, so use the URI port instead.
      port = uri->port;
    }
  }
  else
  {
    LOG_DEBUG("Next route for message cannot be a sproutlet");
  }

  if ((sproutlet == NULL) &&
      (port != 0))
  {
    // No service identifier in the Route URI, so check for a default service
    // for the port.  We can only do this if there is either no route header
    // or the URI in the Route header corresponds to our hostname.
    LOG_DEBUG("No Sproutlet found using service name or host");
    if ((route == NULL) ||
        (PJSIP_URI_SCHEME_IS_SIP(route->name_addr.uri) &&
         (is_host_local(&((pjsip_sip_uri*)route->name_addr.uri)->host))))
    {
      LOG_DEBUG("Find default service for port %d", port);
      for (std::list<Sproutlet*>::iterator it = _sproutlets.begin();
           it != _sproutlets.end();
           ++it)
      {
        if ((*it)->port() == port)
        {
          sproutlet = *it;
          alias = (*it)->service_name();
          break;
        }
      }
    }
  }

  return sproutlet;
}


bool SproutletProxy::does_uri_match_sproutlet(const pjsip_uri* uri,
                                              Sproutlet* sproutlet,
                                              std::string& alias)
{
  if (!PJSIP_URI_SCHEME_IS_SIP(uri))
  {
    // LCOV_EXCL_START
    LOG_DEBUG("Sproutlet's cannot match non-SIP URIs");
    return false;
    // LCOV_EXCL_STOP
  }

  // Now we know we have a SIP URI, cast to one.
  pjsip_sip_uri* sip_uri = (pjsip_sip_uri*)uri;
  bool match = false;

  // Extract the service name, this can appear in one of three places:
  //
  //  - Username
  //  - `services` parameter
  //  - First domain label
  //
  // In each case, the domain name (minus the prefix in the third case) also
  // has to be one of the registered local domains.
  std::string service_name;
  std::list<std::string> possible_service_names;
  std::string domain;

  // Check services parameter.
  pjsip_param* services_param = pjsip_param_find(&sip_uri->other_param,
                                                 &STR_SERVICE);
  if (services_param != NULL)
  {
    // Check the services param
    LOG_DEBUG("Found services param - %.*s",
              services_param->value.slen,
              services_param->value.ptr);
    pj_str_t service_str = services_param->value;

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

    service_name = PJUtils::pj_str_to_string(&service_str);

    if (is_host_local(&sip_uri->host))
    {
      possible_service_names.push_back(service_name);
    }
  }
  else
  {
    if (sip_uri->user.slen != 0)
    {
      // Use the username
      LOG_DEBUG("Found user - %.*s", sip_uri->user.slen, sip_uri->user.ptr);
      service_name = PJUtils::pj_str_to_string(&sip_uri->user);
      if (is_host_local(&sip_uri->host))
      {
        possible_service_names.push_back(service_name);
      }
    }

    // Now spilt the first label off the host and check if the rest is still a
    // local hostname.  This works for IP addresses since IPv4 addresses cannot
    // have only 3 octets and IPv6 addresses contain no periods.
    pj_str_t hostname = sip_uri->host;
    char* sep = pj_strchr(&hostname, '.');
    if (sep != NULL)
    {
      // Extract the possible service name
      service_name = std::string(hostname.ptr, sep - hostname.ptr);

      // Remove the service name part and the period from the hostname.
      hostname.slen -= (sep - hostname.ptr + 1);
      hostname.ptr = sep + 1;

      if (is_host_local(&hostname))
      {
        possible_service_names.push_back(service_name);
      }
    }
  }

  // Check if any of the possible service names from the URI match any of the
  // aliases for the sproutlet.
  for (std::list<std::string>::iterator it = possible_service_names.begin();
       (it != possible_service_names.end()) && (match != true);
       ++it)
  {
    if (*it == sproutlet->service_name())
    {
      alias = *it;
      match = true;
    }
    else
    {
      std::list<std::string> aliases = sproutlet->aliases();
      for (std::list<std::string>::const_iterator jt = aliases.begin();
           jt != aliases.end();
           ++jt)
      {
        if (*it == *jt)
        {
          alias = *it;
          match = true;
          break;
        }
      }
    }
  }

  return match;
}


pjsip_sip_uri* SproutletProxy::create_sproutlet_uri(pj_pool_t* pool,
                                                    Sproutlet* sproutlet) const
{
  LOG_DEBUG("Creating URI for %s", sproutlet->service_name().c_str());
  pjsip_sip_uri* uri = (pjsip_sip_uri*)pjsip_uri_clone(pool, _root_uri);
  uri->lr_param = 1;

  LOG_DEBUG("Add services parameter");
  pjsip_param* p = PJ_POOL_ALLOC_T(pool, pjsip_param);
  pj_strdup(pool, &p->name, &STR_SERVICE);
  pj_list_insert_before(&uri->other_param, p);
  std::string services = sproutlet->service_name();
  pj_strdup2(pool, &p->value, services.c_str());

  LOG_DEBUG(PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                   (pjsip_uri*)uri).c_str());

  return uri;
}


bool SproutletProxy::is_uri_local(const pjsip_uri* uri)
{
  if (PJSIP_URI_SCHEME_IS_SIP(uri))
  {
    pj_str_t hostname = ((pjsip_sip_uri*)uri)->host;
    if (is_host_local(&hostname))
    {
      return true;
    }

    // Maybe this is service.<domain> for a local domain.  Check now.
    char* sep = pj_strchr(&hostname, '.');
    hostname.slen -= sep - hostname.ptr + 1;
    hostname.ptr = sep + 1;

    return is_host_local(&hostname);
  }
  //LCOV_EXCL_START
  return false;
  //LCOV_EXCL_STOP
}


bool SproutletProxy::is_host_local(const pj_str_t* host)
{
  bool rc = false;

  if (!pj_stricmp(host, &_root_uri->host))
  {
    rc = true;
  }

  for (std::unordered_set<std::string>::iterator it = _host_aliases.begin();
       (rc != true) && (it != _host_aliases.end());
       ++it)
  {
    if (!pj_stricmp2(host, it->c_str()))
    {
      rc = true;
    }
  }

  return rc;
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
    std::string alias;
    Sproutlet* sproutlet =
                   target_sproutlet(_req->msg,
                                    rdata->tp_info.transport->local_name.port,
                                    alias);

    if (sproutlet == NULL)
    {
      // Failed to find a target Sproutlet for this request, so we need to
      // decide what to do.
      pjsip_route_hdr* route = (pjsip_route_hdr*)
                  pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_ROUTE, NULL);
      if (route != NULL)
      {
        // There is a top Route header in the request, which by definition
        // caused the request to be routed to this node, so remove it and
        // allow the request to be forwarded.
        LOG_INFO("Remove top Route header and forward request");
        pj_list_erase(route);
      }
      else
      {
        // There is no top Route header in the request, so forwarding it will
        // result in a loop.  There is no option other than to reject the
        // request.
        LOG_INFO("Reject request");
        status = PJ_ENOTSUP;
      }
    }

    if (status == PJ_SUCCESS)
    {
      _root = new SproutletWrapper(_sproutlet_proxy,
                                   this,
                                   sproutlet,
                                   alias,
                                   _req,
                                   trail());
    }
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

    LOG_VERBOSE("Notifying upstream sproutlet %s of client failure: %s",
           upstream_sproutlet->service_name().c_str(), pjsip_event_str(event));

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


Sproutlet* SproutletProxy::UASTsx::target_sproutlet(pjsip_msg* msg,
                                                    int port,
                                                    std::string& alias)
{
  return _sproutlet_proxy->target_sproutlet(msg, port, alias);
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

    // Reject the request if the Max-Forwards value has dropped to zero.
    pjsip_max_fwd_hdr* mf_hdr = (pjsip_max_fwd_hdr*)
                  pjsip_msg_find_hdr(req.req->msg, PJSIP_H_MAX_FORWARDS, NULL);
    if ((mf_hdr != NULL) &&
        (mf_hdr->ivalue <= 0))
    {
      // Max-Forwards has decayed to zero, so either reject the request or
      // discard it if it's an ACK.
      if (req.req->msg->line.req.method.id != PJSIP_ACK_METHOD)
      {
        LOG_INFO("Loop detected - rejecting request with 483 status code");
        pjsip_tx_data* rsp;
        pj_status_t status = PJUtils::create_response(stack_data.endpt,
                                                      req.req,
                                                      PJSIP_SC_TOO_MANY_HOPS,
                                                      NULL,
                                                      &rsp);
        if (status == PJ_SUCCESS)
        {
          // Pass the response back to the Sproutlet.
          req.upstream.first->rx_response(rsp, req.upstream.second);
        }
      }
      else
      {
        LOG_INFO("Loop detected - discarding ACK request");
      }
    }
    else
    {
      std::string alias;
      Sproutlet* sproutlet = target_sproutlet(req.req->msg, 0, alias);

      if (sproutlet != NULL)
      {
        // Found a local Sproutlet to handle the request, so create a
        // SproutletWrapper.
        SproutletWrapper* downstream = new SproutletWrapper(_sproutlet_proxy,
                                                            this,
                                                            sproutlet,
                                                            alias,
                                                            req.req,
                                                            trail());

        // Set up the mappings.
        if (req.req->msg->line.req.method.id != PJSIP_ACK_METHOD)
        {
          _dmap_sproutlet[req.upstream] = downstream;
          _umap[(void*)downstream] = req.upstream;
        }

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
        LOG_DEBUG("No local sproutlet matches request");
        
        // Check whether:
        // - there are no Route headers
        // - the Request-URI points to us
        // - no Sproutlet has changed the Request-URI during processing
        //
        // If all these things are true, then forwarding this on would cause a loop, so we should
        // drop it.
        pjsip_uri* original_uri = _req->msg->line.req.uri;
        pjsip_uri* next_hop = PJUtils::next_hop(req.req->msg);
        if (next_hop == req.req->msg->line.req.uri &&
            (PJUtils::is_uri_local(next_hop) ||
             PJUtils::is_home_domain(next_hop)) &&
            (PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI,
                                    original_uri) ==
             PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI,
                                    req.req->msg->line.req.uri)))
        {
          LOG_WARNING("No local sproutlet accepted request, the URI has not been changed, and the next route is local"
                      " - dropping message to avoid loops");
        }
        else
        {
          // Proxy the request.
          size_t index;

          pj_status_t status = allocate_uac(req.req, index);

          if (status == PJ_SUCCESS)
          {
            // Successfully set up UAC transaction, so set up the mappings and
            // send the request.
            if (req.req->msg->line.req.method.id != PJSIP_ACK_METHOD)
            {
              _dmap_uac[req.upstream] = _uac_tsx[index];
              _umap[(void*)_uac_tsx[index]] = req.upstream;
            }

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
  }

  // Check to see if we can destroy the UASTsx.
  check_destroy();
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

  // Check to see if the UASTsx can be destroyed.
  check_destroy();
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
      (_pending_req_q.empty()) &&
      (_tsx == NULL))
  {
    // UAS transaction has been destroyed and all Sproutlets are complete.
    LOG_DEBUG("Safe for UASTsx to suicide");
    _pending_destroy = true;
  }
}


//
// UASTsx::SproutletWrapper methods.
//

SproutletWrapper::SproutletWrapper(SproutletProxy* proxy,
                                   SproutletProxy::UASTsx* proxy_tsx,
                                   Sproutlet* sproutlet,
                                   const std::string& sproutlet_alias,
                                   pjsip_tx_data* req,
                                   SAS::TrailId trail_id) :
  _proxy(proxy),
  _proxy_tsx(proxy_tsx),
  _sproutlet(sproutlet),
  _sproutlet_tsx(NULL),
  _service_name(""),
  _id(""),
  _req(req),
  _packets(),
  _send_requests(),
  _send_responses(),
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
    _sproutlet_tsx = sproutlet->get_tsx(this, sproutlet_alias, req->msg);
    _service_name = sproutlet->service_name();
  }
  else
  {
    // No Sproutlet specified, so we'll use a default "no-op" Sproutlet.
    _service_name = "noop";
  }

  if (_sproutlet_tsx == NULL)
  {
    // The Sproutlet doesn't want to handle this request, so create a default
    // SproutletTsx to handle it.
    _sproutlet_tsx = new SproutletTsx(this);
  }

  // Construct a unique identifier for this Sproutlet.
  std::ostringstream id;
  id << _service_name << "-" << (const void*)_sproutlet_tsx;
  _id = id.str();
  LOG_VERBOSE("Created Sproutlet %s for %s",
              _id.c_str(), pjsip_tx_data_get_info(req));
}

SproutletWrapper::~SproutletWrapper()
{
  // Destroy the SproutletTsx.
  LOG_DEBUG("Destroying SproutletWrapper %p", this);
  if (_sproutlet_tsx != NULL)
  {
    delete _sproutlet_tsx;
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
    if ((_forks[ii].state.tsx_state != PJSIP_TSX_STATE_NULL) &&
        (_forks[ii].state.tsx_state != PJSIP_TSX_STATE_TERMINATED))
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

bool SproutletWrapper::is_uri_reflexive(const pjsip_uri* uri) const
{
  std::string alias;
  return _proxy->does_uri_match_sproutlet(uri, _sproutlet, alias);
}

bool SproutletWrapper::is_uri_local(const pjsip_uri* uri) const
{
  return _proxy->is_uri_local(uri);
}

pjsip_sip_uri* SproutletWrapper::get_reflexive_uri(pj_pool_t* pool) const
{
  return _proxy->create_sproutlet_uri(pool, _sproutlet);
}

void SproutletWrapper::rx_request(pjsip_tx_data* req)
{
  // Log the request at VERBOSE level before we send it out to aid in
  // tracking its path through the sproutlets.
  if (Log::enabled(Log::VERBOSE_LEVEL))
  {
    log_inter_sproutlet(req, true);
  }

  // Keep an immutable reference to the request.
  _req = req;

  // Decrement Max-Forwards if present.
  pjsip_max_fwd_hdr* mf_hdr = (pjsip_max_fwd_hdr*)
                      pjsip_msg_find_hdr(req->msg, PJSIP_H_MAX_FORWARDS, NULL);
  if (mf_hdr != NULL)
  {
    --mf_hdr->ivalue;
  }

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
    _sproutlet_tsx->on_rx_initial_request(clone);
  }
  else
  {
    LOG_VERBOSE("%s pass in dialog request %s to Sproutlet",
                _id.c_str(), msg_info(clone));
    _sproutlet_tsx->on_rx_in_dialog_request(clone);
  }

  // We consider an ACK transaction to be complete immediately after the
  // sproutlet's actions have been processed, regardless of whether the
  // sproutlet forwarded the ACK (some sproutlets are unable to in certain
  // situations).
  bool complete_after_actions = (req->msg->line.req.method.id == PJSIP_ACK_METHOD);
  process_actions(complete_after_actions);
}

void SproutletWrapper::rx_response(pjsip_tx_data* rsp, int fork_id)
{
  // Log the response at VERBOSE level before we send it out to aid in
  // tracking its path through the sproutlets.
  if (Log::enabled(Log::VERBOSE_LEVEL))
  {
    log_inter_sproutlet(rsp, false);
  }

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
  _sproutlet_tsx->on_rx_response(rsp->msg, fork_id);
  process_actions(false);
}

void SproutletWrapper::rx_cancel(pjsip_tx_data* cancel)
{
  LOG_VERBOSE("%s received CANCEL request", _id.c_str());
  _sproutlet_tsx->on_rx_cancel(PJSIP_SC_REQUEST_TERMINATED,
                           cancel->msg);
  pjsip_tx_data_dec_ref(cancel);
  cancel_pending_forks();
  process_actions(false);
}

void SproutletWrapper::rx_error(int status_code)
{
  LOG_VERBOSE("%s received error %d", _id.c_str(), status_code);
  _sproutlet_tsx->on_rx_cancel(status_code, NULL);
  cancel_pending_forks();

  // Consider the transaction to be complete as no final response should be
  // sent upstream.
  _complete = true;
  process_actions(false);
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
      _sproutlet_tsx->on_rx_response(rsp->msg, fork_id);
      process_actions(false);
    }
  }
}

void SproutletWrapper::on_timer_pop(void* context)
{
  LOG_DEBUG("Timer has popped");
  _sproutlet_tsx->on_timer_expiry(context);
  process_actions(false);
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
void SproutletWrapper::process_actions(bool complete_after_actions)
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

  // The Sproutlet transaction hasn't completed, so handle any requests
  // forwarded/generated by the Sproutlet.
  while (!_send_requests.empty())
  {
    std::unordered_map<int, pjsip_tx_data*>::iterator i = _send_requests.begin();
    int fork_id = i->first;
    pjsip_tx_data* tdata = i->second;
    _send_requests.erase(i);

    LOG_DEBUG("Processing request %p, fork = %d", tdata, fork_id);

    tx_request(tdata, fork_id);
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

  if (complete_after_actions)
  {
    _complete = true;
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
  }

  // Notify the sproutlet that the request is being sent downstream.
  _sproutlet_tsx->on_tx_request(req->msg, fork_id);

  // Forward the request downstream.
  deregister_tdata(req);
  _proxy_tsx->tx_request(this, fork_id, req);
}

void SproutletWrapper::tx_response(pjsip_tx_data* rsp)
{
  // Notify the sproutlet that the response is being sent upstream.
  _sproutlet_tsx->on_tx_response(rsp->msg);

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

void SproutletWrapper::log_inter_sproutlet(pjsip_tx_data* tdata,
                                           bool downstream)
{
  char buf[PJSIP_MAX_PKT_LEN];
  pj_ssize_t size;

  // Serialise the message in a separate buffer using the function
  // exposed by PJSIP.  In principle we could use tdata's own
  // serialisation buffer structure for this, but then we'd need to
  // explicitly invalidate it afterwards to avoid accidentally sending
  // the wrong data over SIP at some future point.  Safer to use a local
  // buffer.
  size = pjsip_msg_print(tdata->msg, buf, sizeof(buf));

  // Defensively set size to zero if pjsip_msg_print failed
  size = std::max(0L, size);

  LOG_VERBOSE("Routing %s (%d bytes) to %s sproutlet %s:\n"
              "--start msg--\n\n"
              "%.*s\n"
              "--end msg--",
              pjsip_tx_data_get_info(tdata),
              size,
              (downstream) ? "downstream" : "upstream",
              _service_name.c_str(),
              (int)size,
              buf);
}
