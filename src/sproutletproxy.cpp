/**
 * @file sproutletproxy.cpp  Sproutlet controlling proxy class implementation
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
#include <pjsip-simple/evsub.h>
}

#include <sstream>

#include "log.h"
#include "pjutils.h"
#include "sproutsasevent.h"
#include "sproutletproxy.h"
#include "snmp_sip_request_types.h"

const pj_str_t SproutletProxy::STR_SERVICE = {"service", 7};

const ForkState NULL_FORK_STATE = {PJSIP_TSX_STATE_NULL, NONE};

/// Constructor.
SproutletProxy::SproutletProxy(pjsip_endpoint* endpt,
                               int priority,
                               const std::string& root_uri,
                               const std::unordered_set<std::string>& host_aliases,
                               const std::list<Sproutlet*>& sproutlets,
                               const std::set<std::string>& stateless_proxies,
                               int max_sproutlet_depth) :
  BasicProxy(endpt,
             "mod-sproutlet-controller",
             priority,
             false,
             stateless_proxies),
  _root_uri(NULL),
  _host_aliases(host_aliases),
  _sproutlets(sproutlets),
  _max_sproutlet_depth(max_sproutlet_depth)
{
  /// Store the URI of this SproutletProxy - this is used for Record-Routing.
  TRC_DEBUG("Root Record-Route URI = %s", root_uri.c_str());
  _root_uri = (pjsip_sip_uri*)PJUtils::uri_from_string("sip:" + root_uri + ";transport=tcp",
                                                       stack_data.pool,
                                                       false);

  for (std::list<Sproutlet*>::iterator it = _sproutlets.begin();
       it != _sproutlets.end();
       ++it)
  {
    pjsip_sip_uri* root_uri = (pjsip_sip_uri*)PJUtils::uri_from_string(
                                                       (*it)->uri_as_str(),
                                                       stack_data.pool,
                                                       false);
    if (root_uri != nullptr)
    {
      _root_uris.insert(std::make_pair((*it)->service_name(), root_uri));
    }

    register_sproutlet(*it);
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

// Registers sproutlet and returns whether this was successful or not.
bool SproutletProxy::register_sproutlet(Sproutlet* sproutlet)
{
  bool ok = true;
  std::string service_name = sproutlet->service_name();

  // Add the service name and any aliases into a map of
  // service names to sproutlets.
  std::map<std::string, Sproutlet*>::const_iterator i;
  i = _services.find(service_name);
  if (i != _services.end())
  {
    std::string sproutlet_name = i->second->service_name();
    TRC_ERROR("Can't assign service name \"%s\" to sproutlet \"%s\" because it is taken by sproutlet \"%s\"",
              service_name.c_str(),
              service_name.c_str(),
              sproutlet_name.c_str());
    ok = false;
  }
  else
  {
    _services.insert(std::make_pair(sproutlet->service_name(), sproutlet));
  }

  std::list<std::string> aliases = sproutlet->aliases();
  for (std::list<std::string>::const_iterator j = aliases.begin();
       j != aliases.end();
       ++j)
  {
    std::map<std::string, Sproutlet*>::const_iterator k;
    k = _services.find(*j);
    if (k != _services.end())
    {
      std::string alias = *j;
      std::string sproutlet_name = k->second->service_name();
      TRC_ERROR("Can't assign alias \"%s\" to sproutlet \"%s\" because it is taken by sproutlet \"%s\"",
                alias.c_str(),
                service_name.c_str(),
                sproutlet_name.c_str());
      ok = false;
    }
    else
    {
      _services.insert(std::make_pair(*j, sproutlet));
    }
  }

  // If the sproutlet owns a port, add that to the map of ports to
  // sproutlets.
  int port = sproutlet->port();
  if (port != 0)
  {
    std::map<int, Sproutlet*>::const_iterator i;
    i = _ports.find(port);
    if (i != _ports.end())
    {
      std::string sproutlet_name = i->second->service_name();
      TRC_ERROR("Can't assign port %d to sproutlet \"%s\" because it is taken by sproutlet \"%s\"",
                port,
                service_name.c_str(),
                sproutlet_name.c_str());
      ok = false;
    }
    else
    {
      _ports.insert(std::make_pair(port, sproutlet));
    }
  }

  return ok;
}


/// Utility method to find the appropriate Sproutlet to handle a request.
Sproutlet* SproutletProxy::target_sproutlet(pjsip_msg* req,
                                            int port,
                                            std::string& alias,
                                            SAS::TrailId trail)
{
  TRC_DEBUG("Find target Sproutlet for request");

  Sproutlet* sproutlet = NULL;
  std::string id;

  // Find and parse the top Route header.
  pjsip_route_hdr* route = (pjsip_route_hdr*)
                                  pjsip_msg_find_hdr(req, PJSIP_H_ROUTE, NULL);


  pjsip_sip_uri* uri = NULL;
  if (route == NULL)
  {
    if (PJSIP_URI_SCHEME_IS_SIP(req->line.req.uri))
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
    std::string uri_str = PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                                 (pjsip_uri*)uri);
    SAS::Event event(trail, SASEvent::STARTING_SPROUTLET_SELECTION_URI, 0);
    event.add_var_param(uri_str);
    SAS::report_event(event);

    TRC_DEBUG("Found next routable URI: %s", uri_str.c_str());

    std::string local_hostname_unused;
    SPROUTLET_SELECTION_TYPES selection_type = NONE_SELECTED;
    sproutlet = match_sproutlet_from_uri((pjsip_uri*)uri,
                                         alias,
                                         local_hostname_unused,
                                         selection_type);

    if (selection_type != NONE_SELECTED)
    {
      SAS::Event event(trail, SASEvent::SPROUTLET_SELECTION_URI, 0);
      event.add_static_param(selection_type);
      event.add_var_param(sproutlet->service_name());
      event.add_var_param(alias);
      event.add_var_param(uri_str);
      SAS::report_event(event);
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
    TRC_DEBUG("Can't match a sproutlet based on the URI");
  }

  if ((sproutlet == NULL) &&
      (port != 0))
  {
    // No service identifier in the Route URI, so check if a sproutlet has
    // registered for the port. We can only do this if there is either no route
    // header or the URI in the Route header corresponds to our hostname.
    TRC_DEBUG("No Sproutlet found using service name or host");

    if ((route == NULL) ||
        ((PJSIP_URI_SCHEME_IS_SIP(route->name_addr.uri)) &&
         (is_host_local(&((pjsip_sip_uri*)route->name_addr.uri)->host))))
    {
      TRC_DEBUG("Find default service for port %d", port);
      SAS::Event event(trail, SASEvent::STARTING_SPROUTLET_SELECTION_PORT, 0);
      event.add_static_param(port);
      SAS::report_event(event);

      std::map<int, Sproutlet*>::const_iterator it = _ports.find(port);
      if (it != _ports.end())
      {
        sproutlet = it->second;
        alias = sproutlet->service_name();
        std::string uri_str = PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR, (pjsip_uri*)uri);
        SAS::Event event(trail, SASEvent::SPROUTLET_SELECTION_PORT, 0);
        event.add_var_param(alias);
        event.add_static_param(port);
        event.add_var_param(uri_str);
        SAS::report_event(event);
      }
    }
  }

  if (sproutlet == NULL)
  {
    SAS::Event event(trail, SASEvent::NO_SPROUTLET_SELECTED, 0);
    SAS::report_event(event);
  }

  return sproutlet;
}


Sproutlet* SproutletProxy::match_sproutlet_from_uri(const pjsip_uri* uri,
                                                    std::string& alias,
                                                    std::string& local_hostname,
                                                    SPROUTLET_SELECTION_TYPES& selection_type) const
{
  Sproutlet* sproutlet = NULL;

  if (!PJSIP_URI_SCHEME_IS_SIP(uri))
  {
    // LCOV_EXCL_START
    TRC_DEBUG("Sproutlets cannot match non-SIP URIs");
    return nullptr;
    // LCOV_EXCL_STOP
  }

  // Now we know we have a SIP URI, cast to one.
  pjsip_sip_uri* sip_uri = (pjsip_sip_uri*)uri;

  std::string service_name;
  std::map<std::string, Sproutlet*>::const_iterator it;

  // First check if there is a services parameter, and if it matches a
  // sproutlet.
  pjsip_param* services_param = pjsip_param_find(&sip_uri->other_param,
                                                 &STR_SERVICE);
  if (services_param != NULL)
  {
    TRC_DEBUG("Found services param - %.*s",
              services_param->value.slen,
              services_param->value.ptr);

    if (is_host_local(&sip_uri->host))
    {
      // Check if this service matches a sproutlet.
      service_name = PJUtils::pj_str_to_string(&services_param->value);
      it = _services.find(service_name);
      if (it != _services.end())
      {
        sproutlet = it->second;
        alias = service_name;
        local_hostname = PJUtils::pj_str_to_string(&sip_uri->host);
        selection_type = SERVICE_NAME;
      }
    }
  }

  // If we haven't found a sproutlet yet, check if the first part of the
  // hostname matches a sproutlet. For example, "scscf.sprout.example.com"
  // should match the "scscf" sproutlet. Split the first label off the host
  // and check if the rest is still a local hostname. This works for IP
  // addresses since IPv4 addresses cannot have only 3 octets and IPv6
  // addresses contain no periods.
  if (sproutlet == NULL)
  {
    pj_str_t hostname = sip_uri->host;
    char* sep = pj_strchr(&hostname, '.');

    if (sep != NULL)
    {
      // Extract the possible service name
      service_name = std::string(hostname.ptr, sep - hostname.ptr);

      // Remove the service name part and the period from the hostname.
      hostname.slen -= (sep - hostname.ptr + 1);
      hostname.ptr = sep + 1;

      TRC_DEBUG("Possible service name %s will be used if %.*s is a local hostname",
                service_name.c_str(),
                hostname.slen,
                hostname.ptr);

      if (is_host_local(&hostname))
      {
        // Check if the part of the hostname before the first '.' matches
        // a sproutlet.
        it = _services.find(service_name);
        if (it != _services.end())
        {
          sproutlet = it->second;
          alias = service_name;
          local_hostname = PJUtils::pj_str_to_string(&hostname);
          selection_type = DOMAIN_PART;
        }
      }
    }
  }

  // If we haven't found a sproutlet yet, check if the user part of the URI
  // matches a sproutlet.
  if ((sproutlet == NULL) &&
      (sip_uri->user.slen != 0))
  {
    TRC_DEBUG("Found user part - %.*s", sip_uri->user.slen, sip_uri->user.ptr);

    if (is_host_local(&sip_uri->host))
    {
      // Check if the user part matches a sproutlet.
      service_name = PJUtils::pj_str_to_string(&sip_uri->user);
      it = _services.find(service_name);
      if (it != _services.end())
      {
        sproutlet = it->second;
        alias = service_name;
        local_hostname = PJUtils::pj_str_to_string(&sip_uri->host);
        selection_type = USER_PART;
      }
    }
  }

  return sproutlet;
}


pjsip_sip_uri* SproutletProxy::next_hop_uri(const std::string& service,
                                            const pjsip_sip_uri* base_uri,
                                            pj_pool_t* pool) const
{
  pjsip_sip_uri* next_hop = create_internal_sproutlet_uri(pool,
                                                          service,
                                                          base_uri);
  return next_hop;
}


pjsip_sip_uri* SproutletProxy::create_sproutlet_uri(pj_pool_t* pool,
                                                    Sproutlet* sproutlet) const
{
  TRC_DEBUG("Creating URI for %s", sproutlet->service_name().c_str());
  pjsip_sip_uri* uri = nullptr;

  std::map<std::string, pjsip_sip_uri*>::const_iterator it =
    _root_uris.find(sproutlet->service_name());

  if (it != _root_uris.end())
  {
    TRC_DEBUG("Found root URI");
    uri = (pjsip_sip_uri*)pjsip_uri_clone(pool, it->second);
    uri->lr_param = 1;

    TRC_DEBUG("Constructed URI %s",
              PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR, (pjsip_uri*)uri).c_str());
  }
  else
  {
    // LCOV_EXCL_START
    TRC_WARNING("No root URI found - unable to construct URI");
    // LCOV_EXCL_STOP
  }

  return uri;
}

pjsip_sip_uri* SproutletProxy::create_internal_sproutlet_uri(pj_pool_t* pool,
                                                             const std::string& name,
                                                             const pjsip_sip_uri* existing_uri) const
{
  TRC_DEBUG("Creating URI for service %s", name.c_str());

  const pjsip_sip_uri* base_uri = ((existing_uri != nullptr) ? existing_uri : _root_uri);
  pjsip_sip_uri* uri = (pjsip_sip_uri*)pjsip_uri_clone(pool, base_uri);

  // Replace the hostname part of the base URI with the local hostname part of
  // the URI that routed to us. If this doesn't work, then fall back to using
  // the root URI.
  std::string local_hostname = get_local_hostname(uri);
  pj_strdup2(pool, &uri->host, local_hostname.c_str());

  uri->port = 0;
  uri->lr_param = 1;

  pjsip_param* p = pjsip_param_find(&uri->other_param, &STR_SERVICE);

  if (p == nullptr)
  {
    p = PJ_POOL_ALLOC_T(pool, pjsip_param);
    pj_strdup(pool, &p->name, &STR_SERVICE);
    pj_list_insert_before(&uri->other_param, p);
  }

  pj_strdup2(pool, &p->value, name.c_str());

  TRC_DEBUG("Constructed URI %s",
              PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR, (pjsip_uri*)uri).c_str());

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
    if (sep != NULL)
    {
      hostname.slen -= sep - hostname.ptr + 1;
      hostname.ptr = sep + 1;

      return is_host_local(&hostname);
    }
  }
  //LCOV_EXCL_START
  return false;
  //LCOV_EXCL_STOP
}

pjsip_sip_uri* SproutletProxy::get_routing_uri(const pjsip_msg* req,
                                               const Sproutlet* sproutlet) const
{
  // Get the URI that caused us to be routed to this Sproutlet or if no such
  // URI exists e.g. if the Sproutlet was matched on a port, return NULL.
  const pjsip_route_hdr* route = (pjsip_route_hdr*)
                                    pjsip_msg_find_hdr(req, PJSIP_H_ROUTE, NULL);
  pjsip_sip_uri* routing_uri = NULL;
  if (route != NULL)
  {
    if ((PJSIP_URI_SCHEME_IS_SIP(route->name_addr.uri)) &&
        (is_uri_reflexive(route->name_addr.uri, sproutlet)))
    {
      routing_uri = (pjsip_sip_uri*)route->name_addr.uri;
    }
  }
  else
  {
    if ((PJSIP_URI_SCHEME_IS_SIP(req->line.req.uri)) &&
        (is_uri_reflexive(req->line.req.uri, sproutlet)))
    {
      routing_uri = (pjsip_sip_uri*)req->line.req.uri;
    }
  }

  return routing_uri;
}

std::string SproutletProxy::get_local_hostname(const pjsip_sip_uri* uri) const
{
  std::string unused_alias, local_hostname;
  SPROUTLET_SELECTION_TYPES unused_selection_type = NONE_SELECTED;
  (void*)match_sproutlet_from_uri((pjsip_uri*)uri,
                                  unused_alias,
                                  local_hostname,
                                  unused_selection_type);

  if (local_hostname.empty())
  {
    // We assume that the URI passed to this function will route back to a
    // Sproutlet, so if we have not found a Sproutlet, default the local
    // hostname to the hostname part of the URI's host.
    local_hostname = PJUtils::pj_str_to_string(&uri->host);
  }

  return local_hostname;
}

bool SproutletProxy::is_host_local(const pj_str_t* host) const
{
  bool rc = false;

  if (!pj_stricmp(host, &_root_uri->host))
  {
    rc = true;
  }

  for (std::unordered_set<std::string>::const_iterator it = _host_aliases.begin();
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

bool SproutletProxy::is_uri_reflexive(const pjsip_uri* uri,
                                      const Sproutlet* sproutlet) const
{
  std::string alias_unused;
  std::string local_hostname_unused;
  SPROUTLET_SELECTION_TYPES selection_type_unused = NONE_SELECTED;
  Sproutlet* matched_sproutlet = match_sproutlet_from_uri(uri,
                                                          alias_unused,
                                                          local_hostname_unused,
                                                          selection_type_unused);

  return (sproutlet == matched_sproutlet);
}

bool SproutletProxy::schedule_timer(pj_timer_entry* tentry, int duration)
{
  pj_time_val tval;
  tval.sec = duration / 1000;
  tval.msec = duration % 1000;

  pj_status_t rc = pjsip_endpt_schedule_timer(_endpt, tentry, &tval);

  TRC_DEBUG("Started Sproutlet timer, id = %ld, duration = %d.%.3d",
            (TimerID)tentry, tval.sec, tval.msec);
  return (rc == 0);
}


bool SproutletProxy::cancel_timer(pj_timer_entry* tentry)
{
  pj_timer_heap_t* timer_heap = pjsip_endpt_get_timer_heap(_endpt);
  if (pj_timer_heap_cancel(timer_heap, tentry) > 0)
  {
    TRC_DEBUG("Cancelled Sproutlet timer, id = %ld", (TimerID)tentry);
    return true;
  }
  else
  {
    TRC_DEBUG("Unable to cancel Sproutlet timer, id = %ld "
              "(already popped or cancelled?)", (TimerID)tentry);
    return false;
  }
}


bool SproutletProxy::timer_running(pj_timer_entry* tentry)
{
  return pj_timer_entry_running(tentry);
}


std::atomic_int SproutletProxy::UASTsx::_num_instances(0);

SproutletProxy::UASTsx::TimerCallback::TimerCallback(pj_timer_entry* timer) :
  _timer_entry(timer)
{
}

void SproutletProxy::UASTsx::TimerCallback::run()
{
  ((TimerCallbackData*)_timer_entry->user_data)->uas_tsx->process_timer_pop(_timer_entry);
}

SproutletProxy::UASTsx::Callback::Callback(UASTsx* tsx, std::function<void()> run_fn) :
  _tsx(tsx),
  _run_fn(run_fn)
{
  // Whenever we create a Callback we expect it to be run, so increase the count
  // of _pending_callbacks on the UASTsx
  _tsx->_pending_callbacks++;
}

void SproutletProxy::UASTsx::Callback::run()
{
  _tsx->enter_context();

  // Now that we are running a Callback, we can decrement the count of pending
  // callbacks
  _tsx->_pending_callbacks--;

  // _run_fn() contains that actual work that we need to do for this Callback
  _run_fn();

  _tsx->exit_context();
}


SproutletProxy::UASTsx::UASTsx(SproutletProxy* proxy) :
  BasicProxy::UASTsx(proxy),
  _root(NULL),
  _dmap_sproutlet(),
  _dmap_uac(),
  _umap(),
  _pending_req_q(),
  _sproutlet_proxy(proxy),
  _timers(),
  _pending_timers()
{
  int instances = ++_num_instances;
  TRC_DEBUG("Sproutlet Proxy transaction (%p) created. There are now %d instances",
            this, instances);
}


SproutletProxy::UASTsx::~UASTsx()
{
  for (std::set<pj_timer_entry*>::const_iterator timer = _timers.begin();
       timer != _timers.end();
       ++timer)
  {
    TimerCallbackData* tdata = (TimerCallbackData*)(*timer)->user_data;
    delete tdata;
    delete *timer;
  }
  _timers.clear();

  if (_trail != 0)
  {
    // Flush the trail so it appears promptly in SAS. Note that we also log an
    // end marker when the transaction moves into completed state, which also
    // flushes the trail (see on_tsx_complete). We need to log a flush marker
    // here as well, because ACKs to successful responses are handled
    // statelessly without a PJSIP transaction, which means that on_tsx_complete
    // is never called.
    //
    // For non-ACK transactions, there isn't any harm in logging an extra flush
    // marker after the end marker.
    SAS::Marker flush(_trail, MARKED_ID_FLUSH);
    SAS::report_marker(flush);
  }

  int instances = --_num_instances;
  TRC_DEBUG("Sproutlet Proxy transaction (%p) destroyed. There are now %d instances",
            this, instances);
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
    Sproutlet* sproutlet = NULL;
    pjsip_route_hdr* route = (pjsip_route_hdr*)
                pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_ROUTE, NULL);
    SproutletTsx* sproutlet_tsx = get_sproutlet_tsx(_req,
                                                    rdata->tp_info.transport->local_name.port,
                                                    alias);

    if (sproutlet_tsx == NULL)
    {
      // Failed to find a target Sproutlet for this request, so we need to
      // decide what to do.
      if (route == NULL)
      {
        // There is no top Route header in the request, so forwarding it will
        // result in a loop.  There is no option other than to reject the
        // request.
        TRC_INFO("Reject request");
        status = PJ_ENOTSUP;
      }
    }
    else
    {
      // We have a SproutletTsx, so get the sproutlet that relates to it.
      sproutlet = sproutlet_tsx->_sproutlet;
    }

    if (status == PJ_SUCCESS)
    {
      _root = new SproutletWrapper(_sproutlet_proxy,
                                   this,
                                   sproutlet,
                                   sproutlet_tsx,
                                   alias,
                                   _req,
                                   _original_transport,
                                   SproutletWrapper::EXTERNAL_NETWORK_FUNCTION,
                                   _sproutlet_proxy->_max_sproutlet_depth,
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
void SproutletProxy::UASTsx::process_cancel_request(pjsip_rx_data* rdata,
                                                    const std::string& reason)
{
  // We may receive a CANCEL after sending a final response, so check that
  // the root Sproutlet is still connected.
  if (_root != NULL)
  {
    // We might have modified the original request that was received, so we
    // should create the CANCEL from that.
    pjsip_tx_data* cancel = PJUtils::create_cancel(stack_data.endpt,
                                                   _req,
                                                   0);
    _root->rx_cancel(cancel, reason);

    // Schedule any requests generated by the Sproutlet.
    schedule_requests();
  }
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
    TRC_DEBUG("Discard response %s (%s)", pjsip_tx_data_get_info(rsp), rsp->obj_name);
    pjsip_tx_data_dec_ref(rsp);
    //LCOV_EXCL_STOP
  }

  exit_context();
}


/// Handles a response to an associated UACTsx.
void SproutletProxy::UASTsx::on_client_not_responding(UACTsx* uac_tsx,
                                                      ForkErrorState fork_error,
                                                      const std::string& reason)
{
  enter_context();

  TRC_DEBUG("%s - client transaction not responding (%s)",
            uac_tsx->name(),
            reason.c_str());

  SAS::Event client_not_responding(trail(), SASEvent::UAC_TSX_FAILED_NO_RESPONSE, 1);
  client_not_responding.add_var_param(reason);
  SAS::report_event(client_not_responding);

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
    // We do this here (before we create and run the Callback) while we've got
    // the lock to avoid races.
    _dmap_uac.erase(i->second);
    _umap.erase(i);


    // We must ensure that the upstream Sproutlet handles this on a worker
    // thread, so we create a Callback which we'll place on the worker thread
    // queue if we're not on a worker thread already
    Callback* cb = new Callback(this, [this, upstream_sproutlet, fork_error, upstream_fork]() -> void
    {
      TRC_VERBOSE("Notifying upstream sproutlet %s of client failure: %s",
                   upstream_sproutlet->service_name().c_str(),
                   fork_error_to_str(fork_error));
      upstream_sproutlet->rx_fork_error(fork_error, upstream_fork);

      // Schedule any requests generated by the Sproutlet.
      this->schedule_requests();
    });

    // If we're already on a worker thread, the Callback is just run directly
    PJUtils::run_callback_on_worker_thread(cb);
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
    TRC_DEBUG("Pass error to Sproutlet %p", _root);
    _root->rx_error(PJSIP_SC_REQUEST_TIMEOUT, pjsip_event_str(event->body.tsx_state.type));

    // Schedule any requests generated by the Sproutlet.
    schedule_requests();

    // The root Sproutlet may suicide at any time now, so don't send anything
    // else to it.
    _root = NULL;
  }

  if (_tsx->state == PJSIP_TSX_STATE_DESTROYED)
  {
    TRC_DEBUG("%s - UAS tsx destroyed", _tsx->obj_name);
    unbind_from_pjsip_tsx();

    // Check to see if we can destroy the UASTsx.
    check_destroy();
  }

  exit_context();
}

void SproutletProxy::UASTsx::tx_request(SproutletWrapper* upstream,
                                        int fork_id,
                                        SproutletProxy::SendRequest req)
{
  // Add the request to the back of the pending request queue.
  PendingRequest pr;
  pr.req = req.tx_data;
  pr.upstream = std::make_pair(upstream, fork_id);
  pr.allowed_host_state = req.allowed_host_state;
  pr.sproutlet_depth = upstream->get_depth() - 1;
  pr.upstream_network_func = upstream->get_network_function();
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
    bool loop_detected = false;

    if ((mf_hdr != NULL) && (mf_hdr->ivalue <= 0))
    {
      // Max-Forwards has decayed to zero - we've detected a loop.
      TRC_DEBUG("Max-Forwards too low");
      loop_detected = true;
    }
    else if (req.sproutlet_depth <= 0)
    {
      // Maximum recursion depth for Sproutlets reached - it's a loop.
      TRC_ERROR("Exceeded maximum Sproutlet tree depth");
      loop_detected = true;
    }

    if (loop_detected)
    {
      // We've detected a loop, so either reject the request or discard it if
      // it's an ACK.
      if (req.req->msg->line.req.method.id != PJSIP_ACK_METHOD)
      {
        TRC_INFO("Loop detected - rejecting request with 483 status code");
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
        TRC_INFO("Loop detected - discarding ACK request");
      }
    }
    else
    {
      std::string alias;
      SproutletTsx* sproutlet_tsx = get_sproutlet_tsx(req.req, 0, alias);

      if (sproutlet_tsx != NULL)
      {
        // Found a local Sproutlet and SproutletTsx to handle the request, so
        // create a SproutletWrapper. Since the Tsx is non-NULL, there is
        // guaranteed to be a sproutlet to handle the request.
        SproutletWrapper* downstream = new SproutletWrapper(_sproutlet_proxy,
                                                            this,
                                                            sproutlet_tsx->_sproutlet,
                                                            sproutlet_tsx,
                                                            alias,
                                                            req.req,
                                                            _original_transport,
                                                            req.upstream_network_func,
                                                            req.sproutlet_depth,
                                                            trail());

        // Set up the mappings.
        if (req.req->msg->line.req.method.id != PJSIP_ACK_METHOD)
        {
          _dmap_sproutlet[req.upstream] = downstream;
          _umap[(void*)downstream] = req.upstream;
        }

        if (downstream->is_network_func_boundary() &&
            (req.req->msg->line.req.method.id == PJSIP_INVITE_METHOD))
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
        downstream->rx_request(req.req, req.allowed_host_state);
      }
      else
      {
        // No local Sproutlet, proxy the request.
        TRC_DEBUG("No local sproutlet matches request");
        size_t index;

        pj_status_t status = allocate_uac(req.req, index, req.allowed_host_state);

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

  // Check to see if we can destroy the UASTsx.
  check_destroy();
}

bool SproutletProxy::UASTsx::schedule_timer(SproutletWrapper* tsx,
                                            void* context,
                                            TimerID& id,
                                            int duration)
{
  TimerCallbackData* tdata = new TimerCallbackData;
  tdata->uas_tsx = this;
  tdata->sproutlet_wrapper = tsx;
  tdata->context = context;

  pj_timer_entry* tentry = new pj_timer_entry();
  pj_timer_entry_init(tentry, 0, tdata, &SproutletProxy::UASTsx::on_timer_pop);

  _timers.insert(tentry);

  id = (TimerID)tentry;

  bool scheduled = _sproutlet_proxy->schedule_timer(tentry, duration);
  if (scheduled)
  {
    _pending_timers.insert(tentry);
  }
  return scheduled;
}

bool SproutletProxy::UASTsx::cancel_timer(TimerID id)
{
  pj_timer_entry* tentry = (pj_timer_entry*)id;
  bool cancelled = _sproutlet_proxy->cancel_timer(tentry);
  if (cancelled)
  {
    _pending_timers.erase(tentry);
  }
  return cancelled;
}


bool SproutletProxy::UASTsx::timer_running(TimerID id)
{
  pj_timer_entry* tentry = (pj_timer_entry*)id;
  return _sproutlet_proxy->timer_running(tentry);
}


void SproutletProxy::UASTsx::on_timer_pop(pj_timer_heap_t* th,
                                          pj_timer_entry* tentry)
{

  TimerCallback* callback = new TimerCallback(tentry);

  // Timer pops happen on the main pjsip transport thread, but we want to handle
  // them on a worker thread.
  // We relinquish ownership of the TimerCallback
  PJUtils::run_callback_on_worker_thread(callback);
}


void SproutletProxy::UASTsx::process_timer_pop(pj_timer_entry* tentry)
{
  enter_context();

  if (_pending_timers.erase(tentry) != 0)
  {
    TimerCallbackData* tdata = (TimerCallbackData*)tentry->user_data;
    tdata->sproutlet_wrapper->on_timer_pop((TimerID)tentry, tdata->context);
    schedule_requests();
  }

  exit_context();
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
      pj_status_t status = pjsip_tsx_send_msg(_tsx, rsp);

      if (status != PJ_SUCCESS)
      {
        TRC_INFO("Failed to send UASTsx message: %s",
                 PJUtils::pj_status_to_string(status).c_str());
        // pjsip_tsx_send_msg only decreases the ref count on success
        pjsip_tx_data_dec_ref(rsp);
      }

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
        TRC_DEBUG("%s - Terminate UAS INVITE transaction", _tsx->obj_name);
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
      upstream->rx_response(rsp, fork_id, downstream->get_error_state());
    }
    else
    {
      // Failed to find the upstream Sproutlet, so discard the response.
      //LCOV_EXCL_START
      TRC_DEBUG("Discard response %s (%s)", pjsip_tx_data_get_info(rsp), rsp->obj_name);
      pjsip_tx_data_dec_ref(rsp);
      //LCOV_EXCL_STOP
    }
  }

  // Check to see if the UASTsx can be destroyed.
  check_destroy();
}


void SproutletProxy::UASTsx::tx_cancel(SproutletWrapper* upstream,
                                       int fork_id,
                                       pjsip_tx_data* cancel,
                                       int st_code,
                                       const std::string& reason)
{
  TRC_DEBUG("Process CANCEL from %s on fork %d",
            upstream->service_name().c_str(), fork_id);
  DMap<SproutletWrapper*>::iterator i =
                       _dmap_sproutlet.find(std::make_pair(upstream, fork_id));

  if (i != _dmap_sproutlet.end())
  {
    // Pass the CANCEL request to the downstream Sproutlet.
    SproutletWrapper* downstream = i->second;
    TRC_DEBUG("Route CANCEL to %s", downstream->service_name().c_str());
    downstream->rx_cancel(cancel, reason);
  }
  else
  {
    DMap<UACTsx*>::iterator j = _dmap_uac.find(std::make_pair(upstream, fork_id));
    if (j != _dmap_uac.end())
    {
      // CANCEL the downstream UAC transaction.
      TRC_DEBUG("Route CANCEL to downstream UAC transaction");
      UACTsx* uac_tsx = j->second;
      uac_tsx->cancel_pending_tsx(st_code, reason);
    }

    // Free the CANCEL request.
    TRC_DEBUG("Free CANCEL request (%s)", cancel->obj_name);
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
      (_pending_timers.empty()) &&
      (_tsx == NULL) &&
      (_pending_callbacks == 0))
  {
    // UAS transaction has been destroyed and all Sproutlets are complete.
    TRC_DEBUG("Safe for UASTsx to suicide");
    _pending_destroy = true;
  }
}

SproutletTsx* SproutletProxy::UASTsx::get_sproutlet_tsx(pjsip_tx_data* req,
                                                        int port,
                                                        std::string& alias)
{
  SproutletTsx* sproutlet_tsx = NULL;

  // Do an initial lookup for the target sproutlet.
  Sproutlet* sproutlet = _sproutlet_proxy->target_sproutlet(req->msg,
                                                            port,
                                                            alias,
                                                            trail());

  // Keep cycling though sproutlets until we either find a sproutlet that
  // wants to handle the request or run out of sproutlets.
  while (sproutlet != NULL)
  {
    // Found a local Sproutlet, so offer the sproutlet a chance to handle
    // the request.
    pjsip_sip_uri* next_hop = NULL;
    sproutlet_tsx = sproutlet->get_tsx(_sproutlet_proxy,
                                       alias,
                                       req->msg,
                                       next_hop,
                                       req->pool,
                                       trail());

    if (sproutlet_tsx != NULL)
    {
      // We've found a sproutlet that wants to handle the request so break
      // out of the loop.
      break;
    }

    // Remove the top route header if there is one and it refers to us.
    pjsip_route_hdr* route = (pjsip_route_hdr*)pjsip_msg_find_hdr(req->msg,
                                                                  PJSIP_H_ROUTE,
                                                                  NULL);
    if ((route != NULL) &&
        (_sproutlet_proxy->is_uri_local(route->name_addr.uri)))
    {
      TRC_DEBUG("Remove top Route header %s", PJUtils::hdr_to_string(route).c_str());
      pj_list_erase(route);
    }

    // Add on the next hop URI if there is one.
    if (next_hop != NULL)
    {
      PJUtils::add_top_route_header(req->msg, next_hop, req->pool);
    }

    // Attempt to find the next Sproutlet.
    sproutlet = _sproutlet_proxy->target_sproutlet(req->msg,
                                                   0,
                                                   alias,
                                                   trail());
  }

  return sproutlet_tsx;
}


//
// UASTsx::SproutletWrapper methods.
//

SproutletWrapper::SproutletWrapper(SproutletProxy* proxy,
                                   SproutletProxy::UASTsx* proxy_tsx,
                                   Sproutlet* sproutlet,
                                   SproutletTsx* sproutlet_tsx,
                                   const std::string& sproutlet_alias,
                                   pjsip_tx_data* req,
                                   pjsip_transport* original_transport,
                                   const std::string& upstream_network_func,
                                   int depth,
                                   SAS::TrailId trail_id) :
  _proxy(proxy),
  _proxy_tsx(proxy_tsx),
  _sproutlet(sproutlet),
  _sproutlet_tsx(sproutlet_tsx),
  _service_name(""),
  _id(""),
  _req(req),
  _req_type(),
  _original_transport(original_transport),
  _this_network_func(""),
  _upstream_network_func(upstream_network_func),
  _depth(depth),
  _packets(),
  _send_requests(),
  _send_responses(),
  _pending_sends(0),
  _best_rsp(NULL),
  _complete(false),
  _process_actions_entered(0),
  _forks(),
  _pending_timers(),
  _allowed_host_state(BaseResolver::ALL_LISTS),
  _trail_id(trail_id)
{
  if (_original_transport != NULL)
  {
    pjsip_transport_add_ref(_original_transport);
  }

  _req_type = SNMP::string_to_request_type(_req->msg->line.req.method.name.ptr,
                                           _req->msg->line.req.method.name.slen);
  if (sproutlet != NULL)
  {
    // Set the service name from the sproutlet
    _service_name = sproutlet->service_name();
  }
  else
  {
    // No Sproutlet specified, so we'll use a default "no-op" Sproutlet.
    _service_name = "noop";
  }

  if (_sproutlet_tsx == NULL)
  {
    // We haven't been supplied a tsx, so create a default SproutletTsx to
    // handle the request.
    _sproutlet_tsx = new SproutletTsx(NULL);
    _this_network_func = _service_name;
  }
  else
  {
    _this_network_func = _sproutlet_tsx->get_network_function();
  }

  // Initialize the Tsx
  _sproutlet_tsx->set_helper(this);

  if ((_sproutlet != NULL) &&
      (_sproutlet->_incoming_sip_transactions_tbl != NULL))
  {
    // Update SNMP SIP transactions statistics for the Sproutlet.
    _sproutlet->_incoming_sip_transactions_tbl->increment_attempts(_req_type);
    if (_req_type == SNMP::SIPRequestTypes::ACK)
    {
      _sproutlet->_incoming_sip_transactions_tbl->increment_successes(_req_type);
    }
  }

  // Construct a unique identifier for this Sproutlet.
  std::ostringstream id;
  id << _service_name << "-" << (const void*)_sproutlet_tsx;
  _id = id.str();
  TRC_VERBOSE("Created Sproutlet %s for %s",
              _id.c_str(), pjsip_tx_data_get_info(req));
}

SproutletWrapper::~SproutletWrapper()
{
  // Destroy the SproutletTsx.
  TRC_DEBUG("Destroying SproutletWrapper %p", this);
  if (_sproutlet_tsx != NULL)
  {
    delete _sproutlet_tsx;
  }

  if (_req != NULL)
  {
    TRC_DEBUG("Free original request %s (%s)",
              pjsip_tx_data_get_info(_req), _req->obj_name);
    pjsip_tx_data_dec_ref(_req);
  }

  if (!_packets.empty())
  {
    TRC_WARNING("Sproutlet %s leaked %d messages - reclaiming", _id.c_str(), _packets.size());
    for (Packets::iterator it = _packets.begin(); it != _packets.end(); ++it)
    {
      TRC_WARNING("  Leaked message - %s", pjsip_tx_data_get_info(it->second));
      pjsip_tx_data_dec_ref(it->second);
    }
  }

  if (_original_transport != NULL)
  {
    pjsip_transport_dec_ref(_original_transport);
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
    TRC_ERROR("Failed to clone original request for Sproutlet %s", _service_name.c_str());
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
    TRC_DEBUG("Remove top Route header %s", PJUtils::hdr_to_string(hr).c_str());
    pj_list_erase(hr);
  }

  register_tdata(clone);

  return clone->msg;
}

// Sets the transport on this request to be the same as on the original.
void SproutletWrapper::copy_original_transport(pjsip_msg* req)
{
  // Get the original transport.
  if (_original_transport == NULL)
  {
    // LCOV_EXCL_START - defensive code not hit in UT
    TRC_WARNING("Sproutlet tried to copy transport from unknown original");
    return;
    // LCOV_EXCL_STOP
  }

  // Get this request's tdata from the map of clones.
  Packets::iterator it = _packets.find(req);
  if (it == _packets.end())
  {
    // LCOV_EXCL_START - defensive code not hit in UT
    TRC_WARNING("Sproutlet tried to copy transport on an unknown request");
    return;
    // LCOV_EXCL_STOP
  }
  pjsip_tx_data* tdata = it->second;

  // Set the transport.
  pjsip_tpselector tpsel;
  pj_bzero(&tpsel, sizeof(tpsel));
  tpsel.type = PJSIP_TPSELECTOR_TRANSPORT;
  tpsel.u.transport = _original_transport;
  pjsip_tx_data_set_transport(tdata, &tpsel);
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

pjsip_msg* SproutletWrapper::create_request()
{
  // Create a new tdata
  pj_status_t status;
  pjsip_tx_data* new_tdata;

  status = pjsip_endpt_create_tdata(stack_data.endpt, &new_tdata);

  if (status != PJ_SUCCESS)
  {
    //LCOV_EXCL_START
    TRC_ERROR("Failed to create new request");
    return NULL;
    //LCOV_EXCL_STOP
  }

  pjsip_tx_data_add_ref(new_tdata);

  // Create a message inside the tdata
  new_tdata->msg = pjsip_msg_create(new_tdata->pool, PJSIP_REQUEST_MSG);

  // Add any additional request headers from the endpoint
  const pjsip_hdr* endpt_hdr = pjsip_endpt_get_request_headers(stack_data.endpt)->next;
  while (endpt_hdr != pjsip_endpt_get_request_headers(stack_data.endpt))
  {
    pjsip_hdr* hdr = (pjsip_hdr*)pjsip_hdr_shallow_clone(new_tdata->pool, endpt_hdr);
    pjsip_msg_add_hdr(new_tdata->msg, hdr);
    endpt_hdr = endpt_hdr->next;
  }

  set_trail(new_tdata, trail());
  register_tdata(new_tdata);

  return new_tdata->msg;
}

pjsip_msg* SproutletWrapper::clone_request(pjsip_msg* req)
{
  return clone_msg(req);
}

pjsip_msg* SproutletWrapper::clone_msg(pjsip_msg* msg)
{
  // Get the old tdata from the map of clones
  Packets::iterator it = _packets.find(msg);
  if (it == _packets.end())
  {
    TRC_WARNING("Sproutlet attempted to clone an unrecognised message");
    return NULL;
  }

  // Clone the tdata and put it back into the map
  pjsip_tx_data* new_tdata = PJUtils::clone_msg(stack_data.endpt, it->second);

  if (new_tdata == NULL)
  {
    //LCOV_EXCL_START
    TRC_ERROR("Failed to clone message for Sproutlet %s", _service_name.c_str());
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
    TRC_WARNING("Sproutlet attempted to create a response from an unrecognised request");
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

int SproutletWrapper::send_request(pjsip_msg*& req, int allowed_host_state)
{
  TRC_DEBUG("Sproutlet send_request %p", req);

  // Get the tdata from the map of clones
  Packets::iterator it = _packets.find(req);
  if (it == _packets.end())
  {
    TRC_ERROR("Sproutlet attempted to forward an unrecognised request");
    return -1;
  }

  // Check that this actually is a request
  if (req->type != PJSIP_REQUEST_MSG)
  {
    TRC_ERROR("Sproutlet attempted to forward a response as a request");
    return -1;
  }

  if ((_sproutlet != NULL) &&
      (_sproutlet->_outgoing_sip_transactions_tbl != NULL))
  {
    // Update SNMP SIP transactions statistics for the Sproutlet.
    _sproutlet->_outgoing_sip_transactions_tbl->increment_attempts(_req_type);
    if (_req_type == SNMP::SIPRequestTypes::ACK)
    {
      _sproutlet->_outgoing_sip_transactions_tbl->increment_successes(_req_type);
    }
  }

  // We've found the tdata, move it to _send_requests under a new unique ID.
  int fork_id = _forks.size();
  _forks.resize(fork_id + 1);
  _forks[fork_id].state.tsx_state = PJSIP_TSX_STATE_NULL;
  _forks[fork_id].state.error_state = NONE;
  _forks[fork_id].pending_cancel = false;

  _send_requests[fork_id] = {
    .tx_data = it->second,
    .allowed_host_state = (_allowed_host_state & allowed_host_state)
  };

  TRC_VERBOSE("%s sending %s on fork %d",
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
    TRC_ERROR("Sproutlet attempted to send an unrecognised response");
    return;
  }

  pjsip_tx_data* tdata = it->second;

  // Check that this actually is a response
  if (rsp->type != PJSIP_RESPONSE_MSG)
  {
    TRC_ERROR("Sproutlet attempted to forward a request as a response");
    return;
  }

  if (is_internal_network_func_boundary())
  {
    // We're at an internal network function boundary - strip off the Via
    // header that we added on the request.
    PJUtils::remove_top_via(tdata);
  }

  TRC_VERBOSE("%s sending %s", _id.c_str(), pjsip_tx_data_get_info(tdata));

  // We've found the tdata, move it to _send_responses.
  _send_responses.push_back(tdata);

  // Move the clone out of the clones list.
  _packets.erase(rsp);

  // Finish up
  rsp = NULL;
}

void SproutletWrapper::cancel_fork(int fork_id, int st_code, std::string reason)
{
  TRC_DEBUG("Request to cancel fork %d, reason = %d (%s)", fork_id, st_code, reason.c_str());
  if ((_forks.size() > (size_t)fork_id) &&
      (_forks[fork_id].state.tsx_state != PJSIP_TSX_STATE_TERMINATED))
  {
    if (_forks[fork_id].req->msg->line.req.method.id == PJSIP_INVITE_METHOD)
    {
      // The fork is still pending a final response to an INVITE request, so
      // we can CANCEL it.
      TRC_VERBOSE("%s cancelling fork %d, reason = %d (%s)",
                  _id.c_str(), fork_id, st_code, reason.c_str());
      _forks[fork_id].pending_cancel = true;
      _forks[fork_id].cancel_st_code = st_code;
      _forks[fork_id].cancel_reason = reason;
    }
  }
}

void SproutletWrapper::cancel_pending_forks(int st_code, std::string reason)
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
        TRC_VERBOSE("%s cancelling fork %d, status code %d, reason %s", _id.c_str(), ii, st_code, reason.c_str());
        _forks[ii].pending_cancel = true;
        _forks[ii].cancel_st_code = st_code;
        _forks[ii].cancel_reason = reason;
      }
    }
  }
}

void SproutletWrapper::mark_pending_forks_as_abandoned()
{
  for (size_t ii = 0; ii < _forks.size(); ++ii)
  {
    if ((_forks[ii].state.tsx_state != PJSIP_TSX_STATE_NULL) &&
        (_forks[ii].state.tsx_state != PJSIP_TSX_STATE_TERMINATED))
    {
      _forks[ii].abandoned = true;
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
    TRC_ERROR("Sproutlet attempted to free an unrecognised message");
    return;
  }

  pjsip_tx_data* tdata = it->second;

  deregister_tdata(tdata);

  TRC_DEBUG("Free message %s", tdata->obj_name);
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
    TRC_ERROR("Sproutlet attempted to get the pool for an unrecognised message");
    return NULL;
  }

  return it->second->pool;
}

bool SproutletWrapper::schedule_timer(void* context, TimerID& id, int duration)
{
  bool scheduled = _proxy_tsx->schedule_timer(this, context, id, duration);
  if (scheduled)
  {
    _pending_timers.insert(id);
  }
  return scheduled;
}

void SproutletWrapper::cancel_timer(TimerID id)
{
  if (_proxy_tsx->cancel_timer(id))
  {
    _pending_timers.erase(id);
  }
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
  return _proxy->is_uri_reflexive(uri, _sproutlet);
}

bool SproutletWrapper::is_uri_local(const pjsip_uri* uri) const
{
  return _proxy->is_uri_local(uri);
}

pjsip_sip_uri* SproutletWrapper::get_reflexive_uri(pj_pool_t* pool) const
{
  return _proxy->create_sproutlet_uri(pool, _sproutlet);
}

pjsip_sip_uri* SproutletWrapper::next_hop_uri(const std::string& service,
                                              const pjsip_sip_uri* base_uri,
                                              pj_pool_t* pool) const
{
  return _proxy->next_hop_uri(service, base_uri, pool);
}

pjsip_sip_uri* SproutletWrapper::get_routing_uri(const pjsip_msg* req) const
{
  // Get the URI that caused us to be routed to this Sproutlet or if no such
  // URI exists e.g. if the Sproutlet was matched on a port, return NULL.
  const pjsip_route_hdr* route = route_hdr();
  pjsip_sip_uri* routing_uri = NULL;
  if (route != NULL)
  {
    if ((PJSIP_URI_SCHEME_IS_SIP(route->name_addr.uri)) &&
        (is_uri_reflexive(route->name_addr.uri)))
    {
      routing_uri = (pjsip_sip_uri*)route->name_addr.uri;
    }
  }
  else
  {
    if ((PJSIP_URI_SCHEME_IS_SIP(req->line.req.uri)) &&
        (is_uri_reflexive(req->line.req.uri)))
    {
      routing_uri = (pjsip_sip_uri*)req->line.req.uri;
    }
  }

  return routing_uri;
}

std::string SproutletWrapper::get_local_hostname(const pjsip_sip_uri* uri) const
{
  return _proxy->get_local_hostname(uri);
}

void SproutletWrapper::rx_request(pjsip_tx_data* req, int allowed_host_state)
{
  // SAS log the start of processing by this sproutlet
  SAS::Event event(trail(), SASEvent::BEGIN_SPROUTLET_REQ, 0);
  event.add_var_param(_service_name);
  SAS::report_event(event);

  // Store a reference to the request.
  _req = req;

  if (is_network_func_boundary())
  {
    // Decrement Max-Forwards when transitioning between Network Functions.
    pjsip_max_fwd_hdr* mf_hdr = (pjsip_max_fwd_hdr*)
                      pjsip_msg_find_hdr(req->msg, PJSIP_H_MAX_FORWARDS, NULL);
    if (mf_hdr != NULL)
    {
      --mf_hdr->ivalue;
    }
  }
  else
  {
    // The request was passed by another sproutlet in the same network
    // function, so respect any host state restrictions passed through.
    _allowed_host_state = allowed_host_state;
  }

  if (is_internal_network_func_boundary() && !stack_data.sprout_hostname.empty())
  {
    // Add a Via header to indicate that the request has traversed the upstream
    // network function.  This can be used to determine the source network
    // function on requests passed internally.
    pjsip_via_hdr *hvia = PJUtils::add_top_via(req);
    std::string network_func_host =
                     _upstream_network_func + "." + stack_data.sprout_hostname;
    pj_strdup2(req->pool, &hvia->sent_by.host, network_func_host.c_str());
    pj_strdup2(req->pool, &hvia->transport, "TCP");
  }

  // Log the request at VERBOSE level before we send it out to aid in
  // tracking its path through the sproutlets.
  if (Log::enabled(Log::VERBOSE_LEVEL))
  {
    log_inter_sproutlet(req, true);
  }

  // Clone the request to get a mutable copy to pass to the Sproutlet.
  pjsip_msg* clone = original_request();
  if (clone == NULL)
  {
    // @TODO
  }

  if (PJSIP_MSG_TO_HDR(clone)->tag.slen == 0)
  {
    TRC_VERBOSE("%s pass initial request %s to Sproutlet",
                _id.c_str(), msg_info(clone));
    _sproutlet_tsx->on_rx_initial_request(clone);
  }
  else
  {
    TRC_VERBOSE("%s pass in dialog request %s to Sproutlet",
                _id.c_str(), msg_info(clone));
    _sproutlet_tsx->on_rx_in_dialog_request(clone);
  }

  // We consider an ACK transaction to be complete immediately after the
  // sproutlet's actions have been processed, as we won't receive any response,
  // so won't get another opportunity to tidy up the transaction state.
  // We do this regardless of whether the sproutlet forwarded the ACK (some
  // sproutlets are unable to in certain situations).
  bool complete_after_actions = (req->msg->line.req.method.id == PJSIP_ACK_METHOD);
  process_actions(complete_after_actions);
}

void SproutletWrapper::rx_response(pjsip_tx_data* rsp,
                                   int fork_id,
                                   ForkErrorState error_state)
{
  // SAS log the start of processing by this sproutlet
  SAS::Event event(trail(), SASEvent::BEGIN_SPROUTLET_RSP, 0);
  event.add_var_param(_service_name);
  event.add_static_param(fork_id);
  SAS::report_event(event);

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
    TRC_VERBOSE("%s received provisional response %s on fork %d, state = %s",
                _id.c_str(), pjsip_tx_data_get_info(rsp),
                fork_id, pjsip_tsx_state_str(_forks[fork_id].state.tsx_state));
  }
  else if (rsp->msg->line.status.code >= PJSIP_SC_OK)
  {
    // Final response, so mark the fork as completed and decrement the number
    // of pending responses.
    _forks[fork_id].state.tsx_state = PJSIP_TSX_STATE_TERMINATED;
    _forks[fork_id].state.error_state = error_state;
    pjsip_tx_data_dec_ref(_forks[fork_id].req);
    _forks[fork_id].req = NULL;
    TRC_VERBOSE("%s received final response %s on fork %d, state = %s",
                _id.c_str(), pjsip_tx_data_get_info(rsp),
                fork_id, pjsip_tsx_state_str(_forks[fork_id].state.tsx_state));
    _forks[fork_id].pending_response = false;

    if ((_sproutlet != NULL) &&
      (_sproutlet->_outgoing_sip_transactions_tbl != NULL))
    {
      // Update SNMP SIP transactions statistics for the Sproutlet.
      if (rsp->msg->line.status.code >= 200 && rsp->msg->line.status.code < 300)
      {
        _sproutlet->_outgoing_sip_transactions_tbl->increment_successes(_req_type);
      }
      else
      {
        _sproutlet->_outgoing_sip_transactions_tbl->increment_failures(_req_type);
      }
    }
  }
  _sproutlet_tsx->on_rx_response(rsp->msg, fork_id);

  process_actions(false);
}

void SproutletWrapper::rx_cancel(pjsip_tx_data* cancel, const std::string& reason)
{
  TRC_VERBOSE("%s received CANCEL request", _id.c_str());
  _sproutlet_tsx->on_rx_cancel(PJSIP_SC_REQUEST_TERMINATED,
                           cancel->msg);
  pjsip_tx_data_dec_ref(cancel);
  cancel_pending_forks(PJSIP_SC_REQUEST_TERMINATED, reason);
  process_actions(false);
}

void SproutletWrapper::rx_error(int status_code, const std::string& reason)
{
  TRC_VERBOSE("%s received error %d (reason %s)",
              _id.c_str(),
              status_code,
              reason.c_str());
  _sproutlet_tsx->on_rx_cancel(status_code, NULL);
  cancel_pending_forks(status_code, reason);

  // Consider the transaction to be complete as no final response should be
  // sent upstream.
  _complete = true;
  process_actions(false);
}

void SproutletWrapper::rx_fork_error(ForkErrorState fork_error, int fork_id)
{
  TRC_VERBOSE("%s received error %s on fork %d, state = %s",
              _id.c_str(), fork_error_to_str(fork_error),
              fork_id, pjsip_tsx_state_str(_forks[fork_id].state.tsx_state));

  if (_forks[fork_id].state.tsx_state != PJSIP_TSX_STATE_TERMINATED)
  {
    // This fork has not already been terminated, so record the error in the
    // fork state.
    _forks[fork_id].state.error_state = fork_error;

    // Create a response for the error.
    int status_code = (fork_error == ForkErrorState::TIMEOUT) ?
                             PJSIP_SC_REQUEST_TIMEOUT :
                             PJSIP_SC_SERVICE_UNAVAILABLE;
    pjsip_tx_data* rsp;
    pj_status_t status = PJUtils::create_response(stack_data.endpt,
                                                  _forks[fork_id].req,
                                                  status_code,
                                                  NULL,
                                                  &rsp);

    // SAS log the error and response
    SAS::Event event(trail(), SASEvent::RX_FORK_ERROR, 0);
    event.add_static_param(fork_id);
    event.add_static_param(fork_error);
    event.add_static_param(status_code);
    SAS::report_event(event);

    // This counts as a final response, so mark the fork as terminated and
    // decrement the number of pending responses.
    _forks[fork_id].state.tsx_state = PJSIP_TSX_STATE_TERMINATED;
    pjsip_tx_data_dec_ref(_forks[fork_id].req);
    _forks[fork_id].req = NULL;
    _forks[fork_id].pending_response = false;

    if (status == PJ_SUCCESS)
    {
      if ((_sproutlet != NULL) &&
          (_sproutlet->_outgoing_sip_transactions_tbl != NULL))
      {
        // Update SNMP SIP transaction failure statistic for the Sproutlet.
        _sproutlet->_outgoing_sip_transactions_tbl->increment_failures(_req_type);
      }

      // Pass the response to the application.
      register_tdata(rsp);
      _sproutlet_tsx->on_rx_response(rsp->msg, fork_id);
      process_actions(false);
    }
  }
}

void SproutletWrapper::on_timer_pop(TimerID id, void* context)
{
  TRC_DEBUG("Processing timer pop, id = %ld", id);
  _pending_timers.erase(id);
  _sproutlet_tsx->on_timer_expiry(context);
  process_actions(false);
}

void SproutletWrapper::register_tdata(pjsip_tx_data* tdata)
{
  TRC_DEBUG("Adding message %p => txdata %p mapping",
            tdata->msg, tdata);
  _packets[tdata->msg] = tdata;
}

void SproutletWrapper::deregister_tdata(pjsip_tx_data* tdata)
{
  TRC_DEBUG("Removing message %p => txdata %p mapping",
            tdata->msg, tdata);
  _packets.erase(tdata->msg);
}

/// Process actions required by a Sproutlet
void SproutletWrapper::process_actions(bool complete_after_actions)
{
  TRC_DEBUG("Processing actions from sproutlet - %d responses, %d requests, %d timers",
            _send_responses.size(), _send_requests.size(), _pending_timers.size());

  // We've entered process_actions again.  We track this counter because
  // process_actions can be re-entered, and we must never delete the
  // SproutletWrapper if so.
  _process_actions_entered++;

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
      (_pending_sends + count_pending_actionable_responses() == 0))
  {
    // There are no pending responses and no new forked requests waiting to
    // be sent, and the Sproutlet has sent at least one final response, so
    // send this best response upstream.
    TRC_DEBUG("All UAC responded");
    tx_response(_best_rsp);
  }

  // The Sproutlet transaction hasn't completed, so handle any requests
  // forwarded/generated by the Sproutlet.
  while (!_send_requests.empty())
  {
    std::map<int, SproutletProxy::SendRequest>::iterator i = _send_requests.begin();
    int fork_id = i->first;
    SproutletProxy::SendRequest req = i->second;
    _send_requests.erase(i);

    TRC_DEBUG("Processing request %p, fork = %d", req.tx_data, fork_id);

    tx_request(req, fork_id);
  }

  for (size_t ii = 0; ii < _forks.size(); ++ii)
  {
    if (_forks[ii].pending_cancel)
    {
      TRC_VERBOSE("%s fork %d pending CANCEL, state = %s",
                  _id.c_str(), ii, pjsip_tsx_state_str(_forks[ii].state.tsx_state));

      if (_forks[ii].state.tsx_state == PJSIP_TSX_STATE_PROCEEDING)
      {
        // Fork has been marked as pending cancel and we have received a
        // provisional response, so can send the CANCEL.
        TRC_DEBUG("Send CANCEL for fork %d", ii);
        tx_cancel(ii);
      }
    }
  }

  if (complete_after_actions)
  {
    _complete = true;
  }

  // We've now finished (almost) the process_actions method, so we're free to
  // delete this SproutletWrapper once more (if it's appropriate to do so).
  _process_actions_entered--;

  if ((_complete) &&
      (count_pending_responses() == 0) &&
      (_pending_timers.empty()) &&
      (_process_actions_entered == 0))
  {
    // Sproutlet has sent a final response, has no downstream forks waiting
    // a response, and has no pending timers, so should destroy itself.
    TRC_VERBOSE("%s suiciding", _id.c_str());
    delete this;
  }
}

void SproutletWrapper::aggregate_response(pjsip_tx_data* rsp)
{
  int status_code = rsp->msg->line.status.code;
  TRC_DEBUG("Aggregating response with status code %d", status_code);

  if (_complete)
  {
    // We've already sent a final response upstream (a 200 OK or 408 timeout) so
    // discard this response.
    TRC_DEBUG("Discard stale response %s (%s)",
              pjsip_tx_data_get_info(rsp), rsp->obj_name);
    deregister_tdata(rsp);
    pjsip_tx_data_dec_ref(rsp);
    return;
  }

  if (status_code == 100)
  {
    if (is_network_func_boundary())
    {
      // We will already have sent a locally generated 100 Trying response, so
      // don't forward this one.
      TRC_DEBUG("Discard 100/INVITE response (%s)", rsp->obj_name);
      deregister_tdata(rsp);
      pjsip_tx_data_dec_ref(rsp);
    }
    else
    {
      // This Sproutlet does not automatically send 100 Trying responses.  Pass
      // this one through now.
      TRC_DEBUG("Forward 100 Trying response");
      tx_response(rsp);
    }
  }
  else if ((status_code > 100) &&
           (status_code < 199))
  {
    // Forward all provisional responses to INVITEs.
    TRC_DEBUG("Forward 1xx response");
    tx_response(rsp);
  }
  else if (PJSIP_IS_STATUS_IN_CLASS(status_code, 200))
  {
    // 2xx response.
    TRC_DEBUG("Forward 2xx response");

    // Send this response immediately as a final response.
    if (_best_rsp != NULL)
    {
      TRC_DEBUG("Discard previous best response %s (%s)",
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
    TRC_DEBUG("3xx/4xx/5xx/6xx response");
    if ((_best_rsp == NULL) ||
        (compare_sip_sc(status_code, _best_rsp->msg->line.status.code) > 0))
    {
      TRC_DEBUG("Best 3xx/4xx/5xx/6xx response so far");

      if (_best_rsp != NULL)
      {
        TRC_DEBUG("Discard previous best response %s (%s)",
                  pjsip_tx_data_get_info(_best_rsp), _best_rsp->obj_name);
        deregister_tdata(_best_rsp);
        pjsip_tx_data_dec_ref(_best_rsp);
      }

      _best_rsp = rsp;
    }
    else
    {
      TRC_DEBUG("Discard response %s (%s) - we already have a better one",
                pjsip_tx_data_get_info(rsp), rsp->obj_name);
      deregister_tdata(rsp);
      pjsip_tx_data_dec_ref(rsp);
    }
  }
}

// Counts the number of forks that are pending a response.
int SproutletWrapper::count_pending_responses()
{
  int forks_pending_response = 0;
  for (size_t ii = 0; ii < _forks.size(); ++ii)
  {
    if (_forks[ii].pending_response)
    {
      ++forks_pending_response;
    }
  }
  return forks_pending_response;
}

// Counts the number of forks that are pending a response, and have not been
// marked as timed out (which means any response they send will not be
// acted on).
int SproutletWrapper::count_pending_actionable_responses()
{
  int forks_pending_actionable_response = 0;
  for (size_t ii = 0; ii < _forks.size(); ++ii)
  {
    if (_forks[ii].pending_response &&
        !_forks[ii].abandoned)
    {
      ++forks_pending_actionable_response;
    }
  }
  return forks_pending_actionable_response;
}

void SproutletWrapper::tx_request(SproutletProxy::SendRequest req,
                                  int fork_id)
{
  TRC_DEBUG("%s transmitting request on fork %d", _id.c_str(), fork_id);
  --_pending_sends;
  pjsip_tx_data* tdata = req.tx_data;

  if (tdata->msg->line.req.method.id != PJSIP_ACK_METHOD)
  {
    // Set the state of this fork to CALLING (strictly speaking this should
    // be TRYING for non-INVITE transaction, but we only need to track this
    // state for determining when we can legally send CANCEL requests so using
    // CALLING in all cases is fine).
    _forks[fork_id].state.tsx_state = PJSIP_TSX_STATE_CALLING;
    _forks[fork_id].pending_response = true;

    // Store a reference to the request.
    TRC_DEBUG("%s store reference to non-ACK request %s on fork %d",
              _id.c_str(), pjsip_tx_data_get_info(tdata), fork_id);
    pjsip_tx_data_add_ref(tdata);
    _forks[fork_id].req = tdata;
  }
  else
  {
    // ACK request, so no response expected.
    _forks[fork_id].state.tsx_state = PJSIP_TSX_STATE_TERMINATED;
  }

  // Notify the sproutlet that the request is being sent downstream.
  _sproutlet_tsx->on_tx_request(tdata->msg, fork_id);

  // Forward the request downstream.
  deregister_tdata(tdata);
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
    if ((_sproutlet != NULL) &&
        (_sproutlet->_incoming_sip_transactions_tbl != NULL))
    {
      // Update SNMP SIP transactions statistics for the Sproutlet.
      if ((_best_rsp != NULL) &&
               (_best_rsp->msg->line.status.code >= 200 && _best_rsp->msg->line.status.code < 300))
      {
        _sproutlet->_incoming_sip_transactions_tbl->increment_successes(_req_type);
      }
      else
      {
        _sproutlet->_incoming_sip_transactions_tbl->increment_failures(_req_type);
      }
    }
  }

  // Forward the response upstream.
  deregister_tdata(rsp);
  _proxy_tsx->tx_response(this, rsp);
}

void SproutletWrapper::tx_cancel(int fork_id)
{
  // Build a CANCEL request from the original request sent on this fork.
  // See issue 1232.
  pjsip_tx_data* cancel = PJUtils::create_cancel(stack_data.endpt,
                                                 _forks[fork_id].req,
                                                 _forks[fork_id].cancel_st_code);
  _proxy_tsx->tx_cancel(this,
                        fork_id,
                        cancel,
                        _forks[fork_id].cancel_st_code,
                        _forks[fork_id].cancel_reason);
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

  TRC_VERBOSE("Routing %s (%d bytes) to %s sproutlet %s:\n"
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

bool SproutletWrapper::is_network_func_boundary() const
{
  // If this network function has a different name to the upstream one, then
  // we're obviously at a network function boundary.  We're also on a boundary
  // between two instances of the same network function if the service name
  // matches the upstream network function (i.e. the two network function names
  // match, but we're entering the first Sproutlet in the network function).
  bool network_func_boundary = (_this_network_func != _upstream_network_func) ||
                               (_service_name == _upstream_network_func);

  TRC_DEBUG("Network function boundary: %s ('%s'->'%s'/'%s')",
            network_func_boundary ? "yes" : "no",
            _upstream_network_func.c_str(),
            _this_network_func.c_str(),
            _service_name.c_str());

  return network_func_boundary;
}

bool SproutletWrapper::is_internal_network_func_boundary() const
{
  // An internal network function boundary doesn't involve an external hop.
  bool internal_boundary = is_network_func_boundary() &&
                           (_upstream_network_func != EXTERNAL_NETWORK_FUNCTION) &&
                           (_this_network_func != EXTERNAL_NETWORK_FUNCTION);

  TRC_DEBUG("Internal network function boundary: %s",
            internal_boundary ? "yes" : "no");

  return internal_boundary;
}

// Get the overall error state for this wrapper.  This is used when passing
// error state upstream to another sproutlet.  In the most common case, there
// will only have been a single fork, and we will return its state.  For more
// complicated scenarios, we can't infer anything about the downstream error
// state unless all forks had the same error state.  For example, a transport
// error on a single fork is not significant, as the sproutlet may have retried
// on another fork, and had a successful result.  If the results don't match,
// we return NONE.
ForkErrorState SproutletWrapper::get_error_state() const
{
  if ((_forks.size() <= 0) || is_network_func_boundary())
  {
    // Don't expose error state upstream across network boundaries.
    return ForkErrorState::NONE;
  }

  ForkErrorState error_state = _forks[0].state.error_state;

  for (const auto& fork : _forks)
  {
    if (fork.state.error_state != error_state)
    {
      return ForkErrorState::NONE;
    }
  }

  return error_state;
}
