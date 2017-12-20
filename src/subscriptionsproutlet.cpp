/**
 *
 * @file subscriptionsproutlet.cpp Definition of the Subscription Sproutlet
 *                                 classes, implementing S-CSCF specific
 *                                 Subscription functions.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

extern "C" {
#include "pjsip-simple/evsub.h"
#include <pjsip-simple/evsub_msg.h>
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}

#include "log.h"
#include "pjutils.h"
#include "analyticslogger.h"
#include "sproutsasevent.h"
#include "constants.h"
#include "custom_headers.h"
#include "stack.h"
#include "contact_filtering.h"
#include "registration_utils.h"
#include "subscriptionsproutlet.h"
#include "uri_classifier.h"
#include "hss_sip_mapping.h"

/// SubscriptionSproutlet constructor
SubscriptionSproutlet::SubscriptionSproutlet(const std::string& name,
                                             int port,
                                             const std::string& uri,
                                             const std::string& network_function,
                                             const std::string& next_hop_service,
                                             SubscriberDataManager* sdm,
                                             std::vector<SubscriberDataManager*> remote_sdms,
                                             HSSConnection* hss_connection,
                                             ACRFactory* acr_factory,
                                             AnalyticsLogger* analytics_logger,
                                             int cfg_max_expires) :
  Sproutlet(name, port, uri, "", {}, NULL, NULL, network_function),
  _sdm(sdm),
  _remote_sdms(remote_sdms),
  _hss(hss_connection),
  _acr_factory(acr_factory),
  _analytics(analytics_logger),
  _max_expires(cfg_max_expires),
  _next_hop_service(next_hop_service)
{
}

/// SubscriptionSproutlet destructor
SubscriptionSproutlet::~SubscriptionSproutlet()
{
}

bool SubscriptionSproutlet::init()
{
  return true;
}

SproutletTsx* SubscriptionSproutlet::get_tsx(SproutletHelper* helper,
                                             const std::string& alias,
                                             pjsip_msg* req,
                                             pjsip_sip_uri*& next_hop,
                                             pj_pool_t* pool,
                                             SAS::TrailId trail)
{
  if (handle_request(req, trail))
  {
    return (SproutletTsx*)new SubscriptionSproutletTsx(this, _next_hop_service);
  }

  // We're not interested in the message so create a next hop URI.
  pjsip_sip_uri* base_uri = helper->get_routing_uri(req, this);
  next_hop = helper->next_hop_uri(_next_hop_service,
                                  base_uri,
                                  pool);
  return NULL;
}

// Check whether this request should be absorbed by the subscription module
bool SubscriptionSproutlet::handle_request(pjsip_msg* req,
                                           SAS::TrailId trail)
{
  if (pjsip_method_cmp(&req->line.req.method, pjsip_get_subscribe_method()))
  {
    // This isn't a SUBSCRIBE, so this module can't process it.
    return false;
  }

  URIClass uri_class = URIClassifier::classify_uri(req->line.req.uri);
  TRC_INFO("URI class is %d", uri_class);
  if (((uri_class != NODE_LOCAL_SIP_URI) &&
       (uri_class != HOME_DOMAIN_SIP_URI) &&
       (uri_class != GLOBAL_PHONE_NUMBER) &&
       (uri_class != LOCAL_PHONE_NUMBER)) ||
      !PJUtils::check_route_headers(req))
  {
    TRC_DEBUG("Not processing subscription request not targeted at this domain or node");
    // LCOV_EXCL_START - No SAS events in UT
    SAS::Event event(trail, SASEvent::SUBSCRIBE_FAILED_EARLY_DOMAIN, 0);
    SAS::report_event(event);
    // LCOV_EXCL_STOP
    return false;
  }

  // We now know we have a SUBSCRIBE request targeted at the home domain
  // or specifically at this node. Check whether it should be processed
  // by this module or passed up to an AS.

  // A valid subscription must have the Event header set to "reg". This is case-sensitive
  pj_str_t event_name = pj_str((char*)"Event");
  pjsip_event_hdr* event = (pjsip_event_hdr*)pjsip_msg_find_hdr_by_name(req, &event_name, NULL);

  if (!event || (PJUtils::pj_str_to_string(&event->event_type) != "reg"))
  {
    // The Event header is missing or doesn't match "reg"
    TRC_DEBUG("Not processing subscription request that's not for the 'reg' package");

    // LCOV_EXCL_START - No SAS events in UT
    SAS::Event sas_event(trail, SASEvent::SUBSCRIBE_FAILED_EARLY_EVENT, 0);
    if (event)
    {
      char event_hdr_str[256];
      memset(event_hdr_str, 0, 256);
      pjsip_hdr_print_on(event, event_hdr_str, 255);
      sas_event.add_var_param(event_hdr_str);
    }
    SAS::report_event(sas_event);
    // LCOV_EXCL_STOP

    return false;
  }

  // Accept header may be present - if so must include the application/reginfo+xml
  pjsip_accept_hdr* accept = (pjsip_accept_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_ACCEPT, NULL);
  if (accept)
  {
    bool found = false;
    pj_str_t reginfo = pj_str((char*)"application/reginfo+xml");
    for (uint32_t i = 0; i < accept->count; i++)
    {
      if (!pj_strcmp(accept->values + i, &reginfo))
      {
        found = true;
      }
    }

    if (!found)
    {
      // The Accept header (if it exists) doesn't contain "application/reginfo+xml"
      TRC_DEBUG("Not processing subscription request that doesn't "
                "accept reginfo notifications");
      char accept_hdr_str[256];
      memset(accept_hdr_str, 0, 256);
      pjsip_hdr_print_on(accept, accept_hdr_str, 255);

      // LCOV_EXCL_START - No SAS events in UT
      SAS::Event event(trail, SASEvent::SUBSCRIBE_FAILED_EARLY_ACCEPT, 0);
      event.add_var_param(accept_hdr_str);
      SAS::report_event(event);
      // LCOV_EXCL_STOP

      return false;
    }
  }

  return true;
}

SubscriptionSproutletTsx::SubscriptionSproutletTsx(SubscriptionSproutlet* subscription,
                                                   const std::string& next_hop_service) :
  CompositeSproutletTsx(subscription, next_hop_service),
  _subscription(subscription)
{
  TRC_DEBUG("Subscription Transaction (%p) created", this);
}

SubscriptionSproutletTsx::~SubscriptionSproutletTsx()
{
  TRC_DEBUG("Subscription Transaction (%p) destroyed", this);
}

void SubscriptionSproutletTsx::on_rx_initial_request(pjsip_msg* req)
{
  TRC_INFO("Subscription sproutlet received intitial request");
  return on_rx_request(req);
}

void SubscriptionSproutletTsx::on_rx_in_dialog_request(pjsip_msg* req)
{
  TRC_INFO("Subscription sproutlet received in dialog request");
  return on_rx_request(req);
}

void SubscriptionSproutletTsx::on_rx_request(pjsip_msg* req)
{
  process_subscription_request(req);
}


void SubscriptionSproutletTsx::process_subscription_request(pjsip_msg* req)
{
  pjsip_status_code st_code = PJSIP_SC_OK;

  SAS::TrailId trail_id = trail();

  // Get the URI from the To header and check it is a SIP or SIPS URI.
  pjsip_uri* uri = (pjsip_uri*)pjsip_uri_get_uri(PJSIP_MSG_TO_HDR(req)->uri);
  pjsip_expires_hdr* expires = (pjsip_expires_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_EXPIRES, NULL);
  int expiry = (expires != NULL) ? expires->ivalue : SubscriptionSproutlet::DEFAULT_SUBSCRIPTION_EXPIRES;

  if (expiry > _subscription->_max_expires)
  {
    // Expiry is too long, set it to the maximum.
    expiry = _subscription->_max_expires;
  }

  if ((!PJSIP_URI_SCHEME_IS_SIP(uri)) && (!PJSIP_URI_SCHEME_IS_TEL(uri)))
  {
    // Reject a non-SIP/TEL URI with 404 Not Found (RFC3261 isn't clear
    // whether 404 is the right status code - it says 404 should be used if
    // the AoR isn't valid for the domain in the RequestURI).
    TRC_ERROR("Rejecting subscribe request using invalid URI scheme");

    SAS::Event event(trail_id, SASEvent::SUBSCRIBE_FAILED_EARLY_URLSCHEME, 0);
    SAS::report_event(event);

    pjsip_msg* rsp = create_response(req, PJSIP_SC_NOT_FOUND);
    send_response(rsp);
    free_msg(req);
    return;
  }

  bool emergency_subscription = false;

  pjsip_contact_hdr* contact_hdr = (pjsip_contact_hdr*)
                 pjsip_msg_find_hdr(req, PJSIP_H_CONTACT, NULL);

  while (contact_hdr != NULL)
  {
    emergency_subscription = PJUtils::is_emergency_registration(contact_hdr);

    if (!emergency_subscription)
    {
      break;
    }

    contact_hdr = (pjsip_contact_hdr*) pjsip_msg_find_hdr(req,
                                                          PJSIP_H_CONTACT,
                                                          contact_hdr->next);
  }

  if (emergency_subscription)
  {
    // Reject a subscription with a Contact header containing a contact address
    // that's been registered for emergency service.
    TRC_ERROR("Rejecting subscribe request from emergency registration");

    SAS::Event event(trail_id, SASEvent::SUBSCRIBE_FAILED_EARLY_EMERGENCY, 0);
    SAS::report_event(event);

    // Allow-Events is a mandatory header on 489 responses.
    pjsip_msg* rsp = create_response(req, PJSIP_SC_BAD_EVENT);
    pjsip_generic_string_hdr* allow_events_hdr =
         pjsip_generic_string_hdr_create(get_pool(rsp), &STR_ALLOW_EVENTS, &STR_REG);
    pjsip_msg_add_hdr(rsp, (pjsip_hdr*)allow_events_hdr);
    send_response(rsp);
    free_msg(req);
    return;
  }

  // Create an ACR for the request.  The node role is always considered
  // originating for SUBSCRIBE requests.
  ACR* acr = _subscription->_acr_factory->get_acr(trail_id,
                                               ACR::CALLING_PARTY,
                                               ACR::NODE_ROLE_ORIGINATING);
  acr->rx_request(req);

  // Canonicalize the public ID from the URI in the To header.
  std::string public_id = PJUtils::public_id_from_uri(uri);

  TRC_DEBUG("Process SUBSCRIBE for public ID %s", public_id.c_str());

  // Get the call identifier from the headers.
  std::string cid = PJUtils::pj_str_to_string(&PJSIP_MSG_CID_HDR(req)->id);

  // Add SAS markers to the trail attached to the message so the trail
  // becomes searchable.
  SAS::Event event(trail_id, SASEvent::SUBSCRIBE_START, 0);
  event.add_var_param(public_id);
  SAS::report_event(event);

  HSSConnection::irs_info irs_info;

  // Check if the contact header is present. If it isn't, we want to abort
  // processing before going any further, to avoid unnecessary work.
  pjsip_contact_hdr* contact = (pjsip_contact_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_CONTACT, NULL);
  if (contact == NULL)
  {
    TRC_ERROR("Unable to parse contact header from request. Aborting processing");
    pjsip_msg* rsp = create_response(req, PJSIP_SC_BAD_REQUEST);
    send_response(rsp);
    free_msg(req);
    delete acr;
    return;
  }

  HTTPCode http_code = _subscription->_hss->get_registration_data(public_id,
                                                                  irs_info,
                                                                  trail_id);
  st_code = determine_hss_sip_response(http_code, irs_info._regstate, "SUBSCRIBE");

  if (st_code != PJSIP_SC_OK)
  {
    if (st_code == PJSIP_SC_TEMPORARILY_UNAVAILABLE)
    {
      // A 480 response means that the subscriber wasn't registered
      SAS::Event event(trail_id, SASEvent::SUBSCRIBE_FAILED_EARLY_NOT_REG, 0);
      SAS::report_event(event);
    }

    pjsip_msg* rsp = create_response(req, st_code);
    send_response(rsp);
    free_msg(req);
    delete acr;
    return;
  }

  // Determine the default URI. If we don't find a default URI, the SUBSCRIBE
  // should already have been rejected for the subscriber being unregistered,
  // but we handle the error case where it isn't.
  std::string aor;
  if (!irs_info._associated_uris.get_default_impu(aor, false))
  {
    pjsip_msg* rsp = create_response(req, PJSIP_SC_FORBIDDEN);
    send_response(rsp);
    free_msg(req);
    delete acr;
    return;
  }

  TRC_DEBUG("aor = %s", aor.c_str());
  TRC_DEBUG("SUBSCRIBE for public ID %s uses AOR %s", public_id.c_str(), aor.c_str());

  // Create a subscription object from the request that we can pass down to
  // be set into/updated in the different stores
  AoR::Subscription new_subscription = create_subscription(req, expiry);

  // Update the local and remote stores with the new subscription
  Store::Status status = update_subscription_in_stores(_subscription,
                                                       new_subscription,
                                                       aor,
                                                       &(irs_info._associated_uris),
                                                       req,
                                                       public_id,
                                                       acr,
                                                       irs_info._ccfs,
                                                       irs_info._ecfs);

  if (_subscription->_analytics != NULL)
  {
    // Generate an analytics log for this subscription update.
    _subscription->_analytics->subscription(aor,
                                            new_subscription._to_tag,
                                            new_subscription._req_uri,
                                            expiry);
  }

  if (status == Store::Status::OK)
  {
    pjsip_msg* rsp = create_response(req, PJSIP_SC_OK);
    // Add expires headers
    pjsip_expires_hdr* expires_hdr = pjsip_expires_hdr_create(get_pool(rsp), expiry);
    pjsip_msg_add_hdr(rsp, (pjsip_hdr*)expires_hdr);

    // Add the to tag to the response
    pjsip_to_hdr *to = (pjsip_to_hdr*) pjsip_msg_find_hdr(rsp,
                                                          PJSIP_H_TO,
                                                          NULL);
    pj_strdup2(get_pool(rsp), &to->tag, new_subscription._to_tag.c_str());

    // Add a P-Charging-Function-Addresses header to the successful SUBSCRIBE
    // response containing the charging addresses returned by the HSS.
    PJUtils::add_pcfa_header(rsp,
                             get_pool(rsp),
                             irs_info._ccfs,
                             irs_info._ecfs,
                             false);

    // Pass the response to the ACR.
    acr->tx_response(rsp);

    send_response(rsp);
  }
  else
  {
    // Failed to connect to the local store.  Reject the subscribe with a 500
    // response.
    st_code = PJSIP_SC_INTERNAL_SERVER_ERROR;

    // Build and send the reply.
    pjsip_msg* rsp = create_response(req, st_code);

    // Add the to tag to the response
    pjsip_to_hdr *to = (pjsip_to_hdr*) pjsip_msg_find_hdr(rsp,
                                                          PJSIP_H_TO,
                                                          NULL);

    pj_strdup2(get_pool(rsp), &to->tag, new_subscription._to_tag.c_str());

    // Pass the response to the ACR.
    acr->tx_response(req);

    // Send the response.
    send_response(rsp);
  }

  SAS::Event sub_accepted(trail_id, SASEvent::SUBSCRIBE_ACCEPTED, 0);
  SAS::report_event(sub_accepted);

  // Send the ACR and delete it.
  acr->send();
  delete acr;

  free_msg(req);
}

// Utility function to take a SUBSCRIBE request, and generate a new subscription object from it
// This saves us from doing this parsing numerous times when getting subscriptions out of the aors
AoR::Subscription SubscriptionSproutletTsx::create_subscription(pjsip_msg* req, int expiry)
{
  int now = time(NULL);
  std::string cid = PJUtils::pj_str_to_string(&PJSIP_MSG_CID_HDR(req)->id);
  pjsip_fromto_hdr* from = (pjsip_fromto_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_FROM, NULL);
  pjsip_fromto_hdr* to = (pjsip_fromto_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_TO, NULL);
  pjsip_contact_hdr* contact = (pjsip_contact_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_CONTACT, NULL);

  std::string contact_uri;
  pjsip_uri* uri = (contact->uri != NULL) ?
                   (pjsip_uri*)pjsip_uri_get_uri(contact->uri) :
                   NULL;

  if ((uri != NULL) &&
      (PJSIP_URI_SCHEME_IS_SIP(uri)))
  {
    contact_uri = PJUtils::uri_to_string(PJSIP_URI_IN_CONTACT_HDR, uri);
  }

  std::string subscription_id = PJUtils::pj_str_to_string(&to->tag);
  if (subscription_id == "")
  {
    // If there's no to tag, generate an unique one
    // TODO: Should use unique deployment and instance IDs here.
    subscription_id = std::to_string(Utils::generate_unique_integer(0, 0));
  }

  // Create a subscription, and fill it with the new data
  AoR::Subscription subscription;
  TRC_DEBUG("Subscription identifier = %s", subscription_id.c_str());

  pjsip_route_hdr* route_hdr = (pjsip_route_hdr*)pjsip_msg_find_hdr(req,
                                                                    PJSIP_H_RECORD_ROUTE,
                                                                    NULL);
  while (route_hdr)
  {
    std::string route = PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                               route_hdr->name_addr.uri);
    TRC_DEBUG("Adding route header %s to subscription %s",
                route.c_str(), subscription_id.c_str());
    // Add the route.
    subscription._route_uris.push_back(route);
    // Look for the next header.
    route_hdr = (pjsip_route_hdr*)pjsip_msg_find_hdr(req,
                                                     PJSIP_H_RECORD_ROUTE,
                                                     route_hdr->next);
  }

  subscription._to_tag = subscription_id;
  subscription._req_uri = contact_uri;
  subscription._cid = cid;
  subscription._to_uri = PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, to->uri);
  subscription._from_uri = PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, from->uri);
  subscription._from_tag = PJUtils::pj_str_to_string(&from->tag);
  subscription._refreshed = true;
  subscription._expires = now + expiry;

  return subscription;
}

// Handles the necessary logic for getting, updating, and setting AoRs from
// local and remote sites with the new subscription data
Store::Status SubscriptionSproutletTsx::update_subscription_in_stores(
                                             SubscriptionSproutlet* subscription,
                                             AoR::Subscription& new_subscription,
                                             std::string aor,
                                             AssociatedURIs* associated_uris,
                                             pjsip_msg* req,
                                             std::string public_id,
                                             ACR* acr,
                                             std::deque<std::string> ccfs,
                                             std::deque<std::string> ecfs)
{
  Store::Status status;

  // We cache AoRPairs from the local and remote SDMs to avoid having
  // to do repeated remote reads, saving thread time
  std::map<SubscriberDataManager*, AoRPair*> _cached_aors;

  AoRPair* local_aor_pair = read_and_cache_from_store(subscription->_sdm,
                                                      aor,
                                                      _cached_aors);
  if (local_aor_pair == NULL)
  {
    TRC_DEBUG("Hit an error reading AoR %s from the local store, unable to update subscription %s",
                aor.c_str(), new_subscription._to_tag.c_str());
    status = Store::Status::ERROR;
    return status;
  }

  // If the NOTIFY Cseq values on the local AoR pair and the remote AoR pair get
  // out of sync, we need a way to recover. We store the local value, and
  // overwrite the remote value if necessary. This means that we will recover
  // once a subscription is updated, possibly after sending some NOTIFYs with
  // incorrect CSeq values.
  // This isn't an ideal solution - this entire area of code is due to be
  // refactored, at which point a more permanent fix should be implemented.
  int local_notify_cseq = -1;

  // Write to the local store, handling any CAS error
  do
  {
    update_subscription(subscription, new_subscription, aor, local_aor_pair, _cached_aors);
    local_aor_pair->get_current()->_associated_uris = *associated_uris;

    local_notify_cseq = local_aor_pair->get_current()->_notify_cseq;

    status = subscription->_sdm->set_aor_data(aor, SubscriberDataManager::EventTrigger::USER, local_aor_pair, trail());
    if (status == Store::DATA_CONTENTION)
    {
      TRC_DEBUG("Hit data contention attempting to write to local store for AoR %s, subscription %s",
                  aor.c_str(), new_subscription._to_tag.c_str());
      local_aor_pair = read_and_cache_from_store(subscription->_sdm, aor, _cached_aors);
      if (local_aor_pair == NULL)
      {
        // LCOV_EXCL_START We test behaviour on store error elsewhere,
        // and UT-ing this case is more effort than it's worth
        TRC_DEBUG("Hit an error reading AoR %s from the local store, unable to update subscription %s",
                    aor.c_str(), new_subscription._to_tag.c_str());
        status = Store::Status::ERROR;
        return status;
        // LCOV_EXCL_STOP
      }
    }
  }
  while (status == Store::DATA_CONTENTION);

  log_subscriptions(aor, local_aor_pair->get_current());

  for (SubscriberDataManager* sdm: subscription->_remote_sdms)
  {
    // Using a different rc for the remote stores, as their success/failure does
    // not impact whether we determine the overall process a success
    Store::Status rc;

    AoRPair* remote_aor_pair = NULL;
    // Check if we have done the remote read for this SDM yet, and do it if not
    // Saves us from doing a re-read if we had to get the AoRs previously
    if ((_cached_aors.find(sdm) == _cached_aors.end()) &&
        (sdm->has_servers()))
    {
      TRC_DEBUG("No cached AoR data found for AoR %s from remote sdm %p",
                  aor.c_str(), sdm);
      remote_aor_pair = read_and_cache_from_store(sdm, aor, _cached_aors);
    }
    else
    {
      TRC_DEBUG("Reading cached AoR data for AoR %s, cached from remote sdm %p",
                  aor.c_str(), sdm);
      remote_aor_pair = _cached_aors[sdm];
    }

    do
    {
      if (remote_aor_pair == NULL)
      {
        // LCOV_EXCL_START
        TRC_DEBUG("Hit an error reading AoR %s from the remote store, unable to update subscription %s",
                    aor.c_str(), new_subscription._to_tag.c_str());
        rc = Store::Status::ERROR;
        // LCOV_EXCL_STOP
      }
      else
      {
        // Attempt to recover in the case that CSeqs are out of sync between the
        // local and remote stores.
        if (remote_aor_pair->get_current()->_notify_cseq < local_notify_cseq)
        {
          // If the remote CSeq is smaller, overwrite it with the local one.
          remote_aor_pair->get_current()->_notify_cseq = local_notify_cseq;
        }
        else if (remote_aor_pair->get_current()->_notify_cseq > local_notify_cseq)
        {
          // If the remote CSeq is larger, do not increment it. It's not easy to
          // test this with the current UT infrastructure.
          remote_aor_pair->get_current()->_notify_cseq -= 1; // LCOV_EXCL_LINE
        }

        update_subscription(subscription, new_subscription, aor, remote_aor_pair, _cached_aors);
        remote_aor_pair->get_current()->_associated_uris = *associated_uris;

        rc = sdm->set_aor_data(aor, SubscriberDataManager::EventTrigger::USER, remote_aor_pair, trail());
        if (rc == Store::DATA_CONTENTION)
        {
          TRC_DEBUG("Hit data contention attempting to write AoR %s to remote store", aor.c_str());
          remote_aor_pair = read_and_cache_from_store(sdm, aor, _cached_aors);
          if (remote_aor_pair == NULL)
          {
            // LCOV_EXCL_START We test behaviour on store error elsewhere,
            // and UT-ing this case is more effort than it's worth

            // We've hit an error in reading from the remote store, but we don't
            // take any action on this. Bail out and try the next store.
            TRC_DEBUG("Failed to read AoR from remote store");
            break;
            // LCOV_EXCL_STOP
          }
        }
      }
    }
    while (rc == Store::DATA_CONTENTION);
  }

  // Clear out the cached AoR data
  for (std::pair<SubscriberDataManager*, AoRPair*> cached_aor: _cached_aors)
  {
    delete cached_aor.second;
  }

 return status;
}

// Reads AoR data from the specified SDM, and stores the returned AoRPair in the
// _cached_aors map. Returns a pointer to the AoRPair if successful, or NULL if
// we failed the read.
// NOTE: Ownership of the AoRPair remains with the _cached_aors map; it does not
// pass over to the caller.
AoRPair* SubscriptionSproutletTsx::read_and_cache_from_store(
                       SubscriberDataManager* sdm,
                       std::string aor,
                       std::map<SubscriberDataManager*, AoRPair*>& _cached_aors)
{
  AoRPair* aor_pair = sdm->get_aor_data(aor, trail());

  if ((aor_pair == NULL) ||
      (aor_pair->get_current() == NULL))
  {
    // Failed to get data for the AoR because there is no connection
    // to the store. SAS logging is left to the SDM
    TRC_DEBUG("Failed to get AoR data for %s from store", aor.c_str());
    delete aor_pair;
    return NULL;
  }

  TRC_DEBUG("Retrieved AoR data %p. Storing in local cache for SDM %p", aor_pair, sdm);

  // Make sure we clean up the old data before caching the new AoR
  if (_cached_aors.find(sdm) != _cached_aors.end())
  {
    delete _cached_aors[sdm];
  }

  _cached_aors[sdm] = aor_pair;

  return aor_pair;
}


// Updates the AoRPair with the details of the new_subscription
// If the AoRPair doesn't contain any subscriptions, checks to see if any remote
// AoRs have subscription information we want to copy over
void SubscriptionSproutletTsx::update_subscription(
                  SubscriptionSproutlet* subscription,
                  AoR::Subscription& new_subscription,
                  std::string aor,
                  AoRPair* aor_pair,
                  std::map<SubscriberDataManager*, AoRPair*>& _cached_aors)
{
  if (aor_pair->get_current()->subscriptions().empty())
  {
    // If we don't have any subscriptions in the local AoR, read from remote
    // stores so that we can check them for any subscriptions. We only want to
    // perform the remote reads once, to avoid added latency.
    // The local AoR is added to the cache in the main function logic
    for (SubscriberDataManager* sdm : subscription->_remote_sdms)
    {
      // We want to read the remote AoR only once at this stage, so we check
      // if there's already an entry in the cache for it.
      if ((_cached_aors.find(sdm) == _cached_aors.end()) &&
          (sdm->has_servers()))
      {
        read_and_cache_from_store(sdm, aor, _cached_aors);
      }
    }

    // Now copy over any details from the first cached aor we have with any subscriptions
    for (std::pair<SubscriberDataManager*, AoRPair*> cached_aor: _cached_aors)
    {
      if (cached_aor.second != aor_pair)
      {
        if (!cached_aor.second->get_current()->subscriptions().empty())
        {
          TRC_DEBUG("AoR contained no subscriptions, but a remote copy did; copying data across");

          // We don't want to overwrite the local CSeq value with that from the
          // remote, as the remote CSeq may have already been incremented, and
          // the local CSeq has not.
          int local_cseq = aor_pair->get_current()->_notify_cseq;

          aor_pair->get_current()->copy_aor(cached_aor.second->get_current());

          aor_pair->get_current()->_notify_cseq = local_cseq;
          break;
        }
      }
    }
  }

  // Find the appropriate subscription in the subscription list for this AoR. If it can't
  // be found a new empty subscription will be created for us by get_subscription.
  AoR::Subscription* current_subscription =
                aor_pair->get_current()->get_subscription(new_subscription._to_tag);

  // Update/create the subscription with the new details.
  current_subscription->_req_uri = new_subscription._req_uri;
  current_subscription->_route_uris = new_subscription._route_uris;
  current_subscription->_cid = new_subscription._cid;
  current_subscription->_to_uri = new_subscription._to_uri;
  current_subscription->_to_tag = new_subscription._to_tag;
  current_subscription->_from_uri = new_subscription._from_uri;
  current_subscription->_from_tag = new_subscription._from_tag;
  current_subscription->_refreshed = true;
  current_subscription->_expires = new_subscription._expires;
}

void SubscriptionSproutletTsx::log_subscriptions(const std::string& aor_name,
                                                 AoR* aor_data)
{
  TRC_DEBUG("Subscriptions for %s", aor_name.c_str());
  for (AoR::Subscriptions::const_iterator i = aor_data->subscriptions().begin();
       i != aor_data->subscriptions().end();
       ++i)
  {
    AoR::Subscription* subscription = i->second;

    TRC_DEBUG("%s URI=%s expires=%d from_uri=%s from_tag=%s to_uri=%s to_tag=%s call_id=%s",
              i->first.c_str(),
              subscription->_req_uri.c_str(),
              subscription->_expires,
              subscription->_from_uri.c_str(),
              subscription->_from_tag.c_str(),
              subscription->_to_uri.c_str(),
              subscription->_to_tag.c_str(),
              subscription->_cid.c_str());
  }
}
