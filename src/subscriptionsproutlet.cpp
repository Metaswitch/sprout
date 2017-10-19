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
                                             const std::string& next_hop_service,
                                             SubscriberDataManager* sdm,
                                             std::vector<SubscriberDataManager*> remote_sdms,
                                             HSSConnection* hss_connection,
                                             ACRFactory* acr_factory,
                                             AnalyticsLogger* analytics_logger,
                                             int cfg_max_expires) :
  Sproutlet(name, port, uri),
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
  pjsip_sip_uri* base_uri = helper->get_routing_uri(req);
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
  ForwardingSproutletTsx(subscription, next_hop_service),
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

  TRC_DEBUG("Report SAS start marker - trail (%llx)", trail_id);
  SAS::Marker start_marker(trail_id, MARKER_ID_START, 1u);
  SAS::report_marker(start_marker);

  // Query the HSS for the associated URIs.
  AssociatedURIs associated_uris = {};
  std::map<std::string, Ifcs> ifc_map;

  // Subscriber must have already registered to be making a subscribe
  std::string state;
  std::deque<std::string> ccfs;
  std::deque<std::string> ecfs;
  HTTPCode http_code = _subscription->_hss->get_registration_data(public_id,
                                                               state,
                                                               ifc_map,
                                                               associated_uris,
                                                               ccfs,
                                                               ecfs,
                                                               trail_id);
  st_code = determine_hss_sip_response(http_code, state, "SUBSCRIBE");

  if (st_code != PJSIP_SC_OK)
  {
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
  if (!associated_uris.get_default_impu(aor, false))
  {
    pjsip_msg* rsp = create_response(req, PJSIP_SC_FORBIDDEN);
    send_response(rsp);
    free_msg(req);
    delete acr;
    return;
  }

  TRC_DEBUG("aor = %s", aor.c_str());
  TRC_DEBUG("SUBSCRIBE for public ID %s uses AOR %s", public_id.c_str(), aor.c_str());

  // Get the system time in seconds for calculating absolute expiry times.
  int now = time(NULL);

  // Write to the local store, checking the remote stores if there is no entry locally.
  // If the write to the local store succeeds, then write to the remote stores.
  AoRPair* aor_pair = write_subscriptions_to_store(_subscription->_sdm,
                                                   aor,
                                                   &associated_uris,
                                                   req,
                                                   now,
                                                   NULL,
                                                   _subscription->_remote_sdms,
                                                   public_id,
                                                   true,
                                                   acr,
                                                   ccfs,
                                                   ecfs);

  if (aor_pair != NULL)
  {
    // Log the subscriptions.
    log_subscriptions(aor, aor_pair->get_current());

    // If we have any remote stores, try to store this there too.  We don't worry
    // about failures in this case.
    for (std::vector<SubscriberDataManager*>::iterator it = _subscription->_remote_sdms.begin();
         it != _subscription->_remote_sdms.end();
         ++it)
    {
      if ((*it)->has_servers())
      {
        AoRPair* remote_aor_pair = write_subscriptions_to_store(*it,
                                                                aor,
                                                                &associated_uris,
                                                                req,
                                                                now,
                                                                aor_pair,
                                                                {},
                                                                public_id,
                                                                false,
                                                                acr,
                                                                ccfs,
                                                                ecfs);
        delete remote_aor_pair;
      }
    }
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
    std::string subscription_id = PJUtils::pj_str_to_string(&to->tag);

    if (subscription_id == "")
    {
      // If there's no to tag, generate an unique one.
      // TODO Should use unique deployment and instance IDs here.

      // LCOV_EXCL_START
      subscription_id = std::to_string(Utils::generate_unique_integer(0, 0));
      // LCOV_EXCL_STOP
    }

    pj_strdup2(get_pool(rsp), &to->tag, subscription_id.c_str());

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

  TRC_DEBUG("Report SAS end marker - trail (%llx)", trail_id);
  SAS::Marker end_marker(trail_id, MARKER_ID_END, 1u);
  SAS::report_marker(end_marker);

  free_msg(req);

  delete aor_pair;
}

/// Write to the registration store. If we can't find the AoR pair in the
/// primary SDM, we will either use the backup_aor or we will try and look up
/// the AoR pair in the backup SDMs. Therefore either the backup_aor should be
/// NULL, or backup_sdms should be empty.
AoRPair* SubscriptionSproutletTsx::write_subscriptions_to_store(
                   SubscriberDataManager* primary_sdm,        ///<store to write to
                   std::string aor,                           ///<address of record to write to
                   AssociatedURIs* associated_uris,
                                                              ///<IMPUs associated with this IRS
                   pjsip_msg* req,                            ///<received request to read headers from
                   int now,                                   ///<time now
                   AoRPair* backup_aor,                       ///<backup data if no entry in store
                   std::vector<SubscriberDataManager*> backup_sdms,
                                                              ///<backup stores to read from if no entry in store and no backup data
                   std::string public_id,                     ///
                   bool is_primary,                           ///<Should we create an OK
                   ACR* acr,                                  ///
                   std::deque<std::string> ccfs,              ///
                   std::deque<std::string> ecfs)              ///
{
  // Parse the headers
  std::string cid = PJUtils::pj_str_to_string(&PJSIP_MSG_CID_HDR(req)->id);
  pjsip_expires_hdr* expires = (pjsip_expires_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_EXPIRES, NULL);
  pjsip_fromto_hdr* from = (pjsip_fromto_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_FROM, NULL);
  pjsip_fromto_hdr* to = (pjsip_fromto_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_TO, NULL);

  // The registration store uses optimistic locking to avoid concurrent
  // updates to the same AoR conflicting.  This means we have to loop
  // reading, updating and writing the AoR until the write is successful.
  bool backup_aor_alloced = false;
  int expiry = 0;
  Store::Status set_rc;
  AoRPair* aor_pair = NULL;
  std::string subscription_contact;
  std::string subscription_id;

  do
  {
    // delete NULL is safe, so we can do this on every iteration.
    delete aor_pair;

    // Find the current subscriptions for the AoR.
    aor_pair = primary_sdm->get_aor_data(aor, trail());
    TRC_DEBUG("Retrieved AoR data %p", aor_pair);

    if ((aor_pair == NULL) ||
        (aor_pair->get_current() == NULL))
    {
      // Failed to get data for the AoR because there is no connection
      // to the store.
      // LCOV_EXCL_START - local store (used in testing) never fails
      TRC_ERROR("Failed to get AoR subscriptions for %s from store", aor.c_str());
      break;
      // LCOV_EXCL_STOP
    }

    // If we don't have any subscriptions, try the backup AoR and/or stores.
    if (aor_pair->get_current()->subscriptions().empty())
    {
      bool found_subscription = false;

      if ((backup_aor != NULL) &&
          (backup_aor->current_contains_subscriptions()))
      {
        found_subscription = true;
      }
      else
      {
        std::vector<SubscriberDataManager*>::iterator it = backup_sdms.begin();
        AoRPair* local_backup_aor = NULL;

        while ((it != backup_sdms.end()) && (!found_subscription))
        {
          if ((*it)->has_servers())
          {
            local_backup_aor = (*it)->get_aor_data(aor, trail());

            if ((local_backup_aor != NULL) &&
                (local_backup_aor->current_contains_subscriptions()))
            {
              // LCOV_EXCL_START - this code is very similar to code in handlers.cpp and is unit tested there.
              found_subscription = true;
              backup_aor = local_backup_aor;

              // Flag that we have allocated the memory for the backup pair so
              // that we can tidy it up later.
              backup_aor_alloced = true;
              // LCOV_EXCL_STOP
            }
          }

          if (!found_subscription)
          {
            ++it;

            if (local_backup_aor != NULL)
            {
              delete local_backup_aor;
              local_backup_aor = NULL;
            }
          }
        }
      }

      if (found_subscription)
      {
        aor_pair->get_current()->copy_aor(backup_aor->get_current());
      }
    }

    pjsip_contact_hdr* contact = (pjsip_contact_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_CONTACT, NULL);

    if (contact != NULL)
    {
      std::string contact_uri;
      pjsip_uri* uri = (contact->uri != NULL) ?
                       (pjsip_uri*)pjsip_uri_get_uri(contact->uri) :
                       NULL;

      if ((uri != NULL) &&
          (PJSIP_URI_SCHEME_IS_SIP(uri)))
      {
        contact_uri = PJUtils::uri_to_string(PJSIP_URI_IN_CONTACT_HDR, uri);
      }

      subscription_id = PJUtils::pj_str_to_string(&to->tag);

      if (subscription_id == "")
      {
        // If there's no to tag, generate an unique one
        // TODO: Should use unique deployment and instance IDs here.
        subscription_id = std::to_string(Utils::generate_unique_integer(0, 0));
      }

      TRC_DEBUG("Subscription identifier = %s", subscription_id.c_str());

      // Find the appropriate subscription in the subscription list for this AoR. If it can't
      // be found a new empty subscription is created.
      AoR::Subscription* subscription =
                    aor_pair->get_current()->get_subscription(subscription_id);

      // Update/create the subscription.
      subscription->_req_uri = contact_uri;

      subscription->_route_uris.clear();
      pjsip_route_hdr* route_hdr = (pjsip_route_hdr*)pjsip_msg_find_hdr(req,
                                                                        PJSIP_H_RECORD_ROUTE,
                                                                        NULL);

      while (route_hdr)
      {
        std::string route = PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                                   route_hdr->name_addr.uri);
        TRC_DEBUG("Route header %s", route.c_str());
        // Add the route.
        subscription->_route_uris.push_back(route);
        // Look for the next header.
        route_hdr = (pjsip_route_hdr*)pjsip_msg_find_hdr(req,
                                                         PJSIP_H_RECORD_ROUTE,
                                                         route_hdr->next);
      }

      subscription->_cid = cid;
      subscription->_to_uri = PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, to->uri);
      subscription->_to_tag = subscription_id;
      subscription->_from_uri = PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, from->uri);
      subscription->_from_tag = PJUtils::pj_str_to_string(&from->tag);
      subscription->_refreshed = true;

      // Calculate the expiry period for the subscription.
      expiry = (expires != NULL) ?
        expires->ivalue : SubscriptionSproutlet::DEFAULT_SUBSCRIPTION_EXPIRES;

      if (expiry > _subscription->_max_expires)
      {
        // Expiry is too long, set it to the maximum.
        expiry = _subscription->_max_expires;
      }

      subscription->_expires = now + expiry;
      subscription_contact = subscription->_req_uri;
    }

    // Try to write the AoR back to the store.
    aor_pair->get_current()->_associated_uris = *associated_uris;
    set_rc = primary_sdm->set_aor_data(aor, 
                                       SubscriberDataManager::EventTrigger::DEREG_TIMEOUT,
                                       aor_pair, 
                                       trail()); 

    if (set_rc == Store::OK)
    {
      if (is_primary)
      {
        pjsip_msg* rsp = create_response(req, PJSIP_SC_OK);

        // Add expires headers
        pjsip_expires_hdr* expires_hdr = pjsip_expires_hdr_create(get_pool(rsp), expiry);
        pjsip_msg_add_hdr(rsp, (pjsip_hdr*)expires_hdr);

        // Add the to tag to the response
        pjsip_to_hdr *to = (pjsip_to_hdr*) pjsip_msg_find_hdr(rsp,
                                                              PJSIP_H_TO,
                                                              NULL);
        pj_strdup2(get_pool(rsp), &to->tag, subscription_id.c_str());

        // Add a P-Charging-Function-Addresses header to the successful SUBSCRIBE
        // response containing the charging addresses returned by the HSS.
        PJUtils::add_pcfa_header(rsp,
                                 get_pool(rsp),
                                 ccfs,
                                 ecfs,
                                 false);

        // Pass the response to the ACR.
        acr->tx_response(rsp);

        send_response(rsp);
      }
    }
    else
    {
      delete aor_pair; aor_pair = NULL;
    }
  }
  while (set_rc == Store::DATA_CONTENTION);

  if ((_subscription->_analytics != NULL) && (is_primary))
  {
    // Generate an analytics log for this subscription update.
    _subscription->_analytics->subscription(aor,
                                         subscription_id,
                                         subscription_contact,
                                         expiry);
  }

  // If we allocated the backup AoR, tidy up.
  if (backup_aor_alloced)
  {
    delete backup_aor; backup_aor = NULL; // LCOV_EXCL_LINE
  }

  return aor_pair;
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
