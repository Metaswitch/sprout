/**
 * @file subscription.cpp
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
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
#include <pjlib-util.h>
#include <pjlib.h>
#include "pjsip-simple/evsub.h"
#include <pjsip-simple/evsub_msg.h>
}

#include <map>
#include <list>
#include <string>

#include "utils.h"
#include "pjutils.h"
#include "stack.h"
#include "memcachedstore.h"
#include "hssconnection.h"
#include "hss_sip_mapping.h"
#include "subscription.h"
#include "log.h"
#include "notify_utils.h"
#include "constants.h"
#include "sas.h"
#include "sproutsasevent.h"
#include "uri_classifier.h"

static SubscriberDataManager* sdm;
static std::vector<SubscriberDataManager*> remote_sdms;

// Connection to the HSS service for retrieving associated public URIs.
static HSSConnection* hss;

/// Factory for generating ACR messages for Rf billing.
static ACRFactory* acr_factory;

static AnalyticsLogger* analytics;

static int max_expires;

/// Default value for a subscription expiry. RFC3860 has this as 3761 seconds.
static const int DEFAULT_SUBSCRIPTION_EXPIRES = 3761;

uint32_t id_deployment = 0;
uint32_t id_instance = 0;

//
// mod_subscription is the module to receive SIP SUBSCRIBE requests.  This
// must get invoked before the proxy UA module.
//
static pj_bool_t subscription_on_rx_request(pjsip_rx_data *rdata);

pjsip_module mod_subscription =
{
  NULL, NULL,                          // prev, next
  pj_str("mod-subscription"),          // Name
  -1,                                  // Id
  PJSIP_MOD_PRIORITY_UA_PROXY_LAYER+2, // Priority
  NULL,                                // load()
  NULL,                                // start()
  NULL,                                // stop()
  NULL,                                // unload()
  &subscription_on_rx_request,         // on_rx_request()
  NULL,                                // on_rx_response()
  NULL,                                // on_tx_request()
  NULL,                                // on_tx_response()
  NULL,                                // on_tsx_state()
};

void log_subscriptions(const std::string& aor_name,
                       SubscriberDataManager::AoR* aor_data)
{
  TRC_DEBUG("Subscriptions for %s", aor_name.c_str());
  for (SubscriberDataManager::AoR::Subscriptions::const_iterator i =
         aor_data->subscriptions().begin();
       i != aor_data->subscriptions().end();
       ++i)
  {
    SubscriberDataManager::AoR::Subscription* subscription = i->second;

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

/// Write to the registration store. If we can't find the AoR pair in the
/// primary SDM, we will either use the backup_aor or we will try and look up
/// the AoR pair in the backup SDMs. Therefore either the backup_aor should be
/// NULL, or backup_sdms should be empty.
SubscriberDataManager::AoRPair* write_subscriptions_to_store(
                   SubscriberDataManager* primary_sdm,        ///<store to write to
                   std::string aor,                           ///<address of record to write to
                   std::vector<std::string> irs_impus,        ///(IMPUs in Implicit Registration Set
                   pjsip_rx_data* rdata,                      ///<received message to read headers from
                   int now,                                   ///<time now
                   SubscriberDataManager::AoRPair* backup_aor,///<backup data if no entry in store
                   std::vector<SubscriberDataManager*> backup_sdms,
                                                              ///<backup stores to read from if no entry in store and no backup data
                   SAS::TrailId trail,                        ///<SAS trail
                   std::string public_id,                     ///
                   bool send_ok,                              ///<Should we create an OK
                   ACR* acr,                                  ///
                   std::deque<std::string> ccfs,              ///
                   std::deque<std::string> ecfs)              ///
{
  // Parse the headers
  std::string cid = PJUtils::pj_str_to_string((const pj_str_t*)&rdata->msg_info.cid->id);;
  pjsip_msg *msg = rdata->msg_info.msg;
  pjsip_expires_hdr* expires = (pjsip_expires_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_EXPIRES, NULL);
  pjsip_fromto_hdr* from = (pjsip_fromto_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_FROM, NULL);
  pjsip_fromto_hdr* to = (pjsip_fromto_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_TO, NULL);

  // The registration store uses optimistic locking to avoid concurrent
  // updates to the same AoR conflicting.  This means we have to loop
  // reading, updating and writing the AoR until the write is successful.
  bool backup_aor_alloced = false;
  int expiry = 0;
  pj_status_t status = PJ_FALSE;
  Store::Status set_rc;
  SubscriberDataManager::AoRPair* aor_pair = NULL;
  std::string subscription_contact;
  std::string subscription_id;

  do
  {
    // delete NULL is safe, so we can do this on every iteration.
    delete aor_pair;

    // Find the current subscriptions for the AoR.
    aor_pair = primary_sdm->get_aor_data(aor, trail);
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
        SubscriberDataManager::AoRPair* local_backup_aor = NULL;

        while ((it != backup_sdms.end()) && (!found_subscription))
        {
          if ((*it)->has_servers())
          {
            local_backup_aor = (*it)->get_aor_data(aor, trail);

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
        aor_pair->get_current()->copy_subscriptions_and_bindings(backup_aor->get_current());
      }
    }

    pjsip_contact_hdr* contact = (pjsip_contact_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_CONTACT, NULL);

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
        subscription_id = std::to_string(Utils::generate_unique_integer(id_deployment,
                                                                        id_instance));
      }

      TRC_DEBUG("Subscription identifier = %s", subscription_id.c_str());

      // Find the appropriate subscription in the subscription list for this AoR. If it can't
      // be found a new empty subscription is created.
      SubscriberDataManager::AoR::Subscription* subscription =
                    aor_pair->get_current()->get_subscription(subscription_id);

      // Update/create the subscription.
      subscription->_req_uri = contact_uri;

      subscription->_route_uris.clear();
      pjsip_route_hdr* route_hdr = (pjsip_route_hdr*)pjsip_msg_find_hdr(msg,
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
        route_hdr = (pjsip_route_hdr*)pjsip_msg_find_hdr(msg,
                                                         PJSIP_H_RECORD_ROUTE,
                                                         route_hdr->next);
      }

      subscription->_cid = cid;
      subscription->_to_uri = PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, to->uri);
      subscription->_to_tag = subscription_id;
      subscription->_from_uri = PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, from->uri);
      subscription->_from_tag = PJUtils::pj_str_to_string(&from->tag);

      // Calculate the expiry period for the subscription.
      expiry = (expires != NULL) ? expires->ivalue : DEFAULT_SUBSCRIPTION_EXPIRES;

      if (expiry > max_expires)
      {
        // Expiry is too long, set it to the maximum.
        expiry = max_expires;
      }

      subscription->_expires = now + expiry;
      subscription_contact = subscription->_req_uri;
    }

    // Build and send the reply.
    pjsip_tx_data* tdata = NULL;

    if (send_ok)
    {
      status = PJUtils::create_response(stack_data.endpt, rdata, PJSIP_SC_OK, NULL, &tdata);
      if (status != PJ_SUCCESS)
      {
        // LCOV_EXCL_START - don't know how to get PJSIP to fail to create a response
        TRC_ERROR("Error building SUBSCRIBE %d response %s", PJSIP_SC_OK,
                  PJUtils::pj_status_to_string(status).c_str());

        SAS::Event event(trail, SASEvent::SUBSCRIBE_FAILED, 0);
        event.add_var_param(public_id);
        std::string error_msg = "Error building SUBSCRIBE (" + std::to_string(PJSIP_SC_OK) + ") " + PJUtils::pj_status_to_string(status);
        event.add_var_param(error_msg);
        SAS::report_event(event);

        PJUtils::respond_stateless(stack_data.endpt,
                                   rdata,
                                   PJSIP_SC_INTERNAL_SERVER_ERROR,
                                   NULL,
                                   NULL,
                                   NULL);
        delete acr;
        delete aor_pair;
        return PJ_FALSE;
        // LCOV_EXCL_STOP
      }

      // Add expires headers
      pjsip_expires_hdr* expires_hdr = pjsip_expires_hdr_create(tdata->pool, expiry);
      pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)expires_hdr);

      // Add the to tag to the response
      pjsip_to_hdr *to = (pjsip_to_hdr*) pjsip_msg_find_hdr(tdata->msg,
                                                            PJSIP_H_TO,
                                                            NULL);
      pj_strdup2(tdata->pool, &to->tag, subscription_id.c_str());

      // Add a P-Charging-Function-Addresses header to the successful SUBSCRIBE
      // response containing the charging addresses returned by the HSS.
      PJUtils::add_pcfa_header(tdata->msg,
                               tdata->pool,
                               ccfs,
                               ecfs,
                               false);

      // Pass the response to the ACR.
      acr->tx_response(tdata->msg);
    }

    // Try to write the AoR back to the store.
    bool unused;
    set_rc = primary_sdm->set_aor_data(aor, irs_impus, aor_pair, trail, unused, rdata, tdata);

    if (set_rc != Store::OK)
    {
      delete aor_pair; aor_pair = NULL;
    }
  }
  while (set_rc == Store::DATA_CONTENTION);

  if (analytics != NULL)
  {
    // Generate an analytics log for this subscription update.
    analytics->subscription(aor,
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

void process_subscription_request(pjsip_rx_data* rdata)
{
  int st_code = PJSIP_SC_OK;

  SAS::TrailId trail = get_trail(rdata);

  // Get the URI from the To header and check it is a SIP or SIPS URI.
  pjsip_uri* uri = (pjsip_uri*)pjsip_uri_get_uri(rdata->msg_info.to->uri);
  pjsip_msg *msg = rdata->msg_info.msg;
  pjsip_expires_hdr* expires = (pjsip_expires_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_EXPIRES, NULL);
  int expiry = (expires != NULL) ? expires->ivalue : DEFAULT_SUBSCRIPTION_EXPIRES;

  if (expiry > max_expires)
  {
    // Expiry is too long, set it to the maximum.
    expiry = max_expires;
  }

  if ((!PJSIP_URI_SCHEME_IS_SIP(uri)) && (!PJSIP_URI_SCHEME_IS_TEL(uri)))
  {
    // Reject a non-SIP/TEL URI with 404 Not Found (RFC3261 isn't clear
    // whether 404 is the right status code - it says 404 should be used if
    // the AoR isn't valid for the domain in the RequestURI).
    TRC_ERROR("Rejecting subscribe request using invalid URI scheme");

    SAS::Event event(trail, SASEvent::SUBSCRIBE_FAILED_EARLY_URLSCHEME, 0);
    SAS::report_event(event);

    PJUtils::respond_stateless(stack_data.endpt,
                               rdata,
                               PJSIP_SC_NOT_FOUND,
                               NULL,
                               NULL,
                               NULL);
    return;
  }

  bool emergency_subscription = false;

  pjsip_contact_hdr* contact_hdr = (pjsip_contact_hdr*)
                 pjsip_msg_find_hdr(msg, PJSIP_H_CONTACT, NULL);

  while (contact_hdr != NULL)
  {
    emergency_subscription = PJUtils::is_emergency_registration(contact_hdr);

    if (!emergency_subscription)
    {
      break;
    }

    contact_hdr = (pjsip_contact_hdr*) pjsip_msg_find_hdr(rdata->msg_info.msg,
                                                          PJSIP_H_CONTACT,
                                                          contact_hdr->next);
  }

  if (emergency_subscription)
  {
    // Reject a subscription with a Contact header containing a contact address
    // that's been registered for emergency service.
    TRC_ERROR("Rejecting subscribe request from emergency registration");

    SAS::Event event(trail, SASEvent::SUBSCRIBE_FAILED_EARLY_EMERGENCY, 0);
    SAS::report_event(event);

    // Allow-Events is a mandatory header on 489 responses.
    pjsip_generic_string_hdr* allow_events_hdr = pjsip_generic_string_hdr_create(rdata->tp_info.pool, &STR_ALLOW_EVENTS, &STR_REG);

    PJUtils::respond_stateless(stack_data.endpt,
                               rdata,
                               PJSIP_SC_BAD_EVENT,
                               NULL,
                               (pjsip_hdr*)allow_events_hdr,
                               NULL);
    return;
  }

  // Create an ACR for the request.  The node role is always considered
  // originating for SUBSCRIBE requests.
  ACR* acr = acr_factory->get_acr(get_trail(rdata),
                                  ACR::CALLING_PARTY,
                                  ACR::NODE_ROLE_ORIGINATING);
  acr->rx_request(rdata->msg_info.msg, rdata->pkt_info.timestamp);

  // Canonicalize the public ID from the URI in the To header.
  std::string public_id = PJUtils::public_id_from_uri(uri);

  TRC_DEBUG("Process SUBSCRIBE for public ID %s", public_id.c_str());

  // Get the call identifier from the headers.
  std::string cid = PJUtils::pj_str_to_string((const pj_str_t*)&rdata->msg_info.cid->id);;

  // Add SAS markers to the trail attached to the message so the trail
  // becomes searchable.
  SAS::Event event(trail, SASEvent::SUBSCRIBE_START, 0);
  event.add_var_param(public_id);
  SAS::report_event(event);

  TRC_DEBUG("Report SAS start marker - trail (%llx)", trail);
  SAS::Marker start_marker(trail, MARKER_ID_START, 1u);
  SAS::report_marker(start_marker);

  // Query the HSS for the associated URIs.
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifc_map;

  // Subscriber must have already registered to be making a subscribe
  std::string state;
  std::deque<std::string> ccfs;
  std::deque<std::string> ecfs;
  HTTPCode http_code = hss->get_registration_data(public_id,
                                                  state,
                                                  ifc_map,
                                                  uris,
                                                  ccfs,
                                                  ecfs,
                                                  trail);

  if (process_hss_sip_failure(http_code,
                              state,
                              rdata,
                              stack_data,
                              NULL,
                              "SUBSCRIBE"))
  {
    delete acr;
    return;
  }

  // Determine the AOR from the first entry in the uris array.
  std::string aor = uris.front();

  TRC_DEBUG("aor = %s", aor.c_str());
  TRC_DEBUG("SUBSCRIBE for public ID %s uses AOR %s", public_id.c_str(), aor.c_str());

  // Get the system time in seconds for calculating absolute expiry times.
  int now = time(NULL);

  // Write to the local store, checking the remote stores if there is no entry locally.
  // If the write to the local store succeeds, then write to the remote stores.
  SubscriberDataManager::AoRPair* aor_pair =
                              write_subscriptions_to_store(sdm,
                                                           aor,
                                                           uris,
                                                           rdata,
                                                           now,
                                                           NULL,
                                                           remote_sdms,
                                                           trail,
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
    for (std::vector<SubscriberDataManager*>::iterator it = remote_sdms.begin();
         it != remote_sdms.end();
         ++it)
    {
      if ((*it)->has_servers())
      {
        SubscriberDataManager::AoRPair* remote_aor_pair =
          write_subscriptions_to_store(*it,
                                       aor,
                                       uris,
                                       rdata,
                                       now,
                                       aor_pair,
                                       {},
                                       trail,
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
    pjsip_tx_data* tdata;
    pj_status_t status = PJUtils::create_response(stack_data.endpt,
                                                  rdata,
                                                  st_code,
                                                  NULL,
                                                  &tdata);

    if (status != PJ_SUCCESS)
    {
      // LCOV_EXCL_START - don't know how to get PJSIP to fail to create a response
      TRC_ERROR("Error building SUBSCRIBE %d response %s", st_code,
                PJUtils::pj_status_to_string(status).c_str());
      SAS::Event event(trail, SASEvent::SUBSCRIBE_FAILED, 0);
      event.add_var_param(public_id);
      std::string error_msg = "Error building SUBSCRIBE (" + std::to_string(st_code) + ") " + PJUtils::pj_status_to_string(status);
      event.add_var_param(error_msg);
      SAS::report_event(event);

      PJUtils::respond_stateless(stack_data.endpt,
                                 rdata,
                                 PJSIP_SC_INTERNAL_SERVER_ERROR,
                                 NULL,
                                 NULL,
                                 NULL);
      delete acr;
      return;
      // LCOV_EXCL_STOP
    }

    // Add the to tag to the response
    pjsip_to_hdr *to = (pjsip_to_hdr*) pjsip_msg_find_hdr(tdata->msg,
                                                          PJSIP_H_TO,
                                                          NULL);
    std::string subscription_id = PJUtils::pj_str_to_string(&to->tag);

    if (subscription_id == "")
    {
      // If there's no to tag, generate an unique one
      // LCOV_EXCL_START
      subscription_id = std::to_string(Utils::generate_unique_integer(id_deployment,
                                                                      id_instance));
      // LCOV_EXCL_STOP
    }

    pj_strdup2(tdata->pool, &to->tag, subscription_id.c_str());

    // Pass the response to the ACR.
    acr->tx_response(tdata->msg);

    // Send the response.
    status = pjsip_endpt_send_response2(stack_data.endpt, rdata, tdata, NULL, NULL);
  }

  SAS::Event sub_accepted(trail, SASEvent::SUBSCRIBE_ACCEPTED, 0);
  SAS::report_event(sub_accepted);

  // Send the ACR and delete it.
  acr->send();
  delete acr;

  TRC_DEBUG("Report SAS end marker - trail (%llx)", trail);
  SAS::Marker end_marker(trail, MARKER_ID_END, 1u);
  SAS::report_marker(end_marker);

  delete aor_pair;
}

// Check whether this request should be absorbed by the subscription module
pj_bool_t request_acceptable_to_subscription_module(pjsip_msg* msg,
                                                    SAS::TrailId trail)
{
  if (pjsip_method_cmp(&msg->line.req.method, pjsip_get_subscribe_method()))
  {
    // This isn't a SUBSCRIBE, so this module can't process it.
    return PJ_FALSE;
  }

  URIClass uri_class = URIClassifier::classify_uri(msg->line.req.uri);
  TRC_INFO("URI class is %d", uri_class);
  if (((uri_class != NODE_LOCAL_SIP_URI) &&
       (uri_class != HOME_DOMAIN_SIP_URI)) ||
      !PJUtils::check_route_headers(msg))
  {
    TRC_DEBUG("Not processing subscription request not targeted at this domain or node");
    if (trail != 0)
    {
      // LCOV_EXCL_START - No SAS events in UT
      SAS::Event event(trail, SASEvent::SUBSCRIBE_FAILED_EARLY_DOMAIN, 0);
      SAS::report_event(event);
      // LCOV_EXCL_STOP
    }
    return PJ_FALSE;
  }

  // We now know we have a SUBSCRIBE request targeted at the home domain
  // or specifically at this node. Check whether it should be processed
  // by this module or passed up to an AS.

  // A valid subscription must have the Event header set to "reg". This is case-sensitive
  pj_str_t event_name = pj_str("Event");
  pjsip_event_hdr* event = (pjsip_event_hdr*)pjsip_msg_find_hdr_by_name(msg, &event_name, NULL);

  if (!event || (PJUtils::pj_str_to_string(&event->event_type) != "reg"))
  {
    // The Event header is missing or doesn't match "reg"
    TRC_DEBUG("Not processing subscription request that's not for the 'reg' package");

    if (trail != 0)
    {
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
    }

    return PJ_FALSE;
  }

  // Accept header may be present - if so must include the application/reginfo+xml
  pjsip_accept_hdr* accept = (pjsip_accept_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_ACCEPT, NULL);
  if (accept)
  {
    bool found = false;
    pj_str_t reginfo = pj_str("application/reginfo+xml");
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

      if (trail != 0)
      {
        // LCOV_EXCL_START - No SAS events in UT
        SAS::Event event(trail, SASEvent::SUBSCRIBE_FAILED_EARLY_ACCEPT, 0);
        event.add_var_param(accept_hdr_str);
        SAS::report_event(event);
        // LCOV_EXCL_STOP
      }

      return PJ_FALSE;
    }
  }

  return PJ_TRUE;
}

// Reject request unless it's a SUBSCRIBE targeted at the home domain / this node.
pj_bool_t subscription_on_rx_request(pjsip_rx_data *rdata)
{
  SAS::TrailId trail = get_trail(rdata);

  // SAS log the start of processing by this module
  SAS::Event event(trail, SASEvent::BEGIN_SUBSCRIPTION_MODULE, 0);
  SAS::report_event(event);

  if (rdata->tp_info.transport->local_name.port != stack_data.scscf_port)
  {
    // Not an S-CSCF, so don't handle SUBSCRIBEs.
    return PJ_FALSE; // LCOV_EXCL_LINE
  }

  pj_bool_t accept =
          request_acceptable_to_subscription_module(rdata->msg_info.msg, trail);

  if (accept)
  {
    process_subscription_request(rdata);
    return PJ_TRUE;
  }
  else
  {
    return PJ_FALSE;
  }
}

pj_status_t init_subscription(SubscriberDataManager* reg_sdm,
                              std::vector<SubscriberDataManager*> reg_remote_sdm,
                              HSSConnection* hss_connection,
                              ACRFactory* rfacr_factory,
                              AnalyticsLogger* analytics_logger,
                              int cfg_max_expires)
{
  pj_status_t status;

  sdm = reg_sdm;
  remote_sdms = reg_remote_sdm;
  hss = hss_connection;
  acr_factory = rfacr_factory;
  analytics = analytics_logger;
  max_expires = cfg_max_expires;

  status = pjsip_endpt_register_module(stack_data.endpt, &mod_subscription);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

  return status;
}

void destroy_subscription()
{
  pjsip_endpt_unregister_module(stack_data.endpt, &mod_subscription);
}
