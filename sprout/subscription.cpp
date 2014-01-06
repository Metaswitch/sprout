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
}

//TODO decide on includes
// Common STL includes.
#include <cassert>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <queue>
#include <string>

#include "utils.h"
#include "sasevent.h"
#include "pjutils.h"
#include "stack.h"
#include "memcachedstore.h"
#include "hssconnection.h"
#include "ifchandler.h"
#include "subscription.h"
#include "constants.h"
#include "log.h"
#include "pjsip-simple/evsub.h"
#include "notify_utils.h"

static RegStore* store;
static RegStore* remote_store;

// Connection to the HSS service for retrieving associated public URIs.
static HSSConnection* hss;

static IfcHandler* ifchandler;

static AnalyticsLogger* analytics;

static int max_expires;

//
// mod_subscription is the module to receive SIP SUBSCRIBE requests.  This
// must get invoked before the proxy UA module.
//
static pj_bool_t subscription_on_rx_request(pjsip_rx_data *rdata);
//TODO decide if this is needed
//static void subscription_on_tsx_state(pjsip_transaction *tsx, pjsip_event *event);

pjsip_module mod_subscription =
{
  NULL, NULL,                          // prev, next
  pj_str("mod-subscription"),          // Name
  -1,                                  // Id
  PJSIP_MOD_PRIORITY_UA_PROXY_LAYER+1, // Priority
  NULL,                                // load()
  NULL,                                // start()
  NULL,                                // stop()
  NULL,                                // unload()
  &subscription_on_rx_request,         // on_rx_request()
  NULL,                                // on_rx_response()
  NULL,                                // on_tx_request()
  NULL,                                // on_tx_response()
  NULL,//&subscription_on_tsx_state,          // on_tsx_state()
};
//TODO decide if this is needed

void log_subscriptions(const std::string& aor_name, RegStore::AoR* aor_data)
{
  LOG_DEBUG("Subscriptions for %s", aor_name.c_str());
  for (RegStore::AoR::Subscriptions::const_iterator i = aor_data->subscriptions().begin();
       i != aor_data->subscriptions().end();
       ++i)
  {
    RegStore::AoR::Subscription* subscription = i->second;
    
    // TODO log out the route headers?
    LOG_DEBUG("%s URI=%s expires=%d from_uri=%s from_tag %s to_uri %s to_tag %s call_id %s",
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

/// Write to the registration store.
RegStore::AoR* write_subscriptions_to_store(RegStore* primary_store,           ///<store to write to
                                            std::string aor,                   ///<address of record to write to
                                            pjsip_rx_data* rdata,              ///<received message to read headers from
                                            int now,                           ///<time now
                                            int& expiry,                       ///<[out] longest expiry time
                                            bool& out_is_initial_subscription,
                                            RegStore::AoR* backup_aor,         ///<backup data if no entry in store
                                            RegStore* backup_store)            ///<backup store to read from if no entry in store and no backup data
{
  // Get the call identifier and the cseq number from the respective headers.
  std::string cid = PJUtils::pj_str_to_string((const pj_str_t*)&rdata->msg_info.cid->id);;

  // Find the expire headers in the message.
  pjsip_msg *msg = rdata->msg_info.msg;
  pjsip_expires_hdr* expires = (pjsip_expires_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_EXPIRES, NULL);
  pjsip_fromto_hdr* from = (pjsip_fromto_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_FROM, NULL);
  pjsip_fromto_hdr* to = (pjsip_fromto_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_TO, NULL);
  pjsip_cid_hdr* cidh = (pjsip_cid_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_CALL_ID, NULL);

  // The registration store uses optimistic locking to avoid concurrent
  // updates to the same AoR conflicting.  This means we have to loop
  // reading, updating and writing the AoR until the write is successful.
  RegStore::AoR* aor_data = NULL;
  bool backup_aor_alloced = false;
  bool is_initial_subscription = true;
  do
  {
    // delete NULL is safe, so we can do this on every iteration.
    delete aor_data;

    // Find the current subscriptions for the AoR.
    aor_data = primary_store->get_aor_data(aor);
    LOG_DEBUG("Retrieved AoR data %p", aor_data);

    if (aor_data == NULL)
    {
      // Failed to get data for the AoR because there is no connection
      // to the store.
      // LCOV_EXCL_START - local store (used in testing) never fails
      LOG_ERROR("Failed to get AoR subscriptions for %s from store", aor.c_str());
      break;
      // LCOV_EXCL_STOP
    }

    // If we don't have any subscriptions, try the backup AoR and/or store.
    if (aor_data->subscriptions().empty())
    {
      if ((backup_aor == NULL) &&
          (backup_store != NULL))
      {
        backup_aor = backup_store->get_aor_data(aor);
        backup_aor_alloced = (backup_aor != NULL);
      }

      if ((backup_aor != NULL) &&
          (!backup_aor->subscriptions().empty()))
      {
        for (RegStore::AoR::Subscriptions::const_iterator i = backup_aor->subscriptions().begin();
             i != backup_aor->subscriptions().end();
             ++i)
        {
          RegStore::AoR::Subscription* src = i->second;
          RegStore::AoR::Subscription* dst = aor_data->get_subscription(i->first);
          *dst = *src;
        }
      }
    }

    is_initial_subscription = is_initial_subscription && aor_data->subscriptions().empty();

    // Now loop through all the contacts.  If there are multiple contacts in
    // the contact header in the SIP message, pjsip parses them to separate
    // contact header structures.
    pjsip_contact_hdr* contact = (pjsip_contact_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_CONTACT, NULL);
    bool continued = true;
    std::list<std::string> contact_uris;

    while (contact != NULL)
    {
      if (contact->star)
      {
        // Wildcard contact, which can only be used to clear all subscriptions for
        // the AoR.
        // TODO decide what should happen here - maybe just reject the subscribe
        aor_data->clear();
        contact_uris.clear();
        continued = false;
        break;
      }

      pjsip_uri* uri = (contact->uri != NULL) ?
                       (pjsip_uri*)pjsip_uri_get_uri(contact->uri) :
                       NULL;

      if ((uri != NULL) &&
          (PJSIP_URI_SCHEME_IS_SIP(uri)))
      {
        // Add the contact uri to the list
        std::string contact_uri = PJUtils::uri_to_string(PJSIP_URI_IN_CONTACT_HDR, uri);
        contact_uris.push_back(contact_uri);
      }
      
      contact = (pjsip_contact_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_CONTACT, contact->next);
    }  

    if (continued)
    {
      std::string subscription_id = PJUtils::pj_str_to_string(&to->tag);
      if (subscription_id == "")
      {
        subscription_id = "testtest";
      }
      LOG_DEBUG(". subscription identifier = %s", subscription_id.c_str());

      // Find the appropriate subscription in the subscription list for this AoR.
      RegStore::AoR::Subscription* subscription = aor_data->get_subscription(subscription_id);

      if (cid != subscription->_cid)
      {
        // Either this is a new subscription or it's an update to an existing subscription.
        subscription->_req_uri = contact_uris.front();

        subscription->_route_uris.clear();
        pjsip_route_hdr* route_hdr = (pjsip_route_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_ROUTE, NULL);
        while (route_hdr)
        {
          std::string route = PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR, route_hdr->name_addr.uri);
          LOG_DEBUG("Route header %s", route.c_str());

          // Add the route.
          subscription->_route_uris.push_back(route);

          // Look for the next header.
          route_hdr = (pjsip_route_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_ROUTE, route_hdr->next);
        }

        subscription->_cid = cid;
        subscription->_from_uri = PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, from->uri);
        subscription->_from_tag = subscription_id;//PJUtils::pj_str_to_string(&from->tag);
        subscription->_to_uri =  PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, to->uri);
        subscription->_to_tag = PJUtils::pj_str_to_string(&to->tag);


        // TODO not right here  
        // Calculate the expiry period for the subscription.
        expiry = 3761;//(contact->expires != -1) ? contact->expires :
               //  (expires != NULL) ? expires->ivalue :
               //  3761;

        subscription->_expires = now + expiry;

        pjsip_tx_data* tdata;
        //pj_str_t body = NotifyUtils::create_body(true);       

        // first create the request with a null body string, then add the body
        pj_status_t status = NotifyUtils::create_request_from_subscription(tdata, subscription, NULL);

        // each notify will have a single subscription and some (or none) bindings to form the body
        const RegStore::AoR::Bindings& bindings = aor_data->bindings();
        // TODO set the correct doc_state and reg_state
        tdata->msg->body = NotifyUtils::notify_create_body(tdata->pool, aor, subscription, bindings, NotifyUtils::FULL, NotifyUtils::ACTIVE );

        // TODO include the bindings - or split into seperate function that returns text. Always will be a full subscription
         // on the first subscribe

//  pjsip_tx_data_add_ref(tdata2);
       /* 
        status = pjsip_endpt_create_request_from_hdr(stack_data.endpt, 
                                                                  pjsip_get_notify_method(), 
                                                                  to->uri,
                                                                  from,
                                                                  to, 
                                                                  (pjsip_contact_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_CONTACT, NULL),
                                                                  cidh,
                                                                  1,//aor_data->_notify_cseq, 
                                                                  NULL, 
                                                                  &tdata);
	*/
//  pjsip_tx_data_dec_ref(tdata2);

        if (analytics != NULL)
        {
          // Generate an analytics log for this subscription update.
          analytics->subscription(aor, subscription_id, contact_uris.front(), expiry);
        }
      }
    }
  }
  while (!primary_store->set_aor_data(aor, aor_data));

  // If we allocated the backup AoR, tidy up.
  if (backup_aor_alloced)
  {
    delete backup_aor;
  }

  out_is_initial_subscription = is_initial_subscription;
  return aor_data;
}

void process_subscription_request(pjsip_rx_data* rdata)
{
  pj_status_t status;
  int st_code = PJSIP_SC_OK;

  // Get the URI from the To header and check it is a SIP or SIPS URI.
  pjsip_uri* uri = (pjsip_uri*)pjsip_uri_get_uri(rdata->msg_info.to->uri);

  if (!PJSIP_URI_SCHEME_IS_SIP(uri))
  {
    // Reject a non-SIP/SIPS URI with 404 Not Found (RFC3261 isn't clear
    // whether 404 is the right status code - it says 404 should be used if
    // the AoR isn't valid for the domain in the RequestURI).
    // LCOV_EXCL_START
    LOG_ERROR("Rejecting subscribe request using non SIP URI");
    PJUtils::respond_stateless(stack_data.endpt,
                               rdata,
                               PJSIP_SC_NOT_FOUND,
                               NULL,
                               NULL,
                               NULL);
    return;
    // LCOV_EXCL_STOP
  }

  // Canonicalize the public ID from the URI in the To header.
  std::string public_id = PJUtils::aor_from_uri((pjsip_sip_uri*)uri);
  LOG_DEBUG("Process SUBSCRIBE for public ID %s", public_id.c_str());

  // Get the call identifier from the headers.
  std::string cid = PJUtils::pj_str_to_string((const pj_str_t*)&rdata->msg_info.cid->id);;
  //pjsip_msg *msg = rdata->msg_info.msg;

  // Add SAS markers to the trail attached to the message so the trail
  // becomes searchable.
  SAS::TrailId trail = get_trail(rdata);
  LOG_DEBUG("Report SAS start marker - trail (%llx)", trail);
  SAS::Marker start_marker(trail, MARKER_ID_START, 1u);
  SAS::report_marker(start_marker);

  SAS::Marker calling_dn(trail, MARKER_ID_CALLING_DN, 1u);
  pjsip_sip_uri* calling_uri = (pjsip_sip_uri*)pjsip_uri_get_uri(rdata->msg_info.to->uri);
  calling_dn.add_var_param(calling_uri->user.slen, calling_uri->user.ptr);
  SAS::report_marker(calling_dn);

  SAS::Marker cid_marker(trail, MARKER_ID_SIP_CALL_ID, 1u);
  cid_marker.add_var_param(rdata->msg_info.cid->id.slen, rdata->msg_info.cid->id.ptr);
  SAS::report_marker(cid_marker, SAS::Marker::Scope::Trace);

  // Query the HSS for the associated URIs.
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifc_map;

  // Subscriber must have already registered to be making a subscribe
  HTTPCode http_code = hss->get_subscription_data(public_id, "", ifc_map, uris, trail);
  if (http_code != HTTP_OK)
  {
    // We failed to get the list of associated URIs.  This indicates that the
    // HSS is unavailable, the public identity doesn't exist or the public
    // identity doesn't belong to the private identity.  Reject with 403.
    LOG_ERROR("Rejecting register request with invalid public/private identity");
    PJUtils::respond_stateless(stack_data.endpt,
                               rdata,
                               PJSIP_SC_FORBIDDEN,
                               NULL,
                               NULL,
                               NULL);
    return;
  }

  // Determine the AOR from the first entry in the uris array.
  std::string aor = uris.front();
  LOG_DEBUG("SUBSCRIBE for public ID %s uses AOR %s", public_id.c_str(), aor.c_str());

  // Get the system time in seconds for calculating absolute expiry times.
  int now = time(NULL);
  int expiry = 0;
  bool is_initial_subscription;

  // Write to the local store, checking the remote store if there is no entry locally.
  RegStore::AoR* aor_data = write_subscriptions_to_store(store, aor, rdata, now, expiry, is_initial_subscription, NULL, remote_store);
  if (aor_data != NULL)
  {
    // Log the subscriptions.
    log_subscriptions(aor, aor_data);

    // If we have a remote store, try to store this there too.  We don't worry
    // about failures in this case.
    if (remote_store != NULL)
    {
      int tmp_expiry = 0;
      bool ignored;
      RegStore::AoR* remote_aor_data = write_subscriptions_to_store(remote_store, aor, rdata, now, tmp_expiry, ignored, aor_data, NULL);
      delete remote_aor_data;
    }
  }
  else
  {
    // Failed to connect to the local store.  Reject the register with a 500
    // response.
    // LCOV_EXCL_START - the can't fail to connect to the store we use for UT
    st_code = PJSIP_SC_INTERNAL_SERVER_ERROR;
    // LCOV_EXCL_STOP
  }

  // Build and send the reply.
  pjsip_tx_data* tdata;
  status = PJUtils::create_response(stack_data.endpt, rdata, st_code, NULL, &tdata);
  if (status != PJ_SUCCESS)
  {
    // LCOV_EXCL_START - don't know how to get PJSIP to fail to create a response
    LOG_ERROR("Error building REGISTER %d response %s", st_code,
              PJUtils::pj_status_to_string(status).c_str());
    PJUtils::respond_stateless(stack_data.endpt,
                               rdata,
                               PJSIP_SC_INTERNAL_SERVER_ERROR,
                               NULL,
                               NULL,
                               NULL);
    delete aor_data;
    return;
    // LCOV_EXCL_STOP
  }

  if (st_code != PJSIP_SC_OK)
  {
    // LCOV_EXCL_START - we only reject SUBSCRIBE if something goes wrong, and
    // we aren't covering any of those paths so we can't hit this either
    status = pjsip_endpt_send_response2(stack_data.endpt, rdata, tdata, NULL, NULL);
    delete aor_data;
    return;
    // LCOV_EXCL_STOP
  }

  // Send the response.
  pjsip_tx_data_add_ref(tdata);
  status = pjsip_endpt_send_response2(stack_data.endpt, rdata, tdata, NULL, NULL);
  pjsip_tx_data_dec_ref(tdata);

  LOG_DEBUG("Report SAS end marker - trail (%llx)", trail);
  SAS::Marker end_marker(trail, MARKER_ID_END, 1u);
  SAS::report_marker(end_marker);

//  pjsip_tx_data* tdata2;
//  pjsip_tx_data_add_ref(tdata2);
//  status = pjsip_endpt_create_request(stack_data.endpt, pjsip_get_notify_method(), aor_dataaor_data->notify_csq, NULL, &tdata2);
//  pjsip_tx_data_dec_ref(tdata2);

  delete aor_data;
}

// Reject request unless it's a SUBSCRIBE targeted at the home domain / this node. 
pj_bool_t subscription_on_rx_request(pjsip_rx_data *rdata)
{
  if ((rdata->tp_info.transport->local_name.port == stack_data.scscf_port) &&
      !(pjsip_method_cmp(&rdata->msg_info.msg->line.req.method, pjsip_get_subscribe_method())) &&
      ((PJUtils::is_home_domain(rdata->msg_info.msg->line.req.uri)) ||
       (PJUtils::is_uri_local(rdata->msg_info.msg->line.req.uri))))
  {
    // SUBSCRIBE request targeted at the home domain or specifically at this node.
    LOG_INFO("In");
    process_subscription_request(rdata);
    return PJ_TRUE;
  }

  LOG_INFO("NA");
  return PJ_FALSE;
}

/*void subscription_on_tsx_state(pjsip_transaction *tsx, pjsip_event *event)
{
  printf("heee");
  if (((bool)tsx->mod_data[mod_subscription.id] == DEFAULT_HANDLING_SESSION_TERMINATED) &&
      (event->type == PJSIP_EVENT_RX_MSG) &&
      ((tsx->status_code == 408) || ((tsx->status_code >= 500) && (tsx->status_code < 600))))
  {
    // Can't create an AS response in UT
    // LCOV_EXCL_START
    LOG_INFO("SUBSCRIBE transaction failed with code %d", tsx->status_code);
    std::string aor = PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, (pjsip_uri*)pjsip_uri_get_uri(PJSIP_MSG_TO_HDR(tsx->last_tx->msg)->uri));

    // 3GPP TS 24.229 V12.0.0 (2013-03) 5.4.1.7 specifies that an AS failure where SESSION_TERMINATED
    // is set means that we should deregister "the currently registered public user identity" - i.e. all bindings
    std::vector<std::string> uris;
    std::map<std::string, Ifcs> ifc_map;
    HTTPCode http_code = hss->get_subscription_data(aor, "", ifc_map, uris, get_trail(tsx));

    if (http_code == HTTP_OK)
    {
  //    RegistrationUtils::network_initiated_deregistration(store, ifc_map[aor], aor, "*", get_trail(tsx));
    }
    // LCOV_EXCL_STOP
  }
}*/

pj_status_t init_subscription(RegStore* registrar_store,
                              RegStore* remote_reg_store,
                              HSSConnection* hss_connection,
                              AnalyticsLogger* analytics_logger,
                              IfcHandler* ifchandler_ref,
                              int cfg_max_expires)
{
  pj_status_t status;

  store = registrar_store;
  remote_store = remote_reg_store;
  hss = hss_connection;
  analytics = analytics_logger;
  ifchandler = ifchandler_ref;
  max_expires = cfg_max_expires;

  status = pjsip_endpt_register_module(stack_data.endpt, &mod_subscription);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

  return status;
}


void destroy_subscription()
{
  pjsip_endpt_unregister_module(stack_data.endpt, &mod_subscription);
}

