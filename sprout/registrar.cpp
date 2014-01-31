/**
 * @file registrar.cpp
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

#include <time.h>

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
#include "registrar.h"
#include "registration_utils.h"
#include "constants.h"
#include "log.h"
#include "notify_utils.h"

static RegStore* store;
static RegStore* remote_store;

// Connection to the HSS service for retrieving associated public URIs.
static HSSConnection* hss;

static IfcHandler* ifchandler;

static AnalyticsLogger* analytics;

static int max_expires;

//
// mod_registrar is the module to receive SIP REGISTER requests.  This
// must get invoked before the proxy UA module.
//
static pj_bool_t registrar_on_rx_request(pjsip_rx_data *rdata);
static void registrar_on_tsx_state(pjsip_transaction *tsx, pjsip_event *event);

pjsip_module mod_registrar =
{
  NULL, NULL,                         // prev, next
  pj_str("mod-registrar"),            // Name
  -1,                                 // Id
  PJSIP_MOD_PRIORITY_UA_PROXY_LAYER+1,// Priority
  NULL,                               // load()
  NULL,                               // start()
  NULL,                               // stop()
  NULL,                               // unload()
  &registrar_on_rx_request,           // on_rx_request()
  NULL,                               // on_rx_response()
  NULL,                               // on_tx_request()
  NULL,                               // on_tx_response()
  &registrar_on_tsx_state,            // on_tsx_state()
};


void log_bindings(const std::string& aor_name, RegStore::AoR* aor_data)
{
  LOG_DEBUG("Bindings for %s", aor_name.c_str());
  for (RegStore::AoR::Bindings::const_iterator i = aor_data->bindings().begin();
       i != aor_data->bindings().end();
       ++i)
  {
    RegStore::AoR::Binding* binding = i->second;
    LOG_DEBUG("  %s URI=%s expires=%d q=%d from %s cseq %d",
              i->first.c_str(),
              binding->_uri.c_str(),
              binding->_expires, binding->_priority,
              binding->_cid.c_str(), binding->_cseq);
  }
}


std::string get_binding_id(pjsip_contact_hdr *contact)
{
  // Get a suitable binding string from +sip.instance and reg_id parameters
  // if they are supplied.
  std::string id;
  pj_str_t *instance = NULL;
  pj_str_t *reg_id = NULL;

  pjsip_param *p = contact->other_param.next;
  while ((p != NULL) && (p != &contact->other_param))
  {
    if (pj_stricmp(&p->name, &STR_SIP_INSTANCE) == 0)
    {
      instance = &p->value;
    }
    else if (pj_stricmp(&p->name, &STR_REG_ID) == 0)
    {
      reg_id = &p->value;
    }
    p = p->next;
  }
  if (instance != NULL)
  {
    // The contact a +sip.instance parameters, so form a suitable binding
    // string.
    id = PJUtils::pj_str_to_string(instance);
    id = id.substr(1, id.size() - 2); // Strip quotes
    if (reg_id != NULL)
    {
      id = id + ":" + PJUtils::pj_str_to_string(reg_id);
    }
  }
  return id;
}


/// Get private ID from a received message by checking the Authorization
/// header. If that uses the Digest scheme and contains a non-empty
/// username, it puts that username into id and returns true;
/// otherwise returns false.
bool get_private_id(pjsip_rx_data* rdata, std::string& id)
{
  bool success = false;

  pjsip_authorization_hdr* auth_hdr = (pjsip_authorization_hdr*)
    pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_AUTHORIZATION, NULL);
  if (auth_hdr != NULL)
  {
    if (pj_stricmp2(&auth_hdr->scheme, "digest") == 0)
    {
      id = PJUtils::pj_str_to_string(&auth_hdr->credential.digest.username);
      if (!id.empty())
      {
        success = true;
      }
    }
    else
    {
      // LCOV_EXCL_START
      LOG_WARNING("Unsupported scheme \"%.*s\" in Authorization header when determining private ID - ignoring",
                  auth_hdr->scheme.slen, auth_hdr->scheme.ptr);
      // LCOV_EXCL_STOP
    }
  }
  return success;
}

/// Write to the registration store.
RegStore::AoR* write_to_store(RegStore* primary_store,       ///<store to write to
                              std::string aor,               ///<address of record to write to
                              pjsip_rx_data* rdata,          ///<received message to read headers from
                              int now,                       ///<time now
                              int& expiry,                   ///<[out] longest expiry time
                              bool& out_is_initial_registration,
                              RegStore::AoR* backup_aor,     ///<backup data if no entry in store
                              RegStore* backup_store,        ///<backup store to read from if no entry in store and no backup data
                              bool send_notify)              ///<whether to send notifies (only send when writing to the local store
{
  // Get the call identifier and the cseq number from the respective headers.
  std::string cid = PJUtils::pj_str_to_string((const pj_str_t*)&rdata->msg_info.cid->id);
  int cseq = rdata->msg_info.cseq->cseq;

  NotifyUtils::ContactEvent contact_event;

  // Find the expire headers in the message.
  pjsip_msg *msg = rdata->msg_info.msg;
  pjsip_expires_hdr* expires = (pjsip_expires_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_EXPIRES, NULL);

  // The registration service uses optimistic locking to avoid concurrent
  // updates to the same AoR conflicting.  This means we have to loop
  // reading, updating and writing the AoR until the write is successful.
  RegStore::AoR* aor_data = NULL;
  bool backup_aor_alloced = false;
  bool is_initial_registration = true;
  std::map<std::string, RegStore::AoR::Binding> bindings;
  do
  {
    // delete NULL is safe, so we can do this on every iteration.
    delete aor_data;

    // Find the current bindings for the AoR.
    aor_data = primary_store->get_aor_data(aor);
    LOG_DEBUG("Retrieved AoR data %p", aor_data);

    if (aor_data == NULL)
    {
      // Failed to get data for the AoR because there is no connection
      // to the store.
      // LCOV_EXCL_START - local store (used in testing) never fails
      LOG_ERROR("Failed to get AoR binding for %s from store", aor.c_str());
      break;
      // LCOV_EXCL_STOP
    }

    // If we don't have any bindings, try the backup AoR and/or store.
    if (aor_data->bindings().empty())
    {
      if ((backup_aor == NULL) &&
          (backup_store != NULL))
      {
        backup_aor = backup_store->get_aor_data(aor);
        backup_aor_alloced = (backup_aor != NULL);
      }

      if ((backup_aor != NULL) &&
          (!backup_aor->bindings().empty()))
      {
        for (RegStore::AoR::Bindings::const_iterator i = backup_aor->bindings().begin();
             i != backup_aor->bindings().end();
             ++i)
        {
          RegStore::AoR::Binding* src = i->second;
          RegStore::AoR::Binding* dst = aor_data->get_binding(i->first);
          *dst = *src;
        }
      }
    }

    is_initial_registration = is_initial_registration && aor_data->bindings().empty();

    // Now loop through all the contacts.  If there are multiple contacts in
    // the contact header in the SIP message, pjsip parses them to separate
    // contact header structures.
    pjsip_contact_hdr* contact = (pjsip_contact_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_CONTACT, NULL);
    while (contact != NULL)
    {
      if (contact->star)
      {
        // Wildcard contact, which can only be used to clear all bindings for
        // the AoR.
        aor_data->clear();
        break;
      }

      pjsip_uri* uri = (contact->uri != NULL) ?
                           (pjsip_uri*)pjsip_uri_get_uri(contact->uri) :
                           NULL;

      if ((uri != NULL) &&
          (PJSIP_URI_SCHEME_IS_SIP(uri)))
      {
        // The binding identifier is based on the +sip.instance parameter if
        // it is present.  If not the contact URI is used instead.
        std::string contact_uri = PJUtils::uri_to_string(PJSIP_URI_IN_CONTACT_HDR, uri);
        std::string binding_id = get_binding_id(contact);
        if (binding_id == "")
        {
          binding_id = contact_uri;
        }
        LOG_DEBUG(". Binding identifier for contact = %s", binding_id.c_str());

        // Find the appropriate binding in the bindings list for this AoR.
        RegStore::AoR::Binding* binding = aor_data->get_binding(binding_id);

        if ((cid != binding->_cid) ||
            (cseq > binding->_cseq))
        {
           
          // Either this is a new binding, has come from a restarted device, or
          // is an update to an existing binding.
          binding->_uri = contact_uri;
          
          if (cid != binding->_cid)
          {
            // New binding, set contact event to created
            contact_event = NotifyUtils::CREATED;
          }
          else
          {
            // Updated binding, set contact event to refreshed
            contact_event = NotifyUtils::REFRESHED;
          } 

          // TODO Examine Via header to see if we're the first hop
          // TODO Only if we're not the first hop, check that the top path header has "ob" parameter

          // Get the Path headers, if present.  RFC 3327 allows us the option of
          // rejecting a request with a Path header if there is no corresponding
          // "path" entry in the Supported header but we don't do so on the assumption
          // that the edge proxy knows what it's doing.
          binding->_path_headers.clear();
          pjsip_generic_string_hdr* path_hdr =
            (pjsip_generic_string_hdr*)pjsip_msg_find_hdr_by_name(msg, &STR_PATH, NULL);
          while (path_hdr)
          {
            std::string path = PJUtils::pj_str_to_string(&path_hdr->hvalue);
            LOG_DEBUG("Path header %s", path.c_str());

            // Extract all the paths from this header.
            Utils::split_string(path, ',', binding->_path_headers, 0, true);

            // Look for the next header.
            path_hdr = (pjsip_generic_string_hdr*)pjsip_msg_find_hdr_by_name(msg, &STR_PATH, path_hdr->next);
          }

          binding->_cid = cid;
          binding->_cseq = cseq;
          binding->_priority = contact->q1000;
          binding->_params.clear();
          pjsip_param* p = contact->other_param.next;
          while ((p != NULL) && (p != &contact->other_param))
          {
            std::string pname = PJUtils::pj_str_to_string(&p->name);
            std::string pvalue = PJUtils::pj_str_to_string(&p->value);
            binding->_params.push_back(std::make_pair(pname, pvalue));
            p = p->next;
          }

          // Calculate the expiry period for the updated binding.
          expiry = (contact->expires != -1) ? contact->expires :
                   (expires != NULL) ? expires->ivalue :
                   max_expires;
          if (expiry > max_expires)
          {
            // Expiry is too long, set it to the maximum.
            expiry = max_expires;
          }

          binding->_expires = now + expiry;
          bindings.insert(std::pair<std::string, RegStore::AoR::Binding>(binding_id, *binding));

          if (analytics != NULL)
          {
            // Generate an analytics log for this binding update.
            analytics->registration(aor, binding_id, contact_uri, expiry);
          }
        }
      }
      contact = (pjsip_contact_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_CONTACT, contact->next);
    }
    
    // Finally, update the cseq
    aor_data->_notify_cseq++;
  }
  while (!primary_store->set_aor_data(aor, aor_data));

  // If we allocated the backup AoR, tidy up.
  if (backup_aor_alloced)
  {
    delete backup_aor;
  }

  // Finally, send out SIP NOTIFYs for any subscriptions
  if (send_notify)
  {
    for (RegStore::AoR::Subscriptions::const_iterator i = aor_data->subscriptions().begin();
         i != aor_data->subscriptions().end();
         ++i)
    {
      RegStore::AoR::Subscription* subscription = i->second;
      if (subscription->_expires > now)
      {
        pjsip_tx_data* tdata_notify;
        
        pj_status_t status = NotifyUtils::create_notify(&tdata_notify, subscription, aor, aor_data->_notify_cseq, bindings,
                                  NotifyUtils::PARTIAL, NotifyUtils::ACTIVE, NotifyUtils::ACTIVE, contact_event);
        if (status == PJ_SUCCESS)
        {
          pjsip_tx_data_add_ref(tdata_notify);
          status = pjsip_endpt_send_request_stateless(stack_data.endpt, tdata_notify, NULL, NULL);
          pjsip_tx_data_dec_ref(tdata_notify);
        }
      }
    }
  }

  out_is_initial_registration = is_initial_registration;
  return aor_data;
}

void process_register_request(pjsip_rx_data* rdata)
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
    LOG_ERROR("Rejecting register request using non SIP URI");
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
  LOG_DEBUG("Process REGISTER for public ID %s", public_id.c_str());

  // Get the call identifier and the cseq number from the respective headers.
  std::string cid = PJUtils::pj_str_to_string((const pj_str_t*)&rdata->msg_info.cid->id);;
  pjsip_msg *msg = rdata->msg_info.msg;

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
  std::string private_id;
  bool success = get_private_id(rdata, private_id);
  if (!success)
  {
    // There are legitimate cases where we don't have a private ID
    // here (for example, on a re-registration where Bono has set the
    // Integrity-Protected header), so this is *not* a failure
    // condition.

    // We want the private ID here so that Homestead can use it to
    // subscribe for updates from the HSS - but on a re-registration,
    // Homestead should already have subscribed for updates during the
    // initial registration, so we can just make a request using our
    // public ID.
    private_id = "";
  }

  HTTPCode http_code = hss->get_subscription_data(public_id, private_id, ifc_map, uris, trail);
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
  LOG_DEBUG("REGISTER for public ID %s uses AOR %s", public_id.c_str(), aor.c_str());

  // Get the system time in seconds for calculating absolute expiry times.
  int now = time(NULL);
  int expiry = 0;
  bool is_initial_registration;

  // Write to the local store, checking the remote store if there is no entry locally.
  RegStore::AoR* aor_data = write_to_store(store, aor, rdata, now, expiry, is_initial_registration, NULL, remote_store, true);
  if (aor_data != NULL)
  {
    // Log the bindings.
    log_bindings(aor, aor_data);

    // If we have a remote store, try to store this there too.  We don't worry
    // about failures in this case.
    if (remote_store != NULL)
    {
      int tmp_expiry = 0;
      bool ignored;
      RegStore::AoR* remote_aor_data = write_to_store(remote_store, aor, rdata, now, tmp_expiry, ignored, aor_data, NULL, false);
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
    // LCOV_EXCL_START - we only reject REGISTER if something goes wrong, and
    // we aren't covering any of those paths so we can't hit this either
    status = pjsip_endpt_send_response2(stack_data.endpt, rdata, tdata, NULL, NULL);
    delete aor_data;
    return;
    // LCOV_EXCL_STOP
  }

  // Add supported and require headers for RFC5626.
  pjsip_generic_string_hdr* gen_hdr;
  gen_hdr = pjsip_generic_string_hdr_create(tdata->pool,
                                            &STR_SUPPORTED,
                                            &STR_OUTBOUND);
  if (gen_hdr == NULL)
  {
    // LCOV_EXCL_START - can't see how this could ever happen
    LOG_ERROR("Failed to add RFC 5626 headers");
    tdata->msg->line.status.code = PJSIP_SC_INTERNAL_SERVER_ERROR;
    status = pjsip_endpt_send_response2(stack_data.endpt, rdata, tdata, NULL, NULL);
    delete aor_data;
    return;
    // LCOV_EXCL_STOP
  }
  pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)gen_hdr);

  // Add contact headers for all active bindings.
  for (RegStore::AoR::Bindings::const_iterator i = aor_data->bindings().begin();
       i != aor_data->bindings().end();
       ++i)
  {
    RegStore::AoR::Binding* binding = i->second;
    if (binding->_expires > now)
    {
      // The binding hasn't expired.
      pjsip_uri* uri = PJUtils::uri_from_string(binding->_uri, tdata->pool);
      if (uri != NULL)
      {
        // Contact URI is well formed, so include this in the response.
        pjsip_contact_hdr* contact = pjsip_contact_hdr_create(tdata->pool);
        contact->star = 0;
        contact->uri = uri;
        contact->q1000 = binding->_priority;
        contact->expires = binding->_expires - now;
        pj_list_init(&contact->other_param);
        for (std::list<std::pair<std::string, std::string> >::iterator j = binding->_params.begin();
             j != binding->_params.end();
             ++j)
        {
          pjsip_param *new_param = PJ_POOL_ALLOC_T(tdata->pool, pjsip_param);
          pj_strdup2(tdata->pool, &new_param->name, j->first.c_str());
          pj_strdup2(tdata->pool, &new_param->value, j->second.c_str());
          pj_list_insert_before(&contact->other_param, new_param);
        }
        pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)contact);
      }
      else
      {
        // Contact URI is malformed.  Log an error, but otherwise don't try and
        // fix it.
        // LCOV_EXCL_START hard to hit - needs bad data in the store
        LOG_WARNING("Badly formed contact URI %s for address of record %s",
                    binding->_uri.c_str(), aor.c_str());
        // LCOV_EXCL_STOP
      }
    }
  }

  // Deal with path header related fields in the response.
  pjsip_generic_string_hdr* path_hdr =
    (pjsip_generic_string_hdr*)pjsip_msg_find_hdr_by_name(msg, &STR_PATH, NULL);
  if ((path_hdr != NULL) &&
      (!aor_data->bindings().empty()))
  {
    // We have bindings with path headers so we must require outbound.
    pjsip_require_hdr* require_hdr = pjsip_require_hdr_create(tdata->pool);
    require_hdr->count = 1;
    require_hdr->values[0] = STR_OUTBOUND;
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)require_hdr);
  }

  // Echo back any Path headers as per RFC 3327, section 5.3.  We take these
  // from the request as they may not exist in the bindings any more if the
  // bindings have expired.
  while (path_hdr)
  {
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)pjsip_hdr_clone(tdata->pool, path_hdr));
    path_hdr = (pjsip_generic_string_hdr*)pjsip_msg_find_hdr_by_name(msg, &STR_PATH, path_hdr->next);
  }

  // Construct a Service-Route header pointing at the domain.  We don't
  // care which sprout handles the subsequent requests as they all have access
  // to all subscriber information.
  pjsip_sip_uri* service_route_uri = pjsip_sip_uri_create(tdata->pool, false);
  pj_strdup(tdata->pool,
            &service_route_uri->host,
            &stack_data.sprout_cluster_domain);
  service_route_uri->port = stack_data.scscf_port;
  service_route_uri->transport_param = pj_str("TCP");
  service_route_uri->lr_param = 1;

  // Add the orig parameter.  The UE must provide this back on future messages
  // to ensure we perform originating processing.
  pjsip_param *orig_param = PJ_POOL_ALLOC_T(tdata->pool, pjsip_param);
  pj_strdup(tdata->pool, &orig_param->name, &STR_ORIG);
  pj_strdup2(tdata->pool, &orig_param->value, "");
  pj_list_insert_after(&service_route_uri->other_param, orig_param);

  pjsip_route_hdr* service_route = pjsip_route_hdr_create(tdata->pool);
  service_route->name = STR_SERVICE_ROUTE;
  service_route->sname = pj_str("");
  service_route->name_addr.uri = (pjsip_uri*)service_route_uri;

  pjsip_msg_insert_first_hdr(tdata->msg, (pjsip_hdr*)service_route);

  // Add P-Associated-URI headers for all of the associated URIs.
  static const pj_str_t p_associated_uri_hdr_name = pj_str("P-Associated-URI");
  for (std::vector<std::string>::iterator it = uris.begin(); it != uris.end(); it++)
  {
    pj_str_t tmp_associated_uri;
    const pj_str_t* associated_uri = pj_cstr(&tmp_associated_uri, it->c_str());
    pjsip_hdr* associated_uri_hdr =
      (pjsip_hdr*)pjsip_generic_string_hdr_create(tdata->pool,
                                                  &p_associated_uri_hdr_name,
                                                  associated_uri);
    pjsip_msg_add_hdr(tdata->msg, associated_uri_hdr);
  }

  // Send the response, but prevent the transmitted data from being freed, as we may need to inform the
  // ASes of the 200 OK response we sent.
  pjsip_tx_data_add_ref(tdata);
  status = pjsip_endpt_send_response2(stack_data.endpt, rdata, tdata, NULL, NULL);

  // TODO in sto397: we should do third-party registration once per
  // service profile (i.e. once per iFC, using an arbitrary public
  // ID). hss->get_subscription_data should be enhanced to provide an
  // appropriate data structure (representing the ServiceProfile
  // nodes) and we should loop through that.

  RegistrationUtils::register_with_application_servers(ifc_map[public_id], store, rdata, tdata, expiry, is_initial_registration, public_id, trail);

  // Now we can free the tdata.
  pjsip_tx_data_dec_ref(tdata);

  LOG_DEBUG("Report SAS end marker - trail (%llx)", trail);
  SAS::Marker end_marker(trail, MARKER_ID_END, 1u);
  SAS::report_marker(end_marker);
  delete aor_data;
}

pj_bool_t registrar_on_rx_request(pjsip_rx_data *rdata)
{
  if ((rdata->tp_info.transport->local_name.port == stack_data.scscf_port) &&
      (rdata->msg_info.msg->line.req.method.id == PJSIP_REGISTER_METHOD) &&
      ((PJUtils::is_home_domain(rdata->msg_info.msg->line.req.uri)) ||
       (PJUtils::is_uri_local(rdata->msg_info.msg->line.req.uri))))
  {
    // REGISTER request targeted at the home domain or specifically at this node.
    process_register_request(rdata);
    return PJ_TRUE;
  }

  return PJ_FALSE;
}

void registrar_on_tsx_state(pjsip_transaction *tsx, pjsip_event *event)
{
  if (((bool)tsx->mod_data[mod_registrar.id] == DEFAULT_HANDLING_SESSION_TERMINATED) &&
      (event->type == PJSIP_EVENT_RX_MSG) &&
      ((tsx->status_code == 408) || ((tsx->status_code >= 500) && (tsx->status_code < 600))))
  {
    // Can't create an AS response in UT
    // LCOV_EXCL_START
    LOG_INFO("REGISTER transaction failed with code %d", tsx->status_code);
    std::string aor = PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, (pjsip_uri*)pjsip_uri_get_uri(PJSIP_MSG_TO_HDR(tsx->last_tx->msg)->uri));

    // 3GPP TS 24.229 V12.0.0 (2013-03) 5.4.1.7 specifies that an AS failure where SESSION_TERMINATED
    // is set means that we should deregister "the currently registered public user identity" - i.e. all bindings
    std::vector<std::string> uris;
    std::map<std::string, Ifcs> ifc_map;
    HTTPCode http_code = hss->get_subscription_data(aor, "", ifc_map, uris, get_trail(tsx));

    if (http_code == HTTP_OK)
    {
      RegistrationUtils::network_initiated_deregistration(store, ifc_map[aor], aor, "*", get_trail(tsx));
    }
    // LCOV_EXCL_STOP
  }
}

pj_status_t init_registrar(RegStore* registrar_store,
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

  status = pjsip_endpt_register_module(stack_data.endpt, &mod_registrar);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

  return status;
}


void destroy_registrar()
{
  pjsip_endpt_unregister_module(stack_data.endpt, &mod_registrar);
}

