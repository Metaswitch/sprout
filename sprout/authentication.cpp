/**
 * @file authentication.cpp
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
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

// Common STL includes.
#include <cassert>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <queue>
#include <string>
#include <boost/algorithm/string/predicate.hpp>

#include "log.h"
#include "stack.h"
#include "sasevent.h"
#include "pjutils.h"
#include "constants.h"
#include "analyticslogger.h"
#include "hssconnection.h"
#include "authentication.h"


//
// mod_auth authenticates SIP requests.  It must be inserted into the
// stack below the transaction layer.
//
static pj_bool_t authenticate_rx_request(pjsip_rx_data *rdata);

pjsip_module mod_auth =
{
  NULL, NULL,                         // prev, next
  pj_str("mod-auth"),                  // Name
  -1,                                 // Id
  PJSIP_MOD_PRIORITY_TSX_LAYER-1,     // Priority
  NULL,                               // load()
  NULL,                               // start()
  NULL,                               // stop()
  NULL,                               // unload()
  &authenticate_rx_request,           // on_rx_request()
  NULL,                               // on_rx_response()
  NULL,                               // on_tx_request()
  NULL,                               // on_tx_response()
  NULL,                               // on_tsx_state()
};


// Connection to the HSS service for retrieving subscriber credentials.
static HSSConnection* hss;


// Analytics logger.
static AnalyticsLogger* analytics;


// Flag that records whether authentication/authorization of transport
// connections is supported.  If so, once authentication has been
// successful on the connection subsequent requests will be accepted on the
// connection without checking or challenging credentials.
bool tp_auth_supported;


// Map for storing information about authenticated/authorized transport
// connections.
pj_mutex_t* tp_auth_lock;
std::map<pjsip_transport*, bool> tp_auth_map;


// PJSIP structure for control server authentication functions.
pjsip_auth_srv auth_srv;


// Do IMS compliant user lookup?  If this flag is set, the lookup uses
// both public and private user identities in the user lookup.  Otherwise,
// the lookup uses only the private user identity.
bool ims_auth;


pj_status_t user_lookup(pj_pool_t *pool,
                        const pjsip_auth_lookup_cred_param *param,
                        pjsip_cred_info *cred_info)
{
  const pj_str_t* acc_name = &param->acc_name;
  const pj_str_t* realm = &param->realm;
  const pjsip_rx_data* rdata = param->rdata;

  SAS::TrailId trail = get_trail(rdata);

  pj_status_t status = PJSIP_EAUTHACCNOTFOUND;
  Json::Value* data;

  std::string private_id;
  std::string public_id;
  if (ims_auth)
  {
    // For IMS authentication use both the private and public user identities
    // in the user lookup.  The private user identity comes from the username
    // field of the Authentication header, and the public user identity from
    // the request-URI of the request.
    private_id = PJUtils::pj_str_to_string(acc_name);
    public_id = PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR,
                                       rdata->msg_info.msg->line.req.uri);

    LOG_DEBUG("Retrieve IMS digest for user %s/%s in realm %.*s",
              private_id.c_str(), public_id.c_str(),
              realm->slen, realm->ptr);
  }
  else
  {
    // For SIP authentication use only the username from the Authentication
    // header for the user lookup.  The username field contains the private
    // user identity and the public user identity can be deduced by adding
    // a sip: prefix.
    //
    private_id = PJUtils::pj_str_to_string(acc_name);
    public_id = "sip:" + private_id;

    LOG_DEBUG("Retrieve SIP digest for user %s/%s in realm %.*s",
              private_id.c_str(), public_id.c_str(),
              realm->slen, realm->ptr);
  }

  data = hss->get_digest_data(private_id, public_id, trail);

  if (data != NULL)
  {
    std::string digest = data->get("digest", "" ).asString();
    if (digest != "")
    {
      LOG_DEBUG("Digest for user %.*s in realm %.*s = %s",
                acc_name->slen, acc_name->ptr,
                realm->slen, realm->ptr,
                digest.c_str());
      pj_strdup(pool, &cred_info->realm, realm);
      pj_cstr(&cred_info->scheme, "digest");
      pj_strdup(pool, &cred_info->username, acc_name);
      cred_info->data_type = PJSIP_CRED_DATA_DIGEST;
      pj_strdup2(pool, &cred_info->data, digest.c_str());
      status = PJ_SUCCESS;
    }
    delete data;
  }

  return status;
}


static void transport_state(pjsip_transport *tp, pjsip_transport_state state, const pjsip_transport_state_info *info)
{
  if (state == PJSIP_TP_STATE_DISCONNECTED)
  {
    // Transport connection has disconnected, so remove it from the authorized
    // map if it is there.
    pj_mutex_lock(tp_auth_lock);
    std::map<pjsip_transport*, bool>::iterator i = tp_auth_map.find(tp);
    if (i != tp_auth_map.end())
    {
      LOG_INFO("%s - Removing disconnected transport from authorized list", tp->obj_name);
      tp_auth_map.erase(i);
    }
    pj_mutex_unlock(tp_auth_lock);
  }
}


pj_bool_t authenticate_rx_request(pjsip_rx_data* rdata)
{
  pj_status_t status;

  if ((tp_auth_supported) &&
      (PJSIP_TRANSPORT_IS_RELIABLE(rdata->tp_info.transport)))
  {
    // The server supports authorization of reliable transport connections, so
    // check to see if this transport is already authenticated and authorized.
    pj_mutex_lock(tp_auth_lock);
    std::map<pjsip_transport*, bool>::const_iterator i = tp_auth_map.find(rdata->tp_info.transport);
    if (i != tp_auth_map.end())
    {
      // Message received on authorized transport, so let it through.
      pj_mutex_unlock(tp_auth_lock);
      return PJ_FALSE;

    }
    pj_mutex_unlock(tp_auth_lock);
  }

  // Check to see if the message has already been integrity protected?
  pjsip_authorization_hdr* auth_hdr = (pjsip_authorization_hdr*)
           pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_AUTHORIZATION, NULL);
  if (auth_hdr == NULL)
  {
    // No authentication header, so the message must have arrived from a node
    // within the trust zone that doesn't need us to do authentication.
    LOG_DEBUG("No authorization header, so accept message");
    return PJ_FALSE;
  }

  LOG_DEBUG("Authorization header in message");
  pjsip_param* integrity =
         pjsip_param_find(&auth_hdr->credential.digest.other_param,
                          &STR_INTEGRITY_PROTECTED);

  if ((integrity != NULL) &&
      ((pj_stricmp2(&integrity->value, "yes") == 0) ||
       (pj_stricmp2(&integrity->value, "tls-yes") == 0) ||
       (pj_stricmp2(&integrity->value, "ip-assoc-yes") == 0)))
  {
    // Message is already integrity protected, so let it through.
    LOG_INFO("Request integrity protected by edge proxy/IBCF");
    return PJ_FALSE;
  }

  if (auth_hdr->credential.digest.response.slen == 0)
  {
    // No response, so the authorization header was likely added by Bono, so
    // remove it.
    LOG_DEBUG("Remove authorization header added by Bono");
    pj_list_erase(auth_hdr);
  }

  int sc;
  LOG_DEBUG("Verify authentication information in request");
  status = pjsip_auth_srv_verify(&auth_srv, rdata, &sc);
  if (status == PJ_SUCCESS)
  {
    // The authentication information in the request was verified, so let
    // the message through.
    LOG_DEBUG("Request authenticated successfully");
    if ((tp_auth_supported) &&
        (PJSIP_TRANSPORT_IS_RELIABLE(rdata->tp_info.transport)))
    {
      // Message received on a reliable transport and transport authorization
      // is supported, so add this to the map, and register as a state
      // listener on the transport.
      LOG_INFO("%s - Adding transport to authorized list",
               rdata->tp_info.transport->obj_name);
      pj_mutex_lock(tp_auth_lock);
      tp_auth_map.insert(std::make_pair(rdata->tp_info.transport, true));
      pj_mutex_unlock(tp_auth_lock);
      pjsip_tp_state_listener_key* key;
      status = pjsip_transport_add_state_listener(rdata->tp_info.transport, &transport_state, NULL, &key);
    }
    return PJ_FALSE;

  }
  else
  {
    // The message either has insufficient authentication information, or
    // has failed authentication.  In either case, the message will be
    // absorbed by the authentication module, so we need to add SAS markers
    // so the trail will become searchable.
    SAS::TrailId trail = get_trail(rdata);
    SAS::Marker start_marker(trail, SASMarker::INIT_TIME, 1u);
    SAS::report_marker(start_marker);
    if (rdata->msg_info.from)
    {
      SAS::Marker calling_dn(trail, SASMarker::CALLING_DN, 1u);
      pjsip_sip_uri* calling_uri = (pjsip_sip_uri*)pjsip_uri_get_uri(rdata->msg_info.from->uri);
      calling_dn.add_var_param(calling_uri->user.slen, calling_uri->user.ptr);
      SAS::report_marker(calling_dn);
    }

    if (rdata->msg_info.to)
    {
      SAS::Marker called_dn(trail, SASMarker::CALLED_DN, 1u);
      pjsip_sip_uri* called_uri = (pjsip_sip_uri*)pjsip_uri_get_uri(rdata->msg_info.to->uri);
      called_dn.add_var_param(called_uri->user.slen, called_uri->user.ptr);
      SAS::report_marker(called_dn);
    }

    if (rdata->msg_info.cid)
    {
      SAS::Marker cid(trail, SASMarker::SIP_CALL_ID, 1u);
      cid.add_var_param(rdata->msg_info.cid->id.slen, rdata->msg_info.cid->id.ptr);
      SAS::report_marker(cid, SAS::Marker::Scope::TrailGroup);
    }

    if (rdata->msg_info.msg->line.req.method.id == PJSIP_ACK_METHOD)
    {
      // Discard unauthenticated ACK request since we can't reject or challenge it.
      LOG_VERBOSE("Discard unauthenticated ACK request");
    }
    else if (rdata->msg_info.msg->line.req.method.id == PJSIP_CANCEL_METHOD)
    {
      // Reject an unauthenticated CANCEL as it cannot be challenged (see RFC3261
      // section 22.1).
      LOG_VERBOSE("Reject unauthenticated CANCEL request");
      PJUtils::respond_stateless(stack_data.endpt,
                                 rdata,
                                 PJSIP_SC_FORBIDDEN,
                                 NULL,
                                 NULL,
                                 NULL);
    }
    else if (status == PJSIP_EAUTHNOAUTH)
    {
      // No authorization information in request, so challenge it.
      LOG_DEBUG("No authentication information in request, so reject with challenge");
      pjsip_tx_data* tdata;
      status = PJUtils::create_response(stack_data.endpt, rdata, sc, NULL, &tdata);
      if (status != PJ_SUCCESS)
      {
        LOG_ERROR("Error building challenge response, %s",
                  PJUtils::pj_status_to_string(status).c_str());
        PJUtils::respond_stateless(stack_data.endpt,
                                   rdata,
                                   PJSIP_SC_INTERNAL_SERVER_ERROR,
                                   NULL,
                                   NULL,
                                   NULL);
        return PJ_TRUE;
      }

      status = pjsip_auth_srv_challenge(&auth_srv, NULL, NULL, NULL, PJ_FALSE, tdata);
      if (status != PJ_SUCCESS)
      {
        LOG_ERROR("Error building challenge response headers, %s",
                  PJUtils::pj_status_to_string(status).c_str());
        tdata->msg->line.status.code = PJSIP_SC_INTERNAL_SERVER_ERROR;
      }

      status = pjsip_endpt_send_response2(stack_data.endpt, rdata, tdata, NULL, NULL);
    }
    else
    {
      // Authentication failed.
      LOG_ERROR("Authentication failed, %s",
                PJUtils::pj_status_to_string(status).c_str());
      if (analytics != NULL)
      {
        analytics->auth_failure(PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, rdata->msg_info.msg->line.req.uri));
      }

      // @TODO - need more diagnostics here so we can identify and flag
      // attacks.

      // Reject the request.
      PJUtils::respond_stateless(stack_data.endpt,
                                 rdata,
                                 sc,
                                 NULL,
                                 NULL,
                                 NULL);
    }

    // Add a SAS end marker
    SAS::Marker end_marker(trail, SASMarker::END_TIME, 1u);
    SAS::report_marker(end_marker);
  }

  return PJ_TRUE;
}


pj_status_t init_authentication(const std::string& realm_name,
                                bool tp_auth,
                                const std::string& auth_config,
                                HSSConnection* hss_connection,
                                AnalyticsLogger* analytics_logger)
{
  pj_status_t status;

  tp_auth_supported = tp_auth;
  hss = hss_connection;
  analytics = analytics_logger;

  if (auth_config == "sip-digest")
  {
    ims_auth = false;
  }
  else if (auth_config == "ims-digest")
  {
    ims_auth = true;
  }
  else
  {
    LOG_ERROR("Unsupported authentication configuration %s", auth_config.c_str());
    return 1;
  }

  status = pj_mutex_create_simple(stack_data.pool, "tp_auth_lock", &tp_auth_lock);

  // Register the authentication module.  This needs to be in the stack
  // before the transaction layer.
  status = pjsip_endpt_register_module(stack_data.endpt, &mod_auth);

  // Initialize the authorization server.
  pj_str_t realm = (realm_name != "") ? pj_strdup3(stack_data.pool, realm_name.c_str()) : stack_data.local_host;
  LOG_STATUS("Initializing authentication server for realm %.*s", realm.slen, realm.ptr);
  pjsip_auth_srv_init_param params;
  params.realm = &realm;
  params.lookup2 = user_lookup;
  params.options = 0;
  status = pjsip_auth_srv_init2(stack_data.pool, &auth_srv, &params);

  return status;
}


void destroy_authentication()
{
  pjsip_endpt_unregister_module(stack_data.endpt, &mod_auth);
  tp_auth_map.clear();
  pj_mutex_destroy(tp_auth_lock);
}

