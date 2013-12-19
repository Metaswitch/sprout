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
  pj_str("mod-auth"),                 // Name
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


// PJSIP structure for control server authentication functions.
pjsip_auth_srv auth_srv;


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

  // The private user identity comes from the username field of the
  // Authentication header, and the public user identity from the request-URI
  // of the request.
  std::string private_id = PJUtils::pj_str_to_string(acc_name);
  std::string public_id = PJUtils::aor_from_uri((pjsip_sip_uri*)pjsip_uri_get_uri(PJSIP_MSG_TO_HDR(rdata->msg_info.msg)->uri));

  LOG_DEBUG("Retrieve digest for user %s/%s in realm %.*s",
            private_id.c_str(), public_id.c_str(),
            realm->slen, realm->ptr);

  // If no homestead is attached, return that the account could not be found.
  if (hss != NULL)
  {
    data = hss->get_digest_data(private_id, public_id, trail);

    if (data != NULL)
    {
      std::string digest = data->get("digest_ha1", "" ).asString();
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
  }

  return status;
}


pj_bool_t authenticate_rx_request(pjsip_rx_data* rdata)
{
  pj_status_t status;

  if (rdata->tp_info.transport->local_name.port != stack_data.scscf_port)
  {
    // Request not received on S-CSCF port, so don't authenticate it.
    return PJ_FALSE;
  }

  if (rdata->msg_info.msg->line.req.method.id != PJSIP_REGISTER_METHOD)
  {
    // Non-REGISTER request, so don't do authentication as it must have come
    // from an authenticated or trusted source.
    return PJ_FALSE;
  }

  // Check to see if the request has already been integrity protected?
  pjsip_authorization_hdr* auth_hdr = (pjsip_authorization_hdr*)
           pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_AUTHORIZATION, NULL);

  if (auth_hdr != NULL)
  {
    LOG_DEBUG("Authorization header in request");
    pjsip_param* integrity =
           pjsip_param_find(&auth_hdr->credential.digest.other_param,
                            &STR_INTEGRITY_PROTECTED);

    if ((integrity != NULL) &&
        ((pj_stricmp(&integrity->value, &STR_YES) == 0) ||
         (pj_stricmp(&integrity->value, &STR_TLS_YES) == 0) ||
         (pj_stricmp(&integrity->value, &STR_IP_ASSOC_YES) == 0)))
    {
      // Request is already integrity protected, so let it through.
      LOG_INFO("Request integrity protected by edge proxy");
      return PJ_FALSE;
    }

    if (auth_hdr->credential.digest.response.slen == 0)
    {
      // There's no response in the header, so remove it to ensure we issue
      // a challenge.
      LOG_DEBUG("Remove authorization header without response field");
      pj_list_erase(auth_hdr);
    }
  }

  int sc;
  LOG_DEBUG("Verify authentication information in request");
  status = pjsip_auth_srv_verify(&auth_srv, rdata, &sc);
  if (status == PJ_SUCCESS)
  {
    // The authentication information in the request was verified, so let
    // the message through.
    LOG_DEBUG("Request authenticated successfully");
    return PJ_FALSE;

  }
  else
  {
    // The message either has insufficient authentication information, or
    // has failed authentication.  In either case, the message will be
    // absorbed by the authentication module, so we need to add SAS markers
    // so the trail will become searchable.
    SAS::TrailId trail = get_trail(rdata);
    SAS::Marker start_marker(trail, MARKER_ID_START, 1u);
    SAS::report_marker(start_marker);
    if (rdata->msg_info.from)
    {
      SAS::Marker calling_dn(trail, MARKER_ID_CALLING_DN, 1u);
      pjsip_sip_uri* calling_uri = (pjsip_sip_uri*)pjsip_uri_get_uri(rdata->msg_info.from->uri);
      calling_dn.add_var_param(calling_uri->user.slen, calling_uri->user.ptr);
      SAS::report_marker(calling_dn);
    }

    if (rdata->msg_info.to)
    {
      SAS::Marker called_dn(trail, MARKER_ID_CALLED_DN, 1u);
      pjsip_sip_uri* called_uri = (pjsip_sip_uri*)pjsip_uri_get_uri(rdata->msg_info.to->uri);
      called_dn.add_var_param(called_uri->user.slen, called_uri->user.ptr);
      SAS::report_marker(called_dn);
    }

    if (rdata->msg_info.cid)
    {
      SAS::Marker cid(trail, MARKER_ID_SIP_CALL_ID, 1u);
      cid.add_var_param(rdata->msg_info.cid->id.slen, rdata->msg_info.cid->id.ptr);
      SAS::report_marker(cid, SAS::Marker::Scope::Trace);
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
        analytics->auth_failure(PJUtils::pj_str_to_string(&auth_hdr->credential.digest.username),
                                PJUtils::aor_from_uri((pjsip_sip_uri*)pjsip_uri_get_uri(PJSIP_MSG_TO_HDR(rdata->msg_info.msg)->uri)));
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
    SAS::Marker end_marker(trail, MARKER_ID_END, 1u);
    SAS::report_marker(end_marker);
  }

  return PJ_TRUE;
}


pj_status_t init_authentication(const std::string& realm_name,
                                HSSConnection* hss_connection,
                                AnalyticsLogger* analytics_logger)
{
  pj_status_t status;

  hss = hss_connection;
  analytics = analytics_logger;

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
}

