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
#include "sproutsasevent.h"
#include "pjutils.h"
#include "constants.h"
#include "analyticslogger.h"
#include "hssconnection.h"
#include "authentication.h"
#include "avstore.h"
#include "snmp_success_fail_count_table.h"
#include "base64.h"


//
// mod_authentication authenticates SIP requests.  It must be inserted into the
// stack below the transaction layer.
//
static pj_bool_t authenticate_rx_request(pjsip_rx_data *rdata);

pjsip_module mod_authentication =
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

// Configuring PJSIP with a realm of "*" means that all realms are considered.
const pj_str_t WILDCARD_REALM = pj_str("*");

// Realm to use on AKA challenges.
static pj_str_t aka_realm;

// Connection to the HSS service for retrieving subscriber credentials.
static HSSConnection* hss;

static ChronosConnection* chronos;

// Factory for creating ACR messages for Rf billing.
static ACRFactory* acr_factory;


// AV store used to store Authentication Vectors while waiting for the
// client to respond to a challenge.
static AvStore* av_store;

// Analytics logger.
static AnalyticsLogger* analytics;

// SNMP tables counting authentication successes and failures.
static SNMP::AuthenticationStatsTables* auth_stats_tables;

// PJSIP structure for control server authentication functions.
pjsip_auth_srv auth_srv;
pjsip_auth_srv auth_srv_proxy;

// Controls when to challenge non-REGISTER messages.
NonRegisterAuthentication non_register_auth_mode;

// Retrieve the digest credentials (from the Authorization header for REGISTERs, and the
// Proxy-Authorization header otherwise).
static pjsip_digest_credential* get_credentials(const pjsip_rx_data* rdata)
{
  pjsip_authorization_hdr* auth_hdr;
  pjsip_digest_credential* credentials = NULL;

  if (rdata->msg_info.msg->line.req.method.id == PJSIP_REGISTER_METHOD)
  {
    auth_hdr = (pjsip_authorization_hdr*)pjsip_msg_find_hdr(rdata->msg_info.msg,
                                                            PJSIP_H_AUTHORIZATION,
                                                            NULL);
  }
  else
  {
    auth_hdr = (pjsip_proxy_authorization_hdr*)pjsip_msg_find_hdr(rdata->msg_info.msg,
                                                                  PJSIP_H_PROXY_AUTHORIZATION,
                                                                  NULL);
  }

  if (auth_hdr)
  {
    credentials = &auth_hdr->credential.digest;
  }

  return credentials;
}


/// Verifies that the supplied authentication vector is valid.
bool verify_auth_vector(rapidjson::Document* av, const std::string& impi, SAS::TrailId trail)
{
  bool rc = true;

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  av->Accept(writer);
  std::string av_str = buffer.GetString();
  TRC_DEBUG("Verifying AV: %s", av_str.c_str());

  // Check the AV is well formed.
  if (av->HasMember("aka"))
  {
    // AKA is specified, check all the expected parameters are present.
    TRC_DEBUG("AKA specified");
    rapidjson::Value& aka = (*av)["aka"];
    if (!(((aka.HasMember("challenge")) && (aka["challenge"].IsString())) &&
          ((aka.HasMember("response")) && (aka["response"].IsString())) &&
          ((aka.HasMember("cryptkey")) && (aka["cryptkey"].IsString())) &&
          ((aka.HasMember("integritykey")) && (aka["integritykey"].IsString()))))
    {
      // Malformed AKA entry
      TRC_INFO("Badly formed AKA authentication vector for %s",
               impi.c_str());
      rc = false;

      SAS::Event event(trail, SASEvent::AUTHENTICATION_FAILED_MALFORMED, 0);
      std::string error_msg = std::string("AKA authentication vector is malformed: ") + av_str.c_str();
      event.add_var_param(error_msg);
      SAS::report_event(event);
    }
  }
  else if (av->HasMember("digest"))
  {
    // Digest is specified, check all the expected parameters are present.
    TRC_DEBUG("Digest specified");
    rapidjson::Value& digest = (*av)["digest"];
    if (!(((digest.HasMember("realm")) && (digest["realm"].IsString())) &&
          ((digest.HasMember("qop")) && (digest["qop"].IsString())) &&
          ((digest.HasMember("ha1")) && (digest["ha1"].IsString()))))
    {
      // Malformed digest entry
      TRC_INFO("Badly formed Digest authentication vector for %s",
               impi.c_str());
      rc = false;

      SAS::Event event(trail, SASEvent::AUTHENTICATION_FAILED_MALFORMED, 0);
      std::string error_msg = std::string("Digest authentication vector is malformed: ") + av_str.c_str();;
      event.add_var_param(error_msg);
      SAS::report_event(event);
    }
  }
  else
  {
    // Neither AKA nor Digest information present.
    TRC_INFO("No AKA or Digest object in authentication vector for %s",
             impi.c_str());
    rc = false;

    SAS::Event event(trail, SASEvent::AUTHENTICATION_FAILED_MALFORMED, 0);
    std::string error_msg = std::string("Authentication vector is malformed: ") + av_str.c_str();
    event.add_var_param(error_msg);
    SAS::report_event(event);
  }

  return rc;
}


pj_status_t user_lookup(pj_pool_t *pool,
                        const pjsip_auth_lookup_cred_param *param,
                        pjsip_cred_info *cred_info,
                        void* av_param)
{
  const pj_str_t* acc_name = &param->acc_name;
  const pj_str_t* realm = &param->realm;
  const pjsip_rx_data* rdata = param->rdata;
  SAS::TrailId trail = get_trail(rdata);

  pj_status_t status = PJSIP_EAUTHACCNOTFOUND;

  // Get the impi and the nonce.  There must be an authorization header otherwise
  // PJSIP wouldn't have called this method.
  std::string impi = PJUtils::pj_str_to_string(acc_name);
  pjsip_digest_credential* credentials = get_credentials(rdata);
  std::string nonce = PJUtils::pj_str_to_string(&credentials->nonce);

  // Get the Authentication Vector from the store.
  rapidjson::Document* av = (rapidjson::Document*)av_param;

  if (av == NULL)
  {
    TRC_WARNING("Received an authentication request for %s with nonce %s, but no matching AV found", impi.c_str(), nonce.c_str());
  }

  if ((av != NULL) &&
      (!verify_auth_vector(av, impi, trail)))
  {
    // Authentication vector is badly formed.
    av = NULL;                                                 // LCOV_EXCL_LINE
  }

  if (av != NULL)
  {
    pj_cstr(&cred_info->scheme, "digest");
    pj_strdup(pool, &cred_info->username, acc_name);
    if (av->HasMember("aka"))
    {
      pjsip_param* auts_param = pjsip_param_find(&credentials->other_param,
                                                 &STR_AUTS);

      // AKA authentication.  The response in the AV must be used as a
      // plain-text password for the MD5 Digest computation.  Convert the text
      // into binary as this is what PJSIP is expecting. If we find the 'auts'
      // parameter, then leave the response as the empty string in accordance
      // with RFC 3310.
      std::string response = "";
      if (((*av)["aka"].HasMember("response")) &&
          ((*av)["aka"]["response"].IsString()) &&
          auts_param == NULL)
      {
        response = (*av)["aka"]["response"].GetString();
      }

      std::string xres;
      for (size_t ii = 0; ii < response.length(); ii += 2)
      {
        xres.push_back((char)(pj_hex_digit_to_val(response[ii]) * 16 +
                              pj_hex_digit_to_val(response[ii+1])));
      }
      cred_info->data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
      pj_strdup2(pool, &cred_info->data, xres.c_str());
      TRC_DEBUG("Found AKA XRES = %.*s", cred_info->data.slen, cred_info->data.ptr);

      // Use default realm as it isn't specified in the AV.
      pj_strdup(pool, &cred_info->realm, realm);
      status = PJ_SUCCESS;
    }
    else if (av->HasMember("digest"))
    {
      std::string digest_realm = "";
      if (((*av)["digest"].HasMember("realm")) &&
          ((*av)["digest"]["realm"].IsString()))
      {
        digest_realm = (*av)["digest"]["realm"].GetString();
      }

      if (pj_strcmp2(realm, digest_realm.c_str()) == 0)
      {
        // Digest authentication, so ha1 field is hashed password.
        cred_info->data_type = PJSIP_CRED_DATA_DIGEST;
        std::string digest_ha1 = "";
        if (((*av)["digest"].HasMember("ha1")) &&
            ((*av)["digest"]["ha1"].IsString()))
        {
          digest_ha1 = (*av)["digest"]["ha1"].GetString();
        }

        pj_strdup2(pool, &cred_info->data, digest_ha1.c_str());
        cred_info->realm = *realm;
        TRC_DEBUG("Found Digest HA1 = %.*s", cred_info->data.slen, cred_info->data.ptr);
        status = PJ_SUCCESS;
      }
      else
      {
        // These credentials are for a different realm, so no credentials were
        // actually provided for us to check.
        status = PJSIP_EAUTHNOAUTH;
      }
    }

    correlate_branch_from_av(av, trail);
  }

  return status;
}

void create_challenge(pjsip_digest_credential* credentials,
                      pj_bool_t stale,
                      std::string resync,
                      pjsip_rx_data* rdata,
                      pjsip_tx_data* tdata)
{
  // Get the public and private identities from the request.
  std::string impi;
  std::string impu;
  std::string nonce;

  PJUtils::get_impi_and_impu(rdata, impi, impu);
  // Set up the authorization type, following Annex P.4 of TS 33.203.  Currently
  // only support AKA and SIP Digest, so only implement the subset of steps
  // required to distinguish between the two.
  std::string auth_type;
  if (credentials != NULL)
  {
    pjsip_param* integrity =
           pjsip_param_find(&credentials->other_param,
                            &STR_INTEGRITY_PROTECTED);

    if ((integrity != NULL) &&
        ((pj_stricmp(&integrity->value, &STR_YES) == 0) ||
         (pj_stricmp(&integrity->value, &STR_NO) == 0)))
    {
      // Authentication scheme is AKA.
      auth_type = "aka";
    }
  }

  // Get the Authentication Vector from the HSS.
  rapidjson::Document* av = NULL;
  HTTPCode http_code = hss->get_auth_vector(impi, impu, auth_type, resync, av, get_trail(rdata));

  if ((av != NULL) &&
      (!verify_auth_vector(av, impi, get_trail(rdata))))
  {
    // Authentication Vector is badly formed.
    delete av;
    av = NULL;
  }

  if (av != NULL)
  {
    // Retrieved a valid authentication vector, so generate the challenge.
    TRC_DEBUG("Valid AV - generate challenge");
    char buf[16];
    pj_str_t random;
    random.ptr = buf;
    random.slen = sizeof(buf);

    pjsip_www_authenticate_hdr* hdr;
    if (rdata->msg_info.msg->line.req.method.id == PJSIP_REGISTER_METHOD)
    {
      TRC_DEBUG("Create WWW-Authenticate header");
      hdr = pjsip_www_authenticate_hdr_create(tdata->pool);
    }
    else
    {
      TRC_DEBUG("Create Proxy-Authenticate header");
      hdr = pjsip_proxy_authenticate_hdr_create(tdata->pool);
    }

    // Set up common fields for Digest and AKA cases (both are considered
    // Digest authentication).
    hdr->scheme = STR_DIGEST;

    if (av->HasMember("aka"))
    {
      // AKA authentication.
      TRC_DEBUG("Add AKA information");

      SAS::Event event(get_trail(rdata), SASEvent::AUTHENTICATION_CHALLENGE_AKA, 0);
      SAS::report_event(event);

      rapidjson::Value& aka = (*av)["aka"];

      // Use default realm for AKA as not specified in the AV.
      pj_strdup(tdata->pool, &hdr->challenge.digest.realm, &aka_realm);
      hdr->challenge.digest.algorithm = STR_AKAV1_MD5;

      if ((aka.HasMember("challenge")) &&
          (aka["challenge"].IsString()))
      {
        nonce = aka["challenge"].GetString();
      }

      pj_strdup2(tdata->pool, &hdr->challenge.digest.nonce, nonce.c_str());
      pj_create_random_string(buf, sizeof(buf));
      pj_strdup(tdata->pool, &hdr->challenge.digest.opaque, &random);
      hdr->challenge.digest.qop = STR_AUTH;
      hdr->challenge.digest.stale = stale;

      // Add the cryptography key parameter.
      pjsip_param* ck_param = (pjsip_param*)pj_pool_alloc(tdata->pool, sizeof(pjsip_param));
      ck_param->name = STR_CK;
      std::string cryptkey = "";
      if ((aka.HasMember("cryptkey")) &&
          (aka["cryptkey"].IsString()))
      {
        cryptkey = aka["cryptkey"].GetString();
      }
      std::string ck = "\"" + cryptkey + "\"";
      pj_strdup2(tdata->pool, &ck_param->value, ck.c_str());
      pj_list_insert_before(&hdr->challenge.digest.other_param, ck_param);

      // Add the integrity key parameter.
      pjsip_param* ik_param = (pjsip_param*)pj_pool_alloc(tdata->pool, sizeof(pjsip_param));
      ik_param->name = STR_IK;
      std::string integritykey = "";
      if ((aka.HasMember("integritykey")) &&
          (aka["integritykey"].IsString()))
      {
        integritykey = aka["integritykey"].GetString();
      }
      std::string ik = "\"" + integritykey + "\"";
      pj_strdup2(tdata->pool, &ik_param->value, ik.c_str());
      pj_list_insert_before(&hdr->challenge.digest.other_param, ik_param);
    }
    else
    {
      // Digest authentication.
      TRC_DEBUG("Add Digest information");

      SAS::Event event(get_trail(rdata), SASEvent::AUTHENTICATION_CHALLENGE_DIGEST, 0);
      SAS::report_event(event);

      rapidjson::Value& digest = (*av)["digest"];
      std::string realm = "";
      if ((digest.HasMember("realm")) &&
          (digest["realm"].IsString()))
      {
        realm = digest["realm"].GetString();
      }

      std::string qop = "";
      if ((digest.HasMember("qop")) &&
          (digest["qop"].IsString()))
      {
        qop = digest["qop"].GetString();
      }
      pj_strdup2(tdata->pool, &hdr->challenge.digest.realm, realm.c_str());
      hdr->challenge.digest.algorithm = STR_MD5;
      pj_create_random_string(buf, sizeof(buf));
      nonce.assign(buf, sizeof(buf));
      pj_strdup(tdata->pool, &hdr->challenge.digest.nonce, &random);
      pj_create_random_string(buf, sizeof(buf));
      pj_strdup(tdata->pool, &hdr->challenge.digest.opaque, &random);
      pj_strdup2(tdata->pool, &hdr->challenge.digest.qop, qop.c_str());
      hdr->challenge.digest.stale = stale;
    }

    // Add the header to the message.
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)hdr);

    // Store the branch parameter in memcached for correlation purposes
    pjsip_via_hdr* via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_VIA, NULL);
    std::string branch = (via_hdr != NULL) ? PJUtils::pj_str_to_string(&via_hdr->branch_param) : "";

    rapidjson::Value branch_value;
    branch_value.SetString(branch.c_str(), (*av).GetAllocator());
    (*av).AddMember("branch", branch_value, (*av).GetAllocator());

    // Write the authentication vector (as a JSON string) into the AV store.
    TRC_DEBUG("Write AV to store");
    uint64_t cas = 0;
    Store::Status status = av_store->set_av(impi, nonce, av, cas, get_trail(rdata));
    if (status == Store::OK)
    {
      // We've written the AV into the store, so need to set a Chronos
      // timer so that an AUTHENTICATION_TIMEOUT SAR is sent to the
      // HSS when it expires.
      std::string timer_id;
      std::string chronos_body = "{\"impi\": \"" + impi + "\", \"impu\": \"" + impu +"\", \"nonce\": \"" + nonce +"\"}";
      TRC_DEBUG("Sending %s to Chronos to set AV timer", chronos_body.c_str());
      chronos->send_post(timer_id, 30, "/authentication-timeout", chronos_body, get_trail(rdata));
    }

    delete av;
  }
  else
  {
    // If we couldn't get the AV because a downstream node is overloaded then don't return
    // a 4xx error to the client.
    if ((http_code == HTTP_SERVER_UNAVAILABLE) || (http_code == HTTP_GATEWAY_TIMEOUT))
    {
      TRC_DEBUG("Downstream node is overloaded or unresponsive, unable to get Authentication vector");
      tdata->msg->line.status.code = PJSIP_SC_SERVER_TIMEOUT;
      tdata->msg->line.status.reason = *pjsip_get_status_text(PJSIP_SC_SERVER_TIMEOUT);
      SAS::Event event(get_trail(rdata), SASEvent::AUTHENTICATION_FAILED_OVERLOAD, 0);
      SAS::report_event(event);
    }
    else
    {
      TRC_DEBUG("Failed to get Authentication vector");
      tdata->msg->line.status.code = PJSIP_SC_FORBIDDEN;
      tdata->msg->line.status.reason = *pjsip_get_status_text(PJSIP_SC_FORBIDDEN);
      SAS::Event event(get_trail(rdata), SASEvent::AUTHENTICATION_FAILED_NO_AV, 0);
      SAS::report_event(event);
    }

    pjsip_tx_data_invalidate_msg(tdata);
  }
}

// Determine whether this request should be challenged (and SAS log appropriately).
static pj_bool_t needs_authentication(pjsip_rx_data* rdata, SAS::TrailId trail)
{
  if (rdata->tp_info.transport->local_name.port != stack_data.scscf_port)
  {
    TRC_DEBUG("Request does not need authentication - not on S-CSCF port");
    // Request not received on S-CSCF port, so don't authenticate it.
    SAS::Event event(trail, SASEvent::AUTHENTICATION_NOT_NEEDED_NOT_SCSCF_PORT, 0);
    SAS::report_event(event);

    return PJ_FALSE;
  }

  if (rdata->msg_info.msg->line.req.method.id == PJSIP_REGISTER_METHOD)
  {
    // Authentication isn't required for emergency registrations. An emergency
    // registration is one where each Contact header contains 'sos' as the SIP
    // URI parameter.
    bool emergency_reg = true;

    pjsip_contact_hdr* contact_hdr = (pjsip_contact_hdr*)
      pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_CONTACT, NULL);

    while ((contact_hdr != NULL) && (emergency_reg))
    {
      emergency_reg = PJUtils::is_emergency_registration(contact_hdr);
      contact_hdr = (pjsip_contact_hdr*) pjsip_msg_find_hdr(rdata->msg_info.msg,
                                                            PJSIP_H_CONTACT,
                                                            contact_hdr->next);
    }

    if (emergency_reg)
    {
      SAS::Event event(trail, SASEvent::AUTHENTICATION_NOT_NEEDED_EMERGENCY_REGISTER, 0);
      SAS::report_event(event);

      return PJ_FALSE;
    }

    // Check to see if the request has already been integrity protected?
    pjsip_authorization_hdr* auth_hdr = (pjsip_authorization_hdr*)
      pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_AUTHORIZATION, NULL);

    if (auth_hdr != NULL)
    {
      // There is an authorization header, so check for the integrity-protected
      // indication.
      TRC_DEBUG("Authorization header in request");
      pjsip_param* integrity =
        pjsip_param_find(&auth_hdr->credential.digest.other_param,
                         &STR_INTEGRITY_PROTECTED);

      if ((integrity != NULL) &&
          ((pj_stricmp(&integrity->value, &STR_TLS_YES) == 0) ||
           (pj_stricmp(&integrity->value, &STR_IP_ASSOC_YES) == 0)))
      {
        // The integrity protected indicator is included and set to tls-yes or
        // ip-assoc-yes.  This indicates the client has already been authenticated
        // so we will accept this REGISTER even if there is a challenge response.
        // (Values of tls-pending or ip-assoc-pending indicate the challenge
        // should be checked.)
        TRC_INFO("SIP Digest authenticated request integrity protected by edge proxy");

        SAS::Event event(trail, SASEvent::AUTHENTICATION_NOT_NEEDED_INTEGRITY_PROTECTED, 0);
        SAS::report_event(event);

        return PJ_FALSE;
      }
      else if ((integrity != NULL) &&
               (pj_stricmp(&integrity->value, &STR_YES) == 0) &&
               (auth_hdr->credential.digest.response.slen == 0))
      {
        // The integrity protected indicator is include and set to yes.  This
        // indicates that AKA authentication is in use and the REGISTER was
        // received on an integrity protected channel, so we will let the
        // request through if there is no challenge response, but must check
        // the challenge response if included.
        TRC_INFO("AKA authenticated request integrity protected by edge proxy");

        SAS::Event event(trail, SASEvent::AUTHENTICATION_NOT_NEEDED_INTEGRITY_PROTECTED, 1);
        SAS::report_event(event);

        return PJ_FALSE;
      }
    }

    return PJ_TRUE;
  }
  else
  {
    if (PJSIP_MSG_TO_HDR(rdata->msg_info.msg)->tag.slen != 0)
    {
      // This is an in-dialog request which needs no authentication.
      return PJ_FALSE;
    }

    // Check to see if we should authenticate this non-REGISTER message - this
    if (non_register_auth_mode == NonRegisterAuthentication::NEVER)
    {
      // Configured to never authenticate non-REGISTER requests.
      SAS::Event event(trail, SASEvent::AUTHENTICATION_NOT_NEEDED_NEVER_AUTH_NON_REG, 0);
      SAS::report_event(event);
      return PJ_FALSE;
    }
    else if (non_register_auth_mode == NonRegisterAuthentication::IF_PROXY_AUTHORIZATION_PRESENT)
    {
      // Only authenticate the request if it has a Proxy-Authorization header.
      pjsip_proxy_authorization_hdr* auth_hdr = (pjsip_proxy_authorization_hdr*)
        pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_PROXY_AUTHORIZATION, NULL);

      if (auth_hdr != NULL)
      {
        // Edge proxy has explicitly asked us to authenticate this non-REGISTER
        // message
        SAS::Event event(trail, SASEvent::AUTHENTICATION_NEEDED_PROXY_AUTHORIZATION, 0);
        SAS::report_event(event);
        return PJ_TRUE;
      }
      else
      {
        // No Proxy-Authorization header - this indicates the P-CSCF trusts this
        // message so we don't need to perform further authentication.
        SAS::Event event(trail, SASEvent::AUTHENTICATION_NOT_NEEDED_PROXY_AUTHORIZATION, 0);
        SAS::report_event(event);
        return PJ_FALSE;
      }
    }
    else
    {
      // Unrecognized authentication mode - should never happen. LCOV_EXCL_START
      assert(!"Unrecognized authentication mode");
      return PJ_FALSE;
      // LCOV_EXCL_STOP
    }
  }
}

pj_bool_t authenticate_rx_request(pjsip_rx_data* rdata)
{
  TRC_DEBUG("Authentication module invoked");
  pj_status_t status;
  bool is_register = (rdata->msg_info.msg->line.req.method.id == PJSIP_REGISTER_METHOD);
  SNMP::SuccessFailCountTable* auth_stats_table = NULL;
  std::string resync;

  SAS::TrailId trail = get_trail(rdata);

  if (!needs_authentication(rdata, trail))
  {
    TRC_DEBUG("Request does not need authentication");
    return PJ_FALSE;
  }

  TRC_DEBUG("Request needs authentication");
  rapidjson::Document* av = NULL;

  const int unauth_sc = is_register ? PJSIP_SC_UNAUTHORIZED : PJSIP_SC_PROXY_AUTHENTICATION_REQUIRED;
  int sc = unauth_sc;
  status = PJSIP_EAUTHNOAUTH;

  pjsip_digest_credential* credentials = get_credentials(rdata);

  if ((credentials != NULL) &&
      (credentials->response.slen != 0))
  {
    std::string impi = PJUtils::pj_str_to_string(&credentials->username);
    std::string nonce = PJUtils::pj_str_to_string(&credentials->nonce);
    uint64_t cas = 0;
    av = av_store->get_av(impi, nonce, cas, trail);

    if (!is_register)
    {
      // Challenged non-register requests must be SIP digest, so only one table
      // needed for this case.
      auth_stats_table = auth_stats_tables->non_register_auth_tbl;
    }
    else
    {
      if (!pj_strcmp2(&credentials->algorithm, "MD5"))
      {
        auth_stats_table = auth_stats_tables->sip_digest_auth_tbl;
      }
      else if (!pj_strcmp2(&credentials->algorithm, "AKAv1-MD5"))
      {
        auth_stats_table = auth_stats_tables->ims_aka_auth_tbl;
      }
      else
      {
        // Authorization header did not specify an algorithm, so check the av for
        // this information instead.
        if ((av != NULL) && (av->HasMember("aka")))
        {
          auth_stats_table = auth_stats_tables->ims_aka_auth_tbl;
        }
        else
        {
          // Use the digest table if the AV specified digest, or as a fallback if there was no AV
          auth_stats_table = auth_stats_tables->sip_digest_auth_tbl;
        }
      }
    }

    if (auth_stats_table != NULL)
    {
      auth_stats_table->increment_attempts();
    }

    // Request contains a response to a previous challenge, so pass it to
    // the authentication module to verify.
    TRC_DEBUG("Verify authentication information in request");
    status = pjsip_auth_srv_verify2((is_register ? &auth_srv : &auth_srv_proxy), rdata, &sc, (void*)av);

    if (status == PJ_SUCCESS)
    {
      // The authentication information in the request was verified.
      TRC_DEBUG("Request authenticated successfully");

      SAS::Event event(trail, SASEvent::AUTHENTICATION_SUCCESS, 0);
      SAS::report_event(event);

      if (auth_stats_table != NULL)
      {
        auth_stats_table->increment_successes();
      }

      // Write a tombstone flag back to the AV store, handling contention.
      // We don't actually expect anything else to be writing to this row in
      // the AV store, but there is a window condition where we failed to read
      // from the primary, successfully read from the backup (with a different
      // CAS value) and then try to write back to the primary, which fails due
      // to "contention".
      Store::Status store_status;
      do
      {
        // Set the tomestone flag in the JSON authentication vector.
        rapidjson::Value tombstone_value;
        tombstone_value.SetBool(true);
        av->AddMember("tombstone", tombstone_value, (*av).GetAllocator());

        // Store it.  If this fails due to contention, read the updated JSON.
        store_status = av_store->set_av(impi, nonce, av, cas, trail);
        if (store_status == Store::DATA_CONTENTION)
        {
          // LCOV_EXCL_START - No support for contention in UT
          TRC_DEBUG("Data contention writing tombstone - retry");
          delete av;
          av = av_store->get_av(impi, nonce, cas, trail);
          if (av == NULL)
          {
            store_status = Store::ERROR;
          }
          // LCOV_EXCL_STOP
        }
      }
      while (store_status == Store::DATA_CONTENTION);

      if (store_status != Store::OK)
      {
        // LCOV_EXCL_START
        TRC_ERROR("Tried to tombstone AV for %s/%s after processing an authentication, but failed",
                  impi.c_str(),
                  nonce.c_str());
        // LCOV_EXCL_STOP
      }

      // If doing AKA authentication, check for an AUTS parameter.  We only
      // check this if the request authenticated as actioning it otherwise
      // is a potential denial of service attack.
      if (!pj_strcmp(&credentials->algorithm, &STR_AKAV1_MD5))
      {
        TRC_DEBUG("AKA authentication so check for client resync request");
        pjsip_param* p = pjsip_param_find(&credentials->other_param,
                                          &STR_AUTS);

        if (p != NULL)
        {
          // Found AUTS parameter, so UE is requesting a resync.  We need to
          // redo the authentication, passing an auts parameter to the HSS
          // comprising the first 16 octets of the nonce (RAND) and the 14
          // octets of the auts parameter.  (See TS 33.203 and table 6.3.3 of
          // TS 29.228 for details.)
          TRC_DEBUG("AKA SQN resync request from UE");
          std::string auts = PJUtils::pj_str_to_string(&p->value);
          std::string nonce = PJUtils::pj_str_to_string(&credentials->nonce);

          // Convert the auts and nonce to binary for manipulation
          nonce = base64_decode(nonce);
          auts  = base64_decode(auts);

          if ((auts.length() != 14) ||
              (nonce.length() != 32))
          {
            // AUTS and/or nonce are malformed, so reject the request.
            TRC_WARNING("Invalid auts/nonce on resync request from private identity %.*s",
                        credentials->username.slen,
                        credentials->username.ptr);
            status = PJSIP_EAUTHINAKACRED;
            sc = PJSIP_SC_FORBIDDEN;
          }
          else
          {
            // auts and nonce are as expected, so create the resync string
            // that needs to be passed to the HSS, and act as if no
            // authentication information was received. The resync string
            // should be RAND || AUTS.
            resync = base64_encode(nonce.substr(0, 16) + auts);
            status = PJSIP_EAUTHNOAUTH;
            sc = unauth_sc;
          }
        }
      }

      if (status == PJ_SUCCESS)
      {
        // Request authentication completed, so let the message through to other
        // modules. Remove any Proxy-Authorization headers first so they are not
        // passed to downstream devices. We can't do this for Authorization
        // headers, as these may need to be included in 3rd party REGISTER
        // messages.
        while (pjsip_msg_find_remove_hdr(rdata->msg_info.msg,
                                         PJSIP_H_PROXY_AUTHORIZATION,
                                         NULL) != NULL);
        delete av;
        return PJ_FALSE;
      }
    }
  }


  // The message either has insufficient authentication information, or
  // has failed authentication.  In either case, the message will be
  // absorbed and responded to by the authentication module, so we need to
  // add SAS markers so the trail will become searchable.
  SAS::Marker start_marker(trail, MARKER_ID_START, 1u);
  SAS::report_marker(start_marker);

  // Add a SAS end marker
  SAS::Marker end_marker(trail, MARKER_ID_END, 1u);
  SAS::report_marker(end_marker);

  // Create an ACR for the message and pass the request to it.  Role is always
  // considered originating for a REGISTER request.
  ACR* acr = acr_factory->get_acr(trail,
                                  CALLING_PARTY,
                                  NODE_ROLE_ORIGINATING);
  acr->rx_request(rdata->msg_info.msg, rdata->pkt_info.timestamp);

  pjsip_tx_data* tdata;

  if ((status == PJSIP_EAUTHNOAUTH) ||
      (status == PJSIP_EAUTHACCNOTFOUND))
  {
    // No authorization information in request, or no authentication vector
    // found in the store (so request is likely stale), so must issue
    // challenge.
    TRC_DEBUG("No authentication information in request or stale nonce, so reject with challenge");
    pj_bool_t stale = (status == PJSIP_EAUTHACCNOTFOUND);

    sc = unauth_sc;

    if (stale && auth_stats_table != NULL)
    {
      auth_stats_table->increment_failures();
    }

    status = PJUtils::create_response(stack_data.endpt, rdata, sc, NULL, &tdata);

    if (status != PJ_SUCCESS)
    {
      // Failed to create a response.  This really shouldn't happen, but there
      // is nothing else we can do.
      // LCOV_EXCL_START
      delete acr;
      return PJ_TRUE;
      // LCOV_EXCL_STOP
    }

    create_challenge(credentials, stale, resync, rdata, tdata);
  }
  else
  {
    // Authentication failed.
    std::string error_msg = PJUtils::pj_status_to_string(status);

    TRC_ERROR("Authentication failed, %s", error_msg.c_str());
    if (auth_stats_table != NULL)
    {
      auth_stats_table->increment_failures();
    }
    SAS::Event event(trail, SASEvent::AUTHENTICATION_FAILED, 0);
    event.add_var_param(error_msg);
    SAS::report_event(event);

    if (sc != unauth_sc)
    {
      // Notify Homestead and the HSS that this authentication attempt
      // has definitively failed.
      std::string impi;
      std::string impu;

      PJUtils::get_impi_and_impu(rdata, impi, impu);

      hss->update_registration_state(impu, impi, HSSConnection::AUTH_FAIL, trail);
    }

    if (analytics != NULL)
    {
      analytics->auth_failure(PJUtils::pj_str_to_string(&credentials->username),
      PJUtils::public_id_from_uri((pjsip_uri*)pjsip_uri_get_uri(PJSIP_MSG_TO_HDR(rdata->msg_info.msg)->uri)));
    }

    status = PJUtils::create_response(stack_data.endpt, rdata, sc, NULL, &tdata);
    if (status != PJ_SUCCESS)
    {
      // Failed to create a response.  This really shouldn't happen, but there
      // is nothing else we can do.
      // LCOV_EXCL_START
      delete acr;
      return PJ_TRUE;
      // LCOV_EXCL_STOP
    }
  }

  acr->tx_response(tdata->msg);

  // Issue the challenge response transaction-statefully. This is so that:
  //  * if we challenge an INVITE, the UE can ACK the 407
  //  * if a challenged request gets retransmitted, we don't repeat the work
  pjsip_transaction* tsx = NULL;
  status = pjsip_tsx_create_uas2(NULL, rdata, NULL, &tsx);
  set_trail(tsx, trail);
  if (status != PJ_SUCCESS)
  {
    // LCOV_EXCL_START - defensive code not hit in UT
    TRC_WARNING("Couldn't create PJSIP transaction for authentication response: %d"
                " (sending statelessly instead)", status);
    // Send the response statelessly in this case - it's better than nothing
    pjsip_endpt_send_response2(stack_data.endpt, rdata, tdata, NULL, NULL);
    // LCOV_EXCL_STOP
  }
  else
  {
    // Let the tsx know about the original message
    pjsip_tsx_recv_msg(tsx, rdata);
    // Send our response in this transaction
    pjsip_tsx_send_msg(tsx, tdata);
  }

  // Send the ACR.
  acr->send();
  delete acr;
  delete av;
  return PJ_TRUE;
}


pj_status_t init_authentication(const std::string& realm_name,
                                AvStore* avstore,
                                HSSConnection* hss_connection,
                                ChronosConnection* chronos_connection,
                                ACRFactory* rfacr_factory,
                                NonRegisterAuthentication non_register_auth_mode_param,
                                AnalyticsLogger* analytics_logger,
                                SNMP::AuthenticationStatsTables* auth_stats_tbls)
{
  pj_status_t status;

  aka_realm = (realm_name != "") ? pj_strdup3(stack_data.pool, realm_name.c_str()) : stack_data.local_host;
  av_store = avstore;
  hss = hss_connection;
  chronos = chronos_connection;
  acr_factory = rfacr_factory;
  analytics = analytics_logger;
  auth_stats_tables = auth_stats_tbls;

  // Register the authentication module.  This needs to be in the stack
  // before the transaction layer.
  status = pjsip_endpt_register_module(stack_data.endpt, &mod_authentication);

  // Initialize the authorization server.
  pjsip_auth_srv_init_param params;
  params.realm = &WILDCARD_REALM;
  params.lookup3 = user_lookup;
  params.options = 0;
  status = pjsip_auth_srv_init2(stack_data.pool, &auth_srv, &params);

  params.options = PJSIP_AUTH_SRV_IS_PROXY;
  status = pjsip_auth_srv_init2(stack_data.pool, &auth_srv_proxy, &params);

  non_register_auth_mode = non_register_auth_mode_param;

  return status;
}


void destroy_authentication()
{
  pjsip_endpt_unregister_module(stack_data.endpt, &mod_authentication);
}
