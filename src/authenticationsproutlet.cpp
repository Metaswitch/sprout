/**
 * @file authenticationsproutlet.cpp
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2016  Metaswitch Networks Ltd
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

#include "constants.h"
#include "sproutsasevent.h"
#include "authenticationsproutlet.h"
#include "sproutletproxy.h"
#include "json_parse_utils.h"
#include <openssl/hmac.h>
#include "base64.h"

// Configuring PJSIP with a realm of "*" means that all realms are considered.
const pj_str_t WILDCARD_REALM = pj_str((char*)"*");

// Initial expiry time (in seconds) for authentication challenges.  This should
// always be long enough for the UE to respond to the authentication challenge,
// and means that on authentication timeout our 30-second Chronos timer should
// pop before it expires.
const uint32_t AUTH_CHALLENGE_INIT_EXPIRES = 40;

std::string unhex(std::string hexstr)
{
  std::string ret = "";

  for (size_t ii = 0; ii < hexstr.length(); ii += 2)
  {
    ret.push_back((char)(pj_hex_digit_to_val(hexstr[ii]) * 16 +
                         pj_hex_digit_to_val(hexstr[ii+1])));
  }

  return ret;
}

//
// Authentication Sproutlet methods.
//

AuthenticationSproutlet::AuthenticationSproutlet(const std::string& name,
                                                 int port,
                                                 const std::string& uri,
                                                 const std::string& next_hop_service,
                                                 const std::list<std::string>& aliases,
                                                 const std::string& realm_name,
                                                 ImpiStore* _impi_store,
                                                 HSSConnection* hss_connection,
                                                 ChronosConnection* chronos_connection,
                                                 ACRFactory* rfacr_factory,
                                                 NonRegisterAuthentication non_register_auth_mode_param,
                                                 AnalyticsLogger* analytics_logger,
                                                 SNMP::AuthenticationStatsTables* auth_stats_tbls,
                                                 bool nonce_count_supported_arg,
                                                 get_expiry_for_binding_fn get_expiry_for_binding_arg) :
  Sproutlet(name, port, uri),
  _aka_realm((realm_name != "") ?
    pj_strdup3(stack_data.pool, realm_name.c_str()) :
    stack_data.local_host),
  _hss(hss_connection),
  _chronos(chronos_connection),
  _acr_factory(rfacr_factory),
  _impi_store(_impi_store),
  _analytics(analytics_logger),
  _auth_stats_tables(auth_stats_tbls),
  _nonce_count_supported(nonce_count_supported_arg),
  _get_expiry_for_binding(get_expiry_for_binding_arg),
  _non_register_auth_mode(non_register_auth_mode_param),
  _next_hop_service(next_hop_service),
  _aliases(aliases)
{
}

AuthenticationSproutlet::~AuthenticationSproutlet() {}

bool AuthenticationSproutlet::init()
{
  pj_status_t status;

  // Initialize the authorization server.
  pjsip_auth_srv_init_param params;
  params.realm = &WILDCARD_REALM;
  params.lookup3 = AuthenticationSproutletTsx::user_lookup;
  params.options = 0;
  status = pjsip_auth_srv_init2(stack_data.pool, &_auth_srv, &params);

  params.options = PJSIP_AUTH_SRV_IS_PROXY;
  status = pjsip_auth_srv_init2(stack_data.pool, &_auth_srv_proxy, &params);

  if (status != PJ_SUCCESS)
  {
    // LCOV_EXCL_START - Don't test initialization failures in UT
    TRC_ERROR("Authentication sproutlet failed to initialize (%d)", status);
    // LCOV_EXCL_STOP
  }

  return (status == PJ_SUCCESS);
}

SproutletTsx* AuthenticationSproutlet::get_tsx(SproutletProxy* proxy,
                                               const std::string& alias,
                                               pjsip_msg* req,
                                               pjsip_sip_uri*& next_hop,
                                               pj_pool_t* pool,
                                               SAS::TrailId trail)
{
  if (needs_authentication(req, trail))
  {
    return new AuthenticationSproutletTsx(_next_hop_service, this);
  }

  // We're not interested in the message so create a next hop URI.
  pjsip_route_hdr* route = (pjsip_route_hdr*)
                              pjsip_msg_find_hdr(req, PJSIP_H_ROUTE, NULL);

  pjsip_sip_uri* base_uri = (pjsip_sip_uri*)(route ? route->name_addr.uri : nullptr);
  next_hop = proxy->create_internal_sproutlet_uri(pool,
                                                  _next_hop_service,
                                                  base_uri);

  return NULL;
}


const std::list<std::string> AuthenticationSproutlet::aliases() const
{
  return { _aliases };
}

// Determine whether this request should be challenged (and SAS log appropriately).
bool AuthenticationSproutlet::needs_authentication(pjsip_msg* req,
                                                   SAS::TrailId trail)
{
  if (req->line.req.method.id == PJSIP_REGISTER_METHOD)
  {
    // Authentication isn't required for emergency registrations. An emergency
    // registration is one where each Contact header contains 'sos' as the SIP
    // URI parameter.
    //
    // Note that a REGISTER with NO contact headers does not count as an
    // emergency registration.
    pjsip_contact_hdr* contact_hdr = (pjsip_contact_hdr*)
      pjsip_msg_find_hdr(req, PJSIP_H_CONTACT, NULL);

    if (contact_hdr != NULL)
    {
      bool all_bindings_emergency = true;

      while ((contact_hdr != NULL) && (all_bindings_emergency))
      {
        all_bindings_emergency = PJUtils::is_emergency_registration(contact_hdr);
        contact_hdr = (pjsip_contact_hdr*) pjsip_msg_find_hdr(req,
                                                              PJSIP_H_CONTACT,
                                                              contact_hdr->next);
      }

      if (all_bindings_emergency)
      {
        SAS::Event event(trail, SASEvent::AUTHENTICATION_NOT_NEEDED_EMERGENCY_REGISTER, 0);
        SAS::report_event(event);

        return PJ_FALSE;
      }
    }

    // Check to see if the request has already been integrity protected?
    pjsip_authorization_hdr* auth_hdr = (pjsip_authorization_hdr*)
      pjsip_msg_find_hdr(req, PJSIP_H_AUTHORIZATION, NULL);

    if (auth_hdr != NULL)
    {
      // There is an authorization header, so check for the integrity-protected
      // indication.
      TRC_DEBUG("Authorization header in request");
      pjsip_param* integrity =
        pjsip_param_find(&auth_hdr->credential.digest.other_param,
                         &STR_INTEGRITY_PROTECTED);

      if (integrity != NULL)
      {
        TRC_DEBUG("Integrity protected with %.*s",
                  integrity->value.slen, integrity->value.ptr);

        if ((pj_stricmp(&integrity->value, &STR_TLS_YES) == 0) ||
            (pj_stricmp(&integrity->value, &STR_IP_ASSOC_YES) == 0))
        {
          // The integrity protected indicator is included and set to tls-yes or
          // ip-assoc-yes.  This indicates the client has already been authenticated
          // so we will accept this REGISTER even if there is a challenge response.
          // Values of tls-pending or ip-assoc-pending indicate the challenge
          // should be checked.
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
          return PJ_FALSE;
        }
      }
    }

    return PJ_TRUE;
  }
  else
  {
    // Check to see if we should authenticate this non-REGISTER message - this
    if (_non_register_auth_mode == NonRegisterAuthentication::NEVER)
    {
      // Configured to never authenticate non-REGISTER requests.
      SAS::Event event(trail, SASEvent::AUTHENTICATION_NOT_NEEDED_NEVER_AUTH_NON_REG, 0);
      SAS::report_event(event);
      return PJ_FALSE;
    }
    else if (_non_register_auth_mode == NonRegisterAuthentication::IF_PROXY_AUTHORIZATION_PRESENT)
    {
      // Only authenticate the request if it has a Proxy-Authorization header.
      pjsip_proxy_authorization_hdr* auth_hdr = (pjsip_proxy_authorization_hdr*)
        pjsip_msg_find_hdr(req, PJSIP_H_PROXY_AUTHORIZATION, NULL);

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

//
// Authentication Sproutlet Tsx methods.
//

AuthenticationSproutletTsx::AuthenticationSproutletTsx(const std::string& next_hop_service,
                                                       AuthenticationSproutlet* auth_sproutlet) :
  ForwardingSproutletTsx(next_hop_service),
  _sproutlet(auth_sproutlet)
{
}

AuthenticationSproutletTsx::~AuthenticationSproutletTsx() {}

// Retrieve the digest credentials (from the Authorization header for REGISTERs, and the
// Proxy-Authorization header otherwise).
pjsip_digest_credential* AuthenticationSproutletTsx::get_credentials(const pjsip_msg* req)
{
  pjsip_authorization_hdr* auth_hdr;
  pjsip_digest_credential* credentials = NULL;

  if (req->line.req.method.id == PJSIP_REGISTER_METHOD)
  {
    auth_hdr = (pjsip_authorization_hdr*)pjsip_msg_find_hdr(req,
                                                            PJSIP_H_AUTHORIZATION,
                                                            NULL);
  }
  else
  {
    auth_hdr = (pjsip_proxy_authorization_hdr*)pjsip_msg_find_hdr(req,
                                                                  PJSIP_H_PROXY_AUTHORIZATION,
                                                                  NULL);
  }

  if (auth_hdr)
  {
    credentials = &auth_hdr->credential.digest;
  }

  return credentials;
}

/// Given a request that has passed authentication, calculate the time at which
/// to expire the challenge.
///
/// @param req - The request in question.
///
/// @return The expiry time of the binding (in seconds since the epoch).
int AuthenticationSproutletTsx::calculate_challenge_expiration_time(pjsip_msg* req)
{
  int expires = 0;

  pjsip_expires_hdr* expires_hdr = (pjsip_expires_hdr*)
    pjsip_msg_find_hdr(req, PJSIP_H_EXPIRES, NULL);

  for (pjsip_contact_hdr* contact_hdr = (pjsip_contact_hdr*)
          pjsip_msg_find_hdr(req, PJSIP_H_CONTACT, NULL);
       contact_hdr != NULL;
       contact_hdr = (pjsip_contact_hdr*)
          pjsip_msg_find_hdr(req, PJSIP_H_CONTACT, contact_hdr->next))
  {
    expires = std::max(expires, _sproutlet->_get_expiry_for_binding(contact_hdr, expires_hdr));
  }

  return expires + time(NULL);
}

/// Verifies that the supplied authentication vector is valid.
bool AuthenticationSproutletTsx::verify_auth_vector(rapidjson::Document* av,
                                                    const std::string& impi)
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

      SAS::Event event(trail(), SASEvent::AUTHENTICATION_FAILED_MALFORMED, 0);
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

      SAS::Event event(trail(), SASEvent::AUTHENTICATION_FAILED_MALFORMED, 0);
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

    SAS::Event event(trail(), SASEvent::AUTHENTICATION_FAILED_MALFORMED, 0);
    std::string error_msg = std::string("Authentication vector is malformed: ") + av_str.c_str();
    event.add_var_param(error_msg);
    SAS::report_event(event);
  }

  return rc;
}

pj_status_t AuthenticationSproutletTsx::user_lookup(pj_pool_t *pool,
                                                    const pjsip_auth_lookup_cred_param *param,
                                                    pjsip_cred_info *cred_info,
                                                    void* auth_challenge_param)
{
  const pj_str_t* acc_name = &param->acc_name;
  const pj_str_t* realm = &param->realm;
  const pjsip_msg* req = param->msg;

  pj_status_t status = PJSIP_EAUTHACCNOTFOUND;

  // Get the impi and the nonce.  There must be an authorization header otherwise
  // PJSIP wouldn't have called this method.
  std::string impi = PJUtils::pj_str_to_string(acc_name);
  pjsip_digest_credential* credentials = get_credentials(req);
  std::string nonce = PJUtils::pj_str_to_string(&credentials->nonce);

  // Get the Authentication Vector from the store.
  ImpiStore::AuthChallenge* auth_challenge = (ImpiStore::AuthChallenge*)auth_challenge_param;

  if (auth_challenge == NULL)
  {
    TRC_DEBUG("Received an authentication request for %s with nonce %s, but no matching challenge found", impi.c_str(), nonce.c_str());
  }

  if (auth_challenge != NULL)
  {
    pj_cstr(&cred_info->scheme, "digest");
    pj_strdup(pool, &cred_info->username, acc_name);
    if (auth_challenge->type == ImpiStore::AuthChallenge::Type::AKA)
    {
      ImpiStore::AKAAuthChallenge* aka_challenge = (ImpiStore::AKAAuthChallenge*)auth_challenge;
      pjsip_param* auts_param = pjsip_param_find(&credentials->other_param,
                                                 &STR_AUTS);

      // AKA authentication.  The response in the challenge must be used as a
      // plain-text password for the MD5 Digest computation.  Convert the text
      // into binary as this is what PJSIP is expecting. If we find the 'auts'
      // parameter, then leave the response as the empty string in accordance
      // with RFC 3310.
      std::string xres = "";
      if (auts_param == NULL)
      {
        xres = unhex(aka_challenge->response);
      }

      cred_info->data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
      pj_strdup4(pool, &cred_info->data, xres.data(), xres.length());
      TRC_DEBUG("Found AKA XRES = %.*s", cred_info->data.slen, cred_info->data.ptr);

      // Use default realm as it isn't specified in the AV.
      pj_strdup(pool, &cred_info->realm, realm);
      status = PJ_SUCCESS;
    }
    else if (auth_challenge->type == ImpiStore::AuthChallenge::Type::DIGEST)
    {
      ImpiStore::DigestAuthChallenge* digest_challenge = (ImpiStore::DigestAuthChallenge*)auth_challenge;

      if (pj_strcmp2(realm, digest_challenge->realm.c_str()) == 0)
      {
        // Digest authentication, so ha1 field is hashed password.
        cred_info->data_type = PJSIP_CRED_DATA_DIGEST;
        pj_strdup2(pool, &cred_info->data, digest_challenge->ha1.c_str());
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
  }

  return status;
}

void AuthenticationSproutletTsx::create_challenge(pjsip_digest_credential* credentials,
                                                  pj_bool_t stale,
                                                  std::string resync,
                                                  pjsip_msg* req,
                                                  pjsip_msg* rsp)
{
  // Get the public and private identities from the request.
  std::string impi;
  std::string impu;
  std::string nonce;
  PJUtils::get_impi_and_impu(req, impi, impu);

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

    // Also check for algorithm=AKAv2-MD5, which is how we've seen AKAv2
    // support requested
    if (pj_stricmp(&credentials->algorithm, &STR_AKAV2_MD5) == 0)
    {
      auth_type = "aka2";
    }
  }

  // Get the Authentication Vector from the HSS.
  rapidjson::Document* av = NULL;
  HTTPCode http_code = _sproutlet->_hss->get_auth_vector(impi, impu, auth_type, resync, av, trail());

  if ((av != NULL) &&
      (!verify_auth_vector(av, impi)))
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
    if (req->line.req.method.id == PJSIP_REGISTER_METHOD)
    {
      TRC_DEBUG("Create WWW-Authenticate header");
      hdr = pjsip_www_authenticate_hdr_create(get_pool(rsp));
    }
    else
    {
      TRC_DEBUG("Create Proxy-Authenticate header");
      hdr = pjsip_proxy_authenticate_hdr_create(get_pool(rsp));
    }

    // Set up common fields for Digest and AKA cases (both are considered
    // Digest authentication).
    hdr->scheme = STR_DIGEST;
    pj_pool_t* rsp_pool = get_pool(rsp);

    ImpiStore::AuthChallenge* auth_challenge;
    if (av->HasMember("aka"))
    {
      // AKA authentication.
      TRC_DEBUG("Add AKA information");

      SAS::Event event(trail(), SASEvent::AUTHENTICATION_CHALLENGE_AKA, 0);
      SAS::report_event(event);

      rapidjson::Value& aka = (*av)["aka"];

      std::string cryptkey = "";
      std::string integritykey = "";
      std::string xres = "";

      // AKA version defaults to 1, for back-compatibility with pre-AKAv2
      // Homestead versions.
      int akaversion = 1;

      JSON_SAFE_GET_STRING_MEMBER(aka, "challenge", nonce);
      JSON_SAFE_GET_STRING_MEMBER(aka, "cryptkey", cryptkey);
      JSON_SAFE_GET_STRING_MEMBER(aka, "integritykey", integritykey);
      JSON_SAFE_GET_STRING_MEMBER(aka, "response", xres);
      JSON_SAFE_GET_INT_MEMBER(aka, "version", akaversion);

      // Use default realm for AKA as not specified in the AV.
      pj_strdup(rsp_pool, &hdr->challenge.digest.realm, &_sproutlet->_aka_realm);
      hdr->challenge.digest.algorithm = ((akaversion == 2) ? STR_AKAV2_MD5 : STR_AKAV1_MD5);

      pj_strdup2(rsp_pool, &hdr->challenge.digest.nonce, nonce.c_str());
      pj_create_random_string(buf, sizeof(buf));
      pj_strdup(rsp_pool, &hdr->challenge.digest.opaque, &random);
      hdr->challenge.digest.qop = STR_AUTH;
      hdr->challenge.digest.stale = stale;

      // Add the cryptography key parameter.
      pjsip_param* ck_param = (pjsip_param*)pj_pool_alloc(rsp_pool, sizeof(pjsip_param));
      ck_param->name = STR_CK;
      std::string ck = "\"" + cryptkey + "\"";
      pj_strdup2(rsp_pool, &ck_param->value, ck.c_str());
      pj_list_insert_before(&hdr->challenge.digest.other_param, ck_param);

      // Add the integrity key parameter.
      pjsip_param* ik_param = (pjsip_param*)pj_pool_alloc(rsp_pool, sizeof(pjsip_param));
      ik_param->name = STR_IK;
      std::string ik = "\"" + integritykey + "\"";
      pj_strdup2(rsp_pool, &ik_param->value, ik.c_str());
      pj_list_insert_before(&hdr->challenge.digest.other_param, ik_param);

      // Calculate the response.  We must not provide this on the SIP message,
      // but we will put it in the store.
      std::string response;

      if (akaversion == 2)
      {
        // In AKAv2, the password for the SIP Digest calculation should be the
        // base64 encoding of:
        //
        //  HMAC_MD5(XRES||IK||CK, "http-digest-akav2-password")
        //
        // We need to:
        //
        // - concatenate the XRES, IK and CK
        // - convert that from the ASCII hex string Homestead sends us to the
        //   binary representation
        // - call the OpenSSL HMAC function to hash the string
        //   "http-digest-akav2-password", using that binary concatenation as
        //   the key
        // - base64-encode that
        std::string joined = unhex(xres + integritykey + cryptkey);
        std::string formality = "http-digest-akav2-password";
        unsigned int digest_len;
        unsigned char hmac[EVP_MAX_MD_SIZE];
        unsigned char* digest = HMAC(EVP_md5(),
                                     (unsigned char*)joined.data(),
                                     joined.size(),
                                     (unsigned char*)(formality.data()),
                                     formality.size(),
                                     hmac,
                                     &digest_len);
        std::string password = base64_encode(std::string((char*) digest, digest_len));

        // We hex-decode this when getting it out of memcached later (for
        // consistency with AKAv1) so hex-encode it now.
        response = Utils::hex((uint8_t*)password.data(), password.size());
      }
      else
      {
        // In AKAv1, the XRES is used directly as the password in the SIP
        // Digest calculation. We want it hex-encoded for storing in memcached,
        // but it's already been hex-encoded by Homestead, so nothing to do.
        response = xres;
      }

      // Now build the AuthChallenge so that we can store it in the ImpiStore.
      auth_challenge = new ImpiStore::AKAAuthChallenge(nonce,
                                                       response,
                                                       time(NULL) + AUTH_CHALLENGE_INIT_EXPIRES);
    }
    else
    {
      // Digest authentication.
      TRC_DEBUG("Add Digest information");

      SAS::Event event(trail(), SASEvent::AUTHENTICATION_CHALLENGE_DIGEST, 0);
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
      pj_strdup2(rsp_pool, &hdr->challenge.digest.realm, realm.c_str());
      hdr->challenge.digest.algorithm = STR_MD5;
      pj_create_random_string(buf, sizeof(buf));
      nonce.assign(buf, sizeof(buf));
      pj_strdup(rsp_pool, &hdr->challenge.digest.nonce, &random);
      pj_create_random_string(buf, sizeof(buf));
      pj_strdup(rsp_pool, &hdr->challenge.digest.opaque, &random);
      pj_strdup2(rsp_pool, &hdr->challenge.digest.qop, qop.c_str());
      hdr->challenge.digest.stale = stale;

      // Get the HA1 digest.  We must not provide this on the SIP message, but
      // we will put it in the store.
      std::string ha1 = "";
      if ((digest.HasMember("ha1")) &&
          (digest["ha1"].IsString()))
      {
        ha1 = digest["ha1"].GetString();
      }

      // Now build the AuthChallenge so that we can store it in the ImpiStore.
      auth_challenge = new ImpiStore::DigestAuthChallenge(nonce,
                                                          realm,
                                                          qop,
                                                          ha1,
                                                          time(NULL) + AUTH_CHALLENGE_INIT_EXPIRES);
    }

    // Add the header to the message.
    pjsip_msg_add_hdr(rsp, (pjsip_hdr*)hdr);

    // Store the branch parameter in memcached for correlation purposes
    pjsip_via_hdr* via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_VIA, NULL);
    auth_challenge->correlator =
      (via_hdr != NULL) ? PJUtils::pj_str_to_string(&via_hdr->branch_param) : "";

    // Write the new authentication challenge to the IMPI store
    TRC_DEBUG("Write authentication challenge to IMPI store");
    Store::Status status;

    do
    {
      // Save off the nonce. We will need it to reclaim the auth challenge from
      // the IMPI at the end of the loop.
      std::string nonce = auth_challenge->nonce;

      ImpiStore::Impi* impi_obj =
        _sproutlet->_impi_store->get_impi_with_nonce(impi,
                                                     nonce,
                                                     trail());

      if (impi_obj == NULL)
      {
        impi_obj = new ImpiStore::Impi(impi);
      }

      // Check whether the IMPI has an existing auth challenge.
      ImpiStore::AuthChallenge* challenge =
        impi_obj->get_auth_challenge(auth_challenge->nonce);

      if (challenge != NULL)
      {
        // The IMPI already has a challenge. This shouldn't happen in mainline
        // operation but it can happen if we hit data contention (the IMPI store
        // may have failed to write data in the new format but succeeded writing
        // a challenge int he old format meaning the challenge could appear on a
        // subsequent get.
        //
        // Regardless, we want to be defensive and update the existing challenge
        // (making sure the nonce count and expiry don't move backwards).
        challenge->nonce_count = std::max(auth_challenge->nonce_count,
                                          challenge->nonce_count);
        challenge->expires = std::max(auth_challenge->expires,
                                      challenge->expires);
        delete auth_challenge; auth_challenge = NULL;
      }
      else
      {
        // Add our new challenges to the IMPI.
        impi_obj->auth_challenges.push_back(auth_challenge);
        auth_challenge = NULL;
      }

      status = _sproutlet->_impi_store->set_impi(impi_obj, trail());

      // Regardless of what happened take the challenge back. If everything
      // went well we will delete it below. If we hit data contention we will
      // need it the next time round the loop.
      auth_challenge = impi_obj->get_auth_challenge(nonce);
      std::vector<ImpiStore::AuthChallenge*>& challenges = impi_obj->auth_challenges;
      challenges.erase(std::remove(challenges.begin(),
                                   challenges.end(),
                                   auth_challenge),
                       challenges.end());

      delete impi_obj; impi_obj = NULL;

    } while (status == Store::DATA_CONTENTION);

    // We're done with the auth challenge now.
    delete auth_challenge; auth_challenge = NULL;

    if (status == Store::OK)
    {
      // We've written the challenge into the store, so need to set a Chronos
      // timer so that an AUTHENTICATION_TIMEOUT SAR is sent to the
      // HSS when it expires.
      std::string timer_id;
      std::string chronos_body = "{\"impi\": \"" + impi + "\", \"impu\": \"" + impu +"\", \"nonce\": \"" + nonce +"\"}";
      TRC_DEBUG("Sending %s to Chronos to set AV timer", chronos_body.c_str());
      _sproutlet->_chronos->send_post(timer_id,
                                      30,
                                      "/authentication-timeout",
                                      chronos_body,
                                      trail());
    }
    else
    {
      // We've failed to store the nonce in memcached, so we have no hope of
      // successfully authenticating any repsonse to a 401 Unauthorized.  Send
      // a 500 Server Internal Error instead.
      TRC_DEBUG("Failed to store nonce in memcached");
      rsp->line.status.code = PJSIP_SC_INTERNAL_SERVER_ERROR;
      rsp->line.status.reason = *pjsip_get_status_text(PJSIP_SC_INTERNAL_SERVER_ERROR);
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
      rsp->line.status.code = PJSIP_SC_SERVER_TIMEOUT;
      rsp->line.status.reason = *pjsip_get_status_text(PJSIP_SC_SERVER_TIMEOUT);
      SAS::Event event(trail(), SASEvent::AUTHENTICATION_FAILED_OVERLOAD, 0);
      SAS::report_event(event);
    }
    else
    {
      TRC_DEBUG("Failed to get Authentication vector");
      rsp->line.status.code = PJSIP_SC_FORBIDDEN;
      rsp->line.status.reason = *pjsip_get_status_text(PJSIP_SC_FORBIDDEN);
      SAS::Event event(trail(), SASEvent::AUTHENTICATION_FAILED_NO_AV, 0);
      SAS::report_event(event);
    }
  }
}


void AuthenticationSproutletTsx::on_rx_initial_request(pjsip_msg* req)
{
  TRC_DEBUG("Authentication module invoked");
  pj_status_t status;
  bool is_register = (req->line.req.method.id == PJSIP_REGISTER_METHOD);
  SNMP::SuccessFailCountTable* auth_stats_table = NULL;
  std::string resync;

  const int unauth_sc = is_register ? PJSIP_SC_UNAUTHORIZED : PJSIP_SC_PROXY_AUTHENTICATION_REQUIRED;
  int sc = unauth_sc;
  status = PJ_SUCCESS;

  pjsip_digest_credential* credentials = get_credentials(req);

  ImpiStore::Impi* impi_obj = NULL;
  if ((credentials != NULL) &&
      (credentials->response.slen != 0))
  {
    std::string impi = PJUtils::pj_str_to_string(&credentials->username);
    std::string nonce = PJUtils::pj_str_to_string(&credentials->nonce);
    impi_obj = _sproutlet->_impi_store->get_impi_with_nonce(impi, nonce, trail());
    ImpiStore::AuthChallenge* auth_challenge = NULL;
    if (impi_obj != NULL)
    {
      auth_challenge = impi_obj->get_auth_challenge(nonce);
    }

    if (!is_register)
    {
      // Challenged non-register requests must be SIP digest, so only one table
      // needed for this case.
      auth_stats_table = _sproutlet->_auth_stats_tables->non_register_auth_tbl;
    }
    else
    {
      if (!pj_strcmp(&credentials->algorithm, &STR_MD5))
      {
        auth_stats_table = _sproutlet->_auth_stats_tables->sip_digest_auth_tbl;
      }
      else if ((!pj_strcmp(&credentials->algorithm, &STR_AKAV1_MD5)) ||
               (!pj_strcmp(&credentials->algorithm, &STR_AKAV2_MD5)))
      {
        auth_stats_table = _sproutlet->_auth_stats_tables->ims_aka_auth_tbl;
      }
      else
      {
        // Authorization header did not specify an algorithm, so check the challenge for
        // this information instead.
        if ((auth_challenge != NULL) && (auth_challenge->type == ImpiStore::AuthChallenge::Type::AKA))
        {
          auth_stats_table = _sproutlet->_auth_stats_tables->ims_aka_auth_tbl;
        }
        else
        {
          // Use the digest table if the AV specified digest, or as a fallback if there was no AV
          auth_stats_table = _sproutlet->_auth_stats_tables->sip_digest_auth_tbl;
        }
      }
    }

    if (auth_stats_table != NULL)
    {
      auth_stats_table->increment_attempts();
    }

    // Calculate the nonce count on the request (if it is not present default
    // to 1).
    unsigned long nonce_count = pj_strtoul2(&credentials->nc, NULL, 16);
    nonce_count = (nonce_count == 0) ? 1 : nonce_count;

    if ((auth_challenge != NULL) && (auth_challenge->nonce_count > 1))
    {
      // A nonce count > 1 is supplied. Check that it is acceptable. If it is
      // not, pretend that we didn't find the challenge to check against as
      // this will force the code below to re-challenge.
      if (!_sproutlet->_nonce_count_supported)
      {
        TRC_INFO("Nonce count %d supplied but nonce counts are not enabled - ignore it",
                 nonce_count);
        SAS::Event event(trail(), SASEvent::AUTHENTICATION_NC_NOT_SUPP, 0);
        event.add_static_param(nonce_count);
        SAS::report_event(event);

        status = PJSIP_EAUTHACCNOTFOUND;
        auth_challenge = NULL;
      }
      else if (nonce_count < auth_challenge->nonce_count)
      {
        // The nonce count is too low - this might be a replay attack.
        TRC_INFO("Nonce count supplied (%d) is lower than expected (%d) - ignore it",
                 nonce_count, auth_challenge->nonce_count);
        SAS::Event event(trail(), SASEvent::AUTHENTICATION_NC_TOO_LOW, 0);
        event.add_static_param(nonce_count);
        event.add_static_param(auth_challenge->nonce_count);
        SAS::report_event(event);

        status = PJSIP_EAUTHACCNOTFOUND;
        auth_challenge = NULL;
      }
      else if (!is_register)
      {
        // We only support nonce counts for REGISTER requests (as for other
        // requests we wouldn't know how long to store the challenge for)
        TRC_INFO("Nonce count %d supplied on a non-REGISTER - ignore it",
                 nonce_count);
        SAS::Event event(trail(), SASEvent::AUTHENTICATION_NC_ON_NON_REG, 0);
        event.add_static_param(nonce_count);
        SAS::report_event(event);

        status = PJSIP_EAUTHACCNOTFOUND;
        auth_challenge = NULL;
      }
    }

    if (status == PJ_SUCCESS)
    {
      // We're about to do the authentication check. If this is the first
      // response to a challenge correlate it to the flow that issued the
      // challenge in the first place.
      if ((auth_challenge != NULL) && (nonce_count == 1))
      {
        correlate_trail_to_challenge(auth_challenge, trail());
      }

      // Request contains a response to a previous challenge, so pass it to
      // the authentication module to verify.
      TRC_DEBUG("Verify authentication information in request");
      status = pjsip_auth_srv_verify3((is_register ?
                                         &_sproutlet->_auth_srv :
                                         &_sproutlet->_auth_srv_proxy),
                                      req,
                                      get_pool(req),
                                      &sc,
                                      (void*)auth_challenge);

      if (status == PJ_SUCCESS)
      {
        // The authentication information in the request was verified.
        TRC_DEBUG("Request authenticated successfully");

        SAS::Event event(trail(), SASEvent::AUTHENTICATION_SUCCESS, 0);
        SAS::report_event(event);

        if (auth_stats_table != NULL)
        {
          auth_stats_table->increment_successes();
        }

        // Increment the nonce count and set it back to the AV store, handling
        // contention.  We don't check for overflow - it will take ~2^32
        // authentications before it happens.
        uint32_t new_nonce_count = nonce_count + 1;

        // Work out when the challenge should expire. We only want to keep it
        // around if nonce counts are supported and the UE authenticates by
        // registering.
        int new_expiry = auth_challenge->expires;
        if (_sproutlet->_nonce_count_supported && is_register)
        {
          new_expiry = calculate_challenge_expiration_time(req);
        }

        Store::Status store_status;
        do
        {
          // Work out the next nonce count and expiry to use. We don't police
          // against another UE using this nonce at exactly the same time, but
          // we don't want the expiration or nonce counts to travel backwards in
          // this case.
          //
          // We don't police this race condition because:
          // * A genuine UE gains no benefit from exploiting it.
          // * An attacker may be able to clone a genuine UE's auth response,
          //   and the attacker's response may beat the genuine UE's response
          //   in a race. If this happens there is no way for us to tell the
          //   difference between the attacker and the genuine UE. The right
          //   way to protect against this attack is to use the auth-int qop.
          auth_challenge->nonce_count = std::max(new_nonce_count,
                                                 auth_challenge->nonce_count);
          auth_challenge->expires = std::max(new_expiry,
                                             auth_challenge->expires);

          // Store it.  If this fails due to contention, read the updated JSON.
          store_status = _sproutlet->_impi_store->set_impi(impi_obj, trail());

          if (store_status == Store::DATA_CONTENTION)
          {
            // LCOV_EXCL_START - No support for contention in UT
            TRC_DEBUG("Data contention writing tombstone - retry");
            delete impi_obj;
            impi_obj = _sproutlet->_impi_store->get_impi_with_nonce(impi, nonce, trail());
            auth_challenge = NULL;

            if (impi_obj != NULL)
            {
              auth_challenge = impi_obj->get_auth_challenge(nonce);
            }

            if (auth_challenge == NULL)
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
          TRC_ERROR("Tried to update IMPI for %s/%s after processing an authentication, but failed",
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
          while (pjsip_msg_find_remove_hdr(req,
                                           PJSIP_H_PROXY_AUTHORIZATION,
                                           NULL) != NULL);
          delete impi_obj;

          forward_request(req); return;
        }
      }
    }
  }
  else
  {
    // No credentials in request.
    status = PJSIP_EAUTHNOAUTH;
  }


  // The message either has insufficient authentication information, or
  // has failed authentication.  In either case, the message will be
  // absorbed and responded to by the authentication module, so we need to
  // add SAS markers so the trail will become searchable.
  SAS::Marker start_marker(trail(), MARKER_ID_START, 1u);
  SAS::report_marker(start_marker);

  // Add a SAS end marker
  SAS::Marker end_marker(trail(), MARKER_ID_END, 1u);
  SAS::report_marker(end_marker);

  // Create an ACR for the message and pass the request to it.  Role is always
  // considered originating for a REGISTER request.
  ACR* acr = _sproutlet->_acr_factory->get_acr(trail(),
                                  ACR::CALLING_PARTY,
                                  ACR::NODE_ROLE_ORIGINATING);

  // TODO: Get the timestamp from the request.
  acr->rx_request(req);

  pjsip_msg* rsp;

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

    rsp = create_response(req, static_cast<pjsip_status_code>(sc));
    create_challenge(credentials, stale, resync, req, rsp);
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
    SAS::Event event(trail(), SASEvent::AUTHENTICATION_FAILED, 0);
    event.add_var_param(error_msg);
    SAS::report_event(event);

    if (sc != unauth_sc)
    {
      // Notify Homestead and the HSS that this authentication attempt
      // has definitively failed.
      std::string impi;
      std::string impu;

      PJUtils::get_impi_and_impu(req, impi, impu);
      _sproutlet->_hss->update_registration_state(impu,
                                                  impi,
                                                  HSSConnection::AUTH_FAIL,
                                                  trail());
    }

    if (_sproutlet->_analytics != NULL)
    {
      _sproutlet->_analytics->auth_failure(PJUtils::pj_str_to_string(&credentials->username),
      PJUtils::public_id_from_uri((pjsip_uri*)pjsip_uri_get_uri(PJSIP_MSG_TO_HDR(req)->uri)));
    }

    rsp = create_response(req, static_cast<pjsip_status_code>(sc));
  }

  // Send the ACR.
  acr->tx_response(rsp);
  acr->send();

  send_response(rsp);
  free_msg(req);

  delete acr;
  delete impi_obj;
}
