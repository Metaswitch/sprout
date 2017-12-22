/**
 * @file authenticationsproutlet.cpp
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "constants.h"
#include "sproutsasevent.h"
#include "authenticationsproutlet.h"
#include "registration_utils.h"
#include "json_parse_utils.h"
#include <openssl/hmac.h>
#include "base64.h"
#include "scscf_utils.h"

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
                                                 const std::list<std::string>& aliases,
                                                 const std::string& network_function,
                                                 const std::string& next_hop_service,
                                                 const std::string& realm_name,
                                                 ImpiStore* _impi_store,
                                                 std::vector<ImpiStore*> remote_impi_stores,
                                                 HSSConnection* hss_connection,
                                                 ChronosConnection* chronos_connection,
                                                 ACRFactory* rfacr_factory,
                                                 uint32_t non_register_auth_mode_param,
                                                 AnalyticsLogger* analytics_logger,
                                                 SNMP::AuthenticationStatsTables* auth_stats_tbls,
                                                 bool nonce_count_supported_arg,
                                                 int cfg_max_expires) :
  Sproutlet(name, port, uri, "", aliases, NULL, NULL, network_function),
  _aka_realm((realm_name != "") ?
    pj_strdup3(stack_data.pool, realm_name.c_str()) :
    stack_data.local_host),
  _hss(hss_connection),
  _chronos(chronos_connection),
  _acr_factory(rfacr_factory),
  _impi_store(_impi_store),
  _remote_impi_stores(remote_impi_stores),
  _analytics(analytics_logger),
  _auth_stats_tables(auth_stats_tbls),
  _nonce_count_supported(nonce_count_supported_arg),
  _max_expires(cfg_max_expires),
  _non_register_auth_mode(non_register_auth_mode_param),
  _next_hop_service(next_hop_service)
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

  if (status != PJ_SUCCESS)
  {
    // LCOV_EXCL_START - Don't test initialization failures in UT
    TRC_ERROR("Authentication sproutlet failed to initialize (%d)", status);
    // LCOV_EXCL_STOP
  }

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

SproutletTsx* AuthenticationSproutlet::get_tsx(SproutletHelper* helper,
                                               const std::string& alias,
                                               pjsip_msg* req,
                                               pjsip_sip_uri*& next_hop,
                                               pj_pool_t* pool,
                                               SAS::TrailId trail)
{
  if (needs_authentication(req, trail))
  {
    return new AuthenticationSproutletTsx(this, _next_hop_service);
  }

  // We're not interested in the message so create a next hop URI.
  pjsip_sip_uri* base_uri = helper->get_routing_uri(req, this);
  next_hop = helper->next_hop_uri(_next_hop_service,
                                  base_uri,
                                  pool);
  return NULL;
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

        if (pj_stricmp(&integrity->value, &STR_TLS_YES) == 0)
        {
          // The integrity protected indicator is included and set to tls-yes.
          // This indicates the client has already been authenticated so we will
          // accept this REGISTER even if there is a challenge response.  Values
          // of tls-pending, ip-assoc-yes, or ip-assoc-pending indicate the
          // challenge should be checked.
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
    if (PJSIP_MSG_TO_HDR(req)->tag.slen != 0)
    {
      // This is an in-dialog request which needs no authentication.
      return PJ_FALSE;
    }

    if (!PJUtils::is_param_in_top_route(req, &STR_ORIG))
    {
      // This is not an originating request so does not get authenticated.
      return PJ_FALSE;
    }

    if (_non_register_auth_mode == 0)
    {
      // There are no conditions where we would consider authenticating this
      // non-REGISTER request.
      SAS::Event event(trail, SASEvent::AUTHENTICATION_NOT_NEEDED_NEVER_AUTH_NON_REG, 0);
      SAS::report_event(event);
      return PJ_FALSE;
    }

    if (_non_register_auth_mode & NonRegisterAuthentication::IF_PROXY_AUTHORIZATION_PRESENT)
    {
      // Authenticate the request if it has a Proxy-Authorization header.
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
    }

    if (_non_register_auth_mode & NonRegisterAuthentication::INITIAL_REQ_FROM_REG_DIGEST_ENDPOINT)
    {
      // Authenticate the request if the endpoint authenticates with digest
      // authentication. If this is the case the top route header will contain
      // a username parameter.
      if (PJUtils::is_param_in_top_route(req, &STR_USERNAME))
      {
        // The username parameter is present so we need to authenticate.
        SAS::Event event(trail, SASEvent::AUTHENTICATION_NEEDED_DIGEST_ENDPOINT, 0);
        SAS::report_event(event);
        return PJ_TRUE;
      }
    }

    // We don't need to authenticate this message, but we considered it.
    // Generate a helpful SAS log.
    SAS::Event event(trail, SASEvent::AUTHENTICATION_NOT_NEEDED_FOR_NON_REG, 0);
    SAS::report_event(event);
    return PJ_FALSE;
  }
}


//
// Authentication Sproutlet Tsx methods.
//

AuthenticationSproutletTsx::AuthenticationSproutletTsx(AuthenticationSproutlet* authentication,
                                                       const std::string& next_hop_service) :
  CompositeSproutletTsx(authentication, next_hop_service),
  _authentication(authentication),
  _authenticated_using_sip_digest(false),
  _scscf_uri()
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
    expires = std::max(expires, RegistrationUtils::expiry_for_binding(contact_hdr,
                                                                      expires_hdr,
                                                                      _authentication->_max_expires));
  }

  return expires + time(NULL);
}

/// Verifies that the supplied authentication vector is valid.
AuthenticationVector* AuthenticationSproutletTsx::verify_auth_vector(rapidjson::Document* doc,
                                                                     const std::string& impi)
{
  AuthenticationVector *av = nullptr;

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  doc->Accept(writer);
  std::string av_str = buffer.GetString();
  TRC_DEBUG("Verifying AV: %s", av_str.c_str());

  // Check the AV is well formed.
  if (doc->HasMember("aka"))
  {
    // AKA is specified, check all the expected parameters are present.
    TRC_DEBUG("AKA specified");
    rapidjson::Value& aka_obj = (*doc)["aka"];
    if (!(((aka_obj.HasMember("challenge")) && (aka_obj["challenge"].IsString())) &&
          ((aka_obj.HasMember("response")) && (aka_obj["response"].IsString())) &&
          ((aka_obj.HasMember("cryptkey")) && (aka_obj["cryptkey"].IsString())) &&
          ((aka_obj.HasMember("integritykey")) && (aka_obj["integritykey"].IsString()))))
    {
      // Malformed AKA entry
      TRC_INFO("Badly formed AKA authentication vector for %s",
               impi.c_str());
      SAS::Event event(trail(), SASEvent::AUTHENTICATION_FAILED_MALFORMED, 0);
      std::string error_msg = std::string("AKA authentication vector is malformed: ") + av_str.c_str();
      event.add_var_param(error_msg);
      SAS::report_event(event);
    }
    else
    {
      AkaAv* aka = new AkaAv();
      JSON_SAFE_GET_STRING_MEMBER(aka_obj, "challenge", aka->nonce);
      JSON_SAFE_GET_STRING_MEMBER(aka_obj, "cryptkey", aka->cryptkey);
      JSON_SAFE_GET_STRING_MEMBER(aka_obj, "integritykey", aka->integritykey);
      JSON_SAFE_GET_STRING_MEMBER(aka_obj, "response", aka->xres);
      JSON_SAFE_GET_INT_MEMBER(aka_obj, "version", aka->akaversion);

      av = aka;
    }
  }
  else if (doc->HasMember("digest"))
  {
    // Digest is specified, check all the expected parameters are present.
    TRC_DEBUG("Digest specified");
    rapidjson::Value& digest_obj = (*doc)["digest"];
    if (!(((digest_obj.HasMember("realm")) && (digest_obj["realm"].IsString())) &&
          ((digest_obj.HasMember("qop")) && (digest_obj["qop"].IsString())) &&
          ((digest_obj.HasMember("ha1")) && (digest_obj["ha1"].IsString()))))
    {
      // Malformed digest entry
      TRC_INFO("Badly formed Digest authentication vector for %s",
               impi.c_str());
      SAS::Event event(trail(), SASEvent::AUTHENTICATION_FAILED_MALFORMED, 0);
      std::string error_msg = std::string("Digest authentication vector is malformed: ") + av_str.c_str();;
      event.add_var_param(error_msg);
      SAS::report_event(event);
    }
    else
    {
      DigestAv* digest = new DigestAv();
      JSON_SAFE_GET_STRING_MEMBER(digest_obj, "realm", digest->realm);
      JSON_SAFE_GET_STRING_MEMBER(digest_obj, "qop", digest->qop);
      JSON_SAFE_GET_STRING_MEMBER(digest_obj, "ha1", digest->ha1);

      av = digest;
    }
  }
  else
  {
    // Neither AKA nor Digest information present.
    TRC_INFO("No AKA or Digest object in authentication vector for %s",
             impi.c_str());
    SAS::Event event(trail(), SASEvent::AUTHENTICATION_FAILED_MALFORMED, 0);
    std::string error_msg = std::string("Authentication vector is malformed: ") + av_str.c_str();
    event.add_var_param(error_msg);
    SAS::report_event(event);
  }

  return av;
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
    if (auth_challenge->get_type() == ImpiStore::AuthChallenge::Type::AKA)
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
        xres = unhex(aka_challenge->get_response());
      }

      cred_info->data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
      pj_strdup4(pool, &cred_info->data, xres.data(), xres.length());
      TRC_DEBUG("Found AKA XRES = %.*s", cred_info->data.slen, cred_info->data.ptr);

      // Use default realm as it isn't specified in the AV.
      pj_strdup(pool, &cred_info->realm, realm);
      status = PJ_SUCCESS;
    }
    else if (auth_challenge->get_type() == ImpiStore::AuthChallenge::Type::DIGEST)
    {
      ImpiStore::DigestAuthChallenge* digest_challenge = (ImpiStore::DigestAuthChallenge*)auth_challenge;

      if (pj_strcmp2(realm, digest_challenge->get_realm().c_str()) == 0)
      {
        // Digest authentication, so ha1 field is hashed password.
        cred_info->data_type = PJSIP_CRED_DATA_DIGEST;
        pj_strdup2(pool, &cred_info->data, digest_challenge->get_ha1().c_str());
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


/// Get an AV from a previous challenge in the IMPI store.
///
/// @param impi         - The IMPI of the previous challenge.
/// @param nonce        - The nonce of the previous challenge.
/// @param out_impi_obj - An optional pointer that can receive the IMPI object
///                       the challenge was retrieved from lookups. Returning
///                       this may allow the caller to avoid unnecessary further
///                       lookups.
///
/// @return             - The retrieved authentication vector, or NULL.
AuthenticationVector* AuthenticationSproutletTsx::get_av_from_store(const std::string& impi,
                                                                    const std::string& nonce,
                                                                    ImpiStore::Impi** out_impi_obj)
{
  AuthenticationVector* av = nullptr;

  ImpiStore::Impi* impi_obj = _authentication->read_impi(impi, trail());

  if (impi_obj != nullptr)
  {
    ImpiStore::AuthChallenge* auth_challenge = impi_obj->get_auth_challenge(nonce);

    if ((auth_challenge != nullptr) &&
        (auth_challenge->get_type() == ImpiStore::AuthChallenge::Type::DIGEST))
    {
      ImpiStore::DigestAuthChallenge* digest_challenge =
        dynamic_cast<ImpiStore::DigestAuthChallenge*>(auth_challenge);

      DigestAv* digest_av = new DigestAv();
      digest_av->qop = digest_challenge->get_qop();
      digest_av->realm = digest_challenge->get_realm();
      digest_av->ha1 = digest_challenge->get_ha1();

      av = digest_av;
    }
  }

  if (out_impi_obj != nullptr)
  {
    *out_impi_obj = impi_obj;
  }

  return av;
}

void AuthenticationSproutletTsx::create_challenge(pjsip_digest_credential* credentials,
                                                  pj_bool_t stale,
                                                  std::string resync,
                                                  pjsip_msg* req,
                                                  pjsip_msg* rsp)
{
  // Get the public and private identities from the request.
  std::string impi;
  std::string impu_for_hss;
  bool av_source_unavailable = false;
  ImpiStore::Impi* impi_obj = nullptr;

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

  // Get an authentication vector to challenge this request.
  AuthenticationVector* av = NULL;

  if ((req->line.req.method.id == PJSIP_REGISTER_METHOD) ||
      (PJUtils::is_param_in_route_hdr(route_hdr(), &STR_AUTO_REG)))
  {
    // This is either a REGISTER, or a request that Sprout should authenticate
    // by treating it like a REGISTER. Get the Authentication Vector from the
    // HSS.
    PJUtils::get_impi_and_impu(req, impi, impu_for_hss, get_pool(req), trail());
    TRC_DEBUG("Get AV from HSS for impi=%s impu=%s",
              impi.c_str(), impu_for_hss.c_str());

    rapidjson::Document* doc = NULL;
    HTTPCode http_code = _authentication->_hss->get_auth_vector(impi,
                                                                impu_for_hss,
                                                                auth_type,
                                                                resync,
                                                                _scscf_uri,
                                                                doc,
                                                                trail());
    av_source_unavailable = ((http_code == HTTP_SERVER_UNAVAILABLE) ||
                             (http_code == HTTP_GATEWAY_TIMEOUT));

    if (doc != NULL)
    {
      av = verify_auth_vector(doc, impi);
    }
    delete doc; doc = NULL;
  }
  else
  {
    // This is a non-REGISTER, so get an AV by finding the challenge that the
    // endpoint authenticated with when it registered. The information we need
    // to look up the challenge will be in the top route header.
    TRC_DEBUG("Get AV from previous challenge");
    std::string nonce;

    if (PJUtils::get_param_in_route_hdr(route_hdr(), &STR_USERNAME, impi) &&
        PJUtils::get_param_in_route_hdr(route_hdr(), &STR_NONCE, nonce))
    {
      impi = Utils::url_unescape(impi);
      nonce = Utils::url_unescape(nonce);

      // Get an AV from the store. Store of the IMPI object we got back from the
      // store so that we don't have to do another read when writing the new
      // challenge back.
      TRC_DEBUG("Challenge ID: impi=%s nonce=%s",impi.c_str(), nonce.c_str());
      av = get_av_from_store(impi, nonce, &impi_obj);

      if (av == NULL)
      {
        // If we didn't get any IMPI back from the store at all, then the store
        // has failed, so flag this for later.
        av_source_unavailable = (impi_obj == NULL);

        // We failed to get an AV so discard the impi store object we got when
        // reading from the store.
        delete impi_obj; impi_obj = NULL;
      }
    }
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
    pj_create_random_string(buf, sizeof(buf));
    pj_strdup(rsp_pool, &hdr->challenge.digest.opaque, &random);

    // Log the opaque value to SAS to enable us to correlate this challenge
    // with the subsequent transaction containing the challenge response.
    std::string opaque;
    opaque.assign(buf, sizeof(buf));
    TRC_DEBUG("Log opaque value %s to SAS as a generic correlator", opaque.c_str());
    SAS::Marker opaque_marker(trail(), MARKED_ID_GENERIC_CORRELATOR, 1u);
    opaque_marker.add_static_param((uint32_t)UniquenessScopes::DIGEST_OPAQUE);
    opaque_marker.add_var_param(opaque);
    SAS::report_marker(opaque_marker, SAS::Marker::Scope::Trace);

    ImpiStore::AuthChallenge* auth_challenge;
    if (av->is_aka())
    {
      // AKA authentication.
      TRC_DEBUG("Add AKA information");
      AkaAv* aka = dynamic_cast<AkaAv*>(av);

      SAS::Event event(trail(), SASEvent::AUTHENTICATION_CHALLENGE_AKA, 0);
      SAS::report_event(event);

      // Use default realm for AKA as not specified in the AV.
      pj_strdup(rsp_pool, &hdr->challenge.digest.realm, &_authentication->_aka_realm);
      hdr->challenge.digest.algorithm = ((aka->akaversion == 2) ? STR_AKAV2_MD5 : STR_AKAV1_MD5);

      pj_strdup2(rsp_pool, &hdr->challenge.digest.nonce, aka->nonce.c_str());
      hdr->challenge.digest.qop = STR_AUTH;
      hdr->challenge.digest.stale = stale;

      // Add the cryptography key parameter.
      pjsip_param* ck_param = (pjsip_param*)pj_pool_alloc(rsp_pool, sizeof(pjsip_param));
      ck_param->name = STR_CK;
      std::string ck = "\"" + aka->cryptkey + "\"";
      pj_strdup2(rsp_pool, &ck_param->value, ck.c_str());
      pj_list_insert_before(&hdr->challenge.digest.other_param, ck_param);

      // Add the integrity key parameter.
      pjsip_param* ik_param = (pjsip_param*)pj_pool_alloc(rsp_pool, sizeof(pjsip_param));
      ik_param->name = STR_IK;
      std::string ik = "\"" + aka->integritykey + "\"";
      pj_strdup2(rsp_pool, &ik_param->value, ik.c_str());
      pj_list_insert_before(&hdr->challenge.digest.other_param, ik_param);

      // Calculate the response.  We must not provide this on the SIP message,
      // but we will put it in the store.
      std::string response;

      if (aka->akaversion == 2)
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
        std::string joined = unhex(aka->xres + aka->integritykey + aka->cryptkey);
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
        response = aka->xres;
      }

      // Now build the AuthChallenge so that we can store it in the ImpiStore.
      auth_challenge = new ImpiStore::AKAAuthChallenge(aka->nonce,
                                                       response,
                                                       time(NULL) + AUTH_CHALLENGE_INIT_EXPIRES);
    }
    else
    {
      // Digest authentication.
      TRC_DEBUG("Add Digest information");
      std::string nonce;
      DigestAv* digest = dynamic_cast<DigestAv*>(av);

      SAS::Event event(trail(), SASEvent::AUTHENTICATION_CHALLENGE_DIGEST, 0);
      SAS::report_event(event);

      pj_strdup2(rsp_pool, &hdr->challenge.digest.realm, digest->realm.c_str());
      hdr->challenge.digest.algorithm = STR_MD5;
      pj_create_random_string(buf, sizeof(buf));
      nonce.assign(buf, sizeof(buf));
      pj_strdup(rsp_pool, &hdr->challenge.digest.nonce, &random);
      pj_strdup2(rsp_pool, &hdr->challenge.digest.qop, digest->qop.c_str());
      hdr->challenge.digest.stale = stale;

      // Now build the AuthChallenge so that we can store it in the ImpiStore.
      auth_challenge = new ImpiStore::DigestAuthChallenge(nonce,
                                                          digest->realm,
                                                          digest->qop,
                                                          digest->ha1,
                                                          time(NULL) + AUTH_CHALLENGE_INIT_EXPIRES);
    }

    // Add the header to the message.
    pjsip_msg_add_hdr(rsp, (pjsip_hdr*)hdr);

    // Store the opaque value that we generated in the IMPI store.  This means
    // that if the challenge times out we can log the same opaque marker to SAS
    // there in order to correlate the SAS trail for the timeout with the SAS
    // trail generated for this initial REGISTER.
    //
    // Note we aren't dependent on this to correlate the challenged REGISTER
    // transaction and the transaction containing the challenge response
    // because we use the opaque value from the SIP messages directly (meaning
    // that transactions get correlated even in the case of IMPI store
    // unavailability).
    auth_challenge->set_correlator(opaque);

    // Add the IMPU to the challenge
    auth_challenge->set_impu(impu_for_hss);

    // Save off the nonce. We will need it to reclaim the auth challenge from
    // the IMPI at the end of the loop.
    std::string nonce = auth_challenge->get_nonce();

    // Create a timer to track the authentication challenge expiry.
    if ((!impu_for_hss.empty()) && (_authentication->_chronos))
    {
      TRC_DEBUG("Set chronos timer for AUTHENTICATION_TIMEOUT SAR");

      // We need to set a Chronos timer so that an AUTHENTICATION_TIMEOUT SAR
      // is sent to the HSS when the challenge expires. We do not have a timer ID
      // until the timer has been set, so do this here and store the timer_id
      // alongside the auth_challenge.
      HTTPCode status;
      std::string timer_id;
      std::string chronos_body = "{\"impi\": \"" + impi +
                              "\", \"impu\": \"" + impu_for_hss +
                              "\", \"nonce\": \"" + nonce +
                              "\"}";
      TRC_DEBUG("Sending %s to Chronos to set AV timer", chronos_body.c_str());
      status = _authentication->_chronos->send_post(timer_id,
                                                    30,
                                                    "/authentication-timeout",
                                                    chronos_body,
                                                    trail());
      if (status == HTTP_OK)
      {
        TRC_DEBUG("Timer %s successfully stored in Chronos for auth challenge %s",
                    timer_id.c_str(),
                    nonce.c_str());
        auth_challenge->set_timer_id(timer_id);
      }
    }

    // Write the new authentication challenge to the IMPI store
    TRC_DEBUG("Write authentication challenge to IMPI store");
    Store::Status status;

    // Set the site-specific server name for the S-CSCF that issued this
    // challenge. This is so that if the authentication timer pops in a remote
    // site, we can use the same server name on the SAR.
    auth_challenge->set_scscf_uri(_scscf_uri);

    // Write the challenge back to the store.
    status = _authentication->write_challenge(impi, auth_challenge, impi_obj, trail());

    if (status == Store::OK)
    {
      TRC_DEBUG("Successfully stored nonce %s in memcached", nonce.c_str());
    }
    else
    {
      // We've failed to store the nonce in memcached, so we have no hope of
      // successfully authenticating any repsonse to a 401 Unauthorized.  Send
      // a 500 Server Internal Error instead.
      TRC_DEBUG("Failed to store nonce in memcached");
      rsp->line.status.code = PJSIP_SC_INTERNAL_SERVER_ERROR;
      rsp->line.status.reason = *pjsip_get_status_text(PJSIP_SC_INTERNAL_SERVER_ERROR);

      // Also attempt to delete the chronos timer we stored for this challenge.
      // This stops the a timer pop not finding an AV, and triggering a cycle of
      // timer pops in every site attempting to find an AV that never existed.
      if ((_authentication->_chronos) && (auth_challenge->get_timer_id() != ""))
      {
        HTTPCode status;
        status = _authentication->_chronos->send_delete(auth_challenge->get_timer_id(),
                                                        trail());
        if (status == HTTP_OK)
        {
          TRC_DEBUG("Timer deleted for auth_challenge %s", nonce.c_str());
          auth_challenge->set_timer_id("");

        }
      }
    }

    delete auth_challenge; auth_challenge = NULL;
    delete impi_obj; impi_obj = NULL;
    delete av;
  }
  else
  {
    // If we couldn't get the AV because a downstream node is overloaded then don't return
    // a 4xx error to the client.
    if (av_source_unavailable)
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

  // Construct the S-CSCF URI for this transaction. Use the configured S-CSCF
  // URI as a starting point.
  pjsip_sip_uri* scscf_uri = (pjsip_sip_uri*)pjsip_uri_clone(get_pool(req), stack_data.scscf_uri);
  pjsip_sip_uri* routing_uri = get_routing_uri(req);
  if (routing_uri != NULL)
  {
    SCSCFUtils::get_scscf_uri(get_pool(req),
                              get_local_hostname(routing_uri),
                              get_local_hostname(scscf_uri),
                              scscf_uri);
  }

  _scscf_uri = PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR, (pjsip_uri*)scscf_uri);

  pjsip_digest_credential* credentials = get_credentials(req);

  ImpiStore::Impi* impi_obj = NULL;
  if ((credentials != NULL) &&
      (credentials->response.slen != 0))
  {
    std::string impi = PJUtils::pj_str_to_string(&credentials->username);
    std::string nonce = PJUtils::pj_str_to_string(&credentials->nonce);
    impi_obj = _authentication->read_impi(impi, trail());
    ImpiStore::AuthChallenge* auth_challenge = NULL;
    if (impi_obj != NULL)
    {
      auth_challenge = impi_obj->get_auth_challenge(nonce);
    }

    if (!is_register)
    {
      // Challenged non-register requests must be SIP digest, so only one table
      // needed for this case.
      auth_stats_table = _authentication->_auth_stats_tables->non_register_auth_tbl;
    }
    else
    {
      if (!pj_strcmp(&credentials->algorithm, &STR_MD5))
      {
        auth_stats_table = _authentication->_auth_stats_tables->sip_digest_auth_tbl;
      }
      else if ((!pj_strcmp(&credentials->algorithm, &STR_AKAV1_MD5)) ||
               (!pj_strcmp(&credentials->algorithm, &STR_AKAV2_MD5)))
      {
        auth_stats_table = _authentication->_auth_stats_tables->ims_aka_auth_tbl;
      }
      else
      {
        // Authorization header did not specify an algorithm, so check the challenge for
        // this information instead.
        if ((auth_challenge != NULL) && (auth_challenge->get_type() == ImpiStore::AuthChallenge::Type::AKA))
        {
          auth_stats_table = _authentication->_auth_stats_tables->ims_aka_auth_tbl;
        }
        else
        {
          // Use the digest table if the AV specified digest, or as a fallback if there was no AV
          auth_stats_table = _authentication->_auth_stats_tables->sip_digest_auth_tbl;
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

    if ((auth_challenge != NULL) && (auth_challenge->get_nonce_count() > 1))
    {
      // A nonce count > 1 is supplied. Check that it is acceptable. If it is
      // not, pretend that we didn't find the challenge to check against as
      // this will force the code below to re-challenge.
      if (!_authentication->_nonce_count_supported)
      {
        TRC_INFO("Nonce count %d supplied but nonce counts are not enabled - ignore it",
                 nonce_count);
        SAS::Event event(trail(), SASEvent::AUTHENTICATION_NC_NOT_SUPP, 0);
        event.add_static_param(nonce_count);
        SAS::report_event(event);

        status = PJSIP_EAUTHACCNOTFOUND;
        auth_challenge = NULL;
      }
      else if (nonce_count < auth_challenge->get_nonce_count())
      {
        // The nonce count is too low - this might be a replay attack.
        TRC_INFO("Nonce count supplied (%d) is lower than expected (%d) - ignore it",
                 nonce_count, auth_challenge->get_nonce_count());
        SAS::Event event(trail(), SASEvent::AUTHENTICATION_NC_TOO_LOW, 0);
        event.add_static_param(nonce_count);
        event.add_static_param(auth_challenge->get_nonce_count());
        SAS::report_event(event);

        status = PJSIP_EAUTHACCNOTFOUND;
        auth_challenge = NULL;
      }
    }

    // If this is the first response to the challenge then log the value of
    // opaque to SAS as a marker. We also do this when we challenge the initial
    // REGISTER and in this way the two transactions (the challenge and the
    // challenge response) get correlated in SAS.
    //
    // We have to be slightly careful how we determine whether this is the first
    // response. If we just check that the nonce_count in the request is 1 then
    // if someone spams us with REGISTERs that have a nonce_count of 1 we will
    // try and correlate them all, ultimately ending up with an unloadable SAS
    // trace. So instead we use the nonce_count from the IMPI store. But we
    // also want to correlate REGISTERs that might be valid initial responses in
    // the case where the IMPIStore is unavailable.
    if ((impi_obj == NULL) ||
        ((auth_challenge != NULL) && (auth_challenge->get_nonce_count() == 1)))
    {
      std::string opaque = PJUtils::pj_str_to_string(&credentials->opaque);
      TRC_DEBUG("Log opaque value %s to SAS as a generic correlator", opaque.c_str());
      SAS::Marker opaque_marker(trail(), MARKED_ID_GENERIC_CORRELATOR, 2u);
      opaque_marker.add_static_param((uint32_t)UniquenessScopes::DIGEST_OPAQUE);
      opaque_marker.add_var_param(opaque);
      SAS::report_marker(opaque_marker, SAS::Marker::Scope::Trace);
    }

    if (status == PJ_SUCCESS)
    {
      // Request contains a response to a previous challenge, so pass it to
      // the authentication module to verify.
      TRC_DEBUG("Verify authentication information in request");
      status = pjsip_auth_srv_verify3((is_register ?
                                         &_authentication->_auth_srv :
                                         &_authentication->_auth_srv_proxy),
                                      req,
                                      get_pool(req),
                                      &sc,
                                      (void*)auth_challenge);

      if ((status == PJ_SUCCESS) && (auth_challenge != NULL))
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
        auth_challenge->set_nonce_count(nonce_count + 1);

        // The challenge has been authenticated against successfully, so we can
        // remove the Chronos timer set at creation to trigger expiry, if present.
        if ((_authentication->_chronos) && (auth_challenge->get_timer_id() != ""))
        {
          HTTPCode status;
          status = _authentication->_chronos->send_delete(auth_challenge->get_timer_id(),
                                                          trail());
          if (status == HTTP_OK)
          {
            TRC_DEBUG("Timer deleted for auth_challenge %s", auth_challenge->get_nonce().c_str());
            auth_challenge->set_timer_id("");
          }
        }

        // Work out when the challenge should expire. We keep it around if we
        // might need it later which is the case if either:
        // - Nonce counts are supported.
        // - It is a digest challenge and we need to challenge initial requests
        //   from endpoints that use digest.
        //
        // We also only store challenges to REGISTERs, as these have a
        // well-defined lifetime (the duration of the REGISTER).
        if (is_register)
        {
          if (_authentication->_nonce_count_supported)
          {
            TRC_DEBUG("Storing challenge because nonce counts are supported");
            auth_challenge->set_expires(calculate_challenge_expiration_time(req));
          }
          else if ((auth_challenge->get_type() == ImpiStore::AuthChallenge::DIGEST) &&
                   (_authentication->_non_register_auth_mode &
                       NonRegisterAuthentication::INITIAL_REQ_FROM_REG_DIGEST_ENDPOINT))
          {
            TRC_DEBUG("Storing challenge in order to challenge non-REGISTER requests");
            auth_challenge->set_expires(calculate_challenge_expiration_time(req));
          }
        }

        // Write the challenge back to the store.
        Store::Status store_status =
          _authentication->write_challenge(impi, auth_challenge, impi_obj, trail());

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

          // Save off the authenticated IMPI and nonce. We need these later to
          // update the service route on a REGISTER. Also store off whether the
          // user authenticated using SIP digest.
          _authenticated_impi = impi;
          _authenticated_nonce = nonce;
          _authenticated_using_sip_digest =
            ((pj_strlen(&credentials->algorithm) == 0) ||
             (pj_stricmp2(&credentials->algorithm, "md5") == 0));

          // Free off the IMPI object before returning.
          delete impi_obj;

          send_request(req); return;
        }
      }
    }
  }
  else
  {
    // No credentials in request.
    status = PJSIP_EAUTHNOAUTH;
  }

  // We're done with the IMPI object now so delete it.
  delete impi_obj; impi_obj = NULL;

  // Create an ACR for the message and pass the request to it.  Role is always
  // considered originating for a REGISTER request.
  ACR* acr = _authentication->_acr_factory->get_acr(trail(),
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
    TRC_DEBUG("No authentication information in request or stale nonce, so reject with challenge (status %d)", status);
    pj_bool_t stale = (status == PJSIP_EAUTHACCNOTFOUND);

    if (stale)
    {
      SAS::Event event(trail(), SASEvent::AUTHENTICATION_FAILED_STALE_NONCE, 0);
      SAS::report_event(event);
    }

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

      HSSConnection::irs_query irs_query;
      irs_query._req_type = HSSConnection::AUTH_FAIL;
      irs_query._server_name = _scscf_uri;
      HSSConnection::irs_info unused_irs_info;

      PJUtils::get_impi_and_impu(req,
                                 irs_query._private_id,
                                 irs_query._public_id,
                                 get_pool(req),
                                 trail());
      _authentication->_hss->update_registration_state(irs_query,
                                                       unused_irs_info,
                                                       trail());
    }

    if (_authentication->_analytics != NULL)
    {
      _authentication->_analytics->auth_failure(PJUtils::pj_str_to_string(&credentials->username),
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
}

void AuthenticationSproutletTsx::on_rx_response(pjsip_msg* rsp, int fork_id)
{
  if (_authenticated_using_sip_digest)
  {
    pjsip_routing_hdr* sr_hdr = (pjsip_routing_hdr*)
      pjsip_msg_find_hdr_by_name(rsp, &STR_SERVICE_ROUTE, nullptr);

    if (sr_hdr != nullptr)
    {
      std::string escaped_username = Utils::url_escape(_authenticated_impi);
      std::string escaped_nonce = Utils::url_escape(_authenticated_nonce);
      TRC_DEBUG("Add parameters to Service-Route username=%s, nonce=%s",
                escaped_username.c_str(), escaped_nonce.c_str());

      pj_pool_t* pool = get_pool(rsp);
      pjsip_sip_uri* sr_uri = (pjsip_sip_uri*)pjsip_uri_get_uri(&sr_hdr->name_addr);

      pjsip_param *username_param = PJ_POOL_ALLOC_T(pool, pjsip_param);
      pj_strdup(pool, &username_param->name, &STR_USERNAME);
      pj_strdup2(pool, &username_param->value, escaped_username.c_str());
      pj_list_insert_before(&sr_uri->other_param, username_param);

      pjsip_param *nonce_param = PJ_POOL_ALLOC_T(pool, pjsip_param);
      pj_strdup(pool, &nonce_param->name, &STR_NONCE);
      pj_strdup2(pool, &nonce_param->value, escaped_nonce.c_str());
      pj_list_insert_before(&sr_uri->other_param, nonce_param);
    }
  }

  send_response(rsp);
}


Store::Status AuthenticationSproutlet::write_challenge(const std::string& impi,
                                                       ImpiStore::AuthChallenge* auth_challenge,
                                                       ImpiStore::Impi* impi_obj,
                                                       SAS::TrailId trail)
{
  Store::Status status = write_challenge_to_store(_impi_store,
                                                  impi,
                                                  auth_challenge,
                                                  impi_obj,
                                                  trail);

  if ((status == Store::OK) && !_remote_impi_stores.empty())
  {
    TRC_DEBUG("Replicate challenge to backup stores");

    for (ImpiStore* store: _remote_impi_stores)
    {
      write_challenge_to_store(store, impi, auth_challenge, impi_obj, trail);
    }
  }

  return status;
}


Store::Status AuthenticationSproutlet::
  write_challenge_to_store(ImpiStore* store,
                           const std::string& impi,
                           ImpiStore::AuthChallenge* auth_challenge,
                           ImpiStore::Impi* impi_obj,
                           SAS::TrailId trail)
{
  Store::Status status;
  const std::string nonce = auth_challenge->get_nonce();
  ImpiStore::Impi* current_impi_obj = impi_obj;

  do
  {
    if (current_impi_obj == NULL)
    {
      TRC_DEBUG("Lookup IMPI %s", impi.c_str());
      current_impi_obj = store->get_impi(impi, trail);
      if (current_impi_obj == NULL)
      {
        // LCOV_EXCL_START in practise this branch is only hit during data
        // contention, which is not tested in UT.
        status = Store::ERROR;
        break;
        // LCOV_EXCL_STOP
      }
    }

    // Check whether the IMPI has an existing auth challenge.
    ImpiStore::AuthChallenge* challenge =
      current_impi_obj->get_auth_challenge(nonce);

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
      challenge->set_nonce_count(std::max(auth_challenge->get_nonce_count(),
                                          challenge->get_nonce_count()));
      challenge->set_expires(std::max(auth_challenge->get_expires(),
                                      challenge->get_expires()));
    }
    else
    {
      // Add our new challenges to the IMPI.
      current_impi_obj->auth_challenges.push_back(auth_challenge);
      auth_challenge = NULL;
    }

    status = store->set_impi(current_impi_obj, trail);

    // If we inserted the auth challenge into the IMPI object take it back - the
    // caller owns it.
    if (auth_challenge == NULL)
    {
      // Take the challenge back as the caller still owns it.
      auth_challenge = current_impi_obj->get_auth_challenge(nonce);
      std::vector<ImpiStore::AuthChallenge*>& challenges = current_impi_obj->auth_challenges;
      challenges.erase(std::remove(challenges.begin(),
                                   challenges.end(),
                                   auth_challenge),
                       challenges.end());
    }

    // If we've allocated a new IMPI object, free it off now. We always NULL off
    // the pointer though - if we hit data contention any IMPI object the caller
    // provided us with is no good as it has the wrong CAS.
    if (current_impi_obj != impi_obj)
    {
      delete current_impi_obj;
    }
    current_impi_obj = NULL;

  } while (status == Store::DATA_CONTENTION);

  return status;
}

ImpiStore::Impi* AuthenticationSproutlet::read_impi(const std::string& impi,
                                                    SAS::TrailId trail)
{
  TRC_DEBUG("Lookup IMPI object: impi=%s", impi.c_str());
  ImpiStore::Impi* impi_obj = _impi_store->get_impi(impi, trail);

  if ((impi_obj != NULL) &&
      impi_obj->auth_challenges.empty() &&
      !_remote_impi_stores.empty())
  {
    TRC_DEBUG("Got an empty IMPI object - try backup stores (%d in total)",
              _remote_impi_stores.size());

    for (ImpiStore* store: _remote_impi_stores)
    {
      TRC_DEBUG("Try to get IMPI from backup store");
      ImpiStore::Impi* backup_impi_obj = store->get_impi(impi, trail);

      if (backup_impi_obj != NULL)
      {
        if (!backup_impi_obj->auth_challenges.empty())
        {
          // We found an IMPI in a backup store that has some challenges. Copy
          // them over and return (remembering to delete the backup IMPI object).
          TRC_DEBUG("Found IMPI in backup store");
          impi_obj->auth_challenges = std::move(backup_impi_obj->auth_challenges);
          delete backup_impi_obj; backup_impi_obj = NULL;
          break;
        }
        else
        {
          // Didn't find a suitable IMPIs in the backup store, so just delete
          // any IMPI object in hand.
          TRC_DEBUG("Didn't find backup IMPI");
          delete backup_impi_obj; backup_impi_obj = NULL;
        }
      }
    }
  }

  return impi_obj;
}
