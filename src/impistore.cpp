  /**
 * @file impistore.cpp Implementation of store for IMPI data
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <map>
#include <pthread.h>

#include "log.h"
#include "impistore.h"
#include "sas.h"
#include "sproutsasevent.h"
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
#include "rapidjson/error/en.h"
#include "json_parse_utils.h"
#include <algorithm>

/// Parses a string to a JSON document.
/// @returns a JSON document or NULL.
/// @param string    the string to parse.
rapidjson::Document* ImpiStore::json_from_string(const std::string& string)
{
  rapidjson::Document* json = new rapidjson::Document;
  json->Parse<0>(string.c_str());
  if (json->HasParseError())
  {
    TRC_INFO("Failed to parse JSON.  Error: %s\n%s",
             rapidjson::GetParseError_En(json->GetParseError()),
             string.c_str());
    delete json;
    json = NULL;
  }
  return json;
}

// JSON field names and values.
static const char* const JSON_TYPE = "type";
static const char* const JSON_TYPE_DIGEST = "digest";
static const char* const JSON_TYPE_AKA = "aka";
static const char* const JSON_TYPE_ENUM[] = {JSON_TYPE_DIGEST, JSON_TYPE_AKA};
static const char* const JSON_NONCE = "nonce";
static const char* const JSON_NONCE_COUNT = "nc";
static const char* const JSON_EXPIRES = "expires";
static const char* const JSON_CORRELATOR = "correlator";
static const char* const JSON_REALM = "realm";
static const char* const JSON_QOP = "qop";
static const char* const JSON_HA1 = "ha1";
static const char* const JSON_RESPONSE = "response";
static const char* const JSON_SCSCF_URI = "scscf-uri";
static const char* const JSON_TIMER_ID = "timer_id";

ImpiStore::AuthChallenge* ImpiStore::Impi::get_auth_challenge(const std::string& nonce)
{
  // Spin through the list of authentication challenges, looking for a
  // matching nonce.
  ImpiStore::AuthChallenge* auth_challenge = NULL;
  for (std::vector<AuthChallenge*>::iterator it = auth_challenges.begin();
       it != auth_challenges.end();
       it++)
  {
    if ((*it)->_nonce == nonce)
    {
      auth_challenge = *it;
      break;
    }
  }
  return auth_challenge;
}

void ImpiStore::AuthChallenge::write_json(rapidjson::Writer<rapidjson::StringBuffer>* writer,
                                          bool expiry_in_ms)
{
  // Write all the base AuthChallenge fields to JSON, in the IMPI format.
  writer->String(JSON_TYPE); writer->String(JSON_TYPE_ENUM[_type]);
  writer->String(JSON_NONCE); writer->String(_nonce.c_str());
  writer->String(JSON_NONCE_COUNT); writer->Uint(_nonce_count);

  // The expiry is in seconds, so if we're supposed to write it in ms multiply
  // by 1000
  int64_t expires = _expires;

  // LCOV_EXCL_START
  if (expiry_in_ms)
  {
    expires *= 1000;
  }
  // LCOV_EXCL_STOP

  writer->String(JSON_EXPIRES); writer->Int64(expires);

  if (_correlator != "")
  {
    writer->String(JSON_CORRELATOR); writer->String(_correlator.c_str());
  }
  writer->String(JSON_SCSCF_URI); writer->String(_scscf_uri.c_str());

  writer->String(JSON_TIMER_ID); writer->String(_timer_id.c_str());
  // We don't serialize the CAS - this is passed to the store on the set_data call.
}

ImpiStore::AuthChallenge* ImpiStore::AuthChallenge::from_json(rapidjson::Value* json,
                                                              bool expiry_in_ms,
                                                              bool include_expired)
{
  ImpiStore::AuthChallenge* auth_challenge = NULL;
  if (json->IsObject())
  {
    // First, identify what type of AuthChallenge this is, and call through to
    // that class to deserialize.  Note that we deserialize "bottom-to-top" -
    // first parsing the type-specific fields and then filling in the general
    // fields.
    std::string type = "";
    JSON_SAFE_GET_STRING_MEMBER(*json, JSON_TYPE, type);
    if (type == JSON_TYPE_DIGEST)
    {
      auth_challenge = ImpiStore::DigestAuthChallenge::from_json(json);
    }
    else if (type == JSON_TYPE_AKA)
    {
      auth_challenge = ImpiStore::AKAAuthChallenge::from_json(json);
    }
    else
    {
      TRC_WARNING("Unknown JSON authentication challenge type: %s", type.c_str());
    }

    // If we successfully parsed the AuthChallenge so far, fill in the
    // remaining (base) fields.
    if (auth_challenge != NULL)
    {
      JSON_SAFE_GET_STRING_MEMBER(*json, JSON_NONCE, auth_challenge->_nonce);
      JSON_SAFE_GET_UINT_MEMBER(*json, JSON_NONCE_COUNT, auth_challenge->_nonce_count);
      JSON_SAFE_GET_STRING_MEMBER(*json, JSON_CORRELATOR, auth_challenge->_correlator);
      JSON_SAFE_GET_STRING_MEMBER(*json, JSON_SCSCF_URI, auth_challenge->_scscf_uri);
      JSON_SAFE_GET_STRING_MEMBER(*json, JSON_TIMER_ID, auth_challenge->_timer_id);

      int64_t expires = 0;
      JSON_SAFE_GET_INT_64_MEMBER(*json, JSON_EXPIRES, expires);

      // LCOV_EXCL_START
      if (expiry_in_ms)
      {
        // The AuthChallenge requires the expiry in seconds, so if we've stored
        // it in ms divide by 1000
        expires /= 1000;
      }
      // LCOV_EXCL_STOP

      auth_challenge->_expires = expires;

      if (auth_challenge->_nonce_count == 0)
      {
        // We should always have a nonce_count, but to ease version
        // forward-compatibility, default it if not found.
        TRC_WARNING("No \"%s\" field in JSON authentication challenge - defaulting to %u",
                    JSON_NONCE_COUNT, INITIAL_NONCE_COUNT);
        auth_challenge->_nonce_count = INITIAL_NONCE_COUNT;
      }

      if (auth_challenge->_expires == 0)
      {
        // We should always have an expires, but to ease version forward-
        // compatibility, default it if not found.  We use the DEFAULT_EXPIRES
        // as this should allow at least one authentication to succeed, even
        // if it won't allow re-authentication later.
        TRC_WARNING("No \"%s\" field in JSON authentication challenge - defaulting to %d",
                    JSON_EXPIRES, DEFAULT_EXPIRES);
        auth_challenge->_expires = time(NULL) + DEFAULT_EXPIRES;
      }

      // Check we have the nonce and the record hasn't expired - otherwise drop
      // the record.
      if (auth_challenge->_nonce == "")
      {
        TRC_WARNING("No \"%s\" field in JSON authentication challenge - dropping",
                    JSON_NONCE);
        delete auth_challenge; auth_challenge = NULL;
      }
      else if ((auth_challenge->_expires < time(NULL)) && (!include_expired))
      {
        TRC_DEBUG("Expires in past - dropping");
        delete auth_challenge; auth_challenge = NULL;
      }
    }
  }
  else
  {
    TRC_WARNING("JSON authentication challenge is not an object - dropping");
  }
  return auth_challenge;
}

void ImpiStore::DigestAuthChallenge::write_json(rapidjson::Writer<rapidjson::StringBuffer>* writer,
                                                bool expiry_in_ms)
{
  // Write all the DigestAuthChallenge fields to JSON, in IMPI format.  We
  // call into the superclass to write base AuthChallenges fields.
  ImpiStore::AuthChallenge::write_json(writer, expiry_in_ms);
  writer->String(JSON_REALM); writer->String(_realm.c_str());
  writer->String(JSON_QOP); writer->String(_qop.c_str());
  writer->String(JSON_HA1); writer->String(_ha1.c_str());
}

ImpiStore::DigestAuthChallenge* ImpiStore::DigestAuthChallenge::from_json(rapidjson::Value* json)
{
  // Construct a DigestAuthChallenge and fill it in.
  ImpiStore::DigestAuthChallenge* auth_challenge = new DigestAuthChallenge();
  JSON_SAFE_GET_STRING_MEMBER(*json, JSON_REALM, auth_challenge->_realm);
  JSON_SAFE_GET_STRING_MEMBER(*json, JSON_QOP, auth_challenge->_qop);
  JSON_SAFE_GET_STRING_MEMBER(*json, JSON_HA1, auth_challenge->_ha1);

  // Check we have the realm, qop and ha1 - otherwise drop the record.
  if (auth_challenge->_realm == "")
  {
    TRC_WARNING("No \"%s\" field in JSON authentication challenge - dropping",
                JSON_REALM);
    delete auth_challenge; auth_challenge = NULL;
  }
  else if (auth_challenge->_qop == "")
  {
    TRC_WARNING("No \"%s\" field in JSON authentication challenge - dropping",
                JSON_QOP);
    delete auth_challenge; auth_challenge = NULL;
  }
  else if (auth_challenge->_ha1 == "")
  {
    TRC_WARNING("No \"%s\" field in JSON authentication challenge - dropping",
                JSON_HA1);
    delete auth_challenge; auth_challenge = NULL;
  }
  return auth_challenge;
}

void ImpiStore::AKAAuthChallenge::write_json(rapidjson::Writer<rapidjson::StringBuffer>* writer,
                                             bool expiry_in_ms)
{
  // Write all the AKAAuthChallenge fields to JSON, in IMPI format.  We call
  // into the superclass to write base AuthChallenges fields.
  ImpiStore::AuthChallenge::write_json(writer, expiry_in_ms);
  writer->String(JSON_RESPONSE); writer->String(_response.c_str());
}

ImpiStore::AKAAuthChallenge* ImpiStore::AKAAuthChallenge::from_json(rapidjson::Value* json)
{
  // Construct an AKAAuthChallenge and fill it in.
  ImpiStore::AKAAuthChallenge* auth_challenge = new AKAAuthChallenge();
  JSON_SAFE_GET_STRING_MEMBER(*json, JSON_RESPONSE, auth_challenge->_response);

  // Check we have the response field - otherwise drop the record.
  if (auth_challenge->_response == "")
  {
    TRC_WARNING("No \"response\" field in JSON authentication challenge - dropping");
    delete auth_challenge; auth_challenge = NULL;
  }
  return auth_challenge;
}

ImpiStore::Impi::~Impi()
{
  // Spin through the AuthChallenges, destroying them.
  for (std::vector<ImpiStore::AuthChallenge*>::iterator it = auth_challenges.begin();
       it != auth_challenges.end();
       it++)
  {
    delete *it;
  }
}

int ImpiStore::Impi::get_expires()
{
  // Spin through the AuthChallenges, finding the latest expires time.
  int expires = 0;
  for (std::vector<ImpiStore::AuthChallenge*>::iterator it = auth_challenges.begin();
       it != auth_challenges.end();
       it++)
  {
    expires = std::max(expires, (*it)->_expires);
  }
  return expires;
}

ImpiStore::~ImpiStore()
{
}

void correlate_trail_to_challenge(ImpiStore::AuthChallenge* auth_challenge,
                                  SAS::TrailId trail)
{
  // Report the correlator as a SAS marker, if it exists.
  if (auth_challenge->get_correlator() != "")
  {
    SAS::Marker marker(trail, MARKED_ID_GENERIC_CORRELATOR, 3u);
    marker.add_static_param((uint32_t)UniquenessScopes::DIGEST_OPAQUE);
    marker.add_var_param(auth_challenge->get_correlator());
    SAS::report_marker(marker, SAS::Marker::Scope::Trace);
  }
  else
  {
    // This should never happen -- we always set a correlator.
    TRC_WARNING("Could not raise correlation marker because correlator is unknown");
  }
}
