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
#include "store.h"
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
static rapidjson::Document* json_from_string(const std::string& string)
{
  rapidjson::Document* json = new rapidjson::Document;
  json->Parse<0>(string.c_str());
  if (json->HasParseError())
  {
    TRC_INFO("Failed to parse JSON: %s\nError: %s",
             string.c_str(),
             rapidjson::GetParseError_En(json->GetParseError()));
    delete json;
    json = NULL;
  }
  return json;
}

// Constant table names.
const std::string ImpiStore::TABLE_IMPI = "impi";

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
static const char* const JSON_AUTH_CHALLENGES = "authChallenges";
static const char* const JSON_SCSCF_URI = "scscf-uri";

ImpiStore::AuthChallenge* ImpiStore::Impi::get_auth_challenge(const std::string& nonce)
{
  // Spin through the list of authentication challenges, looking for a
  // matching nonce.
  ImpiStore::AuthChallenge* auth_challenge = NULL;
  for (std::vector<AuthChallenge*>::iterator it = auth_challenges.begin();
       it != auth_challenges.end();
       it++)
  {
    if ((*it)->nonce == nonce)
    {
      auth_challenge = *it;
      break;
    }
  }
  return auth_challenge;
}

void ImpiStore::AuthChallenge::write_json(rapidjson::Writer<rapidjson::StringBuffer>* writer)
{
  // Write all the base AuthChallenge fields to JSON, in the IMPI format.
  writer->String(JSON_TYPE); writer->String(JSON_TYPE_ENUM[type]);
  writer->String(JSON_NONCE); writer->String(nonce.c_str());
  writer->String(JSON_NONCE_COUNT); writer->Uint(nonce_count);
  writer->String(JSON_EXPIRES); writer->Int(expires);
  if (correlator != "")
  {
    writer->String(JSON_CORRELATOR); writer->String(correlator.c_str());
  }
  writer->String(JSON_SCSCF_URI); writer->String(scscf_uri.c_str());
  // We don't serialize the CAS - this is passed to the store on the set_data call.
}

ImpiStore::AuthChallenge* ImpiStore::AuthChallenge::from_json(rapidjson::Value* json)
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
      JSON_SAFE_GET_STRING_MEMBER(*json, JSON_NONCE, auth_challenge->nonce);
      JSON_SAFE_GET_UINT_MEMBER(*json, JSON_NONCE_COUNT, auth_challenge->nonce_count);
      JSON_SAFE_GET_INT_MEMBER(*json, JSON_EXPIRES, auth_challenge->expires);
      JSON_SAFE_GET_STRING_MEMBER(*json, JSON_CORRELATOR, auth_challenge->correlator);
      JSON_SAFE_GET_STRING_MEMBER(*json, JSON_SCSCF_URI, auth_challenge->scscf_uri);

      if (auth_challenge->nonce_count == 0)
      {
        // We should always have a nonce_count, but to ease version
        // forward-compatibility, default it if not found.
        TRC_WARNING("No \"%s\" field in JSON authentication challenge - defaulting to %u",
                    JSON_NONCE_COUNT, INITIAL_NONCE_COUNT);
        auth_challenge->nonce_count = INITIAL_NONCE_COUNT;
      }

      if (auth_challenge->expires == 0)
      {
        // We should always have an expires, but to ease version forward-
        // compatibility, default it if not found.  We use the DEFAULT_EXPIRES
        // as this should allow at least one authentication to succeed, even
        // if it won't allow re-authentication later.
        TRC_WARNING("No \"%s\" field in JSON authentication challenge - defaulting to %d",
                    JSON_EXPIRES, DEFAULT_EXPIRES);
        auth_challenge->expires = time(NULL) + DEFAULT_EXPIRES;
      }

      // Check we have the nonce and the record hasn't expired - otherwise drop
      // the record.
      if (auth_challenge->nonce == "")
      {
        TRC_WARNING("No \"%s\" field in JSON authentication challenge - dropping",
                    JSON_NONCE);
        delete auth_challenge; auth_challenge = NULL;
      }
      else if (auth_challenge->expires < time(NULL))
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

void ImpiStore::DigestAuthChallenge::write_json(rapidjson::Writer<rapidjson::StringBuffer>* writer)
{
  // Write all the DigestAuthChallenge fields to JSON, in IMPI format.  We
  // call into the superclass to write base AuthChallenges fields.
  ImpiStore::AuthChallenge::write_json(writer);
  writer->String(JSON_REALM); writer->String(realm.c_str());
  writer->String(JSON_QOP); writer->String(qop.c_str());
  writer->String(JSON_HA1); writer->String(ha1.c_str());
}

ImpiStore::DigestAuthChallenge* ImpiStore::DigestAuthChallenge::from_json(rapidjson::Value* json)
{
  // Construct a DigestAuthChallenge and fill it in.
  ImpiStore::DigestAuthChallenge* auth_challenge = new DigestAuthChallenge();
  JSON_SAFE_GET_STRING_MEMBER(*json, JSON_REALM, auth_challenge->realm);
  JSON_SAFE_GET_STRING_MEMBER(*json, JSON_QOP, auth_challenge->qop);
  JSON_SAFE_GET_STRING_MEMBER(*json, JSON_HA1, auth_challenge->ha1);

  // Check we have the realm, qop and ha1 - otherwise drop the record.
  if (auth_challenge->realm == "")
  {
    TRC_WARNING("No \"%s\" field in JSON authentication challenge - dropping",
                JSON_REALM);
    delete auth_challenge; auth_challenge = NULL;
  }
  else if (auth_challenge->qop == "")
  {
    TRC_WARNING("No \"%s\" field in JSON authentication challenge - dropping",
                JSON_QOP);
    delete auth_challenge; auth_challenge = NULL;
  }
  else if (auth_challenge->ha1 == "")
  {
    TRC_WARNING("No \"%s\" field in JSON authentication challenge - dropping",
                JSON_HA1);
    delete auth_challenge; auth_challenge = NULL;
  }
  return auth_challenge;
}

void ImpiStore::AKAAuthChallenge::write_json(rapidjson::Writer<rapidjson::StringBuffer>* writer)
{
  // Write all the AKAAuthChallenge fields to JSON, in IMPI format.  We call
  // into the superclass to write base AuthChallenges fields.
  ImpiStore::AuthChallenge::write_json(writer);
  writer->String(JSON_RESPONSE); writer->String(response.c_str());
}

ImpiStore::AKAAuthChallenge* ImpiStore::AKAAuthChallenge::from_json(rapidjson::Value* json)
{
  // Construct an AKAAuthChallenge and fill it in.
  ImpiStore::AKAAuthChallenge* auth_challenge = new AKAAuthChallenge();
  JSON_SAFE_GET_STRING_MEMBER(*json, JSON_RESPONSE, auth_challenge->response);

  // Check we have the response field - otherwise drop the record.
  if (auth_challenge->response == "")
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

std::string ImpiStore::Impi::to_json()
{
  // Build a writer, serialize the IMPI to it and return the result.
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  writer.StartObject();
  {
    write_json(&writer);
  }
  writer.EndObject();
  return buffer.GetString();
}

void ImpiStore::Impi::write_json(rapidjson::Writer<rapidjson::StringBuffer>* writer)
{
  // Write a JSON array, and then write each of the AuthChallenges into it.
  int now = time(NULL);
  writer->String(JSON_AUTH_CHALLENGES);
  writer->StartArray();
  {
    for (std::vector<ImpiStore::AuthChallenge*>::iterator it = auth_challenges.begin();
         it != auth_challenges.end();
         it++)
    {
      if ((*it)->expires > now)
      {
        writer->StartObject();
        {
          (*it)->write_json(writer);
        }
        writer->EndObject();
      }
    }
  }
  writer->EndArray();
  // The private ID itself is part of the key, so isn't stored in the JSON itself.
}

ImpiStore::Impi* ImpiStore::Impi::from_json(const std::string& impi, const std::string& json)
{
  // Simply parse the string to JSON, and then call through to the
  // deserialization function.
  ImpiStore::Impi* impi_obj = NULL;
  rapidjson::Document* json_obj = json_from_string(json);
  if (json_obj != NULL)
  {
    impi_obj = ImpiStore::Impi::from_json(impi, json_obj);
  }
  delete json_obj;
  return impi_obj;
}

ImpiStore::Impi* ImpiStore::Impi::from_json(const std::string& impi, rapidjson::Value* json)
{
  ImpiStore::Impi* impi_obj = NULL;
  if (json->IsObject())
  {
    // Construct an Impi, and then look for an "authChallenges" array.
    impi_obj = new ImpiStore::Impi(impi);
    if ((json->HasMember(JSON_AUTH_CHALLENGES)) &&
        ((*json)[JSON_AUTH_CHALLENGES].IsArray()))
    {
      // Spin through the array, trying to parse as AuthChallenges.
      rapidjson::Value* array = &((*json)[JSON_AUTH_CHALLENGES]);
      for (unsigned int ii = 0; ii < array->Size(); ii++)
      {
        ImpiStore::AuthChallenge* auth_challenge = ImpiStore::AuthChallenge::from_json(&((*array)[ii]));
        if (auth_challenge != NULL)
        {
          // Got an AuthChallenge, so add it to our array and also add its
          // nonce to the array of nonces we retrieved from the server (so that
          // we can spot when the user deletes AuthChallenges).
          impi_obj->auth_challenges.push_back(auth_challenge);
        }
      }
    }
  }
  else
  {
    TRC_WARNING("JSON IMPI is not an object - dropping");
  }
  return impi_obj;
}

int ImpiStore::Impi::get_expires()
{
  // Spin through the AuthChallenges, finding the latest expires time.
  int expires = 0;
  for (std::vector<ImpiStore::AuthChallenge*>::iterator it = auth_challenges.begin();
       it != auth_challenges.end();
       it++)
  {
    expires = std::max(expires, (*it)->expires);
  }
  return expires;
}

ImpiStore::ImpiStore(Store* data_store) :
  _data_store(data_store)
{
}

ImpiStore::~ImpiStore()
{
}

Store::Status ImpiStore::set_impi(Impi* impi,
                                  SAS::TrailId trail)
{
  int now = time(NULL);

  // First serialize the IMPI and set it in the store.
  std::string data = impi->to_json();
  TRC_DEBUG("Storing IMPI for %s\n%s", impi->impi.c_str(), data.c_str());
  Store::Status status = _data_store->set_data(TABLE_IMPI,
                                               impi->impi,
                                               data,
                                               impi->_cas,
                                               impi->get_expires() - now,
                                               trail);
  if (status == Store::Status::OK)
  {
    SAS::Event event(trail, SASEvent::IMPISTORE_IMPI_SET_SUCCESS, 0);
    event.add_var_param(impi->impi);
    SAS::report_event(event);
  }
  else
  {
    // LCOV_EXCL_START
    if (status != Store::Status::DATA_CONTENTION)
    {
      TRC_ERROR("Failed to write IMPI for private_id %s", impi->impi.c_str());
    }

    SAS::Event event(trail, SASEvent::IMPISTORE_IMPI_SET_FAILURE, 0);
    event.add_var_param(impi->impi);
    SAS::report_event(event);
    // LCOV_EXCL_STOP
  }

  return status;
}

ImpiStore::Impi* ImpiStore::get_impi(const std::string& impi,
                                     SAS::TrailId trail)
{
  // Get the IMPI data from the store and deserialize it.
  ImpiStore::Impi* impi_obj = NULL;
  std::string data;
  uint64_t cas;
  Store::Status status = _data_store->get_data(TABLE_IMPI, impi, data, cas, trail);
  if (status == Store::Status::OK)
  {
    TRC_DEBUG("Retrieved IMPI for %s\n%s", impi.c_str(), data.c_str());
    SAS::Event event(trail, SASEvent::IMPISTORE_IMPI_GET_SUCCESS, 0);
    event.add_var_param(impi);
    SAS::report_event(event);

    impi_obj = ImpiStore::Impi::from_json(impi, data);
    if (impi_obj == NULL)
    {
      // IMPI was corrupt. Create a new one.
      impi_obj = new Impi(impi);
    }

    // By this point we've got an IMPI.  Fill in the CAS.
    impi_obj->_cas = cas;
  }
  else if (status == Store::Status::NOT_FOUND)
  {
    impi_obj = new Impi(impi);
  }
  else
  {
    SAS::Event event(trail, SASEvent::IMPISTORE_IMPI_GET_FAILURE, 0);
    event.add_var_param(impi);
    SAS::report_event(event);
  }
  return impi_obj;
}

Store::Status ImpiStore::delete_impi(Impi* impi,
                                     SAS::TrailId trail)
{
  // First, delete the IMPI data from the store.
  TRC_DEBUG("Deleting IMPI for %s", impi->impi.c_str());
  Store::Status status = _data_store->delete_data(TABLE_IMPI,
                                                  impi->impi,
                                                  trail);
  if (status == Store::Status::OK)
  {
    SAS::Event event(trail, SASEvent::IMPISTORE_IMPI_DELETE_SUCCESS, 0);
    event.add_var_param(impi->impi);
    SAS::report_event(event);
  }
  else
  {
    // LCOV_EXCL_START
    TRC_ERROR("Failed to delete IMPI for private_id %s", impi->impi.c_str());
    SAS::Event event(trail, SASEvent::IMPISTORE_IMPI_DELETE_FAILURE, 0);
    event.add_var_param(impi->impi);
    event.add_static_param(status);
    SAS::report_event(event);
    // LCOV_EXCL_STOP
  }

  return status;
}

void correlate_trail_to_challenge(ImpiStore::AuthChallenge* auth_challenge,
                                  SAS::TrailId trail)
{
  // Report the correlator as a SAS marker, if it exists.
  if (auth_challenge->correlator != "")
  {
    SAS::Marker via_marker(trail, MARKER_ID_VIA_BRANCH_PARAM, 1u);
    via_marker.add_var_param(auth_challenge->correlator);
    SAS::report_marker(via_marker, SAS::Marker::Scope::Trace);
  }
  else
  {
    TRC_WARNING("Could not raise branch correlation marker because correlator is unknown");
  }
}
