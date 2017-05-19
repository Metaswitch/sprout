/**
 * @file impistore.cpp Implementation of store for IMPI data
 *
 * Copyright (C) Metaswitch Networks
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
const std::string ImpiStore::TABLE_AV = "av";

// JSON field names and values.  Note that the IMPI and AV formats name some
// fields differently, so we have different constants for them.
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
static const char* const JSON_AV_TYPE_DIGEST = "digest";
static const char* const JSON_AV_TYPE_AKA = "aka";
static const char* const JSON_AV_NONCE_COUNT = "nc";
static const char* const JSON_AV_EXPIRES = "expires";
static const char* const JSON_AV_CORRELATOR = "branch";
static const char* const JSON_AV_REALM = "realm";
static const char* const JSON_AV_QOP = "qop";
static const char* const JSON_AV_HA1 = "ha1";
static const char* const JSON_AV_RESPONSE = "response";
static const char* const JSON_AV_TOMBSTONE = "tombstone";

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

std::string ImpiStore::AuthChallenge::to_json_av()
{
  // Build a writer, serialize the AuthChallenge to it and return the result.
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  writer.StartObject();
  {
    write_json_av(&writer);
  }
  writer.EndObject();
  return buffer.GetString();
}

void ImpiStore::AuthChallenge::write_json_av(rapidjson::Writer<rapidjson::StringBuffer>* writer)
{
  // Write the outer base AuthChallenge fields to JSON, in the AV format.  This
  // is just the correlator.
  if (correlator != "")
  {
    writer->String(JSON_AV_CORRELATOR); writer->String(correlator.c_str());
  }

  // For backwards-compatibility, set the tombstone flag if this challenge has
  // ever been used.  This behavior might seem odd, but previously we did not
  // support reuse of challenges, so this gives the best upgrade behavior.
  if (nonce_count > INITIAL_NONCE_COUNT)
  {
    writer->String(JSON_AV_TOMBSTONE); writer->Bool(true);
  }

  // Nonce is part of the key, so isn't stored in the JSON.
}

void ImpiStore::AuthChallenge::write_json_av_inner(rapidjson::Writer<rapidjson::StringBuffer>* writer)
{
  // Write the inner base AuthChallenge fields to JSON, in the AV format.
  // Nonce count is a bit complicated.  If the tombstone flag is set (and it
  // will be if nonce count is greater than the initial value), we need to
  // store the last-used nonce count, rather than the next acceptable one.  We
  // calculate this by decrementing the nonce count.  We undo this when we
  // read the AV back in from_json_av.
  //
  // The situation that this solves is:
  // - Uplevel node is in av-impi mode, generates a challenge and writes an AV
  //   with a nonce count of 1.
  // - Downlevel node processes the authentication response, and tombstones the
  //   AV but does not increment the nonce count (because the downlevel node
  //   does not support nonce counts).
  // - An uplevel node reads this AV back and knows the nonce count should have
  //   been incremented but wasn't, so increments the value it reads back
  //   before storing in the AuthChallenge object.
  // - Because of this processing, an uplevel node also needs to decrement the
  //   nonce count when writing AVs if the tombstone flag is set.
  uint32_t nonce_count_with_tombstone = nonce_count;
  if (nonce_count > INITIAL_NONCE_COUNT)
  {
    nonce_count_with_tombstone--;
    TRC_INFO("Entry tombstoned, so decrement nonce count to %u",
             nonce_count_with_tombstone);
  }
  writer->String(JSON_AV_NONCE_COUNT); writer->Uint(nonce_count_with_tombstone);
  writer->String(JSON_AV_EXPIRES); writer->Int(expires);
}

ImpiStore::AuthChallenge* ImpiStore::AuthChallenge::from_json_av(const std::string& nonce, const std::string& json)
{
  // Simply parse the string to JSON, and then call through to the
  // deserialization function.
  ImpiStore::AuthChallenge* auth_challenge = NULL;
  rapidjson::Document* json_obj = json_from_string(json);
  if (json_obj != NULL)
  {
    auth_challenge = ImpiStore::AuthChallenge::from_json_av(nonce, json_obj);
  }
  delete json_obj;
  return auth_challenge;
}

ImpiStore::AuthChallenge* ImpiStore::AuthChallenge::from_json_av(const std::string& nonce, rapidjson::Value* json)
{
  ImpiStore::AuthChallenge* auth_challenge = NULL;
  if (json->IsObject())
  {
    // First, identify what type of AuthChallenge this is, and call through to
    // that class to deserialize.  Note that we deserialize "bottom-to-top" -
    // first parsing the type-specific fields and then filling in the general
    // fields.
    rapidjson::Value* inner_obj = NULL;
    if (json->HasMember(JSON_AV_TYPE_DIGEST))
    {
      auth_challenge = ImpiStore::DigestAuthChallenge::from_json_av(json);
      inner_obj = &((*json)[JSON_AV_TYPE_DIGEST]);
      if (json->HasMember(JSON_AV_TYPE_AKA))
      {
        // We don't expect this to happen, but it's worth highlighting if it
        // does.
        TRC_WARNING("JSON AV contains both digest and AKA data - ignoring AKA");
      }
    }
    else if (json->HasMember(JSON_AV_TYPE_AKA))
    {
      auth_challenge = ImpiStore::AKAAuthChallenge::from_json_av(json);
      inner_obj = &((*json)[JSON_AV_TYPE_AKA]);
    }
    else
    {
      TRC_WARNING("JSON AV contains neither digest nor AKA data - dropping");
    }

    // If we successfully parsed the AuthChallenge so far, fill in the
    // remaining (base) fields.
    if (auth_challenge != NULL)
    {
      auth_challenge->nonce = nonce;
      auth_challenge->nonce_count = INITIAL_NONCE_COUNT;
      JSON_SAFE_GET_UINT_MEMBER(*inner_obj, JSON_AV_NONCE_COUNT, auth_challenge->nonce_count);
      JSON_SAFE_GET_INT_MEMBER(*inner_obj, JSON_AV_EXPIRES, auth_challenge->expires);
      JSON_SAFE_GET_STRING_MEMBER(*json, JSON_AV_CORRELATOR, auth_challenge->correlator);

      // If this challenge has been tombstoned, that means that the retrieved
      // nonce count is out-dated, so we need to increase it by 1 for the next
      // valid nonce count.
      bool tombstone = false;
      JSON_SAFE_GET_BOOL_MEMBER(*json, JSON_AV_TOMBSTONE, tombstone);
      if (tombstone)
      {
        auth_challenge->nonce_count++;
        TRC_INFO("Entry tombstoned, so increment nonce count to %u",
                 auth_challenge->nonce_count);
      }

      if (auth_challenge->expires == 0)
      {
        // No expires.  Previous versions did not store expires values, so this
        // is expected during upgrade.  Default it to the expires value used
        // previously.
        TRC_INFO("No \"%s\" field in JSON authentication challenge - defaulting to %d",
                 JSON_AV_EXPIRES, DEFAULT_EXPIRES);
        auth_challenge->expires = time(NULL) + DEFAULT_EXPIRES;
      }

      // Check the record hasn't expired - otherwise drop it.
      if (auth_challenge->expires < time(NULL))
      {
        TRC_DEBUG("Expires in past - dropping");
        delete auth_challenge; auth_challenge = NULL;
      }
    }
  }
  else
  {
    TRC_WARNING("JSON AV is not an object - dropping");
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

void ImpiStore::DigestAuthChallenge::write_json_av(rapidjson::Writer<rapidjson::StringBuffer>* writer)
{
  // Write all the DigestAuthChallenge fields to JSON, in AV format.  We call
  // into the superclass to write base AuthChallenges fields.
  writer->String(JSON_AV_TYPE_DIGEST);
  writer->StartObject();
  {
    ImpiStore::AuthChallenge::write_json_av_inner(writer);
    writer->String(JSON_AV_REALM); writer->String(realm.c_str());
    writer->String(JSON_AV_QOP); writer->String(qop.c_str());
    writer->String(JSON_AV_HA1); writer->String(ha1.c_str());
  }
  writer->EndObject();
  ImpiStore::AuthChallenge::write_json_av(writer);
}

ImpiStore::DigestAuthChallenge* ImpiStore::DigestAuthChallenge::from_json_av(rapidjson::Value* json)
{
  // First, get the "digest" sub-object.  The caller has checked that this
  // exists.
  ImpiStore::DigestAuthChallenge* auth_challenge = NULL;
  rapidjson::Value* digest_obj = &((*json)[JSON_AV_TYPE_DIGEST]);
  if (digest_obj->IsObject())
  {
    // Construct a DigestAuthChallenge and fill it in.
    auth_challenge = new DigestAuthChallenge();
    JSON_SAFE_GET_STRING_MEMBER(*digest_obj, JSON_AV_REALM, auth_challenge->realm);
    JSON_SAFE_GET_STRING_MEMBER(*digest_obj, JSON_AV_QOP, auth_challenge->qop);
    JSON_SAFE_GET_STRING_MEMBER(*digest_obj, JSON_AV_HA1, auth_challenge->ha1);

    // Check we have the realm, qop and ha1 - otherwise drop the record.
    if (auth_challenge->realm == "")
    {
      TRC_WARNING("No \"%s\" field in JSON authentication challenge - dropping",
                  JSON_AV_REALM);
      delete auth_challenge; auth_challenge = NULL;
    }
    else if (auth_challenge->qop == "")
    {
      TRC_WARNING("No \"%s\" field in JSON authentication challenge - dropping",
                  JSON_AV_QOP);
      delete auth_challenge; auth_challenge = NULL;
    }
    else if (auth_challenge->ha1 == "")
    {
      TRC_WARNING("No \"%s\" field in JSON authentication challenge - dropping",
                  JSON_AV_HA1);
      delete auth_challenge; auth_challenge = NULL;
    }
  }
  else
  {
    TRC_WARNING("JSON digest AV is not an object - dropping");
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

void ImpiStore::AKAAuthChallenge::write_json_av(rapidjson::Writer<rapidjson::StringBuffer>* writer)
{
  // Write all the AKAAuthChallenge fields to JSON, in AV format.  We call into
  // the superclass to write base AuthChallenges fields.
  writer->String(JSON_AV_TYPE_AKA);
  writer->StartObject();
  {
    ImpiStore::AuthChallenge::write_json_av_inner(writer);
    writer->String(JSON_AV_RESPONSE); writer->String(response.c_str());
  }
  writer->EndObject();
  ImpiStore::AuthChallenge::write_json_av(writer);
}

ImpiStore::AKAAuthChallenge* ImpiStore::AKAAuthChallenge::from_json_av(rapidjson::Value* json)
{
  // First, get the "aka" sub-object.  The caller has checked that this
  // exists.
  ImpiStore::AKAAuthChallenge* auth_challenge = NULL;
  rapidjson::Value* aka_obj = &((*json)[JSON_AV_TYPE_AKA]);
  if (aka_obj->IsObject())
  {
    // Construct an AKAAuthChallenge and fill it in.
    auth_challenge = new AKAAuthChallenge();
    JSON_SAFE_GET_STRING_MEMBER(*aka_obj, JSON_AV_RESPONSE, auth_challenge->response);

    // Check we have the response field - otherwise drop the record.
    if (auth_challenge->response == "")
    {
      TRC_WARNING("No \"%s\" field in JSON authentication challenge - dropping",
                  JSON_AV_RESPONSE);
      delete auth_challenge; auth_challenge = NULL;
    }
  }
  else
  {
    TRC_WARNING("JSON digest AV is not an object - dropping");
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
          impi_obj->_nonces.push_back(auth_challenge->nonce);
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

ImpiStore::ImpiStore(Store* data_store, Mode mode) :
  _data_store(data_store), _mode(mode)
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

  // If we're in Mode::READ_AV_IMPI_WRITE_AV_IMPI, also set the AVs in the
  // store.
  if (_mode == ImpiStore::Mode::READ_AV_IMPI_WRITE_AV_IMPI)
  {
    // Build a list of nonces to delete.  We'll remove ones for which
    // AuthChallenges still exist as we go through serializing them, and then
    // delete the rest at the end.
    std::vector<std::string> nonces_to_delete = impi->_nonces;

    for (std::vector<ImpiStore::AuthChallenge*>::iterator it = impi->auth_challenges.begin();
         it != impi->auth_challenges.end();
         it++)
    {
      std::string nonce = (*it)->nonce;
      if ((*it)->expires > now)
      {
        // The AuthChallenge hasn't expired, so serialize it and set it in the
        // store.
        data = (*it)->to_json_av();
        TRC_DEBUG("Storing AV for %s/%s\n%s", impi->impi.c_str(), nonce.c_str(), data.c_str());
        Store::Status local_status = _data_store->set_data(TABLE_AV,
                                                           impi->impi + '\\' + nonce,
                                                           data,
                                                           (*it)->_cas,
                                                           (*it)->expires - now,
                                                           trail);
        if (local_status == Store::Status::OK)
        {
          SAS::Event event(trail, SASEvent::IMPISTORE_AV_SET_SUCCESS, 0);
          event.add_var_param(impi->impi);
          event.add_var_param(nonce);
          SAS::report_event(event);
        }
        else
        {
          // LCOV_EXCL_START
          TRC_ERROR("Failed to set AV for %s/%s", impi->impi.c_str(), nonce.c_str());
          SAS::Event event(trail, SASEvent::IMPISTORE_AV_SET_FAILURE, 0);
          event.add_var_param(impi->impi);
          event.add_var_param(nonce.c_str());
          SAS::report_event(event);
          // Update status, but only if it's not already DATA_CONTENTION - that's
          // the most significant status.
          if (status != Store::Status::DATA_CONTENTION)
          {
            status = local_status;
          }
          // LCOV_EXCL_STOP
        }
      }
      else
      {
        TRC_DEBUG("Not storing AV for %s/%s - expired", impi->impi.c_str(), nonce.c_str());
      }

      // Since this AuthChallenge was still in the list, remove it from the
      // list of nonces to delete.
      nonces_to_delete.erase(std::remove(nonces_to_delete.begin(),
                                         nonces_to_delete.end(),
                                         nonce),
                             nonces_to_delete.end());
    }

    // Now spin through the nonces to delete, deleting them from the AV store.
    for (std::vector<std::string>::iterator it = nonces_to_delete.begin();
         it != nonces_to_delete.end();
         it++)
    {
      std::string nonce = *it;
      TRC_DEBUG("Deleting AV for %s/%s", impi->impi.c_str(), nonce.c_str());
      Store::Status local_status = _data_store->delete_data(TABLE_AV,
                                                            impi->impi + '\\' + nonce,
                                                            trail);
      if (local_status == Store::Status::OK)
      {
        SAS::Event event(trail, SASEvent::IMPISTORE_AV_DELETE_SUCCESS, 0);
        event.add_var_param(impi->impi);
        event.add_var_param(nonce);
        SAS::report_event(event);
      }
      else
      {
        // LCOV_EXCL_START
        TRC_ERROR("Failed to delete AV for %s/%s", impi->impi.c_str(), nonce.c_str());
        SAS::Event event(trail, SASEvent::IMPISTORE_AV_DELETE_FAILURE, 0);
        event.add_var_param(impi->impi);
        event.add_var_param(nonce.c_str());
        SAS::report_event(event);
        // Update status, but only if it's not already DATA_CONTENTION - that's
        // the most significant status.
        if (status != Store::Status::DATA_CONTENTION)
        {
          status = local_status;
        }
        // LCOV_EXCL_STOP
      }
    }
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
    if (impi_obj != NULL)
    {
      // Got an IMPI.  Fill in the CAS.
      impi_obj->_cas = cas;

      // If we're in Mode::READ_AV_IMPI_WRITE_AV_IMPI, spin through the
      // AuthChallenges, getting the version from the AV store if it exists.
      // In particular, this means we have the correct CAS for when we write
      // back.  This might seem expensive but bear in mind that we expect to
      // have very few AuthChallenges outstanding.
      if (_mode == ImpiStore::Mode::READ_AV_IMPI_WRITE_AV_IMPI)
      {
        for (std::vector<ImpiStore::AuthChallenge*>::iterator it = impi_obj->auth_challenges.begin();
             it != impi_obj->auth_challenges.end();
             it++)
        {
          ImpiStore::AuthChallenge* auth_challenge_from_impi = *it;
          ImpiStore::AuthChallenge* auth_challenge_from_av =
            get_av(impi, auth_challenge_from_impi->nonce, trail);
          if (auth_challenge_from_av != NULL)
          {
            // We got an AuthChallenge from the AV store, so replace the IMPI-
            // derived one.
            *it = auth_challenge_from_av;
            delete auth_challenge_from_impi;
          }
        }
      }
    }
  }
  else
  {
    SAS::Event event(trail, SASEvent::IMPISTORE_IMPI_GET_FAILURE, 0);
    event.add_var_param(impi);
    SAS::report_event(event);
  }
  return impi_obj;
}

ImpiStore::Impi* ImpiStore::get_impi_with_nonce(const std::string& impi,
                                                const std::string& nonce,
                                                SAS::TrailId trail)
{
  // First, get the IMPI without worrying about this nonce.
  ImpiStore::Impi* impi_obj = get_impi(impi, trail);

  // If we're in Mode::READ_AV_IMPI_WRITE_AV_IMPI and the IMPI doesn't already
  // contain an AuthChallenge matching this nonce, look up the nonce
  // explicitly.
  if ((_mode == ImpiStore::Mode::READ_AV_IMPI_WRITE_AV_IMPI) &&
      ((impi_obj == NULL) ||
       (impi_obj->get_auth_challenge(nonce) == NULL)))
  {
    ImpiStore::AuthChallenge* auth_challenge = get_av(impi, nonce, trail);
    if (auth_challenge != NULL)
    {
      // Found an AuthChallenge.  Add it to the IMPI, creating if it doesn't
      // exist.
      if (impi_obj == NULL)
      {
        impi_obj = new ImpiStore::Impi(impi);
      }
      impi_obj->auth_challenges.push_back(auth_challenge);
      impi_obj->_nonces.push_back(nonce);
    }
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

  // If we're in Mode::READ_AV_IMPI_WRITE_AV_IMPI, also spin through the
  // AuthChallenges, deleting them.
  if (_mode == ImpiStore::Mode::READ_AV_IMPI_WRITE_AV_IMPI)
  {
    for (std::vector<ImpiStore::AuthChallenge*>::iterator it = impi->auth_challenges.begin();
         it != impi->auth_challenges.end();
         it++)
    {
      std::string nonce = (*it)->nonce;
      TRC_DEBUG("Deleting AV for %s/%s", impi->impi.c_str(), nonce.c_str());
      Store::Status local_status = _data_store->delete_data(TABLE_AV,
                                                            impi->impi + '\\' + nonce,
                                                            trail);
      if (local_status == Store::Status::OK)
      {
        SAS::Event event(trail, SASEvent::IMPISTORE_AV_DELETE_SUCCESS, 0);
        event.add_var_param(impi->impi);
        event.add_var_param(nonce);
        SAS::report_event(event);
      }
      else
      {
        // LCOV_EXCL_START
        TRC_ERROR("Failed to delete AV for %s/%s", impi->impi.c_str(), nonce.c_str());
        SAS::Event event(trail, SASEvent::IMPISTORE_AV_DELETE_FAILURE, 0);
        event.add_var_param(impi->impi);
        event.add_var_param(nonce.c_str());
        event.add_static_param(local_status);
        SAS::report_event(event);
        // Update status, but only if it's not already DATA_CONTENTION - that's
        // the most significant status.
        if (status != Store::Status::DATA_CONTENTION)
        {
          status = local_status;
        }
        // LCOV_EXCL_STOP
      }
    }
  }

  return status;
}

ImpiStore::AuthChallenge* ImpiStore::get_av(const std::string& impi,
                                            const std::string& nonce,
                                            SAS::TrailId trail)
{
  // Get the AuthChallenge data from the store and deserialize it.
  ImpiStore::AuthChallenge* auth_challenge = NULL;
  std::string data;
  uint64_t cas;
  Store::Status status = _data_store->get_data(TABLE_AV, impi + '\\' + nonce, data, cas, trail);
  if (status == Store::Status::OK)
  {
    TRC_DEBUG("Retrieved AV for %s/%s\n%s", impi.c_str(), nonce.c_str(), data.c_str());
    SAS::Event event(trail, SASEvent::IMPISTORE_AV_GET_SUCCESS, 0);
    event.add_var_param(impi);
    event.add_var_param(nonce);
    SAS::report_event(event);
    auth_challenge = ImpiStore::AuthChallenge::from_json_av(nonce, data);
    if (auth_challenge != NULL)
    {
      auth_challenge->_cas = cas;
    }
  }
  else
  {
    SAS::Event event(trail, SASEvent::IMPISTORE_AV_GET_FAILURE, 0);
    event.add_var_param(impi);
    event.add_var_param(nonce);
    SAS::report_event(event);
  }
  return auth_challenge;
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
