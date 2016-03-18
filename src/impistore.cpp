/**
 * @file impistore.cpp Implementation of store for Authentication Vectors
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

const std::string ImpiStore::TABLE_IMPI = "impi";
const std::string ImpiStore::TABLE_AV = "av";

ImpiStore::AuthChallenge* ImpiStore::Impi::get_auth_challenge(const std::string& nonce)
{
  // Spin through the list of authentication challenges, looking for a
  // matching nonce.
  for (std::vector<AuthChallenge*>::iterator it = auth_challenges.begin();
       it != auth_challenges.end();
       it++)
  {
    if ((*it)->nonce == nonce) {
      return *it;
    }
  }
  return NULL;
}

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

std::string ImpiStore::AuthChallenge::to_json()
{
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  writer.StartObject();
  {
    write_json(&writer);
  }
  writer.EndObject();
  return buffer.GetString();
}

void ImpiStore::AuthChallenge::write_json(rapidjson::Writer<rapidjson::StringBuffer>* writer)
{
  writer->String(JSON_TYPE); writer->String(JSON_TYPE_ENUM[type]);
  writer->String(JSON_NONCE); writer->String(nonce.c_str());
  writer->String(JSON_NONCE_COUNT); writer->Uint(nonce_count);
  writer->String(JSON_EXPIRES); writer->Uint64(expires);
  if (correlator != "")
  {
    writer->String(JSON_CORRELATOR); writer->String(correlator.c_str());
  }
}

ImpiStore::AuthChallenge* ImpiStore::AuthChallenge::from_json(const std::string& json)
{
  ImpiStore::AuthChallenge* auth_challenge = NULL;
  rapidjson::Document* json_obj = json_from_string(json);
  if (json_obj != NULL)
  {
    auth_challenge = ImpiStore::AuthChallenge::from_json(json_obj);
  }
  delete json_obj;
  return auth_challenge;
}

ImpiStore::AuthChallenge* ImpiStore::AuthChallenge::from_json(rapidjson::Value* json)
{
  ImpiStore::AuthChallenge* auth_challenge = NULL;
  if (json->IsObject())
  {
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
    if (auth_challenge != NULL)
    {
      // Fill in remaining fields.
      JSON_SAFE_GET_STRING_MEMBER(*json, JSON_NONCE, auth_challenge->nonce);
      JSON_SAFE_GET_UINT_MEMBER(*json, JSON_NONCE_COUNT, auth_challenge->nonce_count);
      JSON_SAFE_GET_UINT_64_MEMBER(*json, JSON_EXPIRES, auth_challenge->expires);
      JSON_SAFE_GET_STRING_MEMBER(*json, JSON_CORRELATOR, auth_challenge->correlator);
      if (auth_challenge->nonce_count == 0)
      {
        TRC_WARNING("No \"%s\" field in JSON authentication challenge - defaulting to %u",
                    JSON_NONCE_COUNT, INITIAL_NONCE_COUNT);
        auth_challenge->nonce_count = INITIAL_NONCE_COUNT;
      }
      if (auth_challenge->expires == 0)
      {
        TRC_WARNING("No \"%s\" field in JSON authentication challenge - defaulting to ",
                    JSON_EXPIRES);
//TODO: Default expires field
//      auth_challenge->expires = 
      }
      if (auth_challenge->nonce == "")
      {
        TRC_WARNING("No \"%s\" field in JSON authentication challenge - dropping",
                    JSON_NONCE);
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
  // Nonce is part of the key, so isn't stored in the JSON.
  writer->String(JSON_AV_NONCE_COUNT); writer->Uint(nonce_count);
  writer->String(JSON_AV_EXPIRES); writer->Uint64(expires);
  if (correlator != "")
  {
    writer->String(JSON_AV_CORRELATOR); writer->String(correlator.c_str());
  }
  // For backwards-compatibility, set the tombstone flag if this challenge has
  // ever been used.  This behavior might seem odd, but previously we did not
  // support reuse of challenges.
  if (nonce_count > INITIAL_NONCE_COUNT)
  {
    writer->String(JSON_AV_TOMBSTONE); writer->Bool(true);
  }
}

ImpiStore::AuthChallenge* ImpiStore::AuthChallenge::from_json_av(const std::string& nonce, const std::string& json)
{
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
    rapidjson::Value* inner_obj = NULL;
    if (json->HasMember(JSON_AV_TYPE_DIGEST))
    {
      auth_challenge = ImpiStore::DigestAuthChallenge::from_json_av(json);
      inner_obj = &((*json)[JSON_AV_TYPE_DIGEST]);
      if (json->HasMember(JSON_AV_TYPE_AKA))
      {
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
    if (auth_challenge != NULL)
    {
      // Fill in remaining fields.
      auth_challenge->nonce = nonce;
      JSON_SAFE_GET_UINT_MEMBER(*inner_obj, JSON_AV_NONCE_COUNT, auth_challenge->nonce_count);
      JSON_SAFE_GET_UINT_64_MEMBER(*inner_obj, JSON_AV_EXPIRES, auth_challenge->expires);
      JSON_SAFE_GET_STRING_MEMBER(*inner_obj, JSON_AV_CORRELATOR, auth_challenge->correlator);
      if (auth_challenge->nonce_count == 0)
      {
        // No nonce count.  Default to the initial value, unless this challenge
        // has been tombstoned, in which case we need to increase by 1.  In
        // previous versions, challenges could only be used once, and would be
        // tombstoned to prevent reuse.
        bool tombstone = false;
        JSON_SAFE_GET_BOOL_MEMBER(*json, JSON_AV_TOMBSTONE, tombstone);
        auth_challenge->nonce_count = INITIAL_NONCE_COUNT + ((tombstone) ? 1 : 0);
        TRC_WARNING("No \"%s\" field in JSON AV - defaulting to %u",
                    JSON_AV_NONCE_COUNT, auth_challenge->nonce_count);
      }
      if (auth_challenge->expires == 0)
      {
        TRC_WARNING("No \"%s\" field in JSON authentication challenge - defaulting to ",
                    JSON_AV_EXPIRES);
//TODO: Default expires field
//      auth_challenge->expires = 
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
  ImpiStore::AuthChallenge::write_json(writer);
  writer->String(JSON_REALM); writer->String(realm.c_str());
  writer->String(JSON_QOP); writer->String(qop.c_str());
  writer->String(JSON_HA1); writer->String(ha1.c_str());
}

ImpiStore::DigestAuthChallenge* ImpiStore::DigestAuthChallenge::from_json(rapidjson::Value* json)
{
  ImpiStore::DigestAuthChallenge* auth_challenge = new DigestAuthChallenge();
  JSON_SAFE_GET_STRING_MEMBER(*json, JSON_REALM, auth_challenge->realm);
  JSON_SAFE_GET_STRING_MEMBER(*json, JSON_QOP, auth_challenge->qop);
  JSON_SAFE_GET_STRING_MEMBER(*json, JSON_HA1, auth_challenge->ha1);
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
  writer->String(JSON_AV_TYPE_DIGEST);
  writer->StartObject();
  {
    ImpiStore::AuthChallenge::write_json_av(writer);
    writer->String(JSON_AV_REALM); writer->String(realm.c_str());
    writer->String(JSON_AV_QOP); writer->String(qop.c_str());
    writer->String(JSON_AV_HA1); writer->String(ha1.c_str());
  }
  writer->EndObject();
}

ImpiStore::DigestAuthChallenge* ImpiStore::DigestAuthChallenge::from_json_av(rapidjson::Value* json)
{
  ImpiStore::DigestAuthChallenge* auth_challenge = NULL;
  rapidjson::Value* digest_obj = &((*json)[JSON_AV_TYPE_DIGEST]);
  if (digest_obj->IsObject())
  {
    auth_challenge = new DigestAuthChallenge();
    JSON_SAFE_GET_STRING_MEMBER(*digest_obj, JSON_AV_REALM, auth_challenge->realm);
    JSON_SAFE_GET_STRING_MEMBER(*digest_obj, JSON_AV_QOP, auth_challenge->qop);
    JSON_SAFE_GET_STRING_MEMBER(*digest_obj, JSON_AV_HA1, auth_challenge->ha1);
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
  ImpiStore::AuthChallenge::write_json(writer);
  writer->String(JSON_RESPONSE); writer->String(response.c_str());
}

ImpiStore::AKAAuthChallenge* ImpiStore::AKAAuthChallenge::from_json(rapidjson::Value* json)
{
  ImpiStore::AKAAuthChallenge* auth_challenge = new AKAAuthChallenge();
  JSON_SAFE_GET_STRING_MEMBER(*json, JSON_RESPONSE, auth_challenge->response);
  if (auth_challenge->response == "")
  {
    TRC_WARNING("No \"response\" field in JSON authentication challenge - dropping");
    delete auth_challenge; auth_challenge = NULL;
  }
  return auth_challenge;
}

void ImpiStore::AKAAuthChallenge::write_json_av(rapidjson::Writer<rapidjson::StringBuffer>* writer)
{
  writer->String(JSON_AV_TYPE_AKA);
  writer->StartObject();
  {
    ImpiStore::AuthChallenge::write_json_av(writer);
    writer->String(JSON_AV_RESPONSE); writer->String(response.c_str());
  }
  writer->EndObject();
}

ImpiStore::AKAAuthChallenge* ImpiStore::AKAAuthChallenge::from_json_av(rapidjson::Value* json)
{
  ImpiStore::AKAAuthChallenge* auth_challenge = NULL;
  rapidjson::Value* aka_obj = &((*json)[JSON_AV_TYPE_AKA]);
  if (aka_obj->IsObject())
  {
    auth_challenge = new AKAAuthChallenge();
    JSON_SAFE_GET_STRING_MEMBER(*aka_obj, JSON_AV_RESPONSE, auth_challenge->response);
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

std::string ImpiStore::Impi::to_json()
{
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
  // Impi is part of the key, so isn't stored in the JSON itself.
  if (auth_challenges.size() > 0)
  {
    writer->String(JSON_AUTH_CHALLENGES);
    writer->StartArray();
    {
      for (std::vector<ImpiStore::AuthChallenge*>::iterator it = auth_challenges.begin();
           it != auth_challenges.end();
           it++)
      {
        writer->StartObject();
        {
          (*it)->write_json(writer); 
        }
        writer->EndObject();
      }
    }
    writer->EndArray();
  }
}

ImpiStore::Impi* ImpiStore::Impi::from_json(const std::string& impi, const std::string& json)
{
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
    impi_obj = new ImpiStore::Impi(impi);
    if ((json->HasMember(JSON_AUTH_CHALLENGES)) &&
        ((*json)[JSON_AUTH_CHALLENGES].IsArray()))
    {
      rapidjson::Value* array = &((*json)[JSON_AUTH_CHALLENGES]);
      for (unsigned int ii = 0; ii < array->Size(); ii++)
      {
        ImpiStore::AuthChallenge* auth_challenge = ImpiStore::AuthChallenge::from_json(&((*array)[ii]));
        if (auth_challenge != NULL)
        {
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
  int expiry = 30000; // TODO: Calculate correctly.
  std::string data = impi->to_json();
  TRC_DEBUG("Storing IMPI for %s\n%s", impi->impi.c_str(), data.c_str());
  Store::Status status = _data_store->set_data(TABLE_IMPI,
                                               impi->impi,
                                               data,
                                               impi->_cas,
                                               expiry,
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
    TRC_ERROR("Failed to write IMPI for private_id %s", impi->impi.c_str());
    SAS::Event event(trail, SASEvent::IMPISTORE_IMPI_SET_FAILURE, 0);
    event.add_var_param(impi->impi);
    SAS::report_event(event);
    // LCOV_EXCL_STOP
  }

  if (_mode == ImpiStore::Mode::READ_AV_IMPI_WRITE_AV_IMPI)
  {
    for (std::vector<ImpiStore::AuthChallenge*>::iterator it = impi->auth_challenges.begin();
         it != impi->auth_challenges.end();
         it++)
    {
      std::string nonce = (*it)->nonce;
      data = (*it)->to_json_av();
      TRC_DEBUG("Storing AV for %s/%s\n%s", impi->impi.c_str(), nonce.c_str(), data.c_str());
      // TODO: Calculate expiry correctly.
      Store::Status local_status = _data_store->set_data(TABLE_AV,
                                                         impi->impi + '\\' + nonce,
                                                         data,
                                                         (*it)->_cas,
                                                         expiry,
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
    // TODO: Delete AVs
  }

  return status;
}

ImpiStore::Impi* ImpiStore::get_impi(const std::string& impi,
                                     SAS::TrailId trail)
{
  ImpiStore::Impi* impi_obj = NULL;
  std::string data;
  uint64_t cas;
  Store::Status status = _data_store->get_data(TABLE_IMPI, impi, data, cas, trail);
  if (status == Store::Status::OK)
  {
    TRC_DEBUG("Retrieved IMPI for %s\n%s", impi.c_str(), data.c_str());
    impi_obj = ImpiStore::Impi::from_json(impi, data);
    if (impi_obj != NULL)
    {
      impi_obj->_cas = cas;
    }
    SAS::Event event(trail, SASEvent::IMPISTORE_IMPI_GET_SUCCESS, 0);
    event.add_var_param(impi);
    SAS::report_event(event);
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
  ImpiStore::Impi* impi_obj = get_impi(impi, trail);
  if (_mode == ImpiStore::Mode::READ_AV_IMPI_WRITE_AV_IMPI)
  {
    std::string data;
    uint64_t cas;
    Store::Status status = _data_store->get_data(TABLE_AV, impi + '\\' + nonce, data, cas, trail);
    if (status == Store::Status::OK)
    {
      TRC_DEBUG("Retrieved AV for %s/%s\n%s", impi.c_str(), nonce.c_str(), data.c_str());
      ImpiStore::AuthChallenge* auth_challenge = ImpiStore::AuthChallenge::from_json_av(nonce, data);
      if (auth_challenge != NULL)
      {
        if (impi_obj == NULL)
        {
          impi_obj = new ImpiStore::Impi(impi);
        }
        auth_challenge->_cas = cas;
        bool auth_challenge_found;
        for (std::vector<ImpiStore::AuthChallenge*>::iterator it = impi_obj->auth_challenges.begin();
             it != impi_obj->auth_challenges.end();
             it++)
        {
          if ((*it)->nonce == auth_challenge->nonce)
          {
            ImpiStore::AuthChallenge* old_auth_challenge = *it;
            *it = auth_challenge;
            delete old_auth_challenge;
            auth_challenge_found = true;
            break;
          }
        }
        if (!auth_challenge_found)
        {
          impi_obj->auth_challenges.push_back(auth_challenge);
          impi_obj->_nonces.push_back(nonce);
        }
      }
      SAS::Event event(trail, SASEvent::IMPISTORE_AV_GET_SUCCESS, 0);
      event.add_var_param(impi);
      event.add_var_param(nonce);
      SAS::report_event(event);
    }
    else
    {
      SAS::Event event(trail, SASEvent::IMPISTORE_AV_GET_FAILURE, 0);
      event.add_var_param(impi);
      event.add_var_param(nonce);
      SAS::report_event(event);
    }
  }
  return impi_obj;
}

Store::Status ImpiStore::delete_impi(Impi* impi,
                                     SAS::TrailId trail)
{
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
    SAS::report_event(event);
    // LCOV_EXCL_STOP
  }

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

void correlate_trail_to_challenge(ImpiStore::AuthChallenge* auth_challenge,
                                  SAS::TrailId trail)
{
  if (auth_challenge->correlator == "")
  {
    TRC_WARNING("Could not raise branch correlation marker because correlator is unknown");
  }
  else
  {
    SAS::Marker via_marker(trail, MARKER_ID_VIA_BRANCH_PARAM, 1u);
    via_marker.add_var_param(auth_challenge->correlator);
    SAS::report_marker(via_marker, SAS::Marker::Scope::Trace);
  }
}

#if 0
Store::Status ImpiStore::set_av(const std::string& impi,
                                const std::string& nonce,
                                const rapidjson::Document* av,
                                uint64_t cas,
                                SAS::TrailId trail)
{
  std::string key = impi + '\\' + nonce;
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  av->Accept(writer);
  std::string data = buffer.GetString();

  TRC_DEBUG("Set AV for %s\n%s", key.c_str(), data.c_str());
  Store::Status status = _data_store->set_data("av", key, data, cas, AV_EXPIRY, trail);

  if (status == Store::Status::OK)
  {
    SAS::Event event(trail, SASEvent::AVSTORE_SET_SUCCESS, 0);
    event.add_var_param(impi);
    SAS::report_event(event);
  }
  else
  {
    // LCOV_EXCL_START
    TRC_ERROR("Failed to write Authentication Vector for private_id %s", impi.c_str());
    SAS::Event event(trail, SASEvent::AVSTORE_SET_FAILURE, 0);
    event.add_var_param(impi);
    SAS::report_event(event);
    // LCOV_EXCL_STOP
  }

  return status;
}

rapidjson::Document* ImpiStore::get_av(const std::string& impi,
                                       const std::string& nonce,
                                       uint64_t& cas,
                                       SAS::TrailId trail)
{
  rapidjson::Document* av = NULL;
  std::string key = impi + '\\' + nonce;
  std::string data;
  Store::Status status = _data_store->get_data("av", key, data, cas, trail);

  if (status == Store::Status::OK)
  {
    TRC_DEBUG("Retrieved AV for %s\n%s", key.c_str(), data.c_str());
    av = new rapidjson::Document;
    av->Parse<0>(data.c_str());

    if (av->HasParseError())
    {
      TRC_INFO("Failed to parse AV: %s\nError: %s",
               data.c_str(),
               rapidjson::GetParseError_En(av->GetParseError()));
      delete av;
      av = NULL;
    }

    SAS::Event event(trail, SASEvent::AVSTORE_GET_SUCCESS, 0);
    event.add_var_param(impi);
    SAS::report_event(event);
  }
  else
  {
    SAS::Event event(trail, SASEvent::AVSTORE_GET_FAILURE, 0);
    event.add_var_param(impi);
    SAS::report_event(event);
  }

  return av;
}

void correlate_branch_from_av(rapidjson::Document* av, SAS::TrailId trail)
{
  if (!(*av).HasMember("branch"))
  {
    TRC_WARNING("Could not raise branch correlation marker because the stored authentication vector is missing 'branch' field");
  }
  else if (!(*av)["branch"].IsString())
  {
    TRC_WARNING("Could not raise branch correlation marker because the stored authentication vector has a non-string 'branch' field");
  }
  else
  {
    std::string branch = (*av)["branch"].GetString();

    if (branch == "")
    {
      TRC_WARNING("Could not raise branch correlation marker because the stored authentication vector has an empty 'branch' field");
    }
    else
    {
      SAS::Marker via_marker(trail, MARKER_ID_VIA_BRANCH_PARAM, 1u);
      via_marker.add_var_param(branch.c_str());
      SAS::report_marker(via_marker, SAS::Marker::Scope::Trace);
    }
  }
}

#endif
