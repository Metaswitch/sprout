/**
 * @file astaire_impistore.cpp Implementation of class for storing IMPIs in a
 *                             Memcached-like store
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
#include "astaire_impistore.h"
#include "sas.h"
#include "sproutsasevent.h"
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
#include "rapidjson/error/en.h"
#include "json_parse_utils.h"
#include <algorithm>

// Constant table names.
const std::string AstaireImpiStore::TABLE_IMPI = "impi";

// JSON field names and values.
static const char* const JSON_AUTH_CHALLENGES = "authChallenges";

std::string AstaireImpiStore::Impi::to_json()
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

void AstaireImpiStore::Impi::write_json(rapidjson::Writer<rapidjson::StringBuffer>* writer)
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
      if ((*it)->get_expires() > now)
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

AstaireImpiStore::Impi* AstaireImpiStore::from_json(const std::string& impi, const std::string& json)
{
  // Simply parse the string to JSON, and then call through to the
  // deserialization function.
  AstaireImpiStore::Impi* impi_obj = NULL;
  rapidjson::Document* json_obj = json_from_string(json);
  if (json_obj != NULL)
  {
    impi_obj = AstaireImpiStore::from_json(impi, json_obj);
  }
  delete json_obj;
  return impi_obj;
}

AstaireImpiStore::Impi* AstaireImpiStore::from_json(const std::string& impi, rapidjson::Value* json)
{
  AstaireImpiStore::Impi* impi_obj = NULL;
  if (json->IsObject())
  {
    // Construct an Impi, and then look for an "authChallenges" array.
    impi_obj = new AstaireImpiStore::Impi(impi);
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

AstaireImpiStore::AstaireImpiStore(Store* data_store) :
  _data_store(data_store)
{
}

AstaireImpiStore::~AstaireImpiStore()
{
}

Store::Status AstaireImpiStore::set_impi(ImpiStore::Impi* impi,
                                         SAS::TrailId trail)
{
  AstaireImpiStore::Impi* astaire_impi = (AstaireImpiStore::Impi*)impi;
  int now = time(NULL);

  // First serialize the IMPI and set it in the store.
  std::string data = astaire_impi->to_json();
  TRC_DEBUG("Storing IMPI for %s\n%s", impi->impi.c_str(), data.c_str());
  Store::Status status = _data_store->set_data(TABLE_IMPI,
                                               astaire_impi->impi,
                                               data,
                                               astaire_impi->_cas,
                                               astaire_impi->get_expires() - now,
                                               trail,
                                               Store::Format::JSON);
  if (status == Store::Status::OK)
  {
    SAS::Event event(trail, SASEvent::IMPISTORE_IMPI_SET_SUCCESS, 0);
    event.add_var_param(astaire_impi->impi);
    SAS::report_event(event);
  }
  else
  {
    // LCOV_EXCL_START
    if (status != Store::Status::DATA_CONTENTION)
    {
      TRC_ERROR("Failed to write IMPI for private_id %s", astaire_impi->impi.c_str());
    }

    SAS::Event event(trail, SASEvent::IMPISTORE_IMPI_SET_FAILURE, 0);
    event.add_var_param(astaire_impi->impi);
    SAS::report_event(event);
    // LCOV_EXCL_STOP
  }

  return status;
}

// The AstaireImpiStore never includes expired challenges, so include_expired is
// unused
ImpiStore::Impi* AstaireImpiStore::get_impi(const std::string& impi,
                                            SAS::TrailId trail,
                                            bool include_expired)
{
  // Get the IMPI data from the store and deserialize it.
  AstaireImpiStore::Impi* impi_obj = NULL;
  std::string data;
  uint64_t cas;
  Store::Status status = _data_store->get_data(TABLE_IMPI,
                                               impi,
                                               data,
                                               cas,
                                               trail,
                                               Store::Format::JSON);
  if (status == Store::Status::OK)
  {
    TRC_DEBUG("Retrieved IMPI for %s\n%s", impi.c_str(), data.c_str());
    SAS::Event event(trail, SASEvent::IMPISTORE_IMPI_GET_SUCCESS, 0);
    event.add_var_param(impi);
    SAS::report_event(event);

    impi_obj = AstaireImpiStore::from_json(impi, data);
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

Store::Status AstaireImpiStore::delete_impi(ImpiStore::Impi* impi,
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
