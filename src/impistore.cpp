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
  return Store::Status::OK;
}

ImpiStore::Impi* ImpiStore::get_impi(const std::string& impi,
                                     SAS::TrailId trail)
{
  return NULL;
}

ImpiStore::Impi* ImpiStore::get_impi_with_nonce(const std::string& impi_str,
                                                const std::string& nonce,
                                                SAS::TrailId trail)
{
  ImpiStore::Impi* impi;
  if (_mode == ImpiStore::Mode::READ_IMPI_WRITE_IMPI)
  {
    // Mode is READ_IMPI_WRITE, so just call through to get_impi.
    impi = get_impi(impi_str, trail);
  }
  else
  {
    impi = NULL;
  }
  return impi;
}

Store::Status ImpiStore::delete_impi(Impi* impi,
                                     SAS::TrailId trail)
{
  return Store::Status::OK;
}

void correlate_trail_to_challenge(ImpiStore::AuthChallenge* auth_challenge,
                                  SAS::TrailId trail)
{
  if (auth_challenge->correlator == "")
  {
    TRC_WARNING("Could not raise branch correlation marker because the stored authentication challenge has an empty 'correlator' field");
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
