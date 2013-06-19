/**
 * @file hssconnection.cpp HSSConnection class methods.
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

///

#include <string>
#include <json/reader.h>
#include <json/writer.h>

#include "utils.h"
#include "log.h"
#include "sas.h"
#include "sasevent.h"
#include "httpconnection.h"
#include "hssconnection.h"


HSSConnection::HSSConnection(const std::string& server) :
  _http(new HttpConnection(server,
                           false,
                           SASEvent::TX_HSS_BASE,
                           "connected_homesteads"))
{
}


HSSConnection::~HSSConnection()
{
  delete _http;
  _http = NULL;
}


/// Retrieve user's digest data as JSON object. Caller is responsible for deleting.
Json::Value* HSSConnection::get_digest_data(const std::string& private_user_identity,
                                            const std::string& public_user_identity,
                                            SAS::TrailId trail)
{
  std::string path = "/credentials/" +
                     Utils::url_escape(private_user_identity) + "/" +
                     Utils::url_escape(public_user_identity) +
                     "/digest";
  return get_object(path, trail);
}


/// Retrieve user's associated URIs as JSON object. Caller is responsible for deleting.
Json::Value* HSSConnection::get_associated_uris(const std::string& public_user_identity,
                                                SAS::TrailId trail)
{
  std::string path = "/associatedpublicbypublic/" +
                     Utils::url_escape(public_user_identity);
  Json::Value* root = get_object(path, trail);
  Json::Value* uris = NULL;
  if (root != NULL)
  {
    if (root->isObject())
    {
      uris = new Json::Value;
      *uris = root->get("public_ids", Json::Value::null);
      if (!uris->isArray())
      {
        Json::FastWriter writer;
        LOG_ERROR("Failed to find \"public_ids\" array in Homestead response:\n %s\n %s\n", path.c_str(), writer.write(*root).c_str());
        delete uris;
        uris = NULL;
      }
    }
    else
    {
      Json::FastWriter writer;
      LOG_ERROR("Homestead response is not JSON object:\n %s\n %s\n", path.c_str(), writer.write(*root).c_str());
    }
    delete root;
  }
  return uris;
}


/// Retrieve user's initial filter criteria as JSON object. Caller is responsible for deleting.
bool HSSConnection::get_user_ifc(const std::string& public_user_identity,
                                 std::string& xml_data,
                                 SAS::TrailId trail)
{
  std::string path = "/filtercriteria/" +
                     Utils::url_escape(public_user_identity);
  return _http->get(path, xml_data, "", trail);
}

/// Retrieve a JSON object from a path on the server. Caller is responsible for deleting.
Json::Value* HSSConnection::get_object(const std::string& path, SAS::TrailId trail)
{
  std::string json_data;
  Json::Value* root = NULL;

  if (_http->get(path, json_data, "", trail))
  {
    root = new Json::Value;
    Json::Reader reader;
    bool parsingSuccessful = reader.parse(json_data, *root);
    if (!parsingSuccessful)
    {
      // report to the user the failure and their locations in the document.
      LOG_ERROR("Failed to parse Homestead response:\n %s\n %s\n %s\n", path.c_str(), json_data.c_str(), reader.getFormatedErrorMessages().c_str());
      delete root;
      root = NULL;
    }
  }

  return root;
}
