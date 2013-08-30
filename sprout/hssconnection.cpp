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

#include <cassert>
#include <string>
#include <memory>
#include <map>
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
  std::string path = "/impi/" +
                     Utils::url_escape(private_user_identity) + 
                     "/digest";

  if (!public_user_identity.empty())
    {
      path += "?public_id=" + Utils::url_escape(public_user_identity);
    }
  return get_json_object(path, trail);
}


/// Retrieve a JSON object from a path on the server. Caller is responsible for deleting.
Json::Value* HSSConnection::get_json_object(const std::string& path,
                                            SAS::TrailId trail)
{
  std::string json_data;
  Json::Value* root = NULL;

  if (_http->get(path, json_data, "", trail) == 200)
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


/// Retrieve an XML object from a path on the server. Caller is responsible for deleting.
long HSSConnection::get_xml_object(const std::string& path,
                                   rapidxml::xml_document<>*& root,
                                   SAS::TrailId trail)
{
  std::string raw_data;

  long http_code = _http->get(path, raw_data, "", trail);

  if (http_code == 200)
  {
    root = new rapidxml::xml_document<>;
    try
    {
      root->parse<0>(root->allocate_string(raw_data.c_str()));
    }
    catch (rapidxml::parse_error& err)
    {
      // report to the user the failure and their locations in the document.
      LOG_ERROR("Failed to parse Homestead response:\n %s\n %s\n %s\n", path.c_str(), raw_data.c_str(), err.what());
      delete root;
      root = NULL;
    }
  }

  return http_code;
}


/// Retrieve user's subscription data from the HSS, filling in the associated
//  URIs in the associated_uris output parameter and the Ifcs object
//  corresponding to each in the ifcs_map parameter.

//  If we retrieve a valid document, we should always be able to
//  populate associated_uris with at least one item. Callers should
//  check whether associated_uris has been populated - if not, then we
//  have either not found the subscriber, failed to communicate with
//  the HSS, or received a document we cannot parse.

long HSSConnection::get_subscription_data(const std::string& public_user_identity,
                                          const std::string& private_user_identity,
                                          std::map<std::string, Ifcs >& ifcs_map,
                                          std::vector<std::string>& associated_uris,
                                          SAS::TrailId trail)
{
  if (public_user_identity.empty())
  {
    LOG_ERROR("Attempted to get data from the HSS without providing a public ID!");
    return 400;
  }

  std::string path = "/impu/" +
                     Utils::url_escape(public_user_identity);

  // Needs to be a shared pointer - multiple Ifcs objects will need a reference
  // to it, so we want to delete the underlying document when they all go out
  // of scope.

  rapidxml::xml_document<>* root_underlying_ptr = NULL;
  long http_code = get_xml_object(path, root_underlying_ptr, trail);
  std::shared_ptr<rapidxml::xml_document<> > root (root_underlying_ptr);
  rapidxml::xml_node<>* sp = NULL;

  if (http_code != 200) {
    // If get_xml_object has returned a HTTP error code, we have either not found
    // the subscriber on the HSS or been unable to communicate with
    // the HSS successfully. In either case we should fail.
    LOG_ERROR("Could not get subscriber data from HSS");
    return http_code;
  }

  if (!root.get())
  {
    // If get_xml_object has not returned a document, there must have been a parsing error.
    LOG_ERROR("Malformed HSS XML - document couldn't be parsed"); 
    return 500;
  }

  rapidxml::xml_node<>* imss = root->first_node("IMSSubscription");

  if (!imss)
  {
    LOG_ERROR("Malformed HSS XML - no IMSSubscription element"); 
    return 500;
  }

  for (sp = imss->first_node("ServiceProfile"); sp != NULL; sp = sp->next_sibling("ServiceProfile"))
  {
    Ifcs ifc(root, sp);
    rapidxml::xml_node<>* public_id = NULL;

    for (public_id = sp->first_node("PublicIdentity"); public_id != NULL; public_id = public_id->next_sibling("PublicIdentity"))
    {

      rapidxml::xml_node<>* identity = public_id->first_node("Identity");
      if (identity)
      {
        std::string uri = std::string(identity->value());
        LOG_DEBUG("Processing Identity node from HSS XML - %s\n", uri.c_str());
        
        associated_uris.push_back(uri);
        ifcs_map[uri] = ifc;
      }
    }
  }
  return 200;
}


