/**
 * @file fakehssconnection.cpp Fake HSS Connection (for testing).
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
///----------------------------------------------------------------------------

#include <cstdio>
#include "fakehssconnection.hpp"
#include "ifchandler.h"
#include <json/reader.h>
#include "gtest/gtest.h"

using namespace std;

FakeHSSConnection::FakeHSSConnection() : HSSConnection("localhost")
{
}

FakeHSSConnection::~FakeHSSConnection()
{
  flush_all();
}

void FakeHSSConnection::flush_all()
{
  _json_db.clear();
  _ifc_db.clear();
}

Json::Value* FakeHSSConnection::get_object(const std::string& url, SAS::TrailId trail)
{
  std::map<std::string, Json::Value>::iterator i = _json_db.find(url);
  if (i != _json_db.end())
  {
    return new Json::Value(i->second);
  }
  return NULL;
}

void FakeHSSConnection::set_object(const std::string& url, Json::Value& object, SAS::TrailId trail)
{
  _json_db[url] = object;
}

void FakeHSSConnection::set_json(const std::string& url, const std::string& json)
{
  Json::Value object;
  Json::Reader reader;
  bool json_parse_success = reader.parse(json, object);
  ASSERT_TRUE(json_parse_success);
  _json_db[url] = object;
}

bool FakeHSSConnection::get_user_ifc(const std::string& public_user_identity,
                                     std::string& xml_data,
                                     SAS::TrailId trail)
{
  std::map<std::string, std::string>::iterator i = _ifc_db.find(public_user_identity);
  if (i != _ifc_db.end())
  {
    xml_data = i->second;
    return true;
  }
  return false;
}

void FakeHSSConnection::set_user_ifc(const std::string& public_user_identity,
                                     const std::string& xml_data)
{
  _ifc_db[public_user_identity] = xml_data;
}

void FakeHSSConnection::get_subscription_data(const std::string& public_user_identity,
const std::string& private_user_identity,
					      std::vector<std::string>* uris,
					      std::map<std::string, Ifcs>* ifcs_map,
					      SAS::TrailId trail) {
  std::map<std::string, std::string>::iterator i = _ifc_db.find(public_user_identity);
  if (i != _ifc_db.end())
  {
    //xml_data = i->second;
    uris->push_back(public_user_identity);
    Ifcs ifcs;
    (*ifcs_map)[public_user_identity] = ifcs;
  }
}
