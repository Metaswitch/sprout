/**
 * @file fakehssconnection.cpp Fake HSS Connection (for testing).
 *
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by post at
 * Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 */

///
///----------------------------------------------------------------------------

#include <cstdio>
#include "fakehssconnection.hpp"

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
    return &i->second;
  }
  return NULL;
}

void FakeHSSConnection::set_object(const std::string& url, Json::Value& object, SAS::TrailId trail)
{
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
