/**
 * @file fakehttpconnection.cpp Fake HTTP connection (for testing).
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


#include <cstdio>
#include "fakehttpconnection.hpp"

using namespace std;

FakeHttpConnection::FakeHttpConnection() :
  HttpConnection("localhost", true, 0, "connected_homesteads")  // dummy values
{
}

FakeHttpConnection::~FakeHttpConnection()
{
  flush_all();
}

void FakeHttpConnection::flush_all()
{
  _db.clear();
}

bool FakeHttpConnection::get(const std::string& uri, std::string& doc, const std::string& username, SAS::TrailId trail)
{
  std::map<std::string, std::string>::iterator i = _db.find(uri);
  if (i != _db.end())
  {
    doc = i->second;
    return true;
  }
  return false;
}

bool FakeHttpConnection::put(const std::string& uri, const std::string& doc, const std::string& username, SAS::TrailId trail)
{
  _db[uri] = doc;
  return true;
}

bool FakeHttpConnection::del(const std::string& uri, const std::string& username, SAS::TrailId trail)
{
  _db.erase(uri);
  return true;
}
