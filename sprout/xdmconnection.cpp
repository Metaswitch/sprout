/**
 * @file xdmconnection.cpp HSSConnection class methods.
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

#include <curl/curl.h>
#include <iostream>
#include <fstream>

#include "utils.h"
#include "log.h"
#include "sas.h"
#include "sasevent.h"
#include "httpconnection.h"
#include "xdmconnection.h"

/// Main constructor.
XDMConnection::XDMConnection(const std::string& server) :
  _http(new HttpConnection(server,
                           true,
                           SASEvent::TX_XDM_GET_BASE,
                           "connected_homers"))
{
}

/// Constructor supplying own connection. For UT use. Ownership passes
/// to this object.
XDMConnection::XDMConnection(HttpConnection* http) :
  _http(http)
{
}

XDMConnection::~XDMConnection()
{
  delete _http;
  _http = NULL;
}

bool XDMConnection::get_simservs(const std::string& user,
                                 std::string& xml_data,
                                 const std::string& password,
                                 SAS::TrailId trail)
{
  return _http->get("/org.etsi.ngn.simservs/users/" + Utils::url_escape(user) + "/simservs.xml", xml_data, user, trail);
}

