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

#include <cstdio>
#include "fakechronosconnection.hpp"
#include "gtest/gtest.h"
#include "sas.h"

FakeChronosConnection::FakeChronosConnection() : ChronosConnection("localhost", "localhost:9888", NULL, NULL)
{
}

FakeChronosConnection::~FakeChronosConnection()
{
  flush_all();
}


void FakeChronosConnection::flush_all()
{
  _results.clear();
}


void FakeChronosConnection::set_result(const std::string& url,
                                       const HTTPCode& result)
{
  _results[url] = result;
}


void FakeChronosConnection::delete_result(const std::string& url)
{
  _results.erase(url);
}

HTTPCode FakeChronosConnection::send_delete(const std::string& delete_identity,
                                            SAS::TrailId trail)
{
  return get_result(delete_identity);
}

HTTPCode FakeChronosConnection::send_post(std::string& post_identity,
                                          uint32_t timer_interval,
                                          const std::string& callback_uri,
                                          const std::string& opaque_data,
                                          SAS::TrailId trail,
                                          const std::map<std::string, uint32_t>& tags)
{
  HTTPCode status = get_result(post_identity);

  post_identity = "post_identity";
  return status;
}

HTTPCode FakeChronosConnection::send_put(std::string& put_identity,
                                         uint32_t timer_interval,
                                         const std::string& callback_uri,
                                         const std::string& opaque_data,
                                         SAS::TrailId trail,
                                         const std::map<std::string, uint32_t>& tags)
{
  HTTPCode status = get_result(put_identity);

  put_identity = "put_identity";
  return status;
}

HTTPCode FakeChronosConnection::get_result(std::string identity)
{
  std::map<std::string, HTTPCode>::const_iterator i = _results.find(identity);

  if (i != _results.end())
  {
    return i->second;
  }
  else
  {
    TRC_DEBUG("Failed to find Chronos result for %s", identity.c_str());
    return HTTP_BAD_REQUEST;
  }
}
