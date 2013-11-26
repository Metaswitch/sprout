/**
 * @file avstore.cpp Implementation of store for Authentication Vectors
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
#include "avstore.h"


AvStore::AvStore() :
  _av_map_lock(PTHREAD_MUTEX_INITIALIZER),
  _av_map()
{
}

AvStore::~AvStore()
{
}

void AvStore::set_av(const std::string& impi,
                     const std::string& nonce,
                     const Json::Value* av)
{
  std::string key = impi + '\0' + nonce;
  std::string data = av->toStyledString();
  LOG_DEBUG("Set AV for %s\n%s", key.c_str(), data.c_str());

  pthread_mutex_lock(&_av_map_lock);
  _av_map[key] = data;
  pthread_mutex_unlock(&_av_map_lock);
}

Json::Value* AvStore::get_av(const std::string& impi,
                             const std::string& nonce)
{
  Json::Value* av = NULL;
  std::string key = impi + '\0' + nonce;

  pthread_mutex_lock(&_av_map_lock);
  std::map<std::string, std::string>::const_iterator i = _av_map.find(key);
  if (i != _av_map.end())
  {
    LOG_DEBUG("Retrieved AV for %s\n%s", key.c_str(), i->second.c_str());
    av = new Json::Value;
    Json::Reader reader;
    bool parsingSuccessful = reader.parse(i->second, *av);
    if (!parsingSuccessful)
    {
      delete av;
      av = NULL;
    }
  }
  pthread_mutex_unlock(&_av_map_lock);

  return av;
}

