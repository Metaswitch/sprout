/**
 * @file memcachedstoreupdater.cpp
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

#include <unistd.h>
#include <signal.h>
#include <errno.h>

// Common STL includes.
#include <cassert>
#include <vector>
#include <list>
#include <string>
#include <iostream>
#include <fstream>

#include "log.h"
#include "utils.h"
#include "memcachedstore.h"
#include "memcachedstoreupdater.h"


MemcachedStoreUpdater::MemcachedStoreUpdater(RegData::Store* store,
                                             std::string file) :
  _store((RegData::MemcachedStore*)store),
  _file(file)
{
  LOG_DEBUG("Created updater for store %p using file %s", _store, _file.c_str());

  // Do initial configuration of the store.
  update_view();

  // Create the thread to handle further changes of view.
  int rc = pthread_create(&_updater, NULL, &updater_thread, this);

  if (rc < 0)
  {
    // LCOV_EXCL_START
    LOG_ERROR("Error creating memcached store updater thread");
    // LCOV_EXCL_STOP
  }
}

MemcachedStoreUpdater::~MemcachedStoreUpdater()
{
}


void MemcachedStoreUpdater::update_view()
{
  // Read the memstore file.
  std::ifstream f(_file);
  std::list<std::string> servers;
  std::vector<std::vector<std::string> > vbuckets;

  if (f.is_open())
  {
    LOG_STATUS("Reloading memcached configuration from %s file", _file.c_str());
    while (f.good())
    {
      std::string line;
      getline(f, line);

      if (line.length() > 0)
      {
        // Read a non-blank line.
        std::vector<std::string> tokens;
        Utils::split_string(line, '=', tokens, 0, true);
        if (tokens.size() != 2)
        {
          LOG_ERROR("Malformed %s file", _file.c_str());
          break;
        }

        LOG_STATUS("  %s=%s", tokens[0].c_str(), tokens[1].c_str());

        if (tokens[0] == "servers")
        {
          // Found line defining servers.
          Utils::split_string(tokens[1], ',', servers, 0, true);
        }
        else if (tokens[0] == "vbuckets")
        {
          // Found the a vbucket map.
          vbuckets.push_back(std::vector<std::string>());
          Utils::split_string(tokens[1], ',', vbuckets[vbuckets.size() - 1], 0, true);
        }
      }
    }
    f.close();

    if (servers.size() > 0)
    {
      LOG_DEBUG("Update memcached store");
      _store->new_view(servers, vbuckets);
    }
  }
  else
  {
    LOG_ERROR("Failed to open %s file", _file.c_str());
  }
}


void* MemcachedStoreUpdater::updater_thread(void* p)
{
  ((MemcachedStoreUpdater*)p)->updater();
  return NULL;
}


void MemcachedStoreUpdater::updater()
{
  LOG_DEBUG("Started updater thread for memstore %p", _store);

  sigset_t sset;
  sigemptyset(&sset);
  sigaddset(&sset, SIGHUP);

  while (true)
  {
    int sig;
    sigwait(&sset, &sig);

    LOG_DEBUG("Received SIGHUP signal");

    update_view();
  }
}






