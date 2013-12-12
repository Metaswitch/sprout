/**
 * @file localstore.cpp Local memory implementation of the Sprout data store.
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

// Common STL includes.
#include <cassert>
#include <map>
#include <list>
#include <string>

#include <time.h>
#include <stdint.h>

#include "log.h"
#include "localstore.h"


LocalStore::LocalStore() :
  _db_lock(PTHREAD_MUTEX_INITIALIZER),
  _db()
{
  LOG_DEBUG("Created local store");
}


LocalStore::~LocalStore()
{
  flush_all();
  pthread_mutex_destroy(&_db_lock);
}


void LocalStore::flush_all()
{
  pthread_mutex_lock(&_db_lock);
  LOG_DEBUG("Flushing local store");
  _db.clear();
  pthread_mutex_unlock(&_db_lock);
}


Store::Status LocalStore::get_data(const std::string& table,
                                   const std::string& key,
                                   std::string& data,
                                   uint64_t& cas)
{
  LOG_DEBUG("get_data table=%s key=%s", table.c_str(), key.c_str());

  Store::Status status = Store::Status::NOT_FOUND;

  // Calculate the fully qualified key.
  std::string fqkey = table + "\\\\" + key;

  pthread_mutex_lock(&_db_lock);

  uint32_t now = time(NULL);

  LOG_DEBUG("Search store for key %s", fqkey.c_str());

  std::map<std::string, Record>::iterator i = _db.find(fqkey);
  if (i != _db.end())
  {
    // Found an existing record, so check the expiry.
    Record& r = i->second;
    LOG_DEBUG("Found record, expiry = %ld (now = %ld)", r.expiry, now);
    if (r.expiry < now)
    {
      // Record has expired, so remove it from the map and return not found.
      LOG_DEBUG("Record has expired, remove it from store");
      _db.erase(i);
    }
    else
    {
      // Record has not expired, so return the data and the cas value.
      LOG_DEBUG("Record has not expires, return %d bytes of data with CAS = %ld",
                r.data.length(), r.cas);
      data = r.data;
      cas = r.cas;
      status = Store::Status::OK;
    }
  }

  pthread_mutex_unlock(&_db_lock);

  LOG_DEBUG("get_data status = %d", status);

  return status;
}


Store::Status LocalStore::set_data(const std::string& table,
                                   const std::string& key,
                                   const std::string& data,
                                   uint64_t cas,
                                   int expiry)
{
  LOG_DEBUG("set_data table=%s key=%s CAS=%ld expiry=%ld",
            table.c_str(), key.c_str(), cas, expiry);

  Store::Status status = Store::Status::DATA_CONTENTION;

  // Calculate the fully qualified key.
  std::string fqkey = table + "\\\\" + key;

  pthread_mutex_lock(&_db_lock);

  uint32_t now = time(NULL);

  LOG_DEBUG("Search store for key %s", fqkey.c_str());

  std::map<std::string, Record>::iterator i = _db.find(fqkey);

  if (i != _db.end())
  {
    // Found an existing record, so check the expiry and CAS value.
    Record& r = i->second;
    LOG_DEBUG("Found existing record, CAS = %ld, expiry = %ld (now = %ld)",
              r.cas, r.expiry, now);

    if (((r.expiry >= now) && (cas == r.cas)) ||
        ((r.expiry < now) && (cas == 0)))
    {
      // Supplied CAS is consistent (either because record hasn't expired and
      // CAS matches, or record has expired and CAS is zero) so update the
      // record.
      LOG_DEBUG("CAS is consistent, update record");
      r.data = data;
      r.cas = ++cas;
      r.expiry = (uint32_t)expiry + now;
      status = Store::Status::OK;
    }
  }
  else if (cas == 0)
  {
    // No existing record and supplied CAS is zero, so add a new record.
    LOG_DEBUG("No existing record so insert");
    Record& r = _db[fqkey];
    r.data = data;
    r.cas = 1;
    r.expiry = expiry + now;
    status = Store::Status::OK;
  }

  pthread_mutex_unlock(&_db_lock);

  return status;
}


