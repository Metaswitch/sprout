/**
 * @file memcachedstore.cpp Memcached-backed implementation of the registration data store.
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
///

#include "memcachedstore.h"

// Common STL includes.
#include <cassert>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <queue>
#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <time.h>

#include "memcachedstorefactory.h"
#include "log.h"

namespace RegData {

  /// Create a new store object, using the memcached implementation.
  ///
  /// For syntax of servers see
  /// http://docs.libmemcached.org/libmemcached_configuration.html#description,
  /// e.g., "localhost:11211".
  RegData::Store* create_memcached_store(const std::list<std::string>& servers,
                                         ///< list of servers to be used
                                         int connections)
                                         ///< size of pool (used as init and
                                         /// max)
  {
    return new MemcachedStore(servers, connections);
  }

  /// Destroy a store object which used the memcached implementation.
  void destroy_memcached_store(RegData::Store* store)
  {
    delete (RegData::MemcachedStore*)store;
  }

  /// Constructor: get a handle to the memcached connection pool of interest.
  ///
  /// For syntax of servers see
  /// http://docs.libmemcached.org/libmemcached_configuration.html#description,
  /// e.g., "localhost:11211".
  MemcachedStore::MemcachedStore(const std::list<std::string>& servers,
                                 ///< list of servers to be used
                                 int pool_size)
                                 ///< size of pool (used as init and max)
  {
    // Create the options string to connect to the servers.
    std::string options;
    for (std::list<std::string>::const_iterator i = servers.begin();
         i != servers.end();
         ++i)
    {
      options += "--SERVER=" + (*i) + " ";
    }
    options += "--BINARY-PROTOCOL";
    options += " --CONNECT-TIMEOUT=200";
    options += " --POOL-MIN=" + to_string<int>(pool_size, std::dec) + " --POOL-MAX=" + to_string<int>(pool_size, std::dec);

    _pool = memcached_pool(options.c_str(), options.length());
  }

  MemcachedStore::~MemcachedStore()
  {
    memcached_pool_destroy(_pool);
  }

  /// Wipe the contents of all the memcached servers immediately, if we can
  /// get a connection.  If not, does nothing.
  void MemcachedStore::flush_all()
  {
    memcached_return_t rc;

    // Try to get a connection
    struct timespec wait_time;
    wait_time.tv_sec = 0;
    wait_time.tv_nsec = 100 * 1000 * 1000;
    memcached_st* st = memcached_pool_fetch(_pool, &wait_time, &rc);

    if (st != NULL)
    {
      // Got one: use it to wipe out the contents of the servers immediately.
      rc = memcached_flush(st, 0);
      memcached_pool_release(_pool, st);
    }
  }

  // LCOV_EXCL_START - need real memcached to test

  /// Retrieve the AoR data for a given SIP URI, creating it if there isn't
  /// any already, and returning NULL if we can't get a connection.
  AoR* MemcachedStore::get_aor_data(const std::string& aor_id)
                                    ///< the SIP URI
  {
    memcached_return_t rc;
    MemcachedAoR* aor_data = NULL;

    // Try to get a connection
    struct timespec wait_time;
    wait_time.tv_sec = 0;
    wait_time.tv_nsec = 100 * 1000 * 1000;
    memcached_st* st = memcached_pool_fetch(_pool, &wait_time, &rc);

    if (st != NULL)
    {
      // Got one: use it.
      const char* key_ptr = aor_id.data();
      const size_t key_len = aor_id.length();
      rc = memcached_mget(st, &key_ptr, &key_len, 1);
      if (memcached_success(rc))
      {
        memcached_result_st result;
        memcached_result_create(st, &result);
        memcached_fetch_result(st, &result, &rc);

        if (memcached_success(rc))
        {
          aor_data = deserialize_aor(std::string(memcached_result_value(&result), memcached_result_length(&result)));
          aor_data->set_cas(memcached_result_cas(&result));
          memcached_result_free(&result);
          int now = time(NULL);
          expire_bindings(aor_data, now);
        }
        else
        {
          // AoR does not exist, so create it.
          aor_data = new MemcachedAoR();
        }
      }
      memcached_pool_release(_pool, st);
    }

    return (AoR*)aor_data;
  }

  /// Update the data for a particular address of record.  Writes the data
  /// atomically.  If the underlying data has changed since it was last
  /// read, the update is rejected and this returns false; if the update
  /// succeeds, this returns true.
  ///
  /// If a connection cannot be obtained, returns a random boolean based on
  /// data found on the call stack at the point of entry.
  bool MemcachedStore::set_aor_data(const std::string& aor_id,
                                    ///< the SIP URI
                                    AoR* data)
                                    ///< the data to store
  {
    memcached_return_t rc;
    MemcachedAoR* aor_data = (MemcachedAoR*)data;

    // Try to get a connection.
    struct timespec wait_time;
    wait_time.tv_sec = 0;
    wait_time.tv_nsec = 100 * 1000 * 1000;
    memcached_st* st = memcached_pool_fetch(_pool, &wait_time, &rc);

    if (st != NULL)
    {
      // Got one: use it.
      //
      // Expire any old bindings before writing to the server.  In theory,
      // if there are no bindings left we could delete the entry, but this
      // may cause concurrency problems because memcached does not support
      // cas on delete operations.  In this case we do a memcached_cas with
      // an effectively immediate expiry time.
      int now = time(NULL);
      int max_expires = expire_bindings(aor_data, now);
      std::string value = serialize_aor(aor_data);
      if (aor_data->get_cas() == 0)
      {
        // New record, so attempt to add.  This will fail if someone else
        // gets there first.
        rc = memcached_add(st, aor_id.data(), aor_id.length(), value.data(), value.length(), max_expires, 0);
      }
      else
      {
        // This is an update to an existing record, so use memcached_cas
        // to make sure it is atomic.
        rc = memcached_cas(st, aor_id.data(), aor_id.length(), value.data(), value.length(), max_expires, 0, aor_data->get_cas());
      }

      memcached_pool_release(_pool, st);
    }

    return memcached_success(rc);
  }

  // LCOV_EXCL_STOP

  /// Serialize the contents of an AoR.
  std::string MemcachedStore::serialize_aor(MemcachedAoR* aor_data)
  {
    std::ostringstream oss(std::ostringstream::out|std::ostringstream::binary);

    int num_bindings = aor_data->bindings().size();
    oss.write((const char *)&num_bindings, sizeof(int));

    for (AoR::Bindings::const_iterator i = aor_data->bindings().begin();
         i != aor_data->bindings().end();
         ++i)
    {
      oss << i->first << '\0';

      AoR::Binding* b = i->second;
      oss << b->_uri << '\0';
      oss << b->_cid << '\0';
      oss.write((const char *)&b->_cseq, sizeof(int));
      oss.write((const char *)&b->_expires, sizeof(int));
      oss.write((const char *)&b->_priority, sizeof(int));
      int num_params = b->_params.size();
      oss.write((const char *)&num_params, sizeof(int));
      for (std::list<std::pair<std::string, std::string> >::const_iterator i = b->_params.begin();
           i != b->_params.end();
           ++i)
      {
        oss << i->first << '\0' << i->second << '\0';
      }
      int num_path_hdrs = b->_path_headers.size();
      oss.write((const char *)&num_path_hdrs, sizeof(int));
      for (std::list<std::string>::const_iterator i = b->_path_headers.begin();
           i != b->_path_headers.end();
           ++i)
      {
        oss << *i << '\0';
      }
    }

    return oss.str();
  }

  /// Deserialize the contents of an AoR
  MemcachedAoR* MemcachedStore::deserialize_aor(const std::string& s)
  {
    std::istringstream iss(s, std::istringstream::in|std::istringstream::binary);

    MemcachedAoR* aor_data = new MemcachedAoR();
    int num_bindings;
    iss.read((char *)&num_bindings, sizeof(int));
    LOG_DEBUG("There are %d bindings", num_bindings);

    for (int ii = 0; ii < num_bindings; ++ii)
    {
      // Extract the binding identifier into a string.
      std::string binding_id;
      getline(iss, binding_id, '\0');

      AoR::Binding* b = aor_data->get_binding(binding_id);

      // Now extract the various fixed binding parameters.
      getline(iss, b->_uri, '\0');
      getline(iss, b->_cid, '\0');
      iss.read((char *)&b->_cseq, sizeof(int));
      iss.read((char *)&b->_expires, sizeof(int));
      iss.read((char *)&b->_priority, sizeof(int));

      int num_params;
      iss.read((char *)&num_params, sizeof(int));
      LOG_DEBUG("Binding has %d params", num_params);
      b->_params.resize(num_params);
      for (std::list<std::pair<std::string, std::string> >::iterator i = b->_params.begin();
           i != b->_params.end();
           ++i)
      {
        getline(iss, i->first, '\0');
        getline(iss, i->second, '\0');
        LOG_DEBUG("Read param %s = %s", i->first.c_str(), i->second.c_str());
      }

      int num_paths = 0;
      iss.read((char *)&num_paths, sizeof(int));
      b->_path_headers.resize(num_paths);
      LOG_DEBUG("Binding has %d paths", num_paths);
      for (std::list<std::string>::iterator i = b->_path_headers.begin();
           i != b->_path_headers.end();
           ++i)
      {
        getline(iss, *i, '\0');
        LOG_DEBUG("Read path %s", i->c_str());
      }
    }

    return aor_data;
  }
} // namespace RegData

