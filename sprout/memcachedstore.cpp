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

#include "log.h"
#include "utils.h"
#include "memcachedstoreupdater.h"
#include "memcachedstoreview.h"
#include "memcachedstore.h"


/// MemcachedStore constructor
///
/// @param binary       Set to true to use binary memcached protocol, false to
///                     use ASCII protocol.
/// @param config_file  File name (including directory path) of the configuration
///                     file.
MemcachedStore::MemcachedStore(bool binary,
                               const std::string& config_file) :
  _updater(NULL),
  _replicas(2),
  _vbuckets(128),
  _options(),
  _view_number(0),
  _servers(),
  _read_replicas(_vbuckets),
  _write_replicas(_vbuckets)
{
  // Create the thread local key for the per thread data.
  pthread_key_create(&_thread_local, MemcachedStore::cleanup_connection);

  // Create the lock for protecting the current view.
  pthread_rwlock_init(&_view_lock, NULL);

  // Set up the fixed options for memcached.  We use a very short connect
  // timeout because libmemcached tries to connect to all servers sequentially
  // during start-up, and if any are not up we don't want to wait for any
  // significant length of time.
  _options = "--CONNECT-TIMEOUT=10 --SUPPORT-CAS";
  _options += (binary) ? " --BINARY_PROTOCOL" : "";

  if (config_file != "")
  {
// LCOV_EXCL_START
    // Create an updater to keep the store configured appropriately.
    _updater = new MemcachedStoreUpdater(this, config_file);
// LCOV_EXCL_STOP
  }
}


MemcachedStore::~MemcachedStore()
{
  // Destroy the updater (if it was created).
  delete _updater;

  // Clean up this thread's connection now, rather than waiting for
  // pthread_exit.  This is to support use by single-threaded code
  // (e.g., UTs), where pthread_exit is never called.
  connection* conn = (connection*)pthread_getspecific(_thread_local);
  if (conn != NULL)
  {
    pthread_setspecific(_thread_local, NULL);
    cleanup_connection(conn);
  }

  pthread_rwlock_destroy(&_view_lock);
}


// LCOV_EXCL_START - need real memcached to test


/// Set up a new view of the memcached cluster(s).  The view determines
/// how data is distributed around the cluster.
void MemcachedStore::new_view(const std::vector<std::string>& servers,
                              const std::vector<std::string>& new_servers)
{
  LOG_STATUS("Updating memcached store configuration");

  // Create a new view with the new server lists.
  MemcachedStoreView view(_vbuckets, _replicas);
  view.update(servers, new_servers);

  // Now copy the view so it can be accessed by the worker threads.
  pthread_rwlock_wrlock(&_view_lock);

  // Get the list of servers from the view.
  _servers = view.servers();

  // For each vbucket, get the list of read replicas and write replicas.
  for (int ii = 0; ii < _vbuckets; ++ii)
  {
    _read_replicas[ii] = view.read_replicas(ii);
    _write_replicas[ii] = view.write_replicas(ii);
  }

  // Update the view number as the last thing here, otherwise we could stall
  // other threads waiting for the lock.
  LOG_STATUS("Finished preparing new view, so flag that workers should switch to it");
  ++_view_number;

  pthread_rwlock_unlock(&_view_lock);
}


/// Gets the set of replicas to use for a read or write operation for the
/// specified key.
const std::vector<memcached_st*>& MemcachedStore::get_replicas(const std::string& key,
                                                               Op operation)
{
  MemcachedStore::connection* conn = (connection*)pthread_getspecific(_thread_local);
  if (conn == NULL)
  {
    // Create a new connection structure for this thread.
    conn = new MemcachedStore::connection;
    pthread_setspecific(_thread_local, conn);
    conn->view_number = 0;
  }

  if (conn->view_number != _view_number)
  {
    // Either the view has changed or has not yet been set up, so set up the
    // connection and replica structures for this thread.
    for (size_t ii = 0; ii < conn->st.size(); ++ii)
    {
      memcached_free(conn->st[ii]);
      conn->st[ii] = NULL;
    }
    pthread_rwlock_rdlock(&_view_lock);

    LOG_DEBUG("Set up new view %d for thread", _view_number);

    // Create a set of memcached_st's one per server.
    conn->st.resize(_servers.size());

    for (size_t ii = 0; ii < _servers.size(); ++ii)
    {
      // Create a new memcached_st for this server.
      std::string options = _options + " --SERVER=" + _servers[ii];
      LOG_DEBUG("Setting up server %d for connection %p (%s)", ii, conn, options.c_str());
      conn->st[ii] = memcached(options.c_str(), options.length());
      LOG_DEBUG("Set up connection %p to server %s", conn->st[ii], _servers[ii].c_str());

      // Switch to a longer connect timeout from here on.
      memcached_behavior_set(conn->st[ii], MEMCACHED_BEHAVIOR_CONNECT_TIMEOUT, 50);
    }

    conn->read_replicas.resize(_vbuckets);
    conn->write_replicas.resize(_vbuckets);

    // Now set up the read and write replica sets.
    for (int ii = 0; ii < _vbuckets; ++ii)
    {
      conn->read_replicas[ii].resize(_read_replicas[ii].size());
      for (size_t jj = 0; jj < _read_replicas[ii].size(); ++jj)
      {
        conn->read_replicas[ii][jj] = conn->st[_read_replicas[ii][jj]];
      }
      conn->write_replicas[ii].resize(_write_replicas[ii].size());
      for (size_t jj = 0; jj < _write_replicas[ii].size(); ++jj)
      {
        conn->write_replicas[ii][jj] = conn->st[_write_replicas[ii][jj]];
      }
    }

    // Flag that we are in sync with the latest view.
    conn->view_number = _view_number;

    pthread_rwlock_unlock(&_view_lock);
  }

  // Hash the key and convert the hash to a vbucket.
  int hash = memcached_generate_hash_value(key.data(), key.length(), MEMCACHED_HASH_MD5);
  int vbucket = hash & (_vbuckets - 1);
  LOG_DEBUG("Key %s hashes to vbucket %d via hash 0x%x", key.c_str(), vbucket, hash);

  return (operation == Op::READ) ? conn->read_replicas[vbucket] : conn->write_replicas[vbucket];
}


/// Called to clean up the thread local data for a thread using the MemcachedStore class.
void MemcachedStore::cleanup_connection(void* p)
{
  MemcachedStore::connection* conn = (MemcachedStore::connection*)p;

  for (size_t ii = 0; ii < conn->st.size(); ++ii)
  {
    memcached_free(conn->st[ii]);
  }

  delete conn;
}


/// Retrieve the data for a given namespace and key.
Store::Status MemcachedStore::get_data(const std::string& table,
                                       const std::string& key,
                                       std::string& data,
                                       uint64_t& cas)
{
  Store::Status status = Store::Status::OK;


  // Construct the fully qualified key.
  std::string fqkey = table + "\\" + key;
  const char* key_ptr = fqkey.data();
  const size_t key_len = fqkey.length();

  const std::vector<memcached_st*>& replicas = get_replicas(fqkey, Op::READ);
  LOG_DEBUG("%d read replicas for key %s", replicas.size(), fqkey.c_str());

  // Read from all replicas until we get a positive result.
  memcached_return_t rc = MEMCACHED_ERROR;
  memcached_result_st result;
  bool active_not_found = false;
  size_t failed_replicas = 0;
  size_t ii;
  for (ii = 0; ii < replicas.size(); ++ii)
  {
    // We must use memcached_mget because memcached_get does not retrieve CAS
    // values.
    LOG_DEBUG("Attempt to read from replica %d (connection %p)", ii, replicas[ii]);
    rc = memcached_mget(replicas[ii], &key_ptr, &key_len, 1);

    if (memcached_success(rc))
    {
      // memcached_mget command was successful, so retrieve the result.
      LOG_DEBUG("Fetch result");
      memcached_result_create(replicas[ii], &result);
      memcached_fetch_result(replicas[ii], &result, &rc);

      if (memcached_success(rc))
      {
        // Found a record, so exit the read loop.
        LOG_DEBUG("Found record on replica %d", ii);
        break;
      }
      else
      {
        // Free the result.
        memcached_result_free(&result);
      }
    }

    if (rc == MEMCACHED_NOTFOUND)
    {
      // Failed to find a record on an active replica.  Flag this so if we do
      // find data on a later replica we can reset the cas value returned to
      // zero to ensure a subsequent write will succeed.
      LOG_DEBUG("Read for %s on replica %d returned NOTFOUND", fqkey.c_str(), ii);
      active_not_found = true;
    }
    else
    {
      // Error from this node, so consider it inactive.
      LOG_DEBUG("Read for %s on replica %d returned error %d (%s)",
                fqkey.c_str(), ii, rc, memcached_strerror(replicas[ii], rc));
      ++failed_replicas;
    }
  }

  if (memcached_success(rc))
  {
    // Return the data and CAS value.  The CAS value is either set to the CAS
    // value from the result, or zero if an earlier active replica returned
    // NOT_FOUND.  This ensures that a subsequent set operation will succeed
    // on the earlier active replica.
    data.assign(memcached_result_value(&result), memcached_result_length(&result));
    cas = (active_not_found) ? 0 : memcached_result_cas(&result);

    // Free the result.
    memcached_result_free(&result);
  }
  else if (failed_replicas < replicas.size())
  {
    // At least one replica returned NOT_FOUND.
    LOG_DEBUG("At least one replica returned not found, so return NOT_FOUND");
    status = Store::Status::NOT_FOUND;
  }
  else
  {
    // All replicas returned an error, so log the error and return the failure.
    LOG_ERROR("Failed to read AoR data for %s from %d replicas",
              fqkey.c_str(), replicas.size());
    status = Store::Status::ERROR;
  }

  return status;
}


/// Update the data for the specified namespace and key.  Writes the data
/// atomically, so if the underlying data has changed since it was last
/// read, the update is rejected and this returns Store::Status::CONTENTION.
Store::Status MemcachedStore::set_data(const std::string& table,
                                       const std::string& key,
                                       const std::string& data,
                                       uint64_t cas,
                                       int expiry)
{
  Store::Status status = Store::Status::OK;

  // Construct the fully qualified key.
  std::string fqkey = table + "\\" + key;
  const char* key_ptr = fqkey.data();
  const size_t key_len = fqkey.length();

  const std::vector<memcached_st*>& replicas = get_replicas(fqkey, Op::WRITE);
  LOG_DEBUG("%d write replicas for key %s", replicas.size(), fqkey.c_str());

  int now = time(NULL);
  expiry += now;

  // First try to write the primary data record to the first responding
  // server.
  memcached_return_t rc = MEMCACHED_ERROR;
  size_t ii;
  for (ii = 0; ii < replicas.size(); ++ii)
  {
    LOG_DEBUG("Attempt conditional write to replica %d (connection %p), CAS = %ld",
              ii,
              replicas[ii],
              cas);

    if (cas == 0)
    {
      // New record, so attempt to add.  This will fail if someone else
      // gets there first.
      rc = memcached_add(replicas[ii],
                         key_ptr,
                         key_len,
                         data.data(),
                         data.length(),
                         expiry,
                         (uint32_t)expiry);
    }
    else
    {
      // This is an update to an existing record, so use memcached_cas
      // to make sure it is atomic.
      rc = memcached_cas(replicas[ii],
                         key_ptr,
                         key_len,
                         data.data(),
                         data.length(),
                         expiry,
                         (uint32_t)expiry,
                         cas);
    }

    if (memcached_success(rc))
    {
      LOG_DEBUG("Conditional write succeeded to replica %d", ii);
      break;
    }
    else
    {
      LOG_DEBUG("memcached_%s command for %s failed on replica %d, rc = %d (%s), expiry = %d",
                (cas == 0) ? "add" : "cas",
                fqkey.c_str(),
                ii,
                rc,
                memcached_strerror(replicas[ii], rc),
                expiry - now);

      if ((rc == MEMCACHED_NOTSTORED) ||
          (rc == MEMCACHED_DATA_EXISTS))
      {
        // A NOT_STORED or EXISTS response indicates a concurrent write failure,
        // so return this to the application immediately - don't go on to
        // other replicas.
        LOG_INFO("Contention writing data for %s to store", fqkey.c_str());
        status = Store::Status::DATA_CONTENTION;
        break;
      }
    }
  }

  if ((rc == MEMCACHED_SUCCESS) &&
      (ii < replicas.size()))
  {
    // Write has succeeded, so write unconditionally (and asynchronously)
    // to the replicas.
    for (size_t jj = ii + 1; jj < replicas.size(); ++jj)
    {
      LOG_DEBUG("Attempt unconditional write to replica %d", jj);
      memcached_behavior_set(replicas[jj], MEMCACHED_BEHAVIOR_NOREPLY, 1);
      memcached_set(replicas[jj],
                    key_ptr,
                    key_len,
                    data.data(),
                    data.length(),
                    expiry,
                    0);
      memcached_behavior_set(replicas[jj], MEMCACHED_BEHAVIOR_NOREPLY, 0);
    }
  }

  if ((!memcached_success(rc)) &&
      (rc != MEMCACHED_NOTSTORED) &&
      (rc != MEMCACHED_DATA_EXISTS))
  {
    LOG_ERROR("Failed to write data for %s to %d replicas",
              fqkey.c_str(), replicas.size());
    status = Store::Status::ERROR;
  }

  return status;
}

// LCOV_EXCL_STOP

