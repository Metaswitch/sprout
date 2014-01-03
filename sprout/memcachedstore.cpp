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
#include "memcachedstorefactory.h"
#include "updater.h"
#include "memcachedstoreview.h"
#include "memcachedstore.h"

namespace RegData {


/// Create a new store object, using the memcached implementation.
RegData::Store* create_memcached_store(bool binary,                    ///< use binary protocol?
                                       const std::string& config_file) ///< configuration file for cluster settings
{
  return new MemcachedStore(binary, config_file);
}

/// Destroy a store object which used the memcached implementation.
void destroy_memcached_store(RegData::Store* store)
{
  delete (RegData::MemcachedStore*)store;
}

MemcachedStore::MemcachedStore(bool binary,                      ///< use binary protocol?
                               const std::string& config_file) : ///< configuration file for cluster settings
  _config_file(config_file),
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

  // Create an updater to keep the store configured appropriately.
  _updater = new Updater<void, MemcachedStore>(this, std::mem_fun(&MemcachedStore::update_view));
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
      // Create a new memcached_st for this server.  Do not specify the server
      // at this point as memcached() does not support IPv6 addresses.
      LOG_DEBUG("Setting up server %d for connection %p (%s)", ii, conn, _options.c_str());
      conn->st[ii] = memcached(_options.c_str(), _options.length());
      LOG_DEBUG("Set up connection %p to server %s", conn->st[ii], _servers[ii].c_str());

      // Switch to a longer connect timeout from here on.
      memcached_behavior_set(conn->st[ii], MEMCACHED_BEHAVIOR_CONNECT_TIMEOUT, 50);

      // Connect to the server.  The address is specified as either <IPv4 address>:<port>
      // or [<IPv6 address>]:<port>.  Look for square brackets to determine whether
      // this is an IPv6 address.
      std::vector<std::string> contact_details;
      size_t close_bracket = server_contact.find(']');

      if (close_bracket == string::npos)
      {
        // IPv4 connection.  Split the string on the colon.
        Utils::split_string(_servers[ii], ':', contact_details);
        if (contact_details.size() != 2)
        {
          LOG_ERROR("Malformed contact details %s", _servers[ii].c_str());
          break;
        }
      }
      else
      {
        // IPv6 connection.  Split the string on ']', which removes any white
        // space from the start and the end, then remove the '[' from the
        // start of the IP addreess string and the start of the ';' from the start
        // of the port string.
        Utils::split_string(_servers[ii], ']', contact_details);
        if ((contact_details.size() != 2) ||
            (contact_details[0].c_str()[0] != '[') ||
            (contact_details[1].c_str()[0] != ':'))
        {
          LOG_ERROR("Malformed contact details %s", _servers[ii].c_str());
          break;
        }

        contact_details[0].erase(contact_details[0].begin());
        contact_details[0].erase(contact_details[1].begin());
      }

      LOG_DEBUG("Setting server to IP address %s port %s",
                contact_details[0].c_str(),
                contact_details[1].c_str());
      int port = atoi(contact_details[1].c_str());
      memcached_server_add(conn->st[ii], contact_details[0].c_str(),
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


/// Not supported for MemcachedStore.
void MemcachedStore::flush_all()
{
}


/// Retrieve the AoR data for a given SIP URI, creating it if there isn't
/// any already.
AoR* MemcachedStore::get_aor_data(const std::string& aor_id)
                                  ///< the SIP URI
{
  memcached_return_t rc = MEMCACHED_ERROR;
  MemcachedAoR* aor_data = NULL;
  memcached_result_st result;
  std::vector<bool> read_repair(_replicas);
  size_t failed_replicas = 0;
  const char* key_ptr = aor_id.data();
  const size_t key_len = aor_id.length();

  const std::vector<memcached_st*>& replicas = get_replicas(aor_id, Op::READ);
  LOG_DEBUG("%d read replicas for key %s", replicas.size(), aor_id.c_str());

  // Read from all replicas until we get a positive result.
  size_t ii;
  for (ii = 0; ii < replicas.size(); ++ii)
  {
    LOG_DEBUG("Attempt to read from replica %d (connection %p)", ii, replicas[ii]);
    rc = memcached_mget(replicas[ii], &key_ptr, &key_len, 1);

    if (memcached_success(rc))
    {
      memcached_result_create(replicas[ii], &result);
      memcached_fetch_result(replicas[ii], &result, &rc);
    }

    if (memcached_success(rc))
    {
      // Found a record, so exit
      LOG_DEBUG("Found record on replica %d", ii);
      break;
    }
    else if (rc == MEMCACHED_NOTFOUND)
    {
      // Failed to find a record on an active replica, so flag that we may
      // need to do a read repair to this node.
      LOG_DEBUG("Read for %s on replica %d returned NOTFOUND", aor_id.c_str(), ii);
      read_repair[ii] = true;
      memcached_result_free(&result);
    }
    else
    {
      // Error from this node, so consider it inactive.
      LOG_DEBUG("Read for %s on replica %d returned error %d (%s)",
                aor_id.c_str(), ii, rc, memcached_strerror(replicas[ii], rc));
      ++failed_replicas;
    }
  }

  if (memcached_success(rc))
  {
    // Deserialize the result and expire any bindings that are out of date.
    LOG_DEBUG("Deserialize record");
    aor_data = deserialize_aor(std::string(memcached_result_value(&result), memcached_result_length(&result)));
    aor_data->set_cas(memcached_result_cas(&result));
    int now = time(NULL);
    int max_expires = expire_bindings(aor_data, now);

    // See if we need to do a read repair on any nodes that didn't find the record.
    bool first_repair = true;
    for (size_t jj = 0; jj < ii; ++jj)
    {
      if (read_repair[jj])
      {
        if (max_expires > now)
        {
          LOG_INFO("Do read repair for %s on replica %d, expiry = %d", aor_id.c_str(), jj, max_expires - now);
          if (first_repair)
          {
            LOG_DEBUG("First repair replica, so must do synchronous add");
            memcached_return_t repair_rc;
            repair_rc = memcached_add(replicas[jj],
                                      key_ptr,
                                      key_len,
                                      memcached_result_value(&result),
                                      memcached_result_length(&result),
                                      max_expires,
                                      0);
            if (memcached_success(repair_rc))
            {
              // Read repair worked, but we have to do another read to get the
              // CAS value on the primary server.
              LOG_DEBUG("Read repair on replica %d successful", jj);
              repair_rc = memcached_mget(replicas[jj], &key_ptr, &key_len, 1);

              if (memcached_success(repair_rc))
              {
                memcached_result_st repaired_result;
                memcached_result_create(replicas[jj], &repaired_result);
                memcached_fetch_result(replicas[jj], &repaired_result, &repair_rc);
                if (memcached_success(repair_rc))
                {
                  LOG_DEBUG("Updating CAS value on AoR record from %ld to %ld",
                            aor_data->get_cas(),
                            memcached_result_cas(&repaired_result));
                  aor_data->set_cas(memcached_result_cas(&repaired_result));
                }
                memcached_result_free(&repaired_result);
              }

              if (!memcached_success(repair_rc))
              {
                // Failed to read data after a successful read repair.  There's
                // not much we can do about this error - it will likely mean a
                // subsequent write will fail because the CAS value will be
                // wrong, but the app should then retry.
                LOG_WARNING("Failed to read data for %s from replica %d after successful read repair, rc = %d (%s)",
                            aor_id.c_str(),
                            jj,
                            repair_rc,
                            memcached_strerror(replicas[jj], repair_rc));
              }

              first_repair = true;
            }
          }
          else
          {
            // Not the first read repair, so can just do the add asynchronously
            // on a best efforts basis.
            LOG_DEBUG("Not first repair replica, so do asynchronous add");
            memcached_behavior_set(replicas[jj], MEMCACHED_BEHAVIOR_NOREPLY, 1);
            memcached_add(replicas[jj],
                          key_ptr,
                          key_len,
                          memcached_result_value(&result),
                          memcached_result_length(&result),
                          max_expires,
                          0);
            memcached_behavior_set(replicas[jj], MEMCACHED_BEHAVIOR_NOREPLY, 0);
          }
        }
        else
        {
          // We would do a read repair here, but the record has expired so
          // there is no point.  To make sure the next write is successful
          // we need to set the CAS value on the record we are about to return
          // to zero so the write will be processed as an add, not a cas.
          LOG_DEBUG("Force CAS to zero on expired record");
          aor_data->set_cas(0);
        }
      }
    }

    // Free the result.
    memcached_result_free(&result);
  }
  else if (failed_replicas < replicas.size())
  {
    // At least one replica returned NOT_FOUND, so return an empty aor_data
    // record
    LOG_DEBUG("At least one replica returned not found, so return empty record");
    aor_data = new MemcachedAoR();
  }
  else
  {
    // All replicas returned an error, so return no data record and log the
    // error.
    LOG_ERROR("Failed to read AoR data for %s from %d replicas",
              aor_id.c_str(), replicas.size());
  }

  return (AoR*)aor_data;
}


/// Update the data for a particular address of record.  Writes the data
/// atomically.  If the underlying data has changed since it was last
/// read, the update is rejected and this returns false; if the update
/// succeeds, this returns true.
bool MemcachedStore::set_aor_data(const std::string& aor_id,
                                  ///< the SIP URI
                                  AoR* data)
                                  ///< the data to store
{
  memcached_return_t rc = MEMCACHED_ERROR;
  MemcachedAoR* aor_data = (MemcachedAoR*)data;
  const char* key_ptr = aor_id.data();
  const size_t key_len = aor_id.length();

  const std::vector<memcached_st*>& replicas = get_replicas(aor_id, Op::WRITE);
  LOG_DEBUG("%d write replicas for key %s", replicas.size(), aor_id.c_str());

  // Expire any old bindings before writing to the server.  In theory,
  // if there are no bindings left we could delete the entry, but this
  // may cause concurrency problems because memcached does not support
  // cas on delete operations.  In this case we do a memcached_cas with
  // an effectively immediate expiry time.
  int now = time(NULL);
  int max_expires = expire_bindings(aor_data, now);
  std::string value = serialize_aor(aor_data);

  // First try to write the primary data record to the first responding
  // server.
  size_t ii;
  for (ii = 0; ii < replicas.size(); ++ii)
  {
    LOG_DEBUG("Attempt conditional write to replica %d (connection %p), CAS = %ld",
              ii,
              replicas[ii],
              aor_data->get_cas());

    if (aor_data->get_cas() == 0)
    {
      // New record, so attempt to add.  This will fail if someone else
      // gets there first.
      rc = memcached_add(replicas[ii],
                         key_ptr,
                         key_len,
                         value.data(),
                         value.length(),
                         max_expires,
                         0);
    }
    else
    {
      // This is an update to an existing record, so use memcached_cas
      // to make sure it is atomic.
      rc = memcached_cas(replicas[ii],
                         key_ptr,
                         key_len,
                         value.data(),
                         value.length(),
                         max_expires,
                         0,
                         aor_data->get_cas());
    }

    if (memcached_success(rc))
    {
      LOG_DEBUG("Conditional write succeeded to replica %d", ii);
      break;
    }
    else
    {
      LOG_DEBUG("memcached_%s command for %s failed on replica %d, rc = %d (%s), expiry = %d",
                (aor_data->get_cas() == 0) ? "add" : "cas",
                aor_id.c_str(),
                ii,
                rc,
                memcached_strerror(replicas[ii], rc),
                max_expires - now);

      if ((rc == MEMCACHED_NOTSTORED) ||
          (rc == MEMCACHED_DATA_EXISTS))
      {
        // A NOT_STORED or EXISTS response indicates a concurrent write failure,
        // so return this to the application immediately - don't go on to
        // other replicas.
        LOG_INFO("Contention writing data for %s to store", aor_id.c_str());
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
                    value.data(),
                    value.length(),
                    max_expires,
                    0);
      memcached_behavior_set(replicas[jj], MEMCACHED_BEHAVIOR_NOREPLY, 0);
    }
  }

  if ((!memcached_success(rc)) &&
      (rc != MEMCACHED_NOTSTORED) &&
      (rc != MEMCACHED_DATA_EXISTS))
  {
    LOG_ERROR("Failed to write AoR data for %s to %d replicas",
              aor_id.c_str(), replicas.size());
  }

  return memcached_success(rc);
}

void MemcachedStore::update_view()
{
  // Read the memstore file.
  std::ifstream f(_config_file);
  std::vector<std::string> servers;
  std::vector<std::string> new_servers;

  if (f.is_open())
  {
    LOG_STATUS("Reloading memcached configuration from %s file", _config_file.c_str());
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
          LOG_ERROR("Malformed %s file", _config_file.c_str());
          break;
        }

        LOG_STATUS(" %s=%s", tokens[0].c_str(), tokens[1].c_str());

        if (tokens[0] == "servers")
        {
          // Found line defining servers.
          Utils::split_string(tokens[1], ',', servers, 0, true);
        }
        else if (tokens[0] == "new_servers")
        {
          // Found line defining new servers.
          Utils::split_string(tokens[1], ',', new_servers, 0, true);
        }
      }
    }
    f.close();

    if (servers.size() > 0)
    {
      LOG_DEBUG("Update memcached store");
      this->new_view(servers, new_servers);
    }
  }
  else
  {
    LOG_ERROR("Failed to open %s file", _config_file.c_str());
  }
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
