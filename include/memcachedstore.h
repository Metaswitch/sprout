/**
 * @file memcachedstore.h Declarations for MemcachedStore class.
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
/// MemcachedStore implements Store interface for storing registration data,
/// using a memcached cluster for storage.
///
///

#ifndef MEMCACHEDSTORE_H__
#define MEMCACHEDSTORE_H__

#include <pthread.h>

#include <sstream>
#include <vector>

extern "C" {
#include <libmemcached/memcached.h>
#include <libmemcached/util.h>
}

#include "regdata.h"
#include "memcachedstoreview.h"


namespace RegData {

class MemcachedStoreUpdater;

/// @class RegData::MemcachedAoR
///
/// A memcached-based implementation of the Address of Record class.
class MemcachedAoR : public AoR
{
public:
  MemcachedAoR() :
    AoR(),
    _cas(0)
  {
  }

  inline void set_cas(uint64_t cas) { _cas = cas; };

  inline uint64_t get_cas() { return _cas; };

  // Override copy constructor and operator= to ensure cas gets copied
  // across also.
  MemcachedAoR(const MemcachedAoR& to_copy) :
    AoR(to_copy)
  {
    if (&to_copy != this)
    {
      _cas = to_copy._cas;
    }
  }

  void operator=(const MemcachedAoR& to_copy)
  {
    if (&to_copy != this)
    {
      AoR::operator=((AoR&)to_copy);
      _cas = to_copy._cas;
    }
  }

private:
  /// Stored CAS sequence number. This tracks the version of the data
  /// supplied by memcached, so we can detect concurrent modifications and
  /// avoid lost updates.
  uint64_t _cas;
};


/// @class RegData::MemcachedStore
///
/// A memcached-based implementation of the Store class.
class MemcachedStore : public Store
{
public:
  MemcachedStore(bool binary, const std::string& config_file);
  ~MemcachedStore();

  /// Flags that the store should use a new view of the memcached cluster to
  /// distribute data.  Note that this is public because it is called from
  /// the MemcachedStoreUpdater class and from UT classes.
  void new_view(const std::vector<std::string>& servers,
                const std::vector<std::string>& new_servers);

  /// Flushes the store.  This is only supported for test purposes - it should
  /// never be called on a live system.
  void flush_all();

  /// Gets the data for the specified Address-of-Record
  AoR* get_aor_data(const std::string& aor_id);

  /// Sets the data for the specified Address-of-Record
  bool set_aor_data(const std::string& aor_id, AoR* aor_data);

private:

  // A copy of this structure is maintained for each worker thread, as
  // thread local data.
  typedef struct connection
  {
    // Indicates the view number being used by this thread.  When the view
    // changes the global view number is updated and each thread switches to
    // the new view by establishing new memcached_st's.
    uint64_t view_number;

    // Contains the memcached_st's for each server.
    std::vector<memcached_st*> st;

    // Contains the set of read and write replicas for each vbucket.
    std::vector<std::vector<memcached_st*> > write_replicas;
    std::vector<std::vector<memcached_st*> > read_replicas;

  } connection;

  /// Gets the set of connections to use for a read or write operation.
  typedef enum {READ, WRITE} Op;
  const std::vector<memcached_st*>& get_replicas(const std::string& key, Op operation);

  static std::string serialize_aor(MemcachedAoR* aor_data);
  static MemcachedAoR* deserialize_aor(const std::string& s);

  // Called by the thread-local-storage clean-up functions when a thread ends.
  static void cleanup_connection(void* p);

  // Stores a pointer to an updater object (if one is
  MemcachedStoreUpdater* _updater;

  // Used to store a connection structure for each worker thread.
  pthread_key_t _thread_local;

  // Stores the number of replicas configured for the store (one means the
  // data is stored on one server, two means it is stored on two servers etc.).
  const int _replicas;

  // Stores the number of vbuckets being used.  This currently doesn't change,
  // but in future we may choose to increase it when the cluster gets
  // sufficiently large.  Note that it _must_ be a power of two.
  const int _vbuckets;

  // The options string used to create appropriate memcached_st's for the
  // current view.
  std::string _options;

  // The current global view number.  Note that this is not protected by the
  // _view_lock.
  uint64_t _view_number;

  // The lock used to protect the view parameters below (_servers,
  // _read_replicas and _write_replicas).
  pthread_rwlock_t _view_lock;

  // The list of servers in this view.
  std::vector<std::string> _servers;

  // The set of read and write replicas for each vbucket.  The integers in
  // each vector index into the list of servers.
  std::vector<std::vector<int> > _read_replicas;
  std::vector<std::vector<int> > _write_replicas;
};

} // namespace RegData

#endif
