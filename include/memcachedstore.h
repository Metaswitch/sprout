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

#include <sstream>
#include <vector>

extern "C" {
#include <libmemcached/memcached.h>
#include <libmemcached/util.h>
}

#include "regdata.h"

namespace RegData {

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
  MemcachedStore(const std::list<std::string>& servers, int pool_size, bool binary=true);
  ~MemcachedStore();

  void flush_all();

  AoR* get_aor_data(const std::string& aor_id);
  bool set_aor_data(const std::string& aor_id, AoR* aor_data);

  static void cleanup_connection(void* p);

private:

  typedef struct connection
  {
    uint64_t view;
    std::vector<memcached_st*> st;
  } connection;

  connection* get_connection();

  void new_view(const std::list<std::string>& servers);

  /// Helper: to_string method using ostringstream.
  template <class T>
  std::string to_string(T t,                                  ///< datum to convert
                        std::ios_base & (*f)(std::ios_base&)) ///< modifier to apply
  {
    std::ostringstream oss;
    oss << f << t;
    return oss.str();
  }

  static std::string serialize_aor(MemcachedAoR* aor_data);
  static MemcachedAoR* deserialize_aor(const std::string& s);

  pthread_key_t _thread_local;

  bool _binary;
  int _replicas;

  uint64_t _view;
  pthread_mutex_t _view_lock;

  int _servers;
  std::string _options;

  static const int NUM_VBUCKETS = 256;

  uint32_t _vbuckets;
  std::vector<uint32_t*> _vbucket_map;
};

} // namespace RegData

#endif
