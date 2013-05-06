/**
 * @file memcachedstore.h Declarations for MemcachedStore class.
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
/// MemcachedStore implements Store interface for storing registration data,
/// using a memcached cluster for storage.
///
///

#ifndef MEMCACHEDSTORE_H__
#define MEMCACHEDSTORE_H__

#include <sstream>

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
    MemcachedStore(const std::list<std::string>& servers, int pool_size);
    ~MemcachedStore();

    void flush_all();

    AoR* get_aor_data(const std::string& aor_id);
    bool set_aor_data(const std::string& aor_id, AoR* aor_data);

  private:
    /// Helper: to_string method using ostringstream.
    template <class T>
      std::string to_string(T t, ///< datum to convert
                            std::ios_base & (*f)(std::ios_base&)
                            ///< modifier to apply
                           )
    {
      std::ostringstream oss;
      oss << f << t;
      return oss.str();
    }

    static std::string serialize_aor(MemcachedAoR* aor_data);
    static MemcachedAoR* deserialize_aor(const std::string& s);

    /// The memcached pool in use. Owned by this object.
    memcached_pool_st* _pool;

  };

} // namespace RegData

#endif
