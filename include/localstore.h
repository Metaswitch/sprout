/**
 * @file localstore.h Definitions for the LocalStore class
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
/// LocalStore implements the Store interface for storing registration data,
/// using local memory for storage.
///
///

#ifndef LOCALSTORE_H__
#define LOCALSTORE_H__

#include "regdata.h"

namespace RegData {

  class LocalAoR : public AoR
  {
  public:
  LocalAoR() :
    AoR(),
      _cas(0)
      {
      }

    inline void set_cas(uint64_t cas) { _cas = cas; };
    inline uint64_t get_cas() { return _cas; };

    // Override copy constructor and operator= to ensure cas gets copied
    // across also.
  LocalAoR(const LocalAoR& to_copy) :
    AoR(to_copy)
    {
      if (&to_copy != this)
      {
        _cas = to_copy._cas;
      }
    }

    void operator=(const LocalAoR& to_copy)
      {
        if (&to_copy != this)
        {
          AoR::operator=((AoR&)to_copy);
          _cas = to_copy._cas;
        }
      }

  private:
    uint64_t _cas;
  };

  class LocalStore : public Store
  {
  public:
    LocalStore();
    virtual ~LocalStore();

    void flush_all();

    AoR* get_aor_data(const std::string& aor_id);
    bool set_aor_data(const std::string& aor_id, AoR* aor_data);

  private:
    std::map<std::string, LocalAoR> _db;
  };

} // namespace RegData

#endif
