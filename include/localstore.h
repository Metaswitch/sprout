/**
 * @file localstore.h Definitions for the LocalStore class
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
