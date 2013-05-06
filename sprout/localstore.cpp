/**
 * @file localstore.cpp Local memory implementation of the registration data store.
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
///

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
#include <stdint.h>

#include "localstorefactory.h"
#include "localstore.h"

namespace RegData {


  RegData::Store* create_local_store()
  {
    return new LocalStore();
  }


  void destroy_local_store(RegData::Store* store)
  {
    delete (RegData::LocalStore*)store;
  }


  LocalStore::LocalStore() :
    _db()
  {
  }


  LocalStore::~LocalStore()
  {
    flush_all();
  }


  void LocalStore::flush_all()
  {
    _db.clear();
  }


  AoR* LocalStore::get_aor_data(const std::string& aor_id)
  {
    LocalAoR* aor_data = new LocalAoR;
    std::map<std::string, LocalAoR>::iterator i = _db.find(aor_id);
    if (i != _db.end())
    {
      // AoR is already in database, so expire the bindings then copy
      // the data.
      expire_bindings(&i->second, time(NULL));
      *aor_data = i->second;
    }
    else
    {
      // AoR is not already in the database, so insert it.
      _db.insert(std::make_pair(aor_id, *aor_data));
    }

    return (AoR*)aor_data;
  }


  bool LocalStore::set_aor_data(const std::string& aor_id, AoR* data)
  {
    bool rc = false;
    LocalAoR* aor_data = (LocalAoR*)(data);
    if (aor_data != NULL)
    {
      std::map<std::string, LocalAoR>::iterator i = _db.find(aor_id);

      if (i != _db.end())
      {
        if (aor_data->get_cas() == i->second.get_cas())
        {
          // CAS is unchanged, so increment the CAS and update the data.
          aor_data->set_cas(aor_data->get_cas() + 1);
          i->second = *aor_data;
          rc = true;
        }
      }
    }

    return rc;
  }

} // namespace RegData

