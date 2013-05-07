/**
 * @file store.cpp Common code for the registration data store.
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

#include "regdata.h"

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

namespace RegData {

  AoR::AoR(const AoR& other)
  {
    for (Bindings::const_iterator i = other._bindings.begin();
         i != other._bindings.end();
         ++i)
    {
      Binding* bb = new Binding(*i->second);
      _bindings.insert(std::make_pair(i->first, bb));
    }
  }

  // Make sure assignment is deep!
  AoR& AoR::operator= (AoR const& other)
  {
    if (this != &other)
    {
      clear();

      for (Bindings::const_iterator i = other._bindings.begin();
           i != other._bindings.end();
           ++i)
      {
        Binding* bb = new Binding(*i->second);
        _bindings.insert(std::make_pair(i->first, bb));
      }
    }

    return *this;
  }

  /// Clear all the bindings from this object.
  void AoR::clear()
  {
    for (Bindings::iterator i = _bindings.begin();
         i != _bindings.end();
         ++i)
    {
      delete i->second;
    }
    _bindings.clear();
  }

  /// Retrieve a binding by Contact URI, creating an empty one if necessary.
  /// The created binding is completely empty, even the Contact URI field.
  AoR::Binding* AoR::get_binding(const std::string& binding_id)
  {
    AoR::Binding* b;
    AoR::Bindings::const_iterator i = _bindings.find(binding_id);
    if (i != _bindings.end())
    {
      b = i->second;
    }
    else
    {
      // No existing binding with this id, so create a new one.
      b = new Binding;
      _bindings.insert(std::make_pair(binding_id, b));
    }
    return b;
  }

  /// Removes any binding that had the given ID.  If there is no such binding,
  /// does nothing.
  void AoR::remove_binding(const std::string& binding_id)
  {
    AoR::Bindings::iterator i = _bindings.find(binding_id);
    if (i != _bindings.end())
    {
      delete i->second;
      _bindings.erase(i);
    }
  }

  /// Expire any old bindings, and report the latest outstanding expiry time,
  /// or now if none.
  int Store::expire_bindings(AoR* aor_data,
                             ///< the data to examine
                             int now)
                             ///< the current time, in seconds since
                             /// the epoch.
  {
    int max_expires = now;
    for (AoR::Bindings::iterator i = aor_data->_bindings.begin();
         i != aor_data->_bindings.end();
      )
    {
      AoR::Binding* b = i->second;
      if (b->_expires <= now)
      {
        // The binding has expired, so remove it.
        delete i->second;
        aor_data->_bindings.erase(i++);
      }
      else
      {
        if (b->_expires > max_expires)
        {
          max_expires = b->_expires;
        }
        ++i;
      }
    }
    return max_expires;
  }
} // namespace RegData

