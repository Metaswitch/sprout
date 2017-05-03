/**
 * @file associated_uris.cpp Implementation of the AssociatedURIs class.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2017  Metaswitch Networks Ltd
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

#include "associated_uris.h"

#include <algorithm>

// Gets the default URI. We return the first unbarred URI. If there is no
// unbarred URI, we don't return anything unless it is an emergency in which
// case we return the first URI.
bool AssociatedURIs::get_default(std::string& uri,
                                 bool emergency)
{
  std::vector<std::string> unbarred_uris = this->unbarred_uris();
  if (!unbarred_uris.empty())
  {
    uri = unbarred_uris.front();
    return true;
  }

  if ((emergency) &&
      (!_associated_uris.empty()))
  {
    uri = _associated_uris.front();
    return true;
  }

  return false;
}

// Checks if the uri is in the list of associated URIs.
bool AssociatedURIs::contains(std::string uri)
{
  return (std::find(_associated_uris.begin(), _associated_uris.end(), uri) !=
          _associated_uris.end());
}

// Adds a uri and its barring state to the list of associated URIs.
void AssociatedURIs::add(std::string uri,
                         bool barred)
{
  _associated_uris.push_back(uri);
  _barred_map[uri] = barred;
}

// Removes all URIs.
void AssociatedURIs::clear()
{
  _associated_uris.clear();
  _barred_map.clear();
}

// Returns if the specified URI is barred.
bool AssociatedURIs::is_barred(std::string uri)
{
  return _barred_map[uri];
}

// Retruns all unbarred associatd URIs.
std::vector<std::string> AssociatedURIs::unbarred_uris()
{
  std::vector<std::string> unbarred_uris;

  for (std::string uri : _associated_uris)
  {
    if (!_barred_map[uri])
    {
      unbarred_uris.push_back(uri);
    }
  }

  return unbarred_uris;
}

// Returns all associated URIs.
std::vector<std::string> AssociatedURIs::all_uris()
{
  return _associated_uris;
}
