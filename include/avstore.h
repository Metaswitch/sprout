/**
 * @file avstore.h  Definition of class for storing Authentication Vectors
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

#ifndef AVSTORE_H_
#define AVSTORE_H_

#include <json/json.h>

#include "store.h"

/// Class implementing store of authentication vectors.  This is a wrapper
/// around an underlying Store class which implements a simple KV store API
/// with atomic write and record expiry semantics.  The underlying store
/// can be any implementation that implements the Store API.
class AvStore
{
public:
  /// Constructor.
  /// @param data_store    A pointer to the underlying data store.
  AvStore(Store* data_store);

  /// Destructor.
  ~AvStore();

  /// Store the specified Authentication Vector in the store, indexed by the
  /// private user identity and nonce.
  /// @param impi      A reference to the private user identity.
  /// @param nonce     A reference to the nonce.
  /// @param av        A pointer to a JSONCPP Json::Value object encoding
  ///                  the Authentication Vector.
  /// @returns True if we successfully set the data in memcached,
  /// false otherwise.
  bool set_av(const std::string& impi,
              const std::string& nonce,
              const Json::Value* av);

  /// Retrieves the Authentication Vector for the specified private user identity
  /// and nonce.
  /// @returns         A pointer to a JSONCPP Json::Value object encoding the
  ///                  Authentication Vector, or NULL if no vector found or if
  ///                  the vector is malformed.
  /// @param impi      A reference to the private user identity.
  /// @param nonce     A reference to the nonce.
  Json::Value* get_av(const std::string& impi,
                      const std::string& nonce);

  bool delete_av(const std::string& impi,
                 const std::string& nonce);

private:
  /// A pointer to the underlying data store.
  Store* _data_store;

  /// Expire AV record after 40 seconds.  This should always be long enough for
  /// the UE to respond to the authentication challenge, and means
  /// that on authentication timeout our 30-second Chronos timer
  /// should pop before it expires.
  static const int AV_EXPIRY = 40;
};

#endif
