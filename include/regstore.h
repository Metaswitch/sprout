/**
 * @file regstore.h Definitions of interfaces for the registration data store.
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


#ifndef REGSTORE_H__
#define REGSTORE_H__

#include <string>
#include <list>
#include <map>
#include <stdio.h>
#include <stdlib.h>

#include "store.h"
#include "regstore.h"

class RegStore
{
public:
  /// @class RegStore::AoR
  ///
  /// Addresses that are registered for this address of record.
  class AoR
  {
  public:
    /// @class Regstore::AoR::Binding
    ///
    /// A single registered address.
    class Binding
    {
    public:
      /// The registered contact URI, e.g.,
      /// "sip:2125551212@192.168.0.1:55491;transport=TCP;rinstance=fad34fbcdea6a931"
      std::string _uri;

      /// The Call-ID: of the registration.  Per RFC3261, this is the same for
      /// all registrations from a given UAC to this registrar (for this AoR).
      /// E.g., "gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq"
      std::string _cid;

      /// Contains any path headers (in order) that were present on the
      /// register.  Empty if there were none.
      std::list<std::string> _path_headers;

      /// The CSeq value of the REGISTER request.
      int _cseq;

      /// The time (in seconds since the epoch) at which this binding should
      /// expire.  Based on the expires parameter of the Contact: header.
      int _expires;

      /// The Contact: header q parameter (qvalue), times 1000.  This is used
      /// to prioritise the registrations (highest value first), per RFC3261
      /// s10.2.1.2.
      int _priority;

      /// Any other parameters found in the Contact: header, stored as key ->
      /// value in order of appearance.  E.g., "+sip.ice" -> "".
      std::list<std::pair<std::string, std::string> > _params;
    };

    /// Default Constructor.
    AoR();

    /// Destructor.
    ~AoR();

    /// Make sure copy is deep!
    AoR(const AoR& other);

    // Make sure assignment is deep!
    AoR& operator= (AoR const& other);

    /// Clear all the bindings from this object.
    void clear();

    /// Retrieve a binding by Contact URI, creating an empty one if necessary.
    /// The created binding is completely empty, even the Contact URI field.
    Binding* get_binding(const std::string& binding_id);

    /// Removes any binding that had the given ID.  If there is no such binding,
    /// does nothing.
    void remove_binding(const std::string& binding_id);

    /// Binding ID -> Binding.  First is sometimes the contact URI, but not always.
    /// Second is a pointer to an object owned by this object.
    typedef std::map<std::string, Binding*> Bindings;

    /// Retrieve all the bindings.
    inline const Bindings& bindings() { return _bindings; }

  private:
    /// Map holding the bindings for a particular AoR indexed by binding ID.
    Bindings _bindings;

    /// CAS value for this AoR record.  Used when updating an existing record.
    /// Zero for a new record that has not yet been written to a store.
    uint64_t _cas;

    /// Store code is allowed to manipulate bindings directly.
    friend class RegStore;
  };

  /// Constructor.
  RegStore(Store* data_store);

  /// Destructor.
  ~RegStore();

  /// Get the data for a particular address of record (registered SIP URI,
  /// in format "sip:2125551212@example.com"), creating creating it if
  /// necessary.  May return NULL in case of error.  Result is owned
  /// by caller and must be freed with delete.
  AoR* get_aor_data(const std::string& aor_id);

  /// Update the data for a particular address of record.  Writes the data
  /// atomically.  If the underlying data has changed since it was last
  /// read, the update is rejected and this returns false; if the update
  /// succeeds, this returns true.
  bool set_aor_data(const std::string& aor_id, AoR* data);

  int expire_bindings(AoR* aor_data, int now);

  std::string serialize_aor(AoR* aor_data);

  AoR* deserialize_aor(const std::string& s);

private:
  Store* _data_store;
};

#endif
