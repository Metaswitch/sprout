/**
 * @file store.h  Abstract base class defining interface to Sprout data store.
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

#ifndef STORE_H_
#define STORE_H_


/// @class Store
///
/// Abstract base class for the Sprout data store.  This can be used to store
/// data that must be shared across the Sprout cluster.
///
class Store
{
public:
  /// Must define a destructor, even though it does nothing, to ensure there
  /// is an entry for it in the vtable.
  virtual ~Store()
  {
  }

  /// Status used to indicate success or failure of store operations.
  typedef enum {OK=1, NOT_FOUND=2, DATA_CONTENTION=3, ERROR=4} Status;

  /// Gets the data for the specified key in the specified namespace.
  ///
  /// @return         Status value indicating the result of the read.
  /// @param table    Name of the table to retrive the data.
  /// @param key      Key of the data record to retrieve.
  /// @param data     String to return the data.
  /// @param cas      Variable to return the CAS value of the data.
  virtual Status get_data(const std::string& table,
                          const std::string& key,
                          std::string& data,
                          uint64_t& cas) = 0;

  /// Sets the data for the specified key in the specified namespace.
  ///
  /// @return         Status value indicating the result of the write.
  /// @param table    Name of the table to store the data.
  /// @param key      Key used to index the data within the table.
  /// @param data     Data to store.
  /// @param cas      CAS (Check-and-Set) value for the data.  Should be set
  ///                 to the CAS value returned when the data was read, or
  ///                 zero if writing a record for the first time.
  /// @param expiry   Expiry period of the data (in seconds).  If zero the
  ///                 data will expire immediately.
  virtual Status set_data(const std::string& table,
                          const std::string& key,
                          const std::string& data,
                          uint64_t cas,
                          int expiry) = 0;
};

#endif
