/**
 * @file cassandrastore.h Declarations for CassandraStore class.
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
/// CassandraStore implements Store interface for storing registration data,
/// using a cassandra cluster for storage.
///
///

#ifndef CASSANDRASTORE_H__
#define CASSANDRASTORE_H__

#include <sstream>

#include "thrift/Thrift.h"
#include "thrift/transport/TSocket.h"
#include "thrift/transport/TTransport.h"
#include "thrift/transport/TBufferTransports.h"
#include "thrift/protocol/TProtocol.h"
#include "thrift/protocol/TBinaryProtocol.h"
#include "Cassandra.h"

#include "regdata.h"

namespace RegData {

  /// @class RegData::CassandraAoR
  ///
  /// A cassandra-based implementation of the Address of Record class.
  class CassandraAoR : public AoR
  {
  public:
    CassandraAoR() : AoR() {}

    // Override copy constructor and operator= to ensure cas gets copied
    // across also.
    CassandraAoR(const CassandraAoR& to_copy) : AoR(to_copy) {}

    void operator=(const CassandraAoR& to_copy)
    {
      if (&to_copy != this)
      {
        AoR::operator=((AoR&)to_copy);
      }
    }
  };

  /// @class RegData::CassandraStore
  ///
  /// A cassandra-based implementation of the Store class.
  class CassandraStore : public Store
  {
  public:
    CassandraStore(std::string server);
    ~CassandraStore();

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

    static void serialize_aor(CassandraAoR* aor_data, std::vector<org::apache::cassandra::Mutation>& mutations);
    static CassandraAoR* deserialize_aor(const std::vector<org::apache::cassandra::ColumnOrSuperColumn>& columns);

    static const int PORT = 9160;
    static const std::string KEYSPACE;
    static const std::string COLUMN_FAMILY;

    /// The cassandra transport and client to use.
    boost::shared_ptr<apache::thrift::transport::TTransport> _transport;
    org::apache::cassandra::CassandraClient* _client;
  };

} // namespace RegData

#endif
