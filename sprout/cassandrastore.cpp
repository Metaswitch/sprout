/**
 * @file cassandrastore.cpp Cassandra-backed implementation of the registration data store.
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

#include "cassandrastore.h"

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

#include "cassandrastorefactory.h"
#include "log.h"

using namespace apache::thrift;
using namespace apache::thrift::transport;
using namespace apache::thrift::protocol;
using namespace org::apache::cassandra;

namespace RegData {

  /// Create a new store object, using the cassandra implementation.
  RegData::Store* create_cassandra_store(const std::string server)
                                         ///< server to use
  {
    return new CassandraStore(server);
  }

  /// Destroy a store object which used the cassandra implementation.
  void destroy_cassandra_store(RegData::Store* store)
  {
    delete (RegData::CassandraStore*)store;
  }

  const std::string CassandraStore::KEYSPACE = "sprout";
  const std::string CassandraStore::COLUMN_FAMILY = "reg";

  static void cleanup_client(void* client)
  {
    // TODO: Implement this properly.
    //transport->close();
    delete((CassandraClient*)client);
  }

  /// Constructor: get a handle to the cassandra connection of interest.
  CassandraStore::CassandraStore(const std::string server) : _server(server)
                                 ///< server to use
  {
    pthread_key_create(&_thread_local, cleanup_client);
  }

  CassandraStore::~CassandraStore()
  {
    // Clean up this thread's client now, rather than waiting for
    // pthread_exit.  This is to support use by single-threaded code
    // (e.g., UTs), where pthread_exit is never called.
    CassandraClient* client = (CassandraClient*)pthread_getspecific(_thread_local);
    if (client != NULL)
    {
      pthread_setspecific(_thread_local, NULL);
      cleanup_client(client);
    }
  }

  CassandraClient* CassandraStore::get_client()
  {
    CassandraClient* client = (CassandraClient*)pthread_getspecific(_thread_local);
    if (client == NULL)
    {
      boost::shared_ptr<TTransport> socket = boost::shared_ptr<TSocket>(new TSocket(_server, PORT));
      boost::shared_ptr<TFramedTransport> transport = boost::shared_ptr<TFramedTransport>(new TFramedTransport(socket));
      boost::shared_ptr<TProtocol> protocol = boost::shared_ptr<TBinaryProtocol>(new TBinaryProtocol(transport));
      client = new CassandraClient(protocol);
      transport->open();
      client->set_keyspace(KEYSPACE);
      pthread_setspecific(_thread_local, client);
    }
    return client;
  }

  /// Wipe the contents of all the cassandra servers immediately, if we can
  /// get a connection.  If not, does nothing.
  void CassandraStore::flush_all()
  {
    get_client()->truncate(COLUMN_FAMILY);
  }

  // LCOV_EXCL_START - need real cassandra to test

  /// Retrieve the AoR data for a given SIP URI, creating it if there isn't
  /// any already, and returning NULL if we can't get a connection.
  AoR* CassandraStore::get_aor_data(const std::string& aor_id)
                                    ///< the SIP URI
  {
    CassandraAoR* aor_data = NULL;

    ColumnParent cparent;
    cparent.column_family = COLUMN_FAMILY;

    // get the entire row for a key
    SliceRange sr;
    sr.start = "";
    sr.finish = "";

    SlicePredicate sp;
    sp.slice_range = sr;
    sp.__isset.slice_range = true; // set __isset for the columns instead if you use them

    KeyRange range;
    range.start_key = aor_id;
    range.end_key = "";
    range.__isset.start_key = true;
    range.__isset.end_key = true;

    try
    {
      std::vector<KeySlice> results;
      get_client()->get_range_slices(results, cparent, sp, range, ConsistencyLevel::ONE);
      if (results.size() > 0)
      {
        aor_data = deserialize_aor(results[0].columns);
      }
      else
      {
        // AoR does not exist, so create it.
        aor_data = new CassandraAoR();
      }
    }
    catch(TTransportException te)
    {
      printf("Exception: %s  [%d]\n", te.what(), te.getType());
    }
    catch(InvalidRequestException ire)
    {
      printf("Exception: %s  [%s]\n", ire.what(), ire.why.c_str());
    }
    catch(NotFoundException nfe)
    {
      printf("Exception: %s\n", nfe.what());
    }

    return (AoR*)aor_data;
  }

  /// Update the data for a particular address of record.  Writes the data
  /// atomically.  If the underlying data has changed since it was last
  /// read, the update is rejected and this returns false; if the update
  /// succeeds, this returns true.
  ///
  /// If a connection cannot be obtained, returns a random boolean based on
  /// data found on the call stack at the point of entry.
  bool CassandraStore::set_aor_data(const std::string& aor_id,
                                    ///< the SIP URI
                                    AoR* data)
                                    ///< the data to store
  {
    std::map<std::string, std::vector<Mutation>> columnFamilyMutationMap;
    serialize_aor((CassandraAoR*)data, columnFamilyMutationMap[COLUMN_FAMILY]);

    std::map<std::string, std::map<std::string, std::vector<Mutation> > > keyColumnFamilyMutationMap;
    keyColumnFamilyMutationMap[aor_id] = columnFamilyMutationMap;

    get_client()->batch_mutate(keyColumnFamilyMutationMap, ConsistencyLevel::ONE);
    // TODO: Handle exception

    return true;
  }

  // LCOV_EXCL_STOP

  /// Serialize the contents of an AoR.
  void CassandraStore::serialize_aor(CassandraAoR* aor_data, std::vector<Mutation>& mutations)
  {
    // have to go through all of this just to get the timestamp in ms
    struct timeval td;
    gettimeofday(&td, NULL);
    int64_t ms = td.tv_sec;
    ms = ms * 1000;
    int64_t usec = td.tv_usec;
    usec = usec / 1000;
    ms += usec;

    for (AoR::Bindings::const_iterator i = aor_data->bindings().begin();
         i != aor_data->bindings().end();
         ++i)
    {
      // TODO: Just serialize deltas.
      Mutation* mutation = new Mutation();
      Column* column = &mutation->column_or_supercolumn.column;
      column->name = i->first;

      std::ostringstream oss(std::ostringstream::out|std::ostringstream::binary);

      AoR::Binding* b = i->second;
      oss << b->_uri << '\0';
      oss << b->_cid << '\0';
      oss.write((const char *)&b->_cseq, sizeof(int));
      oss.write((const char *)&b->_expires, sizeof(int));
      oss.write((const char *)&b->_priority, sizeof(int));
      int num_params = b->_params.size();
      oss.write((const char *)&num_params, sizeof(int));
      for (std::list<std::pair<std::string, std::string> >::const_iterator i = b->_params.begin();
           i != b->_params.end();
           ++i)
      {
        oss << i->first << '\0' << i->second << '\0';
      }
      int num_path_hdrs = b->_path_headers.size();
      oss.write((const char *)&num_path_hdrs, sizeof(int));
      for (std::list<std::string>::const_iterator i = b->_path_headers.begin();
           i != b->_path_headers.end();
           ++i)
      {
        oss << *i << '\0';
      }

      column->value = oss.str();
      column->__isset.value = true;
      column->timestamp = ms;
      column->__isset.timestamp = true;
      // TODO: Adapt from b->_expires
      column->ttl = 300;
      column->__isset.ttl = true;
      mutation->column_or_supercolumn.__isset.column = true;
      mutation->__isset.column_or_supercolumn = true;
      mutations.push_back(*mutation);
    }
  }

  /// Deserialize the contents of an AoR
  CassandraAoR* CassandraStore::deserialize_aor(const std::vector<ColumnOrSuperColumn>& columns)
  {
    CassandraAoR* aor_data = new CassandraAoR();
    LOG_DEBUG("There are %d bindings", columns.size());

    for (std::vector<ColumnOrSuperColumn>::const_iterator i = columns.begin();
         i != columns.end();
         ++i)
    {
      // TODO: Handle multiple contacts for the same binding id

      // Extract the binding identifier into a string.
      std::string binding_id = i->column.name;

      AoR::Binding* b = aor_data->get_binding(binding_id);

      // Now extract the various fixed binding parameters.
      std::istringstream iss(i->column.value, std::istringstream::in|std::istringstream::binary);
      getline(iss, b->_uri, '\0');
      getline(iss, b->_cid, '\0');
      iss.read((char *)&b->_cseq, sizeof(int));
      iss.read((char *)&b->_expires, sizeof(int));
      iss.read((char *)&b->_priority, sizeof(int));

      int num_params;
      iss.read((char *)&num_params, sizeof(int));
      LOG_DEBUG("Binding has %d params", num_params);
      b->_params.resize(num_params);
      for (std::list<std::pair<std::string, std::string> >::iterator i = b->_params.begin();
           i != b->_params.end();
           ++i)
      {
        getline(iss, i->first, '\0');
        getline(iss, i->second, '\0');
        LOG_DEBUG("Read param %s = %s", i->first.c_str(), i->second.c_str());
      }

      int num_paths = 0;
      iss.read((char *)&num_paths, sizeof(int));
      b->_path_headers.resize(num_paths);
      LOG_DEBUG("Binding has %d paths", num_paths);
      for (std::list<std::string>::iterator i = b->_path_headers.begin();
           i != b->_path_headers.end();
           ++i)
      {
        getline(iss, *i, '\0');
        LOG_DEBUG("Read path %s", i->c_str());
      }
    }

    return aor_data;
  }
} // namespace RegData

