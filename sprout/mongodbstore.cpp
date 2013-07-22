/**
 * @file mongodbstore.cpp MongoDB backed implementation of the registration data store.
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

#include "mongodbstore.h"

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

#include "mongodbstorefactory.h"
#include "log.h"
#include "utils.h"

namespace RegData {

/// Create a new store object, using the MongoDB implementation.
///
RegData::Store* create_mongodb_store(const std::list<std::string>& servers)
                                       ///< list of servers to be used
{
  return new MongoDbStore(servers);
}

/// Destroy a store object which used the MongoDB implementation.
///
void destroy_mongodb_store(RegData::Store* store)
{
  delete (RegData::MongoDbStore*)store;
}

/// Constructor: create a connection to the MongoDB replica set.
///
MongoDbStore::MongoDbStore(const std::list<std::string>& servers)  ///< list of servers to be used
{
#if 0

  mongo_replica_set_init(&_conn, "sprout");

  for (std::list<std::string>::const_iterator i = servers.begin();
       i != servers.end();
       ++i)
  {
    // Split the server name in to the IP address and port parts.
    std::vector<std::string> host_port;
    Utils::split_string(*i, ':', host_port, 2, true);

    if (host_port.size() != 2)
    {
      LOG_ERROR("Failed to parse server name %s", (*i).c_str());
      continue;
    }

    mongo_replica_set_add_seed(&_conn, host_port[0].c_str(), atoi(host_port[1].c_str()));
  }

  int status = mongo_replica_set_client(&_conn);
#else
  if (servers.size() > 1)
  {
    LOG_ERROR("Cannot support more than one MongoDB server - ignoring all except first");
  }

  std::vector<std::string> host_port;
  Utils::split_string(*servers.begin(), ':', host_port, 2, true);
  if (host_port.size() != 2)
  {
    LOG_ERROR("Failed to parse server name %s", (*servers.begin()).c_str());
  }

  LOG_STATUS("Connecting to MongoDB %s:%d", host_port[0].c_str(), atoi(host_port[1].c_str()));
  int status = mongo_client(&_conn, host_port[0].c_str(), atoi(host_port[1].c_str()));
#endif

  if (status != MONGO_OK)
  {
    int err = mongo_get_err(&_conn);
#if 0
    LOG_ERROR("Failed to connect to MongoDB sprout replica set, error = %d", err);
#else
    LOG_ERROR("Failed to connect to MongoDB server, error = %d", err);
#endif
    switch (err)
    {
      case MONGO_CONN_NO_SOCKET:
        LOG_ERROR("...  No socket" );
        break;
      case MONGO_CONN_FAIL:
        LOG_ERROR("...  Connection failed" );
        break;
      case MONGO_CONN_NOT_MASTER:
        LOG_ERROR("...  Not master" );
        break;
      default:
        LOG_ERROR("...  Unexpected error %d", err);
        break;
    }
  }
}

MongoDbStore::~MongoDbStore()
{
  mongo_destroy(&_conn);
}

// LCOV_EXCL_START - need real memcached to test

/// Wipe the contents of all the memcached servers immediately, if we can
/// get a connection.  If not, does nothing.
void MongoDbStore::flush_all()
{
}


/// Retrieve the AoR data for a given SIP URI, creating it if there isn't
/// any already, and returning NULL if we can't get a connection.
AoR* MongoDbStore::get_aor_data(const std::string& aor_id)   ///< the address of record
{
  bson query;
  mongo_cursor cursor;

  bson_init(&query);
  bson_append_string(&query, "_id", aor_id.c_str());
  bson_finish(&query);

  mongo_cursor_init(&cursor, &_conn, "db.registrations");
  mongo_cursor_set_query(&cursor, &query);
  mongo_cursor_set_limit(&cursor, 1);   // Always expect one document when querying
                                        // on _id.

  AoR* aor_data = new AoR();

  if (mongo_cursor_next(&cursor) == MONGO_OK)
  {
    // Found the AoR data, so extract all the bindings.
    bson_iterator binding_list;
    if (bson_find(&binding_list, mongo_cursor_bson(&cursor), "bindings"))
    {
      // Found some bindings, so iterate through them decoding the data.
      bson_iterator binding;
      bson_iterator_subiterator(&binding_list, &binding);
      while (bson_iterator_more(&binding))
      {
        bson_iterator_next(&binding);
        const char* binding_id = bson_iterator_key(&binding);

        AoR::Binding* b = aor_data->get_binding(std::string(binding_id));

        bson_iterator binding_data;
        bson_iterator_subiterator(&binding, &binding_data);

        // @TODO - need to support full set of data, or move to a single
        // field encoding.
        while (bson_iterator_more(&binding_data))
        {
          bson_iterator_next(&binding_data);
          const char* key = bson_iterator_key(&binding_data);
          if (strcmp(key, "uri") == 0)
          {
            b->_uri = std::string(bson_iterator_value(&binding_data));
          }
          else if (strcmp(key, "expires") == 0)
          {
            b->_expires = bson_iterator_int(&binding_data);
          }
          else if (strcmp(key, "priority") == 0)
          {
            b->_priority = bson_iterator_int(&binding_data);
          }
        }
      }
    }
  }

  bson_destroy(&query);
  mongo_cursor_destroy(&cursor);

  return (AoR*)aor_data;
}

/// Update the data for a particular address of record.  Writes the data
/// atomically.  If the underlying data has changed since it was last
/// read, the update is rejected and this returns false; if the update
/// succeeds, this returns true.
///
/// If a connection cannot be obtained, returns a random boolean based on
/// data found on the call stack at the point of entry.
bool MongoDbStore::set_aor_data(const std::string& aor_id, ///< the address of record
                                AoR* data)                 ///< the data to store
{
  bool rc = true;
  bson cond, op;

  bson_init(&cond);
  bson_append_string(&cond, "_id", aor_id.c_str());
  bson_finish(&cond);

  bson_init(&op);
  bson_append_start_object(&op, "$set");
  bson_append_start_object(&op, "binding");
  for (AoR::Bindings::const_iterator i = data->bindings().begin();
       i != data->bindings().end();
       ++i)
  {
    bson_append_start_object(&op, i->first.c_str());
    bson_append_string(&op, "uri", i->second->_uri.c_str());
    bson_append_int(&op, "expires", i->second->_expires);
    bson_append_int(&op, "priority", i->second->_priority);
    bson_append_finish_object(&op);
  }
  bson_append_finish_object(&op);
  bson_append_finish_object(&op);
  bson_finish(&op);

#if 0
  printf("BSON condition ...\n");
  bson_print(&cond);
  printf("\n");
  printf("BSON operation ...\n");
  bson_print(&op);
  printf("\n");
#endif

  int ret = mongo_update(&_conn, "db.registrations", &cond, &op, MONGO_UPDATE_UPSERT, NULL);

  if (ret != MONGO_OK)
  {
    LOG_ERROR("MongoDb update failed %d, error = %d", ret, mongo_get_err(&_conn));
    LOG_ERROR("... %d %d %s %d %s", _conn.err, _conn.errcode, _conn.errstr, _conn.lasterrcode, _conn.lasterrstr);
    rc = false;
  }

  bson_destroy(&cond);
  bson_destroy(&op);

  return rc;
}

// LCOV_EXCL_STOP

} // namespace RegData

