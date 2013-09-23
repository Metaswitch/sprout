/**
 * @file memcachedstoreview.h Declarations for MemcachedStoreView class.
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


#ifndef MEMCACHEDSTOREVIEW_H__
#define MEMCACHEDSTOREVIEW_H__

#include <pthread.h>

#include <vector>

namespace RegData {

/// Tracks the current view of the underlying memcached cluster, including
/// calculating the libmemcached server list and the vbucket configurations.

class MemcachedStoreView
{
public:
  MemcachedStoreView(int vbuckets, int replicas);
  ~MemcachedStoreView();

  /// Updates the view for new current and target server lists.
  void update(const std::list<std::string>& servers,
              const std::list<std::string>& new_servers);

  /// Returns the current server list.
  const std::list<std::string>& server_list() const { return _server_list; };

  /// Returns the vbucket table for the specified replica.
  const std::vector<int>& vbucket_map(int replica) const { return _vbucket_map[replica]; };

private:

  std::string vbucket_to_string(std::vector<int> vbucket_map);

  /// Calculates the ring used to generate the vbucket configurations.
  class Ring
  {
  public:
    Ring(int slots);
    ~Ring();

    void update(int nodes);

    std::vector<int> get_nodes(int slot, int replicas);

  private:

    void assign_slot(int slot, int node);
    int owned_slot(int node, int number);

    int _slots;
    int _nodes;

    // This is the master ring.
    std::vector<int> _ring;

    // Tracks which slots in the ring each node is assigned.  Indexing is by
    // node, then an ordered map of the assigned slots.
    std::vector<std::map<int, int> > _node_slots;
  };

  int _replicas;
  int _servers;
  int _vbuckets;

  std::list<std::string> _server_list;
  std::vector<std::vector<int>> _vbucket_map;
};

} // namespace RegData

#endif
