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

#include <map>
#include <string>
#include <vector>

/// Tracks the current view of the underlying memcached cluster, including
/// calculating the server list and the replica configurations.
class MemcachedStoreView
{
public:
  MemcachedStoreView(int vbuckets, int replicas);
  ~MemcachedStoreView();

  /// Updates the view for new current and target server lists.
  void update(const std::vector<std::string>& servers,
              const std::vector<std::string>& new_servers);

  /// Returns the current server list.
  const std::vector<std::string>& servers() const { return _servers; };

  /// Returns the current read and write replica sets for each vbucket.
  const std::vector<int>& read_replicas(int vbucket) const { return _read_set[vbucket]; };
  const std::vector<int>& write_replicas(int vbucket) const { return _write_set[vbucket]; };

private:
  /// Converts the view into a string suitable for logging.
  std::string view_to_string();

  /// Converts a set of replicas into an ordered string suitable for logging.
  std::string replicas_to_string(const std::vector<int>& replicas);

  /// Calculates the ring used to generate the vbucket configurations.  The
  /// ring essentially maps each vbucket slot to a particular node which is
  /// the primary location for data records whose key hashes to that vbucket.
  /// secondary and subsequent replicas are decided by walking around the ring.
  class Ring
  {
  public:
    Ring(int slots);
    ~Ring();

    // Updates the ring to include the specified number of nodes.
    void update(int nodes);

    // Gets the list of replica nodes for the specified slot in the ring.
    // The nodes are guaranteed to be unique if replicas <= nodes, but
    // not otherwise.
    std::vector<int> get_nodes(int slot, int replicas);

  private:

    // Assigns the slot to the specified node.
    void assign_slot(int slot, int node);

    // Finds the nth slot owned by the node.
    int owned_slot(int node, int number);

    // The number of slots in the ring.
    int _slots;

    // The number of nodes currently assigned slots from the ring.
    int _nodes;

    // This is the master ring.
    std::vector<int> _ring;

    // Tracks which slots in the ring each node is assigned.  Indexing is by
    // node, then an ordered map of the assigned slots.
    std::vector<std::map<int, int> > _node_slots;
  };

  // The number of replicas required normally.  During scale-up/down periods
  // some vbuckets may have more read and/or write replicas to maintain
  // redundancy.
  int _replicas;

  // The number of vbuckets being used.
  int _vbuckets;

  // The full list of servers in the memcached cluster.
  std::vector<std::string> _servers;

  // The read and write replica sets for each vbucket.  The first index is the
  // vbucket number.  In stable configurations the read and write set for each
  // vbucket will be the same and have exactly _replicas entries in each.  In
  // unstable configurations (scale-up/scale-down) additional read and write
  // replicas are enabled to maintain redundancy.
  std::vector<std::vector<int> > _read_set;
  std::vector<std::vector<int> > _write_set;
};

#endif
