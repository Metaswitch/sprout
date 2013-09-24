/**
 * @file memcachedstoreview.cpp Class tracking current view of memcached server cluster
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


// Common STL includes.
#include <cassert>
#include <vector>
#include <map>
#include <list>
#include <string>
#include <sstream>
#include <iomanip>

#include "log.h"
#include "memcachedstoreview.h"

namespace RegData {


MemcachedStoreView::MemcachedStoreView(int vbuckets, int replicas) :
  _replicas(replicas),
  _vbuckets(vbuckets),
  _vbucket_map()
{
  _vbucket_map.resize(_replicas);
  for (int ii = 0; ii < _replicas; ++ii)
  {
    _vbucket_map[ii].resize(_vbuckets);
  }
}


MemcachedStoreView::~MemcachedStoreView()
{
}


/// Updates the view for new current and target server lists.
void MemcachedStoreView::update(const std::list<std::string>& servers,
                                const std::list<std::string>& new_servers)
{
  // Generate the appropriate rings and the resulting vbuckets arrays.
  if (new_servers.empty())
  {
    // Stable configuration.
    LOG_DEBUG("View is stable with %d nodes", servers.size());
    _servers = servers.size();
    _server_list = servers;

    // Only need to generate a single ring.
    Ring ring(_vbuckets);
    ring.update(_servers);

    // Generate the vbuckets arrays from the rings.
    for (int ii = 0; ii < _vbuckets; ++ii)
    {
      std::vector<int> nodes = ring.get_nodes(ii, _replicas);
      for (int jj = 0; jj < _replicas; ++jj)
      {
        _vbucket_map[jj][ii] = nodes[jj];
      }
    }
  }
  else
  {
    // Either growing or shrinking the cluster
    if (servers.size() > new_servers.size())
    {
      // Shrinking the cluster, so use the current server list.
      LOG_DEBUG("Cluster is shrinking from %d nodes to %d nodes", servers.size(), new_servers.size());
      _servers = servers.size();
      _server_list = servers;
    }
    else
    {
      // Growing the cluster, so use the new server list.
      LOG_DEBUG("Cluster is growing from %d nodes to %d nodes", servers.size(), new_servers.size());
      _servers = new_servers.size();
      _server_list = new_servers;
    }

    // Calculate the two rings needed to generate the vbuckets.
    Ring c_ring(_vbuckets);
    c_ring.update(servers.size());
    Ring n_ring(_vbuckets);
    n_ring.update(new_servers.size());

    for (int ii = 0; ii < _vbuckets; ++ii)
    {
      // Calculate the replica sets for this bucket for both current and
      // target node sets.  (Replica set means the ordered list of nodes on
      // which data is stored for records that hash to the vbucket.)
      std::vector<int> c_nodes = c_ring.get_nodes(ii, _replicas);
      std::vector<int> n_nodes = n_ring.get_nodes(ii, _replicas);

      // Set the primary vbucket to the second node in the current replica set.
      // This ensures most reads will complete successfully on the first
      // server, while still maintaining redundancy by ensure the first
      // two replicas are on different servers.
      _vbucket_map[0][ii] = c_nodes[1];

      // Set the second and subsequent replica vbuckets to the first _replicas-1
      // nodes in the new replica set.  This ensures that immediately after
      // the subsequent switch to a stable configuration the top _replicas-1
      // nodes should have the right data.
      for (int jj = 1; jj < _replicas; ++jj)
      {
        _vbucket_map[jj][ii] = n_nodes[jj - 1];
      }

      if ((servers.size() == 1) &&
          (_vbucket_map[1][ii] == 0))
      {
        // As a special case when growing a cluster of one node, if the
        //
        // this code it is possible to have the same node as both of the first
        // two replicas for this vbucket.  To avoid this loss of redundancy
        // We use the second node from the replica set instead.
        // For example, with two replicas, the one node ring results in every
        // slot having (0,0) as the primary and secondary replicas, and the two
        // node ring has half of the slots with (0,1) and half with (1,0).
        // Without this special case, during the growth stage half of the
        // slots would end up with (0,0), so no redundancy.  With the change
        // each slot uses (0,1) during the growth phase.
        _vbucket_map[1][ii] = n_nodes[1];
      }
    }
  }

  for (size_t ii = 0; ii < _vbucket_map.size(); ++ii)
  {
    LOG_DEBUG("Replica %d vbucket : %s", ii, vbucket_to_string(_vbucket_map[ii]).c_str());
  }
}


/// Converts a vbucket map to a printable string.
std::string MemcachedStoreView::vbucket_to_string(std::vector<int> vbucket_map)
{
  std::ostringstream oss;

  for (size_t ii = 0; ii < vbucket_map.size() - 1; ++ii)
  {
    oss << std::setw(3) << std::dec << vbucket_map[ii] << " ";
  }
  oss << std::setw(3) << std::dec << vbucket_map[vbucket_map.size() - 1];

  return oss.str();
}


/// Constructs a ring used to assign vbuckets to nodes.
MemcachedStoreView::Ring::Ring(int slots) :
  _slots(slots),
  _nodes(0),
  _ring(slots),
  _node_slots()
{
  LOG_DEBUG("Initializing ring with %d slots", slots);
}


MemcachedStoreView::Ring::~Ring()
{
}


/// Updates the ring to have the specified number of nodes.  This is done
/// incrementally starting from the current number of nodes and reassigning
/// buckets to new nodes one by one.  This algorithm ensures that as the size
/// of the ring increases, slots are either left alone or assigned to new nodes
/// - never assigned to existing nodes.  This property is important for
/// maintaining redundancy as the cluster grows.
///
/// Unfortunately we can't current see how to run the algorithm in reverse,
/// so if the number of nodes reduces the ring must be destroyed and recreated.
void MemcachedStoreView::Ring::update(int nodes)
{
  LOG_DEBUG("Updating ring from %d to %d nodes", _nodes, nodes);

  _node_slots.resize(nodes);

  if (_nodes == 0)
  {
    // Set up the initial ring for the one node case.
    LOG_DEBUG("Set up ring for node 0");
    for (int i = 0; i < _slots; ++i)
    {
      _ring[i] = -1;
      assign_slot(i, 0);
    }
    _nodes = 1;
  }

  while (_nodes < nodes)
  {
    // Increasing the number of nodes, so reassign slots from existing nodes
    // to the next new node.  By choosing the first slot assigned to the
    // most heavily loaded node, then the second slot assigned to the
    // next most heavily loaded, anon.
    int replace_slots = _slots/(_nodes+1);

    for (int i = 0; i < replace_slots; ++i)
    {
      // Find the node which will be replaced, by finding the node with the
      // most assigned slots.  Ties are broken in favour of the highest numbered
      // node.
      int replace_node = 0;
      for (int node = 1; node < _nodes; ++node)
      {
        if (_node_slots[node].size() >= _node_slots[replace_node].size())
        {
          replace_node = node;
        }
      }

      // Now replace the appropriate slot assignment.  (For the first
      int slot = owned_slot(replace_node, i);
      assign_slot(slot, _nodes);
    }

    _nodes += 1;
  }

  LOG_DEBUG("Completed updating ring, now contains %d nodes", _nodes);
}


/// Gets the set of nodes that should be used to store a number of replicas
/// of data where the record key hashes to the appropriate slot in the ring.
/// This is done by starting at the slot, and returning the first n unique
/// nodes walking around the ring.  If there are not enough unique nodes,
/// remaining replica slots are filled with the first node.
std::vector<int> MemcachedStoreView::Ring::get_nodes(int slot, int replicas)
{
  std::vector<int> node_list;
  node_list.reserve(replicas);

  int next_slot = slot;

  while (node_list.size() < (size_t)std::min(replicas, _nodes))
  {
    bool unique = true;

    // Check that the next node in the ring isn't already in the node list.
    for (size_t i = 0; i < node_list.size(); ++i)
    {
      if (node_list[i] == _ring[next_slot])
      {
        // Found the node in the list, so break out and move to the next one.
        unique = false;
        break;
      }
    }

    if (unique)
    {
      // Found a node that is not already in the list, so add it.
      node_list.push_back(_ring[next_slot]);
    }
    next_slot = (next_slot + 1) % _slots;
  }

  while (node_list.size() < (size_t)replicas)
  {
    // Must not be enough nodes for the level of replication requested, so
    // just fill remaining slots with the first node assigned to this slot.
    node_list.push_back(_ring[slot]);
  }

  return node_list;
}


/// Assigns the specified slot to the specified node.  This also keeps the
/// _node_slots maps in sync.
void MemcachedStoreView::Ring::assign_slot(int slot, int node)
{
  int old_node = _ring[slot];
  if (old_node != -1)
  {
    std::map<int, int>::iterator i = _node_slots[old_node].find(slot);
    assert(i != _node_slots[node].end());
    _node_slots[old_node].erase(i);
  }
  _ring[slot] = node;
  _node_slots[node][slot] = slot;
}


/// Returns the nth slot owned by the specified node.  If n is greater
/// than the number of slots owned by the node, return the nth slot modulo
/// the total number of owned slots.
int MemcachedStoreView::Ring::owned_slot(int node, int number)
{
  number = number % _node_slots[node].size();

  std::map<int,int>::const_iterator i;
  int j;
  for (i = _node_slots[node].begin(), j = 0;
       j < number;
       ++i, ++j)
  {
  }

  return i->second;
}


} // namespace RegData
