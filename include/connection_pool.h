/**
 * @file connection_pool.h Class for maintaining a SIP connection pool.
 *
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by post at
 * Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 */

///

#ifndef CONNECTION_POOL_H__
#define CONNECTION_POOL_H__

extern "C" {
#include <pjsip.h>
}

#include <vector>
#include <map>
#include <string>
#include <random>

#include "statistic.h"

class ConnectionPool
{
public:
  ConnectionPool(pjsip_host_port* target,
                 int num_connections,
                 int recycle_period,
                 pj_pool_t* pool,
                 pjsip_endpoint* endpt,
                 pjsip_tpfactory* tp_factory);
  ~ConnectionPool();

  void init();

  pjsip_transport* get_connection();

  // Callback static function passed to PJSIP
  static void transport_state(pjsip_transport* tp,
                              pjsip_transport_state state,
                              const pjsip_transport_state_info* info);

  // Thread entry point for recycling connections.
  static int recycle_thread(void* p);

private:
  pj_status_t resolve_host(const pj_str_t* host, pj_sockaddr* addr);
  pj_status_t create_connection(int hash_slot);
  void quiesce_connection(int hash_slot);
  void quiesce_connections();
  void transport_state_update(pjsip_transport* tp, pjsip_transport_state state);
  void recycle_connections();
  void report_sprout_counts();
  void increment_connection_count(pjsip_transport *);
  void decrement_connection_count(pjsip_transport *);

  pjsip_host_port _target;
  int _num_connections;
  int _recycle_period;
  pj_pool_t* _pool;
  pjsip_endpoint* _endpt;
  pjsip_tpfactory* _tpfactory;

  pj_thread_t* _recycler;
  volatile bool _terminated;

  /// Number of active connections in the hash.
  int _active_connections;

  /// Structure to keep track of the connection in a slot in the hash.  tp
  /// is set as soon as the connection is started, but state is disconnected
  /// until we get a notification from PJSIP that the connection is connected.
  typedef struct tp_hash_slot
  {
    pjsip_transport* tp;
    pjsip_transport_state state;
  } tp_hash_slot;

  pthread_mutex_t _tp_hash_lock;
  std::vector<tp_hash_slot> _tp_hash;
  std::map<pjsip_transport*, int> _tp_map;

  // Statistics
  Statistic _statistic;
  std::map<std::string, int> _host_conn_count;
};

#endif // CONNECTION_POOL_H__
