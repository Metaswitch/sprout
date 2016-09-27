/**
 * @file sip_connection_pool.h Class for maintaining a SIP connection pool.
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

#ifndef SIP_CONNECTION_POOL_H__
#define SIP_CONNECTION_POOL_H__

extern "C" {
#include <pjsip.h>
}

#include <vector>
#include <map>
#include <string>
#include <random>

#include "snmp_ip_count_table.h"

class SIPConnectionPool
{
public:
  SIPConnectionPool(pjsip_host_port* target,
                 int num_connections,
                 int recycle_period,
                 pj_pool_t* pool,
                 pjsip_endpoint* endpt,
                 pjsip_tpfactory* tp_factory,
                 SNMP::IPCountTable* sprout_count_tbl);
  ~SIPConnectionPool();

  void init();

  pjsip_transport* get_connection();

  // Callback static function passed to PJSIP
  static void transport_state(pjsip_transport* tp,
                              pjsip_transport_state state,
                              const pjsip_transport_state_info* info);

  // Thread entry point for recycling connections.
  static int recycle_thread(void* p);

private:
  pj_status_t resolve_host(const pj_str_t* host, int port, pj_sockaddr* addr);
  pj_status_t create_connection(int hash_slot);
  void quiesce_connection(int hash_slot);
  void quiesce_connections();
  void transport_state_update(pjsip_transport* tp, pjsip_transport_state state);
  void recycle_connections();
  void increment_connection_count(pjsip_transport *);
  void decrement_connection_count(pjsip_transport *);

  pjsip_host_port _target;
  int _num_connections;

  // Connections are recycled on average every _recycle_period seconds, but
  // to avoid them all being synchronized, the time is perturbed by a margin
  // of 20% either side.
  static const int RECYCLE_RANDOM_MARGIN = 20;
  int _recycle_period;
  int _recycle_margin;

  pj_pool_t* _pool;
  pjsip_endpoint* _endpt;
  pjsip_tpfactory* _tpfactory;

  pj_thread_t* _recycler;
  volatile bool _terminated;

  /// Number of active connections in the hash.
  int _active_connections;

  /// Structure to keep track of the connection in a slot in the hash.  tp
  /// is set as soon as the connection is started, but it is disconnected
  /// until we get a notification from PJSIP that the connection is connected.
  typedef struct tp_hash_slot
  {
    pjsip_transport* tp;
    pjsip_tp_state_listener_key *listener_key;
    pj_bool_t connected;
    int recycle_time;
  } tp_hash_slot;

  pthread_mutex_t _tp_hash_lock;
  std::vector<tp_hash_slot> _tp_hash;
  std::map<pjsip_transport*, int> _tp_map;

  // Statistics
  SNMP::IPCountTable* _sprout_count_tbl;
};

#endif // CONNECTION_POOL_H__
