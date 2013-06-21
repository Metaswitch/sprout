/**
 * @file connection_pool.cpp
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

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

// Common STL includes.
#include <cassert>
#include <string>

#include "log.h"
#include "pjutils.h"
#include "connection_pool.h"


ConnectionPool::ConnectionPool(pjsip_host_port* target,
                               int num_connections,
                               int recycle_period,
                               pj_pool_t* pool,
                               pjsip_endpoint* endpt,
                               pjsip_tpfactory* tp_factory) :
  _target(*target),
  _num_connections(num_connections),
  _recycle_period(recycle_period),
  _pool(pool),
  _endpt(endpt),
  _tpfactory(tp_factory),
  _recycler(NULL),
  _terminated(false),
  _active_connections(0),
  _statistic("connected_sprouts")
{
  LOG_STATUS("Creating connection pool to %.*s:%d", _target.host.slen, _target.host.ptr, _target.port);
  LOG_STATUS("  connections = %d, recycle time = %d seconds", _num_connections, _recycle_period);

  pthread_mutex_init(&_tp_hash_lock, NULL);
  _tp_hash.resize(_num_connections);

  report_sprout_counts();
}


ConnectionPool::~ConnectionPool()
{
  if (_recycler)
  {
    // Set the terminated flag to signal the recycler thread to exit.
    _terminated = true;

    // Wait for the recycler thread to exit.
    pj_thread_join(_recycler);
  }

  // Quiesce all the connections.
  quiesce_connections();
}


void ConnectionPool::init()
{
  // Create an initial set of connections.
  for (int ii = 0; ii < _num_connections; ++ii)
  {
    create_connection(ii);
  }

  if (_recycle_period != 0)
  {
    // Spawn a thread to recycle connections
    pj_status_t status = pj_thread_create(_pool, "recycler",
                                          &recycle_thread,
                                          (void*)this, 0, 0, &_recycler);
    if (status != PJ_SUCCESS)
    {
      LOG_ERROR("Error creating recycler thread, %s",
                PJUtils::pj_status_to_string(status).c_str());
    }
  }

  LOG_DEBUG("Started %d connections to %.*s:%d", _num_connections, _target.host.slen, _target.host.ptr, _target.port);
}


pjsip_transport* ConnectionPool::get_connection()
{
  pjsip_transport* tp = NULL;

  pthread_mutex_lock(&_tp_hash_lock);

  if (_active_connections > 0)
  {
    // Select a transport by starting at a random point in the hash and
    // stepping through the hash until a connected entry is found.
    int start_slot = rand() % _num_connections;
    int ii = start_slot;
    while (_tp_hash[ii].state == PJSIP_TP_STATE_DISCONNECTED)
    {
      ii = (ii + 1) % _num_connections;
      if (ii == start_slot)
      {
        break;
      }
    }

    tp = _tp_hash[ii].tp;

    if (tp != NULL)
    {
      // Add a reference to the transport to make sure it is not destroyed.
      // The reference must be decremented once again when the transport is set
      // on the message.
      pjsip_transport_add_ref(tp);
    }
  }

  pthread_mutex_unlock(&_tp_hash_lock);

  return tp;
}


pj_status_t ConnectionPool::resolve_host(const pj_str_t* host, pj_sockaddr* addr)
{
  pj_addrinfo ai[PJ_MAX_HOSTNAME];
  unsigned count;
  int af = pj_AF_INET();

  // Use pj_getaddrinfo to resolve the upstream proxy host name to a set of
  // IP addresses.  Note that PJ_MAX_HOSTNAME is the maximum number of entried
  // PJSIP can return - if we decide we need more we will need to change this
  // in the PJSIP code.  Note also that there may be theoretical limits in
  // DNS anyway.
  count = PJ_MAX_HOSTNAME;
  pj_status_t status = pj_getaddrinfo(af, host, &count, ai);
  if (status != PJ_SUCCESS)
  {
    return status;
  }

  // Select an A record at random.
  int selection = rand() % count;

  pj_memcpy(addr, &ai[selection].ai_addr, sizeof(pj_sockaddr));

  return PJ_SUCCESS;
}


pj_status_t ConnectionPool::create_connection(int hash_slot)
{
  // Resolve the target host to an IP address.
  pj_sockaddr remote_addr;
  pj_status_t status = resolve_host(&_target.host, &remote_addr);

  if (status != PJ_SUCCESS)
  {
    LOG_ERROR("Failed to resolve %.*s to an IP address - %s",
              _target.host.slen, _target.host.ptr,
              PJUtils::pj_status_to_string(status).c_str());
    return status;
  }

  pj_sockaddr_set_port(&remote_addr, _target.port);

  // Call TPMGR to create a new transport connection.
  pjsip_transport* tp;
  pjsip_tpselector tp_sel;
  tp_sel.type = PJSIP_TPSELECTOR_LISTENER;
  tp_sel.u.listener = _tpfactory;
  status = pjsip_tpmgr_acquire_transport(pjsip_endpt_get_tpmgr(_endpt),
                                         PJSIP_TRANSPORT_TCP,
                                         &remote_addr,
                                         sizeof(pj_sockaddr_in),
                                         &tp_sel,
                                         &tp);

  if (status != PJ_SUCCESS)
  {
    return status;
  }

  // TPMGR will have already added a reference to the new transport to stop it
  // being destroyed while we have pointers referencing it.

  LOG_DEBUG("Created transport %s in slot %d (%.*s:%d to %.*s:%d)",
            tp->obj_name,
            hash_slot,
            (int)tp->local_name.host.slen,
            tp->local_name.host.ptr,
            tp->local_name.port,
            (int)tp->remote_name.host.slen,
            tp->remote_name.host.ptr,
            tp->remote_name.port);

  // Register for transport state callbacks.
  pjsip_tp_state_listener_key* key;
  status = pjsip_transport_add_state_listener(tp, &transport_state, (void*)this, &key);

  // Store the new transport in the hash slot, but marked as disconnected.
  pthread_mutex_lock(&_tp_hash_lock);
  _tp_hash[hash_slot].tp = tp;
  _tp_hash[hash_slot].state = PJSIP_TP_STATE_DISCONNECTED;
  _tp_map[tp] = hash_slot;

  // Don't increment the connection count here, wait until we get confirmation
  // that the transport is connected.

  pthread_mutex_unlock(&_tp_hash_lock);

  return PJ_SUCCESS;
}


void ConnectionPool::quiesce_connection(int hash_slot)
{
  pthread_mutex_lock(&_tp_hash_lock);
  pjsip_transport* tp = _tp_hash[hash_slot].tp;

  if (tp != NULL)
  {
    if (_tp_hash[hash_slot].state == PJSIP_TP_STATE_CONNECTED)
    {
      // Connection was established, so update statistics.
      --_active_connections;
      decrement_connection_count(tp);
    }

    // Remove the transport from the hash and the map.
    _tp_hash[hash_slot].tp = NULL;
    _tp_hash[hash_slot].state = PJSIP_TP_STATE_DISCONNECTED;
    _tp_map.erase(tp);

    // Release the lock now so we don't have a deadlock if pjsip_transport_shutdown
    // calls the transport state listener.
    pthread_mutex_unlock(&_tp_hash_lock);

    // Quiesce the transport.  PJSIP will destroy the transport when there
    // are no further references to it.
    pjsip_transport_shutdown(tp);

    // Remove our reference to the transport.
    pjsip_transport_dec_ref(tp);
  }
  else
  {
    pthread_mutex_unlock(&_tp_hash_lock);
  }
}


void ConnectionPool::quiesce_connections()
{
  for (int ii = 0; ii < _num_connections; ii++)
  {
    quiesce_connection(ii);
  }
}


void ConnectionPool::transport_state_update(pjsip_transport* tp, pjsip_transport_state state)
{
  // Transport state has changed.
  pthread_mutex_lock(&_tp_hash_lock);

  std::map<pjsip_transport*, int>::const_iterator i = _tp_map.find(tp);

  if (i != _tp_map.end())
  {
    int hash_slot = i->second;

    if ((state == PJSIP_TP_STATE_CONNECTED) &&
        (_tp_hash[hash_slot].state == PJSIP_TP_STATE_DISCONNECTED))
    {
      // New connection has connected successfully, so update the statistics.
      LOG_DEBUG("Transport %s in slot %d has connected", tp->obj_name, hash_slot);
      _tp_hash[hash_slot].state = state;
      ++_active_connections;
      increment_connection_count(tp);
    }
    else if (state == PJSIP_TP_STATE_DISCONNECTED)
    {
      // Either a connection has failed, or a new connection failed to
      // connect.
      LOG_DEBUG("Transport %s in slot %d has failed", tp->obj_name, hash_slot);

      if (_tp_hash[hash_slot].state == PJSIP_TP_STATE_CONNECTED)
      {
        // A connection has failed, so update the statistics.
        --_active_connections;
        decrement_connection_count(tp);
      }

      // Remove the transport from the hash and the map.
      _tp_hash[hash_slot].tp = NULL;
      _tp_hash[hash_slot].state = PJSIP_TP_STATE_DISCONNECTED;
      _tp_map.erase(tp);

      // Remove our reference to the transport.
      pjsip_transport_dec_ref(tp);
    }
  }

  pthread_mutex_unlock(&_tp_hash_lock);
}


void ConnectionPool::recycle_connections()
{
  // The recycler periodically recycles the connections so that any new nodes
  // in the upstream proxy cluster get used reasonably soon after they are
  // active.  To avoid mucking around with variable length waits, the
  // algorithm waits for a fixed period (one second) then recycles a
  // number of connections.
  //
  // Logically the algorithm runs an independent trial for each hash slot
  // with a success probability of (1/_recycle_period).  For efficiency this
  // is implemented by using a binomially distributed random number to find
  // the number of successful trials, then selecting that number of hash slots
  // at random.
  //
  // Currently the selection is done with replacement which raises the possibility
  // that one connection may be recycled twice in the same schedule, but this
  // should only introduce a small error in the recycling rate.

  std::default_random_engine rand;
  std::binomial_distribution<int> rbinomial(_num_connections, 1.0/_recycle_period);

  while (!_terminated)
  {
    sleep(1);

    int recycle = rbinomial(rand);

    LOG_INFO("Recycling %d connections to %.*s:%d", recycle, _target.host.slen, _target.host.ptr, _target.port);

    for (int ii = 0; ii < recycle; ++ii)
    {
      // Pick a hash slot at random, and quiesce the connection (if active).
      int hash_slot = rand() % _num_connections;
      quiesce_connection(hash_slot);

      // Create a new connection for this hash slot.
      create_connection(hash_slot);
    }

    int index = 0;

    // Walk the hash table, attempting to fill in any gaps caused by transports failing.
    //
    // It is safe to walk the vector without the lock since:
    //
    //  * The vector never changes size
    //  * We only care about the value of the entry being NULL (atomic check)
    //  * Only we can change a NULL value to a non-NULL value
    //  * If we just miss a change from non-NULL to NULL (a transport suddenly dies), we'll catch it in a second.
    for (std::vector<tp_hash_slot>::iterator it = _tp_hash.begin();
         it != _tp_hash.end();
         ++it)
    {
      if (it->tp == NULL)
      {
        create_connection(index);
      }
      index++;
    }
  }
}


void ConnectionPool::transport_state(pjsip_transport* tp, pjsip_transport_state state, const pjsip_transport_state_info* info)
{
  ((ConnectionPool*)info->user_data)->transport_state_update(tp, state);
}


int ConnectionPool::recycle_thread(void* p)
{
  ((ConnectionPool*)p)->recycle_connections();
  return 0;
}


void ConnectionPool::report_sprout_counts()
{
  std::map<std::string, int>::iterator it = _host_conn_count.begin();
  std::vector<std::string> reported_value;
  for (; it != _host_conn_count.end(); ++it)
  {
    std::string host = it->first;
    std::string connection_count = std::to_string(it->second);
    LOG_DEBUG("Reporting %s:%s", host.c_str(), connection_count.c_str());
    reported_value.push_back(host);
    reported_value.push_back(connection_count);
  }
  _statistic.report_change(reported_value);
}


void ConnectionPool::decrement_connection_count(pjsip_transport *trans)
{
  std::string host = PJUtils::pj_str_to_string(&trans->remote_name.host);
  assert(_host_conn_count.find(host) != _host_conn_count.end());

  if (_host_conn_count[host] == 1)
  {
    _host_conn_count.erase(host);
  }
  else
  {
    --_host_conn_count[host];
  }

  report_sprout_counts();
}


void ConnectionPool::increment_connection_count(pjsip_transport *trans)
{
  std::string hostname = PJUtils::pj_str_to_string(&trans->remote_name.host);
  if (_host_conn_count.find(hostname) == _host_conn_count.end())
  {
    // This is the first connection to this remote host, create an entry now.
    _host_conn_count[hostname] = 1;
  }
  else
  {
    ++_host_conn_count[hostname];
  }

  report_sprout_counts();
}
