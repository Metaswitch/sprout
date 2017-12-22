/**
 * @file sip_connection_pool.cpp
 *
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}
#include <unistd.h>

// Common STL includes.
#include <cassert>
#include <string>

#include "log.h"
#include "utils.h"
#include "pjutils.h"
#include "sip_connection_pool.h"

SIPConnectionPool::SIPConnectionPool(pjsip_host_port* target,
                               int num_connections,
                               int recycle_period,
                               pj_pool_t* pool,
                               pjsip_endpoint* endpt,
                               pjsip_tpfactory* tp_factory,
                               SNMP::IPCountTable* sprout_count_tbl) :
  _target(*target),
  _num_connections(num_connections),
  _recycle_period(recycle_period),
  _recycle_margin((recycle_period * RECYCLE_RANDOM_MARGIN)/100),
  _pool(pool),
  _endpt(endpt),
  _tpfactory(tp_factory),
  _recycler(NULL),
  _terminated(false),
  _active_connections(0),
  _sprout_count_tbl(sprout_count_tbl)
{
  TRC_STATUS("Creating connection pool to %.*s:%d", _target.host.slen, _target.host.ptr, _target.port);
  TRC_STATUS("  connections = %d, recycle time = %d +/- %d seconds", _num_connections, _recycle_period, _recycle_margin);

  pthread_mutex_init(&_tp_hash_lock, NULL);
  _tp_hash.resize(_num_connections);
}


SIPConnectionPool::~SIPConnectionPool()
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


void SIPConnectionPool::init()
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
      TRC_ERROR("Error creating recycler thread, %s",
                PJUtils::pj_status_to_string(status).c_str());
    }
  }

  TRC_DEBUG("Started %d connections to %.*s:%d", _num_connections, _target.host.slen, _target.host.ptr, _target.port);
}


pjsip_transport* SIPConnectionPool::get_connection()
{
  pjsip_transport* tp = NULL;

  pthread_mutex_lock(&_tp_hash_lock);

  if (_active_connections > 0)
  {
    // Select a transport by starting at a random point in the hash and
    // stepping through the hash until a connected entry is found.
    int start_slot = rand() % _num_connections;
    int ii = start_slot;
    while (!_tp_hash[ii].connected)
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


pj_status_t SIPConnectionPool::resolve_host(const pj_str_t* host,
                                            int port,
                                            pj_sockaddr* addr)
{
  pj_status_t status = PJ_ENOTFOUND;

  // Select a server for this connection.
  std::vector<AddrInfo> servers;
  PJUtils::resolve(std::string(host->ptr, host->slen),
                   port,
                   IPPROTO_TCP,
                   1,
                   servers,
                   BaseResolver::ALL_LISTS);
  memset(addr, 0, sizeof(pj_sockaddr));

  if (!servers.empty())
  {
    if (servers[0].address.af == AF_INET)
    {
      TRC_DEBUG("Successfully resolved %.*s to IPv4 address", host->slen, host->ptr);
      addr->ipv4.sin_family = AF_INET;
      addr->ipv4.sin_addr.s_addr = servers[0].address.addr.ipv4.s_addr;
      pj_sockaddr_set_port(addr, servers[0].port);
      status = PJ_SUCCESS;
    }
    else if (servers[0].address.af == AF_INET6)
    {
      TRC_DEBUG("Successfully resolved %.*s to IPv6 address", host->slen, host->ptr);
      addr->ipv6.sin6_family = AF_INET6;
      memcpy((char*)&addr->ipv6.sin6_addr,
             (char*)&servers[0].address.addr.ipv6,
             sizeof(struct in6_addr));
      pj_sockaddr_set_port(addr, servers[0].port);
      status = PJ_SUCCESS;
    }
    else
    {
      TRC_ERROR("Resolved %.*s to address of unknown family %d - failing connection!", host->slen, host->ptr); //LCOV_EXCL_LINE
    }
  }

  return status;
}


pj_status_t SIPConnectionPool::create_connection(int hash_slot)
{
  // Resolve the target host to an IP address.
  pj_sockaddr remote_addr;
  pj_status_t status = resolve_host(&_target.host, _target.port, &remote_addr);

  if (status != PJ_SUCCESS)
  {
    TRC_ERROR("Failed to resolve %.*s to an IP address - %s",
              _target.host.slen, _target.host.ptr,
              PJUtils::pj_status_to_string(status).c_str());
    return status;
  }

  // Call TPMGR to create a new transport connection.
  pjsip_transport* tp;
  pjsip_tpselector tp_sel;
  tp_sel.type = PJSIP_TPSELECTOR_LISTENER;
  tp_sel.u.listener = _tpfactory;
  status = pjsip_tpmgr_acquire_transport(pjsip_endpt_get_tpmgr(_endpt),
                                         (remote_addr.addr.sa_family == pj_AF_INET6()) ?
                                           PJSIP_TRANSPORT_TCP6 : PJSIP_TRANSPORT_TCP,
                                         &remote_addr,
                                         (remote_addr.addr.sa_family == pj_AF_INET6()) ?
                                           sizeof(pj_sockaddr_in6) : sizeof(pj_sockaddr_in),
                                         &tp_sel,
                                         &tp);

  if (status != PJ_SUCCESS)
  {
    return status;
  }

  // TPMGR will have already added a reference to the new transport to stop it
  // being destroyed while we have pointers referencing it.

  TRC_DEBUG("Created transport %s in slot %d (%.*s:%d to %.*s:%d)",
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

  if (status != PJ_SUCCESS)
  {
    return status;
  }

  // Store the new transport in the hash slot, but marked as disconnected.
  pthread_mutex_lock(&_tp_hash_lock);
  _tp_hash[hash_slot].tp = tp;
  _tp_hash[hash_slot].listener_key = key;
  _tp_hash[hash_slot].connected = PJ_FALSE;
  _tp_map[tp] = hash_slot;

  // Don't increment the connection count here, wait until we get confirmation
  // that the transport is connected.

  pthread_mutex_unlock(&_tp_hash_lock);

  return PJ_SUCCESS;
}


void SIPConnectionPool::quiesce_connection(int hash_slot)
{
  pthread_mutex_lock(&_tp_hash_lock);
  pjsip_transport* tp = _tp_hash[hash_slot].tp;

  if (tp != NULL)
  {
    if (_tp_hash[hash_slot].connected)
    {
      // Connection was established, so update statistics.
      --_active_connections;
      decrement_connection_count(tp);
    }

    // Don't listen for any more state changes on this connection.
    pjsip_transport_remove_state_listener(tp,
                                          _tp_hash[hash_slot].listener_key,
                                          (void *)this);

    // Remove the transport from the hash and the map.
    _tp_hash[hash_slot].tp = NULL;
    _tp_hash[hash_slot].listener_key = NULL;
    _tp_hash[hash_slot].connected = PJ_FALSE;
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


void SIPConnectionPool::quiesce_connections()
{
  for (int ii = 0; ii < _num_connections; ii++)
  {
    quiesce_connection(ii);
  }
}


void SIPConnectionPool::transport_state_update(pjsip_transport* tp, pjsip_transport_state state)
{
  // Transport state has changed.
  pthread_mutex_lock(&_tp_hash_lock);

  std::map<pjsip_transport*, int>::const_iterator i = _tp_map.find(tp);

  if (i != _tp_map.end())
  {
    int hash_slot = i->second;

    if ((state == PJSIP_TP_STATE_CONNECTED) && (!_tp_hash[hash_slot].connected))
    {
      // New connection has connected successfully, so update the statistics.
      TRC_DEBUG("Transport %s in slot %d has connected", tp->obj_name, hash_slot);
      _tp_hash[hash_slot].connected = PJ_TRUE;
      ++_active_connections;
      increment_connection_count(tp);

      if (_recycle_period > 0)
      {
        // Compute a TTL for the connection.  To avoid all the recycling being
        // synchronized we set the TTL to the specified average recycle time
        // perturbed by a random factor.
        int ttl = _recycle_period + (rand() % (2 * _recycle_margin)) - _recycle_margin;
        _tp_hash[hash_slot].recycle_time = time(NULL) + ttl;
      }
      else
      {
        // Connection recycling is disabled.
        _tp_hash[hash_slot].recycle_time = 0;
      }
    }
    else if ((state == PJSIP_TP_STATE_DISCONNECTED) ||
             (state == PJSIP_TP_STATE_DESTROYED))
    {
      // Either a connection has failed or been shutdown, or a new connection
      // failed to connect.
      TRC_DEBUG("Transport %s in slot %d has failed", tp->obj_name, hash_slot);

      if (_tp_hash[hash_slot].connected)
      {
        // A connection has failed, so update the statistics.
        --_active_connections;
        decrement_connection_count(tp);
      }
      else
      {
        // Failed to establish a connection to this server, so blacklist
        // it so we steer clear of it for a while.  We don't blacklist
        // if an existing connection fails as this may be a transient error
        // or even a disconnect triggered by an inactivity timeout .
        AddrInfo server;
        server.transport = IPPROTO_TCP;
        server.port = pj_sockaddr_get_port(&tp->key.rem_addr);
        server.address.af = tp->key.rem_addr.addr.sa_family;
        if (server.address.af == AF_INET)
        {
          server.address.addr.ipv4.s_addr = tp->key.rem_addr.ipv4.sin_addr.s_addr;
        }
        else
        {
          memcpy((char*)&server.address.addr.ipv6,
                 (char*)&tp->key.rem_addr.ipv6.sin6_addr,
                 sizeof(struct in6_addr));
        }
        PJUtils::blacklist(server);
      }

      // Don't listen for any more state changes on this connection (but note
      // it's illegal to call any methods on the transport once it's entered the
      // `destroyed` state).
      if (state != PJSIP_TP_STATE_DESTROYED)
      {
        pjsip_transport_remove_state_listener(tp,
                                              _tp_hash[hash_slot].listener_key,
                                              (void *)this);
      }

      // Remove the transport from the hash and the map.
      _tp_hash[hash_slot].tp = NULL;
      _tp_hash[hash_slot].listener_key = NULL;
      _tp_hash[hash_slot].connected = PJ_FALSE;
      _tp_map.erase(tp);

      // Remove our reference to the transport.
      pjsip_transport_dec_ref(tp);
    }
  }

  pthread_mutex_unlock(&_tp_hash_lock);
}


void SIPConnectionPool::recycle_connections()
{
  // The recycler periodically recycles the connections so that any new nodes
  // in the upstream proxy cluster get used reasonably soon after they are
  // active.  To avoid mucking around with variable length waits, the
  // algorithm waits for a fixed period (one second) then recycles connections
  // that are due to be recycled.

  while (!_terminated)
  {
#ifndef UNIT_TEST
    sleep(1);
#endif

    int now = time(NULL);

    // Walk the vector of connections.  This is safe to do without the lock
    // because the vector is immutable.
    for (size_t ii = 0; ii < _tp_hash.size(); ++ii)
    {
      if (_tp_hash[ii].tp == NULL)
      {
        // This slot is empty, so try to populate it now.
        create_connection(ii);
      }
      else if ((_tp_hash[ii].connected) &&
               (_tp_hash[ii].recycle_time != 0) &&
               (now >= _tp_hash[ii].recycle_time))
      {
        // This slot is due to be recycled, so quiesce the existing
        // connection and create a new one.
        TRC_STATUS("Recycle TCP connection slot %d", ii);
        quiesce_connection(ii);
        create_connection(ii);
      }
    }
  }
}


void SIPConnectionPool::transport_state(pjsip_transport* tp, pjsip_transport_state state, const pjsip_transport_state_info* info)
{
  ((SIPConnectionPool*)info->user_data)->transport_state_update(tp, state);
}


int SIPConnectionPool::recycle_thread(void* p)
{
  ((SIPConnectionPool*)p)->recycle_connections();
  return 0;
}

void SIPConnectionPool::decrement_connection_count(pjsip_transport *trans)
{
  std::string host = PJUtils::pj_str_to_string(&trans->remote_name.host);
  if (_sprout_count_tbl->get(host)->decrement() == 0)
  {
    _sprout_count_tbl->remove(host);
  }
}


void SIPConnectionPool::increment_connection_count(pjsip_transport *trans)
{
  std::string host = PJUtils::pj_str_to_string(&trans->remote_name.host);
  _sprout_count_tbl->get(host)->increment();
}
