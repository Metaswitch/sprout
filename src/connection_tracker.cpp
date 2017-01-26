/**
 * @file connection_tracker.cpp
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

#include <cassert>

#include "log.h"
#include "utils.h"
#include "pjutils.h"
#include "connection_tracker.h"
#include "stack.h"

ConnectionTracker::ConnectionTracker(
                              ConnectionsQuiescedInterface *on_quiesced_handler)
:
  _connection_listeners(),
  _quiescing(PJ_FALSE),
  _on_quiesced_handler(on_quiesced_handler)
{
  // Lock has always been MUTEX_RECURSIVE
  pthread_mutexattr_t attrs;
  pthread_mutexattr_init(&attrs);
  pthread_mutexattr_settype(&attrs, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&_lock, &attrs);
  pthread_mutexattr_destroy(&attrs);
}


ConnectionTracker::~ConnectionTracker()
{
  for (std::map<pjsip_transport *, pjsip_tp_state_listener_key *>::iterator
                                             it = _connection_listeners.begin();
       it != _connection_listeners.end();
       ++it)
  {
    TRC_DEBUG("Stop listening on connection %p", it->first);
    pjsip_transport_remove_state_listener(it->first,
                                          it->second,
                                          (void *)this);
  }
  pthread_mutex_destroy(&_lock);
}


void ConnectionTracker::connection_state(pjsip_transport *tp,
                                         pjsip_transport_state state,
                                         const pjsip_transport_state_info *info)
{
  ((ConnectionTracker *)info->user_data)->connection_state_update(tp, state);
}


void ConnectionTracker::connection_state_update(pjsip_transport *tp,
                                                pjsip_transport_state state)
{
  pj_bool_t quiesce_complete = PJ_FALSE;

  if (state == PJSIP_TP_STATE_DESTROYED)
  {
    TRC_STATUS("Connection %p has been destroyed", tp);

    pthread_mutex_lock(&_lock);
    // We expect to only be called on the PJSIP transport thread, and our data
    // race/locking safety is based on this assumption. Raise an error log if
    // this is not the case.
    CHECK_PJ_TRANSPORT_THREAD();

    _connection_listeners.erase(tp);

    // If we're quiescing and there are no more active connections, then
    // quiescing is complete.
    if (_quiescing)
    {
      if (_connection_listeners.empty())
      {
        TRC_DEBUG("Connection quiescing complete");
        quiesce_complete = PJ_TRUE;
      }
      else
      {
        TRC_STATUS("Quiescing, %d more connections to destroy",
                   _connection_listeners.size());
      }
    }

    pthread_mutex_unlock(&_lock);

    // If quiescing is now complete notify the quiescing manager.
    // Done without the lock to avoid potential deadlock.
    if (quiesce_complete) {
      _on_quiesced_handler->connections_quiesced();
    }
  }
}


void ConnectionTracker::connection_active(pjsip_transport *tp)
{
  // We only track connection-oriented transports.
  if ((tp->flag & PJSIP_TRANSPORT_DATAGRAM) == 0)
  {
    pthread_mutex_lock(&_lock);

    // We expect to be called by only websocket transport threads, or the PJSIP
    // transport thread. We must NOT be called by the PJSIP worker thread.
    // Race/locking safety is based on the above assumption. Raise an error log
    // if the above is not the case.
    if ((strcmp(pj_thread_get_name(pj_thread_this()), "websockets")) != 0)
    {
      CHECK_PJ_TRANSPORT_THREAD();
    }

    if (_connection_listeners.find(tp) == _connection_listeners.end())
    {
      // New connection. Register a state listener so we know when it gets
      // destroyed.
      pjsip_tp_state_listener_key *key;
      pj_status_t rc = pjsip_transport_add_state_listener(tp,
                                         &connection_state,
                                         (void *)this,
                                         &key);
      if (rc != PJ_SUCCESS)
      {
        TRC_STATUS("Failed to add a listener");
      }

      // Record the listener.
      _connection_listeners[tp] = key;

      // If we're quiescing, shutdown the transport immediately.  The connection
      // will be closed when all transactions that use it have ended.
      //
      // This catches cases where the connection was established before
      // quiescing started, but the first message was sent afterwards (so the
      // first time the connection tracker heard about it was after quiesing had
      // started).  Trying to establish new connections after quiescing has
      // started should fail as the listening socket will have been closed.
      if (_quiescing)
      {
        TRC_STATUS("Quiescing newly created connection");
        pjsip_transport_shutdown(tp);
      }
    }
    pthread_mutex_unlock(&_lock);
  }
}


void ConnectionTracker::quiesce()
{
  pj_bool_t quiesce_complete = PJ_FALSE;

  TRC_STATUS("Start quiescing connections");

  pthread_mutex_lock(&_lock);
  // We expect to only be called on the PJSIP transport thread, and our data
  // race/locking safety is based on this assumption. Raise an error log if
  // this is not the case.
  CHECK_PJ_TRANSPORT_THREAD();

  // Flag that we're now quiescing. It is illegal to call this method if we're
  // already quiescing.
  assert(!_quiescing);
  _quiescing = PJ_TRUE;

  TRC_STATUS("Quiescing %d transactions", pjsip_tsx_layer_get_tsx_count());

  if (_connection_listeners.empty())
  {
    // There are no active connections, so quiescing is already complete.
    TRC_STATUS("Connection quiescing complete");
    quiesce_complete = PJ_TRUE;
  }
  else
  {
    // Call shutdown on each connection. PJSIP's reference counting means a
    // connection will be closed once all transactions that use it have
    // completed.
    for (std::map<pjsip_transport *, pjsip_tp_state_listener_key *>::iterator
                                             it = _connection_listeners.begin();
         it != _connection_listeners.end();
         ++it)
    {
      TRC_STATUS("Shutdown connection %p", it->first);
      pj_status_t rc = pjsip_transport_shutdown(it->first);
      if (rc != PJ_SUCCESS)
      {
        TRC_STATUS("Failed to shut down the connection");
      }
    }
  }

  pthread_mutex_unlock(&_lock);

  // If quiescing is now complete notify the quiescing manager.
  // Done without the lock to avoid potential deadlock.
  if (quiesce_complete) {
    _on_quiesced_handler->connections_quiesced();
  }
}


void ConnectionTracker::unquiesce()
{
  TRC_DEBUG("Unquiesce connections");

  pthread_mutex_lock(&_lock);
  // We expect to only be called on the PJSIP transport thread, and our data
  // race/locking safety is based on this assumption. Raise an error log if
  // this is not the case.
  CHECK_PJ_TRANSPORT_THREAD();

  // It is not possible to "un-shutdown" a pjsip transport.  All connections
  // that were previously active will eventually be closed. Instead we just
  // clear the quiescing flag so we won't shut down any new connections that are
  // established.
  //
  // Note it is illegal to call this method if we're not quiescing.
  assert(_quiescing);
  _quiescing = PJ_FALSE;

  pthread_mutex_unlock(&_lock);
}
