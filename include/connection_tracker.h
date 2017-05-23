/**
 * @file connection_tracker.h Definition of COnnectionTracker - a class used to
 * track and manage TCP connections.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


#ifndef CONNECTION_TRACKER_H__
#define CONNECTION_TRACKER_H__

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

// Common STL includes.
#include <map>

/// Interface that the ConnectionTracker notifies when quiescing connections has
/// completed.
class ConnectionsQuiescedInterface
{
public:
  virtual void connections_quiesced() = 0;
};

class ConnectionTracker
{
public:
  ConnectionTracker(ConnectionsQuiescedInterface *handler);
  ~ConnectionTracker();

  /// Notify the connection tracker that a connection is active (usually because
  /// a message has been received on it).
  void connection_active(pjsip_transport *tp);

  /// Quiesce all connections.  When this is called all current connections are
  /// gracefully shutdown, and the connection tracker is put in a state where
  /// subsequent new connections are also gracefully shutdown.
  //
  /// It is only legal to call this method when the connection tracker is
  /// in normal operation (there has never been a call to quiesce, or there
  /// hasn't been one since the most recent call to unquiesce).
  void quiesce();

  /// Unquiesce.  This puts the connection tracker into normal operation (where
  /// new connections are not automatically shutdown).
  ///
  /// It is only legal to call this method when the connection tracker is
  /// quiescing (there has been a previous call to quiesce without an
  /// intervening call to unquiesce).
  void unquiesce();

private:
  // This must be held when accessing _connection_listeners, to avoid contention
  // between the transport thread and websocket threads.
  pthread_mutex_t _lock;

  // A map of all the connections known to the connection manager, and their
  // state listeners.  This is a set of pjsip transports, but only includes
  // connection-based transports (not datagram transports).
  std::map<pjsip_transport *, pjsip_tp_state_listener_key *>
                                                          _connection_listeners;

  // Whether the connection manager is quiescing it's connections.
  pj_bool_t _quiescing;

  // Pointer to the object that handles quiesce-complete notifications.
  ConnectionsQuiescedInterface *_on_quiesced_handler;

  // Static method that is registered as a transport state listener so the
  // connection tracker is told when a connection is destoryed.
  static void connection_state(pjsip_transport* tp,
                               pjsip_transport_state state,
                               const pjsip_transport_state_info* info);

  // Notify the connection tracker that a transport has changed state.  This is
  // called from the static _connection_state_ method above.
  void connection_state_update(pjsip_transport* tp,
                               pjsip_transport_state state);
};

#endif
