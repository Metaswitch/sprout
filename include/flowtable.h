/**
 * @file flowtable.h Definition for the Edge Proxy flow maintenance classes
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


#ifndef FLOWTABLE_H__
#define FLOWTABLE_H__

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

// Common STL includes.
#include <cassert>
#include <map>
#include <unordered_map>
#include <string>
#include <atomic>

#include "snmp_scalar.h"
#include "stack.h"
#include "quiescing_manager.h"

class FlowTable;

class Flow
{
public:
  /// Returns a pointer to the PJSIP transport for this flow.
  inline pjsip_transport* transport() { return _transport; };

  /// Returns a pointer to the remote address for this flow.
  inline const pj_sockaddr* remote_addr() const { return &_remote_addr; };

  /// Returns a reference to the flow token.
  inline const std::string& token() const { return _token; };

  void touch();

  std::string asserted_identity(pjsip_uri* preferred_identity);

  std::string default_identity();

  std::string service_route(const std::string& identity);

  void set_identity(const pjsip_uri* uri,
                    const std::string& service_route,
                    bool is_default,
                    int expires);

  void dec_ref();

  void increment_dialogs();

  void decrement_dialogs();

  bool should_quiesce();

  static void on_transport_state_changed(pjsip_transport *tp,
                                         pjsip_transport_state state,
                                         const pjsip_transport_state_info *info);

  static void on_timer_expiry(pj_timer_heap_t *th, pj_timer_entry *e);

  friend class FlowTable;

private:
  Flow(FlowTable* flow_table, pjsip_transport* transport, const pj_sockaddr* remote_addr);
  ~Flow();

  static const int TOKEN_LENGTH = 10;

  void select_default_identity();
  void restart_timer(int id, int timeout);
  void expiry_timer();

  void inc_ref();

  FlowTable* _flow_table;
  pjsip_transport* _transport;
  pjsip_tp_state_listener_key* _tp_state_listener_key;
  pj_sockaddr _remote_addr;
  std::string _token;

  /// Timer used to expire the associated registration bindings.  This is also
  /// used to expire idle UDP flows (ie. when there are no more associated
  /// registration bindings.
  pj_timer_entry _timer;

  /// Lock used to protect accesses to the various data structures managing
  /// the identifiers authorized on this flow.
  pthread_mutex_t _flow_lock;

  /// Map holding all the authenticated identifiers for this flow.  The key
  /// is a normalized address of record/public identity, the value is the
  /// full name-addr that should be used in P-Asserted-ID, the expiry
  /// time, and whether this identity can be used as a default identity.
  struct AuthId
  {
    std::string name_addr;
    int expires;
    bool default_id;
    std::string service_route;
  };

  typedef std::unordered_map<std::string, struct AuthId> auth_id_map;
  auth_id_map _authorized_ids;

  /// The default identity for this flow.
  std::string _default_id;

  /// Counts the references to this Flow.  This can only be updated or tested
  /// by a thread which currently holds the FlowTable::_flow_map_lock.
  int _refs;

  // Counts the number of active dialogs on this flow. This can be
  // updated or tested without FlowTable::_flow_map_lock being held.
  std::atomic_long _dialogs;

  /// Timer identifiers - the timer either runs as an expiry timer (when there
  /// are active identities) or an idle timer (when there are no active
  /// identities on a non-reliable flow).
  static const int EXPIRY_TIMER = 1;
  static const int IDLE_TIMER = 2;

  /// Timeout (in seconds) used to delete idle non-reliable flows.
  static const int IDLE_TIMEOUT = 600;

  /// Grace period for contact expiry.
  static const int EXPIRY_GRACE_INTERVAL = 30;
};


class FlowTable : public QuiesceFlowsInterface
{
public:
  FlowTable(QuiescingManager* qm, SNMP::U32Scalar* connection_count);
  virtual ~FlowTable();

  /// Create a flow corresponding to the specified received message.
  /// This may be called with parameters that match an existing flow, in
  /// which case it will return the existing flow.
  Flow* find_create_flow(pjsip_transport* transport, const pj_sockaddr* raddr);

  /// Find the flow corresponding to the specified received message using
  /// the transport the message was received on and the IP address/port
  /// if appropriate.
  Flow* find_flow(pjsip_transport* transport, const pj_sockaddr* raddr);

  /// Find the flow corresponding to the specified flow token.
  Flow* find_flow(const std::string& token);

  /// Removes a flow from the flow table.
  void remove_flow(Flow* flow);

  // Functions for quiescing a Bono.
  void check_quiescing_state();
  void quiesce();
  void unquiesce();
  bool is_quiescing();

  friend class Flow;

private:

  /// Class used to identify a particular flow.
  class FlowKey
  {
  public:
    FlowKey(int transport_type, const pj_sockaddr* raddr) :
      _type(transport_type),
      _raddr(*raddr)
    {
    }

    ~FlowKey()
    {
    }

    /// Override operator< so this can be used as a map key.
    bool operator< (const FlowKey& other) const
    {
      // Compare the transport type first.
      if (_type < other._type)
      {
        return true;
      }
      else if (_type > other._type)
      {
        return false;
      }
      else
      {
        // The transport is the same, so check the remote addresses.
        return (pj_sockaddr_cmp(&_raddr, &other._raddr) < 0);
      }
    }

  private:
    int _type;
    pj_sockaddr _raddr;
  };

  pthread_mutex_t _flow_map_lock;
  std::map<FlowKey, Flow*> _tp2flow_map;        // map from transport addresses to flow
  std::map<std::string, Flow*> _tk2flow_map;    // map from token to flow

  // Statistics
  void report_flow_count();
  SNMP::U32Scalar* _conn_count;
  bool _quiescing;
  QuiescingManager* _qm;

};

#endif
