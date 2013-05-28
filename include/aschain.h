/**
 * @file aschain.h The AS chain data type.
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

///
///

#pragma once

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

#include <string>
#include <vector>

#include "callservices.h"
#include "sessioncase.h"
#include "ifchandler.h"


/// Short-lived data structure holding the details of a calculated target.
struct target
{
  pj_bool_t from_store;
  std::string aor;
  std::string binding_id;
  pjsip_uri* uri;
  std::list<pjsip_uri*> paths;
  pjsip_transport* transport;
};
typedef std::list<target> target_list;

class AsChainTable;

/// The AS chain.
//
// Clients should use AsChainLink, not this class directly.
//
// AsChain objects are constructed by AsChainLink::create_as_chain,
// which also returns a reference to the created object.
//
// References can also be obtained via AsChainTable::lookup().
//
// References are released by AsChainLink::release().
//
// AsChain objects are destroyed by AsChain::request_destroy().
//
class AsChain
{
public:
  void request_destroy();

private:
  friend class AsChainLink;
  friend class AsChainTable;

  AsChain(AsChainTable* as_chain_table,
          const SessionCase& session_case,
          const std::string& served_user,
          bool is_registered,
          SAS::TrailId trail,
          std::vector<AsInvocation> application_servers);
  ~AsChain();

  void inc_ref()
  {
    ++_refs;
  }

  void dec_ref()
  {
    int count = --_refs;
    pj_assert(count >= 0);
    if (count == 0)
    {
      delete this;
    }
  }

  std::string to_string(size_t index) const;
  const SessionCase& session_case() const;
  size_t size() const;
  bool matches_target(pjsip_rx_data* rdata) const;
  SAS::TrailId trail() const;

  AsChainTable* const _as_chain_table;
  std::atomic<int> _refs;

  /// ODI tokens, one for each step.
  std::vector<std::string> _odi_tokens;

  const SessionCase& _session_case;
  const std::string _served_user;
  const bool _is_registered;
  const SAS::TrailId _trail;
  std::vector<AsInvocation> _application_servers; //< List of application server URIs.
};


/// A single link in the AsChain. Clients always access an AsChain
// through one of these.
//
// AsChainLink also acts as a context: until release() is called, the
// underlying AsChain object cannot be deleted.
class AsChainLink
{
public:
  AsChainLink() :
    _as_chain(NULL),
    _index(0u)
  {
  }

  ~AsChainLink()
  {
  }

  AsChain* as_chain() const
  {
    return _as_chain;
  }

  bool is_set() const
  {
    return (_as_chain != NULL);
  }

  bool complete() const
  {
    return ((_as_chain == NULL) || (_index == _as_chain->size()));
  }

  /// Caller has finished using this link.
  void release()
  {
    if (_as_chain != NULL)
    {
      _as_chain->dec_ref();
    }
  }

  SAS::TrailId trail() const
  {
    return ((_as_chain == NULL) ? 0 : _as_chain->trail());
  }

  std::string to_string() const
  {
    return is_set() ? _as_chain->to_string(_index) : "None";
  }

  const SessionCase& session_case() const
  {
    return _as_chain->session_case();
  }

  bool matches_target(pjsip_rx_data* rdata) const
  {
    return _as_chain->matches_target(rdata);
  }

  /// Disposition of a request. Suggests what to do next.
  enum Disposition {
    /// The request has been completely handled. Processing should
    // stop.
    Stop,

    /// The request is being passed to an external application
    // server. Processing should skip to target processing,
    // omitting any subsequent stages.
    Skip,

    /// The internal application server (if any) has processed the
    // message. Processing should continue with the next stage.
    Next
  };

  static AsChainLink create_as_chain(AsChainTable* as_chain_table,
                                     const SessionCase& session_case,
                                     const std::string& served_user,
                                     bool is_registered,
                                     SAS::TrailId trail,
                                     std::vector<AsInvocation> application_servers);

  Disposition on_initial_request(CallServices* call_services,
                                 UASTransaction* uas_data,
                                 pjsip_msg* msg,
                                 pjsip_tx_data* tdata,
                                 target** target);

private:
  friend class AsChainTable;

  AsChainLink(AsChain* as_chain, size_t index) :
    _as_chain(as_chain),
    _index(index)
  {
  }

  /// Returns the ODI token of the next AsChainLink in this chain.
  const std::string& next_odi_token() const
  {
    return _as_chain->_odi_tokens[_index];
  }

  AsChain* _as_chain;
  size_t _index;
};


/// Lookup table of AsChain objects.
class AsChainTable
{
public:
  AsChainTable();
  ~AsChainTable();

  /// Lookup the next step to follow when receiving the given
  // token. The 0th token thus indicates the 1st step, the 1st token
  // the 2nd step, and so on.
  AsChainLink lookup(const std::string& token);

private:
  friend class AsChain;

  void register_(AsChain* as_chain, std::vector<std::string>& tokens);
  void unregister(std::vector<std::string>& tokens);

  static const int TOKEN_LENGTH = 10;

  /// Map from token to pair of (AsChain, index).
  std::map<std::string, AsChainLink> _t2c_map;
  pthread_mutex_t _lock;
};
