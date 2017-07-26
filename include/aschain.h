/**
 * @file aschain.h The AS chain data type.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#pragma once

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

#include <string>
#include <vector>

#include "log.h"
#include "sessioncase.h"
#include "ifchandler.h"
#include "acr.h"
#include "fifcservice.h"
#include "utils.h"

// Forward declarations.
class UASTransaction;

/// Short-lived data structure holding the details of a calculated target.
struct Target
{
  pj_bool_t from_store;
  pj_bool_t upstream_route;
  std::string aor;
  std::string binding_id;
  pjsip_uri* uri;
  std::list<pjsip_route_hdr*> paths;
  pjsip_transport* transport;
  pj_sockaddr remote_addr;
  int liveness_timeout;
  uint32_t contact_q1000_value;
  bool deprioritized;
  int contact_expiry;

  // Default constructor.
  Target() :
    from_store(PJ_FALSE),
    upstream_route(PJ_FALSE),
    aor(),
    binding_id(),
    uri(NULL),
    paths(),
    transport(NULL),
    liveness_timeout(0),
    contact_q1000_value(1000),
    deprioritized(false),
    contact_expiry(0)
  {
  }
};
typedef std::vector<Target> TargetList;

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
class AsChain
{
public:

private:
  friend class AsChainLink;
  friend class AsChainTable;

  AsChain(AsChainTable* as_chain_table,
          const SessionCase& session_case,
          const std::string& served_user,
          bool is_registered,
          SAS::TrailId trail,
          Ifcs& ifcs,
          ACR* acr,
          FIFCService* fifc_service,
          IFCConfiguration ifc_configuration);
  ~AsChain();

  bool inc_ref()
  {
    // Increment the reference count if it's non-zero.
    int refs;
    do
    {
      refs = _refs.load();
    }
    while ((refs != 0) &&
           (!_refs.compare_exchange_weak(refs, refs + 1)));
    TRC_DEBUG("AsChain inc ref %p -> %d", this, _refs.load());
    // If the reference count is non-zero, we successfully incremented it.
    return (refs != 0);
  }

  void dec_ref()
  {
    int count = --_refs;
    TRC_DEBUG("AsChain dec ref %p -> %d", this, count);
    pj_assert(count >= 0);
    if (count == 0)
    {
      delete this;
    }
  }

  void reset_chain(bool using_standard_ifcs);
  std::string to_string(size_t index) const;
  const SessionCase& session_case() const;
  size_t size() const;
  SAS::TrailId trail() const;
  ACR* acr() const;
  std::vector<Ifc> fallback_ifcs() const;
  IFCConfiguration ifc_configuration() const;
  bool using_standard_ifcs() const;

  AsChainTable* const _as_chain_table;
  std::atomic<int> _refs;

  /// Structure recording information about invoked application servers.
  typedef struct
  {
    std::string request_uri;
    std::string as_uri;
    int status_code;
    bool timeout;
  } AsInformation;
  std::vector<AsInformation> _as_info;

  /// ODI tokens, one for each step.
  std::vector<std::string> _odi_tokens;

  /// Vector keeping track of whether particular app servers have responded
  /// (either by sending a response to the original request, or forwarding
  /// the request back).
  std::vector<bool> _responsive;

  const SessionCase& _session_case;
  const std::string _served_user;
  const bool _is_registered;
  const SAS::TrailId _trail;
  const Ifcs _ifcs;  //< List of iFCs. Owned by this object.

  /// A pointer to the ACR for this chain if Rf billing is enabled.
  ACR* _acr;

  /// Member variables covering the iFCs for the ASChain.
  std::vector<Ifc> _fallback_ifcs;
  IFCConfiguration _ifc_configuration;
  bool _using_standard_ifcs;
  rapidxml::xml_document<>* _root;

  /// A vector of timers used to track the latency to each AS in the chain
  std::vector<Utils::StopWatch> _timers;
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
    _index(0u),
    _default_handling(SESSION_CONTINUED),
    _interrupted(false)
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
    // We're complete if there is no AS chain, or we're at the end of the
    // chain, or we have been interrupted.
    return ((_as_chain == NULL) ||
            (_index == _as_chain->size()) ||
            (_interrupted));
  }

  /// Get the next link in the chain.
  AsChainLink next() const
  {
    pj_assert(!complete());
    return AsChainLink(_as_chain, _index + 1);
  }

  /// Create a new reference to the underlying AsChain object.  Caller
  // must call release() when they have finished using this duplicate.
  AsChainLink duplicate() const
  {
    if (_as_chain != NULL)
    {
      // No need to check the return code from inc_ref - it only fails if
      // its reference count is already 0 and we know that can't be the case
      // because we already hold one reference.
      (void)_as_chain->inc_ref();
    }
    return *this;
  }

  /// Caller has finished using this link.
  void release()
  {
    if (_as_chain != NULL)
    {
      _as_chain->dec_ref();
      _as_chain = NULL;
    }
  }

  SAS::TrailId trail() const
  {
    return ((_as_chain == NULL) ? 0 : _as_chain->trail());
  }

  ACR* acr() const
  {
    return ((_as_chain == NULL) ? NULL : _as_chain->acr());
  }

  std::string to_string() const
  {
    return is_set() ? _as_chain->to_string(_index) : "None";
  }

  const SessionCase& session_case() const
  {
    return _as_chain->session_case();
  }

  const std::string& served_user() const
  {
    return _as_chain->_served_user;
  }

  /// Returns registration status of the served user.
  bool is_registered() const
  {
    return (_as_chain != NULL) ? _as_chain->_is_registered : false;
  }

  /// Returns the ODI token of the next AsChainLink in this chain.
  const std::string& next_odi_token() const
  {
    return _as_chain->_odi_tokens[_index + 1];
  }

  /// Returns whether the AS is responsive.
  bool responsive() const
  {
    return _as_chain->_responsive[_index];
  }

  /// Returns the default handling for this AS chain link.
  DefaultHandling default_handling()
  {
    return _default_handling;
  }

  /// Called on receipt of each response from the AS.
  void on_response(int status_code);

  /// Disposition of a request. Suggests what to do next.
  enum Disposition {
    /// The request has been completely handled. Processing should
    // stop.
    Stop,

    /// The request is being passed to an external application
    // server. Processing should skip to target processing,
    // omitting any subsequent stages.
    Skip,

    /// There are no links left on the chain. Processing should
    // continue with the next stage.
    Complete,

    /// The internal application server (if any) has processed the
    // message according to the curren link. Processing should
    // continue with the next link.
    Next
  };

  static AsChainLink create_as_chain(AsChainTable* as_chain_table,
                                     const SessionCase& session_case,
                                     const std::string& served_user,
                                     bool is_registered,
                                     SAS::TrailId trail,
                                     Ifcs& ifcs,
                                     ACR* acr,
                                     FIFCService* fifc_service,
                                     IFCConfiguration ifc_configuration);

  pjsip_status_code on_initial_request(pjsip_msg* msg,
                                       std::string& server_name,
                                       SAS::TrailId msg_trail);

  /// Interrupt AS processing on this chain link. This prevents any more
  /// application servers from being invoked.
  void interrupt()
  {
    _interrupted = true;
  }

  /// @return The URI of the AS associated with this AS chain.
  std::string uri()
  {
    return is_set() ? _as_chain->_as_info[_index].as_uri : "";
  }

  /// Starts the latency timer for the next AS hop
  void start_next_timer()
  {
    _as_chain->_timers[_index].start();
  }

  /// Reads the timer for the previous AS hop
  bool read_last_timer(unsigned long& latency)
  {
    return _as_chain->_timers[_index - 1].read(latency);
  }

  /// Returns the URI of the previous AS in the chain
  std::string previous_uri()
  {
    return _as_chain->_as_info[_index - 1].as_uri;
  }

private:
  friend class AsChainTable;

  AsChainLink(AsChain* as_chain, size_t index) :
    _as_chain(as_chain),
    _index(index),
    _default_handling(SESSION_CONTINUED),
    _interrupted(false)
  {
  }

  void get_next_application_server(pjsip_msg* msg,
                                   std::string& server_name,
                                   bool& got_dummy_as,
                                   SAS::TrailId msg_trail);

  /// Pointer to the owning AsChain object.
  AsChain* _as_chain;

  /// The index of this link in the AsChain.
  size_t _index;

  /// The configured Default Handling configured on the relevant iFC.
  DefaultHandling _default_handling;

  /// Whether AS processing has been interrupted (meaning no further application
  /// servers will be invoked).
  bool _interrupted;
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

  /// Map from ODI token to pair of (AsChain, index).
  std::map<std::string, AsChainLink> _odi_token_map;
  pthread_mutex_t _lock;
};
