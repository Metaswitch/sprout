/**
 * @file scscfsproutlet.cpp Definition of the S-CSCF Sproutlet classes,
 *                          implementing S-CSCF specific SIP proxy functions.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2014  Metaswitch Networks Ltd
 *
 * Parts of this module were derived from GPL licensed PJSIP sample code
 * with the following copyrights.
 *   Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 *   Copyright (C) 2003-2008 Benny Prijono <benny@prijono.org>
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

#ifndef SCSCFSPROUTLET_H__
#define SCSCFSPROUTLET_H__

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}

#include <vector>
#include <unordered_map>

#include "pjutils.h"
#include "enumservice.h"
#include "analyticslogger.h"
#include "regstore.h"
#include "stack.h"
#include "sessioncase.h"
#include "ifchandler.h"
#include "hssconnection.h"
#include "aschain.h"
#include "acr.h"
#include "sproutlet.h"
#include "snmp_counter_table.h"
#include "session_expires_helper.h"

class SCSCFSproutletTsx;

class SCSCFSproutlet : public Sproutlet
{
public:
  static const int DEFAULT_SESSION_CONTINUED_TIMEOUT = 2000;
  static const int DEFAULT_SESSION_TERMINATED_TIMEOUT = 4000;

  SCSCFSproutlet(const std::string& scscf_cluster_uri,
                 const std::string& scscf_node_uri,
                 const std::string& icscf_uri,
                 const std::string& bgcf_uri,
                 int port,
                 RegStore* store,
                 HSSConnection* hss,
                 EnumService* enum_service,
                 ACRFactory* acr_factory,
                 bool override_npdi,
                 int session_continued_timeout = DEFAULT_SESSION_CONTINUED_TIMEOUT,
                 int session_terminated_timeout = DEFAULT_SESSION_TERMINATED_TIMEOUT);
  ~SCSCFSproutlet();

  bool init();
  SproutletTsx* get_tsx(SproutletTsxHelper* helper,
                        const std::string& alias,
                        pjsip_msg* req);

  // Methods used to change the values of internal configuration during unit
  // test.
  void set_override_npdi(bool v) { _override_npdi = v; }
  void set_session_continued_timeout(int timeout) { _session_continued_timeout_ms = timeout; }
  void set_session_terminated_timeout(int timeout) { _session_terminated_timeout_ms = timeout; }

  inline bool should_override_npdi() const
  {
    return _override_npdi;
  }

private:

  /// Returns the AS chain table for this system.
  AsChainTable* as_chain_table() const;

  /// Returns the configured S-CSCF cluster URI for this system.
  const pjsip_uri* scscf_cluster_uri() const;

  /// Returns the configured S-CSCF node URI for this system.
  const pjsip_uri* scscf_node_uri() const;

  /// Returns the configured I-CSCF URI for this system.
  const pjsip_uri* icscf_uri() const;

  /// Returns the configured BGCF URI for this system.
  const pjsip_uri* bgcf_uri() const;

  /// Gets all bindings for the specified Address of Record from the 
  /// registration store.
  void get_bindings(const std::string& aor,
                    RegStore::AoR** aor_data,
                    SAS::TrailId trail);

  /// Removes the specified binding for the specified Address of Record from
  /// the registration store.
  void remove_binding(const std::string& aor,
                      const std::string& binding_id,
                      SAS::TrailId trail);

  /// Read data for a public user identity from the HSS.
  bool read_hss_data(const std::string& public_id,
                     const std::string& private_id,
                     const std::string& req_type,
                     bool cache_allowed,
                     bool& registered,
                     std::vector<std::string>& uris,
                     std::vector<std::string>& aliases,
                     Ifcs& ifcs,
                     std::deque<std::string>& ccfs,
                     std::deque<std::string>& ecfs,
                     SAS::TrailId trail);

  /// Translate RequestURI using ENUM service if appropriate.
  void translate_request_uri(pjsip_msg* req, pj_pool_t* pool, SAS::TrailId trail);

  /// Get an ACR instance from the factory.
  /// @param trail                SAS trail identifier to use for the ACR.
  /// @param initiator            The initiator of the SIP transaction (calling
  ///                             or called party).
  ACR* get_acr(SAS::TrailId trail, Initiator initiator, NodeRole role);

  friend class SCSCFSproutletTsx;

  /// A URI which routes to the S-CSCF cluster.
  pjsip_uri* _scscf_cluster_uri;

  /// A URI which routes to this particular S-CSCF node.  This must be
  /// constructed using an IP address or a domain name which resolves to this
  /// Sprout node only.
  pjsip_uri* _scscf_node_uri;

  /// A URI which routes to the URI cluster.
  pjsip_uri* _icscf_uri;

  /// A URI which routes to the BGCF.
  pjsip_uri* _bgcf_uri;

  RegStore* _store;

  HSSConnection* _hss;

  EnumService* _enum_service;

  ACRFactory* _acr_factory;

  AsChainTable* _as_chain_table;

  bool _override_npdi;

  /// Timeouts related to default handling of unresponsive application servers.
  int _session_continued_timeout_ms;
  int _session_terminated_timeout_ms;

  /// String versions of the cluster URIs
  std::string _scscf_cluster_uri_str;
  std::string _scscf_node_uri_str;
  std::string _icscf_uri_str;
  std::string _bgcf_uri_str;

  SNMP::CounterTable* _routed_by_preloaded_route_tbl = NULL;
  SNMP::CounterTable* _invites_cancelled_before_1xx_tbl = NULL;
  SNMP::CounterTable* _invites_cancelled_after_1xx_tbl = NULL;
};


class SCSCFSproutletTsx : public SproutletTsx
{
public:
  SCSCFSproutletTsx(SproutletTsxHelper* helper, SCSCFSproutlet* scscf, pjsip_method_e req_type);
  ~SCSCFSproutletTsx();

  virtual void on_rx_initial_request(pjsip_msg* req) override;
  virtual void on_rx_in_dialog_request(pjsip_msg* req) override;
  virtual void on_tx_request(pjsip_msg* req, int fork_id) override;
  virtual void on_rx_response(pjsip_msg* rsp, int fork_id) override;
  virtual void on_tx_response(pjsip_msg* rsp) override;
  virtual void on_rx_cancel(int status_code, pjsip_msg* req) override;
  virtual void on_timer_expiry(void* context) override;

private:
  /// Examines the top route header to determine the relevant AS chain
  /// (from the ODI token) and the session case (based on the presence of
  /// the 'orig' param), and sets those as member variables.
  void retrieve_odi_and_sesscase(pjsip_msg* req);

  /// Determines the served user for the request.
  pjsip_status_code determine_served_user(pjsip_msg* req);

  /// Gets the served user indicated in the message.
  std::string served_user_from_msg(pjsip_msg* msg);

  /// Creates an AS chain for this service role and links this service hop to
  /// it.
  AsChainLink create_as_chain(Ifcs ifcs,
                              std::string served_user,
                              ACR*& acr,
                              SAS::TrailId chain_trail);

  /// Check whether the request has been retargeted, given the updated URI.
  bool is_retarget(std::string new_served_user);

  /// Apply originating services for this request.
  void apply_originating_services(pjsip_msg* req);

  /// Apply terminating services for this request.
  void apply_terminating_services(pjsip_msg* req);

  /// Route the request to an application server.
  void route_to_as(pjsip_msg* req,
                   const std::string& server_name);

  /// Route the request to the I-CSCF.
  void route_to_icscf(pjsip_msg* req);

  /// Route the request to the BGCF.
  void route_to_bgcf(pjsip_msg* req);

  /// Route the request to the terminating side S-CSCF.
  void route_to_term_scscf(pjsip_msg* req);

  /// Route the request to the appropriate onward target.
  void route_to_target(pjsip_msg* req);

  /// Route the request to UE bindings retrieved from the registration store.
  void route_to_ue_bindings(pjsip_msg* req);

  /// Add a Route header with the specified URI.
  void add_route_uri(pjsip_msg* msg, pjsip_sip_uri* uri);

  /// Does URI translation if required.
  void uri_translation(pjsip_msg* req);

  /// Gets the subscriber's associated URIs and iFCs for each URI from
  /// the HSS. Returns true on success, false on failure.
  bool get_data_from_hss(std::string public_id);

  /// Look up the registration state for the given public ID, using the
  /// per-transaction cache if possible (and caching them and the iFC otherwise).
  bool is_user_registered(std::string public_id);

  /// Look up the associated URIs for the given public ID.  The uris parameter
  /// is only filled in correctly if this function returns true.
  bool get_associated_uris(std::string public_id,
                           std::vector<std::string>& uris);

  /// Look up the aliases for the given public ID.  The uris parameter
  /// is only filled in correctly if this function returns true.
  bool get_aliases(std::string public_id,
                   std::vector<std::string>& aliases);

  /// Look up the Ifcs for the given public ID.  The ifcs parameter is only
  /// filled in correctly if this function returns true.
  bool lookup_ifcs(std::string public_id,
                   Ifcs& ifcs);

  /// Record-Route the S-CSCF sproutlet into a dialog.  The third parameter
  /// passed may be attached to the Record-Route and can be used to recover the
  /// billing role that is in use on subsequent in-dialog messages.
  ///
  /// @param msg          - The message to modify
  /// @param billing_rr   - Whether to add a `billing-role` parameter to the RR
  /// @param billing_role - The contents of the `billing-role` (ignored if
  ///                       `billing_rr` is false)
  void add_record_route(pjsip_msg* msg, bool billing_rr, NodeRole billing_role);

  /// Retrieve the billing role for the incoming message.  This should have been
  /// set during session initiation.
  NodeRole get_billing_role();

  /// Adds a second P-Asserted-Identity header to a message when required.
  void add_second_p_a_i_hdr(pjsip_msg* msg);

  /// Raise a SAS log at the start of originating, terminating, or orig-cdiv
  /// processing.
  void sas_log_start_of_sesion_case(pjsip_msg* req,
                                    const SessionCase* session_case,
                                    const std::string& served_user);

  /// Fetch the ACR for the current transaction, ACRs should always be retrived
  /// through this API, not by inspecting _acr directly, since the ACR may be
  /// owned by the AsChain as a whole.  May return NULL in some cases.
  ACR* get_acr();

  /// Pointer to the parent SCSCFSproutlet object - used for various operations
  /// that require access to global configuration or services.
  SCSCFSproutlet* _scscf;

  /// Flag indicating if the transaction has been cancelled.
  bool _cancelled;

  /// The session case for this service hop (originating, terminating or
  /// originating-cdiv).
  const SessionCase* _session_case;

  /// The link in the owning AsChain for this service hop.
  AsChainLink _as_chain_link;

  /// Data retrieved from HSS for this service hop.
  bool _hss_data_cached;
  bool _registered;
  std::vector<std::string> _uris;
  std::vector<std::string> _aliases;
  Ifcs _ifcs;
  std::deque<std::string> _ccfs;
  std::deque<std::string> _ecfs;

  /// ACRs used where the S-CSCF will only process a single transaction (no
  /// AsChain is created).  There are two cases where this might be true:
  ///
  ///  - An OOD/Session-initializing request that is rejected before the
  ///    AsChain is created (e.g. subscriber not found).
  ///  - An in-dialog request, where the S-CSCF will simply forward the
  ///    request following the route-set.
  ///
  /// These fields should not be used to update the ACR information, get_acr()
  /// should be used instead.
  ACR* _in_dialog_acr;
  ACR* _failed_ood_acr;

  /// State information when the request is routed to UE bindings.  This is
  /// used in cases where a request fails with a Flow Failed status code
  /// (as defined in RFC5626) indicating the binding is no longer valid.
  std::string _target_aor;
  std::unordered_map<int, std::string> _target_bindings;

  /// Liveness timer used for determining when an application server is not
  /// responding.
  TimerID _liveness_timer;

  /// Track if this transaction has already record-routed itself to prevent
  /// us accidentally record routing twice.
  bool _record_routed;

  /// Track request type and whether a 1xx response has been seen so that the
  /// correct stats can be updated.
  pjsip_method_e _req_type;
  bool _seen_1xx;

  static const int MAX_FORKING = 10;

  /// The private identity associated with the request. Empty unless the
  /// request had a Proxy-Authorization header.
  std::string _impi;

  /// Whether this request should cause the user to be automatically
  /// registered in the HSS. This is set if there is an `auto-reg` parameter
  /// in the S-CSCF's route header.
  ///
  /// This has the following impacts:
  /// - It causes registration state updates to have a type of REG rather than
  ///   CALL.
  /// - If there is a real HSS it forces registration state updates to flow all
  ///   the way to the HSS (i.e. Homestead may not answer the response solely
  ///   from its cache).
  bool _auto_reg;

  /// Class to handle session-expires processing.
  SessionExpiresHelper _se_helper;
};

#endif
