/**
 * @file bono.h Initialization/termination functions for Bono subcomponent.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * Parts of this header were derived from GPL licensed PJSIP sample code
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

#ifndef STATEFUL_PROXY_H__
#define STATEFUL_PROXY_H__

// Forward declarations.
class UASTransaction;
class UACTransaction;

#include <list>

#include "pjutils.h"
#include "enumservice.h"
#include "bgcfservice.h"
#include "analyticslogger.h"
#include "regstore.h"
#include "stack.h"
#include "trustboundary.h"
#include "sessioncase.h"
#include "ifchandler.h"
#include "hssconnection.h"
#include "aschain.h"
#include "quiescing_manager.h"
#include "scscfselector.h"
#include "icscfrouter.h"
#include "acr.h"
#include "session_expires_helper.h"

/// Short-lived data structure holding details of how we are to serve
// this request.
class ServingState
{
public:
  ServingState() :
    _session_case(NULL)
  {
  }

  ServingState(const SessionCase* session_case,
               AsChainLink original_dialog) :
    _session_case(session_case),
    _original_dialog(original_dialog)
  {
  }

  ServingState(const ServingState& to_copy) :
    _session_case(to_copy._session_case),
    _original_dialog(to_copy._original_dialog)
  {
  }

  ServingState& operator=(const ServingState& to_copy)
  {
    if (&to_copy != this)
    {
      _session_case = to_copy._session_case;
      _original_dialog = to_copy._original_dialog;
    }
    return *this;
  }

  std::string to_string() const
  {
    if (_session_case != NULL)
    {
      return _session_case->to_string() + " " + (_original_dialog.is_set() ? _original_dialog.to_string() : "(new)");
    }
    else
    {
      return "None";
    }
  }

  bool is_set() const { return _session_case != NULL; };
  const SessionCase& session_case() const { return *_session_case; };
  AsChainLink original_dialog() const { return _original_dialog; };

private:

  /// Points to the session case.  If this is NULL it means the serving
  // state has not been set up.
  const SessionCase* _session_case;

  /// Is this related to an existing (original) dialog? If so, we
  // should continue handling the existing AS chain rather than
  // creating a new one. Index and pointer to that existing chain, or
  // !is_set() if none.
  AsChainLink _original_dialog;
};

struct HSSCallInformation
{
  bool registered;
  Ifcs ifcs;
  std::vector<std::string> uris;
};

// This is the data that is attached to the UAS transaction
class UASTransaction
{
public:
  ~UASTransaction();

  static pj_status_t create(pjsip_rx_data* rdata,
                            pjsip_tx_data* tdata,
                            TrustBoundary* trust,
                            ACR* acr,
                            UASTransaction** uas_data_ptr);
  static UASTransaction* get_from_tsx(pjsip_transaction* tsx);

  void routing_proxy_handle_initial_non_cancel(const ServingState& serving_state);
  void routing_proxy_handle_subsequent_non_cancel(ACR* downstream_acr);
  void access_proxy_handle_non_cancel(Target* target);

  void on_new_client_response(UACTransaction* uac_data, pjsip_rx_data *rdata);
  void on_client_not_responding(UACTransaction* uac_data);
  void on_tsx_state(pjsip_event* event);
  void cancel_pending_uac_tsx(int st_code, bool dissociate_uac);
  pj_status_t handle_final_response();

  pj_status_t send_trying(pjsip_rx_data* rdata);
  pj_status_t send_response(int st_code, const pj_str_t* st_text=NULL);
  bool redirect(std::string, int);
  bool redirect(pjsip_uri*, int);
  inline pjsip_method_e method() { return (_tsx != NULL) ? _tsx->method.id : PJSIP_OTHER_METHOD; }
  inline SAS::TrailId trail() { return (_tsx != NULL) ? get_trail(_tsx) : 0; }
  inline const char* name() { return (_tsx != NULL) ? _tsx->obj_name : "unknown"; }

  void trying_timer_expired();
  static void trying_timer_callback(pj_timer_heap_t *timer_heap, struct pj_timer_entry *entry);

  // Enters/exits this UASTransaction's context.  This takes a group lock,
  // single-threading any processing on this UASTransaction and associated
  // UACTransactions.  While in the UASTransaction's context, it will not be
  // destroyed.  The underlying PJSIP transaction (_tsx) may or may not exist,
  // but it won't disappear under your feet.
  //
  // enter_context and exit_context should always be called at the start and
  // end of any entry point (e.g. call from non-transaction code into
  // transaction or callback from PJSIP).  On return from exit_context, you
  // must not assume that the transaction still exists.
  void enter_context();
  void exit_context();

  friend class UACTransaction;

private:
  UASTransaction(pjsip_transaction* tsx,
                 pjsip_rx_data* rdata,
                 pjsip_tx_data* tdata,
                 TrustBoundary* trust,
                 ACR* acr);
  void log_on_tsx_start(const pjsip_rx_data* rdata);
  void log_on_tsx_complete();
  pj_status_t init_uac_transactions(TargetList& targets);
  void dissociate(UACTransaction *uac_data);
  bool redirect_int(pjsip_uri* target, int code);
  pjsip_history_info_hdr* create_history_info_hdr(pjsip_uri* target);
  void update_history_info_reason(pjsip_uri* history_info_uri, int code);
  AsChainLink create_as_chain(const SessionCase& session_case, Ifcs ifcs, std::string served_user = "");

  bool find_as_chain(const ServingState& serving_state);
  AsChainLink::Disposition handle_originating(Target*& target);
  void common_start_of_terminating_processing();
  bool move_to_terminating_chain();
  AsChainLink::Disposition handle_terminating(Target*& target);
  AsChainLink::Disposition apply_services(Target*& target);
  void handle_outgoing_non_cancel(Target* target);

  bool get_data_from_hss(std::string public_id, HSSCallInformation& data, SAS::TrailId trail);
  bool lookup_ifcs(std::string public_id, Ifcs& ifcs, SAS::TrailId trail);
  bool get_associated_uris(std::string public_id, std::vector<std::string>& uris, SAS::TrailId trail);
  bool is_user_registered(std::string public_id);

  void routing_proxy_record_route(const SessionCase& session_case);

  void proxy_calculate_targets(pjsip_msg* msg,
                               pj_pool_t* pool,
                               TargetList& targets,
                               int max_targets,
                               SAS::TrailId trail);
  void get_targets_from_store(const std::string& aor,
                              RegStore*& store,
                              RegStore*& remote_store,
                              pjsip_msg*& msg,
                              pj_pool_t* pool,
                              int max_targets,
                              TargetList& targets,
                              SAS::TrailId trail);
  void get_all_bindings(const std::string& aor,
                        RegStore*& store,
                        RegStore*& remote_store,
                        RegStore::AoR** aor_data,
                        SAS::TrailId trail);

  void cancel_trying_timer();

  pj_grp_lock_t*       _lock;      //< Lock to protect this UASTransaction and the underlying PJSIP transaction
  pjsip_transaction*   _tsx;
  int                  _num_targets;
  int                  _pending_targets;
  pj_bool_t            _ringing;
  pjsip_tx_data*       _req;       //< Request to forward on to next element.
  pjsip_tx_data*       _best_rsp;  //< Response to send back to caller.
  TrustBoundary*       _trust;     //< Trust-boundary processing for this B2BUA to apply.
  static const int MAX_FORKING = 10;
  UACTransaction*      _uac_data[MAX_FORKING];
  struct
  {
    pjsip_from_hdr* from;
    pjsip_to_hdr*   to;
    pjsip_cid_hdr*  cid;
  } _analytics;
  bool                 _pending_destroy;
  int                  _context_count;
  std::list<AsChainLink> _as_chain_links; //< References to the AsChains this transaction is associated with.
                                          //< The last in the list is the chain currently controlling the
                                          //< transaction.
  std::map<std::string, HSSCallInformation> cached_hss_data; // Maps public IDs to their associated URIs and IFC

  /// Pointer to ACR used for the upstream side of the transaction.  NULL if
  /// Rf not enabled.
  ACR*                 _upstream_acr;

  /// Pointer to ACR used for the downstream side of the transaction.  This
  /// may be the same as the upstream ACR if both sides of the transaction are
  /// happening in the same Rf context, but they may be different, for example
  /// if upstream is originating side S-CSCF and downstream is terminating side
  /// S-CSCF, or I-CSCF or BGCF.
  ACR*                 _downstream_acr;

  /// Indication of in-dialog transaction.  This is used to determine whether
  /// or not to send ACRs on 1xx responses.
  bool                 _in_dialog;

  /// I-CSCF router instance if inline I-CSCF processing is performed in this
  /// transaction, NULL otherwise.
  ICSCFRouter*         _icscf_router;

  /// Stores an I-CSCF ACR if inline I-CSCF processing was performed in this
  /// transaction.
  ACR*                 _icscf_acr;

  /// Stores a BGCF ACR if BGCF processing was performed in this transaction.
  ACR*                 _bgcf_acr;

  /// Object to handle session expires processing.
  SessionExpiresHelper _se_helper;

public:
  pj_timer_entry       _trying_timer;
  static const int     TRYING_TIMER = 1;
  pthread_mutex_t      _trying_timer_lock;
};

// This is the data that is attached to the UAC transaction
class UACTransaction
{
public:
  UACTransaction(UASTransaction* uas_data, int target, pjsip_transaction* tsx, pjsip_tx_data *tdata);
  ~UACTransaction();

  static UACTransaction* get_from_tsx(pjsip_transaction* tsx);

  void set_target(const struct Target& target);
  void send_request();
  void cancel_pending_tsx(int st_code);
  void on_tsx_state(pjsip_event* event);
  bool retry_request();

  inline pjsip_method_e method() { return (_tsx != NULL) ? _tsx->method.id : PJSIP_OTHER_METHOD; }
  inline SAS::TrailId trail() { return (_tsx != NULL) ? get_trail(_tsx) : 0; }
  inline const char* name() { return (_tsx != NULL) ? _tsx->obj_name : "unknown"; }

  void liveness_timer_expired();

  static void liveness_timer_callback(pj_timer_heap_t *timer_heap, struct pj_timer_entry *entry);

  // Enters/exits this UACTransaction's context.  This takes a group lock,
  // single-threading any processing on this UACTransaction, the associated
  // UASTransaction and other associated UACTransactions.  While in the
  // UACTransaction's context, it will not be destroyed.  The underlying PJSIP
  // transaction (_tsx) may or may not exist, but it won't disappear under
  // your feet.
  //
  // enter_context and exit_context should always be called at the start and
  // end of any entry point (e.g. call from non-transaction code into
  // transaction or callback from PJSIP).  On return from exit_context, you
  // must not assume that the transaction still exists.
  void enter_context();
  void exit_context();

  friend class UASTransaction;

private:
  UASTransaction*      _uas_data;
  int                  _target;
  pj_grp_lock_t*       _lock;       //< Lock to protect this UACTransaction and the underlying PJSIP transaction
  pjsip_transaction*   _tsx;
  pjsip_tx_data*       _tdata;
  pj_bool_t            _from_store; /* If true, the aor and binding_id
                                       identify the binding. */
  pj_str_t             _aor;
  pj_str_t             _binding_id;
  pjsip_transport*     _transport;

  // Stores the list of targets returned by the SIPResolver for this transaction.
  std::vector<AddrInfo> _servers;
  int                  _current_server;

  bool                 _pending_destroy;
  int                  _context_count;

  int                  _liveness_timeout;
  pj_timer_entry       _liveness_timer;
  static const int LIVENESS_TIMER = 1;
};

pj_status_t init_stateful_proxy(IfcHandler* ifc_handler,
                                pj_bool_t enable_access_proxy,
                                const std::string& upstream_proxy,
                                int upstream_proxy_port,
                                int upstream_proxy_connections,
                                int upstream_proxy_recycle,
                                pj_bool_t enable_ibcf,
                                const std::string& trusted_hosts,
                                const std::string& pbx_host_str,
                                const std::string& pbx_service_route_arg,
                                AnalyticsLogger* analytics_logger,
                                EnumService *enumService,
                                BgcfService *bgcfService,
                                HSSConnection* hss_connection,
                                ACRFactory* cscf_rfacr_factory,
                                ACRFactory* bgcf_rfacr_factory,
                                ACRFactory* icscf_rfacr_factory,
                                const std::string& icscf_uri_str,
                                QuiescingManager* quiescing_manager,
                                SCSCFSelector *scscfSelector,
                                bool icscf_enabled,
                                bool scscf_enabled,
                                bool emerg_reg_accepted);

void destroy_stateful_proxy();

enum SIPPeerType
{
  SIP_PEER_TRUSTED_PORT,
  SIP_PEER_CONFIGURED_TRUNK,
  SIP_PEER_CLIENT,
  SIP_PEER_NONREGISTERING_PBX,
  SIP_PEER_UNKNOWN
};


#ifdef UNIT_TEST
pj_status_t proxy_process_access_routing(pjsip_rx_data *rdata,
                                         pjsip_tx_data *tdata);
#endif

#endif
