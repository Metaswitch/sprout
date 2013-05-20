/**
 * @file stateful_proxy.h Initialization/termination functions for Stateful Proxy module.
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

///
///

#ifndef STATEFUL_PROXY_H__
#define STATEFUL_PROXY_H__

// Forward declarations.
class UASTransaction;
class UACTransaction;

#include <list>

#include "enumservice.h"
#include "bgcfservice.h"
#include "analyticslogger.h"
#include "callservices.h"
#include "regdata.h"
#include "stack.h"
#include "trustboundary.h"
#include "sessioncase.h"
#include "ifchandler.h"
#include "aschain.h"

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

// This is the data that is attached to the UAS transaction
class UASTransaction
{
public:
  ~UASTransaction();

  static pj_status_t create(pjsip_rx_data* rdata,
                            pjsip_tx_data* tdata,
                            TrustBoundary* trust,
                            UASTransaction** uas_data_ptr);
  static UASTransaction* get_from_tsx(pjsip_transaction* tsx);

  AsChainLink handle_incoming_non_cancel(pjsip_rx_data* rdata, pjsip_tx_data* tdata, const ServingState& serving_state);
  AsChainLink::Disposition handle_originating(AsChainLink& as_chain, pjsip_rx_data* rdata, pjsip_tx_data* tdata, target** pre_target);
  AsChainLink move_to_terminating_chain(pjsip_rx_data* rdata, pjsip_tx_data* tdata);
  AsChainLink::Disposition handle_terminating(AsChainLink& as_chain, pjsip_tx_data* tdata, target** pre_target);
  void handle_outgoing_non_cancel(pjsip_tx_data* tdata, target* pre_target);

  void on_new_client_response(UACTransaction* uac_data, pjsip_rx_data *rdata);
  void on_client_not_responding(UACTransaction* uac_data);
  void on_tsx_state(pjsip_event* event);
  void cancel_pending_uac_tsx(int st_code, pj_bool_t integrity_protected=PJ_FALSE);
  pj_status_t handle_final_response();

  void register_proxy(CallServices::Terminating* proxy);

  pj_status_t send_response(int st_code, const pj_str_t* st_text=NULL);
  bool redirect(std::string, int);
  bool redirect(pjsip_uri*, int);
  inline pjsip_method_e method() { return (_tsx != NULL) ? _tsx->method.id : PJSIP_OTHER_METHOD; }
  inline SAS::TrailId trail() { return (_tsx != NULL) ? get_trail(_tsx) : 0; }
  inline const char* name() { return (_tsx != NULL) ? _tsx->obj_name : "unknown"; }

  // Enters/exits this transaction's context.  While in the transaction's
  // context, it will not be destroyed.  enter_context and exit_context should
  // always be called at the start and end of any entry point (e.g. call from
  // non-transaction code into transaction or callback from PJSIP) to avoid
  // the transaction object being destroyed under our feet.  On return from
  // exit_context, you must not assume that the transaction still exists.  Note
  // that this does not prevent the _tsx from being destroyed.
  void enter_context();
  void exit_context();

  friend class UACTransaction;

private:
  UASTransaction(pjsip_transaction* tsx,
                 pjsip_rx_data* rdata,
                 pjsip_tx_data* tdata,
                 TrustBoundary* trust);
  void log_on_tsx_start(const pjsip_rx_data* rdata);
  void log_on_tsx_complete();
  pj_status_t init_uac_transactions(pjsip_tx_data* tdata, target_list& targets);
  void dissociate(UACTransaction *uac_data);
  bool redirect_int(pjsip_uri* target, int code);
  AsChainLink create_as_chain(const SessionCase& session_case,
                              pjsip_rx_data* rdata);

  pjsip_transaction*   _tsx;
  int                  _num_targets;
  int                  _pending_targets;
  pj_bool_t            _ringing;
  pjsip_tx_data*       _req;
  pjsip_tx_data*       _best_rsp;
  TrustBoundary*       _trust;  //< Trust-boundary processing for this B2BUA to apply.
#define MAX_FORKING 10
  UACTransaction*      _uac_data[MAX_FORKING];
  struct
  {
    pjsip_from_hdr* from;
    pjsip_to_hdr*   to;
    pjsip_cid_hdr*  cid;
  } _analytics;
  CallServices::Terminating* _proxy;  //< A proxy inserted into the signalling path, which sees all responses.
  bool                 _pending_destroy;
  int                  _context_count;
  std::list<AsChain*> _victims;  //< Objects to die along with the transaction. Never more than 2.
};

// This is the data that is attached to the UAC transaction
class UACTransaction
{
public:
  UACTransaction(UASTransaction* uas_data, int target, pjsip_transaction* tsx, pjsip_tx_data *tdata);
  ~UACTransaction();

  static UACTransaction* get_from_tsx(pjsip_transaction* tsx);

  void set_target(const struct target& target);
  void send_request();
  void cancel_pending_tsx(int st_code, pj_bool_t integrity_protected);
  void on_tsx_state(pjsip_event* event);
  inline pjsip_method_e method() { return (_tsx != NULL) ? _tsx->method.id : PJSIP_OTHER_METHOD; }
  inline SAS::TrailId trail() { return (_tsx != NULL) ? get_trail(_tsx) : 0; }
  inline const char* name() { return (_tsx != NULL) ? _tsx->obj_name : "unknown"; }

  // Enters/exits this transaction's context.  While in the transaction's
  // context, it will not be destroyed.  enter_context and exit_context should
  // always be called at the start and end of any entry point (e.g. call from
  // non-transaction code into transaction or callback from PJSIP) to avoid
  // the transaction object being destroyed under our feet.  On return from
  // exit_context, you must not assume that the transaction still exists.  Note
  // that this does not prevent the _tsx from being destroyed.
  void enter_context();
  void exit_context();

  friend class UASTransaction;

private:
  UASTransaction      *_uas_data;
  int                  _target;
  pjsip_transaction   *_tsx;
  pjsip_tx_data       *_tdata;
  pj_bool_t            _from_store; /* If true, the aor and binding_id
                                       identify the binding. */
  pj_str_t             _aor;
  pj_str_t             _binding_id;
  bool                 _pending_destroy;
  int                  _context_count;
};

pj_status_t init_stateful_proxy(RegData::Store* registrar_store,
                                CallServices* call_services,
                                IfcHandler* ifc_handler,
                                pj_bool_t enable_edge_proxy,
                                const std::string& upstream_proxy,
                                int upstream_proxy_connections,
                                int upstream_proxy_recycle,
                                pj_bool_t enable_ibcf,
                                const std::string& trusted_hosts,
                                AnalyticsLogger* analytics_logger,
                                EnumService *enumService,
                                BgcfService *bgcfService);

void destroy_stateful_proxy();

#ifdef UNIT_TEST
pj_status_t proxy_process_edge_routing(pjsip_rx_data *rdata,
                                       pjsip_tx_data *tdata);

void proxy_calculate_targets(pjsip_msg* msg,
                             pj_pool_t* pool,
                             target_list& targets,
                             int max_targets);
#endif

#endif
