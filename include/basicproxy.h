/**
 * @file basicproxy.cpp  BasicProxy class implementation
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
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


#ifndef _BASICPROXY_H__
#define _BASICPROXY_H__

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}

#include <utility>
#include <vector>
#include <list>

#include "stack.h"
#include "sipresolver.h"
#include "pjmodule.h"
#include "rfacr.h"


/// Class implementing basic SIP proxy functionality.  Various methods in
/// this class can be overriden to implement different proxy behaviours.
class BasicProxy
{
public:
  BasicProxy(pjsip_endpoint* endpt,
             std::string name,
             SIPResolver* sipresolver,
             RfACRFactory* acr_factory,
             int priority,
             bool delay_trying);
  virtual ~BasicProxy();

  virtual pj_bool_t on_rx_request(pjsip_rx_data* rdata);
  virtual pj_bool_t on_rx_response(pjsip_rx_data* rdata);
  virtual pj_status_t on_tx_request(pjsip_tx_data* tdata);
  virtual pj_status_t on_tx_response(pjsip_tx_data* tdata);
  virtual void on_tsx_state(pjsip_transaction* tsx, pjsip_event* event);

protected:

  /// Class holding the details of a calculated target for a transaction.
  class Target
  {
  public:
    Target() :
      uri(NULL),
      paths(),
      transport(NULL)
    {
    }
    pjsip_uri* uri;
    std::list<pjsip_uri*> paths;
    pjsip_transport* transport;
  };

  class UACTsx;

  /// Class tracking the UAS-related state for a proxied transaction.
  class UASTsx
  {

  public:
    /// Constructor.
    UASTsx(BasicProxy* proxy);

    /// Destructor.
    virtual ~UASTsx();

    /// Returns the name of the underlying PJSIP transaction.
    inline const char* name() { return (_tsx != NULL) ? _tsx->obj_name : "unknown"; }

    /// Initializes the UAS transaction.
    virtual pj_status_t init(pjsip_rx_data* rdata, pjsip_tx_data* tdata);

    /// Adds a target to the target list for this transaction.
    virtual void add_target(BasicProxy::Target* target);

    /// Handle the incoming half of a transaction request.
    virtual void process_tsx_request();

    /// Initializes UAC transactions to each of the specified targets.
    /// @returns a status code indicating whether or not the operation succeeded.
    virtual pj_status_t init_uac_transactions();

    /// Handles a response to an associated UACTransaction.
    virtual void on_new_client_response(UACTsx* uac_tsx,
                                        pjsip_rx_data *rdata);

    /// Notification that a client transaction is not responding.
    virtual void on_client_not_responding(UACTsx* uac_tsx);

    /// Notification that the underlying PJSIP transaction has changed state.
    /// After calling this, the caller must not assume that the UASTsx still
    /// exists - if the PJSIP transaction is being destroyed, this method will
    /// destroy the UASTsx.
    virtual void on_tsx_state(pjsip_event* event);

    /// Cancels all pending UAC transactions associated with this UAS transaction.
    virtual void cancel_pending_uac_tsx(int st_code, bool dissociate_uac);

    /// Enters this transaction's context.  While in the transaction's
    /// context, it will not be destroyed.  Whenever enter_context is called,
    /// exit_context must be called before the end of the method.
    void enter_context();

    /// Exits this transaction's context.  On return from this method, the caller
    /// must not assume that the transaction still exists.
    void exit_context();

  protected:
    /// Calculate targets for requests where Route headers do not determine
    /// the target.
    virtual int calculate_targets(pjsip_tx_data* tdata);

    /// Called when the final response has been determined and should be sent
    /// back on the UAS transaction.
    /// @Returns whether or not the send was a success.
    virtual void on_final_response();

    /// Sends a response using the buffer saved off for the best response.
    /// @Returns whether or not the send was a success.
    virtual void send_response(int st_code,
                               const pj_str_t* st_text=NULL);

    /// Called when a new transaction is starting.
    virtual void on_tsx_start(const pjsip_rx_data* rdata);

    /// Called when a transaction completes.
    virtual void on_tsx_complete();

    /// Compare SIP status codes.
    virtual int compare_sip_sc(int sc1, int sc2);

    /// Disassociates the specified UAC transaction from this UAS transaction,
    /// and vice-versa.  This must be called before destroying either transaction.
    void dissociate(UACTsx* uac_tsx);

    /// Creates a new downstream UACTsx object for this transaction.
    virtual BasicProxy::UACTsx* create_uac_tsx(size_t index);

    /// Returns the SAS trail identifier attached to the transaction.
    SAS::TrailId trail() const { return (_tsx != NULL) ? get_trail(_tsx) : 0; }

    /// Owning proxy object.
    BasicProxy* _proxy;

    /// A pointer to the original request.  This is valid throughout the
    /// lifetime of this object, so can be used to retry the request or fork
    /// to additional targets if required.
    pjsip_tx_data* _req;

    /// Pointer to the underlying PJSIP UAS transaction.
    pjsip_transaction* _tsx;

    /// PJSIP group lock used to protect all PJSIP UAS and UAC transactions
    /// involved in this proxied request.
    pj_grp_lock_t* _lock;

    /// Targets the request is forked to.
    std::list<Target*> _targets;

    /// Associated UACTsx objects for each forked request.
    std::vector<UACTsx*> _uac_tsx;

    /// Count of targets the request was forked to that have yet to respond.
    size_t _pending_targets;

    /// A pointer to the best response received so far.  This is initialised
    /// to a 408 Request Timeout response.
    pjsip_tx_data* _best_rsp;

    bool _pending_destroy;
    int _context_count;

    friend class UACTsx;
  };


  /// Class implementing the UAC side of a proxied transaction.  There may be
  /// multiple instances of this class for a single proxied transaction if it
  /// is forked.
  class UACTsx
  {
  public:
    /// UAC Transaction constructor
    UACTsx(BasicProxy* proxy, UASTsx* uas_tsx, size_t index);
    virtual ~UACTsx();

    /// Returns the name of the underlying PJSIP transaction.
    inline const char* name() { return (_tsx != NULL) ? _tsx->obj_name : "unknown"; }

    /// Initializes a UAC transaction.
    virtual pj_status_t init(pjsip_tx_data* tdata);

    /// Set the target for this UAC transaction.
    virtual void set_target(BasicProxy::Target* target);

    /// Sends the initial request on this UAC transaction.
    virtual void send_request();

    /// Cancels the pending transaction, using the specified status code in the
    /// Reason header.
    virtual void cancel_pending_tsx(int st_code);

    /// Notification that the underlying PJSIP transaction has changed state.
    /// After calling this, the caller must not assume that the UACTransaction still
    /// exists - if the PJSIP transaction is being destroyed, this method will
    /// destroy the UACTransaction.
    virtual void on_tsx_state(pjsip_event* event);

    // Enters this transaction's context.  While in the transaction's
    // context, it will not be destroyed.  Whenever enter_context is called,
    // exit_context must be called before the end of the method.
    void enter_context();

    // Exits this transaction's context.  On return from this method, the caller
    // must not assume that the transaction still exists.
    void exit_context();

  protected:
    /// Owning proxy object.
    BasicProxy* _proxy;

    /// Parent UASTsx object if still associated, NULL when this UACTsx is
    /// orphaned.
    UASTsx* _uas_tsx;

    /// PJSIP group lock used to protect all PJSIP UAS and UAC transactions
    /// involved in this proxied request.
    pj_grp_lock_t* _lock;

    /// Index of this UACTsx object within the parent.  Always zero
    /// for non-forked transactions.
    int _index;

    /// Pointer to the associated PJSIP UAC transaction.
    pjsip_transaction* _tsx;

    /// The request data for this transaction.  This is only valid prior to
    /// sending the request, and should not be accessed afterwards.
    pjsip_tx_data* _tdata;

    /// A pointer to the transport selected for this transaction.
    pjsip_transport* _transport;

    /// The resolved server address for this transaction.
    bool _resolved;
    AddrInfo _ai;

    bool _pending_destroy;
    int _context_count;

    friend class UASTsx;
  };

  void bind_transaction(void* uas_uac_tsx, pjsip_transaction* tsx);
  void unbind_transaction(pjsip_transaction* tsx);
  void* get_from_transaction(pjsip_transaction* tsx);

  virtual void on_tsx_request(pjsip_rx_data* rdata);
  virtual void on_cancel_request(pjsip_rx_data* rdata);

  /// Utility to verify incoming requests.
  /// Return non-zero if verification failed.
  virtual pj_status_t verify_request(pjsip_rx_data *rdata);

  /// Process route information in the request.
  virtual int process_routing(pjsip_tx_data* tdata,
                              BasicProxy::Target*& target);

  /// Utility method to create a UASTsx objects for incoming requests.
  virtual BasicProxy::UASTsx* create_uas_tsx();

  /// PJModule binding a pjsip_module to an instance of this class for the
  /// on_rx_request and on_rx_response callbacks.
  static const int PJMODULE_MASK_PROXY = PJCallback::ON_RX_REQUEST|
                                         PJCallback::ON_RX_RESPONSE;
  PJModule<BasicProxy, 1> _mod_proxy;

  /// PJModule binding a pjsip_module to an instance of this class for the
  /// on_tsx_state callbacks.
  static const int PJMODULE_MASK_TU = PJCallback::ON_TSX_STATE;
  PJModule<BasicProxy, 2> _mod_tu;

  /// A pointer to the SIP resolver used to resolve URI targets to servers.
  SIPResolver* _sipresolver;

  /// Factory for generating Rf ACR messages.
  RfACRFactory* _acr_factory;

  /// Indicates that 100 Trying response to INVITE requests should be delayed
  /// until at least one downstream node has sent a 100 Trying response.
  bool _delay_trying;

  friend class UASTsx;
  friend class UACTsx;

};

#endif
