/**
 * @file basicproxy.cpp  BasicProxy class implementation
 *
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


#ifndef _BASICPROXY_H__
#define _BASICPROXY_H__

#include <utility>
#include <vector>
#include <list>
#include <set>

#include "fork_error_state.h"
#include "stack.h"
#include "pjmodule.h"
#include "acr.h"

/// Class implementing basic SIP proxy functionality.  Various methods in
/// this class can be overriden to implement different proxy behaviours.
class BasicProxy
{
public:
  BasicProxy(pjsip_endpoint* endpt,
             std::string name,
             int priority,
             bool delay_trying,
             const std::set<std::string>& stateless_proxies);
  virtual ~BasicProxy();

  virtual pj_bool_t on_rx_request(pjsip_rx_data* rdata);
  virtual pj_bool_t on_rx_response(pjsip_rx_data* rdata);
  virtual pj_status_t on_tx_request(pjsip_tx_data* tdata);
  virtual pj_status_t on_tx_response(pjsip_tx_data* tdata);
  virtual void on_tsx_state(pjsip_transaction* tsx, pjsip_event* event);

  void bind_transaction(void* uas_uac_tsx, pjsip_transaction* tsx);
  void unbind_transaction(pjsip_transaction* tsx);

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
    virtual pj_status_t init(pjsip_rx_data* rdata);

    /// Handle the incoming half of a transaction request.
    virtual void process_tsx_request(pjsip_rx_data* rdata);

    /// Handle a received CANCEL request.
    virtual void process_cancel_request(pjsip_rx_data* rdata, const std::string& reason);

    /// Handles a response to an associated UACTsx.
    virtual void on_new_client_response(UACTsx* uac_tsx,
                                        pjsip_tx_data *tdata);

    /// Notification that an client transaction is not responding.
    virtual void on_client_not_responding(UACTsx* uac_tsx,
                                          ForkErrorState fork_error,
                                          const std::string& reason);

    /// Notification that a response is being transmitted on this transaction.
    virtual void on_tx_response(pjsip_tx_data* tdata);

    /// Notification that a request is being transmitted to a client.
    virtual void on_tx_client_request(pjsip_tx_data* tdata, UACTsx* uac_tsx);

    /// Notification that the underlying PJSIP transaction has changed state.
    /// After calling this, the caller must not assume that the UASTsx still
    /// exists - if the PJSIP transaction is being destroyed, this method will
    /// destroy the UASTsx.
    virtual void on_tsx_state(pjsip_event* event);

    /// Cancels all pending UAC transactions associated with this UAS transaction.
    virtual void cancel_pending_uac_tsx(int st_code,
                                        const std::string& reason,
                                        bool dissociate_uac);

    /// Enters this transaction's context.  While in the transaction's
    /// context, it will not be destroyed.  Whenever enter_context is called,
    /// exit_context must be called before the end of the method.
    void enter_context();

    /// Exits this transaction's context.  On return from this method, the caller
    /// must not assume that the transaction still exists.
    void exit_context();

    void trying_timer_expired();
    static void trying_timer_callback(pj_timer_heap_t *timer_heap, struct pj_timer_entry *entry);
    pj_status_t send_trying(pjsip_rx_data* rdata);

  protected:
    /// Process route information in the request.
    virtual int process_routing();

    /// Create a PJSIP transaction for the request.
    virtual pj_status_t create_pjsip_transaction(pjsip_rx_data* rdata);

    /// Adds a target to the target list for this transaction.
    virtual void add_target(BasicProxy::Target* target);

    /// Initializes UAC transactions to each of the specified targets and
    /// forwards the request.
    /// @returns a status code indicating whether or not the operation succeeded.
    virtual pj_status_t forward_to_targets();

    /// Adds the target information to a request ready to send.
    virtual void set_req_target(pjsip_tx_data* tdata, BasicProxy::Target* target);

    /// Allocates and initializes a UAC transaction.
    virtual pj_status_t allocate_uac(pjsip_tx_data* tdata,
                                     size_t& index,
                                     int allowed_host_state);

    /// Forwards a request, allocating and initializing the transaction.
    virtual pj_status_t forward_request(pjsip_tx_data* tdata, size_t& index);

    /// Calculate targets for requests where Route headers do not determine
    /// the target.
    virtual int calculate_targets();

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

    /// Unbind this UASTSx from the PJSIP transaction (if any) and cancel any
    /// timers that should only be running when the UASTsx is bound.
    void unbind_from_pjsip_tsx();

    /// Creates a new downstream UACTsx object for this transaction.
    virtual BasicProxy::UACTsx* create_uac_tsx(size_t index);

    /// Returns the SAS trail identifier attached to the transaction.
    SAS::TrailId trail() const { return _trail; }

    /// Owning proxy object.
    BasicProxy* _proxy;

    /// A pointer to the original request.  This is valid throughout the
    /// lifetime of this object, so can be used to retry the request or fork
    /// to additional targets if required.
    pjsip_tx_data* _req;

    /// Pointer to the transport associated with the original request.
    pjsip_transport* _original_transport;

    /// Pointer to the underlying PJSIP UAS transaction.
    pjsip_transaction* _tsx;

    /// PJSIP group lock used to protect all PJSIP UAS and UAC transactions
    /// involved in this proxied request.
    pj_grp_lock_t* _lock;

    /// The trail identifier for the transaction/request.
    SAS::TrailId _trail;

    /// Targets the request is forked to.
    std::list<Target*> _targets;

    /// Associated UACTsx objects for each forked request.
    std::vector<UACTsx*> _uac_tsx;

    /// Count of targets the request is about to be forked to.
    size_t _pending_sends;

    /// Count of targets the request was forked to that have yet to respond.
    size_t _pending_responses;

    /// A pointer to the best final response received so far.  This is
    /// initialised to a 408 Request Timeout response.
    pjsip_tx_data* _final_rsp;

    bool _pending_destroy;
    int _context_count;

    pj_timer_entry       _trying_timer;
    static const int     TRYING_TIMER = 1;

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

    /// Returns the index of this UACTsx.
    inline int index() { return _index; }

    /// Initializes a UAC transaction.
    virtual pj_status_t init(pjsip_tx_data* tdata, int allowed_host_state);

    /// Sends the initial request on this UAC transaction.
    virtual void send_request();

    /// Cancels the pending transaction, using the specified status code in the
    /// Reason header.
    virtual void cancel_pending_tsx(int st_code, const std::string& reason);

    /// Attempts a retry of the request.
    virtual bool retry_request();

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

    /// Static function called when a timer expires.
    static void timer_expired(pj_timer_heap_t *timer_heap,
                              struct pj_timer_entry *entry);

  protected:
    /// Helper class to make sure that targets are blacklisted or whitelisted,
    /// even in the event the calling code does not make a definitive decision.
    class Target
    {
    public:
      Target();
      ~Target();

      /// Tell the Target about an address and whether it represents a stateless
      /// proxy.
      /// @param addr - The address in question.
      /// @param blacklist_by_default
      ///             - Whether to blacklist the address when we have finished
      ///               with it (if the state of the address is not known).
      void set(AddrInfo& addr, bool blacklist_by_default);

      /// Helper method to check if the Target had been initialized with an
      /// address.
      /// @param - Whether the Target has an address.
      bool is_set();

      /// Helper method to access the address of the target.
      /// @return - A reference to the address.
      const AddrInfo& address();

      /// Mark this target as having definitively failed.
      void failed();

      /// Mark this target as having definitively succeeded.
      void succeeded();

    protected:
      AddrInfo _addr;
      bool _is_set;
      bool _health_known;
      bool _blacklist_by_default;

      // This class is not copyable or moveable. If it were, the semantics of
      Target(const Target& rhs) = delete;
      Target(Target&& rhs) = delete;

      // Unset the address in the target. If the address has not already been
      // blacklisted or whitelisted, this method will do that.
      void unset();
    };

    /// Returns the SAS trail identifier attached to the transaction.
    SAS::TrailId trail() const { return _trail; }

    /// Starts Timer C on the UAC transaction.
    void start_timer_c();

    /// Stops Timer C on the UAC transaction.
    void stop_timer_c();

    /// Called when timer C expires.
    void timer_c_expired();

    /// Called to get the next server to try, which is stored in
    /// _current_server. Returns false if there are no servers or left, or if
    /// the maximum number of attempts has been attempted.
    bool get_next_server();

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

    /// The request data for this transaction.  The reference count is
    /// incremented on this request so it is available for retries even
    /// after it has been passed to PJSIP for sending.
    pjsip_tx_data* _tdata;

    /// Iterator to the list of available servers.
    BaseAddrIterator* _servers_iter;

    /// Current server target.
    Target _current_server;

    /// Pointer to the associated PJSIP UAC transaction used to send a
    /// CANCEL request.  NULL if no CANCEL has been sent.
    pjsip_transaction* _cancel_tsx;

    /// Timer C timer entry.  This timer runs while the downstream UAC
    /// transaction is active.  If the timer expires, the transaction is
    /// either cancelled or reported as non-responsive.
    pj_timer_entry _timer_c;

    SAS::TrailId _trail;

    bool _pending_destroy;
    int _context_count;

    // Whether this UAC transaction is to a stateless proxy.
    bool _stateless_proxy;

    // Tracks how many attempts the UACTsx has left to try the request.
    int _num_attempts_left;

    friend class UASTsx;

    static const int TIMER_C = 3;
  };

  void* get_from_transaction(pjsip_transaction* tsx);

  virtual void on_tsx_request(pjsip_rx_data* rdata);
  virtual void on_cancel_request(pjsip_rx_data* rdata);

  /// Utility to verify incoming requests.
  /// Return the SIP status code if verification failed.
  virtual int verify_request(pjsip_rx_data* rdata);

  /// Rejects a received request statelessly.
  virtual void reject_request(pjsip_rx_data* rdata, int status_code);

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

  /// Indicates that 100 Trying response to INVITE requests should be delayed
  /// until at least one downstream node has sent a 100 Trying response.
  bool _delay_trying;

  /// The pjsip endpoint this proxy is associated with.
  pjsip_endpoint* _endpt;

  /// Set of next hops that are considered stateless proxies.  A stateless proxy
  /// does not generate 100 trying responses itself, and does not perform
  /// retries if devices further downstream fail.
  ///
  /// Normally if a next hop is unresponsive it is temporarily blacklisted.
  /// However for a stateless proxy it may be that the device downstream of it
  /// is the one that is actually being unresponsive, so blacklisting the
  /// stateless proxy is incorrect (and in the case of a pool of proxies
  /// fronting a pool of downstream servers, one downstream server failing could
  /// cause the entire pool to be blacklisted).  Therefore downstream proxies
  /// are only blacklisted in the event of a transport error, not by a SIP
  /// transaction timeout.
  ///
  /// When determining whether a next hop is a stateless proxy, the SIP-level
  /// identifier of the next hop is used. For example if there are two servers
  /// acting as a stateless proxy pool identified by the domain-name
  /// pool.example.com, then the `_stateless_proxies` set should contain the
  /// entry "pool.example.com", not one entry for each server.
  std::set<std::string> _stateless_proxies;

  friend class UASTsx; friend class UACTsx;
};

#endif
