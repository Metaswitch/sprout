/**
 * @file sproutletproxy.h  Sproutlet controller proxy class definition
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

#ifndef SPROUTLETPROXY_H__
#define SPROUTLETPROXY_H__

#include <map>
#include <unordered_map>
#include <unordered_set>
#include <list>

#include "basicproxy.h"
#include "sproutlet.h"
#include "snmp_sip_request_types.h"
#include "sproutlet_options.h"

class SproutletWrapper;

class SproutletProxy : public BasicProxy, SproutletHelper
{
public:
  /// Constructor.
  ///
  /// @param  endpt             - The pjsip endpoint to associate with.
  /// @param  priority          - The pjsip priority to load at.
  /// @param  host_aliases      - The IP addresses/domains that refer to this proxy.
  /// @param  sproutlets        - Sproutlets to load in this proxy.
  /// @param  stateless_proxies - A set of next-hops that are considered to be
  ///                             stateless proxies.
  SproutletProxy(pjsip_endpoint* endpt,
                 int priority,
                 const std::string& root_uri,
                 const std::unordered_set<std::string>& host_aliases,
                 const std::list<Sproutlet*>& sproutlets,
                 const std::set<std::string>& stateless_proxies);

  /// Destructor.
  virtual ~SproutletProxy();

  /// Static callback for timers
  static void on_timer_pop(pj_timer_heap_t* th, pj_timer_entry* tentry);

  /// Constructs the next hop URI if a Sproutlet doesn't want to handle a
  /// request.
  pjsip_sip_uri* next_hop_uri(const std::string& service,
                              const pjsip_route_hdr* route,
                              pj_pool_t* pool) const;

protected:
  /// Pre-declaration
  class UASTsx;

  /// Create Sproutlet UAS transaction objects.
  BasicProxy::UASTsx* create_uas_tsx();

  /// Registers a sproutlet.
  bool register_sproutlet(Sproutlet* sproutlet);

  /// Gets the next target Sproutlet for the message by analysing the top
  /// Route header.
  Sproutlet* target_sproutlet(pjsip_msg* req,
                              int port,
                              std::string& alias,
                              SAS::TrailId trail);

  /// Return the sproutlet that matches the URI supplied.
  Sproutlet* match_sproutlet_from_uri(const pjsip_uri* uri,
                                      std::string& alias,
                                      SAS::TrailId trail);

  /// Create a URI that routes to a given Sproutlet.
  pjsip_sip_uri* create_sproutlet_uri(pj_pool_t* pool,
                                      Sproutlet* sproutlet) const;

  /// Create a URI that routes to the named sproutlet internally within the
  /// sproutlet proxy.
  ///
  /// @param pool         - Pool to allocate the URI from.
  /// @param name         - The name of the service to invoke.
  /// @param existing_uri - An existing URI to base the new URI on.
  pjsip_sip_uri* create_internal_sproutlet_uri(pj_pool_t* pool,
                                               const std::string& name,
                                               pjsip_sip_uri* existing_uri) const;

  Sproutlet* service_from_host(pjsip_sip_uri* uri);
  Sproutlet* service_from_user(pjsip_sip_uri* uri);
  Sproutlet* service_from_params(pjsip_sip_uri* uri);

  void report_sproutlet_selection_event(int selection_type,
                                        std::string service_name,
                                        std::string value,
                                        std::string uri_str,
                                        SAS::TrailId trail);

  bool is_uri_local(const pjsip_uri* uri);
  bool is_host_local(const pj_str_t* host);

  /// Defintion of a timer set by an child sproutlet transaction.
  struct SproutletTimerCallbackData
  {
    SproutletProxy::UASTsx* uas_tsx;
    SproutletWrapper* sproutlet_wrapper;
    void* context;
  };

  bool schedule_timer(pj_timer_entry* tentry, int duration);
  bool cancel_timer(pj_timer_entry* tentry);
  bool timer_running(pj_timer_entry* tentry);

  class UASTsx : public BasicProxy::UASTsx
  {
  public:
    /// Constructor.
    UASTsx(SproutletProxy* proxy);

    /// Destructor.
    virtual ~UASTsx();

    /// Initializes the UAS transaction.
    virtual pj_status_t init(pjsip_rx_data* rdata);

    /// Handle the incoming half of a transaction request.
    virtual void process_tsx_request(pjsip_rx_data* rdata);

    /// Handle a received CANCEL request.
    virtual void process_cancel_request(pjsip_rx_data* rdata);

    /// Handle a timer pop.
    static void on_timer_pop(pj_timer_heap_t* th, pj_timer_entry* tentry);

  protected:
    /// Handles a response to an associated UACTsx.
    virtual void on_new_client_response(UACTsx* uac_tsx,
                                        pjsip_tx_data *tdata);

    /// Notification that an client transaction is not responding.
    virtual void on_client_not_responding(UACTsx* uac_tsx,
                                          pjsip_event_id_e event);

    virtual void on_tsx_state(pjsip_event* event);


  private:
    void tx_request(SproutletWrapper* sproutlet,
                    int fork_id,
                    pjsip_tx_data* req);

    void schedule_requests();

    void process_timer_pop(pj_timer_entry* tentry);
    bool schedule_timer(SproutletWrapper* tsx, void* context, TimerID& id, int duration);
    bool cancel_timer(TimerID id);
    bool timer_running(TimerID id);

    void tx_response(SproutletWrapper* sproutlet,
                     pjsip_tx_data* rsp);

    void tx_cancel(SproutletWrapper* sproutlet,
                   int fork_id,
                   pjsip_tx_data* cancel);

    /// Checks to see if it is safe to destroy the UASTsx.
    void check_destroy();

    /// Finds a SproutletTsx willing to handle a request
    SproutletTsx* get_sproutlet_tsx(pjsip_tx_data* req,
                                    int port,
                                    std::string& alias);

    /// The root Sproutlet for this transaction.
    SproutletWrapper* _root;

    /// Templated type used to map from upstream Sproutlet/fork to the
    /// downstream Sproutlet or UACTsx.
    template<typename T>
    struct DMap
    {
      typedef std::map<std::pair<SproutletWrapper*, int>, T> type;
      typedef typename std::map<std::pair<SproutletWrapper*, int>, T>::iterator iterator;
    };

    /// Mapping from upstream Sproutlet/fork to downstream Sproutlet.
    DMap<SproutletWrapper*>::type _dmap_sproutlet;

    /// Mapping from upstream Sproutlet/fork to downstream UACTsx.
    DMap<UACTsx*>::type _dmap_uac;

    /// Mapping from downstream Sproutlet or UAC transaction to upstream
    /// Sproutlet/fork.
    typedef std::map<void*, std::pair<SproutletWrapper*, int> > UMap;
    UMap _umap;

    /// Queue of pending requests to be scheduled.
    typedef struct
    {
      pjsip_tx_data* req;
      std::pair<SproutletWrapper*, int> upstream;
    } PendingRequest;
    std::queue<PendingRequest> _pending_req_q;

    /// Parent proxy object
    SproutletProxy* _sproutlet_proxy;

    /// This set holds all the timers created by sproutlet tsxs that are
    /// children of this UASTsx. They are only freed when the UASTsx is freed
    /// (they are not freed when a timer pops or is cancelled for example).
    /// This prevents race conditions (such as a double free caused by one
    /// thread popping a timer and another thread cancelling it).
    std::set<pj_timer_entry*> _timers;

    /// This set holds all the timers created by sproutlet tsx that are
    /// children of this UASTsx that have not popped or been cancelled yet.
    /// The UASTsx will persist while there are pending timers.
    std::set<pj_timer_entry*> _pending_timers;

    friend class SproutletWrapper;
  };

  pjsip_sip_uri* _root_uri;
  std::map<std::string, pjsip_sip_uri*> _root_uris;

  std::unordered_set<std::string> _host_aliases;

  std::map<std::string, Sproutlet*> _services;

  std::map<int, Sproutlet*> _ports;

  std::list<Sproutlet*> _sproutlets;

  static const pj_str_t STR_SERVICE;

  friend class UASTsx;
  friend class SproutletWrapper;
};


class SproutletWrapper : public SproutletTsxHelper
{
public:
  /// Constructor
  SproutletWrapper(SproutletProxy* proxy,
                   SproutletProxy::UASTsx* proxy_tsx,
                   Sproutlet* sproutlet,
                   SproutletTsx* sproutlet_tsx,
                   const std::string& sproutlet_alias,
                   pjsip_tx_data* req,
                   pjsip_transport* original_transport,
                   SAS::TrailId trail_id);

  /// Virtual destructor.
  virtual ~SproutletWrapper();

  const std::string& service_name() const;

  /// This implementation has concrete implementations for all of the virtual
  /// functions from SproutletTsxHelper.  See there for function comments for
  /// the following.
  void add_to_dialog(const std::string& dialog_id="");
  pjsip_msg* original_request();
  void copy_original_transport(pjsip_msg*);
  const char* msg_info(pjsip_msg*);
  const pjsip_route_hdr* route_hdr() const;
  const std::string& dialog_id() const;
  pjsip_msg* create_request();
  pjsip_msg* clone_request(pjsip_msg* req);
  pjsip_msg* clone_msg(pjsip_msg* msg);
  pjsip_msg* create_response(pjsip_msg* req,
                             pjsip_status_code status_code,
                             const std::string& status_text="");
  int send_request(pjsip_msg*& req);
  void send_response(pjsip_msg*& rsp);
  void cancel_fork(int fork_id, int reason=0);
  void cancel_pending_forks(int reason=0);
  const ForkState& fork_state(int fork_id);
  void free_msg(pjsip_msg*& msg);
  pj_pool_t* get_pool(const pjsip_msg* msg);
  bool schedule_timer(void* context, TimerID& id, int duration);
  void cancel_timer(TimerID id);
  bool timer_running(TimerID id);
  SAS::TrailId trail() const;
  bool is_uri_reflexive(const pjsip_uri*) const;
  pjsip_sip_uri* get_reflexive_uri(pj_pool_t*) const;
  pjsip_sip_uri* next_hop_uri(const std::string& service,
                              const pjsip_route_hdr* route,
                              pj_pool_t* pool) const;

private:
  void rx_request(pjsip_tx_data* req);
  void rx_response(pjsip_tx_data* rsp, int fork_id);
  void rx_cancel(pjsip_tx_data* cancel);
  void rx_error(int status_code);
  void rx_fork_error(pjsip_event_id_e event, int fork_id);
  void on_timer_pop(TimerID id, void* context);
  void register_tdata(pjsip_tx_data* tdata);
  void deregister_tdata(pjsip_tx_data* tdata);

  void process_actions(bool complete_after_actions);
  void aggregate_response(pjsip_tx_data* rsp);
  void tx_request(pjsip_tx_data* req, int fork_id);
  void tx_response(pjsip_tx_data* rsp);
  void tx_cancel(int fork_id);
  int compare_sip_sc(int sc1, int sc2);
  bool is_uri_local(const pjsip_uri*) const;
  void log_inter_sproutlet(pjsip_tx_data* tdata, bool downstream);

  SproutletProxy* _proxy;

  SproutletProxy::UASTsx* _proxy_tsx;

  Sproutlet* _sproutlet;

  SproutletTsx* _sproutlet_tsx;

  std::string _service_name;
  std::string _service_host;

  /// Identifier for this SproutletTsx instance - currently a concatenation
  /// of the service name and the address of the object.
  std::string _id;

  /// Reference to the original request. This can been modified by the Sproutlet
  /// Proxy depending on where it sends this message. A clone of this is passed
  /// to the root Sproutlet.
  pjsip_tx_data* _req;
  SNMP::SIPRequestTypes _req_type;

  // Immutable reference to the transport used by the original request.
  pjsip_transport* _original_transport;

  typedef std::unordered_map<const pjsip_msg*, pjsip_tx_data*> Packets;
  Packets _packets;

  typedef std::map<int, pjsip_tx_data*> Requests;
  Requests _send_requests;

  typedef std::list<pjsip_tx_data*> Responses;
  Responses _send_responses;

  int _pending_sends;
  int _pending_responses;
  pjsip_tx_data* _best_rsp;

  bool _complete;

  // All the actions are performed within SproutletWrapper::process_actions,
  // including deleting the SproutletWrapper itself.  However, process_actions
  // can be re-entered - it sends messages, which can fail and call back into
  // the SproutletWrapper synchronously.  This counter counts how many times
  // the method has currently been entered - if it is non-zero, the
  // SproutletWrapper must not be destroyed.
  int _process_actions_entered;

  /// Vector keeping track of the status of each fork.  The state field can
  /// only ever take a subset of the values defined by PJSIP - NULL, CALLING,
  /// PROCEEDING and TERMINATED.
  typedef struct
  {
    ForkState state;
    pjsip_tx_data* req;
    bool pending_cancel;
    int cancel_reason;
  } ForkStatus;
  std::vector<ForkStatus> _forks;

  /// Set keeping track of pending timers for this SproutletWrapper.  The
  /// SproutletWrapper (and the SproutletTsx it wraps) won't be deleted
  /// until all these timers have popped or been cancelled.
  std::set<TimerID> _pending_timers;

  SAS::TrailId _trail_id;

  friend class SproutletProxy::UASTsx;
};

#endif
