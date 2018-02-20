/**
 * @file scscfsproutlet.h Definition of the S-CSCF Sproutlet classes,
 *                        implementing S-CSCF specific SIP proxy functions.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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
#include "stack.h"
#include "sessioncase.h"
#include "ifchandler.h"
#include "hssconnection.h"
#include "aschain.h"
#include "acr.h"
#include "sproutlet.h"
#include "snmp_counter_table.h"
#include "session_expires_helper.h"
#include "as_communication_tracker.h"
#include "compositesproutlet.h"
#include "subscriber_manager.h"
#include "httpclient.h"

class SCSCFSproutletTsx;

/// @class SCSCFSproutlet
///
/// The S-CSCF sproutlet class, built off the base sproutlet class.
/// This contains the functionality for the S-CSCF sproutlet.
class SCSCFSproutlet : public Sproutlet
{
public:
  /// Default timeouts for waiting for a response from an AS with its default
  /// handling set to session continued and session terminated.
  static const int DEFAULT_SESSION_CONTINUED_TIMEOUT = 2000;
  static const int DEFAULT_SESSION_TERMINATED_TIMEOUT = 4000;

  /// SCSCFSproutlet constructor.
  SCSCFSproutlet(const std::string& name,
                 const std::string& scscf_name,
                 const std::string& scscf_cluster_uri,
                 const std::string& scscf_node_uri,
                 const std::string& icscf_uri,
                 const std::string& bgcf_uri,
                 int port,
                 const std::string& uri,
                 const std::string& network_function,
                 const std::string& next_hop_service,
                 SubscriberManager* sm,
                 EnumService* enum_service,
                 ACRFactory* acr_factory,
                 SNMP::SuccessFailCountByRequestTypeTable* incoming_sip_transactions_tbl,
                 SNMP::SuccessFailCountByRequestTypeTable* outgoing_sip_transactions_tbl,
                 bool override_npdi,
                 FIFCService* fifcservice,
                 IFCConfiguration ifc_configuration,
                 int session_continued_timeout = DEFAULT_SESSION_CONTINUED_TIMEOUT,
                 int session_terminated_timeout = DEFAULT_SESSION_TERMINATED_TIMEOUT,
                 AsCommunicationTracker* sess_term_as_tracker = NULL,
                 AsCommunicationTracker* sess_cont_as_tracker = NULL);

  /// SCSCFSproutlet destructor.
  ~SCSCFSproutlet();

  /// Creates the S-CSCF sproutlet.
  ///
  /// @return - True if creation was successful, false otherwise.
  bool init();

  /// Creates a SCSCFSproutletTsx instance for performing S-SCSCF service
  /// processing on a request.
  SproutletTsx* get_tsx(SproutletHelper* helper,
                        const std::string& alias,
                        pjsip_msg* req,
                        pjsip_sip_uri*& next_hop,
                        pj_pool_t* pool,
                        SAS::TrailId trail);

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

  /// Returns the service name of the entire S-CSCF.
  const std::string scscf_service_name() const;

  /// Returns the configured S-CSCF cluster URI for this system.
  const pjsip_uri* scscf_cluster_uri() const;

  /// Returns the configured S-CSCF node URI for this system.
  const pjsip_uri* scscf_node_uri() const;

  /// Returns the configured I-CSCF URI for this system.
  const pjsip_uri* icscf_uri() const;

  /// Returns the configured BGCF URI for this system.
  const pjsip_uri* bgcf_uri() const;

  /// Returns an instance of the fallback iFC class, which contains any fallback
  /// iFCs that the S-CSCF should apply.
  FIFCService* fifcservice() const;

  /// Returns a structure containing details of the iFC configuration
  /// (ie. whether or not fallback iFCs be applied).
  IFCConfiguration ifc_configuration() const;

  /// Gets all bindings for the specified public ID from the Subscriber Manager.
  ///
  /// @param[in]  public_id  - The public ID of the subscriber.
  /// @param[out] bindings   - The bindings stored for this subscriber.
  /// @param[in]  trail      - The SAS trail ID.
  void get_bindings(const std::string& public_id,
                    Bindings& bindings,
                    SAS::TrailId trail);

  /// Freed the bindings object, which was returned by the subscriber manager,
  /// as this object is owned by the sproutlet.
  ///
  /// @param[in] bindings  - The bindings object to free.
  void free_bindings(Bindings& bindings);

  /// Removes the binding, specified by its binding ID, using the Subscriber
  /// Manager.
  ///
  /// @param[in]  binding_id  - The ID of the binding to remove.
  /// @param[in]  aor_id      - The public ID of the subscriber to remove the
  ///                           binding from.
  /// @param[out] bindings    - The bindings belonging to the subscriber (after
  ///                           removal).
  /// @param[in]  trail       - The SAS trail ID.
  void remove_binding(const std::string& binding_id,
                      const std::string& aor_id,
                      Bindings& bindings,
                      SAS::TrailId trail);

  /// Record that communication with an AS failed.
  ///
  /// @param uri               - The URI of the AS.
  /// @param reason            - Textual representation of the reason the AS is
  ///                            being treated as failed.
  /// @param default_handling  - The AS's default handling.
  void track_app_serv_comm_failure(const std::string& uri,
                                   const std::string& reason,
                                   DefaultHandling default_handling);

  /// Record that communication with an AS succeeded.
  ///
  /// @param uri               - The URI of the AS.
  /// @param default_handling  - The AS's default handling.
  void track_app_serv_comm_success(const std::string& uri,
                                   DefaultHandling default_handling);

  /// Record the time an INVITE took to reach ringing state.
  ///
  /// @param tsx_start_time_usec  - The time the request was received.
  /// @param video_call           - True if INVITE was for a video session,
  ///                               false otherwise.
  void track_session_setup_time(uint64_t tsx_start_time_usec, bool video_call);

  /// Translate RequestURI using ENUM service if appropriate.
  ///
  /// @param req    - The request containing the RequestURI.
  /// @param pool   - The pool correspnding to the request.
  /// @param trail  - The SAS trail ID.
  void translate_request_uri(pjsip_msg* req,
                             pj_pool_t* pool,
                             SAS::TrailId trail);

  /// Get an ACR instance from the factory.
  ///
  /// @param trail      - The SAS trail ID.
  /// @param initiator  - The initiator of the SIP transaction (calling or
  ///                     called party).
  /// @param role       - Node role (originating or terminating).
  ACR* get_acr(SAS::TrailId trail,
               ACR::Initiator initiator,
               ACR::NodeRole role);

  friend class SCSCFSproutletTsx;

  /// The service name of the entire S-CSCF.
  std::string _scscf_name;

  /// A URI which routes to the S-CSCF cluster.
  pjsip_uri* _scscf_cluster_uri;

  /// A URI which routes to this particular S-CSCF node.
  /// This must be constructed using an IP address or a domain name which
  /// resolves to this Sprout node only.
  pjsip_uri* _scscf_node_uri;

  /// A URI which routes to the URI cluster.
  pjsip_uri* _icscf_uri;

  /// A URI which routes to the BGCF.
  pjsip_uri* _bgcf_uri;

  std::string _next_hop_service;

  /// The subscriber manager class instance used by the S-CSCF.
  SubscriberManager* _sm;

  /// The enum service class instance used by the S-CSCF.
  EnumService* _enum_service;

  /// Instance of class used for creating null ACR instances.
  ACRFactory* _acr_factory;

  /// The AS chain table object used to manage AS chains and the associated ODI
  /// tokens.
  AsChainTable* _as_chain_table;

  bool _override_npdi;

  /// Instance of the fallback iFC class, which contains any fallback iFCs that
  /// the S-CSCF should apply.
  FIFCService* _fifcservice;

  /// Structure containing details of the iFC configuration (ie. whether or not
  /// fallback iFCs be applied).
  IFCConfiguration _ifc_configuration;

  /// Timeouts related to default handling of unresponsive application servers.
  int _session_continued_timeout_ms;
  int _session_terminated_timeout_ms;

  /// String versions of the cluster URIs.
  std::string _scscf_cluster_uri_str;
  std::string _scscf_node_uri_str;
  std::string _icscf_uri_str;
  std::string _bgcf_uri_str;

  /// String tables to be used by the S-CSCF sproutlet.
  SNMP::CounterTable* _routed_by_preloaded_route_tbl = NULL;
  SNMP::CounterTable* _invites_cancelled_before_1xx_tbl = NULL;
  SNMP::CounterTable* _invites_cancelled_after_1xx_tbl = NULL;
  SNMP::EventAccumulatorTable* _video_session_setup_time_tbl = NULL;
  SNMP::EventAccumulatorTable* _audio_session_setup_time_tbl = NULL;
  SNMP::CounterTable* _forked_invite_tbl = NULL;
  SNMP::CounterTable* _barred_calls_tbl = NULL;

  // AS communication trackers, to keep track of number of successful/failed
  // communications with ASs.
  AsCommunicationTracker* _sess_term_as_tracker;
  AsCommunicationTracker* _sess_cont_as_tracker;
};


/// @class SCSCFSproutletTsx
///
/// S-SCSCF sproutlet transaction class. Used to perform S-CSCF processing on a
/// single request.
class SCSCFSproutletTsx : public CompositeSproutletTsx
{
public:
  /// SCSCFSproutletTsx constructor.
  SCSCFSproutletTsx(SCSCFSproutlet* scscf,
                    const std::string& next_hop_service,
                    pjsip_method_e req_type);

  /// SCSCFSproutletTsx destructor.
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
  ///
  /// @param req  - The request being handled.
  void retrieve_odi_and_sesscase(pjsip_msg* req);

  /// Determines the served user for the request.
  ///
  /// @param req  - The request being handled.
  pjsip_status_code determine_served_user(pjsip_msg* req);

  /// Gets the served user indicated in the message.
  std::string served_user_from_msg(pjsip_msg* msg);

  /// Creates an AS chain for this service role and links this service hop to
  /// it. The AS chain must be released once it has been used.
  ///
  /// @param[in] ifcs         - iFCs belonging to the served user.
  /// @param[in] served_user  - The served user for the request.
  /// @param[in] acr          - The ACR object associated with the AS chain.
  /// @param[in] chain_trail  - The SAS trail ID.
  AsChainLink create_as_chain(Ifcs ifcs,
                              std::string served_user,
                              ACR*& acr,
                              SAS::TrailId chain_trail);

  /// Check whether the request has been retargeted, given the updated URI.
  ///
  /// @return                     - True if a retarget has taken place, false
  ///                               otherwise.
  /// @param[in] new_served_user  - The new served user, from a request returned
  ///                               by an AS.
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
  ///
  /// @param req      - The request to route
  /// @param reason   - The SAS Event ID to log as the reason
  void route_to_bgcf(pjsip_msg* req, int reason);

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

  /// Look up the registration state for the given public ID, using the
  /// per-transaction cache, which will be present at this point.
  bool is_user_registered(std::string public_id);

  /// Look up the associated URIs for the given public ID, using the cache if
  /// possible (and caching the subscriber data otherwise).
  ///
  /// The uris parameter is only filled in correctly if this function
  /// returns true.
  ///
  /// @return                - True if the associated uris have been correctly
  ///                          returned, false otherwise.
  /// @param[in]  public_id  - The public ID whose associated URIs are being
  ///                          looked up.
  /// @param[out] uris       - The associated uris for the public ID passed in.
  bool get_associated_uris(std::string public_id,
                           std::vector<std::string>& uris);

  /// Look up the aliases for the given public ID, using the cache if
  /// possible (and caching the subscriber data otherwise).
  ///
  /// The aliases parameter is only filled in correctly if this function
  /// returns true.
  ///
  /// @return                - True if the aliases have been correctly returned,
  ///                          false otherwise.
  /// @param[in]  public_id  - The public ID whose aliases are being looked up.
  /// @param[out] aliases    - The aliases for the public ID passed in.
  bool get_aliases(std::string public_id,
                   std::vector<std::string>& aliases);

  /// Look up the iFCs for the given public ID, using the cache if possible
  /// (and caching the subscriber data otherwise).
  ///
  /// Returns the HTTP result code obtained from homestead (passed through the
  /// subscriber manager).
  /// The ifcs parameter is only filled in correctly if this function
  /// returns HTTP_OK.
  ///
  /// @return                - The HTTP result code from homestead (passed
  ///                          through the subscriber manager).
  /// @param[in]  public_id  - The public ID whose iFCs are being looked up.
  /// @param[out] ifcs       - The iFCs for the public ID passed in.
  HTTPCode lookup_ifcs(std::string public_id,
                       Ifcs& ifcs);

  /// Gets the subscriber's data (associated URIs, iFCs...) from the cache if
  /// possible, or from the subscriber manager (which talks to homestead, which
  /// talks to the HSS) if the data isn't cached, and then caches the data.
  /// Class variables are set containing the info returned by the HSS, which is
  /// why this function doesn't need to return this info.
  ///
  /// @return               - The HTTP result code from the subscriber manager.
  /// @param[in] public_id  - The public ID of the subscriber whose info is
  ///                         being looked up.
  HTTPCode get_data_from_hss(std::string public_id);

  /// Asks the subscriber manager to fetch the subscriber's data (associated
  /// URIs, iFCs...) from homestead (which talks to the HSS).
  /// Class variables are set containing the info returned by the HSS, which is
  /// why this function doesn't need to return this info.
  ///
  /// @return               - The HTTP result code from the subscriber manager.
  /// @param[in] public_id  - The public ID of the subscriber whose info is
  ///                         being looked up.
  /// @param[in] irs_query  - IRS query containing details about the subscriber,
  ///                         to allow them to be found.
  HTTPCode read_hss_data(std::string public_id,
                         const HSSConnection::irs_query& irs_query);

  /// Add the S-CSCF sproutlet into a dialog.
  /// The third parameter passed may be attached to the Record-Route and can be
  /// used to recover the billing role that is in use on subsequent in-dialog
  /// messages.
  ///
  /// @param msg           - The message that we are currently processing.
  /// @param billing_rr    - Whether to add a `billing-role` parameter to the
  ///                        RR.
  /// @param billing_role  - The contents of the `billing-role` (ignored if
  ///                        `billing_rr` is false). This should be used when
  ///                        generating future ACRs.
  void add_to_dialog(pjsip_msg* msg,
                     bool billing_rr,
                     ACR::NodeRole billing_role);

  // Inspects the charging-role in the top route header of the incoming message
  // to determine whether this is a transaction that we should generate an ACR
  // for. If it is then it returns true and sets role to one of ACR::NodeRole.
  // Otherwise it returns false.
  //
  // @return          - True is we should generate an ACR for this transaction,
  //                    false otherwise.
  // @param[in] role  - The billing role. Only set if true is returned.
  bool get_billing_role(ACR::NodeRole& role);

  /// Adds a second P-Asserted-Identity header to a message when required.
  ///
  /// We only add the header to messages for which all of the following is true:
  ///  - We can't find our Route header or our Route header doesn't contain an
  ///    ODI token.
  ///  - There is exactly one P-Asserted-Identity header on the message already.
  ///  - If that header contains a SIP URI sip:user@example.com, that SIP URI is
  ///    an alias of the tel URI tel:user. That tel URI is used in the new
  ///    header.
  ///    If that header contains a tel URI tel:user, we use the SIP URI
  ///    sip:user@<homedomain> in the new header.
  void add_second_p_a_i_hdr(pjsip_msg* msg);

  /// Raise a SAS log at the start of originating, terminating, or orig-cdiv
  /// processing.
  void sas_log_start_of_session_case(pjsip_msg* req,
                                     const SessionCase* session_case,
                                     const std::string& served_user);

  /// Fetch the ACR for the current transaction, ACRs should always be retrieved
  /// through this API, not by inspecting _acr directly, since the ACR may be
  /// owned by the AsChain as a whole.  May return NULL in some cases.
  ACR* get_acr();

  /// Get a string representation of why a fork failed.
  ///
  /// @return          - The failure reason for the fork.
  /// @param fork_id   - The fork's number.
  /// @param sip_code  - The reported SIP return code.
  std::string fork_failure_reason_as_string(int fork_id, int sip_code);

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

  /// Flag indicating if data has already been fetched from the HSS and cached
  /// for this transaction.
  bool _hss_data_cached;

  /// Data received from HSS for this service hop.
  bool _registered;
  bool _barred;
  std::string _default_uri;
  Ifcs _ifcs;
  HSSConnection::irs_info _irs_info;

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

  /// Track various properties of the transaction / transaction state so that
  /// we can generate the correct stats:
  ///  - _req_type:   the type of the request, e.g. INVITE, REGISTER etc.
  ///  - _seen_1xx:   whether we've seen a 1xx response to this transaction.
  ///  - _record_session_setup_time:
  ///                 whether we should record session setup time for this
  ///                 transaction.  Set to false if this is a transaction that
  ///                 we shouldn't track, or if we have already tracked it.
  ///  - _tsx_start_time_usec:
  ///                 the time that the session started -- only valid if
  ///                 _record_session_setup_time is true.
  ///  - _video_call: whether this is a video call -- only valid if
  ///                 _record_session_setup_time is true.
  pjsip_method_e _req_type;
  bool _seen_1xx;
  bool _record_session_setup_time;
  uint64_t _tsx_start_time_usec;
  bool _video_call;

  static const int MAX_FORKING = 10;

  /// The private identity associated with the request. Empty unless the
  /// request had a Proxy-Authorization header.
  std::string _impi;

  /// Whether this request should cause the user to be automatically
  /// registered in the HSS. This is set if there is an `auto-reg` parameter
  /// in the S-CSCF's route header.
  ///
  /// This has the following impacts:
  ///  - It causes registration state updates to have a type of REG rather than
  ///    CALL.
  ///  - If there is a real HSS it forces registration state updates to flow all
  ///    the way to the HSS (i.e. Homestead may not answer the response solely
  ///    from its cache).
  bool _auto_reg;

  /// The wildcarded public identity associated with the requestee. This is
  /// pulled from the P-Profile-Key header (RFC 5002).
  std::string _wildcard;

  /// Class to handle session-expires processing.
  SessionExpiresHelper _se_helper;

  /// The base request that the S-CSCF should use when retrying a request. This
  /// is currently only used when invoking default handling for an Application
  /// Server.
  ///
  /// This variable is updated when the S-CSCF record-routes itself into the
  /// dialog. If the S-CSCF has not record-routed itself, then this pointer will
  /// be NULL and the original request should be used instead (this is all
  /// handled by the `get_base_request` utility method below).
  pjsip_msg* _base_req;

  /// Get the base request that the S-CSCF should use when retrying a request.
  pjsip_msg* get_base_request();

  /// SAS logs that the next hop URI is invalid and rejects the request with a
  /// 400 Bad Request error (which also frees the request).
  ///
  /// @param req      - The request to reject
  void reject_invalid_uri(pjsip_msg* req);

  /// The S-CSCF URI for this transaction. This is used in the SAR sent to the
  /// HSS. This field should not be changed once it has been set by the
  /// on_rx_intial_request() call.
  std::string _scscf_uri;
};

#endif
