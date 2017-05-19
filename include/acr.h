/**
 * @file acr.h  Rf Transaction class declaration.
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef _ACR_H__
#define _ACR_H__

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

#include <string>
#include <list>
#include <vector>

#include "sas.h"
#include "ralf_processor.h"
#include "servercaps.h"

/// Class tracking state required for Rf ACR messages.  An instance of this
/// class is created for each SIP transaction that requires accounting, and
/// the class is passed messages and other data during processing of the
/// transaction, and finally triggered to send the ACR message to Ralf.
///
/// In general there is a one-to-one mapping between SIP transactions and
/// ACR objects, with a few exceptions.
///
/// -   When an S-CSCF is invoking application servers for originating or
///     terminating services, a single ACR object is associated with all
///     the S-CSCF SIP transactions involved in the application server chain.
///
/// -   When a single Sprout instance performs multiple IMS functions within a
///     single SIP transaction, multiple ACR's may be associated with that
///     SIP transaction.  The specific cases here are
///     -   when a single Sprout handles both the originating and terminating
///         S-CSCF side of a call
///     -   when Sprout has I-CSCF function enabled and it performs I-CSCF
///         routing to the terminating S-CSCF on the same Sprout instance
///         that performed originating S-CSCF processing
///     -   when Sprout has BGCF function enabled and it performs BGCF routing
///         on the same Sprout instance that performed originating S-CSCF
///         processing.


/// The ACR class is an null implementation of the class which also defines
/// the interface.  Instances of this class are used when ACRs are disabled.
class ACR
{
public:
  typedef enum { SCSCF=0, PCSCF=1, ICSCF=2, BGCF=5, AS=6, IBCF=7 } Node;
  typedef enum { CALLED_PARTY=0, CALLING_PARTY=1 } Initiator;
  typedef enum { NODE_ROLE_ORIGINATING=0, NODE_ROLE_TERMINATING=1 } NodeRole;

  /// Unspecified timestamp value.
  static const pj_time_val unspec;

  /// Constructor.
  ACR();

  /// Destructor is virtual.
  virtual ~ACR();

  /// Called with all requests received by this node for this SIP transaction.
  /// When acting as an S-CSCF this includes both the original request and
  /// the request as subsequently forwarded by any ASs invoked in the service
  /// chain.
  /// @param  req             A pointer to the parsed SIP request message.
  /// @param  timestamp       Timestamp of the request receipt.
  virtual void rx_request(pjsip_msg* req, pj_time_val timestamp=unspec);

  /// Called with the request as it is forwarded by this node.  When acting
  /// as an S-CSCF this includes when the request is forwarded to any ASs
  /// in the service chain.
  /// @param  req             A pointer to the parsed SIP request message.
  /// @param  timestamp       Timestamp of the request receipt.
  virtual void tx_request(pjsip_msg* req, pj_time_val timestamp=unspec);

  /// Called with all responses as received by the node.  When acting as an
  /// S-CSCF, this includes all forwarded responses received from ASs
  /// invoked in the service chain.
  /// @param   rsp            A pointer to the parsed SIP response message.
  /// @param   timestamp      Timestamp of the response transmission.
  virtual void rx_response(pjsip_msg* rsp, pj_time_val timestamp=unspec);

  /// Called with all responses transmitted by the node.  When acting as an
  /// S-CSCF, this includes all responses sent to ASs in the service chain.
  /// @param   rsp            A pointer to the parsed SIP response message.
  /// @param   timestamp      Timestamp of the response transmission.
  virtual void tx_response(pjsip_msg* rsp, pj_time_val timestamp=unspec);

  /// Called when an AS has been invoked by an S-CSCF and the AS has sent a
  /// final response.
  /// @param   uri            The URI used to invoke the AS (from iFC).
  /// @param   redirect_uri   The RequestURI from the request forwarded by the
  ///                         AS if different from the RequestURI on the
  ///                         request sent to the URI, empty otherwise.
  /// @param   status_code    The status code from the final response from the
  ///                         AS.
  /// @param   timeout        true if the AS timed out without returning a
  ///                         final response.
  virtual void as_info(const std::string& uri,
                       const std::string& redirect_uri,
                       int status_code,
                       bool timeout);

  /// Called by I-CSCF when server capabilities have been received from the
  /// HSS.
  /// @param   caps           Capabiliies as received from I-CSCF.
  virtual void server_capabilities(const ServerCapabilities& caps);

  /// Returns the JSON encoded message in string form.
  ///
  /// If the ACR has been cancelled, this function's behaviour is unspecified
  /// (though the UTs expect it to return "Cancelled ACR").
  ///
  /// @param   timestamp      Timestamp to be used as Event-Timestamp AVP.
  virtual std::string get_message(pj_time_val timestamp=unspec);

  /// Convert the ENUM node functionality to a displayable string.
  static std::string node_name(Node node_functionality);

  /// Convert the ENUM node role to a displayable string.
  static std::string node_role_str(NodeRole role);

  /// Set the default CCF for this ACR.
  virtual void set_default_ccf(const std::string& default_ccf);

  /// Sets the session ID for this ACR.
  ///
  /// This allows the caller to override the default session ID (which is the
  /// call ID of the first request passed to the ACR).  This is useful if there
  /// are B2BUAs involved in the call and the caller needs more control about
  /// what call ID is reported to Ralf.
  ///
  /// @param session_id       The session ID to use.
  virtual void override_session_id(const std::string& session_id);

  /// Get a lock on the ACR.
  ///
  /// An ACR can be accessed from multiple threads (if there are multiple
  /// SproutletTsx objects that use the same ACR), so those threads must call
  /// lock() before accessing the ACR.
  virtual void lock();

  /// Release the lock on the ACR.
  ///
  /// Should be called after a matching call to lock() once the ACR is no longer
  /// being accessed.
  virtual void unlock();

  /// Called when the ACR message should be sent if it's not yet been
  /// cancelled.  In general this will be when the relevant transaction or AS
  /// chain has ended.
  /// @param   timestamp      Timestamp to be used as Event-Timestamp AVP.
  inline void send(pj_time_val timestamp=unspec)
  {
    if (!_cancelled)
    {
      send_message(timestamp);
    }
  }

  /// Cancel this ACR, preventing it from being sent.  Used if a call leg
  /// should no longer be considered for billing.
  inline void cancel() { _cancelled = true; }

protected:
  /// Tracks if the ACR has been cancelled.
  ///
  /// `send_message()` will not be called if this is true.
  /// `get_message()` is undefined if this is true
  bool _cancelled;

private:
  /// Called when the ACR message should be triggered.
  ///
  /// This will never be called on a cancelled ACR.
  ///
  /// @param   timestamp      Timestamp to be used as Event-Timestamp AVP.
  virtual void send_message(pj_time_val timestamp=unspec);

};


/// Factory class for creating null ACR instances.
class ACRFactory
{
public:
  /// Constructor.
  ACRFactory();

  /// Destructor.
  virtual ~ACRFactory();

  /// Get an ACR instance from the factory.
  /// @param trail                SAS trail identifier to use for the ACR.
  /// @param initiator            The initiator of the SIP transaction (calling
  ///                             or called party).
  virtual ACR* get_acr(SAS::TrailId trail,
                       ACR::Initiator initiator,
                       ACR::NodeRole role);
};


/// Implementation of the ACR for IMS Rf billing.
class RalfACR : public ACR
{
public:
  /// Constructor.
  RalfACR(RalfProcessor* ralf,
          SAS::TrailId trail,
          Node node_functionality,
          Initiator initiator,
          NodeRole role);

  /// Destructor.
  ~RalfACR();

  /// Called with all requests received by this node for this SIP transaction.
  /// When acting as an S-CSCF this includes both the original request and
  /// the request as subsequently forwarded by any ASs invoked in the service
  /// chain.
  /// @param  req             A pointer to the parsed SIP request message.
  /// @param  timestamp       Timestamp of the request receipt.
  virtual void rx_request(pjsip_msg* req, pj_time_val timestamp=unspec);

  /// Called with the request as it is forwarded by this node.  When acting
  /// as an S-CSCF this includes when the request is forwarded to any ASs
  /// in the service chain.
  /// @param  req             A pointer to the parsed SIP request message.
  /// @param  timestamp       Timestamp of the request receipt.
  virtual void tx_request(pjsip_msg* req, pj_time_val timestamp=unspec);

  /// Called with all responses as received by the node.  When acting as an
  /// S-CSCF, this includes all forwarded responses received from ASs
  /// invoked in the service chain.
  /// @param   rsp            A pointer to the parsed SIP response message.
  /// @param   timestamp      Timestamp of the response transmission.
  virtual void rx_response(pjsip_msg* rsp, pj_time_val timestamp=unspec);

  /// Called with all responses transmitted by the node.  When acting as an
  /// S-CSCF, this includes all responses sent to ASs in the service chain.
  /// @param   rsp            A pointer to the parsed SIP response message.
  /// @param   timestamp      Timestamp of the response transmission.
  virtual void tx_response(pjsip_msg* rsp, pj_time_val timestamp=unspec);

  /// Called when an AS has been invoked by an S-CSCF and the AS has sent a
  /// final response.
  /// @param   uri            The URI used to invoke the AS (from iFC).
  /// @param   redirect_uri   The RequestURI from the request forwarded by the
  ///                         AS if different from the RequestURI on the
  ///                         request sent to the URI, empty otherwise.
  /// @param   status_code    The status code from the final response from the
  ///                         AS.
  /// @param   timeout        true if the AS timed out without returning a
  ///                         final response.
  virtual void as_info(const std::string& uri,
                       const std::string& redirect_uri,
                       int status_code,
                       bool timeout);

  /// Called by I-CSCF when server capabilities have been received from the
  /// HSS.
  /// @param   caps           Capabiliies as received from I-CSCF.
  virtual void server_capabilities(const ServerCapabilities& caps);

  /// Returns the JSON encoded message in string form.
  /// @param   timestamp      Timestamp to be used as Event-Timestamp AVP.
  virtual std::string get_message(pj_time_val timestamp=unspec);

  /// Set the default CCF for this ACR.
  virtual void set_default_ccf(const std::string& default_ccf);

  /// Sets the session ID for this ACR.
  ///
  /// This allows the caller to override the default session ID (which is the
  /// call ID of the first request passed to the ACR).  This is useful if there
  /// are B2BUAs involved in the call and the caller needs more control about
  /// what call ID is reported to Ralf.
  ///
  /// @param session_id       The session ID to use.
  virtual void override_session_id(const std::string& session_id);

  // Get/release the _acr_lock
  virtual void lock();
  virtual void unlock();

private:

  /// Called when the Rf message should be triggered.  In general this will
  /// be when the relevant transaction or AS chain has ended.
  /// @param   timestamp      Timestamp to be used as Event-Timestamp AVP.
  virtual void send_message(pj_time_val timestamp=unspec);

  typedef enum { EVENT_RECORD=1,
                 START_RECORD=2,
                 INTERIM_RECORD=3,
                 STOP_RECORD=4 } RecordType;

  typedef enum { END_USER_E164=0,
                 END_USER_IMSI=1,
                 END_USER_SIP_URI=2,
                 END_USER_NAI=3,
                 END_USER_PRIVATE=4 } SubscriptionIdType;

  typedef enum { SDP_OFFER=0, SDP_ANSWER=1 } SDPType;

  typedef enum { CALLING_PARTY=0, CALLED_PARTY=1 } Originator;

  typedef enum { STATUS_CODE_NONE=-1,
                 STATUS_CODE_4XX=0,
                 STATUS_CODE_5XX=1,
                 STATUS_CODE_TIMEOUT=2 } StatusCode;

  struct SubscriptionId
  {
    SubscriptionIdType type;
    std::string id;
  };

  struct ASInformation
  {
    std::string uri;
    std::string redirect_uri;
    StatusCode status_code;
  };

  struct MediaComponents
  {
    std::string sdp;
    Initiator initiator_flag;
    std::string initiator_party;
  };

  struct MediaDescription
  {
    MediaComponents offer;
    MediaComponents answer;
  };

  struct EarlyMediaDescription
  {
    pj_time_val offer_timestamp;
    pj_time_val answer_timestamp;
    MediaDescription media;
  };

  struct MessageBody
  {
    std::string type;
    int length;
    std::string disposition;
    Originator originator;
  };

  void encode_sdp_description(rapidjson::Writer<rapidjson::StringBuffer>* writer,
                              const MediaDescription& media);

  void encode_media_components(rapidjson::Writer<rapidjson::StringBuffer>* writer,
                               const std::vector<std::string>& sdp,
                               SDPType sdp_type,
                               Initiator initiator_flag,
                               const std::string& initiator_party);

  void split_sdp(const std::string& sdp, std::vector<std::string>& lines);

  void store_charging_addresses(pjsip_msg* msg);

  void store_subscription_ids(pjsip_msg* msg);

  SubscriptionId uri_to_subscription_id(pjsip_uri* uri);

  void store_calling_party_addresses(pjsip_msg* msg);

  void store_called_party_address(pjsip_msg* msg);

  void store_called_asserted_ids(pjsip_msg* msg);

  void store_associated_uris(pjsip_msg* msg);

  void store_charging_info(pjsip_msg* msg);

  void store_media_description(pjsip_msg* msg,
                               MediaDescription& description);

  void store_media_components(pjsip_msg* msg, MediaComponents& components);

  void store_message_bodies(pjsip_msg* msg);

  void store_instance_id(pjsip_msg* msg);

  std::string hdr_contents(pjsip_hdr* hdr);

  pthread_mutex_t _acr_lock;

  RalfProcessor* _ralf;
  SAS::TrailId _trail;

  Initiator _initiator;

  bool _first_req;
  bool _first_rsp;

  std::list<std::string> _ccfs;
  std::list<std::string> _ecfs;

  RecordType _record_type;

  std::string _username;

  int _interim_interval;

  std::list<SubscriptionId> _subscription_ids;

  std::string _method;

  std::string _event;

  int _expires;

  int _num_contacts;

  NodeRole _node_role;

  Node _node_functionality;

  std::string _user_session_id;

  std::list<std::string> _calling_party_addresses;

  std::string _called_party_address;

  std::string _requested_party_address;

  std::list<std::string> _called_asserted_ids;

  std::list<std::string> _associated_uris;

  pj_time_val _req_timestamp;

  pj_time_val _rsp_timestamp;

  std::list<ASInformation> _as_information;

  std::string _orig_ioi;

  std::string _term_ioi;

  std::list<std::string> _transit_iois;

  std::string _icid;

  std::list<EarlyMediaDescription> _early_media;

  MediaDescription _media;

  std::string _served_party_ip_address;

  ServerCapabilities _server_caps;

  std::list<MessageBody> _msg_bodies;

  int _status_code;

  std::list<std::string> _reasons;

  std::list<std::string> _access_network_info;

  std::string _from_address;

  std::string _visited_network_id;

  std::string _route_hdr_received;

  std::string _route_hdr_transmitted;

  std::string _instance_id;
};


/// Factory class for creating Ralf ACR instances with the appropriate settings.
class RalfACRFactory : public ACRFactory
{
public:
  /// Constructor.
  /// @param ralf                 RalfProcessor pool set up to connect to
  ///                             Ralf cluster.
  /// @param node_functionality   Node-Functionality value to set in ACRs.
  RalfACRFactory(RalfProcessor* ralf,
                 ACR::Node node_functionality);

  /// Destructor.
  ~RalfACRFactory();

  /// Get an ACR instance from the factory.
  /// @param trail                SAS trail identifier to use for the ACR.
  /// @param initiator            The initiator of the SIP transaction (calling
  ///                             or called party).
  /// @param role                 The role that this node is playing
  ///                             (originating or terminating).
  virtual ACR* get_acr(SAS::TrailId trail,
                       ACR::Initiator initiator,
                       ACR::NodeRole role);

private:
  RalfProcessor* _ralf;
  ACR::Node _node_functionality;
};

#endif
