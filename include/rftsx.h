/**
 * @file rftsx.h  Rf Transaction class declaration.
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

#ifndef _RFTSX_H__
#define _RFTSX_H__

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

#include <json/json.h>

#include <string>
#include <list>
#include <vector>

#include "sas.h"
#include "httpconnection.h"
#include "icscfproxy.h"

typedef enum { SCSCF=0, PCSCF=1, ICSCF=2, BGCF=6, AS=7, IBCF=8 } RfNode;

typedef enum { CALLED_PARTY=0, CALLING_PARTY=1 } Initiator;

/// Class tracking state required for Rf billing/accounting messages.
/// An instance of this class is created for each SIP transaction that requires
/// accounting, and the class is passed messages and other data during processing
/// of the transaction, and finally triggered to send the ACR message to Ralf.
///
/// In general there is a one-to-one mapping between SIP transactions and
/// RfTsx objects, with a few exceptions.
///
/// -   When an S-CSCF is invoking application servers for originating or
///     terminating services, a single RfTsx object is associated with all
///     the S-CSCF SIP transactions involved in the application server chain.
///
/// -   When a single Sprout instance performs multiple IMS functions within a
///     single SIP transaction, multiple RfTsx's may be associated with that
///     SIP transaction.  The specific cases here are
///     -   when a single Sprout handles both the originating and terminating
///         S-CSCF side of a call
///     -   when Sprout has I-CSCF function enabled and it performs I-CSCF
///         routing to the terminating S-CSCF on the same Sprout instance
///         that performed originating S-CSCF processing
///     -   when Sprout has BGCF function enabled and it performs BGCF routing
///         on the same Sprout instance that performed originating S-CSCF
///         processing.

class RfTsx
{
public:
  RfTsx(HttpConnection* ralf,
        SAS::TrailId trail,
        const std::string& origin_host,
        RfNode node_functionality,
        Initiator initiator);
  ~RfTsx();

  /// Called with all requests received by this node for this SIP transaction.
  /// When acting as an S-CSCF this includes both the original request and
  /// the request as subsequently forwarded by any ASs invoked in the service
  /// chain.
  void rx_request(pjsip_msg* msg, pj_time_val timestamp);

  /// Called with the request as it is forwarded by this node.  When acting
  /// as an S-CSCF this includes when the request is forwarded to any ASs
  /// in the service chain.
  void tx_request(pjsip_msg* msg, pj_time_val timestamp);

  /// Called with all non-100 responses as received by the node.  When acting
  /// as an S-CSCF, this includes all forwarded responses received from ASs
  /// invoked in the service chain.
  void rx_response(pjsip_msg* msg, pj_time_val timestamp);

  /// Called with all non-100 responses transmitted by the node.  When acting
  /// as an S-CSCF, this includes all responses sent to ASs in the service
  /// chain.
  void tx_response(pjsip_msg* msg, pj_time_val timestamp);

  /// Called when an AS has been invoked by an S-CSCF and has forwarded the
  /// the request back via the AS.
  void as_request(pjsip_msg* msg);

  /// Called when an AS has been invoked by an S-CSCF and has returned a
  /// response.
  void as_response(pjsip_msg* msg);

  /// Called by I-CSCF when server capabilities have been received from the
  /// HSS.
  void server_capabilities(ServerCapabilities& caps);

  void send_message();

private:

  typedef enum { EVENT_RECORD=1,
                 START_RECORD=2,
                 INTERIM_RECORD=3,
                 STOP_RECORD=4 } RecordType;

  typedef enum { END_USER_E164=0, END_USER_SIP_URI=1 } SubscriptionIdType;

  typedef enum { NODE_ROLE_ORIGINATING=0, NODE_ROLE_TERMINATING=1 } NodeRole;

  typedef enum { SDP_OFFER=0, SDP_ANSWER=1 } SDPType;

  typedef enum { CALLING_PARTY=0, CALLED_PARTY=1 } Originator;

  struct SubscriptionId
  {
    SubscriptionIdType type;
    std::string id;
  };

  struct ASInformation
  {
    std::string uri;
    std::string redirect;
    int status_code;
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

  void encode_sdp_description(Json::Value& v, const MediaDescription& media);

  void encode_media_components(Json::Value& v,
                               const std::vector<std::string>& sdp,
                               SDPType sdp_type,
                               Initiator initiator_flag,
                               const std::string& initiator_party);

  std::string avp_timestamp(time_t ts);

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

  HttpConnection* _ralf;
  SAS::TrailId _trail;

  Initiator _initiator;

  bool _first_req;
  bool _first_rsp;

  std::list<std::string> _ccfs;
  std::list<std::string> _ecfs;

  std::string _origin_host;

  RecordType _record_type;

  std::string _username;

  int _interim_interval;

  std::list<SubscriptionId> _subscription_ids;

  std::string _method;

  std::string _event;

  int _expires;

  NodeRole _node_role;

  RfNode _node_functionality;

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

#endif
