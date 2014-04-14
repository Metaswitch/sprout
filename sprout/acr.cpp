/**
 * @file acr.cpp  ACR class
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

#include "log.h"
#include "utils.h"
#include "pjutils.h"
#include "constants.h"
#include "custom_headers.h"
#include "acr.h"

const pj_time_val ACR::unspec = {-1,0};

ACR::ACR()
{
  LOG_DEBUG("Created ACR (%p)", this);
}

ACR::~ACR()
{
  LOG_DEBUG("Destroyed ACR (%p)", this);
}

void ACR::rx_request(pjsip_msg* req, pj_time_val timestamp)
{
}

void ACR::tx_request(pjsip_msg* req, pj_time_val timestamp)
{
}

void ACR::rx_response(pjsip_msg* rsp, pj_time_val timestamp)
{
}

void ACR::tx_response(pjsip_msg* rsp, pj_time_val timestamp)
{
}

void ACR::as_info(const std::string& uri, const std::string& redirect_uri, int status_code)
{
}

void ACR::server_capabilities(const ServerCapabilities& caps)
{
}

void ACR::send_message(pj_time_val timestamp)
{
  LOG_DEBUG("Sending Null ACR (%p)", this);
}

std::string ACR::get_message(pj_time_val timestamp)
{
  return std::string();
}

std::string ACR::node_name(Node node_functionality)
{
  switch (node_functionality)
  {
    case SCSCF:
      return "S-CSCF";

    case PCSCF:
      return "P-CSCF";

    case ICSCF:
      return "I-CSCF";

    case BGCF:
      return "BGCF";

    case AS:
      return "AS";

    case IBCF:
      return "IBCF";

    default:
      return "Unknown";
  }
}

ACRFactory::ACRFactory()
{
}

ACRFactory::~ACRFactory()
{
}

ACR* ACRFactory::get_acr(SAS::TrailId trail, Initiator initiator)
{
  return new ACR();
}

RalfACR::RalfACR(HttpConnection* ralf,
                 SAS::TrailId trail,
                 Node node_functionality,
                 Initiator initiator) :
  _ralf(ralf),
  _trail(trail),
  _initiator(initiator),
  _first_req(true),
  _first_rsp(true),
  _interim_interval(0),
  _node_functionality(node_functionality),
  _user_session_id(),
  _status_code(0)
{
  // Clear timestamps.
  _req_timestamp.sec = 0;
  _rsp_timestamp.sec = 0;

  LOG_DEBUG("Created %s Ralf ACR",
            ACR::node_name(_node_functionality).c_str(), this);
}

RalfACR::~RalfACR()
{
}

void RalfACR::rx_request(pjsip_msg* req, pj_time_val timestamp)
{
  if (timestamp.sec == -1)
  {
    // Timestamp is unspecified, so get the current time.
    pj_gettimeofday(&timestamp);
  }

  if (_first_req)
  {
    // This is the first time we have seen a request for this transaction,
    // so extract all the "first request" fields.
    _first_req = false;

    // Store a timestamp for the original request.
    _req_timestamp = timestamp;

    // Save the method.
    _method = PJUtils::pj_str_to_string(&req->line.req.method.name);

    // Find the From and To headers.
    pjsip_fromto_hdr* to_hdr = (pjsip_fromto_hdr*)
                                     pjsip_msg_find_hdr(req, PJSIP_H_TO, NULL);
    pjsip_fromto_hdr* from_hdr = (pjsip_fromto_hdr*)
                                   pjsip_msg_find_hdr(req, PJSIP_H_FROM, NULL);

    // Set the record type based on the node functionality and the method.
    // This may get changed later (for example, if an INVITE transaction fails
    // we send EVENT instead of START).
    if ((_node_functionality == PCSCF) ||
        (_node_functionality == SCSCF))
    {
      LOG_DEBUG("Set record type for P/S-CSCF");
      if ((_method == "REGISTER") ||
          (_method == "SUBSCRIBE") ||
          (_method == "NOTIFY") ||
          (_method == "PUBLISH") ||
          (_method == "MESSAGE"))
      {
        // Non-dialog message, must be an EVENT record.
        LOG_DEBUG("Non-dialog message => EVENT_RECORD");
        _record_type = EVENT_RECORD;
      }
      else if (_method == "BYE")
      {
        // BYE request must be a STOP record.
        LOG_DEBUG("BYE => STOP_RECORD");
        _record_type = STOP_RECORD;
      }
      else if ((to_hdr != NULL) &&
               (to_hdr->tag.slen > 0))
      {
        // Any other requests with a To tag are INTERIMs.
        LOG_DEBUG("In-dialog %s request => INTERIM_RECORD", _method.c_str());
        _record_type = INTERIM_RECORD;
      }
      else if (_method == "INVITE")
      {
        // INVITE with no To tag is a START.
        LOG_DEBUG("Dialog-initiating INVITE => START_RECORD");
        _record_type = START_RECORD;
      }
      else
      {
        // Anything else is an EVENT.
        LOG_DEBUG("EVENT_RECORD");
        _record_type = EVENT_RECORD;
      }
    }
    else
    {
      // All other node types only generate EVENTs.
      LOG_DEBUG("Set record type for I-CSCF, BGCF, IBCF, AS to EVENT_RECORD");
      _record_type = EVENT_RECORD;
    }

    // Store the content of the event header if present.
    if ((_method == "SUBSCRIBE") ||
        (_method == "NOTIFY"))
    {
      pjsip_generic_string_hdr* event_hdr = (pjsip_generic_string_hdr*)
                             pjsip_msg_find_hdr_by_name(req, &STR_EVENT, NULL);
      if (event_hdr != NULL)
      {
        _event = PJUtils::pj_str_to_string(&event_hdr->hvalue);
      }
    }

    // Store the content of the expires header if present.
    pjsip_expires_hdr* expires_hdr = (pjsip_expires_hdr*)
                                pjsip_msg_find_hdr(req, PJSIP_H_EXPIRES, NULL);
    if (expires_hdr != NULL)
    {
      _expires = expires_hdr->ivalue;
    }
    else if (req->line.req.method.id == PJSIP_REGISTER_METHOD)
    {
      // Check for expires values in Contact headers.  Set the default to
      // -1, so if there are no contact headers, or no expires values in the
      // contact headers we won't include an Expires AVP.
      _expires = PJUtils::max_expires(req, -1);
    }
    else
    {
      _expires = -1;
    }

    // Store the call ID.
    pjsip_cid_hdr* cid_hdr = (pjsip_cid_hdr*)
                                pjsip_msg_find_hdr(req, PJSIP_H_CALL_ID, NULL);
    if (cid_hdr != NULL)
    {
      _user_session_id = PJUtils::pj_str_to_string(&cid_hdr->id);
    }

    // Store contents of From header.
    if (from_hdr != NULL)
    {
      _from_address = hdr_contents((pjsip_hdr*)from_hdr);
    }

    // Save the username from the Authorization header if present.
    pjsip_authorization_hdr* auth_hdr = (pjsip_authorization_hdr*)
                          pjsip_msg_find_hdr(req, PJSIP_H_AUTHORIZATION, NULL);
    if ((auth_hdr != NULL) &&
        (pj_stricmp(&auth_hdr->scheme, &STR_DIGEST) == 0))
    {
      _username =
              PJUtils::pj_str_to_string(&auth_hdr->credential.digest.username);
    }

    // If the request is an INVITE, save the delta_seconds value from the
    // Session-Expires header if present.
    if (req->line.req.method.id == PJSIP_INVITE_METHOD)
    {
      pjsip_session_expires_hdr* sess_expires = (pjsip_session_expires_hdr*)
                               pjsip_msg_find_hdr_by_names(req,
                                                           &STR_SESSION_EXPIRES,
                                                           &STR_X,
                                                           NULL);
      if (sess_expires != NULL)
      {
        _interim_interval = sess_expires->expires;
      }
    }

    // Store the contents of the top-most route header if present.
    pjsip_route_hdr* route_hdr = (pjsip_route_hdr*)
                                  pjsip_msg_find_hdr(req, PJSIP_H_ROUTE, NULL);
    if (route_hdr != NULL)
    {
      _route_hdr_received = hdr_contents((pjsip_hdr*)route_hdr);
    }

    // Determine whether this an originating or terminating request.  REGISTERs,
    // are neither, but since it's a mandatory field, we'll plump for originating.
    if ((route_hdr != NULL) &&
        (pjsip_param_find(&((pjsip_sip_uri*)route_hdr->name_addr.uri)->other_param,
                          &STR_ORIG) != NULL))
    {
      _node_role = NODE_ROLE_ORIGINATING;
    }
    else if (req->line.req.method.id == PJSIP_REGISTER_METHOD)
    {
      _node_role = NODE_ROLE_ORIGINATING;
    }
    else
    {
      _node_role = NODE_ROLE_TERMINATING;
    }

    if (_node_role == NODE_ROLE_ORIGINATING)
    {
      // For originating requests take the subscription identifiers from
      // P-Asserted-Identity headers in the original request.
      store_subscription_ids(req);
    }

    if ((_method == "REGISTER") &&
        (to_hdr != NULL))
    {
      // For a register method, both the subscription id and the called party
      // address are the public user identity being registered, so should be
      // the URI in the To header.
      pjsip_uri* uri = (pjsip_uri*)pjsip_uri_get_uri(to_hdr->uri);
      _called_party_address =
                          PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, uri);
      SubscriptionId id;
      id.type = END_USER_SIP_URI;
      id.id = _called_party_address;
      _subscription_ids.push_back(id);
    }

    // Store the calling party addresses (from P-Asserted-Identity headers).
    store_calling_party_addresses(req);

    // Store the RequestURI in case it is needed for a Requested-Party-Address
    // AVP or as a Media-Originator-Party AVP.
    _requested_party_address =
               PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, req->line.req.uri);

    // Store IOIs and ICID from P-Charging-Vector header if present.
    store_charging_info(req);

    // In the originating case we always take SDP and other message bodies
    // from the original request.
    if (_node_role == NODE_ROLE_ORIGINATING)
    {
      // Store media description if present.
      store_media_description(req, _media);

      // Store non-SDP message bodies if present.
      store_message_bodies(req);
    }

    // Store contents of Reason header(s) if CANCEL or BYE request.
    if ((req->line.req.method.id == PJSIP_CANCEL_METHOD) ||
        (req->line.req.method.id == PJSIP_BYE_METHOD))
    {
      pjsip_generic_string_hdr* reason_hdr = (pjsip_generic_string_hdr*)
                            pjsip_msg_find_hdr_by_name(req, &STR_REASON, NULL);
      while (reason_hdr != NULL)
      {
        _reasons.push_back(PJUtils::pj_str_to_string(&reason_hdr->hvalue));
        reason_hdr = (pjsip_generic_string_hdr*)
                pjsip_msg_find_hdr_by_name(req, &STR_REASON, reason_hdr->next);
      }
    }

    // Store contents of P-Access-Network-Info headers if present.
    pjsip_generic_string_hdr* pani_hdr = (pjsip_generic_string_hdr*)
                           pjsip_msg_find_hdr_by_name(req, &STR_P_A_N_I, NULL);
    while (pani_hdr != NULL)
    {
      _access_network_info.push_back(
                                 PJUtils::pj_str_to_string(&pani_hdr->hvalue));
      pani_hdr = (pjsip_generic_string_hdr*)
                 pjsip_msg_find_hdr_by_name(req, &STR_P_A_N_I, pani_hdr->next);
    }

    // Store contents of P-Visited-Network-ID header.
    pjsip_generic_string_hdr* pvni_hdr = (pjsip_generic_string_hdr*)
                           pjsip_msg_find_hdr_by_name(req, &STR_P_V_N_I, NULL);
    if (pvni_hdr != NULL)
    {
      _visited_network_id = PJUtils::pj_str_to_string(&pvni_hdr->hvalue);
    }

    // Get instance-ID if this is originating case.
    if (_node_role == NODE_ROLE_ORIGINATING)
    {
      store_instance_id(req);
    }
  }

  // Now process any fields which may be overriden by subsequent forwarded
  // requests.

  // Store the charging function addresses if present.
  store_charging_addresses(req);

  if (_node_role == NODE_ROLE_TERMINATING)
  {
    // In the terminating case, the called party address is taken from the
    // RequestURI after it has been modified by any ASs, but before it has
    // been converted to a contact address.  We therefore store the RequestURI
    // on every received request as we will catch it as received from the
    // final AS in the chain but before we convert to a contact address.
    store_called_party_address(req);
  }
}

/// Called with the request as it is forwarded by this node.
void RalfACR::tx_request(pjsip_msg* req, pj_time_val timestamp)
{
  if (timestamp.sec == -1)
  {
    // Timestamp is unspecified, so get the current time.
    pj_gettimeofday(&timestamp);
  }

  // Store the contents of the top-most route header if present.
  pjsip_route_hdr* route_hdr = (pjsip_route_hdr*)
                                  pjsip_msg_find_hdr(req, PJSIP_H_ROUTE, NULL);
  if (route_hdr != NULL)
  {
    _route_hdr_transmitted = hdr_contents((pjsip_hdr*)route_hdr);
  }

  if (_node_role == NODE_ROLE_ORIGINATING)
  {
    // In the originating case, the called party address is taken from the
    // RequestURI when the request is transmitted.
    store_called_party_address(req);
  }

  // Store the charging function addresses if present.
  store_charging_addresses(req);

  // If this is a terminating request store the SDP and non-SDP bodies from
  // every transmitted request.
  if (_node_role == NODE_ROLE_TERMINATING)
  {
    // Store media description if present.
    store_media_description(req, _media);

    // Store non-SDP message bodies if present.
    store_message_bodies(req);
  }
}

/// Called with all non-100 responses as first received by the node.
void RalfACR::rx_response(pjsip_msg* rsp, pj_time_val timestamp)
{
  if (timestamp.sec == -1)
  {
    // Timestamp is unspecified, so get the current time.
    pj_gettimeofday(&timestamp);
  }

  if (rsp->line.status.code >= PJSIP_SC_OK)
  {
    // This is a final response.
    if (_first_rsp)
    {
      _first_rsp = false;

      // Store IOIs and ICID from P-Charging-Vector header if present.
      store_charging_info(rsp);

      if (_node_role == NODE_ROLE_TERMINATING)
      {
        // For terminating requests take the subscription identifiers from
        // P-Asserted-Identity headers in the first response.
        store_subscription_ids(rsp);

        // For terminating requests store media from the first received final
        // response.
        store_media_description(rsp, _media);

        // Store non-SDP message bodies if present.
        store_message_bodies(rsp);
      }

      if (rsp->line.status.code >= PJSIP_SC_OK)
      {
        // First 200 OK response, so store the called asserted identities.
        store_called_asserted_ids(rsp);
      }
    }
  }

  // Store the charging function addresses if present.
  store_charging_addresses(rsp);

  // Store the latest status code.
  _status_code = rsp->line.status.code;
}

void RalfACR::tx_response(pjsip_msg* rsp, pj_time_val timestamp)
{
  if (timestamp.sec == -1)
  {
    // Timestamp is unspecified, so get the current time.
    pj_gettimeofday(&timestamp);
  }

  _rsp_timestamp = timestamp;

  // Store the charging function addresses if present.
  store_charging_addresses(rsp);

  if (_node_role == NODE_ROLE_ORIGINATING)
  {
    // For originating requests store media from the final transmitted response.
    store_media_description(rsp, _media);

    // Store non-SDP message bodies if present.
    store_message_bodies(rsp);
  }

  if ((_method == "REGISTER") &&
      (rsp->line.status.code == PJSIP_SC_OK))
  {
    // Store the associated URIs from the 200 OK/REGISTER response.  These
    // are stored from the transmitted response to catch the case where the
    // S-CSCF has generated the response itself.
    store_associated_uris(rsp);
  }

  // Store the latest status code.
  _status_code = rsp->line.status.code;

  if ((_record_type == START_RECORD) &&
      (_status_code >= 300))
  {
    // Failed to start the session, so convert to an EVENT record.
    LOG_DEBUG("Failed to start session, change record type to EVENT_RECORD");
    _record_type = EVENT_RECORD;
  }
}

void RalfACR::as_info(const std::string& uri,
                      const std::string& redirect_uri,
                      int status_code)
{
  // Add an entry to the _as_information list.
  LOG_DEBUG("Storing AS information for AS %s", uri.c_str());
  ASInformation as_info;
  as_info.uri = uri;
  as_info.redirect_uri = redirect_uri;
  as_info.status_code = status_code;
  _as_information.push_back(as_info);
}

void RalfACR::server_capabilities(const ServerCapabilities& caps)
{
  // Store the server capabilities.
  LOG_DEBUG("Storing Server-Capabilities");
  _server_caps = caps;
}

void RalfACR::send_message(pj_time_val timestamp)
{
  if ((!_ccfs.empty()) ||
      (!_ecfs.empty()))
  {
    // We have at least one valid destination CCF or ECF, so encode and send
    // the request using the Ralf HTTP connection.
    LOG_VERBOSE("Sending %s Ralf ACR (%p)",
                ACR::node_name(_node_functionality).c_str(), this);
    std::string path = "/call-id/" + _user_session_id;
    std::map<std::string, std::string> headers;
    long rc = _ralf->send_post(path,
                               headers,
                               get_message(timestamp),
                               _trail);

    if (rc != HTTP_OK)
    {
      LOG_ERROR("Failed to send Ralf ACR message (%p), rc = %ld", this, rc);
    }
  }
}

std::string RalfACR::get_message(pj_time_val timestamp)
{
  LOG_DEBUG("Building message");

  if (timestamp.sec == -1)
  {
    // Timestamp is unspecified, so get the current time.
    pj_gettimeofday(&timestamp);
  }

  Json::Value v;

  // Add the peers section with charging function addresses if this is a
  // start or event message.
  if ((_record_type == START_RECORD) ||
      (_record_type == EVENT_RECORD))
  {
    LOG_DEBUG("Adding peers meta-data, %d ccfs, %d ecfs", _ccfs.size(), _ecfs.size());
    Json::Value& p = v["peers"];
    for (std::list<std::string>::const_iterator i = _ccfs.begin();
         i != _ccfs.end();
         ++i)
    {
      p["ccf"].append(Json::Value(*i));
    }
    for (std::list<std::string>::const_iterator i = _ecfs.begin();
         i != _ecfs.end();
         ++i)
    {
      p["ecf"].append(Json::Value(*i));
    }
  }

  // Build the event data.
  LOG_DEBUG("Building event");
  Json::Value& e = v["event"];

  // Add top-level fields.
  LOG_DEBUG("Adding Account-Record-Type AVP %d", _record_type);
  e["Accounting-Record-Type"] = Json::Value(_record_type);
  if (!_username.empty())
  {
    e["User-Name"] = Json::Value(_username);
  }
  if (_interim_interval != 0)
  {
    e["Acct-Interim-Interval"] = Json::Value(_interim_interval);
  }
  e["Event-Timestamp"] = Json::Value((Json::UInt)timestamp.sec);

  // Add Service-Information AVP group.
  LOG_DEBUG("Adding Service-Information AVP group");
  Json::Value& si = e["Service-Information"];

  // Add Subscription-Id AVPs.
  LOG_DEBUG("Adding %d Subscription-Id AVPs", _subscription_ids.size());
  for (std::list<SubscriptionId>::const_iterator i = _subscription_ids.begin();
       i != _subscription_ids.end();
       ++i)
  {
    Json::Value& sub = si["Subscription-Id"].append(Json::Value());
    sub["Subscription-Id-Type"] = Json::Value(i->type);
    sub["Subscription-Id-Data"] = Json::Value(i->id);
  }

  // Add IMS-Information AVP group.
  LOG_DEBUG("Adding IMS-Information AVP group");
  Json::Value& ii = si["IMS-Information"];

  // Add Event-Type AVP group.
  LOG_DEBUG("Adding Event-Type AVP group");
  Json::Value& event_type = ii["Event-Type"];
  event_type["SIP-Method"] = Json::Value(_method);
  if (!_event.empty())
  {
    event_type["Event"] = Json::Value(_event);
  }
  if (_expires != -1)
  {
    event_type["Expires"] = Json::Value(_expires);
  }

  ii["Role-Of-Node"] = Json::Value(_node_role);
  ii["Node-Functionality"] = Json::Value(_node_functionality);
  ii["User-Session-Id"] = Json::Value(_user_session_id);

  // Add the Calling-Party-Address AVPs.
  LOG_DEBUG("Adding %d Calling-Party-Address AVPs", _calling_party_addresses.size());
  for (std::list<std::string>::const_iterator i = _calling_party_addresses.begin();
       i != _calling_party_addresses.end();
       ++i)
  {
    ii["Calling-Party-Address"].append(Json::Value(*i));
  }

  // Add the Called-Party-Address AVP.
  if (!_called_party_address.empty())
  {
    LOG_DEBUG("Adding Called-Party-Address AVP");
    ii["Called-Party-Address"] = Json::Value(_called_party_address);
  }

  // Add the Requested-Party-Address AVP.  This is only present if different
  // from the called party address.
  if (_requested_party_address != _called_party_address)
  {
    LOG_DEBUG("Adding Requested-Party-Address AVP");
    ii["Requested-Party-Address"] = Json::Value(_requested_party_address);
  }

  // Add the Called-Asserted-Identity AVPs.
  LOG_DEBUG("Adding %d Called-Asserted-Identity AVPs", _called_asserted_ids.size());
  for (std::list<std::string>::const_iterator i = _called_asserted_ids.begin();
       i != _called_asserted_ids.end();
       ++i)
  {
    ii["Called-Asserted-Identity"].append(Json::Value(*i));
  }

  // Add the Associated-URI AVPs.
  LOG_DEBUG("Adding %d Associated-URI AVPs", _associated_uris.size());
  for (std::list<std::string>::const_iterator i = _associated_uris.begin();
       i != _associated_uris.end();
       ++i)
  {
    ii["Associated-URI"].append(Json::Value(*i));
  }

  // Add the Time-Stamps AVP group.
  LOG_DEBUG("Adding Time-Stamps AVP group");
  Json::Value& timestamps = ii["Time-Stamps"];
  if (_req_timestamp.sec != 0)
  {
    timestamps["SIP-Request-Timestamp"] = Json::Value((Json::UInt)_req_timestamp.sec);
    timestamps["SIP-Request-Timestamp-Fraction"] = Json::Value((Json::UInt)_req_timestamp.msec);
  }
  if (_rsp_timestamp.sec != 0)
  {
    timestamps["SIP-Response-Timestamp"] = Json::Value((Json::UInt)_rsp_timestamp.sec);
    timestamps["SIP-Response-Timestamp-Fraction"] = Json::Value((Json::UInt)_rsp_timestamp.msec);
  }

  // Add the Application-Server-Information AVPs.
  LOG_DEBUG("Adding %d Application-Server-Information AVP groups", _as_information.size());
  for (std::list<ASInformation>::const_iterator i = _as_information.begin();
       i != _as_information.end();
       ++i)
  {
    Json::Value& as = ii["Application-Server-Information"].append(Json::Value());
    as["Application-Server"] = Json::Value(i->uri);
    if (!i->redirect_uri.empty())
    {
      as["Application-Provided-Called-Party-Address"].append(Json::Value(i->redirect_uri));
    }
    as["Status-Code"] = Json::Value(i->status_code);
  }

  // Add a single Inter-Operator-Identifier AVP group.  (According to 7.2.77 of
  // TS 32.299 there could be multiple of these, but only one
  // IMS-Charging-Identifier - but since they both come from the same SIP
  // header this seems inconsistent, so we only add a single IOI AVP group.
  if ((!_orig_ioi.empty()) || (!_term_ioi.empty()))
  {
    LOG_DEBUG("Adding Inter-Operator-Identifier AVP group");
    Json::Value& ioi = ii["Inter-Operator-Identifier"].append(Json::Value());
    if (!_orig_ioi.empty())
    {
      ioi["Originating-IOI"] = Json::Value(_orig_ioi);
    }
    if (!_term_ioi.empty())
    {
      ioi["Terminating-IOI"] = Json::Value(_term_ioi);
    }
  }

  // Add Transit-IOI-List AVPs.
  LOG_DEBUG("Adding %d Transit-IOI-List AVPs", _transit_iois.size());
  for (std::list<std::string>::const_iterator i = _transit_iois.begin();
       i != _transit_iois.end();
       ++i)
  {
    ii["Transit-IOI-List"].append(Json::Value(*i));
  }

  ii["IMS-Charging-Identifier"] = Json::Value(_icid);

  // Add Early-Media-Description AVPs.
  LOG_DEBUG("Adding %d Early-Media-Description AVPs", _early_media.size());
  for (std::list<EarlyMediaDescription>::const_iterator i = _early_media.begin();
       i != _early_media.end();
       ++i)
  {
    Json::Value& em = ii["Early-Media-Description"].append(Json::Value());
    em["SDP-Timestamps"]["SDP-Offer-Timestamp"] =
                               Json::Value((Json::UInt)i->offer_timestamp.sec);
    em["SDP-Timestamps"]["SDP-Answer-Timestamp"] =
                              Json::Value((Json::UInt)i->answer_timestamp.sec);
    encode_sdp_description(em, i->media);
  }

  // Add SDP related AVPs to IMS-Information AVP.
  LOG_DEBUG("Adding Media AVPs");
  encode_sdp_description(ii, _media);

  // Add the Server-Capabilities AVP if I-CSCF.
  if (_node_functionality == ICSCF)
  {
    LOG_DEBUG("Adding Server-Capabilities AVP group");
    Json::Value& server_caps = ii["Server-Capabilities"];
    for (std::vector<int>::const_iterator i = _server_caps.mandatory_caps.begin();
         i != _server_caps.mandatory_caps.end();
         ++i)
    {
      server_caps["Mandatory-Capability"].append(Json::Value(*i));
    }
    for (std::vector<int>::const_iterator i = _server_caps.optional_caps.begin();
         i != _server_caps.optional_caps.end();
         ++i)
    {
      server_caps["Optional-Capability"].append(Json::Value(*i));
    }
    if (!_server_caps.scscf.empty())
    {
      server_caps["Server-Name"].append(Json::Value(_server_caps.scscf));
    }
  }

  // Add Message-Body AVPs.
  LOG_DEBUG("Adding %d Message-Body AVPs", _msg_bodies.size());
  for (std::list<MessageBody>::const_iterator i = _msg_bodies.begin();
       i != _msg_bodies.end();
       ++i)
  {
    Json::Value& body = ii["Message-Body"].append(Json::Value());
    body["Content-Type"] = Json::Value(i->type);
    body["Content-Length"] = Json::Value(i->length);
    if (!i->disposition.empty())
    {
      body["Content-Disposition"] = Json::Value(i->disposition);
    }
    body["Originator"] = Json::Value(i->originator);
  }

  // Add Cause-Code AVP if STOP or EVENT message.
  if (_record_type == STOP_RECORD)
  {
    // Cause code is always zero for STOP requests.
    LOG_DEBUG("Adding Cause-Code(0) AVP to ACR[Stop]");
    ii["Cause-Code"] = Json::Value(0);
  }
  else if (_record_type == EVENT_RECORD)
  {
    // Calculate the cause code to include on the request (see 7.2.35/TS 32.299
    // for all the gory details).
    int cause_code = 0;
    if (_status_code == PJSIP_SC_OK)
    {
      if ((_method == "SUBSCRIBE") &&
          (_expires == 0))
      {
        // End of SUBSCRIBE dialog.
        cause_code = -2;
      }
      else if ((_method == "REGISTER") &&
               (_expires == 0))
      {
        // End of REGISTER dialog (nonsense I know, but it's what the spec
        // says).
        cause_code = -3;
      }
      else
      {
        // Successful transaction.
        cause_code = -1;
      }
    }
    else if ((_status_code > PJSIP_SC_OK) &&
             (_status_code < PJSIP_SC_BAD_REQUEST))
    {
      // 2xx or 3xx response.
      cause_code = -_status_code;
    }
    else
    {
      // 4xx, 5xx or 6xx response.
      cause_code = _status_code;
    }
    // We don't currently support the Unspecified error (1), Unsuccessful
    // session setup (2) or Internal error (3) cause codes - in all of these
    // cases we have to send a SIP response with a valid 4xx/5xx/6xx status
    // code, so we use that status code.
    LOG_DEBUG("Adding Cause-Code(%d) AVP to ACR[Interim]", cause_code);
    ii["Cause-Code"] = Json::Value(cause_code);
  }

  // Add Reason-Header AVPs.
  LOG_DEBUG("Adding %d Reason-Header AVPs", _reasons.size());
  for (std::list<std::string>::const_iterator i = _reasons.begin();
       i != _reasons.end();
       ++i)
  {
    ii["Reason-Header"].append(Json::Value(*i));
  }

  // Add Access-Network-Information AVPs
  LOG_DEBUG("Adding %d Access-Network-Information AVPs", _access_network_info.size());
  for (std::list<std::string>::const_iterator i = _access_network_info.begin();
       i != _access_network_info.end();
       ++i)
  {
    ii["Access-Network-Information"].append(Json::Value(*i));
  }

  // Add From-Address AVP.
  LOG_DEBUG("Adding From-Address AVP");
  ii["From-Address"] = Json::Value(_from_address);

  // Add IMS-Visited-Network-Identifier AVP if set.
  if (!_visited_network_id.empty())
  {
    LOG_DEBUG("Adding IMS-Visited-Network-Identifier AVP");
    ii["IMS-Visited-Network-Identifier"] = Json::Value(_visited_network_id);
  }

  // Add Route-Header-Received and Route-Header-Transmitted AVPs if set.
  if (!_route_hdr_received.empty())
  {
    LOG_DEBUG("Adding Route-Header-Received AVP");
    ii["Route-Header-Received"] = Json::Value(_route_hdr_received);
  }
  if (!_route_hdr_transmitted.empty())
  {
    LOG_DEBUG("Adding Route-Header-Transmitted AVP");
    ii["Route-Header-Transmitted"] = Json::Value(_route_hdr_transmitted);
  }

  // Add the Instance-Id AVP if set.
  if (!_instance_id.empty())
  {
    LOG_DEBUG("Adding Instance-Id AVP");
    ii["Instance-Id"] = Json::Value(_instance_id);
  }

  //LOG_DEBUG("Built JSON message %s", v.toStyledString().c_str());

  // Render the message to a string and return it.
  Json::FastWriter writer;
  return writer.write(v);
}

void RalfACR::encode_sdp_description(Json::Value& v, const MediaDescription& media)
{
  // Split the offer and answer in to lines.
  std::vector<std::string> offer;
  split_sdp(media.offer.sdp, offer);
  std::vector<std::string> answer;
  split_sdp(media.answer.sdp, answer);

  // First add the SDP-Session-Description AVPs.  We take these from the
  // answer if there is one, and from the offer otherwise (rather than
  // repeating them).
  LOG_DEBUG("Adding SDP-Session-Description AVPs");
  std::vector<std::string>& session_sdp = (answer.empty()) ? offer : answer;
  for (size_t ii = 0; ii < session_sdp.size(); ++ii)
  {
    if (session_sdp[ii][0] == 'm')
    {
      break;
    }
    v["SDP-Session-Description"].append(Json::Value(session_sdp[ii]));
  }

  // Now parse and encode the offer and answer media components.
  LOG_DEBUG("Adding media AVPs for offer");
  encode_media_components(v,
                          offer,
                          SDP_OFFER,
                          media.offer.initiator_flag,
                          media.offer.initiator_party);
  LOG_DEBUG("Adding media AVPs for answer");
  encode_media_components(v,
                          answer,
                          SDP_ANSWER,
                          media.answer.initiator_flag,
                          media.answer.initiator_party);
}

void RalfACR::encode_media_components(Json::Value& v,
                                  const std::vector<std::string>& sdp,
                                  SDPType sdp_type,
                                  Initiator initiator_flag,
                                  const std::string& initiator_party)
{
  for (size_t ii = 0; ii < sdp.size(); )
  {
    if (sdp[ii][0] == 'm')
    {
      // Generate an SDP-Media-Component AVP.
      Json::Value& mc = v["SDP-Media-Component"].append(Json::Value());

      // Add the SDP-Media-Name AVP.
      mc["SDP-Media-Name"] = Json::Value(sdp[ii]);

      // Add SDP-Media-Description AVPs.
      for (ii = ii + 1; (ii < sdp.size()) && (sdp[ii][0] != 'm'); ++ii)
      {
        mc["SDP-Media-Description"].append(Json::Value(sdp[ii]));
      }

      // Add the Local-GW-Inserted-Indication AVP (alway 0 - Local GW not
      // inserted).
      mc["Local-GW-Inserted-Indication"] = Json::Value(0);

      // Add the IP-Realm-Default-Indication AVP (always 1 - Default IP
      // realm used).
      mc["IP-Realm-Default-Indication"] = Json::Value(1);

      // Add the Transcoder-Inserted-Indication AVP (always 0 - Transcode not
      // inserted).
      mc["Transcoder-Inserted-Indication"] = Json::Value(0);

      // Add the Media-Initiator-Flag AVP.
      mc["Media-Initiator-Flag"] = Json::Value(initiator_flag);

      // Add the Media-Initiator-Party AVP.
      mc["Media-Initiator-Party"] = Json::Value(initiator_party);

      // Add the SDP-Type AVP.
      mc["SDP-Type"] = Json::Value(sdp_type);
    }
    else
    {
      // Not an m= line, so move to the next one.
      ++ii;
    }
  }
}

/// Splits a block of SDP in to individual lines, removing any carriage
/// return characters at the end of the lines if present.
void RalfACR::split_sdp(const std::string& sdp, std::vector<std::string>& lines)
{
  size_t start_pos = 0;
  size_t end_pos;
  size_t next_start_pos;

  do
  {
    end_pos = sdp.find('\n', start_pos);
    if (end_pos == std::string::npos)
    {
      // Reached the end of the string.
      next_start_pos = std::string::npos;
      end_pos = sdp.length();
    }
    else
    {
      // Found a line feed.
      next_start_pos = end_pos + 1;
    }

    if (sdp[end_pos - 1] == '\r')
    {
      // Line ends in carriage return, so strip it.
      end_pos = end_pos - 1;
    }

    if (end_pos > start_pos)
    {
      // Non-blank line, so add it to output.
      lines.push_back(sdp.substr(start_pos, end_pos - start_pos));
    }

    // Move to the start of the next line.
    start_pos = next_start_pos;
  }
  while (start_pos != std::string::npos);
}

void RalfACR::store_charging_addresses(pjsip_msg* msg)
{
  // Only store charging addresses for START or EVENT ACRs - they are not
  // needed for INTERIM or STOP ACRs.
  if ((_record_type == START_RECORD) ||
      (_record_type == EVENT_RECORD))
  {
    pjsip_p_c_f_a_hdr* p_cfa_hdr = (pjsip_p_c_f_a_hdr*)
                             pjsip_msg_find_hdr_by_name(msg, &STR_P_C_F_A, NULL);
    if (p_cfa_hdr != NULL)
    {
      // Clear out any existing entries.
      LOG_DEBUG("Found a P-Charging-Function-Address header");
      _ccfs.clear();
      _ecfs.clear();

      // Copy CCFs from the header.
      for (pjsip_param* p = p_cfa_hdr->ccf.next;
           (p != NULL) && (p != &p_cfa_hdr->ccf);
           p = p->next)
      {
        _ccfs.push_back(PJUtils::pj_str_to_string(&p->value));
      }

      // Copy ECFs from the header.
      for (pjsip_param* p = p_cfa_hdr->ecf.next;
           (p != NULL) && (p != &p_cfa_hdr->ecf);
           p = p->next)
      {
        _ecfs.push_back(PJUtils::pj_str_to_string(&p->value));
      }
      LOG_DEBUG("%d ccfs and %d ecfs", _ccfs.size(), _ecfs.size());
    }
  }
}

void RalfACR::store_subscription_ids(pjsip_msg* msg)
{
  pjsip_routing_hdr* pa_id = (pjsip_routing_hdr*)
               pjsip_msg_find_hdr_by_name(msg, &STR_P_ASSERTED_IDENTITY, NULL);
  while (pa_id != NULL)
  {
    pjsip_uri* uri = (pjsip_uri*)pjsip_uri_get_uri(&pa_id->name_addr);
    _subscription_ids.push_back(uri_to_subscription_id(uri));
    pa_id = (pjsip_routing_hdr*)
        pjsip_msg_find_hdr_by_name(msg, &STR_P_ASSERTED_IDENTITY, pa_id->next);
  }
  LOG_DEBUG("Stored %d subscription identifiers", _subscription_ids.size());
}

RalfACR::SubscriptionId RalfACR::uri_to_subscription_id(pjsip_uri* uri)
{
  SubscriptionId id;
  if (PJSIP_URI_SCHEME_IS_SIP(uri))
  {
    // SIP URI
    id.type = END_USER_SIP_URI;
    id.id = PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, uri);
    LOG_DEBUG("Found SIP URI subscription identifier %s", id.id.c_str());
  }
  else
  {
    // TEL URI
    id.type = END_USER_E164;
    id.id = PJUtils::pj_str_to_string(&((pjsip_tel_uri*)uri)->number);
    LOG_DEBUG("Found E.164 subscription identifier %s", id.id.c_str());
  }
  return id;
}

void RalfACR::store_calling_party_addresses(pjsip_msg* msg)
{
  pjsip_routing_hdr* pa_id = (pjsip_routing_hdr*)
               pjsip_msg_find_hdr_by_name(msg, &STR_P_ASSERTED_IDENTITY, NULL);
  while (pa_id != NULL)
  {
    pjsip_uri* uri = (pjsip_uri*)pjsip_uri_get_uri(&pa_id->name_addr);
    _calling_party_addresses.push_back(
                         PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, uri));
    pa_id = (pjsip_routing_hdr*)
        pjsip_msg_find_hdr_by_name(msg, &STR_P_ASSERTED_IDENTITY, pa_id->next);
  }
}

void RalfACR::store_called_party_address(pjsip_msg* msg)
{
  _called_party_address =
               PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, msg->line.req.uri);
}

void RalfACR::store_called_asserted_ids(pjsip_msg* msg)
{
  pjsip_routing_hdr* pa_id = (pjsip_routing_hdr*)
               pjsip_msg_find_hdr_by_name(msg, &STR_P_ASSERTED_IDENTITY, NULL);
  while (pa_id != NULL)
  {
    pjsip_uri* uri = (pjsip_uri*)pjsip_uri_get_uri(&pa_id->name_addr);
    _called_asserted_ids.push_back(
                         PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, uri));
    pa_id = (pjsip_routing_hdr*)
        pjsip_msg_find_hdr_by_name(msg, &STR_P_ASSERTED_IDENTITY, pa_id->next);
  }
}

void RalfACR::store_associated_uris(pjsip_msg* msg)
{
  LOG_DEBUG("Store associated URIs");
  pjsip_routing_hdr* pau = (pjsip_routing_hdr*)
                  pjsip_msg_find_hdr_by_name(msg, &STR_P_ASSOCIATED_URI, NULL);
  while (pau != NULL)
  {
    pjsip_uri* uri = (pjsip_uri*)pjsip_uri_get_uri(&pau->name_addr);
    _associated_uris.push_back(
                         PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, uri));
    pau = (pjsip_routing_hdr*)
             pjsip_msg_find_hdr_by_name(msg, &STR_P_ASSOCIATED_URI, pau->next);
  }
}

void RalfACR::store_charging_info(pjsip_msg* msg)
{
  pjsip_p_c_v_hdr* pcv_hdr = (pjsip_p_c_v_hdr*)
                             pjsip_msg_find_hdr_by_name(msg, &STR_P_C_V, NULL);
  if (pcv_hdr != NULL)
  {
    LOG_DEBUG("Found P-Charging-Vector header, store information");
    _icid = PJUtils::pj_str_to_string(&pcv_hdr->icid);
    _orig_ioi = PJUtils::pj_str_to_string(&pcv_hdr->orig_ioi);
    _term_ioi = PJUtils::pj_str_to_string(&pcv_hdr->term_ioi);

    for (pjsip_param* p = pcv_hdr->other_param.next;
         (p != NULL) && (p != &pcv_hdr->other_param);
         p = p->next)
    {
      if (pj_stricmp(&p->name, &STR_TRANSIT_IOI) == 0)
      {
        _transit_iois.push_back(PJUtils::pj_str_to_string(&p->value));
      }
    }
  }
}

void RalfACR::store_media_description(pjsip_msg* msg, MediaDescription& description)
{
  // If the message has an SDP body store it in the offer or answer slot.
  pjsip_msg_body* body = msg->body;

  if ((body != NULL) &&
      (pj_stricmp(&body->content_type.type, &STR_APPLICATION) == 0) &&
      (pj_stricmp(&body->content_type.subtype, &STR_SDP) == 0))
  {
    if (_method == "ACK")
    {
      // ACKs can only every carry answers.
      store_media_components(msg, description.answer);
    }
    else if ((msg->type == PJSIP_REQUEST_MSG) ||
             (description.offer.sdp == ""))
    {
      // Either a request (so by definition an offer), or no offer on the
      // request, so store as the offer.
      store_media_components(msg, description.offer);
    }
    else
    {
      // Store the SDP as the answer.
      store_media_components(msg, description.answer);
    }
  }
}

void RalfACR::store_media_components(pjsip_msg* msg, MediaComponents& components)
{
  pjsip_msg_body* body = msg->body;

  // Store the SDP body.
  components.sdp = std::string((char*)body->data, body->len);

  // Determine the initiator of the media action.  This will depend on
  // - whether the SDP is on the request or response
  // - the orientation of this transaction relative to the initial
  //   transaction that set up the dialog
  if (((_initiator == Initiator::CALLING_PARTY) &&
       (msg->type == PJSIP_REQUEST_MSG)) ||
      ((_initiator == Initiator::CALLED_PARTY) &&
       (msg->type == PJSIP_RESPONSE_MSG)))
  {
    components.initiator_flag = Initiator::CALLING_PARTY;
  }
  else
  {
    components.initiator_flag = Initiator::CALLED_PARTY;
  }

  // Store the URI of the originator.  This is the first P-Asserted-Identity
  // from the message (request or response) if present, or the RequestURI from
  // the original request if the message is a response and there is no
  // P-Asserted-Identity.
  pjsip_routing_hdr* pa_id = (pjsip_routing_hdr*)
               pjsip_msg_find_hdr_by_name(msg, &STR_P_ASSERTED_IDENTITY, NULL);
  if (pa_id != NULL)
  {
    pjsip_uri* uri = (pjsip_uri*)pjsip_uri_get_uri(&pa_id->name_addr);
    components.initiator_party =
                          PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, uri);
  }
  else if (msg->type == PJSIP_RESPONSE_MSG)
  {
    components.initiator_party = _requested_party_address;
  }
}

void RalfACR::store_message_bodies(pjsip_msg* msg)
{
  pjsip_msg_body* msg_body = msg->body;

  if ((msg_body != NULL) &&
      ((pj_stricmp(&msg_body->content_type.type, &STR_APPLICATION) != 0) ||
       (pj_stricmp(&msg_body->content_type.subtype, &STR_SDP) != 0)))
  {
    // Create a MessageBody structure encoding the required information about
    // the message body.
    MessageBody body;
    body.type = PJUtils::pj_str_to_string(&msg_body->content_type.type)
                + "/"
                + PJUtils::pj_str_to_string(&msg_body->content_type.subtype);
    body.length = msg_body->len;
    pjsip_generic_string_hdr* cdisp_hdr = (pjsip_generic_string_hdr*)
               pjsip_msg_find_hdr_by_name(msg, &STR_CONTENT_DISPOSITION, NULL);
    if (cdisp_hdr != NULL)
    {
      // Get disposition from header.
      body.disposition = PJUtils::pj_str_to_string(&cdisp_hdr->hvalue);
    }
    else
    {
      // Default disposition for non application/sdp bodies is "render"
      body.disposition = "render";
    }
    if (((_initiator == Initiator::CALLING_PARTY) &&
         (msg->type == PJSIP_REQUEST_MSG)) ||
        ((_initiator == Initiator::CALLED_PARTY) &&
         (msg->type == PJSIP_RESPONSE_MSG)))
    {
      body.originator = Originator::CALLING_PARTY;
    }
    else
    {
      body.originator = Originator::CALLED_PARTY;
    }

    _msg_bodies.push_back(body);
  }
}

void RalfACR::store_instance_id(pjsip_msg* msg)
{
  pjsip_contact_hdr* contact_hdr =
            (pjsip_contact_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_CONTACT, NULL);

  while (contact_hdr != NULL)
  {
    // Scan the parameters for a +sip.instance parameter.
    pjsip_param* p = pjsip_param_find(&contact_hdr->other_param,
                                      &STR_SIP_INSTANCE);
    if (p != NULL)
    {
      // Found the instance identifier, so convert to a string and dequote.
      _instance_id = PJUtils::pj_str_to_string(&p->value);
      _instance_id = _instance_id.substr(1, _instance_id.size() - 2);
      break;
    }
    contact_hdr = (pjsip_contact_hdr*)
                   pjsip_msg_find_hdr(msg, PJSIP_H_CONTACT, contact_hdr->next);
  }
}

std::string RalfACR::hdr_contents(pjsip_hdr* hdr)
{
  // Print the header using PJSIP print_on function.
  char buf[1000];
  int len = pjsip_hdr_print_on(hdr, buf, sizeof(buf));
  buf[len] = '\0';

  // Strip the header name plus the colon character and space that PJSIP
  // always renders.
  char* p = strchr(buf, ':') + 2;

  return std::string(p);
}

/// RalfACRFactory Constructor.
RalfACRFactory::RalfACRFactory(HttpConnection* ralf,
                               Node node_functionality) :
  _ralf(ralf),
  _node_functionality(node_functionality)
{
  LOG_DEBUG("Created RalfACR factory for node type %s",
            ACR::node_name(_node_functionality).c_str());
}

/// RalfACRFactory Destructor.
RalfACRFactory::~RalfACRFactory()
{
}

/// Get an RalfACR instance from the factory.
ACR* RalfACRFactory::get_acr(SAS::TrailId trail,
                                 Initiator initiator)
{
  LOG_DEBUG("Create RalfACR for node type %s",
            ACR::node_name(_node_functionality).c_str());
  return (ACR*)new RalfACR(_ralf, trail, _node_functionality, initiator);
}

