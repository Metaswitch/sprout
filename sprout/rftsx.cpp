/**
 * @file rftsx.cpp  The Rf Transaction class.
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
#include "rftsx.h"

RfTsx::RfTsx(HttpConnection* ralf,
             SAS::TrailId trail,
             const std::string& origin_host,
             RfNode node_functionality,
             Initiator initiator) :
  _ralf(ralf),
  _trail(trail),
  _initiator(initiator),
  _first_req(true),
  _first_rsp(true),
  _origin_host(origin_host),
  _node_functionality(node_functionality),
  _status_code(0)
{
}

RfTsx::~RfTsx()
{
}

void RfTsx::rx_request(pjsip_msg* req, pj_time_val timestamp)
{
  if (_first_req)
  {
    // This is the first time we have seen a request for this transaction,
    // so extract all the "first request" fields.
    _first_req = false;

    // Store a timestamp for the original request.
    _req_timestamp = timestamp;

    // Save the method.
    _method = PJUtils::pj_str_to_string(&req->line.req.method.name);

    // Set the record type based on the node functionality and the method.
    // This may get changed later (for example, if an INVITE transaction fails
    // we send EVENT instead of START).
    if ((_node_functionality == PCSCF) ||
        (_node_functionality == SCSCF))
    {
      pjsip_fromto_hdr* to_hdr = (pjsip_fromto_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_TO, NULL);
      if ((to_hdr != NULL) && (to_hdr->tag.slen > 0))
      {
        if (_method == "BYE")
        {
          // BYE requests with a valid To tag must be a STOP request.
          _record_type = STOP_RECORD;
        }
        else
        {
          // Any other requests with a To tag are INTERIMs.
          _record_type = INTERIM_RECORD;
        }
      }
      else if (_method == "INVITE")
      {
        // INVITE with no To tag is a START.
        _record_type = START_RECORD;
      }
      else
      {
        // Anything else is an EVENT.
        _record_type = EVENT_RECORD;
      }
    }
    else
    {
      // All other node types only generate EVENTs.
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
      // Check for expires values in Contact headers???
    }

    // Store the call ID.
    pjsip_cid_hdr* cid_hdr = (pjsip_cid_hdr*)
                                pjsip_msg_find_hdr(req, PJSIP_H_CALL_ID, NULL);
    if (cid_hdr != NULL)
    {
      _user_session_id = PJUtils::pj_str_to_string(&cid_hdr->id);
    }

    // Store contents of From header.
    pjsip_fromto_hdr* from_hdr = (pjsip_fromto_hdr*)
                                   pjsip_msg_find_hdr(req, PJSIP_H_FROM, NULL);
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
#if 0
    if (req->line.req.method.id == PJSIP_INVITE_METHOD)
    {
      pjsip_session_expires_hdr* sess_expires = (pjsip_session_expires_hdr*)
                               pjsip_msg_find_hdr_by_names(req,
                                                           &STR_SESSION_EXPIRES,
                                                           &STR_X,
                                                           NULL);
      if (sess_expires != NULL)
      {
        _interim_interval = sess_expires->delta_seconds;
      }
    }
#endif

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
void RfTsx::tx_request(pjsip_msg* req, pj_time_val timestamp)
{
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

/// Called with all non-100 responses as first received by the node.  As
/// above, this does not include S-CSCF responses received from ASs, only when the
/// response is first received from
void RfTsx::rx_response(pjsip_msg* rsp, pj_time_val timestamp)
{
  if (_first_rsp)
  {
    _first_rsp = false;

    if (_node_role == NODE_ROLE_TERMINATING)
    {
      // For terminating requests take the subscription identifiers from
      // P-Asserted-Identity headers in the first response.
      store_subscription_ids(rsp);
    }

    if (rsp->line.status.code == PJSIP_SC_OK)
    {
      // First 200 OK response, so store the called asserted identities.
      store_called_asserted_ids(rsp);
    }
  }

  // Store the latest status code.
  _status_code = rsp->line.status.code;
}

void RfTsx::tx_response(pjsip_msg* rsp, pj_time_val timestamp)
{
  _rsp_timestamp = timestamp;

  // Store the charging function addresses.  Currently we take this from the
  // response we transmit as this is guaranteed to have the correct
  // P-Charging-Function-Address header in all cases.
  store_charging_addresses(rsp);

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
      (_status_code > 299))
  {
    // Failed to start the session, so convert to an EVENT record.
    _record_type = EVENT_RECORD;
  }
}

void RfTsx::send_message()
{
  // Build the JSON message body.
  Json::Value v;

  // Add the peers section with charging function addresses if this is a
  // start or event message.
  if ((_record_type == START_RECORD) ||
      (_record_type == EVENT_RECORD))
  {
    Json::Value& p = v["peers"];
    for (std::list<std::string>::const_iterator i = _ccfs.begin();
         i != _ccfs.end();
         ++i)
    {
      p["ccfs"].append(Json::Value(*i));
    }
    for (std::list<std::string>::const_iterator i = _ecfs.begin();
         i != _ecfs.end();
         ++i)
    {
      p["ecfs"].append(Json::Value(*i));
    }
  }

  // Build the event data.
  Json::Value& e = v["event"];

  // Add top-level fields.
  e["Origin-Host"] = Json::Value(_origin_host);
  e["Accounting-Record-Type"] = Json::Value(_record_type);
  if (!_username.empty())
  {
    e["User-Name"] = Json::Value(_username);
  }
  e["Acct-Interim-Interval"] = _interim_interval;
  e["Event-Timestamp"] = avp_timestamp(time(NULL));

  // Add Service-Information AVP group.
  Json::Value& si = e["Service-Information"];

  // Add Subscription-Id AVPs.
  for (std::list<SubscriptionId>::const_iterator i = _subscription_ids.begin();
       i != _subscription_ids.end();
       ++i)
  {
    Json::Value sub = si["Subscription-Id"].append(Json::Value());
    sub["Subscription-Id-Type"] = Json::Value(i->type);
    sub["Subscription-Id-Data"] = Json::Value(i->id);
  }

  // Add IMS-Information AVP group.
  Json::Value& ii = si["IMS-Information"];

  // Add Event-Type AVP group.
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
  for (std::list<std::string>::const_iterator i = _calling_party_addresses.begin();
       i != _calling_party_addresses.end();
       ++i)
  {
    ii["Calling-Party-Address"].append(Json::Value(*i));
  }

  // Add the Called-Party-Address AVP.
  if (!_called_party_address.empty())
  {
    ii["Called-Party-Address"] = Json::Value(_called_party_address);
  }

  // Add the Requested-Party-Address AVP.  This is only present if different
  // from the called party address.
  if (_requested_party_address != _called_party_address)
  {
    ii["Requested-Party-Address"] = Json::Value(_requested_party_address);
  }

  // Add the Called-Asserted-Identity AVPs.
  for (std::list<std::string>::const_iterator i = _called_asserted_ids.begin();
       i != _called_asserted_ids.end();
       ++i)
  {
    ii["Called-Asserted-Identity"].append(Json::Value(*i));
  }

  // Add the Associated-URI AVPs.
  for (std::list<std::string>::const_iterator i = _associated_uris.begin();
       i != _associated_uris.end();
       ++i)
  {
    ii["Associated-URI"].append(Json::Value(*i));
  }

  // Add the Time-Stamps AVP group.
  Json::Value& timestamps = ii["Time-Stamps"];
  timestamps["SIP-Request-Timestamp"] = Json::Value(avp_timestamp(_req_timestamp.sec));
  timestamps["SIP-Request-Timestamp-Fraction"] = Json::Value((Json::Int)_req_timestamp.msec);
  timestamps["SIP-Response-Timestamp"] = Json::Value(avp_timestamp(_rsp_timestamp.sec));
  timestamps["SIP-Response-Timestamp-Fraction"] = Json::Value((Json::Int)_rsp_timestamp.msec);

  // Add the Application-Server-Information AVPs.
  for (std::list<ASInformation>::const_iterator i = _as_information.begin();
       i != _as_information.end();
       ++i)
  {
    Json::Value& as = ii["Application-Server-Information"].append(Json::Value());
    as["Application-Server"] = Json::Value(i->uri);
    if (!i->redirect.empty())
    {
      as["Application-Provided-Called-Party-Address"].append(Json::Value(i->redirect));
    }
    as["Status-Code"] = Json::Value(i->status_code);
  }

  // Add a single Inter-Operator-Identifier AVP group.  (According to 7.2.77 of
  // TS 32.299 there could be multiple of these, but only one
  // IMS-Charging-Identifier - but since they both come from the same SIP
  // header this seems inconsistent, so we only add a single IOI AVP group.
  if ((!_orig_ioi.empty()) || (!_term_ioi.empty()))
  {
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
  for (std::list<std::string>::const_iterator i = _transit_iois.begin();
       i != _transit_iois.end();
       ++i)
  {
    ii["Transit-IOI-List"].append(Json::Value(*i));
  }

  ii["IMS-Charging-Identifier"] = Json::Value(_icid);

  // Add Early-Media-Description AVPs.
  for (std::list<EarlyMediaDescription>::const_iterator i = _early_media.begin();
       i != _early_media.end();
       ++i)
  {
    Json::Value& em = ii["Early-Media-Description"].append(Json::Value());
    em["SDP-Timestamps"]["SDP-Offer-Timestamp"] = avp_timestamp(i->offer_timestamp.sec);
    em["SDP-Timestamps"]["SDP-Answer-Timestamp"] = avp_timestamp(i->answer_timestamp.sec);
    encode_sdp_description(em, i->media);
  }

  // Add SDP related AVPs to IMS-Information AVP.
  encode_sdp_description(ii, _media);

#if 0
  // Add the Server-Party-IP-Address AVP if P-CSCF and we have the information.
  if ((_node_functionality == PCSCF) &&
      (_served_party_ip_address.sa_family != pf_AF_UNSPEC()))
  {
    ii["Served-Party-IP-Address"] = avp_address(_served_party_ip_address);
  }
#endif

  // Add the Server-Capabilities AVP if I-CSCF.
  if (_node_functionality == ICSCF)
  {
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
    ii["Cause_code"] = Json::Value(0);
  }
  else if (_record_type == EVENT_RECORD)
  {
    // Calculate the cause code to include on the request.
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
        // says").
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
    ii["Cause-Code"] = Json::Value(cause_code);
  }

  // Add Reason-Header AVPs.
  for (std::list<std::string>::const_iterator i = _reasons.begin();
       i != _reasons.end();
       ++i)
  {
    ii["Reason-Header"].append(Json::Value(*i));
  }

  // Add Access-Network-Information AVPs
  for (std::list<std::string>::const_iterator i = _access_network_info.begin();
       i != _access_network_info.end();
       ++i)
  {
    ii["Access-Network-Information"].append(Json::Value(*i));
  }

  // Add From address AVP.
  ii["From-Address"] = Json::Value(_from_address);

  // Add IMS-Visited-Network-Identifier AVP if set.
  if (!_visited_network_id.empty())
  {
    ii["IMS-Visited-Network-Identifier"] = Json::Value(_visited_network_id);
  }

  // Add Route-Header-Received and Route-Header-Transmitted AVPs if set.
  if (!_route_hdr_received.empty())
  {
    ii["Route-Header-Received"] = Json::Value(_route_hdr_received);
  }
  if (!_route_hdr_transmitted.empty())
  {
    ii["Route-Header-Transmitted"] = Json::Value(_route_hdr_transmitted);
  }

  // Add the Instance-Id AVP if set.
  if (!_instance_id.empty())
  {
    ii["Instance-Id"] = Json::Value(_instance_id);
  }

  // Send the request using the Ralf HTTP connection.
  Json::FastWriter writer;
  std::string path = "/call_id/" + _user_session_id;
  std::map<std::string, std::string> headers;
  long rc = _ralf->send_post(path,
                             writer.write(v),
                             headers,
                             _trail);

  if (rc != HTTP_OK)
  {
    LOG_ERROR("Ralf billing message failed, rc = %ld", rc);
  }
}

void RfTsx::encode_sdp_description(Json::Value& v, const MediaDescription& media)
{
  // Split the offer and answer in to lines.
  std::vector<std::string> offer_lines;
  Utils::split_string(media.offer.sdp, '\n', offer_lines);
  std::vector<std::string> answer_lines;
  Utils::split_string(media.answer.sdp, '\n', answer_lines);

  // First add the SDP-Session-Description AVPs.  We take these from the
  // answer if there is one, and from the offer otherwise (rather than
  // repeating them).
  std::vector<std::string>& session_lines =
                           (answer_lines.empty()) ? offer_lines : answer_lines;
  for (size_t ii = 0; ii < session_lines.size(); ++ii)
  {
    if (session_lines[ii][0] == 'm')
    {
      break;
    }
    v["SDP-Session-Description"].append(Json::Value(session_lines[ii]));
  }

  // Now parse and encode the offer and answer media components.
  encode_media_components(v,
                          offer_lines,
                          SDP_OFFER,
                          media.offer.initiator_flag,
                          media.offer.initiator_party);
  encode_media_components(v,
                          answer_lines,
                          SDP_ANSWER,
                          media.answer.initiator_flag,
                          media.answer.initiator_party);
}

void RfTsx::encode_media_components(Json::Value& v,
                                    const std::vector<std::string>& sdp,
                                    SDPType sdp_type,
                                    Initiator initiator_flag,
                                    const std::string& initiator_party)
{
  for (size_t ii = 0; ii < sdp.size(); )
  {
    if (sdp[ii][0] == 'm')
    {
      // Found an m= line - check it looks basically valid.
      std::vector<std::string> media_tokens;
      Utils::split_string(sdp[ii], ' ', media_tokens);
      if (media_tokens.size() > 0)
      {
        // Generate an SDP-Media-Component AVP.
        Json::Value mc = v["SDP-Media-Component"].append(Json::Value());

        // Add the SDP-Media-Name AVP.
        mc["SDP-Media-Name"] = Json::Value(media_tokens[0]);

        // Add SDP-Media-Description AVPs.
        for (; (ii < sdp.size()) && (sdp[ii][0] != 'm'); ++ii)
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
    }
    else
    {
      // Not an m= line, so move to the next one.
      ++ii;
    }
  }
}

std::string RfTsx::avp_timestamp(time_t ts)
{
  // AVP timestamps are formatted as an 4 octet string, encoded as the first
  // 4 octets of the NTP format (as per RFC2030).  Note that this is in
  // seconds since 1900, so we must convert from Unix time (time since 1970)
  // to NTP time.  This conversion must take account of the extension
  // mechanism defined in RFC2030 to handle the NTP time wrap in 2036.
  // @TODO
  return "";
}

void RfTsx::store_charging_addresses(pjsip_msg* msg)
{

  pjsip_p_c_f_a_hdr* p_cfa_hdr = (pjsip_p_c_f_a_hdr*)
                           pjsip_msg_find_hdr_by_name(msg, &STR_P_C_F_A, NULL);
  if (p_cfa_hdr != NULL)
  {
    // Clear out any existing entries.
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
  }
}

void RfTsx::store_subscription_ids(pjsip_msg* msg)
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
}

RfTsx::SubscriptionId RfTsx::uri_to_subscription_id(pjsip_uri* uri)
{
  SubscriptionId id;
  if (PJSIP_URI_SCHEME_IS_SIP(uri))
  {
    // SIP URI
    id.type = END_USER_SIP_URI;
    id.id = PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, uri);
  }
  else
  {
    // TEL URI
    id.type = END_USER_E164;
    id.id = PJUtils::pj_str_to_string(&((pjsip_tel_uri*)uri)->number);
  }
  return id;
}

void RfTsx::store_calling_party_addresses(pjsip_msg* msg)
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

void RfTsx::store_called_party_address(pjsip_msg* msg)
{
  _called_party_address =
               PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, msg->line.req.uri);
}

void RfTsx::store_called_asserted_ids(pjsip_msg* msg)
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

void RfTsx::store_associated_uris(pjsip_msg* msg)
{
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

void RfTsx::store_charging_info(pjsip_msg* msg)
{
  pjsip_p_c_v_hdr* pcv_hdr = (pjsip_p_c_v_hdr*)
                             pjsip_msg_find_hdr_by_name(msg, &STR_P_C_V, NULL);
  if (pcv_hdr != NULL)
  {
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

void RfTsx::store_media_description(pjsip_msg* msg,
                                    MediaDescription& description)
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

void RfTsx::store_media_components(pjsip_msg* msg, MediaComponents& components)
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

void RfTsx::store_message_bodies(pjsip_msg* msg)
{
  pjsip_msg_body* body = msg->body;

  if ((body != NULL) &&
      ((pj_stricmp(&body->content_type.type, &STR_APPLICATION) != 0) ||
       (pj_stricmp(&body->content_type.subtype, &STR_SDP) != 0)))
  {
    // @TODO - how to record all the message bodies, but avoid duplicates when
    // simply forwarding requests or responses multiple times in S-CSCF case.

  }
}

void RfTsx::store_instance_id(pjsip_msg* msg)
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

std::string RfTsx::hdr_contents(pjsip_hdr* hdr)
{
  // Print the header using PJSIP print_on function.
  char buf[1000];
  pjsip_hdr_print_on(hdr, buf, sizeof(buf));

  // Strip the header name plus the colon character and space that PJSIP
  // always renders.
  char* p = strchr(buf, ':') + 2;

  return std::string(p);
}

