/**
 * @file acr.cpp  ACR class
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "log.h"
#include "utils.h"
#include "pjutils.h"
#include "constants.h"
#include "custom_headers.h"
#include "acr.h"
#include "sproutsasevent.h"

const pj_time_val ACR::unspec = {-1,0};

ACR::ACR() : _cancelled(false)
{
  TRC_DEBUG("Created ACR (%p)", this);
}

ACR::~ACR()
{
  TRC_DEBUG("Destroyed ACR (%p)", this);
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

void ACR::as_info(const std::string& uri, const std::string& redirect_uri, int status_code, bool timeout)
{
}

void ACR::server_capabilities(const ServerCapabilities& caps)
{
}

void ACR::send_message(pj_time_val timestamp)
{
  TRC_DEBUG("Sending Null ACR (%p)", this);
}

// LCOV_EXCL_START - never used, exists to provide same interface as RalfACR
std::string ACR::get_message(pj_time_val timestamp)
{
  return std::string();
}
// LCOV_EXCL_STOP

void ACR::set_default_ccf(const std::string& default_ccf)
{
}

void ACR::override_session_id(const std::string& session_id)
{
}

// The lock and unlock functions are no-ops for the Null ACR (no need to lock if
// there's no work to do)
void ACR::lock()
{
}

void ACR::unlock()
{
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

    // LCOV_EXCL_START - functionality is ENUM and should be covered in cases
    default:
      return "Unknown";
    // LCOV_EXCL_STOP
  }
}

std::string ACR::node_role_str(NodeRole role)
{
  switch (role)
  {
    case NODE_ROLE_ORIGINATING:
      return "Originating";

    case NODE_ROLE_TERMINATING:
      return "Terminating";

    // LCOV_EXCL_START - node role is ENUM and should be covered in cases
    default:
      return "Unknown";
    // LCOV_EXCL_STOP
  }
}

ACRFactory::ACRFactory()
{
}

ACRFactory::~ACRFactory()
{
}

ACR* ACRFactory::get_acr(SAS::TrailId trail,
                         ACR::Initiator initiator,
                         ACR::NodeRole role)
{
  return new ACR();
}

RalfACR::RalfACR(RalfProcessor* ralf,
                 SAS::TrailId trail,
                 Node node_functionality,
                 Initiator initiator,
                 NodeRole role) :
  _ralf(ralf),
  _trail(trail),
  _initiator(initiator),
  _first_req(true),
  _first_rsp(true),
  _interim_interval(0),
  _node_role(role),
  _node_functionality(node_functionality),
  _user_session_id(),
  _status_code(0)
{
  // Clear timestamps.
  _req_timestamp.sec = 0;
  _rsp_timestamp.sec = 0;

  pthread_mutex_init(&_acr_lock, NULL);

  TRC_DEBUG("Created %s Ralf ACR",
            ACR::node_name(_node_functionality).c_str(), this);
}

RalfACR::~RalfACR()
{
  pthread_mutex_destroy(&_acr_lock);
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
      TRC_DEBUG("Set record type for P/S-CSCF");
      if ((_method == "REGISTER") ||
          (_method == "SUBSCRIBE") ||
          (_method == "NOTIFY") ||
          (_method == "PUBLISH") ||
          (_method == "MESSAGE"))
      {
        // Non-dialog message, must be an EVENT record.
        TRC_DEBUG("Non-dialog message => EVENT_RECORD");
        _record_type = EVENT_RECORD;
      }
      else if (_method == "BYE")
      {
        // BYE request must be a STOP record.
        TRC_DEBUG("BYE => STOP_RECORD");
        _record_type = STOP_RECORD;
      }
      else if ((to_hdr != NULL) &&
               (to_hdr->tag.slen > 0))
      {
        // Any other requests with a To tag are INTERIMs.
        TRC_DEBUG("In-dialog %s request => INTERIM_RECORD", _method.c_str());
        _record_type = INTERIM_RECORD;
      }
      else if (_method == "INVITE")
      {
        // INVITE with no To tag is a START.
        TRC_DEBUG("Dialog-initiating INVITE => START_RECORD");
        _record_type = START_RECORD;
      }
      else
      {
        // Anything else is an EVENT.
        TRC_DEBUG("EVENT_RECORD");
        _record_type = EVENT_RECORD;
      }
    }
    else
    {
      // All other node types only generate EVENTs.
      TRC_DEBUG("Set record type for I-CSCF, BGCF, IBCF, AS to EVENT_RECORD");
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

    if (
        (req->line.req.method.id == PJSIP_REGISTER_METHOD) || 
        ( (req->line.req.method.id == PJSIP_OTHER_METHOD) &&
          (pj_strcmp2(&(req->line.req.method.name), "SUBSCRIBE") == 0) )   
       )
    {
      PJUtils::get_max_expires(req, -1, _expires);
    }
    else
    {
      _expires = -1;
    }

    // Determine the number of contact headers
    pjsip_contact_hdr* contact_hdr =
            (pjsip_contact_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_CONTACT, NULL);
    _num_contacts = 0;

    while (contact_hdr != NULL)
    {
      _num_contacts++;
      contact_hdr = (pjsip_contact_hdr*)
                     pjsip_msg_find_hdr(req, PJSIP_H_CONTACT, contact_hdr->next);
    }

    // Store the call ID but only if the session ID has not already been set.
    if (_user_session_id.empty())
    {
      pjsip_cid_hdr* cid_hdr = (pjsip_cid_hdr*)
                                  pjsip_msg_find_hdr(req, PJSIP_H_CALL_ID, NULL);
      if (cid_hdr != NULL)
      {
        _user_session_id = PJUtils::pj_str_to_string(&cid_hdr->id);
      }
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

  if ((_method != "REGISTER") &&
      (_node_role == NODE_ROLE_ORIGINATING))
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
    TRC_DEBUG("Failed to start session, change record type to EVENT_RECORD");
    _record_type = EVENT_RECORD;
  }
}

void RalfACR::as_info(const std::string& uri,
                      const std::string& redirect_uri,
                      int status_code,
                      bool timeout)
{
  // Add an entry to the _as_information list.
  TRC_DEBUG("Storing AS information for AS %s", uri.c_str());
  ASInformation as_info;
  as_info.uri = uri;
  as_info.redirect_uri = redirect_uri;
  if (timeout)
  {
    as_info.status_code = STATUS_CODE_TIMEOUT;
  }
  else if ((status_code >= 400) &&
           (status_code <= 499))
  {
    as_info.status_code = STATUS_CODE_4XX;
  }
  else if (status_code >= 500)
  {
    // TS 32.299 doesn't specify what to do with 6xx errors, so we choose to
    // report as 5xx.
    as_info.status_code = STATUS_CODE_5XX;
  }
  else
  {
    as_info.status_code = STATUS_CODE_NONE;
  }
  _as_information.push_back(as_info);
}

void RalfACR::server_capabilities(const ServerCapabilities& caps)
{
  // Store the server capabilities.
  TRC_DEBUG("Storing Server-Capabilities");
  _server_caps = caps;
}

void RalfACR::send_message(pj_time_val timestamp)
{
  // Calls to this function are always made through calls to `ACR::send()` which
  // ensures that the ACR has not been cancelled.  This means it is safe to
  // call `get_message()` to produce our request body.
  assert(!_cancelled);

  // If we have a CCF or ECF, or this isn't a record type that needs one, send
  // the message.
  if ((!_ccfs.empty()) ||
      (!_ecfs.empty()) ||
      (_record_type == INTERIM_RECORD) ||
      (_record_type == STOP_RECORD))
  {
    // Encode and add the request to the RalfProcessor pool
    TRC_VERBOSE("Sending %s Ralf ACR (%p)",
                ACR::node_name(_node_functionality).c_str(), this);
    std::string path = "/call-id/" + Utils::url_escape(_user_session_id);

    // Create a Ralf request and populate it
    RalfProcessor::RalfRequest* rr = new RalfProcessor::RalfRequest();
    rr->path = path;
    rr->message = get_message(timestamp);
    rr->trail = _trail;

    _ralf->send_request_to_ralf(rr);
  }
  else
  {
    // There's no CCF or ECF to send to, and we need one.  Drop the ACR.  This
    // is a software or configuration fault - we shouldn't be trying to supply
    // an ACR without a CCF.
    TRC_INFO("No CCF or ECF to send ACR for session %s to - dropping!",
             _user_session_id.c_str());
    SAS::Event event(_trail, SASEvent::NO_CCFS_FOR_ACR, 0);
    SAS::report_event(event);
  }
}

std::string RalfACR::get_message(pj_time_val timestamp)
{
  if (_cancelled)
  {
    return "Cancelled ACR";
  }

  TRC_DEBUG("Building message");

  if (timestamp.sec == -1)
  {
    // Timestamp is unspecified, so get the current time.
    pj_gettimeofday(&timestamp);
  }

  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
  writer.StartObject();

  // Add the peers section with charging function addresses if this is a
  // start or event message.
  if ((_record_type == START_RECORD) ||
      (_record_type == EVENT_RECORD))
  {
    TRC_DEBUG("Adding peers meta-data, %d ccfs, %d ecfs", _ccfs.size(), _ecfs.size());

    writer.String("peers");
    writer.StartObject();

    if (!_ccfs.empty())
    {
      writer.String("ccf");
      writer.StartArray();

      for (std::list<std::string>::const_iterator i = _ccfs.begin();
           i != _ccfs.end();
           ++i)
      {
        writer.String((*i).c_str());
      }

      writer.EndArray();
    }

    if (!_ecfs.empty())
    {
      writer.String("ecf");
      writer.StartArray();

      for (std::list<std::string>::const_iterator i = _ecfs.begin();
           i != _ecfs.end();
           ++i)
      {
        writer.String((*i).c_str());
      }

      writer.EndArray();
   }

   writer.EndObject();
  }

  // Build the event data.
  TRC_DEBUG("Building event");
  writer.String("event");
  writer.StartObject();

  // Add top-level fields.
  TRC_DEBUG("Adding Account-Record-Type AVP %d", _record_type);
  writer.String("Accounting-Record-Type");
  writer.Int(_record_type);

  if (!_username.empty())
  {
    writer.String("User-Name");
    writer.String(_username.c_str());
  }

  if (_interim_interval != 0)
  {
    writer.String("Acct-Interim-Interval");
    writer.Int(_interim_interval);
  }

  writer.String("Event-Timestamp");
  writer.Int(timestamp.sec);

  // Add Service-Information AVP group.
  TRC_DEBUG("Adding Service-Information AVP group");
  writer.String("Service-Information");
  writer.StartObject();

  if ((_node_functionality == PCSCF) ||
      (_node_functionality == SCSCF) ||
      (_node_functionality == IBCF))
  {
    // Add Subscription-Id AVPs on P-CSCF/S-CSCF/IBCF ACRs (should be omitted
    // on I-CSCF and BGCF).
    TRC_DEBUG("Adding %d Subscription-Id AVPs", _subscription_ids.size());

    if (_subscription_ids.size() > 0)
    {
      writer.String("Subscription-Id");
      writer.StartArray();

      for (std::list<SubscriptionId>::const_iterator i = _subscription_ids.begin();
           i != _subscription_ids.end();
           ++i)
      {
        writer.StartObject();
        {
          writer.String("Subscription-Id-Type");
          writer.Int(i->type);
          writer.String("Subscription-Id-Data");
          writer.String(i->id.c_str());
        }
        writer.EndObject();
      }

      writer.EndArray();
    }
  }

  // Add IMS-Information AVP group.
  TRC_DEBUG("Adding IMS-Information AVP group");
  writer.String("IMS-Information");
  writer.StartObject();

  // Add Event-Type AVP group.
  TRC_DEBUG("Adding Event-Type AVP group");
  writer.String("Event-Type");
  writer.StartObject();
  {
    writer.String("SIP-Method");
    writer.String(_method.c_str());

    if (!_event.empty())
    {
      writer.String("Event");
      writer.String(_event.c_str());
    }

    if (_expires != -1)
    {
      writer.String("Expires");
      writer.Int(_expires);
    }
  }
  writer.EndObject();

  writer.String("Role-Of-Node");
  writer.Int(_node_role);
  writer.String("Node-Functionality");
  writer.Int(_node_functionality);
  writer.String("User-Session-Id");
  writer.String(_user_session_id.c_str());

  // Add the Calling-Party-Address AVPs.
  TRC_DEBUG("Adding %d Calling-Party-Address AVPs", _calling_party_addresses.size());

  if (_calling_party_addresses.size() > 0)
  {
    writer.String("Calling-Party-Address");
    writer.StartArray();

    for (std::list<std::string>::const_iterator i = _calling_party_addresses.begin();
         i != _calling_party_addresses.end();
         ++i)
    {
      writer.String((*i).c_str());
    }

    writer.EndArray();
  }

  // Add the Called-Party-Address AVP.
  if (!_called_party_address.empty())
  {
    TRC_DEBUG("Adding Called-Party-Address AVP");
    writer.String("Called-Party-Address");
    writer.String(_called_party_address.c_str());
  }

  if (_node_functionality == SCSCF)
  {
    // Add the Requested-Party-Address AVP.  This is only present if different
    // from the called party address.
    if (_requested_party_address != _called_party_address)
    {
      TRC_DEBUG("Adding Requested-Party-Address AVP");
      writer.String("Requested-Party-Address");
      writer.String(_requested_party_address.c_str());
    }
  }

  if ((_node_functionality == PCSCF) ||
      (_node_functionality == SCSCF))
  {
    // Add the Called-Asserted-Identity AVPs.
    TRC_DEBUG("Adding %d Called-Asserted-Identity AVPs", _called_asserted_ids.size());

    if (_called_asserted_ids.size() > 0)
    {
      writer.String("Called-Asserted-Identity");
      writer.StartArray();

      for (std::list<std::string>::const_iterator i = _called_asserted_ids.begin();
           i != _called_asserted_ids.end();
           ++i)
      {
        writer.String((*i).c_str());
      }

      writer.EndArray();
    }
  }

  if (_node_functionality != BGCF)
  {
    // Add the Associated-URI AVPs.
    TRC_DEBUG("Adding %d Associated-URI AVPs", _associated_uris.size());

    if (_associated_uris.size() > 0)
    {
      writer.String("Associated-URI");
      writer.StartArray();

      for (std::list<std::string>::const_iterator i = _associated_uris.begin();
           i != _associated_uris.end();
           ++i)
      {
        writer.String((*i).c_str());
      }

      writer.EndArray();
    }
  }

  // Add the Time-Stamps AVP group.
  TRC_DEBUG("Adding Time-Stamps AVP group");
  writer.String("Time-Stamps");
  writer.StartObject();
  {
    if (_req_timestamp.sec != 0)
    {
      writer.String("SIP-Request-Timestamp");
      writer.Int(_req_timestamp.sec);
      writer.String("SIP-Request-Timestamp-Fraction");
      writer.Int(_req_timestamp.msec);
    }

    if (_rsp_timestamp.sec != 0)
    {
      writer.String("SIP-Response-Timestamp");
      writer.Int(_rsp_timestamp.sec);
      writer.String("SIP-Response-Timestamp-Fraction");
      writer.Int(_rsp_timestamp.msec);
    }
  }
  writer.EndObject();

  if (_node_functionality == SCSCF)
  {
    // Add the Application-Server-Information AVPs.
    TRC_DEBUG("Adding %d Application-Server-Information AVP groups", _as_information.size());

    if (_as_information.size() > 0)
    {
      writer.String("Application-Server-Information");
      writer.StartArray();

      for (std::list<ASInformation>::const_iterator i = _as_information.begin();
           i != _as_information.end();
           ++i)
      {
        writer.StartObject();
        {
          writer.String("Application-Server");
          writer.String(i->uri.c_str());

          if (!i->redirect_uri.empty())
          {
            writer.String("Application-Provided-Called-Party-Address");
            writer.StartArray();
            writer.String(i->redirect_uri.c_str());
            writer.EndArray();
          }

          if (i->status_code != STATUS_CODE_NONE)
          {
            writer.String("Status-Code");
            writer.Int(i->status_code);
          }
        }
        writer.EndObject();
      }

      writer.EndArray();
    }
  }

  // Add a single Inter-Operator-Identifier AVP group.  (According to 7.2.77 of
  // TS 32.299 there could be multiple of these, but only one
  // IMS-Charging-Identifier - but since they both come from the same SIP
  // header this seems inconsistent, so we only add a single IOI AVP group.
  if ((!_orig_ioi.empty()) || (!_term_ioi.empty()))
  {
    TRC_DEBUG("Adding Inter-Operator-Identifier AVP group");
    writer.String("Inter-Operator-Identifier");
    writer.StartArray();
    writer.StartObject();
    {
      if (!_orig_ioi.empty())
      {
        writer.String("Originating-IOI");
        writer.String(_orig_ioi.c_str());
      }

      if (!_term_ioi.empty())
      {
        writer.String("Terminating-IOI");
        writer.String(_term_ioi.c_str());
      }
    }
    writer.EndObject();
    writer.EndArray();
  }

  // Add Transit-IOI-List AVPs.
  TRC_DEBUG("Adding %d Transit-IOI-List AVPs", _transit_iois.size());

  if (_transit_iois.size() > 0)
  {
    writer.String("Transit-IOI-List");
    writer.StartArray();

    for (std::list<std::string>::const_iterator i = _transit_iois.begin();
         i != _transit_iois.end();
         ++i)
    {
      writer.String((*i).c_str());
    }

    writer.EndArray();
  }

  writer.String("IMS-Charging-Identifier");
  writer.String(_icid.c_str());

  // Add the Server-Capabilities AVP if I-CSCF.
  if (_node_functionality == ICSCF)
  {
    TRC_DEBUG("Adding Server-Capabilities AVP group");
    writer.String("Server-Capabilities");
    writer.StartObject();
    {
      writer.String("Mandatory-Capability");
      writer.StartArray();

      for (std::vector<int>::const_iterator i = _server_caps.mandatory_caps.begin();
           i != _server_caps.mandatory_caps.end();
           ++i)
      {
        writer.Int(*i);
      }

      writer.EndArray();
      writer.String("Optional-Capability");
      writer.StartArray();

      for (std::vector<int>::const_iterator i = _server_caps.optional_caps.begin();
           i != _server_caps.optional_caps.end();
           ++i)
      {
        writer.Int(*i);
      }

      writer.EndArray();

      if (!_server_caps.scscf.empty())
      {
        // Note that the Server-Name in Server-Capabilities is an array AVP
        // according to 6.3.4/TS 29.229.
        writer.String("Server-Name");
        writer.StartArray();
        writer.String(_server_caps.scscf.c_str());
        writer.EndArray();
      }
    }
    writer.EndObject();
  }

  // Add media and message body related AVPs on P-CSCF/S-CSCF/IBCF ACRs.  Note
  // that according to TS 32.260, a BGCF should include early media AVPs if
  // it has the information, but since a BGCF does not have to record route
  // itself, it may not have the information.  We therefore choose not to
  // include early media on BGCF ACRs.
  if ((_node_functionality == SCSCF) ||
      (_node_functionality == PCSCF) ||
      (_node_functionality == IBCF))
  {
    // Add Early-Media-Description AVPs to Start and Event ACRs.
    if ((_record_type == START_RECORD) ||
        (_record_type == EVENT_RECORD))
    {
      TRC_DEBUG("Adding %d Early-Media-Description AVPs", _early_media.size());

      // LCOV_EXCL_START - missing code to populate _early_media, raised in
      // clearwater-issues
      if (_early_media.size() > 0)
      {
        writer.String("Early-Media-Description");
        writer.StartArray();

        for (std::list<EarlyMediaDescription>::const_iterator i = _early_media.begin();
             i != _early_media.end();
             ++i)
        {
          writer.Int(i->offer_timestamp.sec);
          writer.Int(i->answer_timestamp.sec);
          encode_sdp_description(&writer, i->media);
        }

        writer.EndArray();
      }
      // LCOV_EXCL_STOP
    }

    if ((_record_type == START_RECORD) ||
        (_record_type == INTERIM_RECORD))
    {
      // Add SDP related AVPs to Start and Interim ACRs.
      TRC_DEBUG("Adding Media AVPs");
      encode_sdp_description(&writer, _media);
    }

    // Add Message-Body AVPs.
    TRC_DEBUG("Adding %d Message-Body AVPs", _msg_bodies.size());

    if (_msg_bodies.size() > 0)
    {
      writer.String("Message-Body");
      writer.StartArray();

      for (std::list<MessageBody>::const_iterator i = _msg_bodies.begin();
           i != _msg_bodies.end();
           ++i)
      {
        writer.StartObject();
        {
          writer.String("Content-Type");
          writer.String(i->type.c_str());
          writer.String("Content-Length");
          writer.Int(i->length);

          if (!i->disposition.empty())
          {
            writer.String("Content-Disposition");
            writer.String(i->disposition.c_str());
          }

          writer.String("Originator");
          writer.Int(i->originator);
        }
        writer.EndObject();
      }

      writer.EndArray();
    }
  }

  // Add Cause-Code AVP if STOP or EVENT message.
  if (_record_type == STOP_RECORD)
  {
    // Cause code is always zero for STOP requests.
    TRC_DEBUG("Adding Cause-Code(0) AVP to ACR[Stop]");
    writer.String("Cause-Code");
    writer.Int(0);
  }
  else if ((_record_type == EVENT_RECORD) &&
           (_status_code != 0))
  {
    // Calculate the cause code to include on the request (see 7.2.35/TS 32.299
    // for all the gory details).
    int cause_code = 0;
    if (_status_code == PJSIP_SC_OK)
    {
      if ((_method == "REGISTER")  &&
          (_num_contacts == 0))
      {
        // REGISTERs without contacts don't affect the registration state of
        // the subscriber, so use a cause code of 0
        cause_code = 0;
      }
      else if ((_method == "SUBSCRIBE") &&
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
    TRC_DEBUG("Adding Cause-Code(%d) AVP to ACR[Interim]", cause_code);
    writer.String("Cause-Code");
    writer.Int(cause_code);
  }

  // Add Reason-Header AVPs.
  TRC_DEBUG("Adding %d Reason-Header AVPs", _reasons.size());

  if (_reasons.size() > 0)
  {
    writer.String("Reason-Header");
    writer.StartArray();

    for (std::list<std::string>::const_iterator i = _reasons.begin();
         i != _reasons.end();
         ++i)
    {
      writer.String((*i).c_str());
    }

    writer.EndArray();
  }

  // Add Access-Network-Information AVPs
  TRC_DEBUG("Adding %d Access-Network-Information AVPs", _access_network_info.size());

  if (_access_network_info.size() > 0)
  {
    writer.String("Access-Network-Information");
    writer.StartArray();

    for (std::list<std::string>::const_iterator i = _access_network_info.begin();
         i != _access_network_info.end();
         ++i)
    {
      writer.String((*i).c_str());
    }

    writer.EndArray();
  }

  // Add From-Address AVP.
  TRC_DEBUG("Adding From-Address AVP");
  writer.String("From-Address");
  writer.String(_from_address.c_str());

  // Add IMS-Visited-Network-Identifier AVP if set.
  if (!_visited_network_id.empty())
  {
    TRC_DEBUG("Adding IMS-Visited-Network-Identifier AVP");
    writer.String("IMS-Visited-Network-Identifier");
    writer.String(_visited_network_id.c_str());
  }

  // Add Route-Header-Received and Route-Header-Transmitted AVPs if set.
  if (!_route_hdr_received.empty())
  {
    TRC_DEBUG("Adding Route-Header-Received AVP");
    writer.String("Route-Header-Received");
    writer.String(_route_hdr_received.c_str());
  }

  if (!_route_hdr_transmitted.empty())
  {
    TRC_DEBUG("Adding Route-Header-Transmitted AVP");
    writer.String("Route-Header-Transmitted");
    writer.String(_route_hdr_transmitted.c_str());
  }

  // Add the Instance-Id AVP if set.
  if (!_instance_id.empty())
  {
    TRC_DEBUG("Adding Instance-Id AVP");
    writer.String("Instance-Id");
    writer.String(_instance_id.c_str());
  }

  writer.EndObject(); // End ims information object
  writer.EndObject(); // End service indication object
  writer.EndObject(); // End event object
  writer.EndObject(); // End whole object

  // Render the message to a string and return it.
  return sb.GetString();
}

void RalfACR::set_default_ccf(const std::string& default_ccf)
{
  // If we don't yet have a CCF, set this.  It will get overwritten if we
  // subsequently find another CCF.
  if (_ccfs.empty())
  {
    _ccfs.push_back(default_ccf);
  }
}

void RalfACR::override_session_id(const std::string& session_id)
{
  _user_session_id = session_id;
}

void RalfACR::lock()
{
  pthread_mutex_lock(&_acr_lock);
}

void RalfACR::unlock()
{
  pthread_mutex_unlock(&_acr_lock);
}

void RalfACR::encode_sdp_description(
                             rapidjson::Writer<rapidjson::StringBuffer>* writer,
                             const MediaDescription& media)
{
  // Split the offer and answer in to lines.
  std::vector<std::string> offer;
  split_sdp(media.offer.sdp, offer);
  std::vector<std::string> answer;
  split_sdp(media.answer.sdp, answer);

  // First add the SDP-Session-Description AVPs.  We take these from the
  // answer if there is one, and from the offer otherwise (rather than
  // repeating them).
  TRC_DEBUG("Adding SDP-Session-Description AVPs");
  std::vector<std::string>& session_sdp = (answer.empty()) ? offer : answer;

  if (session_sdp.size() > 0)
  {
    writer->String("SDP-Session-Description");
    writer->StartArray();

    for (size_t ii = 0; ii < session_sdp.size(); ++ii)
    {
      if (session_sdp[ii][0] == 'm')
      {
        break;
      }
      writer->String(session_sdp[ii].c_str());
    }

    writer->EndArray();
  }

  // Now parse and encode the offer and answer media components.
  if ((offer.size() > 0) || (answer.size() > 0))
  {
    writer->String("SDP-Media-Component");
    writer->StartArray();

    TRC_DEBUG("Adding media AVPs for offer");
    encode_media_components(writer,
                            offer,
                            SDP_OFFER,
                            media.offer.initiator_flag,
                            media.offer.initiator_party);

    TRC_DEBUG("Adding media AVPs for answer");
    encode_media_components(writer,
                            answer,
                            SDP_ANSWER,
                            media.answer.initiator_flag,
                            media.answer.initiator_party);
    writer->EndArray();
  }
}

void RalfACR::encode_media_components(
                             rapidjson::Writer<rapidjson::StringBuffer>* writer,
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
      writer->StartObject();

      // Add the SDP-Media-Name AVP.
      writer->String("SDP-Media-Name");
      writer->String(sdp[ii].c_str());

      // Add SDP-Media-Description AVPs.
      writer->String("SDP-Media-Description");
      writer->StartArray();

      for (ii = ii + 1; (ii < sdp.size()) && (sdp[ii][0] != 'm'); ++ii)
      {
        writer->String(sdp[ii].c_str());
      }

      writer->EndArray();

      // Add the Local-GW-Inserted-Indication AVP (alway 0 - Local GW not
      // inserted).
      writer->String("Local-GW-Inserted-Indication");
      writer->Int(0);

      // Add the IP-Realm-Default-Indication AVP (always 1 - Default IP
      // realm used).
      writer->String("IP-Realm-Default-Indication");
      writer->Int(1);

      // Add the Transcoder-Inserted-Indication AVP (always 0 - Transcode not
      // inserted).
      writer->String("Transcoder-Inserted-Indication");
      writer->Int(0);

      // Add the Media-Initiator-Flag AVP.
      writer->String("Media-Initiator-Flag");
      writer->Int(initiator_flag);

      // Add the Media-Initiator-Party AVP.
      writer->String("Media-Initiator-Party");
      writer->String(initiator_party.c_str());

      // Add the SDP-Type AVP.
      writer->String("SDP-Type");
      writer->Int(sdp_type);
      writer->EndObject();
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
      TRC_DEBUG("Found a P-Charging-Function-Address header");
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
      TRC_DEBUG("%d ccfs and %d ecfs", _ccfs.size(), _ecfs.size());
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
  TRC_DEBUG("Stored %d subscription identifiers", _subscription_ids.size());
}

RalfACR::SubscriptionId RalfACR::uri_to_subscription_id(pjsip_uri* uri)
{
  SubscriptionId id;
  if (PJSIP_URI_SCHEME_IS_SIP(uri))
  {
    // SIP URI
    id.type = END_USER_SIP_URI;
    id.id = PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, uri);
    TRC_DEBUG("Found SIP URI subscription identifier %s", id.id.c_str());
  }
  else
  {
    // TEL URI
    id.type = END_USER_E164;
    id.id = PJUtils::pj_str_to_string(&((pjsip_tel_uri*)uri)->number);
    TRC_DEBUG("Found E.164 subscription identifier %s", id.id.c_str());
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
  TRC_DEBUG("Store associated URIs");
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
    TRC_DEBUG("Found P-Charging-Vector header, store information");
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
      std::string instance = PJUtils::pj_str_to_string(&p->value);

      // Check that the value is a valid length before we dequote
      if (instance.size() >= 2)
      {
        // Found the instance identifier, so convert to a string and dequote.
        _instance_id = instance.substr(1, instance.size() - 2);
        break;
      }
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
RalfACRFactory::RalfACRFactory(RalfProcessor* ralf,
                               ACR::Node node_functionality) :
  _ralf(ralf),
  _node_functionality(node_functionality)
{
  TRC_DEBUG("Created RalfACR factory for node type %s",
            ACR::node_name(_node_functionality).c_str());
}

/// RalfACRFactory Destructor.
RalfACRFactory::~RalfACRFactory()
{
}

/// Get an RalfACR instance from the factory.
ACR* RalfACRFactory::get_acr(SAS::TrailId trail,
                             ACR::Initiator initiator,
                             ACR::NodeRole role)
{
  TRC_DEBUG("Create RalfACR for node type %s with role %s",
            ACR::node_name(_node_functionality).c_str(),
            ACR::node_role_str(role).c_str());

  return (ACR*)new RalfACR(_ralf, trail, _node_functionality, initiator, role);
}

