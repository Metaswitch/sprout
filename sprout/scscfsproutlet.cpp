/**
 * @file scscfsproutlet.cpp S-CSCF Sproutlet classes, implementing S-CSCF
 *                          specific SIP proxy functions.
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

#include "log.h"
#include "sproutsasevent.h"
#include "constants.h"
#include "custom_headers.h"
#include "stack.h"
#include "contact_filtering.h"
#include "scscfsproutlet.h"

/// SCSCFSproutlet constructor.
SCSCFSproutlet::SCSCFSproutlet(const std::string& scscf_uri,
                               const std::string& icscf_uri,
                               const std::string& bgcf_uri,
                               int port,
                               RegStore* store,
                               RegStore* remote_store,
                               HSSConnection* hss,
                               EnumService* enum_service,
                               ACRFactory* acr_factory,
                               bool user_phone,
                               bool global_only_lookups) :
  Sproutlet("scscf", port),
  _scscf_uri(NULL),
  _icscf_uri(NULL),
  _bgcf_uri(NULL),
  _store(store),
  _remote_store(remote_store),
  _hss(hss),
  _enum_service(enum_service),
  _acr_factory(acr_factory),
  _global_only_lookups(global_only_lookups),
  _user_phone(user_phone)
{
  LOG_DEBUG("Creating S-CSCF Sproutlet");
  LOG_DEBUG("  S-CSCF URI = %s", scscf_uri.c_str());
  LOG_DEBUG("  I-CSCF URI = %s", icscf_uri.c_str());
  LOG_DEBUG("  BGCF   URI = %s", bgcf_uri.c_str());

  // Convert the routing URIs to a form suitable for PJSIP, so we're
  // not continually converting from strings.
  _scscf_uri = PJUtils::uri_from_string(scscf_uri, stack_data.pool, false);
  if (_scscf_uri == NULL)
  {
    LOG_ERROR("Invalid S-CSCF URI %s", scscf_uri.c_str());
  }
  _bgcf_uri = PJUtils::uri_from_string(bgcf_uri, stack_data.pool, false);
  if (_bgcf_uri == NULL)
  {
    LOG_ERROR("Invalid BGCF URI %s", bgcf_uri.c_str());
  }
  if (icscf_uri != "")
  {
    _icscf_uri = PJUtils::uri_from_string(icscf_uri, stack_data.pool, false);
    if (_icscf_uri == NULL)
    {
      LOG_ERROR("Invalid I-CSCF URI %s", icscf_uri.c_str());
    }
  }

  // Create an AS Chain table for maintaining the mapping from ODI tokens to
  // AS chains (and links in those chains).
  _as_chain_table = new AsChainTable;
}


/// SCSCFSproutlet destructor.
SCSCFSproutlet::~SCSCFSproutlet()
{
  delete _as_chain_table;
}


/// Creates a SCSCFSproutletTsx instance for performing S-CSCF service processing
/// on a request.
SproutletTsx* SCSCFSproutlet::get_tsx(SproutletTsxHelper* helper,
                                      const std::string& alias,
                                      pjsip_msg* req)
{
  return (SproutletTsx*)new SCSCFSproutletTsx(helper, this);
}


/// Returns the configured S-CSCF URI for this system.
const pjsip_uri* SCSCFSproutlet::scscf_uri() const
{
  return _scscf_uri;
}


/// Returns the configured I-CSCF URI for this system.
const pjsip_uri* SCSCFSproutlet::icscf_uri() const
{
  return _icscf_uri;
}


/// Returns the configured BGCF URI for this system.
const pjsip_uri* SCSCFSproutlet::bgcf_uri() const
{
  return _bgcf_uri;
}


/// Returns the AS chain table object used to manage AS chains and the
/// associated ODI tokens.
AsChainTable* SCSCFSproutlet::as_chain_table() const
{
  return _as_chain_table;
}


/// Gets all bindings for the specified Address of Record from the local or
/// remote registration stores.
void SCSCFSproutlet::get_bindings(const std::string& aor,
                                  RegStore::AoR** aor_data,
                                  SAS::TrailId trail)
{
  // Look up the target in the registration data store.
  LOG_INFO("Look up targets in registration store: %s", aor.c_str());
  *aor_data = _store->get_aor_data(aor, trail);

  // If we didn't get bindings from the local store and we have a remote
  // store, try the remote.
  if ((_remote_store != NULL) &&
      ((*aor_data == NULL) ||
       ((*aor_data)->bindings().empty())))
  {
    delete *aor_data;
    *aor_data = _remote_store->get_aor_data(aor, trail);
  }

  // TODO - Log bindings to SAS
}


/// Read data for a public user identity from the HSS.
bool SCSCFSproutlet::read_hss_data(const std::string& public_id,
                                   bool& registered,
                                   std::vector<std::string>& uris,
                                   Ifcs& ifcs,
                                   std::deque<std::string>& ccfs,
                                   std::deque<std::string>& ecfs,
                                   SAS::TrailId trail)
{
  std::string regstate;
  std::map<std::string, Ifcs> ifc_map;

  long http_code = _hss->update_registration_state(public_id,
                                                   "",
                                                   HSSConnection::CALL,
                                                   regstate,
                                                   ifc_map,
                                                   uris,
                                                   ccfs,
                                                   ecfs,
                                                   trail);
  ifcs = ifc_map[public_id];
  registered = (regstate == HSSConnection::STATE_REGISTERED);

  return (http_code == 200);
}


/// Attempt ENUM lookup if appropriate.
std::string SCSCFSproutlet::translate_request_uri(pjsip_msg* req,
                                                  SAS::TrailId trail)
{
  std::string user;
  std::string new_uri;
  pjsip_uri* uri = req->line.req.uri;

  if (_enum_service != NULL)
  {
    // ENUM is enabled.
    LOG_DEBUG("ENUM is enabled");

    // Determine whether we have a SIP URI or a tel URI
    if (PJSIP_URI_SCHEME_IS_SIP(uri))
    {
      user = PJUtils::pj_str_to_string(&((pjsip_sip_uri*)uri)->user);
      LOG_DEBUG("SIP URI - user = %s", user.c_str());
    }
    else if (PJSIP_URI_SCHEME_IS_TEL(uri))
    {
      user = PJUtils::public_id_from_uri(uri);
      LOG_DEBUG("TEL URI - user = %s", user.c_str());
    }

    // Check whether we have a global number or whether we allow
    // ENUM lookups for local numbers
    if ((PJUtils::is_user_global(user)) || (!_global_only_lookups))
    {
      // Perform an ENUM lookup if we have a tel URI, or if we have
      // a SIP URI which is being treated as a phone number.

      // If we aren't configured to require 'user=phone', we treat any
      // numeric SIP URIs as phone numbers - unless it's a GRUU, which
      // can never be generated by the user dialling a string of digits.
      LOG_DEBUG("Global number or look-ups allowed for non-global numbers");
      if ((PJUtils::is_uri_phone_number(uri)) ||
          ((!_user_phone) && (is_user_numeric(user)) && (!PJUtils::is_uri_gruu(uri))))
      {
        LOG_DEBUG("Performing ENUM lookup for user %s", user.c_str());
        new_uri = _enum_service->lookup_uri_from_user(user, trail);
      }
    }
  }
  else
  {
    // If we have no ENUM server configured, we act as if all ENUM lookups
    // return a successful response and perform the following mappings:
    //  - tel:<number> to sip:<number>@<homedomain>
    //  - sip:<number>@<homedomain> to itself
    //
    // We do this in order to avoid needing to setup an ENUM server on test
    // systems just to allow local calls to work.
    LOG_DEBUG("No ENUM server configured, perform default translation");

    if (PJSIP_URI_SCHEME_IS_TEL(uri))
    {
      new_uri = "sip:";
      pj_str_t number = PJUtils::user_from_uri(uri);
      new_uri += PJUtils::pj_str_to_string(&number);
      new_uri += "@";
      new_uri += PJUtils::pj_str_to_string(&stack_data.default_home_domain);
      LOG_DEBUG("Translate tel URI to SIP URI %s", new_uri.c_str());
    }
    else
    {
      new_uri = PJUtils::public_id_from_uri(uri);
      LOG_DEBUG("Translate SIP URI %s to itself", new_uri.c_str());
    }
  }

  return new_uri;
}


/// Get an ACR instance from the factory.
/// @param trail                SAS trail identifier to use for the ACR.
/// @param initiator            The initiator of the SIP transaction (calling
///                             or called party).
ACR* SCSCFSproutlet::get_acr(SAS::TrailId trail, Initiator initiator, NodeRole role)
{
  return _acr_factory->get_acr(trail, initiator, role);
}


/// Determines whether a user string is purely numeric (maybe with a leading +).
// @returns true/false
bool SCSCFSproutlet::is_user_numeric(const std::string& user)
{
  for (size_t i = 0; i < user.size(); i++)
  {
    if ((!isdigit(user[i])) &&
        ((user[i] != '+') || (i != 0)))
    {
      return false;
    }
  }
  return true;
}


SCSCFSproutletTsx::SCSCFSproutletTsx(SproutletTsxHelper* helper,
                                     SCSCFSproutlet* scscf) :
  SproutletTsx(helper),
  _scscf(scscf),
  _cancelled(false),
  _session_case(NULL),
  _as_chain_link(),
  _hss_data_cached(false),
  _registered(false),
  _uris(),
  _ifcs(),
  _acr(NULL),
  _target_aor(),
  _target_bindings(),
  _liveness_timer(0),
  _record_routed(false)
{
  LOG_DEBUG("S-CSCF Transaction (%p) created", this);
}


SCSCFSproutletTsx::~SCSCFSproutletTsx()
{
  LOG_DEBUG("S-CSCF Transaction (%p) destroyed", this);
  if ((_acr != NULL) &&
      (!_as_chain_link.is_set()))
  {
    _acr->send_message();
    delete _acr;
  }

  if (_as_chain_link.is_set())
  {
    _as_chain_link.release();
  }

  if (_liveness_timer != 0)
  {
    cancel_timer(_liveness_timer);
  }

  _target_bindings.clear();
}


void SCSCFSproutletTsx::on_rx_initial_request(pjsip_msg* req)
{
  LOG_INFO("S-CSCF received initial request");

  pjsip_status_code status_code = PJSIP_SC_OK;

  // Add a Session-Expires header if required.
  add_session_expires(req);

  // Determine the session case and the served user.  This will link to
  // an AsChain object (creating it if necessary), if we need to provide
  // services.
  status_code = determine_served_user(req);

  if (_acr == NULL)
  {
    // No ACR found or created while determining the served user, so create
    // a new one.
    _acr = _scscf->get_acr(trail(),
                           CALLING_PARTY,
                           ACR::requested_node_role(req));
  }

  // Pass the received request to the ACR.
  // @TODO - request timestamp???
  _acr->rx_request(req);

  if (status_code != PJSIP_SC_OK)
  {
    // Failed to determine the served user for a request we should provide
    // services on, so reject the request.
    LOG_INFO("Failed to determine served user for request, reject with %d status code",
             status_code);
    pjsip_msg* rsp = create_response(req, status_code);
    send_response(rsp);
    free_msg(req);
  }
  else if (_as_chain_link.is_set())
  {
    // AS chain is set up, so must apply services to the request.
    LOG_INFO("Found served user, so apply services");

    // First add a P-Charging-Function-Addresses header if one is
    // not already present for some reason. We only do this if we have
    // the charging addresses cached (which we should do). We do this
    // for originating and terminating services.
    PJUtils::add_pcfa_header(req, get_pool(req), _ccfs, _ecfs, false);

    if (_session_case->is_originating())
    {
      apply_originating_services(req);
    }
    else
    {
      apply_terminating_services(req);
    }
  }
  else
  {
    // No AS chain set, so don't apply services to the request.
    // Default action is to route the request directly to the BGCF.
    LOG_INFO("Route request to BGCF without applying services");
    route_to_bgcf(req);
  }
}


void SCSCFSproutletTsx::on_rx_in_dialog_request(pjsip_msg* req)
{
  LOG_INFO("S-CSCF received in-dialog request");

  // Add a Session-Expires header if required.
  add_session_expires(req);

  // Create an ACR for this request and pass the request to it.
  _acr = _scscf->get_acr(trail(),
                         CALLING_PARTY,
                         ACR::requested_node_role(req));

  // @TODO - request timestamp???
  _acr->rx_request(req);

  send_request(req);
}


void SCSCFSproutletTsx::on_tx_request(pjsip_msg* req)
{
  if (_acr != NULL)
  {
    // Pass the transmitted request to the ACR to update the accounting
    // information.
    _acr->tx_request(req);
  }
}


void SCSCFSproutletTsx::on_rx_response(pjsip_msg* rsp, int fork_id)
{
  LOG_INFO("S-CSCF received response");

  // Pass the received response to the ACR.
  // @TODO - timestamp from response???
  if (_acr != NULL)
  {
    _acr->rx_response(rsp);
  }

  if (_liveness_timer != 0)
  {
    // The liveness timer is running on this request, so cancel it.
    cancel_timer(_liveness_timer);
    _liveness_timer = 0;
  }

  int st_code = rsp->line.status.code;

  if (st_code == SIP_STATUS_FLOW_FAILED)
  {
    // The edge proxy / P-CSCF has reported that this flow has failed.
    // We should remove the binding from the registration store so we don't
    // try it again.
    // @TODO - this code has been removed from stateful_proxy, not sure why???
  }
  else if ((st_code >= PJSIP_SC_OK) && (_hss_data_cached))
  {
    // Final response. Add a P-Charging-Function-Addresses header if one is
    // not already present for some reason. We only do this if we have
    // the charging addresses cached (which we should do).
    PJUtils::add_pcfa_header(rsp, get_pool(rsp), _ccfs, _ecfs, false);
  }

  if (_as_chain_link.is_set())
  {
    // Pass the response code to the controlling AsChain for accounting.
    _as_chain_link.on_response(st_code);

    if (!_as_chain_link.complete())
    {
      // The AS chain isn't complete, so the response must be from an
      // application server.  Check to see if we need to trigger default
      // handling.
      if ((!_cancelled) &&
          ((st_code == PJSIP_SC_REQUEST_TIMEOUT) ||
           (PJSIP_IS_STATUS_IN_CLASS(st_code, 500))) &&
          (_as_chain_link.continue_session()))
      {
        // The AS either timed out or returned a 5xx error, and default
        // handling is set to continue.
        LOG_DEBUG("Trigger default_handling=CONTINUE processing");
        _as_chain_link = _as_chain_link.next();
        pjsip_msg* req = original_request();
        if (_session_case->is_originating())
        {
          apply_originating_services(req);
        }
        else
        {
          apply_terminating_services(req);
        }

        // Free off the response as we no longer need it.
        free_msg(rsp);
      }
    }
  }

  if (rsp != NULL)
  {
    // Forward the response upstream.  The proxy layer will aggregate responses
    // if required.
    send_response(rsp);
  }
}


void SCSCFSproutletTsx::on_tx_response(pjsip_msg* rsp)
{
  if (_acr != NULL)
  {
    // Pass the transmitted response to the ACR to update the accounting
    // information.
    _acr->tx_response(rsp);
  }
}


void SCSCFSproutletTsx::on_rx_cancel(int status_code, pjsip_msg* cancel_req)
{
  LOG_INFO("S-CSCF received CANCEL");

  _cancelled = true;

  if ((status_code == PJSIP_SC_REQUEST_TERMINATED) &&
      (cancel_req != NULL))
  {
    // Create and send an ACR for the CANCEL request.
    ACR* acr = _scscf->get_acr(trail(),
                               CALLING_PARTY,
                               ACR::requested_node_role(cancel_req));

    // @TODO - timestamp from request.
    acr->rx_request(cancel_req);
    acr->send_message();

    delete acr;
  }
}


pjsip_status_code SCSCFSproutletTsx::determine_served_user(pjsip_msg* req)
{
  pjsip_status_code status_code = PJSIP_SC_OK;

  // Get the top route header.
  const pjsip_route_hdr* hroute = route_hdr();

  if ((hroute != NULL) &&
      ((PJUtils::is_home_domain(hroute->name_addr.uri)) ||
       (PJUtils::is_uri_local(hroute->name_addr.uri))))
  {
    // This is our own Route header, containing a SIP URI.  Check for an
    // ODI token.  We need to determine the session case: is
    // this an originating request or not - see 3GPP TS 24.229
    // s5.4.3.1, s5.4.1.2.2F and the behaviour of
    // proxy_calculate_targets as an access proxy.
    LOG_DEBUG("Route header references this system");
    pjsip_sip_uri* uri = (pjsip_sip_uri*)hroute->name_addr.uri;
    pjsip_param* orig_param = pjsip_param_find(&uri->other_param, &STR_ORIG);

    _session_case = (orig_param != NULL) ? &SessionCase::Originating :
                                           &SessionCase::Terminating;

    if (pj_strncmp(&uri->user, &STR_ODI_PREFIX, STR_ODI_PREFIX.slen) == 0)
    {
      // This is one of our original dialog identifier (ODI) tokens.
      // See 3GPP TS 24.229 s5.4.3.4.
      std::string odi_token = std::string(uri->user.ptr + STR_ODI_PREFIX.slen,
                                          uri->user.slen - STR_ODI_PREFIX.slen);
      LOG_DEBUG("Found ODI token %s", odi_token.c_str());
      _as_chain_link = _scscf->as_chain_table()->lookup(odi_token);

      if (_as_chain_link.is_set())
      {
        LOG_INFO("Original dialog for %.*s found: %s",
                 uri->user.slen, uri->user.ptr,
                 _as_chain_link.to_string().c_str());
        _session_case = &_as_chain_link.session_case();
      }
      else
      {
        // The ODI token is invalid or expired.  Treat call as OOTB.
        LOG_INFO("Expired ODI token %s so handle as OOTB request", odi_token.c_str());
        SAS::Event event(trail(), SASEvent::SCSCF_ODI_INVALID, 0);
        event.add_var_param(PJUtils::pj_str_to_string(&uri->user));
        SAS::report_event(event);
      }
    }

    LOG_DEBUG("Got our Route header, session case %s, OD=%s",
              _session_case->to_string().c_str(),
              _as_chain_link.to_string().c_str());
  }
  else if (hroute == NULL)
  {
    // No Route header on the request.  This probably shouldn't happen, but
    // if it does we will treat it as a terminating request.
    LOG_DEBUG("No Route header, so treat as terminating request");
    _session_case = &SessionCase::Terminating;
  }

  if (_as_chain_link.is_set())
  {
    std::string served_user = served_user_from_msg(req);

    if ((_session_case->is_terminating()) &&
        (served_user != _as_chain_link.served_user()))
    {
      // AS is retargeting per 3GPP TS 24.229 s5.4.3.3 step 3, so
      // create new AS chain with session case orig-cdiv and the
      // terminating user as served user.
      LOG_INFO("Request-URI has changed, retargeting");
      _session_case = &SessionCase::OriginatingCdiv;
      served_user = _as_chain_link.served_user();

      // We might not be the terminating server any more, so we
      // should blank out the term_ioi parameter. If we are still
      // the terminating server, we'll fill it back in when we go
      // through handle_terminating.

      // Note that there's no need to change orig_ioi - we don't
      // actually become the originating server when we do this redirect.
      pjsip_p_c_v_hdr* pcv = (pjsip_p_c_v_hdr*)
                             pjsip_msg_find_hdr_by_name(req, &STR_P_C_V, NULL);
      if (pcv)
      {
        LOG_DEBUG("Blanking out term_ioi parameter due to redirect");
        pcv->term_ioi = pj_str("");
      }


      Ifcs ifcs;
      if (lookup_ifcs(served_user, ifcs))
      {
        LOG_DEBUG("Creating originating CDIV AS chain");
        _as_chain_link.release();
        _as_chain_link = create_as_chain(ifcs, served_user);

        if (stack_data.record_route_on_diversion)
        {
          LOG_DEBUG("Add service to dialog - originating Cdiv");
          add_record_route(req, "charge-orig");
        }
      }
      else
      {
        LOG_DEBUG("Failed to retrieve ServiceProfile for %s", served_user.c_str());
        status_code = PJSIP_SC_NOT_FOUND;
      }
    }
    else
    {
      // Continuing the existing chain, so get the ACR from the chain.
      _acr = _as_chain_link.acr();
      LOG_DEBUG("Retrieved ACR %p for existing AS chain", _acr);

      if (stack_data.record_route_on_every_hop)
      {
        LOG_DEBUG("Add service to dialog - AS hop");
        if (_session_case->is_terminating())
        {
          add_record_route(req, "charge-term");
        }
        else
        {
          add_record_route(req, "charge-orig");
        }
      }
    }
  }
  else if (_session_case != NULL)
  {
    // No existing AS chain - create new.
    std::string served_user = served_user_from_msg(req);

    if (!served_user.empty())
    {
      LOG_DEBUG("Looking up iFCs for %s for new AS chain", served_user.c_str());
      Ifcs ifcs;
      if (lookup_ifcs(served_user, ifcs))
      {
        LOG_DEBUG("Successfully looked up iFCs");
        _as_chain_link = create_as_chain(ifcs, served_user);
      }
      else
      {
        LOG_DEBUG("Failed to retrieve ServiceProfile for %s", served_user.c_str());
        status_code = PJSIP_SC_NOT_FOUND;
      }

      if (_session_case->is_terminating())
      {
        if (stack_data.record_route_on_initiation_of_terminating)
        {
          LOG_DEBUG("Single Record-Route - initiation of terminating handling");
          add_record_route(req, "charge-term");
        }
      }
      else if (_session_case->is_originating())
      {
        if (stack_data.record_route_on_initiation_of_originating)
        {
          LOG_DEBUG("Single Record-Route - initiation of originating handling");
          add_record_route(req, "charge-orig");
        }
      }
    }
  }

  return status_code;
}


std::string SCSCFSproutletTsx::served_user_from_msg(pjsip_msg* msg)
{
  // For originating:
  //
  // We determine the served user as described in 3GPP TS 24.229 s5.4.3.2,
  // step 1. This first relies on P-Served-User (RFC5502), if present
  // (step 1a). If not (step 1b), we then look at P-Asserted-Identity.
  // For compliance with non-IMS devices (and contrary to the IMS spec),
  // if there is no P-Asserted-Identity we then look at the From header
  // or the request URI as appropriate for the session case.  Per 24.229,
  // we ignore the session case and registration state parameters of
  // P-Served-User; these are intended for the AS, not the S-CSCF (which
  // has other means of determining these).

  // For terminating:
  //
  // We determine the served user as described in 3GPP TS 24.229
  // s5.4.3.3, step 1, i.e., purely on the Request-URI.

  // For originating after retargeting (orig-cdiv), we normally don't
  // call this method at all, because we can pick up the served user
  // from the existing AsChain. If this method is called, however, the
  // following logic applies:
  //
  // We could determine the served user as described in 3GPP TS
  // 24.229 s5.4.3.3 step 3b. This relies on History-Info (RFC4244)
  // and P-Served-User (RFC5502) in step 3b. We should never respect
  // P-Asserted-Identity.
  //
  // We implement P-Served-User, and fall back on the From
  // header. However, the History-Info mechanism has fundamental
  // problems as outlined in RFC5502 appendix A, and we do not
  // implement it.
  pjsip_uri* uri;
  std::string user;

  if (_session_case->is_originating())  // (includes orig-cdiv)
  {
    uri = PJUtils::orig_served_user(msg);
  }
  else
  {
    uri = PJUtils::term_served_user(msg);
  }

  if ((PJSIP_URI_SCHEME_IS_SIP(uri)) &&
     ((PJUtils::is_home_domain(uri)) ||
      (PJUtils::is_uri_local(uri))))
  {
    user = PJUtils::aor_from_uri((pjsip_sip_uri*)uri);
  }
  else if (PJSIP_URI_SCHEME_IS_TEL(uri))
  {
    user = PJUtils::public_id_from_uri(uri);
  }
  else
  {
    LOG_DEBUG("URI is not locally hosted");
  }

  return user;
}


/// Factory method: create AsChain by looking up iFCs.
AsChainLink SCSCFSproutletTsx::create_as_chain(Ifcs ifcs,
                                               std::string served_user)
{
  if (served_user.empty())
  {
    LOG_WARNING("create_as_chain called with an empty served_user");
  }
  bool is_registered = is_user_registered(served_user);

  // Create a new ACR to use for this service hop and the new AS chain.
  _acr = _scscf->get_acr(trail(),
                         CALLING_PARTY,
                         _session_case->is_originating() ?
                                NODE_ROLE_ORIGINATING : NODE_ROLE_TERMINATING);

  AsChainLink ret = AsChainLink::create_as_chain(_scscf->as_chain_table(),
                                                 *_session_case,
                                                 served_user,
                                                 is_registered,
                                                 trail(),
                                                 ifcs,
                                                 _acr);
  LOG_DEBUG("S-CSCF sproutlet transaction %p linked to AsChain %s",
            this, ret.to_string().c_str());
  return ret;
}


/// Apply originating services for this request.
void SCSCFSproutletTsx::apply_originating_services(pjsip_msg* req)
{
  LOG_DEBUG("Performing originating initiating request processing");

  // Add ourselves as orig-IOI.
  pjsip_p_c_v_hdr* pcv = (pjsip_p_c_v_hdr*)
                             pjsip_msg_find_hdr_by_name(req, &STR_P_C_V, NULL);
  if (pcv)
  {
    pcv->orig_ioi = PJUtils::domain_from_uri(_as_chain_link.served_user(),
                                             get_pool(req));
  }

  // Find the next application server to invoke.
  std::string server_name;
  _as_chain_link.on_initial_request(req, server_name);

  if (!server_name.empty())
  {
    // We've should have identified an application server to be invoked, so
    // encode the app server hop and the return hop in Route headers.
    route_to_as(req, server_name);
  }
  else
  {
    // No more application servers, so perform processing at the end of
    // originating call processing.
    LOG_INFO("Completed applying originating services");

    if (stack_data.record_route_on_completion_of_originating)
    {
      LOG_DEBUG("Add service to dialog - end of originating handling");
      add_record_route(req, "charge-orig");
    }

    // Attempt to translate the RequestURI using ENUM or an alternative
    // database.
    if (uri_translation(req) == PJSIP_SC_OK)
    {
      if ((PJSIP_URI_SCHEME_IS_TEL(req->line.req.uri)) ||
          (!PJUtils::is_home_domain(req->line.req.uri)))
      {
        // Destination is off-net, so route to the BGCF.
        route_to_bgcf(req);
      }
      else
      {
        // Destination is on-net so route to the I-CSCF.
        route_to_icscf(req);
      }
    }
  }
}


/// Apply terminating services for this request.
void SCSCFSproutletTsx::apply_terminating_services(pjsip_msg* req)
{
  // Include ourselves as the terminating operator for billing.
  pjsip_p_c_v_hdr* pcv = (pjsip_p_c_v_hdr*)
                             pjsip_msg_find_hdr_by_name(req, &STR_P_C_V, NULL);
  if (pcv)
  {
    pcv->term_ioi = PJUtils::domain_from_uri(_as_chain_link.served_user(),
                                             get_pool(req));
  }

  // Find the next application server to invoke.
  std::string server_name;
  _as_chain_link.on_initial_request(req, server_name);

  if (!server_name.empty())
  {
    // We've should have identified an application server to be invoked, so
    // encode the app server hop and the return hop in Route headers.
    route_to_as(req, server_name);
  }
  else
  {
    // No more application servers to invoke, so perform end of terminating
    // request processing.
    LOG_INFO("Completed applying originating services");

    if (stack_data.record_route_on_completion_of_terminating)
    {
      LOG_DEBUG("Add service to dialog - end of terminating handling");
      add_record_route(req, "charge-term");
    }

    // Route the call to the appropriate target.
    route_to_target(req);
  }
}


/// Route the request to an application server.
void SCSCFSproutletTsx::route_to_as(pjsip_msg* req,
                                    const std::string& server_name)
{
  std::string odi_value = PJUtils::pj_str_to_string(&STR_ODI_PREFIX) +
                          _as_chain_link.next_odi_token();
  LOG_INFO("Routing to Application Server %s with ODI token %s for %s",
           server_name.c_str(),
           odi_value.c_str(),
           _as_chain_link.to_string().c_str());


  // Set P-Served-User, including session case and registration
  // state, per RFC5502 and the extension in 3GPP TS 24.229
  // s7.2A.15, following the description in 3GPP TS 24.229 5.4.3.2
  // step 5 s5.4.3.3 step 4c.
  PJUtils::remove_hdr(req, &STR_P_SERVED_USER);
  pj_pool_t* pool = get_pool(req);
  pjsip_routing_hdr* psu_hdr = identity_hdr_create(pool, STR_P_SERVED_USER);
  psu_hdr->name_addr.uri =
                  PJUtils::uri_from_string(_as_chain_link.served_user(), pool);
  pjsip_param* p = PJ_POOL_ALLOC_T(pool, pjsip_param);
  pj_strdup2(pool, &p->name, "sescase");
  pj_strdup2(pool, &p->value, _session_case->to_string().c_str());
  pj_list_insert_before(&psu_hdr->other_param, p);
  if (_session_case != &SessionCase::OriginatingCdiv)
  {
    p = PJ_POOL_ALLOC_T(pool, pjsip_param);
    pj_strdup2(pool, &p->name, "regstate");
    if (_as_chain_link.is_registered())
    {
      pj_strdup2(pool, &p->value, "reg");
    }
    else
    {
      pj_strdup2(pool, &p->value, "unreg");
    }
    pj_list_insert_before(&psu_hdr->other_param, p);
  }
  pjsip_msg_add_hdr(req, (pjsip_hdr*)psu_hdr);

  // Add the application server URI as the next Route header.
  pjsip_sip_uri* as_uri = (pjsip_sip_uri*)
                          PJUtils::uri_from_string(server_name, get_pool(req));
  PJUtils::add_route_header(req, as_uri, get_pool(req));

  // Insert route header below it with an ODI in it.
  pjsip_sip_uri* odi_uri = (pjsip_sip_uri*)
                           pjsip_uri_clone(get_pool(req), _scscf->scscf_uri());
  pj_strdup2(get_pool(req), &odi_uri->user, odi_value.c_str());
  odi_uri->transport_param = as_uri->transport_param;  // Use same transport as AS, in case it can only cope with one.
  if (_session_case->is_originating())
  {
    pjsip_param *orig_param = PJ_POOL_ALLOC_T(get_pool(req), pjsip_param);
    pj_strdup(get_pool(req), &orig_param->name, &STR_ORIG);
    pj_strdup2(get_pool(req), &orig_param->value, "");
    pj_list_insert_after(&odi_uri->other_param, orig_param);
  }
  PJUtils::add_route_header(req, odi_uri, get_pool(req));

  // Forward the request.
  send_request(req);

  // Start the liveness timer for the AS.
  if (!schedule_timer(NULL, _liveness_timer, _as_chain_link.as_timeout() * 1000))
  {
    LOG_WARNING("Failed to start liveness timer");
  }
}


/// Route the request to the I-CSCF.
void SCSCFSproutletTsx::route_to_icscf(pjsip_msg* req)
{
  const pjsip_uri* icscf_uri = _scscf->icscf_uri();

  if (icscf_uri != NULL)
  {
    // I-CSCF is enabled, so route to it.
    LOG_INFO("Routing to I-CSCF %s",
             PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR, icscf_uri).c_str());
    PJUtils::add_route_header(req,
                              (pjsip_sip_uri*)pjsip_uri_clone(get_pool(req), icscf_uri),
                              get_pool(req));
  }
  else
  {
    // I-CSCF is disabled, so route directly to the local S-CSCF.
    const pjsip_uri* scscf_uri = _scscf->scscf_uri();
    LOG_INFO("Routing directly to S-CSCF %s",
             PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR, scscf_uri).c_str());
    PJUtils::add_route_header(req,
                              (pjsip_sip_uri*)pjsip_uri_clone(get_pool(req), scscf_uri),
                              get_pool(req));
  }
  send_request(req);
}


/// Route the request to the BGCF.
void SCSCFSproutletTsx::route_to_bgcf(pjsip_msg* req)
{
  LOG_INFO("Routing to BGCF %s",
           PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                  _scscf->bgcf_uri()).c_str());
  PJUtils::add_route_header(req,
                            (pjsip_sip_uri*)pjsip_uri_clone(get_pool(req),
                                                            _scscf->bgcf_uri()),
                            get_pool(req));
  send_request(req);
}


/// Route the request to the terminating side S-CSCF.
void SCSCFSproutletTsx::route_to_term_scscf(pjsip_msg* req)
{
  LOG_INFO("Routing to terminating S-CSCF %s",
           PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                  _scscf->scscf_uri()).c_str());
  PJUtils::add_route_header(req,
                            (pjsip_sip_uri*)pjsip_uri_clone(get_pool(req),
                                                            _scscf->scscf_uri()),
                            get_pool(req));
  send_request(req);
}


/// Route the request to the appropriate onward target.
void SCSCFSproutletTsx::route_to_target(pjsip_msg* req)
{
  pjsip_uri* req_uri = req->line.req.uri;

  if ((PJSIP_URI_SCHEME_IS_SIP(req_uri) &&
      ((pjsip_sip_uri*)req_uri)->maddr_param.slen))
  {
    // The Request-URI of the request contains an maddr parameter, so forward
    // the request to the Request-URI.
    LOG_INFO("Route request to maddr %.*s",
             ((pjsip_sip_uri*)req_uri)->maddr_param.slen,
             ((pjsip_sip_uri*)req_uri)->maddr_param.ptr);
    send_request(req);
  }
  else if ((!PJUtils::is_home_domain(req_uri)) &&
           (!PJUtils::is_uri_local(req_uri)))
  {
    // The Request-URI indicates an non-home domain, so forward the request
    // to the domain in the Request-URI unchanged.
    LOG_INFO("Route request to Request-URI %s",
             PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, req_uri).c_str());
    send_request(req);
  }
  else if (PJSIP_URI_SCHEME_IS_SIP(req_uri))
  {
    // The Request-URI contains a home domain, so route to any UE bindings
    // in the registration store.
    LOG_INFO("Route request to registered UE bindings");
    route_to_ue_bindings(req);
  }
  else
  {
    // The RequestURI contains a Tel URI???
    LOG_INFO("Rejecting request with Tel: URI");
    pjsip_msg* rsp = create_response(req, PJSIP_SC_NOT_FOUND);
    send_response(rsp);
    free_msg(req);
  }
}


/// Route the request to UE bindings retrieved from the registration store.
void SCSCFSproutletTsx::route_to_ue_bindings(pjsip_msg* req)
{
  // Get the public user identity corresponding to the RequestURI.
  pjsip_uri* req_uri = req->line.req.uri;
  std::string public_id = PJUtils::aor_from_uri((pjsip_sip_uri*)req_uri);

  // Add a P-Called-Party-ID header containing the public user identity,
  // replacing any existing header.
  pj_pool_t* pool = get_pool(req);
  PJUtils::remove_hdr(req, &STR_P_CALLED_PARTY_ID);
  std::string name_addr_str("<" + public_id + ">");
  pj_str_t called_party_id;
  pj_strdup2(pool, &called_party_id, name_addr_str.c_str());
  pjsip_hdr* hdr = (pjsip_hdr*)
                        pjsip_generic_string_hdr_create(pool,
                                                        &STR_P_CALLED_PARTY_ID,
                                                        &called_party_id);
  pjsip_msg_add_hdr(req, hdr);

  // Determine the canonical public ID, and look up the set of associated
  // URIs on the HSS.
  std::vector<std::string> uris;
  bool success = get_associated_uris(public_id, uris);

  std::string aor;
  if (success && (uris.size() > 0))
  {
    // Take the first associated URI as the AOR.
    aor = uris.front();
  }
  else
  {
    // Failed to get the associated URIs from Homestead.  We'll try to
    // do the registration look-up with the specified target URI - this may
    // fail, but we'll never misroute the call.
    LOG_WARNING("Invalid Homestead response - a user is registered but has no list of associated URIs");
    aor = public_id;
  }

  // Get the bindings from the store and filter/sort them for the request.
  RegStore::AoR* aor_data = NULL;
  _scscf->get_bindings(aor, &aor_data, trail());

  TargetList targets;
  filter_bindings_to_targets(aor,
                             aor_data,
                             req,
                             pool,
                             MAX_FORKING,
                             targets,
                             trail());

  if (targets.empty())
  {
    // No valid target bindings for this request, so reject it.
    pjsip_msg* rsp = create_response(req, PJSIP_SC_TEMPORARILY_UNAVAILABLE);
    send_response(rsp);
    free_msg(req);
  }
  else
  {
    // Fork the request to the bindings, and remember the AoR used to query
    // the registration store and the binding identifier for each fork.
    _target_aor = aor;
    for (size_t ii = 0; ii < targets.size(); ++ii)
    {
      // Clone for all but the last request.
      pjsip_msg* to_send = (ii == targets.size() - 1) ? req : clone_request(req);
      pool = get_pool(to_send);

      // Set up the Rquest URI.
      to_send->line.req.uri = (pjsip_uri*)
                                        pjsip_uri_clone(pool, targets[ii].uri);

      // Copy across the path URIs in to Route headers.
      for (std::list<pjsip_uri*>::const_iterator j = targets[ii].paths.begin();
           j != targets[ii].paths.end();
           ++j)
      {
        pjsip_sip_uri* path_uri = (pjsip_sip_uri*)pjsip_uri_get_uri(*j);
        PJUtils::add_route_header(to_send,
                                  (pjsip_sip_uri*)pjsip_uri_clone(pool,
                                                                  path_uri),
                                  pool);
      }

      // Forward the request and remember the binding identifier used for this
      // in case we get a Flow Failed response.
      int fork_id = send_request(to_send);
      _target_bindings.insert(std::make_pair(fork_id, targets[ii].binding_id));
    }
  }

  delete aor_data; aor_data = NULL;
}


/// Do URI translation if required.
pjsip_status_code SCSCFSproutletTsx::uri_translation(pjsip_msg* req)
{
  pjsip_status_code status_code = PJSIP_SC_OK;
  pjsip_uri* uri = req->line.req.uri;

  if ((PJUtils::is_home_domain(uri)) ||
      (PJSIP_URI_SCHEME_IS_TEL(uri)))
  {
    // Request is either to a URI in this domain, or a Tel URI, so attempt
    // to translate it.
    LOG_DEBUG("Translating URI");
    std::string new_uri_str = _scscf->translate_request_uri(req, trail());

    if (!new_uri_str.empty())
    {
      // The URI was successfully translated, so attempt to parse the returned
      // URI and substitute it in to the request.
      pjsip_uri* new_uri = (pjsip_uri*)PJUtils::uri_from_string(new_uri_str, get_pool(req));

      if (new_uri != NULL)
      {
        LOG_DEBUG("Update request URI to %s", new_uri_str.c_str());
        uri = new_uri;
      }
      else
      {
        LOG_WARNING("Badly formed URI %s from ENUM translation", new_uri_str.c_str());
        status_code = PJSIP_SC_NOT_FOUND;
        pjsip_msg* rsp = create_response(req, PJSIP_SC_NOT_FOUND, "ENUM Failed");
        send_response(rsp);
        free_msg(req);
      }
    }
    else if (PJUtils::is_uri_phone_number(uri))
    {
      // The URI translation failed, but we have been left with a URI that
      // definitely encodes a phone number, so we should route to the BGCF.
      LOG_DEBUG("Unable to resolve URI phone number %s using ENUM, route to BGCF",
                PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, uri).c_str());
      status_code = PJSIP_SC_NOT_FOUND;
      route_to_bgcf(req);
    }
  }
  return status_code;
}


/// Gets the subscriber's associated URIs and iFCs for each URI from
/// the HSS and stores cached values. Returns true on success, false on failure.
bool SCSCFSproutletTsx::get_data_from_hss(std::string public_id)
{
  if (!_hss_data_cached)
  {
    // We haven't previous read data from the HSS, so read it now.
    if (_scscf->read_hss_data(public_id,
                              _registered,
                              _uris,
                              _ifcs,
                              _ccfs,
                              _ecfs,
                              trail()))
    {
      _hss_data_cached = true;
    }
  }

  return _hss_data_cached;
}


/// Look up the registration state for the given public ID, using the
/// per-transaction cache if possible (and caching them and the iFC otherwise).
bool SCSCFSproutletTsx::is_user_registered(std::string public_id)
{
  bool success = get_data_from_hss(public_id);
  if (success)
  {
    return _registered;
  }
  else
  {
    LOG_ERROR("Connection to Homestead failed, treating user as unregistered");
    return false;
  }
}


/// Look up the associated URIs for the given public ID, using the cache if
/// possible (and caching them and the iFC otherwise).
/// The uris parameter is only filled in correctly if this function
/// returns true,
bool SCSCFSproutletTsx::get_associated_uris(std::string public_id,
                                            std::vector<std::string>& uris)
{
  bool success = get_data_from_hss(public_id);
  if (success)
  {
    uris = _uris;
  }
  return success;
}


/// Look up the Ifcs for the given public ID, using the cache if possible
/// (and caching them and the associated URIs otherwise).
/// The ifcs parameter is only filled in correctly if this function
/// returns true,
bool SCSCFSproutletTsx::lookup_ifcs(std::string public_id, Ifcs& ifcs)
{
  bool success = get_data_from_hss(public_id);
  if (success)
  {
    ifcs = _ifcs;
  }
  return success;
}


/// Ensures the request carries a Session-Expires header with an appropriate
/// duration so the UAs at either end of the session send keepalives.
void SCSCFSproutletTsx::add_session_expires(pjsip_msg* req)
{
  pjsip_session_expires_hdr* session_expires =
    (pjsip_session_expires_hdr*)pjsip_msg_find_hdr_by_name(req,
                                                           &STR_SESSION_EXPIRES,
                                                           NULL);
  if (session_expires == NULL)
  {
    session_expires = pjsip_session_expires_hdr_create(get_pool(req));
    pjsip_msg_add_hdr(req, (pjsip_hdr*)session_expires);
  }
  session_expires->expires = stack_data.default_session_expires;
}


/// Record-Route the S-CSCF sproutlet into a dialog.  The parameter passed will
/// be attached to the Record-Route and can be used to recover the billing
/// role that is in use on subsequent in-dialog messages.
void SCSCFSproutletTsx::add_record_route(pjsip_msg* msg,
                                         const std::string& billing_role)
{
  if (!_record_routed)
  {
    pj_pool_t* pool = get_pool(msg);

    pjsip_param* param = PJ_POOL_ALLOC_T(pool, pjsip_param);
    pj_strdup(pool, &param->name, &STR_BILLING_ROLE);
    pj_strdup2(pool, &param->value, billing_role.c_str());

    pjsip_sip_uri* uri = get_reflexive_uri(pool);
    pj_list_insert_before(&uri->other_param, param);

    pjsip_route_hdr* rr = pjsip_rr_hdr_create(pool);
    rr->name_addr.uri = (pjsip_uri*)uri;

    pjsip_msg_insert_first_hdr(msg, (pjsip_hdr*)rr);

    _record_routed = true;
  }
}


/// Retrieve the billing role for an in-dialog message.
void SCSCFSproutletTsx::get_billing_role(std::string& billing_role)
{
  const pjsip_route_hdr* route = route_hdr();
  pjsip_sip_uri* uri = (pjsip_sip_uri*)route->name_addr.uri;
  pjsip_param* param = pjsip_param_find(&uri->other_param,
                                        &STR_BILLING_ROLE);
  if (param != NULL)
  {
    billing_role = PJUtils::pj_str_to_string(&param->value);
  }
  else
  {
    LOG_WARNING("Billing role unknown, assuming originating only");
    billing_role = "charge-orig";
  }
}


/// Handles liveness timer expiry.
void SCSCFSproutletTsx::on_timer_expiry(void* context)
{
  _liveness_timer = 0;

  if (_as_chain_link.is_set())
  {
    // The request was routed to a downstream AS, so cancel any outstanding
    // forks.
    cancel_pending_forks();

    if (_as_chain_link.continue_session())
    {
      // The AS either timed out or returned a 5xx error, and default
      // handling is set to continue.
      LOG_DEBUG("Trigger default_handling=CONTINUE processing");
      _as_chain_link = _as_chain_link.next();
      pjsip_msg* req = original_request();
      if (_session_case->is_originating())
      {
        apply_originating_services(req);
      }
      else
      {
        apply_terminating_services(req);
      }
    }
    else
    {
      // Build and send a timeout response upstream.
      pjsip_msg* req = original_request();
      pjsip_msg* rsp = create_response(req,
                                       PJSIP_SC_REQUEST_TIMEOUT);
      free_msg(req);
      send_response(rsp);
    }
  }
}
