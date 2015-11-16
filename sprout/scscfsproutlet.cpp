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
#include "registration_utils.h"
#include "scscfsproutlet.h"
#include "uri_classifier.h"

// Constant indicating there is no served user for a request.
const char* NO_SERVED_USER = "";

/// SCSCFSproutlet constructor.
SCSCFSproutlet::SCSCFSproutlet(const std::string& scscf_cluster_uri,
                               const std::string& scscf_node_uri,
                               const std::string& icscf_uri,
                               const std::string& bgcf_uri,
                               int port,
                               RegStore* store,
                               HSSConnection* hss,
                               EnumService* enum_service,
                               ACRFactory* acr_factory,
                               bool override_npdi,
                               int session_continued_timeout_ms,
                               int session_terminated_timeout_ms) :
  Sproutlet("scscf", port),
  _scscf_cluster_uri(NULL),
  _scscf_node_uri(NULL),
  _icscf_uri(NULL),
  _bgcf_uri(NULL),
  _store(store),
  _hss(hss),
  _enum_service(enum_service),
  _acr_factory(acr_factory),
  _override_npdi(override_npdi),
  _session_continued_timeout_ms(session_continued_timeout_ms),
  _session_terminated_timeout_ms(session_terminated_timeout_ms),
  _scscf_cluster_uri_str(scscf_cluster_uri),
  _scscf_node_uri_str(scscf_node_uri),
  _icscf_uri_str(icscf_uri),
  _bgcf_uri_str(bgcf_uri)
{
  _incoming_sip_transactions_tbl = SNMP::SuccessFailCountByRequestTypeTable::create("scscf_incoming_sip_transactions",
                                                                                    "1.2.826.0.1.1578918.9.3.20");
  _outgoing_sip_transactions_tbl = SNMP::SuccessFailCountByRequestTypeTable::create("scscf_outgoing_sip_transactions",
                                                                                    "1.2.826.0.1.1578918.9.3.21");
  _routed_by_preloaded_route_tbl = SNMP::CounterTable::create("scscf_routed_by_preloaded_route",
                                                              "1.2.826.0.1.1578918.9.3.26");
  _invites_cancelled_before_1xx_tbl = SNMP::CounterTable::create("invites_cancelled_before_1xx",
                                                                 "1.2.826.0.1.1578918.9.3.32");
  _invites_cancelled_after_1xx_tbl = SNMP::CounterTable::create("invites_cancelled_after_1xx",
                                                                "1.2.826.0.1.1578918.9.3.33");
}


/// SCSCFSproutlet destructor.
SCSCFSproutlet::~SCSCFSproutlet()
{
  delete _as_chain_table;
  delete _incoming_sip_transactions_tbl;
  delete _outgoing_sip_transactions_tbl;
  delete _routed_by_preloaded_route_tbl;
  delete _invites_cancelled_before_1xx_tbl;
  delete _invites_cancelled_after_1xx_tbl;
}

bool SCSCFSproutlet::init()
{
  TRC_DEBUG("Creating S-CSCF Sproutlet");
  TRC_DEBUG("  S-CSCF cluster URI = %s", _scscf_cluster_uri_str.c_str());
  TRC_DEBUG("  S-CSCF node URI    = %s", _scscf_node_uri_str.c_str());
  TRC_DEBUG("  I-CSCF URI         = %s", _icscf_uri_str.c_str());
  TRC_DEBUG("  BGCF URI           = %s", _bgcf_uri_str.c_str());

  bool init_success = true;

  // Convert the routing URIs to a form suitable for PJSIP, so we're
  // not continually converting from strings.
  _scscf_cluster_uri = PJUtils::uri_from_string(_scscf_cluster_uri_str, stack_data.pool, false);

  if (_scscf_cluster_uri == NULL)
  {
    TRC_ERROR("Invalid S-CSCF cluster %s", _scscf_cluster_uri_str.c_str());
    init_success = false;
  }

  _scscf_node_uri = PJUtils::uri_from_string(_scscf_node_uri_str, stack_data.pool, false);

  if (_scscf_node_uri == NULL)
  {
    TRC_ERROR("Invalid S-CSCF node URI %s", _scscf_node_uri_str.c_str());
    init_success = false;
  }

  _bgcf_uri = PJUtils::uri_from_string(_bgcf_uri_str, stack_data.pool, false);

  if (_bgcf_uri == NULL)
  {
    TRC_ERROR("Invalid BGCF URI %s", _bgcf_uri_str.c_str());
    init_success = false;
  }

  if (_icscf_uri_str != "")
  {
    _icscf_uri = PJUtils::uri_from_string(_icscf_uri_str, stack_data.pool, false);

    if (_icscf_uri == NULL)
    {
      TRC_ERROR("Invalid I-CSCF URI %s", _icscf_uri_str.c_str());
      init_success = false;
    }
  }

  // Create an AS Chain table for maintaining the mapping from ODI tokens to
  // AS chains (and links in those chains).
  _as_chain_table = new AsChainTable;

  return init_success;
}

/// Creates a SCSCFSproutletTsx instance for performing S-CSCF service processing
/// on a request.
SproutletTsx* SCSCFSproutlet::get_tsx(SproutletTsxHelper* helper,
                                      const std::string& alias,
                                      pjsip_msg* req)
{
  pjsip_method_e req_type = req->line.req.method.id;
  return (SproutletTsx*)new SCSCFSproutletTsx(helper, this, req_type);
}


/// Returns the configured S-CSCF cluster URI for this system.
const pjsip_uri* SCSCFSproutlet::scscf_cluster_uri() const
{
  return _scscf_cluster_uri;
}


/// Returns the configured S-CSCF node URI for this system.
const pjsip_uri* SCSCFSproutlet::scscf_node_uri() const
{
  return _scscf_node_uri;
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


/// Gets all bindings for the specified Address of Record from the registration
/// store.
void SCSCFSproutlet::get_bindings(const std::string& aor,
                                  RegStore::AoR** aor_data,
                                  SAS::TrailId trail)
{
  // Look up the target in the registration data store.
  TRC_INFO("Look up targets in registration store: %s", aor.c_str());
  *aor_data = _store->get_aor_data(aor, trail);

  // TODO - Log bindings to SAS
}


/// Removes the specified binding for the specified Address of Record from
/// the registration store.
void SCSCFSproutlet::remove_binding(const std::string& aor,
                                    const std::string& binding_id,
                                    SAS::TrailId trail)
{
  RegistrationUtils::remove_bindings(_store,
                                     _hss,
                                     aor,
                                     binding_id,
                                     HSSConnection::DEREG_TIMEOUT,
                                     trail);
}


/// Read data for a public user identity from the HSS.
bool SCSCFSproutlet::read_hss_data(const std::string& public_id,
                                   const std::string& private_id,
                                   const std::string& req_type,
                                   bool cache_allowed,
                                   bool& registered,
                                   std::vector<std::string>& uris,
                                   std::vector<std::string>& aliases,
                                   Ifcs& ifcs,
                                   std::deque<std::string>& ccfs,
                                   std::deque<std::string>& ecfs,
                                   SAS::TrailId trail)
{
  std::string regstate;
  std::map<std::string, Ifcs> ifc_map;

  long http_code = _hss->update_registration_state(public_id,
                                                   private_id,
                                                   req_type,
                                                   regstate,
                                                   ifc_map,
                                                   uris,
                                                   aliases,
                                                   ccfs,
                                                   ecfs,
                                                   cache_allowed,
                                                   trail);
  if (http_code == 200)
  {
    ifcs = ifc_map[public_id];
  }

  registered = (regstate == HSSConnection::STATE_REGISTERED);

  return (http_code == 200);
}


/// Attempt ENUM lookup if appropriate.
void SCSCFSproutlet::translate_request_uri(pjsip_msg* req,
                                           pj_pool_t* pool,
                                           SAS::TrailId trail)
{
  return PJUtils::translate_request_uri(req,
                                        pool,
                                        _enum_service,
                                        should_override_npdi(),
                                        trail);
}


/// Get an ACR instance from the factory.
/// @param trail                SAS trail identifier to use for the ACR.
/// @param initiator            The initiator of the SIP transaction (calling
///                             or called party).
ACR* SCSCFSproutlet::get_acr(SAS::TrailId trail, Initiator initiator, NodeRole role)
{
  return _acr_factory->get_acr(trail, initiator, role);
}


SCSCFSproutletTsx::SCSCFSproutletTsx(SproutletTsxHelper* helper,
                                     SCSCFSproutlet* scscf,
                                     pjsip_method_e req_type) :
  SproutletTsx(helper),
  _scscf(scscf),
  _cancelled(false),
  _session_case(NULL),
  _as_chain_link(),
  _hss_data_cached(false),
  _registered(false),
  _uris(),
  _ifcs(),
  _in_dialog_acr(NULL),
  _failed_ood_acr(NULL),
  _target_aor(),
  _target_bindings(),
  _liveness_timer(0),
  _record_routed(false),
  _req_type(req_type),
  _seen_1xx(false),
  _impi(),
  _auto_reg(false),
  _se_helper(stack_data.default_session_expires)
{
  TRC_DEBUG("S-CSCF Transaction (%p) created", this);
}


SCSCFSproutletTsx::~SCSCFSproutletTsx()
{
  TRC_DEBUG("S-CSCF Transaction (%p) destroyed", this);
  if (!_as_chain_link.is_set())
  {
    ACR* acr = get_acr();
    if (acr)
    {
      acr->send();
    }
  }

  if (_as_chain_link.is_set())
  {
    _as_chain_link.release();
  }

  if (_liveness_timer != 0)
  {
    cancel_timer(_liveness_timer);
  }

  // If the ACR was stored locally, destroy it now.
  if (_failed_ood_acr)
  {
    delete _failed_ood_acr;
  }
  if (_in_dialog_acr)
  {
    delete _in_dialog_acr;
  }

  _target_bindings.clear();
}


void SCSCFSproutletTsx::on_rx_initial_request(pjsip_msg* req)
{
  TRC_INFO("S-CSCF received initial request");

  pjsip_status_code status_code = PJSIP_SC_OK;

  _se_helper.process_request(req, get_pool(req), trail());

  // Work out if we should be auto-registering the user based on this
  // request and if we are, also work out the IMPI to register them with.
  const pjsip_route_hdr* top_route = route_hdr();
  if (top_route != NULL)
  {
    pjsip_sip_uri* uri = (pjsip_sip_uri*)top_route->name_addr.uri;

    if ((pjsip_param_find(&uri->other_param, &STR_ORIG) != NULL) &&
        (pjsip_param_find(&uri->other_param, &STR_AUTO_REG) != NULL))
    {
      _auto_reg = true;

      pjsip_proxy_authorization_hdr* proxy_auth_hdr =
        (pjsip_proxy_authorization_hdr*)pjsip_msg_find_hdr(req,
                                                           PJSIP_H_PROXY_AUTHORIZATION,
                                                           NULL);
      _impi = PJUtils::extract_username(proxy_auth_hdr,
                                        PJUtils::orig_served_user(req));
    }
  }

  // Determine the session case and the served user.  This will link to
  // an AsChain object (creating it if necessary), if we need to provide
  // services.
  status_code = determine_served_user(req);

  // Pass the received request to the ACR.
  // @TODO - request timestamp???
  ACR* acr = get_acr();
  if (acr)
  {
    acr->rx_request(req);
  }

  if (status_code != PJSIP_SC_OK)
  {
    // Failed to determine the served user for a request we should provide
    // services on, so reject the request.
    TRC_INFO("Failed to determine served user for request, reject with %d status code",
             status_code);
    pjsip_msg* rsp = create_response(req, status_code);
    send_response(rsp);
    free_msg(req);
    return;
  }
  else
  {
    // Add a P-Charging-Function-Addresses header if one is not already present
    // for some reason. We only do this if we have the charging addresses cached
    // (which we should do).
    PJUtils::add_pcfa_header(req, get_pool(req), _ccfs, _ecfs, false);

    // Add a second P-Asserted-Identity header if required on originating calls.
    // See 3GPP TS24.229, 5.4.3.2.
    if (_session_case->is_originating())
    {
      add_second_p_a_i_hdr(req);
    }

    if (_as_chain_link.is_set())
    {
      // AS chain is set up, so must apply services to the request.
      TRC_INFO("Found served user, so apply services");

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
      TRC_INFO("Route request to BGCF without applying services");
      route_to_bgcf(req);
    }
  }
}


void SCSCFSproutletTsx::on_rx_in_dialog_request(pjsip_msg* req)
{
  TRC_INFO("S-CSCF received in-dialog request");

  _se_helper.process_request(req, get_pool(req), trail());

  // Create an ACR for this request and pass the request to it.
  _in_dialog_acr = _scscf->get_acr(trail(),
                         CALLING_PARTY,
                         get_billing_role());

  // @TODO - request timestamp???
  get_acr()->rx_request(req);

  send_request(req);
}


void SCSCFSproutletTsx::on_tx_request(pjsip_msg* req, int fork_id)
{
  ACR* acr = get_acr();
  if (acr)
  {
    // Pass the transmitted request to the ACR to update the accounting
    // information.
    acr->tx_request(req);
  }
}


void SCSCFSproutletTsx::on_rx_response(pjsip_msg* rsp, int fork_id)
{
  TRC_INFO("S-CSCF received response");

  _se_helper.process_response(rsp, get_pool(rsp), trail());

  // Pass the received response to the ACR.
  // @TODO - timestamp from response???
  ACR* acr = get_acr();
  if (acr != NULL)
  {
    acr->rx_response(rsp);
  }

  if (_liveness_timer != 0)
  {
    // The liveness timer is running on this request, so cancel it.
    cancel_timer(_liveness_timer);
    _liveness_timer = 0;
  }

  int st_code = rsp->line.status.code;

  if (st_code > 100)
  {
    _seen_1xx = true;
  }

  if (st_code == SIP_STATUS_FLOW_FAILED)
  {
    // The edge proxy / P-CSCF has reported that this flow has failed.
    // We should remove the binding from the registration store so we don't
    // try it again.
    std::unordered_map<int, std::string>::iterator i = _target_bindings.find(fork_id);

    if (i != _target_bindings.end())
    {
      // We're the auth proxy and the flow we used failed, so delete the binding
      // corresponding to this flow.
      _scscf->remove_binding(_target_aor, i->second, trail());
    }
  }

  if ((st_code >= PJSIP_SC_OK) && (_hss_data_cached))
  {
    // Final response. Add a P-Charging-Function-Addresses header if one is
    // not already present for some reason. We only do this if we have
    // the charging addresses cached (which we should do).
    PJUtils::add_pcfa_header(rsp, get_pool(rsp), _ccfs, _ecfs, false);
  }

  if ((st_code < 300) && (_session_case->is_terminating()))
  {
    // Add a second P-Asserted-Identity header if required. See 3GPP TS24.229,
    // 5.4.3.3.
    add_second_p_a_i_hdr(rsp);
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
        TRC_DEBUG("Trigger default_handling=CONTINUE processing");
        SAS::Event bypass_As(trail(), SASEvent::BYPASS_AS, 1);
        SAS::report_event(bypass_As);

        _as_chain_link = _as_chain_link.next();
        pjsip_msg* req = original_request();
        _record_routed = false;
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
  ACR* acr = get_acr();
  if (acr != NULL)
  {
    // Pass the transmitted response to the ACR to update the accounting
    // information.
    acr->tx_response(rsp);
  }
}


void SCSCFSproutletTsx::on_rx_cancel(int status_code, pjsip_msg* cancel_req)
{
  TRC_INFO("S-CSCF received CANCEL");

  if (_req_type == PJSIP_INVITE_METHOD)
  // If an INVITE is being cancelled, then update INVITE cancellation stats.
  {
    if (_seen_1xx)
    {
      _scscf->_invites_cancelled_after_1xx_tbl->increment();
    }
    else
    {
      _scscf->_invites_cancelled_before_1xx_tbl->increment();
    }
  }

  _cancelled = true;

  if ((status_code == PJSIP_SC_REQUEST_TERMINATED) &&
      (cancel_req != NULL))
  {
    // Create and send an ACR for the CANCEL request.
    NodeRole role = NODE_ROLE_ORIGINATING;
    if ((_session_case != NULL) &&
        (_session_case->is_terminating()))
    {
      role = NODE_ROLE_TERMINATING;
    }
    ACR* cancel_acr = _scscf->get_acr(trail(), CALLING_PARTY, role);

    // @TODO - timestamp from request.
    cancel_acr->rx_request(cancel_req);
    cancel_acr->send();

    delete cancel_acr;
  }
}

void SCSCFSproutletTsx::retrieve_odi_and_sesscase(pjsip_msg* req)
{
  // Get the top route header.
  const pjsip_route_hdr* hroute = route_hdr();
  URIClass uri_class;
  if (hroute != NULL)
  {
    uri_class = URIClassifier::classify_uri(hroute->name_addr.uri);
  }

  if ((hroute != NULL) &&
      ((uri_class == NODE_LOCAL_SIP_URI) ||
       (uri_class == HOME_DOMAIN_SIP_URI)))
  {
    // This is our own Route header, containing a SIP URI.  Check for an
    // ODI token.  We need to determine the session case: is
    // this an originating request or not - see 3GPP TS 24.229
    // s5.4.3.1, s5.4.1.2.2F and the behaviour of
    // proxy_calculate_targets as an access proxy.
    TRC_DEBUG("Route header references this system");
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
      TRC_DEBUG("Found ODI token %s", odi_token.c_str());
      _as_chain_link = _scscf->as_chain_table()->lookup(odi_token);

      if (_as_chain_link.is_set())
      {
        TRC_INFO("Original dialog for %.*s found: %s",
                 uri->user.slen, uri->user.ptr,
                 _as_chain_link.to_string().c_str());
        _session_case = &_as_chain_link.session_case();
      }
      else
      {
        // The ODI token is invalid or expired.  Treat call as OOTB.
        TRC_INFO("Expired ODI token %s so handle as OOTB request", odi_token.c_str());
        SAS::Event event(trail(), SASEvent::SCSCF_ODI_INVALID, 0);
        event.add_var_param(PJUtils::pj_str_to_string(&uri->user));
        SAS::report_event(event);
      }
    }

    // If an application server is a B2BUA and so changes the Call-ID,
    // we'll normally correlate that in SAS through the AS chain
    // (directly correlating the new trail and the trail of the
    // original dialog). If it strips the ODI token for any reason,
    // that won't work - so as a fallback, if we have no ODI token,
    // we'll log an ICID marker to correlate the trails.
    if (!_as_chain_link.is_set())
    {
      pjsip_p_c_v_hdr* pcv = (pjsip_p_c_v_hdr*)pjsip_msg_find_hdr_by_name(req,
                                                                          &STR_P_C_V,
                                                                          NULL);
      if (pcv)
      {
        TRC_DEBUG("No ODI token, or invalid ODI token, on request - logging ICID marker %.*s for B2BUA AS correlation", pcv->icid.slen, pcv->icid.ptr);
        SAS::Marker icid_marker(trail(), MARKER_ID_IMS_CHARGING_ID, 1u);
        icid_marker.add_var_param(pcv->icid.slen, pcv->icid.ptr);
        SAS::report_marker(icid_marker, SAS::Marker::Scope::Trace);
      }
      else
      {
        TRC_DEBUG("No ODI token, or invalid ODI token, on request, and no P-Charging-Vector header (so can't log ICID for correlation)");
      }
    }

    TRC_DEBUG("Got our Route header, session case %s, OD=%s",
              _session_case->to_string().c_str(),
              _as_chain_link.to_string().c_str());
  }
  else
  {
    // No Route header on the request or top Route header does not correspond to
    // the S-CSCF.  This probably shouldn't happen, but if it does we will
    // treat it as a terminating request.
    TRC_DEBUG("No S-CSCF Route header, so treat as terminating request");
    _session_case = &SessionCase::Terminating;
  }

}

bool SCSCFSproutletTsx::is_retarget(std::string new_served_user)
{
  std::string old_served_user = _as_chain_link.served_user();

  // TS 24.229 section 5.4.3.3 says that changing the Request-URI to an alias of the original URI
  // doesn't count as a retarget, so get the aliases ready to check
  std::vector<std::string> aliases;
  get_aliases(old_served_user, aliases);

  if (new_served_user == old_served_user)
  {
    // URIs match exactly - this is not a retarget
    return false;
  }
  else if (std::find(aliases.begin(), aliases.end(), new_served_user) != aliases.end())
  {
    TRC_DEBUG("Application server has changed URI %s to the aliased URI %s - "
              "not treating as a retarget, not invoking originating-cdiv processing",
              old_served_user.c_str(),
              new_served_user.c_str());
    SAS::Event event(trail(), SASEvent::AS_RETARGETED_TO_ALIAS, 1);
    event.add_var_param(old_served_user);
    event.add_var_param(new_served_user);
    SAS::report_event(event);
    return false;
  }
  else
  {
    // The new URI is not identical to the old one and is not an aliased URI - the request has been retargeted
    SAS::Event event(trail(), SASEvent::AS_RETARGETED_CDIV, 1);
    event.add_var_param(old_served_user);
    event.add_var_param(new_served_user);
    SAS::report_event(event);
    return true;
  }
}

pjsip_status_code SCSCFSproutletTsx::determine_served_user(pjsip_msg* req)
{
  pjsip_status_code status_code = PJSIP_SC_OK;

  retrieve_odi_and_sesscase(req);

  if (_as_chain_link.is_set())
  {
    bool retargeted = false;
    std::string served_user = served_user_from_msg(req);

    if ((_session_case->is_terminating()) &&
        is_retarget(served_user))
    {
      if (pjsip_msg_find_hdr(req, PJSIP_H_ROUTE, NULL) != NULL)
      {
        // The AS has supplied a pre-loaded route, which means it is routing
        // directly to the target. Interrupt the AS chain link to prevent any
        // more app servers from being triggered.
        TRC_INFO("Preloaded route - interrupt AS processing");
        _scscf->_routed_by_preloaded_route_tbl->increment(); // Update SNMP statistics.
        SAS::Event preloaded_route(trail(), SASEvent::AS_SUPPLIED_PRELOADED_ROUTE, 0);
        SAS::report_event(preloaded_route);
        _as_chain_link.interrupt();
      }
      else
      {
        // AS is retargeting per 3GPP TS 24.229 s5.4.3.3 step 3, so
        // create new AS chain with session case orig-cdiv and the
        // terminating user as served user.
        TRC_INFO("AS is retargeting the request");
        retargeted = true;

        _session_case = &SessionCase::OriginatingCdiv;
        served_user = _as_chain_link.served_user();

        sas_log_start_of_sesion_case(req, _session_case, served_user);

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
          TRC_DEBUG("Blanking out term_ioi parameter due to redirect");
          pcv->term_ioi = pj_str("");
        }

        // Abandon the `term` ACR we're building up as we're about to perform CDIV.
        if (_as_chain_link.acr())
        {
          _as_chain_link.acr()->cancel();
        }

        Ifcs ifcs;
        if (lookup_ifcs(served_user, ifcs))
        {
          TRC_DEBUG("Creating originating CDIV AS chain");

          // Preserve the SAS trail ID of the AS chain, to allow us to correlate even when a B2BUA
          // retargets the call
          SAS::TrailId old_chain_trail = _as_chain_link.trail();
          _as_chain_link.release();

          // Don't provide an ACR for the CDIV orig processing.
          ACR* cdiv_acr = NULL;
          _as_chain_link = create_as_chain(ifcs, served_user, cdiv_acr, old_chain_trail);

          if (stack_data.record_route_on_diversion)
          {
            TRC_DEBUG("Add service to dialog - originating Cdiv");
            add_record_route(req, false, NODE_ROLE_ORIGINATING);
          }
        }
        else
        {
          TRC_DEBUG("Failed to retrieve ServiceProfile for %s", served_user.c_str());
          status_code = PJSIP_SC_NOT_FOUND;
          SAS::Event no_ifcs(trail(), SASEvent::IFC_GET_FAILURE, 0);
          SAS::report_event(no_ifcs);
        }
      }
    }

    if (!retargeted)
    {
      if (stack_data.record_route_on_every_hop)
      {
        TRC_DEBUG("Add service to dialog - AS hop");
        if (_session_case->is_terminating())
        {
          add_record_route(req, false, NODE_ROLE_TERMINATING);
        }
        else
        {
          add_record_route(req, false, NODE_ROLE_ORIGINATING);
        }
      }
    }
  }
  else
  {
    // No existing AS chain - create new.
    std::string served_user = served_user_from_msg(req);

    // Create a new ACR for this request.
    ACR* acr = _scscf->get_acr(trail(),
                               CALLING_PARTY,
                               _session_case->is_originating() ?
                                 NODE_ROLE_ORIGINATING : NODE_ROLE_TERMINATING);

    if (!served_user.empty())
    {
      // SAS log the start of originating or terminating processing.
      sas_log_start_of_sesion_case(req, _session_case, served_user);

      if (_session_case->is_terminating())
      {
        if (stack_data.record_route_on_initiation_of_terminating)
        {
          TRC_DEBUG("Single Record-Route - initiation of terminating handling");
          add_record_route(req, false, NODE_ROLE_TERMINATING);
        }
      }
      else if (_session_case->is_originating())
      {
        if (stack_data.record_route_on_initiation_of_originating)
        {
          TRC_DEBUG("Single Record-Route - initiation of originating handling");
          add_record_route(req, true, NODE_ROLE_ORIGINATING);
          acr->override_session_id(PJUtils::pj_str_to_string(&PJSIP_MSG_CID_HDR(req)->id));
        }
      }

      TRC_DEBUG("Looking up iFCs for %s for new AS chain", served_user.c_str());

      Ifcs ifcs;
      if (lookup_ifcs(served_user, ifcs))
      {
        TRC_DEBUG("Successfully looked up iFCs");
        _as_chain_link = create_as_chain(ifcs, served_user, acr, trail());
      }
      else
      {
        TRC_DEBUG("Failed to retrieve ServiceProfile for %s", served_user.c_str());
        status_code = PJSIP_SC_NOT_FOUND;
        SAS::Event no_ifcs(trail(), SASEvent::IFC_GET_FAILURE, 1);
        SAS::report_event(no_ifcs);

        // No IFC, so no AsChain, store the ACR locally.
        _failed_ood_acr = acr;
      }
    }
    else
    {
      delete acr;
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
  pjsip_uri* uri = NULL;
  std::string user;

  if (_session_case->is_originating())  // (includes orig-cdiv)
  {
    uri = PJUtils::orig_served_user(msg);
  }
  else
  {
    // We only consider a terminating request to be destined for a served user
    // if it doesn't have a route header.
    if (pjsip_msg_find_hdr(msg, PJSIP_H_ROUTE, NULL) == NULL)
    {
      uri = PJUtils::term_served_user(msg);
    }
  }

  if (uri != NULL)
  {
    URIClass uri_class = URIClassifier::classify_uri(uri);

    if ((PJSIP_URI_SCHEME_IS_SIP(uri)) &&
        ((uri_class == NODE_LOCAL_SIP_URI) ||
         (uri_class == HOME_DOMAIN_SIP_URI)))
    {
      user = PJUtils::public_id_from_uri(uri);
    }
    else if (PJSIP_URI_SCHEME_IS_TEL(uri))
    {
      user = PJUtils::public_id_from_uri(uri);
    }
    else
    {
      TRC_DEBUG("URI is not locally hosted");
    }
  }

  return user;
}


/// Factory method: create AsChain by looking up iFCs.
AsChainLink SCSCFSproutletTsx::create_as_chain(Ifcs ifcs,
                                               std::string served_user,
                                               ACR*& acr,
                                               SAS::TrailId chain_trail)
{
  if (served_user.empty())
  {
    TRC_WARNING("create_as_chain called with an empty served_user");
  }
  bool is_registered = is_user_registered(served_user);

  AsChainLink ret = AsChainLink::create_as_chain(_scscf->as_chain_table(),
                                                 *_session_case,
                                                 served_user,
                                                 is_registered,
                                                 chain_trail,
                                                 ifcs,
                                                 acr);
  acr = NULL;
  TRC_DEBUG("S-CSCF sproutlet transaction %p linked to AsChain %s",
            this, ret.to_string().c_str());
  return ret;
}


/// Apply originating services for this request.
void SCSCFSproutletTsx::apply_originating_services(pjsip_msg* req)
{
  TRC_DEBUG("Performing originating initiating request processing");

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
  _as_chain_link.on_initial_request(req, server_name, trail());

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
    TRC_INFO("Completed applying originating services");

    if (stack_data.record_route_on_completion_of_originating)
    {
      TRC_DEBUG("Add service to dialog - end of originating handling");
      add_record_route(req, false, NODE_ROLE_ORIGINATING);
    }

    // Attempt to translate the RequestURI using ENUM or an alternative
    // database.
    _scscf->translate_request_uri(req, get_pool(req), trail());

    URIClass uri_class = URIClassifier::classify_uri(req->line.req.uri);
    std::string new_uri_str = PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, req->line.req.uri);
    TRC_INFO("New URI string is %s", new_uri_str.c_str());

    if ((uri_class == LOCAL_PHONE_NUMBER) ||
        (uri_class == GLOBAL_PHONE_NUMBER) ||
        (uri_class == NP_DATA) ||
        (uri_class == FINAL_NP_DATA))
    {
      TRC_DEBUG("Routing to BGCF");
      SAS::Event event(trail(), SASEvent::PHONE_ROUTING_TO_BGCF, 0);
      event.add_var_param(new_uri_str);
      SAS::report_event(event);
      route_to_bgcf(req);
    }
    else if (uri_class == OFFNET_SIP_URI)
    {
      // Destination is off-net, so route to the BGCF.
      TRC_DEBUG("Routing to BGCF");
      SAS::Event event(trail(), SASEvent::OFFNET_ROUTING_TO_BGCF, 0);
      event.add_var_param(new_uri_str);
      SAS::report_event(event);
      route_to_bgcf(req);
    }
    else
    {
      // Destination is on-net so route to the I-CSCF.
      route_to_icscf(req);
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
  _as_chain_link.on_initial_request(req, server_name, trail());

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
    TRC_INFO("Completed applying terminating services");

    if (stack_data.record_route_on_completion_of_terminating)
    {
      TRC_DEBUG("Add service to dialog - end of terminating handling");
      add_record_route(req, true, NODE_ROLE_TERMINATING);

      ACR* acr = _as_chain_link.acr();
      if (acr != NULL)
      {
        acr->override_session_id(PJUtils::pj_str_to_string(&PJSIP_MSG_CID_HDR(req)->id));
      }
    }

    if (pjsip_msg_find_hdr(req, PJSIP_H_ROUTE, NULL) != NULL)
    {
      // Route according to normal SIP routing.
      send_request(req);
    }
    else
    {
      // Route the call to the appropriate target.
      route_to_target(req);
    }
  }
}


/// Attempt to route the request to an application server.
void SCSCFSproutletTsx::route_to_as(pjsip_msg* req, const std::string& server_name)
{
  SAS::Event invoke_as(trail(), SASEvent::SCSCF_INVOKING_AS, 0);
  invoke_as.add_var_param(server_name);
  SAS::report_event(invoke_as);

  // Check that the AS URI is well-formed.
  pjsip_sip_uri* as_uri = (pjsip_sip_uri*)
                        PJUtils::uri_from_string(server_name, get_pool(req));

  if ((as_uri != NULL) &&
      (PJSIP_URI_SCHEME_IS_SIP(as_uri)))
  {
    // AS URI is valid, so encode the AS hop and the return hop in Route headers.
    std::string odi_value = PJUtils::pj_str_to_string(&STR_ODI_PREFIX) +
                            _as_chain_link.next_odi_token();
    TRC_INFO("Routing to Application Server %s with ODI token %s for %s",
             server_name.c_str(),
             odi_value.c_str(),
             _as_chain_link.to_string().c_str());

    // Insert route header below it with an ODI in it.  This must use the
    // URI for this S-CSCF node (not the cluster) to ensure any forwarded
    // requests are routed to this node.
    pjsip_sip_uri* odi_uri = (pjsip_sip_uri*)
                             pjsip_uri_clone(get_pool(req), _scscf->scscf_node_uri());
    pj_strdup2(get_pool(req), &odi_uri->user, odi_value.c_str());
    odi_uri->transport_param = as_uri->transport_param;  // Use same transport as AS, in case it can only cope with one.
    if (_session_case->is_originating())
    {
      pjsip_param *orig_param = PJ_POOL_ALLOC_T(get_pool(req), pjsip_param);
      pj_strdup(get_pool(req), &orig_param->name, &STR_ORIG);
      pj_strdup2(get_pool(req), &orig_param->value, "");
      pj_list_insert_after(&odi_uri->other_param, orig_param);
    }
    PJUtils::add_top_route_header(req, odi_uri, get_pool(req));

    // Add the application server URI as the top Route header, per TS 24.229.
    PJUtils::add_top_route_header(req, as_uri, get_pool(req));

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

    // Forward the request.
    send_request(req);

    // Start the liveness timer for the AS.
    int timeout = (_as_chain_link.continue_session() ?
                   _scscf->_session_continued_timeout_ms :
                   _scscf->_session_terminated_timeout_ms);

    if (timeout != 0)
    {
      if (!schedule_timer(NULL, _liveness_timer, timeout))
      {
        TRC_WARNING("Failed to start liveness timer");
      }
    }
  }
  else
  {
    // The AS URI is badly formed, so reject the request.  (We could choose
    // to continue processing here with the next AS if the default handling
    // is set to allow it, but it feels better to fail the request for a
    // misconfiguration.)
    TRC_ERROR("Badly formed AS URI %s", server_name.c_str());
    SAS::Event bad_uri(trail(), SASEvent::BAD_AS_URI, 0);
    SAS::report_event(bad_uri);

    pjsip_msg* rsp = create_response(req, PJSIP_SC_BAD_GATEWAY);
    send_response(rsp);
    free_msg(req);
  }
}


/// Route the request to the I-CSCF.
void SCSCFSproutletTsx::route_to_icscf(pjsip_msg* req)
{
  const pjsip_uri* icscf_uri = _scscf->icscf_uri();

  if (icscf_uri != NULL)
  {
    // I-CSCF is enabled, so route to it.
    TRC_INFO("Routing to I-CSCF %s",
             PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR, icscf_uri).c_str());
    PJUtils::add_route_header(req,
                              (pjsip_sip_uri*)pjsip_uri_clone(get_pool(req), icscf_uri),
                              get_pool(req));
  }
  else
  {
    // I-CSCF is disabled, so route directly to the local S-CSCF.
    const pjsip_uri* scscf_uri = _scscf->scscf_cluster_uri();
    TRC_INFO("Routing directly to S-CSCF %s",
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
  TRC_INFO("Routing to BGCF %s",
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
  TRC_INFO("Routing to terminating S-CSCF %s",
           PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                  _scscf->scscf_cluster_uri()).c_str());
  PJUtils::add_route_header(req,
                            (pjsip_sip_uri*)pjsip_uri_clone(get_pool(req),
                                                            _scscf->scscf_cluster_uri()),
                            get_pool(req));
  send_request(req);
}


/// Route the request to the appropriate onward target.
void SCSCFSproutletTsx::route_to_target(pjsip_msg* req)
{
  pjsip_uri* req_uri = req->line.req.uri;
  URIClass uri_class = URIClassifier::classify_uri(req_uri);

  if ((PJSIP_URI_SCHEME_IS_SIP(req_uri) &&
      ((pjsip_sip_uri*)req_uri)->maddr_param.slen))
  {
    // The Request-URI of the request contains an maddr parameter, so forward
    // the request to the Request-URI.
    TRC_INFO("Route request to maddr %.*s",
             ((pjsip_sip_uri*)req_uri)->maddr_param.slen,
             ((pjsip_sip_uri*)req_uri)->maddr_param.ptr);
    send_request(req);
  }
  else if (uri_class == OFFNET_SIP_URI)
  {
    // The Request-URI indicates an non-home domain, so forward the request
    // to the domain in the Request-URI unchanged.
    TRC_INFO("Route request to Request-URI %s",
             PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, req_uri).c_str());
    send_request(req);
  }
  else
  {
    // The Request-URI is a SIP URI local to us, or a tel: URI that would only have reached this
    // point if it was owned by us, so look it up in the registration store.
    TRC_INFO("Route request to registered UE bindings");
    route_to_ue_bindings(req);
  }
}


/// Route the request to UE bindings retrieved from the registration store.
void SCSCFSproutletTsx::route_to_ue_bindings(pjsip_msg* req)
{
  // Get the public user identity corresponding to the RequestURI.
  pjsip_uri* req_uri = req->line.req.uri;
  std::string public_id = PJUtils::public_id_from_uri(req_uri);

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

  TargetList targets;
  std::string aor;

  if (is_user_registered(public_id))
  {
    // User is registered, so look up bindings.  Determine the canonical public
    // ID, and look up the set of associated URIs on the HSS.
    std::vector<std::string> uris;
    bool success = get_associated_uris(public_id, uris);

    if (success &&
        (uris.size() > 0) &&
        (std::find(uris.begin(), uris.end(), public_id) != uris.end()))
    {
      // Take the first associated URI as the AOR.
      aor = uris.front();
    }
    else
    {
      // Failed to get the associated URIs from Homestead.  We'll try to
      // do the registration look-up with the specified target URI - this may
      // fail, but we'll never misroute the call.
      TRC_WARNING("Invalid Homestead response - a user is registered but has no list of "
                  "associated URIs, or is not in its own list of associated URIs");
      aor = public_id;
    }

    // Get the bindings from the store and filter/sort them for the request.
    RegStore::AoR* aor_data = NULL;
    _scscf->get_bindings(aor, &aor_data, trail());

    if ((aor_data != NULL) && (!(aor_data)->bindings().empty()))
    {
      // Retrieved bindings from the store so filter them to an ordered list
      // of targets.
      filter_bindings_to_targets(aor,
                                 aor_data,
                                 req,
                                 pool,
                                 MAX_FORKING,
                                 targets,
                                 trail());
      delete aor_data; aor_data = NULL;
    }
    else
    {
      // Subscriber is registered, but there are no bindings in the store.
      // This indicates an error case - it is likely that de-registration
      // has failed.  Make a SAS log, the call will be rejected with a 480.
      TRC_DEBUG("Public ID %s registered, but 0 bindings in store",
                public_id.c_str());
      SAS::Event event(trail(), SASEvent::SCSCF_NO_BINDINGS, 0);
      event.add_var_param(public_id);
      SAS::report_event(event);
    }
  }
  else
  {
    // Subscriber is not registered.  This is not necessarily an error case,
    // but make a SAS log for clarity.  The call will be rejected with a 480.
    TRC_DEBUG("Public ID %s not registered", public_id.c_str());
    SAS::Event event(trail(), SASEvent::SCSCF_NOT_REGISTERED, 0);
    event.add_var_param(public_id);
    SAS::report_event(event);
  }

  if (targets.empty())
  {
    // No valid target bindings for this request, so reject it.
    pjsip_msg* rsp = create_response(req, PJSIP_SC_TEMPORARILY_UNAVAILABLE);
    send_response(rsp);
    free_msg(req);
  }
  else
  {
    SAS::Event route_to_ues(trail(), SASEvent::SCSCF_ROUTING_TO_UES, 0);
    route_to_ues.add_static_param(targets.size());
    SAS::report_event(route_to_ues);

    // Fork the request to the bindings, and remember the AoR used to query
    // the registration store and the binding identifier for each fork.
    _target_aor = aor;
    for (size_t ii = 0; ii < targets.size(); ++ii)
    {
      // Clone for all but the last request.
      pjsip_msg* to_send = (ii == targets.size() - 1) ? req : clone_request(req);
      pool = get_pool(to_send);

      // Set up the Request URI.
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
      // in case we get a 430 Flow Failed response.
      int fork_id = send_request(to_send);
      _target_bindings.insert(std::make_pair(fork_id, targets[ii].binding_id));
    }
  }
}

/// Gets the subscriber's associated URIs and iFCs for each URI from
/// the HSS and stores cached values. Returns true on success, false on failure.
bool SCSCFSproutletTsx::get_data_from_hss(std::string public_id)
{
  if (!_hss_data_cached)
  {
    std::string req_type = _auto_reg ? HSSConnection::REG : HSSConnection::CALL;
    bool cache_allowed = !_auto_reg;

    // We haven't previous read data from the HSS, so read it now.
    if (_scscf->read_hss_data(public_id,
                              _impi,
                              req_type,
                              cache_allowed,
                              _registered,
                              _uris,
                              _aliases,
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
    TRC_ERROR("Connection to Homestead failed, treating user as unregistered");
    return false;
  }
}


/// Look up the associated URIs for the given public ID, using the cache if
/// possible (and caching them and the iFC otherwise).
/// The uris parameter is only filled in correctly if this function
/// returns true.
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

/// Look up the aliases for the given public ID, using the cache if
/// possible (and caching them and the iFC otherwise).
/// The aliases parameter is only filled in correctly if this function
/// returns true.
bool SCSCFSproutletTsx::get_aliases(std::string public_id,
                                    std::vector<std::string>& aliases)
{
  bool success = get_data_from_hss(public_id);
  if (success)
  {
    aliases = _aliases;
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


/// Record-Route the S-CSCF sproutlet into a dialog.  The parameter passed will
/// be attached to the Record-Route and can be used to recover the billing
/// role that is in use on subsequent in-dialog messages.
void SCSCFSproutletTsx::add_record_route(pjsip_msg* msg,
                                         bool billing_rr,
                                         NodeRole billing_role)
{
  pj_pool_t* pool = get_pool(msg);

  pjsip_route_hdr* rr = NULL;
  if (!_record_routed)
  {
    pjsip_sip_uri* uri = get_reflexive_uri(pool);

    rr = pjsip_rr_hdr_create(pool);
    rr->name_addr.uri = (pjsip_uri*)uri;

    pjsip_msg_insert_first_hdr(msg, (pjsip_hdr*)rr);

    _record_routed = true;
  }
  else
  {
    rr = (pjsip_route_hdr*)pjsip_msg_find_hdr(msg,
                                              PJSIP_H_RECORD_ROUTE,
                                              NULL);
  }

  // Ensure the billing scope flag is set on the RR header.
  if (billing_rr)
  {
    // We've records routed before (either earlier in this function or in a
    // previous call to this function within this transaction).  Therefore the
    // Record-Route header we added then must be present (and must be the top
    // such header).
    assert(rr != NULL);

    pjsip_sip_uri* uri = (pjsip_sip_uri*)rr->name_addr.uri;
    pjsip_param* param = pjsip_param_find(&uri->other_param,
                                          &STR_BILLING_ROLE);
    if (!param)
    {
      param = PJ_POOL_ALLOC_T(pool, pjsip_param);
      pj_strdup(pool, &param->name, &STR_BILLING_ROLE);

      if (billing_role == NODE_ROLE_ORIGINATING)
      {
        pj_strdup(pool, &param->value, &STR_CHARGE_ORIG);
      }
      else
      {
        pj_strdup(pool, &param->value, &STR_CHARGE_TERM);
      }
      pj_list_insert_before(&uri->other_param, param);
    }
  }
}


/// Retrieve the billing role for an in-dialog message.
NodeRole SCSCFSproutletTsx::get_billing_role()
{
  NodeRole role;

  const pjsip_route_hdr* route = route_hdr();
  if ((route != NULL) &&
      (is_uri_reflexive(route->name_addr.uri)))
  {
    pjsip_sip_uri* uri = (pjsip_sip_uri*)route->name_addr.uri;
    pjsip_param* param = pjsip_param_find(&uri->other_param,
                                          &STR_BILLING_ROLE);
    if (param != NULL)
    {
      if (!pj_strcmp(&param->value, &STR_CHARGE_ORIG))
      {
        TRC_INFO("Charging role is originating");
        role = NODE_ROLE_ORIGINATING;
      }
      else if (!pj_strcmp(&param->value, &STR_CHARGE_TERM))
      {
        TRC_INFO("Charging role is terminating");
        role = NODE_ROLE_TERMINATING;
      }
      else
      {
        TRC_WARNING("Unknown charging role %.*s, assume originating",
                    param->value.slen, param->value.ptr);
        role = NODE_ROLE_ORIGINATING;
      }
    }
    else
    {
      TRC_WARNING("No charging role in Route header, assume originating");
      role = NODE_ROLE_ORIGINATING;
    }
  }
  else
  {
    TRC_WARNING("Cannot determine charging role as no Route header, assume originating");
    role = NODE_ROLE_ORIGINATING;
  }

  return role;
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
      TRC_DEBUG("Trigger default_handling=CONTINUED processing");
      SAS::Event bypass_as(trail(), SASEvent::BYPASS_AS, 0);
      SAS::report_event(bypass_as);

      _as_chain_link = _as_chain_link.next();
      pjsip_msg* req = original_request();
      _record_routed = false;
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
      TRC_DEBUG("Trigger default_handling=TERMINATED processing");
      SAS::Event as_failed(trail(), SASEvent::AS_FAILED, 0);
      SAS::report_event(as_failed);

      // Build and send a timeout response upstream.
      pjsip_msg* req = original_request();
      pjsip_msg* rsp = create_response(req,
                                       PJSIP_SC_REQUEST_TIMEOUT);
      free_msg(req);
      send_response(rsp);
    }
  }
}

/// Adds a second P-Asserted-Identity header to a message when required.
///
/// We only add the header to messages for which all of the following is true:
/// - We can't find our Route header or our Route header doesn't contain an
///   ODI token.
/// - There is exactly one P-Asserted-Identity header on the message already.
/// - If that header contains a SIP URI sip:user@example.com, that SIP URI is
///   an alias of the tel URI tel:user. That tel URI is used in the new header.
///   If that header contains a tel URI tel:user, we use the SIP URI
///   sip:user@<homedomain> in the new header.
void SCSCFSproutletTsx::add_second_p_a_i_hdr(pjsip_msg* msg)
{
  const pjsip_route_hdr* hroute = route_hdr();

  if ((hroute != NULL) &&
      (!pj_strncmp(&((pjsip_sip_uri*)hroute->name_addr.uri)->user,
                   &STR_ODI_PREFIX,
                   STR_ODI_PREFIX.slen)))
  {
    // Found our Route header and it contains one of our original dialog
    // identifier (ODI) tokens. No need to add a second P-Asserted-Identity
    // header.
    return;
  }

  // Look for P-Asserted-Identity header.
  pjsip_routing_hdr* asserted_id =
    (pjsip_routing_hdr*)pjsip_msg_find_hdr_by_name(msg,
                                                   &STR_P_ASSERTED_IDENTITY,
                                                   NULL);

  // If we have one and only one P-Asserted-Identity header we may need to add
  // a second one.
  if ((asserted_id != NULL) &&
      (pjsip_msg_find_hdr_by_name(msg,
                                  &STR_P_ASSERTED_IDENTITY,
                                  asserted_id->next) == NULL))
  {
    std::string new_p_a_i_str;
    pjsip_uri* uri = (pjsip_uri*)pjsip_uri_get_uri(&asserted_id->name_addr);

    if (PJSIP_URI_SCHEME_IS_SIP(uri))
    {
      // If we have a SIP URI, we add a second P-Asserted-Identity containing a
      // tel URI if this SIP URI has a tel URI alias.
      new_p_a_i_str = "tel:";
      new_p_a_i_str += PJUtils::pj_str_to_string(&((pjsip_sip_uri*)uri)->user);

      if (find(_aliases.begin(),
               _aliases.end(),
               new_p_a_i_str) != _aliases.end())
      {
        TRC_DEBUG("Add second P-Asserted-Identity for %s", new_p_a_i_str.c_str());
        PJUtils::add_asserted_identity(msg,
                                       get_pool(msg),
                                       new_p_a_i_str,
                                       asserted_id->name_addr.display);
      }
    }
    else if (PJSIP_URI_SCHEME_IS_TEL(uri))
    {
      // If we have a tel URI, we add a second P-Asserted-Identity containg the
      // corresponding SIP URI.
      new_p_a_i_str = "sip:";
      new_p_a_i_str += PJUtils::pj_str_to_string(&((pjsip_tel_uri*)uri)->number);
      new_p_a_i_str += "@";
      new_p_a_i_str += PJUtils::pj_str_to_string(&stack_data.default_home_domain);
      new_p_a_i_str += ";user=phone";
      TRC_DEBUG("Add second P-Asserted-Identity for %s", new_p_a_i_str.c_str());
      PJUtils::add_asserted_identity(msg,
                                     get_pool(msg),
                                     new_p_a_i_str,
                                     asserted_id->name_addr.display);
    }
  }
}

void SCSCFSproutletTsx::sas_log_start_of_sesion_case(pjsip_msg* req,
                                                     const SessionCase* session_case,
                                                     const std::string& served_user)
{
  int event_id;

  if (session_case == &SessionCase::Originating)
  {
    event_id = SASEvent::SCSCF_STARTED_ORIG_PROC;
  }
  else if (session_case == &SessionCase::Terminating)
  {
    event_id = SASEvent::SCSCF_STARTED_TERM_PROC;
  }
  else
  {
    event_id = SASEvent::SCSCF_STARTED_ORIG_CDIV_PROC;
  }

  SAS::Event event(trail(), event_id, 0);
  event.add_var_param(served_user);
  event.add_var_param(req->line.req.method.name.slen,
                      req->line.req.method.name.ptr);
  SAS::report_event(event);
}

ACR* SCSCFSproutletTsx::get_acr()
{
  if (_as_chain_link.is_set())
  {
    return _as_chain_link.acr();
  }
  else if (_in_dialog_acr)
  {
    return _in_dialog_acr;
  }
  else
  {
    return _failed_ood_acr;
  }
}
