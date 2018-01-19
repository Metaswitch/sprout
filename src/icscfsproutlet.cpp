/**
 * @file icscfsproutlet.cpp  I-CSCF sproutlet implementation
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}


#include "log.h"
#include "pjutils.h"
#include "stack.h"
#include "sproutsasevent.h"
#include "icscfsproutlet.h"
#include "scscfselector.h"
#include "constants.h"
#include "uri_classifier.h"
#include "snmp_success_fail_count_by_request_type_table.h"
#include "custom_headers.h"

/// Define a constant for the maximum number of ENUM lookups
/// we want to do in I-CSCF termination processing.
#define MAX_ENUM_LOOKUPS 2

/// Constructor.
ICSCFSproutlet::ICSCFSproutlet(const std::string& icscf_name,
                               const std::string& bgcf_uri,
                               int port,
                               const std::string& uri,
                               const std::string& network_function,
                               const std::string& next_hop_service,
                               HSSConnection* hss,
                               ACRFactory* acr_factory,
                               SCSCFSelector* scscf_selector,
                               EnumService* enum_service,
                               SNMP::SuccessFailCountByRequestTypeTable* incoming_sip_transactions_tbl,
                               SNMP::SuccessFailCountByRequestTypeTable* outgoing_sip_transactions_tbl,
                               bool override_npdi,
                               int network_function_port,
                               std::set<std::string> blacklisted_scscfs) :
  Sproutlet(icscf_name,
            port,
            uri,
            "",
            {},
            incoming_sip_transactions_tbl,
            outgoing_sip_transactions_tbl,
            network_function),
  _bgcf_uri(NULL),
  _next_hop_service(next_hop_service),
  _hss(hss),
  _scscf_selector(scscf_selector),
  _acr_factory(acr_factory),
  _enum_service(enum_service),
  _override_npdi(override_npdi),
  _bgcf_uri_str(bgcf_uri),
  _network_function_port(network_function_port),
  _blacklisted_scscfs(blacklisted_scscfs)
{
  _session_establishment_tbl = SNMP::SuccessFailCountTable::create("icscf_session_establishment",
                                                                   "1.2.826.0.1.1578918.9.3.36");
  _session_establishment_network_tbl = SNMP::SuccessFailCountTable::create("icscf_session_establishment_network",
                                                                           "1.2.826.0.1.1578918.9.3.37");
}


/// Destructor.
ICSCFSproutlet::~ICSCFSproutlet()
{
  delete _session_establishment_tbl;
  delete _session_establishment_network_tbl;
}

bool ICSCFSproutlet::init()
{
  bool init_success = true;

  // Convert the BGCF routing URI to a form suitable for PJSIP, so we're
  // not continually converting from a string.
  _bgcf_uri = PJUtils::uri_from_string(_bgcf_uri_str, stack_data.pool, false);

  // LCOV_EXCL_START - Don't test pjsip URI failures in the I-CSCF UTs
  if (_bgcf_uri == NULL)
  {
    TRC_ERROR("Invalid BGCF URI %s", _bgcf_uri_str.c_str());
    init_success = false;
  }
  // LCOV_EXCL_STOP

  return init_success;
}

/// Creates a ICSCFSproutletTsx instance for performing I-CSCF service processing
/// on a request.
SproutletTsx* ICSCFSproutlet::get_tsx(SproutletHelper* helper,
                                      const std::string& alias,
                                      pjsip_msg* req,
                                      pjsip_sip_uri*& next_hop,
                                      pj_pool_t* pool,
                                      SAS::TrailId trail)
{
  if (req->line.req.method.id == PJSIP_REGISTER_METHOD)
  {
    return (SproutletTsx*)new ICSCFSproutletRegTsx(this, _next_hop_service);
  }
  else
  {
    return (SproutletTsx*)new ICSCFSproutletTsx(this,
                                                _next_hop_service,
                                                req->line.req.method.id);
  }
}

/// Get an ACR instance from the factory.
///
/// @param trail                SAS trail identifier to use for the ACR.
ACR* ICSCFSproutlet::get_acr(SAS::TrailId trail)
{
  return _acr_factory->get_acr(trail,
                               ACR::CALLING_PARTY,
                               ACR::NODE_ROLE_TERMINATING);
}

/// Translates a Tel URI to a SIP URI (if ENUM is enabled).
void ICSCFSproutlet::translate_request_uri(pjsip_msg* req,
                                           pj_pool_t* pool,
                                           SAS::TrailId trail)
{
  PJUtils::translate_request_uri(req,
                                 pool,
                                 _enum_service,
                                 should_override_npdi(),
                                 trail);
}

/*****************************************************************************/
/* REGISTER handling.                                                        */
/*****************************************************************************/

/// Individual Tsx constructor for REGISTER requests.
ICSCFSproutletRegTsx::ICSCFSproutletRegTsx(ICSCFSproutlet* icscf,
                                           const std::string& next_hop_service) :
  CompositeSproutletTsx(icscf, next_hop_service),
  _icscf(icscf),
  _acr(NULL),
  _router(NULL)
{
}


/// REGISTER-handling Tsx destructor (may also cause ACRs to be sent).
ICSCFSproutletRegTsx::~ICSCFSproutletRegTsx()
{
  if (_acr != NULL)
  {
    // Send the ACR for this transaction.
    _acr->send();
  }

  delete _acr;
  delete _router;
}


void ICSCFSproutletRegTsx::on_rx_initial_request(pjsip_msg* req)
{
  // Create an ACR for this transaction.
  _acr = _icscf->get_acr(trail());
  _acr->rx_request(req);

  TRC_DEBUG("I-CSCF initialize transaction for REGISTER request");

  // Extract relevant fields from the message
  std::string impu;
  std::string impi;
  std::string visited_network;
  std::string auth_type;

  // Get the public identity from the To: header.
  pjsip_to_hdr* to_hdr = PJSIP_MSG_TO_HDR(req);
  pjsip_uri* to_uri = (pjsip_uri*)pjsip_uri_get_uri(to_hdr->uri);
  pj_bool_t status = PJUtils::valid_public_id_from_uri(to_uri, impu);

  if (!status)
  {
    // We're unable to get the IMPU from the message - reject it now
    SAS::Event event(trail(), SASEvent::ICSCF_INVALID_IMPU, 0);
    event.add_var_param(PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, to_uri));
    SAS::report_event(event);

    pjsip_msg* rsp = create_response(req, PJSIP_SC_BAD_REQUEST);
    send_response(rsp);
    free_msg(req);
    return;
  }

  SAS::Event reg_event(trail(), SASEvent::ICSCF_RCVD_REGISTER, 0);
  reg_event.add_var_param(impu);
  SAS::report_event(reg_event);

  // Get the private identity from the Authentication header, or generate
  // a default if there is no Authentication header or no username in the
  // header.
  pjsip_authorization_hdr* auth_hdr =
    (pjsip_authorization_hdr*)pjsip_msg_find_hdr(req,
                                                 PJSIP_H_AUTHORIZATION,
                                                 NULL);
  if ((auth_hdr != NULL) &&
      (auth_hdr->credential.digest.username.slen != 0))
  {
    // Get the IMPI from the username.
    impi = PJUtils::pj_str_to_string(&auth_hdr->credential.digest.username);
  }
  else
  {
    // Create a default IMPI from the IMPU by removing the sip: prefix.
    impi = impu.substr(4);
  }

  // Get the visited network identification if present.  If not, warn
  // (because a spec-compliant P-CSCF should default it) and use a
  // sensible default.
  pjsip_generic_string_hdr* vn_hdr =
    (pjsip_generic_string_hdr*)pjsip_msg_find_hdr_by_name(req,
                                                          &STR_P_V_N_I,
                                                          NULL);

  if (vn_hdr != NULL)
  {
    visited_network = PJUtils::pj_str_to_string(&vn_hdr->hvalue);
  }
  else if (PJSIP_URI_SCHEME_IS_SIP(to_uri) || PJSIP_URI_SCHEME_IS_SIPS(to_uri))
  {
    // Use the domain of the IMPU as the visited network.
    visited_network = PJUtils::pj_str_to_string(&((pjsip_sip_uri*)to_uri)->host);
    TRC_WARNING("No P-Visited-Network-ID in REGISTER - using %s as a default",
                visited_network.c_str());
  }

  // Work out what authorization type to use by looking at the expiry
  // values in the request.  (Use a default of 1 because if there is no
  // expires header or expires values in the contact headers this will
  // be a registration not a deregistration.)
  auth_type = PJUtils::is_deregistration(req) ? "DEREG" : "REG";

  // Remove any Route headers present on the request as we're re-routing the
  // message.
  pj_str_t route_hdr_name = pj_str((char *)"Route");
  PJUtils::remove_hdr(req, &route_hdr_name);

  // Check if this is an emergency registration. This is true if any of the
  // contact headers in the message contain the "sos" parameter.
  bool emergency = false;
  pjsip_contact_hdr* contact_hdr = (pjsip_contact_hdr*)pjsip_msg_find_hdr(req,
                                                                          PJSIP_H_CONTACT,
                                                                          NULL);
  while (contact_hdr != NULL)
  {
    if (PJUtils::is_emergency_registration(contact_hdr))
    {
      emergency = true;
      break;
    }

    contact_hdr = (pjsip_contact_hdr*) pjsip_msg_find_hdr(req,
                                                          PJSIP_H_CONTACT,
                                                          contact_hdr->next);
  }

  // Create an UAR router to handle the HSS interactions and S-CSCF
  // selection.
  _router = (ICSCFRouter*)new ICSCFUARouter(_icscf->get_hss_connection(),
                                            _icscf->get_scscf_selector(),
                                            trail(),
                                            _acr,
                                            _icscf->network_function_port(),
                                            impi,
                                            impu,
                                            visited_network,
                                            auth_type,
                                            emergency,
                                            _icscf->_blacklisted_scscfs);

  // We have a router, query it for an S-CSCF to use.
  pjsip_sip_uri* scscf_sip_uri = NULL;
  std::string dummy_wildcard;
  pjsip_status_code status_code =
    (pjsip_status_code)_router->get_scscf(get_pool(req),
                                          scscf_sip_uri,
                                          dummy_wildcard);

  if (status_code == PJSIP_SC_OK)
  {
    TRC_DEBUG("Found SCSCF for REGISTER");
    req->line.req.uri = (pjsip_uri*)scscf_sip_uri;
    send_request(req);
  }
  else
  {
    pjsip_msg* rsp = create_response(req, status_code);
    send_response(rsp);
    free_msg(req);
  }
}


// LCOV_EXCL_START - Excluding from UTs as this is a scenario that shouldn't
// happen
void ICSCFSproutletRegTsx::on_rx_in_dialog_request(pjsip_msg* req)
{
  // I-CSCF shouldn't need to handle in-dialog requests, but it happens, so
  // handle as an initial request.
  on_rx_initial_request(req);
}
// LCOV_EXCL_STOP

void ICSCFSproutletRegTsx::on_tx_request(pjsip_msg* req, int fork_id)
{
  if (_acr != NULL)
  {
    // Pass the transmitted request to the ACR to update the accounting
    // information.
    _acr->tx_request(req);
  }
}


void ICSCFSproutletRegTsx::on_rx_response(pjsip_msg* rsp, int fork_id)
{
  if (_acr != NULL)
  {
    // Pass the received response to the ACR.
    // @TODO - timestamp from response???
    _acr->rx_response(rsp);
  }

  // Check if this response is one that we are allowed to retry the HSS lookup
  // for.  See TS 24.229 - section 5.3.1.3.
  //
  // Note we support service restoration, so integrity-protected settings in
  // Authorization header are immaterial).
  pjsip_status_code rsp_status = (pjsip_status_code)rsp->line.status.code;
  const ForkState& fork_status = fork_state(fork_id);
  TRC_DEBUG("Check retry conditions for REGISTER, status = %d, S-CSCF %sresponsive",
            rsp_status,
            (fork_status.error_state != NONE) ? "not " : "");
  if ((PJSIP_IS_STATUS_IN_CLASS(rsp_status, 300)) ||
      (fork_status.error_state != NONE) ||
      (rsp_status == PJSIP_SC_TEMPORARILY_UNAVAILABLE))
  {
    // Indeed it is, first log to SAS.
    TRC_DEBUG("Attempt retry to alternate S-CSCF for REGISTER request");
    std::string st_code = std::to_string(rsp_status);
    SAS::Event event(trail(), SASEvent::SCSCF_RETRY, 0);
    std::string method = "REGISTER";
    event.add_var_param(method);
    event.add_var_param(st_code);
    SAS::report_event(event);

    // Now we can simply reuse the UA router we made on the initial request.
    pjsip_sip_uri* scscf_sip_uri = NULL;
    pjsip_msg* req = original_request();
    std::string wildcard;
    int status_code = _router->get_scscf(get_pool(req), scscf_sip_uri, wildcard);

    if (status_code == PJSIP_SC_OK)
    {
      TRC_DEBUG("Found SCSCF for REGISTER");

      req->line.req.uri = (pjsip_uri*)scscf_sip_uri;
      send_request(req);

      // We're not forwarding this response upstream.
      free_msg(rsp);
    }
    else
    {
      // In the register case the spec's are quite particular about how
      // failures are reported.
      if (status_code == PJSIP_SC_FORBIDDEN)
      {
        // The HSS has returned a negative response to the user registration
        // request - I-CSCF should respond with 403.
        rsp->line.status.code = PJSIP_SC_FORBIDDEN;
        rsp->line.status.reason =
          *pjsip_get_status_text(rsp->line.status.code);
      }
      else
      {
        // The I-CSCF can't select an S-CSCF for the REGISTER request (either
        // because there are no more S-CSCFs that meet the mandatory
        // capabilitires, or the HSS is temporarily unavailable). There was at
        // least one valid S-CSCF (as this is retry processing). The I-CSCF
        // must return 504 (TS 24.229, 5.3.1.3) in this case.
        rsp->line.status.code = PJSIP_SC_SERVER_TIMEOUT;
        rsp->line.status.reason =
          *pjsip_get_status_text(rsp->line.status.code);
      }

      // We're done, no more retries.
      free_msg(req);
      send_response(rsp);
    }
  }
  else
  {
    // Provisional, successful or non-retryable response, simply forward on
    // upstream.  If this is a final response, there will be no more retries.
    send_response(rsp);
  }
}


void ICSCFSproutletRegTsx::on_tx_response(pjsip_msg* rsp)
{
  if (_acr != NULL)
  {
    // Pass the transmitted response to the ACR to update the accounting
    // information.
    _acr->tx_response(rsp);
  }
}

/*****************************************************************************/
/* Non-REGISTER handling.                                                    */
/*****************************************************************************/

/// Individual Tsx constructor for non-REGISTER requests.
ICSCFSproutletTsx::ICSCFSproutletTsx(ICSCFSproutlet* icscf,
                                     const std::string& next_hop_service,
                                     pjsip_method_e req_type) :
  CompositeSproutletTsx(icscf, next_hop_service),
  _icscf(icscf),
  _acr(NULL),
  _router(NULL),
  _originating(false),
  _routed_to_bgcf(false),
  _req_type(req_type),
  _session_set_up(false)
{
}


/// REGISTER-handling Tsx destructor (may also cause ACRs to be sent).
ICSCFSproutletTsx::~ICSCFSproutletTsx()
{
  if (_acr != NULL)
  {
    _acr->send();
    delete _acr;
  }

  if (_router != NULL)
  {
    delete _router;
  }
}


void ICSCFSproutletTsx::on_rx_initial_request(pjsip_msg* req)
{
  pj_pool_t* pool = get_pool(req);

  pjsip_route_hdr* hroute = (pjsip_route_hdr*)
                                pjsip_msg_find_hdr(req, PJSIP_H_ROUTE, NULL);

  // TS 24.229 says I-CSCF processing shouldn't be done if a message has more than one Route header.
  // We've stripped one off in Sproutlet processing, so check for a second and just forward the
  // message if it's there.
  if (hroute != NULL)
  {
    send_request(req);
    return;
  }

  pjsip_uri* next_hop = PJUtils::next_hop(req);
  URIClass next_hop_class = URIClassifier::classify_uri(next_hop);
  if (req->line.req.method.id == PJSIP_ACK_METHOD &&
      next_hop == req->line.req.uri &&
      ((next_hop_class == NODE_LOCAL_SIP_URI) ||
       (next_hop_class == HOME_DOMAIN_SIP_URI)))
  {
    // Ignore ACK messages with no Route headers and a local Request-URI, as:
    // - the I-CSCF should not be handling these
    // - we've seen ACKs matching this descrption being generated at overload and looping repeatedly
    //
    // This is a fairly targeted fix for https://github.com/Metaswitch/sprout/issues/1091.
    // TODO: remove this code when #1091 is fixed by other means.
    free_msg(req);
    return;
  }

  // Create an ACR for this transaction.
  _acr = _icscf->get_acr(trail());
  _acr->rx_request(req);

  TRC_DEBUG("I-CSCF initialize transaction for non-REGISTER request");

  // Before we clone the request for retries, remove the P-Profile-Key header
  // if present.
  PJUtils::remove_hdr(req, &STR_P_PROFILE_KEY);

  // Determine orig/term and the served user's name.
  const pjsip_route_hdr* route = route_hdr();
  std::string impu;

  if ((route != NULL) &&
      (pjsip_param_find(&((pjsip_sip_uri*)route->name_addr.uri)->other_param,
                        &STR_ORIG) != NULL))
  {
    // Originating request.
    TRC_DEBUG("Originating request");
    _originating = true;

    pjsip_uri* orig_uri = PJUtils::orig_served_user(req, pool, trail());
    pj_bool_t status = PJUtils::valid_public_id_from_uri(orig_uri, impu);

    if (!status)
    {
      // We're unable to get the IMPU from the message - reject it now
      SAS::Event event(trail(), SASEvent::ICSCF_INVALID_IMPU, 1);
      event.add_var_param(PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, orig_uri));
      SAS::report_event(event);

      pjsip_msg* rsp = create_response(req, PJSIP_SC_BAD_REQUEST);
      send_response(rsp);
      free_msg(req);
      return;
    }

    SAS::Event event(trail(), SASEvent::ICSCF_RCVD_ORIG_NON_REG, 0);
    event.add_var_param(impu);
    event.add_var_param(req->line.req.method.name.slen,
                        req->line.req.method.name.ptr);
    SAS::report_event(event);
  }
  else
  {
    // Terminating request.
    TRC_DEBUG("Terminating request");
    _originating = false;
    pjsip_uri* uri = PJUtils::term_served_user(req);

    // If the Req URI is a SIP URI with the user=phone parameter set, is not a
    // GRUU and the user part starts with '+' (i.e. is a global phone number),
    // we should replace it with a tel URI, as per TS24.229 5.3.2.1.
    if (PJSIP_URI_SCHEME_IS_SIP(uri))
    {
      URIClass uri_class = URIClassifier::classify_uri(uri);
      pjsip_sip_uri* sip_uri = (pjsip_sip_uri*)uri;

      if (uri_class == GLOBAL_PHONE_NUMBER)
      {
        TRC_DEBUG("Change request URI from SIP URI to tel URI");
        req->line.req.uri =
          PJUtils::translate_sip_uri_to_tel_uri(sip_uri, pool);
      }
    }

    pjsip_uri* term_uri = PJUtils::term_served_user(req);
    pj_bool_t status = PJUtils::valid_public_id_from_uri(term_uri, impu);

    if (!status)
    {
      // We're unable to get the IMPU from the message - reject it now
      SAS::Event event(trail(), SASEvent::ICSCF_INVALID_IMPU, 2);
      event.add_var_param(PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, term_uri));
      SAS::report_event(event);

      pjsip_msg* rsp = create_response(req, PJSIP_SC_BAD_REQUEST);
      send_response(rsp);
      free_msg(req);
      return;
    }

    SAS::Event event(trail(), SASEvent::ICSCF_RCVD_TERM_NON_REG, 0);
    event.add_var_param(impu);
    event.add_var_param(req->line.req.method.name.slen,
                        req->line.req.method.name.ptr);
    SAS::report_event(event);
  }

  // Create an LIR router to handle the HSS interactions and S-CSCF
  // selection.
  _router = (ICSCFRouter*)new ICSCFLIRouter(_icscf->get_hss_connection(),
                                            _icscf->get_scscf_selector(),
                                            trail(),
                                            _acr,
                                            _icscf->network_function_port(),
                                            impu,
                                            _originating);

  pjsip_sip_uri* scscf_sip_uri = NULL;

  // Use the router we just created to query the HSS for an S-CSCF to use.
  // TS 32.260 Table 5.2.1.1 says an EVENT ACR should be generated on the
  // completion of a Cx query issued in response to a SIP INVITE
  bool do_billing = (req->line.req.method.id == PJSIP_INVITE_METHOD);
  std::string wildcard;
  pjsip_status_code status_code =
    (pjsip_status_code)_router->get_scscf(pool,
                                          scscf_sip_uri,
                                          wildcard,
                                          do_billing);

  if ((!_originating) && (scscf_not_found(status_code)))
  {
    TRC_DEBUG("Couldn't find an S-CSCF, attempt to translate the URI");
    pjsip_uri* uri = PJUtils::term_served_user(req);
    URIClass uri_class = URIClassifier::classify_uri(uri, false);

    // For terminating processing, if the HSS indicates that the user does not
    // exist, and if the request URI is a tel URI, try an ENUM translation. If
    // this succeeds, go back to the HSS. See TS24.229, 5.3.2.1.
    //
    // Before doing that we should check whether the enforce_user_phone flag is
    // set. If it isn't, and we have a numeric SIP URI, it is possible that
    // this should have been a tel URI, so translate it and do the HSS lookup
    // again.  Once again, only do this for global numbers.
    if (PJSIP_URI_SCHEME_IS_SIP(uri) && (uri_class == GLOBAL_PHONE_NUMBER))
    {
      TRC_DEBUG("enforce_user_phone set to false, try using a tel URI");
      uri = PJUtils::translate_sip_uri_to_tel_uri((pjsip_sip_uri*)uri, pool);
      req->line.req.uri = uri;

      // We need to change the IMPU stored on our LIR router so that when
      // we do a new LIR we look up the new IMPU.
      impu = PJUtils::public_id_from_uri(PJUtils::term_served_user(req));
      ((ICSCFLIRouter *)_router)->change_impu(impu);
      status_code = (pjsip_status_code)_router->get_scscf(pool,
                                                          scscf_sip_uri,
                                                          wildcard,
                                                          do_billing);
    }

    if (_icscf->_enum_service)
    {
      // If we still haven't found an S-CSCF, we can now try an ENUM lookup.
      // We put this processing in a loop because in theory we may go round
      // several times before finding an S-CSCF. In reality this is unlikely
      // so we set MAX_ENUM_LOOKUPS to 2.
      for (int ii = 0;
           (ii < MAX_ENUM_LOOKUPS) && (scscf_not_found(status_code));
           ++ii)
      {
        if (PJSIP_URI_SCHEME_IS_TEL(uri))
        {
          // Do an ENUM lookup and see if we should translate the TEL URI
          pjsip_uri* original_req_uri = req->line.req.uri;
          _icscf->translate_request_uri(req, get_pool(req), trail());
          uri = req->line.req.uri;
          URIClass uri_class = URIClassifier::classify_uri(uri, false, true);

          std::string rn;

          if ((uri_class == NP_DATA) ||
              (uri_class == FINAL_NP_DATA))
          {
            // We got number portability information from ENUM - drop out and route to the BGCF.
            route_to_bgcf(req);
            return;
          }
          else if (pjsip_uri_cmp(PJSIP_URI_IN_REQ_URI,
                                 original_req_uri,
                                 req->line.req.uri) != PJ_SUCCESS)
          {
            // The URI has changed, so make sure we do a LIR lookup on it.
            pj_bool_t status =
                     PJUtils::valid_public_id_from_uri(req->line.req.uri, impu);

            if (!status)
            {
              // We're unable to get the IMPU from the message - reject it now
              SAS::Event event(trail(), SASEvent::ICSCF_INVALID_IMPU, 3);
              event.add_var_param(PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, req->line.req.uri));
              SAS::report_event(event);

              pjsip_msg* rsp = create_response(req, PJSIP_SC_BAD_REQUEST);
              send_response(rsp);
              free_msg(req);
              return;
            }

            ((ICSCFLIRouter *)_router)->change_impu(impu);
          }

          // If we successfully translate the req URI and end up with either another TEL URI or a
          // local SIP URI, we should look for an S-CSCF again.
          if ((uri_class == LOCAL_PHONE_NUMBER) ||
              (uri_class == GLOBAL_PHONE_NUMBER) ||
              (uri_class == HOME_DOMAIN_SIP_URI))
          {
            // TEL or local SIP URI.  Look up the S-CSCF again.
            status_code = (pjsip_status_code)_router->get_scscf(pool,
                                                                scscf_sip_uri,
                                                                wildcard,
                                                                do_billing);
          }
          else
          {
            // Number translated to off-switch.  Drop out of the loop.
            ii = MAX_ENUM_LOOKUPS;
          }
        }
        else
        {
          // Can't translate the number, skip to the end of the loop.
          ii = MAX_ENUM_LOOKUPS;
        }
      }
    }
    else
    {
      // The user is not in the HSS and ENUM is not configured. TS 24.229
      // says that, as an alternative to ENUM, we can "forward the request to
      // the transit functionality for subsequent routeing". Let's do that
      // (currently, we assume the BGCF is the transit functionality, but that
      // may be made configurable in future).
      TRC_DEBUG("No ENUM service available - outing request directly to transit function (BGCF)");
      route_to_bgcf(req);
      return;
    }
  }

  URIClass uri_class = URIClassifier::classify_uri(req->line.req.uri);
  if (status_code == PJSIP_SC_OK)
  {
    TRC_DEBUG("Found SCSCF for non-REGISTER");

    if (_originating)
    {
      // Add the `orig` parameter.
      pjsip_param* orig_param = PJ_POOL_ALLOC_T(get_pool(req), pjsip_param);
      pj_strdup(get_pool(req), &orig_param->name, &STR_ORIG);
      orig_param->value.slen = 0;
      pj_list_insert_after(&scscf_sip_uri->other_param, orig_param);
    }

    // Add the P-Profile-Key header here if we've got a wildcard
    if (wildcard != "")
    {
      add_p_profile_header(wildcard, req);
    }

    PJUtils::add_route_header(req, scscf_sip_uri, get_pool(req));

    // We might be invoking a directly attached AS here, so we should log the
    // ICID if it exists
    PJUtils::mark_icid(trail(), req);

    send_request(req);
  }
  else if ((uri_class == OFFNET_SIP_URI) ||
           (uri_class == GLOBAL_PHONE_NUMBER))
  {
    // Target is a TEL URI or not in our home domain.  Pass to the BGCF.
    route_to_bgcf(req);
  }
  else
  {
    // Target is in our home domain, but we failed to find an S-CSCF. This is the final response.
    pjsip_msg* rsp = create_response(req, status_code);
    send_response(rsp);
    free_msg(req);
  }
}

// LCOV_EXCL_START - Excluding from UTs as this is a scenario that shouldn't
// happen
void ICSCFSproutletTsx::on_rx_in_dialog_request(pjsip_msg* req)
{
  // I-CSCF shouldn't need to handle in-dialog requests, but it happens, so
  // handle as an initial request.
  on_rx_initial_request(req);
}
// LCOV_EXCL_STOP

void ICSCFSproutletTsx::on_tx_request(pjsip_msg* req, int fork_id)
{
  if (_acr != NULL)
  {
    // Pass the transmitted request to the ACR to update the accounting
    // information.
    _acr->tx_request(req);
  }
}


void ICSCFSproutletTsx::on_rx_response(pjsip_msg* rsp, int fork_id)
{
  if (_acr != NULL)
  {
    // Pass the received response to the ACR.
    // @TODO - timestamp from response???
    _acr->rx_response(rsp);
  }

  // Check if this response is one that we are allowed to retry the HSS lookup
  // for.  See TS 24.229 - section 5.3.2.2.
  //
  // Note we support service restoration, so integrity-protected settings in
  // Authorization header are immaterial.
  //
  // Note also that we can never retry once we've routed to the BGCF.
  pjsip_status_code rsp_status = (pjsip_status_code)rsp->line.status.code;
  const ForkState& fork_status = fork_state(fork_id);
  TRC_DEBUG("Check retry conditions for non-REGISTER, S-CSCF %sresponsive",
            (fork_status.error_state != NONE) ? "not " : "");
  if ((!_routed_to_bgcf) &&
      (fork_status.error_state != NONE))
  {
    // Indeed it it, first log to SAS.
    TRC_DEBUG("Attempt retry to alternate S-CSCF for non-REGISTER request");
    std::string st_code = std::to_string(rsp_status);
    SAS::Event event(trail(), SASEvent::SCSCF_RETRY, 0);
    std::string method = "non-REGISTER";
    event.add_var_param(method);
    event.add_var_param(st_code);
    SAS::report_event(event);

    // Now we can simply reuse the UA router we made on the initial request.
    pjsip_sip_uri* scscf_sip_uri = NULL;
    pjsip_msg* req = original_request();
    pj_pool_t* pool = get_pool(req);

    // TS 32.260 Table 5.2.1.1 says an EVENT ACR should be generated on the
    // completion of a Cx query issued in response to a SIP INVITE. It's
    // ambiguous on whether this should be sent on each Cx query completion
    // so we err on the side of over-sending events.
    bool do_billing = (rsp->line.req.method.id == PJSIP_INVITE_METHOD);
    std::string wildcard;
    int status_code = _router->get_scscf(pool,
                                         scscf_sip_uri,
                                         wildcard,
                                         do_billing);

    if (status_code == PJSIP_SC_OK)
    {
      TRC_DEBUG("Found SCSCF for non-REGISTER");

      if (_originating)
      {
        // Add the `orig` parameter.
        pjsip_param* orig_param = PJ_POOL_ALLOC_T(pool, pjsip_param);
        pj_strdup(pool, &orig_param->name, &STR_ORIG);
        orig_param->value.slen = 0;
        pj_list_insert_after(&scscf_sip_uri->other_param, orig_param);
      }

      // Add the P-Profile-Key header here if we've got a wildcard
      if (wildcard != "")
      {
        add_p_profile_header(wildcard, req);
      }

      PJUtils::add_route_header(req, scscf_sip_uri, pool);
      send_request(req);

      // We're not forwarding this response upstream.
      free_msg(rsp);
    }
    else
    {
      free_msg(req);
      send_response(rsp);
    }
  }
  else
  {
    // Provisional, successful or non-retryable response, simply forward on
    // upstream.
    send_response(rsp);
  }
}


void ICSCFSproutletTsx::on_tx_response(pjsip_msg* rsp)
{
  if (_acr != NULL)
  {
    // Pass the transmitted response to the ACR to update the accounting
    // information.
    _acr->tx_response(rsp);
  }

  pjsip_status_code rsp_status = (pjsip_status_code)rsp->line.status.code;

  // Check if this is a terminating INVITE.  If it is then check whether we need
  // to update our session establishment stats.  We consider the session to be
  // set up as soon as we receive a final response OR a 180 Ringing (per TS
  // 32.409).
  if (!_originating &&
      (_req_type == PJSIP_INVITE_METHOD) &&
      !_session_set_up &&
      ((rsp_status == PJSIP_SC_RINGING) ||
       !PJSIP_IS_STATUS_IN_CLASS(rsp_status, 100)))
  {
    // Session is now set up.
    _session_set_up = true;
    _icscf->_session_establishment_tbl->increment_attempts();
    _icscf->_session_establishment_network_tbl->increment_attempts();

    if ((rsp_status == PJSIP_SC_RINGING) ||
         PJSIP_IS_STATUS_IN_CLASS(rsp_status, 200))
    {
      // Session has been set up successfully.
      TRC_DEBUG("Session successful");
      _icscf->_session_establishment_tbl->increment_successes();
      _icscf->_session_establishment_network_tbl->increment_successes();
    }
    else if ((rsp_status == PJSIP_SC_BUSY_HERE) ||
             (rsp_status == PJSIP_SC_BUSY_EVERYWHERE) ||
             (rsp_status == PJSIP_SC_NOT_FOUND) ||
             (rsp_status == PJSIP_SC_ADDRESS_INCOMPLETE))
    {
      // Session failed, but should be counted as successful from a network
      // perspective.
      TRC_DEBUG("Session failed but network successful");
      _icscf->_session_establishment_tbl->increment_failures();
      _icscf->_session_establishment_network_tbl->increment_successes();
    }
    else
    {
      // Session establishment failed.
      TRC_DEBUG("Session failed");
      _icscf->_session_establishment_tbl->increment_failures();
      _icscf->_session_establishment_network_tbl->increment_failures();
    }
  }

}


void ICSCFSproutletTsx::on_rx_cancel(int status_code, pjsip_msg* cancel_req)
{
  // If this is cancelling a terminating INVITE then check whether we need to
  // update our session establishment stats.
  if (!_originating &&
      (_req_type == PJSIP_INVITE_METHOD) &&
      (!_session_set_up))
  {
    // Session has failed to establish but for a reason that is not the fault
    // of the network.
    _icscf->_session_establishment_tbl->increment_attempts();
    _icscf->_session_establishment_tbl->increment_failures();
    _icscf->_session_establishment_network_tbl->increment_attempts();
    _icscf->_session_establishment_network_tbl->increment_successes();

    // Set _session_set_up to true so that we don't count this session again
    // when we receive the subsequent final response.
    _session_set_up = true;
  }

  if ((status_code == PJSIP_SC_REQUEST_TERMINATED) &&
      (cancel_req != NULL))
  {
    // Create and send an ACR for the CANCEL request.
    ACR* acr = _icscf->get_acr(trail());

    // @TODO - timestamp from request.
    acr->rx_request(cancel_req);
    acr->send();

    delete acr;
  }
}

/// Route the request to the BGCF.
void ICSCFSproutletTsx::route_to_bgcf(pjsip_msg* req)
{
  TRC_INFO("Routing to BGCF %s",
           PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                  _icscf->bgcf_uri()).c_str());
  PJUtils::add_route_header(req,
                            (pjsip_sip_uri*)pjsip_uri_clone(get_pool(req),
                                                            _icscf->bgcf_uri()),
                            get_pool(req));
  send_request(req);
  _routed_to_bgcf = true;
}

void ICSCFSproutletTsx::add_p_profile_header(const std::string& wildcard,
                                             pjsip_msg* req)
{
  // The wildcard can contain characters that aren't valid in
  // URIs (e.g. square brackets) - escape these before attempting to
  // create a URI.
  pjsip_routing_hdr* ppk = identity_hdr_create(get_pool(req),
                                               STR_P_PROFILE_KEY);
  pjsip_uri* wildcard_uri = PJUtils::uri_from_string(
                                   PJUtils::escape_string_for_uri(wildcard),
                                   get_pool(req));

  if (wildcard_uri)
  {
    TRC_DEBUG("Adding a P-Profile-Key header for %s", wildcard.c_str());
    ppk->name_addr.uri = wildcard_uri;
    pjsip_msg_add_hdr(req, (pjsip_hdr*)ppk);
  }
  else
  {
    // LCOV_EXCL_START - Don't test pjsip URI failures in the I-CSCF UTs
    TRC_ERROR("Invalid wildcard returned on LIA: %s", wildcard.c_str());
    // LCOV_EXCL_STOP
  }
}
