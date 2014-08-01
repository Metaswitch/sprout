/**
 * @file icscfsproutlet.cpp  I-CSCF sproutlet implementation
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
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


extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}


#include "log.h"
#include "pjutils.h"
#include "sproutsasevent.h"
#include "icscfsproutlet.h"
#include "scscfselector.h"
#include "constants.h"


/// Constructor.
ICSCFSproutlet::ICSCFSproutlet(HSSConnection* hss,
                               ACRFactory* acr_factory,
                               SCSCFSelector* scscf_selector) :
  Sproutlet("icscf"),
  _hss(hss),
  _scscf_selector(scscf_selector),
  _acr_factory(acr_factory)
{
}


/// Destructor.
ICSCFSproutlet::~ICSCFSproutlet()
{
}

/// Creates a ICSCFSproutletTsx instance for performing BGCF service processing
/// on a request.
SproutletTsx* ICSCFSproutlet::get_app_tsx(SproutletTsxHelper* helper, pjsip_msg* req)
{
  if (req->line.req.method.id == PJSIP_REGISTER_METHOD)
  {
    return (SproutletTsx*)new ICSCFSproutletRegTsx(helper, this);
  }
  else
  {
    return (SproutletTsx*)new ICSCFSproutletTsx(helper, this);
  }
}

/// Get an ACR instance from the factory.
///
/// @param trail                SAS trail identifier to use for the ACR.
ACR* ICSCFSproutlet::get_acr(SAS::TrailId trail)
{
  return _acr_factory->get_acr(trail, CALLING_PARTY, NODE_ROLE_TERMINATING);
}

/*****************************************************************************/
/* REGISTER handling.                                                        */
/*****************************************************************************/

/// Individual Tsx constructor for REGISTER requests.
ICSCFSproutletRegTsx::ICSCFSproutletRegTsx(SproutletTsxHelper* helper,
                                           ICSCFSproutlet* icscf) :
  SproutletTsx(helper),
  _icscf(icscf),
  _acr(NULL)
{
}


/// REGISTER-handling Tsx destructor (may also cause ACRs to be sent).
ICSCFSproutletRegTsx::~ICSCFSproutletRegTsx()
{
  delete _acr;
}


void ICSCFSproutletRegTsx::on_rx_initial_request(pjsip_msg* req)
{
  // Create an ACR for this transaction.
  _acr = _icscf->get_acr(trail());
  _acr->rx_request(req);

  LOG_DEBUG("I-CSCF initialize transaction for REGISTER request");

  // Since we may retry the request on a negative response, clone the original
  // request now.
  _cloned_req = clone_request(req);

  // Extract relevant fields from the message
  std::string impu;
  std::string impi;
  std::string visited_network;
  std::string auth_type;

  // Get the public identity from the To: header.
  pjsip_to_hdr* to_hdr = PJSIP_MSG_TO_HDR(req);
  pjsip_uri* to_uri = (pjsip_uri*)pjsip_uri_get_uri(to_hdr->uri);
  impu = PJUtils::public_id_from_uri(to_uri);

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

  // Get the visted network identification if present.  If not, homestead will
  // default it.
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
  }

  // Work out what authorization type to use by looking at the expiry
  // values in the request.  (Use a default of 1 because if there is no
  // expires header or expires values in the contact headers this will
  // be a registration not a deregistration.)
  auth_type = (PJUtils::max_expires(req, 1) > 0) ? "REG" : "DEREG";

  // Create an UAR router to handle the HSS interactions and S-CSCF
  // selection.
  _router = (ICSCFRouter*)new ICSCFUARouter(_icscf->get_hss_connection(),
                                            _icscf->get_scscf_selector(),
                                            trail(),
                                            _acr,
                                            impi,
                                            impu,
                                            visited_network,
                                            auth_type);

  // We have a router, query it for an S-CSCF to use.
  pjsip_sip_uri* scscf_sip_uri = NULL;
  pjsip_status_code status_code =
    (pjsip_status_code)_router->get_scscf(get_pool(req), scscf_sip_uri);

  if (status_code == PJSIP_SC_OK)
  {
    LOG_DEBUG("Found SCSCF for REGISTER");
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


void ICSCFSproutletRegTsx::on_tx_request(pjsip_msg* req)
{
  // Pass the transmitted request to the ACR to update the accounting
  // information.
  _acr->tx_request(req);
}


void ICSCFSproutletRegTsx::on_rx_response(pjsip_msg* rsp, int fork_id)
{
  // Pass the received response to the ACR.
  // @TODO - timestamp from response???
  _acr->rx_response(rsp);

  // Check if this reqponse is one that we are allowed to retry the HSS lookup
  // for.  See TS 24.229 - section 5.3.1.3.
  //
  // Note we support service restoration, so integrity-protected settings in
  // Authorization header are immaterial).
  pjsip_status_code rsp_status = (pjsip_status_code)rsp->line.status.code;
  LOG_DEBUG("Check retry conditions for REGISTER request, status code = %d",
            rsp_status);
  if ((rsp_status >= 300) && 
      ((rsp_status <= 399) ||
       (rsp_status == PJSIP_SC_REQUEST_TIMEOUT) ||
       (rsp_status == PJSIP_SC_TEMPORARILY_UNAVAILABLE)))
  {
    // Indeed it is, first log to SAS.
    LOG_DEBUG("Attempt retry to alternate S-CSCF for REGISTER request");
    std::string st_code = std::to_string(rsp_status);
    SAS::Event event(trail(), SASEvent::SCSCF_RETRY, 0);
    std::string method = "REGISTER";
    event.add_var_param(method);
    event.add_var_param(st_code);
    SAS::report_event(event);

    // Now we can simply reuse the UA router we made on the initial request.
    pjsip_sip_uri* scscf_sip_uri = NULL;
    int status_code = _router->get_scscf(get_pool(_cloned_req), scscf_sip_uri);

    if (status_code == PJSIP_SC_OK)
    {
      LOG_DEBUG("Found SCSCF for REGISTER");

      // Re-clone the request for future retries.
      pjsip_msg* tmp_clone = clone_request(_cloned_req);

      // Send the old clone as a new fork and save off the new clone.
      _cloned_req->line.req.uri = (pjsip_uri*)scscf_sip_uri;
      send_request(_cloned_req);
      _cloned_req = tmp_clone;

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
      free_msg(_cloned_req);
      send_response(rsp);
    }
  }
  else
  {
    // Provisional, successful or non-retryable response, simply forward on
    // upstream.  If this is a final response, there will be no more retries.
    if (rsp_status >= 200)
    {
      free_msg(_cloned_req);
    }
    send_response(rsp);
  }
}


void ICSCFSproutletRegTsx::on_tx_response(pjsip_msg* rsp) 
{
  // Pass the transmitted response to the ACR to update the accounting
  // information.
  _acr->tx_response(rsp);
}


void ICSCFSproutletRegTsx::on_cancel(int status_code, pjsip_msg* cancel_req)
{
  if ((status_code == PJSIP_SC_REQUEST_TERMINATED) &&
      (cancel_req != NULL))
  {
    // Create and send an ACR for the CANCEL request.
    ACR* acr = _icscf->get_acr(trail());

    // @TODO - timestamp from request.
    acr->rx_request(cancel_req);
    acr->send_message();

    delete acr;
  }
}

/*****************************************************************************/
/* Non-REGISTER handling.                                                    */
/*****************************************************************************/

/// Individual Tsx constructor for non-REGISTER requests.
ICSCFSproutletTsx::ICSCFSproutletTsx(SproutletTsxHelper* helper,
                                     ICSCFSproutlet* icscf) :
  SproutletTsx(helper),
  _icscf(icscf),
  _acr(NULL)
{
}


/// REGISTER-handling Tsx destructor (may also cause ACRs to be sent).
ICSCFSproutletTsx::~ICSCFSproutletTsx()
{
  delete _acr;
}


void ICSCFSproutletTsx::on_rx_initial_request(pjsip_msg* req)
{
  // Create an ACR for this transaction.
  _acr = _icscf->get_acr(trail());
  _acr->rx_request(req);

  LOG_DEBUG("I-CSCF initialize transaction for non-REGISTER request");

  // Before we clone the request for retries, remove the P-Profile-Key header
  // if present.
  PJUtils::remove_hdr(req, &STR_P_PROFILE_KEY);

  // Since we may retry the request on a negative response, clone the original
  // request now.
  _cloned_req = clone_request(req);

  // Determine orig/term and the served user's name.
  pjsip_route_hdr* route = (pjsip_route_hdr*)pjsip_msg_find_hdr(req,
                                                                PJSIP_H_ROUTE,
                                                                NULL);
  std::string impu;

  if ((route != NULL) &&
      (pjsip_param_find(&((pjsip_sip_uri*)route->name_addr.uri)->other_param,
                        &STR_ORIG) != NULL))
  {
    // Originating request.
    LOG_DEBUG("Originating request");
    _originating = true;
    impu = PJUtils::public_id_from_uri(PJUtils::orig_served_user(req));
  }
  else
  {
    // Terminating request.
    LOG_DEBUG("Terminating request");
    _originating = false;
    impu = PJUtils::public_id_from_uri(PJUtils::term_served_user(req));
  }

  // Create an LIR router to handle the HSS interactions and S-CSCF
  // selection.
  _router = (ICSCFRouter*)new ICSCFLIRouter(_icscf->get_hss_connection(),
                                            _icscf->get_scscf_selector(),
                                            trail(),
                                            _acr,
                                            impu,
                                            _originating);

  // We have a router, query it for an S-CSCF to use.
  pjsip_sip_uri* scscf_sip_uri = NULL;
  pjsip_status_code status_code = 
    (pjsip_status_code)_router->get_scscf(get_pool(req), scscf_sip_uri);

  if (status_code == PJSIP_SC_OK)
  {
    LOG_DEBUG("Found SCSCF for non-REGISTER");

    if (_originating)
    {
      // Add the `orig` parameter.
      pjsip_param* orig_param = PJ_POOL_ALLOC_T(get_pool(req), pjsip_param);
      pj_strdup(get_pool(req), &orig_param->name, &STR_ORIG);
      orig_param->value.slen = 0;
      pj_list_insert_after(&scscf_sip_uri->other_param, orig_param);
    }

    PJUtils::add_route_header(req, scscf_sip_uri, get_pool(req));
    send_request(req);
  }
  else
  {
    pjsip_msg* rsp = create_response(req, status_code);
    send_response(rsp);
    free_msg(req);
  }
}


void ICSCFSproutletTsx::on_tx_request(pjsip_msg* req)
{
  // Pass the transmitted request to the ACR to update the accounting
  // information.
  _acr->tx_request(req);
}


void ICSCFSproutletTsx::on_rx_response(pjsip_msg* rsp, int fork_id)
{
  // Pass the received response to the ACR.
  // @TODO - timestamp from response???
  _acr->rx_response(rsp);

  // Check if this response is one that we are allowed to retry the HSS lookup
  // for.  See TS 24.229 - section 5.3.1.3.
  //
  // Note we support service restoration, so integrity-protected settings in
  // Authorization header are immaterial).
  pjsip_status_code rsp_status = (pjsip_status_code)rsp->line.status.code;
  LOG_DEBUG("Check retry conditions for non-REGISTER request, status code = %d",
            rsp_status);
  if (rsp_status == PJSIP_SC_REQUEST_TIMEOUT)
  {
    // Indeed it it, first log to SAS.
    LOG_DEBUG("Attempt retry to alternate S-CSCF for non-REGISTER request");
    std::string st_code = std::to_string(rsp_status);
    SAS::Event event(trail(), SASEvent::SCSCF_RETRY, 0);
    std::string method = "non-REGISTER";
    event.add_var_param(method);
    event.add_var_param(st_code);
    SAS::report_event(event);

    // Now we can simply reuse the UA router we made on the initial request.
    pjsip_sip_uri* scscf_sip_uri = NULL;
    int status_code = _router->get_scscf(get_pool(_cloned_req), scscf_sip_uri);

    if (status_code == PJSIP_SC_OK)
    {
      LOG_DEBUG("Found SCSCF for non-REGISTER");
      _cloned_req->line.req.uri = (pjsip_uri*)scscf_sip_uri;

      if (_originating)
      {
        // Add the `orig` parameter.
        pjsip_param* orig_param = PJ_POOL_ALLOC_T(get_pool(_cloned_req),
                                                  pjsip_param);
        pj_strdup(get_pool(_cloned_req), &orig_param->name, &STR_ORIG);
        orig_param->value.slen = 0;
        pj_list_insert_after(&scscf_sip_uri->other_param, orig_param);
      }

      // Re-clone the request for future retries.
      pjsip_msg* tmp_clone = clone_request(_cloned_req);

      // Send the old clone as a new fork and save off the new clone.
      _cloned_req->line.req.uri = (pjsip_uri*)scscf_sip_uri;
      send_request(_cloned_req);
      _cloned_req = tmp_clone;

      // We're not forwarding this response upstream.
      free_msg(rsp);
    }
    else
    {
      free_msg(_cloned_req);
      send_response(rsp);
    }
  }
  else
  {
    // Provisional, successful or non-retryable response, simply forward on
    // upstream.  If this is a final response there will be not more retrying.
    if (rsp_status >= 200)
    {
      free_msg(_cloned_req);
    }
    send_response(rsp);
  }
}


void ICSCFSproutletTsx::on_tx_response(pjsip_msg* rsp) 
{
  // Pass the transmitted response to the ACR to update the accounting
  // information.
  _acr->tx_response(rsp);
}


void ICSCFSproutletTsx::on_cancel(int status_code, pjsip_msg* cancel_req)
{
  if ((status_code == PJSIP_SC_REQUEST_TERMINATED) &&
      (cancel_req != NULL))
  {
    // Create and send an ACR for the CANCEL request.
    ACR* acr = _icscf->get_acr(trail());

    // @TODO - timestamp from request.
    acr->rx_request(cancel_req);
    acr->send_message();

    delete acr;
  }
}
