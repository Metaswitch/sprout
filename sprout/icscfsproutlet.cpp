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
#include "stack.h"
#include "sproutsasevent.h"
#include "icscfsproutlet.h"
#include "scscfselector.h"
#include "constants.h"

/// Define a constant for the maximum number of ENUM lookups
/// we want to do in I-CSCF termination processing.
#define MAX_ENUM_LOOKUPS 2

/// Constructor.
ICSCFSproutlet::ICSCFSproutlet(const std::string& bgcf_uri,
                               int port,
                               HSSConnection* hss,
                               ACRFactory* acr_factory,
                               SCSCFSelector* scscf_selector,
                               EnumService* enum_service,
                               bool enforce_global_only_lookups,
                               bool enforce_user_phone,
                               bool override_npdi) :
  Sproutlet("icscf", port),
  _bgcf_uri(NULL),
  _hss(hss),
  _scscf_selector(scscf_selector),
  _acr_factory(acr_factory),
  _enum_service(enum_service),
  _global_only_lookups(enforce_global_only_lookups),
  _user_phone(enforce_user_phone),
  _override_npdi(override_npdi),
  _bgcf_uri_str(bgcf_uri)
{
}


/// Destructor.
ICSCFSproutlet::~ICSCFSproutlet()
{
}

bool ICSCFSproutlet::init()
{
  bool init_success = true;

  // Convert the BGCF routing URI to a form suitable for PJSIP, so we're
  // not continually converting from a string.
  _bgcf_uri = PJUtils::uri_from_string(_bgcf_uri_str, stack_data.pool, false);

  if (_bgcf_uri == NULL)
  {
    LOG_ERROR("Invalid BGCF URI %s", _bgcf_uri_str.c_str()); //LCOV_EXCL_LINE
    init_success = false;
  }

  return init_success;
}


/// Creates a ICSCFSproutletTsx instance for performing I-CSCF service processing
/// on a request.
SproutletTsx* ICSCFSproutlet::get_tsx(SproutletTsxHelper* helper,
                                      const std::string& alias,
                                      pjsip_msg* req)
{
  if (req->line.req.method.id == PJSIP_REGISTER_METHOD)
  {
    return (SproutletTsx*)new ICSCFSproutletRegTsx(helper, this);
  }
  else if (req->line.req.method.id != PJSIP_ACK_METHOD)
  {
    return (SproutletTsx*)new ICSCFSproutletTsx(helper, this);
  }
  else
  {
    // ACKs are never "initial requests" (as used by TS 24.229), so never perform
    // I-CSCF processing - just forward them as-is, or fail them.
    return NULL;
  }
}

/// Get an ACR instance from the factory.
///
/// @param trail                SAS trail identifier to use for the ACR.
ACR* ICSCFSproutlet::get_acr(SAS::TrailId trail)
{
  return _acr_factory->get_acr(trail, CALLING_PARTY, NODE_ROLE_TERMINATING);
}

/// Translates a Tel URI to a SIP URI (if ENUM is enabled).
std::string ICSCFSproutlet::enum_translate_tel_uri(pjsip_tel_uri* uri,
                                                   SAS::TrailId trail)
{
  std::string new_uri;
  if (_enum_service != NULL)
  {
    // ENUM is enabled, so extract the user name from the Request-URI.
    std::string user = PJUtils::pj_str_to_string(&uri->number);

    // If we're enforcing global only lookups then check we have a global user.
    if ((!_global_only_lookups) ||
        (PJUtils::is_user_global(user)))
    {
      new_uri = _enum_service->lookup_uri_from_user(user, trail);
    }
  }
  else
  {
    LOG_DEBUG("ENUM isn't enabled");
    SAS::Event event(trail, SASEvent::ENUM_NOT_ENABLED, 0);
    SAS::report_event(event);
  }

  return new_uri;
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
  if (_acr != NULL)
  {
    // Send the ACR for this transaction.
    _acr->send_message();
  }

  delete _acr;
  delete _router;
}


void ICSCFSproutletRegTsx::on_rx_initial_request(pjsip_msg* req)
{
  // Create an ACR for this transaction.
  _acr = _icscf->get_acr(trail());
  _acr->rx_request(req);

  LOG_DEBUG("I-CSCF initialize transaction for REGISTER request");

  // Extract relevant fields from the message
  std::string impu;
  std::string impi;
  std::string visited_network;
  std::string auth_type;

  // Get the public identity from the To: header.
  pjsip_to_hdr* to_hdr = PJSIP_MSG_TO_HDR(req);
  pjsip_uri* to_uri = (pjsip_uri*)pjsip_uri_get_uri(to_hdr->uri);
  impu = PJUtils::public_id_from_uri(to_uri);

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
    LOG_WARNING("No P-Visited-Network-ID in REGISTER - using %s as a default",
                visited_network.c_str());
  }

  // Work out what authorization type to use by looking at the expiry
  // values in the request.  (Use a default of 1 because if there is no
  // expires header or expires values in the contact headers this will
  // be a registration not a deregistration.)
  auth_type = (PJUtils::max_expires(req, 1) > 0) ? "REG" : "DEREG";

  // Remove any Route headers present on the request as we're re-routing the
  // message.
  pj_str_t route_hdr_name = pj_str((char *)"Route");
  PJUtils::remove_hdr(req, &route_hdr_name);

  // Create an UAR router to handle the HSS interactions and S-CSCF
  // selection.
  _router = (ICSCFRouter*)new ICSCFUARouter(_icscf->get_hss_connection(),
                                            _icscf->get_scscf_selector(),
                                            trail(),
                                            _acr,
                                            _icscf->port(),
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


void ICSCFSproutletRegTsx::on_rx_in_dialog_request(pjsip_msg* req)
{
  // I-CSCF shouldn't need to handle in-dialog requests, but it happens, so
  // handle as an initial request.
  on_rx_initial_request(req);
}


void ICSCFSproutletRegTsx::on_tx_request(pjsip_msg* req)
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
  LOG_DEBUG("Check retry conditions for REGISTER, status = %d, S-CSCF %sresponsive",
            rsp_status,
            (fork_status.error_state != NONE) ? "not " : "");
  if ((PJSIP_IS_STATUS_IN_CLASS(rsp_status, 300)) ||
      (fork_status.error_state != NONE) ||
      (rsp_status == PJSIP_SC_TEMPORARILY_UNAVAILABLE))
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
    pjsip_msg* req = original_request();
    int status_code = _router->get_scscf(get_pool(req), scscf_sip_uri);

    if (status_code == PJSIP_SC_OK)
    {
      LOG_DEBUG("Found SCSCF for REGISTER");

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
  _acr(NULL),
  _routed_to_bgcf(false)
{
}


/// REGISTER-handling Tsx destructor (may also cause ACRs to be sent).
ICSCFSproutletTsx::~ICSCFSproutletTsx()
{
  if (_acr != NULL)
  {
    _acr->send_message();
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

  // Create an ACR for this transaction.
  _acr = _icscf->get_acr(trail());
  _acr->rx_request(req);

  LOG_DEBUG("I-CSCF initialize transaction for non-REGISTER request");

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
    LOG_DEBUG("Originating request");
    _originating = true;
    impu = PJUtils::public_id_from_uri(PJUtils::orig_served_user(req));

    SAS::Event event(trail(), SASEvent::ICSCF_RCVD_ORIG_NON_REG, 0);
    event.add_var_param(impu);
    event.add_var_param(req->line.req.method.name.slen,
                        req->line.req.method.name.ptr);
    SAS::report_event(event);
  }
  else
  {
    // Terminating request.
    LOG_DEBUG("Terminating request");
    _originating = false;
    pjsip_uri* uri = PJUtils::term_served_user(req);

    // If the Req URI is a SIP URI with the user=phone parameter set, is not a
    // GRUU and the user part starts with '+' (i.e. is a global phone number),
    // we should replace it with a tel URI, as per TS24.229 5.3.2.1.
    if (PJSIP_URI_SCHEME_IS_SIP(uri))
    {
      pjsip_sip_uri* sip_uri = (pjsip_sip_uri*)uri;

      if ((!pj_strcmp(&sip_uri->user_param, &STR_USER_PHONE)) &&
          (PJUtils::is_user_numeric(sip_uri->user)) &&
          (!_icscf->are_global_only_lookups_enforced() || PJUtils::is_user_global(sip_uri->user)) &&
          (!PJUtils::is_uri_gruu(uri)))
      {
        LOG_DEBUG("Change request URI from SIP URI to tel URI");
        req->line.req.uri =
          PJUtils::translate_sip_uri_to_tel_uri(sip_uri, pool);
      }
    }

    impu = PJUtils::public_id_from_uri(PJUtils::term_served_user(req));

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
                                            _icscf->port(),
                                            impu,
                                            _originating);

  pjsip_sip_uri* scscf_sip_uri = NULL;

  // Use the router we just created to query the HSS for an S-CSCF to use.
  pjsip_status_code status_code =
    (pjsip_status_code)_router->get_scscf(pool, scscf_sip_uri);

  if ((!_originating) && (scscf_not_found(status_code)))
  {
    LOG_DEBUG("Couldn't find an S-CSCF, attempt to translate the URI");
    pjsip_uri* uri = PJUtils::term_served_user(req);

    // For terminating processing, if the HSS indicates that the user does not
    // exist, and if the request URI is a tel URI, try an ENUM translation. If
    // this succeeds, go back to the HSS. See TS24.229, 5.3.2.1.
    //
    // Before doing that we should check whether the enforce_user_phone flag is
    // set. If it isn't, and we have a numeric SIP URI, it is possible that
    // this should have been a tel URI, so translate it and do the HSS lookup
    // again.  Once again, only do this for global numbers.
    if ((!_icscf->should_require_user_phone()) &&
        (PJSIP_URI_SCHEME_IS_SIP(uri)) &&
        (PJUtils::is_user_numeric(((pjsip_sip_uri*)uri)->user)) &&
        (!_icscf->are_global_only_lookups_enforced() || PJUtils::is_user_global(((pjsip_sip_uri*)uri)->user)) &&
        (!PJUtils::is_uri_gruu(uri)))
    {
      LOG_DEBUG("enforce_user_phone set to false, try using a tel URI");
      uri = PJUtils::translate_sip_uri_to_tel_uri((pjsip_sip_uri*)uri, pool);
      req->line.req.uri = uri;

      // We need to change the IMPU stored on our LIR router so that when
      // we do a new LIR we look up the new IMPU.
      impu = PJUtils::public_id_from_uri(PJUtils::term_served_user(req));
      ((ICSCFLIRouter *)_router)->change_impu(impu);
      status_code = (pjsip_status_code)_router->get_scscf(pool, scscf_sip_uri);
    }

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
        std::string new_uri = _icscf->enum_translate_tel_uri(
                                    (pjsip_tel_uri*)req->line.req.uri, trail());

        if (!new_uri.empty())
        {
          pjsip_uri* req_uri = (pjsip_uri*)PJUtils::uri_from_string(new_uri,
                                                                    pool);

          if (req_uri != NULL)
          {
            if (PJUtils::get_npdi(uri))
            {
              if (!PJUtils::does_uri_represent_number(req_uri,
                                           _icscf->should_require_user_phone()))
              {
                // The existing URI had NP data, but the ENUM lookup has returned
                // a URI that doesn't represent a telephone number. This trumps the
                // NP data.
                req->line.req.uri = req_uri;

                // We need to change the IMPU stored on our LIR router so that when
                // we next do an LIR we look up the new IMPU.
                ((ICSCFLIRouter *)_router)->change_impu(new_uri);
              }
              else
              {
                LOG_DEBUG("Request URI already has existing NP information");

                // The existing URI had NP data. Only overwrite the URI if
                // we're configured to do so.
                if (_icscf->should_override_npdi())
                {
                  LOG_DEBUG("Override existing NP information");
                  req->line.req.uri = req_uri;
                }

                route_to_bgcf(req);
                return;
              }
            }
            else if (PJUtils::get_npdi(req_uri))
            {
              // The ENUM lookup has returned NP data. Rewrite the request
              // URI and route the request to the BGCF
              LOG_DEBUG("Update request URI to %s", new_uri.c_str());
              req->line.req.uri = req_uri;
              route_to_bgcf(req);
              return;
            }
            else
            {
              LOG_DEBUG("Update request URI to %s", new_uri.c_str());
              req->line.req.uri = req_uri;
              ((ICSCFLIRouter *)_router)->change_impu(new_uri);
            }
          }
          else
          {
            LOG_WARNING("Badly formed URI %s from ENUM translation",
                        new_uri.c_str());
            SAS::Event event(trail(), SASEvent::ENUM_INVALID, 0);
            event.add_var_param(new_uri);
            SAS::report_event(event);
          }
        }

        // If we successfully translate the req URI and end up with either another TEL URI or a
        // local SIP URI, we should look for an S-CSCF again.
        uri = req->line.req.uri;
        if ((PJSIP_URI_SCHEME_IS_TEL(uri)) ||
            ((PJSIP_URI_SCHEME_IS_SIP(uri)) &&
             (PJUtils::is_home_domain(uri))))
        {
          // TEL or local SIP URI.  Look up the S-CSCF again.
          status_code = (pjsip_status_code)_router->get_scscf(pool, scscf_sip_uri);
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
  else if ((PJSIP_URI_SCHEME_IS_SIP(req->line.req.uri)) &&
           (PJUtils::is_home_domain(req->line.req.uri)))
  {
    // Target is in our home domain, but we failed to find an S-CSCF. This is the final response.
    pjsip_msg* rsp = create_response(req, status_code);
    send_response(rsp);
    free_msg(req);
  }
  else
  {
    // Target is a TEL URI or not in our home domain.  Pass to the BGCF.
    route_to_bgcf(req);
  }
}


void ICSCFSproutletTsx::on_rx_in_dialog_request(pjsip_msg* req)
{
  // I-CSCF shouldn't need to handle in-dialog requests, but it happens, so
  // handle as an initial request.
  on_rx_initial_request(req);
}


void ICSCFSproutletTsx::on_tx_request(pjsip_msg* req)
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
  LOG_DEBUG("Check retry conditions for non-REGISTER, S-CSCF %sresponsive",
            (fork_status.error_state != NONE) ? "not " : "");
  if ((!_routed_to_bgcf) &&
      (fork_status.error_state != NONE))
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
    pjsip_msg* req = original_request();
    pj_pool_t* pool = get_pool(req);
    int status_code = _router->get_scscf(pool, scscf_sip_uri);

    if (status_code == PJSIP_SC_OK)
    {
      LOG_DEBUG("Found SCSCF for non-REGISTER");

      if (_originating)
      {
        // Add the `orig` parameter.
        pjsip_param* orig_param = PJ_POOL_ALLOC_T(pool, pjsip_param);
        pj_strdup(pool, &orig_param->name, &STR_ORIG);
        orig_param->value.slen = 0;
        pj_list_insert_after(&scscf_sip_uri->other_param, orig_param);
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

/// Route the request to the BGCF.
void ICSCFSproutletTsx::route_to_bgcf(pjsip_msg* req)
{
  LOG_INFO("Routing to BGCF %s",
           PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                  _icscf->bgcf_uri()).c_str());
  PJUtils::add_route_header(req,
                            (pjsip_sip_uri*)pjsip_uri_clone(get_pool(req),
                                                            _icscf->bgcf_uri()),
                            get_pool(req));
  send_request(req);
  _routed_to_bgcf = true;
}
