/**
 * @file icscfproxy.cpp  I-CSCF proxy class implementation
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
#include "analyticslogger.h"
#include "constants.h"
#include "basicproxy.h"
#include "icscfproxy.h"


/// Constructor.
ICSCFProxy::ICSCFProxy(pjsip_endpoint* endpt,
                       int port,
                       int priority,
                       HSSConnection* hss,
                       ACRFactory* acr_factory,
                       SCSCFSelector* scscf_selector) :
  BasicProxy(endpt, "mod-icscf", priority, false),
  _port(port),
  _hss(hss),
  _scscf_selector(scscf_selector),
  _acr_factory(acr_factory)
{
}


/// Destructor.
ICSCFProxy::~ICSCFProxy()
{
}


/// Process received requests not absorbed by transaction layer.
pj_bool_t ICSCFProxy::on_rx_request(pjsip_rx_data* rdata)
{
  if (rdata->tp_info.transport->local_name.port == _port)
  {
    // Request received on I-CSCF port, so process it.
    LOG_INFO("I-CSCF processing request");

    return BasicProxy::on_rx_request(rdata);
  }

  return PJ_FALSE;
}


/// Perform I-CSCF specific verification of incoming requests.
pj_status_t ICSCFProxy::verify_request(pjsip_rx_data *rdata)
{
  return BasicProxy::verify_request(rdata);
}


/// Rejects a request statelessly.
void ICSCFProxy::reject_request(pjsip_rx_data* rdata, int status_code)
{
  pj_status_t status;

  ACR* acr = _acr_factory->get_acr(get_trail(rdata), CALLING_PARTY);
  acr->rx_request(rdata->msg_info.msg, rdata->pkt_info.timestamp);

  if (rdata->msg_info.msg->line.req.method.id != PJSIP_ACK_METHOD)
  {
    LOG_ERROR("Rejecting %.*s request with %d status code",
              rdata->msg_info.msg->line.req.method.name.slen,
              rdata->msg_info.msg->line.req.method.name.ptr,
              status_code);
    pjsip_tx_data* tdata;

    status = PJUtils::create_response(stack_data.endpt, rdata, status_code, NULL, &tdata);
    if (status == PJ_SUCCESS)
    {
      // Pass the response to the ACR.
      acr->tx_response(tdata->msg);

      status = pjsip_endpt_send_response2(stack_data.endpt, rdata, tdata, NULL, NULL);
      if (status != PJ_SUCCESS)
      {
        // LCOV_EXCL_START
        pjsip_tx_data_dec_ref(tdata);
        // LCOV_EXCL_STOP
      }
    }
  }

  // Send the ACR and delete it.
  acr->send_message();
  delete acr;
}


/// Utility method to create a UASTsx object for incoming requests.
BasicProxy::UASTsx* ICSCFProxy::create_uas_tsx()
{
  return (BasicProxy::UASTsx*)new ICSCFProxy::UASTsx(this);
}


ICSCFProxy::UASTsx::UASTsx(BasicProxy* proxy) :
  BasicProxy::UASTsx(proxy),
  _router(NULL),
  _acr(NULL),
  _in_dialog(false)
{
}


ICSCFProxy::UASTsx::~UASTsx()
{
  LOG_DEBUG("ICSCFProxy::UASTsx destructor (%p)", this);

  delete _router;

  // Send the ACR and delete it.
  _acr->send_message();
  delete _acr;
}


/// Initialise the UAS transaction object.
pj_status_t ICSCFProxy::UASTsx::init(pjsip_rx_data* rdata)
{
  // Do the BasicProxy initialization first.
  pj_status_t status = BasicProxy::UASTsx::init(rdata);

  pjsip_msg* msg = rdata->msg_info.msg;

  // Create an ACR if ACR generation is enabled.
  _acr = create_acr();

  // Parse interesting parameters from the request for the later lookups.
  if (msg->line.req.method.id == PJSIP_REGISTER_METHOD)
  {
    // REGISTER request.
    LOG_DEBUG("I-CSCF initialize transaction for REGISTER request");
    _case = SessionCase::REGISTER;

    std::string impu;
    std::string impi;
    std::string visited_network;
    std::string auth_type;

    // Get the public identity from the To: header.
    pjsip_to_hdr* to_hdr = PJSIP_MSG_TO_HDR(msg);
    pjsip_uri* to_uri = (pjsip_uri*)pjsip_uri_get_uri(to_hdr->uri);
    impu = PJUtils::public_id_from_uri(to_uri);

    // Get the private identity from the Authentication header, or generate
    // a default if there is no Authentication header or no username in the
    // header.
    pjsip_authorization_hdr* auth_hdr =
           (pjsip_authorization_hdr*)pjsip_msg_find_hdr(msg,
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
         (pjsip_generic_string_hdr*)pjsip_msg_find_hdr_by_name(msg,
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
    auth_type = (PJUtils::max_expires(msg, 1) > 0) ? "REG" : "DEREG";

    // Create an UAR router to handle the HSS interactions and S-CSCF
    // selection.
    _router = (ICSCFRouter*)new ICSCFUARouter(((ICSCFProxy*)_proxy)->_hss,
                                              ((ICSCFProxy*)_proxy)->_scscf_selector,
                                              trail(),
                                              _acr,
                                              impi,
                                              impu,
                                              visited_network,
                                              auth_type);
  }
  else
  {
    // Non-register request.
    LOG_DEBUG("I-CSCF initialize transaction for non-REGISTER request");

    // Check for a route header containing the orig parameter;
    pjsip_route_hdr* route = rdata->msg_info.route;

    std::string impu;

    if ((route != NULL) &&
        (pjsip_param_find(&((pjsip_sip_uri*)route->name_addr.uri)->other_param,
                          &STR_ORIG) != NULL))
    {
      // Originating request.
      LOG_DEBUG("Originating request");
      _case = SessionCase::ORIGINATING;
      impu = PJUtils::public_id_from_uri(PJUtils::orig_served_user(msg));
    }
    else
    {
      // Terminating request.
      LOG_DEBUG("Terminating request");
      _case = SessionCase::TERMINATING;
      impu = PJUtils::public_id_from_uri(PJUtils::term_served_user(msg));
    }

    // Create an LIR router to handle the HSS interactions and S-CSCF
    // selection.
    _router = (ICSCFRouter*)new ICSCFLIRouter(((ICSCFProxy*)_proxy)->_hss,
                                              ((ICSCFProxy*)_proxy)->_scscf_selector,
                                              trail(),
                                              _acr,
                                              impu,
                                              (_case == SessionCase::ORIGINATING));
  }

  // Pass the received request to the ACR.
  _acr->rx_request(rdata->msg_info.msg, rdata->pkt_info.timestamp);

  // Record whether or not this is an in-dialog request.  This is needed
  // to determine whether or not to send interim ACRs on provisional
  // responses.
  _in_dialog = (rdata->msg_info.msg->line.req.method.id != PJSIP_BYE_METHOD) &&
               (rdata->msg_info.to->tag.slen != 0);

  return status;
}


/// Handle a received CANCEL request.
void ICSCFProxy::UASTsx::process_cancel_request(pjsip_rx_data* rdata)
{
  // Pass the CANCEL to the BasicProxy code to handle.
  BasicProxy::UASTsx::process_cancel_request(rdata);

  // Create and send an ACR for the CANCEL request.
  ACR* acr = create_acr();
  acr->rx_request(rdata->msg_info.msg, rdata->pkt_info.timestamp);
  acr->send_message();
  delete acr;
}


/// Calculate targets for incoming requests by querying HSS.
int ICSCFProxy::UASTsx::calculate_targets()
{
  // Invoke the router to select an S-CSCF.
  std::string scscf;
  int status_code = _router->get_scscf(scscf);

  if (status_code == PJSIP_SC_OK)
  {
    // Found a suitable S-CSCF.
    if (_case == SessionCase::REGISTER)
    {
      // REGISTER request, so add a target with this S-CSCF as the Request-URI.
      LOG_DEBUG("Route REGISTER to S-CSCF %s", scscf.c_str());
      Target* target = new Target;
      target->uri = PJUtils::uri_from_string(scscf, _req->pool);
      add_target(target);

      // Don't add a P-User-Database header - as per 5.3.1.2/TS24.229 Note 3
      // this can only be added if we have local configuration that the S-CSCF
      // can process P-User-Database.
    }
    else
    {
      // Non-register request, so add a Route header for the destination S-CSCF.
      LOG_DEBUG("Route Non-REGISTER to S-CSCF %s", scscf.c_str());
      Target* target = new Target;
      pjsip_sip_uri* route_uri =
               (pjsip_sip_uri*)PJUtils::uri_from_string(scscf, _req->pool);
      route_uri->lr_param = 1;
      if (_case == SessionCase::ORIGINATING)
      {
        // Add the "orig" parameter.
        pjsip_param* p = PJ_POOL_ALLOC_T(_req->pool, pjsip_param);
        pj_strdup(_req->pool, &p->name, &STR_ORIG);
        p->value.slen = 0;
        pj_list_insert_after(&route_uri->other_param, p);
      }
      target->paths.push_back((pjsip_uri*)route_uri);
      add_target(target);

      // Remove the P-Profile-Key header if present.
      PJUtils::remove_hdr(_req->msg, &STR_P_PROFILE_KEY);
    }
  }

  return status_code;
}


/// Handles a response to an associated UACTsx.
void ICSCFProxy::UASTsx::on_new_client_response(UACTsx* uac_tsx,
                                                pjsip_rx_data *rdata)
{
  // Pass the response to the ACR for reporting.
  _acr->rx_response(rdata->msg_info.msg, rdata->pkt_info.timestamp);

  // Pass the response on to the BasicProxy method.
  BasicProxy::UASTsx::on_new_client_response(uac_tsx, rdata);
}


/// Handles the best final response, once all final responses have been received
/// from all forked INVITEs.
void ICSCFProxy::UASTsx::on_final_response()
{
  if (_tsx != NULL)
  {
    bool retried = false;
    if (_best_rsp->msg->line.status.code >= 300)
    {
      // Request rejected, see if we can/should do a retry.
      retried = retry_to_alternate_scscf(_best_rsp->msg->line.status.code);
    }

    if (!retried)
    {
      // Send the final response.
      BasicProxy::UASTsx::on_final_response();
    }
  }
}


/// Called when a response is transmitted on this transaction.  Handles
/// interactions with the ACR if one is allocated.
void ICSCFProxy::UASTsx::on_tx_response(pjsip_tx_data* tdata)
{
  _acr->tx_response(tdata->msg);

  if ((_in_dialog) &&
      (tdata->msg->line.status.code > 100) &&
      (tdata->msg->line.status.code < 200))
  {
    // This is a provisional response to a mid-dialog message, so we
    // should send an ACR now.
    // LCOV_EXCL_START
    _acr->send_message();
    // LCOV_EXCL_STOP

    // Don't delete the ACR as we will send another on any subsequent
    // provisional responses, and also when the transaction completes.
  }
}


/// Called when a request is transmitted on an associated client transaction.
/// Handles interactions with the ACR for the request if one is allocated.
void ICSCFProxy::UASTsx::on_tx_client_request(pjsip_tx_data* tdata)
{
  _acr->tx_request(tdata->msg);
}


/// Retry the request to an alternate S-CSCF if possible.
bool ICSCFProxy::UASTsx::retry_to_alternate_scscf(int rsp_status)
{
  bool retry = false;

  if (_case == SessionCase::REGISTER)
  {
    // Check whether conditions are satisfied for retrying a REGISTER (see
    // 5.3.1.3/TS24.229).
    LOG_DEBUG("Check retry conditions for REGISTER request, status code = %d",
              rsp_status);
    if (((rsp_status >= 300) && (rsp_status <= 399)) ||
        (rsp_status == PJSIP_SC_REQUEST_TIMEOUT) ||
        (rsp_status == PJSIP_SC_TEMPORARILY_UNAVAILABLE))
    {
      // Can do a retry (we support service restoration, so integrity-protected
      // settings in Authorization header are immaterial).
      LOG_DEBUG("Attempt retry to alternate S-CSCF for REGISTER request");
      retry = true;

      std::string st_code = std::to_string(rsp_status);
      SAS::Event event(trail(), SASEvent::SCSCF_RETRY, 0);
      std::string method = "REGISTER";
      event.add_var_param(method);
      event.add_var_param(st_code);
      SAS::report_event(event);
    }
  }
  else
  {
    // Check whether conditions are satisfied for retrying a Non-REGISTER.
    LOG_DEBUG("Check retry conditions for Non-REGISTER request, status code = %d",
              rsp_status);

    if (rsp_status == PJSIP_SC_REQUEST_TIMEOUT)
    {
      LOG_DEBUG("Attempt retry to alternate S-CSCF for non-REGISTER request");
      retry = true;

      std::string st_code = std::to_string(rsp_status);
      SAS::Event event(trail(), SASEvent::SCSCF_RETRY, 0);
      std::string method = "NON-REGISTER";
      event.add_var_param(method);
      event.add_var_param(st_code);
      SAS::report_event(event);
    }
  }

  if (retry)
  {
    // Retry conditions are satisfied, so try to calculate a new target.
    int status_code = calculate_targets();

    if (status_code == PJSIP_SC_OK)
    {
      // We found a suitable alternate S-CSCF and have programmed it as a
      // target, so action the retry.
      forward_request();
    }
    else
    {
      // Failed to find another S-CSCF for the request.
      LOG_DEBUG("Failed to find alternate S-CSCF for retry");
      retry = false;

      if (_case == SessionCase::REGISTER)
      {
        // In the register case the spec's are quite particular about how
        // failures are reported.
        if (status_code == PJSIP_SC_FORBIDDEN)
        {
          // The HSS has returned a negative response to the user registration
          // request - I-CSCF should respond with 403.
          _best_rsp->msg->line.status.code = PJSIP_SC_FORBIDDEN;
          _best_rsp->msg->line.status.reason =
                       *pjsip_get_status_text(_best_rsp->msg->line.status.code);
        }
        else
        {
          // The I-CSCF can't select an S-CSCF for the REGISTER request (either
          // because there are no more S-CSCFs that meet the mandatory
          // capabilitires, or the HSS is temporarily unavailable). There was at
          // least one valid S-CSCF (as this is retry processing). The I-CSCF
          //  must return 504 (TS 24.229, 5.3.1.3) in this case.
          _best_rsp->msg->line.status.code = PJSIP_SC_SERVER_TIMEOUT;
          _best_rsp->msg->line.status.reason =
                       *pjsip_get_status_text(_best_rsp->msg->line.status.code);
        }
      }
    }
  }

  return retry;
}


/// Create an ACR.
ACR* ICSCFProxy::UASTsx::create_acr()
{
  return ((ICSCFProxy*)_proxy)->_acr_factory->get_acr(_trail, CALLING_PARTY);
}


