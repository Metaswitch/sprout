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
#include "sasevent.h"
#include "analyticslogger.h"
#include "constants.h"
#include "basicproxy.h"
#include "icscfproxy.h"


/// Constructor.
ICSCFProxy::ICSCFProxy(pjsip_endpoint* endpt,
                       int port,
                       int priority,
                       HSSConnection* hss,
                       SCSCFSelector* scscf_selector) :
  BasicProxy(endpt, "mod-icscf", priority, false),
  _port(port),
  _hss(hss),
  _scscf_selector(scscf_selector)
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
    /// Request received on I-CSCF port, so process it.
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


/// Utility method to create a UASTsx object for incoming requests.
BasicProxy::UASTsx* ICSCFProxy::create_uas_tsx()
{
  return (BasicProxy::UASTsx*)new ICSCFProxy::UASTsx(_hss, _scscf_selector, this);
}


ICSCFProxy::UASTsx::UASTsx(HSSConnection* hss,
                           SCSCFSelector* scscf_selector,
                           BasicProxy* proxy) :
  BasicProxy::UASTsx(proxy),
  _hss(hss),
  _scscf_selector(scscf_selector),
  _hss_rsp(),
  _attempted_scscfs()
{
}


ICSCFProxy::UASTsx::~UASTsx()
{
  LOG_DEBUG("ICSCFProxy::UASTsx destructor (%p)", this);
}


/// Initialise the UAS transaction object.
pj_status_t ICSCFProxy::UASTsx::init(pjsip_rx_data* rdata,
                                     pjsip_tx_data* tdata)
{
  // Do the BasicProxy initialization first.
  pj_status_t status = BasicProxy::UASTsx::init(rdata, tdata);

  pjsip_msg* msg = rdata->msg_info.msg;

  // Parse interesting parameters from the request for the later lookups.
  if (msg->line.req.method.id == PJSIP_REGISTER_METHOD)
  {
    // REGISTER request.
    LOG_DEBUG("I-CSCF initialize transaction for REGISTER request");
    _case = SessionCase::REGISTER;

    // Get the public identity from the To: header.
    pjsip_to_hdr* to_hdr = PJSIP_MSG_TO_HDR(msg);
    pjsip_uri* to_uri = (pjsip_uri*)pjsip_uri_get_uri(to_hdr->uri);
    _impu = PJUtils::public_id_from_uri(to_uri);

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
      _impi = PJUtils::pj_str_to_string(&auth_hdr->credential.digest.username);
    }
    else
    {
      // Create a default IMPI from the IMPU by removing the sip: prefix.
      _impi = _impu.substr(4);
    }

    // Get the visted network identification if present.  If not, homestead will
    // default it.
    pjsip_generic_string_hdr* vn_hdr =
         (pjsip_generic_string_hdr*)pjsip_msg_find_hdr_by_name(msg,
                                                               &STR_P_V_N_I,
                                                               NULL);

    if (vn_hdr != NULL)
    {
      _visited_network = PJUtils::pj_str_to_string(&vn_hdr->hvalue);
    }
    else if (PJSIP_URI_SCHEME_IS_SIP(to_uri) || PJSIP_URI_SCHEME_IS_SIPS(to_uri))
    {
      // Use the domain of the IMPU as the visited network.
      _visited_network = PJUtils::pj_str_to_string(&((pjsip_sip_uri*)to_uri)->host);
    }

    // Work out what authorization type to use by looking at the expiry
    // values in the request.  (Use a default of 1 because if there is no
    // expires header or expires values in the contact headers this will
    // be a registration not a deregistration.)
    _auth_type = (PJUtils::max_expires(msg, 1) > 0) ? "REG" :
                                                      "DEREG";
  }
  else
  {
    // Non-register request.
    LOG_DEBUG("I-CSCF initialize transaction for non-REGISTER request");

    // Check for a route header containing the orig parameter;
    pjsip_route_hdr* route = rdata->msg_info.route;

    if ((route != NULL) &&
        (pjsip_param_find(&((pjsip_sip_uri*)route->name_addr.uri)->other_param,
                          &STR_ORIG) != NULL))
    {
      // Originating request.
      LOG_DEBUG("Originating request");
      _case = SessionCase::ORIGINATING;
      _impu = PJUtils::public_id_from_uri(PJUtils::orig_served_user(tdata->msg));
    }
    else
    {
      // Terminating request.
      LOG_DEBUG("Terminating request");
      _case = SessionCase::TERMINATING;
      _impu = PJUtils::public_id_from_uri(PJUtils::term_served_user(tdata->msg));
    }
    _auth_type = "";
  }

  return status;
}


/// Calculate targets for incoming requests by querying HSS.
int ICSCFProxy::UASTsx::calculate_targets(pjsip_tx_data* tdata)
{
  int status_code = PJSIP_SC_OK;

  if (_case == SessionCase::REGISTER)
  {
    // REGISTER request.
    LOG_DEBUG("I-CSCF calculate target for REGISTER request");

    // Do the HSS user registration status query.
    std::string scscf;
    status_code = registration_status_query(_impi,
                                            _impu,
                                            _visited_network,
                                            _auth_type,
                                            scscf);


    if (status_code == PJSIP_SC_OK)
    {
      // Found a suitable S-CSCF, so add a target with this S-CSCF as the
      // Request-URI.
      LOG_DEBUG("Route REGISTER to S-CSCF %s", scscf.c_str());
      Target* target = new Target;
      target->uri = PJUtils::uri_from_string(scscf, _req->pool);
      add_target(target);

      // Add the S-CSCF to the list of attempted S-CSCFs.
      _attempted_scscfs.push_back(scscf);

      // Don't add a P-User-Database header - as per 5.3.1.2/TS24.229 Note 3
      // this can only be added if we have local configuration that the S-CSCF
      // can process P-User-Database.
    }
  }
  else
  {
    // Non-register request.
    LOG_DEBUG("I-CSCF - calculate target for non-REGISTER request");

    // Remove P-Profile-Key header if present.
    PJUtils::remove_hdr(tdata->msg, &STR_P_PROFILE_KEY);

    std::string scscf;

    if (_case == SessionCase::ORIGINATING)
    {
      // Do originating request specific processing.
      status_code = location_query(_impu, true, _auth_type, scscf);
    }
    else
    {
      // Do terminating request specific processing.
      status_code = location_query(_impu, false, _auth_type, scscf);
    }

    if (status_code == PJSIP_SC_OK)
    {
      // Found a suitable S-CSCF, so add a target with a Route URI.
      LOG_DEBUG("Route Non-REGISTER to S-CSCF %s", scscf.c_str());
      Target* target = new Target;
      pjsip_sip_uri* route_uri =
               (pjsip_sip_uri*)PJUtils::uri_from_string(scscf, _req->pool);
      route_uri->lr_param = 1;
      if (_case == SessionCase::ORIGINATING)
      {
        // Add the "orig" parameter.
        pjsip_param* p = PJ_POOL_ALLOC_T(tdata->pool, pjsip_param);
        pj_strdup(tdata->pool, &p->name, &STR_ORIG);
        p->value.slen = 0;
        pj_list_insert_after(&route_uri->other_param, p);
      }
      target->paths.push_back((pjsip_uri*)route_uri);
      add_target(target);

      // Add the S-CSCF to the list of attempted S-CSCFs.
      _attempted_scscfs.push_back(scscf);
    }
  }

  return status_code;
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
      retried = retry_request(_best_rsp->msg->line.status.code);
    }

    if (!retried)
    {
      // Send the final response.
      BasicProxy::UASTsx::on_final_response();
    }
  }
}


/// Retry the request to an alternate S-CSCF if possible.
bool ICSCFProxy::UASTsx::retry_request(int rsp_status)
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
      LOG_DEBUG("Attempt retry for REGISTER request");
      _auth_type = "CAPAB";
      std::string scscf;
      int status_code = registration_status_query(_impi,
                                                  _impu,
                                                  _visited_network,
                                                  _auth_type,
                                                  scscf);

      if (status_code == PJSIP_SC_OK)
      {
        // REGISTER request, so set the S-CSCF as the Request-URI in the target.
        LOG_DEBUG("Retry REGISTER to %s", scscf.c_str());
        Target* target = new Target;
        target->uri = PJUtils::uri_from_string(scscf, _req->pool);
        add_target(target);

        // Add the S-CSCF to the list of attempted S-CSCFs.
        _attempted_scscfs.push_back(scscf);

        // Invoke the retry.
        process_tsx_request();

        retry = true;
      }
      else if (status_code == PJSIP_SC_FORBIDDEN)
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
  else
  {
    // Check whether conditions are satisfied for retrying a Non-REGISTER.
    LOG_DEBUG("Check retry conditions for Non-REGISTER request, status code = %d",
              rsp_status);

    if (rsp_status == PJSIP_SC_REQUEST_TIMEOUT)
    {
      LOG_DEBUG("Attempt retry for non-REGISTER request");
      _auth_type = "CAPAB";
      std::string scscf;
      int status_code = location_query(_impu,
                                       (_case == SessionCase::ORIGINATING),
                                       _auth_type,
                                       scscf);

      if (status_code == PJSIP_SC_OK)
      {
        // We have another S-CSCF to try, so add it as a new target.
        // Set the S-CSCF as a route header in the target.
        LOG_DEBUG("Retry request to S-CSCF %s", scscf.c_str());
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

        // Add the S-CSCF to the list of attempted S-CSCFs.
        _attempted_scscfs.push_back(scscf);

        // Invoke the retry.
        process_tsx_request();
        retry = true;
      }
    }
  }

  return retry;
}


/// Perform a registration status query to the HSS.
int ICSCFProxy::UASTsx::registration_status_query(const std::string& impi,
                                                  const std::string& impu,
                                                  const std::string& visited_network,
                                                  const std::string& auth_type,
                                                  std::string& scscf)
{
  int status_code = PJSIP_SC_OK;

  if (!_hss_rsp._queried_caps)
  {
    LOG_DEBUG("Perform UAR - impi %s, impu %s, vn %s, auth_type %s",
              impi.c_str(), impu.c_str(), visited_network.c_str(), auth_type.c_str());

    Json::Value* rsp = NULL;
    HTTPCode rc =_hss->get_user_auth_status(impi,
                                            impu,
                                            visited_network,
                                            auth_type,
                                            rsp,
                                            trail());

    // Return a 480 response if the lookup times out, or the HSS returns
    // invalid information. If the HSS has returned a negative response,
    // then return a 403.
    if (rc != HTTP_OK)
    {
      status_code = PJSIP_SC_TEMPORARILY_UNAVAILABLE;

      if (rc == HTTP_NOT_FOUND || rc == HTTP_FORBIDDEN)
      {
        status_code = PJSIP_SC_FORBIDDEN;
      }
    }
    else
    {
      status_code = (rsp != NULL) ? parse_hss_response(*rsp, auth_type == "CAPAB") :
                                    PJSIP_SC_TEMPORARILY_UNAVAILABLE;
    }

    delete rsp;
  }

  if (status_code == PJSIP_SC_OK)
  {
    // The HSS can return the s-cscf name on a CAPAB request.
    // Only use the name returned from the HSS if it hasn't already
    // been tried.
    if ((!_hss_rsp._scscf.empty()) &&
        (std::find(_attempted_scscfs.begin(), _attempted_scscfs.end(),
                   _hss_rsp._scscf) == _attempted_scscfs.end()))
    {
      scscf = _hss_rsp._scscf;
    }

    // Use the capabilites to select an S-CSCF if the HSS didn't
    // return one (that hadn't already been tried).
    if (scscf.empty() && _hss_rsp._queried_caps)
    {
      // Queried capabilities from the HSS, so select a suitable S-CSCF.
      scscf = _scscf_selector->get_scscf(_hss_rsp._mandatory_caps,
                                         _hss_rsp._optional_caps,
                                         _attempted_scscfs);
    }

    if (scscf.empty())
    {
      // Failed to select an S-CSCF providing all the mandatory parameters,
      // so return 600 Busy Everywhere response.
      status_code = PJSIP_SC_BUSY_EVERYWHERE;
    }
  }

  if (status_code == PJSIP_SC_NOT_FOUND)
  {
    // Convert 404 Not Found to 403 Forbidden for registration status query.
    status_code = PJSIP_SC_FORBIDDEN;
  }

  return status_code;
}


/// Perform a location query to the HSS.
int ICSCFProxy::UASTsx::location_query(const std::string& impu,
                                       bool originating,
                                       const std::string& auth_type,
                                       std::string& scscf)
{
  int status_code = PJSIP_SC_OK;

  if (!_hss_rsp._queried_caps)
  {
    LOG_DEBUG("Perform LIR - impu %s, originating %s, auth_type %s",
              impu.c_str(),
              (originating) ? "true" : "false",
              (auth_type != "") ? auth_type.c_str() : "None");
    Json::Value* rsp = NULL;
    HTTPCode rc =_hss->get_location_data(impu,
                                         originating,
                                         auth_type,
                                         rsp,
                                         trail());

    // Return a 480 response if the lookup times out, or the HSS returns
    // invalid information. If the subscriber doesn't exist then return
    // 404.
    if (rc != HTTP_OK)
    {
      status_code = PJSIP_SC_TEMPORARILY_UNAVAILABLE;

      if (rc == HTTP_NOT_FOUND)
      {
        status_code = PJSIP_SC_NOT_FOUND;
      }
    }
    else
    {
      status_code = (rsp != NULL) ? parse_hss_response(*rsp, auth_type == "CAPAB") :
                                    PJSIP_SC_TEMPORARILY_UNAVAILABLE;
    }

    delete rsp;
  }

  if (status_code == PJSIP_SC_OK)
  {
    // The HSS can return the s-cscf name on a CAPAB request.
    // Only use the name returned from the HSS if it hasn't already
    // been tried.
    if ((!_hss_rsp._scscf.empty()) &&
        (std::find(_attempted_scscfs.begin(), _attempted_scscfs.end(),
                   _hss_rsp._scscf) == _attempted_scscfs.end()))
    {
      // Received a specific S-CSCF from the HSS, so use it.
      scscf = _hss_rsp._scscf;
    }

    // Use the capabilites to select an S-CSCF if the HSS didn't
    // return one (that hadn't already been tried).
    if (scscf.empty() && _hss_rsp._queried_caps)
    {
      // Queried capabilities from the HSS, so select a suitable S-CSCF.
      scscf = _scscf_selector->get_scscf(_hss_rsp._mandatory_caps,
                                         _hss_rsp._optional_caps,
                                         _attempted_scscfs);
    }

    if (scscf.empty())
    {
      // Failed to select an S-CSCF providing all the mandatory parameters,
      // so return 600 Busy Everywhere response.
      LOG_DEBUG("No suitable S-CSCF");
      status_code = PJSIP_SC_BUSY_EVERYWHERE;
    }
  }

  return status_code;
}


int ICSCFProxy::UASTsx::parse_hss_response(Json::Value& rsp, bool queried_caps)
{
  int status_code = PJSIP_SC_OK;

  // Clear out any older response.
  _hss_rsp._queried_caps = false;
  _hss_rsp._mandatory_caps.clear();
  _hss_rsp._optional_caps.clear();
  _hss_rsp._scscf = "";

  if ((!rsp.isMember("result-code")) ||
      ((rsp["result-code"].asString() != "2001") &&
       (rsp["result-code"].asString() != "2002") &&
       (rsp["result-code"].asString() != "2003")))
  {
    // Error from HSS, so respond with 404 Not Found.  (This may be changed
    // to 403 Forbidden if request is a REGISTER.)
    status_code = PJSIP_SC_NOT_FOUND;
  }
  else
  {
    // Successful response from HSS, so parse it.
    if ((rsp.isMember("scscf")) &&
        (rsp["scscf"].isString()))
    {
      // Response specifies a S-CSCF, so select this as the target.
      LOG_DEBUG("HSS returned S-CSCF %s as target", rsp["scscf"].asCString());
      _hss_rsp._scscf = rsp["scscf"].asString();
    }

    if ((rsp.isMember("mandatory-capabilities")) &&
        (rsp["mandatory-capabilities"].isArray()) &&
        (rsp.isMember("optional-capabilities")) &&
        (rsp["optional-capabilities"].isArray()))
    {
      // Response specifies capabilities - we might have explicitly queried capabilities
      // or implicitly because there was no server assigned.
      LOG_DEBUG("HSS returned capabilities");
      queried_caps = true;
      if ((!parse_capabilities(rsp["mandatory-capabilities"], _hss_rsp._mandatory_caps)) ||
          (!parse_capabilities(rsp["optional-capabilities"], _hss_rsp._optional_caps)))
      {
        // Failed to parse capabilities, so reject with 480 response.
        LOG_WARNING("Malformed required capabilities returned by HSS for %s\n%s",
                    _impu.c_str(), rsp.toStyledString().c_str());
        status_code = PJSIP_SC_TEMPORARILY_UNAVAILABLE;
      }
    }
  }
  _hss_rsp._queried_caps = (status_code == PJSIP_SC_OK) ? queried_caps : false;

  return status_code;
}


bool ICSCFProxy::UASTsx::parse_capabilities(Json::Value& caps,
                                            std::vector<int>& parsed_caps)
{
  for (size_t ii = 0; ii < caps.size(); ++ii)
  {
    if (caps[(int)ii].isUInt())
    {
      parsed_caps.push_back(caps[(int)ii].asUInt());
    }
    else
    {
      return false;
    }
  }
  return true;
}


