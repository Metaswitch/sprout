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
                       int priority,
                       HSSConnection* hss,
                       SCSCFSelector* scscf_selector,
                       AnalyticsLogger* analytics_logger) :
  BasicProxy(endpt, "mod-icscf", priority, analytics_logger, false),
  _hss(hss),
  _scscf_selector(scscf_selector)
{
}

/// Destructor.
ICSCFProxy::~ICSCFProxy()
{
}

/// Perform I-CSCF specific verification of incoming requests.
pj_status_t ICSCFProxy::verify_request(pjsip_rx_data *rdata)
{




  return BasicProxy::verify_request(rdata);
}


/// Utility method to create a UASTsx objects for incoming requests.
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
  _scscf(),
  _have_caps(false),
  _mandatory_caps(),
  _optional_caps(),
  _attempted_scscfs()
{
}


ICSCFProxy::UASTsx::~UASTsx()
{
}


/// Calculate targets for incoming requests by querying HSS.
int ICSCFProxy::UASTsx::calculate_targets(pjsip_tx_data* tdata)
{
  int status_code = PJSIP_SC_OK;

  if (tdata->msg->line.req.method.id == PJSIP_REGISTER_METHOD)
  {
    // REGISTER request.
    LOG_DEBUG("I-CSCF Calculate target for REGISTER request");

    // Get the public identity from the To: header.
    pjsip_to_hdr* to_hdr = PJSIP_MSG_TO_HDR(tdata->msg);
    std::string impu = PJUtils::public_id_from_uri(to_hdr->uri);

    // Get the private identity from the Authentication header, or generate
    // a default if there is no Authentication header or no username in the
    // header.
    std::string impi;
    pjsip_authorization_hdr* auth_hdr =
           (pjsip_authorization_hdr*)pjsip_msg_find_hdr(tdata->msg,
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

    // Get the visted network identification if present.
    std::string visited_network;
    pjsip_generic_string_hdr* vn_hdr =
         (pjsip_generic_string_hdr*)pjsip_msg_find_hdr_by_name(tdata->msg,
                                                               &STR_P_V_N_I,
                                                               NULL);

    if (vn_hdr != NULL)
    {
      // @TODO - check it is safe to assume this will always be a domain name
      // RFC3455 suggests is can be either a domain name or a quoted string,
      // but Cx interface definitely requires a domain name, so do we need
      // to support resolving arbitrary quoted strings to visited network
      // domain names?
      visited_network = PJUtils::pj_str_to_string(&vn_hdr->hvalue);
    }

    // Work out what authorization type to use by looking at the expiry
    // values in the request.  (Use a default of 1 because if there is no
    // expires header or expires values in the contact headers this will
    // be a registration not a deregistration.)
    int expires = PJUtils::max_expires(tdata->msg, 1);
    std::string auth_type = (expires > 0) ? "REGISTRATION" : "DE-REGISTRATION";

    // Do the HSS user registration status query.
    Json::Value* rsp = _hss->get_user_auth_status(impi,
                                                  impu,
                                                  visited_network,
                                                  auth_type,
                                                  trail());

    // Parse the response and potentially look at configuration to get
    // a suitable target S-CSCF.
    status_code = get_scscf(rsp);

    if (status_code == PJSIP_SC_OK)
    {
      // Found a suitable S-CSCF, so add a target with this S-CSCF as the
      // Request-URI.
      Target* target = new Target;
      target->uri = PJUtils::uri_from_string(_scscf, tdata->pool);
      add_target(target);

      // Add the S-CSCF to the list of attempted S-CSCFs.
      _attempted_scscfs.push_back(_scscf);
    }
    else if (status_code == PJSIP_SC_NOT_FOUND)
    {
      // Convert 404 Not Found to 403 Forbidden for REGISTER requests.
      status_code = PJSIP_SC_FORBIDDEN;
    }
  }
  else
  {
    // Non-register request.
    LOG_DEBUG("I-CSCF - calculate target for non-REGISTER request");

    // Remove P-Profile-Key header if present.
    PJUtils::remove_hdr(tdata->msg, &STR_P_PROFILE_KEY);

    // Check for a route header containing the orig parameter;
    pjsip_route_hdr* route = (pjsip_route_hdr*)
                           pjsip_msg_find_hdr(tdata->msg, PJSIP_H_ROUTE, NULL);

    if ((route != NULL) &&
        (pjsip_param_find(&((pjsip_sip_uri*)route->name_addr.uri)->other_param,
                          &STR_ORIG) != NULL))
    {
      // Originating request.
      LOG_DEBUG("Originating request");

      // Do the HSS location query for the user.
      std::string impu =
            PJUtils::public_id_from_uri(PJUtils::orig_served_user(tdata->msg));
      Json::Value* rsp = _hss->get_location_data(impu,
                                                 true,
                                                 "",
                                                 trail());

      // Parse the response and potentially look at configuration to get
      // a suitable target S-CSCF.
      status_code = get_scscf(rsp);

      if (status_code == PJSIP_SC_OK)
      {
        // Found a suitable S-CSCF, so add a target with a Route URI.  The
        // Route URI must include the orig parameter.
        Target* target = new Target;
        pjsip_sip_uri* route_uri =
                 (pjsip_sip_uri*)PJUtils::uri_from_string(_scscf, tdata->pool);
        route_uri->lr_param = 1;
        pjsip_param* p = PJ_POOL_ALLOC_T(tdata->pool, pjsip_param);
        pj_strdup(tdata->pool, &p->name, &STR_ORIG);
        p->value.slen = 0;
        pj_list_insert_after(&route_uri->other_param, p);
        target->paths.push_back((pjsip_uri*)route_uri);
        add_target(target);

        // Add the S-CSCF to the list of attempted S-CSCFs.
        _attempted_scscfs.push_back(_scscf);
      }
    }
    else
    {
      // Terminating request.
      LOG_DEBUG("Terminating request");

      // Do the HSS location query for the user.
      std::string impu =
            PJUtils::public_id_from_uri(PJUtils::orig_served_user(tdata->msg));
      Json::Value* rsp = _hss->get_location_data(impu,
                                                 true,
                                                 "",
                                                 trail());

      // Parse the response and potentially look at configuration to get
      // a suitable target S-CSCF.
      status_code = get_scscf(rsp);

      if (status_code == PJSIP_SC_OK)
      {
        // Found a suitable S-CSCF, so add a target with a Route URI.
        Target* target = new Target;
        pjsip_sip_uri* route_uri =
                 (pjsip_sip_uri*)PJUtils::uri_from_string(_scscf, tdata->pool);
        route_uri->lr_param = 1;
        target->paths.push_back((pjsip_uri*)route_uri);
        add_target(target);

        // Add the S-CSCF to the list of attempted S-CSCFs.
        _attempted_scscfs.push_back(_scscf);
      }
    }
  }

  return status_code;
}


// Handles the best final response, once all final responses have been received
// from all forked INVITEs.
// @Returns whether or not the send was a success.
void ICSCFProxy::UASTsx::on_final_response()
{
  if (_tsx != NULL)
  {
    pjsip_tx_data *best_rsp = _best_rsp;
    int st_code = best_rsp->msg->line.status.code;

    if (st_code == PJSIP_SC_REQUEST_TIMEOUT)
    {
      // Request timed out or connection failed to the selected S-CSCF, so
      // attempt a retry to another S-CSCF.
    }

    _best_rsp = NULL;
    set_trail(best_rsp, trail());
    pjsip_tsx_send_msg(_tsx, best_rsp);

    if ((_tsx->method.id == PJSIP_INVITE_METHOD) &&
        (st_code == 200))
    {
      // Terminate the UAS transaction (this needs to be done
      // manually for INVITE 200 OK response, otherwise the
      // transaction layer will wait for an ACK).  This will also
      // cause all other pending UAC transactions to be cancelled.
      LOG_DEBUG("%s - Terminate UAS INVITE transaction (non-forking case)",
                _tsx->obj_name);
      pjsip_tsx_terminate(_tsx, 200);
    }
  }
}



int ICSCFProxy::UASTsx::get_scscf(Json::Value* rsp)
{
  int status_code = (rsp != NULL) ? parse_hss_response(*rsp) :
                                    PJSIP_SC_TEMPORARILY_UNAVAILABLE;

  if ((status_code == PJSIP_SC_OK) &&
      (_scscf.size() == 0))
  {
    // HSS did not return an S-CSCF, so select one if we have capabilities.
    if (_have_caps)
    {
      // Received capabilities from the HSS, so select a suitable
      _scscf = _scscf_selector->get_scscf(_mandatory_caps, _optional_caps);
    }

    if (_scscf.empty())
    {
      // Either no capabilities returned, or failed to select an S-CSCF
      // providing all the mandatory parameters, so return 600 Busy
      // Everywhere response.
      status_code = PJSIP_SC_BUSY_EVERYWHERE;
    }
  }

  return status_code;
}


int ICSCFProxy::UASTsx::parse_hss_response(Json::Value& rsp)
{
  int status_code = PJSIP_SC_OK;

  if (rsp["result-code"] != "DIAMETER_SUCCESS")
  {
    // Error from HSS, so response with 404 Not Found.  (This may be changed
    // to 403 Forbidden if request is a REGISTER.)
    status_code = PJSIP_SC_FORBIDDEN;
  }
  else
  {
    // Successful response from HSS, so parse it.
    if ((rsp.isMember("scscf")) &&
        (rsp["scscf"].isString()))
    {
      // Response specifies a S-CSCF, so select this as the target.
      LOG_DEBUG("HSS returned S-CSCF %s as target", rsp["scscf"].asCString());
      _scscf = rsp["scscf"].asString();
    }

    if ((rsp.isMember("mandatory-capabilities")) &&
        (rsp["mandatory-capabilities"].isArray()) &&
        (rsp.isMember("optional-capabilities")) &&
        (rsp["optional-capabilities"].isArray()))
    {
      // Response specifies capabilities.
      LOG_DEBUG("HSS returned capabilities");
      if ((parse_capabilities(rsp["mandatory-capabilities"], _mandatory_caps)) &&
          (parse_capabilities(rsp["optional-capabilities"], _optional_caps)))
      {
        // Parsed requested capabilities successfully
        _have_caps = true;
      }
    }
  }

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


