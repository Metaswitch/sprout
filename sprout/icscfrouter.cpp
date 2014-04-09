/**
 * @file icscfrouter.cpp  I-CSCF routing functions
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
#include "sasevent.h"
#include "icscfrouter.h"


ICSCFRouter::ICSCFRouter(HSSConnection* hss,
                         SCSCFSelector* scscf_selector,
                         SAS::TrailId trail,
                         ACR* acr) :
  _hss(hss),
  _scscf_selector(scscf_selector),
  _trail(trail),
  _acr(acr),
  _queried_caps(false),
  _hss_rsp(),
  _attempted_scscfs()
{
}


ICSCFRouter::~ICSCFRouter()
{
}


/// Selects the appropriate S-CSCF for the request, performing an HSS query
/// if required.
int ICSCFRouter::get_scscf(std::string& scscf)
{
  int status_code = PJSIP_SC_OK;

  if (!_queried_caps)
  {
    // Do the HSS query.
    status_code = hss_query();

    // TS 32.260 table 5.2.1.1 says we should generate an ACR[Event] on
    // completion of a Cx Query.  We therefore send the ACR here, but
    // leave it in place so we will send another ACR when the transaction
    // completes.  (Note that TS 32.260 isn't clear on whether this ACR
    // should be generated if the Cx Query fails - we are sending on both
    // success and failure, but that could be wrong.  Also, in the failure
    // case we will not include a Server-Capabilities AVP.)
    _acr->send_message();
  }

  if (status_code == PJSIP_SC_OK)
  {
    if ((!_hss_rsp.scscf.empty()) &&
        (std::find(_attempted_scscfs.begin(), _attempted_scscfs.end(),
                   _hss_rsp.scscf) == _attempted_scscfs.end()))
    {
      // The HSS returned a S-CSCF name and it's not one we have tried
      // already.
      scscf = _hss_rsp.scscf;
    }
    else if (_queried_caps)
    {
      // We queried capabilities from the HSS, so select a suitable S-CSCF.
      scscf = _scscf_selector->get_scscf(_hss_rsp.mandatory_caps,
                                         _hss_rsp.optional_caps,
                                         _attempted_scscfs);
    }

    if (!scscf.empty())
    {
      // Found an S-CSCF to try, so add it to the list of attempted S-CSCFs.
      _attempted_scscfs.push_back(scscf);
    }
    else
    {
      // Failed to select an S-CSCF providing all the mandatory parameters,
      // so return 600 Busy Everywhere response.
      status_code = PJSIP_SC_BUSY_EVERYWHERE;
    }
  }

  if (status_code == PJSIP_SC_OK)
  {
    SAS::Event event(trail(), SASEvent::SCSCF_SELECTION_SUCCESS, 0);
    event.add_var_param(scscf);
    event.add_var_param(_hss_rsp._scscf);
    SAS::report_event(event);
  }
  else
  {
    SAS::Event event(trail(), SASEvent::SCSCF_SELECTION_FAILED, 0);
    std::string st_code = std::to_string(status_code);
    event.add_var_param(st_code);
    SAS::report_event(event);
  }

  return status_code;
}


/// Parses the response from the HSS.
int ICSCFRouter::parse_hss_response(Json::Value& rsp, bool queried_caps)
{
  int status_code = PJSIP_SC_OK;

  // Clear out any older response.
  _queried_caps = false;
  _hss_rsp.mandatory_caps.clear();
  _hss_rsp.optional_caps.clear();
  _hss_rsp.scscf = "";

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
      _hss_rsp.scscf = rsp["scscf"].asString();
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
      if ((!parse_capabilities(rsp["mandatory-capabilities"], _hss_rsp.mandatory_caps)) ||
          (!parse_capabilities(rsp["optional-capabilities"], _hss_rsp.optional_caps)))
      {
        // Failed to parse capabilities, so reject with 480 response.
        LOG_WARNING("Malformed required capabilities returned by HSS\n%s",
                    rsp.toStyledString().c_str());
        status_code = PJSIP_SC_TEMPORARILY_UNAVAILABLE;
      }
    }
  }

  // Record whether or not we got valid capabilities from the HSS.  This can
  // either be because we forced capabilities in the query (in this case, empty
  // capabilities means the HSS doesn't care which S-CSCF we select) or because
  // the HSS decided to return capabilities anyway.
  _queried_caps = (status_code == PJSIP_SC_OK) ? queried_caps : false;

  if (_acr != NULL)
  {
    // Pass the server capabilities to the ACR for reporting.
    _acr->server_capabilities(_hss_rsp);
  }

  return status_code;
}


/// Parses a set of capabilities in the HSS response to a vector of integers.
bool ICSCFRouter::parse_capabilities(Json::Value& caps,
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


ICSCFUARouter::ICSCFUARouter(HSSConnection* hss,
                             SCSCFSelector* scscf_selector,
                             SAS::TrailId trail,
                             ACR* acr,
                             const std::string& impi,
                             const std::string& impu,
                             const std::string& visited_network,
                             const std::string& auth_type) :
  ICSCFRouter(hss, scscf_selector, trail, acr),
  _impi(impi),
  _impu(impu),
  _visited_network(visited_network),
  _auth_type(auth_type)
{
}

ICSCFUARouter::~ICSCFUARouter()
{
}


/// Performs an HSS UAR query.
int ICSCFUARouter::hss_query()
{
  int status_code = PJSIP_SC_OK;

  // If we've already done one query we must force the HSS to return
  // capabilities this time.
  std::string auth_type = (_hss_rsp.scscf.empty()) ? _auth_type : "CAPAB";

  LOG_DEBUG("Perform UAR - impi %s, impu %s, vn %s, auth_type %s",
            _impi.c_str(), _impu.c_str(),
            _visited_network.c_str(), auth_type.c_str());

  Json::Value* rsp = NULL;
  HTTPCode rc =_hss->get_user_auth_status(_impi,
                                          _impu,
                                          _visited_network,
                                          auth_type,
                                          rsp,
                                          _trail);

  if ((rc == HTTP_NOT_FOUND) ||
      (rc == HTTP_FORBIDDEN))
  {
    // HSS returned not found or forbidden, so reject the request with a
    // 403.
    status_code = PJSIP_SC_FORBIDDEN;
  }
  else if ((rc != HTTP_OK) ||
           (rsp == NULL))
  {
    // HSS failed to respond or responded with invalid data, so reject the
    // request with a 480.
    status_code = PJSIP_SC_TEMPORARILY_UNAVAILABLE;
  }
  else
  {
    // HSS returned a well-formed response, so parse it.
    status_code = parse_hss_response(*rsp, auth_type == "CAPAB");

    if (status_code == PJSIP_SC_NOT_FOUND)
    {
      // HSS reported an 2xxx result which the parser returns as a
      // 404 response.  Convert this to a 403 Forbidden response for
      // REGISTER requests.
      status_code = PJSIP_SC_FORBIDDEN;
    }
  }

  delete rsp;

  return status_code;
}


ICSCFLIRouter::ICSCFLIRouter(HSSConnection* hss,
                             SCSCFSelector* scscf_selector,
                             SAS::TrailId trail,
                             ACR* acr,
                             const std::string& impu,
                             bool originating) :
  ICSCFRouter(hss, scscf_selector, trail, acr),
  _impu(impu),
  _originating(originating)
{
}


ICSCFLIRouter::~ICSCFLIRouter()
{
}


/// Performs an HSS LIR query.
int ICSCFLIRouter::hss_query()
{
  int status_code = PJSIP_SC_OK;

  // If we've already done one query we must force the HSS to return
  // capabilities this time.
  std::string auth_type = (_hss_rsp.scscf.empty()) ? "" : "CAPAB";

  LOG_DEBUG("Perform LIR - impu %s, originating %s, auth_type %s",
            _impu.c_str(),
            (_originating) ? "true" : "false",
            (auth_type != "") ? auth_type.c_str() : "None");
  Json::Value* rsp = NULL;
  HTTPCode rc =_hss->get_location_data(_impu,
                                       _originating,
                                       auth_type,
                                       rsp,
                                       _trail);

  if (rc == HTTP_NOT_FOUND)
  {
    // HSS returned not found, so reject the request with a 404.
    status_code = PJSIP_SC_NOT_FOUND;
  }
  else if ((rc != HTTP_OK) ||
           (rsp == NULL))
  {
    // HSS failed to respond or responded with invalid data, so reject the
    // request with a 480.
    // LCOV_EXCL_START
    status_code = PJSIP_SC_TEMPORARILY_UNAVAILABLE;
    // LCOV_EXCL_STOP
  }
  else
  {
    // HSS returned a well-formed response, so parse it.
    status_code = parse_hss_response(*rsp, auth_type == "CAPAB");
  }

  delete rsp;

  return status_code;
}


