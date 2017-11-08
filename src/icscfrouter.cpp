/**
 * @file icscfrouter.cpp  I-CSCF routing functions
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
#include "sproutsasevent.h"
#include "icscfrouter.h"
#include "pjutils.h"
#include "uri_classifier.h"

ICSCFRouter::ICSCFRouter(HSSConnection* hss,
                         SCSCFSelector* scscf_selector,
                         SAS::TrailId trail,
                         ACR* acr,
                         int port,
                         std::set<std::string> blacklisted_scscfs) :
  _hss(hss),
  _scscf_selector(scscf_selector),
  _trail(trail),
  _acr(acr),
  _port(port),
  _queried_caps(false),
  _hss_rsp(),
  _attempted_scscfs(),
  _blacklisted_scscfs(blacklisted_scscfs)
{
}


ICSCFRouter::~ICSCFRouter()
{
}


/// Selects the appropriate S-CSCF for the request, performing an HSS query
/// if required.
///
/// @param pool          Pool to parse the SCSCF URI into.  This must be valid
///                      for at least as long as the returned SCSCF URI.
/// @param scscf_sip_uri Output parameter holding the parsed SCSCF URI.  This
///                      is only valid if the function returns PJSIP_SC_OK.
/// @param wildcard      Output parameter holding any wildcard identity in the
///                      response
/// @param do_billing    Flag to determine whether we send an ACR after the HSS
///                      query. Defaults to 'false'
int ICSCFRouter::get_scscf(pj_pool_t* pool,
                           pjsip_sip_uri*& scscf_sip_uri,
                           std::string& wildcard,
                           bool do_billing)
{
  int status_code = PJSIP_SC_OK;
  std::string scscf;
  scscf_sip_uri = NULL;

  if (!_queried_caps)
  {
    // Do the HSS query.
    status_code = hss_query();

    if (do_billing)
    {
      _acr->send();
    }
  }

  if (status_code == PJSIP_SC_OK)
  {
    wildcard = _hss_rsp.wildcard;
    if ((!_hss_rsp.scscf.empty()) && 
        (_blacklisted_scscfs.find(_hss_rsp.scscf) != _blacklisted_scscfs.end()))
    {
      // The HSS returned blacklisted S-CSCF. Query the capabilities.
      TRC_DEBUG("S-CSCF %s is blacklisted - not routing request to this S-CSCF", _hss_rsp.scscf.c_str());
      _attempted_scscfs.push_back(_hss_rsp.scscf);
      status_code = hss_query();

      SAS::Event event(_trail, SASEvent::SCSCF_BLACKLISTED, 0);
      event.add_var_param(_hss_rsp.scscf);
      SAS::report_event(event);
    }

    if ((!_hss_rsp.scscf.empty()) &&
        (std::find(_attempted_scscfs.begin(), _attempted_scscfs.end(),
                   _hss_rsp.scscf) == _attempted_scscfs.end()))
    {
      // The HSS returned a S-CSCF name and it's not one we have tried
      // already.
      scscf = _hss_rsp.scscf;
      TRC_DEBUG("SCSCF specified by HSS: %s", scscf.c_str());
    }
    else if (_queried_caps)
    {
      // We queried capabilities from the HSS, so select a suitable S-CSCF.
      // We pass both _blacklisted_scscfs and _attempted_scscfs to be rejected 
      // since these are not suitable S-CSCFs.
      std::vector<std::string> rejected_scscfs;
      rejected_scscfs.insert(rejected_scscfs.end(), _attempted_scscfs.begin(), _attempted_scscfs.end());
      rejected_scscfs.insert(rejected_scscfs.end(), _blacklisted_scscfs.begin(), _blacklisted_scscfs.end());
      scscf = _scscf_selector->get_scscf(_hss_rsp.mandatory_caps,
                                         _hss_rsp.optional_caps,
                                         rejected_scscfs,
                                         _trail);
      TRC_DEBUG("SCSCF selected: %s", scscf.c_str());
    }

    if (!scscf.empty())
    {
      // Found an S-CSCF to try, so add it to the list of attempted S-CSCFs.
      _attempted_scscfs.push_back(scscf);

      // Check that the returned scscf is a valid SIP URI.
      pjsip_uri* scscf_uri = PJUtils::uri_from_string(scscf, pool);

      if ((scscf_uri != NULL) && PJSIP_URI_SCHEME_IS_SIP(scscf_uri))
      {
        // Check whether the URI points back to ourselves, i.e.
        // - The host is either this server or the home domain.
        // - The port is the I-CSCF port for this deployment
        //
        // If the URI matches these criteria, we need to reject this message
        // now (with a signature SAS log) as this is never valid and would
        // lead to an infinite loop (were it not for our separate Max-Forwards
        // checking).
        //
        // The motivation for putting an explicit check here (rather than
        // relying on Max Forwards checking) is that this is reasonably likely
        // to occur when turning up a new deployment: customers can very easily
        // get their S-CSCF and I-CSCF ports the wrong way round (resulting in
        // an I-CSCF loop) and this fix will save them time diagnosing the
        // condition.
        //
        // Note that we are only checking the I-CSCF => I-CSCF loop condition
        // explicitly in this way.  S-CSCF => S-CSCF loops are much harder to
        // explicitly block because messages can be legitimately routed by an
        // S-CSCF back to itself (with subtly changed headers) for various
        // reasons.  Max Forwards checking should catch these instances.
        pjsip_sip_uri *sip_uri = (pjsip_sip_uri*)scscf_uri;
        URIClass uri_class = URIClassifier::classify_uri(scscf_uri);

        if (((uri_class == NODE_LOCAL_SIP_URI) ||
             (uri_class == HOME_DOMAIN_SIP_URI)) &&
             (sip_uri->port == _port))
        {
          TRC_WARNING("SCSCF URI %s points back to ICSCF", scscf.c_str());
          status_code = PJSIP_SC_LOOP_DETECTED;
          SAS::Event event(_trail, SASEvent::SCSCF_ICSCF_LOOP_DETECTED, 0);
          SAS::report_event(event);
        }
        else
        {
          scscf_sip_uri = sip_uri;
        }
      }
      else
      {
        TRC_WARNING("Invalid SCSCF URI %s", scscf.c_str());
        status_code = PJSIP_SC_TEMPORARILY_UNAVAILABLE;
      }
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
    SAS::Event event(_trail, SASEvent::SCSCF_SELECTION_SUCCESS, 0);
    event.add_var_param(scscf);
    event.add_var_param(_hss_rsp.scscf);
    SAS::report_event(event);
  }
  else
  {
    SAS::Event event(_trail, SASEvent::SCSCF_SELECTION_FAILED, 0);
    std::string st_code = std::to_string(status_code);
    event.add_var_param(st_code);
    SAS::report_event(event);
  }

  return status_code;
}


/// Parses the response from the HSS.
int ICSCFRouter::parse_hss_response(rapidjson::Document*& rsp, bool queried_caps)
{
  int status_code = PJSIP_SC_OK;

  // Clear out any older response.
  _queried_caps = false;
  _hss_rsp.mandatory_caps.clear();
  _hss_rsp.optional_caps.clear();
  _hss_rsp.scscf = "";
  _hss_rsp.wildcard = "";

  if ((!rsp->HasMember("result-code")) ||
      (!(*rsp)["result-code"].IsInt()))
  {
    // Error from HSS, so respond with 404 Not Found.  (This may be changed
    // to 403 Forbidden if request is a REGISTER.)
    status_code = PJSIP_SC_NOT_FOUND;
  }
  else
  {
    int rc = (*rsp)["result-code"].GetInt();

    if ((rc == 2001) ||
        (rc == 2002) ||
        (rc == 2003))
    {
      // Successful response from HSS, so parse it.
      if ((rsp->HasMember("scscf")) &&
          ((*rsp)["scscf"].IsString()))
      {
        // Response specifies a S-CSCF, so select this as the target.
        TRC_DEBUG("HSS returned S-CSCF %s as target", (*rsp)["scscf"].GetString());
        _hss_rsp.scscf = (*rsp)["scscf"].GetString();
      }

      if ((rsp->HasMember("mandatory-capabilities")) &&
          ((*rsp)["mandatory-capabilities"].IsArray()) &&
          (rsp->HasMember("optional-capabilities")) &&
          ((*rsp)["optional-capabilities"].IsArray()))
      {
        // Response specifies capabilities - we might have explicitly
        // queried capabilities or implicitly because there was no
        // server assigned.
        TRC_DEBUG("HSS returned capabilities");
        queried_caps = true;

        if ((!parse_capabilities((*rsp)["mandatory-capabilities"],
                                 _hss_rsp.mandatory_caps)) ||
            (!parse_capabilities((*rsp)["optional-capabilities"],
                                 _hss_rsp.optional_caps)))
        {
          // Failed to parse capabilities, so reject with 480 response.
          TRC_INFO("Malformed required capabilities returned by HSS");
          status_code = PJSIP_SC_TEMPORARILY_UNAVAILABLE;
        }
      }

      if ((rsp->HasMember("wildcard-identity")) &&
          ((*rsp)["wildcard-identity"].IsString()))
      {
        // Response included a wildcard, so save this.
        TRC_DEBUG("HSS returned a wildcarded public user identity %s",
                  (*rsp)["wildcard-identity"].GetString());
        _hss_rsp.wildcard = (*rsp)["wildcard-identity"].GetString();
      }
    }
    else if (rc == 5003)
    {
      // Failure response from HSS indicating that a subscriber exists but is unregistered and
      // has no unregistered services, so respond with 480 Temporarily Unavailable.
      status_code = PJSIP_SC_TEMPORARILY_UNAVAILABLE;
    }
    else
    {
      // Error from HSS, so respond with 404 Not Found.  (This may be changed
      // to 403 Forbidden if request is a REGISTER.)
      status_code = PJSIP_SC_NOT_FOUND;
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
bool ICSCFRouter::parse_capabilities(rapidjson::Value& caps,
                                     std::vector<int>& parsed_caps)
{
  for (size_t ii = 0; ii < caps.Size(); ++ii)
  {
    if (caps[(int)ii].IsUint())
    {
      parsed_caps.push_back(caps[(int)ii].GetUint());
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
                             int port,
                             const std::string& impi,
                             const std::string& impu,
                             const std::string& visited_network,
                             const std::string& auth_type,
                             const bool& emergency,
                             std::set<std::string> blacklisted_scscfs) :
  ICSCFRouter(hss, scscf_selector, trail, acr, port, blacklisted_scscfs),
  _impi(impi),
  _impu(impu),
  _visited_network(visited_network),
  _auth_type(auth_type),
  _emergency(emergency)
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

  TRC_DEBUG("Perform UAR - impi %s, impu %s, vn %s, auth_type %s",
            _impi.c_str(), _impu.c_str(),
            _visited_network.c_str(), auth_type.c_str());

  rapidjson::Document* rsp = NULL;
  HTTPCode rc =_hss->get_user_auth_status(_impi,
                                          _impu,
                                          _visited_network,
                                          auth_type,
                                          _emergency,
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
    status_code = parse_hss_response(rsp, auth_type == "CAPAB");

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
                             int port,
                             const std::string& impu,
                             bool originating,
                             std::set<std::string> blacklisted_scscfs) :
  ICSCFRouter(hss, scscf_selector, trail, acr, port, blacklisted_scscfs),
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

  TRC_DEBUG("Perform LIR - impu %s, originating %s, auth_type %s",
            _impu.c_str(),
            (_originating) ? "true" : "false",
            (auth_type != "") ? auth_type.c_str() : "None");
  rapidjson::Document* rsp = NULL;
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
    status_code = parse_hss_response(rsp, auth_type == "CAPAB");
  }

  delete rsp;

  return status_code;
}


