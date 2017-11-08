/**
 * @file hssconnection.cpp HSSConnection class methods.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <cassert>
#include <string>
#include <memory>
#include <map>

#include "utils.h"
#include "wildcard_utils.h"
#include "log.h"
#include "sas.h"
#include "sproutsasevent.h"
#include "httpconnection.h"
#include "hssconnection.h"
#include "rapidjson/error/en.h"
#include "rapidxml/rapidxml_print.hpp"
#include "snmp_continuous_accumulator_table.h"
#include "xml_utils.h"
#include "sprout_xml_utils.h"

const std::string HSSConnection::REG = "reg";
const std::string HSSConnection::CALL = "call";
const std::string HSSConnection::DEREG_USER = "dereg-user";
const std::string HSSConnection::DEREG_ADMIN = "dereg-admin";
const std::string HSSConnection::DEREG_TIMEOUT = "dereg-timeout";
const std::string HSSConnection::AUTH_TIMEOUT = "dereg-auth-timeout";
const std::string HSSConnection::AUTH_FAIL = "dereg-auth-failed";

HSSConnection::HSSConnection(const std::string& server,
                             HttpResolver* resolver,
                             LoadMonitor *load_monitor,
                             SNMP::IPCountTable* homestead_count_tbl,
                             SNMP::EventAccumulatorTable* homestead_overall_latency_tbl,
                             SNMP::EventAccumulatorTable* homestead_mar_latency_tbl,
                             SNMP::EventAccumulatorTable* homestead_sar_latency_tbl,
                             SNMP::EventAccumulatorTable* homestead_uar_latency_tbl,
                             SNMP::EventAccumulatorTable* homestead_lir_latency_tbl,
                             CommunicationMonitor* comm_monitor,
                             SIFCService* sifc_service,
                             long homestead_timeout_ms) :
  _http(new HttpConnection(server,
                           false,
                           resolver,
                           homestead_count_tbl,
                           load_monitor,
                           SASEvent::HttpLogLevel::PROTOCOL,
                           comm_monitor,
                           "http",
                           false,
                           false,
                           homestead_timeout_ms)),
  _latency_tbl(homestead_overall_latency_tbl),
  _mar_latency_tbl(homestead_mar_latency_tbl),
  _sar_latency_tbl(homestead_sar_latency_tbl),
  _uar_latency_tbl(homestead_uar_latency_tbl),
  _lir_latency_tbl(homestead_lir_latency_tbl),
  _sifc_service(sifc_service)
{
}


HSSConnection::~HSSConnection()
{
  delete _http;
  _http = NULL;
}

/// Get an Authentication Vector as JSON object. Caller is responsible for deleting.
HTTPCode HSSConnection::get_auth_vector(const std::string& private_user_identity,
                                        const std::string& public_user_identity,
                                        const std::string& auth_type,
                                        const std::string& resync_auth,
                                        const std::string& server_name,
                                        rapidjson::Document*& av,
                                        SAS::TrailId trail)
{
  Utils::StopWatch stopWatch;
  stopWatch.start();

  SAS::Event event(trail, SASEvent::HTTP_HOMESTEAD_VECTOR, 0);
  event.add_var_param(private_user_identity);
  event.add_var_param(public_user_identity);
  event.add_var_param(auth_type);
  SAS::report_event(event);

  std::string path = "/impi/" +
                     Utils::url_escape(private_user_identity) +
                     "/av";

  if (!auth_type.empty())
  {
    path += "/" + auth_type;
  }

  if (!public_user_identity.empty())
  {
    path += "?impu=" + Utils::url_escape(public_user_identity);
  }

  if (!resync_auth.empty())
  {
    path += public_user_identity.empty() ? "?" : "&";
    path += "resync-auth=" + Utils::url_escape(resync_auth);
  }

  if (!server_name.empty())
  {
    path += (public_user_identity.empty() && resync_auth.empty()) ? "?" : "&";
    path += "server-name=" + Utils::url_escape(server_name);
  }

  HTTPCode rc = get_json_object(path, av, trail);
  unsigned long latency_us = 0;

  // Only accumulate the latency if we haven't already applied a
  // penalty
  if ((rc != HTTP_SERVER_UNAVAILABLE) &&
      (rc != HTTP_GATEWAY_TIMEOUT)    &&
      (stopWatch.read(latency_us)))
  {
    _latency_tbl->accumulate(latency_us);
    _mar_latency_tbl->accumulate(latency_us);
  }

  if (av == NULL)
  {
    TRC_ERROR("Failed to get Authentication Vector for %s",
              private_user_identity.c_str());
  }

  return rc;
}


/// Retrieve a JSON object from a path on the server. Caller is responsible for deleting.
HTTPCode HSSConnection::get_json_object(const std::string& path,
                                        rapidjson::Document*& json_object,
                                        SAS::TrailId trail)
{
  std::string json_data;
  HTTPCode rc = _http->send_get(path, json_data, "", trail);

  if (rc == HTTP_OK)
  {
    json_object = new rapidjson::Document;
    json_object->Parse<0>(json_data.c_str());

    if (json_object->HasParseError())
    {
      TRC_INFO("Failed to parse Homestead response:\nPath: %s\nData: %s\nError: %s",
               path.c_str(),
               json_data.c_str(),
               rapidjson::GetParseError_En(json_object->GetParseError()));
      delete json_object;
      json_object = NULL;
    }
  }
  else
  {
    json_object = NULL;
  }

  return rc;
}

rapidxml::xml_document<>* HSSConnection::parse_xml(std::string raw_data, const std::string& url = "")
{
  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;
  try
  {
    root->parse<0>(root->allocate_string(raw_data.c_str()));
  }
  catch (rapidxml::parse_error& err)
  {
    // report to the user the failure and their locations in the document.
    TRC_WARNING("Failed to parse Homestead response:\n %s\n %s\n %s", url.c_str(), raw_data.c_str(), err.what());
    delete root;
    root = NULL;
  }
  return root;
}


/// Make a PUT to the server and store off the XML response. Caller is
/// responsible for deleting the filled-in "root" pointer.
HTTPCode HSSConnection::put_for_xml_object(const std::string& path,
                                           std::string body,
                                           const bool& cache_allowed,
                                           rapidxml::xml_document<>*& root,
                                           SAS::TrailId trail)
{
  std::string raw_data;
  std::map<std::string, std::string> rsp_headers;
  std::vector<std::string> req_headers;

  if (!cache_allowed)
  {
    req_headers.push_back("Cache-control: no-cache");
  }

  HTTPCode http_code = _http->send_put(path,
                                       rsp_headers,
                                       raw_data,
                                       body,
                                       req_headers,
                                       trail);

  if (http_code == HTTP_OK)
  {
    root = parse_xml(raw_data, path);
  }

  return http_code;
}


/// Retrieve an XML object from a path on the server. Caller is responsible for deleting.
HTTPCode HSSConnection::get_xml_object(const std::string& path,
                                       rapidxml::xml_document<>*& root,
                                       SAS::TrailId trail)
{
  std::string raw_data;

  HTTPCode http_code = _http->send_get(path, raw_data, "", trail);

  if (http_code == HTTP_OK)
  {
    root = parse_xml(raw_data, path);
  }

  return http_code;
}


bool compare_charging_addrs(const rapidxml::xml_node<>* ca1,
                            const rapidxml::xml_node<>* ca2)
{
  // Compare the nodes on the basis of their priority attribute. A lower value is
  // higher priority.
  if (std::stoi(ca1->first_attribute(RegDataXMLUtils::CCF_ECF_PRIORITY)->value()) <
        std::stoi(ca2->first_attribute(RegDataXMLUtils::CCF_ECF_PRIORITY)->value()))
  {
    return true;
  }
  else
  {
    return false;
  }
}


// Decode the charging addresses node of the xml send from Homestead.
void parse_charging_addrs_node(rapidxml::xml_node<>* charging_addrs_node,
                               std::deque<std::string>& ccfs,
                               std::deque<std::string>& ecfs)
{
  rapidxml::xml_node<>* ccf = NULL;
  std::vector<rapidxml::xml_node<>*> xml_ccfs;
  rapidxml::xml_node<>* ecf = NULL;
  std::vector<rapidxml::xml_node<>*> xml_ecfs;

  // Save off all of the CCF nodes so that we can sort them based on their
  // priority attribute.
  for (ccf = charging_addrs_node->first_node(RegDataXMLUtils::CCF);
       ccf != NULL;
       ccf = ccf->next_sibling(RegDataXMLUtils::CCF))
  {
    xml_ccfs.push_back(ccf);
  }

  // Sort them and add them to ccfs in order.
  std::sort(xml_ccfs.begin(), xml_ccfs.end(), compare_charging_addrs);

  for (std::vector<rapidxml::xml_node<>*>::iterator it = xml_ccfs.begin();
       it != xml_ccfs.end();
       ++it)
  {
    TRC_DEBUG("Found CCF: %s", (*it)->value());
    ccfs.push_back((*it)->value());
  }

  // Save off all of the ECF nodes so that we can sort them based on their
  // priority attribute.
  for (ecf = charging_addrs_node->first_node(RegDataXMLUtils::ECF);
       ecf != NULL;
       ecf = ecf->next_sibling(RegDataXMLUtils::ECF))
  {
    xml_ecfs.push_back(ecf);
  }

  // Sort them and add them to ecfs in order.
  std::sort(xml_ecfs.begin(), xml_ecfs.end(), compare_charging_addrs);

  for (std::vector<rapidxml::xml_node<>*>::iterator it = xml_ecfs.begin();
       it != xml_ecfs.end();
       ++it)
  {
    TRC_DEBUG("Found ECF: %s", (*it)->value());
    ecfs.push_back((*it)->value());
  }
}

bool decode_homestead_xml(const std::string& public_id,
                          HSSConnection::irs_info& irs_info,
                          std::shared_ptr<rapidxml::xml_document<> > root,
                          SIFCService* sifc_service,
                          const bool& allowNoIMS,
                          SAS::TrailId trail)
{
  if (!root.get())
  {
    // If get_xml_object has not returned a document, there must have been a parsing error.
    TRC_WARNING("Malformed HSS XML for %s - document couldn't be parsed",
                public_id.c_str());
    return false;
  }

  rapidxml::xml_node<>* cw = root->first_node(RegDataXMLUtils::CLEARWATER_REG_DATA);

  if (!cw)
  {
    std::string sp_str;
    rapidxml::print(std::back_inserter(sp_str), *root, 0);
    TRC_WARNING("Malformed Homestead XML for %s - no ClearwaterRegData element:\n%s",
                public_id.c_str(),
                sp_str.c_str());
    return false;
  }

  rapidxml::xml_node<>* reg = cw->first_node(RegDataXMLUtils::REGISTRATION_STATE);

  if (!reg)
  {
    std::string sp_str;
    rapidxml::print(std::back_inserter(sp_str), *root, 0);
    TRC_WARNING("Malformed Homestead XML for %s - no RegistrationState element:\n%s",
                public_id.c_str(),
                sp_str.c_str());
    return false;
  }

  irs_info._regstate = reg->value();

  if ((irs_info._regstate == RegDataXMLUtils::STATE_NOT_REGISTERED) && (allowNoIMS))
  {
    TRC_DEBUG("Subscriber is not registered on a get_registration_state request");
    return true;
  }

  // Look for the Previous Registration State.  If there is no Previous
  // Registration State in the message set prev_regstate to the empty
  // string.
  rapidxml::xml_node<>* prev_reg = cw->first_node(RegDataXMLUtils::PREVIOUS_REGISTRATION_STATE);
  irs_info._prev_regstate = (!prev_reg) ? "" : prev_reg->value();

  rapidxml::xml_node<>* imss = cw->first_node(RegDataXMLUtils::IMS_SUBSCRIPTION);

  if (!imss)
  {
    std::string sp_str;
    rapidxml::print(std::back_inserter(sp_str), *root, 0);
    TRC_WARNING("Malformed HSS XML for %s - no IMSSubscription element:\n%s",
                public_id.c_str(),
                sp_str.c_str());
    return false;
  }

  if (!SproutXmlUtils::parse_ims_subscription(public_id,
                                              root,
                                              imss,
                                              irs_info._service_profiles,
                                              irs_info._associated_uris,
                                              irs_info._aliases,
                                              sifc_service,
                                              trail))
  {
    std::string sp_str;
    rapidxml::print(std::back_inserter(sp_str), *root, 0);
    TRC_WARNING("Malformed HSS XML for %s:\n%s",
                public_id.c_str(),
                sp_str.c_str());
    return false;
  }

  rapidxml::xml_node<>* charging_addrs_node = cw->first_node("ChargingAddresses");

  if (charging_addrs_node)
  {
    parse_charging_addrs_node(charging_addrs_node, irs_info._ccfs, irs_info._ecfs);
  }
  return true;
}


/// Retrieve user's subscription data from the HSS, filling in the associated
//  URIs in the associated_uris output parameter and the Ifcs object
//  corresponding to each in the ifcs_map parameter.

// Returns the HTTP code from Homestead - callers should check that
// this is HTTP_OK before relying on the output parameters.

HTTPCode HSSConnection::update_registration_state(const irs_query& irs_query,
                                                  irs_info& irs_info,
                                                  SAS::TrailId trail)
{
  Utils::StopWatch stopWatch;
  stopWatch.start();

  SAS::Event event(trail, SASEvent::HTTP_HOMESTEAD_CHECK_STATE, 0);
  event.add_var_param(irs_query._public_id);
  event.add_var_param(irs_query._private_id);
  event.add_var_param(irs_query._req_type);
  SAS::report_event(event);

  std::string path = "/impu/" +
                     Utils::url_escape(irs_query._public_id) +
                     "/reg-data";

  if (!irs_query._private_id.empty())
  {
    path += "?private_id=" +
            Utils::url_escape(irs_query._private_id);
  }

  TRC_DEBUG("Making Homestead request for %s", path.c_str());
  // Needs to be a shared pointer - multiple Ifcs objects will need a reference
  // to it, so we want to delete the underlying document when they all go out
  // of scope.

  rapidxml::xml_document<>* root_underlying_ptr = NULL;
  std::string json_wildcard = (irs_query._wildcard != "") ?
    ", \"wildcard_identity\": \"" +
    irs_query._wildcard +
    "\""
    : "";

  std::string req_body = "{\"reqtype\": \"" +
                         irs_query._req_type +
                         "\"" +
                         ", \"server_name\": \"" +
                         irs_query._server_name +
                         "\"" +
                         json_wildcard +
                         "}";
  HTTPCode http_code = put_for_xml_object(path,
                                          req_body,
                                          irs_query._cache_allowed,
                                          root_underlying_ptr,
                                          trail);
  std::shared_ptr<rapidxml::xml_document<> > root (root_underlying_ptr);

  unsigned long latency_us = 0;

  // Only accumulate the latency if we haven't already applied a
  // penalty
  if ((http_code != HTTP_SERVER_UNAVAILABLE) &&
      (http_code != HTTP_GATEWAY_TIMEOUT)    &&
      (stopWatch.read(latency_us)))
  {
    _latency_tbl->accumulate(latency_us);
    _sar_latency_tbl->accumulate(latency_us);
  }

  if (http_code != HTTP_OK)
  {
    // If get_xml_object has returned a HTTP error code, we have either not found
    // the subscriber on the HSS or been unable to communicate with
    // the HSS successfully. In either case we should fail.
    TRC_ERROR("Could not get subscriber data from HSS");
    return http_code;
  }
  return decode_homestead_xml(irs_query._public_id,
                              irs_info,
                              root,
                              _sifc_service,
                              false,
                              trail) ? HTTP_OK : HTTP_SERVER_ERROR;
}


HTTPCode HSSConnection::get_registration_data(const std::string& public_id,
                                              irs_info& irs_info,
                                              SAS::TrailId trail)
{
  Utils::StopWatch stopWatch;
  stopWatch.start();

  SAS::Event event(trail, SASEvent::HTTP_HOMESTEAD_GET_REG, 0);
  event.add_var_param(public_id);
  SAS::report_event(event);

  std::string path = "/impu/" +
                     Utils::url_escape(public_id) +
                     "/reg-data";

  TRC_DEBUG("Making Homestead request for %s", path.c_str());
  rapidxml::xml_document<>* root_underlying_ptr = NULL;
  HTTPCode http_code = get_xml_object(path, root_underlying_ptr, trail);

  // Needs to be a shared pointer - multiple Ifcs objects will need a reference
  // to it, so we want to delete the underlying document when they all go out
  // of scope.
  std::shared_ptr<rapidxml::xml_document<> > root (root_underlying_ptr);
  unsigned long latency_us = 0;

  // Only accumulate the latency if we haven't already applied a
  // penalty
  if ((http_code != HTTP_SERVER_UNAVAILABLE) &&
      (http_code != HTTP_GATEWAY_TIMEOUT)    &&
      (stopWatch.read(latency_us)))
  {
    _latency_tbl->accumulate(latency_us);
    _sar_latency_tbl->accumulate(latency_us);
  }

  if (http_code != HTTP_OK)
  {
    // If get_xml_object has returned a HTTP error code, we have either not found
    // the subscriber on the HSS or been unable to communicate with
    // the HSS successfully. In either case we should fail.
    TRC_ERROR("Could not get subscriber data from HSS");
    return http_code;
  }

  // Return whether the XML was successfully decoded. The XML can be decoded and
  // not return any iFCs (when the subscriber isn't registered), so a successful
  // response shouldn't be taken as a guarantee of iFCs.
  return decode_homestead_xml(public_id,
                              irs_info,
                              root,
                              _sifc_service,
                              true,
                              trail) ? HTTP_OK : HTTP_SERVER_ERROR;
}


// Makes a user authorization request, and returns the data as a JSON object.
HTTPCode HSSConnection::get_user_auth_status(const std::string& private_user_identity,
                                             const std::string& public_user_identity,
                                             const std::string& visited_network,
                                             const std::string& auth_type,
                                             const bool& emergency,
                                             rapidjson::Document*& user_auth_status,
                                             SAS::TrailId trail)
{
  Utils::StopWatch stopWatch;
  stopWatch.start();

  SAS::Event event(trail, SASEvent::HTTP_HOMESTEAD_AUTH_STATUS, 0);
  event.add_var_param(private_user_identity);
  event.add_var_param(public_user_identity);
  SAS::report_event(event);

  std::string path = "/impi/" +
                     Utils::url_escape(private_user_identity) +
                     "/registration-status" +
                     "?impu=" +
                     Utils::url_escape(public_user_identity);

  if (!visited_network.empty())
  {
    path += "&visited-network=" + Utils::url_escape(visited_network);
  }
  if (!auth_type.empty())
  {
    path += "&auth-type=" + Utils::url_escape(auth_type);
  }
  if (emergency)
  {
    path += "&sos=true";
  }

  HTTPCode rc = get_json_object(path, user_auth_status, trail);

  unsigned long latency_us = 0;
  // Only accumulate the latency if we haven't already applied a
  // penalty
  if ((rc != HTTP_SERVER_UNAVAILABLE) &&
      (rc != HTTP_GATEWAY_TIMEOUT)    &&
      (stopWatch.read(latency_us)))
  {
    _latency_tbl->accumulate(latency_us);
    _uar_latency_tbl->accumulate(latency_us);
  }

  return rc;
}

/// Makes a location information request, and returns the data as a JSON object.
HTTPCode HSSConnection::get_location_data(const std::string& public_user_identity,
                                          const bool& originating,
                                          const std::string& auth_type,
                                          rapidjson::Document*& location_data,
                                          SAS::TrailId trail)
{
  Utils::StopWatch stopWatch;
  stopWatch.start();

  SAS::Event event(trail, SASEvent::HTTP_HOMESTEAD_LOCATION, 0);
  event.add_var_param(public_user_identity);
  SAS::report_event(event);

  std::string path = "/impu/" +
                     Utils::url_escape(public_user_identity) +
                     "/location";

  if (originating)
  {
    path += "?originating=true";
  }
  if (!auth_type.empty())
  {
    std::string prefix = !originating ? "?" : "&";
    path += prefix + "auth-type=" + Utils::url_escape(auth_type);
  }

  HTTPCode rc = get_json_object(path, location_data, trail);

  unsigned long latency_us = 0;
  // Only accumulate the latency if we haven't already applied a
  // penalty
  if ((rc != HTTP_SERVER_UNAVAILABLE) &&
      (rc != HTTP_GATEWAY_TIMEOUT)    &&
      (stopWatch.read(latency_us)))
  {
    _latency_tbl->accumulate(latency_us);
    _lir_latency_tbl->accumulate(latency_us);
  }

  return rc;
}
