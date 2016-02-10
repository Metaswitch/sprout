/**
 * @file hssconnection.cpp HSSConnection class methods.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
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

#include <cassert>
#include <string>
#include <memory>
#include <map>

#include "utils.h"
#include "log.h"
#include "sas.h"
#include "sproutsasevent.h"
#include "httpconnection.h"
#include "hssconnection.h"
#include "rapidjson/error/en.h"
#include "snmp_continuous_accumulator_table.h"

const std::string HSSConnection::REG = "reg";
const std::string HSSConnection::CALL = "call";
const std::string HSSConnection::DEREG_USER = "dereg-user";
const std::string HSSConnection::DEREG_ADMIN = "dereg-admin";
const std::string HSSConnection::DEREG_TIMEOUT = "dereg-timeout";
const std::string HSSConnection::AUTH_TIMEOUT = "dereg-auth-timeout";
const std::string HSSConnection::AUTH_FAIL = "dereg-auth-failed";

const std::string HSSConnection::STATE_REGISTERED = "REGISTERED";
const std::string HSSConnection::STATE_NOT_REGISTERED = "NOT_REGISTERED";

HSSConnection::HSSConnection(const std::string& server,
                             HttpResolver* resolver,
                             LoadMonitor *load_monitor,
                             SNMP::IPCountTable* homestead_count_tbl,
                             SNMP::EventAccumulatorTable* homestead_overall_latency_tbl,
                             SNMP::EventAccumulatorTable* homestead_mar_latency_tbl,
                             SNMP::EventAccumulatorTable* homestead_sar_latency_tbl,
                             SNMP::EventAccumulatorTable* homestead_uar_latency_tbl,
                             SNMP::EventAccumulatorTable* homestead_lir_latency_tbl,
                             CommunicationMonitor* comm_monitor) :
  _http(new HttpConnection(server,
                           false,
                           resolver,
                           homestead_count_tbl,
                           load_monitor,
                           SASEvent::HttpLogLevel::PROTOCOL,
                           comm_monitor)),
  _latency_tbl(homestead_overall_latency_tbl),
  _mar_latency_tbl(homestead_mar_latency_tbl),
  _sar_latency_tbl(homestead_sar_latency_tbl),
  _uar_latency_tbl(homestead_uar_latency_tbl),
  _lir_latency_tbl(homestead_lir_latency_tbl)
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
      TRC_INFO("Failed to parse Homestead response:\nPath: %s\nData: %s\nError: %s\n",
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
    TRC_WARNING("Failed to parse Homestead response:\n %s\n %s\n %s\n", url.c_str(), raw_data.c_str(), err.what());
    delete root;
    root = NULL;
  }
  return root;
}


/// Make a PUT to the server and store off the XML response. Caller is
/// responsible for deleting the filled-in "root" pointer.
HTTPCode HSSConnection::put_for_xml_object(const std::string& path,
                                           std::string body,
                                           bool cache_allowed,
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
  if (std::stoi(ca1->first_attribute("priority")->value()) <
        std::stoi(ca2->first_attribute("priority")->value()))
  {
    return true;
  }
  else
  {
    return false;
  }
}


bool decode_homestead_xml(const std::string public_user_identity,
                          std::shared_ptr<rapidxml::xml_document<> > root,
                          std::string& regstate,
                          std::map<std::string, Ifcs >& ifcs_map,
                          std::vector<std::string>& associated_uris,
                          std::vector<std::string>& aliases,
                          std::deque<std::string>& ccfs,
                          std::deque<std::string>& ecfs,
                          bool allowNoIMS)
{
  if (!root.get())
  {
    // If get_xml_object has not returned a document, there must have been a parsing error.
    TRC_WARNING("Malformed HSS XML - document couldn't be parsed");
    return false;
  }

  rapidxml::xml_node<>* cw = root->first_node("ClearwaterRegData");

  if (!cw)
  {
    TRC_WARNING("Malformed Homestead XML - no ClearwaterRegData element");
    return false;
  }

  rapidxml::xml_node<>* reg = cw->first_node("RegistrationState");

  if (!reg)
  {
    TRC_WARNING("Malformed Homestead XML - no RegistrationState element");
    return false;
  }

  regstate = reg->value();

  if ((regstate == HSSConnection::STATE_NOT_REGISTERED) && (allowNoIMS))
  {
    TRC_DEBUG("Subscriber is not registered on a get_registration_state request");
    return true;
  }

  rapidxml::xml_node<>* imss = cw->first_node("IMSSubscription");

  if (!imss)
  {
    TRC_WARNING("Malformed HSS XML - no IMSSubscription element");
    return false;
  }

  // The set of aliases consists of the set of public identities in the same
  // Service Profile. It is a subset of the associated URIs. In order to find
  // the set of aliases we want, we need to find the Service Profile containing
  // our public identity and then save off all of the public identities in this
  // Service Profile.
  //
  // sp_identities is used to save the public identities in the current Service
  // Profile.
  // current_sp_contains_public_id is a flag used to indicate that the Service
  // Profile we're currently cycling through contains our public identity.
  // found_aliases is a flag used to indicate that we've already found our list
  // of aliases.
  std::vector<std::string> sp_identities;
  bool current_sp_contains_public_id = false;
  bool found_aliases = false;
  rapidxml::xml_node<>* sp = NULL;

  if (!imss->first_node("ServiceProfile"))
  {
    TRC_WARNING("Malformed HSS XML - no ServiceProfiles");
    return false;
  }

  for (sp = imss->first_node("ServiceProfile");
       sp != NULL;
       sp = sp->next_sibling("ServiceProfile"))
  {
    Ifcs ifc(root, sp);
    rapidxml::xml_node<>* public_id = NULL;

    if (!sp->first_node("PublicIdentity"))
    {
      TRC_WARNING("Malformed ServiceProfile XML - no Public Identity");
      return false;
    }

    for (public_id = sp->first_node("PublicIdentity");
         public_id != NULL;
         public_id = public_id->next_sibling("PublicIdentity"))
    {
      rapidxml::xml_node<>* identity = public_id->first_node("Identity");

      if (identity)
      {
        std::string uri = std::string(identity->value());
        TRC_DEBUG("Processing Identity node from HSS XML - %s\n",
                  uri.c_str());

        associated_uris.push_back(uri);
        ifcs_map[uri] = ifc;

        if (!found_aliases)
        {
          sp_identities.push_back(uri);

          if (uri == public_user_identity)
          {
            current_sp_contains_public_id = true;
          }
        }
      }
      else
      {
        TRC_WARNING("Malformed PublicIdentity XML - no Identity");
        return false;
      }
    }

    if (!found_aliases)
    {
      if (current_sp_contains_public_id)
      {
        aliases = sp_identities;
        found_aliases = true;
      }
      else
      {
        sp_identities.clear();
      }
    }
  }

  rapidxml::xml_node<>* charging_addrs_node = cw->first_node("ChargingAddresses");

  if (charging_addrs_node)
  {
    rapidxml::xml_node<>* ccf = NULL;
    std::vector<rapidxml::xml_node<>*> xml_ccfs;
    rapidxml::xml_node<>* ecf = NULL;
    std::vector<rapidxml::xml_node<>*> xml_ecfs;

    // Save off all of the CCF nodes so that we can sort them based on their
    // priority attribute.
    for (ccf = charging_addrs_node->first_node("CCF");
         ccf != NULL;
         ccf = ccf->next_sibling("CCF"))
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
    for (ecf = charging_addrs_node->first_node("ECF");
         ecf != NULL;
         ecf = ecf->next_sibling("ECF"))
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
  return true;
}


/// Retrieve user's subscription data from the HSS, filling in the associated
//  URIs in the associated_uris output parameter and the Ifcs object
//  corresponding to each in the ifcs_map parameter.

// Returns the HTTP code from Homestead - callers should check that
// this is HTTP_OK before relying on the output parameters.

HTTPCode HSSConnection::update_registration_state(const std::string& public_user_identity,
                                                  const std::string& private_user_identity,
                                                  const std::string& type,
                                                  std::string& regstate,
                                                  std::map<std::string, Ifcs >& ifcs_map,
                                                  std::vector<std::string>& associated_uris,
                                                  SAS::TrailId trail)
{
  std::vector<std::string> unused_aliases;
  std::deque<std::string> unused_ccfs;
  std::deque<std::string> unused_ecfs;
  return update_registration_state(public_user_identity,
                                   private_user_identity,
                                   type,
                                   regstate,
                                   ifcs_map,
                                   associated_uris,
                                   unused_aliases,
                                   unused_ccfs,
                                   unused_ecfs,
                                   true,
                                   trail);
}

HTTPCode HSSConnection::update_registration_state(const std::string& public_user_identity,
                                                  const std::string& private_user_identity,
                                                  const std::string& type,
                                                  std::map<std::string, Ifcs >& ifcs_map,
                                                  std::vector<std::string>& associated_uris,
                                                  SAS::TrailId trail)
{
  std::string unused;
  std::vector<std::string> unused_aliases;
  std::deque<std::string> unused_ccfs;
  std::deque<std::string> unused_ecfs;
  return update_registration_state(public_user_identity,
                                   private_user_identity,
                                   type,
                                   unused,
                                   ifcs_map,
                                   associated_uris,
                                   unused_aliases,
                                   unused_ccfs,
                                   unused_ecfs,
                                   true,
                                   trail);
}

HTTPCode HSSConnection::update_registration_state(const std::string& public_user_identity,
                                                  const std::string& private_user_identity,
                                                  const std::string& type,
                                                  SAS::TrailId trail)
{
  std::map<std::string, Ifcs > ifcs_map;
  std::vector<std::string> associated_uris;
  std::string unused;
  std::vector<std::string> unused_aliases;
  std::deque<std::string> unused_ccfs;
  std::deque<std::string> unused_ecfs;
  return update_registration_state(public_user_identity,
                                   private_user_identity,
                                   type,
                                   unused,
                                   ifcs_map,
                                   associated_uris,
                                   unused_aliases,
                                   unused_ccfs,
                                   unused_ecfs,
                                   true,
                                   trail);
}

HTTPCode HSSConnection::update_registration_state(const std::string& public_user_identity,
                                                  const std::string& private_user_identity,
                                                  const std::string& type,
                                                  std::string& regstate,
                                                  std::map<std::string, Ifcs >& ifcs_map,
                                                  std::vector<std::string>& associated_uris,
                                                  std::deque<std::string>& ccfs,
                                                  std::deque<std::string>& ecfs,
                                                  SAS::TrailId trail)
{
  std::vector<std::string> unused_aliases;
  return update_registration_state(public_user_identity,
                                   private_user_identity,
                                   type,
                                   regstate,
                                   ifcs_map,
                                   associated_uris,
                                   unused_aliases,
                                   ccfs,
                                   ecfs,
                                   true,
                                   trail);
}

HTTPCode HSSConnection::update_registration_state(const std::string& public_user_identity,
                                                  const std::string& private_user_identity,
                                                  const std::string& type,
                                                  std::string& regstate,
                                                  std::map<std::string, Ifcs >& ifcs_map,
                                                  std::vector<std::string>& associated_uris,
                                                  std::vector<std::string>& aliases,
                                                  std::deque<std::string>& ccfs,
                                                  std::deque<std::string>& ecfs,
                                                  bool cache_allowed,
                                                  SAS::TrailId trail)
{
  Utils::StopWatch stopWatch;
  stopWatch.start();

  SAS::Event event(trail, SASEvent::HTTP_HOMESTEAD_CHECK_STATE, 0);
  event.add_var_param(public_user_identity);
  event.add_var_param(private_user_identity);
  event.add_var_param(type);
  SAS::report_event(event);

  std::string path = "/impu/" + Utils::url_escape(public_user_identity) + "/reg-data";
  if (!private_user_identity.empty())
  {
    path += "?private_id=" + Utils::url_escape(private_user_identity);
  }

  TRC_DEBUG("Making Homestead request for %s", path.c_str());
  // Needs to be a shared pointer - multiple Ifcs objects will need a reference
  // to it, so we want to delete the underlying document when they all go out
  // of scope.

  rapidxml::xml_document<>* root_underlying_ptr = NULL;
  HTTPCode http_code = put_for_xml_object(path,
                                          "{\"reqtype\": \""+type+"\"}",
                                          cache_allowed,
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

  return decode_homestead_xml(public_user_identity,
                              root,
                              regstate,
                              ifcs_map,
                              associated_uris,
                              aliases,
                              ccfs,
                              ecfs,
                              false) ? HTTP_OK : HTTP_SERVER_ERROR;
}

HTTPCode HSSConnection::get_registration_data(const std::string& public_user_identity,
                                              std::string& regstate,
                                              std::map<std::string, Ifcs >& ifcs_map,
                                              std::vector<std::string>& associated_uris,
                                              SAS::TrailId trail)
{
  std::deque<std::string> unused_ccfs;
  std::deque<std::string> unused_ecfs;
  return get_registration_data(public_user_identity,
                               regstate,
                               ifcs_map,
                               associated_uris,
                               unused_ccfs,
                               unused_ecfs,
                               trail);
}

HTTPCode HSSConnection::get_registration_data(const std::string& public_user_identity,
                                              std::string& regstate,
                                              std::map<std::string, Ifcs >& ifcs_map,
                                              std::vector<std::string>& associated_uris,
                                              std::deque<std::string>& ccfs,
                                              std::deque<std::string>& ecfs,
                                              SAS::TrailId trail)
{
  Utils::StopWatch stopWatch;
  stopWatch.start();

  SAS::Event event(trail, SASEvent::HTTP_HOMESTEAD_GET_REG, 0);
  event.add_var_param(public_user_identity);
  SAS::report_event(event);

  std::string path = "/impu/" + Utils::url_escape(public_user_identity) + "/reg-data";

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
  // not return any IFCs (when the subscriber isn't registered), so a successful
  // response shouldn't be taken as a guarantee of IFCs.
  std::vector<std::string> unused_aliases;
  return decode_homestead_xml(public_user_identity,
                              root,
                              regstate,
                              ifcs_map,
                              associated_uris,
                              unused_aliases,
                              ccfs,
                              ecfs,
                              true) ? HTTP_OK : HTTP_SERVER_ERROR;
}


// Makes a user authorization request, and returns the data as a JSON object.
HTTPCode HSSConnection::get_user_auth_status(const std::string& private_user_identity,
                                             const std::string& public_user_identity,
                                             const std::string& visited_network,
                                             const std::string& auth_type,
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
