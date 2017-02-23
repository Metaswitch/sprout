/**
 * @file hssconnection.h Definitions for HSSConnection class.
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

///
///

#ifndef HSSCONNECTION_H__
#define HSSCONNECTION_H__

#include <curl/curl.h>
#include "rapidjson/document.h"

#include "httpconnection.h"
#include "rapidxml/rapidxml.hpp"
#include "ifchandler.h"
#include "sas.h"
#include "snmp_event_accumulator_table.h"
#include "load_monitor.h"

/// @class HSSConnection
///
/// Provides a connection to the Homstead service for retrieving user
/// profiles and authentication information.
///
class HSSConnection
{
public:
  HSSConnection(const std::string& server,
                HttpResolver* resolver,
                LoadMonitor *load_monitor,
                SNMP::IPCountTable* homestead_count_tbl,
                SNMP::EventAccumulatorTable* homestead_overall_latency_tbl,
                SNMP::EventAccumulatorTable* homestead_mar_latency_tbl,
                SNMP::EventAccumulatorTable* homestead_sar_latency_tbl,
                SNMP::EventAccumulatorTable* homestead_uar_latency_tbl,
                SNMP::EventAccumulatorTable* homestead_lir_latency_tbl,
                CommunicationMonitor* comm_monitor,
                std::string scscf_uri,
                bool fallback_if_no_matching_ifc = false);
  virtual ~HSSConnection();

  HTTPCode get_auth_vector(const std::string& private_user_id,
                           const std::string& public_user_id,
                           const std::string& auth_type,
                           const std::string& autn,
                           rapidjson::Document*& object,
                           SAS::TrailId trail);
  HTTPCode get_user_auth_status(const std::string& private_user_identity,
                                const std::string& public_user_identity,
                                const std::string& visited_network,
                                const std::string& auth_type,
                                rapidjson::Document*& object,
                                SAS::TrailId trail);
  HTTPCode get_location_data(const std::string& public_user_identity,
                             const bool& originating,
                             const std::string& auth_type,
                             rapidjson::Document*& object,
                             SAS::TrailId trail);

  HTTPCode update_registration_state(const std::string& public_user_identity,
                                     const std::string& private_user_identity,
                                     const std::string& type,
                                     std::string& regstate,
                                     std::map<std::string, Ifcs >& service_profiles,
                                     std::vector<std::string>& associated_uris,
                                     std::vector<std::string>& aliases,
                                     std::deque<std::string>& ccfs,
                                     std::deque<std::string>& ecfs,
                                     bool cache_allowed,
                                     const std::string& wildcard,
                                     SAS::TrailId trail);
  virtual HTTPCode update_registration_state(const std::string& public_user_identity,
                                             const std::string& private_user_identity,
                                             const std::string& type,
                                             std::string& regstate,
                                             std::map<std::string, Ifcs >& service_profiles,
                                             std::vector<std::string>& associated_uris,
                                             std::deque<std::string>& ccfs,
                                             std::deque<std::string>& ecfs,
                                             SAS::TrailId trail);
  HTTPCode update_registration_state(const std::string& public_user_identity,
                                     const std::string& private_user_identity,
                                     const std::string& type,
                                     std::string& regstate,
                                     std::map<std::string, Ifcs >& service_profiles,
                                     std::vector<std::string>& associated_uris,
                                     SAS::TrailId trail);
  virtual HTTPCode update_registration_state(const std::string& public_user_identity,
                                             const std::string& private_user_identity,
                                             const std::string& type,
                                             SAS::TrailId trail);
  virtual HTTPCode update_registration_state(const std::string& public_user_identity,
                                             const std::string& private_user_identity,
                                             const std::string& type,
                                             std::map<std::string, Ifcs >& service_profiles,
                                             std::vector<std::string>& associated_uris,
                                             SAS::TrailId trail);

  HTTPCode get_registration_data(const std::string& public_user_identity,
                                 std::string& regstate,
                                 std::map<std::string, Ifcs >& service_profiles,
                                 std::vector<std::string>& associated_uris,
                                 std::deque<std::string>& ccfs,
                                 std::deque<std::string>& ecfs,
                                 SAS::TrailId trail);
  virtual HTTPCode get_registration_data(const std::string& public_user_identity,
                                         std::string& regstate,
                                         std::map<std::string, Ifcs >& service_profiles,
                                         std::vector<std::string>& associated_uris,
                                         SAS::TrailId trail);
  rapidxml::xml_document<>* parse_xml(std::string raw, const std::string& url);

  static const std::string REG;
  static const std::string CALL;
  static const std::string DEREG_USER;
  static const std::string DEREG_ADMIN;
  static const std::string DEREG_TIMEOUT;
  static const std::string AUTH_TIMEOUT;
  static const std::string AUTH_FAIL;

  static const std::string STATE_REGISTERED;
  static const std::string STATE_NOT_REGISTERED;

private:
  virtual long get_json_object(const std::string& path,
                               rapidjson::Document*& object,
                               SAS::TrailId trail);
  virtual long get_xml_object(const std::string& path,
                              rapidxml::xml_document<>*& root,
                              SAS::TrailId trail);
  virtual long put_for_xml_object(const std::string& path,
                                  std::string body,
                                  bool cache_allowed,
                                  rapidxml::xml_document<>*& root,
                                  SAS::TrailId trail);

  HttpConnection* _http;
  SNMP::EventAccumulatorTable* _latency_tbl;
  SNMP::EventAccumulatorTable* _mar_latency_tbl;
  SNMP::EventAccumulatorTable* _sar_latency_tbl;
  SNMP::EventAccumulatorTable* _uar_latency_tbl;
  SNMP::EventAccumulatorTable* _lir_latency_tbl;
  std::string _scscf_uri;
  bool _fallback_if_no_matching_ifc;
};

#endif
