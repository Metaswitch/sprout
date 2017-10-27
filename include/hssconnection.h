/**
 * @file hssconnection.h Definitions for HSSConnection class.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

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
#include "associated_uris.h"
#include "sifcservice.h"

/// @class HSSConnection
///
/// Provides a connection to the Homestead service for retrieving user
/// profiles and authentication information.
///
class HSSConnection
{
public:
  struct irs_query
  {
    std::string _public_id;
    std::string _private_id;
    std::string _req_type;
    std::string _server_name;
    std::string _wildcard;
    bool _cache_allowed;

    irs_query() : 
      _public_id(""),
      _private_id(""),
      _req_type(""),
      _server_name(""),
      _wildcard(""),
      _cache_allowed(true)
   {
   }
  };

  struct irs_info
  {
    std::string _regstate;
    std::string _prev_regstate;
    std::map<std::string, Ifcs> _service_profiles;
    AssociatedURIs _associated_uris;
    std::vector<std::string> _aliases;
    std::deque<std::string> _ccfs;
    std::deque<std::string> _ecfs;

    irs_info() : 
      _regstate(""),
      _prev_regstate(""),
      _service_profiles(),
      _associated_uris({}),
      _aliases(),
      _ccfs(),
      _ecfs()
    {
    }
  };

  HSSConnection(const std::string& server,
                HttpResolver* resolver,
                LoadMonitor* load_monitor,
                SNMP::IPCountTable* homestead_count_tbl,
                SNMP::EventAccumulatorTable* homestead_overall_latency_tbl,
                SNMP::EventAccumulatorTable* homestead_mar_latency_tbl,
                SNMP::EventAccumulatorTable* homestead_sar_latency_tbl,
                SNMP::EventAccumulatorTable* homestead_uar_latency_tbl,
                SNMP::EventAccumulatorTable* homestead_lir_latency_tbl,
                CommunicationMonitor* comm_monitor,
                SIFCService* sifc_service,
                long homestead_timeout_ms);
  virtual ~HSSConnection();

  HTTPCode get_auth_vector(const std::string& private_user_id,
                           const std::string& public_user_id,
                           const std::string& auth_type,
                           const std::string& resync_auth,
                           const std::string& server_name,
                           rapidjson::Document*& object,
                           SAS::TrailId trail);
  HTTPCode get_user_auth_status(const std::string& private_user_identity,
                                const std::string& public_user_identity,
                                const std::string& visited_network,
                                const std::string& auth_type,
                                const bool& emergency,
                                rapidjson::Document*& object,
                                SAS::TrailId trail);
  HTTPCode get_location_data(const std::string& public_user_identity,
                             const bool& originating,
                             const std::string& auth_type,
                             rapidjson::Document*& object,
                             SAS::TrailId trail);

  virtual HTTPCode update_registration_state(const irs_query& irs_query,
                                             irs_info& irs_info,
                                             SAS::TrailId trail);

  virtual HTTPCode get_registration_data(const std::string& public_id,
                                         irs_info& irs_info,
                                         SAS::TrailId trail);
  rapidxml::xml_document<>* parse_xml(std::string raw, const std::string& url);

  static const std::string REG;
  static const std::string CALL;
  static const std::string DEREG_USER;
  static const std::string DEREG_ADMIN;
  static const std::string DEREG_TIMEOUT;
  static const std::string AUTH_TIMEOUT;
  static const std::string AUTH_FAIL;

private:
  virtual long get_json_object(const std::string& path,
                               rapidjson::Document*& object,
                               SAS::TrailId trail);
  virtual long get_xml_object(const std::string& path,
                              rapidxml::xml_document<>*& root,
                              SAS::TrailId trail);
  virtual long put_for_xml_object(const std::string& path,
                                  std::string body,
                                  const bool& cache_allowed,
                                  rapidxml::xml_document<>*& root,
                                  SAS::TrailId trail);

  HttpConnection* _http;
  SNMP::EventAccumulatorTable* _latency_tbl;
  SNMP::EventAccumulatorTable* _mar_latency_tbl;
  SNMP::EventAccumulatorTable* _sar_latency_tbl;
  SNMP::EventAccumulatorTable* _uar_latency_tbl;
  SNMP::EventAccumulatorTable* _lir_latency_tbl;
  SIFCService* _sifc_service;
};

#endif
