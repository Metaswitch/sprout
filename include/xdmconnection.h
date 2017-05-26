/**
 * @file xdmconnection.h External interface file for the XDMS client class
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

///
///

#ifndef XDMCONNECTION_H__
#define XDMCONNECTION_H__

#include <string>
#include <curl/curl.h>
#include "httpconnection.h"
#include "sas.h"
#include "load_monitor.h"
#include "snmp_ip_count_table.h"
#include "snmp_event_accumulator_table.h"

class XDMConnection
{
public:
  XDMConnection(const std::string& server,
                HttpResolver* resolver,
                LoadMonitor *load_monitor,
                SNMP::IPCountTable* xdm_cxn_count,
                SNMP::EventAccumulatorTable* xdm_latency);
  XDMConnection(HttpConnection* http, SNMP::EventAccumulatorTable* xdm_latency);
  virtual ~XDMConnection();

  bool get_simservs(const std::string& user, std::string& xml_data, const std::string& password, SAS::TrailId trail);

private:
  HttpConnection* _http;
  SNMP::EventAccumulatorTable* _latency_tbl;
};

#endif
