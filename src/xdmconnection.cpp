/**
 * @file xdmconnection.cpp HSSConnection class methods.
 *
 * Copyright (C) Metaswitch Networks 2015
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

///

#include <curl/curl.h>
#include <iostream>
#include <fstream>

#include "utils.h"
#include "log.h"
#include "sas.h"
#include "sproutsasevent.h"
#include "httpconnection.h"
#include "xdmconnection.h"
#include "snmp_continuous_accumulator_table.h"

/// Main constructor.
XDMConnection::XDMConnection(const std::string& server,
                             HttpResolver* resolver,
                             LoadMonitor *load_monitor,
                             SNMP::IPCountTable* xdm_cxn_count,
                             SNMP::EventAccumulatorTable* xdm_latency):
  _client(new HttpClient(true,
                         resolver,
                         xdm_cxn_count,
                         load_monitor,
                         SASEvent::HttpLogLevel::PROTOCOL,
                         NULL)),
  _http(new HttpConnection(server,
                           _client)),
  _latency_tbl(xdm_latency)
{
}

XDMConnection::~XDMConnection()
{
  delete _http; _http = NULL;
  delete _client; _client = NULL;
}

bool XDMConnection::get_simservs(const std::string& user,
                                 std::string& xml_data,
                                 const std::string& password,
                                 SAS::TrailId trail)
{
  Utils::StopWatch stopWatch;
  stopWatch.start();

  std::string url = "/org.etsi.ngn.simservs/users/" + Utils::url_escape(user) + "/simservs.xml";

  std::unique_ptr<HttpRequest> req = _http->create_request(HttpClient::RequestType::GET, url);
  req->set_sas_trail(trail);
  req->set_username(user);
  HttpResponse response = req->send();
  
  HTTPCode http_code = response.get_rc();
  xml_data = response.get_body();

  unsigned long latency_us = 0;
  if (stopWatch.read(latency_us))
  {
    _latency_tbl->accumulate(latency_us);
  }

  return (http_code == HTTP_OK);
}

