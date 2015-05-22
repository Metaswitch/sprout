/**
 * @file cfgoptions.h  Sproutlet configuration options.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2014  Metaswitch Networks Ltd
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

#ifndef CFGOPTIONS_H__
#define CFGOPTIONS_H__

#include <string>

#include "hssconnection.h"
#include "regstore.h"
#include "httpconnection.h"
#include "httpresolver.h"
#include "acr.h"
#include "enumservice.h"
#include "exception_handler.h"

enum struct MemcachedWriteFormat
{
  BINARY, JSON
};

struct options
{
  bool                                 pcscf_enabled;
  int                                  pcscf_untrusted_port;
  int                                  pcscf_trusted_port;
  int                                  webrtc_port;
  std::string                          upstream_proxy;
  int                                  upstream_proxy_port;
  int                                  upstream_proxy_connections;
  int                                  upstream_proxy_recycle;
  bool                                 ibcf;
  bool                                 scscf_enabled;
  int                                  scscf_port;
  bool                                 icscf_enabled;
  int                                  icscf_port;
  std::string                          external_icscf_uri;
  int                                  record_routing_model;
  int                                  default_session_expires;
  int                                  max_session_expires;
  int                                  target_latency_us;
  std::string                          local_host;
  std::string                          public_host;
  std::string                          home_domain;
  std::string                          additional_home_domains;
  std::string                          scscf_uri;
  std::string                          alias_hosts;
  std::string                          trusted_hosts;
  bool                                 auth_enabled;
  std::string                          auth_realm;
  std::string                          sas_server;
  std::string                          sas_system_name;
  std::string                          hss_server;
  std::string                          xdm_server;
  std::string                          chronos_service;
  std::string                          store_servers;
  std::string                          remote_store_servers;
  std::string                          ralf_server;
  std::vector<std::string>             dns_servers;
  std::vector<std::string>             enum_servers;
  std::string                          enum_suffix;
  std::string                          enum_file;
  bool                                 enforce_user_phone;
  bool                                 enforce_global_only_lookups;
  bool                                 analytics_enabled;
  std::string                          analytics_directory;
  int                                  reg_max_expires;
  int                                  sub_max_expires;
  int                                  pjsip_threads;
  std::string                          http_address;
  int                                  http_port;
  int                                  http_threads;
  std::string                          billing_cdf;
  bool                                 emerg_reg_accepted;
  int                                  max_call_list_length;
  int                                  memento_threads;
  int                                  call_list_ttl;
  bool                                 memento_enabled;
  bool                                 gemini_enabled;
  bool                                 alarms_enabled;
  int                                  worker_threads;
  bool                                 log_to_file;
  std::string                          log_directory;
  int                                  log_level;
  bool                                 interactive;
  bool                                 daemon;
  MemcachedWriteFormat                 memcached_write_format;
  bool                                 override_npdi;
  int                                  max_tokens;
  float                                init_token_rate;
  float                                min_token_rate;
  int                                  cass_target_latency_us;
  int                                  exception_max_ttl;
  int                                  sip_blacklist_duration;
  int                                  http_blacklist_duration;
  int                                  sip_tcp_connect_timeout;
};

// Objects that must be shared with dynamically linked sproutlets must be
// globally scoped.
extern LoadMonitor* load_monitor;
extern HSSConnection* hss_connection;
extern RegStore* local_reg_store;
extern RegStore* remote_reg_store;
extern HttpConnection* ralf_connection;
extern HttpResolver* http_resolver;
extern ACRFactory* scscf_acr_factory;
extern EnumService* enum_service;
extern ExceptionHandler* exception_handler;

#endif
