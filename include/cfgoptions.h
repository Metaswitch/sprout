/**
 * @file cfgoptions.h  Sproutlet configuration options.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef CFGOPTIONS_H__
#define CFGOPTIONS_H__

#include <string>
#include <set>

#include "hssconnection.h"
#include "subscriber_data_manager.h"
#include "httpconnection.h"
#include "httpresolver.h"
#include "acr.h"
#include "enumservice.h"
#include "exception_handler.h"
#include "ralf_processor.h"
#include "sproutlet_options.h"
#include "impistore.h"
#include "analyticslogger.h"
#include "fifcservice.h"

// Struct containing the possible values for non-REGISTER authentication. These
// are a set of flags that indicate different conditions that may cause a
// non-REGISTER to be authenticated. They are represented as a bitmask where
// each value must be a power of two.
struct NonRegisterAuthentication
{
  // Never authenticate non-REGISTER requests. This represents the case where no
  // conditions are set, so this must have the value 0.
  static const uint32_t NEVER = 0;

  // Authenticate a non-REGISTER if it has a Proxy-Authorization header.
  static const uint32_t IF_PROXY_AUTHORIZATION_PRESENT = 1;

  // Authenticate a non-REGISTER if it came from a registered endpoint that uses
  // SIP digest authentication (see TS 24.229, section 5.4.3.6).
  static const uint32_t INITIAL_REQ_FROM_REG_DIGEST_ENDPOINT = 2;
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
  std::string                          external_icscf_uri;
  int                                  record_routing_model;
  int                                  default_session_expires;
  int                                  max_session_expires;
  int                                  target_latency_us;
  std::string                          local_host;
  std::string                          public_host;
  std::string                          home_domain;
  std::string                          sprout_hostname;
  std::string                          additional_home_domains;
  std::string                          alias_hosts;
  std::string                          trusted_hosts;
  bool                                 auth_enabled;
  std::string                          auth_realm;
  std::string                          sas_server;
  std::string                          sas_system_name;
  std::string                          hss_server;
  std::string                          xdm_server;
  std::string                          local_site_name;
  std::vector<std::string>             registration_stores;
  std::vector<std::string>             impi_stores;
  std::string                          ralf_server;
  int                                  ralf_threads;
  std::vector<std::string>             dns_servers;
  std::vector<std::string>             enum_servers;
  std::string                          enum_suffix;
  std::string                          enum_file;
  bool                                 default_tel_uri_translation;
  bool                                 analytics_enabled;
  std::string                          analytics_directory;
  int                                  reg_max_expires;
  int                                  sub_max_expires;
  std::string                          http_address;
  int                                  http_port;
  int                                  http_threads;
  std::string                          billing_cdf;
  bool                                 emerg_reg_accepted;
  int                                  max_call_list_length;
  int                                  memento_threads;
  int                                  call_list_ttl;
  int                                  worker_threads;
  bool                                 log_to_file;
  std::string                          log_directory;
  int                                  log_level;
  bool                                 interactive;
  bool                                 daemon;
  bool                                 override_npdi;
  int                                  max_tokens;
  float                                init_token_rate;
  float                                min_token_rate;
  float                                max_token_rate;
  int                                  cass_target_latency_us;
  int                                  exception_max_ttl;
  int                                  sip_blacklist_duration;
  int                                  http_blacklist_duration;
  int                                  astaire_blacklist_duration;
  int                                  sip_tcp_connect_timeout;
  int                                  sip_tcp_send_timeout;
  int                                  dns_timeout;
  int                                  session_continued_timeout_ms;
  int                                  session_terminated_timeout_ms;
  std::set<std::string>                stateless_proxies;
  int                                  max_sproutlet_depth;
  std::string                          pbxes;
  std::string                          pbx_service_route;
  uint32_t                             non_register_auth_mode;
  bool                                 force_third_party_register_body;
  std::string                          memento_notify_url;
  std::string                          pidfile;
  std::map<std::string, std::multimap<std::string, std::string>>
                                       plugin_options;
  int                                  listen_port;
  std::set<int>                        sproutlet_ports;
  SPROUTLET_MACRO(SPROUTLET_CFG_OPTIONS)
  bool                                 nonce_count_supported;
  std::string                          scscf_node_uri;
  bool                                 sas_signaling_if;
  bool                                 disable_tcp_switch;
  std::string                          chronos_hostname;
  std::string                          sprout_chronos_callback_uri;
  bool                                 apply_fallback_ifcs;
  bool                                 reject_if_no_matching_ifcs;
  std::string                          dummy_app_server;
  bool                                 http_acr_logging;
  int                                  homestead_timeout;
  int                                  request_on_queue_timeout;
  std::set<std::string>                blacklisted_scscfs;
  bool                                 enable_orig_sip_to_tel_coerce;
};

// Objects that must be shared with dynamically linked sproutlets must be
// globally scoped.
extern LoadMonitor* load_monitor;
extern HSSConnection* hss_connection;
extern Store* local_data_store;
extern std::vector<Store*> remote_data_stores;
extern Store* local_impi_data_store;
extern std::vector<Store*> remote_impi_data_stores;
extern SubscriberDataManager* local_sdm;
extern std::vector<SubscriberDataManager*> remote_sdms;
extern ImpiStore* local_impi_store;
extern std::vector<ImpiStore*> remote_impi_stores;
extern RalfProcessor* ralf_processor;
extern DnsCachedResolver* dns_resolver;
extern HttpResolver* http_resolver;
extern ACRFactory* scscf_acr_factory;
extern EnumService* enum_service;
extern ExceptionHandler* exception_handler;
extern AlarmManager* alarm_manager;
extern AnalyticsLogger* analytics_logger;
extern ChronosConnection* chronos_connection;
extern FIFCService* fifc_service;

#endif
