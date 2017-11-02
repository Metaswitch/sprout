/**
 * @file stack.h PJSIP stack initialization/termination functions and PJSIP related utilities.
 *
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


#ifndef STACK_H__
#define STACK_H__

extern "C" {
#include <pjsip.h>
}

#include <string>
#include <unordered_set>

#include "sas.h"
#include "quiescing_manager.h"
#include "load_monitor.h"
#include "sipresolver.h"

/* Pre-declariations */
class LastValueCache;

/* Options */
struct stack_data_struct
{
  SIPResolver*         sipresolver;

  pj_caching_pool      cp;
  pj_pool_t           *pool;
  pjsip_endpoint      *endpt;
  pj_thread_t         *pjsip_transport_thread;
  int                  pcscf_untrusted_port;
  pjsip_tpfactory     *pcscf_untrusted_tcp_factory;
  int                  pcscf_trusted_port;
  pjsip_tpfactory     *pcscf_trusted_tcp_factory;
  int                  scscf_port;
  pjsip_tpfactory     *scscf_trusted_tcp_factory;
  std::map<int, pjsip_tpfactory*> sproutlets;
  int                  sas_logging_module_id;

  pj_str_t             local_host;
  pj_str_t             public_host;
  pj_str_t             default_home_domain;
  std::unordered_set<std::string> home_domains;
  std::unordered_set<std::string> aliases;
  std::string          sprout_hostname;
  pj_str_t             cdf_domain;
  pj_str_t             scscf_uri_str;
  pjsip_sip_uri*       scscf_uri;
  pj_str_t             scscf_contact;

  int                  addr_family;

  std::vector<pj_str_t> name;
  LastValueCache *     stats_aggregator;

  bool record_route_on_every_hop;
  bool record_route_on_initiation_of_originating;
  bool record_route_on_initiation_of_terminating;
  bool record_route_on_completion_of_originating;
  bool record_route_on_completion_of_terminating;
  bool record_route_on_diversion;

  int default_session_expires;
  int max_session_expires;
  int sip_tcp_connect_timeout;
  int sip_tcp_send_timeout;
  bool enable_orig_sip_to_tel_coerce;
};

extern struct stack_data_struct stack_data;

inline bool is_pjsip_transport_thread()
{
#ifdef UNIT_TEST
  // This check doesn't make sense in UT, where we use a different threading model
  return true;
#else
  return (pj_thread_this() == stack_data.pjsip_transport_thread);
#endif
}

#define CHECK_PJ_TRANSPORT_THREAD() \
  if (!is_pjsip_transport_thread()) \
  { \
    TRC_ERROR("Function expected to be called on PJSIP transport thread (%s) has been called on different thread (%s)", pj_thread_get_name(stack_data.pjsip_transport_thread), pj_thread_get_name(pj_thread_this())); \
  };

inline void set_trail(pjsip_rx_data* rdata, SAS::TrailId trail)
{
  rdata->endpt_info.mod_data[stack_data.sas_logging_module_id] = (void*)trail;
}

inline void set_trail(pjsip_tx_data* tdata, SAS::TrailId trail)
{
  tdata->mod_data[stack_data.sas_logging_module_id] = (void*)trail;
}

inline void set_trail(pjsip_transaction* tsx, SAS::TrailId trail)
{
  tsx->mod_data[stack_data.sas_logging_module_id] = (void*)trail;
}

inline SAS::TrailId get_trail(const pjsip_rx_data* rdata)
{
  return (SAS::TrailId)rdata->endpt_info.mod_data[stack_data.sas_logging_module_id];
}

inline SAS::TrailId get_trail(const pjsip_tx_data* tdata)
{
  return (SAS::TrailId)tdata->mod_data[stack_data.sas_logging_module_id];
}

inline SAS::TrailId get_trail(const pjsip_transaction* tsx)
{
  return (SAS::TrailId)tsx->mod_data[stack_data.sas_logging_module_id];
}

extern void set_quiescing_true();

extern void set_quiescing_false();

extern void init_pjsip_logging(int log_level,
                               pj_bool_t log_to_file,
                               const std::string& directory);

extern pj_status_t init_stack(const std::string& sas_system_name,
                              const std::string& sas_address,
                              int pcscf_trusted_port,
                              int pcscf_untrusted_port,
                              int scscf_port,
                              bool sas_signaling_if,
                              std::set<int> sproutlet_ports,
                              const std::string& local_host,
                              const std::string& public_host,
                              const std::string& home_domain,
                              const std::string& additional_home_domains,
                              const std::string& sproutlet_uri,
                              const std::string& sprout_hostname,
                              const std::string& alias_hosts,
                              SIPResolver* sipresolver,
                              int record_routing_model,
                              const int default_session_expires,
                              const int max_session_expires,
                              const int sip_tcp_connect_timeout,
                              const int sip_tcp_send_timeout,
                              QuiescingManager *quiescing_mgr,
                              const std::string& cdf_domain,
                              std::vector<std::string> sproutlet_uris,
                              bool enable_orig_sip_to_tel_coerce);
extern pj_status_t start_pjsip_thread();
extern pj_status_t stop_pjsip_thread();
extern void stop_stack();
extern void destroy_stack();
extern pj_status_t init_pjsip();
extern void term_pjsip();

extern const std::string* known_statnames;
extern const int num_known_stats;

#endif
