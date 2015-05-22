/**
 * @file stack.h PJSIP stack initialization/termination functions and PJSIP related utilities.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * Parts of this header were derived from GPL licensed PJSIP sample code
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
  int                  pcscf_untrusted_port;
  pjsip_tpfactory     *pcscf_untrusted_tcp_factory;
  int                  pcscf_trusted_port;
  pjsip_tpfactory     *pcscf_trusted_tcp_factory;
  int                  scscf_port;
  pjsip_tpfactory     *scscf_tcp_factory;
  int                  icscf_port;
  pjsip_tpfactory     *icscf_tcp_factory;

  int                  sas_logging_module_id;

  pj_str_t             local_host;
  pj_str_t             public_host;
  pj_str_t             default_home_domain;
  std::unordered_set<std::string> home_domains;
  std::unordered_set<std::string> aliases;
  pj_str_t             cdf_domain;
  pj_str_t             scscf_uri;

  int                  addr_family;

  unsigned             name_cnt;
  pj_str_t             name[16];
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
};

extern struct stack_data_struct stack_data;

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

extern void init_pjsip_logging(int log_level,
                               pj_bool_t log_to_file,
                               const std::string& directory);

extern pj_status_t init_stack(const std::string& sas_system_name,
                              const std::string& sas_address,
                              int pcscf_trusted_port,
                              int pcscf_untrusted_port,
                              int scscf_port,
                              int icscf_port,
                              const std::string& local_host,
                              const std::string& public_host,
                              const std::string& home_domain,
                              const std::string& additional_home_domains,
                              const std::string& scscf_uri,
                              const std::string& alias_hosts,
                              SIPResolver* sipresolver,
                              int num_pjsip_threads,
                              int record_routing_model,
                              const int default_session_expires,
                              const int max_session_expires,
                              const int sip_tcp_connect_timeout,
                              QuiescingManager *quiescing_mgr,
                              const std::string& cdf_domain);
extern pj_status_t start_pjsip_threads();
extern pj_status_t stop_pjsip_threads();
extern void stop_stack();
extern void destroy_stack();
extern pj_status_t init_pjsip();
extern void term_pjsip();

extern const std::string* known_statnames;
extern const int num_known_stats;

#endif
