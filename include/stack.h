/**
 * @file stack.h PJSIP stack initialization/termination functions and PJSIP related utilities.
 *
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by post at
 * Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 */

///
///

#ifndef STACK_H__
#define STACK_H__

extern "C" {
#include <pjsip.h>
}

#include <string>

#include "sas.h"

/* Pre-declariations */
class LastValueCache;

/* Options */
struct stack_data_struct
{
  pj_caching_pool      cp;
  pj_pool_t           *pool;
  pjsip_endpoint      *endpt;
  pjsip_tpfactory     *tcp_factory;
  int                  module_id;

  int                  trusted_port;
  int                  untrusted_port;
  pj_str_t             local_host;
  pj_str_t             home_domain;

  unsigned             name_cnt;
  pj_str_t             name[16];
  LastValueCache *     stats_aggregator;
};

extern struct stack_data_struct stack_data;

inline void set_trail(pjsip_rx_data* rdata, SAS::TrailId trail)
{
  rdata->endpt_info.mod_data[stack_data.module_id] = (void*)trail;
}

inline void set_trail(pjsip_tx_data* tdata, SAS::TrailId trail)
{
  tdata->mod_data[stack_data.module_id] = (void*)trail;
}

inline void set_trail(pjsip_transaction* tsx, SAS::TrailId trail)
{
  tsx->mod_data[stack_data.module_id] = (void*)trail;
}

inline SAS::TrailId get_trail(const pjsip_rx_data* rdata)
{
  return (SAS::TrailId)rdata->endpt_info.mod_data[stack_data.module_id];
}

inline SAS::TrailId get_trail(const pjsip_tx_data* tdata)
{
  return (SAS::TrailId)tdata->mod_data[stack_data.module_id];
}

inline SAS::TrailId get_trail(const pjsip_transaction* tsx)
{
  return (SAS::TrailId)tsx->mod_data[stack_data.module_id];
}

extern void init_pjsip_logging(int log_level,
                               pj_bool_t log_to_file,
                               const std::string& directory);

extern pj_status_t init_stack(const std::string& system_name,
                              const std::string& sas_address,
                              int trusted_port,
                              int untrusted_port,
                              const std::string& local_host,
                              const std::string& home_domain,
                              const std::string& alias_hosts,
                              int num_pjsip_threads,
                              int num_worker_threads);
extern pj_status_t start_stack();
extern void stop_stack();
void unregister_stack_modules(void);
extern void destroy_stack();

#endif
