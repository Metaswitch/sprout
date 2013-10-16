/**
 * @file stack.cpp
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
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

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

// Common STL includes.
#include <cassert>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <queue>
#include <string>

#include "constants.h"
#include "eventq.h"
#include "pjutils.h"
#include "log.h"
#include "sas.h"
#include "sasevent.h"
#include "stack.h"
#include "utils.h"
#include "zmq_lvc.h"
#include "statistic.h"
#include "custom_headers.h"
#include "utils.h"
#include "accumulator.h"
#include "connection_tracker.h"
#include "quiescing_manager.h"
#include "load_monitor.h"

class StackQuiesceHandler;

struct stack_data_struct stack_data;

static std::vector<pj_thread_t*> pjsip_threads;
static std::vector<pj_thread_t*> worker_threads;
static volatile pj_bool_t quit_flag;

// Queue for incoming messages.
struct rx_msg_qe
{
  pjsip_rx_data* rdata;    // received message
  Utils::StopWatch stop_watch;    // stop watch for tracking message latency
};
eventq<struct rx_msg_qe> rx_msg_q;

static Accumulator* latency_accumulator;
static Accumulator* requests_accumulator;
static Accumulator* overload_accumulator;

static LoadMonitor *load_monitor = NULL; 
static QuiescingManager *quiescing_mgr = NULL;
static StackQuiesceHandler *stack_quiesce_handler = NULL;
static ConnectionTracker *connection_tracker = NULL;

// We register a single module to handle scheduling plus local and
// SAS logging.
static pj_bool_t on_rx_msg(pjsip_rx_data* rdata);
static pj_status_t on_tx_msg(pjsip_tx_data* tdata);

static pjsip_module mod_stack =
{
  NULL, NULL,                           /* prev, next.          */
  pj_str("mod-stack"),                  /* Name.                */
  -1,                                   /* Id                   */
  PJSIP_MOD_PRIORITY_TRANSPORT_LAYER-1, /* Priority             */
  NULL,                                 /* load()               */
  NULL,                                 /* start()              */
  NULL,                                 /* stop()               */
  NULL,                                 /* unload()             */
  &on_rx_msg,                           /* on_rx_request()      */
  &on_rx_msg,                           /* on_rx_response()     */
  &on_tx_msg,                           /* on_tx_request()      */
  &on_tx_msg,                           /* on_tx_response()     */
  NULL,                                 /* on_tsx_state()       */
};

/// PJSIP threads are donated to PJSIP to handle receiving at transport level
/// and timers.
static int pjsip_thread(void *p)
{
  pj_time_val delay = {0, 10};

  PJ_UNUSED_ARG(p);

  LOG_DEBUG("PJSIP thread started");

  while (!quit_flag)
  {
    pjsip_endpt_handle_events(stack_data.endpt, &delay);
  }

  LOG_DEBUG("PJSIP thread ended");

  return 0;
}


/// Worker threads handle most SIP message processing.
static int worker_thread(void* p)
{
  // Set up data to always process incoming messages at the first PJSIP
  // module after our module.
  pjsip_process_rdata_param rp;
  pjsip_process_rdata_param_default(&rp);
  rp.start_mod = &mod_stack;
  rp.idx_after_start = 1;

  LOG_DEBUG("Worker thread started");

  struct rx_msg_qe qe = {0};

  while (rx_msg_q.pop(qe))
  {
    pjsip_rx_data* rdata = qe.rdata;
    if (rdata)
    {
      LOG_DEBUG("Worker thread dequeue message %p", rdata);
      pjsip_endpt_process_rx_data(stack_data.endpt, rdata, &rp, NULL);
      LOG_DEBUG("Worker thread completed processing message %p", rdata);
      pjsip_rx_data_free_cloned(rdata);

      unsigned long latency_us;
      if (qe.stop_watch.stop(latency_us))
      {
        LOG_DEBUG("Request latency = %ldus", latency_us);
        latency_accumulator->accumulate(latency_us);
        load_monitor->request_complete(latency_us);
      }
      else
      {
        LOG_ERROR("Failed to get done timestamp: %s", strerror(errno));
      }
    }
  }

  LOG_DEBUG("Worker thread ended");

  return 0;
}


static void local_log_rx_msg(pjsip_rx_data* rdata)
{
  LOG_VERBOSE("RX %d bytes %s from %s %s:%d:\n"
              "--start msg--\n\n"
              "%.*s\n"
              "--end msg--",
              rdata->msg_info.len,
              pjsip_rx_data_get_info(rdata),
              rdata->tp_info.transport->type_name,
              rdata->pkt_info.src_name,
              rdata->pkt_info.src_port,
              (int)rdata->msg_info.len,
              rdata->msg_info.msg_buf);
}


static void local_log_tx_msg(pjsip_tx_data* tdata)
{
  LOG_VERBOSE("TX %d bytes %s to %s %s:%d:\n"
              "--start msg--\n\n"
              "%.*s\n"
              "--end msg--",
              (tdata->buf.cur - tdata->buf.start),
              pjsip_tx_data_get_info(tdata),
              tdata->tp_info.transport->type_name,
              tdata->tp_info.dst_name,
              tdata->tp_info.dst_port,
              (int)(tdata->buf.cur - tdata->buf.start),
              tdata->buf.start);
}


static void sas_log_rx_msg(pjsip_rx_data* rdata)
{
  SAS::TrailId trail = 0;

  if (rdata->msg_info.msg->type == PJSIP_RESPONSE_MSG)
  {
    // Message is a response, so try to correlate to an existing UAC
    // transaction using the top-most Via header.
    pj_str_t key;
    pjsip_tsx_create_key(rdata->tp_info.pool, &key, PJSIP_ROLE_UAC,
                         &rdata->msg_info.cseq->method, rdata);
    pjsip_transaction* tsx = pjsip_tsx_layer_find_tsx(&key, PJ_TRUE);
    if (tsx)
    {
      // Found the UAC transaction, so get the trail if there is one.
      trail = get_trail(tsx);

      // Unlock tsx because it is locked in find_tsx()
      pj_grp_lock_release(tsx->grp_lock);
    }
  }
  else if (rdata->msg_info.msg->line.req.method.id == PJSIP_ACK_METHOD)
  {
    // Message is an ACK, so try to correlate it to the existing UAS
    // transaction using the top-most Via header.
    pj_str_t key;
    pjsip_tsx_create_key(rdata->tp_info.pool, &key, PJSIP_UAS_ROLE,
                         &rdata->msg_info.cseq->method, rdata);
    pjsip_transaction* tsx = pjsip_tsx_layer_find_tsx(&key, PJ_TRUE);
    if (tsx)
    {
      // Found the UAS transaction, so get the trail if there is one.
      trail = get_trail(tsx);

      // Unlock tsx because it is locked in find_tsx()
      pj_grp_lock_release(tsx->grp_lock);
    }
  }
  else if (rdata->msg_info.msg->line.req.method.id == PJSIP_CANCEL_METHOD)
  {
    // Message is a CANCEL request chasing an INVITE, so we want to try to
    // correlate it to the INVITE trail for the purposes of SAS tracing.
    pj_str_t key;
    pjsip_tsx_create_key(rdata->tp_info.pool, &key, PJSIP_UAS_ROLE,
                         pjsip_get_invite_method(), rdata);
    pjsip_transaction* tsx = pjsip_tsx_layer_find_tsx(&key, PJ_TRUE);
    if (tsx)
    {
      // Found the INVITE UAS transaction, so get the trail if there is one.
      trail = get_trail(tsx);

      // Unlock tsx because it is locked in find_tsx()
      pj_grp_lock_release(tsx->grp_lock);
    }
  }

  if (trail == 0)
  {
    // The message doesn't correlate to an existing trail, so create a new
    // one.
    trail = SAS::new_trail(1u);
  }

  // Store the trail in the message as it gets passed up the stack.
  set_trail(rdata, trail);

  // Log the message event.
  SAS::Event event(trail, SASEvent::RX_SIP_MSG, 1u);
  event.add_static_param(pjsip_transport_get_type_from_flag(rdata->tp_info.transport->flag));
  event.add_static_param(rdata->pkt_info.src_port);
  event.add_var_param(rdata->pkt_info.src_name);
  event.add_var_param(rdata->msg_info.len, rdata->msg_info.msg_buf);
  SAS::report_event(event);
}


static void sas_log_tx_msg(pjsip_tx_data *tdata)
{
  // For outgoing messages always use the trail identified in the module data
  SAS::TrailId trail = get_trail(tdata);

  if (trail != 0)
  {
    // Log the message event.
    SAS::Event event(trail, SASEvent::TX_SIP_MSG, 1u);
    event.add_static_param(pjsip_transport_get_type_from_flag(tdata->tp_info.transport->flag));
    event.add_static_param(tdata->tp_info.dst_port);
    event.add_var_param(tdata->tp_info.dst_name);
    event.add_var_param((int)(tdata->buf.cur - tdata->buf.start), tdata->buf.start);
    SAS::report_event(event);
  }
  else
  {
    LOG_ERROR("Transmitting message with no SAS trail identifier\n%.*s",
              (int)(tdata->buf.cur - tdata->buf.start),
              tdata->buf.start);
  }
}


static pj_bool_t on_rx_msg(pjsip_rx_data* rdata)
{
  // Before we start, get a timestamp.  This will track the time from
  // receiving a message to forwarding it on (or rejecting it).
  struct rx_msg_qe qe;
  qe.stop_watch.start();

  // Do logging.
  local_log_rx_msg(rdata);
  sas_log_rx_msg(rdata);

  if ((load_monitor->admit_request())                                   &&
      (rdata->msg_info.msg->type == PJSIP_REQUEST_MSG)                  &&
      (rdata->msg_info.msg->line.req.method.id != PJSIP_ACK_METHOD)     &&
   //   (!(rdata->msg_info.msg->line.req.method.id == PJSIP_OTHER_METHOD) && 
   //     (rdata->msg_info.msg->line.req.method.name == "PRACK"))         &&     
      (rdata->msg_info.msg->line.req.method.id != PJSIP_OPTIONS_METHOD))
  {
    // Discard non-OPTIONS requests if queue is too big.
    // Respond statelessly with a 503 Service Unavailable, including a
    // Retry-After header with a zero length timeout.
    pjsip_retry_after_hdr* retry_after = pjsip_retry_after_hdr_create(rdata->tp_info.pool, 0);
    PJUtils::respond_stateless(stack_data.endpt,
                               rdata,
                               PJSIP_SC_SERVICE_UNAVAILABLE,
                               NULL,
                               (pjsip_hdr*)retry_after,
                               NULL);
   
    // If the sprout/bono is overloaded, then close the TCP connection. This 
    // causes the connection to retry against a different (probably) instance. 
    pjsip_transport_shutdown(rdata->tp_info.transport);
  
    //overload_accumulator->accumulate(1); 
    return PJ_TRUE;
  } 

  // Notify the connection tracker that the transport is active.
  connection_tracker->connection_active(rdata->tp_info.transport);

  // Clone the message and queue it to a scheduler thread.
  pjsip_rx_data* clone_rdata;
  pj_status_t status = pjsip_rx_data_clone(rdata, 0, &clone_rdata);

  if (status != PJ_SUCCESS)
  {
    // Failed to clone the message, so drop it.
    LOG_ERROR("Failed to clone incoming message (%s)", PJUtils::pj_status_to_string(status).c_str());
    return PJ_TRUE;
  }

  // Make sure the trail identifier is passed across.
  set_trail(clone_rdata, get_trail(rdata));

  // @TODO - need to think about back-pressure mechanisms.  For example,
  // should we have a maximum depth of queue and drop messages after that?
  // May be better to hold on to the message until the queue has space - this
  // will force back pressure on the particular TCP connection.  Or should we
  // have a queue per transport and round-robin them?

  LOG_DEBUG("Queuing cloned received message %p for worker threads", clone_rdata);
  qe.rdata = clone_rdata;
  rx_msg_q.push(qe);

  // return TRUE to flag that we have absorbed the incoming message.
  return PJ_TRUE;
}


static pj_status_t on_tx_msg(pjsip_tx_data* tdata)
{
  // Do logging.
  local_log_tx_msg(tdata);
  sas_log_tx_msg(tdata);

  // Return success so the message gets transmitted.
  return PJ_SUCCESS;
}


static void pjsip_log_handler(int level,
                              const char* data,
                              int len)
{
  switch (level) {
  case 0:
  case 1: level = 0; break;
  case 2: level = 1; break;
  case 3: level = 3; break;
  case 4: level = 4; break;
  case 5:
  case 6:
  default: level = 5; break;
  }

  Log::write(level, "pjsip", 0, data);
}


void init_pjsip_logging(int log_level,
                        pj_bool_t log_to_file,
                        const std::string& directory)
{
  pj_log_set_level(log_level);
  pj_log_set_decor(PJ_LOG_HAS_SENDER);
  pj_log_set_log_func(&pjsip_log_handler);
}

void fill_transport_details(int port,
                            pj_sockaddr_in *addr,
                            pjsip_host_port *published_name)
{
  addr->sin_family = pj_AF_INET();
  addr->sin_addr.s_addr = 0;
  addr->sin_port = pj_htons((pj_uint16_t)port);

  published_name->host = stack_data.local_host;
  published_name->port = port;
}


pj_status_t create_udp_transport(int port)
{
  pj_status_t status;
  pj_sockaddr_in addr;
  pjsip_host_port published_name;

  fill_transport_details(port, &addr, &published_name);
  status = pjsip_udp_transport_start(stack_data.endpt,
                                     &addr,
                                     &published_name,
                                     50,
                                     NULL);
  if (status != PJ_SUCCESS) {
    LOG_ERROR("Failed to start UDP transport for port %d (%s)", port, PJUtils::pj_status_to_string(status).c_str());
  }

  return status;
}


pj_status_t create_tcp_listener_transport(int port, pjsip_tpfactory **tcp_factory)
{
  pj_status_t status;
  pj_sockaddr_in addr;
  pjsip_host_port published_name;

  fill_transport_details(port, &addr, &published_name);
  status = pjsip_tcp_transport_start2(stack_data.endpt,
                                      &addr,
                                      &published_name,
                                      50,
                                      tcp_factory);
  if (status != PJ_SUCCESS) {
    LOG_ERROR("Failed to start TCP transport for port %d (%s)", port, PJUtils::pj_status_to_string(status).c_str());
  }

  return status;
}


void destroy_tcp_listener_transport(int port, pjsip_tpfactory *tcp_factory)
{
  LOG_STATUS("Destroyed TCP transport for port %d", port);
  tcp_factory->destroy(tcp_factory);
}


pj_status_t start_transports(int port, pjsip_tpfactory** tcp_factory)
{
  pj_status_t status;

  status = create_udp_transport(port);

  if (status != PJ_SUCCESS) {
    return status;
  }

  status = create_tcp_listener_transport(port, tcp_factory);

  if (status != PJ_SUCCESS) {
    return status;
  }

  LOG_STATUS("Listening on port %d", port);

  return PJ_SUCCESS;
}


// This class distributes quiescing work within the stack module.  It receives
// requests from the QuiscingManager and ConnectionTracker, and calls the
// relevant methods in the stack module, QuiescingManager and ConnectionManager
// as appropriate.
class StackQuiesceHandler :
  public QuiesceConnectionsInterface,
  public ConnectionsQuiescedInterface
{
public:

  //
  // The following methods are from QuiesceConnectionsInterface.
  //
  void close_untrusted_port()
  {
    if (stack_data.untrusted_tcp_factory != NULL) {
      destroy_tcp_listener_transport(stack_data.untrusted_port,
                                     stack_data.untrusted_tcp_factory);
    }
  }

  void close_trusted_port()
  {
    if (stack_data.trusted_tcp_factory != NULL) {
      destroy_tcp_listener_transport(stack_data.trusted_port,
                                     stack_data.trusted_tcp_factory);
    }
  }

  void open_trusted_port()
  {
    if (stack_data.trusted_port != 0) {
      create_tcp_listener_transport(stack_data.trusted_port,
                                    &stack_data.trusted_tcp_factory);
    }
  }

  void open_untrusted_port()
  {
    if (stack_data.untrusted_port != 0) {
      create_tcp_listener_transport(stack_data.untrusted_port,
                                    &stack_data.untrusted_tcp_factory);
    }
  }

  void quiesce()
  {
    connection_tracker->quiesce();
  }

  void unquiesce()
  {
    connection_tracker->unquiesce();
  }

  //
  // The following methods are from ConnectionsQuiescedInterface.
  //
  void connections_quiesced()
  {
    quiescing_mgr->connections_gone();
  }
};


pj_status_t init_pjsip()
{
  pj_status_t status;

  // Must init PJLIB first:
  status = pj_init();
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);

  // Dump PJLIB config to log file.
  pj_dump_config();

  // Then init PJLIB-UTIL:
  status = pjlib_util_init();
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);

  // Must create a pool factory before we can allocate any memory.
  pj_caching_pool_init(&stack_data.cp, &pj_pool_factory_default_policy, 0);

  // Create the endpoint.
  status = pjsip_endpt_create(&stack_data.cp.factory, NULL, &stack_data.endpt);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);

  // Init transaction layer.
  status = pjsip_tsx_layer_init_module(stack_data.endpt);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);

  // Create pool for the application
  stack_data.pool = pj_pool_create(&stack_data.cp.factory,
                                   "sprout-bono",
                                   4000,
                                   4000,
                                   NULL);

  status = register_custom_headers();
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);

  return PJ_SUCCESS;
}


pj_status_t init_stack(bool edge_proxy,
                       const std::string& system_name,
                       const std::string& sas_address,
                       int trusted_port,
                       int untrusted_port,
                       const std::string& local_host,
                       const std::string& home_domain,
                       const std::string& sprout_cluster_domain,
                       const std::string& bono_cluster_domain,
                       const std::string& alias_hosts,
                       int num_pjsip_threads,
                       int num_worker_threads,
                       QuiescingManager *quiescing_mgr_arg,
                       LoadMonitor *load_monitor_arg)
{
  pj_status_t status;
  pj_sockaddr pri_addr;
  pj_sockaddr addr_list[16];
  unsigned addr_cnt = PJ_ARRAY_SIZE(addr_list);
  unsigned i;

  // Set up the vectors of threads.  The threads don't get created until
  // start_stack is called.
  pjsip_threads.resize(num_pjsip_threads);
  worker_threads.resize(num_worker_threads);

  // Get ports and host names specified on options.  If local host was not
  // specified, use the host name returned by pj_gethostname.
  memset(&stack_data, 0, sizeof(stack_data));
  char* local_host_cstr = strdup(local_host.c_str());
  char* home_domain_cstr = strdup(home_domain.c_str());
  char* sprout_cluster_domain_cstr = strdup(sprout_cluster_domain.c_str());
  char* bono_cluster_domain_cstr = strdup(bono_cluster_domain.c_str());
  stack_data.trusted_port = trusted_port;
  stack_data.untrusted_port = untrusted_port;
  stack_data.local_host = (local_host != "") ? pj_str(local_host_cstr) : *pj_gethostname();
  stack_data.home_domain = (home_domain != "") ? pj_str(home_domain_cstr) : stack_data.local_host;
  stack_data.sprout_cluster_domain = (sprout_cluster_domain != "") ? pj_str(sprout_cluster_domain_cstr) : stack_data.local_host;
  stack_data.bono_cluster_domain = (bono_cluster_domain != "") ? pj_str(bono_cluster_domain_cstr) : stack_data.local_host;

  // Initialize SAS logging.
  if (system_name != "")
  {
    SAS::init(system_name.length(), system_name.c_str(), sas_address);
  }
  else
  {
    SAS::init(stack_data.local_host.slen, stack_data.local_host.ptr, sas_address);
  }

  // Initialise PJSIP and all the associated resources.
  status = init_pjsip();

  // Register the stack module.
  pjsip_endpt_register_module(stack_data.endpt, &mod_stack);
  stack_data.module_id = mod_stack.id;

  // Create listening transports for trusted and untrusted ports.
  stack_data.trusted_tcp_factory = NULL;
  if (stack_data.trusted_port != 0)
  {
    status = start_transports(stack_data.trusted_port,
                              &stack_data.trusted_tcp_factory);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
  }

  stack_data.untrusted_tcp_factory = NULL;
  if (stack_data.untrusted_port != 0)
  {
    status = start_transports(stack_data.untrusted_port,
                              &stack_data.untrusted_tcp_factory);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
  }

  // List all names matching local endpoint.
  // Note that PJLIB version 0.6 and newer has a function to
  // enumerate local IP interface (pj_enum_ip_interface()), so
  // by using it would be possible to list all IP interfaces in
  // this host.

  // The first address is important since this would be the one
  // to be added in Record-Route.
  stack_data.name[stack_data.name_cnt] = stack_data.local_host;
  stack_data.name_cnt++;

  if (edge_proxy)
  {
    stack_data.name[stack_data.name_cnt] = stack_data.bono_cluster_domain;
    stack_data.name_cnt++;
  }
  else
  {
    stack_data.name[stack_data.name_cnt] = stack_data.sprout_cluster_domain;
    stack_data.name_cnt++;
  }

  if (pj_gethostip(pj_AF_INET(), &pri_addr) == PJ_SUCCESS)
  {
    pj_strdup2(stack_data.pool, &stack_data.name[stack_data.name_cnt],
               pj_inet_ntoa(pri_addr.ipv4.sin_addr));
    stack_data.name_cnt++;
  }

  // Get the rest of IP interfaces.
  if (pj_enum_ip_interface(pj_AF_INET(), &addr_cnt, addr_list) == PJ_SUCCESS)
  {
    for (i = 0; i < addr_cnt; ++i)
    {
      if (addr_list[i].ipv4.sin_addr.s_addr == pri_addr.ipv4.sin_addr.s_addr)
      {
        continue;
      }

      pj_strdup2(stack_data.pool, &stack_data.name[stack_data.name_cnt],
                 pj_inet_ntoa(addr_list[i].ipv4.sin_addr));
      stack_data.name_cnt++;
    }
  }

  // Add loopback address.
#if PJ_IP_HELPER_IGNORE_LOOPBACK_IF
  stack_data.name[stack_data.name_cnt] = pj_str("127.0.0.1");
  stack_data.name_cnt++;
#endif

  stack_data.name[stack_data.name_cnt] = pj_str("localhost");
  stack_data.name_cnt++;
  // Parse the list of alias host names.
  if (alias_hosts != "")
  {
    std::list<std::string> hosts;
    Utils::split_string(alias_hosts, ',', hosts, 0, true);
    for (std::list<std::string>::iterator it = hosts.begin();
         it != hosts.end();
         ++it)
    {
      pj_strdup2(stack_data.pool, &stack_data.name[stack_data.name_cnt], it->c_str());
      stack_data.name_cnt++;
    }
  }

  LOG_STATUS("Local host aliases:");
  for (i = 0; i < stack_data.name_cnt; ++i)
  {
    LOG_STATUS(" %.*s",
               (int)stack_data.name[i].slen,
               stack_data.name[i].ptr);
  }

  stack_data.stats_aggregator = new LastValueCache(Statistic::known_stats_count(),
                                                   Statistic::known_stats());

  latency_accumulator = new StatisticAccumulator("latency_us");
  requests_accumulator = new StatisticAccumulator("incoming_requests");
  overload_accumulator = new StatisticAccumulator("rejected_overload");

  if (load_monitor_arg != NULL)
  {
    load_monitor = load_monitor_arg;
  }

  if (quiescing_mgr_arg != NULL)
  {
    quiescing_mgr = quiescing_mgr_arg;

    // Create an instance of the stack quiesce handler. This acts as a glue
    // class between the stack modulem connections tracker, and the quiescing
    // manager.
    stack_quiesce_handler = new StackQuiesceHandler();

    // Create a new connection tracker, and register the quiesce handler with
    // it.
    connection_tracker = new ConnectionTracker(stack_quiesce_handler);

    // Register the quiesce handler with the quiescing manager (the former
    // implements the connection handling interface).
    quiescing_mgr->register_conns_handler(stack_quiesce_handler);
  }

  return status;
}


pj_status_t start_stack()
{
  pj_status_t status = PJ_SUCCESS;

  quit_flag = PJ_FALSE;

  // Create worker threads first as they take work from the PJSIP threads so
  // need to be ready.
  for (size_t ii = 0; ii < worker_threads.size(); ++ii)
  {
    pj_thread_t* thread;
    status = pj_thread_create(stack_data.pool, "worker", &worker_thread,
                              NULL, 0, 0, &thread);
    if (status != PJ_SUCCESS)
    {
      LOG_ERROR("Error creating worker thread, %s",
                PJUtils::pj_status_to_string(status).c_str());
      return 1;
    }
    worker_threads[ii] = thread;
  }

  // Now create the PJSIP threads.
  for (size_t ii = 0; ii < pjsip_threads.size(); ++ii)
  {
    pj_thread_t* thread;
    status = pj_thread_create(stack_data.pool, "pjsip", &pjsip_thread,
                              NULL, 0, 0, &thread);
    if (status != PJ_SUCCESS)
    {
      LOG_ERROR("Error creating PJSIP thread, %s",
                PJUtils::pj_status_to_string(status).c_str());
      return 1;
    }
    pjsip_threads[ii] = thread;
  }

  return status;
}

void stop_stack()
{
  // Terminate the PJSIP threads and the worker threads to exit.  We kill
  // the PJSIP threads first - if we killed the worker threads first the
  // rx_msg_q will stop getting serviced so could fill up blocking
  // PJSIP threads, causing a deadlock.

  // Set the quit flag to signal the PJSIP threads to exit, then wait
  // for them to exit.
  quit_flag = PJ_TRUE;

  for (std::vector<pj_thread_t*>::iterator i = pjsip_threads.begin();
       i != pjsip_threads.end();
       ++i)
  {
    pj_thread_join(*i);
  }

  // Now it is safe to signal the worker threads to exit via the queue and to
  // wait for them to terminate.
  rx_msg_q.terminate();
  for (std::vector<pj_thread_t*>::iterator i = worker_threads.begin();
       i != worker_threads.end();
       ++i)
  {
    pj_thread_join(*i);
  }
}


// Unregister all modules registered by the stack.  In particular, unregister
// the transaction layer module, which terminates all transactions.
void unregister_stack_modules(void)
{
  pjsip_tsx_layer_destroy();
  pjsip_endpt_unregister_module(stack_data.endpt, &mod_stack);
}


void term_pjsip()
{
  pjsip_endpt_destroy(stack_data.endpt);
  pj_pool_release(stack_data.pool);
  pj_caching_pool_destroy(&stack_data.cp);
  pj_shutdown();
}


// Destroy stack
void destroy_stack(void)
{
  // Tear down the stack.
  delete latency_accumulator;
  latency_accumulator = NULL;
  delete requests_accumulator;
  requests_accumulator = NULL;
  delete overload_accumulator;
  overload_accumulator = NULL;
  delete stack_data.stats_aggregator;

  delete stack_quiesce_handler;
  stack_quiesce_handler = NULL;

  delete connection_tracker;
  connection_tracker = NULL;

  pjsip_threads.clear();
  worker_threads.clear();

  SAS::term();

  // Terminate PJSIP.
  term_pjsip();
}

