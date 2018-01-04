/**
 * @file stack.cpp
 *
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include "pjsip-simple/evsub.h"
}

#include <arpa/inet.h>

#include <pthread.h>
#include <sched.h>

// Common STL includes.
#include <cassert>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <queue>
#include <string>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/resource.h>

#include "constants.h"
#include "eventq.h"
#include "pjutils.h"
#include "log.h"
#include "sas.h"
#include "saslogger.h"
#include "sproutsasevent.h"
#include "stack.h"
#include "utils.h"
#include "zmq_lvc.h"
#include "statistic.h"
#include "custom_headers.h"
#include "utils.h"
#include "accumulator.h"
#include "connection_tracker.h"
#include "quiescing_manager.h"
#include "counter.h"
#include "sprout_pd_definitions.h"
#include "uri_classifier.h"
#include "namespace_hop.h"

class StackQuiesceHandler;

struct stack_data_struct stack_data;

static QuiescingManager *quiescing_mgr = NULL;
static StackQuiesceHandler *stack_quiesce_handler = NULL;
static ConnectionTracker *connection_tracker = NULL;

static volatile pj_bool_t quit_flag;
static pj_bool_t on_rx_msg(pjsip_rx_data* rdata);

// Handles updating the connection tracker when requests are received,
// for quiescing processing.
static pjsip_module mod_connection_tracking =
{
  NULL, NULL,                           /* prev, next.          */
  pj_str("mod-connection-tracking"),    /* Name.                */
  -1,                                   /* Id                   */
  PJSIP_MOD_PRIORITY_TRANSPORT_LAYER-3, /* Priority             */
  NULL,                                 /* load()               */
  NULL,                                 /* start()              */
  NULL,                                 /* stop()               */
  NULL,                                 /* unload()             */
  &on_rx_msg,                           /* on_rx_request()      */
  &on_rx_msg,                           /* on_rx_response()     */
  NULL,                                 /* on_tx_request()      */
  NULL,                                 /* on_tx_response()     */
  NULL,                                 /* on_tsx_state()       */
};

static pj_bool_t on_rx_msg(pjsip_rx_data* rdata)
{
  // Notify the connection tracker that the transport is active.
  connection_tracker->connection_active(rdata->tp_info.transport);
  return PJ_FALSE;
}

const static std::string _known_statnames[] = {
  "client_count",
  "connected_homers",
  "connected_homesteads",
  "connected_sprouts",
  "latency_us",
  "hss_latency_us",
  "hss_digest_latency_us",
  "hss_subscription_latency_us",
  "xdm_latency_us",
  "incoming_requests",
  "rejected_overload",
  "queue_size",
  "hss_user_auth_latency_us",
  "hss_location_latency_us",
  "connected_ralfs",
  "cdiv_total",
  "cdiv_unconditional",
  "cdiv_busy",
  "cdiv_not_registered",
  "cdiv_no_answer",
  "cdiv_not_reachable",
  // The following stats are used by memento-as. Since memento has not yet been
  // updated to use SNMP stats, we must declare the statistics here. All new
  // sproutlets should use SNMP stats, so this is a problem unique to memento.
  "memento_completed_calls",
  "memento_failed_calls",
  "memento_not_recorded_overload",
  "memento_cassandra_read_latency",
  "memento_cassandra_write_latency",
};

const std::string* known_statnames = _known_statnames;
const int num_known_stats = sizeof(_known_statnames) / sizeof(std::string);

// Variable to hold quiescing state, and interfaces to alter it
static pj_bool_t quiescing = PJ_FALSE;

extern void set_quiescing_true()
{
  TRC_STATUS("Setting quiescing = PJ_TRUE");
  quiescing = PJ_TRUE;
}

extern void set_quiescing_false()
{
  TRC_STATUS("Setting quiescing = PJ_FALSE");
  quiescing = PJ_FALSE;
}

static void on_io_started(const std::string& msg)
{
  TRC_WARNING("Performing blocking work on PJSIP transport thread: %s", msg.c_str());

  if (Log::enabled(Log::DEBUG_LEVEL))
  {
    TRC_BACKTRACE("Call stack for blocking work follows");
  }
}

/// PJSIP threads are donated to PJSIP to handle receiving at transport level
/// and timers.
static int pjsip_thread_func(void *p)
{
  pj_time_val delay = {0, 10};

  PJ_UNUSED_ARG(p);

  // Get the Kernel's ID for this thread so we can log it out.
  pid_t tid;
  tid = syscall(SYS_gettid);

  TRC_STATUS("PJSIP transport thread started with kernel thread ID %d", tid);

  // Increase the priority of the transport thread (by giving it a real-time
  // scheduling policy and a non-zero priority). This means that the transport
  // thread is scheduled more aggressively than the worker threads which means
  // that messages are read from the network promptly, but then rejected due to
  // unavailability of the worker threads.
  pthread_t this_thread = pthread_self();

  struct sched_param params;
  params.sched_priority = sched_get_priority_min(SCHED_FIFO);

  if (pthread_setschedparam(this_thread, SCHED_FIFO, &params) != 0)
  {
    TRC_WARNING("Unable to set SCHED_FIFO scheduling policy on the transport thread. "
                "Overload may not be handled gracefully");
  }

  pj_bool_t curr_quiescing = PJ_FALSE;

  // Log whenever we do any I/O on this thread. There is only one transport
  // thread so blocking on it is a really bad idea!
  Utils::IOHook io_hook(&on_io_started,
                        Utils::IOHook::NOOP_ON_COMPLETE);

  while (!quit_flag)
  {
    pjsip_endpt_handle_events(stack_data.endpt, &delay);

    // Check if our quiescing state has changed, and act appropriately
    pj_bool_t new_quiescing = quiescing;
    if (curr_quiescing != new_quiescing)
    {
      TRC_STATUS("Quiescing state changed");
      curr_quiescing = new_quiescing;

      if (new_quiescing)
      {
        quiescing_mgr->quiesce();
      }
      else
      {
       quiescing_mgr->unquiesce();
      }
    }

  }

  TRC_STATUS("PJSIP thread ended");

  return 0;
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

  // Pass the data string as a parameter, with a format of "%s", to the standard
  // common log write routine.
  // Note that we mustn't pass data as the format string (with no parameters),
  // because it may contain % characters which we don't want to be accidentally
  // interpreted as format specifiers.
  Log::write(level, "pjsip", 0, "%s", data);
}


void init_pjsip_logging(int log_level,
                        pj_bool_t log_to_file,
                        const std::string& directory)
{
  pj_log_set_level(log_level);
  pj_log_set_decor(PJ_LOG_HAS_SENDER);
  pj_log_set_log_func(&pjsip_log_handler);
}


pj_status_t fill_transport_details(int port,
                                   pj_sockaddr *addr,
                                   pj_str_t& host,
                                   pjsip_host_port *published_name)
{
  pj_status_t status;
  unsigned count = 1;
  pj_addrinfo addr_info[count];
  int af = pj_AF_UNSPEC();

  // Use pj_getaddrinfo() to convert the localhost string into an IPv4 or IPv6 address in
  // a pj_sockaddr structure.  The localhost string could be an IP address in string format
  // or a hostname that needs to be resolved.  The localhost string should only contain a
  // single address or hostname.
  // Bono/Sprout needs to bind to the local host, but use the host passed into this
  // function in the route header (which can be the local or public host)
  status = pj_getaddrinfo(af, &stack_data.local_host, &count, addr_info);
  if (status != PJ_SUCCESS)
  {
    TRC_ERROR("Failed to decode IP address %.*s (%s)",
              stack_data.local_host.slen,
              stack_data.local_host.ptr,
              PJUtils::pj_status_to_string(status).c_str());
    return status;
  }

  pj_memcpy(addr, &addr_info[0].ai_addr, sizeof(pj_sockaddr));

  // Set up the port in the appropriate part of the structure.
  if (addr->addr.sa_family == PJ_AF_INET)
  {
    addr->ipv4.sin_port = pj_htons((pj_uint16_t)port);
  }
  else if (addr->addr.sa_family == PJ_AF_INET6)
  {
    addr->ipv6.sin6_port =  pj_htons((pj_uint16_t)port);
  }
  else
  {
    status = PJ_EAFNOTSUP;
  }

  published_name->host = host;
  published_name->port = port;

  return status;
}


pj_status_t create_udp_transport(int port, pj_str_t& host)
{
  pj_status_t status;
  pj_sockaddr addr;
  pjsip_host_port published_name;

  status = fill_transport_details(port, &addr, host, &published_name);
  if (status != PJ_SUCCESS)
  {
    CL_SPROUT_SIP_UDP_INTERFACE_START_FAIL.log(port, PJUtils::pj_status_to_string(status).c_str());
    TRC_ERROR("Failed to fill in UDP transport for port %d (%s)", port, PJUtils::pj_status_to_string(status).c_str());

    return status;
  }

  // The UDP function call depends on the address type, which should be IPv4
  // or IPv6, otherwise something has gone wrong so don't try to start transport.
  if (addr.addr.sa_family == PJ_AF_INET)
  {
    status = pjsip_udp_transport_start(stack_data.endpt,
                                       &addr.ipv4,
                                       &published_name,
                                       50,
                                       NULL);
  }
  else if (addr.addr.sa_family == PJ_AF_INET6)
  {
    status = pjsip_udp_transport_start6(stack_data.endpt,
                                        &addr.ipv6,
                                        &published_name,
                                        50,
                                        NULL);
  }
  else
  {
    status = PJ_EAFNOTSUP;
  }

  if (status != PJ_SUCCESS)
  {
    CL_SPROUT_SIP_UDP_INTERFACE_START_FAIL.log(port, PJUtils::pj_status_to_string(status).c_str());
    TRC_ERROR("Failed to start UDP transport for port %d (%s)", port, PJUtils::pj_status_to_string(status).c_str());
  }

  return status;
}


pj_status_t create_tcp_listener_transport(int port, pj_str_t& host, pjsip_tpfactory **tcp_factory)
{
  pj_status_t status;
  pj_sockaddr addr;
  pjsip_host_port published_name;
  pjsip_tcp_transport_cfg cfg;

  status = fill_transport_details(port, &addr, host, &published_name);
  if (status != PJ_SUCCESS)
  {
    CL_SPROUT_SIP_TCP_START_FAIL.log(port,
                                     PJUtils::pj_status_to_string(status).c_str());
    TRC_ERROR("Failed to fill in TCP transport for port %d (%s)",
              port,
              PJUtils::pj_status_to_string(status).c_str());

    return status;
  }

  // pjsip_tcp_transport_start2() builds up a configuration structure then calls
  // through to pjsip_tcp_transport_start3().  However it only supports IPv4.
  // Therefore setup the config structure and use pjsip_tcp_transport_start3()
  // instead.

  if (addr.addr.sa_family == PJ_AF_INET)
  {
    pjsip_tcp_transport_cfg_default(&cfg, pj_AF_INET());
  }
  else if (addr.addr.sa_family == PJ_AF_INET6)
  {
    pjsip_tcp_transport_cfg_default(&cfg, pj_AF_INET6());
  }
  else
  {
    status = PJ_EAFNOTSUP;
    CL_SPROUT_SIP_TCP_START_FAIL.log(port,
                                     PJUtils::pj_status_to_string(status).c_str());
    TRC_ERROR("Failed to start TCP transport for port %d  (%s)",
              port,
              PJUtils::pj_status_to_string(status).c_str());
    return status;
  }

  pj_sockaddr_cp(&cfg.bind_addr, &addr);
  pj_memcpy(&cfg.addr_name, &published_name, sizeof(published_name));
  cfg.async_cnt = 50;
  cfg.connect_timeout_ms = stack_data.sip_tcp_connect_timeout;
  cfg.send_timeout_ms = stack_data.sip_tcp_send_timeout;

  status = pjsip_tcp_transport_start3(stack_data.endpt, &cfg, tcp_factory);

  if (status != PJ_SUCCESS)
  {
    CL_SPROUT_SIP_TCP_SERVICE_START_FAIL.log(port,
                                             PJUtils::pj_status_to_string(status).c_str());
    TRC_ERROR("Failed to start TCP transport for port %d (%s)",
              port,
              PJUtils::pj_status_to_string(status).c_str());
  }

  return status;
}


void destroy_tcp_listener_transport(int port, pjsip_tpfactory *tcp_factory)
{
  TRC_STATUS("Destroyed TCP transport for port %d", port);
  tcp_factory->destroy(tcp_factory);
}


pj_status_t start_transports(int port, pj_str_t& host, pjsip_tpfactory** tcp_factory)
{
  pj_status_t status;

  status = create_udp_transport(port, host);

  if (status != PJ_SUCCESS) {
    return status;
  }

  status = create_tcp_listener_transport(port, host, tcp_factory);

  if (status != PJ_SUCCESS) {
    return status;
  }

  TRC_STATUS("Listening on port %d", port);

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

  virtual ~StackQuiesceHandler(){};

  //
  // The following methods are from QuiesceConnectionsInterface.
  //
  void close_untrusted_port()
  {
    // This can only apply to the untrusted P-CSCF port.
    if (stack_data.pcscf_untrusted_tcp_factory != NULL)
    {
      destroy_tcp_listener_transport(stack_data.pcscf_untrusted_port,
                                     stack_data.pcscf_untrusted_tcp_factory);
    }
  }

  void close_trusted_port()
  {
    // This applies to all trusted ports, so the P-CSCF trusted port, or the
    // S-CSCF and I-CSCF ports.
    if (stack_data.pcscf_trusted_tcp_factory != NULL)
    {
      destroy_tcp_listener_transport(stack_data.pcscf_trusted_port,
                                     stack_data.pcscf_trusted_tcp_factory);
    }

    for (std::map<int, pjsip_tpfactory*>::const_iterator ii =
                                            stack_data.sproutlets.begin();
                                            ii != stack_data.sproutlets.end();
                                            ++ii)
    {
      destroy_tcp_listener_transport(ii->first,
                                     ii->second);
      CL_SPROUT_SPROUTLET_END.log(ii->first);
    }
  }

  void open_trusted_port()
  {
    // This applies to all trusted ports, so the P-CSCF trusted port, or the
    // S-CSCF and I-CSCF ports.
    if (stack_data.pcscf_trusted_port != 0)
    {
      create_tcp_listener_transport(stack_data.pcscf_trusted_port,
                                    stack_data.local_host,
                                    &stack_data.pcscf_trusted_tcp_factory);
    }

    for (std::map<int, pjsip_tpfactory*>::const_iterator ii =
                                            stack_data.sproutlets.begin();
                                            ii != stack_data.sproutlets.end();
                                            ++ii)
    {
      create_tcp_listener_transport(ii->first,
                                    stack_data.local_host,
                                    (pjsip_tpfactory**)(ii->second));
    }
  }

  void open_untrusted_port()
  {
    // This can only apply to the untrusted P-CSCF port.
    if (stack_data.pcscf_untrusted_port != 0)
    {
      create_tcp_listener_transport(stack_data.pcscf_untrusted_port,
                                    stack_data.public_host,
                                    &stack_data.pcscf_untrusted_tcp_factory);
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

  // Increase the limit on the number of timers that PJSIP processes each time
  // it polls the timer heap.
  //
  // By default PJSIP will process up to 64 timers and 16 epoll events per call
  // to pjsip_endpt_handle_events. This ratio means that if inbound messages
  // spawn more than a handlful of timers we can set timers faster than they can
  // be expired.
  pj_timer_heap_set_max_timed_out_per_poll(
                                   pjsip_endpt_get_timer_heap(stack_data.endpt),
                                   4096);

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

pj_status_t start_pjsip_thread()
{
  pj_status_t status = PJ_SUCCESS;

  status = pj_thread_create(stack_data.pool, "pjsip", &pjsip_thread_func,
                            NULL, 0, 0, &stack_data.pjsip_transport_thread);
  if (status != PJ_SUCCESS)
  {
    TRC_ERROR("Error creating PJSIP thread, %s",
              PJUtils::pj_status_to_string(status).c_str());
    return 1;
  }

  return PJ_SUCCESS;
}


pj_status_t init_stack(const std::string& system_name,
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
                       const std::string& scscf_uri,
                       const std::string& sprout_hostname,
                       const std::string& alias_hosts,
                       SIPResolver* sipresolver,
                       int record_routing_model,
                       const int default_session_expires,
                       const int max_session_expires,
                       const int sip_tcp_connect_timeout,
                       const int sip_tcp_send_timeout,
                       QuiescingManager *quiescing_mgr_arg,
                       const std::string& cdf_domain,
                       std::vector<std::string> sproutlet_uris,
                       bool enable_orig_sip_to_tel_coerce)
{
  pj_status_t status;
  pj_sockaddr pri_addr;
  pj_sockaddr addr_list[16];
  unsigned addr_cnt = PJ_ARRAY_SIZE(addr_list);
  unsigned i;

  // Get ports and host names specified on options.  If local host was not
  // specified, use the host name returned by pj_gethostname.
  char* local_host_cstr = strdup(local_host.c_str());
  char* public_host_cstr = strdup(public_host.c_str());
  char* home_domain_cstr = strdup(home_domain.c_str());
  char* scscf_uri_cstr = strdup(scscf_uri.c_str());

  // This is only set on Bono nodes (it's the empty string otherwise)
  char* cdf_domain_cstr = strdup(cdf_domain.c_str());

  // Copy port numbers to stack data.
  stack_data.pcscf_trusted_port = pcscf_trusted_port;
  stack_data.pcscf_untrusted_port = pcscf_untrusted_port;
  stack_data.scscf_port = scscf_port;

  stack_data.sipresolver = sipresolver;

  // Copy other functional options to stack data.
  stack_data.default_session_expires = default_session_expires;
  stack_data.max_session_expires = max_session_expires;
  stack_data.sip_tcp_connect_timeout = sip_tcp_connect_timeout;
  stack_data.sip_tcp_send_timeout = sip_tcp_send_timeout;
  stack_data.enable_orig_sip_to_tel_coerce = enable_orig_sip_to_tel_coerce;

  // Work out local and public hostnames and cluster domain names.
  stack_data.local_host = (local_host != "") ? pj_str(local_host_cstr) : *pj_gethostname();
  stack_data.public_host = (public_host != "") ? pj_str(public_host_cstr) : stack_data.local_host;
  stack_data.default_home_domain = (home_domain != "") ? pj_str(home_domain_cstr) : stack_data.local_host;
  stack_data.scscf_uri_str = pj_str(scscf_uri_cstr);
  stack_data.cdf_domain = pj_str(cdf_domain_cstr);

  // Need a version of the SCSCF URI in angle brackets for use as contact header.
  std::string contact_str = "<"+scscf_uri+">";
  stack_data.scscf_contact = pj_str(strdup(contact_str.c_str()));

  // Sprout hostname
  stack_data.sprout_hostname = sprout_hostname;

  // Build a set of home domains
  stack_data.home_domains = std::unordered_set<std::string>();
  stack_data.home_domains.insert(PJUtils::pj_str_to_string(&stack_data.default_home_domain));
  URIClassifier::home_domains.push_back(&stack_data.default_home_domain);
  if (additional_home_domains != "")
  {
    std::list<std::string> domains;
    Utils::split_string(additional_home_domains, ',', domains, 0, true);

    for (std::list<std::string>::iterator ii = domains.begin();
         ii != domains.end();
         ii++)
    {
      stack_data.home_domains.insert(*ii);

      // We can't allocate using PJSIP memory allocation here because it's not yet initialized.
      pj_str_t* domain = (pj_str_t*)malloc(sizeof(pj_str_t));
      *domain = pj_str(strdup(ii->c_str()));
      URIClassifier::home_domains.push_back(domain);
    }
  }

  // Set up the default address family.  This is IPv4 unless our local host is an IPv6 address.
  stack_data.addr_family = AF_INET;
  struct in6_addr dummy_addr;
  if (inet_pton(AF_INET6, local_host_cstr, &dummy_addr) == 1)
  {
    TRC_DEBUG("Local host is an IPv6 address - enabling IPv6 mode");
    stack_data.addr_family = AF_INET6;
  }

  stack_data.record_route_on_every_hop = false;
  stack_data.record_route_on_initiation_of_originating = false;
  stack_data.record_route_on_initiation_of_terminating = false;
  stack_data.record_route_on_completion_of_originating = false;
  stack_data.record_route_on_completion_of_terminating = false;
  stack_data.record_route_on_diversion = false;

  if (scscf_port != 0)
  {
    switch (record_routing_model)
    {
    case 1:
      stack_data.record_route_on_initiation_of_originating = true;
      stack_data.record_route_on_completion_of_terminating = true;
      break;
    case 2:
      stack_data.record_route_on_initiation_of_originating = true;
      stack_data.record_route_on_initiation_of_terminating = true;
      stack_data.record_route_on_completion_of_originating = true;
      stack_data.record_route_on_completion_of_terminating = true;
      stack_data.record_route_on_diversion = true;
      break;
    case 3:
      stack_data.record_route_on_every_hop = true;
      stack_data.record_route_on_initiation_of_originating = true;
      stack_data.record_route_on_initiation_of_terminating = true;
      stack_data.record_route_on_completion_of_originating = true;
      stack_data.record_route_on_completion_of_terminating = true;
      stack_data.record_route_on_diversion = true;
      break;
    default:
      TRC_ERROR("Record-Route setting should be 1, 2, or 3, is %d. Defaulting to Record-Route on every hop.", record_routing_model);
      stack_data.record_route_on_every_hop = true;
    }
  }

  std::string system_name_sas = system_name;
  std::string system_type_sas = (pcscf_trusted_port != 0) ? "bono" : "sprout";
  // Initialize SAS logging.
  if (system_name_sas == "")
  {
    system_name_sas = std::string(stack_data.local_host.ptr, stack_data.local_host.slen);
  }
  SAS::init(system_name,
            system_type_sas,
            SASEvent::CURRENT_RESOURCE_BUNDLE,
            sas_address,
            sas_write,
            sas_signaling_if ? create_connection_in_signaling_namespace
                             : create_connection_in_management_namespace);

  // Initialise PJSIP and all the associated resources.
  status = init_pjsip();

  // Initialize the PJUtils module.
  PJUtils::init();

  stack_data.scscf_uri = (pjsip_sip_uri*)PJUtils::uri_from_string(scscf_uri,
                                                                  stack_data.pool);

  // Create listening transports for the ports whichtrusted and untrusted ports.
  stack_data.pcscf_trusted_tcp_factory = NULL;
  if (stack_data.pcscf_trusted_port != 0)
  {
    status = start_transports(stack_data.pcscf_trusted_port,
                              stack_data.local_host,
                              &stack_data.pcscf_trusted_tcp_factory);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
  }

  stack_data.pcscf_untrusted_tcp_factory = NULL;
  if (stack_data.pcscf_untrusted_port != 0)
  {
    status = start_transports(stack_data.pcscf_untrusted_port,
                              stack_data.public_host,
                              &stack_data.pcscf_untrusted_tcp_factory);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
  }

  for (std::set<int>::iterator ii = sproutlet_ports.begin();
       ii != sproutlet_ports.end();
       ++ii)
  {
    pjsip_tpfactory* tcp_factory = NULL;
    status = start_transports(*ii,
                              stack_data.public_host,
                              &tcp_factory);
    stack_data.sproutlets.insert(std::pair<int, pjsip_tpfactory*>(*ii, tcp_factory));

    if (status == PJ_SUCCESS)
    {
      CL_SPROUT_SPROUTLET_AVAIL.log(*ii);
    }
    else
    {
      CL_SPROUT_SPROUTLET_INIT_FAIL2.log(*ii);
    }

    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
  }

  // List all names matching local endpoint.
  // Note that PJLIB version 0.6 and newer has a function to
  // enumerate local IP interface (pj_enum_ip_interface()), so
  // by using it would be possible to list all IP interfaces in
  // this host.

  // The first address is important since this would be the one
  // to be added in Record-Route.
  stack_data.name.push_back(stack_data.local_host);

  if (strcmp(local_host_cstr, public_host_cstr))
  {
    stack_data.name.push_back(stack_data.public_host);
  }

  // S-CSCF enabled with a specified URI, so add host name from the URI to hostnames.
  if ((scscf_port != 0) && (stack_data.scscf_uri != NULL))
  {
    stack_data.name.push_back(stack_data.scscf_uri->host);
  }

  if (pj_gethostip(pj_AF_INET(), &pri_addr) == PJ_SUCCESS)
  {
    pj_str_t pri_addr_pj_str;
    pj_strdup2(stack_data.pool, &pri_addr_pj_str,
               pj_inet_ntoa(pri_addr.ipv4.sin_addr));
    stack_data.name.push_back(pri_addr_pj_str);
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

      pj_str_t other_addr_pj_str;
      pj_strdup2(stack_data.pool, &other_addr_pj_str,
                 pj_inet_ntoa(addr_list[i].ipv4.sin_addr));
      stack_data.name.push_back(other_addr_pj_str);
    }
  }

  // Note that we no longer consider 127.0.0.1 and localhost as aliases.

  // Parse the list of alias host names. Also add the Sprout hostname, and the
  // sproutlet URIs
  stack_data.aliases = std::unordered_set<std::string>();
  stack_data.aliases.insert(sprout_hostname);
  for (std::vector<std::string>::iterator it = sproutlet_uris.begin();
       it != sproutlet_uris.end();
       ++it)
  {
    pjsip_sip_uri* sproutlet_uri = (pjsip_sip_uri*)PJUtils::uri_from_string(
                                                       *it,
                                                       stack_data.pool,
                                                       false);
    if (sproutlet_uri)
    {
      stack_data.aliases.insert(PJUtils::pj_str_to_string(&sproutlet_uri->host));
    }
  }

  if (alias_hosts != "")
  {
    std::list<std::string> aliases;
    Utils::split_string(alias_hosts, ',', aliases, 0, true);
    stack_data.aliases.insert(aliases.begin(), aliases.end());
  }

  for (std::unordered_set<std::string>::iterator it = stack_data.aliases.begin();
       it != stack_data.aliases.end();
       ++it)
  {
    pj_str_t alias_pj_str;
    pj_strdup2(stack_data.pool, &alias_pj_str, it->c_str());
    stack_data.name.push_back(alias_pj_str);
  }

  TRC_STATUS("Local host aliases:");
  for (std::vector<pj_str_t>::iterator it = stack_data.name.begin();
       it != stack_data.name.end();
       ++it)
  {
    TRC_STATUS(" %.*s",
               (int)(*it).slen,
               (*it).ptr);
  }

  // Set up the Last Value Cache, accumulators and counters.
  std::string process_name;
  if ((stack_data.pcscf_trusted_port != 0) &&
      (stack_data.pcscf_untrusted_port != 0))
  {
    process_name = "bono";
  }
  else
  {
    process_name = "sprout";
  }

  stack_data.stats_aggregator = new LastValueCache(num_known_stats,
                                                   known_statnames,
                                                   process_name);

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

    pjsip_endpt_register_module(stack_data.endpt, &mod_connection_tracking);
  }

  return status;
}


pj_status_t stop_pjsip_thread()
{
  // Set the quit flag to signal the PJSIP thread to exit, then wait
  // for them to exit.
  quit_flag = PJ_TRUE;

  pj_thread_join(stack_data.pjsip_transport_thread);

  stack_data.pjsip_transport_thread = NULL;

  return PJ_SUCCESS;
}

void term_pjsip()
{
  pjsip_endpt_destroy(stack_data.endpt);
  pj_pool_release(stack_data.pool);
  pj_caching_pool_destroy(&stack_data.cp);
  pj_shutdown();
}

void stop_stack()
{
  PJUtils::term();
  pjsip_tsx_layer_destroy();
  pjsip_endpt_unregister_module(stack_data.endpt, &mod_connection_tracking);
}

// Destroy stack
void destroy_stack(void)
{
  // Tear down the stack.
  delete stack_data.stats_aggregator;

  delete stack_quiesce_handler;
  stack_quiesce_handler = NULL;

  delete connection_tracker;
  connection_tracker = NULL;

  SAS::term();

  // Terminate PJSIP.
  term_pjsip();
}
