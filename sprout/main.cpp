/**
 * @file main.cpp
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
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

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <semaphore.h>

// Common STL includes.
#include <cassert>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <queue>
#include <string>


#include "logger.h"
#include "utils.h"
#include "analyticslogger.h"
#include "regdata.h"
#include "stack.h"
#include "hssconnection.h"
#include "xdmconnection.h"
#include "stateful_proxy.h"
#include "websockets.h"
#include "callservices.h"
#include "registrar.h"
#include "authentication.h"
#include "options.h"
#include "memcachedstorefactory.h"
#include "localstorefactory.h"
#include "enumservice.h"
#include "bgcfservice.h"
#include "pjutils.h"
#include "log.h"
#include "zmq_lvc.h"
#include "quiescing_manager.h"
#include "load_monitor.h"
#include "scscfselector.h"
#include "icscfproxy.h"

struct options
{
  bool                   pcscf_enabled;
  int                    pcscf_untrusted_port;
  int                    pcscf_trusted_port;
  int                    webrtc_port;
  std::string            upstream_proxy;
  int                    upstream_proxy_port;
  int                    upstream_proxy_connections;
  int                    upstream_proxy_recycle;
  pj_bool_t              ibcf;
  bool                   scscf_enabled;
  int                    scscf_port;
  bool                   icscf_enabled;
  int                    icscf_port;
  std::string            external_icscf_uri;
  int                    record_routing_model;
  std::string            local_host;
  std::string            public_host;
  std::string            home_domain;
  std::string            sprout_domain;
  std::string            alias_hosts;
  std::string            trusted_hosts;
  pj_bool_t              auth_enabled;
  std::string            auth_realm;
  std::string            auth_config;
  std::string            sas_server;
  std::string            sas_system_name;
  std::string            hss_server;
  std::string            xdm_server;
  std::string            store_servers;
  std::string            remote_store_servers;
  std::string            enum_server;
  std::string            enum_suffix;
  std::string            enum_file;
  pj_bool_t              analytics_enabled;
  std::string            analytics_directory;
  int                    reg_max_expires;
  int                    pjsip_threads;
  int                    worker_threads;
  pj_bool_t              log_to_file;
  std::string            log_directory;
  int                    log_level;
  pj_bool_t              interactive;
  pj_bool_t              daemon;
};


static sem_t term_sem;

static pj_bool_t quiescing = PJ_FALSE;
static sem_t quiescing_sem;
QuiescingManager *quiescing_mgr;

const static int QUIESCE_SIGNAL = SIGQUIT;
const static int UNQUIESCE_SIGNAL = SIGUSR1;

const static int TARGET_LATENCY = 1000000;
const static int MAX_TOKENS = 20;
const static float INITIAL_TOKEN_RATE = 100.0;
const static float MIN_TOKEN_RATE = 10.0;

static void usage(void)
{
  puts("Options:\n"
       "\n"
       " -p, --pcscf <untrusted port>:<trusted port>\n"
       "                            Enable P-CSCF function with the specified ports\n"
       " -i, --icscf <port>         Enable I-CSCF function on the specified port\n"
       " -s, --scscf <port>         Enable S-CSCF function on the specified port\n"
       " -w, --webrtc-port N        Set local WebRTC listener port to N\n"
       "                            If not specified WebRTC support will be disabled\n"
       " -l, --localhost [<hostname>|<private hostname>:<public hostname>]\n"
       "                            Override the local host name with the specified\n"
       "                            hostname(s).  If one name is specified it is used\n"
       "                            as both private and public names.\n"
       " -D, --domain <name>        Override the home domain name\n"
       " -c, --sprout-domain <name> Override the sprout cluster domain name\n"
       " -n, --alias <names>        Optional list of alias host names\n"
       " -r, --routing-proxy <name>[:<port>[:<connections>[:<recycle time>]]]\n"
       "                            Operate as an access proxy using the specified node\n"
       "                            as the upstream routing proxy.  Optionally specifies the port,\n"
       "                            the number of parallel connections to create, and how\n"
       "                            often to recycle these connections (by default a\n"
       "                            single connection to the trusted port is used and never\n"
       "                            recycled).\n"
       " -I, --ibcf <IP addresses>  Operate as an IBCF accepting SIP flows from\n"
       "                            the pre-configured list of IP addresses\n"
       " -j, --external-icscf <I-CSCF URI>\n"
       "                            Route calls to specified external I-CSCF\n"
       " -R, --realm <realm>        Use specified realm for authentication\n"
       "                            (if not specified, local host name is used)\n"
       " -M, --memstore <config_file>"
       "                            Enables local memcached store for registration state and\n"
       "                            specifies configuration file\n"
       "                            (otherwise uses local store)\n"
       " -m, --remote-memstore <config file>\n"
       "                            Enabled remote memcached store for geo-redundant storage\n"
       "                            of registration state, and specifies configuration file\n"
       "                            (otherwise uses no remote memcached store)\n"
       " -S, --sas <ipv4>:<system name>\n"
       "                            Use specified host as software assurance server and specified\n"
       "                            system name to identify this system to SAS.  If this option isn't\n"
       "                            specified SAS is disabled\n"
       " -H, --hss <server>         Name/IP address of HSS server\n"
       " -C, --record-routing-model <model>\n"
       "                            If 'pcscf', Sprout Record-Routes itself only on initiation of\n"
       "                            originating processing and completion of terminating\n"
       "                            processing. If 'pcscf,icscf', it also Record-Routes on completion\n"
       "                            of originating processing and initiation of terminating\n"
       "                            processing (i.e. when it receives or sends to an I-CSCF).\n"
       "                            If 'pcscf,icscf,as', it also Record-Routes between every AS.\n"
       " -X, --xdms <server>        Name/IP address of XDM server\n"
       " -E, --enum <server>        Name/IP address of ENUM server (can't be enabled at same\n"
       "                            time as -f)\n"
       " -x, --enum-suffix <suffix> Suffix appended to ENUM domains (default: .e164.arpa)\n"
       " -f, --enum-file <file>     JSON ENUM config file (can't be enabled at same time as\n"
       "                            -E)\n"
       " -e, --reg-max-expires <expiry>\n"
       "                            The maximum allowed registration period (in seconds)\n"
       " -P, --pjsip_threads N      Number of PJSIP threads (default: 1)\n"
       " -W, --worker_threads N     Number of worker threads (default: 1)\n"
       " -a, --analytics <directory>\n"
       "                            Generate analytics logs in specified directory\n"
       " -A, --authentication       Enable authentication\n"
       " -F, --log-file <directory>\n"
       "                            Log to file in specified directory\n"
       " -L, --log-level N          Set log level to N (default: 4)\n"
       " -d, --daemon               Run as daemon\n"
       " -t, --interactive          Run in foreground with interactive menu\n"
       " -h, --help                 Show this help screen\n"
    );
}


/// Parse a string representing a port.
/// @returns The port number as an int, or zero if the port is invalid.
int parse_port(const std::string& port_str)
{
  int port = atoi(port_str.c_str());

  if ((port < 0) || (port > 0xFFFF))
  {
    port = 0;
  }

  return port;
}


static pj_status_t init_options(int argc, char *argv[], struct options *options)
{
  struct pj_getopt_option long_opt[] =
  {
    { "pcscf",             required_argument, 0, 'p'},
    { "scscf",             required_argument, 0, 's'},
    { "icscf",             required_argument, 0, 'i'},
    { "webrtc-port",       required_argument, 0, 'w'},
    { "localhost",         required_argument, 0, 'l'},
    { "domain",            required_argument, 0, 'D'},
    { "sprout-domain",     required_argument, 0, 'c'},
    { "alias",             required_argument, 0, 'n'},
    { "routing-proxy",     required_argument, 0, 'r'},
    { "ibcf",              required_argument, 0, 'I'},
    { "external-icscf",    required_argument, 0, 'j'},
    { "auth",              required_argument, 0, 'A'},
    { "realm",             required_argument, 0, 'R'},
    { "memstore",          required_argument, 0, 'M'},
    { "remote-memstore",   required_argument, 0, 'm'},
    { "sas",               required_argument, 0, 'S'},
    { "hss",               required_argument, 0, 'H'},
    { "record-routing-model",          required_argument, 0, 'C'},
    { "xdms",              required_argument, 0, 'X'},
    { "enum",              required_argument, 0, 'E'},
    { "enum-suffix",       required_argument, 0, 'x'},
    { "enum-file",         required_argument, 0, 'f'},
    { "reg-max-expires",   required_argument, 0, 'e'},
    { "pjsip-threads",     required_argument, 0, 'P'},
    { "worker-threads",    required_argument, 0, 'W'},
    { "analytics",         required_argument, 0, 'a'},
    { "authentication",    no_argument,       0, 'A'},
    { "log-file",          required_argument, 0, 'F'},
    { "log-level",         required_argument, 0, 'L'},
    { "daemon",            no_argument,       0, 'd'},
    { "interactive",       no_argument,       0, 't'},
    { "help",              no_argument,       0, 'h'},
    { NULL,                0, 0, 0}
  };
  int c;
  int opt_ind;
  int reg_max_expires;

  pj_optind = 0;
  while ((c = pj_getopt_long(argc, argv, "p:s:i:l:D:c:C:n:e:I:A:R:M:S:H:X:E:x:f:r:p:w:a:F:L:dth", long_opt, &opt_ind)) != -1)
  {
    switch (c)
    {
    case 'p':
      {
        std::vector<std::string> pcscf_options;
        Utils::split_string(std::string(pj_optarg), ':', pcscf_options, 0, false);
        if (pcscf_options.size() == 2)
        {
          options->pcscf_untrusted_port = parse_port(pcscf_options[0]);
          options->pcscf_trusted_port = parse_port(pcscf_options[1]);
        }

        if ((options->pcscf_untrusted_port != 0) &&
            (options->pcscf_trusted_port != 0))
        {
          fprintf(stdout, "P-CSCF enabled on ports %d (untrusted) and %d (trusted)\n",
                  options->pcscf_untrusted_port, options->pcscf_trusted_port);
          options->pcscf_enabled = true;
        }
        else
        {
          fprintf(stdout, "P-CSCF ports %s invalid\n", pj_optarg);
          return -1;
        }
      }
      break;

    case 's':
      options->scscf_port = parse_port(std::string(pj_optarg));
      if (options->scscf_port != 0)
      {
        fprintf(stdout, "S-CSCF enabled on port %d\n", options->scscf_port);
        options->scscf_enabled = true;
      }
      else
      {
        fprintf(stdout, "S-CSCF port %s is invalid\n", pj_optarg);
        return -1;
      }
      break;

    case 'i':
      options->icscf_port = parse_port(std::string(pj_optarg));
      if (options->icscf_port != 0)
      {
        fprintf(stdout, "I-CSCF enabled on port %d\n", options->icscf_port);
        options->icscf_enabled = true;
      }
      else
      {
        fprintf(stdout, "I-CSCF port %s is invalid\n", pj_optarg);
        return -1;
      }
      break;

    case 'w':
      options->webrtc_port = parse_port(std::string(pj_optarg));
      if (options->webrtc_port != 0)
      {
        fprintf(stdout, "WebRTC port is set to %d\n", options->webrtc_port);
      }
      else
      {
        fprintf(stdout, "WebRTC port %s is invalid\n", pj_optarg);
        return -1;
      }
      break;

    case 'C':
      if (strcmp(pj_optarg, "pcscf") == 0)
      {
        options->record_routing_model = 1;
      }
      else if (strcmp(pj_optarg, "pcscf,icscf") == 0)
      {
        options->record_routing_model = 2;
      }
      else if (strcmp(pj_optarg, "pcscf,icscf,as") == 0)
      {
        options->record_routing_model = 3;
      }
      else
      {
        fprintf(stdout, "--record-routing-model must be one of 'pcscf', 'pcscf,icscf', or 'pcscf,icscf,as'");
        return -1;
      }
      fprintf(stdout, "Record-Routing model is set to %d\n", options->record_routing_model);
      break;

    case 'l':
      {
        std::vector<std::string> localhost_options;
        Utils::split_string(std::string(pj_optarg), ':', localhost_options, 0, false);
        if (localhost_options.size() == 1)
        {
          options->local_host = localhost_options[0];
          options->public_host = localhost_options[0];
          fprintf(stdout, "Override private and public local host names %s\n",
                  options->local_host.c_str());
        }
        else if (localhost_options.size() == 2)
        {
          options->local_host = localhost_options[0];
          options->public_host = localhost_options[1];
          fprintf(stdout, "Override private local host name to %s\n",
                  options->local_host.c_str());
          fprintf(stdout, "Override public local host name to %s\n",
                  options->public_host.c_str());
        }
        else
        {
          fprintf(stdout, "Invalid --local-host option, ignored\n");
        }
      }
      break;

    case 'D':
      options->home_domain = std::string(pj_optarg);
      fprintf(stdout, "Override home domain set to %s\n", pj_optarg);
      break;

    case 'c':
      options->sprout_domain = std::string(pj_optarg);
      fprintf(stdout, "Override sprout cluster domain set to %s\n", pj_optarg);
      break;

    case 'n':
      options->alias_hosts = std::string(pj_optarg);
      fprintf(stdout, "Alias host names = %s\n", pj_optarg);
      break;

    case 'r':
      {
        std::vector<std::string> upstream_proxy_options;
        Utils::split_string(std::string(pj_optarg), ':', upstream_proxy_options, 0, false);
        options->upstream_proxy = upstream_proxy_options[0];
        options->upstream_proxy_port = 0;
        options->upstream_proxy_connections = 1;
        options->upstream_proxy_recycle = 0;
        if (upstream_proxy_options.size() > 1)
        {
          options->upstream_proxy_port = atoi(upstream_proxy_options[1].c_str());
          if (upstream_proxy_options.size() > 2)
          {
            options->upstream_proxy_connections = atoi(upstream_proxy_options[2].c_str());
            if (upstream_proxy_options.size() > 3)
            {
              options->upstream_proxy_recycle = atoi(upstream_proxy_options[3].c_str());
            }
          }
        }
        fprintf(stdout, "Upstream proxy is set to %s", options->upstream_proxy.c_str());
        if (options->upstream_proxy_port != 0)
        {
          fprintf(stdout, ":%d", options->upstream_proxy_port);
        }
        fprintf(stdout, "\n");
        fprintf(stdout, "  connections = %d\n", options->upstream_proxy_connections);
        fprintf(stdout, "  recycle time = %d seconds\n", options->upstream_proxy_recycle);
      }
      break;

    case 'I':
      options->ibcf = PJ_TRUE;
      options->trusted_hosts = std::string(pj_optarg);
      fprintf(stdout, "IBCF mode enabled, trusted hosts = %s\n", pj_optarg);
      break;

    case 'j':
      options->external_icscf_uri = std::string(pj_optarg);
      fprintf(stdout, "External I-CSCF URI = %s\n", pj_optarg);
      break;

    case 'R':
      options->auth_realm = std::string(pj_optarg);
      fprintf(stdout, "Authentication realm %s\n", pj_optarg);
      break;

    case 'M':
      options->store_servers = std::string(pj_optarg);
      fprintf(stdout, "Using memcached store with configuration file %s\n", pj_optarg);
      break;

    case 'm':
      options->remote_store_servers = std::string(pj_optarg);
      fprintf(stdout, "Using remote memcached store with configuration file %s\n", pj_optarg);
      break;

    case 'S':
      {
        std::vector<std::string> sas_options;
        Utils::split_string(std::string(pj_optarg), ':', sas_options, 0, false);
        if (sas_options.size() == 2)
        {
          options->sas_server = sas_options[0];
          options->sas_system_name = sas_options[1];
          fprintf(stdout, "SAS set to %s\n", options->sas_server.c_str());
          fprintf(stdout, "System name is set to %s\n", options->sas_system_name.c_str());
        }
        else
        {
          fprintf(stdout, "Invalid --sas option, SAS disabled\n");
        }
      }
      break;

    case 'H':
      options->hss_server = std::string(pj_optarg);
      fprintf(stdout, "HSS server set to %s\n", pj_optarg);
      break;

    case 'X':
      options->xdm_server = std::string(pj_optarg);
      fprintf(stdout, "XDM server set to %s\n", pj_optarg);
      break;

    case 'E':
      options->enum_server = std::string(pj_optarg);
      fprintf(stdout, "ENUM server set to %s\n", pj_optarg);
      break;

    case 'x':
      options->enum_suffix = std::string(pj_optarg);
      fprintf(stdout, "ENUM suffix set to %s\n", pj_optarg);
      break;

    case 'f':
      options->enum_file = std::string(pj_optarg);
      fprintf(stdout, "ENUM file set to %s\n", pj_optarg);
      break;

    case 'e':
      reg_max_expires = atoi(pj_optarg);

      if (reg_max_expires > 0)
      {
        options->reg_max_expires = reg_max_expires;
        fprintf(stdout, "Maximum registration period set to %d seconds\n",
                options->reg_max_expires);
      }
      else
      {
        // The parameter could be invalid either because it's -ve, or it's not
        // an integer (in which case atoi returns 0). Log, but don't store it.
        LOG_WARNING("Invalid value for reg_max_expires: '%s'. "
                    "The default value of %d will be used.",
                    pj_optarg, options->reg_max_expires);
      }
      break;

    case 'P':
      options->pjsip_threads = atoi(pj_optarg);
      fprintf(stdout, "Use %d PJSIP threads\n", options->pjsip_threads);
      break;

    case 'W':
      options->worker_threads = atoi(pj_optarg);
      fprintf(stdout, "Use %d worker threads\n", options->worker_threads);
      break;

    case 'a':
      options->analytics_enabled = PJ_TRUE;
      options->analytics_directory = std::string(pj_optarg);
      fprintf(stdout, "Analytics directory set to %s\n", pj_optarg);
      break;

    case 'A':
      options->auth_enabled = PJ_TRUE;
      fprintf(stdout, "Authentication enabled\n");
      break;

    case 'L':
      options->log_level = atoi(pj_optarg);
      fprintf(stdout, "Log level set to %s\n", pj_optarg);
      break;

    case 'F':
      options->log_to_file = PJ_TRUE;
      options->log_directory = std::string(pj_optarg);
      fprintf(stdout, "Log directory set to %s\n", pj_optarg);
      break;

    case 'd':
      options->daemon = PJ_TRUE;
      break;

    case 't':
      options->interactive = PJ_TRUE;
      break;

    case 'h':
      usage();
      return -1;

    default:
      fprintf(stdout, "Unknown option. Run with --help for help.\n");
      return -1;
    }
  }

  // If the upstream proxy port is not set, default it to the trusted port.
  // We couldn't do this earlier because the trusted port might be set after
  // the upstream proxy.
  if (options->upstream_proxy_port == 0)
  {
    options->upstream_proxy_port = options->pcscf_trusted_port;
  }

  return PJ_SUCCESS;
}


int daemonize()
{
  LOG_STATUS("Switching to daemon mode");

  pid_t pid = fork();
  if (pid == -1)
  {
    // Fork failed, return error.
    return errno;
  }
  else if (pid > 0)
  {
    // Parent process, fork successful, so exit.
    exit(0);
  }

  // Must now be running in the context of the child process.

  // Redirect standard files to /dev/null
  if (freopen("/dev/null", "r", stdin) == NULL)
    return errno;
  if (freopen("/dev/null", "w", stdout) == NULL)
    return errno;
  if (freopen("/dev/null", "w", stderr) == NULL)
    return errno;

  if (setsid() == -1)
  {
    // Create a new session to divorce the child from the tty of the parent.
    return errno;
  }

  signal(SIGHUP, SIG_IGN);

  umask(0);

  return 0;
}


// Signal handler that simply dumps the stack and then crashes out.
void exception_handler(int sig)
{
  // Reset the signal handlers so that another exception will cause a crash.
  signal(SIGABRT, SIG_DFL);
  signal(SIGSEGV, SIG_DFL);

  // Log the signal, along with a backtrace.
  LOG_BACKTRACE("Signal %d caught", sig);

  // Dump a core.
  abort();
}


// Signal handler that receives requests to (un)quiesce.
void quiesce_unquiesce_handler(int sig)
{
  // Set the flag indicating whether we're quiescing or not.
  if (sig == QUIESCE_SIGNAL)
  {
    LOG_STATUS("Quiesce signal received");
    quiescing = PJ_TRUE;
  }
  else
  {
    LOG_STATUS("Unquiesce signal received");
    quiescing = PJ_FALSE;
  }

  // Wake up the thread that acts on the notification (don't act on it in this
  // thread since we're in a signal handler).
  sem_post(&quiescing_sem);
}


// Signal handler that triggers sprout termination.
void terminate_handler(int sig)
{
  sem_post(&term_sem);
}


void *quiesce_unquiesce_thread_func(void *dummy)
{
   // First register the thread with PJSIP.
  pj_thread_desc desc;
  pj_thread_t *thread;
  pj_status_t status;

  status = pj_thread_register("Quiesce/unquiesce thread", desc, &thread);

  if (status != PJ_SUCCESS) {
    LOG_ERROR("Error creating quiesce/unquiesce thread (status = %d). "
              "This function will not be available",
              status);
    return NULL;
  }

  pj_bool_t curr_quiescing = PJ_FALSE;
  pj_bool_t new_quiescing = quiescing;

  while (PJ_TRUE)
  {
    // Only act if the quiescing state has changed.
    if (curr_quiescing != new_quiescing)
    {
      curr_quiescing = new_quiescing;

      if (new_quiescing) {
        quiescing_mgr->quiesce();
      } else {
        quiescing_mgr->unquiesce();
      }
    }

    // Wait for the quiescing flag to be written to and read in the new value.
    // Read into a local variable to avoid issues if the flag changes under our
    // feet.
    //
    // Note that sem_wait is a cancel point, so calling pthread_cancel on this
    // thread while it is waiting on the semaphore will cause it to cancel.
    sem_wait(&quiescing_sem);
    new_quiescing = quiescing;
  }

  return NULL;
}

class QuiesceCompleteHandler : public QuiesceCompletionInterface
{
public:
  void quiesce_complete()
  {
    sem_post(&term_sem);
  }
};


/*
 * main()
 */
int main(int argc, char *argv[])
{
  pj_status_t status;
  struct options opt;

  HSSConnection* hss_connection = NULL;
  XDMConnection* xdm_connection = NULL;
  CallServices* call_services = NULL;
  IfcHandler* ifc_handler = NULL;
  AnalyticsLogger* analytics_logger = NULL;
  EnumService* enum_service = NULL;
  BgcfService* bgcf_service = NULL;
  pthread_t quiesce_unquiesce_thread;
  LoadMonitor* load_monitor = NULL;
  SCSCFSelector* scscf_selector = NULL;
  ICSCFProxy* icscf_proxy = NULL;
  RegData::Store* registrar_store = NULL;
  RegData::Store* remote_reg_store = NULL;
  pj_bool_t websockets_enabled = PJ_FALSE;

  // Set up our exception signal handler for asserts and segfaults.
  signal(SIGABRT, exception_handler);
  signal(SIGSEGV, exception_handler);

  // Initialize the semaphore that unblocks the quiesce thread, and the thread
  // itself.
  sem_init(&quiescing_sem, 0, 0);
  pthread_create(&quiesce_unquiesce_thread,
                 NULL,
                 quiesce_unquiesce_thread_func,
                 NULL);

  // Set up our signal handler for (un)quiesce signals.
  signal(QUIESCE_SIGNAL, quiesce_unquiesce_handler);
  signal(UNQUIESCE_SIGNAL, quiesce_unquiesce_handler);

  sem_init(&term_sem, 0, 0);
  signal(SIGTERM, terminate_handler);

  // Create a new quiescing manager instance and register our completion handler
  // with it.
  quiescing_mgr = new QuiescingManager();
  quiescing_mgr->register_completion_handler(new QuiesceCompleteHandler());

  opt.pcscf_enabled = false;
  opt.pcscf_trusted_port = 0;
  opt.pcscf_untrusted_port = 0;
  opt.upstream_proxy_port = 0;
  opt.webrtc_port = 0;
  opt.ibcf = PJ_FALSE;
  opt.scscf_enabled = false;
  opt.scscf_port = 0;
  opt.external_icscf_uri = "";
  opt.auth_enabled = PJ_FALSE;
  opt.enum_suffix = ".e164.arpa";
  opt.reg_max_expires = 300;
  opt.icscf_enabled = false;
  opt.icscf_port = 0;
  opt.sas_server = "0.0.0.0";
  opt.pjsip_threads = 1;
  opt.record_routing_model = 1;
  opt.worker_threads = 1;
  opt.analytics_enabled = PJ_FALSE;
  opt.log_to_file = PJ_FALSE;
  opt.log_level = 0;
  opt.daemon = PJ_FALSE;
  opt.interactive = PJ_FALSE;

  status = init_options(argc, argv, &opt);
  if (status != PJ_SUCCESS)
  {
    return 1;
  }

  Log::setLoggingLevel(opt.log_level);
  LOG_STATUS("Log level set to %d", opt.log_level);

  if (opt.daemon && opt.interactive)
  {
    LOG_ERROR("Cannot specify both --daemon and --interactive");
    return 1;
  }

  if ((!opt.pcscf_enabled) && (!opt.scscf_enabled) && (!opt.icscf_enabled))
  {
    LOG_ERROR("Must enable P-CSCF, S-CSCF or I-CSCF");
    return 1;
  }

  if ((opt.pcscf_enabled) && ((opt.scscf_enabled)))
  {
    LOG_ERROR("Cannot enable both P-CSCF and S-CSCF");
    return 1;
  }

  if ((opt.pcscf_enabled) && ((opt.scscf_enabled) || (opt.icscf_enabled)))
  {
    LOG_ERROR("Cannot enable both P-CSCF and S/I-CSCF");
    return 1;
  }

  if ((opt.pcscf_enabled) &&
      (opt.upstream_proxy == ""))
  {
    LOG_ERROR("Cannot enable P-CSCF without specifying --routing-proxy");
    return 1;
  }

  if ((opt.ibcf) && (!opt.pcscf_enabled))
  {
    LOG_ERROR("Cannot enable IBCF without also enabling P-CSCF");
    return 1;
  }

  if ((opt.webrtc_port != 0 ) && (!opt.pcscf_enabled))
  {
    LOG_ERROR("Cannot enable WebRTC without also enabling P-CSCF");
    return 1;
  }

  if (((opt.scscf_enabled) || (opt.icscf_enabled)) &&
      (opt.hss_server == ""))
  {
    LOG_ERROR("S/I-CSCF enabled with no HSS server");
    return 1;
  }

  if ((opt.auth_enabled) && (opt.hss_server == ""))
  {
    LOG_ERROR("Authentication enable, but no HSS server specified");
    return 1;
  }

  if ((opt.xdm_server != "") && (opt.hss_server == ""))
  {
    LOG_ERROR("XDM server configured for services, but no HSS server specified");
    return 1;
  }

  if ((opt.store_servers != "") &&
      (opt.auth_enabled) &&
      (opt.worker_threads == 1))
  {
    LOG_WARNING("Use multiple threads for good performance when using memstore and/or authentication");
  }

  if (opt.daemon)
  {
    int errnum = daemonize();
    if (errnum != 0)
    {
      LOG_ERROR("Failed to convert to daemon, %d (%s)", errnum, strerror(errnum));
      exit(0);
    }
  }

  if ((opt.pcscf_enabled) && (opt.reg_max_expires != 0))
  {
    LOG_WARNING("A registration expiry period should not be specified for P-CSCF");
  }

  if ((!opt.enum_server.empty()) &&
      (!opt.enum_file.empty()))
  {
    LOG_WARNING("Both ENUM server and ENUM file lookup enabled - ignoring ENUM file");
  }

  // Ensure our random numbers are unpredictable.
  unsigned int seed;
  pj_time_val now;
  pj_gettimeofday(&now);
  seed = (unsigned int)now.sec ^ (unsigned int)now.msec ^ getpid();
  srand(seed);

  init_pjsip_logging(opt.log_level, opt.log_to_file, opt.log_directory);

  if ((opt.log_to_file) && (opt.log_directory != ""))
  {
    // Work out the program name from argv[0], stripping anything before the final slash.
    char* prog_name = argv[0];
    char* slash_ptr = rindex(argv[0], '/');
    if (slash_ptr != NULL) {
      prog_name = slash_ptr + 1;
    }
    Log::setLogger(new Logger(opt.log_directory, prog_name));
  }

  if (opt.analytics_enabled)
  {
    analytics_logger = new AnalyticsLogger(opt.analytics_directory);
  }

  // Start the load monitor
  load_monitor = new LoadMonitor(TARGET_LATENCY, MAX_TOKENS, INITIAL_TOKEN_RATE, MIN_TOKEN_RATE);

  // Initialize the PJSIP stack and associated subsystems.
  status = init_stack(opt.sas_system_name,
                      opt.sas_server,
                      opt.pcscf_trusted_port,
                      opt.pcscf_untrusted_port,
                      opt.scscf_port,
                      opt.icscf_port,
                      opt.local_host,
                      opt.public_host,
                      opt.home_domain,
                      opt.sprout_domain,
                      opt.alias_hosts,
                      opt.pjsip_threads,
                      opt.worker_threads,
                      opt.record_routing_model,
                      quiescing_mgr,
                      load_monitor);

  if (status != PJ_SUCCESS)
  {
    LOG_ERROR("Error initializing stack %s", PJUtils::pj_status_to_string(status).c_str());
    return 1;
  }

  // Initialise the OPTIONS handling module.
  status = init_options();

  if (opt.hss_server != "")
  {
    // Create a connection to the HSS.
    LOG_STATUS("Creating connection to HSS %s", opt.hss_server.c_str());
    hss_connection = new HSSConnection(opt.hss_server, load_monitor);
  }

  if (opt.scscf_enabled)
  {
    if (opt.store_servers != "")
    {
      // Use memcached store.
      LOG_STATUS("Using memcached compatible store with ASCII protocol");
      registrar_store = RegData::create_memcached_store(false, opt.store_servers);
    }
    else
    {
      // Use local store.
      LOG_STATUS("Using local store");
      registrar_store = RegData::create_local_store();
    }

    if (registrar_store == NULL)
    {
      LOG_ERROR("Failed to connect to data store");
      return 1;
    }

    if (opt.remote_store_servers != "")
    {
      // Use remote memcached store too.
      LOG_STATUS("Using remote memcached compatible store with ASCII protocol");
      remote_reg_store = RegData::create_memcached_store(false, opt.remote_store_servers);
    }

    if (opt.xdm_server != "")
    {
      // Create a connection to the XDMS.
      LOG_STATUS("Creating connection to XDMS %s", opt.xdm_server.c_str());
      xdm_connection = new XDMConnection(opt.xdm_server, load_monitor);
    }

    if (xdm_connection != NULL)
    {
      LOG_STATUS("Creating call services handler");
      call_services = new CallServices(xdm_connection);
    }

    if (hss_connection != NULL)
    {
      LOG_STATUS("Initializing iFC handler");
      ifc_handler = new IfcHandler();
    }

    if (opt.auth_enabled)
    {
      LOG_STATUS("Initialise S-CSCF authentication module");
      status = init_authentication(opt.auth_realm, hss_connection, analytics_logger);
    }

    // Create Enum and BGCF services required for S-CSCF.
    if (!opt.enum_server.empty())
    {
      enum_service = new DNSEnumService(opt.enum_server, opt.enum_suffix);
    }
    else if (!opt.enum_file.empty())
    {
      enum_service = new JSONEnumService(opt.enum_file);
    }
    bgcf_service = new BgcfService();

    // Launch the registrar.
    status = init_registrar(registrar_store,
                            remote_reg_store,
                            hss_connection,
                            analytics_logger,
                            ifc_handler,
                            opt.reg_max_expires);

    if (status != PJ_SUCCESS)
    {
      LOG_ERROR("Failed to enable S-CSCF registrar");
      return 1;
    }

    // Launch stateful proxy as S-CSCF.
    status = init_stateful_proxy(registrar_store,
                                 remote_reg_store,
                                 call_services,
                                 ifc_handler,
                                 false,
                                 "",
                                 0,
                                 0,
                                 0,
                                 false,
                                 "",
                                 analytics_logger,
                                 enum_service,
                                 bgcf_service,
                                 hss_connection,
                                 opt.external_icscf_uri,
                                 quiescing_mgr,
                                 scscf_selector,
                                 opt.icscf_enabled,
                                 opt.scscf_enabled);

    if (status != PJ_SUCCESS)
    {
      LOG_ERROR("Failed to enable S-CSCF proxy");
      return 1;
    }
  }

  if (opt.pcscf_enabled)
  {
    // Launch stateful proxy as P-CSCF.
    status = init_stateful_proxy(NULL,
                                 NULL,
                                 NULL,
                                 NULL,
                                 true,
                                 opt.upstream_proxy,
                                 opt.upstream_proxy_port,
                                 opt.upstream_proxy_connections,
                                 opt.upstream_proxy_recycle,
                                 opt.ibcf,
                                 opt.trusted_hosts,
                                 analytics_logger,
                                 NULL,
                                 NULL,
                                 NULL,
                                 "",
                                 quiescing_mgr,
                                 scscf_selector,
                                 opt.icscf_enabled,
                                 opt.scscf_enabled);
    if (status != PJ_SUCCESS)
    {
      LOG_ERROR("Failed to enable P-CSCF edge proxy");
      return 1;
    }

    pj_bool_t websockets_enabled = (opt.webrtc_port != 0);
    if (websockets_enabled)
    {
      status = init_websockets((unsigned short)opt.webrtc_port);
      if (status != PJ_SUCCESS)
      {
        LOG_ERROR("Error initializing websockets, %s",
                  PJUtils::pj_status_to_string(status).c_str());

        return 1;
      }
    }

  }

  if (opt.icscf_enabled)
  {
    // Create the SCSCFSelector.
    scscf_selector = new SCSCFSelector();

    if (scscf_selector == NULL)
    {
      LOG_ERROR("Failed to load S-CSCF capabilities configuration for I-CSCF");
      return 1;
    }

    // Launch I-CSCF proxy.
    icscf_proxy = new ICSCFProxy(stack_data.endpt,
                                 stack_data.icscf_port,
                                 PJSIP_MOD_PRIORITY_UA_PROXY_LAYER,
                                 hss_connection,
                                 scscf_selector,
                                 analytics_logger);

    if (icscf_proxy == NULL)
    {
      LOG_ERROR("Failed to enable I-CSCF proxy");
      return 1;
    }
  }

  status = start_stack();
  if (status != PJ_SUCCESS)
  {
    LOG_ERROR("Error starting SIP stack, %s", PJUtils::pj_status_to_string(status).c_str());
    return 1;
  }

  // Wait here until the quite semaphore is signaled.
  sem_wait(&term_sem);

  stop_stack();
  // We must unregister stack modules here because this terminates the
  // transaction layer, which can otherwise generate work for other modules
  // after they have unregistered.
  unregister_stack_modules();

  if (opt.scscf_enabled)
  {
    destroy_registrar();
    if (opt.auth_enabled)
    {
      destroy_authentication();
    }
    destroy_stateful_proxy();
    delete ifc_handler;
    delete call_services;
    delete hss_connection;
    delete xdm_connection;
    delete enum_service;
    delete bgcf_service;
    if (opt.store_servers != "")
    {
      RegData::destroy_memcached_store(registrar_store);
    }
    else
    {
      RegData::destroy_local_store(registrar_store);
    }

    if (remote_reg_store != NULL)
    {
      RegData::destroy_memcached_store(remote_reg_store);
    }

  }
  if (opt.pcscf_enabled)
  {
    if (websockets_enabled)
    {
      destroy_websockets();
    }
    destroy_stateful_proxy();
  }
  if (opt.icscf_enabled)
  {
    delete icscf_proxy;
    delete scscf_selector;
  }
  destroy_options();
  destroy_stack();

  delete quiescing_mgr;
  delete load_monitor;

  // Unregister the handlers that use semaphores (so we can safely destroy
  // them).
  signal(QUIESCE_SIGNAL, SIG_DFL);
  signal(UNQUIESCE_SIGNAL, SIG_DFL);
  signal(SIGTERM, SIG_DFL);

  // Cancel the (un)quiesce thread (so that we can safely destroy the semaphore
  // it uses).
  pthread_cancel(quiesce_unquiesce_thread);
  pthread_join(quiesce_unquiesce_thread, NULL);

  sem_destroy(&quiescing_sem);
  sem_destroy(&term_sem);

  return 0;
}



