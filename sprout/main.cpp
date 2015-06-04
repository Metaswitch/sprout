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
#include <boost/filesystem.hpp>

#include "ipv6utils.h"
#include "logger.h"
#include "utils.h"
#include "cfgoptions.h"
#include "sasevent.h"
#include "analyticslogger.h"
#include "regstore.h"
#include "stack.h"
#include "hssconnection.h"
#include "xdmconnection.h"
#include "bono.h"
#include "websockets.h"
#include "mmtel.h"
#include "subscription.h"
#include "registrar.h"
#include "authentication.h"
#include "options.h"
#include "dnsresolver.h"
#include "enumservice.h"
#include "bgcfservice.h"
#include "pjutils.h"
#include "log.h"
#include "zmq_lvc.h"
#include "quiescing_manager.h"
#include "load_monitor.h"
#include "memcachedstore.h"
#include "localstore.h"
#include "scscfselector.h"
#include "chronosconnection.h"
#include "handlers.h"
#include "httpstack.h"
#include "sproutlet.h"
#include "sproutletproxy.h"
#include "pluginloader.h"
#include "sprout_pd_definitions.h"
#include "alarm.h"
#include "communicationmonitor.h"
#include "common_sip_processing.h"
#include "thread_dispatcher.h"
#include "exception_handler.h"

enum OptionTypes
{
  OPT_DEFAULT_SESSION_EXPIRES=256+1,
  OPT_ADDITIONAL_HOME_DOMAINS,
  OPT_EMERGENCY_REG_ACCEPTED,
  OPT_SUB_MAX_EXPIRES,
  OPT_MAX_CALL_LIST_LENGTH,
  OPT_MEMENTO_THREADS,
  OPT_CALL_LIST_TTL,
  OPT_ALARMS_ENABLED,
  OPT_DNS_SERVER,
  OPT_TARGET_LATENCY_US,
  OPT_MEMCACHED_WRITE_FORMAT,
  OPT_OVERRIDE_NPDI,
  OPT_MAX_TOKENS,
  OPT_INIT_TOKEN_RATE,
  OPT_MIN_TOKEN_RATE,
  OPT_CASS_TARGET_LATENCY_US,
  OPT_EXCEPTION_MAX_TTL,
  OPT_MAX_SESSION_EXPIRES,
  OPT_SIP_BLACKLIST_DURATION,
  OPT_HTTP_BLACKLIST_DURATION,
  OPT_SIP_TCP_CONNECT_TIMEOUT
};


const static struct pj_getopt_option long_opt[] =
{
  { "pcscf",                        required_argument, 0, 'p'},
  { "scscf",                        required_argument, 0, 's'},
  { "icscf",                        required_argument, 0, 'i'},
  { "webrtc-port",                  required_argument, 0, 'w'},
  { "localhost",                    required_argument, 0, 'l'},
  { "domain",                       required_argument, 0, 'D'},
  { "additional-domains",           required_argument, 0, OPT_ADDITIONAL_HOME_DOMAINS},
  { "scscf-uri",                    required_argument, 0, 'c'},
  { "alias",                        required_argument, 0, 'n'},
  { "routing-proxy",                required_argument, 0, 'r'},
  { "ibcf",                         required_argument, 0, 'I'},
  { "external-icscf",               required_argument, 0, 'j'},
  { "realm",                        required_argument, 0, 'R'},
  { "memstore",                     required_argument, 0, 'M'},
  { "remote-memstore",              required_argument, 0, 'm'},
  { "sas",                          required_argument, 0, 'S'},
  { "hss",                          required_argument, 0, 'H'},
  { "record-routing-model",         required_argument, 0, 'C'},
  { "default-session-expires",      required_argument, 0, OPT_DEFAULT_SESSION_EXPIRES},
  { "max-session-expires",          required_argument, 0, OPT_MAX_SESSION_EXPIRES},
  { "target-latency-us",            required_argument, 0, OPT_TARGET_LATENCY_US},
  { "xdms",                         required_argument, 0, 'X'},
  { "chronos",                      required_argument, 0, 'K'},
  { "ralf",                         required_argument, 0, 'G'},
  { "dns-server",                   required_argument, 0, OPT_DNS_SERVER },
  { "enum",                         required_argument, 0, 'E'},
  { "enum-suffix",                  required_argument, 0, 'x'},
  { "enum-file",                    required_argument, 0, 'f'},
  { "enforce-user-phone",           no_argument,       0, 'u'},
  { "enforce-global-only-lookups",  no_argument,       0, 'g'},
  { "reg-max-expires",              required_argument, 0, 'e'},
  { "sub-max-expires",              required_argument, 0, OPT_SUB_MAX_EXPIRES},
  { "pjsip-threads",                required_argument, 0, 'P'},
  { "worker-threads",               required_argument, 0, 'W'},
  { "analytics",                    required_argument, 0, 'a'},
  { "authentication",               no_argument,       0, 'A'},
  { "log-file",                     required_argument, 0, 'F'},
  { "http-address",                 required_argument, 0, 'T'},
  { "http-port",                    required_argument, 0, 'o'},
  { "http-threads",                 required_argument, 0, 'q'},
  { "billing-cdf",                  required_argument, 0, 'B'},
  { "allow-emergency-registration", no_argument,       0, OPT_EMERGENCY_REG_ACCEPTED},
  { "max-call-list-length",         required_argument, 0, OPT_MAX_CALL_LIST_LENGTH},
  { "memento-threads",              required_argument, 0, OPT_MEMENTO_THREADS},
  { "call-list-ttl",                required_argument, 0, OPT_CALL_LIST_TTL},
  { "alarms-enabled",               no_argument,       0, OPT_ALARMS_ENABLED},
  { "log-level",                    required_argument, 0, 'L'},
  { "daemon",                       no_argument,       0, 'd'},
  { "interactive",                  no_argument,       0, 't'},
  { "help",                         no_argument,       0, 'h'},
  { "memcached-write-format",       required_argument, 0, OPT_MEMCACHED_WRITE_FORMAT},
  { "override-npdi",                no_argument,       0, OPT_OVERRIDE_NPDI},
  { "max-tokens",                   required_argument, 0, OPT_MAX_TOKENS},
  { "init-token-rate",              required_argument, 0, OPT_INIT_TOKEN_RATE},
  { "min-token-rate",               required_argument, 0, OPT_MIN_TOKEN_RATE},
  { "cass-target-latency-us",       required_argument, 0, OPT_CASS_TARGET_LATENCY_US},
  { "exception-max-ttl",            required_argument, 0, OPT_EXCEPTION_MAX_TTL},
  { "sip-blacklist-duration",       required_argument, 0, OPT_SIP_BLACKLIST_DURATION},
  { "http-blacklist-duration",      required_argument, 0, OPT_HTTP_BLACKLIST_DURATION},
  { "sip-tcp-connect-timeout",      required_argument, 0, OPT_SIP_TCP_CONNECT_TIMEOUT},
  { NULL,                           0,                 0, 0}
};

static std::string pj_options_description = "p:s:i:l:D:c:C:n:e:I:A:R:M:S:H:T:o:q:X:E:x:f:u:g:r:P:w:a:F:L:K:G:B:dth";

static sem_t term_sem;

static pj_bool_t quiescing = PJ_FALSE;
static sem_t quiescing_sem;
QuiescingManager* quiescing_mgr;

const static int QUIESCE_SIGNAL = SIGQUIT;
const static int UNQUIESCE_SIGNAL = SIGUSR1;

static void usage(void)
{
  puts("Options:\n"
       "\n"
       " -p, --pcscf <untrusted port>,<trusted port>\n"
       "                            Enable P-CSCF function with the specified ports\n"
       " -i, --icscf <port>         Enable I-CSCF function on the specified port\n"
       " -s, --scscf <port>         Enable S-CSCF function on the specified port\n"
       " -w, --webrtc-port N        Set local WebRTC listener port to N\n"
       "                            If not specified WebRTC support will be disabled\n"
       " -l, --localhost [<hostname>|<private hostname>,<public hostname>]\n"
       "                            Override the local host name with the specified\n"
       "                            hostname(s) or IP address(es).  If one name/address\n"
       "                            is specified it is used as both private and public names.\n"
       " -D, --domain <name>        The home domain name\n"
       "     --additional-domains <names>\n"
       "                            Comma-separated list of additional home domain names\n"
       " -c, --scscf-uri <name>     The Sprout S-CSCF cluster domain URI.  This URI\n"
       "                            must route requests to the S-CSCF port on the Sprout\n"
       "                            cluster, either by specifying the port explicitly or\n"
       "                            using DNS SRV records to specify the port.\n"
       " -n, --alias <names>        Optional list of alias host names\n"
       " -r, --routing-proxy <name>[,<port>[,<connections>[,<recycle time>]]]\n"
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
       " -M, --memstore <config_file>\n"
       "                            Enables local memcached store for registration state and\n"
       "                            specifies configuration file\n"
       "                            (otherwise uses local store)\n"
       " -m, --remote-memstore <config file>\n"
       "                            Enabled remote memcached store for geo-redundant storage\n"
       "                            of registration state, and specifies configuration file\n"
       "                            (otherwise uses no remote memcached store)\n"
       " -S, --sas <ipv4>,<system name>\n"
       "                            Use specified host as Service Assurance Server and specified\n"
       "                            system name to identify this system to SAS.  If this option isn't\n"
       "                            specified SAS is disabled\n"
       " -H, --hss <server>         Name/IP address of the Homestead cluster\n"
       " -K, --chronos              Name/IP address of the local chronos service\n"
       " -C, --record-routing-model <model>\n"
       "                            If 'pcscf', Sprout Record-Routes itself only on initiation of\n"
       "                            originating processing and completion of terminating\n"
       "                            processing. If 'pcscf,icscf', it also Record-Routes on completion\n"
       "                            of originating processing and initiation of terminating\n"
       "                            processing (i.e. when it receives or sends to an I-CSCF).\n"
       "                            If 'pcscf,icscf,as', it also Record-Routes between every AS.\n"
       " -G, --ralf <server>        Name/IP address of Ralf (Rf) billing server.\n"
       " -X, --xdms <server>        Name/IP address of XDM server\n"
       "     --dns-server <server>[,<server2>,<server3>]\n"
       "                            IP addresses of the DNS servers to use (defaults to 127.0.0.1)\n"
       " -E, --enum <server>[,<server2>,<server3>]\n"
       "                            IP addresses of ENUM server (can't be enabled at same\n"
       "                            time as -f)\n"
       " -x, --enum-suffix <suffix> Suffix appended to ENUM domains (default: .e164.arpa)\n"
       " -f, --enum-file <file>     JSON ENUM config file (can't be enabled at same time as\n"
       "                            -E)\n"
       " -u, --enforce-user-phone   Controls whether ENUM lookups are only done on SIP URIs if they\n"
       "                            contain the SIP URI parameter user=phone (defaults to false)\n"
       " -g, --enforce-global-only-lookups\n"
       "                            Controls whether ENUM lookups are only done when the URI\n"
       "                            contains a global number (defaults to false)\n"
       " -e, --reg-max-expires <expiry>\n"
       "                            The maximum allowed registration period (in seconds)\n"
       "     --sub-max-expires <expiry>\n"
       "                            The maximum allowed subscription period (in seconds)\n"
       "     --default-session-expires <expiry>\n"
       "                            The session expiry period to request (in seconds)\n"
       "     --max-session-expires <expiry>\n"
       "                            The maximum allowed session expiry period (in seconds)\n"
       "     --target-latency-us <usecs>\n"
       "                            Target latency above which throttling applies (default: 100000)\n"
       "     --cass-target-latency-us <usecs>\n"
       "                            Target latency above which throttling applies for the Cassandra store\n"
       "                            that's part of the Memento application server (default: 1000000)\n"
       "     --max-tokens N         Maximum number of tokens allowed in the token bucket (used by\n"
       "                            the throttling code (default: 20))\n"
       "     --init-token-rate N    Initial token refill rate of tokens in the token bucket (used by\n"
       "                            the throttling code (default: 100.0))\n"
       "     --min-token-rate N     Minimum token refill rate of tokens in the token bucket (used by\n"
       "                            the throttling code (default: 10.0))\n"
       " -T  --http-address <server>\n"
       "                            Specify the HTTP bind address\n"
       " -o  --http-port <port>     Specify the HTTP bind port\n"
       " -q  --http-threads N       Number of HTTP threads (default: 1)\n"
       " -P, --pjsip-threads N      Number of PJSIP threads (default: 1)\n"
       " -B, --billing-cdf <server> Billing CDF server\n"
       " -W, --worker-threads N     Number of worker threads (default: 1)\n"
       " -a, --analytics <directory>\n"
       "                            Generate analytics logs in specified directory\n"
       " -A, --authentication       Enable authentication\n"
       "     --allow-emergency-registration\n"
       "                            Allow the P-CSCF to acccept emergency registrations.\n"
       "                            Only valid if -p/pcscf is specified.\n"
       "                            WARNING: If this is enabled, all emergency registrations are accepted,\n"
       "                            but they are not policed.\n"
       "                            This parameter is only intended to be enabled during testing.\n"
       "     --max-call-list-length N\n"
       "                            Maximum number of complete call list entries to store. If this is 0,\n"
       "                            then there is no limit (default: 0)\n"
       "     --memento-threads N    Number of Memento threads (default: 25)\n"
       "     --call-list-ttl N      Time to store call lists entries (default: 604800)\n"
       "     --alarms-enabled       Whether SNMP alarms are enabled (default: false)\n"
       "     --memcached-write-format\n"
       "                            The data format to use when writing registration and subscription data\n"
       "                            to memcached. Valid values are 'binary' and 'json' (default is 'json')\n"
       "     --override-npdi        Whether the deployment should check for number portability data on \n"
       "                            requests that already have the 'npdi' indicator (default: false)\n"
       "     --exception-max-ttl <secs>\n"
       "                            The maximum time before the process exits if it hits an exception.\n"
       "                            The actual time is randomised.\n"
       "     --sip-blacklist-duration <secs>\n"
       "                            The amount of time to blacklist a SIP peer when it is unresponsive.\n"
       "     --http-blacklist-duration <secs>\n"
       "                            The amount of time to blacklist an HTTP peer when it is unresponsive.\n"
       "     --sip-tcp-connect-timeout <milliseconds>\n"
       "                            The amount of time to wait for a SIP TCP connection to establish.\n"
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


static pj_status_t init_logging_options(int argc, char* argv[], struct options* options)
{
  int c;
  int opt_ind;

  pj_optind = 0;
  while ((c = pj_getopt_long(argc, argv, pj_options_description.c_str(), long_opt, &opt_ind)) != -1)
  {
    switch (c)
    {
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

    default:
      // Ignore other options at this point
      break;
    }
  }

  return PJ_SUCCESS;
}

static pj_status_t init_options(int argc, char* argv[], struct options* options)
{
  int c;
  int opt_ind;
  int reg_max_expires;
  int sub_max_expires;

  pj_optind = 0;
  while ((c = pj_getopt_long(argc, argv, pj_options_description.c_str(), long_opt, &opt_ind)) != -1)
  {
    switch (c)
    {
    case 'p':
      {
        std::vector<std::string> pcscf_options;
        Utils::split_string(std::string(pj_optarg), ',', pcscf_options, 0, false);
        if (pcscf_options.size() == 2)
        {
          options->pcscf_untrusted_port = parse_port(pcscf_options[0]);
          options->pcscf_trusted_port = parse_port(pcscf_options[1]);
        }

        if ((options->pcscf_untrusted_port != 0) &&
            (options->pcscf_trusted_port != 0))
        {
          LOG_INFO("P-CSCF enabled on ports %d (untrusted) and %d (trusted)",
                   options->pcscf_untrusted_port, options->pcscf_trusted_port);
          options->pcscf_enabled = true;
        }
        else
        {
          LOG_ERROR("P-CSCF ports %s invalid", pj_optarg);
          return -1;
        }
      }
      break;

    case 's':
      options->scscf_port = parse_port(std::string(pj_optarg));
      if (options->scscf_port != 0)
      {
        LOG_INFO("S-CSCF enabled on port %d", options->scscf_port);
        options->scscf_enabled = true;
      }
      else
      {
        CL_SPROUT_INVALID_S_CSCF_PORT.log(pj_optarg);
        LOG_ERROR("S-CSCF port %s is invalid\n", pj_optarg);
        return -1;
      }
      break;

    case 'i':
      options->icscf_port = parse_port(std::string(pj_optarg));
      if (options->icscf_port != 0)
      {
        LOG_INFO("I-CSCF enabled on port %d", options->icscf_port);
        options->icscf_enabled = true;
      }
      else
      {
        CL_SPROUT_INVALID_I_CSCF_PORT.log(pj_optarg);
        LOG_ERROR("I-CSCF port %s is invalid", pj_optarg);
        return -1;
      }
      break;

    case 'w':
      options->webrtc_port = parse_port(std::string(pj_optarg));
      if (options->webrtc_port != 0)
      {
        LOG_INFO("WebRTC port is set to %d", options->webrtc_port);
      }
      else
      {
        LOG_ERROR("WebRTC port %s is invalid", pj_optarg);
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
        LOG_ERROR("--record-routing-model must be one of 'pcscf', 'pcscf,icscf', or 'pcscf,icscf,as'");
        return -1;
      }
      LOG_INFO("Record-Routing model is set to %d", options->record_routing_model);
      break;

    case 'l':
      {
        std::vector<std::string> localhost_options;
        Utils::split_string(std::string(pj_optarg), ',', localhost_options, 0, false);
        if (localhost_options.size() == 1)
        {
          options->local_host = localhost_options[0];
          options->public_host = localhost_options[0];
          LOG_INFO("Override private and public local host names %s",
                   options->local_host.c_str());
        }
        else if (localhost_options.size() == 2)
        {
          options->local_host = localhost_options[0];
          options->public_host = localhost_options[1];
          LOG_INFO("Override private local host name to %s",
                  options->local_host.c_str());
          LOG_INFO("Override public local host name to %s",
                  options->public_host.c_str());
        }
        else
        {
          LOG_WARNING("Invalid --local-host option, ignored");
        }
      }
      break;

    case 'D':
      options->home_domain = std::string(pj_optarg);
      LOG_INFO("Home domain set to %s", pj_optarg);
      break;

    case OPT_ADDITIONAL_HOME_DOMAINS:
      options->additional_home_domains = std::string(pj_optarg);
      LOG_INFO("Additional home domains set to %s", pj_optarg);
      break;

    case 'c':
      options->scscf_uri = std::string(pj_optarg);
      LOG_INFO("Sprout cluster URI set to %s", pj_optarg);
      break;

    case 'n':
      options->alias_hosts = std::string(pj_optarg);
      LOG_INFO("Alias host names = %s", pj_optarg);
      break;

    case 'r':
      {
        std::vector<std::string> upstream_proxy_options;
        Utils::split_string(std::string(pj_optarg), ',', upstream_proxy_options, 0, false);
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
        LOG_INFO("Upstream proxy is set to %s:%d", options->upstream_proxy.c_str(), options->upstream_proxy_port);
        LOG_INFO("  connections = %d", options->upstream_proxy_connections);
        LOG_INFO("  recycle time = %d seconds", options->upstream_proxy_recycle);
      }
      break;

    case 'I':
      options->ibcf = PJ_TRUE;
      options->trusted_hosts = std::string(pj_optarg);
      LOG_INFO("IBCF mode enabled, trusted hosts = %s", pj_optarg);
      break;

    case 'j':
      options->external_icscf_uri = std::string(pj_optarg);
      LOG_INFO("External I-CSCF URI = %s", pj_optarg);
      break;

    case 'R':
      options->auth_realm = std::string(pj_optarg);
      LOG_INFO("Authentication realm %s", pj_optarg);
      break;

    case 'M':
      options->store_servers = std::string(pj_optarg);
      LOG_INFO("Using memcached store with configuration file %s", pj_optarg);
      break;

    case 'm':
      options->remote_store_servers = std::string(pj_optarg);
      LOG_INFO("Using remote memcached store with configuration file %s", pj_optarg);
      break;

    case 'S':
      {
        std::vector<std::string> sas_options;
        Utils::split_string(std::string(pj_optarg), ',', sas_options, 0, false);
        if (sas_options.size() == 2)
        {
          options->sas_server = sas_options[0];
          options->sas_system_name = sas_options[1];
          LOG_INFO("SAS set to %s", options->sas_server.c_str());
          LOG_INFO("System name is set to %s", options->sas_system_name.c_str());
        }
        else
        {
          CL_SPROUT_INVALID_SAS_OPTION.log();
          LOG_WARNING("Invalid --sas option, SAS disabled");
        }
      }
      break;

    case 'H':
      options->hss_server = std::string(pj_optarg);
      LOG_INFO("HSS server set to %s", pj_optarg);
      break;

    case 'X':
      options->xdm_server = std::string(pj_optarg);
      LOG_INFO("XDM server set to %s", pj_optarg);
      break;

    case 'K':
      options->chronos_service = std::string(pj_optarg);
      LOG_INFO("Chronos service set to %s", pj_optarg);
      break;

    case 'G':
      options->ralf_server = std::string(pj_optarg);
      fprintf(stdout, "Ralf server set to %s\n", pj_optarg);
      break;

    case 'E':
      options->enum_servers.clear();
      Utils::split_string(std::string(pj_optarg), ',', options->enum_servers, 0, false);
      LOG_INFO("%d ENUM servers passed on the command line",
               options->enum_servers.size());
      break;

    case 'x':
      options->enum_suffix = std::string(pj_optarg);
      LOG_INFO("ENUM suffix set to %s", pj_optarg);
      break;

    case 'f':
      options->enum_file = std::string(pj_optarg);
      LOG_INFO("ENUM file set to %s", pj_optarg);
      break;

    case 'u':
      options->enforce_user_phone = true;
      LOG_INFO("ENUM lookups are only done on SIP URIs if they contain user=phone");
      break;

    case 'g':
      options->enforce_global_only_lookups = true;
      LOG_INFO("ENUM lookups are only done on URIs if they contain a global number");
      break;

    case 'e':
      reg_max_expires = atoi(pj_optarg);

      if (reg_max_expires > 0)
      {
        options->reg_max_expires = reg_max_expires;
        LOG_INFO("Maximum registration period set to %d seconds\n",
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

    case OPT_SUB_MAX_EXPIRES:
      sub_max_expires = atoi(pj_optarg);

      if (sub_max_expires > 0)
      {
        options->sub_max_expires = sub_max_expires;
        LOG_INFO("Maximum registration period set to %d seconds\n",
                 options->sub_max_expires);
      }
      else
      {
        // The parameter could be invalid either because it's -ve, or it's not
        // an integer (in which case atoi returns 0). Log, but don't store it.
        LOG_WARNING("Invalid value for sub_max_expires: '%s'. "
                    "The default value of %d will be used.",
                    pj_optarg, options->sub_max_expires);
      }
      break;

    case OPT_TARGET_LATENCY_US:
      options->target_latency_us = atoi(pj_optarg);
      if (options->target_latency_us <= 0)
      {
        LOG_ERROR("Invalid --target-latency-us option %s", pj_optarg);
        return -1;
      }
      break;

    case OPT_CASS_TARGET_LATENCY_US:
      options->cass_target_latency_us = atoi(pj_optarg);
      if (options->cass_target_latency_us <= 0)
      {
        LOG_ERROR("Invalid --cass-target-latency-us option %s", pj_optarg);
        return -1;
      }
      break;

    case OPT_MAX_TOKENS:
      options->max_tokens = atoi(pj_optarg);
      if (options->max_tokens <= 0)
      {
        LOG_ERROR("Invalid --max-tokens option %s", pj_optarg);
        return -1;
      }
      break;

    case OPT_INIT_TOKEN_RATE:
      options->init_token_rate = atoi(pj_optarg);
      if (options->init_token_rate <= 0)
      {
        LOG_ERROR("Invalid --init-token-rate option %s", pj_optarg);
        return -1;
      }
      break;

    case OPT_MIN_TOKEN_RATE:
      options->min_token_rate = atoi(pj_optarg);
      if (options->min_token_rate <= 0)
      {
        LOG_ERROR("Invalid --min-token-rate option %s", pj_optarg);
        return -1;
      }
      break;

    case OPT_MEMCACHED_WRITE_FORMAT:
      if (strcmp(pj_optarg, "binary") == 0)
      {
        LOG_INFO("Memcached write format set to 'binary'");
        options->memcached_write_format = MemcachedWriteFormat::BINARY;
      }
      else if (strcmp(pj_optarg, "json") == 0)
      {
        LOG_INFO("Memcached write format set to 'json'");
        options->memcached_write_format = MemcachedWriteFormat::JSON;
      }
      else
      {
        LOG_WARNING("Invalid value for memcached-write-format, using '%s'."
                    "Got '%s', valid vales are 'json' and 'binary'",
                    ((options->memcached_write_format == MemcachedWriteFormat::JSON) ?
                     "json" : "binary"),
                    pj_optarg);
      }
      break;

    case 'P':
      options->pjsip_threads = atoi(pj_optarg);
      LOG_INFO("Use %d PJSIP threads", options->pjsip_threads);
      break;

    case 'W':
      options->worker_threads = atoi(pj_optarg);
      LOG_INFO("Use %d worker threads", options->worker_threads);
      break;

    case 'a':
      options->analytics_enabled = PJ_TRUE;
      options->analytics_directory = std::string(pj_optarg);
      LOG_INFO("Analytics directory set to %s", pj_optarg);
      break;

    case 'A':
      options->auth_enabled = PJ_TRUE;
      LOG_INFO("Authentication enabled");
      break;

    case 'T':
      options->http_address = std::string(pj_optarg);
      LOG_INFO("HTTP address set to %s", pj_optarg);
      break;

    case 'o':
      options->http_port = parse_port(std::string(pj_optarg));
      if (options->http_port != 0)
      {
        LOG_INFO("HTTP port set to %d", options->http_port);
      }
      else
      {
        LOG_ERROR("HTTP port %s is invalid", pj_optarg);
        return -1;
      }
      break;

    case 'q':
      options->http_threads = atoi(pj_optarg);
      LOG_INFO("Use %d HTTP threads", options->http_threads);
      break;

    case 'B':
      options->billing_cdf = std::string(pj_optarg);
      LOG_INFO("Use %s as billing cdf server", options->billing_cdf.c_str());
      break;

    case 'L':
    case 'F':
    case 'd':
    case 't':
      // Ignore L, F, d and t - these are handled by init_logging_options
      break;

    case OPT_DEFAULT_SESSION_EXPIRES:
      options->default_session_expires = atoi(pj_optarg);
      LOG_INFO("Default session expiry set to %d",
               options->default_session_expires);
      break;

    case OPT_MAX_SESSION_EXPIRES:
      options->max_session_expires = atoi(pj_optarg);
      LOG_INFO("Max session expiry set to %d",
               options->max_session_expires);
      break;

    case OPT_EMERGENCY_REG_ACCEPTED:
      options->emerg_reg_accepted = PJ_TRUE;
      LOG_INFO("Emergency registrations accepted");
      break;

    case OPT_MAX_CALL_LIST_LENGTH:
      options->max_call_list_length = atoi(pj_optarg);
      LOG_INFO("Max call list length set to %d",
               options->max_call_list_length);
      break;

    case OPT_MEMENTO_THREADS:
      options->memento_threads = atoi(pj_optarg);
      LOG_INFO("Number of memento threads set to %d",
               options->memento_threads);
      break;

    case OPT_CALL_LIST_TTL:
      options->call_list_ttl = atoi(pj_optarg);
      LOG_INFO("Call list TTL set to %d",
               options->call_list_ttl);
      break;

    case OPT_ALARMS_ENABLED:
      options->alarms_enabled = PJ_TRUE;
      LOG_INFO("SNMP alarms are enabled");
      break;

    case OPT_DNS_SERVER:
      options->dns_servers.clear();
      Utils::split_string(std::string(pj_optarg), ',', options->dns_servers, 0, false);
      LOG_INFO("%d DNS servers passed on the command line",
               options->dns_servers.size());
    break;

    case OPT_OVERRIDE_NPDI:
      options->override_npdi = true;
      LOG_INFO("Number portability lookups will be done on URIs containing the 'npdi' indicator");
      break;

    case OPT_EXCEPTION_MAX_TTL:
      options->exception_max_ttl = atoi(pj_optarg);
      LOG_INFO("Max TTL after an exception set to %d",
               options->exception_max_ttl);
      break;

    case OPT_SIP_BLACKLIST_DURATION:
      options->sip_blacklist_duration = atoi(pj_optarg);
      LOG_INFO("SIP blacklist duration set to %d",
               options->sip_blacklist_duration);
      break;

    case OPT_HTTP_BLACKLIST_DURATION:
      options->http_blacklist_duration = atoi(pj_optarg);
      LOG_INFO("HTTP blacklist duration set to %d",
               options->http_blacklist_duration);
      break;

    case OPT_SIP_TCP_CONNECT_TIMEOUT:
      options->sip_tcp_connect_timeout = atoi(pj_optarg);
      LOG_INFO("SIP TCP connect timeout set to %d",
               options->sip_tcp_connect_timeout);
      break;

    case 'h':
      usage();
      return -1;

    default:
      LOG_ERROR("Unknown option. Run with --help for help.");
      return -1;
    }
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
  {
    return errno;
  }
  if (freopen("/dev/null", "w", stdout) == NULL)
  {
    return errno;
  }
  if (freopen("/dev/null", "w", stderr) == NULL)
  {
    return errno;
  }

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
void signal_handler(int sig)
{
  // Reset the signal handlers so that another exception will cause a crash.
  signal(SIGABRT, SIG_DFL);
  signal(SIGSEGV, signal_handler);

  // Log the signal, along with a backtrace.
  LOG_BACKTRACE("Signal %d caught", sig);

  // Ensure the log files are complete - the core file created by abort() below
  // will trigger the log files to be copied to the diags bundle
  LOG_COMMIT();

  // Check if there's a stored jmp_buf on the thread and handle if there is
  exception_handler->handle_exception();

  CL_SPROUT_CRASH.log(strsignal(sig));
  closelog();

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


void* quiesce_unquiesce_thread_func(void* dummy)
{
  // First register the thread with PJSIP.
  pj_thread_desc desc;
  pj_thread_t* thread;
  pj_status_t status;
  pj_bzero(desc, sizeof(pj_thread_desc));

  status = pj_thread_register("Quiesce/unquiesce thread", desc, &thread);

  if (status != PJ_SUCCESS)
  {
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

      if (new_quiescing)
      {
        quiescing_mgr->quiesce();
      }
      else
      {
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
    LOG_STATUS("Value of new_quiescing is %s", (new_quiescing == PJ_FALSE) ? "false" : "true");
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


/// Registers HTTP threads with PJSIP so we can use PJSIP APIs on these threads
void reg_httpthread_with_pjsip(evhtp_t * htp, evthr_t * httpthread, void * arg)
{
  if (!pj_thread_is_registered())
  {
    // The thread descriptor must stay in scope for the lifetime of the thread
    // so we must allocate it from heap.  However, this will leak because
    // there is no way of freeing it when the thread terminates (HttpStack
    // does not support a thread termination callback and pthread_cleanup_push
    // won't work in this case).  This is okay for now because HttpStack
    // just creates a pool of threads at start of day.
    pj_thread_desc* td = (pj_thread_desc*)malloc(sizeof(pj_thread_desc));
    pj_bzero(*td, sizeof(pj_thread_desc));
    pj_thread_t *thread = 0;

    pj_status_t thread_reg_status = pj_thread_register("SproutHTTPThread",
                                                       *td,
                                                       &thread);

    if (thread_reg_status != PJ_SUCCESS)
    {
      LOG_ERROR("Failed to register thread with pjsip");
    }
  }
}


void create_regstore_plugins(RegStore::SerializerDeserializer*& serializer,
                             std::vector<RegStore::SerializerDeserializer*>& deserializers,
                             MemcachedWriteFormat write_format)
{
  deserializers.clear();
  deserializers.push_back(new RegStore::JsonSerializerDeserializer());
  deserializers.push_back(new RegStore::BinarySerializerDeserializer());

  if (write_format == MemcachedWriteFormat::JSON)
  {
    serializer = new RegStore::JsonSerializerDeserializer();
  }
  else
  {
    serializer = new RegStore::BinarySerializerDeserializer();
  }
}


// Objects that must be shared with dynamically linked sproutlets must be
// globally scoped.
LoadMonitor* load_monitor = NULL;
HSSConnection* hss_connection = NULL;
RegStore* local_reg_store = NULL;
RegStore* remote_reg_store = NULL;
HttpConnection* ralf_connection = NULL;
HttpResolver* http_resolver = NULL;
ACRFactory* scscf_acr_factory = NULL;
EnumService* enum_service = NULL;
ExceptionHandler* exception_handler = NULL;

/*
 * main()
 */
int main(int argc, char* argv[])
{
  pj_status_t status;
  struct options opt;

  Logger* analytics_logger_logger = NULL;
  AnalyticsLogger* analytics_logger = NULL;
  pthread_t quiesce_unquiesce_thread;
  DnsCachedResolver* dns_resolver = NULL;
  SIPResolver* sip_resolver = NULL;
  Store* local_data_store = NULL;
  Store* remote_data_store = NULL;
  AvStore* av_store = NULL;
  ChronosConnection* chronos_connection = NULL;
  ACRFactory* pcscf_acr_factory = NULL;
  pj_bool_t websockets_enabled = PJ_FALSE;
  AccessLogger* access_logger = NULL;
  SproutletProxy* sproutlet_proxy = NULL;
  std::list<Sproutlet*> sproutlets;
  CommunicationMonitor* chronos_comm_monitor = NULL;
  CommunicationMonitor* enum_comm_monitor = NULL;
  CommunicationMonitor* hss_comm_monitor = NULL;
  CommunicationMonitor* memcached_comm_monitor = NULL;
  CommunicationMonitor* memcached_remote_comm_monitor = NULL;
  CommunicationMonitor* ralf_comm_monitor = NULL;
  Alarm* vbucket_alarm = NULL;
  Alarm* remote_vbucket_alarm = NULL;

  // Set up our exception signal handler for asserts and segfaults.
  signal(SIGABRT, signal_handler);
  signal(SIGSEGV, signal_handler);

  sem_init(&term_sem, 0, 0);
  signal(SIGTERM, terminate_handler);

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
  opt.enforce_user_phone = false;
  opt.enforce_global_only_lookups = false;
  opt.reg_max_expires = 300;
  opt.sub_max_expires = 300;
  opt.icscf_enabled = false;
  opt.icscf_port = 0;
  opt.sas_server = "0.0.0.0";
  opt.chronos_service = "localhost:7253";
  opt.pjsip_threads = 1;
  opt.record_routing_model = 1;
  opt.default_session_expires = 10 * 60;
  opt.max_session_expires = 10 * 60;
  opt.worker_threads = 1;
  opt.analytics_enabled = PJ_FALSE;
  opt.http_address = "127.0.0.1";
  opt.http_port = 9888;
  opt.http_threads = 1;
  opt.dns_servers.push_back("127.0.0.1");
  opt.billing_cdf = "";
  opt.emerg_reg_accepted = PJ_FALSE;
  opt.max_call_list_length = 0;
  opt.memento_threads = 25;
  opt.call_list_ttl = 604800;
  opt.alarms_enabled = PJ_FALSE;
  opt.target_latency_us = 100000;
  opt.cass_target_latency_us = 1000000;
  opt.max_tokens = 20;
  opt.init_token_rate = 100.0;
  opt.min_token_rate = 10.0;
  opt.log_to_file = PJ_FALSE;
  opt.log_level = 0;
  opt.daemon = PJ_FALSE;
  opt.interactive = PJ_FALSE;
  opt.memcached_write_format = MemcachedWriteFormat::JSON;
  opt.override_npdi = PJ_FALSE;
  opt.exception_max_ttl = 600;
  opt.sip_blacklist_duration = SIPResolver::DEFAULT_BLACKLIST_DURATION;
  opt.http_blacklist_duration = HttpResolver::DEFAULT_BLACKLIST_DURATION;
  opt.sip_tcp_connect_timeout = 2000;

  boost::filesystem::path p = argv[0];
  // Copy the filename to a string so that we can be sure of its lifespan -
  // the value passed to openlog must be valid for the duration of the program.
  std::string filename = p.filename().c_str();
  openlog(filename.c_str(), PDLOG_PID, PDLOG_LOCAL6);
  CL_SPROUT_STARTED.log();

  status = init_logging_options(argc, argv, &opt);

  if (status != PJ_SUCCESS)
  {
    closelog();
    return 1;
  }

  if (opt.daemon && opt.interactive)
  {
    closelog();
    LOG_ERROR("Cannot specify both --daemon and --interactive");
    return 1;
  }

  if (opt.daemon)
  {
    int errnum = daemonize();
    if (errnum != 0)
    {
      closelog();
      LOG_ERROR("Failed to convert to daemon, %d (%s)", errnum, strerror(errnum));
      exit(0);
    }
  }

  Log::setLoggingLevel(opt.log_level);
  init_pjsip_logging(opt.log_level, opt.log_to_file, opt.log_directory);

  if ((opt.log_to_file) && (opt.log_directory != ""))
  {
    // Work out the program name from argv[0], stripping anything before the final slash.
    char* prog_name = argv[0];
    char* slash_ptr = rindex(argv[0], '/');
    if (slash_ptr != NULL)
    {
      prog_name = slash_ptr + 1;
    }
    Log::setLogger(new Logger(opt.log_directory, prog_name));

    LOG_STATUS("Access logging enabled to %s", opt.log_directory.c_str());
    access_logger = new AccessLogger(opt.log_directory);
  }

  LOG_STATUS("Log level set to %d", opt.log_level);

  std::stringstream options_ss;
  for (int ii = 0; ii < argc; ii++)
  {
    options_ss << argv[ii];
    options_ss << " ";
  }
  std::string options = "Command-line options were: " + options_ss.str();

  LOG_INFO(options.c_str());

  status = init_options(argc, argv, &opt);
  if (status != PJ_SUCCESS)
  {
    closelog();
    return 1;
  }

  if (opt.analytics_enabled)
  {
    analytics_logger_logger = new Logger(opt.analytics_directory, std::string("log"));
    analytics_logger_logger->set_flags(Logger::ADD_TIMESTAMPS|Logger::FLUSH_ON_WRITE);
    analytics_logger = new AnalyticsLogger(analytics_logger_logger);
  }

  if ((!opt.pcscf_enabled) && (!opt.scscf_enabled) && (!opt.icscf_enabled))
  {
    CL_SPROUT_NO_SI_CSCF.log();
    closelog();
    LOG_ERROR("Must enable P-CSCF, S-CSCF or I-CSCF");
    return 1;
  }

  if ((opt.pcscf_enabled) && ((opt.scscf_enabled) || (opt.icscf_enabled)))
  {
    closelog();
    LOG_ERROR("Cannot enable both P-CSCF and S/I-CSCF");
    return 1;
  }

  if ((opt.pcscf_enabled) &&
      (opt.upstream_proxy == ""))
  {
    closelog();
    LOG_ERROR("Cannot enable P-CSCF without specifying --routing-proxy");
    return 1;
  }

  if ((opt.ibcf) && (!opt.pcscf_enabled))
  {
    closelog();
    LOG_ERROR("Cannot enable IBCF without also enabling P-CSCF");
    return 1;
  }

  if ((opt.webrtc_port != 0 ) && (!opt.pcscf_enabled))
  {
    closelog();
    LOG_ERROR("Cannot enable WebRTC without also enabling P-CSCF");
    return 1;
  }

  if ((opt.scscf_enabled) && (opt.scscf_uri == ""))
  {
    LOG_ERROR("S-CSCF enabled, but no S-CSCF URI specified");
    return 1;
  }

  if (((opt.scscf_enabled) || (opt.icscf_enabled)) &&
      (opt.hss_server == ""))
  {
    CL_SPROUT_SI_CSCF_NO_HOMESTEAD.log();
    closelog();
    LOG_ERROR("S/I-CSCF enabled with no Homestead server");
    return 1;
  }

  if ((opt.auth_enabled) && (opt.hss_server == ""))
  {
    CL_SPROUT_AUTH_NO_HOMESTEAD.log();
    closelog();
    LOG_ERROR("Authentication enabled, but no Homestead server specified");
    return 1;
  }

  if ((opt.xdm_server != "") && (opt.hss_server == ""))
  {
    CL_SPROUT_XDM_NO_HOMESTEAD.log();
    closelog();
    LOG_ERROR("XDM server configured for services, but no Homestead server specified");
    return 1;
  }

  if ((opt.pcscf_enabled) && (opt.hss_server != ""))
  {
    LOG_WARNING("Homestead server configured on P-CSCF, ignoring");
  }

  if ((opt.pcscf_enabled) && (opt.xdm_server != ""))
  {
    LOG_WARNING("XDM server configured on P-CSCF, ignoring");
  }

  if ((opt.store_servers != "") &&
      (opt.auth_enabled) &&
      (opt.worker_threads == 1))
  {
    LOG_WARNING("Use multiple threads for good performance when using memstore and/or authentication");
  }

  if ((opt.pcscf_enabled) && (opt.reg_max_expires != 0))
  {
    LOG_WARNING("A registration expiry period should not be specified for P-CSCF");
  }

  if ((!opt.enum_servers.empty()) &&
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

  if ((opt.icscf_enabled || opt.scscf_enabled) && opt.alarms_enabled)
  {
    // Create Sprout's alarm objects.

    chronos_comm_monitor = new CommunicationMonitor(new Alarm("sprout", AlarmDef::SPROUT_CHRONOS_COMM_ERROR,
                                                                        AlarmDef::MAJOR));

    enum_comm_monitor = new CommunicationMonitor(new Alarm("sprout", AlarmDef::SPROUT_ENUM_COMM_ERROR,
                                                                     AlarmDef::MAJOR));

    hss_comm_monitor = new CommunicationMonitor(new Alarm("sprout", AlarmDef::SPROUT_HOMESTEAD_COMM_ERROR,
                                                                    AlarmDef::CRITICAL));

    memcached_comm_monitor = new CommunicationMonitor(new Alarm("sprout", AlarmDef::SPROUT_MEMCACHED_COMM_ERROR,
                                                                          AlarmDef::CRITICAL));

    memcached_remote_comm_monitor = new CommunicationMonitor(new Alarm("sprout", AlarmDef::SPROUT_REMOTE_MEMCACHED_COMM_ERROR,
                                                                                 AlarmDef::CRITICAL));

    ralf_comm_monitor = new CommunicationMonitor(new Alarm("sprout", AlarmDef::SPROUT_RALF_COMM_ERROR,
                                                                     AlarmDef::MAJOR));

    vbucket_alarm = new Alarm("sprout", AlarmDef::SPROUT_VBUCKET_ERROR,
                                        AlarmDef::MAJOR);

    remote_vbucket_alarm = new Alarm("sprout", AlarmDef::SPROUT_REMOTE_VBUCKET_ERROR,
                                               AlarmDef::MAJOR);

    // Start the alarm request agent
    AlarmReqAgent::get_instance().start();
    AlarmState::clear_all("sprout");
  }

  // Start the load monitor
  load_monitor = new LoadMonitor(opt.target_latency_us, // Initial target latency (us).
                                 opt.max_tokens,        // Maximum token bucket size.
                                 opt.init_token_rate,   // Initial token fill rate (per sec).
                                 opt.min_token_rate);   // Minimum token fill rate (per sec).

  // Start the health checker
  HealthChecker* health_checker = new HealthChecker();
  pthread_t health_check_thread;
  pthread_create(&health_check_thread,
                 NULL,
                 &HealthChecker::static_main_thread_function,
                 (void*)health_checker);

  // Create an exception handler. The exception handler should attempt to
  // quiesce the process before killing it.
  exception_handler = new ExceptionHandler(opt.exception_max_ttl,
                                           true,
                                           health_checker);

  // Create a DNS resolver and a SIP specific resolver.
  dns_resolver = new DnsCachedResolver(opt.dns_servers);
  sip_resolver = new SIPResolver(dns_resolver, opt.sip_blacklist_duration);

  // Create a new quiescing manager instance and register our completion handler
  // with it.
  quiescing_mgr = new QuiescingManager();
  quiescing_mgr->register_completion_handler(new QuiesceCompleteHandler());

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
                      opt.additional_home_domains,
                      opt.scscf_uri,
                      opt.alias_hosts,
                      sip_resolver,
                      opt.pjsip_threads,
                      opt.record_routing_model,
                      opt.default_session_expires,
                      opt.max_session_expires,
                      opt.sip_tcp_connect_timeout,
                      quiescing_mgr,
                      opt.billing_cdf);

  if (status != PJ_SUCCESS)
  {
    CL_SPROUT_SIP_INIT_INTERFACE_FAIL.log(PJUtils::pj_status_to_string(status).c_str());
    LOG_ERROR("Error initializing stack %s", PJUtils::pj_status_to_string(status).c_str());
    return 1;
  }

  // Initialize the semaphore that unblocks the quiesce thread, and the thread
  // itself. This must happen after init_stack is called, because this
  // calls init_pjsip, which calls pj_init, which sets up the
  // necessary environment for us to register threads with pjsip.
  sem_init(&quiescing_sem, 0, 0);
  pthread_create(&quiesce_unquiesce_thread,
                 NULL,
                 quiesce_unquiesce_thread_func,
                 NULL);

  // Set up our signal handler for (un)quiesce signals.
  signal(QUIESCE_SIGNAL, quiesce_unquiesce_handler);
  signal(UNQUIESCE_SIGNAL, quiesce_unquiesce_handler);

  // Now that we know the address family, create an HttpResolver too.
  http_resolver = new HttpResolver(dns_resolver,
                                   stack_data.addr_family,
                                   opt.http_blacklist_duration);

  if (opt.ralf_server != "")
  {
    // Create HttpConnection pool for Ralf Rf billing interface.
    ralf_connection = new HttpConnection(opt.ralf_server,
                                         false,
                                         http_resolver,
                                         "connected_ralfs",
                                         load_monitor,
                                         stack_data.stats_aggregator,
                                         SASEvent::HttpLogLevel::PROTOCOL,
                                         ralf_comm_monitor);
  }
  else
  {
    CL_SPROUT_NO_RALF_CONFIGURED.log();
  }

  // Initialise the OPTIONS handling module.
  status = init_options();

  if (opt.hss_server != "")
  {
    // Create a connection to the HSS.
    LOG_STATUS("Creating connection to HSS %s", opt.hss_server.c_str());
    hss_connection = new HSSConnection(opt.hss_server,
                                       http_resolver,
                                       load_monitor,
                                       stack_data.stats_aggregator,
                                       hss_comm_monitor);
  }

  if ((opt.scscf_enabled) || (opt.icscf_enabled))
  {
    // Create ENUM service required for I/S-CSCF.
    if (!opt.enum_servers.empty())
    {
      LOG_STATUS("Setting up the ENUM server(s)");
      enum_service = new DNSEnumService(opt.enum_servers,
                                        opt.enum_suffix,
                                        new DNSResolverFactory(),
                                        enum_comm_monitor);
    }
    else if (!opt.enum_file.empty())
    {
      LOG_STATUS("Reading from an ENUM file");
      enum_service = new JSONEnumService(opt.enum_file);
    }
  }

  if (opt.chronos_service != "")
  {
    std::string port_str = std::to_string(opt.http_port);
    std::string chronos_callback_host = "127.0.0.1:" + port_str;

    // We want Chronos to call back to its local sprout instance so that we can
    // handle Sprouts failing without missing timers.
    if (is_ipv6(opt.http_address))
    {
      chronos_callback_host = "[::1]:" + port_str;
    }

    // Create a connection to Chronos.
    LOG_STATUS("Creating connection to Chronos %s using %s as the callback URI",
               opt.chronos_service.c_str(),
               chronos_callback_host.c_str());
    chronos_connection = new ChronosConnection(opt.chronos_service,
                                               chronos_callback_host,
                                               http_resolver,
                                               chronos_comm_monitor);
  }

  if (opt.pcscf_enabled)
  {
    // Create an ACR factory for the P-CSCF.
    pcscf_acr_factory = (ralf_connection != NULL) ?
                (ACRFactory*)new RalfACRFactory(ralf_connection, PCSCF) :
                new ACRFactory();

    // Launch stateful proxy as P-CSCF.
    status = init_stateful_proxy(NULL,
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
                                 false,
                                 false,
                                 NULL,
                                 NULL,
                                 pcscf_acr_factory,
                                 NULL,
                                 NULL,
                                 "",
                                 quiescing_mgr,
                                 NULL,
                                 opt.icscf_enabled,
                                 opt.scscf_enabled,
                                 opt.emerg_reg_accepted);
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

  if (opt.scscf_enabled)
  {
    scscf_acr_factory = (ralf_connection != NULL) ?
                      (ACRFactory*)new RalfACRFactory(ralf_connection, SCSCF) :
                      new ACRFactory();

    if (opt.store_servers != "")
    {
      // Use memcached store.
      LOG_STATUS("Using memcached compatible store with ASCII protocol");

      local_data_store = (Store*)new MemcachedStore(true,
                                                    opt.store_servers,
                                                    memcached_comm_monitor,
                                                    vbucket_alarm);

      if (!(((MemcachedStore*)local_data_store)->has_servers()))
      {
        LOG_ERROR("Cluster settings file '%s' does not contain a valid set of servers",
                  opt.store_servers.c_str());
        return 1;
      };

      if (opt.remote_store_servers != "")
      {
        // Use remote memcached store too.
        LOG_STATUS("Using remote memcached compatible store with ASCII protocol");

        remote_data_store = (Store*)new MemcachedStore(true,
                                                       opt.remote_store_servers,
                                                       memcached_remote_comm_monitor,
                                                       remote_vbucket_alarm);

        if (!(((MemcachedStore*)remote_data_store)->has_servers()))
        {
          LOG_WARNING("Remote cluster settings file '%s' does not contain a valid set of servers",
                      opt.remote_store_servers.c_str());
        };
      }
    }
    else
    {
      // Use local store.
      LOG_STATUS("Using local store");
      local_data_store = (Store*)new LocalStore();
    }

    if (local_data_store == NULL)
    {
      CL_SPROUT_MEMCACHE_CONN_FAIL.log();
      closelog();
      LOG_ERROR("Failed to connect to data store");
      exit(0);
    }

    // Create local and optionally remote registration data stores.
    //
    // It is fine to reuse these variables for creating both stores, as
    // ownership of the objects they point to is transferred to the store when
    // it is constructed.
    RegStore::SerializerDeserializer* serializer;
    std::vector<RegStore::SerializerDeserializer*> deserializers;

    create_regstore_plugins(serializer,
                            deserializers,
                            opt.memcached_write_format);
    local_reg_store = new RegStore(local_data_store,
                                   serializer,
                                   deserializers,
                                   chronos_connection);

    if (remote_data_store != NULL)
    {
      create_regstore_plugins(serializer,
                              deserializers,
                              opt.memcached_write_format);
      remote_reg_store = new RegStore(remote_data_store,
                                      serializer,
                                      deserializers,
                                      chronos_connection);
    }

    if (opt.auth_enabled)
    {
      // Create an AV store using the local store and initialise the authentication
      // module.  We don't create a AV store using the remote data store as
      // Authentication Vectors are only stored for a short period after the
      // relevant challenge is sent.
      LOG_STATUS("Initialise S-CSCF authentication module");
      av_store = new AvStore(local_data_store);
      status = init_authentication(opt.auth_realm,
                                   av_store,
                                   hss_connection,
                                   chronos_connection,
                                   scscf_acr_factory,
                                   analytics_logger);
    }

    // Launch the registrar.
    status = init_registrar(local_reg_store,
                            remote_reg_store,
                            hss_connection,
                            analytics_logger,
                            scscf_acr_factory,
                            opt.reg_max_expires);

    if (status != PJ_SUCCESS)
    {
      CL_SPROUT_INIT_SERVICE_ROUTE_FAIL.log(PJUtils::pj_status_to_string(status).c_str());
      closelog();
      LOG_ERROR("Failed to enable S-CSCF registrar");
      return 1;
    }

    // Launch the subscription module.
    status = init_subscription(local_reg_store,
                               remote_reg_store,
                               hss_connection,
                               scscf_acr_factory,
                               analytics_logger,
                               opt.sub_max_expires);

    if (status != PJ_SUCCESS)
    {
      CL_SPROUT_REG_SUBSCRIBER_HAND_FAIL.log(PJUtils::pj_status_to_string(status).c_str());
      closelog();
      LOG_ERROR("Failed to enable subscription module");
      return 1;
    }
  }

  // Load the sproutlet plugins.
  PluginLoader* loader = new PluginLoader("/usr/share/clearwater/sprout/plugins", opt);

  if (!loader->load(sproutlets))
  {
    CL_SPROUT_PLUGIN_FAILURE.log();
    closelog();
    LOG_ERROR("Failed to successfully load plug-ins");
    return 1;
  }

  if (!sproutlets.empty())
  {
    // There are Sproutlets loaded, so start the Sproutlet proxy.
    std::unordered_set<std::string> host_aliases;
    host_aliases.insert(opt.local_host);
    host_aliases.insert(opt.public_host);
    host_aliases.insert(opt.home_domain);
    host_aliases.insert(stack_data.home_domains.begin(),
                        stack_data.home_domains.end());
    host_aliases.insert(stack_data.aliases.begin(),
                        stack_data.aliases.end());

    sproutlet_proxy = new SproutletProxy(stack_data.endpt,
                                         PJSIP_MOD_PRIORITY_UA_PROXY_LAYER+3,
                                         std::string(stack_data.scscf_uri.ptr,
                                                     stack_data.scscf_uri.slen),
                                         host_aliases,
                                         sproutlets);
    if (sproutlet_proxy == NULL)
    {
      CL_SPROUT_S_CSCF_INIT_FAIL.log();
      CL_SPROUT_BGCF_INIT_FAIL.log();
      CL_SPROUT_I_CSCF_INIT_FAIL.log();
      LOG_ERROR("Failed to create SproutletProxy");
      closelog();
      return 1;
    }
  }

  Accumulator* latency_accumulator =
      new StatisticAccumulator("latency_us",
                               stack_data.stats_aggregator);
  Accumulator* queue_size_accumulator =
      new StatisticAccumulator("queue_size",
                               stack_data.stats_aggregator);
  Counter* requests_counter =
      new StatisticCounter("incoming_requests",
                           stack_data.stats_aggregator);
  Counter* overload_counter =
      new StatisticCounter("rejected_overload",
                           stack_data.stats_aggregator);

  init_common_sip_processing(load_monitor,
                             requests_counter,
                             overload_counter,
                             health_checker);

  init_thread_dispatcher(opt.worker_threads,
                         latency_accumulator,
                         queue_size_accumulator,
                         load_monitor,
                         exception_handler);

  // Create worker threads first as they take work from the PJSIP threads so
  // need to be ready.

  status = start_worker_threads();
  if (status != PJ_SUCCESS)
  {
    LOG_ERROR("Error starting SIP worker threads, %s", PJUtils::pj_status_to_string(status).c_str());
    return 1;
  }

  status = start_pjsip_threads();
  if (status != PJ_SUCCESS)
  {
    CL_SPROUT_SIP_STACK_INIT_FAIL.log(PJUtils::pj_status_to_string(status).c_str());
    closelog();
    LOG_ERROR("Error starting SIP stack, %s", PJUtils::pj_status_to_string(status).c_str());
    return 1;
  }

  RegistrationTimeoutTask::Config reg_timeout_config(local_reg_store, remote_reg_store, hss_connection);
  AuthTimeoutTask::Config auth_timeout_config(av_store, hss_connection);
  DeregistrationTask::Config deregistration_config(local_reg_store, remote_reg_store, hss_connection, sip_resolver);

  // The RegistrationTimeoutTask and AuthTimeoutTask both handle
  // chronos requests, so use the ChronosHandler.
  ChronosHandler<RegistrationTimeoutTask, RegistrationTimeoutTask::Config> reg_timeout_handler(&reg_timeout_config);
  ChronosHandler<AuthTimeoutTask, AuthTimeoutTask::Config> auth_timeout_handler(&auth_timeout_config);
  HttpStackUtils::SpawningHandler<DeregistrationTask, DeregistrationTask::Config> deregistration_handler(&deregistration_config);
  HttpStackUtils::PingHandler ping_handler;

  HttpStack* http_stack = NULL;
  if (opt.scscf_enabled)
  {
    http_stack = HttpStack::get_instance();

    try
    {
      http_stack->initialize();
      http_stack->configure(opt.http_address,
                            opt.http_port,
                            opt.http_threads,
                            exception_handler,
                            access_logger);
      http_stack->register_handler("^/ping$",
                                   &ping_handler);
      http_stack->register_handler("^/timers$",
                                   &reg_timeout_handler);
      http_stack->register_handler("^/authentication-timeout$",
                                   &auth_timeout_handler);
      http_stack->register_handler("^/registrations?*$",
                                   &deregistration_handler);
      http_stack->start(&reg_httpthread_with_pjsip);
    }
    catch (HttpStack::Exception& e)
    {
      CL_SPROUT_HTTP_INTERFACE_FAIL.log(e._func, e._rc);
      closelog();
      LOG_ERROR("Caught HttpStack::Exception - %s - %d\n", e._func, e._rc);
      return 1;
    }
  }

  // Wait here until the quit semaphore is signaled.
  sem_wait(&term_sem);

  CL_SPROUT_ENDED.log();
  if (opt.scscf_enabled)
  {
    try
    {
      http_stack->stop();
      http_stack->wait_stopped();
    }
    catch (HttpStack::Exception& e)
    {
      CL_SPROUT_HTTP_INTERFACE_STOP_FAIL.log(e._func, e._rc);
      LOG_ERROR("Caught HttpStack::Exception - %s - %d\n", e._func, e._rc);
    }
  }

  // Terminate the PJSIP threads and the worker threads to exit.  We kill
  // the PJSIP threads first - if we killed the worker threads first the
  // rx_msg_q will stop getting serviced so could fill up blocking
  // PJSIP threads, causing a deadlock.
  stop_pjsip_threads();
  stop_worker_threads();

  // We must call stop_stack here because this terminates the
  // transaction layer, which can otherwise generate work for other modules
  // after they have unregistered.
  stop_stack();

  unregister_thread_dispatcher();
  unregister_common_processing_module();

  // Destroy the Sproutlet Proxy.
  delete sproutlet_proxy;

  // Unload any dynamically loaded sproutlets and delete the loader.
  loader->unload();
  delete loader;

  if (opt.scscf_enabled)
  {
    destroy_subscription();
    destroy_registrar();
    if (opt.auth_enabled)
    {
      destroy_authentication();
    }
    delete chronos_connection;
  }
  if (opt.pcscf_enabled)
  {
    if (websockets_enabled)
    {
      destroy_websockets();
    }
    destroy_stateful_proxy();
    delete pcscf_acr_factory;
  }

  destroy_options();
  destroy_stack();

  delete hss_connection;
  delete quiescing_mgr;
  delete exception_handler;
  delete load_monitor;
  delete local_reg_store;
  delete remote_reg_store;
  delete av_store;
  delete local_data_store;
  delete remote_data_store;
  delete ralf_connection;
  delete enum_service;
  delete scscf_acr_factory;

  delete sip_resolver;
  delete http_resolver;
  delete dns_resolver;

  delete analytics_logger;
  delete analytics_logger_logger;

  if ((opt.icscf_enabled || opt.scscf_enabled) && opt.alarms_enabled)
  {
    // Stop the alarm request agent
    AlarmReqAgent::get_instance().stop();

    // Delete Sprout's alarm objects
    delete chronos_comm_monitor;
    delete enum_comm_monitor;
    delete hss_comm_monitor;
    delete memcached_comm_monitor;
    delete memcached_remote_comm_monitor;
    delete ralf_comm_monitor;
    delete vbucket_alarm;
    delete remote_vbucket_alarm;
  }

  delete latency_accumulator;
  delete queue_size_accumulator;
  delete requests_counter;
  delete overload_counter;

  health_checker->terminate();
  pthread_join(health_check_thread, NULL);
  delete health_checker;

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
  closelog();

  return 0;
}
