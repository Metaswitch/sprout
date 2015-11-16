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
#include "bono.h"
#include "hssconnection.h"
#include "xdmconnection.h"
#include "bono.h"
#include "websockets.h"
#include "memcachedstore.h"
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
#include "quiescing_manager.h"
#include "load_monitor.h"
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
#include "scscfsproutlet.h"
#include "snmp_continuous_accumulator_table.h"
#include "snmp_event_accumulator_table.h"
#include "snmp_scalar.h"
#include "snmp_counter_table.h"
#include "snmp_success_fail_count_table.h"
#include "snmp_agent.h"
#include "ralf_processor.h"
#include "sprout_alarmdefinition.h"

enum OptionTypes
{
  OPT_DEFAULT_SESSION_EXPIRES=256+1,
  OPT_ADDITIONAL_HOME_DOMAINS,
  OPT_EMERGENCY_REG_ACCEPTED,
  OPT_SUB_MAX_EXPIRES,
  OPT_MAX_CALL_LIST_LENGTH,
  OPT_MEMENTO_THREADS,
  OPT_CALL_LIST_TTL,
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
  OPT_SIP_TCP_CONNECT_TIMEOUT,
  OPT_SIP_TCP_SEND_TIMEOUT,
  OPT_SESSION_CONTINUED_TIMEOUT_MS,
  OPT_SESSION_TERMINATED_TIMEOUT_MS,
  OPT_STATELESS_PROXIES,
  OPT_RALF_THREADS,
  OPT_NON_REGISTERING_PBXES,
  OPT_PBX_SERVICE_ROUTE,
  OPT_NON_REGISTER_AUTHENTICATION,
  OPT_FORCE_THIRD_PARTY_REGISTER_BODY,
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
  { "sip-tcp-send-timeout",         required_argument, 0, OPT_SIP_TCP_SEND_TIMEOUT},
  { "session-continued-timeout",    required_argument, 0, OPT_SESSION_CONTINUED_TIMEOUT_MS},
  { "session-terminated-timeout",   required_argument, 0, OPT_SESSION_TERMINATED_TIMEOUT_MS},
  { "stateless-proxies",            required_argument, 0, OPT_STATELESS_PROXIES},
  { "non-registering-pbxes",        required_argument, 0, OPT_NON_REGISTERING_PBXES},
  { "ralf-threads",                 required_argument, 0, OPT_RALF_THREADS},
  { "non-register-authentication",  required_argument, 0, OPT_NON_REGISTER_AUTHENTICATION},
  { "pbx-service-route",            required_argument, 0, OPT_PBX_SERVICE_ROUTE},
  { "force-3pr-body",               no_argument,       0, OPT_FORCE_THIRD_PARTY_REGISTER_BODY},
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
       "     --ralf-threads N       Number of Ralf threads (default: 25)\n"
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
       "     --sip-tcp-send-timeout <milliseconds>\n"
       "                            The amount of time to wait for data sent on a SIP TCP connection to be\n"
       "                            acknowledged by the peer.\n"
       "     --session-continued-timeout <milliseconds>\n"
       "                            If an Application Server with default handling of 'continue session'\n"
       "                            is unresponsive, this is the time that sprout will wait (in ms)\n"
       "                            before bypassing the AS and moving onto the next AS in the chain.\n"
       "     --session-terminated-timeout <milliseconds>\n"
       "                            If an Application Server with default handling of 'terminate session'\n"
       "                            is unresponsive, this is the time that sprout will wait (in ms)\n"
       "                            before terminating the session.\n"
       "     --stateless-proxies <comma-separated-list>\n"
       "                            A comma separated list of domain names that are treated as SIP\n"
       "                            stateless proxies. This field should reflect how the servers are\n"
       "                            identified in SIP (for example if a cluster of nodes is identified by\n"
       "                            the name 'cluster.example.com', this value should be used instead of\n"
       "                            the hostnames or IP addresses of individual servers\n"
       "     --non-registering-pbxes <comma-separated-list>\n"
       "                            A comma separated list of IP addresses that are treated as\n"
       "                            non-registering PBXes (i.e. INVITEs should be allowed by the \n"
       "                            P-CSCF, but challenged by the core)\n"
       "     --pbx-service-route <URI>\n"
       "                            The URI of the S-CSCF used to provide services for originating\n"
       "                            services to non-registering PBXes\n"
       "     --non-register-authentication <option>\n"
       "                            Controls when sprout will challenge the sender of a non-REGISTER\n"
       "                            message to provide authentication. Takes one of the following values:\n"
       "                            - 'never' means that sprout never challenges non-REGISTER requests.\n"
       "                            - 'if_proxy_authorization_present' means sprout will only challenge\n"
       "                              requests that already have a Proxy-Authorization header.\n"
       "     --force-3pr-body       Always include the original REGISTER and 200 OK in the body of\n"
       "                            third-party REGISTER messages to application servers, even if the\n"
       "                            User-Data doesn't specify it\n"
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
          TRC_INFO("P-CSCF enabled on ports %d (untrusted) and %d (trusted)",
                   options->pcscf_untrusted_port, options->pcscf_trusted_port);
          options->pcscf_enabled = true;
        }
        else
        {
          TRC_ERROR("P-CSCF ports %s invalid", pj_optarg);
          return -1;
        }
      }
      break;

    case 's':
      options->scscf_port = parse_port(std::string(pj_optarg));
      if (options->scscf_port != 0)
      {
        TRC_INFO("S-CSCF enabled on port %d", options->scscf_port);
        options->scscf_enabled = true;
      }
      else
      {
        CL_SPROUT_INVALID_S_CSCF_PORT.log(pj_optarg);
        TRC_ERROR("S-CSCF port %s is invalid\n", pj_optarg);
        return -1;
      }
      break;

    case 'i':
      options->icscf_port = parse_port(std::string(pj_optarg));
      if (options->icscf_port != 0)
      {
        TRC_INFO("I-CSCF enabled on port %d", options->icscf_port);
        options->icscf_enabled = true;
      }
      else
      {
        CL_SPROUT_INVALID_I_CSCF_PORT.log(pj_optarg);
        TRC_ERROR("I-CSCF port %s is invalid", pj_optarg);
        return -1;
      }
      break;

    case 'w':
      options->webrtc_port = parse_port(std::string(pj_optarg));
      if (options->webrtc_port != 0)
      {
        TRC_INFO("WebRTC port is set to %d", options->webrtc_port);
      }
      else
      {
        TRC_ERROR("WebRTC port %s is invalid", pj_optarg);
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
        TRC_ERROR("--record-routing-model must be one of 'pcscf', 'pcscf,icscf', or 'pcscf,icscf,as'");
        return -1;
      }
      TRC_INFO("Record-Routing model is set to %d", options->record_routing_model);
      break;

    case 'l':
      {
        std::vector<std::string> localhost_options;
        Utils::split_string(std::string(pj_optarg), ',', localhost_options, 0, false);
        if (localhost_options.size() == 1)
        {
          options->local_host = localhost_options[0];
          options->public_host = localhost_options[0];
          TRC_INFO("Override private and public local host names %s",
                   options->local_host.c_str());
        }
        else if (localhost_options.size() == 2)
        {
          options->local_host = localhost_options[0];
          options->public_host = localhost_options[1];
          TRC_INFO("Override private local host name to %s",
                  options->local_host.c_str());
          TRC_INFO("Override public local host name to %s",
                  options->public_host.c_str());
        }
        else
        {
          TRC_WARNING("Invalid --local-host option, ignored");
        }
      }
      break;

    case 'D':
      options->home_domain = std::string(pj_optarg);
      TRC_INFO("Home domain set to %s", pj_optarg);
      break;

    case OPT_ADDITIONAL_HOME_DOMAINS:
      options->additional_home_domains = std::string(pj_optarg);
      TRC_INFO("Additional home domains set to %s", pj_optarg);
      break;

    case 'c':
      options->scscf_uri = std::string(pj_optarg);
      TRC_INFO("Sprout cluster URI set to %s", pj_optarg);
      break;

    case 'n':
      options->alias_hosts = std::string(pj_optarg);
      TRC_INFO("Alias host names = %s", pj_optarg);
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
        TRC_INFO("Upstream proxy is set to %s:%d", options->upstream_proxy.c_str(), options->upstream_proxy_port);
        TRC_INFO("  connections = %d", options->upstream_proxy_connections);
        TRC_INFO("  recycle time = %d seconds", options->upstream_proxy_recycle);
      }
      break;

    case 'I':
      options->ibcf = PJ_TRUE;
      options->trusted_hosts = std::string(pj_optarg);
      TRC_INFO("IBCF mode enabled, trusted hosts = %s", pj_optarg);
      break;

    case 'j':
      options->external_icscf_uri = std::string(pj_optarg);
      TRC_INFO("External I-CSCF URI = %s", pj_optarg);
      break;

    case 'R':
      options->auth_realm = std::string(pj_optarg);
      TRC_INFO("Authentication realm %s", pj_optarg);
      break;

    case 'S':
      {
        std::vector<std::string> sas_options;
        Utils::split_string(std::string(pj_optarg), ',', sas_options, 0, false);
        if (sas_options.size() == 2)
        {
          options->sas_server = sas_options[0];
          options->sas_system_name = sas_options[1];
          TRC_INFO("SAS set to %s", options->sas_server.c_str());
          TRC_INFO("System name is set to %s", options->sas_system_name.c_str());
        }
        else
        {
          CL_SPROUT_INVALID_SAS_OPTION.log();
          TRC_WARNING("Invalid --sas option, SAS disabled");
        }
      }
      break;

    case 'H':
      options->hss_server = std::string(pj_optarg);
      TRC_INFO("HSS server set to %s", pj_optarg);
      break;

    case 'X':
      options->xdm_server = std::string(pj_optarg);
      TRC_INFO("XDM server set to %s", pj_optarg);
      break;

    case 'K':
      options->chronos_service = std::string(pj_optarg);
      TRC_INFO("Chronos service set to %s", pj_optarg);
      break;

    case 'G':
      options->ralf_server = std::string(pj_optarg);
      fprintf(stdout, "Ralf server set to %s\n", pj_optarg);
      break;

    case OPT_RALF_THREADS:
      options->ralf_threads = atoi(pj_optarg);
      TRC_INFO("Number of ralf threads set to %d",
               options->ralf_threads);
      break;

    case 'E':
      options->enum_servers.clear();
      Utils::split_string(std::string(pj_optarg), ',', options->enum_servers, 0, false);
      TRC_INFO("%d ENUM servers passed on the command line",
               options->enum_servers.size());
      break;

    case 'x':
      options->enum_suffix = std::string(pj_optarg);
      TRC_INFO("ENUM suffix set to %s", pj_optarg);
      break;

    case 'f':
      options->enum_file = std::string(pj_optarg);
      TRC_INFO("ENUM file set to %s", pj_optarg);
      break;

    case 'u':
      URIClassifier::enforce_user_phone = true;
      TRC_INFO("ENUM lookups are only done on SIP URIs if they contain user=phone");
      break;

    case 'g':
      URIClassifier::enforce_global = true;
      TRC_INFO("ENUM lookups are only done on URIs if they contain a global number");
      break;

    case 'e':
      reg_max_expires = atoi(pj_optarg);

      if (reg_max_expires > 0)
      {
        options->reg_max_expires = reg_max_expires;
        TRC_INFO("Maximum registration period set to %d seconds\n",
                 options->reg_max_expires);
      }
      else
      {
        // The parameter could be invalid either because it's -ve, or it's not
        // an integer (in which case atoi returns 0). Log, but don't store it.
        TRC_WARNING("Invalid value for reg_max_expires: '%s'. "
                    "The default value of %d will be used.",
                    pj_optarg, options->reg_max_expires);
      }
      break;

    case OPT_SUB_MAX_EXPIRES:
      sub_max_expires = atoi(pj_optarg);

      if (sub_max_expires > 0)
      {
        options->sub_max_expires = sub_max_expires;
        TRC_INFO("Maximum registration period set to %d seconds\n",
                 options->sub_max_expires);
      }
      else
      {
        // The parameter could be invalid either because it's -ve, or it's not
        // an integer (in which case atoi returns 0). Log, but don't store it.
        TRC_WARNING("Invalid value for sub_max_expires: '%s'. "
                    "The default value of %d will be used.",
                    pj_optarg, options->sub_max_expires);
      }
      break;

    case OPT_TARGET_LATENCY_US:
      options->target_latency_us = atoi(pj_optarg);
      if (options->target_latency_us <= 0)
      {
        TRC_ERROR("Invalid --target-latency-us option %s", pj_optarg);
        return -1;
      }
      break;

    case OPT_CASS_TARGET_LATENCY_US:
      options->cass_target_latency_us = atoi(pj_optarg);
      if (options->cass_target_latency_us <= 0)
      {
        TRC_ERROR("Invalid --cass-target-latency-us option %s", pj_optarg);
        return -1;
      }
      break;

    case OPT_MAX_TOKENS:
      options->max_tokens = atoi(pj_optarg);
      if (options->max_tokens <= 0)
      {
        TRC_ERROR("Invalid --max-tokens option %s", pj_optarg);
        return -1;
      }
      break;

    case OPT_INIT_TOKEN_RATE:
      options->init_token_rate = atoi(pj_optarg);
      if (options->init_token_rate <= 0)
      {
        TRC_ERROR("Invalid --init-token-rate option %s", pj_optarg);
        return -1;
      }
      break;

    case OPT_MIN_TOKEN_RATE:
      options->min_token_rate = atoi(pj_optarg);
      if (options->min_token_rate <= 0)
      {
        TRC_ERROR("Invalid --min-token-rate option %s", pj_optarg);
        return -1;
      }
      break;

    case OPT_MEMCACHED_WRITE_FORMAT:
      if (strcmp(pj_optarg, "binary") == 0)
      {
        TRC_INFO("Memcached write format set to 'binary'");
        options->memcached_write_format = MemcachedWriteFormat::BINARY;
      }
      else if (strcmp(pj_optarg, "json") == 0)
      {
        TRC_INFO("Memcached write format set to 'json'");
        options->memcached_write_format = MemcachedWriteFormat::JSON;
      }
      else
      {
        TRC_WARNING("Invalid value for memcached-write-format, using '%s'."
                    "Got '%s', valid vales are 'json' and 'binary'",
                    ((options->memcached_write_format == MemcachedWriteFormat::JSON) ?
                     "json" : "binary"),
                    pj_optarg);
      }
      break;

    case 'P':
      options->pjsip_threads = atoi(pj_optarg);
      TRC_INFO("Use %d PJSIP threads", options->pjsip_threads);
      break;

    case 'W':
      options->worker_threads = atoi(pj_optarg);
      TRC_INFO("Use %d worker threads", options->worker_threads);
      break;

    case 'a':
      options->analytics_enabled = PJ_TRUE;
      options->analytics_directory = std::string(pj_optarg);
      TRC_INFO("Analytics directory set to %s", pj_optarg);
      break;

    case 'A':
      options->auth_enabled = PJ_TRUE;
      TRC_INFO("Authentication enabled");
      break;

    case 'T':
      options->http_address = std::string(pj_optarg);
      TRC_INFO("HTTP address set to %s", pj_optarg);
      break;

    case 'o':
      options->http_port = parse_port(std::string(pj_optarg));
      if (options->http_port != 0)
      {
        TRC_INFO("HTTP port set to %d", options->http_port);
      }
      else
      {
        TRC_ERROR("HTTP port %s is invalid", pj_optarg);
        return -1;
      }
      break;

    case 'q':
      options->http_threads = atoi(pj_optarg);
      TRC_INFO("Use %d HTTP threads", options->http_threads);
      break;

    case 'B':
      options->billing_cdf = std::string(pj_optarg);
      TRC_INFO("Use %s as billing cdf server", options->billing_cdf.c_str());
      break;

    case 'L':
    case 'F':
    case 'd':
    case 't':
      // Ignore L, F, d and t - these are handled by init_logging_options
      break;

    case OPT_DEFAULT_SESSION_EXPIRES:
      options->default_session_expires = atoi(pj_optarg);
      TRC_INFO("Default session expiry set to %d",
               options->default_session_expires);
      break;

    case OPT_MAX_SESSION_EXPIRES:
      options->max_session_expires = atoi(pj_optarg);
      TRC_INFO("Max session expiry set to %d",
               options->max_session_expires);
      break;

    case OPT_EMERGENCY_REG_ACCEPTED:
      options->emerg_reg_accepted = PJ_TRUE;
      TRC_INFO("Emergency registrations accepted");
      break;

    case OPT_MAX_CALL_LIST_LENGTH:
      options->max_call_list_length = atoi(pj_optarg);
      TRC_INFO("Max call list length set to %d",
               options->max_call_list_length);
      break;

    case OPT_MEMENTO_THREADS:
      options->memento_threads = atoi(pj_optarg);
      TRC_INFO("Number of memento threads set to %d",
               options->memento_threads);
      break;

    case OPT_CALL_LIST_TTL:
      options->call_list_ttl = atoi(pj_optarg);
      TRC_INFO("Call list TTL set to %d",
               options->call_list_ttl);
      break;

    case OPT_DNS_SERVER:
      options->dns_servers.clear();
      Utils::split_string(std::string(pj_optarg), ',', options->dns_servers, 0, false);
      TRC_INFO("%d DNS servers passed on the command line",
               options->dns_servers.size());
    break;

    case OPT_OVERRIDE_NPDI:
      options->override_npdi = true;
      TRC_INFO("Number portability lookups will be done on URIs containing the 'npdi' indicator");
      break;

    case OPT_EXCEPTION_MAX_TTL:
      options->exception_max_ttl = atoi(pj_optarg);
      TRC_INFO("Max TTL after an exception set to %d",
               options->exception_max_ttl);
      break;

    case OPT_SIP_BLACKLIST_DURATION:
      options->sip_blacklist_duration = atoi(pj_optarg);
      TRC_INFO("SIP blacklist duration set to %d",
               options->sip_blacklist_duration);
      break;

    case OPT_HTTP_BLACKLIST_DURATION:
      options->http_blacklist_duration = atoi(pj_optarg);
      TRC_INFO("HTTP blacklist duration set to %d",
               options->http_blacklist_duration);
      break;

    case OPT_SIP_TCP_CONNECT_TIMEOUT:
      options->sip_tcp_connect_timeout = atoi(pj_optarg);
      TRC_INFO("SIP TCP connect timeout set to %d",
               options->sip_tcp_connect_timeout);
      break;

    case OPT_SIP_TCP_SEND_TIMEOUT:
      options->sip_tcp_send_timeout = atoi(pj_optarg);
      TRC_INFO("SIP TCP send timeout set to %d",
               options->sip_tcp_send_timeout);
      break;

    case OPT_SESSION_CONTINUED_TIMEOUT_MS:
      options->session_continued_timeout_ms = atoi(pj_optarg);
      TRC_INFO("Session continue timeout set to %dms",
               options->session_continued_timeout_ms);
      break;

    case OPT_SESSION_TERMINATED_TIMEOUT_MS:
      options->session_terminated_timeout_ms = atoi(pj_optarg);
      TRC_INFO("Session terminated timeout set to %dms",
               options->session_terminated_timeout_ms);
      break;

    case OPT_STATELESS_PROXIES:
      {
        std::vector<std::string> stateless_proxies;
        Utils::split_string(std::string(pj_optarg), ',', stateless_proxies, 0, false);
        options->stateless_proxies.insert(stateless_proxies.begin(),
                                          stateless_proxies.end());
        TRC_INFO("%d stateless proxies are configured",
                 options->stateless_proxies.size());
      }
      break;

    case OPT_NON_REGISTERING_PBXES:
      {
        options->pbxes = std::string(pj_optarg);
        TRC_INFO("Non-registering PBX IP addresses are %s",
                 options->pbxes.c_str());
      }
      break;

    case OPT_PBX_SERVICE_ROUTE:
      {
        options->pbx_service_route = std::string(pj_optarg);
        TRC_INFO("PBX service route is: %s",
                 options->pbx_service_route.c_str());
      }
      break;

    case OPT_NON_REGISTER_AUTHENTICATION:
      {
        std::string this_arg = pj_optarg;

        if (this_arg == "never")
        {
          TRC_INFO("Non-REGISTER authentication set to 'never'");
          options->non_register_auth_mode = NonRegisterAuthentication::NEVER;
        }
        else if (this_arg == "if_proxy_authorization_present")
        {
          TRC_INFO("Non-REGISTER authentication set to 'if_proxy_authorization_present'");
          options->non_register_auth_mode =
            NonRegisterAuthentication::IF_PROXY_AUTHORIZATION_PRESENT;
        }
        else
        {
          TRC_ERROR("Invalid value for non-REGISTER authentication: %s", pj_optarg);
          return -1;
        }
      }
      break;

    case OPT_FORCE_THIRD_PARTY_REGISTER_BODY:
      {
        TRC_INFO("Forcing inclusion of original REGISTER requests/responses on third-party REGISTERs");
        options->force_third_party_register_body = true;
      }
      break;


    case 'h':
      usage();
      return -1;

    default:
      TRC_ERROR("Unknown option. Run with --help for help.");
      return -1;
    }
  }

  return PJ_SUCCESS;
}


int daemonize()
{
  TRC_STATUS("Switching to daemon mode");

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
  TRC_BACKTRACE("Signal %d caught", sig);

  // Ensure the log files are complete - the core file created by abort() below
  // will trigger the log files to be copied to the diags bundle
  TRC_COMMIT();

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
    TRC_STATUS("Quiesce signal received");
    quiescing = PJ_TRUE;
  }
  else
  {
    TRC_STATUS("Unquiesce signal received");
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
    TRC_ERROR("Error creating quiesce/unquiesce thread (status = %d). "
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
    TRC_STATUS("Value of new_quiescing is %s", (new_quiescing == PJ_FALSE) ? "false" : "true");
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
      TRC_ERROR("Failed to register thread with pjsip");
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
Store* local_data_store = NULL;
RegStore* local_reg_store = NULL;
RalfProcessor* ralf_processor = NULL;
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
  AvStore* av_store = NULL;
  HttpConnection* ralf_connection = NULL;
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
  CommunicationMonitor* ralf_comm_monitor = NULL;

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
  opt.sip_tcp_send_timeout = 2000;
  opt.session_continued_timeout_ms = SCSCFSproutlet::DEFAULT_SESSION_CONTINUED_TIMEOUT;
  opt.session_terminated_timeout_ms = SCSCFSproutlet::DEFAULT_SESSION_TERMINATED_TIMEOUT;
  opt.stateless_proxies.clear();
  opt.ralf_threads = 25;
  opt.non_register_auth_mode = NonRegisterAuthentication::NEVER;
  opt.force_third_party_register_body = false;

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
    TRC_ERROR("Cannot specify both --daemon and --interactive");
    return 1;
  }

  if (opt.daemon)
  {
    int errnum = daemonize();
    if (errnum != 0)
    {
      closelog();
      TRC_ERROR("Failed to convert to daemon, %d (%s)", errnum, strerror(errnum));
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

    TRC_STATUS("Access logging enabled to %s", opt.log_directory.c_str());
    access_logger = new AccessLogger(opt.log_directory);
  }

  TRC_STATUS("Log level set to %d", opt.log_level);

  std::stringstream options_ss;
  for (int ii = 0; ii < argc; ii++)
  {
    options_ss << argv[ii];
    options_ss << " ";
  }
  std::string options = "Command-line options were: " + options_ss.str();

  TRC_INFO(options.c_str());

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
    TRC_ERROR("Must enable P-CSCF, S-CSCF or I-CSCF");
    return 1;
  }

  if ((opt.pcscf_enabled) && ((opt.scscf_enabled) || (opt.icscf_enabled)))
  {
    closelog();
    TRC_ERROR("Cannot enable both P-CSCF and S/I-CSCF");
    return 1;
  }

  if ((opt.pcscf_enabled) &&
      (opt.upstream_proxy == ""))
  {
    closelog();
    TRC_ERROR("Cannot enable P-CSCF without specifying --routing-proxy");
    return 1;
  }

  if ((opt.ibcf) && (!opt.pcscf_enabled))
  {
    closelog();
    TRC_ERROR("Cannot enable IBCF without also enabling P-CSCF");
    return 1;
  }

  if ((opt.webrtc_port != 0 ) && (!opt.pcscf_enabled))
  {
    closelog();
    TRC_ERROR("Cannot enable WebRTC without also enabling P-CSCF");
    return 1;
  }

  if ((opt.scscf_enabled) && (opt.scscf_uri == ""))
  {
    TRC_ERROR("S-CSCF enabled, but no S-CSCF URI specified");
    return 1;
  }

  if (((opt.scscf_enabled) || (opt.icscf_enabled)) &&
      (opt.hss_server == ""))
  {
    CL_SPROUT_SI_CSCF_NO_HOMESTEAD.log();
    closelog();
    TRC_ERROR("S/I-CSCF enabled with no Homestead server");
    return 1;
  }

  if ((opt.auth_enabled) && (opt.hss_server == ""))
  {
    CL_SPROUT_AUTH_NO_HOMESTEAD.log();
    closelog();
    TRC_ERROR("Authentication enabled, but no Homestead server specified");
    return 1;
  }

  if ((opt.xdm_server != "") && (opt.hss_server == ""))
  {
    CL_SPROUT_XDM_NO_HOMESTEAD.log();
    closelog();
    TRC_ERROR("XDM server configured for services, but no Homestead server specified");
    return 1;
  }

  if ((opt.pcscf_enabled) && (opt.hss_server != ""))
  {
    TRC_WARNING("Homestead server configured on P-CSCF, ignoring");
  }

  if ((opt.pcscf_enabled) && (opt.xdm_server != ""))
  {
    TRC_WARNING("XDM server configured on P-CSCF, ignoring");
  }

  if ((opt.auth_enabled) &&
      (opt.worker_threads == 1))
  {
    TRC_WARNING("Use multiple threads for good performance when using memstore and/or authentication");
  }

  if ((opt.pcscf_enabled) && (opt.reg_max_expires != 0))
  {
    TRC_WARNING("A registration expiry period should not be specified for P-CSCF");
  }

  if ((!opt.enum_servers.empty()) &&
      (!opt.enum_file.empty()))
  {
    TRC_WARNING("Both ENUM server and ENUM file lookup enabled - ignoring ENUM file");
  }

  // Ensure our random numbers are unpredictable.
  unsigned int seed;
  pj_time_val now;
  pj_gettimeofday(&now);
  seed = (unsigned int)now.sec ^ (unsigned int)now.msec ^ getpid();
  srand(seed);

  if (opt.pcscf_enabled)
  {
    snmp_setup("bono");
  }
  else
  {
    snmp_setup("sprout");
  }

  SNMP::EventAccumulatorTable* latency_table;
  SNMP::EventAccumulatorTable* queue_size_table;
  SNMP::CounterTable* requests_counter;
  SNMP::CounterTable* overload_counter;

  SNMP::IPCountTable* homestead_cxn_count = NULL;

  SNMP::EventAccumulatorTable* homestead_latency_table = NULL;
  SNMP::EventAccumulatorTable* homestead_mar_latency_table = NULL;
  SNMP::EventAccumulatorTable* homestead_sar_latency_table = NULL;
  SNMP::EventAccumulatorTable* homestead_uar_latency_table = NULL;
  SNMP::EventAccumulatorTable* homestead_lir_latency_table = NULL;

  SNMP::ContinuousAccumulatorTable* token_rate_table = NULL;
  SNMP::U32Scalar* smoothed_latency_scalar = NULL;
  SNMP::U32Scalar* target_latency_scalar = NULL;
  SNMP::U32Scalar* penalties_scalar = NULL;
  SNMP::U32Scalar* token_rate_scalar = NULL;

  SNMP::RegistrationStatsTables reg_stats_tbls;
  SNMP::RegistrationStatsTables third_party_reg_stats_tbls;
  SNMP::AuthenticationStatsTables auth_stats_tbls;

  if (opt.pcscf_enabled)
  {
    latency_table = SNMP::EventAccumulatorTable::create("bono_latency",
                                                   ".1.2.826.0.1.1578918.9.2.2");
    queue_size_table = SNMP::EventAccumulatorTable::create("bono_queue_size",
                                                      ".1.2.826.0.1.1578918.9.2.6");
    requests_counter = SNMP::CounterTable::create("bono_incoming_requests",
                                                  ".1.2.826.0.1.1578918.9.2.4");
    overload_counter = SNMP::CounterTable::create("bono_rejected_overload",
                                                  ".1.2.826.0.1.1578918.9.2.5");
  }
  else
  {
    latency_table = SNMP::EventAccumulatorTable::create("sprout_latency",
                                                   ".1.2.826.0.1.1578918.9.3.1");
    queue_size_table = SNMP::EventAccumulatorTable::create("sprout_queue_size",
                                                      ".1.2.826.0.1.1578918.9.3.8");
    requests_counter = SNMP::CounterTable::create("sprout_incoming_requests",
                                                  ".1.2.826.0.1.1578918.9.3.6");
    overload_counter = SNMP::CounterTable::create("sprout_rejected_overload",
                                                  ".1.2.826.0.1.1578918.9.3.7");

    homestead_cxn_count = SNMP::IPCountTable::create("sprout_homestead_cxn_count",
                                                     ".1.2.826.0.1.1578918.9.3.3.1");
    homestead_latency_table = SNMP::EventAccumulatorTable::create("sprout_homestead_latency",
                                                             ".1.2.826.0.1.1578918.9.3.3.2");
    homestead_mar_latency_table = SNMP::EventAccumulatorTable::create("sprout_homestead_mar_latency",
                                                                 ".1.2.826.0.1.1578918.9.3.3.3");
    homestead_sar_latency_table = SNMP::EventAccumulatorTable::create("sprout_homestead_sar_latency",
                                                                 ".1.2.826.0.1.1578918.9.3.3.4");
    homestead_uar_latency_table = SNMP::EventAccumulatorTable::create("sprout_homestead_uar_latency",
                                                                 ".1.2.826.0.1.1578918.9.3.3.5");
    homestead_lir_latency_table = SNMP::EventAccumulatorTable::create("sprout_homestead_lir_latency",
                                                                 ".1.2.826.0.1.1578918.9.3.3.6");

    reg_stats_tbls.init_reg_tbl = SNMP::SuccessFailCountTable::create("initial_reg_success_fail_count",
                                                                      ".1.2.826.0.1.1578918.9.3.9");
    reg_stats_tbls.re_reg_tbl = SNMP::SuccessFailCountTable::create("re_reg_success_fail_count",
                                                                    ".1.2.826.0.1.1578918.9.3.10");
    reg_stats_tbls.de_reg_tbl = SNMP::SuccessFailCountTable::create("de_reg_success_fail_count",
                                                                     ".1.2.826.0.1.1578918.9.3.11");

    third_party_reg_stats_tbls.init_reg_tbl = SNMP::SuccessFailCountTable::create("third_party_initial_reg_success_fail_count",
                                                                                  ".1.2.826.0.1.1578918.9.3.12");
    third_party_reg_stats_tbls.re_reg_tbl = SNMP::SuccessFailCountTable::create("third_party_re_reg_success_fail_count",
                                                                                ".1.2.826.0.1.1578918.9.3.13");
    third_party_reg_stats_tbls.de_reg_tbl = SNMP::SuccessFailCountTable::create("third_party_de_reg_success_fail_count",
                                                                                ".1.2.826.0.1.1578918.9.3.14");

    auth_stats_tbls.sip_digest_auth_tbl = SNMP::SuccessFailCountTable::create("sip_digest_auth_success_fail_count",
                                                                              ".1.2.826.0.1.1578918.9.3.15");
    auth_stats_tbls.ims_aka_auth_tbl = SNMP::SuccessFailCountTable::create("ims_aka_auth_success_fail_count",
                                                                           ".1.2.826.0.1.1578918.9.3.16");

    auth_stats_tbls.non_register_auth_tbl = SNMP::SuccessFailCountTable::create("non_register_auth_success_fail_count",
                                                                                ".1.2.826.0.1.1578918.9.3.17");

    token_rate_table = SNMP::ContinuousAccumulatorTable::create("sprout_token_rate",
                                                      ".1.2.826.0.1.1578918.9.3.27");
    smoothed_latency_scalar = new SNMP::U32Scalar("sprout_smoothed_latency",
                                                      ".1.2.826.0.1.1578918.9.3.28");
    target_latency_scalar = new SNMP::U32Scalar("sprout_target_latency",
                                                      ".1.2.826.0.1.1578918.9.3.29");
    penalties_scalar = new SNMP::U32Scalar("sprout_penalties",
                                                      ".1.2.826.0.1.1578918.9.3.30");
    token_rate_scalar = new SNMP::U32Scalar("sprout_current_token_rate",
                                                      ".1.2.826.0.1.1578918.9.3.31");
  }

  if (opt.icscf_enabled || opt.scscf_enabled)
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

    ralf_comm_monitor = new CommunicationMonitor(new Alarm("sprout", AlarmDef::SPROUT_RALF_COMM_ERROR,
                                                                     AlarmDef::MAJOR));

    // Start the alarm request agent
    AlarmReqAgent::get_instance().start();
    AlarmState::clear_all("sprout");
  }

  // Start the load monitor
  load_monitor = new LoadMonitor(opt.target_latency_us,   // Initial target latency (us).
                                 opt.max_tokens,          // Maximum token bucket size.
                                 opt.init_token_rate,     // Initial token fill rate (per sec).
                                 opt.min_token_rate,      // Minimum token fill rate (per sec).
                                 token_rate_table,        // Statistics table for token rate.
                                 smoothed_latency_scalar, // Statistics scalar for current latency.
                                 target_latency_scalar,   // Statistics scalar for target latency.
                                 penalties_scalar,        // Statistics scalar for number of penalties.
                                 token_rate_scalar);      // Statistics scalar for current token rate.

  // Start the health checker
  HealthChecker* hc = new HealthChecker();
  hc->start_thread();

  // Create an exception handler. The exception handler should attempt to
  // quiesce the process before killing it.
  exception_handler = new ExceptionHandler(opt.exception_max_ttl,
                                           true,
                                           hc);

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
                      opt.sip_tcp_send_timeout,
                      quiescing_mgr,
                      opt.billing_cdf);

  if (status != PJ_SUCCESS)
  {
    CL_SPROUT_SIP_INIT_INTERFACE_FAIL.log(PJUtils::pj_status_to_string(status).c_str());
    TRC_ERROR("Error initializing stack %s", PJUtils::pj_status_to_string(status).c_str());
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
                                         NULL, // No SNMP table for connected Ralfs
                                         load_monitor,
                                         SASEvent::HttpLogLevel::PROTOCOL,
                                         ralf_comm_monitor);
    ralf_processor = new RalfProcessor(ralf_connection,
                                       exception_handler,
                                       opt.ralf_threads);
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
    TRC_STATUS("Creating connection to HSS %s", opt.hss_server.c_str());
    hss_connection = new HSSConnection(opt.hss_server,
                                       http_resolver,
                                       load_monitor,
                                       homestead_cxn_count,
                                       homestead_latency_table,
                                       homestead_mar_latency_table,
                                       homestead_sar_latency_table,
                                       homestead_uar_latency_table,
                                       homestead_lir_latency_table,
                                       hss_comm_monitor);
  }

  if ((opt.scscf_enabled) || (opt.icscf_enabled))
  {
    // Create ENUM service required for I/S-CSCF.
    if (!opt.enum_servers.empty())
    {
      TRC_STATUS("Setting up the ENUM server(s)");
      enum_service = new DNSEnumService(opt.enum_servers,
                                        opt.enum_suffix,
                                        new DNSResolverFactory(),
                                        enum_comm_monitor);
    }
    else if (!opt.enum_file.empty())
    {
      TRC_STATUS("Reading from an ENUM file");
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
    TRC_STATUS("Creating connection to Chronos %s using %s as the callback URI",
               opt.chronos_service.c_str(),
               chronos_callback_host.c_str());
    chronos_connection = new ChronosConnection(opt.chronos_service,
                                               chronos_callback_host,
                                               http_resolver,
                                               chronos_comm_monitor);
  }

  HttpStack* http_stack = HttpStack::get_instance();
  if (opt.pcscf_enabled)
  {
    // Create an ACR factory for the P-CSCF.
    pcscf_acr_factory = (ralf_processor != NULL) ?
                (ACRFactory*)new RalfACRFactory(ralf_processor, PCSCF) :
                new ACRFactory();

    // Launch stateful proxy as P-CSCF.
    status = init_stateful_proxy(NULL,
                                 true,
                                 opt.upstream_proxy,
                                 opt.upstream_proxy_port,
                                 opt.upstream_proxy_connections,
                                 opt.upstream_proxy_recycle,
                                 opt.ibcf,
                                 opt.trusted_hosts,
                                 opt.pbxes,
                                 opt.pbx_service_route,
                                 analytics_logger,
                                 NULL,
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
      TRC_ERROR("Failed to enable P-CSCF edge proxy");
      return 1;
    }

    pj_bool_t websockets_enabled = (opt.webrtc_port != 0);
    if (websockets_enabled)
    {
      status = init_websockets((unsigned short)opt.webrtc_port);
      if (status != PJ_SUCCESS)
      {
        TRC_ERROR("Error initializing websockets, %s",
                  PJUtils::pj_status_to_string(status).c_str());

        return 1;
      }
    }
  }

  if (opt.scscf_enabled)
  {
    scscf_acr_factory = (ralf_processor != NULL) ?
                      (ACRFactory*)new RalfACRFactory(ralf_processor, SCSCF) :
                      new ACRFactory();

    // Use memcached store.
    TRC_STATUS("Using memcached compatible store");

    local_data_store = (Store*)new MemcachedStore(memcached_comm_monitor);

    if (local_data_store == NULL)
    {
      CL_SPROUT_MEMCACHE_CONN_FAIL.log();
      closelog();
      TRC_ERROR("Failed to connect to data store");
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

    // Start the HTTP stack early as plugins might need to register handlers
    // with it.
    try
    {
      http_stack->initialize();
      http_stack->configure(opt.http_address,
                            opt.http_port,
                            opt.http_threads,
                            exception_handler,
                            access_logger);
    }
    catch (HttpStack::Exception& e)
    {
      CL_SPROUT_HTTP_INTERFACE_FAIL.log(e._func, e._rc);
      closelog();
      TRC_ERROR("Caught HttpStack::Exception - %s - %d\n", e._func, e._rc);
      return 1;
    }

    if (opt.auth_enabled)
    {
      // Create an AV store using the local store and initialise the authentication
      // module.  We don't create a AV store using the remote data store as
      // Authentication Vectors are only stored for a short period after the
      // relevant challenge is sent.
      TRC_STATUS("Initialise S-CSCF authentication module");
      av_store = new AvStore(local_data_store);
      status = init_authentication(opt.auth_realm,
                                   av_store,
                                   hss_connection,
                                   chronos_connection,
                                   scscf_acr_factory,
                                   opt.non_register_auth_mode,
                                   analytics_logger,
                                   &auth_stats_tbls);
    }

    // Launch the registrar.
    status = init_registrar(local_reg_store,
                            hss_connection,
                            analytics_logger,
                            scscf_acr_factory,
                            opt.reg_max_expires,
                            opt.force_third_party_register_body,
                            &reg_stats_tbls,
                            &third_party_reg_stats_tbls);

    if (status != PJ_SUCCESS)
    {
      CL_SPROUT_INIT_SERVICE_ROUTE_FAIL.log(PJUtils::pj_status_to_string(status).c_str());
      closelog();
      TRC_ERROR("Failed to enable S-CSCF registrar");
      return 1;
    }

    // Launch the subscription module.
    status = init_subscription(local_reg_store,
                               hss_connection,
                               scscf_acr_factory,
                               analytics_logger,
                               opt.sub_max_expires);

    if (status != PJ_SUCCESS)
    {
      CL_SPROUT_REG_SUBSCRIBER_HAND_FAIL.log(PJUtils::pj_status_to_string(status).c_str());
      closelog();
      TRC_ERROR("Failed to enable subscription module");
      return 1;
    }
  }

  // Load the sproutlet plugins.
  PluginLoader* loader = new PluginLoader("/usr/share/clearwater/sprout/plugins", opt);

  if (!loader->load(sproutlets))
  {
    CL_SPROUT_PLUGIN_FAILURE.log();
    closelog();
    TRC_ERROR("Failed to successfully load plug-ins");
    return 1;
  }

  // Must happen after all SNMP tables have been registered.
  if (opt.pcscf_enabled)
  {
    init_snmp_handler_threads("bono");
  }
  else
  {
    init_snmp_handler_threads("sprout");
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
                                         sproutlets,
                                         opt.stateless_proxies);
    if (sproutlet_proxy == NULL)
    {
      CL_SPROUT_S_CSCF_INIT_FAIL.log();
      CL_SPROUT_BGCF_INIT_FAIL.log();
      CL_SPROUT_I_CSCF_INIT_FAIL.log();
      TRC_ERROR("Failed to create SproutletProxy");
      closelog();
      return 1;
    }
  }

  init_common_sip_processing(load_monitor,
                             requests_counter,
                             overload_counter,
                             hc);

  init_thread_dispatcher(opt.worker_threads,
                         latency_table,
                         queue_size_table,
                         load_monitor,
                         exception_handler);

  // Create worker threads first as they take work from the PJSIP threads so
  // need to be ready.

  status = start_worker_threads();
  if (status != PJ_SUCCESS)
  {
    TRC_ERROR("Error starting SIP worker threads, %s", PJUtils::pj_status_to_string(status).c_str());
    return 1;
  }

  status = start_pjsip_threads();
  if (status != PJ_SUCCESS)
  {
    CL_SPROUT_SIP_STACK_INIT_FAIL.log(PJUtils::pj_status_to_string(status).c_str());
    closelog();
    TRC_ERROR("Error starting SIP stack, %s", PJUtils::pj_status_to_string(status).c_str());
    return 1;
  }

  RegSubTimeoutTask::Config reg_sub_timeout_config(local_reg_store, hss_connection);
  AuthTimeoutTask::Config auth_timeout_config(av_store, hss_connection);
  DeregistrationTask::Config deregistration_config(local_reg_store, hss_connection, sip_resolver);

  // The RegSubTimeoutTask and AuthTimeoutTask both handle
  // chronos requests, so use the ChronosHandler.
  ChronosHandler<RegSubTimeoutTask, RegSubTimeoutTask::Config> reg_timeout_handler(&reg_sub_timeout_config);
  ChronosHandler<AuthTimeoutTask, AuthTimeoutTask::Config> auth_timeout_handler(&auth_timeout_config);
  HttpStackUtils::SpawningHandler<DeregistrationTask, DeregistrationTask::Config> deregistration_handler(&deregistration_config);
  HttpStackUtils::PingHandler ping_handler;

  if (opt.scscf_enabled)
  {
    try
    {
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
      TRC_ERROR("Caught HttpStack::Exception - %s - %d\n", e._func, e._rc);
      return 1;
    }
  }

  // Wait here until the quit semaphore is signaled.
  sem_wait(&term_sem);
  snmp_terminate("sprout");

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
      TRC_ERROR("Caught HttpStack::Exception - %s - %d\n", e._func, e._rc);
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
  delete av_store;
  delete local_data_store;
  delete ralf_processor;
  delete ralf_connection;
  delete enum_service;
  delete scscf_acr_factory;

  delete sip_resolver;
  delete http_resolver;
  delete dns_resolver;

  delete analytics_logger;
  delete analytics_logger_logger;

  if (opt.icscf_enabled || opt.scscf_enabled)
  {
    // Stop the alarm request agent
    AlarmReqAgent::get_instance().stop();

    // Delete Sprout's alarm objects
    delete chronos_comm_monitor;
    delete enum_comm_monitor;
    delete hss_comm_monitor;
    delete memcached_comm_monitor;
    delete ralf_comm_monitor;
  }

  delete latency_table;
  delete queue_size_table;
  delete requests_counter;
  delete overload_counter;

  delete homestead_cxn_count;

  delete homestead_latency_table;
  delete homestead_mar_latency_table;
  delete homestead_sar_latency_table;
  delete homestead_uar_latency_table;
  delete homestead_lir_latency_table;

  delete token_rate_table;
  delete smoothed_latency_scalar;
  delete target_latency_scalar;
  delete penalties_scalar;
  delete token_rate_scalar;

  if (!opt.pcscf_enabled)
  {
    delete reg_stats_tbls.init_reg_tbl;
    delete reg_stats_tbls.re_reg_tbl;
    delete reg_stats_tbls.de_reg_tbl;

    delete third_party_reg_stats_tbls.init_reg_tbl;
    delete third_party_reg_stats_tbls.re_reg_tbl;
    delete third_party_reg_stats_tbls.de_reg_tbl;

    delete auth_stats_tbls.sip_digest_auth_tbl;
    delete auth_stats_tbls.ims_aka_auth_tbl;
    delete auth_stats_tbls.non_register_auth_tbl;
  }
  hc->stop_thread();
  delete hc;

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
