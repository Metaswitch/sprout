/*,
 * @file main.cpp
 *
 * Copyright (C) Metaswitch Networks 2017
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

#include "logger.h"
#include "utils.h"
#include "cfgoptions.h"
#include "sasevent.h"
#include "analyticslogger.h"
#include "subscriber_data_manager.h"
#include "stack.h"
#include "bono.h"
#include "hssconnection.h"
#include "xdmconnection.h"
#include "bono.h"
#include "websockets.h"
#include "memcachedstore.h"
#include "mmtel.h"
#include "options.h"
#include "dnsresolver.h"
#include "astaire_resolver.h"
#include "enumservice.h"
#include "bgcfservice.h"
#include "pjutils.h"
#include "log.h"
#include "quiescing_manager.h"
#include "load_monitor.h"
#include "localstore.h"
#include "scscfselector.h"
#include "chronosconnection.h"
#include "chronoshandlers.h"
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
#include "snmp_continuous_accumulator_by_scope_table.h"
#include "snmp_event_accumulator_table.h"
#include "snmp_event_accumulator_by_scope_table.h"
#include "snmp_scalar.h"
#include "snmp_scalar_by_scope_table.h"
#include "snmp_counter_table.h"
#include "snmp_counter_by_scope_table.h"
#include "snmp_success_fail_count_table.h"
#include "snmp_agent.h"
#include "ralf_processor.h"
#include "sprout_alarmdefinition.h"
#include "sproutlet_options.h"
#include "astaire_impistore.h"

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
  OPT_OVERRIDE_NPDI,
  OPT_MAX_TOKENS,
  OPT_INIT_TOKEN_RATE,
  OPT_MIN_TOKEN_RATE,
  OPT_MAX_TOKEN_RATE,
  OPT_CASS_TARGET_LATENCY_US,
  OPT_EXCEPTION_MAX_TTL,
  OPT_MAX_SESSION_EXPIRES,
  OPT_SIP_BLACKLIST_DURATION,
  OPT_HTTP_BLACKLIST_DURATION,
  OPT_ASTAIRE_BLACKLIST_DURATION,
  OPT_SIP_TCP_CONNECT_TIMEOUT,
  OPT_SIP_TCP_SEND_TIMEOUT,
  OPT_DNS_TIMEOUT,
  OPT_SESSION_CONTINUED_TIMEOUT_MS,
  OPT_SESSION_TERMINATED_TIMEOUT_MS,
  OPT_STATELESS_PROXIES,
  OPT_MAX_SPROUTLET_DEPTH,
  OPT_RALF_THREADS,
  OPT_NON_REGISTERING_PBXES,
  OPT_PBX_SERVICE_ROUTE,
  OPT_NON_REGISTER_AUTHENTICATION,
  OPT_FORCE_THIRD_PARTY_REGISTER_BODY,
  OPT_MEMENTO_NOTIFY_URL,
  OPT_PIDFILE,
  OPT_SPROUT_HOSTNAME,
  OPT_LISTEN_PORT,
  SPROUTLET_MACRO(SPROUTLET_OPTION_TYPES)
  OPT_NONCE_COUNT_SUPPORTED,
  OPT_LOCAL_SITE_NAME,
  OPT_REGISTRATION_STORES,
  OPT_IMPI_STORES,
  OPT_SCSCF_NODE_URI,
  OPT_SAS_USE_SIGNALING_IF,
  OPT_DISABLE_TCP_SWITCH,
  OPT_DEFAULT_TEL_URI_TRANSLATION,
  OPT_CHRONOS_HOSTNAME,
  OPT_SPROUT_CHRONOS_CALLBACK_URI,
  OPT_APPLY_FALLBACK_IFCS,
  OPT_REJECT_IF_NO_MATCHING_IFCS,
  OPT_DUMMY_APP_SERVER,
  OPT_HTTP_ACR_LOGGING,
  OPT_HOMESTEAD_TIMEOUT,
  OPT_ORIG_SIP_TO_TEL_COERCE,
  OPT_REQUEST_ON_QUEUE_TIMEOUT,
  OPT_BLACKLISTED_SCSCFS
};


const static struct pj_getopt_option long_opt[] =
{
  { "pcscf",                        required_argument, 0, 'p'},
  { "webrtc-port",                  required_argument, 0, 'w'},
  { "localhost",                    required_argument, 0, 'l'},
  { "domain",                       required_argument, 0, 'D'},
  { "additional-domains",           required_argument, 0, OPT_ADDITIONAL_HOME_DOMAINS},
  { "alias",                        required_argument, 0, 'n'},
  { "routing-proxy",                required_argument, 0, 'r'},
  { "ibcf",                         required_argument, 0, 'I'},
  { "external-icscf",               required_argument, 0, 'j'},
  { "realm",                        required_argument, 0, 'R'},
  { "local-site-name",              required_argument, 0, OPT_LOCAL_SITE_NAME},
  { "registration-stores",          required_argument, 0, OPT_REGISTRATION_STORES},
  { "impi-store",                   required_argument, 0, OPT_IMPI_STORES},
  { "sas",                          required_argument, 0, 'S'},
  { "hss",                          required_argument, 0, 'H'},
  { "record-routing-model",         required_argument, 0, 'C'},
  { "default-session-expires",      required_argument, 0, OPT_DEFAULT_SESSION_EXPIRES},
  { "max-session-expires",          required_argument, 0, OPT_MAX_SESSION_EXPIRES},
  { "target-latency-us",            required_argument, 0, OPT_TARGET_LATENCY_US},
  { "xdms",                         required_argument, 0, 'X'},
  { "ralf",                         required_argument, 0, 'G'},
  { "dns-server",                   required_argument, 0, OPT_DNS_SERVER },
  { "enum",                         required_argument, 0, 'E'},
  { "enum-suffix",                  required_argument, 0, 'x'},
  { "enum-file",                    required_argument, 0, 'f'},
  { "default-tel-uri-translation",  no_argument,       0, OPT_DEFAULT_TEL_URI_TRANSLATION},
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
  { "memento-notify-url",           required_argument, 0, OPT_MEMENTO_NOTIFY_URL},
  { "log-level",                    required_argument, 0, 'L'},
  { "daemon",                       no_argument,       0, 'd'},
  { "interactive",                  no_argument,       0, 't'},
  { "help",                         no_argument,       0, 'h'},
  { "override-npdi",                no_argument,       0, OPT_OVERRIDE_NPDI},
  { "max-tokens",                   required_argument, 0, OPT_MAX_TOKENS},
  { "init-token-rate",              required_argument, 0, OPT_INIT_TOKEN_RATE},
  { "min-token-rate",               required_argument, 0, OPT_MIN_TOKEN_RATE},
  { "max-token-rate",               required_argument, 0, OPT_MAX_TOKEN_RATE},
  { "cass-target-latency-us",       required_argument, 0, OPT_CASS_TARGET_LATENCY_US},
  { "exception-max-ttl",            required_argument, 0, OPT_EXCEPTION_MAX_TTL},
  { "sip-blacklist-duration",       required_argument, 0, OPT_SIP_BLACKLIST_DURATION},
  { "http-blacklist-duration",      required_argument, 0, OPT_HTTP_BLACKLIST_DURATION},
  { "astaire-blacklist-duration",   required_argument, 0, OPT_ASTAIRE_BLACKLIST_DURATION},
  { "sip-tcp-connect-timeout",      required_argument, 0, OPT_SIP_TCP_CONNECT_TIMEOUT},
  { "sip-tcp-send-timeout",         required_argument, 0, OPT_SIP_TCP_SEND_TIMEOUT},
  { "dns-timeout",                  required_argument, 0, OPT_DNS_TIMEOUT},
  { "session-continued-timeout",    required_argument, 0, OPT_SESSION_CONTINUED_TIMEOUT_MS},
  { "session-terminated-timeout",   required_argument, 0, OPT_SESSION_TERMINATED_TIMEOUT_MS},
  { "stateless-proxies",            required_argument, 0, OPT_STATELESS_PROXIES},
  { "non-registering-pbxes",        required_argument, 0, OPT_NON_REGISTERING_PBXES},
  { "ralf-threads",                 required_argument, 0, OPT_RALF_THREADS},
  { "non-register-authentication",  required_argument, 0, OPT_NON_REGISTER_AUTHENTICATION},
  { "pbx-service-route",            required_argument, 0, OPT_PBX_SERVICE_ROUTE},
  { "force-3pr-body",               no_argument,       0, OPT_FORCE_THIRD_PARTY_REGISTER_BODY},
  { "pidfile",                      required_argument, 0, OPT_PIDFILE},
  { "plugin-option",                required_argument, 0, 'N'},
  { "sprout-hostname",              required_argument, 0, OPT_SPROUT_HOSTNAME},
  { "listen-port",                  required_argument, 0, OPT_LISTEN_PORT},
  SPROUTLET_MACRO(SPROUTLET_CFG_PJ_STRUCT)
  { "nonce-count-supported",        no_argument,       0, OPT_NONCE_COUNT_SUPPORTED},
  { "scscf-node-uri",               required_argument, 0, OPT_SCSCF_NODE_URI},
  { "sas-use-signaling-interface",  no_argument,       0, OPT_SAS_USE_SIGNALING_IF},
  { "disable-tcp-switch",           no_argument,       0, OPT_DISABLE_TCP_SWITCH},
  { "chronos-hostname",             required_argument, 0, OPT_CHRONOS_HOSTNAME},
  { "sprout-chronos-callback-uri",  required_argument, 0, OPT_SPROUT_CHRONOS_CALLBACK_URI},
  { "apply-fallback-ifcs",          no_argument,       0, OPT_APPLY_FALLBACK_IFCS},
  { "reject-if-no-matching-ifcs",   no_argument,       0, OPT_REJECT_IF_NO_MATCHING_IFCS},
  { "dummy-app-server",             required_argument, 0, OPT_DUMMY_APP_SERVER},
  { "http-acr-logging",             no_argument,       0, OPT_HTTP_ACR_LOGGING},
  { "homestead-timeout",            required_argument, 0, OPT_HOMESTEAD_TIMEOUT},
  { "request-on-queue-timeout",     required_argument, 0, OPT_REQUEST_ON_QUEUE_TIMEOUT},
  { "blacklisted-scscfs",           required_argument, 0, OPT_BLACKLISTED_SCSCFS},
  { "enable-orig-sip-to-tel-coerce",no_argument,       0, OPT_ORIG_SIP_TO_TEL_COERCE},
  { NULL,                           0,                 0, 0}
};

static std::string pj_options_description = "p:s:i:l:D:c:C:n:e:I:A:R:M:S:H:T:o:q:X:E:x:f:u:g:r:P:w:a:F:L:K:G:B:N:dth";

static sem_t term_sem;

QuiescingManager* quiescing_mgr;

const static int QUIESCE_SIGNAL = SIGQUIT;
const static int UNQUIESCE_SIGNAL = SIGUSR1;

// The minimum value allowed for session expires is 90 seconds, as per RFC4028, section 4
const static int MIN_SESSION_EXPIRES = 90;

static const std::string SPROUT_HTTP_MGMT_SOCKET_PATH = "/tmp/sprout-http-mgmt-socket";
static const int NUM_HTTP_MGMT_THREADS = 5;

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
       "     --local-site-name <name>\n"
       "                            The name of the local site (used in a geo-redundant deployment)\n"
       "     --registration-stores <site_name>=<domain>[:<port>][,<site_name>=<domain>[:<port>],...]\n"
       "                            Enables memcached store for registration state and specifies\n"
       "                            location of the memcached store in each site. One of the sites must\n"
       "                            be the local site. Remote sites for geo-redundant storage are optional.\n"
       "                            (If not provided, local store is used)\n"
       "     --impi-store <domain>  Specifies the location of the memcached store for storing\n"
       "                            authentication vectors. There is currently no geo-redundant storage\n"
       "                            for authentication vectors. If this option isn't provided, Sprout uses\n"
       "                            the local site registration store.\n"
       " -S, --sas <ipv4>,<system name>\n"
       "                            Use specified host as Service Assurance Server and specified\n"
       "                            system name to identify this system to SAS.  If this option isn't\n"
       "                            specified SAS is disabled\n"
       " -H, --hss <server>         Name/IP address of the Homestead cluster\n"
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
       "     --default-tel-uri-translation\n"
       "                            If no ENUM file or server is configured, always\n"
       "                            convert tel:+1234 to sip:+1234@homedomain\n"
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
       "                            The session expiry period to request\n"
       "                            (in seconds. Min 90. Defaults to 600)\n"
       "     --max-session-expires <expiry>\n"
       "                            The maximum allowed session expiry period.\n"
       "                            (in seconds. Min 90. Defaults to 600)\n"
       "     --target-latency-us <usecs>\n"
       "                            Target latency above which throttling applies (default: 100000)\n"
       "     --cass-target-latency-us <usecs>\n"
       "                            Target latency above which throttling applies for the Cassandra store\n"
       "                            that's part of the Memento application server (default: 1000000)\n"
       "     --max-tokens N         Maximum number of tokens allowed in the token bucket (used by\n"
       "                            the throttling code (default: 1000))\n"
       "     --init-token-rate N    Initial token refill rate of tokens in the token bucket (used by\n"
       "                            the throttling code (default: 100.0))\n"
       "     --min-token-rate N     Minimum token refill rate of tokens in the token bucket (used by\n"
       "                            the throttling code (default: 10.0))\n"
       "     --max-token-rate N     Maximum token refill rate of tokens in the token bucket (used by\n"
       "                            the throttling code (default: 0.0 - no maximum))\n"
       "     --request-queue-timeout <msecs>\n"
       "                            Maximum time a request can be waiting to be processed before it\n"
       "                            is rejected (used by the throttling code (default: 4000))\n"
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
       "     --memento-notify-url <url>\n"
       "                            URL Memento should notify when call lists change.\n"
       "     --alarms-enabled       Whether SNMP alarms are enabled (default: false)\n"
       "     --override-npdi        Whether the deployment should check for number portability data on \n"
       "                            requests that already have the 'npdi' indicator (default: false)\n"
       "     --exception-max-ttl <secs>\n"
       "                            The maximum time before the process exits if it hits an exception.\n"
       "                            The actual time is randomised.\n"
       "     --sip-blacklist-duration <secs>\n"
       "                            The amount of time to blacklist a SIP peer when it is unresponsive.\n"
       "     --http-blacklist-duration <secs>\n"
       "                            The amount of time to blacklist an HTTP peer when it is unresponsive.\n"
       "     --astaire-blacklist-duration <secs>\n"
       "                            The amount of time to blacklist an Astaire node when it is unresponsive.\n"
       "     --sip-tcp-connect-timeout <milliseconds>\n"
       "                            The amount of time to wait for a SIP TCP connection to establish.\n"
       "     --sip-tcp-send-timeout <milliseconds>\n"
       "                            The amount of time to wait for data sent on a SIP TCP connection to be\n"
       "                            acknowledged by the peer.\n"
       "     --enable-orig-sip-to-tel-coerce\n"
       "                            Whether to treat originating SIP URIs that correspond to global phone\n"
       "                            numbers as Tel URIs.\n"
       "     --dns-timeout <milliseconds>\n"
       "                            The amount of time to wait for a DNS response (default: 200)n"
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
       "                            message to provide authentication. A comma separated list, of one or\n"
       "                            more of the following:\n"
       "                            - 'if_proxy_authorization_present' means sprout will challenge\n"
       "                              requests that already have a Proxy-Authorization header.\n"
       "                            - 'initial_req_from_reg_digest_endpoint' means sprout will challenge\n"
       "                              requests from an endpoint that reigsters with SIP digest authentication.\n"
       "     --force-3pr-body       Always include the original REGISTER and 200 OK in the body of\n"
       "                            third-party REGISTER messages to application servers, even if the\n"
       "                            User-Data doesn't specify it\n"
       "     --nonce-count-supported\n"
       "                            Whether sprout accepts authentication responses with a nonce count\n"
       "                            greater than 1\n"
       "     --scscf-node-uri <URI>\n"
       "                            The URI of this S-CSCF used by other servers, including AS, to contact\n"
       "                            this specific node. Defaults to \"sip:<localhost>:<port_scscf>\".\n"
       "     --sas-use-signaling-interface\n"
       "                            Whether SAS traffic is to be dispatched over the signaling network\n"
       "                            interface rather than the default management interface\n"
       "     --disable-tcp-switch\n"
       "                            Whether to disable TCP-to-UDP uplift when messages are greater than.\n"
       "                            1300 bytes.\n"
       "     --pidfile=<filename>   Write pidfile\n"
       "     --chronos-hostname <hostname>\n"
       "                            Specify the hostname of a remote Chronos cluster. If unset the default\n"
       "                            is to use localhost, using localhost as the callback URL.\n"
       "     --sprout-chronos-callback-uri <hostname>\n"
       "                            Specify the sprout hostname used for Chronos callbacks. If unset \n"
       "                            the default is to use the sprout-hostname.\n"
       "                            Ignored if chronos-hostname is not set.\n"
       "     --apply-default-ifcs   Whether calls that don't have any matching iFCs should have some \n"
       "                            preconfigured iFCs applied instead.\n"
       "     --reject-if-no-matching-ifcs\n"
       "                            Whether calls that don't have any matching iFCs should be rejected.\n"
       "     --dummy-app-server <app server URI>\n"
       "                            If any iFC has an application server that matches the one defined here, \n"
       "                            then the iFC is skipped over.\n"
       "     --http-acr-logging     Whether to include the bodies of ACR HTTP requests when they are logged \n"
       "                            to SAS\n"
       "     --homestead-timeout    The timeout in ms to use on HTTP requests to Homestead\n"
       "     --blacklisted-scscfs   List of URIs of blacklisted S-CSCFs\n"
       " -N, --plugin-option <plugin>,<name>,<value>\n"
       "                            Provide an option value to a plugin.\n"
       " -F, --log-file <directory>\n"
       "                            Log to file in specified directory\n"
       " -L, --log-level N          Set log level to N (default: 4)\n"
       " -d, --daemon               Run as daemon\n"
       " -t, --interactive          Run in foreground with interactive menu\n"
       " -h, --help                 Show this help screen\n"
      );
}

/// Validate the result we get when using atoi
bool validated_atoi(const char* char_to_int,
                    int& char_as_int)
{
  char_as_int = atoi(char_to_int);
  return (char_to_int == std::to_string(char_as_int));
}

/// Parse a string representing a port.
/// @returns The port number as an int, or zero if the port is invalid.
int parse_port(const std::string& port_str)
{
  int port;
  bool rc = validated_atoi(port_str.c_str(), port);

  if ((!rc) || (port < 0) || (port > 0xFFFF))
  {
    port = 0;
  }

  return port;
}

/// Parse a string representing a port.
/// @returns whether the port is invalid and sets the port
bool parse_port(const std::string& port_str, int& port)
{
  bool rc = validated_atoi(port_str.c_str(), port);

  if ((!rc) || (port < 0) || (port > 0xFFFF))
  {
    return false;
  }

  return true;
}

// Macros for validating an integer parameter
#define VALIDATE_INT_PARAM(PARAMETER, PARAMETER_NAME, TRC_STATEMENT)           \
  int parameter;                                                               \
  bool rc = validated_atoi(pj_optarg, parameter);                              \
                                                                               \
  if (rc)                                                                      \
  {                                                                            \
    PARAMETER = parameter;                                                     \
    TRC_INFO(""#TRC_STATEMENT" set to %d", parameter);                         \
  }                                                                            \
  else                                                                         \
  {                                                                            \
    TRC_ERROR("Invalid value for "#PARAMETER_NAME": %s", pj_optarg);           \
    return -1;                                                                 \
  }

#define VALIDATE_INT_PARAM_NON_ZERO(PARAMETER, PARAMETER_NAME, TRC_STATEMENT)  \
  int parameter;                                                               \
  bool rc = validated_atoi(pj_optarg, parameter);                              \
                                                                               \
  if ((rc) && (parameter > 0))                                                 \
  {                                                                            \
    PARAMETER = parameter;                                                     \
    TRC_INFO(""#TRC_STATEMENT" set to %d", parameter);                         \
  }                                                                            \
  else                                                                         \
  {                                                                            \
    TRC_ERROR("Invalid value for "#PARAMETER_NAME": %s", pj_optarg);           \
    return -1;                                                                 \
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
      {
        int log_level;
        bool rc = validated_atoi(pj_optarg, log_level);

        if (rc)
        {
          options->log_level = log_level;
        }
        else
        {
          fprintf(stdout, "Invalid log level value (%s), using log level of %d\n",
                  pj_optarg, options->log_level);
        }
      }
      break;

    case 'F':
      options->log_to_file = PJ_TRUE;
      options->log_directory = std::string(pj_optarg);
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

    case OPT_LOCAL_SITE_NAME:
      options->local_site_name = std::string(pj_optarg);
      TRC_INFO("Local site name = %s", pj_optarg);
      break;

    case OPT_REGISTRATION_STORES:
      {
        // This option has the format
        // <site_name>=<domain>,[<site_name>=<domain>,<site_name=<domain>,...].
        // For now, just split into a vector of <site_name>=<domain> strings. We
        // need to know the local site name to parse this properly, so we'll do
        // that later.
        std::string stores_arg = std::string(pj_optarg);
        boost::split(options->registration_stores,
                     stores_arg,
                     boost::is_any_of(","));
      }
      break;

    case OPT_IMPI_STORES:
      {
        // This option has the same format as OPT_REGISTRATION_STORES. Handle in
        // the same way.
        std::string stores_arg = std::string(pj_optarg);
        boost::split(options->impi_stores, stores_arg, boost::is_any_of(","));
      }
      break;

    case 'S':
      {
        std::vector<std::string> sas_options;
        Utils::split_string(std::string(pj_optarg), ',', sas_options, 0, false);

        if ((sas_options.size() == 2) &&
            !sas_options[0].empty() &&
            !sas_options[1].empty())
        {
          options->sas_server = sas_options[0];
          options->sas_system_name = sas_options[1];
          TRC_INFO("SAS set to %s", options->sas_server.c_str());
          TRC_INFO("System name is set to %s", options->sas_system_name.c_str());
        }
        else
        {
          TRC_WARNING("Invalid --sas option: %s", pj_optarg);
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

    case 'G':
      options->ralf_server = std::string(pj_optarg);
      TRC_INFO("Ralf server set to %s", pj_optarg);
      break;

    case OPT_RALF_THREADS:
      {
        VALIDATE_INT_PARAM(options->ralf_threads,
                           ralf_threads,
                           Number of ralf threads);
      }
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

    case OPT_DEFAULT_TEL_URI_TRANSLATION:
      options->default_tel_uri_translation = true;
      TRC_INFO("Default TEL->SIP URI translation available as a fallback if no ENUM is configured");
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
      {
        VALIDATE_INT_PARAM_NON_ZERO(options->reg_max_expires,
                                    reg_max_expires,
                                    Maximum registration period (in seconds));
      }
      break;

    case OPT_SUB_MAX_EXPIRES:
      {
        VALIDATE_INT_PARAM_NON_ZERO(options->sub_max_expires,
                                    sub_max_expires,
                                    Maximum subscription period (in seconds));
      }
      break;

    case OPT_TARGET_LATENCY_US:
      {
        VALIDATE_INT_PARAM_NON_ZERO(options->target_latency_us,
                                    target_latency_us,
                                    Target latency (in microseconds));
      }
      break;

    case OPT_CASS_TARGET_LATENCY_US:
      {
        VALIDATE_INT_PARAM_NON_ZERO(options->cass_target_latency_us,
                                    cass_target_latency_us,
                                    Target cassandra latency (in microseconds));
      }
      break;

    case OPT_MAX_TOKENS:
      {
        VALIDATE_INT_PARAM_NON_ZERO(options->max_tokens,
                                    max_tokens,
                                    Max tokens);
      }
      break;

    case OPT_INIT_TOKEN_RATE:
      options->init_token_rate = std::stof(std::string(pj_optarg));
      TRC_INFO("Initial token rate set to %s", pj_optarg);
      break;

    case OPT_MIN_TOKEN_RATE:
      options->min_token_rate = std::stof(std::string(pj_optarg));
      TRC_INFO("Minimum token rate set to %s", pj_optarg);
      break;

    case OPT_MAX_TOKEN_RATE:
      options->max_token_rate = std::stof(std::string(pj_optarg));
      TRC_INFO("Maximum token rate set to %s", pj_optarg);
      break;

    case 'W':
      {
        VALIDATE_INT_PARAM_NON_ZERO(options->worker_threads,
                                    worker_threads,
                                    Number of worker threads);
      }
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
      {
        VALIDATE_INT_PARAM_NON_ZERO(options->http_threads,
                                    http_threads,
                                    Number of HTTP threads);
      }
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
      {
        int default_session_expires;
        bool rc = validated_atoi(pj_optarg, default_session_expires);

        if ((rc) && default_session_expires >= MIN_SESSION_EXPIRES)
        {
          options->default_session_expires = default_session_expires;
          TRC_INFO("Default session expiry time set to %d", default_session_expires);
        }
        else
        {
          TRC_WARNING("Invalid value for default session expiry: '%s'. "
                      "The default value of %d will be used.",
                      pj_optarg, options->default_session_expires);
        }
      }
      break;

    case OPT_MAX_SESSION_EXPIRES:
      {
        int max_session_expires;
        bool rc = validated_atoi(pj_optarg, max_session_expires);

        if ((rc) && max_session_expires >= MIN_SESSION_EXPIRES)
        {
          options->max_session_expires = max_session_expires;
          TRC_INFO("Max session expiry time set to %d", max_session_expires);
        }
        else
        {
          TRC_WARNING("Invalid value for max session expiry: '%s'. "
                      "The default value of %d will be used.",
                      pj_optarg, options->max_session_expires);
        }
      }
      break;

    case OPT_EMERGENCY_REG_ACCEPTED:
      options->emerg_reg_accepted = PJ_TRUE;
      TRC_INFO("Emergency registrations accepted");
      break;

    case OPT_MAX_CALL_LIST_LENGTH:
      {
        VALIDATE_INT_PARAM(options->max_call_list_length,
                           max_call_list_length,
                           Max call list length);
      }
      break;

    case OPT_MEMENTO_THREADS:
      {
        VALIDATE_INT_PARAM(options->memento_threads,
                           memento_threads,
                           Memento threads);
      }
      break;

    case OPT_CALL_LIST_TTL:
      {
        VALIDATE_INT_PARAM(options->call_list_ttl,
                           call_list_ttl,
                           TTL for entries in the call list);
      }
      break;

    case OPT_BLACKLISTED_SCSCFS:
      {
        std::vector<std::string> blacklisted_scscfs;
        Utils::split_string(std::string(pj_optarg), ',', blacklisted_scscfs, 0, false);
        options->blacklisted_scscfs.clear();
        options->blacklisted_scscfs.insert(blacklisted_scscfs.begin(), blacklisted_scscfs.end());
        TRC_INFO("%d blacklisted S-CSCF URIs passed on the command line: %s",
                  options->blacklisted_scscfs.size(), pj_optarg);
      }
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
      {
        VALIDATE_INT_PARAM(options->exception_max_ttl,
                           exception_max_ttl,
                           Max TTL after an exception);
      }
      break;

    case OPT_SIP_BLACKLIST_DURATION:
      {
        VALIDATE_INT_PARAM(options->sip_blacklist_duration,
                           sip_blacklist_duration,
                           SIP blacklist duration);
      }
      break;

    case OPT_HTTP_BLACKLIST_DURATION:
      {
        VALIDATE_INT_PARAM(options->http_blacklist_duration,
                           http_blacklist_duration,
                           HTTP blacklist duration);
      }
      break;

    case OPT_ASTAIRE_BLACKLIST_DURATION:
      options->astaire_blacklist_duration = atoi(pj_optarg);
      TRC_INFO("Astaire blacklist duration set to %d",
               options->astaire_blacklist_duration);
      break;

    case OPT_SIP_TCP_CONNECT_TIMEOUT:
      {
        VALIDATE_INT_PARAM(options->sip_tcp_connect_timeout,
                           sip_tcp_connect_timeout,
                           SIP TCP connect timeout);
      }
      break;

    case OPT_SIP_TCP_SEND_TIMEOUT:
      {
        VALIDATE_INT_PARAM(options->sip_tcp_send_timeout,
                           sip_tcp_send_timeout,
                           SIP TCP send timeout);
      }
      break;

    case OPT_DNS_TIMEOUT:
      {
        VALIDATE_INT_PARAM(options->dns_timeout,
                           dns_timeout,
                           DNS request timeout);
      }
      break;

    case OPT_SESSION_CONTINUED_TIMEOUT_MS:
      {
        VALIDATE_INT_PARAM(options->session_continued_timeout_ms,
                           session_continued_timeout_ms,
                           Session continue timeout (in ms));
      }
      break;

    case OPT_SESSION_TERMINATED_TIMEOUT_MS:
      {
        VALIDATE_INT_PARAM(options->session_terminated_timeout_ms,
                           session_terminated_timeout_ms,
                           Session terminated timeout (in ms));
      }
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

    case OPT_MAX_SPROUTLET_DEPTH:
      {
        VALIDATE_INT_PARAM(options->max_sproutlet_depth,
                           max_sproutlet_depth,
                           Maximum depth of Sproutlet recursion);
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
        TRC_INFO("Non-REGISTER authentication set to %s", this_arg.c_str());

        std::vector<std::string> tokens;
        Utils::split_string(this_arg, ',', tokens);

        for (const std::string& token: tokens)
        {
          if (token == "if_proxy_authorization_present")
          {
            options->non_register_auth_mode |=
              NonRegisterAuthentication::IF_PROXY_AUTHORIZATION_PRESENT;
          }
          else if (token == "initial_req_from_reg_digest_endpoint")
          {
            options->non_register_auth_mode |=
              NonRegisterAuthentication::INITIAL_REQ_FROM_REG_DIGEST_ENDPOINT;
          }
          else
          {
            TRC_ERROR("Invalid token in non-REGISTER authentication field: %s",
                      token.c_str());
            return -1;
          }
        }
      }
      break;

    case OPT_FORCE_THIRD_PARTY_REGISTER_BODY:
      {
        TRC_INFO("Forcing inclusion of original REGISTER requests/responses on third-party REGISTERs");
        options->force_third_party_register_body = true;
      }
      break;

    case OPT_MEMENTO_NOTIFY_URL:
      options->memento_notify_url = std::string(pj_optarg);
      TRC_INFO("Memento notify URL set to: '%s'",
               options->memento_notify_url.c_str());
      break;

    case OPT_PIDFILE:
      options->pidfile = std::string(pj_optarg);
      TRC_INFO("Pidfile set to %s", pj_optarg);
      break;

    case OPT_NONCE_COUNT_SUPPORTED:
      options->nonce_count_supported = true;
      TRC_INFO("Nonce counts supported");
      break;

    case OPT_SAS_USE_SIGNALING_IF:
      options->sas_signaling_if = true;
      TRC_INFO("SAS connections created in the signaling namespace");
      break;

    case OPT_DISABLE_TCP_SWITCH:
      options->disable_tcp_switch = true;
      TRC_INFO("Switching to TCP is disabled");
      break;

    case OPT_ORIG_SIP_TO_TEL_COERCE:
      options->enable_orig_sip_to_tel_coerce = true;
      TRC_INFO("Treatment of user=phone orig SIP URIs as Tel URIs enabled");
      break;

    case 'N':
      {
        std::vector<std::string> fields;
        Utils::split_string(std::string(pj_optarg), ',', fields, 3);
        if (fields.size() < 3)
        {
          TRC_ERROR("Invalid value for plugin option: %s", pj_optarg);
          return -1;
        }
        TRC_INFO("Plugin '%s' option '%s' set to '%s'",
                 fields[0].c_str(), fields[1].c_str(), fields[2].c_str());
        options->plugin_options[fields[0]].insert({fields[1], fields[2]});
      }
      break;

    case OPT_SCSCF_NODE_URI:
      options->scscf_node_uri = std::string(pj_optarg);
      TRC_INFO("S-CSCF node URI set to %s", pj_optarg);
      break;

    case OPT_SPROUT_HOSTNAME:
      {
        options->sprout_hostname = std::string(pj_optarg);

        if (Utils::parse_ip_address(options->sprout_hostname) ==
            Utils::IPAddressType::INVALID_WITH_PORT)
        {
          TRC_ERROR("The sprout hostname (%s) must not include a port",
                    options->sprout_hostname.c_str());
          return -1;
        }
        else if (Utils::parse_ip_address(options->sprout_hostname) !=
                 Utils::IPAddressType::INVALID)
        {
          TRC_ERROR("The sprout hostname (%s) must not be an IP address",
                    options->sprout_hostname.c_str());
          return -1;
        }

        TRC_INFO("Sprout hostname set to %s", pj_optarg);
      }
      break;

    case OPT_CHRONOS_HOSTNAME:
      options->chronos_hostname = std::string(pj_optarg);
      TRC_INFO("Chronos hostname set to %s", pj_optarg);
      break;

    case OPT_SPROUT_CHRONOS_CALLBACK_URI:
      options->sprout_chronos_callback_uri = std::string(pj_optarg);
      TRC_INFO("Sprout Chronos callback uri set to %s", pj_optarg);
      break;

    case OPT_APPLY_FALLBACK_IFCS:
      options->apply_fallback_ifcs = true;
      TRC_INFO("Requests that have no matching iFCs will have some preconfigured iFCs applied");
      break;

    case OPT_REJECT_IF_NO_MATCHING_IFCS:
      options->reject_if_no_matching_ifcs = true;
      TRC_INFO("Requests that have no matching iFCs will be rejected");
      break;

    case OPT_DUMMY_APP_SERVER:
      options->dummy_app_server = std::string(pj_optarg);
      TRC_INFO("Dummy application server set to %s", pj_optarg);
      break;

    case OPT_HTTP_ACR_LOGGING:
      options->http_acr_logging = true;
      TRC_INFO("Bodies of ACR HTTP messages will be logged to SAS");
      break;

    case OPT_HOMESTEAD_TIMEOUT:
      {
        VALIDATE_INT_PARAM(options->homestead_timeout,
                          homestead_timeout,
                          Homestead HTTP timeout);
      }
      break;

    case OPT_LISTEN_PORT:
      {
        int listen_port;
        bool rc = validated_atoi(pj_optarg, listen_port);

        if ((rc) && (listen_port > 0))
        {
          options->sproutlet_ports.insert(listen_port);
          TRC_INFO("Opening port %d for non-default sproutlets", listen_port);
        }
        else
        {
          TRC_ERROR("Invalid value for listen_port: %s", pj_optarg);
          return -1;
        }
      }
      break;

    case OPT_REQUEST_ON_QUEUE_TIMEOUT:
      {
        VALIDATE_INT_PARAM(options->request_on_queue_timeout,
                           request_on_queue_timeout,
                           Maximum time (in ms) a request can wait to be processed);
      }
      break;

    SPROUTLET_MACRO(SPROUTLET_OPTIONS)

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
    set_quiescing_true();
  }
  else
  {
    TRC_STATUS("Unquiesce signal received");
    set_quiescing_false();
  }
}


// Signal handler that triggers sprout termination.
void terminate_handler(int sig)
{
  sem_post(&term_sem);
}

class QuiesceCompleteHandler : public QuiesceCompletionInterface
{
public:
  void quiesce_complete()
  {
    TRC_STATUS("Quiesce complete");
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

// Objects that must be shared with dynamically linked sproutlets must be
// globally scoped.
LoadMonitor* load_monitor = NULL;
HSSConnection* hss_connection = NULL;
Store* local_data_store = NULL;
std::vector<Store*> remote_data_stores;
Store* local_impi_data_store = NULL;
std::vector<Store*> remote_impi_data_stores;
AoRStore* local_aor_store = NULL;
std::vector<AoRStore*> remote_aor_stores;
SubscriberDataManager* local_sdm = NULL;
std::vector<SubscriberDataManager*> remote_sdms;
ImpiStore* local_impi_store = NULL;
std::vector<ImpiStore*> remote_impi_stores;
RalfProcessor* ralf_processor = NULL;
DnsCachedResolver* dns_resolver = NULL;
HttpResolver* http_resolver = NULL;
ACRFactory* scscf_acr_factory = NULL;
EnumService* enum_service = NULL;
ExceptionHandler* exception_handler = NULL;
AlarmManager* alarm_manager = NULL;
AnalyticsLogger* analytics_logger = NULL;
ChronosConnection* chronos_connection = NULL;
SIFCService* sifc_service = NULL;
FIFCService* fifc_service = NULL;

int create_astaire_stores(struct options opt,
                          AstaireResolver*& astaire_resolver,
                          CommunicationMonitor*& astaire_comm_monitor,
                          CommunicationMonitor*& remote_astaire_comm_monitor)
{
  // Parse the registration-stores argument.
  std::string registration_store_location;
  std::vector<std::string> remote_registration_stores_locations;

  if (!Utils::parse_multi_site_stores_arg(opt.registration_stores,
                                          opt.local_site_name,
                                          "registration-store",
                                          registration_store_location,
                                          remote_registration_stores_locations))
  {
    return 1;
  }

  // Parse the impi-stores argument.
  std::string impi_store_location;
  std::vector<std::string> remote_impi_stores_locations;

  if (opt.impi_stores.empty())
  {
    // The config option was not specified so use the same locations as for the
    // regstore.
    TRC_DEBUG("Use same store locations for IMPI stores as reg stores");
    impi_store_location = registration_store_location;
    remote_impi_stores_locations = remote_registration_stores_locations;
  }
  else
  {
    TRC_DEBUG("Parse IMPI store locations argument");
    if (!Utils::parse_multi_site_stores_arg(opt.impi_stores,
                                            opt.local_site_name,
                                            "impi-store",
                                            impi_store_location,
                                            remote_impi_stores_locations))
    {
      return 1;
    }
  }

  astaire_resolver = new AstaireResolver(dns_resolver,
                                         stack_data.addr_family,
                                         opt.astaire_blacklist_duration);

  astaire_comm_monitor = new CommunicationMonitor(new Alarm(alarm_manager,
                                                            "sprout",
                                                            AlarmDef::SPROUT_ASTAIRE_COMM_ERROR,
                                                            AlarmDef::CRITICAL),
                                                  "Sprout",
                                                  "Astaire");

  remote_astaire_comm_monitor = new CommunicationMonitor(new Alarm(alarm_manager,
                                                                   "sprout",
                                                                   AlarmDef::SPROUT_REMOTE_ASTAIRE_COMM_ERROR,
                                                                   AlarmDef::CRITICAL),
                                                         "Sprout",
                                                         "remote Astaire");

  if (registration_store_location != "")
  {
    // Use memcached store.
    TRC_STATUS("Using memcached store");
    local_data_store = (Store*)new TopologyNeutralMemcachedStore(registration_store_location,
                                                                 astaire_resolver,
                                                                 false,
                                                                 astaire_comm_monitor);

    if (!remote_registration_stores_locations.empty())
    {
      // Use remote memcached store too.
      TRC_STATUS("Using remote memcached stores");
       for (std::vector<std::string>::iterator it = remote_registration_stores_locations.begin();
           it != remote_registration_stores_locations.end();
           ++it)
      {
        Store* remote_data_store = (Store*)new TopologyNeutralMemcachedStore(*it,
                                                                             astaire_resolver,
                                                                             true,
                                                                             remote_astaire_comm_monitor);
        remote_data_stores.push_back(remote_data_store);
      }
    }
  }
  else
  {
    // Use local store.
    TRC_STATUS("Using local store");
    local_data_store = (Store*)new LocalStore();
  }

  if (local_data_store == NULL)
  {
    TRC_ERROR("Failed to connect to data store. Aborting startup");
    return 1;
  }

  local_aor_store = new AstaireAoRStore(local_data_store);

  for (std::vector<Store*>::iterator it = remote_data_stores.begin();
       it != remote_data_stores.end();
       ++it)
  {
    AoRStore* remote_aor_store = new AstaireAoRStore(*it);
    remote_aor_stores.push_back(remote_aor_store);
  }

  // Create an AV store using the local store and initialise the authentication
  // sproutlet.
  if (impi_store_location != "")
  {
    // Use memcached store.
    TRC_STATUS("Using memcached store");
    local_impi_data_store = (Store*)new TopologyNeutralMemcachedStore(impi_store_location,
                                                                      astaire_resolver,
                                                                      false,
                                                                      astaire_comm_monitor);
    local_impi_store = new AstaireImpiStore(local_impi_data_store);

    // Only set up remote IMPI stores if some have been configured, and we need
    // the IMPI store to be GR.
    if (!remote_impi_stores_locations.empty() &&
        (opt.non_register_auth_mode &
           NonRegisterAuthentication::INITIAL_REQ_FROM_REG_DIGEST_ENDPOINT))
    {
      // Use remote memcached store too.
      TRC_STATUS("Using remote memcached stores");
       for (std::vector<std::string>::iterator it = remote_impi_stores_locations.begin();
           it != remote_impi_stores_locations.end();
           ++it)
      {
        Store* remote_data_store = (Store*)new TopologyNeutralMemcachedStore(*it,
                                                                             astaire_resolver,
                                                                             true,
                                                                             remote_astaire_comm_monitor);
        remote_impi_data_stores.push_back(remote_data_store);
        remote_impi_stores.push_back(new AstaireImpiStore(remote_data_store));
      }
    }
  }
  else
  {
    // Use local store.
    TRC_STATUS("Using local store");
    local_impi_data_store = (Store*)new LocalStore();
    local_impi_store = new AstaireImpiStore(local_data_store);
  }
  return 0;
}

void create_chronos_connection(struct options opt,
                               CommunicationMonitor*& chronos_comm_monitor)
{
  chronos_comm_monitor = new CommunicationMonitor(new Alarm(alarm_manager,
                                                            "sprout",
                                                            AlarmDef::SPROUT_CHRONOS_COMM_ERROR,
                                                            AlarmDef::MAJOR),
                                                  "Sprout",
                                                  "Chronos");

  // Create a connection to Chronos.
  std::string port_str = std::to_string(opt.http_port);

  std::string chronos_service;
  std::string chronos_callback_host = "127.0.0.1:" + port_str;

  if (opt.chronos_hostname == "")
  {
    chronos_service = "127.0.0.1:7253";

    Utils::IPAddressType address_type = Utils::parse_ip_address(opt.http_address);

    if ((address_type == Utils::IPAddressType::IPV6_ADDRESS) ||
        (address_type == Utils::IPAddressType::IPV6_ADDRESS_WITH_PORT) ||
        (address_type == Utils::IPAddressType::IPV6_ADDRESS_BRACKETED))
    {
      chronos_callback_host = "[::1]:" + port_str;
    }
  }
  else
  {
    std::string chronos_callback_uri = opt.sprout_chronos_callback_uri;

    if (chronos_callback_uri == "")
    {
      chronos_callback_uri = opt.sprout_hostname;
    }

    chronos_service = opt.chronos_hostname + ":7253";
    chronos_callback_host = chronos_callback_uri + ":" + port_str;
  }

  TRC_STATUS("Creating connection to Chronos %s using %s as the callback URI",
             chronos_service.c_str(),
             chronos_callback_host.c_str());
  chronos_connection = new ChronosConnection(chronos_service,
                                             chronos_callback_host,
                                             http_resolver,
                                             chronos_comm_monitor);

}

/*
 * main()
 */
int main(int argc, char* argv[])
{
  pj_status_t status;
  struct options opt;

  SIPResolver* sip_resolver = NULL;
  HttpConnection* ralf_connection = NULL;
  ACRFactory* pcscf_acr_factory = NULL;
  pj_bool_t websockets_enabled = PJ_FALSE;
  AccessLogger* access_logger = NULL;
  SproutletProxy* sproutlet_proxy = NULL;
  std::list<Sproutlet*> sproutlets;
  CommunicationMonitor* chronos_comm_monitor = NULL;
  CommunicationMonitor* enum_comm_monitor = NULL;
  CommunicationMonitor* hss_comm_monitor = NULL;
  AstaireResolver* astaire_resolver = NULL;
  CommunicationMonitor* astaire_comm_monitor = NULL;
  CommunicationMonitor* remote_astaire_comm_monitor = NULL;
  CommunicationMonitor* ralf_comm_monitor = NULL;
  RPHService* rph_service = NULL;

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
  opt.external_icscf_uri = "";
  opt.auth_enabled = PJ_FALSE;
  opt.enum_suffix = ".e164.arpa";
  opt.default_tel_uri_translation = false;

  // If changing this default for reg_max_expires, note that
  // debian/homestead.init.d in the homestead repository also defaults
  // reg_max_expires, and so the default value set in that file must be changed
  // also.
  opt.reg_max_expires = 300;

  opt.sub_max_expires = 0;
  opt.sas_server = "0.0.0.0";
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
  opt.target_latency_us = 10000;
  opt.cass_target_latency_us = 1000000;
  opt.max_tokens = 1000;
  opt.init_token_rate = 100.0;
  opt.min_token_rate = 10.0;
  opt.max_token_rate = 0.0;
  opt.log_to_file = PJ_FALSE;
  opt.log_level = 0;
  opt.daemon = PJ_FALSE;
  opt.interactive = PJ_FALSE;
  opt.override_npdi = PJ_FALSE;
  opt.exception_max_ttl = 600;
  opt.sip_blacklist_duration = SIPResolver::DEFAULT_BLACKLIST_DURATION;
  opt.http_blacklist_duration = HttpResolver::DEFAULT_BLACKLIST_DURATION;
  opt.astaire_blacklist_duration = AstaireResolver::DEFAULT_BLACKLIST_DURATION;
  opt.sip_tcp_connect_timeout = 1800;
  opt.sip_tcp_send_timeout = 1800;
  opt.dns_timeout = DnsCachedResolver::DEFAULT_TIMEOUT;
  opt.session_continued_timeout_ms = SCSCFSproutlet::DEFAULT_SESSION_CONTINUED_TIMEOUT;
  opt.session_terminated_timeout_ms = SCSCFSproutlet::DEFAULT_SESSION_TERMINATED_TIMEOUT;
  opt.stateless_proxies.clear();
  opt.max_sproutlet_depth = SproutletProxy::DEFAULT_MAX_SPROUTLET_DEPTH;
  opt.ralf_threads = 25;
  opt.non_register_auth_mode = NonRegisterAuthentication::NEVER;
  opt.force_third_party_register_body = false;
  opt.listen_port = 0;
  SPROUTLET_MACRO(SPROUTLET_CFG_OPTIONS_DEFAULT_VALUES)
  opt.nonce_count_supported = false;
  opt.scscf_node_uri = "";
  opt.sas_signaling_if = false;
  opt.disable_tcp_switch = false;
  opt.apply_fallback_ifcs = false;
  opt.reject_if_no_matching_ifcs = false;
  opt.dummy_app_server = "";
  opt.http_acr_logging = false;
  opt.homestead_timeout = 750;
  opt.enable_orig_sip_to_tel_coerce = false;
  opt.request_on_queue_timeout = 4000;

  status = init_logging_options(argc, argv, &opt);

  if (status != PJ_SUCCESS)
  {
    return 1;
  }

  if (opt.daemon && opt.interactive)
  {
    TRC_ERROR("Cannot specify both --daemon and --interactive");
    return 1;
  }

  Utils::daemon_log_setup(argc,
                          argv,
                          opt.daemon,
                          opt.log_directory,
                          opt.log_level,
                          opt.log_to_file);

  // We should now have a connection to syslog so we can write the started ENT
  // log.
  CL_SPROUT_STARTED.log();

  if ((opt.log_to_file) && (opt.log_directory != ""))
  {
    TRC_STATUS("Access logging enabled to %s", opt.log_directory.c_str());
    access_logger = new AccessLogger(opt.log_directory);
  }

  init_pjsip_logging(opt.log_level, opt.log_to_file, opt.log_directory);

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
    return 1;
  }

  // If sub_max_expires is unset, then allow a higher number than the
  // maximum registration expiry, as required by TS 24.229 5.2.3.
  // RFC 3680 suggests 3761 seconds for an expiry of 3600. We thus add
  // 161 seconds for the maximum subscription expiry by default.
  if (opt.sub_max_expires == 0)
  {
    opt.sub_max_expires = opt.reg_max_expires + 161;
    TRC_INFO("Maximum subscription period defaulted to %d seconds, based maximum registration expiry %d seconds",
             opt.sub_max_expires, opt.reg_max_expires);
  }

  if (opt.pidfile != "")
  {
    int rc = Utils::lock_and_write_pidfile(opt.pidfile);
    if (rc == -1)
    {
      // Failure to acquire pidfile lock
      TRC_ERROR("Could not write pidfile - exiting");
      return 2;
    }
  }

  start_signal_handlers();

  if (opt.analytics_enabled)
  {
    analytics_logger = new AnalyticsLogger();
  }

  std::vector<std::string> sproutlet_uris;
  SPROUTLET_MACRO(SPROUTLET_VERIFY_OPTIONS)

  if (opt.sas_server == "0.0.0.0")
  {
    TRC_WARNING("SAS server option was invalid or not configured - SAS is disabled");
    CL_SPROUT_INVALID_SAS_OPTION.log();
  }

  if ((!opt.pcscf_enabled) && (!opt.enabled_scscf) && (!opt.enabled_icscf))
  {
    CL_SPROUT_NO_SI_CSCF.log();
    TRC_WARNING("Most Sprout nodes have at least one of P-CSCF, S-CSCF or I-CSCF enabled");
  }

  if ((opt.pcscf_enabled) && ((opt.enabled_scscf) || (opt.enabled_icscf)))
  {
    TRC_ERROR("Cannot enable both P-CSCF and S/I-CSCF");
    return 1;
  }

  if ((opt.pcscf_enabled) &&
      (opt.upstream_proxy == ""))
  {
    TRC_ERROR("Cannot enable P-CSCF without specifying --routing-proxy");
    return 1;
  }

  if ((opt.ibcf) && (!opt.pcscf_enabled))
  {
    TRC_ERROR("Cannot enable IBCF without also enabling P-CSCF");
    return 1;
  }

  if ((opt.webrtc_port != 0 ) && (!opt.pcscf_enabled))
  {
    TRC_ERROR("Cannot enable WebRTC without also enabling P-CSCF");
    return 1;
  }

  if (((opt.enabled_scscf) || (opt.enabled_icscf)) &&
      (opt.hss_server == ""))
  {
    CL_SPROUT_SI_CSCF_NO_HOMESTEAD.log();
    TRC_ERROR("S/I-CSCF enabled with no Homestead server");
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

  if (((!opt.registration_stores.empty()) || (!opt.impi_stores.empty())) &&
      (opt.auth_enabled) &&
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

  SNMP::EventAccumulatorByScopeTable* latency_table;
  SNMP::EventAccumulatorByScopeTable* queue_size_table;
  SNMP::SuccessFailCountByPriorityAndScopeTable* queue_success_fail_table;
  SNMP::CounterByScopeTable* requests_counter;
  SNMP::CounterByScopeTable* overload_counter;

  SNMP::IPCountTable* homestead_cxn_count = NULL;

  SNMP::EventAccumulatorTable* homestead_latency_table = NULL;
  SNMP::EventAccumulatorTable* homestead_mar_latency_table = NULL;
  SNMP::EventAccumulatorTable* homestead_sar_latency_table = NULL;
  SNMP::EventAccumulatorTable* homestead_uar_latency_table = NULL;
  SNMP::EventAccumulatorTable* homestead_lir_latency_table = NULL;
  SNMP::CounterTable* no_shared_ifcs_set_table = NULL;

  SNMP::ContinuousAccumulatorByScopeTable* token_rate_table = NULL;
  SNMP::ScalarByScopeTable* smoothed_latency_scalar = NULL;
  SNMP::ScalarByScopeTable* target_latency_scalar = NULL;
  SNMP::ScalarByScopeTable* penalties_scalar = NULL;
  SNMP::ScalarByScopeTable* token_rate_scalar = NULL;

  if (opt.pcscf_enabled)
  {
    latency_table = SNMP::EventAccumulatorByScopeTable::create("bono_latency",
                                                               ".1.2.826.0.1.1578918.9.2.2");
    queue_size_table = SNMP::EventAccumulatorByScopeTable::create("bono_queue_size",
                                                                  ".1.2.826.0.1.1578918.9.2.6");
    queue_success_fail_table = SNMP::SuccessFailCountByPriorityAndScopeTable::create("bono_queue_success_fail",
                                                                                     ".1.2.826.0.1.1578918.9.2.7");
    requests_counter = SNMP::CounterByScopeTable::create("bono_incoming_requests",
                                                         ".1.2.826.0.1.1578918.9.2.4");
    overload_counter = SNMP::CounterByScopeTable::create("bono_rejected_overload",
                                                         ".1.2.826.0.1.1578918.9.2.5");
  }
  else
  {
    latency_table = SNMP::EventAccumulatorByScopeTable::create("sprout_latency",
                                                               ".1.2.826.0.1.1578918.9.3.1");
    queue_size_table = SNMP::EventAccumulatorByScopeTable::create("sprout_queue_size",
                                                                  ".1.2.826.0.1.1578918.9.3.8");
    queue_success_fail_table = SNMP::SuccessFailCountByPriorityAndScopeTable::create("sprout_queue_success_fail",
                                                                                     ".1.2.826.0.1.1578918.9.3.43");
    requests_counter = SNMP::CounterByScopeTable::create("sprout_incoming_requests",
                                                         ".1.2.826.0.1.1578918.9.3.6");
    overload_counter = SNMP::CounterByScopeTable::create("sprout_rejected_overload",
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
    no_shared_ifcs_set_table = SNMP::CounterTable::create("no_shared_ifcs_set",
                                                          ".1.2.826.0.1.1578918.9.3.40");
    token_rate_table = SNMP::ContinuousAccumulatorByScopeTable::create("sprout_token_rate",
                                                                       ".1.2.826.0.1.1578918.9.3.27");
    smoothed_latency_scalar = SNMP::ScalarByScopeTable::create("sprout_smoothed_latency",
                                                                ".1.2.826.0.1.1578918.9.3.28");
    target_latency_scalar = SNMP::ScalarByScopeTable::create("sprout_target_latency",
                                                             ".1.2.826.0.1.1578918.9.3.29");
    penalties_scalar = SNMP::ScalarByScopeTable::create("sprout_penalties",
                                                        ".1.2.826.0.1.1578918.9.3.30");
    token_rate_scalar = SNMP::ScalarByScopeTable::create("sprout_current_token_rate",
                                                         ".1.2.826.0.1.1578918.9.3.31");
  }

  // Create Sprout's alarm objects.
  alarm_manager = new AlarmManager();

  enum_comm_monitor = new CommunicationMonitor(new Alarm(alarm_manager,
                                                         "sprout",
                                                         AlarmDef::SPROUT_ENUM_COMM_ERROR,
                                                         AlarmDef::MAJOR),
                                               "Sprout",
                                               "ENUM");

  hss_comm_monitor = new CommunicationMonitor(new Alarm(alarm_manager,
                                                        "sprout",
                                                        AlarmDef::SPROUT_HOMESTEAD_COMM_ERROR,
                                                        AlarmDef::CRITICAL),
                                              "Sprout",
                                              "Homestead");

  ralf_comm_monitor = new CommunicationMonitor(new Alarm(alarm_manager,
                                                         "sprout",
                                                         AlarmDef::SPROUT_RALF_COMM_ERROR,
                                                         AlarmDef::MAJOR),
                                               "Sprout",
                                               "Ralf");

  // Start the load monitor
  load_monitor = new LoadMonitor(opt.target_latency_us,   // Initial target latency (us).
                                 opt.max_tokens,          // Maximum token bucket size.
                                 opt.init_token_rate,     // Initial token fill rate (per sec).
                                 opt.min_token_rate,      // Minimum token fill rate (per sec).
                                 opt.max_token_rate,      // Maximum token fill rate (per sec).
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
  dns_resolver = new DnsCachedResolver(opt.dns_servers, opt.dns_timeout);
  if (opt.pcscf_enabled)
  {
    sip_resolver = new SIPResolver(dns_resolver, opt.sip_blacklist_duration, 0);
  }
  else
  {
    sip_resolver = new SIPResolver(dns_resolver, opt.sip_blacklist_duration);
  }

  // Create a new quiescing manager instance and register our completion handler
  // with it.
  quiescing_mgr = new QuiescingManager();
  quiescing_mgr->register_completion_handler(new QuiesceCompleteHandler());

  // Initialize the PJSIP stack and associated subsystems.
  status = init_stack(opt.sas_system_name,
                      opt.sas_server,
                      opt.pcscf_trusted_port,
                      opt.pcscf_untrusted_port,
                      opt.port_scscf,
                      opt.sas_signaling_if,
                      opt.sproutlet_ports,
                      opt.local_host,
                      opt.public_host,
                      opt.home_domain,
                      opt.additional_home_domains,
                      opt.uri_scscf,
                      opt.sprout_hostname,
                      opt.alias_hosts,
                      sip_resolver,
                      opt.record_routing_model,
                      opt.default_session_expires,
                      opt.max_session_expires,
                      opt.sip_tcp_connect_timeout,
                      opt.sip_tcp_send_timeout,
                      quiescing_mgr,
                      opt.billing_cdf,
                      sproutlet_uris,
                      opt.enable_orig_sip_to_tel_coerce);

  if (status != PJ_SUCCESS)
  {
    CL_SPROUT_SIP_INIT_INTERFACE_FAIL.log(PJUtils::pj_status_to_string(status).c_str());
    TRC_ERROR("Error initializing stack %s", PJUtils::pj_status_to_string(status).c_str());
    return 1;
  }

  //If the flag is set, disable UDP-to-TCP uplift.
  if (opt.disable_tcp_switch)
  {
    TRC_STATUS("Disabling UDP-to-TCP uplift");
    pjsip_cfg_t* pjsip_config = pjsip_cfg();
    pjsip_config->endpt.disable_tcp_switch = true;
  }

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
                                         ralf_comm_monitor,
                                         "http",
                                         !opt.http_acr_logging);
    ralf_processor = new RalfProcessor(ralf_connection,
                                       exception_handler,
                                       opt.ralf_threads);
  }
  else
  {
    CL_SPROUT_NO_RALF_CONFIGURED.log();
  }

  // Initialise the OPTIONS handling module.
  init_options();

  if (opt.hss_server != "")
  {
    // Create a connection to the HSS.
    TRC_STATUS("Creating connection to HSS %s with HTTP timeout %d",
               opt.hss_server.c_str(), opt.homestead_timeout);
    sifc_service = new SIFCService(new Alarm(alarm_manager,
                                             "sprout",
                                             AlarmDef::SPROUT_SIFC_STATUS,
                                             AlarmDef::CRITICAL),
                                   no_shared_ifcs_set_table);
    hss_connection = new HSSConnection(opt.hss_server,
                                       http_resolver,
                                       load_monitor,
                                       homestead_cxn_count,
                                       homestead_latency_table,
                                       homestead_mar_latency_table,
                                       homestead_sar_latency_table,
                                       homestead_uar_latency_table,
                                       homestead_lir_latency_table,
                                       hss_comm_monitor,
                                       sifc_service,
                                       opt.homestead_timeout);
  }

  // Create FIFC service
  fifc_service = new FIFCService(new Alarm(alarm_manager,
                                           "sprout",
                                           AlarmDef::SPROUT_FIFC_STATUS,
                                           AlarmDef::CRITICAL));

  // Create ENUM service.
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
  else if (opt.default_tel_uri_translation)
  {
    TRC_STATUS("Setting up ENUM service to do default TEL->SIP URI translation");
    enum_service = new DummyEnumService(opt.home_domain);
  }

  // Create RPH service.
  TRC_STATUS("Setting up RPH service");
  rph_service = new RPHService(new Alarm(alarm_manager,
                                         "sprout",
                                         AlarmDef::SPROUT_RPH_STATUS,
                                         AlarmDef::CRITICAL));

  if (opt.pcscf_enabled)
  {
    // Create an ACR factory for the P-CSCF.
    pcscf_acr_factory = (ralf_processor != NULL) ?
                (ACRFactory*)new RalfACRFactory(ralf_processor, ACR::PCSCF) :
                new ACRFactory();

    // Launch stateful proxy as P-CSCF.
    status = init_stateful_proxy(true,
                                 opt.upstream_proxy,
                                 opt.upstream_proxy_port,
                                 opt.upstream_proxy_connections,
                                 opt.upstream_proxy_recycle,
                                 opt.ibcf,
                                 opt.trusted_hosts,
                                 opt.pbxes,
                                 opt.pbx_service_route,
                                 analytics_logger,
                                 pcscf_acr_factory,
                                 "",
                                 quiescing_mgr,
                                 opt.enabled_icscf,
                                 opt.enabled_scscf,
                                 opt.emerg_reg_accepted);
    if (status != PJ_SUCCESS)
    {
      TRC_ERROR("Failed to enable P-CSCF edge proxy. Aborting startup");
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

  create_chronos_connection(opt,
                            chronos_comm_monitor);

  scscf_acr_factory = (ralf_processor != NULL) ?
                    (ACRFactory*)new RalfACRFactory(ralf_processor, ACR::SCSCF) :
                    new ACRFactory();

  // Create the SDM and IMPI stores
  int rc = create_astaire_stores(opt,
                                 astaire_resolver,
                                 astaire_comm_monitor,
                                 remote_astaire_comm_monitor);
  if (rc != 0)
  {
    return rc;
  }

  // Use the AOR stores we've create to create the local (and optionally remote)
  // SDMs.
  local_sdm = new SubscriberDataManager(local_aor_store,
                                        chronos_connection,
                                        analytics_logger,
                                        true);

  for (std::vector<AoRStore*>::iterator it = remote_aor_stores.begin();
       it != remote_aor_stores.end();
       ++it)
  {
    SubscriberDataManager* remote_sdm = new SubscriberDataManager(*it,
                                                                  chronos_connection,
                                                                  NULL,
                                                                  false);
    remote_sdms.push_back(remote_sdm);
  }

  // Start the HTTP stack early as plugins might need to register handlers
  // with it.
  HttpStack* http_stack_sig = new HttpStack(opt.http_threads,
                                            exception_handler,
                                            access_logger,
                                            load_monitor);
  try
  {
    http_stack_sig->initialize();
  }
  catch (HttpStack::Exception& e)
  {
    CL_SPROUT_HTTP_INTERFACE_FAIL.log(e._func, e._rc);
    closelog();
    TRC_ERROR("Caught signaling HttpStack::Exception - %s - %d", e._func, e._rc);
    return 1;
  }

  HttpStack* http_stack_mgmt = new HttpStack(NUM_HTTP_MGMT_THREADS,
                                             exception_handler,
                                             access_logger,
                                             load_monitor);
  try
  {
    http_stack_mgmt->initialize();
  }
  catch (HttpStack::Exception& e)
  {
    CL_SPROUT_HTTP_INTERFACE_FAIL.log(e._func, e._rc);
    closelog();
    TRC_ERROR("Caught management HttpStack::Exception - %s - %d", e._func, e._rc);
    return 1;
  }

  // Load the sproutlet plugins.
  PluginLoader* loader = new PluginLoader("/usr/share/clearwater/sprout/plugins",
                                          opt);

  if (!loader->load(sproutlets))
  {
    CL_SPROUT_PLUGIN_FAILURE.log();
    TRC_ERROR("Failed to successfully load plug-ins. Aborting startup");
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
                                         opt.sprout_hostname,
                                         host_aliases,
                                         sproutlets,
                                         opt.stateless_proxies,
                                         opt.max_sproutlet_depth);
    if (sproutlet_proxy == NULL)
    {
      TRC_ERROR("Failed to create SproutletProxy. Aborting startup");
      return 1;
    }
  }

  init_common_sip_processing(requests_counter,
                             hc);

  init_thread_dispatcher(opt.worker_threads,
                         latency_table,
                         queue_size_table,
                         queue_success_fail_table,
                         overload_counter,
                         load_monitor,
                         rph_service,
                         exception_handler,
                         opt.request_on_queue_timeout);

  // Create worker threads first as they take work from the PJSIP threads so
  // need to be ready.
  status = start_worker_threads();
  if (status != PJ_SUCCESS)
  {
    TRC_ERROR("Error starting SIP worker threads, %s", PJUtils::pj_status_to_string(status).c_str());
    return 1;
  }

  status = start_pjsip_thread();
  if (status != PJ_SUCCESS)
  {
    CL_SPROUT_SIP_STACK_INIT_FAIL.log(PJUtils::pj_status_to_string(status).c_str());
    TRC_ERROR("Error starting SIP stack, %s", PJUtils::pj_status_to_string(status).c_str());
    return 1;
  }

  // These tasks can cause a request to be sent to an application server
  // relating to a third party registration, which may cause fallback iFCs to
  // be invoked. We don't increment any statistics relating to the fallback
  // iFCs in these flows though (as they should only be used on initial
  // registration).
  DeregistrationTask::Config deregistration_config(local_sdm,
                                                   remote_sdms,
                                                   hss_connection,
                                                   fifc_service,
                                                   IFCConfiguration(opt.apply_fallback_ifcs,
                                                                    opt.reject_if_no_matching_ifcs,
                                                                    opt.dummy_app_server,
                                                                    NULL,
                                                                    NULL),
                                                   sip_resolver,
                                                   local_impi_store,
                                                   remote_impi_stores);
  PushProfileTask::Config push_profile_config(local_sdm,
                                              remote_sdms,
                                              hss_connection);
  GetCachedDataTask::Config get_cached_data_config(local_sdm, remote_sdms);
  DeleteImpuTask::Config delete_impu_config(local_sdm,
                                            remote_sdms,
                                            hss_connection,
                                            fifc_service,
                                            IFCConfiguration(opt.apply_fallback_ifcs,
                                                             opt.reject_if_no_matching_ifcs,
                                                             opt.dummy_app_server,
                                                             NULL,
                                                             NULL));

  AoRTimeoutTask::Config aor_timeout_config(local_sdm,
                                            remote_sdms,
                                            hss_connection);
  AuthTimeoutTask::Config auth_timeout_config(local_impi_store,
                                              hss_connection);

  TimerHandler<ChronosAoRTimeoutTask, AoRTimeoutTask::Config> aor_timeout_handler(&aor_timeout_config);
  TimerHandler<ChronosAuthTimeoutTask, AuthTimeoutTask::Config> auth_timeout_handler(&auth_timeout_config);
  HttpStackUtils::SpawningHandler<DeregistrationTask, DeregistrationTask::Config> deregistration_handler(&deregistration_config);
  HttpStackUtils::SpawningHandler<PushProfileTask, PushProfileTask::Config> push_profile_handler(&push_profile_config);
  HttpStackUtils::PingHandler ping_handler;
  HttpStackUtils::SpawningHandler<GetBindingsTask, GetCachedDataTask::Config> get_bindings_handler(&get_cached_data_config);
  HttpStackUtils::SpawningHandler<GetSubscriptionsTask, GetCachedDataTask::Config> get_subscriptions_handler(&get_cached_data_config);
  HttpStackUtils::SpawningHandler<DeleteImpuTask, DeleteImpuTask::Config> delete_impu_handler(&delete_impu_config);

  if (opt.enabled_scscf)
  {
    try
    {
      http_stack_sig->register_handler("^/ping$",
                                       &ping_handler);
      http_stack_sig->register_handler("^/timers$",
                                       &aor_timeout_handler);
      http_stack_sig->register_handler("^/authentication-timeout$",
                                       &auth_timeout_handler);
      http_stack_sig->register_handler("^/registrations?*$",
                                       &deregistration_handler);
      http_stack_sig->register_handler("^/registrations/[^/]+$",
                                       &push_profile_handler);
      http_stack_sig->bind_tcp_socket(opt.http_address, opt.http_port);
      http_stack_sig->start(&reg_httpthread_with_pjsip);
    }
    catch (HttpStack::Exception& e)
    {
      CL_SPROUT_HTTP_INTERFACE_FAIL.log(e._func, e._rc);
      TRC_ERROR("Caught signaling HttpStack::Exception - %s - %d", e._func, e._rc);
      return 1;
    }

    try
    {
      http_stack_mgmt->register_handler("^/ping$",
                                        &ping_handler);
      http_stack_mgmt->register_handler("^/impu/[^/]+/bindings$",
                                        &get_bindings_handler);
      http_stack_mgmt->register_handler("^/impu/[^/]+/subscriptions$",
                                        &get_subscriptions_handler);
      http_stack_mgmt->register_handler("^/impu/[^/]+$",
                                        &delete_impu_handler);
      http_stack_mgmt->bind_unix_socket(SPROUT_HTTP_MGMT_SOCKET_PATH);
      http_stack_mgmt->start(&reg_httpthread_with_pjsip);
    }
    catch (HttpStack::Exception& e)
    {
      CL_SPROUT_HTTP_INTERFACE_FAIL.log(e._func, e._rc);
      TRC_ERROR("Caught management HttpStack::Exception - %s - %d", e._func, e._rc);
      return 1;
    }
  }

  // Wait here until the quit semaphore is signaled.
  sem_wait(&term_sem);

  // If we received a TERM while we were quiescing, log that as an error.  We
  // should only receive a TERM when quiescing if something has gone wrong and
  // we have taken longer than 5 minutes to quiesce.
  if (quiescing_mgr->is_quiescing())
  {
    TRC_ERROR("Sprout received a TERM signal when quiescing");
  }

  snmp_terminate("sprout");

  CL_SPROUT_ENDED.log();
  if (opt.enabled_scscf)
  {
    try
    {
      http_stack_sig->stop();
      http_stack_sig->wait_stopped();
    }
    catch (HttpStack::Exception& e)
    {
      CL_SPROUT_HTTP_INTERFACE_STOP_FAIL.log(e._func, e._rc);
      TRC_ERROR("Caught signaling HttpStack::Exception - %s - %d", e._func, e._rc);
    }

    try
    {
      http_stack_mgmt->stop();
      http_stack_mgmt->wait_stopped();
    }
    catch (HttpStack::Exception& e)
    {
      CL_SPROUT_HTTP_INTERFACE_STOP_FAIL.log(e._func, e._rc);
      TRC_ERROR("Caught management HttpStack::Exception - %s - %d", e._func, e._rc);
    }
  }

  // Terminate the PJSIP thread and the worker threads to exit.  We kill
  // the PJSIP thread first - if we killed the worker threads first the
  // rx_msg_q will stop getting serviced so could fill up blocking
  // the PJSIP thread, causing a deadlock.
  stop_pjsip_thread();
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

  delete http_stack_sig; http_stack_sig = NULL;
  delete http_stack_mgmt; http_stack_mgmt = NULL;
  delete chronos_connection;
  delete hss_connection;
  delete fifc_service;
  delete sifc_service;
  delete rph_service;
  delete quiescing_mgr;
  delete exception_handler;
  delete load_monitor;
  delete local_sdm;
  delete local_aor_store;
  delete local_data_store;

  for (std::vector<SubscriberDataManager*>::iterator it = remote_sdms.begin();
       it != remote_sdms.end();
       ++it)
  {
    delete *it;
  }
  remote_sdms.clear();

  for (std::vector<AoRStore*>::iterator it = remote_aor_stores.begin();
       it != remote_aor_stores.end();
       ++it)
  {
    delete *it;
  }
  remote_aor_stores.clear();

  for (std::vector<Store*>::iterator it = remote_data_stores.begin();
       it != remote_data_stores.end();
       ++it)
  {
    delete *it;
  }
  remote_data_stores.clear();


  delete local_impi_store;
  delete local_impi_data_store;

  for (ImpiStore* store: remote_impi_stores) { delete store; }
  remote_impi_stores.clear();
  for (Store* store: remote_impi_data_stores) { delete store; }
  remote_impi_data_stores.clear();

  delete ralf_processor;
  delete ralf_connection;
  delete enum_service;
  delete scscf_acr_factory;

  delete sip_resolver;
  delete http_resolver;
  delete astaire_resolver;
  delete dns_resolver;

  delete analytics_logger;

  // Delete Sprout's alarm objects
  delete chronos_comm_monitor;
  delete enum_comm_monitor;
  delete hss_comm_monitor;
  delete astaire_comm_monitor;
  delete remote_astaire_comm_monitor;
  delete ralf_comm_monitor;
  delete alarm_manager;

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
  delete no_shared_ifcs_set_table;

  delete token_rate_table;
  delete smoothed_latency_scalar;
  delete target_latency_scalar;
  delete penalties_scalar;
  delete token_rate_scalar;

  hc->stop_thread();
  delete hc;

  // Unregister the handlers that use semaphores (so we can safely destroy
  // them).
  signal(QUIESCE_SIGNAL, SIG_DFL);
  signal(UNQUIESCE_SIGNAL, SIG_DFL);
  signal(SIGTERM, SIG_DFL);

  sem_destroy(&term_sem);

  return 0;
}

