/**
 * @file sprout_pd_definitions.h  Sprout PDLog instances.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2014  Metaswitch Networks Ltd
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

#ifndef _SPROUT_PD_DEFINITIONS_H__
#define _SPROUT_PD_DEFINITIONS_H__

#include <string>
#include "pdlog.h"


// Defines instances of PDLog for Sprout

// The fields for each PDLog instance contains:
//   Identity - Identifies the log id to be used in the syslog id field.
//   Severity - One of Emergency, Alert, Critical, Error, Warning, Notice, 
//              and Info.  Directly corresponds to the syslog severity types.
//              Only PDLOG_ERROR or PDLOG_NOTICE are used.  
//              See syslog_facade.h for definitions.
//   Message  - Formatted description of the condition.
//   Cause    - The cause of the condition.
//   Effect   - The effect the condition.
//   Action   - A list of one or more actions to take to resolve the condition 
//              if it is an error.
static const PDLog1<const char*> CL_SPROUT_INVALID_S_CSCF_PORT
(
  PDLogBase::CL_SPROUT_ID + 1,
  PDLOG_ERR,
  "The S-CSCF port specified in /etc/clearwater/config must be in a range from"
  "1 to 65535 but has a value of %s.",
  "The scscf=<port> port value is outside the permitted range.",
  "The application will exit and restart until the problem is fixed.",
  "Correct the port value.  Typically this is set to 5054."
);

static const PDLog1<const char*> CL_SPROUT_INVALID_I_CSCF_PORT
(
  PDLogBase::CL_SPROUT_ID + 2,
  PDLOG_ERR,
  "Fatal - The I-CSCF port specified in /etc/clearwater/config "
  "must be in a range "
  "from 1 to 65535 but has a value of %s.",
  "The icscf=<port> value is outside the permitted range.",
  "The application will exit and restart until the problem is fixed.",
  "Correct the port value.  Typically this is set to 5052."
);

static const PDLog CL_SPROUT_INVALID_SAS_OPTION
(
  PDLogBase::CL_SPROUT_ID + 3,
  PDLOG_INFO,
  "The sas_server option in /etc/clearwater/config is invalid "
  "or not configured.",
  "The interface to the SAS is not specified.",
  "No call traces will appear in the SAS.",
  "Set the fully qualified SAS hostname for the sas_server=<host> option. "
);

static const PDLog1<const char*> CL_SPROUT_CRASH
(
  PDLogBase::CL_SPROUT_ID + 4,
  PDLOG_ERR,
  "Fatal - The application has exited or crashed with signal %s.",
  "The application has encountered a fatal software error or has "
  "been terminated.",
  "The application will restart.",
  "This error can occur if The application has been terminated by "
  "operator command. "
  "Check your installation and configuration for other types of crashes."
);

static const PDLog CL_SPROUT_STARTED
(
  PDLogBase::CL_SPROUT_ID + 5,
  PDLOG_ERR,
  "Application started.",
  "The application is starting.",
  "Normal.",
  "None."
);

static const PDLog CL_SPROUT_NO_SI_CSCF
(
  PDLogBase::CL_SPROUT_ID + 6,
  PDLOG_ERR,
  "Fatal - Must enable P-CSCF, S-CSCF or I-CSCF in /etc/clearwater/config.",
  "Neither a P-CSCF, S-CSCF nor an I-CSCF was configured in "
  "/etc/clearwater/config.",
  "The application will exit and restart until the problem is fixed.",
  "The P-CSCF is configured by setting the pcscf=<port> option. "
  "The S-CSCF is configured by setting the scscf=<port> option. "
  "The I-CSCF is configured by setting the icscf=<port> option."
);

static const PDLog CL_SPROUT_SI_CSCF_NO_HOMESTEAD
(
  PDLogBase::CL_SPROUT_ID + 7,
  PDLOG_ERR,
  "Fatal - S/I-CSCF enabled with no Homestead server specified in "
  "/etc/clearwater/config.",
  "The S-CSCF and/or the I-CSCF options (scscf=<port>, icscf=<port>) "
  "were configured in the /etc/clearwater/config file but no Homestead "
  "was configured in the same file.",
  "The application will exit and restart until the problem is fixed.",
  "Set the hs_hostname=<hostname> option in the "
  "/etc/clearwater/config file. "
);

static const PDLog CL_SPROUT_AUTH_NO_HOMESTEAD
(
  PDLogBase::CL_SPROUT_ID + 8,
  PDLOG_ERR,
  "Fatal - Authentication enabled, but no Homestead server specified in "
  "/etc/clearwater/config.",
  "The hs_hostname was not set in the /etc/clearwater/config file.",
  "The application will exit and restart until the problem is fixed.",
  "Set the hs_hostname=<hostname> option in the "
  "/etc/clearwater/config file. "
);

static const PDLog CL_SPROUT_XDM_NO_HOMESTEAD
(
  PDLogBase::CL_SPROUT_ID + 9,
  PDLOG_ERR,
  "Fatal - Homer XDM service is configured but no Homestead server specified "
  "in /etc/clearwater/config.",
  "The hs_hostname was not set in the /etc/clearwater/config file.",
  "The application will exit and restart until the problem is fixed.",
  "Set the hs_hostname=<hostname> option in the "
  "/etc/clearwater/config file. "
);

static const PDLog CL_SPROUT_S_CSCF_NO_CHRONOS
(
  PDLogBase::CL_SPROUT_ID + 10,
  PDLOG_ERR,
  "Fatal - S-CSCF and I-CSCF enabled with no Chronos service specified in "
  "/etc/clearwater/config.",
  "The chronos_hostname=<host:port> was not set in /etc/clearwater/config.",
  "The application will exit and restart until the problem is fixed.",
  "Set the chronos_hostname=<host:port> option in the /etc/clearwater/config. "
);

static const PDLog CL_SPROUT_BAD_S_CSCF_JSON
(
  PDLogBase::CL_SPROUT_ID + 11,
  PDLOG_ERR,
  "Fatal - Missing or malformed /etc/clearwater/s-cscf.json file.",
  "The s-cscf.json file must be corrected or created to provide "
  "S-CSCF service.",
  "This prevents the I-CSCF from selecting an S-CSCF.",
  "Correct or add the /etc/clearwater/s-cscf.json file "
  "and restart Sprout."
);

static const PDLog1<const char*> CL_SPROUT_SIP_INIT_INTERFACE_FAIL
(
  PDLogBase::CL_SPROUT_ID + 12,
  PDLOG_ERR,
  "Fatal - Error initializing sip interfaces with error %s.",
  "The SIP interfaces could not be started.",
  "The application will exit and restart until the problem is fixed.",
  "(1). Check the /etc/clearwater/config configuration."
  "(2). Check the /etc/clearwater/user_settings configuration."
  "(3). Check the network configuration and status." 
);

static const PDLog CL_SPROUT_NO_RALF_CONFIGURED
(
  PDLogBase::CL_SPROUT_ID + 13,
  PDLOG_ERR,
  "The application did not start a connection to Ralf because "
  "Ralf is not enabled.",
  "Ralf was not configured in the /etc/clearwater/config file.",
  "Billing service will not be available.",
  "Correct the /etc/clearwater/config file if the billing feature is desired. "
);

static const PDLog CL_SPROUT_MEMCACHE_CONN_FAIL
(
  PDLogBase::CL_SPROUT_ID + 14,
  PDLOG_ERR,
  "Fatal - Failed to connect to the memcached data store.",
  "The connection to the local store could not be created.",
  "The application will exit and restart until the problem is fixed.",
  "(1).Check to see if the memcached is running using ps -ef | grep memcached."
  "(2). If not, try starting the memcached by entering the command sudo "
  "service memcached start. "
  "(3). Restart the node to see if the problem clears."
);

static const PDLog1<const char*> CL_SPROUT_INIT_SERVICE_ROUTE_FAIL
(
  PDLogBase::CL_SPROUT_ID + 15,
  PDLOG_ERR,
  "Fatal - Failed to enable the S-CSCF registrar with error %s.",
  "The S-CSCF registar could not be initialized.",
  "The application will exit and restart until the problem is fixed.",
  "Check the configuration in /etc/clearwater/config."
);

static const PDLog1<const char*> CL_SPROUT_REG_SUBSCRIBER_HAND_FAIL
(
  PDLogBase::CL_SPROUT_ID + 16,
  PDLOG_ERR,
  "Fatal - Failed to register the SUBSCRIBE handlers with the SIP stack %s.",
  "The Application subscription module could not be loaded.",
  "The application will exit and restart until the problem is fixed.",
  "The restart should clear the issue."
);

static const PDLog CL_SPROUT_S_CSCF_INIT_FAIL
(
  PDLogBase::CL_SPROUT_ID + 17,
  PDLOG_ERR,
  "Fatal - The S-CSCF service failed to initialize.",
  "The S-CSCF did not initialize.",
  "The S-CSCF proxy is not enabled.",
  "(1). Check the configuration in the /etc/clearwater/config and correct."
  "(2). Check the configuration in the /etc/clearwater/s-cscf.json and correct"
);

static const PDLog CL_SPROUT_I_CSCF_INIT_FAIL
(
  PDLogBase::CL_SPROUT_ID + 18,
  PDLOG_ERR,
  "Fatal - The I-CSCF service failed to initialize.",
  "The I-CSCF service did not initialize.",
  "The application will exit and restart until the problem is fixed.",
  "Check the configuration in /etc/clearwater/config"
);

static const PDLog1<const char*> CL_SPROUT_SIP_STACK_INIT_FAIL
(
  PDLogBase::CL_SPROUT_ID + 19,
  PDLOG_ERR,
  "Fatal - The SIP stack failed to initialize with error, %s.",
  "The SIP interfaces could not be started.",
  "The application will exit and restart until the problem is fixed.",
  "(1). Check the configuration on Sprout."
  "(2). Check the network status and configuration on Sprout."
);

static const PDLog2<const char*, int> CL_SPROUT_HTTP_INTERFACE_FAIL
(
  PDLogBase::CL_SPROUT_ID + 20,
  PDLOG_ERR,
  "An HTTP interface failed to initialize or start in %s with error %d.",
  "An HTTP interface has failed initialization.",
  "The timeout handlers for the application could not be registered "
  "with Chronos if the interface is for Chronos. "
  "Requests to Homestead are affected if the interface is for Homestead.",
  "(1). Check the configuration in /etc/clearwater/config for hs_hostname "
  " and chronos_hostname."
  "(2). Insure that Homestead and Chronos are both running."
  "(3). Check the network status and configuration." 
);

static const PDLog CL_SPROUT_ENDED
(
  PDLogBase::CL_SPROUT_ID + 21,
  PDLOG_ERR,
  "The application is ending -- Shutting down.",
  "The application has been terminated by Monit or has exited.",
  "Application services are no longer available.",
  "(1). This occurs normally when Sprout is stopped. "
  "(2). If the Application failed to respond to Monit queries in a "
  "timely manner, Monit restarts the application. "
  " This can occur if the application is busy or unresponsive."
);

static const PDLog2<const char*, int> CL_SPROUT_HTTP_INTERFACE_STOP_FAIL
(
  PDLogBase::CL_SPROUT_ID + 22,
  PDLOG_ERR,
  "The HTTP interfaces encountered an error when stopping the HTTP stack in "
  "%s with error %d.",
  "When the Application was exiting it encountered an error when shutting "
  "down the HTTP stack.",
  "Not critical as the Application is exiting anyway.",
  "None."
);

static const PDLog2<const char*, const char*> CL_SPROUT_SIP_SEND_REQUEST_ERR
(
  PDLogBase::CL_SPROUT_ID + 23,
  PDLOG_ERR,
  "Failed to send SIP request to %s with error %s.",
  "An attempt to send a SIP request failed.",
  "This may cause a call to fail.",
  "If the problem persists check the network connectivity."
);

static const PDLog CL_SPROUT_SIP_DEADLOCK
(
  PDLogBase::CL_SPROUT_ID + 24,
  PDLOG_ERR,
  "Fatal - The Application detected a fatal software deadlock "
  "affecting SIP communication.",
  "An internal Application software error has been detected.",
  "A SIP interface has failed.",
  "The Sprout node should automatically be restarted and the problem cleared."
);

static const PDLog2<int, const char*> CL_SPROUT_SIP_UDP_INTERFACE_START_FAIL
(
  PDLogBase::CL_SPROUT_ID + 25,
  PDLOG_ERR,
  "Failed to start a SIP UDP interface for port %d with error %s.",
  "The Application could not start a UDP interface.",
  "This may affect call processing.",
  "(1). Check the configuration. "
  "(2). Check the network status and configuration."
);

static const PDLog2<int, const char*> CL_SPROUT_SIP_TCP_START_FAIL
(
  PDLogBase::CL_SPROUT_ID + 26,
  PDLOG_ERR,
  "Failed to start a SIP TCP transport for port %d with error %s.",
  "Failed to start a SIP TCP connection.",
  "This may affect call processing.",
  "(1). Check the configuration. "
  "(2). Check the network status and configration."
);

static const PDLog2<int, const char*> CL_SPROUT_SIP_TCP_SERVICE_START_FAIL
(
  PDLogBase::CL_SPROUT_ID + 27,
  PDLOG_ERR,
  "Failed to start a SIP TCP service for port %d with error %s.",
  "The Application could not start a TCP service.",
  "This may affect call processing.",
  "(1). Check to see that the scscf_port or icscf_port in the "
  "/etc/clearwater/config file do not conflict with any other service. "
  "(2). Check the network status and configuration."
);

static const PDLog CL_SPROUT_BGCF_INIT_FAIL
(
  PDLogBase::CL_SPROUT_ID + 28,
  PDLOG_ERR,
  "Failed to start BGCF service.",
  "The Application could not start the BGCF service.",
  "This may affect call processing.",
  "Check the BGCF configuration in /etc/clearwater/bgcf.json "
  "if the feature is desired. "
);

static const PDLog1<int> CL_SPROUT_S_CSCF_END
(
  PDLogBase::CL_SPROUT_ID + 30,
  PDLOG_ERR,
  "The S-CSCF service on port %d has ended.",
  "The S-CSCF service is no longer available.",
  "Call processing is no longer available.",
  "Monit will restart the application unless Sprout has been stopped. "
);

static const PDLog1<int> CL_SPROUT_I_CSCF_END
(
  PDLogBase::CL_SPROUT_ID + 31,
  PDLOG_ERR,
  "The I-CSCF service on port %d has ended.",
  "The I-CSCF service is no longer available.",
  "Call processing is no longer available.",
  "Monit will restart Sprout unless Sprout has been stopped. "
);

static const PDLog1<int> CL_SPROUT_S_CSCF_AVAIL
(
  PDLogBase::CL_SPROUT_ID + 34,
  PDLOG_NOTICE,
  "The S-CSCF service on port %d is now available.",
  "The S-CSCF service is now available.",
  "Normal.",
  "None."
);

static const PDLog1<int> CL_SPROUT_S_CSCF_INIT_FAIL2
(
  PDLogBase::CL_SPROUT_ID + 35,
  PDLOG_ERR,
  "The S-CSCF service on port %d failed to initialize.",
  "The S-CSCF service is no longer available.",
  "Call processing is no longer available.",
  "Monit will restart Sprout unless Sprout has been stopped. "
);

static const PDLog1<int> CL_SPROUT_I_CSCF_AVAIL
(
  PDLogBase::CL_SPROUT_ID + 36,
  PDLOG_NOTICE,
  "The I-CSCF service on port %d is now available.",
  "The I-CSCF service is now available.",
  "Normal.",
  "None."
);

static const PDLog1<int> CL_SPROUT_I_CSCF_INIT_FAIL2
(
  PDLogBase::CL_SPROUT_ID + 37,
  PDLOG_ERR,
  "The I-CSCF service on port %d failed to initialize.",
  "The I-CSCF service is no longer available.",
  "Call processing is no longer available.",
  "Check the Sprout configuration."
);

#endif
