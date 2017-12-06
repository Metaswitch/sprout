/**
 * @file sprout_pd_definitions.h  Sprout PDLog instances.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef _SPROUT_PD_DEFINITIONS_H__
#define _SPROUT_PD_DEFINITIONS_H__

#include <string>
#include "pdlog.h"


// Defines instances of PDLog for Sprout

// The fields for each PDLog instance contains:
//   Identity - Identifies the log id to be used in the syslog id field.
//   Severity - One of Emergency, Alert, Critical, Error, Warning, Notice,
//              and Info.  Only LOG_ERROR or LOG_NOTICE are used.
//   Message  - Formatted description of the condition.
//   Cause    - The cause of the condition.
//   Effect   - The effect the condition.
//   Action   - A list of one or more actions to take to resolve the condition
//              if it is an error.
static const PDLog2<const char*, const char*> CL_SPROUT_INVALID_PORT_SPROUTLET
(
  PDLogBase::CL_SPROUT_ID + 1,
  LOG_ERR,
  "The %s port specified in /etc/clearwater/ must be in a range from"
  "1 to 65535 but has a value of %s.",
  "The <sproutlet>=<port> port value is outside the permitted range.",
  "The application will exit and restart until the problem is fixed.",
  "Correct the port value.  Typically this is set to 5054."
);

static const PDLog CL_SPROUT_INVALID_SAS_OPTION
(
  PDLogBase::CL_SPROUT_ID + 3,
  LOG_INFO,
  "The sas_server option in /etc/clearwater/config is invalid "
  "or not configured.",
  "The interface to the SAS is not specified.",
  "No call traces will appear in the SAS.",
  "Set the fully qualified SAS hostname for the sas_server=<host> option. "
);

static const PDLog1<const char*> CL_SPROUT_CRASH
(
  PDLogBase::CL_SPROUT_ID + 4,
  LOG_ERR,
  "Fatal - The application has exited or crashed with signal %s.",
  "The application has encountered a fatal software error or has "
  "been terminated.",
  "The application will exit and restart until the problem is fixed.",
  "Ensure that the node has been installed correctly and that it "
  "has valid configuration."
);

static const PDLog CL_SPROUT_STARTED
(
  PDLogBase::CL_SPROUT_ID + 5,
  LOG_ERR,
  "Application started.",
  "The application is starting.",
  "Normal.",
  "None."
);

static const PDLog CL_SPROUT_NO_SI_CSCF
(
  PDLogBase::CL_SPROUT_ID + 6,
  LOG_NOTICE,
  "The Sprout process is running but not providing I-CSCF, S-CSCF or P-SCSCF functionality.",
  "None of P-CSCF, S-CSCF or I-CSCF were configured in local or shared configuration.",
  "Most Sprout processes act as either a P-CSCF, an S-CSCF or an I-CSCF. "
  "None of P-CSCF, S-CSCF or I-CSCF functionality are enabled for this process.",
  "The P-CSCF is configured by setting the pcscf=<port> option. "
  "The S-CSCF is configured by setting the scscf=<port> option. "
  "The I-CSCF is configured by setting the icscf=<port> option."
);

static const PDLog CL_SPROUT_SI_CSCF_NO_HOMESTEAD
(
  PDLogBase::CL_SPROUT_ID + 7,
  LOG_ERR,
  "Fatal - S/I-CSCF enabled with no Homestead hostname specified in shared "
  "configuration.",
  "The S-CSCF and/or the I-CSCF options (scscf=<port>, icscf=<port>) were "
  "configured in local or shared configuration but no Homestead was "
  "configured.",
  "The application will exit and restart until the problem is fixed.",
  "Set the hs_hostname=<hostname> option in shared configuration."
);

static const PDLog CL_SPROUT_AUTH_NO_HOMESTEAD
(
  PDLogBase::CL_SPROUT_ID + 8,
  LOG_ERR,
  "Fatal - Authentication enabled, but no Homestead hostname specified in "
  "shared configuration.",
  "The hs_hostname was not set in /etc/clearwater/shared_config.",
  "The application will exit and restart until the problem is fixed.",
  "Set the hs_hostname=<hostname> option in shared configuration."
);

static const PDLog CL_SPROUT_XDM_NO_HOMESTEAD
(
  PDLogBase::CL_SPROUT_ID + 9,
  LOG_ERR,
  "Fatal - Homer XDM service is configured but no Homestead hostname specified "
  "in shared configuration.",
  "The hs_hostname was not set in /etc/clearwater/shared_config.",
  "The application will exit and restart until the problem is fixed.",
  "Set the hs_hostname=<hostname> option in shared configuration. "
);

static const PDLog1<const char*> CL_SPROUT_SIP_INIT_INTERFACE_FAIL
(
  PDLogBase::CL_SPROUT_ID + 12,
  LOG_ERR,
  "Fatal - Error initializing SIP interfaces with error %s.",
  "The SIP interfaces could not be started.",
  "The application will exit and restart until the problem is fixed.",
  "(1). Check the /etc/clearwater/config configuration."
  "(2). Check the /etc/clearwater/user_settings configuration."
  "(3). Check the network configuration and status."
);

static const PDLog CL_SPROUT_NO_RALF_CONFIGURED
(
  PDLogBase::CL_SPROUT_ID + 13,
  LOG_ERR,
  "The application did not start a connection to Ralf because "
  "Ralf is not enabled.",
  "Ralf was not configured in the /etc/clearwater/config file.",
  "Billing service will not be available.",
  "Correct the /etc/clearwater/config file if the billing feature is desired. "
);

static const PDLog1<const char*> CL_SPROUT_INIT_SERVICE_ROUTE_FAIL
(
  PDLogBase::CL_SPROUT_ID + 15,
  LOG_ERR,
  "Fatal - Failed to enable the S-CSCF registrar with error %s.",
  "The S-CSCF registar could not be initialized.",
  "The application will exit and restart until the problem is fixed.",
  "The restart should clear the issue."
);

static const PDLog1<const char*> CL_SPROUT_REG_SUBSCRIBER_HAND_FAIL
(
  PDLogBase::CL_SPROUT_ID + 16,
  LOG_ERR,
  "Fatal - Failed to register the SUBSCRIBE handlers with the SIP stack %s.",
  "The application subscription module could not be loaded.",
  "The application will exit and restart until the problem is fixed.",
  "The restart should clear the issue."
);

static const PDLog1<const char*> CL_SPROUT_SIP_STACK_INIT_FAIL
(
  PDLogBase::CL_SPROUT_ID + 19,
  LOG_ERR,
  "Fatal - The SIP stack failed to initialize with error, %s.",
  "The SIP interfaces could not be started.",
  "The application will exit and restart until the problem is fixed.",
  "(1). Check the configuration."
  "(2). Check the network status and configuration."
);

static const PDLog2<const char*, int> CL_SPROUT_HTTP_INTERFACE_FAIL
(
  PDLogBase::CL_SPROUT_ID + 20,
  LOG_ERR,
  "An HTTP interface failed to initialize or start in %s with error %d.",
  "An HTTP interface has failed initialization.",
  "The application will exit and restart until the problem is fixed.",
  "Check the network status and configuration."
);

static const PDLog CL_SPROUT_ENDED
(
  PDLogBase::CL_SPROUT_ID + 21,
  LOG_ERR,
  "The application is ending -- Shutting down.",
  "The application has been terminated by monit or has exited.",
  "Application services are no longer available.",
  "(1). This occurs normally when the application is stopped. "
  "(2). If the application failed to respond to monit queries in a "
  "timely manner, monit restarts the application. "
  " This can occur if the application is busy or unresponsive."
);

static const PDLog2<const char*, int> CL_SPROUT_HTTP_INTERFACE_STOP_FAIL
(
  PDLogBase::CL_SPROUT_ID + 22,
  LOG_ERR,
  "The HTTP interfaces encountered an error when stopping the HTTP stack in "
  "%s with error %d.",
  "When the application was exiting it encountered an error when shutting "
  "down the HTTP stack.",
  "Not critical as the application is exiting anyway.",
  "None."
);

static const PDLog CL_SPROUT_SIP_DEADLOCK
(
  PDLogBase::CL_SPROUT_ID + 24,
  LOG_ERR,
  "Fatal - The application detected a fatal software deadlock "
  "affecting SIP communication.",
  "An internal application software error has been detected.",
  "A SIP interface has failed.",
  "The application will exit and restart until the problem is fixed."
);

static const PDLog2<int, const char*> CL_SPROUT_SIP_UDP_INTERFACE_START_FAIL
(
  PDLogBase::CL_SPROUT_ID + 25,
  LOG_ERR,
  "Failed to start a SIP UDP interface for port %d with error %s.",
  "The application could not start a UDP interface.",
  "This may affect call processing.",
  "(1). Check the configuration. "
  "(2). Check the network status and configuration."
);

static const PDLog2<int, const char*> CL_SPROUT_SIP_TCP_START_FAIL
(
  PDLogBase::CL_SPROUT_ID + 26,
  LOG_ERR,
  "Failed to start a SIP TCP transport for port %d with error %s.",
  "Failed to start a SIP TCP connection.",
  "This may affect call processing.",
  "(1). Check the configuration. "
  "(2). Check the network status and configuration."
);

static const PDLog2<int, const char*> CL_SPROUT_SIP_TCP_SERVICE_START_FAIL
(
  PDLogBase::CL_SPROUT_ID + 27,
  LOG_ERR,
  "Failed to start a SIP TCP service for port %d with error %s.",
  "The application could not start a TCP service.",
  "This may affect call processing.",
  "(1). Check to see that the ports in the "
  "/etc/clearwater/config file do not conflict with any other service. "
  "(2). Check the network status and configuration."
);

static const PDLog1<int> CL_SPROUT_SPROUTLET_END
(
  PDLogBase::CL_SPROUT_ID + 30,
  LOG_ERR,
  "All Sproutlets using port %d have ended.",
  "The Sproutlet services are no longer available.",
  "The application will exit and restart until the problem is fixed.",
  "Ensure that the application has been installed correctly and that it "
  "has valid configuration."
);

static const PDLog1<int> CL_SPROUT_SPROUTLET_AVAIL
(
  PDLogBase::CL_SPROUT_ID + 34,
  LOG_NOTICE,
  "The Sproutlet services on port %d are now available.",
  "The Sproutlet services are now available.",
  "Normal.",
  "None."
);

static const PDLog1<int> CL_SPROUT_SPROUTLET_INIT_FAIL2
(
  PDLogBase::CL_SPROUT_ID + 35,
  LOG_ERR,
  "The Sproutlet services on port %d failed to initialize.",
  "The Sproutlet services are no longer available.",
  "The application will exit and restart until the problem is fixed.",
  "Check the configuration files in /etc/clearwater."
);

static const PDLog CL_SPROUT_PLUGIN_FAILURE
(
  PDLogBase::CL_SPROUT_ID + 38,
  LOG_ERR,
  "One or more plugins failed to load.",
  "The service is no longer available.",
  "The application will exit and restart until the problem is fixed.",
  "Check the configuration in /etc/clearwater/config."
);

static const PDLog1<const char*> CL_SPROUT_ENUM_FILE_MISSING
(
  PDLogBase::CL_SPROUT_ID + 39,
  LOG_ERR,
  "The ENUM file is not present.",
  "Sprout is configured to use file-based ENUM, but the configuration file does not exist.",
  "Sprout will not be able to translate telephone numbers into routable URIs.",
  "Confirm that %s is the correct file to be using. If not, correct /etc/clearwater/shared_config. If so, create it according to the documentation. If you are expecting clearwater-config-manager to be managing this file, check that it is running and that there are no ENT logs relating to it or clearwater-etcd."
);

static const PDLog1<const char*> CL_SPROUT_ENUM_FILE_EMPTY
(
  PDLogBase::CL_SPROUT_ID + 40,
  LOG_ERR,
  "The ENUM file is empty.",
  "Sprout is configured to use file-based ENUM, but the configuration file is empty.",
  "Sprout will not be able to translate telephone numbers into routable URIs.",
  "Confirm that %s is the correct file to be using. If not, correct /etc/clearwater/shared_config. If so, create it according to the documentation. If you are expecting clearwater-config-manager to be managing this file, check that it is running and that there are no ENT logs relating to it or clearwater-etcd."
);

static const PDLog1<const char*> CL_SPROUT_ENUM_FILE_INVALID
(
  PDLogBase::CL_SPROUT_ID + 41,
  LOG_ERR,
  "The ENUM file is invalid.",
  "Sprout is configured to use file-based ENUM, but the configuration file is not correctly formatted.",
  "Sprout will not be able to translate telephone numbers into routable URIs.",
  "Confirm that %s is the correct file to be using. If not, correct /etc/clearwater/shared_config. If so, check that it is a valid and correctly formatted file."
);

static const PDLog CL_SPROUT_SCSCF_FILE_MISSING
(
  PDLogBase::CL_SPROUT_ID + 42,
  LOG_ERR,
  "The file listing S-CSCFs is not present.",
  "Sprout is configured as an I-CSCF, but the /etc/clearwater/s-cscf.json file (defining which S-CSCFs to use) does not exist.",
  "The Sprout I-CSCF will use the default S-CSCF URI only.",
  "If you are expecting clearwater-config-manager to be managing this file, check that it is running and that there are no ENT logs relating to it or clearwater-etcd. If you are managing /etc/clearwater/s-cscf.json manually, follow the documentation to create it."
);

static const PDLog CL_SPROUT_SCSCF_FILE_EMPTY
(
  PDLogBase::CL_SPROUT_ID + 43,
  LOG_ERR,
  "The file listing S-CSCFs is empty.",
  "Sprout is configured as an I-CSCF, but the /etc/clearwater/s-cscf.json file (defining which S-CSCFs to use) is empty.",
  "The Sprout I-CSCF will use the default S-CSCF URI only.",
  "If you are expecting clearwater-config-manager to be managing this file, check that it is running and that there are no ENT logs relating to it or clearwater-etcd. If you are managing /etc/clearwater/s-cscf.json manually, follow the documentation to create it."
);

static const PDLog CL_SPROUT_SCSCF_FILE_INVALID
(
  PDLogBase::CL_SPROUT_ID + 44,
  LOG_ERR,
  "The file listing S-CSCFs is invalid.",
  "Sprout is configured as an I-CSCF, but the /etc/clearwater/s-cscf.json file (defining which S-CSCFs to use) is invalid due to invalid JSON or missing elements.",
  "The Sprout I-CSCF will use the default S-CSCF URI only.",
  "Follow the documentation to create this file correctly."
);

static const PDLog CL_SPROUT_BGCF_FILE_MISSING
(
  PDLogBase::CL_SPROUT_ID + 45,
  LOG_NOTICE,
  "The file listing BGCF routes is not present.",
  "The /etc/clearwater/bgcf.json file, defining which BGCF routes to use, does not exist.",
  "Sprout will not be able to route any calls outside the local deployment.",
  "If you are expecting clearwater-config-manager to be managing this file, check that it is running and that there are no ENT logs relating to it or clearwater-etcd. If you are not expecting clearwater-config-manager to manage this, but are expecting to route calls off-net, follow the documentation to create routes in /etc/clearwater/bgcf.json. Otherwise, no action is needed."
);

static const PDLog CL_SPROUT_BGCF_FILE_EMPTY
(
  PDLogBase::CL_SPROUT_ID + 46,
  LOG_ERR,
  "The file listing BGCF routes is empty.",
  "The /etc/clearwater/bgcf.json file, defining which BGCF routes to use, is empty.",
  "Sprout will not be able to route any calls outside the local deployment.",
  "If you are expecting clearwater-config-manager to be managing this file, check that it is running and that there are no ENT logs relating to it or clearwater-etcd. If you are not expecting clearwater-config-manager to manage this, but are expecting to route calls off-net, follow the documentation to create routes in /etc/clearwater/bgcf.json. Otherwise, delete this empty file."
);

static const PDLog CL_SPROUT_BGCF_FILE_INVALID
(
  PDLogBase::CL_SPROUT_ID + 47,
  LOG_ERR,
  "The file listing BGCF routes is not present or empty.",
  "The /etc/clearwater/bgcf.json file, defining which BGCF routes to use, is not valid (due to invalid JSON or missing elements).",
  "Sprout will not be able to route some or all calls outside the local deployment.",
  "If you are expecting to route calls off-net, follow the documentation to create routes in /etc/clearwater/bgcf.json. Otherwise, delete this file."
);

static const PDLog2<const char *, const char*> CL_SPROUT_SESS_TERM_AS_COMM_FAILURE
(
  PDLogBase::CL_SPROUT_ID + 48,
  LOG_ERR,
  "Sprout is currently unable to successfully communicate with an Application Server that uses session terminated default handling. The server's URI is: %s. Failure reason: %s",
  "Communication is failing to an Application Server",
  "Probable major loss of service. The precise impact will vary depending on the role of this Application Server.",
  "Investigate why communication to this Application Server is failing. It might be due to failure of the AS, misconfiguration of Initial Filter Criteria, or network / DNS problems"
);

static const PDLog1<const char *> CL_SPROUT_SESS_TERM_AS_COMM_SUCCESS
(
  PDLogBase::CL_SPROUT_ID + 49,
  LOG_NOTICE,
  "Sprout is able to successfully communicate with an Application Server that uses session terminated default handling. ",
  "Communication has been restored to an Application Server",
  "Full service has been restored.",
  "No action"
);

static const PDLog2<const char *, const char*> CL_SPROUT_SESS_CONT_AS_COMM_FAILURE
(
  PDLogBase::CL_SPROUT_ID + 50,
  LOG_ERR,
  "Sprout is currently unable to successfully communicate with an Application Server that uses session continued default handling. The server's URI is %s. Failure reason: %s",
  "Communication is failing to an Application server",
  "The service(s) provided by this Application Server will be unavailable until communication is restored. In addition, call setup time will likely be increased for all subscribers configured to use this Application Server.",
  "Investigate why communication to this Application Server is failing. It might be due to failure of the AS, misconfiguration of Initial Filter Criteria, or network / DNS problems"
);

static const PDLog1<const char *> CL_SPROUT_SESS_CONT_AS_COMM_SUCCESS
(
  PDLogBase::CL_SPROUT_ID + 51,
  LOG_NOTICE,
  "Sprout is able to successfully communicate with an Application Server that uses session continued default handling.",
  "Communication has been restored to an Application Server",
  "Full service has been restored.",
  "No action"
);

static const PDLog CL_SPROUT_SIFC_FILE_MISSING
(
  PDLogBase::CL_SPROUT_ID + 52,
  LOG_ERR,
  "The shared iFC sets file is not present.",
  "The S-CSCF supports shared iFC sets, but the configuration file for this does not exist.",
  "The S-CSCF will not be able to correctly translate IDs in Service Profiles sent from the HSS into Initial Filter Criteria.",
  "The shared iFC sets should be defined in /etc/clearwater/shared_ifcs.xml. Create this file according to the documentation. If you are expecting clearwater-config-manager to be managing this file, check that it is running and that there are no ENT logs relating to it or clearwater-etcd."
);

static const PDLog CL_SPROUT_SIFC_FILE_EMPTY
(
  PDLogBase::CL_SPROUT_ID + 53,
  LOG_ERR,
  "The shared iFC sets file is empty.",
  "The S-CSCF supports shared iFC sets, but the configuration file for this is empty.",
  "The S-CSCF will not be able to correctly translate IDs in Service Profiles sent from the HSS into Initial Filter Criteria.",
  "The shared iFC sets should be defined in /etc/clearwater/shared_ifcs.xml. Populate this file according to the documentation."
);

static const PDLog CL_SPROUT_SIFC_FILE_INVALID_XML
(
  PDLogBase::CL_SPROUT_ID + 54,
  LOG_ERR,
  "The shared iFC sets file contains invalid XML.",
  "The S-CSCF supports shared iFC sets, but the configuration file for this is invalid.",
  "The S-CSCF will not be able to correctly translate IDs in Service Profiles sent from the HSS into Initial Filter Criteria.",
  "The shared iFC sets should be defined in /etc/clearwater/shared_ifcs.xml. Populate this file according to the documentation."
);

static const PDLog CL_SPROUT_SIFC_FILE_MISSING_SHARED_IFCS_SETS
(
  PDLogBase::CL_SPROUT_ID + 55,
  LOG_ERR,
  "The shared iFCs file doesn't have the correct syntax.",
  "The S-CSCF supports shared iFC sets, but the configuration file for this doesn't match the expected syntax (no SharedIFCsSets block).",
  "The S-CSCF will not be able to correctly translate IDs in Service Profiles sent from the HSS into Initial Filter Criteria.",
  "The shared iFCs should be defined in /etc/clearwater/shared_ifcs.xml. Populate this file according to the documentation."
);

static const PDLog CL_SPROUT_SIFC_FILE_MISSING_SET_ID
(
  PDLogBase::CL_SPROUT_ID + 56,
  LOG_ERR,
  "An entry in the shared iFC file doesn't have the correct syntax; it's missing the SetID.",
  "The S-CSCF supports shared iFC sets, but one of the shared iFC sets in the configuration file for this doesn't match the expected syntax (no SetID).",
  "The S-CSCF will not be able to correctly translate some IDs in Service Profiles sent from the HSS into Initial Filter Criteria.",
  "The shared iFCs should be defined in /etc/clearwater/shared_ifcs.xml. Populate this file according to the documentation."
);

static const PDLog1<const char *> CL_SPROUT_SIFC_FILE_INVALID_SET_ID
(
  PDLogBase::CL_SPROUT_ID + 57,
  LOG_ERR,
  "An entry in the shared iFCs file doesn't have the correct syntax; its SetID (%s) isn't an integer.",
  "The S-CSCF supports shared iFC sets, but one of the shared iFC sets in the configuration file for this doesn't match the expected syntax (invalid SetID).",
  "The S-CSCF will not be able to correctly translate some IDs in Service Profiles sent from the HSS into Initial Filter Criteria.",
  "The shared iFCs should be defined in /etc/clearwater/shared_ifcs.xml. Populate this file according to the documentation."
);

static const PDLog1<const char *> CL_SPROUT_SIFC_FILE_REPEATED_SET_ID
(
  PDLogBase::CL_SPROUT_ID + 58,
  LOG_ERR,
  "Multiple entries in the shared iFC sets file use the same SetID (%s)(",
  "The S-CSCF supports shared iFC sets, but the configuration file for this has multiple entries for one ID.",
  "The S-CSCF will not be able to correctly translate some IDs in Service Profiles sent from the HSS into Initial Filter Criteria.",
  "The shared iFC sets should be defined in /etc/clearwater/shared_ifcs.xml. Populate this file according to the documentation."
);

static const PDLog1<const char *> CL_SPROUT_SIFC_FILE_INVALID_PRIORITY
(
  PDLogBase::CL_SPROUT_ID + 59,
  LOG_ERR,
  "An entry in the shared iFC sets file doesn't have the correct syntax; its Priority (%s) isn't an integer.",
  "The S-CSCF supports shared iFC sets, but one of the shared iFC sets in the configuration file for this doesn't match the expected syntax (invalid Priority).",
  "The S-CSCF will not be able to correctly translate some IDs in Service Profiles sent from the HSS into Initial Filter Criteria.",
  "The shared iFC sets should be defined in /etc/clearwater/shared_ifcs.xml. Populate this file according to the documentation."
);

static const PDLog CL_SPROUT_FIFC_FILE_MISSING
(
  PDLogBase::CL_SPROUT_ID + 60,
  LOG_ERR,
  "The fallback iFCs configuration file is not present.",
  "The S-CSCF supports fallback iFCs, but the configuration file for them does not exist.",
  "The S-CSCF will not be able to correctly apply any fallback iFCs.",
  "The fallback iFCs should be defined in /etc/clearwater/fallback_ifcs.xml. Create this file according to the documentation. If you are expecting clearwater-config-manager to be managing this file, check that it is running and that there are no ENT logs relating to it or clearwater-etcd."
);

static const PDLog CL_SPROUT_FIFC_FILE_EMPTY
(
  PDLogBase::CL_SPROUT_ID + 61,
  LOG_ERR,
  "The fallback iFCs configuration file is empty.",
  "The S-CSCF supports fallback iFCs, but the configuration file for this is empty.",
  "The S-CSCF will not be able to correctly apply any fallback iFCs.",
  "The fallback iFCs should be defined in /etc/clearwater/fallback_ifcs.xml. Populate this file according to the documentation."
);

static const PDLog CL_SPROUT_FIFC_FILE_INVALID_XML
(
  PDLogBase::CL_SPROUT_ID + 62,
  LOG_ERR,
  "The fallback iFCs configuration file contains invalid XML.",
  "The S-CSCF supports fallback iFCs, but the configuration file for this is invalid.",
  "The S-CSCF will not be able to correctly apply any fallback iFCs.",
  "The fallback iFCs should be defined in /etc/clearwater/fallback_ifcs.xml. Populate this file according to the documentation."
);

static const PDLog CL_SPROUT_FIFC_FILE_MISSING_FALLBACK_IFCS_SET
(
 PDLogBase::CL_SPROUT_ID + 63,
 LOG_ERR,
 "The fallback iFCs configuration file doesn't have the correct syntax.",
 "The S-CSCF supports fallback iFCs, but the configuration file for this doesn't match the expected syntax (no FallbackIFCsSet block).",
 "The S-CSCF will not be able to correctly apply any fallback iFCs.",
 "The fallback iFCs should be defined in /etc/clearwater/fallback_ifcs.xml. Populate this file according to the documentation."
 );

static const PDLog1<const char *> CL_SPROUT_FIFC_FILE_INVALID_PRIORITY
(
  PDLogBase::CL_SPROUT_ID + 64,
  LOG_ERR,
  "An iFC in the fallback iFCs configuration file doesn't have the correct syntax; its Priority (%s) isn't an integer.",
  "The S-CSCF supports fallback iFCs, but one of the fallback iFCs doesn't match the expected syntax (invalid Priority).",
  "The S-CSCF will not be able to apply this fallback iFC.",
  "The fallback iFCs should be defined in /etc/clearwater/fallback_ifcs.xml. Populate this file according to the documentation."
);

static const PDLog1<const char *> CL_SPROUT_ORIG_PARTY_BARRED
(
  PDLogBase::CL_SPROUT_ID + 65,
  LOG_NOTICE,
  "An originating call has been barred",
  "An originating call from subscriber (%s) has been rejected with a 403 Forbidden because they are barred.",
  "Normal",
  "None"
);

static const PDLog1<const char *> CL_SPROUT_TERM_PARTY_BARRED
(
  PDLogBase::CL_SPROUT_ID + 66,
  LOG_NOTICE,
  "An originating call has been barred",
  "An originating call from subscriber (%s) has been rejected with a 404 Not Found because they are barred.",
  "Normal",
  "None"
);

static const PDLog CL_SPROUT_RPH_FILE_MISSING
(
  PDLogBase::CL_SPROUT_ID + 67,
  LOG_ERR,
  "The RPH file is not present.",
  "The S-CSCF supports message prioritization based on the Resource-Priority header, but the configuration file for this does not exist.",
  "The S-CSCF will not be able to prioritize messages based on a Resource-Priority header.",
  "The RPH configuration should be defined in /etc/clearwater/rph.json. Create this file according to the documentation. If you are expecting clearwater-config-manager to be managing this file, check that it is running and that there are no ENT logs relating to it or clearwater-etcd."
);

static const PDLog CL_SPROUT_RPH_FILE_EMPTY
(
  PDLogBase::CL_SPROUT_ID + 68,
  LOG_ERR,
  "The RPH file is empty.",
  "The S-CSCF supports message prioritization based on the Resource-Priority header, but the configuration file for this is empty.",
  "The S-CSCF will not be able to prioritize messages based on a Resource-Priority header.",
  "The RPH configuration should be defined in /etc/clearwater/rph.json. Populate this file according to the documentation."
);

static const PDLog CL_SPROUT_RPH_FILE_INVALID
(
  PDLogBase::CL_SPROUT_ID + 69,
  LOG_ERR,

  "The RPH file contains invalid JSON.",
  "The S-CSCF supports message prioritization based on the Resource-Priority header, but the configuration file for this is invalid.",
  "The S-CSCF will not be able to prioritize messages based on a Resource-Priority header.",
  "The RPH configuration should be defined in /etc/clearwater/rph.json. Populate this file according to the documentation."
);

static const PDLog CL_SPROUT_RPH_FILE_INVALID_CONFIG
(
  PDLogBase::CL_SPROUT_ID + 70,
  LOG_ERR,

  "The RPH file contains invalid configuration.",
  "The S-CSCF supports message prioritization based on the Resource-Priority header, but the configuration file contains invalid configuration.",
  "The S-CSCF will not be able to prioritize messages based on a Resource-Priority header.",
  "The RPH configuration should be defined in /etc/clearwater/rph.json. Populate this file according to the documentation."
);

#endif
