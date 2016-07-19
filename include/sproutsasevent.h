/**
 * @file sproutsasevent.h Sprout-specific SAS event IDs
 *
 * project clearwater - ims in the cloud
 * copyright (c) 2013  metaswitch networks ltd
 *
 * this program is free software: you can redistribute it and/or modify it
 * under the terms of the gnu general public license as published by the
 * free software foundation, either version 3 of the license, or (at your
 * option) any later version, along with the "special exception" for use of
 * the program along with ssl, set forth below. this program is distributed
 * in the hope that it will be useful, but without any warranty;
 * without even the implied warranty of merchantability or fitness for
 * a particular purpose.  see the gnu general public license for more
 * details. you should have received a copy of the gnu general public
 * license along with this program.  if not, see
 * <http://www.gnu.org/licenses/>.
 *
 * the author can be reached by email at clearwater@metaswitch.com or by
 * post at metaswitch networks ltd, 100 church st, enfield en2 6bq, uk
 *
 * special exception
 * metaswitch networks ltd  grants you permission to copy, modify,
 * propagate, and distribute a work formed by combining openssl with the
 * software, or a work derivative of such a combination, even if such
 * copying, modification, propagation, or distribution would otherwise
 * violate the terms of the gpl. you must comply with the gpl in all
 * respects for all of the code used other than openssl.
 * "openssl" means openssl toolkit software distributed by the openssl
 * project and licensed under the openssl licenses, or a work based on such
 * software and licensed under the openssl licenses.
 * "openssl licenses" means the openssl license and original ssleay license
 * under which the openssl project distributes the openssl toolkit software,
 * as those licenses appear in the file license-openssl.
 */

#ifndef SPROUTSASEVENT_H__
#define SPROUTSASEVENT_H__

#include "sasevent.h"

namespace SASEvent
{
  //----------------------------------------------------------------------------
  // Sprout events.
  //----------------------------------------------------------------------------
  const int ENUM_START = SPROUT_BASE + 0x000000;
  const int ENUM_MATCH = SPROUT_BASE + 0x000001;
  const int ENUM_INCOMPLETE = SPROUT_BASE + 0x000002;
  const int ENUM_COMPLETE = SPROUT_BASE + 0x000003;
  const int TX_ENUM_REQ = SPROUT_BASE + 0x000004;
  const int RX_ENUM_RSP = SPROUT_BASE + 0x000005;
  const int RX_ENUM_ERR = SPROUT_BASE + 0x000006;
  const int ENUM_NOT_ENABLED = SPROUT_BASE + 0x000007;
  const int ENUM_INVALID = SPROUT_BASE + 0x000008;
  const int SIP_URI_FROM_ENUM = SPROUT_BASE + 0x000009;
  const int NP_DATA_FROM_ENUM = SPROUT_BASE + 0x00000A;
  const int NP_DATA_FROM_ENUM_IGNORING_NPDI = SPROUT_BASE + 0x00000B;
  const int IGNORED_NP_DATA_FROM_ENUM = SPROUT_BASE + 0x00000C;
  const int NON_SIP_URI_FROM_ENUM = SPROUT_BASE + 0x00000D;

  const int BGCF_FOUND_ROUTE_DOMAIN = SPROUT_BASE + 0x000010;
  const int BGCF_DEFAULT_ROUTE_DOMAIN = SPROUT_BASE + 0x000011;
  const int BGCF_NO_ROUTE_DOMAIN = SPROUT_BASE + 0x000012;
  const int BGCF_FOUND_ROUTE_NUMBER = SPROUT_BASE + 0x000013;
  const int BGCF_NO_ROUTE_NUMBER = SPROUT_BASE + 0x000014;

  const int SCSCF_NONE_CONFIGURED = SPROUT_BASE + 0x000020;
  const int SCSCF_NONE_VALID = SPROUT_BASE + 0x000021;
  const int SCSCF_SELECTED = SPROUT_BASE + 0x000022;
  const int SCSCF_SELECTION_SUCCESS = SPROUT_BASE + 0x000023;
  const int SCSCF_RETRY = SPROUT_BASE + 0x000024;
  const int SCSCF_SELECTION_FAILED = SPROUT_BASE + 0x000025;
  const int SCSCF_ODI_INVALID = SPROUT_BASE + 0x000026;
  const int SCSCF_ICSCF_LOOP_DETECTED = SPROUT_BASE + 0x000027;
  const int SCSCF_NO_BINDINGS = SPROUT_BASE + 0x000028;
  const int SCSCF_NOT_REGISTERED = SPROUT_BASE + 0x000029;

  const int PHONE_ROUTING_TO_BGCF = SPROUT_BASE + 0x00002E;
  const int OFFNET_ROUTING_TO_BGCF = SPROUT_BASE + 0x00002F;

  const int SIPRESOLVE_START = SPROUT_BASE + 0x000030;
  const int SIPRESOLVE_PORT_A_LOOKUP = SPROUT_BASE + 0x000031;
  const int SIPRESOLVE_NAPTR_LOOKUP = SPROUT_BASE + 0x000032;
  const int SIPRESOLVE_NAPTR_SUCCESS_SRV = SPROUT_BASE + 0x000033;
  const int SIPRESOLVE_NAPTR_SUCCESS_A = SPROUT_BASE + 0x000034;
  const int SIPRESOLVE_NAPTR_FAILURE = SPROUT_BASE + 0x000035;
  const int SIPRESOLVE_TRANSPORT_SRV_LOOKUP = SPROUT_BASE + 0x000036;
  const int SIPRESOLVE_SRV_LOOKUP = SPROUT_BASE + 0x000037;
  const int SIPRESOLVE_A_LOOKUP = SPROUT_BASE + 0x000038;
  const int SIPRESOLVE_IP_ADDRESS = SPROUT_BASE + 0x000039;

  const int AUTHENTICATION_FAILED_OVERLOAD = SPROUT_BASE + 0x000041;
  const int AUTHENTICATION_FAILED = SPROUT_BASE + 0x000042;
  const int AUTHENTICATION_SUCCESS = SPROUT_BASE + 0x000043;
  const int AUTHENTICATION_CHALLENGE_AKA = SPROUT_BASE + 0x000044;
  const int AUTHENTICATION_CHALLENGE_DIGEST = SPROUT_BASE + 0x000045;
  const int AUTHENTICATION_FAILED_MALFORMED = SPROUT_BASE + 0x000046;
  const int AUTHENTICATION_NOT_NEEDED_PROXY_AUTHORIZATION = SPROUT_BASE + 0x000047;
  const int AUTHENTICATION_NOT_NEEDED_EMERGENCY_REGISTER = SPROUT_BASE + 0x000048;
  const int AUTHENTICATION_NOT_NEEDED_INTEGRITY_PROTECTED = SPROUT_BASE + 0x000049;
  const int AUTHENTICATION_TIMER_POP_IGNORED = SPROUT_BASE + 0x00004A;
  const int AUTHENTICATION_FAILED_NO_AV = SPROUT_BASE + 0x00004B;
  const int AUTHENTICATION_NEEDED_PROXY_AUTHORIZATION = SPROUT_BASE + 0x00004C;
  const int AUTHENTICATION_NOT_NEEDED_NEVER_AUTH_NON_REG = SPROUT_BASE + 0x00004D;

  const int SUBSCRIBE_START = SPROUT_BASE + 0x000050;
  const int SUBSCRIBE_FAILED = SPROUT_BASE + 0x000051;
  const int SUBSCRIBE_FAILED_EARLY_URLSCHEME = SPROUT_BASE + 0x000052;
  const int SUBSCRIBE_FAILED_EARLY_DOMAIN = SPROUT_BASE + 0x000053;
  const int SUBSCRIBE_FAILED_EARLY_EMERGENCY = SPROUT_BASE + 0x000054;
  const int SUBSCRIBE_FAILED_EARLY_ACCEPT = SPROUT_BASE + 0x000055;
  const int SUBSCRIBE_FAILED_EARLY_EVENT = SPROUT_BASE + 0x000056;

  const int NOTIFICATION_FAILED = SPROUT_BASE + 0x000060;

  const int REGSTORE_GET_FOUND = SPROUT_BASE + 0x000070;
  const int REGSTORE_GET_NEW = SPROUT_BASE + 0x000071;
  const int REGSTORE_GET_FAILURE = SPROUT_BASE + 0x000072;
  const int REGSTORE_SET_START = SPROUT_BASE + 0x000073;
  const int REGSTORE_SET_SUCCESS = SPROUT_BASE + 0x000074;
  const int REGSTORE_SET_FAILURE = SPROUT_BASE + 0x000075;
  const int REGSTORE_DESERIALIZATION_FAILED = SPROUT_BASE + 0x000076;

  const int REGISTER_START = SPROUT_BASE + 0x000080;
  const int REGISTER_FAILED = SPROUT_BASE + 0x000081;
  const int REGISTER_AS_START = SPROUT_BASE + 0x000082;
  const int REGISTER_AS_FAILED = SPROUT_BASE + 0x000083;
  const int REGISTER_FAILED_INVALIDURISCHEME = SPROUT_BASE + 0x000084;
  const int REGISTER_FAILED_INVALIDPUBPRIV = SPROUT_BASE + 0x000085;
  const int REGISTER_FAILED_INVALIDCONTACT = SPROUT_BASE + 0x000086;
  const int DEREGISTER_FAILED_EMERGENCY = SPROUT_BASE + 0x000087;
  const int REGISTER_FAILED_REGSTORE = SPROUT_BASE + 0x000088;
  const int REGISTER_FAILED_5636 = SPROUT_BASE + 0x000089;
  const int DEREGISTER_AS_FAILED = SPROUT_BASE + 0x00008A;
  const int REGISTRATION_EXPIRED = SPROUT_BASE + 0x00008B;
  const int SOME_BINDINGS_EXPIRED = SPROUT_BASE + 0x00008C;

  const int IMPISTORE_AV_SET_SUCCESS = SPROUT_BASE + 0x000090;
  const int IMPISTORE_AV_GET_SUCCESS = SPROUT_BASE + 0x000091;
  const int IMPISTORE_AV_SET_FAILURE = SPROUT_BASE + 0x000092;
  const int IMPISTORE_AV_GET_FAILURE = SPROUT_BASE + 0x000093;
  const int IMPISTORE_AV_DELETE_SUCCESS = SPROUT_BASE + 0x000094;
  const int IMPISTORE_AV_DELETE_FAILURE = SPROUT_BASE + 0x000095;

  const int IMPISTORE_IMPI_GET_SUCCESS = SPROUT_BASE + 0x000096;
  const int IMPISTORE_IMPI_GET_FAILURE = SPROUT_BASE + 0x000097;
  const int IMPISTORE_IMPI_SET_SUCCESS = SPROUT_BASE + 0x000098;
  const int IMPISTORE_IMPI_SET_FAILURE = SPROUT_BASE + 0x000099;
  const int IMPISTORE_IMPI_DELETE_SUCCESS = SPROUT_BASE + 0x00009A;
  const int IMPISTORE_IMPI_DELETE_FAILURE = SPROUT_BASE + 0x00009B;

  const int HTTP_HOMESTEAD_DIGEST = SPROUT_BASE + 0x0000A0;
  const int HTTP_HOMESTEAD_VECTOR = SPROUT_BASE + 0x0000A1;
  const int HTTP_HOMESTEAD_CHECK_STATE = SPROUT_BASE + 0x0000A2;
  const int HTTP_HOMESTEAD_GET_REG = SPROUT_BASE + 0x0000A3;
  const int HTTP_HOMESTEAD_AUTH_STATUS = SPROUT_BASE + 0x0000A4;
  const int HTTP_HOMESTEAD_LOCATION = SPROUT_BASE + 0x0000A5;

  const int IFC_INVALID = SPROUT_BASE + 0x0000C0;
  const int IFC_INVALID_NOAS = SPROUT_BASE + 0x0000C1;
  const int IFC_NOT_MATCHED = SPROUT_BASE + 0x0000C2;
  const int IFC_NOT_MATCHED_PPI = SPROUT_BASE + 0x0000C3;
  const int IFC_TESTING = SPROUT_BASE + 0x0000C4;
  const int IFC_MATCHED = SPROUT_BASE + 0x0000C5;

  const int TRANSPORT_FAILURE = SPROUT_BASE + 0x0000D0;
  const int TIMEOUT_FAILURE = SPROUT_BASE + 0x0000D1;

  const int SIP_OVERLOAD = SPROUT_BASE + 0x0000D2;

  const int GRUU_FILTERING = SPROUT_BASE + 0x0000D3;
  const int BINDINGS_FROM_TARGETS = SPROUT_BASE + 0x0000D4;
  const int ALL_BINDINGS_FILTERED = SPROUT_BASE + 0x0000D5;

  const int UNPARSEABLE_HEADER = SPROUT_BASE + 0x0000D6;

  const int ICSCF_RCVD_REGISTER = SPROUT_BASE + 0x0000D7;
  const int ICSCF_RCVD_ORIG_NON_REG = SPROUT_BASE + 0x0000D8;
  const int ICSCF_RCVD_TERM_NON_REG = SPROUT_BASE + 0x0000D9;
  const int SCSCF_STARTED_ORIG_PROC = SPROUT_BASE + 0x0000DA;
  const int SCSCF_STARTED_TERM_PROC = SPROUT_BASE + 0x0000DB;
  const int SCSCF_STARTED_ORIG_CDIV_PROC = SPROUT_BASE + 0x0000DC;
  const int SCSCF_INVOKING_AS = SPROUT_BASE + 0x0000DD;
  const int SCSCF_ROUTING_TO_UES = SPROUT_BASE + 0x0000DE;
  const int REGISTER_ACCEPTED = SPROUT_BASE + 0x0000DF;
  const int SUBSCRIBE_ACCEPTED = SPROUT_BASE + 0x0000E0;
  const int IFC_GET_FAILURE = SPROUT_BASE + 0x0000E1;
  const int BAD_AS_URI = SPROUT_BASE + 0x0000E2;
  const int CANNOT_ROUTE_TO_TEL_URI = SPROUT_BASE + 0x0000E3;
  const int BYPASS_AS = SPROUT_BASE + 0x0000E4;
  const int AS_FAILED = SPROUT_BASE + 0x0000E5;
  const int SESS_TIMER_NO_UA_SUPPORT = SPROUT_BASE + 0x0000E6;
  const int AS_SUPPLIED_PRELOADED_ROUTE = SPROUT_BASE + 0x0000E7;
  const int SESS_TIMER_INTERVAL_TOO_LONG = SPROUT_BASE + 0x0000E8;
  const int AS_RETARGETED_CDIV = SPROUT_BASE + 0x0000E9;
  const int AS_RETARGETED_TO_ALIAS = SPROUT_BASE + 0x0000EA;
  const int NO_AS_CHAIN_ROUTE = SPROUT_BASE + 0x0000EB;

  const int NO_CCFS_FOR_ACR = SPROUT_BASE + 0xF0;

  const int AUTHENTICATION_NC_NOT_SUPP = SPROUT_BASE + 0x0100;
  const int AUTHENTICATION_NC_TOO_LOW = SPROUT_BASE + 0x0101;
  const int AUTHENTICATION_NC_ON_NON_REG = SPROUT_BASE + 0x0102;

  const int STARTING_SPROUTLET_SELECTION_URI = SPROUT_BASE + 0x0110;
  const int STARTING_SPROUTLET_SELECTION_PORT = SPROUT_BASE + 0x0111;
  const int SPROUTLET_SELECTION_PORT = SPROUT_BASE + 0x0112;
  const int SPROUTLET_SELECTION_SERVICE_NAME = SPROUT_BASE + 0x0113;
  const int SPROUTLET_SELECTION_ALIAS = SPROUT_BASE + 0x0114;
  const int FORCE_EXTERNAL_ROUTING_SUBSCRIBE = SPROUT_BASE + 0x0115;
  const int NO_SPROUTLET_SELECTED = SPROUT_BASE + 0x0116;

} //namespace SASEvent

#endif

