/**
 * @file constants.h
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

#ifndef CONSTANTS_H_
#define CONSTANTS_H_

#include <pjsip.h>

const pj_str_t STR_DIVERSION = pj_str((char *)"Diversion");
const pj_str_t STR_SUPPORTED = pj_str((char *)"Supported");
const pj_str_t STR_REQUIRE = pj_str((char *)"Require");
const pj_str_t STR_PATH = pj_str((char *)"Path");
const pj_str_t STR_OUTBOUND = pj_str((char *)"outbound");
const pj_str_t STR_PARAM_OB = pj_str((char *)"ob");
const pj_str_t STR_SIP_INSTANCE = pj_str((char *)"+sip.instance");
const pj_str_t STR_REG_ID = pj_str((char *)"reg-id");
const pj_str_t STR_OB = pj_str((char *)"ob");
const pj_str_t STR_INTEGRITY_PROTECTED = pj_str((char *)"integrity-protected");
const pj_str_t STR_YES = pj_str((char *)"yes");
const pj_str_t STR_NO = pj_str((char *)"no");
const pj_str_t STR_TLS_YES = pj_str((char *)"tls-yes");
const pj_str_t STR_TLS_PENDING = pj_str((char *)"tls-pending");
const pj_str_t STR_IP_ASSOC_YES = pj_str((char *)"ip-assoc-yes");
const pj_str_t STR_IP_ASSOC_PENDING = pj_str((char *)"ip-assoc-pending");
const pj_str_t STR_AUTH_DONE = pj_str((char *)"auth-done");
const pj_str_t STR_PRIVACY = pj_str((char *)"Privacy");
const pj_str_t STR_P_A_N_I = pj_str((char *)"P-Access-Network-Info");
const pj_str_t STR_P_V_N_I = pj_str((char *)"P-Visited-Network-Id");
const pj_str_t STR_P_SERVED_USER = pj_str((char*)"P-Served-User");
const pj_str_t STR_P_ASSERTED_IDENTITY = pj_str((char*)"P-Asserted-Identity");
const pj_str_t STR_P_PREFERRED_IDENTITY = pj_str((char*)"P-Preferred-Identity");
const pj_str_t STR_P_ASSOCIATED_URI = pj_str((char*)"P-Associated-URI");
const pj_str_t STR_REQUEST_DISPOSITION = pj_str((char*)"Request-Disposition");
const pj_str_t STR_SERVICE_ROUTE = pj_str((char*)"Service-Route");
const pj_str_t STR_ORIG = pj_str((char*)"orig");
const pj_str_t STR_NO_FORK = pj_str((char*)"no-fork");
const pj_str_t STR_P_C_V = pj_str((char*)"P-Charging-Vector");
const pj_str_t STR_P_C_F_A = pj_str((char*)"P-Charging-Function-Addresses");
const pj_str_t STR_DIGEST = pj_str((char*)"Digest");
const pj_str_t STR_MD5 = pj_str((char*)"MD5");
const pj_str_t STR_AKAV1_MD5 = pj_str((char*)"AKAv1-MD5");
const pj_str_t STR_AUTH = pj_str((char*)"auth");
const pj_str_t STR_AUTS = pj_str((char*)"auts");
const pj_str_t STR_CK = pj_str((char*)"ck");
const pj_str_t STR_IK = pj_str((char*)"ik");
const pj_str_t STR_P_PROFILE_KEY = pj_str((char*)"P-Profile-Key");
const pj_str_t STR_APPLICATION = pj_str((char*)"application");
const pj_str_t STR_SDP = pj_str((char*)"sdp");
const pj_str_t STR_EVENT = pj_str((char*)"Event");
const pj_str_t STR_X = pj_str((char*)"X");
const pj_str_t STR_REASON = pj_str((char*)"Reason");
const pj_str_t STR_TRANSIT_IOI = pj_str((char*)"transit-ioi");
const pj_str_t STR_SESSION_EXPIRES = pj_str((char*)"Session-Expires");
const pj_str_t STR_CALL_ID = pj_str((char*)"Call-ID");
const pj_str_t STR_CCF = pj_str((char*)"ccf");
const pj_str_t STR_CONTENT_DISPOSITION = pj_str((char*)"Content-Disposition");
const pj_str_t STR_REG = pj_str((char*)"reg");
const pj_str_t STR_SOS = pj_str((char*)"sos");
const pj_str_t STR_USER = pj_str((char*)"user");
const pj_str_t STR_CHARGE_ORIG = pj_str((char*)"charge-orig");
const pj_str_t STR_CHARGE_TERM = pj_str((char*)"charge-term");
const pj_str_t STR_ALLOW_EVENTS = pj_str((char*)"Allow-Events");

/// Prefix of ODI tokens we generate.
const pj_str_t STR_ODI_PREFIX = pj_str((char*)"odi_");

const int SIP_STATUS_FLOW_FAILED = 430;
const pj_str_t SIP_REASON_FLOW_FAILED = pj_str((char*)"Flow failed");
const pj_str_t SIP_REASON_ENUM_FAILED = pj_str((char*)"ENUM translation failed");
const pj_str_t SIP_REASON_OFFNET_DISALLOWED = pj_str((char*)"Off-net calling not allowed");
const pj_str_t SIP_REASON_ADDR_INCOMPLETE = pj_str((char*)"Address Incomplete");

#endif /* CONSTANTS_H_ */
