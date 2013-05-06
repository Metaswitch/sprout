/**
 * @file constants.h
 *
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by post at
 * Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 */

#ifndef CONSTANTS_H_
#define CONSTANTS_H_

const pj_str_t STR_SUPPORTED = pj_str("Supported");
const pj_str_t STR_REQUIRE = pj_str("Require");
const pj_str_t STR_PATH = pj_str("Path");
const pj_str_t STR_OUTBOUND = pj_str("outbound");
const pj_str_t STR_PARAM_OB = pj_str("ob");
const pj_str_t STR_SIP_INSTANCE = pj_str("+sip.instance");
const pj_str_t STR_REG_ID = pj_str("reg-id");
const pj_str_t STR_OB = pj_str("ob");
const pj_str_t STR_INTEGRITY_PROTECTED = pj_str("integrity-protected");
const pj_str_t STR_P_A_N_I = pj_str("P-Access-Network-Info");
const pj_str_t STR_ORIG = pj_str("orig");

/// Prefix of ODI tokens we generate.
const pj_str_t STR_ODI_PREFIX = pj_str("odi_");

const int SIP_STATUS_FLOW_FAILED = 430;
const pj_str_t SIP_REASON_FLOW_FAILED = pj_str("Flow failed");
const pj_str_t SIP_REASON_ENUM_FAILED = pj_str("ENUM translation failed");
const pj_str_t SIP_REASON_OFFNET_DISALLOWED = pj_str("Off-net calling not allowed");

#endif /* CONSTANTS_H_ */
