/**
 * @file authentication.h Initialization and termination functions for Sprout Authentication module.
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


#ifndef AUTHENTICATION_H__
#define AUTHENTICATION_H__

#include "impistore.h"
#include "hssconnection.h"
#include "chronosconnection.h"
#include "acr.h"
#include "analyticslogger.h"
#include "snmp_success_fail_count_table.h"

extern pjsip_module mod_authentication;

enum struct NonRegisterAuthentication
{
  // Never challenge a non-REGISTER.
  NEVER,

  // Only challenge a non-REGISTER if it has a Proxy-Authorization header.
  IF_PROXY_AUTHORIZATION_PRESENT
};

typedef int(*get_expiry_for_binding_fn)(pjsip_contact_hdr* contact,
                                        pjsip_expires_hdr* expires);

pj_status_t init_authentication(const std::string& realm_name,
                                ImpiStore* impi_store,
                                HSSConnection* hss_connection,
                                ChronosConnection* chronos_connection,
                                ACRFactory* rfacr_factory,
                                NonRegisterAuthentication non_register_auth_mode_param,
                                AnalyticsLogger* analytics_logger,
                                SNMP::AuthenticationStatsTables* auth_stats_tables,
                                bool nonce_count_supported_arg,
                                get_expiry_for_binding_fn get_expiry_for_binding_arg);

void destroy_authentication();

#endif
