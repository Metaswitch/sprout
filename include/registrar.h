/**
 * @file registrar.h Initialization/termination functions for Sprout's Registrar module
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


#ifndef REGISTRAR_H__
#define REGISTRAR_H__

extern "C" {
#include <pjsip.h>
}

#include "regstore.h"
#include "hssconnection.h"
#include "chronosconnection.h"
#include "analyticslogger.h"
#include "acr.h"
#include "snmp_success_fail_count_table.h"

extern pjsip_module mod_registrar;

void third_party_register_failed(const std::string& public_id,
                                 SAS::TrailId trail);

extern pj_status_t init_registrar(RegStore* registrar_store,
                                  HSSConnection* hss_connection,
                                  AnalyticsLogger* analytics_logger,
                                  ACRFactory* rfacr_factory,
                                  int cfg_max_expires,
                                  bool force_third_party_register_body,
                                  SNMP::RegistrationStatsTables* reg_stats_tbls,
                                  SNMP::RegistrationStatsTables* third_party_reg_stats_tbls);


extern void destroy_registrar();

#endif
