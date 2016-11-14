/**
 * @file registration_utils.h
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

#ifndef REGISTRATION_UTILS_H__
#define REGISTRATION_UTILS_H__

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}

#include <string>
#include "subscriber_data_manager.h"
#include "ifchandler.h"
#include "hssconnection.h"
#include "snmp_success_fail_count_table.h"

namespace RegistrationUtils {

void init(SNMP::RegistrationStatsTables* third_party_reg_stats_tables_arg,
          bool force_third_party_register_body_arg);

bool remove_bindings(SubscriberDataManager* sdm,
                     std::vector<SubscriberDataManager*> remote_sdms,
                     HSSConnection* hss,
                     const std::string& aor,
                     const std::string& binding_id,
                     const std::string& dereg_type,
                     SAS::TrailId trail,
                     HTTPCode* hss_status_code = nullptr);

void register_with_application_servers(Ifcs& ifcs,
                                       SubscriberDataManager* sdm,
                                       pjsip_rx_data* received_register,
                                       pjsip_tx_data* ok_response,
                                       int expires,
                                       bool is_initial_registration,
                                       const std::string& served_user,
                                       SAS::TrailId trail);

void deregister_with_application_servers(Ifcs&,
                                         SubscriberDataManager* sdm,
                                         const std::string&,
                                         SAS::TrailId trail);

} // namespace RegistrationUtils

#endif
