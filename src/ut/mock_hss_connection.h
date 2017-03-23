/**
 * @file mock_hss_connection.h Mock HSS connection class
 *
 * Project Clearwater - IMS in the cloud.
 * Copyright (C) 2015  Metaswitch Networks Ltd
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

#ifndef MOCK_HSS_CONNECTION_H_
#define MOCK_HSS_CONNECTION_H_

#include "gmock/gmock.h"

#include "hssconnection.h"
#include "fakesnmp.hpp"

class MockHSSConnection : public HSSConnection
{
public:
  MockHSSConnection() : HSSConnection("localhost",
                                      NULL,
                                      NULL,
                                      &SNMP::FAKE_IP_COUNT_TABLE,
                                      &SNMP::FAKE_EVENT_ACCUMULATOR_TABLE,
                                      &SNMP::FAKE_EVENT_ACCUMULATOR_TABLE,
                                      &SNMP::FAKE_EVENT_ACCUMULATOR_TABLE,
                                      &SNMP::FAKE_EVENT_ACCUMULATOR_TABLE,
                                      &SNMP::FAKE_EVENT_ACCUMULATOR_TABLE,
                                      NULL,
                                      "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                      NULL) {};
  virtual ~MockHSSConnection() {};

  MOCK_METHOD4(update_registration_state,
               HTTPCode(const std::string& public_user_identity,
                        const std::string& private_user_identity,
                        const std::string& type,
                        SAS::TrailId trail));
  MOCK_METHOD6(update_registration_state,
               HTTPCode(const std::string& public_user_identity,
                        const std::string& private_user_identity,
                        const std::string& type,
                        std::map<std::string, Ifcs >& service_profiles,
                        std::vector<std::string>& associated_uris,
                        SAS::TrailId trail));
  MOCK_METHOD9(update_registration_state,
               HTTPCode(const std::string& public_user_identity,
                        const std::string& private_user_identity,
                        const std::string& type,
                        std::string& regstate,
                        std::map<std::string, Ifcs >& ifcs_map,
                        std::vector<std::string>& associated_uris,
                        std::deque<std::string>& ccfs,
                        std::deque<std::string>& ecfs,
                        SAS::TrailId trail));

  MOCK_METHOD5(get_registration_data,
               HTTPCode(const std::string& public_user_identity,
                        std::string& regstate,
                        std::map<std::string, Ifcs >& ifcs_map,
                        std::vector<std::string>& associated_uris,
                        SAS::TrailId trail));
};

#endif

