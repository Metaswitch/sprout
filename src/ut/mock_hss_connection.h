/**
 * @file mock_hss_connection.h Mock HSS connection class
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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
                                      "sip:scscf.sprout.homedomain:5058;transport=TCP") {};
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

