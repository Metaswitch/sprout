/**
 * @file mock_hss_connection.h Mock HSS connection class
 *
 * Copyright (C) Metaswitch Networks 2017
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
  MockHSSConnection();
  virtual ~MockHSSConnection();

  MOCK_METHOD5(update_registration_state,
               HTTPCode(const std::string& public_user_identity,
                        const std::string& private_user_identity,
                        const std::string& type,
                        std::string server_name,
                        SAS::TrailId trail));
  MOCK_METHOD7(update_registration_state,
               HTTPCode(const std::string& public_user_identity,
                        const std::string& private_user_identity,
                        const std::string& type,
                        std::string server_name,
                        std::map<std::string, Ifcs >& service_profiles,
                        AssociatedURIs& associated_uris,
                        SAS::TrailId trail));
  MOCK_METHOD10(update_registration_state,
                HTTPCode(const std::string& public_user_identity,
                         const std::string& private_user_identity,
                         const std::string& type,
                         std::string& regstate,
                         std::string server_name,
                         std::map<std::string, Ifcs >& ifcs_map,
                         AssociatedURIs& associated_uris,
                         std::deque<std::string>& ccfs,
                         std::deque<std::string>& ecfs,
                         SAS::TrailId trail));

  MOCK_METHOD3(get_registration_data,
               HTTPCode(const HSSConnection::hss_query_parameter_t& hss_query_parameter,
                        HSSConnection::hss_query_return_t& hss_query_return,
                        SAS::TrailId trail));

};

#endif

