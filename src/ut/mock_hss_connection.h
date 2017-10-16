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

  MOCK_METHOD3(update_registration_state,
               HTTPCode(const HSSConnection::hss_query_param_t& hss_query_param,
                        HSSConnection::hss_query_return_t& hss_query_return,
                        SAS::TrailId trail));

  MOCK_METHOD3(get_registration_data,
               HTTPCode(const HSSConnection::hss_query_param& hss_query_param,
                        HSSConnection::hss_query_return_t& hss_query_return,
                        SAS::TrailId trail));

};

#endif

