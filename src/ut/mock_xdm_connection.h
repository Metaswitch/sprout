/**
 * @file mock_xdm_connection.h
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef MOCK_XDM_CONNECTION_H__
#define MOCK_XDM_CONNECTION_H__

#include "gmock/gmock.h"
#include "xdmconnection.h"

using ::testing::_;

class MockXDMConnection : public XDMConnection
{
public:
  MockXDMConnection();
  ~MockXDMConnection();

  MOCK_METHOD4(get_simservs, bool(const std::string& user, std::string& xml_data, const std::string& password, SAS::TrailId trail));
};

#endif
