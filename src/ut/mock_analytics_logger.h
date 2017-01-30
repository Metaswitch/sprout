/**
 * @file mock_impi_store.h
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2016  Metaswitch Networks Ltd
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

#ifndef MOCK_ANALYTICS_LOGGER_H__
#define MOCK_ANALYTICS_LOGGER_H__

#include "gmock/gmock.h"
#include "analyticslogger.h"

class MockAnalyticsLogger : public AnalyticsLogger
{
public:
  MockAnalyticsLogger() {}
  virtual ~MockAnalyticsLogger() {}

  MOCK_METHOD4(registration, void(const std::string& aor,
                                  const std::string& binding_id,
                                  const std::string& contact,
                                  int expires));

  MOCK_METHOD4(subscription, void(const std::string& aor,
                                  const std::string& subscription_id,
                                  const std::string& contact,
                                  int expires));

  MOCK_METHOD2(auth_failure, void(const std::string& auth,
                    const std::string& to));

  MOCK_METHOD3(call_connected, void(const std::string& from,
                      const std::string& to,
                      const std::string& call_id));

  MOCK_METHOD4(call_not_connected, void(const std::string& from,
                          const std::string& to,
                          const std::string& call_id,
                          int reason));

  MOCK_METHOD2(call_disconnected, void(const std::string& call_id,
                         int reason));

};

#endif

