/**
 * @file mock_analytics_logger.h
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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

