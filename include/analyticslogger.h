/**
 * @file analyticslogger.h Declaration of AnalyticsLogger class.
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

///
///

#ifndef ANALYTICSLOGGER_H__
#define ANALYTICSLOGGER_H__

#include <sstream>

class AnalyticsLogger
{
public:
  AnalyticsLogger();
  virtual ~AnalyticsLogger();

  void log_with_tag_and_timestamp(char* log);

  virtual void registration(const std::string& aor,
                    const std::string& binding_id,
                    const std::string& contact,
                    int expires);

  virtual void subscription(const std::string& aor,
                    const std::string& subscription_id,
                    const std::string& contact,
                    int expires);

  virtual void auth_failure(const std::string& auth,
                    const std::string& to);

  virtual void call_connected(const std::string& from,
                      const std::string& to,
                      const std::string& call_id);

  virtual void call_not_connected(const std::string& from,
                          const std::string& to,
                          const std::string& call_id,
                          int reason);

  virtual void call_disconnected(const std::string& call_id,
                         int reason);

private:
  static const int BUFFER_SIZE = 1000;
};

#endif

