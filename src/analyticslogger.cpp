/**
 * @file analyticslogger.cpp
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>

// Common STL includes.
#include <cassert>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <queue>
#include <string>

#include "analyticslogger.h"

AnalyticsLogger::AnalyticsLogger()
{
}

AnalyticsLogger::~AnalyticsLogger()
{
}

void AnalyticsLogger::log_with_tag_and_timestamp(char* log)
{
  // Add the current UTC time, in RFC3339 format.
  struct timespec timespec;
  struct tm dt;
  clock_gettime(CLOCK_REALTIME, &timespec);
  gmtime_r(&timespec.tv_sec, &dt);
  char timestamp[100];
  sprintf(timestamp,
          "%4.4d-%2.2d-%2.2dT%2.2d:%2.2d:%2.2d.%3.3d+00:00",
          (dt.tm_year + 1900),
          (dt.tm_mon + 1),
          dt.tm_mday,
          dt.tm_hour,
          dt.tm_min,
          dt.tm_sec,
          (int)(timespec.tv_nsec / 1000000));

  syslog(LOG_INFO, "<analytics> %s %s", timestamp, log);
}

void AnalyticsLogger::registration(const std::string& aor,
                                   const std::string& binding_id,
                                   const std::string& contact,
                                   int expires)
{
  char buf[BUFFER_SIZE];

  snprintf(buf, sizeof(buf),
           "Registration: USER_URI=%s BINDING_ID=%s CONTACT_URI=%s EXPIRES=%d",
           aor.c_str(),
           binding_id.c_str(),
           contact.c_str(),
           expires);
  log_with_tag_and_timestamp(buf);
}

void AnalyticsLogger::subscription(const std::string& aor,
                                   const std::string& subscription_id,
                                   const std::string& contact,
                                   int expires)
{
  char buf[BUFFER_SIZE];
  snprintf(buf, sizeof(buf),
           "Subscription: USER_URI=%s SUBSCRIPTION_ID=%s CONTACT_URI=%s EXPIRES=%d",
           aor.c_str(),
           subscription_id.c_str(),
           contact.c_str(),
           expires);
  log_with_tag_and_timestamp(buf);
}

void AnalyticsLogger::auth_failure(const std::string& auth,
                                   const std::string& to)
{
  char buf[BUFFER_SIZE];
  snprintf(buf, sizeof(buf),
           "Auth-Failure: Private Identity=%s Public Identity=%s",
           auth.c_str(),
           to.c_str());
  log_with_tag_and_timestamp(buf);
}


void AnalyticsLogger::call_connected(const std::string& from,
                                     const std::string& to,
                                     const std::string& call_id)
{
  char buf[BUFFER_SIZE];
  snprintf(buf, sizeof(buf),
           "Call-Connected: FROM=%s TO=%s CALL_ID=%s",
           from.c_str(),
           to.c_str(),
           call_id.c_str());
  log_with_tag_and_timestamp(buf);
}


void AnalyticsLogger::call_not_connected(const std::string& from,
                                         const std::string& to,
                                         const std::string& call_id,
                                         int reason)
{
  char buf[BUFFER_SIZE];
  snprintf(buf, sizeof(buf),
           "Call-Not-Connected: FROM=%s TO=%s CALL_ID=%s REASON=%d",
           from.c_str(),
           to.c_str(),
           call_id.c_str(),
           reason);
  log_with_tag_and_timestamp(buf);
}


void AnalyticsLogger::call_disconnected(const std::string& call_id,
                                        int reason)
{
  char buf[BUFFER_SIZE];
  snprintf(buf, sizeof(buf),
           "Call-Disconnected: CALL_ID=%s REASON=%d",
           call_id.c_str(),
           reason);
  log_with_tag_and_timestamp(buf);
}

