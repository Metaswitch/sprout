/**
 * @file as_communication_tracker.h
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <map>
#include <string>

#include "pdlog.h"
#include "alarm.h"

#ifndef AS_COMMUNICATION_TRACKER_H_
#define AS_COMMUNICATION_TRACKER_H_

class AsCommunicationTracker
{
public:
  /// Constructor.
  ///
  /// @param alarm         - The alarm to raise when AS communication is not
  ///                        working correctly.
  /// @param as_failed_log - The log to generate when communication to an AS
  ///                        has started to fail.
  /// @param as_ok_log     - The log to generate when communication to an AS
  ///                        has started succeeding again.
  ///
  /// The object takes ownership of the alarm and the logs passed to it.
  AsCommunicationTracker(Alarm* alarm,
                         const PDLog2<const char*, const char*>* as_failed_log,
                         const PDLog1<const char*>* as_ok_log);

  /// Destructor.
  virtual ~AsCommunicationTracker();

  /// Method to be called when communication to an Application Server succeeds.
  ///
  /// @param as_uri - The URI of the AS in question.
  virtual void on_success(const std::string& as_uri);

  /// Method to be called when communication to an Application Server fails.
  ///
  /// @param as_uri - The URI of the AS in question.
  /// @param reason - A short string describing the reason the AS has been
  ///                 treated as failed. For example "Transport error" or
  ///                 "SIP 500 response received"
  virtual void on_failure(const std::string& as_uri, const std::string& reason);

private:
  // A lock that protects all member variables of this class.
  pthread_mutex_t _lock;

  // A count of how many times we have had a communication failure to each AS
  // in the last time period.
  std::map<std::string, int> _as_failures;

  // The time (in ms since the epoch) at which we should check the _as_failures
  // to determine if some ASs are now OK again.
  std::atomic<uint64_t> _next_check_time_ms;

  // The length of time that must pass between checks of _as_failures.
  const static uint64_t NEXT_CHECK_INTERVAL_MS = 5 * 60 * 1000;

  // The alarm to raise when communication to some Application Servers is
  // failing.
  Alarm* _alarm;

  // Logs that are raised when communications are considered to have failed, and
  // when they are considered to be OK.
  //
  // The failed log has two parameters: the URI of the AS, and the reason the AS
  // is being treated as failed.  The success log takes one parameter: the URI
  // of the AS.
  const PDLog2<const char*, const char*>* _as_failed_log;
  const PDLog1<const char*>* _as_ok_log;

  /// Check if any application servers are healthy. If so, log them and
  /// consider clearing the alarm.
  void check_for_healthy_app_servers();

  /// @return The current monotonic time in ms. Note that this is not wall time!
  static uint64_t current_time_ms();
};

#endif

