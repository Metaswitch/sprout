/**
 * @file as_communication_tracker.h
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
                         const PDLog1<const char*>* as_failed_log,
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
  virtual void on_failure(const std::string& as_uri);

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

  // Logs that are raised when communications are considered to have failed,
  // and when they are considered to be OK.
  //
  // Each log takes the URI of the AS as a parameter.
  const PDLog1<const char*>* _as_failed_log;
  const PDLog1<const char*>* _as_ok_log;

  /// Check if any application servers are healthy. If so, log them and
  /// consider clearing the alarm.
  void check_for_healthy_app_servers();

  /// @return The current monotonic time in ms. Note that this is not wall time!
  static uint64_t current_time_ms();
};

#endif

