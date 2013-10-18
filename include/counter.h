/**
 * @file counter.h class definition for a statistics counter
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
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

#ifndef COUNTER_H__
#define COUNTER_H__

#include <atomic>
#include <time.h>

#include "statistic.h"

/// @class Counter
///
/// Counts events over a set period, pushing the total number as the statistic
class Counter
{
public:
  /// Default counting period, in microseconds.
  static const uint_fast64_t DEFAULT_PERIOD_US = 5 * 1000 * 1000;

  /// Constructor.
  inline Counter(uint_fast64_t period_us = DEFAULT_PERIOD_US) :
                     _target_period_us(period_us)
  {
    reset();
  }

  /// Increment function
  void increment(void);
  /// Refresh our calculations - called at the end of each period, or
  /// optionally at other times to get an up-to-date result.
  void refresh(bool force = false);
  /// Resets the counter.
  void reset();

  /// Get number of results in last period.
  inline uint_fast64_t get_count() { return _last._count; }

  /// Callback whenever the accumulated statistics are refreshed. Default is
  /// to do nothing.
  virtual void refreshed() {};

private:
  static const uint_fast64_t MAX_UINT_FAST64 = ~((uint_fast64_t)0);

  /// Target period (in microseconds) over which samples are accumulated.
  /// Might be inaccurate due to timing errors, or because events don't come
  /// in frequently enough.
  uint_fast64_t _target_period_us;

  /// Current accumulated count.
  struct {
    std::atomic_uint_fast64_t _timestamp_us;
    std::atomic_uint_fast64_t _count;
  } _current;

  /// Count accumulated over the previous period.
  struct {
    volatile uint_fast64_t _count;
  } _last;

  /// Get a timestamp in microseconds.
  inline uint_fast64_t get_timestamp_us()
  {
    uint_fast64_t timestamp = 0;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
    {
      timestamp = (ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);
    }
    return timestamp;
  }

  /// Read the accumulated counts, calculate their properties and report
  /// them as the last set of statistics.
  void read(uint_fast64_t period_us);
};

/// @class StatisticCounter
///
/// Counts and reports value as a zeroMQ-based statistic.
class StatisticCounter : public Counter
{
public:
  /// Constructor.
  inline StatisticCounter(std::string statname,
                              uint_fast64_t period_us = DEFAULT_PERIOD_US) :
                              Counter(period_us),
                              _statistic(statname) {}

  /// Callback whenever the accumulated statistics are refreshed. Passes
  /// values to zeroMQ.
  virtual void refreshed();

private:
  /// The zeroMQ-based statistic to report to.
  Statistic _statistic;
};

#endif
