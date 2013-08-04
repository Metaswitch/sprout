/**
 * @file accumulator.h class definition for a statistics accumulator
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

#ifndef ACCUMULATOR_H__
#define ACCUMULATOR_H__

#include <atomic>
#include <time.h>

#include "statistic.h"

/// @class Accumulator
///
/// Accumulates samples, calculating mean, variance and low- and high-water
/// marks on them.
class Accumulator
{
public:
  /// Default accumulation period, in microseconds.
  static const uint_fast64_t DEFAULT_PERIOD_US = 5 * 1000 * 1000;

  /// Constructor.
  inline Accumulator(uint_fast64_t period_us = DEFAULT_PERIOD_US) :
                     _target_period_us(period_us)
  {
    reset();
  }

  /// Accumulate a sample into our results.
  void accumulate(unsigned long sample);
  /// Refresh our calculations - called at the end of each period, or
  /// optionally at other times to get an up-to-date result.
  void refresh(bool force = false);
  /// Resets the accumulator.
  void reset();

  /// Get number of results in last period.
  inline uint_fast64_t get_n()        { return _last._n; }
  /// Get mean.
  inline uint_fast64_t get_mean()     { return _last._mean; }
  /// Get variance.
  inline uint_fast64_t get_variance() { return _last._variance; }
  /// Get low-water mark.
  inline uint_fast64_t get_lwm()      { return _last._lwm; }
  /// Get high-water mark.
  inline uint_fast64_t get_hwm()      { return _last._hwm; }

  /// Callback whenever the accumulated statistics are refreshed.  Default is
  /// to do nothing.
  virtual void refreshed() {};

private:
  /// Maximum value of a uint_fast64_t (assuming 2s-complement).  There is a
  /// #define for this, but it's unavailable in C++.
  static const uint_fast64_t MAX_UINT_FAST64 = ~((uint_fast64_t)0);

  /// Target period (in microseconds) over which samples are accumulated.
  /// Might be inaccurate due to timing errors, or because events don't come
  /// in frequently enough.
  uint_fast64_t _target_period_us;

  /// Set of current statistics being accumulated.
  struct {
    // We use a set of atomics here.  This isn't perfect, as reads are not
    // synchronized (e.g. we could read a value of _n that is more recent than
    // the value we read of _sigma).  However, given that _n is likely to be
    // quite large and only out by 1 or 2, it's not expected to matter.
    std::atomic_uint_fast64_t _timestamp_us;
    std::atomic_uint_fast64_t _n;
    std::atomic_uint_fast64_t _sigma;
    std::atomic_uint_fast64_t _sigma_squared;
    std::atomic_uint_fast64_t _lwm;
    std::atomic_uint_fast64_t _hwm;
  } _current;

  /// Set of statistics accumulated over the previous period.
  struct {
    volatile uint_fast64_t _n;
    volatile uint_fast64_t _mean;
    volatile uint_fast64_t _variance;
    volatile uint_fast64_t _lwm;
    volatile uint_fast64_t _hwm;
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

  /// Read the accumulated statistics, calculate their properties and report
  /// them as the last set of statistics.
  void read(uint_fast64_t period_us);
};

/// @class StatisticAccumulator
///
/// Accumulates statistics and reports them as a zeroMQ-based statistic.
class StatisticAccumulator : public Accumulator
{
public:
  /// Constructor.
  inline StatisticAccumulator(std::string statname,
                              uint_fast64_t period_us = DEFAULT_PERIOD_US) :
                              Accumulator(period_us),
                              _statistic(statname) {}

  /// Callback whenever the accumulated statistics are refreshed.  Passes
  /// values to zeroMQ.
  virtual void refreshed();

private:
  /// The zeroMQ-based statistic to report to.
  Statistic _statistic;
};

#endif
