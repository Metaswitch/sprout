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

/// @class Accumulator
///
/// Accumulates samples
class Accumulator
{
public:
  static const uint_fast64_t DEFAULT_PERIOD_US = 5 * 1000 * 1000;

  inline Accumulator(uint_fast64_t period_us = DEFAULT_PERIOD_US) :
                     _target_period_us(period_us)
  {
    reset();
  }

  void accumulate(unsigned long sample)
  {
    // Update the basic counters and samples.
    _current._n++;
    _current._sigma += sample;
    _current._sigma_squared += sample * sample;

    // Update the low- and high-water marks.  In each case, we get the current
    // value, decide whether a change is required and then atomically swap it
    // if so, repeating if it was changed in the meantime.
    uint_fast64_t lwm = _current._lwm.load();
    while ((sample < lwm) &&
           (!_current._lwm.compare_exchange_weak(lwm, sample)))
    {
      // Do nothing.
    }
    uint_fast64_t hwm = _current._hwm.load();
    while ((sample > hwm) &&
           (!_current._hwm.compare_exchange_weak(hwm, sample)))
    {
      // Do nothing.
    }

    refresh();
  }

  void refresh(bool force = false)
  {
    uint_fast64_t timestamp = _current._timestamp.load();
    uint_fast64_t timestamp_now = get_timestamp();
    if ((force ||
         (timestamp_now >= timestamp + _target_period_us)) &&
        (_current._timestamp.compare_exchange_weak(timestamp, timestamp_now)))
    {
      read(timestamp_now - timestamp);
      refreshed();
    }
  }

  void reset()
  {
    _current._timestamp.store(get_timestamp());
    _current._n.store(0);
    _current._sigma.store(0);
    _current._sigma_squared.store(0);
    _current._lwm.store(MAX_UINT_FAST64);
    _current._hwm.store(0);
    _last._n = 0;
    _last._mean = 0;
    _last._variance = 0;
    _last._lwm = 0;
    _last._hwm = 0;
  }

  inline uint_fast64_t get_n()        { return _last._n; }
  inline uint_fast64_t get_mean()     { return _last._mean; }
  inline uint_fast64_t get_variance() { return _last._variance; }
  inline uint_fast64_t get_lwm()      { return _last._lwm; }
  inline uint_fast64_t get_hwm()      { return _last._hwm; }

  virtual void refreshed() {};

private:
  static const uint_fast64_t MAX_UINT_FAST64 = ~((uint_fast64_t)0);

  uint_fast64_t _target_period_us;

  // We use a set of atomics here.  This isn't perfect, as reads are not
  // synchronized (e.g. we could read a value of _n that is more recent than
  // the value we read of _sigma).  However, given that _n is likely to be
  // quite large and only out by 1 or 2, it's not expected to matter.
  struct {
    std::atomic_uint_fast64_t _timestamp;
    std::atomic_uint_fast64_t _n;
    std::atomic_uint_fast64_t _sigma;
    std::atomic_uint_fast64_t _sigma_squared;
    std::atomic_uint_fast64_t _lwm;
    std::atomic_uint_fast64_t _hwm;
  } _current;

  struct {
    volatile uint_fast64_t _n;
    volatile uint_fast64_t _mean;
    volatile uint_fast64_t _variance;
    volatile uint_fast64_t _lwm;
    volatile uint_fast64_t _hwm;
  } _last;

  inline uint_fast64_t get_timestamp()
  {
    uint_fast64_t timestamp = 0;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
    {
      timestamp = (ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);
    }
    return timestamp;
  }

  void read(uint_fast64_t period_us)
  {
    uint_fast64_t n = _current._n.exchange(0);
    uint_fast64_t sigma = _current._sigma.exchange(0);
    uint_fast64_t sigma_squared = _current._sigma_squared.exchange(0);
    _last._n = n * period_us / _target_period_us;
    uint_fast64_t mean = (n > 0) ? sigma / n : 0;
    _last._mean = mean;
    _last._variance = (n > 0) ? ((sigma_squared / n) - (mean * mean)) : 0;
    _last._lwm = _current._lwm.exchange(MAX_UINT_FAST64);
    _last._hwm = _current._hwm.exchange(0);
  }
};

class StatisticAccumulator : public Accumulator
{
public:
  inline StatisticAccumulator(std::string statname,
                              uint_fast64_t period_us = DEFAULT_PERIOD_US) :
                              Accumulator(period_us),
                              _statistic(statname) {}

  virtual void refreshed()
  {
    std::vector<std::string> values;
    values.push_back(std::to_string(get_mean()));
    values.push_back(std::to_string(get_variance()));
    values.push_back(std::to_string(get_lwm()));
    values.push_back(std::to_string(get_hwm()));
    _statistic.report_change(values);
  }

private:
  Statistic _statistic;
};

#endif
