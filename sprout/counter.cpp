/**
 * @file counter.cpp class implementation for a statistics counter
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

#include <vector>
#include "counter.h"

/// Increase the current count by 1.
void Counter::increment(void)
{
  // Update the basic counters and samples.
  _current._count++;
  // Refresh the statistics, if required.
  refresh();
}

/// Refresh our calculations - called at the end of each period, or
/// optionally at other times to get an up-to-date result.
void Counter::refresh(bool force)
{
  // Get the timestamp from the start of the current period, and the timestamp
  // now.
  uint_fast64_t timestamp_us = _current._timestamp_us.load();
  uint_fast64_t timestamp_us_now = get_timestamp_us();

  // If we're forced, or this period is already long enough, read the new
  // values and make the refreshed() callback.
  if ((force ||
      (timestamp_us_now >= timestamp_us + _target_period_us)) &&
      (_current._timestamp_us.compare_exchange_weak(timestamp_us, timestamp_us_now)))
  {
    read(timestamp_us_now - timestamp_us);
    refreshed();
  }
}

/// Reset the counter.
void Counter::reset()
{
  // Get the timestamp now.
  _current._timestamp_us.store(get_timestamp_us());
  // Reset everything else to 0.
  _current._count.store(0);
  _last._count = 0;
}

/// Read the counter and report
/// it as the last set of statistics.
void Counter::read(uint_fast64_t period_us)
{
  // Read the basic statistics, and replace them with 0.
  uint_fast64_t count = _current._count.exchange(0);
  _last._count = count ;
}

/// Callback whenever the accumulated statistics are refreshed. Passes
/// values to zeroMQ.
void StatisticCounter::refreshed()
{
  // Simply construct a vector of count only and pass it to zeroMQ.
  std::vector<std::string> values;
  values.push_back(std::to_string(get_count()));
  _statistic.report_change(values);
}
