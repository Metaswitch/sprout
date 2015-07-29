/**
 * @file load_monitor_test.cpp UT for LoadMonitor classes.
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

///
///----------------------------------------------------------------------------

#include <string>
#include "gtest/gtest.h"

#include "basetest.hpp"
#include "load_monitor.h"
#include "test_interposer.hpp"

static SNMP::ContinuousAccumulatorTable* token_rate_table = SNMP::ContinuousAccumulatorTable::create("","");
static SNMP::U32Scalar* smoothed_latency_scalar = new SNMP::U32Scalar("","");
static SNMP::U32Scalar* target_latency_scalar = new SNMP::U32Scalar("","");
static SNMP::U32Scalar* penalties_scalar = new SNMP::U32Scalar("","");
static SNMP::U32Scalar* token_rate_scalar = new SNMP::U32Scalar("","");

/// Fixture for LoadMonitorTest.
class LoadMonitorTest : public BaseTest
{
  LoadMonitor _load_monitor;

  LoadMonitorTest() :
    _load_monitor(100000, 20, 10, 10,
                  token_rate_table, smoothed_latency_scalar,
                  target_latency_scalar, penalties_scalar,
                  token_rate_scalar)
  {
    cwtest_completely_control_time();
  }

  virtual ~LoadMonitorTest()
  {
    cwtest_reset_time();
  }
};

class TokenBucketTest : public BaseTest
{
  TokenBucket _token_bucket;

  TokenBucketTest() :
    _token_bucket(20, 10)
  {
  }

  virtual ~TokenBucketTest()
  {
  }
};

TEST_F(LoadMonitorTest, RequestComplete)
{
  float initial_rate = _load_monitor.bucket.rate;

  // Keep the latency at the expected value.
  for (int ii = 0; ii < 20; ii++)
  {
   _load_monitor.request_complete(100000);
  }

  // The token rate is unchanged, because although we've seen 20 requests, 2 seconds haven't passed
  EXPECT_EQ(_load_monitor.bucket.rate, initial_rate);

  // Move time forwards 2 seconds and inject another request.
  cwtest_advance_time_ms(2000);

  _load_monitor.request_complete(100000);

  // Bucket fill rate should still be at the initial rate, because the latency is as expected.
  EXPECT_EQ(_load_monitor.bucket.rate, initial_rate);
  initial_rate = _load_monitor.bucket.rate;

  // Keep the latency low, but without a penalty.
  for (int ii = 0; ii < 20; ii++)
  {
   _load_monitor.request_complete(1000);
  }

  // The token rate is unchanged, because although we've seen 20 requests, 2 seconds haven't passed
  EXPECT_EQ(_load_monitor.bucket.rate, initial_rate);

  // Move time forwards 2 seconds and inject another request.
  cwtest_advance_time_ms(2000);
  _load_monitor.request_complete(1000);

  // Bucket fill rate should have increased due to the low latency.
  EXPECT_GT(_load_monitor.bucket.rate, initial_rate);

  float changed_rate = _load_monitor.bucket.rate;

  // Keep the latency low, but incur a penalty.
  _load_monitor.incr_penalties();

  for (int ii = 0; ii < 20; ii++)
  {
    _load_monitor.request_complete(1000);
  }

  // The token rate is unchanged, because although we've seen 20 requests, 2 seconds haven't passed
  EXPECT_EQ(_load_monitor.bucket.rate, changed_rate);

  // Move time forwards 2 seconds and inject another request.
  cwtest_advance_time_ms(2000);
  _load_monitor.request_complete(1000);

  // Bucket fill rate should have decreased due to the penalty.
  EXPECT_LT(_load_monitor.bucket.rate, changed_rate);

}

TEST_F(LoadMonitorTest, NoRateDecreaseBelowMinimum)
{
  float initial_rate = _load_monitor.bucket.rate;

  for (int ii = 0; ii < 20; ii++)
  {
    _load_monitor.request_complete(100000000);
  }

  // Move time forwards 2 seconds and inject another request.
  cwtest_advance_time_ms(2000);
  _load_monitor.request_complete(100000000);

  // Bucket fill rate should be unchanged at the minimum value.
  EXPECT_EQ(_load_monitor.bucket.rate, initial_rate);
}

TEST_F(LoadMonitorTest, AdmitRequest)
{
  // Test that initially the load monitor admits requests, but after a large number
  // of attempts in quick succession it has run out.
  EXPECT_EQ(_load_monitor.admit_request(), true);

  for (int ii = 0; ii <= 50; ii++)
  {
    _load_monitor.admit_request();
  }

  EXPECT_EQ(_load_monitor.admit_request(), false);
}

TEST_F(TokenBucketTest, GetToken)
{
  // Test that initially the token bucket gives out tokens, but after a large number
  // of attempts in quick succession it has run out.
  bool got_token = _token_bucket.get_token();
  EXPECT_EQ(got_token, true);

  for (int ii = 0; ii <= 50; ii++)
  {
    got_token = _token_bucket.get_token();
  }

  EXPECT_EQ(got_token, false);

}
