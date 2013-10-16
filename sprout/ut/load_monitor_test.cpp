/**
 * @file accumulator_test.cpp UT for statistics accumulator classes.
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

using namespace std;

/// Fixture for AccumulatorTest.
class LoadMonitorTest : public BaseTest
{
  LoadMonitor _load_monitor;

  LoadMonitorTest() :
    _load_monitor(100, 20, 10, 10) // make the period large to avoid intermittent failures due to timing
  {
  }

  virtual ~LoadMonitorTest()
  {
  }
};

class LeakyBucketTest : public BaseTest
{
  LeakyBucket _leaky_bucket;

  LeakyBucketTest() :
    _leaky_bucket(20, 10) // make the period large to avoid intermittent failures due to timing
  {
  }

  virtual ~LeakyBucketTest()
  {
  }
};

/// Fixture for StatisticAccumulatorTest.
//class StatisticAccumulatorTest : public BaseTest
//{
//  StatisticAccumulator _accumulator;
//
//  StatisticAccumulatorTest() :
//    _accumulator("latency_us", 999999999999) // make the period large to avoid intermittent failures due to timing
//  {
//  }

 // virtual ~StatisticAccumulatorTest()
 // {
 // }
//};

TEST_F(LoadMonitorTest, NoSamples)
{
  for (int ii = 0; ii <= 50; ii++)
  {
   bool test = _load_monitor.admit_request();
  }
 
//.refresh(true);
  EXPECT_EQ(_load_monitor.admit_request(), false);
  _load_monitor.request_complete(1);
  // EXPECT_EQ(_accumulator.get_mean(), (uint_fast64_t)0);
 // EXPECT_EQ(_accumulator.get_variance(), (uint_fast64_t)0);
 // EXPECT_EQ(_accumulator.get_lwm(), (uint_fast64_t)0);
 // EXPECT_EQ(_accumulator.get_hwm(), (uint_fast64_t)0);
}

TEST_F(LeakyBucketTest, NoSamples2)
{
  for (int ii = 0; ii <= 50; ii++)
  {
   bool test = _leaky_bucket.get_token();
  }

//.refresh(true);
  EXPECT_EQ(_leaky_bucket.get_token(), false);
 // EXPECT_EQ(_accumulator.get_mean(), (uint_fast64_t)0);
 // EXPECT_EQ(_accumulator.get_variance(), (uint_fast64_t)0);
 // EXPECT_EQ(_accumulator.get_lwm(), (uint_fast64_t)0);
 // EXPECT_EQ(_accumulator.get_hwm(), (uint_fast64_t)0);
}

TEST_F(LeakyBucketTest, NoSamples3)
{
  _leaky_bucket.update_rate(1);
  _leaky_bucket.update_max_size(1);
  _leaky_bucket.replenish_bucket();
  for (int ii = 0; ii <= 50; ii++)
  {
   bool test = _leaky_bucket.get_token();
  }

//.refresh(true);
  EXPECT_EQ(_leaky_bucket.get_token(), false);
 // EXPECT_EQ(_accumulator.get_mean(), (uint_fast64_t)0);
 // EXPECT_EQ(_accumulator.get_variance(), (uint_fast64_t)0);
 // EXPECT_EQ(_accumulator.get_lwm(), (uint_fast64_t)0);
 // EXPECT_EQ(_accumulator.get_hwm(), (uint_fast64_t)0);
}

TEST_F(LoadMonitorTest, NoSamples4)
{
  for (int ii = 0; ii <= 50; ii++)
  {
    _load_monitor.request_complete(1);
  }

//.refresh(true);
 // EXPECT_EQ(_load_monitor.admit_request(), false);
//  _load_monitor.request_complete(1);
  // EXPECT_EQ(_accumulator.get_mean(), (uint_fast64_t)0);
 // EXPECT_EQ(_accumulator.get_variance(), (uint_fast64_t)0);
 // EXPECT_EQ(_accumulator.get_lwm(), (uint_fast64_t)0);
 // EXPECT_EQ(_accumulator.get_hwm(), (uint_fast64_t)0);
}


//TEST_F(StatisticAccumulatorTest, BasicTest)
//{
//  _accumulator.accumulate(1234);
//  _accumulator.refresh(true);
  // No easy way to read statistics back.
//}
