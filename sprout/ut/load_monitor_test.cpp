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

/// Fixture for LoadMonitorTest.
class LoadMonitorTest : public BaseTest
{
  LoadMonitor _load_monitor;

  LoadMonitorTest() :
    _load_monitor(100000, 20, 10, 10)
  {
  }

  virtual ~LoadMonitorTest()
  {
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
  // Start with the expected latency. The rate will be unchanged. 
  for (int ii = 0; ii < 40; ii++)
  {
   _load_monitor.request_complete(100000);
  }

  EXPECT_EQ(_load_monitor.smoothed_latency, 99517);

  // Increase the latency; this will cause the token rate to decrease
  for (int ii = 0; ii < 20; ii++)
  {
   _load_monitor.request_complete(200000);
  }

  EXPECT_EQ(_load_monitor.smoothed_latency, 193042);

  // Dectease the latency; this will cause the token rate to increase. 
  for (int ii = 0; ii < 20; ii++)
  {
    _load_monitor.request_complete(1000);
  }

  EXPECT_EQ(_load_monitor.smoothed_latency, 14288);

  // Keep the latency low, but incur a penalty. The token rate increases. 
  _load_monitor.incr_penalties();

  for (int ii = 0; ii < 20; ii++)
  {
    _load_monitor.request_complete(1000);
  }

  EXPECT_EQ(_load_monitor.smoothed_latency, 1917);
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
