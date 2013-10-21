/**
 * @file counter_test.cpp UT for statistics counter classes.
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
#include "counter.h"

using namespace std;

/// Fixture for StatisticCounterTest.
class StatisticCounterTest : public BaseTest
{
  StatisticCounter _counter;

  StatisticCounterTest() :
    _counter("incoming_requests", 999999999999) // make the period large to avoid intermittent failures due to timing
  {
  }

  virtual ~StatisticCounterTest()
  {
  }
};

TEST_F(StatisticCounterTest, NoSamples)
{
  _counter.refresh(true);
  EXPECT_EQ(_counter.get_count(), (uint_fast64_t)0);
}

TEST_F(StatisticCounterTest, OneSample)
{
  _counter.increment();
  _counter.refresh(true);
  EXPECT_EQ(_counter.get_count(), (uint_fast64_t)1);
}

TEST_F(StatisticCounterTest, BasicTest)
{
  _counter.increment();
  _counter.refresh(true);
  // No easy way to read statistics back.
}
