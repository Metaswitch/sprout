/**
 * @file basetest.cpp Base class for UTs.
 *
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by post at
 * Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 */

///
///----------------------------------------------------------------------------

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "statistic.h"
#include "zmq_lvc.h"
#include "stack.h"
#include "fakelogger.hpp"

#include "basetest.hpp"

using namespace std;

BaseTest::BaseTest()
{
  stack_data.stats_aggregator = new LastValueCache(Statistic::known_stats_count(),
                                                   Statistic::known_stats());
}

BaseTest::~BaseTest()
{
  delete stack_data.stats_aggregator;
  stack_data.stats_aggregator = NULL;
}

