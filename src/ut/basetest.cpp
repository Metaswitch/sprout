/**
 * @file basetest.cpp Base class for UTs.
 *
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

///
///----------------------------------------------------------------------------

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "statistic.h"
#include "stack.h"

#include "basetest.hpp"
#include "test_interposer.hpp"

using namespace std;

BaseTest::~BaseTest()
{
  // This ensures the UTs don't carry over any time they've advanced.
  cwtest_reset_time();
};

