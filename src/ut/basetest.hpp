/**
 * @file basetest.hpp Base class for UTs.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

///
///----------------------------------------------------------------------------

#pragma once

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "fakelogger.h"
#include "stack.h"
#include "snmp_event_accumulator_table.h"

/// Fixture for test.
class BaseTest : public ::testing::Test
{
  virtual ~BaseTest();
};

