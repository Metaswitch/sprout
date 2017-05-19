/**
 * @file test_utils.hpp Unit test utility functions header file
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


#pragma once

#include "gtest/gtest.h"
#include <algorithm>
#include <string>

/// Expect that std::list L contains value X.
#define EXPECT_CONTAINED(X, L) \
  EXPECT_TRUE(find((L).begin(), (L).end(), (X)) != (L).end())

/// The directory that contains the unit tests.
extern const std::string UT_DIR;
