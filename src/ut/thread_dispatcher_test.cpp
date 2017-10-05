/**
 * @file thread_dispatcher_test.cpp UT for classes defined in
 *       thread_dispatcher.cpp
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "gtest/gtest.h"

#include "thread_dispatcher.h"

TEST(rxDataQueueInfoTest, PriorityOrdering)
{
  rxDataQueueInfo r1(nullptr, 0, 0);
  rxDataQueueInfo r2(nullptr, 1, 0);
  EXPECT_TRUE(r1(r1, r2));
  EXPECT_TRUE(r2(r1, r2));
  EXPECT_FALSE(r1(r2, r1));
  EXPECT_FALSE(r2(r2, r1));
}

TEST(rxDataQueueInfoTest, TimeOrdering)
{
  rxDataQueueInfo r1(nullptr, 0, 0);
  rxDataQueueInfo r2(nullptr, 0, 1);
  EXPECT_TRUE(r1(r1, r2));
  EXPECT_TRUE(r2(r1, r2));
  EXPECT_FALSE(r1(r2, r1));
  EXPECT_FALSE(r2(r2, r1));
}

TEST(rxDataQueueInfoTest, PriorityBeforeTimeOrdering)
{
  rxDataQueueInfo r1(nullptr, 0, 1);
  rxDataQueueInfo r2(nullptr, 1, 0);
  EXPECT_TRUE(r1(r1, r2));
}
