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

class EventInfoTest : public ::testing::Test
{
public:
  virtual void SetUp()
  {
    Event event;
    struct EventInfo event_info = {MESSAGE, event, 0, 0};
    e1 = event_info;
    e2 = event_info;
  }

  EventInfo e1;
  EventInfo e2;
};

TEST_F(EventInfoTest, PriorityOrdering)
{
  e2.priority = 1;
  EXPECT_TRUE(e1(e1, e2));
  EXPECT_TRUE(e2(e1, e2));
  EXPECT_FALSE(e1(e2, e1));
  EXPECT_FALSE(e2(e2, e1));
}

TEST_F(EventInfoTest, TimeOrdering)
{
  e2.queue_start_time = 1;
  EXPECT_TRUE(e1(e1, e2));
  EXPECT_TRUE(e2(e1, e2));
  EXPECT_FALSE(e1(e2, e1));
  EXPECT_FALSE(e2(e2, e1));
}

TEST_F(EventInfoTest, PriorityBeforeTimeOrdering)
{
  e2.priority = 1;
  e1.queue_start_time = 1;
  EXPECT_TRUE(e1(e1, e2));
}
