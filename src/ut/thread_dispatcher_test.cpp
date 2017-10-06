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

class WorkerThreadQeTest : public ::testing::Test
{
public:
  virtual void SetUp()
  {
    // We can distinguish e1 and e2 by the value of en.event.message
    SipEvent event;
    event.message = &event_msg_1;
    e1 = {MESSAGE, event, 0};

    event.message = &event_msg_2;
    e2 = {MESSAGE, event, 0};

    PriorityEventQueueBackend* q_backend = new PriorityEventQueueBackend();
    q = new eventq<struct WorkerThreadQe>(0, true, q_backend);
  }

  virtual void TearDown()
  {
    delete q;
    q = nullptr;
  }

  WorkerThreadQe e1;
  WorkerThreadQe e2;

  SipMessageEvent event_msg_1;
  SipMessageEvent event_msg_2;

  eventq<struct WorkerThreadQe>* q;
};

// Test that the queue is FIFO at each priority level.
TEST_F(WorkerThreadQeTest, TimeTest)
{
  q->push(e1);
  q->push(e2);

  WorkerThreadQe e;

  q->pop(e);
  EXPECT_EQ(e1.event.message, e.event.message);

  q->pop(e);
  EXPECT_EQ(e2.type, e.type);
}

// Test that higher priority elements are returned before lower priority ones,
// regardless of order added.
TEST_F(WorkerThreadQeTest, PriorityTest)
{
  // Lower the priority of e2
  e2.priority = 1;

  q->push(e2);
  q->push(e1);

  WorkerThreadQe e;

  q->pop(e);
  EXPECT_EQ(e1.priority, e.priority);

  q->pop(e);
  EXPECT_EQ(e2.priority, e.priority);
}
