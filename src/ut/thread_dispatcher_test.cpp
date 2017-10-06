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

class worker_thread_qeTest : public ::testing::Test
{
public:
  virtual void SetUp()
  {
    SipEvent event;
    struct worker_thread_qe event_info = {MESSAGE, event, 0};
    e1 = event_info;
    e2 = event_info;
    PriorityEventQueueBackend* q_backend = new PriorityEventQueueBackend();
    q = new eventq<struct worker_thread_qe>(0, true, q_backend);
  }

  virtual void TearDown()
  {
    delete q;
    q = nullptr;
  }

  worker_thread_qe e1;
  worker_thread_qe e2;
  eventq<struct worker_thread_qe>* q;
};

TEST_F(worker_thread_qeTest, PriorityTest)
{
  e2.priority = 1;
  q->push(e2);
  q->push(e1);
  worker_thread_qe e;
  q->pop(e);
  EXPECT_EQ(e1.priority, e.priority);
  q->pop(e);
  EXPECT_EQ(e2.priority, e.priority);
}
