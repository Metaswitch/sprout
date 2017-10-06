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


class SipEventQueueTest : public ::testing::Test
{
public:
  virtual void SetUp()
  {
    // We can distinguish e1 and e2 by the value of en.event_data.rdata
    SipEventData event_data;
    event_data.rdata = &rdata_1;
    e1.type = MESSAGE;
    e1.event_data = event_data;

    event_data.rdata = &rdata_2;
    e2.type = MESSAGE;
    e2.event_data = event_data;

    PriorityEventQueueBackend* q_backend = new PriorityEventQueueBackend();
    q = new eventq<struct SipEvent>(0, true, q_backend);
  }

  virtual void TearDown()
  {
    delete q;
    q = nullptr;
  }

  SipEvent e1;
  SipEvent e2;

  pjsip_rx_data rdata_1;
  pjsip_rx_data rdata_2;

  eventq<struct SipEvent>* q;
};

// Test that the queue is FIFO at each priority level.
TEST_F(SipEventQueueTest, TimeTest)
{
  q->push(e1);
  q->push(e2);

  SipEvent e;

  q->pop(e);
  EXPECT_EQ(e1.event_data.rdata, e.event_data.rdata);

  q->pop(e);
  EXPECT_EQ(e2.type, e.type);
}

// Test that higher priority elements are returned before lower priority ones,
// regardless of order added.
TEST_F(SipEventQueueTest, PriorityTest)
{
  // Lower the priority of e2
  e2.priority = 1;

  q->push(e2);
  q->push(e1);

  SipEvent e;

  q->pop(e);
  EXPECT_EQ(e1.priority, e.priority);

  q->pop(e);
  EXPECT_EQ(e2.priority, e.priority);
}
