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
#include "test_interposer.hpp"
#include "mock_load_monitor.h"
#include "mock_pjsip_module.h"
#include "custom_headers.h"
#include "stack.h"
#include "testingcommon.h"

#include "thread_dispatcher.h"

class ThreadDispatcherTest : public ::testing::Test
{
public:
  virtual void SetUp()
  {
    init_test_pjsip();
  }

  // TODO: Fix memory leaks and check code
  virtual pj_status_t init_test_pjsip()
  {
    pj_status_t status;

    status = pj_init();
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);

    status = pjlib_util_init();
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);

    pj_caching_pool_init(&cp, &pj_pool_factory_default_policy, 0);

    status = pjsip_endpt_create(&cp.factory, NULL, &endpt);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);

    //status = pjsip_tsx_layer_init_module(endpt);

    pool = pj_pool_create(&cp.factory,
                          "test-pool",
                          4000,
                          4000,
                          NULL);

    status = register_custom_headers();
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);

    //PJUtils::init();

    mod_mock = new MockPJSipModule(endpt,
                                   "test-module",
                                   PJSIP_MOD_PRIORITY_TRANSPORT_LAYER);
    init_thread_dispatcher(1, NULL, NULL, &load_monitor, NULL, NULL);
    pjsip_process_rdata_param_default(&entry_point);
    entry_point.start_mod = get_mod_thread_dispatcher();

    return status;
  }

  virtual void inject_msg(const string& msg)
  {
    pjsip_rx_data* rdata = PJ_POOL_ZALLOC_T(pool, pjsip_rx_data);

    rdata->pkt_info.packet = (char*)pj_pool_alloc(pool, strlen(msg.data()) + 1);
    strcpy(rdata->pkt_info.packet, msg.data());
    rdata->pkt_info.len = msg.length();

    pjsip_endpt_process_rx_data(endpt, rdata, &entry_point, NULL);
  }

  virtual void term_test_pjsip()
  {
    //PJUtils::term();
    //pjsip_tsx_layer_destroy();
    pjsip_endpt_destroy(endpt);
    pj_pool_release(pool);
    pj_caching_pool_destroy(&cp);
    pj_shutdown();
  }

  virtual void Teardown()
  {
    delete mod_mock;
    mod_mock = nullptr;
    unregister_thread_dispatcher();
    term_test_pjsip();
  }

  MockPJSipModule* mod_mock;
  MockLoadMonitor load_monitor;
  pjsip_process_rdata_param entry_point;

protected:
  pj_caching_pool cp;
  pj_pool_t* pool;
  pjsip_endpoint* endpt;
};

TEST_F(ThreadDispatcherTest, NullTest)
{
  /*
  TestingCommon::Message msg;
  msg._first_hop = true;
  msg._method = "INVITE";
  msg._requri = "sip:bob@awaydomain";
  msg._from = "alice";
  msg._to = "bob";
  msg._todomain = "awaydomain";
  inject_msg(msg.get_request());
  */
}

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

    cwtest_completely_control_time();
  }

  virtual void TearDown()
  {
    cwtest_reset_time();

    delete q;
    q = nullptr;
  }

  SipEvent e1;
  SipEvent e2;

  pjsip_rx_data rdata_1;
  pjsip_rx_data rdata_2;

  eventq<struct SipEvent>* q;
};

// Test that higher priority SipEvents are 'larger' than lower priority ones.
TEST_F(SipEventQueueTest, PriorityOrdering)
{
  // Lower the priority of e2
  e2.priority = 1;

  // e1 should be 'larger' than e2
  EXPECT_TRUE(e1(e2, e1));
  EXPECT_TRUE(e2(e2, e1));
}

// Test that older SipEvents are 'larger' than newer ones at the same priority
// level.
TEST_F(SipEventQueueTest, TimeOrdering)
{
  // Set e1 to be older than e2
  e1.stop_watch.start();
  cwtest_advance_time_ms(1);
  e2.stop_watch.start();

  // e1 should be 'larger' than e2
  EXPECT_TRUE(e1(e2, e1));
  EXPECT_TRUE(e2(e2, e1));
}

// Test that SipEvents are ordered by priority before time.
TEST_F(SipEventQueueTest, PriorityAndTimeOrdering)
{
  // Lower the priority of e2
  e2.priority = 1;

  // Set e2 to be older than e1
  e1.stop_watch.start();
  cwtest_advance_time_ms(1);
  e2.stop_watch.start();

  // e1 should be 'larger' than e2
  EXPECT_TRUE(e1(e2, e1));
  EXPECT_TRUE(e2(e2, e1));
}

// Test that higher priority SipEvents are returned before lower priority ones.
TEST_F(SipEventQueueTest, QueuePriorityOrdering)
{
  // Lower the priority of e2
  e2.priority = 1;

  q->push(e2);
  q->push(e1);

  SipEvent e;

  // e1 is higher priority, so should be returned first
  q->pop(e);
  EXPECT_EQ(e1.event_data.rdata, e.event_data.rdata);

  q->pop(e);
  EXPECT_EQ(e2.priority, e.priority);
}

// Test that older SipEvents are returned before newer ones at the same priority
// level.
TEST_F(SipEventQueueTest, QueueTimeOrdering)
{
  // Set e1 to be older than e2
  e1.stop_watch.start();
  cwtest_advance_time_ms(1);
  e2.stop_watch.start();

  q->push(e2);
  q->push(e1);

  SipEvent e;

  // e1 is older, so should be returned first
  q->pop(e);
  EXPECT_EQ(e1.event_data.rdata, e.event_data.rdata);

  q->pop(e);
  EXPECT_EQ(e2.event_data.rdata, e.event_data.rdata);
}

// Test that SipEvents are returned from the queue in priority, then time, order
TEST_F(SipEventQueueTest, QueuePriorityAndTimeOrdering)
{
  // Lower the priority of e2
  e2.priority = 1;

  // Set e2 to be older than e1
  e1.stop_watch.start();
  cwtest_advance_time_ms(1);
  e2.stop_watch.start();

  q->push(e2);
  q->push(e1);

  SipEvent e;

  // e1 is higher priority, so should be returned first despite e2 being older
  q->pop(e);
  EXPECT_EQ(e1.event_data.rdata, e.event_data.rdata);

  q->pop(e);
  EXPECT_EQ(e2.event_data.rdata, e.event_data.rdata);
}

// TODO: Test overloading
