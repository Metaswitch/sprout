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
#include "testingcommon.h"
#include "mock_load_monitor.h"
#include "mock_pjsip_module.h"
#include "siptest.hpp"
#include "stack.h"

#include "thread_dispatcher.h"

using ::testing::Return;
using ::testing::StrictMock;
using ::testing::_;

class MockCallback : public PJUtils::Callback
{
  MOCK_METHOD0(run, void());
  MOCK_METHOD0(destruct, void());
  virtual ~MockCallback() { destruct(); }
};

class ThreadDispatcherTest : public SipTest
{
public:

  ThreadDispatcherTest()
  {
    mod_mock = new StrictMock<MockPJSipModule>(stack_data.endpt,
                                               "test-module",
                                               PJSIP_MOD_PRIORITY_TRANSPORT_LAYER);

    init_thread_dispatcher(1, NULL, NULL, NULL, &load_monitor, NULL, 2);
    mod_thread_dispatcher = get_mod_thread_dispatcher();

    cwtest_completely_control_time();
  }

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();

  }

  virtual void inject_msg_thread(std::string msg)
  {
    TRC_DEBUG("Injecting message:\n%s", msg.c_str());
    inject_msg_direct(msg, mod_thread_dispatcher);
  }

  static void TearDownTestCase()
  {
    SipTest::TearDownTestCase();
  }

  virtual ~ThreadDispatcherTest()
  {
    cwtest_reset_time();

    delete mod_mock;
    unregister_thread_dispatcher();
  }

  StrictMock<MockPJSipModule>* mod_mock;
  MockLoadMonitor load_monitor;
  pjsip_module* mod_thread_dispatcher;
  pjsip_process_rdata_param rp;

  const std::string sip_invite =
      "INVITE sip:a@homedomain SIP/2.0\n"
      "Via: SIP/2.0/TCP 0.0.0.0:5060;rport;branch=z9hG4bK0\n"
      "From: <sip:b@homedomain>;tag=0\n"
      "To: <sip:a@homedomain>\n"
      "Max-Forwards: 70\n"
      "Call-ID: 0\n"
      "CSeq: 1 INVITE\n"
      "User-Agent: Accession 2.0.0.0\n"
      "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\n"
      "Content-Length: 0\n"
      "";

  const std::string sip_options =
      "OPTIONS sip:a@homedomain SIP/2.0\n"
      "Via: SIP/2.0/TCP 0.0.0.0:5060;rport;branch=z9hG4bK0\n"
      "From: <sip:b@homedomain>;tag=0\n"
      "To: <sip:a@homedomain>\n"
      "Max-Forwards: 70\n"
      "Call-ID: 0\n"
      "CSeq: 1 OPTIONS\n"
      "User-Agent: Accession 2.0.0.0\n"
      "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\n"
      "Content-Length: 0\n"
      "";

  const std::string sip_response =
      "SIP/2.0 200 OK\n"
      "Via: SIP/2.0/TCP 0.0.0.0:5060;rport;branch=z9hG4bK0\n"
      "From: <sip:b@homedomain>;tag=0\n"
      "To: <sip:a@homedomain>\n"
      "Max-Forwards: 70\n"
      "Call-ID: 0\n"
      "CSeq: 1 INVITE\n"
      "User-Agent: Accession 2.0.0.0\n"
      "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\n"
      "Content-Length: 0\n"
      "";
};

TEST_F(ThreadDispatcherTest, StandardInviteTest)
{
  EXPECT_CALL(load_monitor, admit_request(_)).WillOnce(Return(true));
  EXPECT_CALL(*mod_mock, on_rx_request(_)).WillOnce(Return(PJ_TRUE));
  EXPECT_CALL(load_monitor, request_complete(_));

  inject_msg_thread(sip_invite);
  process_queue_element();
}

// Invites should be rejected with a 503 if the load monitor returns false.
TEST_F(ThreadDispatcherTest, OverloadedInviteTest)
{
  EXPECT_CALL(load_monitor, admit_request(_)).WillOnce(Return(false));
  EXPECT_CALL(*mod_mock, on_tx_response(_));
  // TODO: Check that this is a 503

  inject_msg_thread(sip_invite);
}

// Invites older than the specified request_on_queue_timeout parameter should
// be rejected.
TEST_F(ThreadDispatcherTest, RejectOldInviteTest)
{
  EXPECT_CALL(load_monitor, admit_request(_)).WillOnce(Return(true));
  EXPECT_CALL(*mod_mock, on_tx_response(_));
  // TODO: Check that this is a 503

  inject_msg_thread(sip_invite);
  cwtest_advance_time_ms(10);
  process_queue_element();
}

// On recieving an OPTIONS message, the thread dispatcher should not call into
// the load monitor - it should process the request regardless of load.
TEST_F(ThreadDispatcherTest, NeverRejectOptionsTest)
{
  EXPECT_CALL(*mod_mock, on_rx_request(_)).WillOnce(Return(PJ_TRUE));
  EXPECT_CALL(load_monitor, request_complete(_));

  inject_msg_thread(sip_options);
  process_queue_element();
}

// On recieving a SIP response, the thread dispatcher should not call into the
// load monitor - it should process the request regardless of load.
TEST_F(ThreadDispatcherTest, NeverRejectResponseTest)
{
  EXPECT_CALL(*mod_mock, on_rx_response(_)).WillOnce(Return(PJ_TRUE));
  EXPECT_CALL(load_monitor, request_complete(_));

  inject_msg_thread(sip_response);
  process_queue_element();
}

TEST_F(ThreadDispatcherTest, CallbackTest)
{
  StrictMock<MockCallback>* cb = new StrictMock<MockCallback>();
  add_callback_to_queue(cb);

  // The callback should be run then destroyed
  EXPECT_CALL(*cb, run());
  EXPECT_CALL(*cb, destruct());

  process_queue_element();
}

class SipEventQueueTest : public ::testing::Test
{
public:
  SipEventQueueTest()
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

  virtual ~SipEventQueueTest()
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
