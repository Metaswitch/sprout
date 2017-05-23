/**
 * @file connection_tracker_test.cpp UT for Sprout connection tracker class.
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

#include <string>
#include "gtest/gtest.h"

#include "utils.h"
#include "stack.h"
#include "connection_tracker.h"

#include "faketransport_udp.hpp"
#include "faketransport_tcp.hpp"
#include "siptest.hpp"

using namespace std;

class ConnectionsQuiescedHandler : public ConnectionsQuiescedInterface
{
public:
  ConnectionsQuiescedHandler() :
    quiesced(false)
  {}

  virtual ~ConnectionsQuiescedHandler()
  {}

  bool quiesced;
  void connections_quiesced()
  {
    quiesced = true;
  }

private:
};

class ConnectionTrackerTest : public SipTest
{
public:
  // Called before any testcases have been run.
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
  }

  // Called at the start of every testcase.
  ConnectionTrackerTest()
  {
    _conns_quiesced_handler = new ConnectionsQuiescedHandler();
    _conn_tracker = new ConnectionTracker(_conns_quiesced_handler);
  }

  // Called at the end of every testcase.
  virtual ~ConnectionTrackerTest()
  {
    delete _conn_tracker; _conn_tracker = NULL;
    delete _conns_quiesced_handler; _conns_quiesced_handler = NULL;
  }

  // Called after all testcases have ben run.
  static void TearDownTestCase()
  {
    SipTest::TearDownTestCase();
  }

private:

  pjsip_transport *create_new_tcp_conn()
  {
    pjsip_transport *tp;
    pj_sockaddr rem_addr;
    pj_str_t addr_str = pj_str("1.2.3.4");
    pj_sockaddr_init(PJ_AF_INET, &rem_addr, &addr_str, stack_data.scscf_port);

    pj_status_t status = pjsip_fake_tcp_accept(TransportFlow::tcp_factory(stack_data.scscf_port),
                                               (pj_sockaddr_t*)&rem_addr,
                                               sizeof(pj_sockaddr_in),
                                               &tp);
    EXPECT_EQ(PJ_SUCCESS, status);

    return tp;
  }

  ConnectionTracker *_conn_tracker;
  ConnectionsQuiescedHandler *_conns_quiesced_handler;
};

//
// Tests defined below.
//

// When the connection tracker does not know about any connections, it quiesces
// immediately.
TEST_F(ConnectionTrackerTest, QuiesceWithNoConnections)
{
  _conn_tracker->quiesce();
  EXPECT_TRUE(_conns_quiesced_handler->quiesced);
}

// When the connection tracker only knows about one connection, it quiesces once
// that connection is not longer referenced.
TEST_F(ConnectionTrackerTest, QuiesceWithOneConnection)
{
  // Create a new TCP transport.
  pjsip_transport *tp = create_new_tcp_conn();

  // Reference the transport.  This makes it look like there is a transaction in
  // progress.
  pjsip_transport_add_ref(tp);

  // Notify the connection tracker of the connection.
  _conn_tracker->connection_active(tp);

  // Quiesce the connection manager.  The transport gets shutdown, but the
  // manager does not report it has quiesced (as there is still a reference on
  // the transport).
  _conn_tracker->quiesce();
  EXPECT_FALSE(_conns_quiesced_handler->quiesced);
  EXPECT_TRUE(tp->is_shutdown);

  // Unref the transport.  The tracker reports quiesce complete.  This happens
  // on a zero length timer, which we trigger via poll.
  pjsip_transport_dec_ref(tp); poll();

  EXPECT_TRUE(_conns_quiesced_handler->quiesced);
}

TEST_F(ConnectionTrackerTest, QuiesceNewConnections)
{
  // Create 2 new TCP transports.
  pjsip_transport *tp1 = create_new_tcp_conn();
  pjsip_transport *tp2 = create_new_tcp_conn();

  // Reference them both.
  pjsip_transport_add_ref(tp1);
  pjsip_transport_add_ref(tp2);

  // Notify the connection tracker of the first connection.
  _conn_tracker->connection_active(tp1);

  // Quiesce. Only the first connection is shutdown (as the connection tracker
  // doesn't know about the other one yet).
  _conn_tracker->quiesce();
  EXPECT_TRUE(tp1->is_shutdown);
  EXPECT_FALSE(tp2->is_shutdown);
  EXPECT_FALSE(_conns_quiesced_handler->quiesced);

  // Notify the connection tracker of the 2nd connection. It's shutdown
  // immediately.
  _conn_tracker->connection_active(tp2);
  EXPECT_TRUE(tp1->is_shutdown);
  EXPECT_TRUE(tp2->is_shutdown);
  EXPECT_FALSE(_conns_quiesced_handler->quiesced);

  // Unref the transports. Quiescing only comlpetes once all have been
  // unreferenced.
  pjsip_transport_dec_ref(tp1); poll();
  EXPECT_FALSE(_conns_quiesced_handler->quiesced);

  pjsip_transport_dec_ref(tp2); poll();
  EXPECT_TRUE(_conns_quiesced_handler->quiesced);
}


// Mainline unquiesce testcase involving one connection.
TEST_F(ConnectionTrackerTest, UnquiesceWithOneConnection)
{
  pjsip_transport *tp = create_new_tcp_conn();
  pjsip_transport_add_ref(tp);

  _conn_tracker->connection_active(tp);

  _conn_tracker->quiesce();
  EXPECT_TRUE(tp->is_shutdown);
  EXPECT_FALSE(_conns_quiesced_handler->quiesced);

  _conn_tracker->unquiesce();
  EXPECT_FALSE(_conns_quiesced_handler->quiesced);

  // Even when the connection is destroyed the connection tracker does not
  // consider quiescing as complete (since we have unquiesced it).
  pjsip_transport_dec_ref(tp); poll();
  EXPECT_FALSE(_conns_quiesced_handler->quiesced);
}


// Unquiescing makes the connection tracker accept new connections.
TEST_F(ConnectionTrackerTest, UnquiesceAllowsNewConnections)
{
  pjsip_transport *tp1 = create_new_tcp_conn();
  pjsip_transport *tp2 = create_new_tcp_conn();
  pjsip_transport_add_ref(tp1);
  pjsip_transport_add_ref(tp2);

  // Quiesce while the tracker knows about one connection.
  _conn_tracker->connection_active(tp1);
  _conn_tracker->quiesce();
  EXPECT_TRUE(tp1->is_shutdown);
  EXPECT_FALSE(_conns_quiesced_handler->quiesced);

  _conn_tracker->unquiesce();

  // After we've unquiesced new connections are not immediately shutdown.
  _conn_tracker->connection_active(tp2);
  EXPECT_FALSE(tp2->is_shutdown);

  // The first connection completes shutdown.  Quiescing is not considered
  // complete.
  pjsip_transport_dec_ref(tp1); poll();
  EXPECT_FALSE(_conns_quiesced_handler->quiesced);

  // Unreference the 2nd connection (as if it no longer had any transactions),
  // then shut it down.  The connection tracker does not report a quiesce (as we
  // have unquiesced it).
  fake_tcp_init_shutdown((fake_tcp_transport *)tp2, 1);
  pjsip_transport_dec_ref(tp2); poll();
  EXPECT_FALSE(_conns_quiesced_handler->quiesced);
}


// Unquiesce the connection tracker after quiescing is complete.  This is a
// non-mainline case but is allowed according to the ConnectionTracker's
// interface.
TEST_F(ConnectionTrackerTest, UnquiescAfterQuiesceComplete)
{
  // Quiesce and unquiesce.
  _conn_tracker->quiesce();
  EXPECT_TRUE(_conns_quiesced_handler->quiesced);

  _conn_tracker->unquiesce();

  // Create a new connection and tell the tracker about it.  It is not shutdown.
  pjsip_transport *tp = create_new_tcp_conn();
  pjsip_transport_add_ref(tp);

  _conn_tracker->connection_active(tp);
  EXPECT_FALSE(tp->is_shutdown);

  // Clean up.
  fake_tcp_init_shutdown((fake_tcp_transport *)tp, 1);
  pjsip_transport_dec_ref(tp); poll();
}


// Check the connection tracker can be deleted while there are still active
// connections it knows about.
TEST_F(ConnectionTrackerTest, DeleteTrackerWithConnections)
{
  // Create a connection and tell the tracker about it.
  pjsip_transport *tp = create_new_tcp_conn();
  pjsip_transport_add_ref(tp);
  _conn_tracker->connection_active(tp);

  // Delete the tracker, then shutdown the connection it was referencing. This
  // should not cause any crashes.
  delete _conn_tracker; _conn_tracker = NULL;

  fake_tcp_init_shutdown((fake_tcp_transport *)tp, 1);
  pjsip_transport_dec_ref(tp); poll();
}

