/**
 * @file connection_tracker_test.cpp UT for Sprout connection tracker class.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version, along with the "Special Exception" for use of
 * the program along with SSL, set forth below. This program is distributed
 * in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details. You should have received a copy of the GNU General Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by
 * post at Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 *
 * Special Exception
 * Metaswitch Networks Ltd  grants you permission to copy, modify,
 * propagate, and distribute a work formed by combining OpenSSL with The
 * Software, or a work derivative of such a combination, even if such
 * copying, modification, propagation, or distribution would otherwise
 * violate the terms of the GPL. You must comply with the GPL in all
 * respects for all of the code used other than OpenSSL.
 * "OpenSSL" means OpenSSL toolkit software distributed by the OpenSSL
 * Project and licensed under the OpenSSL Licenses, or a work based on such
 * software and licensed under the OpenSSL Licenses.
 * "OpenSSL Licenses" means the OpenSSL License and Original SSLeay License
 * under which the OpenSSL Project distributes the OpenSSL toolkit software,
 * as those licenses appear in the file LICENSE-OPENSSL.
 */

///
///----------------------------------------------------------------------------

#include <string>
#include "gtest/gtest.h"
#include <json/reader.h>

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
  virtual ~ConnectionTrackerTest() {}

  // Called after all testcases have ben run.
  static void TearDownTestCase()
  {
    SipTest::TearDownTestCase();
  }

private:

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

TEST_F(ConnectionTrackerTest, QuiesceWithOneConnection)
{
  // Create a new TCP transport.
  pjsip_transport *tp;
  pj_sockaddr rem_addr;
  pj_str_t addr_str = pj_str("1.2.3.4");
  pj_sockaddr_init(PJ_AF_INET, &rem_addr, &addr_str, stack_data.trusted_port);

  pj_status_t status = pjsip_fake_tcp_accept(_tcp_tpfactory_trusted,
                                             (pj_sockaddr_t*)&rem_addr,
                                             sizeof(pj_sockaddr_in),
                                             &tp);
  EXPECT_EQ(PJ_SUCCESS, status);

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

  // Unref the transport.  The tracker reports quiesce complete.
  pjsip_transport_dec_ref(tp);
  EXPECT_TRUE(_conns_quiesced_handler->quiesced);
}

TEST_F(ConnectionTrackerTest, AlwaysFails) { EXPECT_TRUE(false); }
