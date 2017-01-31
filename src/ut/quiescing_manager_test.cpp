/**
 * @file quiesing_manager_test.cpp UT for Sprout quiescing manager class.
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

#include "utils.h"
#include "stack.h"
#include "quiescing_manager.h"

#include "basetest.hpp"

using namespace std;

// Macro to set a boolean flag to a new value, checking that it had the other
// value first.
#define TOGGLE_FLAG(FLAG, NEW_VALUE)      \
  assert((FLAG) || (NEW_VALUE));          \
  assert((!(FLAG)) || (!(NEW_VALUE)));    \
  (FLAG) = (NEW_VALUE)


// The following three classes implement the three QuiescingManager interfaces
// that handle connection management, flow management, and notification when
// quiescing completes.  They record what state the quiescing manager has
// requested.
class TestConnectionHandler : public QuiesceConnectionsInterface
{
public:
  TestConnectionHandler() :
    trusted_port_open(true),
    untrusted_port_open(true),
    connections_quiesced(false)
  {}

  virtual ~TestConnectionHandler() {}

  void close_untrusted_port() { TOGGLE_FLAG(untrusted_port_open, false); }
  void close_trusted_port() { TOGGLE_FLAG(trusted_port_open, false); }
  void quiesce() { TOGGLE_FLAG(connections_quiesced, true); }
  void unquiesce() { TOGGLE_FLAG(connections_quiesced, false); }
  void open_trusted_port() { TOGGLE_FLAG(trusted_port_open, true); }
  void open_untrusted_port() { TOGGLE_FLAG(untrusted_port_open, true); }

  bool trusted_port_open;
  bool untrusted_port_open;
  bool connections_quiesced;
};

class TestFlowsHandler : public QuiesceFlowsInterface
{
public:
  TestFlowsHandler() :
    flows_quiesced(false)
  {};

  virtual ~TestFlowsHandler() {}

  void quiesce() { TOGGLE_FLAG(flows_quiesced, true); }
  void unquiesce() { TOGGLE_FLAG(flows_quiesced, false); }

  bool flows_quiesced;
};

class TestCompletionHandler : public QuiesceCompletionInterface
{
public:
  TestCompletionHandler() :
    complete(false)
  {}

  virtual ~TestCompletionHandler() {}

  void quiesce_complete() { TOGGLE_FLAG(complete, true); }

  bool complete;
};

#undef TOGGLE_FLAG


// Test fixture.
class QuiescingManagerTest : public BaseTest
{
public:
  // Called at the start of every testcase.
  QuiescingManagerTest()
  {
    _qm = new QuiescingManager();

    _conns_handler = new TestConnectionHandler();
    _flows_handler = new TestFlowsHandler();
    _completion_handler = new TestCompletionHandler();
  }

  // Called at the end of every testcase.
  virtual ~QuiescingManagerTest()
  {
    delete _conns_handler; _conns_handler = NULL;
    delete _flows_handler; _flows_handler = NULL;
    delete _completion_handler; _completion_handler = NULL;

    delete _qm; _qm = NULL;
  }

  void register_all()
  {
    _qm->register_conns_handler(_conns_handler);
    _qm->register_flows_handler(_flows_handler);
    _qm->register_completion_handler(_completion_handler);
  }

private:
  QuiescingManager *_qm;

  TestConnectionHandler *_conns_handler;
  TestFlowsHandler *_flows_handler;
  TestCompletionHandler *_completion_handler;
};


#define EXPECT_UNQUIESCED()                               \
  EXPECT_TRUE(_conns_handler->trusted_port_open);         \
  EXPECT_TRUE(_conns_handler->untrusted_port_open);       \
  EXPECT_FALSE(_conns_handler->connections_quiesced);     \
  EXPECT_FALSE(_flows_handler->flows_quiesced);           \
  EXPECT_FALSE(_completion_handler->complete)

#define EXPECT_FULLY_QUIESCED()                           \
  EXPECT_FALSE(_conns_handler->trusted_port_open);        \
  EXPECT_FALSE(_conns_handler->untrusted_port_open);      \
  EXPECT_TRUE(_conns_handler->connections_quiesced);      \
  EXPECT_TRUE(_flows_handler->flows_quiesced);            \
  EXPECT_TRUE(_completion_handler->complete)

//
// Tests defined below.
//

// Satisfy ourselves that the test framework is set up correctly before we run
// any more tests.
TEST_F(QuiescingManagerTest, VerifyTestFramework)
{
  EXPECT_UNQUIESCED();
}


// Mainline quiescing:
//   Quiesce:   Untrusted port closed, flows start to quiesce.
//   FlowsGone: Trusted port closed, connections start to quiesce.
//   ConnsGone: Quiescing is complete.
TEST_F(QuiescingManagerTest, MainlineQuiescing)
{
  register_all();

  EXPECT_FALSE(_qm->is_quiescing());
  _qm->quiesce();
  EXPECT_TRUE(_qm->is_quiescing());
  EXPECT_FALSE(_conns_handler->untrusted_port_open);
  EXPECT_TRUE(_flows_handler->flows_quiesced);

  _qm->flows_gone();
  EXPECT_FALSE(_conns_handler->untrusted_port_open);
  EXPECT_TRUE(_flows_handler->flows_quiesced);
  EXPECT_FALSE(_conns_handler->trusted_port_open);
  EXPECT_TRUE(_conns_handler->connections_quiesced);

  _qm->connections_gone();
  EXPECT_FULLY_QUIESCED();
}


// Unquiesce while flows are quiescing.
TEST_F(QuiescingManagerTest, QuiesceWhileFlowsQuiescing)
{
  register_all();

  _qm->quiesce();

  _qm->unquiesce();
  EXPECT_UNQUIESCED();

  // Check that we can still quiesce successfully.
  _qm->quiesce();
  _qm->flows_gone();
  _qm->connections_gone();
  EXPECT_FULLY_QUIESCED();
}


// Unquiesce while connections are quiescing.
TEST_F(QuiescingManagerTest, QuiesceWhileConnsQuiescing)
{
  register_all();

  _qm->quiesce();
  _qm->flows_gone();

  _qm->unquiesce();
  EXPECT_UNQUIESCED();

  // Check that we can still quiesce successfully.
  _qm->quiesce();
  _qm->flows_gone();
  _qm->connections_gone();
  EXPECT_FULLY_QUIESCED();
}

// Once we're quiesced you can never unquiesce.
TEST_F(QuiescingManagerTest, CannotUnquiesceOnceQuiesced)
{
  register_all();

  // Quiesce.
  _qm->quiesce();
  _qm->flows_gone();
  _qm->connections_gone();
  EXPECT_FULLY_QUIESCED();

  // Try to unquiesce. Allowed, but does nothing.
  _qm->unquiesce();
  EXPECT_FULLY_QUIESCED();

  // Try to quiesce again. Allowed, but does nothing.
  _qm->unquiesce();
  EXPECT_FULLY_QUIESCED();
}


// Window condition: unquiesce while the flows_gone call is being made (so that
// the unquiesce call beats the flows_gone call).
TEST_F(QuiescingManagerTest, FlowsGoneAfterUnquiesce)
{
  register_all();

  _qm->quiesce();

  // We're expecting a flows_gone call now, but instead we quiesce.
  _qm->unquiesce();

  // Now get flows_gone.  It is ignored.
  _qm->flows_gone();
  EXPECT_UNQUIESCED();

  // Check that we can still quiesce successfully.
  _qm->quiesce();
  _qm->flows_gone();
  _qm->connections_gone();
  EXPECT_FULLY_QUIESCED();
}

// Window condition: Unquiesce while the connections_gone call is being made (so
// the unquiesce call beats the connections_gone call).
TEST_F(QuiescingManagerTest, ConnsGoneAfterQuiesce)
{
  register_all();

  _qm->quiesce();
  _qm->flows_gone();

  // We're expecting a connections_gone call now, but instead unquiesce.
  _qm->unquiesce();

  // now get connections gone. It is ignored.
  _qm->connections_gone();
  EXPECT_UNQUIESCED();

  // Check that we can still quiesce successfully.
  _qm->quiesce();
  _qm->flows_gone();
  _qm->connections_gone();
  EXPECT_FULLY_QUIESCED();
}

// Window condition: Unquiesce and re-quiesce before the connections_gone call
// is made.
TEST_F(QuiescingManagerTest, ComnnsGoneWhileflowsQuiescing)
{
  register_all();

  _qm->quiesce();
  _qm->flows_gone();

  // We're expecting a connections_gone call now, but first we unquiesce and
  // re-quiesce.
  _qm->unquiesce();
  _qm->quiesce();

  // Now get the connections_gone.
  _qm->connections_gone();

  // Finish off quiescing, to check that it still works.
  _qm->flows_gone();
  _qm->connections_gone();
  EXPECT_FULLY_QUIESCED();
}

TEST_F(QuiescingManagerTest, FlowsGoneWhileConnsQuiescing)
{
  register_all();

  _qm->quiesce();

  // Expecting flwos_gone call now, but instead unquiesce and re-quiesce.
  _qm->unquiesce();
  _qm->quiesce();

  // Now get the flows gone for the first quiesce, followed by the flows_gone
  // and connections_gone for the second quiesce.
  _qm->flows_gone();
  _qm->flows_gone();
  _qm->connections_gone();
  EXPECT_FULLY_QUIESCED();
}


// Trivial testcase to hit an invalid cell and check that error logging works.
TEST_F(QuiescingManagerTest, InvalidCells)
{
  CapturingTestLogger log;
  _qm->quiesce();
  _qm->quiesce();
  EXPECT_TRUE(log.contains("invalid input"));
}


// When no flows handler is registered we do not need to call flows_gone to
// continue quiescing.
TEST_F(QuiescingManagerTest, QuiesceWithoutFlowsHandler)
{
  // Don't register the flows handler.
  _qm->register_conns_handler(_conns_handler);
  _qm->register_completion_handler(_completion_handler);

  // Quiesce.  No flows handler so we moved straight on to quiescing
  // connections.
  _qm->quiesce();
  EXPECT_FALSE(_conns_handler->untrusted_port_open);
  EXPECT_FALSE(_conns_handler->trusted_port_open);
  EXPECT_TRUE(_conns_handler->connections_quiesced);

  // Quiescing completes successfully.
  _qm->connections_gone();
  EXPECT_FALSE(_conns_handler->trusted_port_open);
  EXPECT_FALSE(_conns_handler->untrusted_port_open);
  EXPECT_TRUE(_conns_handler->connections_quiesced);
  EXPECT_TRUE(_completion_handler->complete);
}
