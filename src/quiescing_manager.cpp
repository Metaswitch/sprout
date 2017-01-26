/**
 * @file quiescing_manager.cpp
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

// Common STL includes.
#include <cassert>

#include "log.h"
#include "utils.h"
#include "pjutils.h"

#include "quiescing_manager.h"

// Definitions of the names for the quiescing manager's inputs and states.
const char *QuiescingManager::STATE_NAMES[4] = {
  "ACTIVE",
  "QUIESCING_FLOWS",
  "QUIESCING_CONNS",
  "QUIESCED",
};

const char *QuiescingManager::INPUT_NAMES[4] = {
  "QUIESCE",
  "FLOWS_GONE",
  "CONNS_GONE",
  "UNQUIESCE",
};

SynchronizedFSM::SynchronizedFSM() :
  _running(false),
  _input_q()
{
  pthread_mutex_init(&_lock, NULL);
}

SynchronizedFSM::~SynchronizedFSM()
{
  pthread_mutex_destroy(&_lock);
}

void SynchronizedFSM::send_input(int input)
{
  pthread_mutex_lock(&_lock);

  // Queue the new input, even if we could process it immediately.
  _input_q.push(input);

  if (!_running)
  {
    // The FSM is not already running. Set a flag to show that it is running (so
    // now other threads will attempt to run it at the same time we are).
    _running = true;

    // Process all the inputs on the queue.  For each one remove it from the
    // queue and call process_input (which is implemented by the subclass).
    while (!_input_q.empty())
    {
      int next_input = _input_q.front();
      _input_q.pop();

      // Drop the lock when calling process_input.  This allows the FSM to be
      // re-entrant.
      pthread_mutex_unlock(&_lock);
      process_input(next_input);
      pthread_mutex_lock(&_lock);
    }

    _running = false;
  }

  pthread_mutex_unlock(&_lock);
}


QuiescingManager::QuiescingManager() :
  SynchronizedFSM(),
  _conns_handler(NULL),
  _flows_handler(NULL),
  _completion_handler(NULL)
{
  _state = STATE_ACTIVE;
}


// Implement the state machine for the QuiescingManager class.
//
// The state machine is descibed by the table below where each cell sepcifies
// the state to move to (as a number) and the action to take (as a letter).
// Dashes indicate no state change / action.  Empty cells are not hittable.
//
// Inputs \ States |  0  |  1  |  2  |  3  |
// ----------------+-----+-----+-----+-----+
// QUIESCE         | 1 A |     |     | - - |
// FLOWS_GONE      | - - | 2 B | - - |     |
// CONNS_GONE      | - - | - - | 3 C |     |
// UNQUIESCE       |     | 0 D | 0 E | - - |
//
// States:
//   0  ACTIVE
//   1  QUIESCING_FLOWS
//   2  QUIESCING_CONNS
//   3  QUIESCED
//
// Actions:
//   A  Call quiesce_untrusted_interface
//   B  Call quiesce_connections
//   C  Call quiesce_complete
//   D  Call unquiesce_untrusted_interface
//   E  Call unquiesce_connections followed by unquiesce_untrusted_interface
//
// This method just implements the transition table.  The actual processing
// associated with actions is handled by various submethods.
//
void QuiescingManager::process_input(int input)
{
  // Check that we're in a valid state and have received a valid input.

  // LCOV_EXCL_START Preprocessor stops these lines being covered.
  assert((input == INPUT_QUIESCE) ||
         (input == INPUT_FLOWS_GONE) ||
         (input == INPUT_CONNS_GONE) ||
         (input == INPUT_UNQUIESCE));
  assert((_state == STATE_ACTIVE) ||
         (_state == STATE_QUIESCING_FLOWS) ||
         (_state == STATE_QUIESCING_CONNS) ||
         (_state == STATE_QUIESCED));
  // LCOV_EXCL_STOP

  TRC_STATUS("The Quiescing Manager received input %s (%d) "
             "when in state %s (%d)",
            INPUT_NAMES[input], input,
            STATE_NAMES[_state], _state);

  switch (_state)
  {
    case STATE_ACTIVE:

      switch (input)
      {
        case INPUT_QUIESCE:
          _state = STATE_QUIESCING_FLOWS;
          quiesce_untrusted_interface();
          break;

        case INPUT_FLOWS_GONE:
        case INPUT_CONNS_GONE:
          // No-op.
          break;

        case INPUT_UNQUIESCE:
          // LCOV_EXCL_START Don't dogmatically hit empty FSM cells.
          invalid_input(input, _state);
          break;
          // LCOV_EXCL_STOP
      }
      break;

    case STATE_QUIESCING_FLOWS:

      switch (input)
      {
        case INPUT_QUIESCE:
          // LCOV_EXCL_START Don't dogmatically hit empty FSM cells.
          invalid_input(input, _state);
          break;
          // LCOV_EXCL_STOP

        case INPUT_FLOWS_GONE:
          _state = STATE_QUIESCING_CONNS;
          quiesce_connections();
          break;

        case INPUT_CONNS_GONE:
          // No-op.
          break;

        case INPUT_UNQUIESCE:
          _state = STATE_ACTIVE;
          unquiesce_untrusted_interface();
          break;
      }
      break;

    case STATE_QUIESCING_CONNS:

      switch (input)
      {
        case INPUT_QUIESCE:
          invalid_input(input, _state);
          break;

        case INPUT_FLOWS_GONE:
          // No-op.
          break;

        case INPUT_CONNS_GONE:
          _state = STATE_QUIESCED;
          quiesce_complete();
          break;

        case INPUT_UNQUIESCE:
          _state = STATE_ACTIVE;
          unquiesce_connections();
          unquiesce_untrusted_interface();
          break;
      }
      break;

    case STATE_QUIESCED:

      switch (input)
      {
        case INPUT_QUIESCE:
        case INPUT_UNQUIESCE:
          // No-op.
          break;

        case INPUT_FLOWS_GONE:
        case INPUT_CONNS_GONE:
          // LCOV_EXCL_START Don't dogmatically hit empty FSM cells.
          invalid_input(input, _state);
          break;
          // LCOV_EXCL_STOP
      }
      break;
  }
}


void QuiescingManager::invalid_input(int input, int state)
{
  TRC_ERROR("The Quiescing Manager received an invalid input %s (%d) "
            "when in state %s (%d)",
            INPUT_NAMES[input], input,
            STATE_NAMES[state], state);

  // Assert we're not in the active state.  The reasoning here is:
  //
  // -  If we're not active it's better to keep going rather to try ansd
  // preserve service.  There is a chance we could get stuck quiescing, but
  // there are other situations when this could happen. The orchestration layer
  // expects us to be quiescing so should be monitoring us, and can kill the
  // process if it think's we're stuck.
  //
  // -  If we're active, the orchestration layer probably expects us to be
  // active so isn't monitoring us.  It's better to abort rather than pretend
  // we're healthy when we're not.
  assert(_state != STATE_ACTIVE);
}


void QuiescingManager::quiesce_untrusted_interface()
{
  if (_conns_handler != NULL)
  {
    // Close the untrusted listening port.  This prevents any new clients from
    // connecting.
    TRC_STATUS("Close untrusted listening port");
    _conns_handler->close_untrusted_port();
  }

  if (_flows_handler != NULL)
  {
    // Instruct the FlowTable to quiesce.  This waits until all flows have
    // expired, at which case it calls flows_gone().
    TRC_STATUS("Quiesce FlowTable");
    _flows_handler->quiesce();
  }
  else
  {
    // No flows handler so there can't be any flows to quiesce.
    flows_gone();
  }
}

void QuiescingManager::quiesce_connections()
{
  if (_conns_handler != NULL)
  {
    // Close the trusted listening port.  This prevents any new connections from
    // being established (note that on an edge proxy we should already have
    // closed the untrusted listening port).
    TRC_STATUS("Closing trusted port");
    _conns_handler->close_trusted_port();

    // Quiesce open connections.  This will close them when they no longer have
    // any outstanding transactions.  When this process has completed the
    // connection tracker will call connections_gone().
    TRC_STATUS("Quiescing all connections");
    _conns_handler->quiesce();
  }
}

void QuiescingManager::quiesce_complete()
{
  if (_completion_handler != NULL)
  {
    // Notify the completion handler that quiescing is done.
    _completion_handler->quiesce_complete();
  }
}

void QuiescingManager::unquiesce_connections()
{
  if (_conns_handler != NULL)
  {
    // Unquiesce connections (so that new connections can be accepted).
    _conns_handler->unquiesce();

    // Repoen the untrusted listening port.
    _conns_handler->open_trusted_port();
  }
}

void QuiescingManager::unquiesce_untrusted_interface()
{
  if (_flows_handler != NULL)
  {
    // Take the flows out of quiescing mode.
    _flows_handler->unquiesce();
  }

  if (_conns_handler != NULL)
  {
    // Reopen untrusted listening port.
    _conns_handler->open_untrusted_port();
  }
}

bool QuiescingManager::is_quiescing()
{
  if ((_state == STATE_QUIESCING_FLOWS) ||
      (_state == STATE_QUIESCING_CONNS))
  {
    return true;
  }

  return false;
}

