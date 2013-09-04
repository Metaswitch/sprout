/**
 * @file quiescing_manager.h Definition of QuiescingManager - a class used to
 * co-ordinate quiescing of bono/sprout.
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


#ifndef QUIESCING_MANAGER_H__
#define QUIESCING_MANAGER_H__

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

#include "connection_tracker.h"

// Abstract base class for a synchnronized finite state machine. This ensures
// that only one thread is running the state machine at once.
class SynchronizedFSM
{
public:
  SynchronizedFSM();
  virtual ~SynchronizedFSM();

protected:
  // The state of the FSM.
  int _state;

  // Send a new input to the state machine.
  void send_input(int input);

  // Function that is called when an input is ready to be processed.  Subclasses
  // must override this with an implementation of their specific FSM.
  virtual void process_input(int input) = 0;

private:
  // Lock protecting access to the rest of the member varaibles of this class.
  pthread_mutex_t _lock;

  // Whether the state machine is currently running.  If a new input arrives
  // when this is set to true, new inputs are queued instead of being processed
  // immediately.  They will eventually be processed by the thread that is
  // currently running the machine.
  bool _running;

  // Queue of inputs waiting to be consumed by the state machine.
  std::queue<int> _input_q;
};


// The quiescing manager is a finite state machine that controls the processing
// required for quiescing bono/sprout, and ensures the right actions are carried
// out at the right time.
class QuiescingManager : public SynchronizedFSM
{
public:
  QuiescingManager(bool edge_proxy,
                   ConnectionTracker *connection_tracker);

  // Inputs methods for the state machine.
  //
  // These just send a new input to the state machine, so we define the
  // implmentation of them here.
  void quiesce() { send_input(INPUT_QUIESCE); }
  void flows_gone() { send_input(INPUT_FLOWS_GONE); }
  void connections_gone() { send_input(INPUT_CONNS_GONE); }
  void unquiesce() { send_input(INPUT_UNQUIESCE); }

private:
  void process_input(int input);

  // The quiescing manager's states and inputs.
  enum {
    STATE_ACTIVE,
    STATE_QUIESCING_FLOWS,
    STATE_QUIESCING_CONNS,
    STATE_QUIESCED,
  };

  enum {
    INPUT_QUIESCE,
    INPUT_FLOWS_GONE,
    INPUT_CONNS_GONE,
    INPUT_UNQUIESCE
  };

  static const char *STATE_NAMES[4];
  static const char *INPUT_NAMES[4];

  // Pointer to the object tracking TCP connections.
  ConnectionTracker *_conn_tracker;

  // Whether we're currently running as an edge proxy.
  bool _edge_proxy;

  // Utility method that should is called when the FSM encounters receives an
  // input that is invalid for the current state.
  void invalid_input(int input, int state);

  // Private methods called as part of the state machine implementation.
  void quiesce_untrusted_interface();
  void quiesce_connections();
  void quiesce_complete();

  void unquiesce_connections();
  void unquiesce_untrusted_interface();
};

// Definitions of the names for the quiescing manager's inputs and states.
// Wrapped in a pre-processor directive so that these are only defined once (in
// quiescing_manager.cpp).
#ifdef QUIESCING_MANAGER_DEFINE_VARS

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
#endif

#endif
