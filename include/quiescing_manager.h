/**
 * @file quiescing_manager.h Definition of QuiescingManager - a class used to
 * co-ordinate quiescing of bono/sprout.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


#ifndef QUIESCING_MANAGER_H__
#define QUIESCING_MANAGER_H__

#include <queue>

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

#include "connection_tracker.h"

/// Quiescing is controlled by the QuiescingManager class.  This orchestrates
/// quiescing but doesn't actually do any of the heavy lifting.  This is done by
/// handlers that are registered with the manager:
/// -  Connections handler, which controls quiescing of TCP connections.
/// -  Flows handler, which controls quiescing of flows (edge proxy only).
/// -  Completion handler, which gets notified when quiescing is complete and
///    does any final clean up.
/// Each handler has an abstract base class which defines the interface that
/// the handler must implement.
///
/// When told to quiesce we first do any processing specific to an edge proxy
/// (bono) followed by processing common to bono and sprout. Specifically:
///
/// 1). Quiescing starts when quiesce() is called on the QuiescingManager.
/// 2). The untrusted port is closed
///     (QuiesceConnectionsInterface::close_untrusted_port).
/// 3). On an edge proxy, wait for flows to expire
///     (QuiesceFlowsInterface::quiesce).  Otherwise go to step 5.
/// 4). Once flows are quiesced, call flows_gone() on the QuiescingManager.
/// 5). The trusted port is closed
///     (QuiesceConnectionsInterface::close_trusted_port).
/// 6). Connections are quiesced.
///     (QuiesceConnectionsInterface::quiesce).
/// 7). Once all connections have been destroyed, call connections_gone() on
///     the QuiescingManager.
/// 8). Notify that quiescing has completed
///     (QuiesceCompletionInterface::quiesce_complete).

/// Abstract base class for a synchnronized finite state machine. This ensures
/// that only one thread is running the state machine at once.
class SynchronizedFSM
{
public:
  SynchronizedFSM();
  virtual ~SynchronizedFSM();

protected:
  /// The state of the FSM.
  int _state;

  /// Send a new input to the state machine.
  void send_input(int input);

  /// Function that is called when an input is ready to be processed.
  /// Subclasses must override this with an implementation of their specific
  /// FSM.
  virtual void process_input(int input) = 0;

private:
  // Lock protecting access to the private member varaibles of this class.
  pthread_mutex_t _lock;

  // Whether the state machine is currently running.  If a new input arrives
  // when this is set to true, new inputs are queued instead of being processed
  // immediately.  They will eventually be processed by the thread that is
  // currently running the machine.
  bool _running;

  // Queue of inputs waiting to be consumed by the state machine.
  std::queue<int> _input_q;
};


/// Interface that the QuiescingManager uses to control (un)quiescing TCP
/// connections.
class QuiesceConnectionsInterface
{
public:
  /// Stop listening for new connections on the untrusted interface.  If not
  /// running as an edge proxy this will be a no-op.
  virtual void close_untrusted_port() = 0;

  /// Stop listening for new connections on the trusted interface.
  virtual void close_trusted_port() = 0;

  /// Quiesce all currently active TCP connections.  This method should shut
  /// down connections gracefully such that transactions in progress are not
  /// dropped.
  ///
  /// Once all connections have been closed QuiescingManager::connections_gone
  /// must be called.
  virtual void quiesce() = 0;

  /// Unquiesce TCP connections (stop actively trying to get rid of them).
  virtual void unquiesce() = 0;

  /// Start listening for new connections on the trusted interface.
  virtual void open_trusted_port() = 0;

  /// Start listening for new connections on the untrusted interface.  If not
  /// running as an edge proxy this will be a no-op.
  virtual void open_untrusted_port() = 0;
};


/// Interface that the QuiescingManager uses to manage (un)quiescing flows.
class QuiesceFlowsInterface
{
public:
  /// Quiesce all currently active flows.  This method should gracefully
  /// shutdown flows so that subscribers do not lose service.
  ///
  /// Once all flows have been deleted QuiescingManager::flows_gone must be
  /// called.
  virtual void quiesce() = 0;

  /// Unquiesce flows (stop actively trying to get rid of them).
  virtual void unquiesce() = 0;
};


/// Interface that the QuiescingManager notifies when quiescing is complete.
class QuiesceCompletionInterface
{
public:
  virtual void quiesce_complete() = 0;
};


/// The quiescing manager is a finite state machine that controls the processing
/// required for quiescing bono/sprout, and ensures the right actions are
/// carried out at the right time.
class QuiescingManager : public SynchronizedFSM
{
public:
  QuiescingManager();

  /// Inputs methods for the state machine.  These just send a new method to the
  /// state machine.
  void quiesce()          { send_input(INPUT_QUIESCE); }
  void flows_gone()       { send_input(INPUT_FLOWS_GONE); }
  void connections_gone() { send_input(INPUT_CONNS_GONE); }
  void unquiesce()        { send_input(INPUT_UNQUIESCE); }

  /// The quiescing manager uses three interfaces to communicate with other
  /// components in bono/sprout.  The following methods are used to register
  /// implementations of these interfaces (which we refer to as 'handlers').
  void register_conns_handler(QuiesceConnectionsInterface *handler)
  {
    _conns_handler = handler;
  }

  void register_flows_handler(QuiesceFlowsInterface *handler)
  {
    _flows_handler = handler;
  }

  void register_completion_handler(QuiesceCompletionInterface *handler)
  {
    _completion_handler = handler;
  }

  /// Used to check if bono/sprout is quiescing
  bool is_quiescing();

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

  // Utility method that should is called when the FSM encounters receives an
  // input that is invalid for the current state.
  void invalid_input(int input, int state);

  // Private methods called as part of the state machine implementation.
  void quiesce_untrusted_interface();
  void quiesce_connections();
  void quiesce_complete();
  void unquiesce_connections();
  void unquiesce_untrusted_interface();

  // Handlers that implement the various interfaces exposed by the quiescing
  // manager.
  QuiesceConnectionsInterface *_conns_handler;
  QuiesceFlowsInterface *_flows_handler;
  QuiesceCompletionInterface *_completion_handler;
};

#endif
