/**
 * @file stack.cpp
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * Parts of this module were derived from GPL licensed PJSIP sample code
 * with the following copyrights.
 *   Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 *   Copyright (C) 2003-2008 Benny Prijono <benny@prijono.org>
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

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include "pjsip-simple/evsub.h"
}
#include <arpa/inet.h>

// Common STL includes.
#include <cassert>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <queue>
#include <string>

#include "constants.h"
#include "eventq.h"
#include "pjutils.h"
#include "log.h"
#include "sas.h"
#include "saslogger.h"
#include "sproutsasevent.h"
#include "stack.h"
#include "utils.h"
#include "zmq_lvc.h"
#include "statistic.h"
#include "custom_headers.h"
#include "utils.h"
#include "accumulator.h"
#include "connection_tracker.h"
#include "quiescing_manager.h"
#include "load_monitor.h"
#include "counter.h"

static std::vector<pj_thread_t*> pjsip_threads;
static std::vector<pj_thread_t*> worker_threads;

// Queue for incoming messages.
struct rx_msg_qe
{
  pjsip_rx_data* rdata;    // received message
  Utils::StopWatch stop_watch;    // stop watch for tracking message latency
};
eventq<struct rx_msg_qe> rx_msg_q;

// Deadlock detection threshold for the message queue (in milliseconds).  This
// is set to roughly twice the expected maximum service time for each message
// (currently four seconds, allowing for four Homestead/Homer interactions
// from a single request, each with a possible 500ms timeout).
static const int MSG_Q_DEADLOCK_TIME = 4000;

static Accumulator* latency_accumulator = NULL;
static LoadMonitor* load_monitor = NULL;
static Accumulator* queue_size_accumulator = NULL;

static pj_bool_t threads_on_rx_msg(pjsip_rx_data* rdata);

static pjsip_module mod_distribute_to_threads =
{
  NULL, NULL,                           /* prev, next.          */
  pj_str("mod-distribute-to-threads"),                  /* Name.                */
  -1,                                   /* Id                   */
  PJSIP_MOD_PRIORITY_TRANSPORT_LAYER-1, /* Priority             */
  NULL,                                 /* load()               */
  NULL,                                 /* start()              */
  NULL,                                 /* stop()               */
  NULL,                                 /* unload()             */
  &threads_on_rx_msg,                           /* on_rx_request()      */
  &threads_on_rx_msg,                           /* on_rx_response()     */
  NULL,                           /* on_tx_request()      */
  NULL,                           /* on_tx_response()     */
  NULL,                                 /* on_tsx_state()       */
};

/// Worker threads handle most SIP message processing.
static int worker_thread(void* p)
{
  // Set up data to always process incoming messages at the first PJSIP
  // module after our module.
  pjsip_process_rdata_param rp;
  pjsip_process_rdata_param_default(&rp);
  rp.start_mod = &mod_distribute_to_threads;
  rp.idx_after_start = 1;

  LOG_DEBUG("Worker thread started");

  struct rx_msg_qe qe = {0};

  while (rx_msg_q.pop(qe))
  {
    pjsip_rx_data* rdata = qe.rdata;
    if (rdata)
    {
      LOG_DEBUG("Worker thread dequeue message %p", rdata);
      pjsip_endpt_process_rx_data(stack_data.endpt, rdata, &rp, NULL);
      LOG_DEBUG("Worker thread completed processing message %p", rdata);
      pjsip_rx_data_free_cloned(rdata);

      unsigned long latency_us;
      if (qe.stop_watch.read(latency_us))
      {
        LOG_DEBUG("Request latency = %ldus", latency_us);
        latency_accumulator->accumulate(latency_us);
        load_monitor->request_complete(latency_us);
      }
      else
      {
        LOG_ERROR("Failed to get done timestamp: %s", strerror(errno));
      }
    }
  }

  LOG_DEBUG("Worker thread ended");

  return 0;
}

static pj_bool_t threads_on_rx_msg(pjsip_rx_data* rdata)
{
  // Check that the worker threads are not all deadlocked.
  if (rx_msg_q.is_deadlocked())
  {
    // The queue has not been serviced for sufficiently long to imply that
    // all the worker threads are deadlock, so exit the process so it will be
    // restarted.
    LOG_ERROR("Detected worker thread deadlock - exiting");
    abort();
  }

  // Before we start, get a timestamp.  This will track the time from
  // receiving a message to forwarding it on (or rejecting it).
  struct rx_msg_qe qe;
  qe.stop_watch.start();

  // Clone the message and queue it to a scheduler thread.
  pjsip_rx_data* clone_rdata;
  pj_status_t status = pjsip_rx_data_clone(rdata, 0, &clone_rdata);

  if (status != PJ_SUCCESS)
  {
    // Failed to clone the message, so drop it.
    LOG_ERROR("Failed to clone incoming message (%s)", PJUtils::pj_status_to_string(status).c_str());
    return PJ_TRUE;
  }

  // Make sure the trail identifier is passed across.
  set_trail(clone_rdata, get_trail(rdata));

  // @TODO - need to think about back-pressure mechanisms.  For example,
  // should we have a maximum depth of queue and drop messages after that?
  // May be better to hold on to the message until the queue has space - this
  // will force back pressure on the particular TCP connection.  Or should we
  // have a queue per transport and round-robin them?

  LOG_DEBUG("Queuing cloned received message %p for worker threads", clone_rdata);
  qe.rdata = clone_rdata;

  // Track the current queue size
  queue_size_accumulator->accumulate(rx_msg_q.size());
  rx_msg_q.push(qe);

  // return TRUE to flag that we have absorbed the incoming message.
  return PJ_TRUE;
}

pj_status_t init_thread_dispatcher(int num_worker_threads,
                                   LoadMonitor *load_monitor_arg)
{
  // Set up the vectors of threads.  The threads don't get created until
  // start_stack is called.
  worker_threads.resize(num_worker_threads);

  // Enable deadlock detection on the message queue.
  rx_msg_q.set_deadlock_threshold(MSG_Q_DEADLOCK_TIME);

  if (load_monitor_arg != NULL)
  {
    load_monitor = load_monitor_arg;
  }

  // Register the stack modules.
  pjsip_endpt_register_module(stack_data.endpt, &mod_distribute_to_threads);
  stack_data.thread_module_id = mod_distribute_to_threads.id;

}


pj_status_t start_worker_threads()
{
  pj_status_t status = PJ_SUCCESS;

  // Create worker threads first as they take work from the PJSIP threads so
  // need to be ready.
  for (size_t ii = 0; ii < worker_threads.size(); ++ii)
  {
    pj_thread_t* thread;
    status = pj_thread_create(stack_data.pool, "worker", &worker_thread,
                              NULL, 0, 0, &thread);
    if (status != PJ_SUCCESS)
    {
      LOG_ERROR("Error creating worker thread, %s",
                PJUtils::pj_status_to_string(status).c_str());
      return 1;
    }
    worker_threads[ii] = thread;
  }

  return status;
}

void stop_worker_threads()
{
  // Terminate the PJSIP threads and the worker threads to exit.  We kill
  // the PJSIP threads first - if we killed the worker threads first the
  // rx_msg_q will stop getting serviced so could fill up blocking
  // PJSIP threads, causing a deadlock.


  // Now it is safe to signal the worker threads to exit via the queue and to
  // wait for them to terminate.
  rx_msg_q.terminate();
  for (std::vector<pj_thread_t*>::iterator i = worker_threads.begin();
       i != worker_threads.end();
       ++i)
  {
    pj_thread_join(*i);
  }
  worker_threads.clear();
}


// Unregister all modules registered by the stack.  In particular, unregister
// the transaction layer module, which terminates all transactions.
void unregister_thread_dispatcher(void)
{
  pjsip_endpt_unregister_module(stack_data.endpt, &mod_distribute_to_threads);

}
