/**
 * @file thread_dispatcher.cpp
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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
#include "statistic.h"
#include "custom_headers.h"
#include "utils.h"
#include "connection_tracker.h"
#include "quiescing_manager.h"
#include "load_monitor.h"
#include "counter.h"
#include "sprout_pd_definitions.h"
#include "exception_handler.h"
#include "snmp_event_accumulator_table.h"
#include "snmp_event_accumulator_by_scope_table.h"
#include "thread_dispatcher.h"

static std::vector<pj_thread_t*> worker_threads;

// Queue for incoming events.
static PriorityEventQueueBackend* sip_event_queue_backend =
  new PriorityEventQueueBackend();
static eventq<struct SipEvent> sip_event_queue(0,
                                               true,
                                               sip_event_queue_backend);

// Deadlock detection threshold for the message queue (in milliseconds).  This
// is set to roughly twice the expected maximum service time for each message
// (currently four seconds, allowing for four Homestead/Homer interactions
// from a single request, each with a possible 500ms timeout).
static const int MSG_Q_DEADLOCK_TIME = 4000;

static int num_worker_threads = 1;

static SNMP::EventAccumulatorByScopeTable* latency_table = NULL;
static SNMP::EventAccumulatorByScopeTable* queue_size_table = NULL;

static LoadMonitor* load_monitor = NULL;

static SNMP::CounterByScopeTable* overload_counter = NULL;

static ExceptionHandler* exception_handler = NULL;

static pj_bool_t threads_on_rx_msg(pjsip_rx_data* rdata);

// Module to clone SIP requests and dispatch them to worker threads.

// Priority of PJSIP_MOD_PRIORITY_TRANSPORT_LAYER-1 causes this to run
// right after the initial processing module, but before everything
// else. This is important - this module clones the rdata, which loses
// some of the parsing error information which the initial processing
// module uses. (Note that this module only handles received data, and
// the transport module isn't actually invoked on received processing,
// so this priority really just means "early".)
static pjsip_module mod_thread_dispatcher =
{
  NULL, NULL,                           /* prev, next.          */
  pj_str("mod-thread-dispatcher"),      /* Name.                */
  -1,                                   /* Id                   */
  PJSIP_MOD_PRIORITY_TRANSPORT_LAYER-1, /* Priority             */
  NULL,                                 /* load()               */
  NULL,                                 /* start()              */
  NULL,                                 /* stop()               */
  NULL,                                 /* unload()             */
  &threads_on_rx_msg,                   /* on_rx_request()      */
  &threads_on_rx_msg,                   /* on_rx_response()     */
  NULL,                                 /* on_tx_request()      */
  NULL,                                 /* on_tx_response()     */
  NULL,                                 /* on_tsx_state()       */
};

/// Worker threads handle most SIP message processing.
static int worker_thread(void* p)
{
  // Set up data to always process incoming messages at the first PJSIP
  // module after our module.
  pjsip_process_rdata_param rp;
  pjsip_process_rdata_param_default(&rp);
  rp.start_mod = &mod_thread_dispatcher;
  rp.idx_after_start = 1;

  TRC_DEBUG("Worker thread started");

  SipEvent qe;
  qe.type = MESSAGE; // TODO: Why?

  while (sip_event_queue.pop(qe))
  {
    if (qe.type == MESSAGE)
    {
      pjsip_rx_data* rdata = qe.event_data.rdata;

      if (rdata)
      {
        TRC_DEBUG("Worker thread dequeue message %p", rdata);

        CW_TRY
        {
          pjsip_endpt_process_rx_data(stack_data.endpt, rdata, &rp, NULL);
        }
        CW_EXCEPT(exception_handler)
        {
          // Dump details about the exception.  Be defensive about reading these
          // as we don't know much about the state we're in.
          TRC_ERROR("Exception SAS Trail: %llu (maybe)", get_trail(rdata));
          if (rdata->msg_info.cid != NULL)
          {
            TRC_ERROR("Exception Call-Id: %.*s (maybe)",
                      ((pjsip_cid_hdr*)rdata->msg_info.cid)->id.slen,
                      ((pjsip_cid_hdr*)rdata->msg_info.cid)->id.ptr);
          }
          if (rdata->msg_info.cseq != NULL)
          {
            TRC_ERROR("Exception CSeq: %ld %.*s (maybe)",
                      ((pjsip_cseq_hdr*)rdata->msg_info.cseq)->cseq,
                      ((pjsip_cseq_hdr*)rdata->msg_info.cseq)->method.name.slen,
                      ((pjsip_cseq_hdr*)rdata->msg_info.cseq)->method.name.ptr);
          }

          // Make a 500 response to the rdata with a retry-after header of
          // 10 mins if it's a request other than an ACK

          if ((rdata->msg_info.msg->type == PJSIP_REQUEST_MSG) &&
             (rdata->msg_info.msg->line.req.method.id != PJSIP_ACK_METHOD))
          {
            TRC_DEBUG("Returning 500 response following exception");
            pjsip_retry_after_hdr* retry_after =
                           pjsip_retry_after_hdr_create(rdata->tp_info.pool, 600);
            PJUtils::respond_stateless(stack_data.endpt,
                                     rdata,
                                     PJSIP_SC_INTERNAL_SERVER_ERROR,
                                     NULL,
                                     (pjsip_hdr*)retry_after,
                                     NULL);
          }

          if (num_worker_threads == 1)
          {
            // There's only one worker thread, so we can't sensibly proceed.
            exit(1);
          }
        }
        CW_END

        TRC_DEBUG("Worker thread completed processing message %p", rdata);
        pjsip_rx_data_free_cloned(rdata);

        unsigned long latency_us = 0;
        if (qe.stop_watch.read(latency_us))
        {
          TRC_DEBUG("Request latency = %ldus", latency_us);
          latency_table->accumulate(latency_us);
          load_monitor->request_complete(latency_us);
        }
        else
        {
          TRC_ERROR("Failed to get done timestamp: %s", strerror(errno));
        }
      }
    }
    else
    {
      // If this is a Callback, we just run it and then delete it.
      PJUtils::Callback* cb = qe.event_data.callback;
      cb->run();
      delete cb; cb = NULL;
    }
  }

  TRC_DEBUG("Worker thread ended");

  return 0;
}

// Returns true if the SIP message should always be processed, regardless of
// overload, and false otherwise.
static bool ignore_overload(pjsip_rx_data* rdata)
{
  // The type of a message is either REQUEST or RESPONSE; we only check the load
  // monitor for REQUEST messages
  if (rdata->msg_info.msg->type != PJSIP_REQUEST_MSG)
  {
    return true;
  }

  // Always accept ACK and OPTIONS requests
  pjsip_method_e method_id = rdata->msg_info.msg->line.req.method.id;
  if (method_id == PJSIP_ACK_METHOD || method_id == PJSIP_OPTIONS_METHOD)
  {
    return true;
  }

  return false;
}

// Reject a SIP message with a 503 Service Unavailable
static void reject_rx_msg_overload(pjsip_rx_data* rdata, SAS::TrailId trail)
{
  // Respond statelessly with a 503 Service Unavailable, including a
  // Retry-After header with a zero length timeout.
  TRC_DEBUG("Rejected request due to overload");

  // LCOV_EXCL_START - can't meaningfully verify SAS in UT
  SAS::Marker start_marker(trail, MARKER_ID_START, 1u);
  SAS::report_marker(start_marker);

  SAS::Event event(trail, SASEvent::SIP_OVERLOAD, 0);
  event.add_static_param(load_monitor->get_target_latency());
  event.add_static_param(load_monitor->get_current_latency());
  event.add_static_param(load_monitor->get_rate_limit());
  SAS::report_event(event);

  SAS::Marker end_marker(trail, MARKER_ID_END, 1u);
  SAS::report_marker(end_marker);

  // LCOV_EXCL_STOP

  pjsip_retry_after_hdr* retry_after = pjsip_retry_after_hdr_create(rdata->tp_info.pool, 0);
  PJUtils::respond_stateless(stack_data.endpt,
                             rdata,
                             PJSIP_SC_SERVICE_UNAVAILABLE,
                             NULL,
                             (pjsip_hdr*)retry_after,
                             NULL);

  // We no longer terminate TCP connections on overload as the shutdown has
  // to wait for existing transactions to end and therefore it takes too
  // long to get feedback to the downstream node.  We expect downstream nodes
  // to rebalance load if possible triggered by receipt of the 503 responses.

  overload_counter->increment();
}

static int get_rx_msg_priority(pjsip_rx_data* rdata)
{
  // TODO: Determine priority from message
  // TODO: SAS log priority
  return 4;
}

static pj_bool_t threads_on_rx_msg(pjsip_rx_data* rdata)
{
  SAS::TrailId trail = get_trail(rdata);

  // SAS log the start of processing by this module
  SAS::Event event(trail, SASEvent::BEGIN_THREAD_DISPATCHER, 0);
  SAS::report_event(event);

  // Check whether the request should be rejected due to overload
  if (!ignore_overload(rdata) && !(load_monitor->admit_request(trail)))
  {
    reject_rx_msg_overload(rdata, trail);
    return PJ_TRUE;
  }

  // Check that the worker threads are not all deadlocked.
  if (sip_event_queue.is_deadlocked())
  {
    // The queue has not been serviced for sufficiently long to imply that
    // all the worker threads are deadlock, so exit the process so it will be
    // restarted.
    CL_SPROUT_SIP_DEADLOCK.log();
    TRC_ERROR("Detected worker thread deadlock - exiting");
    abort();
  }

  // Before we start, get a timestamp.  This will track the time from
  // receiving a message to forwarding it on (or rejecting it).
  SipEvent qe;
  qe.stop_watch.start();

  // Clone the message and queue it to a scheduler thread.
  pjsip_rx_data* clone_rdata;
  pj_status_t status = pjsip_rx_data_clone(rdata, 0, &clone_rdata);

  if (status != PJ_SUCCESS)
  {
    // Failed to clone the message, so drop it.
    TRC_ERROR("Failed to clone incoming message (%s)",
              PJUtils::pj_status_to_string(status).c_str());
    return PJ_TRUE;
  }

  // Make sure the trail identifier is passed across.
  set_trail(clone_rdata, trail);

  // @TODO - need to think about back-pressure mechanisms.  For example,
  // should we have a maximum depth of queue and drop messages after that?
  // May be better to hold on to the message until the queue has space - this
  // will force back pressure on the particular TCP connection.  Or should we
  // have a queue per transport and round-robin them?

  // Set up a SipEvent struct
  qe.event_data.rdata = clone_rdata;
  qe.type = MESSAGE;

  // Set the message priority and log to SAS
  qe.priority = get_rx_msg_priority(clone_rdata);
  TRC_DEBUG("Queuing cloned received message %p for worker threads with priority %d",
            clone_rdata, qe.priority);
  SAS::Event priority_event(trail, SASEvent::THREAD_DISPATCHER_SET_PRIORITY_LEVEL, 0);
  std::string priority_str = std::to_string(qe.priority);
  priority_event.add_var_param(priority_str);
  SAS::report_event(priority_event);

  // Track the current queue size
  queue_size_table->accumulate(sip_event_queue.size());
  sip_event_queue.push(qe);

  // return TRUE to flag that we have absorbed the incoming message.
  return PJ_TRUE;
}

pj_status_t init_thread_dispatcher(int num_worker_threads_arg,
                                   SNMP::EventAccumulatorByScopeTable* latency_table_arg,
                                   SNMP::EventAccumulatorByScopeTable* queue_size_table_arg,
                                   LoadMonitor* load_monitor_arg,
                                   SNMP::CounterByScopeTable* overload_counter_arg,
                                   ExceptionHandler* exception_handler_arg)
{
  // Set up the vectors of threads.  The threads don't get created until
  // start_worker_threads is called.
  worker_threads.resize(num_worker_threads_arg);

  // Enable deadlock detection on the message queue.
  sip_event_queue.set_deadlock_threshold(MSG_Q_DEADLOCK_TIME);

  num_worker_threads = num_worker_threads_arg;
  latency_table = latency_table_arg;
  queue_size_table = queue_size_table_arg;
  load_monitor = load_monitor_arg;
  overload_counter = overload_counter_arg;
  exception_handler = exception_handler_arg;

  // Register the PJSIP module.
  pjsip_endpt_register_module(stack_data.endpt, &mod_thread_dispatcher);

  return PJ_SUCCESS;
}


pj_status_t start_worker_threads()
{
  pj_status_t status = PJ_SUCCESS;

  for (size_t ii = 0; ii < worker_threads.size(); ++ii)
  {
    pj_thread_t* thread;
    status = pj_thread_create(stack_data.pool, "worker", &worker_thread,
                              NULL, 0, 0, &thread);
    if (status != PJ_SUCCESS)
    {
      TRC_ERROR("Error creating worker thread, %s",
                PJUtils::pj_status_to_string(status).c_str());
      return 1;
    }
    worker_threads[ii] = thread;
  }

  return status;
}

void stop_worker_threads()
{
  // Now it is safe to signal the worker threads to exit via the queue and to
  // wait for them to terminate.
  sip_event_queue.terminate();
  for (std::vector<pj_thread_t*>::iterator i = worker_threads.begin();
       i != worker_threads.end();
       ++i)
  {
    pj_thread_join(*i);
  }
  worker_threads.clear();
}

void unregister_thread_dispatcher(void)
{
  pjsip_endpt_unregister_module(stack_data.endpt, &mod_thread_dispatcher);

}

void add_callback_to_queue(PJUtils::Callback* cb)
{
  // Create a SipEvent to hold the Callback
  SipEvent qe;
  qe.type = CALLBACK;
  qe.event_data.callback = cb;
  // TODO: Set priority

  // Track the current queue size
  queue_size_table->accumulate(sip_event_queue.size());

  // Add the SipEvent
  sip_event_queue.push(qe);
}
