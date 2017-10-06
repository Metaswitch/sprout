/**
 * @file thread_dispatcher.h
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


#ifndef THREAD_DISPATCHER_H
#define THREAD_DISPATCHER_H

extern "C" {
#include <pjsip.h>
}

#include "pjutils.h"
#include "load_monitor.h"
#include "snmp_event_accumulator_table.h"
#include "snmp_event_accumulator_by_scope_table.h"
#include "exception_handler.h"
#include "eventq.h"

pj_status_t init_thread_dispatcher(int num_worker_threads_arg,
                                   SNMP::EventAccumulatorByScopeTable* latency_tbl_arg,
                                   SNMP::EventAccumulatorByScopeTable* queue_size_tbl_arg,
                                   LoadMonitor* load_monitor_arg,
                                   ExceptionHandler* exception_handler_arg);

void unregister_thread_dispatcher(void);

pj_status_t start_worker_threads();
void stop_worker_threads(); // TODO: Should this return its status?

struct SipMessageEvent
{
  // The received message
  pjsip_rx_data* rdata;

  // A stop watch for tracking SIP message latency
  Utils::StopWatch stop_watch;
};

// A SipEvent on the queue is either a SIP message or a callback
enum SipEventType { MESSAGE, CALLBACK };

union SipEvent
{
  PJUtils::Callback* callback;
  SipMessageEvent* message;
};


// Add a Callback object to the queue, to be run on a worker thread.
// This MUST be called from the main PJSIP transport thread.
void add_callback_to_queue(PJUtils::Callback*);

struct worker_thread_qe
{
  // The type of the event
  SipEventType type;

  // The event itself
  SipEvent event;

  // The priority of the event
  int priority;

};

class PriorityEventQueueBackend : public eventq<worker_thread_qe>::Backend
{
public:

  PriorityEventQueueBackend() : _queue() {}
  virtual ~PriorityEventQueueBackend() {}

  virtual const worker_thread_qe& front()
  {
    return _queue.top().qe;
  }

  virtual bool empty()
  {
    return _queue.empty();
  }

  virtual int size()
  {
    return _queue.size();
  }

  virtual void push(const worker_thread_qe& value)
  {
    qe_info value_info;
    value_info.qe = value;
    value_info.queue_start_time_us = 0; // TODO: Set time
    _queue.push(value_info);
  }

  virtual void pop()
  {
    _queue.pop();
  }

private:

  struct qe_info
  {
    worker_thread_qe qe;

    // The time at which the event is to be queued
    unsigned long queue_start_time_us; // TODO: Proper time type

    // Compares two qe_info structs. 'larger' structs are returned sooner by the
    // priority queue. Higher priority structs, that is, those with a lower
    // value of the priority variable, are 'larger'; within each priority level,
    // older structs are 'larger'.
    bool operator<(const qe_info& rhs) const
    {
      if (qe.priority != rhs.qe.priority)
      {
        return qe.priority > rhs.qe.priority;
      }
      else
      {
        return queue_start_time_us > rhs.queue_start_time_us;
      }
    }

  };

  std::priority_queue<qe_info, std::deque<qe_info> > _queue;
};

#endif
