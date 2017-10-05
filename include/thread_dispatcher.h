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

struct MessageEvent
{
  // The received message
  pjsip_rx_data* rdata;

  // A stop watch for tracking SIP message latency
  Utils::StopWatch stop_watch;
};

// An Event on the queue is either a SIP message or a callback
enum EventType { MESSAGE, CALLBACK };

union Event
{
  PJUtils::Callback* callback;
  MessageEvent* message;
};


// Add a Callback object to the queue, to be run on a worker thread.
// This MUST be called from the main PJSIP transport thread.
void add_callback_to_queue(PJUtils::Callback*);

struct EventInfo
{
  // The type of the event
  EventType type;

  // The event itself
  Event event;

  // The priority of the event
  int priority;

  // The time at which the event is to be queued
  int queue_start_time; // TODO: Proper time type

  // Compares two EventInfo structs. Higher priority structs (i.e. structs with
  // a lower value of priority) are returned first, and structs are returned
  // oldest to newest within each priority level.
  bool operator()(const EventInfo& lhs, const EventInfo& rhs)
  {
    if (lhs.priority != rhs.priority)
    {
      return lhs.priority < rhs.priority;
    }
    else
    {
      return lhs.queue_start_time < rhs.queue_start_time;
    }
  }
};

class PriorityEventQueueBackend : eventq<EventInfo>::Backend
{
public:

  PriorityEventQueueBackend() : _queue() {}
  virtual ~PriorityEventQueueBackend() {}

  virtual const EventInfo& front()
  {
    return _queue.top();
  }

  virtual bool empty()
  {
    return _queue.empty();
  }

  virtual int size()
  {
    return _queue.size();
  }

  virtual void push(const EventInfo& value)
  {
    _queue.push(value);
  }

  virtual void pop()
  {
    _queue.pop();
  }

private:

  std::priority_queue<EventInfo,
                      std::deque<EventInfo>,
                      EventInfo > _queue;
};

#endif
