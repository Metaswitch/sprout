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
#include "rphservice.h"
#include "snmp_event_accumulator_table.h"
#include "snmp_event_accumulator_by_scope_table.h"
#include "snmp_success_fail_count_by_priority_and_scope_table.h"
#include "exception_handler.h"
#include "snmp_counter_by_scope_table.h"
#include "sip_event_priority.h"
#include "eventq.h"

pj_status_t init_thread_dispatcher(int num_worker_threads_arg,
                                   SNMP::EventAccumulatorByScopeTable* latency_tbl_arg,
                                   SNMP::EventAccumulatorByScopeTable* queue_size_tbl_arg,
                                   SNMP::SuccessFailCountByPriorityAndScopeTable* queue_success_fail_table_arg,
                                   SNMP::CounterByScopeTable* overload_counter_arg,
                                   LoadMonitor* load_monitor_arg,
                                   RPHService* rph_service_arg,
                                   ExceptionHandler* exception_handler_arg,
                                   unsigned long request_on_queue_timeout);

void unregister_thread_dispatcher(void);

pj_status_t start_worker_threads();
void stop_worker_threads();

pjsip_module* get_mod_thread_dispatcher();

// A SipEvent on the queue is either a SIP message or a callback
enum SipEventType { MESSAGE, CALLBACK };

union SipEventData
{
  pjsip_rx_data* rdata;
  PJUtils::Callback* callback;
};

struct SipEvent
{
  // The type of the event
  SipEventType type;

  // The event's priority - a higher value corresponds to a higher priority level
  SIPEventPriorityLevel priority;

  // A stop watch for tracking latency and determining the length of time the
  // message has been on the queue
  Utils::StopWatch stop_watch;

  // The event data itself
  SipEventData event_data;

  SipEvent() : type(MESSAGE), priority(SIPEventPriorityLevel::NORMAL_PRIORITY) {}

  // Compares two SipEvents. Returns true if rhs is 'larger' than lhs, where
  // 'larger' SipEvents are those that should be processed earlier.
  static bool compare(SipEvent lhs, SipEvent rhs)
  {
    if (lhs.priority != rhs.priority)
    {
      // Higher priority SipEvents, that is, SipEvents with a higher priority
      // level, are 'larger'
      return lhs.priority < rhs.priority;
    }
    else
    {
      // At the same priority level, older SipEvents are 'larger'
      unsigned long lhs_us = 0;
      unsigned long rhs_us = 0;

      if (!lhs.stop_watch.read(lhs_us) || !rhs.stop_watch.read(rhs_us))
      {
        // We're extremely unlikely to end up in this case, but we try to cope
        // with it as well as possible
        TRC_ERROR("Failed to read stopwatch.");
        return false;
      }

      return lhs_us < rhs_us;
    }
  }
};

// Internal method exposed for testing purposes. Pops a single element off the
// event queue and processes it. If the queue is empty, waits until either an
// element is added to the queue or the queue is terminated.
// Returns true if an element was processed, and false if the queue was
// terminated.
bool process_queue_element();

// Add a Callback object to the queue, to be run on a worker thread.
void add_callback_to_queue(PJUtils::Callback*);

// Implements eventq::Backend as a std::priority_queue of SipEvent structs.
class PriorityEventQueueBackend : public eventq<SipEvent>::Backend
{
public:

  PriorityEventQueueBackend() : _queue(SipEvent::compare) {}
  virtual ~PriorityEventQueueBackend() {}

  virtual const SipEvent& front()
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

  virtual void push(const SipEvent& value)
  {
    _queue.push(value);
  }

  virtual void pop()
  {
    _queue.pop();
  }

  // SipEvents are compared using operator()
  std::priority_queue<SipEvent,
                      std::deque<SipEvent>,
                      std::function<bool(SipEvent, SipEvent)> > _queue;
};

#endif
