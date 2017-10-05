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
pj_status_t stop_worker_threads();

// Add a Callback object to the queue, to be run on a worker thread.
// This MUST be called from the main PJSIP transport thread.
void add_callback_to_queue(PJUtils::Callback*);

struct rxDataQueueInfo
{
  pjsip_rx_data* rdata; // TODO: Import correct header

  // The priority of the data pointed to by rdata.
  int priority_value;

  // The time at which the struct is to be queued.
  int queue_start_time; // TODO: Proper time type

  // The type used for comparison in a std::priority_queue must be default
  // constructable.
  rxDataQueueInfo() {}

  rxDataQueueInfo(pjsip_rx_data* rdata,
                  int priority_value,
                  int queue_start_time) :
                  rdata(rdata),
                  priority_value(priority_value),
                  queue_start_time(queue_start_time)
  {
  }

  // Compares two rxDataQueueInfo structs. Higher priority structs (i.e. structs
  // with a lower priority_value) are returned first, and structs are returned
  // oldest to newest within each priority level.
  bool operator()(const rxDataQueueInfo& lhs, const rxDataQueueInfo& rhs)
  {
    if (lhs.priority_value != rhs.priority_value)
    {
      return lhs.priority_value < rhs.priority_value;
    }
    else
    {
      return lhs.queue_start_time < rhs.queue_start_time;
    }
  }
};

class rxDataPriorityQueueBackend : eventq<rxDataQueueInfo>::Backend
{
public:

  rxDataPriorityQueueBackend() : _queue() {}
  virtual ~rxDataPriorityQueueBackend() {}

  virtual const rxDataQueueInfo& front()
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

  virtual void push(const rxDataQueueInfo& value)
  {
    _queue.push(value);
  }

  virtual void pop()
  {
    _queue.pop();
  }

private:

  std::priority_queue<rxDataQueueInfo,
                      std::deque<rxDataQueueInfo>,
                      rxDataQueueInfo > _queue;
};

#endif
