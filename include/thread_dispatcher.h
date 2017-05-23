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

#include "load_monitor.h"
#include "snmp_event_accumulator_table.h"
#include "snmp_event_accumulator_by_scope_table.h"
#include "exception_handler.h"

pj_status_t init_thread_dispatcher(int num_worker_threads_arg,
                                   SNMP::EventAccumulatorByScopeTable* latency_tbl_arg,
                                   SNMP::EventAccumulatorByScopeTable* queue_size_tbl_arg,
                                   LoadMonitor* load_monitor_arg,
                                   ExceptionHandler* exception_handler_arg);

void unregister_thread_dispatcher(void);

pj_status_t start_worker_threads();
pj_status_t stop_worker_threads();

#endif
