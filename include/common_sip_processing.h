/**
 * @file common_sip_processing.h
 *
 * Processing that needs to be done
 * early on every SIP message.
 *
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


#ifndef COMMON_SIP_PROCESSING_H
#define COMMON_SIP_PROCESSING_H

extern "C" {
#include <pjsip.h>
}

#include "load_monitor.h"
#include "snmp_counter_table.h"
#include "snmp_counter_by_scope_table.h"
#include "health_checker.h"

pj_status_t
init_common_sip_processing(SNMP::CounterByScopeTable* requests_counter_arg,
                           HealthChecker* health_checker_arg);

void unregister_common_processing_module(void);

#endif
