/**
 * @file snmp_agent.cpp
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2015 Metaswitch Networks Ltd
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

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "snmp_agent.h"
#include "snmp_latency_table.h"
    
static oid test_oid[] = { 1, 2, 826, 0, 1, 1578918, 9, 3, 1 };

static pthread_t snmp_thread_var;

void* snmp_thread(void* data)
{
  ManagedSNMPTable<SNMPLatencyTable, SNMPLatencyRowGroup, int> TBL("hello", test_oid, OID_LENGTH(test_oid));
  TBL.get(0);
  while (1) {
    agent_check_and_process(1);
  }
  return NULL;
};

int snmp_setup(const char* name)
{
  netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 1);
  netsnmp_container_init_list();
  int rc = init_agent(name);
  if (rc != 0)
  {
    LOG_WARNING("SNMP AgentX initialization failed");
    return -1;
  }
  else
  {
  LOG_STATUS("AgentX agent initialised");
  }
  init_snmp(name);
  int ret = pthread_create(&snmp_thread_var, NULL, snmp_thread, NULL);
  return ret;
}


void snmp_close(const char* name)
{
  pthread_cancel(snmp_thread_var);
  shutdown_agent();
  snmp_shutdown(name);
  netsnmp_container_free_list();
}
