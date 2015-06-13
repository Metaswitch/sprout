/**
 * @file snmp_latency_table.h
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

#include "snmp_table.h"
#include <vector>
#include <map>
#include <string>
#include <atomic>

#ifndef SNMP_LATENCY_TABLE_H
#define SNMP_LATENCY_TABLE_H

class SNMPLatencyRowGroup : public SNMPRowGroup
{
public:
  SNMPLatencyRowGroup(int ignored);
  ColumnData get_columns(netsnmp_tdata_row* row);
  void accumulate_latency(uint32_t latency);

  netsnmp_tdata_row* five_second_row;
  netsnmp_tdata_row* five_minute_row;

  struct LatencyValues
  {
    int idx;
    std::atomic<uint32_t> count;
    std::atomic<uint32_t> sum;
    std::atomic<uint32_t> sqsum;
    std::atomic<uint32_t> hwm;
    std::atomic<uint32_t> lwm;
  };

  uint32_t tick;

  LatencyValues* fiveseconds_writing;
  LatencyValues* fiveseconds_reading;
  LatencyValues fiveseconds_even;
  LatencyValues fiveseconds_odd;

  LatencyValues* fiveminutes_writing;
  LatencyValues* fiveminutes_reading;
  LatencyValues fiveminutes_even;
  LatencyValues fiveminutes_odd;
  
private:
  void update_internal(LatencyValues* val, uint32_t latency);
  void zero_struct(LatencyValues& s);
  void update_time();
  SNMPLatencyRowGroup(const SNMPLatencyRowGroup&);
  SNMPLatencyRowGroup(const SNMPLatencyRowGroup&&);
};

class SNMPLatencyTable: public SNMPTable<SNMPLatencyRowGroup>
{
public:
  SNMPLatencyTable(std::string name,
            oid* tbl_oid,
            int oidlen) : SNMPTable(name, tbl_oid, oidlen)
  {
    netsnmp_tdata_add_index(_table, ASN_INTEGER);
    netsnmp_table_helper_add_index(_table_info, ASN_INTEGER);

    _table_info->min_column = 1;
    _table_info->max_column = 6;
    register_tbl();
  }
};

#endif
