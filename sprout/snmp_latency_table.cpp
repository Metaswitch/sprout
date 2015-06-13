/**
 * @file snmp_latency_table.cpp
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

#include "snmp_latency_table.h"
#include <vector>
#include <map>
#include <string>
#include <atomic>

SNMPLatencyRowGroup::SNMPLatencyRowGroup(int ignored): SNMPRowGroup()
{
}

void SNMPLatencyRowGroup::init()
{
  five_second_index = 1;
  five_minute_index = 2;

  fiveseconds = {1, 0, 0, 0, 0, 0};
  fiveminutes = {1, 0, 0, 0, 0, 0};

  five_second_row = netsnmp_tdata_create_row();
  netsnmp_tdata_row_add_index(five_second_row, ASN_INTEGER, &five_second_index, sizeof(int));
  five_second_row->data = static_cast<SNMPRowGroup*>(this);
  _rows.push_back(five_second_row);

  five_minute_row = netsnmp_tdata_create_row();
  netsnmp_tdata_row_add_index(five_minute_row, ASN_INTEGER, &five_minute_index, sizeof(int));
  five_minute_row->data = static_cast<SNMPRowGroup*>(this);
  _rows.push_back(five_minute_row);
}

ColumnData SNMPLatencyRowGroup::get_columns(netsnmp_tdata_row* row)
{
  ColumnData ret;
  LatencyValues* values;
  if (row == five_second_row)
  {
    values = &fiveseconds;
  }
  else
  {
    values = &fiveminutes;
  }

  LOG_STATUS("Created 0 SNMPValues");
  ret[1] = SNMPValue::integer(values->idx);
  LOG_STATUS("Created 1 SNMPValues - data is %p", ret[1].value);
  ret[2] = SNMPValue::uint(values->count);
  ret[3] = SNMPValue::uint(values->average);
  ret[4] = SNMPValue::uint(values->variance);
  ret[5] = SNMPValue::uint(values->lwm);
  ret[6] = SNMPValue::uint(values->hwm);
  LOG_STATUS("Created all SNMPValues");
  return ret;
}

void SNMPLatencyRowGroup::recalculate_values()
{
}

void SNMPLatencyRowGroup::accumulate_latency(uint32_t latency)
{
  update_internal(&fiveseconds, latency);
  update_internal(&fiveminutes, latency);
}

void SNMPLatencyRowGroup::update_internal(LatencyValues* val, uint32_t latency)
{
  val->count++;
  val->sum += latency;
  val->sqsum += latency^2;
  if (latency > val->hwm)
  {
    val->hwm = latency;
  }
  if (latency < val->lwm)
  {
    val->lwm = latency;
  }
  
};
