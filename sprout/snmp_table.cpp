/**
 * @file snmp_table.cpp
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

#include <map>

#include "snmp_table.h"
#include "log.h"

// General handler function, which extracts the SNMPRowGroup from the request, calls its
// get_columns() method, and plumbs the answer back into net-snmp.
int netsnmp_table_handler_fn(netsnmp_mib_handler *handler,
                             netsnmp_handler_registration *reginfo,
                             netsnmp_agent_request_info *reqinfo,
                             netsnmp_request_info *requests)
{
  std::map<netsnmp_tdata_row*, ColumnData> cache;
  LOG_DEBUG("Starting handling batch of SNMP requests");
  for (; requests != NULL; requests = requests->next)
  {
    LOG_DEBUG("Handling SNMP request");
    if (requests->processed)
    {
      continue;
    }

    netsnmp_tdata_row* row = netsnmp_tdata_extract_row(requests);
    netsnmp_table_request_info* table_info = netsnmp_extract_table_info(requests);

    if (!row || !table_info || !row->data)
    {
      LOG_WARNING("Request for nonexistent row");
      return SNMP_ERR_NOSUCHNAME;
    }

    SNMPRowGroup* data = static_cast<SNMPRowGroup*>(row->data);

    // We need to get information a row at a time, and remember it - this avoids us reading column
    // 1, and having the data change before we query column 2
    if (cache.find(row) == cache.end())
    {
      ColumnData cd = data->get_columns(row);
      cache[row] = cd;
    }
    LOG_DEBUG("Got %d columns for row %p\n", cache[row].size(), row);

    if (cache[row][table_info->colnum].size != 0)
    {
      snmp_set_var_typed_value(requests->requestvb,
                               cache[row][table_info->colnum].type,
                               cache[row][table_info->colnum].value,
                               cache[row][table_info->colnum].size);
    }
    else
    {
      LOG_WARNING("No value for row %p column %d", row, table_info->colnum);
    }
  }
  LOG_DEBUG("Finished handling batch of SNMP requests");
  return SNMP_ERR_NOERROR;
}
