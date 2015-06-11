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

#include "snmp_table.h"
#include <vector>
#include <map>
#include <string>
#include <atomic>

#include "log.h"

int netsnmp_table_handler_fn(netsnmp_mib_handler *handler,
                             netsnmp_handler_registration *reginfo,
                             netsnmp_agent_request_info *reqinfo,
                             netsnmp_request_info *requests)
{
  std::map<netsnmp_tdata_row*, ColumnData> columns_cache;
  while (requests)
  {
    LOG_STATUS("Handling request %p!", requests);
    if (requests->processed)
    {
      requests = requests->next;
      continue;
    }

    netsnmp_tdata_row *row = netsnmp_tdata_extract_row(requests);
    netsnmp_table_request_info *table_info = netsnmp_extract_table_info(requests);
    if (!row || !table_info || !row->data)
    {
      return SNMP_ERR_NOSUCHNAME;
    }

    SNMPRowGroup* data = static_cast<SNMPRowGroup*>(row->data);
    if (columns_cache.find(row) == columns_cache.end())
    {
      ColumnData cd = data->get_columns(row);
      columns_cache[row] = cd;
    }
    LOG_STATUS("Got %d columns for %p\n", columns_cache[row].size(), row);

    if (columns_cache[row][table_info->colnum].size != 0)
    {
      snmp_set_var_typed_value(requests->requestvb,
                               columns_cache[row][table_info->colnum].type,
                               columns_cache[row][table_info->colnum].value,
                               columns_cache[row][table_info->colnum].size);
    }
    else
    {
      LOG_STATUS("No value for row %p column %d", row, table_info->colnum);
    }
    requests = requests->next;
  }
  LOG_STATUS("Handled all requests!");
  return SNMP_ERR_NOERROR;
}
