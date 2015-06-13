/**
 * @file load_monitor_test.cpp UT for LoadMonitor classes.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
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

///
///----------------------------------------------------------------------------

#include <string>
#include "gtest/gtest.h"

#include "basetest.hpp"
#include "snmp_latency_table.h"
#include "test_interposer.hpp"

static oid test_oid[] = { 1, 2, 826, 0, 1, 1578918, 9, 3, 1 };

class SNMPLatencyTableTest : public BaseTest
{
};


TEST_F(SNMPLatencyTableTest, BasicTest)
{
  init_snmp("");
  netsnmp_container_init_list();
  ManagedSNMPTable<SNMPLatencyTable, SNMPLatencyRowGroup, int>* tbl =
  new ManagedSNMPTable<SNMPLatencyTable, SNMPLatencyRowGroup, int>("h",
                                                                   test_oid,
                                                                   OID_LENGTH(test_oid));
  SNMPLatencyRowGroup* row = tbl->get(0);
  SNMPLatencyRowGroup* reconstructed_row = (SNMPLatencyRowGroup*)(row->five_second_row->data);
  LOG_STATUS("Calling get_columns");
  ColumnData c = reconstructed_row->get_columns(row->five_second_row);
  LOG_STATUS("Value in column 1 is %p with data %p", &(c[1]), c[1].value);
  delete tbl; tbl = NULL;
  row = NULL;
  reconstructed_row = NULL;
  netsnmp_container_free_list();
  snmp_shutdown("");
}

TEST_F(SNMPLatencyTableTest, LatencyUpdateTest)
{
  init_snmp("");
  netsnmp_container_init_list();
  ManagedSNMPTable<SNMPLatencyTable, SNMPLatencyRowGroup, int>* tbl =
  new ManagedSNMPTable<SNMPLatencyTable, SNMPLatencyRowGroup, int>("hello2",
                                                                   test_oid,
                                                                   OID_LENGTH(test_oid));
  SNMPLatencyRowGroup* row = tbl->get(0);
  row->accumulate_latency(100);
  ASSERT_NE(row->fiveseconds.hwm, 0);
  delete(tbl);
  netsnmp_container_free_list();
  snmp_shutdown("");
}
