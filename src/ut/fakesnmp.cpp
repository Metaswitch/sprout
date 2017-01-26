/**
 * @file fakesnmp.cpp Fake SNMP infrastructure (for testing).
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

#include "snmp_internal/snmp_includes.h"
#include "fakesnmp.hpp"
#include "snmp_success_fail_count_table.h"
#include "snmp_success_fail_count_by_request_type_table.h"

namespace SNMP
{
struct in_addr dummy_addr;
FakeIPCountRow FAKE_IP_COUNT_ROW;
FakeIPCountTable FAKE_IP_COUNT_TABLE;
FakeCounterTable FAKE_COUNTER_TABLE;
FakeCounterByScopeTable FAKE_COUNTER_BY_SCOPE_TABLE;
FakeEventAccumulatorTable FAKE_EVENT_ACCUMULATOR_TABLE;
FakeContinuousAccumulatorTable FAKE_CONTINUOUS_ACCUMULATOR_TABLE;
FakeSuccessFailCountTable FAKE_INIT_REG_TABLE;
FakeSuccessFailCountTable FAKE_RE_REG_TABLE;
FakeSuccessFailCountTable FAKE_DE_REG_TABLE;
FakeSuccessFailCountTable FAKE_THIRD_PARTY_INIT_REG_TABLE;
FakeSuccessFailCountTable FAKE_THIRD_PARTY_RE_REG_TABLE;
FakeSuccessFailCountTable FAKE_THIRD_PARTY_DE_REG_TABLE;
FakeSuccessFailCountTable FAKE_SIP_DIGEST_AUTH_TABLE;
FakeSuccessFailCountTable FAKE_IMS_AKA_AUTH_TABLE;
FakeSuccessFailCountTable FAKE_NON_REG_AUTH_TABLE;
FakeSuccessFailCountByRequestTypeTable FAKE_INCOMING_SIP_TRANSACTIONS_TABLE;
FakeSuccessFailCountByRequestTypeTable FAKE_OUTGOING_SIP_TRANSACTIONS_TABLE;

RegistrationStatsTables FAKE_REGISTRATION_STATS_TABLES =
{
  &FAKE_INIT_REG_TABLE,
  &FAKE_RE_REG_TABLE,
  &FAKE_DE_REG_TABLE
};

RegistrationStatsTables FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES =
{
  &FAKE_THIRD_PARTY_INIT_REG_TABLE,
  &FAKE_THIRD_PARTY_RE_REG_TABLE,
  &FAKE_THIRD_PARTY_DE_REG_TABLE,
};

AuthenticationStatsTables FAKE_AUTHENTICATION_STATS_TABLES =
{
  &FAKE_SIP_DIGEST_AUTH_TABLE,
  &FAKE_IMS_AKA_AUTH_TABLE,
  &FAKE_NON_REG_AUTH_TABLE
};

// Alternative implementations is some functions, so we aren't calling real SNMP code in UT
EventAccumulatorTable* EventAccumulatorTable::create(std::string name, std::string oid) { return new FakeEventAccumulatorTable(); };

CounterTable* CounterTable::create(std::string name, std::string oid) { return new FakeCounterTable(); };

IPCountTable* IPCountTable::create(std::string name, std::string oid) { return new FakeIPCountTable(); };
IPCountRow::IPCountRow(struct in_addr addr) : IPRow(addr) {};
IPCountRow::IPCountRow(struct in6_addr addr) : IPRow(addr) {};

ColumnData IPCountRow::get_columns()
{
  ColumnData ret;
  return ret;
}

SuccessFailCountByRequestTypeTable* SuccessFailCountByRequestTypeTable::create(std::string name, std::string oid)
{
  return new FakeSuccessFailCountByRequestTypeTable();
};

SuccessFailCountTable* SuccessFailCountTable::create(std::string name, std::string oid)
{
  return new FakeSuccessFailCountTable();
};

} // Namespace SNMP ends

// Fake implementation of scalar registration function, so SNMP::U32Scalar doesn't call real SNMP
// code
int netsnmp_register_read_only_ulong_instance(const char *name,
                                              oid *reg_oid,
                                              size_t reg_oid_len,
                                              u_long *it,
                                              Netsnmp_Node_Handler *subhandler)
{
  return 0;
}
