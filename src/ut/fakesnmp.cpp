/**
 * @file fakesnmp.cpp Fake SNMP infrastructure (for testing).
 *
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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
FakeCounterTable FAKE_NO_MATCHING_IFCS_TABLE;
FakeCounterTable FAKE_NO_MATCHING_FALLBACK_IFCS_TABLE;
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
