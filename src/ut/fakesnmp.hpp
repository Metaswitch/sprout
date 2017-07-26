/**
 * @file fakesnmp.hpp Fake SNMP infrastructure (for testing).
 *
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef FAKE_SNMP_H
#define FAKE_SNMP_H

#include "snmp_row.h"
#include "snmp_event_accumulator_table.h"
#include "snmp_continuous_accumulator_table.h"
#include "snmp_scalar.h"
#include "snmp_counter_table.h"
#include "snmp_counter_by_scope_table.h"
#include "snmp_ip_count_table.h"
#include "snmp_success_fail_count_table.h"
#include "snmp_success_fail_count_by_request_type_table.h"
#include "snmp_time_and_string_based_event_table.h"

namespace SNMP
{
class FakeEventAccumulatorTable: public EventAccumulatorTable
{
public:
  int _count;
  FakeEventAccumulatorTable() { _count = 0; };
  void accumulate(uint32_t sample) { _count++; };
};

class FakeContinuousAccumulatorTable: public ContinuousAccumulatorTable
{
public:
  FakeContinuousAccumulatorTable() {};
  void accumulate(uint32_t sample) {};
};

class FakeCounterTable: public CounterTable
{
public:
  int _count;
  FakeCounterTable() { _count = 0; };
  void increment() { _count++; };
  void reset_count() { _count = 0; }
};

class FakeCounterByScopeTable: public CounterByScopeTable
{
public:
  int _count;
  FakeCounterByScopeTable() { _count = 0; };
  void increment() { _count++; };
  void reset_count() { _count = 0; }
};

extern struct in_addr dummy_addr;

class FakeIPCountRow: public IPCountRow
{
public:
  FakeIPCountRow(): IPCountRow(dummy_addr) {};

  uint32_t increment() { return ++_count; };
  uint32_t decrement() { return --_count; };

  ColumnData get_columns() { ColumnData c; return c; };

  uint32_t _count;
};

extern FakeIPCountRow FAKE_IP_COUNT_ROW;

class FakeIPCountTable : public IPCountTable
{
public:
  FakeIPCountTable() {};
  IPCountRow* get(std::string key) {return &FAKE_IP_COUNT_ROW; };
  void add(std::string key) {};
  void remove(std::string key) {};
};

class FakeSuccessFailCountTable : public SuccessFailCountTable
{
public:
  int _attempts, _successes, _failures;
  FakeSuccessFailCountTable()
  {
    _attempts = 0;
    _successes = 0;
    _failures = 0;
  };
  void increment_attempts()
  {
    _attempts++;
  };
  void increment_successes()
  {
    _successes++;
  };
  void increment_failures()
  {
    _failures++;
  };
  void reset_count()
  {
    _attempts = 0;
    _successes = 0;
    _failures = 0;
  };
};

class FakeSuccessFailCountByRequestTypeTable : public SuccessFailCountByRequestTypeTable
{
public:
  FakeSuccessFailCountByRequestTypeTable() {};
  void increment_attempts(SIPRequestTypes type) {};
  void increment_successes(SIPRequestTypes type) {};
  void increment_failures(SIPRequestTypes type) {};
};

class FakeTimeAndStringBasedEventTable : public TimeAndStringBasedEventTable
{
public:
  std::vector<std::pair<std::string, uint32_t>> _stats;
  FakeTimeAndStringBasedEventTable() {};
  void accumulate(std::string str_index, uint32_t sample) override
  {
    _stats.push_back(std::pair<std::string, uint32_t>(str_index, sample));
  };
};

extern FakeIPCountTable FAKE_IP_COUNT_TABLE;
extern FakeCounterTable FAKE_COUNTER_TABLE;
extern FakeCounterByScopeTable FAKE_COUNTER_BY_SCOPE_TABLE;
extern FakeEventAccumulatorTable FAKE_EVENT_ACCUMULATOR_TABLE;
extern FakeContinuousAccumulatorTable FAKE_CONTINUOUS_ACCUMULATOR_TABLE;
extern FakeSuccessFailCountTable FAKE_INIT_REG_TABLE;
extern FakeSuccessFailCountTable FAKE_RE_REG_TABLE;
extern FakeSuccessFailCountTable FAKE_DE_REG_TABLE;
extern FakeSuccessFailCountTable FAKE_THIRD_PARTY_INIT_REG_TABLE;
extern FakeSuccessFailCountTable FAKE_THIRD_PARTY_RE_REG_TABLE;
extern FakeSuccessFailCountTable FAKE_THIRD_PARTY_DE_REG_TABLE;
extern FakeSuccessFailCountTable FAKE_SIP_DIGEST_AUTH_TABLE;
extern FakeSuccessFailCountTable FAKE_IMS_AKA_AUTH_TABLE;
extern FakeSuccessFailCountTable FAKE_NON_REG_AUTH_TABLE;
extern RegistrationStatsTables FAKE_REGISTRATION_STATS_TABLES;
extern RegistrationStatsTables FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES;
extern AuthenticationStatsTables FAKE_AUTHENTICATION_STATS_TABLES;
extern FakeSuccessFailCountByRequestTypeTable FAKE_INCOMING_SIP_TRANSACTIONS_TABLE;
extern FakeSuccessFailCountByRequestTypeTable FAKE_OUTGOING_SIP_TRANSACTIONS_TABLE;
extern FakeTimeAndStringBasedEventTable FAKE_TIME_AND_STRING_BASED_EVENT_TABLE;
}

#endif
