/**
 * @file fakesnmp.hpp Fake SNMP infrastructure (for testing).
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
}

#endif
