#include "mock_hss_connection.h"

MockHSSConnection::MockHSSConnection():
  HSSConnection("localhost",
                NULL,
                NULL,
                &SNMP::FAKE_IP_COUNT_TABLE,
                &SNMP::FAKE_EVENT_ACCUMULATOR_TABLE,
                &SNMP::FAKE_EVENT_ACCUMULATOR_TABLE,
                &SNMP::FAKE_EVENT_ACCUMULATOR_TABLE,
                &SNMP::FAKE_EVENT_ACCUMULATOR_TABLE,
                &SNMP::FAKE_EVENT_ACCUMULATOR_TABLE,
                NULL,
                NULL,
                0) {};
MockHSSConnection::~MockHSSConnection() {};

