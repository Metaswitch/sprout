/**
 * @file communicationmonitor_test.cpp
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2014  Metaswitch Networks Ltd
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

#include <string>
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "utils.h"
#include "test_utils.hpp"
#include "test_interposer.hpp"

#include "communicationmonitor.h"
#include "mockalarm.h"

using ::testing::Return;

/// Fixture for CommunicationMonitor test.
class CommunicationMonitorTest : public ::testing::Test
{
public:
  CommunicationMonitorTest() :
    _ma(new MockAlarm()),
    _cm(_ma, "sprout", "chronos")
  {
    cwtest_completely_control_time();
  }

  virtual ~CommunicationMonitorTest()
  {
    cwtest_reset_time();
  }

private:
  MockAlarm* _ma;
  CommunicationMonitor _cm;
};

// State Definitions:
//
// NO_ERRORS == No failures, at least one success
// SOME_ERRORS == At least one failure, at least one success
// ONLY_ERRORS == At least one failure, no successes.

// Tests that the alarm is raised at the corect point as we move up error states.
TEST_F(CommunicationMonitorTest, ErrorsStateIncrement)
{
  // Default start point is state NO_ERRORS
  // Move to SOME_ERRORS: set a success, then update with a failure.
  // This should not set or clear any alarm.
  EXPECT_CALL(*_ma, set()).Times(0);
  EXPECT_CALL(*_ma, clear()).Times(0);
  _cm.inform_success();
  cwtest_advance_time_ms(16000);
  _cm.inform_failure();

  // Move to ONLY_ERRORS: set a failure after the set_confirm interval.
  // This should raise the alarm.
  EXPECT_CALL(*_ma, set()).Times(1);
  EXPECT_CALL(*_ma, clear()).Times(0);
  cwtest_advance_time_ms(16000);
  _cm.inform_failure();
}

// Tests that the alarm is cleared as we move down the error states.
TEST_F(CommunicationMonitorTest, ErrorStateDecrement)
{
  // Move to ONLY_ERRORS as start point.
  EXPECT_CALL(*_ma, set()).Times(1);
  EXPECT_CALL(*_ma, clear()).Times(0);
  cwtest_advance_time_ms(16000);
  _cm.inform_failure();

  // Advance time beyond the clear_confirm interval.
  // Move to SOME_ERRORS: set a success, advance time, then update with a failure.
  // This should clear the alarm.
  _cm.inform_success();
  cwtest_advance_time_ms(31000);
  EXPECT_CALL(*_ma, set()).Times(0);
  EXPECT_CALL(*_ma, clear()).Times(1);
  _cm.inform_failure();

  // Advance time beyond the set_confirm interval.
  // Move to NO_ERRORS: advance time, then update with a success.
  // This should not change anything
  cwtest_advance_time_ms(16000);
  EXPECT_CALL(*_ma, set()).Times(0);
  EXPECT_CALL(*_ma, clear()).Times(0);
  _cm.inform_success();

}

// Tests that the alarm is raised and cleared on moving from NO_ERRORS to ONLY_ERRORS and back.
TEST_F(CommunicationMonitorTest, OnlyErrorsToNoErrorsUpdate)
{
  // Move to ONLY_ERRORS as start point.
  // This should set the alarm.
  EXPECT_CALL(*_ma, set()).Times(1);
  EXPECT_CALL(*_ma, clear()).Times(0);
  cwtest_advance_time_ms(16000);
  _cm.inform_failure();

  // Advance time beyond the clear_confirm interval.
  // Move to NO_ERRORS: advance time, then update with a success.
  // This should clear the alarm.
  cwtest_advance_time_ms(31000);
  EXPECT_CALL(*_ma, set()).Times(0);
  EXPECT_CALL(*_ma, clear()).Times(1);
  _cm.inform_success();
}

// Tests that the set_confirm_ms check is working.
// The communication monitor should only update to set an alarm if the
// time has advanced by the set_confirm_ms interval at the time of update.
TEST_F(CommunicationMonitorTest, TestSetConfirmMs)
{
  // Set us to SOME_ERRORS as a starting point.
  // This should do nothing, but will leave the next_check as now+set_confirm_ms.
  EXPECT_CALL(*_ma, set()).Times(0);
  EXPECT_CALL(*_ma, clear()).Times(0);
  _cm.inform_success();
  cwtest_advance_time_ms(16000);
  _cm.inform_failure();
  
  // Advance time by less than the set_confirm interval, and set a failure.
  // This should do nothing.
  EXPECT_CALL(*_ma, set()).Times(0);
  EXPECT_CALL(*_ma, clear()).Times(0);
  cwtest_advance_time_ms(10000);
  _cm.inform_failure();

  // Advance time beyond the set_confirm interval, but less than clear_confirm, and set a failure.
  // This should now set the alarm.
  EXPECT_CALL(*_ma, set()).Times(1);
  EXPECT_CALL(*_ma, clear()).Times(0);
  cwtest_advance_time_ms(10000);
  _cm.inform_failure();
}

// Tests that the clear_confirm check is working.
// The communication monitor should only update to clear an alarm if the
// time has advanced by the clear_confirm_ms interval at the time of update.
TEST_F(CommunicationMonitorTest, TestClearConfirmMs)
{
  // Set up the ONLY_ERRORS state. This sets the alarm.
  EXPECT_CALL(*_ma, set()).Times(1);
  EXPECT_CALL(*_ma, clear()).Times(0);
  cwtest_advance_time_ms(16000);
  _cm.inform_failure();

  // Advance time less than clear_confirm, but more than set_confirm, and inform of a success.
  // This should do nothing.
  EXPECT_CALL(*_ma, set()).Times(0);
  EXPECT_CALL(*_ma, clear()).Times(0);
  cwtest_advance_time_ms(16000);
  _cm.inform_success();

  // Advance time again, beyond clear_confirm, and inform of a success.
  // This should clear the alarm.
  EXPECT_CALL(*_ma, set()).Times(0);
  EXPECT_CALL(*_ma, clear()).Times(1);
  cwtest_advance_time_ms(16000);
  _cm.inform_success();
}
