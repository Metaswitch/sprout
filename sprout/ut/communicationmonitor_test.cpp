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
    _cm(_ma)
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

TEST_F(CommunicationMonitorTest, SuccessNoUpdate)
{
  EXPECT_CALL(*_ma, alarmed()).Times(0);
  _cm.inform_success();
}

TEST_F(CommunicationMonitorTest, FailureNoUpdate)
{
  EXPECT_CALL(*_ma, alarmed()).Times(0);
  _cm.inform_failure();
}

TEST_F(CommunicationMonitorTest, UpdateNoAlarmSuccessCleared)
{
  cwtest_advance_time_ms(16000);
  EXPECT_CALL(*_ma, alarmed()).Times(2).WillRepeatedly(Return(false));
  EXPECT_CALL(*_ma, set()).Times(0);
  EXPECT_CALL(*_ma, clear()).Times(0);
  _cm.inform_success();
}

TEST_F(CommunicationMonitorTest, UpdateNoAlarmFailureSet)
{
  cwtest_advance_time_ms(31000);
  EXPECT_CALL(*_ma, alarmed()).Times(2).WillRepeatedly(Return(true));
  EXPECT_CALL(*_ma, set()).Times(0);
  EXPECT_CALL(*_ma, clear()).Times(0);
  _cm.inform_failure();
}

TEST_F(CommunicationMonitorTest, UpdateAlarmFailureCleared)
{
  cwtest_advance_time_ms(16000);
  EXPECT_CALL(*_ma, alarmed()).Times(2).WillRepeatedly(Return(false));
  EXPECT_CALL(*_ma, set()).Times(1);
  EXPECT_CALL(*_ma, clear()).Times(0);
  _cm.inform_failure();
}

TEST_F(CommunicationMonitorTest, UpdateAlarmSuccessSet)
{
  cwtest_advance_time_ms(31000);
  EXPECT_CALL(*_ma, alarmed()).Times(2).WillRepeatedly(Return(true));
  EXPECT_CALL(*_ma, set()).Times(0);
  EXPECT_CALL(*_ma, clear()).Times(1);
  _cm.inform_success();
}
