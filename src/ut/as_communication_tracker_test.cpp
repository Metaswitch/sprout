/**
 * @file as_communication_tracker_test.cpp
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2016  Metaswitch Networks Ltd
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

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "as_communication_tracker.h"

#include "mockalarm.h"
#include "test_interposer.hpp"

using ::testing::_;

class MockLog : public PDLog1<const char*>
{
public:
  MockLog() : PDLog1(1, 2, "", "", "", "") {};
  MOCK_CONST_METHOD1(log, void(const char*));
};

class AsCommunicationTrackerTest : public ::testing::Test
{
public:
  AsCommunicationTracker* _comm_tracker;
  MockAlarm* _mock_alarm;
  const MockLog* _mock_error_log;
  const MockLog* _mock_ok_log;

  void SetUp()
  {
    _mock_alarm = new MockAlarm();
    _mock_error_log = new MockLog();
    _mock_ok_log = new MockLog();
    _comm_tracker = new AsCommunicationTracker(_mock_alarm,
                                               _mock_error_log,
                                               _mock_ok_log);
  }

  void TearDown()
  {
    delete _comm_tracker;
    delete _mock_alarm;
    delete _mock_error_log;
    delete _mock_ok_log;
  }

  const std::string AS1 = "as1";
};

static void advance_time()
{
  cwtest_advance_time_ms((5 * 60 * 1000) + 1);
}


TEST_F(AsCommunicationTrackerTest, SuccessIsIdempotent)
{
  _comm_tracker->on_success(AS1);
  _comm_tracker->on_success(AS1);
  _comm_tracker->on_success(AS1);
}


TEST_F(AsCommunicationTrackerTest, SingleAsFailure)
{
  EXPECT_CALL(*_mock_alarm, set());
  EXPECT_CALL(*_mock_error_log, log(_));
  _comm_tracker->on_failure(AS1);

  advance_time();
  _comm_tracker->on_success(AS1);

  EXPECT_CALL(*_mock_alarm, clear());
  EXPECT_CALL(*_mock_ok_log, log(_));

  advance_time();
  _comm_tracker->on_success(AS1);
}
