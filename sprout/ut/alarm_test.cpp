/**
 * @file alarm_test.cpp
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

#include "alarm.h"
#include "fakezmq.h"
#include "fakelogger.h"

using ::testing::_;
using ::testing::Return;
using ::testing::ReturnNull;
using ::testing::InSequence;
using ::testing::SafeMatcherCast;
using ::testing::StrEq;

static const char issuer[] = "sprout";

MATCHER_P(VoidPointeeEqualsInt, value, "") 
{
  return (*((int*)arg) == value);
}

class AlarmTest : public ::testing::Test
{
public:
  AlarmTest() :
    _alarm_state(issuer, AlarmDef::SPROUT_HOMESTEAD_COMM_ERROR, AlarmDef::CRITICAL),
    _alarm(issuer, AlarmDef::SPROUT_CHRONOS_COMM_ERROR, AlarmDef::MAJOR),
    _c(1),
    _s(2)
  {
    cwtest_intercept_zmq(&_mz);

    EXPECT_CALL(_mz, zmq_ctx_new())
      .Times(1)
      .WillOnce(Return(&_c));

    EXPECT_CALL(_mz, zmq_socket(VoidPointeeEqualsInt(_c),ZMQ_REQ))
      .Times(1)
      .WillOnce(Return(&_s));

    EXPECT_CALL(_mz, zmq_setsockopt(VoidPointeeEqualsInt(_s),ZMQ_LINGER,_,_))
      .Times(1)
      .WillOnce(Return(0));

    EXPECT_CALL(_mz, zmq_connect(VoidPointeeEqualsInt(_s),StrEq("tcp://127.0.0.1:6664")))
      .Times(1)
      .WillOnce(Return(0));

    AlarmReqAgent::get_instance().start();
  }

  virtual ~AlarmTest()
  {
    EXPECT_CALL(_mz, zmq_close(VoidPointeeEqualsInt(_s)))
      .Times(1)
      .WillOnce(Return(0));

    EXPECT_CALL(_mz, zmq_ctx_destroy(VoidPointeeEqualsInt(_c)))
      .Times(1)
      .WillOnce(Return(0));

    AlarmReqAgent::get_instance().stop();
    cwtest_restore_zmq();
  }

private:
  MockZmqInterface _mz;
  AlarmState _alarm_state;
  Alarm _alarm;
  int _c;
  int _s;
};

class AlarmQueueErrorTest : public ::testing::Test
{
public:
  AlarmQueueErrorTest() :
    _alarm_state(issuer, AlarmDef::SPROUT_HOMESTEAD_COMM_ERROR, AlarmDef::CRITICAL)
  {
    AlarmReqAgent::get_instance().start();
  }

  virtual ~AlarmQueueErrorTest()
  {
    AlarmReqAgent::get_instance().stop();
  }

private:
  AlarmState _alarm_state;
};

class AlarmZmqErrorTest : public ::testing::Test
{
public:
  AlarmZmqErrorTest() :
    _alarm_state(issuer, AlarmDef::SPROUT_HOMESTEAD_COMM_ERROR, AlarmDef::CRITICAL),
    _c(1),
    _s(2)
  {
    cwtest_intercept_zmq(&_mz);
  }

  virtual ~AlarmZmqErrorTest()
  {
    cwtest_restore_zmq();
  }

private:
  MockZmqInterface _mz;
  AlarmState _alarm_state;
  int _c;
  int _s;
};

MATCHER_P(VoidPointeeEqualsStr, value, "") 
{
  return (strcmp((char*)arg, value) == 0);
}

TEST_F(AlarmTest, IssueAlarm)
{
  {
    InSequence s;

    EXPECT_CALL(_mz, zmq_send(_,VoidPointeeEqualsStr("issue-alarm"),11,ZMQ_SNDMORE))
      .Times(1)
      .WillOnce(Return(0));

    EXPECT_CALL(_mz, zmq_send(_,VoidPointeeEqualsStr(issuer),strlen(issuer),ZMQ_SNDMORE))
      .Times(1)
      .WillOnce(Return(0));

    EXPECT_CALL(_mz, zmq_send(_,VoidPointeeEqualsStr("1001.3"),6,0))
      .Times(1)
      .WillOnce(Return(0));

    EXPECT_CALL(_mz, zmq_recv(_,_,_,_))
      .Times(1)
      .WillOnce(Return(0));
  }
  _alarm_state.issue();
  _mz.call_complete(ZmqInterface::ZMQ_RECV, 5);
}

TEST_F(AlarmTest, ClearAlarms)
{
  {
    InSequence s;

    EXPECT_CALL(_mz, zmq_send(_,VoidPointeeEqualsStr("clear-alarms"),12,ZMQ_SNDMORE))
      .Times(1)
      .WillOnce(Return(0));

    EXPECT_CALL(_mz, zmq_send(_,VoidPointeeEqualsStr(issuer),strlen(issuer),0))
      .Times(1)
      .WillOnce(Return(0));

    EXPECT_CALL(_mz, zmq_recv(_,_,_,_))
      .Times(1)
      .WillOnce(Return(0));
  }
  AlarmState::clear_all(issuer);
  _mz.call_complete(ZmqInterface::ZMQ_RECV, 5);
}

TEST_F(AlarmTest, PairSetNotAlarmed)
{
  InSequence s;

  EXPECT_CALL(_mz, zmq_send(_,VoidPointeeEqualsStr("issue-alarm"),11,ZMQ_SNDMORE))
    .Times(1)
    .WillOnce(Return(0));

  EXPECT_CALL(_mz, zmq_send(_,VoidPointeeEqualsStr(issuer),strlen(issuer),ZMQ_SNDMORE))
    .Times(1)
    .WillOnce(Return(0));

  EXPECT_CALL(_mz, zmq_send(_,VoidPointeeEqualsStr("1004.4"),6,0))
    .Times(1)
    .WillOnce(Return(0));

  EXPECT_CALL(_mz, zmq_recv(_,_,_,_))
    .Times(1)
    .WillOnce(Return(0));

  _alarm.set();
  _mz.call_complete(ZmqInterface::ZMQ_RECV, 5);
}

TEST_F(AlarmTest, PairSetAlarmed)
{
  {
    InSequence s;

    EXPECT_CALL(_mz, zmq_send(_,_,_,_))
      .Times(3)
      .WillRepeatedly(Return(0));

    EXPECT_CALL(_mz, zmq_recv(_,_,_,_))
      .Times(1)
      .WillOnce(Return(0));

    _alarm.set();
    _mz.call_complete(ZmqInterface::ZMQ_RECV, 5);
  }

  EXPECT_CALL(_mz, zmq_send(_,_,_,_)).Times(0);
  _alarm.set();
}

TEST_F(AlarmTest, PairClearNotAlarmed)
{
  EXPECT_CALL(_mz, zmq_send(_,_,_,_)).Times(0);
  _alarm.clear();
}

TEST_F(AlarmTest, PairClearAlarmed)
{
  {
    InSequence s;

    EXPECT_CALL(_mz, zmq_send(_,_,_,_))
      .Times(3)
      .WillRepeatedly(Return(0));

    EXPECT_CALL(_mz, zmq_recv(_,_,_,_))
      .Times(1)
      .WillOnce(Return(0));

    _alarm.set();
    _mz.call_complete(ZmqInterface::ZMQ_RECV, 5);
  }

  {
    InSequence s;

    EXPECT_CALL(_mz, zmq_send(_,VoidPointeeEqualsStr("issue-alarm"),11,ZMQ_SNDMORE))
      .Times(1)
      .WillOnce(Return(0));

    EXPECT_CALL(_mz, zmq_send(_,VoidPointeeEqualsStr(issuer),strlen(issuer),ZMQ_SNDMORE))
      .Times(1)
      .WillOnce(Return(0));

    EXPECT_CALL(_mz, zmq_send(_,VoidPointeeEqualsStr("1004.1"),6,0))
      .Times(1)
      .WillOnce(Return(0));

    EXPECT_CALL(_mz, zmq_recv(_,_,_,_))
      .Times(1)
      .WillOnce(Return(0));

    _alarm.clear();
    _mz.call_complete(ZmqInterface::ZMQ_RECV, 5);
  }
}

TEST_F(AlarmQueueErrorTest, Overflow)
{
  CapturingTestLogger log;
  for (int idx = 0; idx < AlarmReqAgent::MAX_Q_DEPTH+1; idx++)
  {
    _alarm_state.issue();
  }
  EXPECT_TRUE(log.contains("queue overflowed"));
}

TEST_F(AlarmZmqErrorTest, CreateContext)
{
  CapturingTestLogger log;

  EXPECT_CALL(_mz, zmq_ctx_new()).WillOnce(ReturnNull());

  EXPECT_FALSE(AlarmReqAgent::get_instance().start());
  EXPECT_TRUE(log.contains("zmq_ctx_new failed"));
}

TEST_F(AlarmZmqErrorTest, CreateSocket)
{
  CapturingTestLogger log;

  EXPECT_CALL(_mz, zmq_ctx_new()).WillOnce(Return(&_c));
  EXPECT_CALL(_mz, zmq_socket(_,_)) .WillOnce(ReturnNull());
  EXPECT_CALL(_mz, zmq_ctx_destroy(_)).WillOnce(Return(0));

  EXPECT_TRUE(AlarmReqAgent::get_instance().start());

  AlarmReqAgent::get_instance().stop();
  EXPECT_TRUE(log.contains("zmq_socket failed"));
}

TEST_F(AlarmZmqErrorTest, SetSockOpt)
{
  CapturingTestLogger log;

  EXPECT_CALL(_mz, zmq_ctx_new()).WillOnce(Return(&_c));
  EXPECT_CALL(_mz, zmq_socket(_,_)).WillOnce(Return(&_s));
  EXPECT_CALL(_mz, zmq_setsockopt(_,_,_,_)).WillOnce(Return(-1));
  EXPECT_CALL(_mz, zmq_ctx_destroy(_)).WillOnce(Return(0));

  EXPECT_TRUE(AlarmReqAgent::get_instance().start());

  AlarmReqAgent::get_instance().stop();
  EXPECT_TRUE(log.contains("zmq_setsockopt failed"));
}

TEST_F(AlarmZmqErrorTest, Connect)
{
  CapturingTestLogger log;

  EXPECT_CALL(_mz, zmq_ctx_new()).WillOnce(Return(&_c));
  EXPECT_CALL(_mz, zmq_socket(_,_)).WillOnce(Return(&_s));
  EXPECT_CALL(_mz, zmq_setsockopt(_,_,_,_)).WillOnce(Return(0));
  EXPECT_CALL(_mz, zmq_connect(_,_)).WillOnce(Return(-1));
  EXPECT_CALL(_mz, zmq_ctx_destroy(_)).WillOnce(Return(0));

  EXPECT_TRUE(AlarmReqAgent::get_instance().start());

  AlarmReqAgent::get_instance().stop();
  EXPECT_TRUE(log.contains("zmq_connect failed"));
}

TEST_F(AlarmZmqErrorTest, Send)
{
  CapturingTestLogger log;

  EXPECT_CALL(_mz, zmq_ctx_new()).WillOnce(Return(&_c));
  EXPECT_CALL(_mz, zmq_socket(_,_)).WillOnce(Return(&_s));
  EXPECT_CALL(_mz, zmq_setsockopt(_,_,_,_)).WillOnce(Return(0));
  EXPECT_CALL(_mz, zmq_connect(_,_)).WillOnce(Return(0));
  EXPECT_CALL(_mz, zmq_send(_,_,_,_)).WillOnce(Return(-1));
  EXPECT_CALL(_mz, zmq_close(_)).WillOnce(Return(0));
  EXPECT_CALL(_mz, zmq_ctx_destroy(_)).WillOnce(Return(0));

  EXPECT_TRUE(AlarmReqAgent::get_instance().start());
  _alarm_state.issue();
  _mz.call_complete(ZmqInterface::ZMQ_SEND, 5);

  AlarmReqAgent::get_instance().stop();
  EXPECT_TRUE(log.contains("zmq_send failed"));
}

TEST_F(AlarmZmqErrorTest, Receive)
{
  CapturingTestLogger log;

  EXPECT_CALL(_mz, zmq_ctx_new()).WillOnce(Return(&_c));
  EXPECT_CALL(_mz, zmq_socket(_,_)).WillOnce(Return(&_s));
  EXPECT_CALL(_mz, zmq_setsockopt(_,_,_,_)).WillOnce(Return(0));
  EXPECT_CALL(_mz, zmq_connect(_,_)).WillOnce(Return(0));
  EXPECT_CALL(_mz, zmq_send(_,_,_,_)).Times(3).WillRepeatedly(Return(0));
  EXPECT_CALL(_mz, zmq_recv(_,_,_,_)).WillOnce(Return(-1));
  EXPECT_CALL(_mz, zmq_close(_)).WillOnce(Return(0));
  EXPECT_CALL(_mz, zmq_ctx_destroy(_)).WillOnce(Return(0));

  EXPECT_TRUE(AlarmReqAgent::get_instance().start());
  _alarm_state.issue();
  _mz.call_complete(ZmqInterface::ZMQ_RECV, 5);

  AlarmReqAgent::get_instance().stop();
  EXPECT_TRUE(log.contains("zmq_recv failed"));
}

TEST_F(AlarmZmqErrorTest, CloseSocket)
{
  CapturingTestLogger log;

  EXPECT_CALL(_mz, zmq_ctx_new()).WillOnce(Return(&_c));
  EXPECT_CALL(_mz, zmq_socket(_,_)).WillOnce(Return(&_s));
  EXPECT_CALL(_mz, zmq_setsockopt(_,_,_,_)).WillOnce(Return(0));
  EXPECT_CALL(_mz, zmq_connect(_,_)).WillOnce(Return(0));
  EXPECT_CALL(_mz, zmq_close(_)).WillOnce(Return(-1));
  EXPECT_CALL(_mz, zmq_ctx_destroy(_)).WillOnce(Return(0));

  EXPECT_TRUE(AlarmReqAgent::get_instance().start());
  AlarmReqAgent::get_instance().stop();

  EXPECT_TRUE(log.contains("zmq_close failed"));
}

TEST_F(AlarmZmqErrorTest, DestroyContext)
{
  CapturingTestLogger log;

  EXPECT_CALL(_mz, zmq_ctx_new()).WillOnce(Return(&_c));
  EXPECT_CALL(_mz, zmq_socket(_,_)).WillOnce(Return(&_s));
  EXPECT_CALL(_mz, zmq_setsockopt(_,_,_,_)).WillOnce(Return(0));
  EXPECT_CALL(_mz, zmq_connect(_,_)).WillOnce(Return(0));
  EXPECT_CALL(_mz, zmq_close(_)).WillOnce(Return(0));
  EXPECT_CALL(_mz, zmq_ctx_destroy(_)).WillOnce(Return(-1));

  EXPECT_TRUE(AlarmReqAgent::get_instance().start());
  AlarmReqAgent::get_instance().stop();

  EXPECT_TRUE(log.contains("zmq_ctx_destroy failed"));
}

