/**
 * @file rphservice_test.cpp - UTs for the RPHService class
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "rphservice.h"
#include "test_utils.hpp"
#include "fakelogger.h"
#include "mockalarm.h"

using ::testing::AtLeast;

using namespace std;

/// Fixture for SIFCServiceTest.
class RPHServiceTest : public ::testing::Test
{
  RPHServiceTest()
  {
    _am = new AlarmManager();
    _mock_alarm = new MockAlarm(_am);
  }

  virtual ~RPHServiceTest()
  {
    delete _am; _am = NULL;
  }

  AlarmManager* _am;
  MockAlarm* _mock_alarm;
};

TEST_F(RPHServiceTest, NoRPHFile)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  RPHService rph(_mock_alarm, string(UT_DIR).append("/test_non_existent_rph.json"));
  EXPECT_TRUE(log.contains("No RPH configuration (file ut/test_non_existent_rph.json does not exist)"));
  EXPECT_TRUE(rph._rph_map.empty());
}

TEST_F(RPHServiceTest, EmptyRPHFile)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  RPHService rph(_mock_alarm, string(UT_DIR).append("/test_empty_rph.json"));
  EXPECT_TRUE(log.contains("Failed to read RPH configuration data from ut/test_empty_rph.json"));
  EXPECT_TRUE(rph._rph_map.empty());
}

TEST_F(RPHServiceTest, InvalidRPHFile)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  RPHService rph(_mock_alarm, string(UT_DIR).append("/test_invalid_rph.json"));
  EXPECT_TRUE(log.contains("Failed to read RPH configuration data: {"));
  EXPECT_TRUE(log.contains("Error: Missing a name for object member."));
  EXPECT_TRUE(rph._rph_map.empty());
}

TEST_F(RPHServiceTest, NoPriorityBlocksRPHFile)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  RPHService rph(_mock_alarm, string(UT_DIR).append("/test_no_priority_blocks_rph.json"));
  EXPECT_TRUE(log.contains("Badly formed RPH configuration data - missing priority_blocks array"));
  EXPECT_TRUE(rph._rph_map.empty());
}

TEST_F(RPHServiceTest, NonIntegerPriorityRPHFile)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  RPHService rph(_mock_alarm, string(UT_DIR).append("/test_non_integer_priority_rph.json"));
  EXPECT_TRUE(log.contains("Badly formed RPH priority block (hit error at"));
  EXPECT_TRUE(rph._rph_map.empty());
}

TEST_F(RPHServiceTest, InvalidPriorityRPHFile)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  RPHService rph(_mock_alarm, string(UT_DIR).append("/test_invalid_priority_rph.json"));
  EXPECT_TRUE(log.contains("RPH value block contains a priority not in the range 1-15"));
  EXPECT_TRUE(rph._rph_map.empty());
}

TEST_F(RPHServiceTest, DuplicatedValueRPHFile)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  RPHService rph(_mock_alarm, string(UT_DIR).append("/test_duplicated_value_rph.json"));
  EXPECT_TRUE(log.contains("Attempted to insert an RPH value into the map that already exists"));
  EXPECT_TRUE(rph._rph_map.empty());
}

TEST_F(RPHServiceTest, ValidRPHFile)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, clear()).Times(AtLeast(1));
  RPHService rph(_mock_alarm, string(UT_DIR).append("/test_rph.json"));
  EXPECT_TRUE(log.contains("RPH configuration successfully updated"));

  // Check that the map is correctly populated. Mix up cases to check that case
  // insensitive matching works.
  EXPECT_EQ(rph.lookup_priority("wPs.4", 0), SIPEventPriorityLevel::HIGH_PRIORITY_1);
  EXPECT_EQ(rph.lookup_priority("EtS.4", 0), SIPEventPriorityLevel::HIGH_PRIORITY_1);
  EXPECT_EQ(rph.lookup_priority("WPS.3", 0), SIPEventPriorityLevel::HIGH_PRIORITY_3);
  EXPECT_EQ(rph.lookup_priority("ets.3", 0), SIPEventPriorityLevel::HIGH_PRIORITY_3);
  EXPECT_EQ(rph.lookup_priority("foo", 0), SIPEventPriorityLevel::HIGH_PRIORITY_4);
  EXPECT_EQ(rph.lookup_priority("WPs.2", 0), SIPEventPriorityLevel::HIGH_PRIORITY_5);
  EXPECT_EQ(rph.lookup_priority("eTS.2", 0), SIPEventPriorityLevel::HIGH_PRIORITY_5);
  EXPECT_EQ(rph.lookup_priority("wPs.1", 0), SIPEventPriorityLevel::HIGH_PRIORITY_7);
  EXPECT_EQ(rph.lookup_priority("ETS.1", 0), SIPEventPriorityLevel::HIGH_PRIORITY_7);
  EXPECT_EQ(rph.lookup_priority("wpS.0", 0), SIPEventPriorityLevel::HIGH_PRIORITY_9);
  EXPECT_EQ(rph.lookup_priority("ETs.0", 0), SIPEventPriorityLevel::HIGH_PRIORITY_9);
  EXPECT_EQ(rph.lookup_priority("dSn.flASH-OVerride", 0), SIPEventPriorityLevel::HIGH_PRIORITY_10);
  EXPECT_EQ(rph.lookup_priority("dRSn.flash-oVeRridE", 0), SIPEventPriorityLevel::HIGH_PRIORITY_13);
  EXPECT_EQ(rph.lookup_priority("dRsn.Flash-overrIde-OVERRIDE", 0), SIPEventPriorityLevel::HIGH_PRIORITY_15);

  // Check that if we lookup an unknown RPH value, that we get back the default
  // priority.
  EXPECT_EQ(rph.lookup_priority("unknown", 0), SIPEventPriorityLevel::NORMAL_PRIORITY);
}

TEST_F(RPHServiceTest, BadlyOrderedRPHFile)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  RPHService rph(_mock_alarm, string(UT_DIR).append("/test_badly_ordered_rph.json"));
  EXPECT_TRUE(log.contains("RPH value \"wps.0\" has lower priority than a lower priority RPH value from the same namespace"));
  EXPECT_TRUE(rph._rph_map.empty());
}
