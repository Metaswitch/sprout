/**
 * @file MMFservice_test.cpp Tests support of MMF configuration
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "gmock/gmock.h"
#include "fakelogger.h"

#include <string>
#include <vector>

#include "test_utils.hpp"
#include "mmfservice.h"
#include "mockalarm.h"

using ::testing::UnorderedElementsAreArray;
using ::testing::AtLeast;

using namespace std;

///Fixture for MMFServiceTest.
class MMFServiceTest : public ::testing::Test
{
  MMFServiceTest()
  {
    _am = new AlarmManager();
    _mock_alarm = new MockAlarm(_am);
  }

  virtual ~MMFServiceTest()
  {
    delete _am; _am = NULL;
  }

  AlarmManager* _am;
  MockAlarm* _mock_alarm;
};

// Test a valid MMF configuration file is parsed correctly.
TEST_F(MMFServiceTest, ValidMMFFile)
{
  EXPECT_CALL(*_mock_alarm, clear()).Times(AtLeast(1));
  MMFService MMF(_mock_alarm, string(UT_DIR).append("/test_mmf.json"));

  EXPECT_TRUE(MMF.has_config_for_address("10.231.0.2"));
  EXPECT_TRUE(MMF.has_config_for_address("as.test.domain"));
  EXPECT_FALSE(MMF.has_config_for_address("guff.address"));
  EXPECT_TRUE(MMF.apply_mmf_pre_as("as.test.domain"));
  EXPECT_FALSE(MMF.apply_mmf_post_as("10.231.0.2"));
}

// Test that reloading a valid MMF file with an invalid file doesn't cause the
// valid entries to be lost.
TEST_F(MMFServiceTest, ReloadInvalidMMFFile)
{
  // Load a configuration file containing two iFCs.
  EXPECT_CALL(*_mock_alarm, clear()).Times(AtLeast(1));
  MMFService MMF(_mock_alarm, string(UT_DIR).append("/test_mmf.json"));

  // Change the file the MMF service is using to an invalid file (to mimic the
  // file being changed), then reload the file, and recheck the parsed list.
  // Nothing should have changed.
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  MMF._configuration = string(UT_DIR).append("/test_mmf_invalid.json");
  MMF.update_config();

  EXPECT_TRUE(MMF.has_config_for_address("10.231.0.2"));
  EXPECT_TRUE(MMF.has_config_for_address("as.test.domain"));
  EXPECT_FALSE(MMF.has_config_for_address("guff.address"));
  EXPECT_TRUE(MMF.apply_mmf_pre_as("as.test.domain"));
  EXPECT_FALSE(MMF.apply_mmf_post_as("10.231.0.2"));
}


// In the following tests we have various invalid/unexpected MMF Json
// files.
// These tests check that the correct logs are made in each case; this isn't
// ideal as it means the tests are quite fragile, but it's the best we can do.

// Test that we log appropriately if the MMF config file is mising.
TEST_F(MMFServiceTest, MissingFile)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  MMFService MMF(_mock_alarm, string(UT_DIR).append("/non_existent_file.json"));
  EXPECT_TRUE(log.contains("No MMF configuration found (file"));
}

// Test that we log appropriately if the MMF config file is empty.
TEST_F(MMFServiceTest, EmptyFile)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  MMFService MMF(_mock_alarm, string(UT_DIR).append("/test_mmf_empty.json"));
  EXPECT_TRUE(log.contains("Failed to read MMF configuration data from "));
}

// Test that we log appropriately if the MMF config file has invalid json.
TEST_F(MMFServiceTest, BadJson)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  MMFService MMF(_mock_alarm, string(UT_DIR).append("/test_mmf_bad_json.json"));
  EXPECT_TRUE(log.contains("Failed to read the MMF configuration data from "));
}

// Test that we cope with the case that the MMF file is valid but empty.
// (Use case - customer wishes to 'turn off' MMF.)
TEST_F(MMFServiceTest, EmptyValidFile)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, clear()).Times(AtLeast(1));
  MMFService MMF(_mock_alarm, string(UT_DIR).append("/test_mmf_empty_valid.json"));
  EXPECT_FALSE(log.contains("No MMF config present in the .* file.  Sprout will not apply MMF to any calls"));
}

// Test that we log appropriately if a set of MMF config has no post-AS field.
TEST_F(MMFServiceTest, MissingPostAS)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  MMFService MMF(_mock_alarm, string(UT_DIR).append("/test_mmf_no_post_as.json"));
  EXPECT_TRUE(log.contains("Invalid 'post-AS' field in MMF configuration"));
  EXPECT_TRUE(log.contains("Badly formed MMF configuration file - keep current config"));
}

// Test that we log appropriately if a set of MMF config has an invalid post-AS field.
TEST_F(MMFServiceTest, InvalidPostAS)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  MMFService MMF(_mock_alarm, string(UT_DIR).append("/test_mmf_bad_post_as.json"));
  EXPECT_TRUE(log.contains("Invalid 'post-AS' field in MMF configuration"));
  EXPECT_TRUE(log.contains("Badly formed MMF configuration file - keep current config"));
}

// Test that we log appropriately if a set of MMF config has no pre-AS field.
TEST_F(MMFServiceTest, MissingPreAS)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  MMFService MMF(_mock_alarm, string(UT_DIR).append("/test_mmf_no_pre_as.json"));
  EXPECT_TRUE(log.contains("Invalid 'pre-AS' field in MMF configuration"));
  EXPECT_TRUE(log.contains("Badly formed MMF configuration file - keep current config"));
}

// Test that we log appropriately if a set of MMF config has an invalid pre-AS field.
TEST_F(MMFServiceTest, InvalidPreAS)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  MMFService MMF(_mock_alarm, string(UT_DIR).append("/test_mmf_bad_pre_as.json"));
  EXPECT_TRUE(log.contains("Invalid 'pre-AS' field in MMF configuration"));
  EXPECT_TRUE(log.contains("Badly formed MMF configuration file - keep current config"));
}

// Test that we log appropriately if a set of MMF config has no context field.
TEST_F(MMFServiceTest, MissingContext)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  MMFService MMF(_mock_alarm, string(UT_DIR).append("/test_mmf_no_context.json"));
  EXPECT_TRUE(log.contains("Invalid 'context' field in MMF configuration"));
  EXPECT_TRUE(log.contains("Badly formed MMF configuration file - keep current config"));
}

// Test that we log appropriately if a set of MMF config has an invalid context field.
TEST_F(MMFServiceTest, InvalidContext)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  MMFService MMF(_mock_alarm, string(UT_DIR).append("/test_mmf_bad_context.json"));
  EXPECT_TRUE(log.contains("Invalid 'context' field in MMF configuration"));
  EXPECT_TRUE(log.contains("Badly formed MMF configuration file - keep current config"));
}

// Test that we log appropriately if a set of MMF config has no addresses field.
TEST_F(MMFServiceTest, MissingAddresses)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  MMFService MMF(_mock_alarm, string(UT_DIR).append("/test_mmf_no_addresses.json"));
  EXPECT_TRUE(log.contains("Invalid 'addresses' field in MMF configuration"));
  EXPECT_TRUE(log.contains("Badly formed MMF configuration file - keep current config"));
}

// Test that we log appropriately if a set of MMF config has an invalid addresses field.
TEST_F(MMFServiceTest, InvalidAddresses)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  MMFService MMF(_mock_alarm, string(UT_DIR).append("/test_mmf_bad_addresses.json"));
  EXPECT_TRUE(log.contains("Invalid 'addresses' field in MMF configuration"));
  EXPECT_TRUE(log.contains("Badly formed MMF configuration file - keep current config"));
}

// Test that we log appropriately if a set of MMF config has an invalid address.
TEST_F(MMFServiceTest, InvalidAddress)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  MMFService MMF(_mock_alarm, string(UT_DIR).append("/test_mmf_bad_address.json"));
  EXPECT_TRUE(log.contains("Invalid 'addresses' field in MMF configuration"));
  EXPECT_TRUE(log.contains("Badly formed MMF configuration file - keep current config"));
}

// Test that we log appropriately if we have multiple sets of MMF config for
// the same address.
TEST_F(MMFServiceTest, DuplicateAddress)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  MMFService MMF(_mock_alarm, string(UT_DIR).append("/test_mmf_duplicate_address.json"));
  EXPECT_TRUE(log.contains("Duplicate config present in the"));
  EXPECT_TRUE(log.contains("Badly formed MMF configuration file - keep current config"));
}
