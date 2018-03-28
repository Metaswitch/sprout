/**
 * @file scscfselector_test.cpp
 *
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <string>
#include <vector>
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "utils.h"
#include "sas.h"
#include "scscfselector.h"
#include "fakelogger.h"
#include "test_utils.hpp"
#include "test_interposer.hpp"

using namespace std;

/// Fixture for SCSCFSelectorTest.
class SCSCFSelectorTest : public ::testing::Test
{
  SCSCFSelectorTest()
  {
  }

  virtual ~SCSCFSelectorTest()
  {
  }
};

/// A single test case.
class ST
{
public:
  ST(vector<int> mandate, vector<int> optional, vector<string> rejects, string out) :
    _mandate(mandate),
    _optional(optional),
    _rejects(rejects),
    _out(out)
  {
  }

  void test(SCSCFSelector& scscf_)
  {
    string ret = scscf_.get_scscf(_mandate, _optional, _rejects, 0);
    EXPECT_EQ(_out, ret);
  }

private:
  vector<int> _mandate;    // input
  vector<int> _optional;   // input
  vector<string> _rejects; // input
  string _out;             // expected output
};


TEST_F(SCSCFSelectorTest, ValidConfig)
{
  CapturingTestLogger log(5);
  // Parse a valid file. There should be no warnings in the logs. If this
  // test fails, so will the Select* tests below
  SCSCFSelector scscf_("scscf_uri", string(UT_DIR).append("/test_scscf.json"));
  EXPECT_FALSE(log.contains("Failed to read S-CSCF configuration data"));
  EXPECT_FALSE(log.contains("Badly formed S-CSCF entry"));
  EXPECT_FALSE(log.contains("Badly formed S-CSCF configuration file - missing s-cscfs object"));
  EXPECT_FALSE(log.contains("Failed to read S-CSCF configuration data"));
}

TEST_F(SCSCFSelectorTest, SelectMandatoryCapabilities)
{
  // Parse a valid file.
  SCSCFSelector scscf_("scscf_uri", string(UT_DIR).append("/test_scscf.json"));

  // Test when there's no S-CSCF with all the mandatory capabilities
  ST({9999}, {}, {}, "").test(scscf_);

  // Test when there's only one S-CSCF with all the mandatory capabilities
  ST({123, 432, 345}, {}, {}, "cw-scscf1.cw-ngv.com").test(scscf_);
}

TEST_F(SCSCFSelectorTest, SelectOptionalCapabilities)
{
  // Parse a valid file.
  SCSCFSelector scscf_("scscf_uri", string(UT_DIR).append("/test_scscf.json"));

  // Test with two S-CSCFs with the mandatory capabilities, and one has more
  // optional capabilites.
  ST({123, 432}, {654}, {}, "cw-scscf2.cw-ngv.com").test(scscf_);
}

TEST_F(SCSCFSelectorTest, SelectPriorities)
{
  // Parse a valid file.
  SCSCFSelector scscf_("scscf_uri", string(UT_DIR).append("/test_scscf.json"));

  // Test with S-CSCFs with the same mandatory and optional capabilities, but
  // different priorities.
  ST({}, {654, 567}, {}, "cw-scscf4.cw-ngv.com").test(scscf_);
}

// Check that an S-CSCF with a weighting of zero is never selected.
TEST_F(SCSCFSelectorTest, SelectWeightsBasic)
{
  // Parse a valid file.
  SCSCFSelector scscf_("scscf_uri", string(UT_DIR).append("/test_scscf.json"));

  // Test with three S-CSCFs with the same capabilities and priorites, but
  // different weights. One of the weights is 0 - this is for code coverage
  // reasons to ensure that the first S-CSCF considered is never chosen. The
  // remaining two S-CSCFs with different weights have the same name, so that
  // the test can pick either randomly and still pass.
  ST({654}, {876}, {}, "cw-scscf6.cw-ngv.com").test(scscf_);
}

// Check that two S-CSCFs with the same properties but different weightings can
// both be chosen, depending on the random number used to select them.
TEST_F(SCSCFSelectorTest, SelectWeightsAdvanced)
{
  // Set time to epoch. Since the random number generator is seeded with the
  // time, setting it to a specific time allows the "random" output to be
  // controlled.
  cwtest_completely_control_time(true);

  // Parse a valid file.
  SCSCFSelector scscf_("scscf_uri", string(UT_DIR).append("/test_scscf.json"));

  // Test with two S-CSCFs with the same properties, but different weights.
  // Check the expected S-CSCF is chosen.
  ST({654}, {987}, {}, "cw-scscf8.cw-ngv.com").test(scscf_);

  // Advance time to control the next "random" output. Check the other S-CSCF
  // is chosen.
  cwtest_advance_time_ms(4444);
  ST({654}, {987}, {}, "cw-scscf7.cw-ngv.com").test(scscf_);

  // Advance time to control the next "random" output. Check the first S-CSCF
  // is chosen again.
  cwtest_advance_time_ms(1111);
  ST({654}, {987}, {}, "cw-scscf8.cw-ngv.com").test(scscf_);

  cwtest_reset_time();
}

TEST_F(SCSCFSelectorTest, RejectSCSCFs)
{
  // Parse a valid file.
  SCSCFSelector scscf_("scscf_uri", string(UT_DIR).append("/test_scscf.json"));

  // Test when there's only one S-CSCF with all the mandatory capabilities, but
  // it's on the reject list.
  ST({123, 432, 345}, {}, {"cw-scscf1.cw-ngv.com"}, "").test(scscf_);

  // Test with two S-CSCFs with the mandatory capabilities, and one has more
  // optional capabilites. The one with more optional capabilities is on the
  // reject list, so the other one should be chosen.
  ST({123, 432}, {654}, {"cw-scscf2.cw-ngv.com"}, "cw-scscf1.cw-ngv.com").test(scscf_);
}

TEST_F(SCSCFSelectorTest, ParseError)
{
  CapturingTestLogger log;
  SCSCFSelector scscf_("scscf_uri", string(UT_DIR).append("/test_scscf_parse_error.json"));
  EXPECT_TRUE(log.contains("Failed to read S-CSCF configuration data"));

  // Check that one default S-CSCF is returned
  ST({}, {}, {}, "scscf_uri").test(scscf_);
}

TEST_F(SCSCFSelectorTest, MissingParts)
{
  CapturingTestLogger log;
  SCSCFSelector scscf_("scscf_uri", string(UT_DIR).append("/test_scscf_missing_parts.json"));
  EXPECT_TRUE(log.contains("Badly formed S-CSCF entry"));

  // Check that only one S-CSCF returned (with low priority), as the others
  // couldn't be parsed.
  ST({123, 432}, {123, 432}, {}, "cw-scscf1.cw-ngv.com").test(scscf_);
}

TEST_F(SCSCFSelectorTest, MissingBlock)
{
  CapturingTestLogger log;
  SCSCFSelector scscf_("scscf_uri", string(UT_DIR).append("/test_scscf_missing_block.json"));
  EXPECT_TRUE(log.contains("Badly formed S-CSCF configuration file - missing s-cscfs object"));

  // Check that one default S-CSCF is returned
  ST({}, {}, {}, "scscf_uri").test(scscf_);
}

TEST_F(SCSCFSelectorTest, MissingFile)
{
  CapturingTestLogger log;
  SCSCFSelector scscf_("scscf_uri", string(UT_DIR).append("/NONEXISTENT_FILE.json"));
  EXPECT_TRUE(log.contains("No S-CSCF configuration data"));

  // Check that one default S-CSCF is returned
  ST({}, {}, {}, "scscf_uri").test(scscf_);
}
