/**
 * @file scscfselector_test.cpp
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
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
#include <vector>
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "utils.h"
#include "sas.h"
#include "scscfselector.h"
#include "fakelogger.h"
#include "test_utils.hpp"

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

  // Test with two S-CSCFs with the mandatory capabilities, and one has more optional capabilites
  ST({123, 432}, {654}, {}, "cw-scscf2.cw-ngv.com").test(scscf_);
}

TEST_F(SCSCFSelectorTest, SelectPriorities)
{
  // Parse a valid file.
  SCSCFSelector scscf_("scscf_uri", string(UT_DIR).append("/test_scscf.json"));

  // Test with S-CSCFs with the same mandatory and optional capabilities, but different priorities
  ST({}, {654, 567}, {}, "cw-scscf4.cw-ngv.com").test(scscf_);
}

TEST_F(SCSCFSelectorTest, SelectWeights)
{
  // Parse a valid file.
  SCSCFSelector scscf_("scscf_uri", string(UT_DIR).append("/test_scscf.json"));

  // Test with two S-CSCFs with the same capabilities and priorites, but different weights.
  // One of the weights is 0 - this is for code coverage reasons to ensure that the first S-CSCF
  // considered is never chosen. The S-CSCFs with different weights have the same name, so that
  // the test can pick either randomly and still pass.
  ST({654}, {876}, {}, "cw-scscf6.cw-ngv.com").test(scscf_);
}

TEST_F(SCSCFSelectorTest, RejectSCSCFs)
{
  // Parse a valid file.
  SCSCFSelector scscf_("scscf_uri", string(UT_DIR).append("/test_scscf.json"));

  // Test when there's only one S-CSCF with all the mandatory capabilities, but it's on the
  // reject list
  ST({123, 432, 345}, {}, {"cw-scscf1.cw-ngv.com"}, "").test(scscf_);

  // Test with two S-CSCFs with the mandatory capabilities, and one has more optional capabilites. The
  // one with more optional capabilities is on the reject list, so the other one should be chosen.
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

  // Check that only one S-CSCF returned (with low priority), as the others couldn't
  // be parsed
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
