/**
 * @file sifcservice_test.cpp
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2017  Metaswitch Networks Ltd
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
#include "sifcservice.h"
#include "fakelogger.h"
#include "test_utils.hpp"

using ::testing::UnorderedElementsAreArray;

using namespace std;

/// Fixture for SIFCServiceTest.
class SIFCServiceTest : public ::testing::Test
{
  SIFCServiceTest()
  {
  }

  virtual ~SIFCServiceTest()
  {
  }
};

std::string get_server_name(Ifc ifc)
{
  return std::string(ifc._ifc->first_node("ApplicationServer")->
                                             first_node("ServerName")->value());
}

int32_t get_priority(Ifc ifc)
{
  if (ifc._ifc->first_node("Priority"))
  {
    return std::atoi(ifc._ifc->first_node("Priority")->value());
  }

  return 0;
}

// Test a valid shared IFC file is parsed correctly
TEST_F(SIFCServiceTest, ValidSIFCFile)
{
  SIFCService sifc(string(UT_DIR).append("/test_sifc.xml"));

  // Pull out a single IFC (the test file is set up to only return a single
  // IFC for ID 2).
  std::set<int> single_ifc; single_ifc.insert(2);
  std::multimap<int32_t, Ifc> single_ifc_map;
  sifc.get_ifcs_from_id(single_ifc_map, single_ifc, 0);
  EXPECT_EQ(single_ifc_map.size(), 1);
  EXPECT_EQ(get_server_name(single_ifc_map.find(0)->second), "publish.example.com");

  // Pull out multiple IFCs (the test file is set up to return two IFCs for
  // ID 1)
  std::set<int> multiple_ifcs; multiple_ifcs.insert(1);
  std::multimap<int32_t, Ifc> multiple_ifc_map;
  sifc.get_ifcs_from_id(multiple_ifc_map, multiple_ifcs, 0);
  EXPECT_EQ(multiple_ifc_map.size(), 2);
  std::vector<std::string> expected_server_names;
  expected_server_names.push_back("invite.example.com");
  expected_server_names.push_back("register.example.com");
  std::vector<std::string> server_names_single_id;
  for (std::multimap<int32_t, Ifc>::iterator it = multiple_ifc_map.begin();
       it != multiple_ifc_map.end();
       ++it)
  {
    server_names_single_id.push_back(get_server_name(it->second));
  }
  EXPECT_THAT(expected_server_names, UnorderedElementsAreArray(server_names_single_id));

  // Pull out multiple IFCs from multiple IDs
  std::set<int> multiple_ids; multiple_ids.insert(1); multiple_ids.insert(2);
  std::multimap<int32_t, Ifc> multiple_ids_map;
  sifc.get_ifcs_from_id(multiple_ids_map, multiple_ids, 0);
  EXPECT_EQ(multiple_ids_map.size(), 3);
  expected_server_names.push_back("publish.example.com");
  std::vector<std::string> server_names_multiple_ids;
  for (std::multimap<int32_t, Ifc>::iterator it = multiple_ids_map.begin();
       it != multiple_ids_map.end();
       ++it)
  {
    server_names_multiple_ids.push_back(get_server_name(it->second));
  }
  EXPECT_THAT(expected_server_names, UnorderedElementsAreArray(server_names_multiple_ids));

  // Attempt to get the IFCs for an ID that doesn't exist in the test file -
  // check that this doesn't return any IFCs.
  std::set<int> missing_ids; missing_ids.insert(100);
  std::multimap<int32_t, Ifc> missing_ids_map;
  sifc.get_ifcs_from_id(missing_ids_map, missing_ids, 0);
  EXPECT_EQ(missing_ids_map.size(), 0);
}

// Test that reloading a shared IFC file works correctly
TEST_F(SIFCServiceTest, SIFCReload)
{
  SIFCService sifc(string(UT_DIR).append("/test_sifc.xml"));

  // Load the IFC file, and check that it's been parsed correctly
  std::set<int> id; id.insert(2);
  std::multimap<int32_t, Ifc> ifc_map;
  sifc.get_ifcs_from_id(ifc_map, id, 0);
  EXPECT_EQ(ifc_map.size(), 1);
  EXPECT_EQ(get_server_name(ifc_map.find(0)->second), "publish.example.com");

  // Reload the file, then repeat the check. Nothing should have changed,
  // and there should be no memory issues
  std::multimap<int32_t, Ifc> ifc_map_reload;
  sifc.get_ifcs_from_id(ifc_map_reload, id, 0);
  EXPECT_EQ(ifc_map_reload.size(), 1);
  EXPECT_EQ(get_server_name(ifc_map_reload.find(0)->second), "publish.example.com");
}

// Test that the priorities are parsed correctly
TEST_F(SIFCServiceTest, SIFCPriorities)
{
  // The test file 3 IFCs under ID 1. One IFC doesn't have the priority set,
  // one has it set to 200, and one has an invalid value.
  CapturingTestLogger log;
  SIFCService sifc(string(UT_DIR).append("/test_sifc_priorities.xml"));
  EXPECT_TRUE(log.contains("Invalid shared IFC set block - Priority (NaN) isn't an int. Skipping this entry"));

  // Get the IFCs for ID. There should be two (as one was invalid)
  std::set<int> id; id.insert(1);
  std::multimap<int32_t, Ifc> ifc_map;
  sifc.get_ifcs_from_id(ifc_map, id, 0);
  EXPECT_EQ(ifc_map.size(), 2);
  EXPECT_EQ(get_server_name(ifc_map.find(0)->second), "invite.example.com");
  EXPECT_EQ(get_server_name(ifc_map.find(200)->second), "register.example.com");
}

// In the following tests we have various invalid/unexpected SIFC xml files.
// These tests check that the correct logs are made in each case; this isn't
// ideal as it means the tests are quite fragile, but it's the best we can do.
// They also check that the internal shared IFC map is empty; again this isn't
// ideal/ as its not using a public interface, but it's the only way to be sure
// that no entries made it into the map.

// Test that we log appropriately if the shared IFC file is missing
TEST_F(SIFCServiceTest, MissingFile)
{
  CapturingTestLogger log;
  SIFCService sifc(string(UT_DIR).append("/non_existent_file.xml"));
  EXPECT_TRUE(log.contains("No shared IFC sets configuration"));
  EXPECT_TRUE(sifc._shared_ifc_sets.empty());
}

// Test that we log appropriately if the shared IFC file is empty.
TEST_F(SIFCServiceTest, EmptyFile)
{
  CapturingTestLogger log;
  SIFCService sifc(string(UT_DIR).append("/test_sifc_empty_file.xml"));
  EXPECT_TRUE(log.contains("Failed to read shared IFC set configuration"));
  EXPECT_TRUE(sifc._shared_ifc_sets.empty());
}

// Test that we log appropriately if the shared IFC file is unparseable.
TEST_F(SIFCServiceTest, ParseError)
{
  CapturingTestLogger log;
  SIFCService sifc(string(UT_DIR).append("/test_sifc_parse_error.xml"));
  EXPECT_TRUE(log.contains("Failed to parse the shared IFC set configuration data"));
  EXPECT_TRUE(sifc._shared_ifc_sets.empty());
}

// Test that we log appropriately if the shared IFC file has the wrong syntax.
TEST_F(SIFCServiceTest, MissingSetBlock)
{
  CapturingTestLogger log;
  SIFCService sifc(string(UT_DIR).append("/test_sifc_missing_set.xml"));
  EXPECT_TRUE(log.contains("Invalid shared IFC set configuration file - missing Sets block"));
  EXPECT_TRUE(sifc._shared_ifc_sets.empty());
}

// Test that we cope with the case that the shared IFC file is valid but empty
TEST_F(SIFCServiceTest, NoEntries)
{
  CapturingTestLogger log;
  SIFCService sifc(string(UT_DIR).append("/test_sifc_no_entries.xml"));
  EXPECT_FALSE(log.contains("Failed"));
  EXPECT_TRUE(sifc._shared_ifc_sets.empty());
}

// In the following tests we have various SIFC xml files that have invalid
// individual entries, but the file as a whole is parsable. These tests check
// that the correct logs are made in each case; this isn't ideal as it means
// the tests are quite fragile, but it's the best we can do. They also check
// that the invalid entries aren't added to the map (but we can use the public
// interface for this check).

// Test that if an entry is missing a Set ID we log and move on.
TEST_F(SIFCServiceTest, MissingSetID)
{
  CapturingTestLogger log;
  SIFCService sifc(string(UT_DIR).append("/test_sifc_missing_set_id.xml"));
  EXPECT_TRUE(log.contains("Invalid shared IFC set block - missing SetId. Skipping this entry"));

  // The test file has an invalid entry, and an entry for ID 2. Check that this
  // was added to the map.
  std::set<int> single_ifc; single_ifc.insert(2);
  std::multimap<int32_t, Ifc> single_ifc_map;
  sifc.get_ifcs_from_id(single_ifc_map, single_ifc, 0);
  EXPECT_EQ(single_ifc_map.size(), 1);
  EXPECT_EQ(get_server_name(single_ifc_map.find(0)->second), "register.example.com");
}

// Test that if an entry has an invalid Set ID we log and move on.
TEST_F(SIFCServiceTest, InvalidSetID)
{
  CapturingTestLogger log;
  SIFCService sifc(string(UT_DIR).append("/test_sifc_invalid_set_id.xml"));
  EXPECT_TRUE(log.contains("Invalid shared IFC set block - SetId (NaN) isn't an int. Skipping this entry"));

  // The test file has an invalid entry, and an entry for ID 2. Check that this
  // was added to the map.
  std::set<int> single_ifc; single_ifc.insert(2);
  std::multimap<int32_t, Ifc> single_ifc_map;
  sifc.get_ifcs_from_id(single_ifc_map, single_ifc, 0);
  EXPECT_EQ(single_ifc_map.size(), 1);
  EXPECT_EQ(get_server_name(single_ifc_map.find(0)->second), "register.example.com");
}

// Test that if an entry has a Set ID that's already been used we log and move
// on. It doesn't override the existing value.
TEST_F(SIFCServiceTest, RepeatedSetID)
{
  CapturingTestLogger log;
  SIFCService sifc(string(UT_DIR).append("/test_sifc_repeated_id.xml"));
  EXPECT_TRUE(log.contains("Invalid shared IFC set block - SetId (1) is repeated. Skipping this entry"));

  // The test file has two entries for ID 1 (with different server names).
  // Check that the map entry has the correct server name.
  std::set<int> single_ifc; single_ifc.insert(1);
  std::multimap<int32_t, Ifc> single_ifc_map;
  sifc.get_ifcs_from_id(single_ifc_map, single_ifc, 0);
  EXPECT_EQ(single_ifc_map.size(), 1);
  EXPECT_EQ(get_server_name(single_ifc_map.find(0)->second), "publish.example.com");
}
