/**
 * @file difcservice_test.cpp Tests support of Default iFCs.
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

#include "gmock/gmock.h"
#include "fakelogger.h"

#include <string>
#include <vector>

#include "test_utils.hpp"
#include "difcservice.h"

using ::testing::UnorderedElementsAreArray;

using namespace std;

///Fixture for DIFCServiceTest.
class DIFCServiceTest : public ::testing::Test
{
  DIFCServiceTest()
  {
  }

  virtual ~DIFCServiceTest()
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
  else
  {
    return 0;
  }
}

void get_ifc_properties(std::vector<std::pair<int32_t, Ifc>> *difc_list,
                               std::vector<std::string> *server_names,
                               std::vector<int32_t> *priorities)
{
  for (std::vector<std::pair<int32_t, Ifc>>::iterator it = difc_list->begin();
       it != difc_list->end();
       ++it)
  {
    server_names->push_back(get_server_name(it->second));
    priorities->push_back(get_priority(it->second));
  }
  return;
}

// TODO - In the below tests when the parsed default iFCs are examined, the
// class variable needs to be looked at. In the future this should be changed so
// that the function that will be used in the codebase is called instead.

// Test a valid Default iFC configuration file is parsed correctly.
TEST_F(DIFCServiceTest, ValidDIFCFile)
{
  // Load a configuration file containing two iFCs.
  DIFCService difc(string(UT_DIR).append("/test_difc.xml"));

  std::vector<std::pair<int32_t, Ifc>> difc_list = difc._default_ifcs;
  EXPECT_EQ(difc_list.size(), 2);

  std::vector<std::string> server_names;
  std::vector<int32_t> priorities;
  get_ifc_properties(&difc_list, &server_names, &priorities);

  std::vector<std::string> expected_server_names;
  expected_server_names.push_back("example.com");
  expected_server_names.push_back("example_two.com");
  EXPECT_THAT(expected_server_names, UnorderedElementsAreArray(server_names));

  std::vector<int32_t> expected_priorities = {1, 2};
  EXPECT_THAT(expected_priorities, UnorderedElementsAreArray(priorities));
}

// Test that reloading the Default iFC config file works correctly.
TEST_F(DIFCServiceTest, ReloadDIFCFile)
{
  // Load a configuration file containing two iFCs.
  DIFCService difc(string(UT_DIR).append("/test_difc.xml"));

  std::vector<std::pair<int32_t, Ifc>> difc_list = difc._default_ifcs;
  EXPECT_EQ(difc_list.size(), 2);

  // Reload the file, and recheck the parsed list.
  // Nothing should have changed and this should cause no memory issues.
  difc.update_difcs();
  difc_list = difc._default_ifcs;
  EXPECT_EQ(difc_list.size(), 2);

 std::vector<std::string> server_names;
 std::vector<int32_t> priorities;
 get_ifc_properties(&difc_list, &server_names, &priorities);

 std::vector<std::string> expected_server_names;
 expected_server_names.push_back("example.com");
 expected_server_names.push_back("example_two.com");
 EXPECT_THAT(expected_server_names, UnorderedElementsAreArray(server_names));

 std::vector<int32_t> expected_priorities = {1, 2};
 EXPECT_THAT(expected_priorities, UnorderedElementsAreArray(priorities));
}

// Test that reloading a Default iFC file with an invalid file doesn't cause the
// valid entries to be lost.
TEST_F(DIFCServiceTest, ReloadInvalidDIFCFile)
{
  // Load a configuration file containing two iFCs.
  DIFCService difc(string(UT_DIR).append("/test_difc.xml"));

  std::vector<std::pair<int32_t, Ifc>> difc_list = difc._default_ifcs;
  EXPECT_EQ(difc_list.size(), 2);

  // Change the file the difc service is using to an invalid file (to mimic the
  // file being changed), then reload the file, and recheck the parsed list.
  // Nothing should have changed and this should cause no memory issues.
  difc._configuration = string(UT_DIR).append("/test_difc_invalid.xml");
  difc.update_difcs();
  difc_list = difc._default_ifcs;
  EXPECT_EQ(difc_list.size(), 2);

  std::vector<std::string> server_names;
  std::vector<int32_t> priorities;
  get_ifc_properties(&difc_list, &server_names, &priorities);

  std::vector<std::string> expected_server_names;
  expected_server_names.push_back("example.com");
  expected_server_names.push_back("example_two.com");
  EXPECT_THAT(expected_server_names, UnorderedElementsAreArray(server_names));

  std::vector<int32_t> expected_priorities = {1, 2};
  EXPECT_THAT(expected_priorities, UnorderedElementsAreArray(priorities));
}

// In the following tests we have various invalid/unexpected Default iFC xml
// files.
// These tests check that the correct logs are made in each case; this isn't
// ideal as it means the tests are quite fragile, but it's the best we can do.
// They also check that the internal Default iFC map is empty; again this isn't
// ideal as it's not using a public interface, but it's the only way to be sure
// that no entries made it into the map.

// Test that we log appropriately if the DiFC config file is mising.
TEST_F(DIFCServiceTest, MissingFile)
{
  CapturingTestLogger log;
  DIFCService difc(string(UT_DIR).append("/non_existent_file.xml"));
  EXPECT_TRUE(log.contains("No default IFC configuration found"));
  EXPECT_TRUE(difc._default_ifcs.empty());
}

// Test that we log appropriately if the DiFC config file is empty.
TEST_F(DIFCServiceTest, EmptyFile)
{
  CapturingTestLogger log;
  DIFCService difc(string(UT_DIR).append("/test_difc_empty_file.xml"));
  EXPECT_TRUE(log.contains("Failed to read default IFC configuration data"));
  EXPECT_TRUE(difc._default_ifcs.empty());
}

// Test that we log appropriately if the DiFC config file is unparseable.
TEST_F(DIFCServiceTest, ParseError)
{
  CapturingTestLogger log;
  DIFCService difc(string(UT_DIR).append("/test_difc_invalid.xml"));
  EXPECT_TRUE(log.contains("Failed to parse the default IFC configuration data"));
  EXPECT_TRUE(difc._default_ifcs.empty());
}

// Test that we log appropriately if the DiFC config file has the wrong syntax.
TEST_F(DIFCServiceTest, IncorrectSyntax)
{
  CapturingTestLogger log;
  DIFCService difc(string(UT_DIR).append("/test_difc_missing_node.xml"));
  EXPECT_TRUE(log.contains("Failed to parse the default IFC configuration file as it is invalid (missing DefaultIfcSet block)"));
  EXPECT_TRUE(difc._default_ifcs.empty());
}

// Test that we cope with the case that the Default iFC file is valid but empty.
// (Use case - customer wishes to remove their Default iFCs.)
TEST_F(DIFCServiceTest, EmptyValidFile)
{
  CapturingTestLogger log;
  DIFCService difc(string(UT_DIR).append("/test_difc_valid_empty.xml"));
  EXPECT_FALSE(log.contains("Failed"));
  EXPECT_TRUE(difc._default_ifcs.empty());
}

// In the following test there is a Default iFC xml file that has an invalid
// individual iFC, but the file as a whole is parsable. This test checks
// that the correct logs are made in this case; this isn't ideal as it
// means the test is quite fragile, but it's the best we can do. It also checks
// that the invalid iFC isn't added to the map (but we can use the public
// interface for this check).

// Test that the Default iFC file is parsed correctly even if one of the iFCs
// within it is invalid (the other correct iFCs should be parsed).
TEST_F(DIFCServiceTest, SingleInvalidIfc)
{
  CapturingTestLogger log;

  // Load a configuration file which contains one valid, and one invalid, iFC.
  DIFCService difc(string(UT_DIR).append("/test_difc_one_invalid.xml"));

  EXPECT_TRUE(log.contains("Failed to parse one default IFC"));

 std::vector<std::pair<int32_t, Ifc>> difc_list = difc._default_ifcs;
 EXPECT_EQ(difc_list.size(), 1);

 std::string server_name = get_server_name(difc_list.begin()->second);
 int32_t priority = get_priority(difc_list.begin()->second);
 EXPECT_EQ(server_name, "example_two.com");
 EXPECT_EQ(priority, 2);
}


