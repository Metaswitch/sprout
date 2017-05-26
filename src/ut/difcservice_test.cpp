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
#include "ifc_parsing_utils.h"
#include "mockalarm.h"

using ::testing::UnorderedElementsAreArray;
using ::testing::AtLeast;

using namespace std;

///Fixture for DIFCServiceTest.
class DIFCServiceTest : public ::testing::Test
{
  DIFCServiceTest()
  {
    _am = new AlarmManager();
    _mock_alarm = new MockAlarm(_am);
  }

  virtual ~DIFCServiceTest()
  {
    delete _am; _am = NULL;
  }

  AlarmManager* _am;
  MockAlarm* _mock_alarm;
};

void get_ifc_properties(std::vector<Ifc>& difc_list,
                        std::vector<std::string> *server_names,
                        std::vector<int32_t> *priorities)
{
  for (Ifc ifc : difc_list)
  {
    server_names->push_back(get_server_name(ifc));
    priorities->push_back(get_priority(ifc));
  }
}

// Test a valid Default iFC configuration file is parsed correctly.
TEST_F(DIFCServiceTest, ValidDIFCFile)
{
  // Load a configuration file containing two iFCs.
  EXPECT_CALL(*_mock_alarm, clear()).Times(AtLeast(1));
  DIFCService difc(_mock_alarm, string(UT_DIR).append("/test_difc.xml"));

  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;
  std::vector<Ifc> difc_list = difc.get_default_ifcs(root);
  EXPECT_EQ(difc_list.size(), 2);

  std::vector<std::string> server_names;
  std::vector<int32_t> priorities;
  get_ifc_properties(difc_list, &server_names, &priorities);

  std::vector<std::string> expected_server_names;
  expected_server_names.push_back("example.com");
  expected_server_names.push_back("example_two.com");
  EXPECT_THAT(expected_server_names, UnorderedElementsAreArray(server_names));

  std::vector<int32_t> expected_priorities = {1, 2};
  EXPECT_THAT(expected_priorities, UnorderedElementsAreArray(priorities));
  delete root; root = NULL;
}

// Test that reloading a Default iFC file with an invalid file doesn't cause the
// valid entries to be lost.
TEST_F(DIFCServiceTest, ReloadInvalidDIFCFile)
{
  // Load a configuration file containing two iFCs.
  EXPECT_CALL(*_mock_alarm, clear()).Times(AtLeast(1));
  DIFCService difc(_mock_alarm, string(UT_DIR).append("/test_difc.xml"));

  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;
  std::vector<Ifc> difc_list = difc.get_default_ifcs(root);
  EXPECT_EQ(difc_list.size(), 2);

  // Change the file the difc service is using to an invalid file (to mimic the
  // file being changed), then reload the file, and recheck the parsed list.
  // Nothing should have changed and this should cause no memory issues.
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  difc._configuration = string(UT_DIR).append("/test_difc_invalid.xml");
  difc.update_difcs();
  rapidxml::xml_document<>* root_reload = new rapidxml::xml_document<>;
  difc_list = difc.get_default_ifcs(root_reload);
  EXPECT_EQ(difc_list.size(), 2);

  std::vector<std::string> server_names;
  std::vector<int32_t> priorities;
  get_ifc_properties(difc_list, &server_names, &priorities);

  std::vector<std::string> expected_server_names;
  expected_server_names.push_back("example.com");
  expected_server_names.push_back("example_two.com");
  EXPECT_THAT(expected_server_names, UnorderedElementsAreArray(server_names));

  std::vector<int32_t> expected_priorities = {1, 2};
  EXPECT_THAT(expected_priorities, UnorderedElementsAreArray(priorities));
  delete root; root = NULL;
  delete root_reload; root_reload = NULL;
}

// Test that reloading a Default iFC file with valid file doesn't destroy any
// references to the old values.
TEST_F(DIFCServiceTest, ReloadChangedDIFCFile)
{
  // Load a configuration file containing two iFCs.
  EXPECT_CALL(*_mock_alarm, clear()).Times(AtLeast(1));
  DIFCService difc(_mock_alarm, string(UT_DIR).append("/test_difc.xml"));

  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;
  std::vector<Ifc> difc_list = difc.get_default_ifcs(root);
  EXPECT_EQ(difc_list.size(), 2);

  // Change the file the difc service is using (to mimic the file being
  // changed), then reload the file, and recheck the parsed list. Nothing
  // should have changed and this should cause no memory issues.
  difc._configuration = string(UT_DIR).append("/test_difc_changed.xml");
  EXPECT_CALL(*_mock_alarm, clear()).Times(AtLeast(1));
  difc.update_difcs();
  rapidxml::xml_document<>* root_reload = new rapidxml::xml_document<>;
  std::vector<Ifc> difc_list_reload = difc.get_default_ifcs(root_reload);
  EXPECT_EQ(difc_list.size(), 2);

  std::string server_name = get_server_name(difc_list[0]);
  EXPECT_EQ(server_name, "example.com");
  std::string server_name_reload = get_server_name(difc_list_reload[0]);
  EXPECT_EQ(server_name_reload, "example_two.com");
  delete root; root = NULL;
  delete root_reload; root_reload = NULL;
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
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  DIFCService difc(_mock_alarm, string(UT_DIR).append("/non_existent_file.xml"));
  EXPECT_TRUE(log.contains("No default IFC configuration found"));
  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;
  EXPECT_TRUE(difc.get_default_ifcs(root).empty());
  delete root; root = NULL;
}

// Test that we log appropriately if the DiFC config file is empty.
TEST_F(DIFCServiceTest, EmptyFile)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  DIFCService difc(_mock_alarm, string(UT_DIR).append("/test_difc_empty_file.xml"));
  EXPECT_TRUE(log.contains("Failed to read default IFC configuration data"));
  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;
  EXPECT_TRUE(difc.get_default_ifcs(root).empty());
  delete root; root = NULL;
}

// Test that we log appropriately if the DiFC config file is unparseable.
TEST_F(DIFCServiceTest, ParseError)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  DIFCService difc(_mock_alarm, string(UT_DIR).append("/test_difc_invalid.xml"));
  EXPECT_TRUE(log.contains("Failed to parse the default IFC configuration data"));
  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;
  EXPECT_TRUE(difc.get_default_ifcs(root).empty());
  delete root; root = NULL;
}

// Test that we log appropriately if the DiFC config file has the wrong syntax.
TEST_F(DIFCServiceTest, IncorrectSyntax)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  DIFCService difc(_mock_alarm, string(UT_DIR).append("/test_difc_missing_node.xml"));
  EXPECT_TRUE(log.contains("Failed to parse the default IFC configuration file as it is invalid (missing DefaultIFCsSet block)"));
  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;
  EXPECT_TRUE(difc.get_default_ifcs(root).empty());
  delete root; root = NULL;
}

// Test that we cope with the case that the Default iFC file is valid but empty.
// (Use case - customer wishes to remove their Default iFCs.)
TEST_F(DIFCServiceTest, EmptyValidFile)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, clear()).Times(AtLeast(1));
  DIFCService difc(_mock_alarm, string(UT_DIR).append("/test_difc_empty_valid.xml"));
  EXPECT_FALSE(log.contains("Failed"));
  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;
  EXPECT_TRUE(difc.get_default_ifcs(root).empty());
  delete root; root = NULL;
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
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  DIFCService difc(_mock_alarm, string(UT_DIR).append("/test_difc_one_invalid.xml"));

  EXPECT_TRUE(log.contains("Failed to parse one default IFC"));

  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;
  std::vector<Ifc> difc_list = difc.get_default_ifcs(root);
  EXPECT_EQ(difc_list.size(), 1);

  std::string server_name = get_server_name(difc_list[0]);
  int32_t priority = get_priority(difc_list[0]);
  EXPECT_EQ(server_name, "example_two.com");
  EXPECT_EQ(priority, 2);
  delete root; root = NULL;
}
