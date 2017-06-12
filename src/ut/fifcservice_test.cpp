/**
 * @file fifcservice_test.cpp Tests support of fallback iFCs.
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
#include "fifcservice.h"
#include "ifc_parsing_utils.h"
#include "mockalarm.h"

using ::testing::UnorderedElementsAreArray;
using ::testing::AtLeast;

using namespace std;

///Fixture for FIFCServiceTest.
class FIFCServiceTest : public ::testing::Test
{
  FIFCServiceTest()
  {
    _am = new AlarmManager();
    _mock_alarm = new MockAlarm(_am);
  }

  virtual ~FIFCServiceTest()
  {
    delete _am; _am = NULL;
  }

  AlarmManager* _am;
  MockAlarm* _mock_alarm;
};

void get_ifc_properties(std::vector<Ifc>& fifc_list,
                        std::vector<std::string> *server_names,
                        std::vector<int32_t> *priorities)
{
  for (Ifc ifc : fifc_list)
  {
    server_names->push_back(get_server_name(ifc));
    priorities->push_back(get_priority(ifc));
  }
}

// Test a valid fallback iFC configuration file is parsed correctly.
TEST_F(FIFCServiceTest, ValidFIFCFile)
{
  // Load a configuration file containing two iFCs.
  EXPECT_CALL(*_mock_alarm, clear()).Times(AtLeast(1));
  FIFCService fifc(_mock_alarm, string(UT_DIR).append("/test_fifc.xml"));

  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;
  std::vector<Ifc> fifc_list = fifc.get_fallback_ifcs(root);
  EXPECT_EQ(fifc_list.size(), 2);

  std::vector<std::string> server_names;
  std::vector<int32_t> priorities;
  get_ifc_properties(fifc_list, &server_names, &priorities);

  std::vector<std::string> expected_server_names;
  expected_server_names.push_back("example.com");
  expected_server_names.push_back("example_two.com");
  EXPECT_THAT(expected_server_names, UnorderedElementsAreArray(server_names));

  std::vector<int32_t> expected_priorities = {1, 2};
  EXPECT_THAT(expected_priorities, UnorderedElementsAreArray(priorities));
  delete root; root = NULL;
}

// Test that reloading a fallback iFC file with an invalid file doesn't cause the
// valid entries to be lost.
TEST_F(FIFCServiceTest, ReloadInvalidFIFCFile)
{
  // Load a configuration file containing two iFCs.
  EXPECT_CALL(*_mock_alarm, clear()).Times(AtLeast(1));
  FIFCService fifc(_mock_alarm, string(UT_DIR).append("/test_fifc.xml"));

  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;
  std::vector<Ifc> fifc_list = fifc.get_fallback_ifcs(root);
  EXPECT_EQ(fifc_list.size(), 2);

  // Change the file the fifc service is using to an invalid file (to mimic the
  // file being changed), then reload the file, and recheck the parsed list.
  // Nothing should have changed and this should cause no memory issues.
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  fifc._configuration = string(UT_DIR).append("/test_fifc_invalid.xml");
  fifc.update_fifcs();
  rapidxml::xml_document<>* root_reload = new rapidxml::xml_document<>;
  fifc_list = fifc.get_fallback_ifcs(root_reload);
  EXPECT_EQ(fifc_list.size(), 2);

  std::vector<std::string> server_names;
  std::vector<int32_t> priorities;
  get_ifc_properties(fifc_list, &server_names, &priorities);

  std::vector<std::string> expected_server_names;
  expected_server_names.push_back("example.com");
  expected_server_names.push_back("example_two.com");
  EXPECT_THAT(expected_server_names, UnorderedElementsAreArray(server_names));

  std::vector<int32_t> expected_priorities = {1, 2};
  EXPECT_THAT(expected_priorities, UnorderedElementsAreArray(priorities));
  delete root; root = NULL;
  delete root_reload; root_reload = NULL;
}

// Test that reloading a fallback iFC file with valid file doesn't destroy any
// references to the old values.
TEST_F(FIFCServiceTest, ReloadChangedFIFCFile)
{
  // Load a configuration file containing two iFCs.
  EXPECT_CALL(*_mock_alarm, clear()).Times(AtLeast(1));
  FIFCService fifc(_mock_alarm, string(UT_DIR).append("/test_fifc.xml"));

  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;
  std::vector<Ifc> fifc_list = fifc.get_fallback_ifcs(root);
  EXPECT_EQ(fifc_list.size(), 2);

  // Change the file the fifc service is using (to mimic the file being
  // changed), then reload the file, and recheck the parsed list. Nothing
  // should have changed and this should cause no memory issues.
  fifc._configuration = string(UT_DIR).append("/test_fifc_changed.xml");
  EXPECT_CALL(*_mock_alarm, clear()).Times(AtLeast(1));
  fifc.update_fifcs();
  rapidxml::xml_document<>* root_reload = new rapidxml::xml_document<>;
  std::vector<Ifc> fifc_list_reload = fifc.get_fallback_ifcs(root_reload);
  EXPECT_EQ(fifc_list.size(), 2);

  std::string server_name = get_server_name(fifc_list[0]);
  EXPECT_EQ(server_name, "example.com");
  std::string server_name_reload = get_server_name(fifc_list_reload[0]);
  EXPECT_EQ(server_name_reload, "example_two.com");
  delete root; root = NULL;
  delete root_reload; root_reload = NULL;
}

// In the following tests we have various invalid/unexpected fallback iFC xml
// files.
// These tests check that the correct logs are made in each case; this isn't
// ideal as it means the tests are quite fragile, but it's the best we can do.
// They also check that the internal fallback iFC map is empty; again this isn't
// ideal as it's not using a public interface, but it's the only way to be sure
// that no entries made it into the map.

// Test that we log appropriately if the DiFC config file is mising.
TEST_F(FIFCServiceTest, MissingFile)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  FIFCService fifc(_mock_alarm, string(UT_DIR).append("/non_existent_file.xml"));
  EXPECT_TRUE(log.contains("No fallback IFC configuration found"));
  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;
  EXPECT_TRUE(fifc.get_fallback_ifcs(root).empty());
  delete root; root = NULL;
}

// Test that we log appropriately if the DiFC config file is empty.
TEST_F(FIFCServiceTest, EmptyFile)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  FIFCService fifc(_mock_alarm, string(UT_DIR).append("/test_fifc_empty_file.xml"));
  EXPECT_TRUE(log.contains("Failed to read fallback IFC configuration data"));
  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;
  EXPECT_TRUE(fifc.get_fallback_ifcs(root).empty());
  delete root; root = NULL;
}

// Test that we log appropriately if the DiFC config file is unparseable.
TEST_F(FIFCServiceTest, ParseError)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  FIFCService fifc(_mock_alarm, string(UT_DIR).append("/test_fifc_invalid.xml"));
  EXPECT_TRUE(log.contains("Failed to parse the fallback IFC configuration data"));
  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;
  EXPECT_TRUE(fifc.get_fallback_ifcs(root).empty());
  delete root; root = NULL;
}

// Test that we log appropriately if the DiFC config file has the wrong syntax.
TEST_F(FIFCServiceTest, IncorrectSyntax)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  FIFCService fifc(_mock_alarm, string(UT_DIR).append("/test_fifc_missing_node.xml"));
  EXPECT_TRUE(log.contains("Failed to parse the fallback IFC configuration file as it is invalid (missing FallbackIFCsSet block)"));
  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;
  EXPECT_TRUE(fifc.get_fallback_ifcs(root).empty());
  delete root; root = NULL;
}

// Test that we cope with the case that the fallback iFC file is valid but empty.
// (Use case - customer wishes to remove their fallback iFCs.)
TEST_F(FIFCServiceTest, EmptyValidFile)
{
  CapturingTestLogger log;
  EXPECT_CALL(*_mock_alarm, clear()).Times(AtLeast(1));
  FIFCService fifc(_mock_alarm, string(UT_DIR).append("/test_fifc_empty_valid.xml"));
  EXPECT_FALSE(log.contains("Failed"));
  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;
  EXPECT_TRUE(fifc.get_fallback_ifcs(root).empty());
  delete root; root = NULL;
}

// In the following test there is a fallback iFC xml file that has an invalid
// individual iFC, but the file as a whole is parsable. This test checks
// that the correct logs are made in this case; this isn't ideal as it
// means the test is quite fragile, but it's the best we can do. It also checks
// that the invalid iFC isn't added to the map (but we can use the public
// interface for this check).

// Test that the fallback iFC file is parsed correctly even if one of the iFCs
// within it is invalid (the other correct iFCs should be parsed).
TEST_F(FIFCServiceTest, SingleInvalidIfc)
{
  CapturingTestLogger log;

  // Load a configuration file which contains one valid, and one invalid, iFC.
  EXPECT_CALL(*_mock_alarm, set()).Times(AtLeast(1));
  FIFCService fifc(_mock_alarm, string(UT_DIR).append("/test_fifc_one_invalid.xml"));

  EXPECT_TRUE(log.contains("Failed to parse one fallback IFC"));

  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;
  std::vector<Ifc> fifc_list = fifc.get_fallback_ifcs(root);
  EXPECT_EQ(fifc_list.size(), 1);

  std::string server_name = get_server_name(fifc_list[0]);
  int32_t priority = get_priority(fifc_list[0]);
  EXPECT_EQ(server_name, "example_two.com");
  EXPECT_EQ(priority, 2);
  delete root; root = NULL;
}
