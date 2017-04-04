/**
 * @file hssconnection_test.cpp UT for Sprout HSS connection.
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

///
///----------------------------------------------------------------------------

#include <string>
#include <algorithm>
#include "gtest/gtest.h"

#include "utils.h"
#include "sas.h"
#include "fakehttpresolver.hpp"
#include "hssconnection.h"
#include "basetest.hpp"
#include "fakecurl.hpp"
#include "fakesnmp.hpp"
#include "sprout_alarmdefinition.h"
#include "mock_sifc_parser.h"

using namespace std;
using testing::SetArgReferee;
using testing::_;
using testing::UnorderedElementsAreArray;

/// Fixture for HssConnectionTest.
class HssConnectionTest : public BaseTest
{
  FakeHttpResolver _resolver;
  AlarmManager _am;
  CommunicationMonitor _cm;
  HSSConnection _hss;

  HssConnectionTest() :
    _resolver("10.42.42.42"),
    _cm(new Alarm(&_am, "sprout", AlarmDef::SPROUT_HOMESTEAD_COMM_ERROR, AlarmDef::CRITICAL), "sprout", "homestead"),
    _hss("narcissus",
         &_resolver,
         NULL,
         &SNMP::FAKE_IP_COUNT_TABLE,
         &SNMP::FAKE_EVENT_ACCUMULATOR_TABLE,
         &SNMP::FAKE_EVENT_ACCUMULATOR_TABLE,
         &SNMP::FAKE_EVENT_ACCUMULATOR_TABLE,
         &SNMP::FAKE_EVENT_ACCUMULATOR_TABLE,
         &SNMP::FAKE_EVENT_ACCUMULATOR_TABLE,
         &_cm,
         "server_name",
         NULL)
    {
    fakecurl_responses.clear();
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/pubid42/reg-data", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<ClearwaterRegData>"
        "<RegistrationState>REGISTERED</RegistrationState>"
        "<IMSSubscription>"
          "<ServiceProfile>"
            "<PublicIdentity>"
              "<Identity>sip:123@example.com</Identity>"
            "</PublicIdentity>"
            "<PublicIdentity>"
              "<Identity>sip:456@example.com</Identity>"
            "</PublicIdentity>"
            "<InitialFilterCriteria>"
              "<TriggerPoint>"
                "<ConditionTypeCNF>0</ConditionTypeCNF>"
                "<SPT>"
                  "<ConditionNegated>0</ConditionNegated>"
                  "<Group>0</Group>"
                  "<Method>INVITE</Method>"
                  "<Extension></Extension>"
                "</SPT>"
              "</TriggerPoint>"
              "<ApplicationServer>"
                "<ServerName>mmtel.narcissi.example.com</ServerName>"
                "<DefaultHandling>0</DefaultHandling>"
              "</ApplicationServer>"
            "</InitialFilterCriteria>"
          "</ServiceProfile>"
        "</IMSSubscription>"
        "<ChargingAddresses>"
          "<CCF priority=\"1\">ccf1</CCF>"
          "<CCF priority=\"2\">ccf2</CCF>"
          "<ECF priority=\"2\">ecf2</ECF>"
          "<ECF priority=\"1\">ecf1</ECF>"
        "</ChargingAddresses>"
      "</ClearwaterRegData>";
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/pubid43/reg-data", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<ClearwaterRegData>"
        "<RegistrationState>NOT_REGISTERED</RegistrationState>"
      "</ClearwaterRegData>";
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/pubid42/reg-data", "")] = fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/pubid42/reg-data", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")];
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/pubid43/reg-data", "")] = fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/pubid43/reg-data", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")];

    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/pubid42_malformed/reg-data", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
              "<Grou";
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/pubid43_malformed/reg-data", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<ClearwaterRegData>"
        "<RegistrationState>REGISTERED</RegistrationState>"
        "<NonsenseWord>"
          "<ServiceProfile>"
            "<PublicIdentity>"
              "<Identity>sip:123@example.com</Identity>"
            "</PublicIdentity>"
            "<PublicIdentity>"
              "<Identity>sip:456@example.com</Identity>"
            "</PublicIdentity>"
            "<InitialFilterCriteria>"
              "<TriggerPoint>"
                "<ConditionTypeCNF>0</ConditionTypeCNF>"
                "<SPT>"
                  "<ConditionNegated>0</ConditionNegated>"
                  "<Group>0</Group>"
                  "<Method>INVITE</Method>"
                  "<Extension></Extension>"
                "</SPT>"
              "</TriggerPoint>"
              "<ApplicationServer>"
                "<ServerName>mmtel.narcissi.example.com</ServerName>"
                "<DefaultHandling>0</DefaultHandling>"
              "</ApplicationServer>"
            "</InitialFilterCriteria>"
          "</ServiceProfile>"
        "</NonsenseWord>"
      "</ClearwaterRegData>";
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/pubid44/reg-data", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")] = CURLE_REMOTE_FILE_NOT_FOUND;
    fakecurl_responses["http://10.42.42.42:80/impi/privid69/registration-status?impu=pubid44"] = "{\"result-code\": 2001, \"scscf\": \"server-name\"}";
    fakecurl_responses["http://10.42.42.42:80/impi/privid69/registration-status?impu=pubid44&visited-network=domain&auth-type=REG"] = "{\"result-code\": 2001, \"mandatory-capabilities\": [1, 2, 3], \"optional-capabilities\": []}";
    fakecurl_responses["http://10.42.42.42:80/impi/privid_corrupt/registration-status?impu=pubid44"] = "{\"result-code\": 2001, \"scscf\"; \"server-name\"}";
    fakecurl_responses["http://10.42.42.42:80/impu/pubid44/location"] = "{\"result-code\": 2001, \"scscf\": \"server-name\"}";
    fakecurl_responses["http://10.42.42.42:80/impu/pubid44/location?auth-type=DEREG"] = "{\"result-code\": 2001, \"mandatory-capabilities\": [], \"optional-capabilities\": []}";
    fakecurl_responses["http://10.42.42.42:80/impu/pubid44/location?originating=true&auth-type=CAPAB"] = "{\"result-code\": 2001, \"mandatory-capabilities\": [1, 2, 3], \"optional-capabilities\": []}";
    fakecurl_responses["http://10.42.42.42:80/impu/pubid45/location"] = CURLE_REMOTE_FILE_NOT_FOUND;
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/pubid50/reg-data", "{\"reqtype\": \"call\", \"server_name\": \"server_name\"}")] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<ClearwaterRegData>"
        "<RegistrationState>UNREGISTERED</RegistrationState>"
        "<IMSSubscription>"
        "</IMSSubscription>"
      "</ClearwaterRegData>";
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/pubid50/reg-data", "{\"reqtype\": \"dereg-admin\", \"server_name\": \"server_name\"}")] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<ClearwaterRegData>"
        "<RegistrationState>NOT_REGISTERED</RegistrationState>"
        "<IMSSubscription>"
        "</IMSSubscription>"
      "</ClearwaterRegData>";
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/missingelement1/reg-data", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<ClearwaterRegData>"
        "<IMSSubscription>"
        "</IMSSubscription>"
      "</ClearwaterRegData>";
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/missingelement2/reg-data", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<ClearwaterRegData>"
        "<RegistrationState>NOT_REGISTERED</RegistrationState>"
      "</ClearwaterRegData>";
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/missingelement3/reg-data", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<C>"
        "<RegistrationState>NOT_REGISTERED</RegistrationState>"
        "<IMSSubscription>"
        "</IMSSubscription>"
      "</C>";
   fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/missingelement4/reg-data", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<ClearwaterRegData>"
        "<RegistrationState>REGISTERED</RegistrationState>"
        "<IMSSubscription xsi=\"http://www.w3.org/2001/XMLSchema-instance\" noNamespaceSchemaLocation=\"CxDataType.xsd\">"
                "<PrivateID>Unspecified</PrivateID>"
        "</IMSSubscription>"
      "</ClearwaterRegData>";
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/missingelement5/reg-data", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<ClearwaterRegData>"
        "<RegistrationState>REGISTERED</RegistrationState>"
        "<IMSSubscription xsi=\"http://www.w3.org/2001/XMLSchema-instance\" noNamespaceSchemaLocation=\"CxDataType.xsd\">"
          "<PrivateID>Unspecified</PrivateID>"
          "<ServiceProfile>"
         "</ServiceProfile>"
        "</IMSSubscription>"
      "</ClearwaterRegData>";
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/missingelement6/reg-data", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<ClearwaterRegData>"
        "<RegistrationState>REGISTERED</RegistrationState>"
        "<IMSSubscription xsi=\"http://www.w3.org/2001/XMLSchema-instance\" noNamespaceSchemaLocation=\"CxDataType.xsd\">"
          "<PrivateID>Unspecified</PrivateID>"
          "<ServiceProfile>"
            "<PublicIdentity>"
            "</PublicIdentity>"
         "</ServiceProfile>"
        "</IMSSubscription>"
      "</ClearwaterRegData>";
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/pubid46/reg-data", "{\"reqtype\": \"call\", \"server_name\": \"server_name\"}")] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<ClearwaterRegData>"
        "<RegistrationState>REGISTERED</RegistrationState>"
        "<IMSSubscription>"
          "<ServiceProfile>"
            "<PublicIdentity>"
              "<Identity>sip:123@example.com</Identity>"
            "</PublicIdentity>"
            "<PublicIdentity>"
              "<Identity>sip:456@example.com</Identity>"
            "</PublicIdentity>"
            "<InitialFilterCriteria>"
              "<TriggerPoint>"
                "<ConditionTypeCNF>0</ConditionTypeCNF>"
                "<SPT>"
                  "<ConditionNegated>0</ConditionNegated>"
                  "<Group>0</Group>"
                  "<Method>INVITE</Method>"
                  "<Extension></Extension>"
                "</SPT>"
              "</TriggerPoint>"
              "<ApplicationServer>"
                "<ServerName>mmtel.narcissi.example.com</ServerName>"
                "<DefaultHandling>0</DefaultHandling>"
              "</ApplicationServer>"
            "</InitialFilterCriteria>"
          "</ServiceProfile>"
          "<ServiceProfile>"
            "<PublicIdentity>"
              "<Identity>sip:321@example.com</Identity>"
            "</PublicIdentity>"
            "<PublicIdentity>"
              "<Identity>pubid46</Identity>"
            "</PublicIdentity>"
            "<PublicIdentity>"
              "<Identity>tel:321</Identity>"
            "</PublicIdentity>"
            "<InitialFilterCriteria>"
              "<TriggerPoint>"
                "<ConditionTypeCNF>0</ConditionTypeCNF>"
                "<SPT>"
                  "<ConditionNegated>0</ConditionNegated>"
                  "<Group>0</Group>"
                  "<Method>INVITE</Method>"
                  "<Extension></Extension>"
                "</SPT>"
              "</TriggerPoint>"
              "<ApplicationServer>"
                "<ServerName>mmtel.narcissi.example.com</ServerName>"
                "<DefaultHandling>0</DefaultHandling>"
              "</ApplicationServer>"
            "</InitialFilterCriteria>"
          "</ServiceProfile>"
          "<ServiceProfile>"
            "<PublicIdentity>"
              "<Identity>sip:89@example.com</Identity>"
            "</PublicIdentity>"
            "<PublicIdentity>"
              "<Identity>sip:67@example.com</Identity>"
            "</PublicIdentity>"
            "<InitialFilterCriteria>"
              "<TriggerPoint>"
                "<ConditionTypeCNF>0</ConditionTypeCNF>"
                "<SPT>"
                  "<ConditionNegated>0</ConditionNegated>"
                  "<Group>0</Group>"
                  "<Method>INVITE</Method>"
                  "<Extension></Extension>"
                "</SPT>"
              "</TriggerPoint>"
              "<ApplicationServer>"
                "<ServerName>mmtel.narcissi.example.com</ServerName>"
                "<DefaultHandling>0</DefaultHandling>"
              "</ApplicationServer>"
            "</InitialFilterCriteria>"
          "</ServiceProfile>"
        "</IMSSubscription>"
        "<ChargingAddresses>"
          "<CCF priority=\"1\">ccf1</CCF>"
          "<CCF priority=\"2\">ccf2</CCF>"
          "<ECF priority=\"2\">ecf2</ECF>"
          "<ECF priority=\"1\">ecf1</ECF>"
        "</ChargingAddresses>"
      "</ClearwaterRegData>";
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/public-needs-private/reg-data?private_id=a-private-id", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<ClearwaterRegData>"
        "<RegistrationState>REGISTERED</RegistrationState>"
        "<IMSSubscription>"
          "<ServiceProfile>"
            "<PublicIdentity>"
              "<Identity>sip:123@example.com</Identity>"
            "</PublicIdentity>"
            "<InitialFilterCriteria>"
              "<ApplicationServer>"
                "<ServerName>mmtel.narcissi.example.com</ServerName>"
                "<DefaultHandling>0</DefaultHandling>"
              "</ApplicationServer>"
            "</InitialFilterCriteria>"
          "</ServiceProfile>"
        "</IMSSubscription>"
        "<ChargingAddresses>"
          "<CCF priority=\"1\">ccf1</CCF>"
          "<CCF priority=\"2\">ccf2</CCF>"
          "<ECF priority=\"2\">ecf2</ECF>"
          "<ECF priority=\"1\">ecf1</ECF>"
        "</ChargingAddresses>"
      "</ClearwaterRegData>";
  }
  virtual ~HssConnectionTest()
  {
  }
};

TEST_F(HssConnectionTest, SimpleAssociatedUris)
{
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.get_registration_data("pubid42", regstate, ifcs_map, uris, 0);
  EXPECT_EQ("REGISTERED", regstate);
  ASSERT_EQ(2u, uris.size());
  EXPECT_EQ("sip:123@example.com", uris[0]);
  EXPECT_EQ("sip:456@example.com", uris[1]);
}

TEST_F(HssConnectionTest, SimpleNotRegisteredGet)
{
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.get_registration_data("pubid43", regstate, ifcs_map, uris, 0);
  EXPECT_EQ("NOT_REGISTERED", regstate);
  EXPECT_EQ(0u, uris.size());
}

TEST_F(HssConnectionTest, SimpleUnregistered)
{
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("pubid50", "", HSSConnection::CALL, regstate, ifcs_map, uris, 0);
  EXPECT_EQ("UNREGISTERED", regstate);
}

TEST_F(HssConnectionTest, SimpleNotRegisteredUpdate)
{
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("pubid50", "", HSSConnection::DEREG_ADMIN, regstate, ifcs_map, uris, 0);
  EXPECT_EQ("NOT_REGISTERED", regstate);
}

TEST_F(HssConnectionTest, SimpleIfc)
{
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("pubid42", "", HSSConnection::REG, regstate, ifcs_map, uris, 0);
  EXPECT_FALSE(ifcs_map.empty());
}

TEST_F(HssConnectionTest, SimpleChargingAddrs)
{
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  std::deque<std::string> ccfs;
  std::deque<std::string> actual_ccfs = {"ccf1", "ccf2"};
  std::deque<std::string> ecfs;
  std::deque<std::string> actual_ecfs = {"ecf1", "ecf2"};
  _hss.update_registration_state("pubid42", "", HSSConnection::REG, regstate, ifcs_map, uris, ccfs, ecfs, 0);
  EXPECT_EQ(actual_ccfs, ccfs);
  EXPECT_EQ(actual_ecfs, ecfs);
}

TEST_F(HssConnectionTest, BadXML)
{
  CapturingTestLogger log;
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("pubid42_malformed", "", HSSConnection::REG, regstate, ifcs_map, uris, 0);
  EXPECT_TRUE(uris.empty());
  EXPECT_TRUE(log.contains("Failed to parse Homestead response"));
}


TEST_F(HssConnectionTest, BadXML2)
{
  CapturingTestLogger log;
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("pubid43_malformed", "", HSSConnection::REG, regstate, ifcs_map, uris, 0);
  EXPECT_TRUE(uris.empty());
  EXPECT_TRUE(log.contains("Malformed HSS XML"));
}

TEST_F(HssConnectionTest, BadXML_MissingServiceProfile)
{
  CapturingTestLogger log;
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("missingelement4", "", HSSConnection::REG, regstate, ifcs_map, uris, 0);
  EXPECT_TRUE(uris.empty());
  EXPECT_TRUE(log.contains("Malformed HSS XML"));
}

TEST_F(HssConnectionTest, BadXML_MissingPublicIdentity)
{
  CapturingTestLogger log;
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("missingelement5", "", HSSConnection::REG, regstate, ifcs_map, uris, 0);
  EXPECT_TRUE(uris.empty());
  EXPECT_TRUE(log.contains("Malformed ServiceProfile XML"));
}

TEST_F(HssConnectionTest, BadXML_MissingIdentity)
{
  CapturingTestLogger log;
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("missingelement6", "", HSSConnection::REG, regstate, ifcs_map, uris, 0);
  EXPECT_TRUE(uris.empty());
  EXPECT_TRUE(log.contains("Malformed PublicIdentity XML"));
}

TEST_F(HssConnectionTest, BadXML_MissingRegistrationState)
{
  CapturingTestLogger log;
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("missingelement1", "", HSSConnection::REG, regstate, ifcs_map, uris, 0);
  EXPECT_TRUE(uris.empty());
  EXPECT_TRUE(log.contains("Malformed Homestead XML"));
}

TEST_F(HssConnectionTest, BadXML_MissingClearwaterRegData)
{
  CapturingTestLogger log;
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("missingelement3", "", HSSConnection::REG, regstate, ifcs_map, uris, 0);
  EXPECT_TRUE(uris.empty());
  EXPECT_TRUE(log.contains("Malformed Homestead XML"));
}

TEST_F(HssConnectionTest, BadXML_MissingIMSSubscription)
{
  CapturingTestLogger log;
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("missingelement2", "", HSSConnection::REG, regstate, ifcs_map, uris, 0);
  EXPECT_TRUE(uris.empty());
  EXPECT_TRUE(log.contains("Malformed HSS XML"));
}


TEST_F(HssConnectionTest, ServerFailure)
{
  CapturingTestLogger log;
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("pubid44", "", HSSConnection::REG, regstate, ifcs_map, uris, 0);
  EXPECT_EQ("", regstate);
  EXPECT_TRUE(uris.empty());
  EXPECT_TRUE(log.contains("http://narcissus/impu/pubid44/reg-data failed"));
}

TEST_F(HssConnectionTest, SimpleUserAuth)
{
  rapidjson::Document* actual;
  _hss.get_user_auth_status("privid69", "pubid44", "", "", actual, 0);
  ASSERT_TRUE(actual != NULL);
  EXPECT_EQ(std::string("server-name"), (*actual)["scscf"].GetString());
  delete actual;
}

TEST_F(HssConnectionTest, FullUserAuth)
{
  rapidjson::Document* actual;
  _hss.get_user_auth_status("privid69", "pubid44", "domain", "REG", actual, 0);
  ASSERT_TRUE(actual != NULL);
  EXPECT_EQ(2001, (*actual)["result-code"].GetInt());
  delete actual;
}

TEST_F(HssConnectionTest, CorruptAuth)
{
  CapturingTestLogger log;
  rapidjson::Document* actual;
  _hss.get_user_auth_status("privid_corrupt", "pubid44", "", "", actual, 0);
  ASSERT_TRUE(actual == NULL);
  EXPECT_TRUE(log.contains("Failed to parse Homestead response"));
  delete actual;
}

TEST_F(HssConnectionTest, SimpleLocation)
{
  rapidjson::Document* actual;
  _hss.get_location_data("pubid44", false, "", actual, 0);
  ASSERT_TRUE(actual != NULL);
  EXPECT_EQ(std::string("server-name"), (*actual)["scscf"].GetString());
  delete actual;
}

TEST_F(HssConnectionTest, LocationWithAuthType)
{
  rapidjson::Document* actual;
  _hss.get_location_data("pubid44", false, "DEREG", actual, 0);
  ASSERT_TRUE(actual != NULL);
  EXPECT_EQ(2001, (*actual)["result-code"].GetInt());
  delete actual;
}

TEST_F(HssConnectionTest, FullLocation)
{
  rapidjson::Document* actual;
  _hss.get_location_data("pubid44", true, "CAPAB", actual, 0);
  ASSERT_TRUE(actual != NULL);
  EXPECT_EQ(2001, (*actual)["result-code"].GetInt());
  delete actual;
}

TEST_F(HssConnectionTest, LocationNotFound)
{
  rapidjson::Document* actual;
  HTTPCode rc = _hss.get_location_data("pubid45", false, "", actual, 0);
  ASSERT_TRUE(actual == NULL);
  ASSERT_TRUE(rc == 404);
  delete actual;
}

TEST_F(HssConnectionTest, SimpleAliases)
{
  std::vector<std::string> aliases;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  std::vector<std::string> unused_vector;
  std::deque<std::string> unused_deque;
  _hss.update_registration_state("pubid46",
                                 "",
                                 HSSConnection::CALL,
                                 regstate,
                                 ifcs_map,
                                 unused_vector,
                                 aliases,
                                 unused_deque,
                                 unused_deque,
                                 true,
                                 "",
                                 0);
  ASSERT_EQ(3u, aliases.size());
  EXPECT_EQ("sip:321@example.com", aliases[0]);
  EXPECT_EQ("pubid46", aliases[1]);
  EXPECT_EQ("tel:321", aliases[2]);
}

TEST_F(HssConnectionTest, CacheNotAllowed)
{
  std::vector<std::string> aliases;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  std::vector<std::string> unused_vector;
  std::deque<std::string> unused_deque;
  HTTPCode rc = _hss.update_registration_state("public-needs-private",
                                               "a-private-id",
                                               HSSConnection::REG,
                                               regstate,
                                               ifcs_map,
                                               unused_vector,
                                               aliases,
                                               unused_deque,
                                               unused_deque,
                                               false, // Do not allow cached answers.
                                               "",
                                               0);
  // The request has a cache control header on it to prevent cached responses.
  Request& request = fakecurl_requests[
    "http://narcissus:80/impu/public-needs-private/reg-data?private_id=a-private-id"];
  EXPECT_NE(std::find(request._headers.begin(),
                      request._headers.end(),
                      "Cache-control: no-cache"),
            request._headers.end());

  // The request worked.
  EXPECT_EQ(rc, 200);
}

/// Fixture for HssWithSifcTest.
class HssWithSifcTest : public BaseTest
{
  FakeHttpResolver _resolver;
  HSSConnection _sifc_hss;
  MockSIFCService _sifc_service;

  HssWithSifcTest() :
    _resolver("10.42.42.42"),
    _sifc_hss("narcissus",
              &_resolver,
              NULL,
              NULL,
              &SNMP::FAKE_EVENT_ACCUMULATOR_TABLE,
              &SNMP::FAKE_EVENT_ACCUMULATOR_TABLE,
              &SNMP::FAKE_EVENT_ACCUMULATOR_TABLE,
              &SNMP::FAKE_EVENT_ACCUMULATOR_TABLE,
              &SNMP::FAKE_EVENT_ACCUMULATOR_TABLE,
              NULL,
              "server_name",
              &_sifc_service)
  {
    fakecurl_responses.clear();
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/onesifc/reg-data", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")] =
     "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
     "<ClearwaterRegData>"
       "<RegistrationState>REGISTERED</RegistrationState>"
       "<IMSSubscription>"
         "<ServiceProfile>"
           "<PublicIdentity>"
             "<Identity>sip:123@example.com</Identity>"
           "</PublicIdentity>"
           "<Extension>"
             "<SharedIFCSetID>10</SharedIFCSetID>"
           "</Extension>"
         "</ServiceProfile>"
       "</IMSSubscription>"
       "<ChargingAddresses>"
         "<CCF priority=\"1\">ccf1</CCF>"
         "<CCF priority=\"2\">ccf2</CCF>"
         "<ECF priority=\"2\">ecf2</ECF>"
         "<ECF priority=\"1\">ecf1</ECF>"
       "</ChargingAddresses>"
     "</ClearwaterRegData>";
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/sifcandifc/reg-data", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")] =
     "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
     "<ClearwaterRegData>"
       "<RegistrationState>REGISTERED</RegistrationState>"
       "<IMSSubscription>"
         "<ServiceProfile>"
           "<PublicIdentity>"
             "<Identity>sip:123@example.com</Identity>"
           "</PublicIdentity>"
           "<InitialFilterCriteria>"
             "<ApplicationServer>"
               "<ServerName>mmtel.narcissi.example.com</ServerName>"
               "<DefaultHandling>0</DefaultHandling>"
             "</ApplicationServer>"
           "</InitialFilterCriteria>"
           "<Extension>"
             "<SharedIFCSetID>0</SharedIFCSetID>"
           "</Extension>"
         "</ServiceProfile>"
       "</IMSSubscription>"
       "<ChargingAddresses>"
         "<CCF priority=\"1\">ccf1</CCF>"
         "<CCF priority=\"2\">ccf2</CCF>"
         "<ECF priority=\"2\">ecf2</ECF>"
         "<ECF priority=\"1\">ecf1</ECF>"
       "</ChargingAddresses>"
     "</ClearwaterRegData>";
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/invalidsifc/reg-data", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")] =
     "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
     "<ClearwaterRegData>"
       "<RegistrationState>REGISTERED</RegistrationState>"
       "<IMSSubscription>"
         "<ServiceProfile>"
           "<PublicIdentity>"
             "<Identity>sip:123@example.com</Identity>"
           "</PublicIdentity>"
           "<Extension>"
             "<SharedIFCSetID>one</SharedIFCSetID>"
           "</Extension>"
         "</ServiceProfile>"
       "</IMSSubscription>"
       "<ChargingAddresses>"
         "<CCF priority=\"1\">ccf1</CCF>"
         "<CCF priority=\"2\">ccf2</CCF>"
         "<ECF priority=\"2\">ecf2</ECF>"
         "<ECF priority=\"1\">ecf1</ECF>"
       "</ChargingAddresses>"
     "</ClearwaterRegData>";
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/multipleextensions/reg-data", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")] =
     "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
     "<ClearwaterRegData>"
       "<RegistrationState>REGISTERED</RegistrationState>"
       "<IMSSubscription>"
         "<ServiceProfile>"
           "<PublicIdentity>"
             "<Identity>sip:123@example.com</Identity>"
           "</PublicIdentity>"
           "<Extension>"
             "<SharedIFCSetID>1</SharedIFCSetID>"
             "<SharedIFCSetID>2</SharedIFCSetID>"
           "</Extension>"
           "<Extension>"
             "<SharedIFCSetID>10</SharedIFCSetID>"
           "</Extension>"
         "</ServiceProfile>"
       "</IMSSubscription>"
       "<ChargingAddresses>"
         "<CCF priority=\"1\">ccf1</CCF>"
         "<CCF priority=\"2\">ccf2</CCF>"
         "<ECF priority=\"2\">ecf2</ECF>"
         "<ECF priority=\"1\">ecf1</ECF>"
       "</ChargingAddresses>"
     "</ClearwaterRegData>";
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/multiplesifc/reg-data", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")] =
     "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
     "<ClearwaterRegData>"
       "<RegistrationState>REGISTERED</RegistrationState>"
       "<IMSSubscription>"
         "<ServiceProfile>"
           "<PublicIdentity>"
             "<Identity>sip:123@example.com</Identity>"
           "</PublicIdentity>"
           "<Extension>"
             "<SharedIFCSetID>1</SharedIFCSetID>"
             "<SharedIFCSetID>2</SharedIFCSetID>"
           "</Extension>"
         "</ServiceProfile>"
       "</IMSSubscription>"
       "<ChargingAddresses>"
         "<CCF priority=\"1\">ccf1</CCF>"
         "<CCF priority=\"2\">ccf2</CCF>"
         "<ECF priority=\"2\">ecf2</ECF>"
         "<ECF priority=\"1\">ecf1</ECF>"
       "</ChargingAddresses>"
     "</ClearwaterRegData>";
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/multiplepubids/reg-data", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")] =
     "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
     "<ClearwaterRegData>"
       "<RegistrationState>REGISTERED</RegistrationState>"
       "<IMSSubscription>"
         "<ServiceProfile>"
           "<PublicIdentity>"
             "<Identity>sip:123@example.com</Identity>"
           "</PublicIdentity>"
           "<PublicIdentity>"
             "<Identity>sip:456@example.com</Identity>"
           "</PublicIdentity>"
           "<Extension>"
             "<SharedIFCSetID>1</SharedIFCSetID>"
           "</Extension>"
         "</ServiceProfile>"
         "<ServiceProfile>"
           "<PublicIdentity>"
             "<Identity>sip:789@example.com</Identity>"
           "</PublicIdentity>"
           "<Extension>"
             "<SharedIFCSetID>2</SharedIFCSetID>"
           "</Extension>"
         "</ServiceProfile>"
       "</IMSSubscription>"
       "<ChargingAddresses>"
         "<CCF priority=\"1\">ccf1</CCF>"
         "<CCF priority=\"2\">ccf2</CCF>"
         "<ECF priority=\"2\">ecf2</ECF>"
         "<ECF priority=\"1\">ecf1</ECF>"
       "</ChargingAddresses>"
     "</ClearwaterRegData>";
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/sifcifcmix/reg-data", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")] =
     "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
     "<ClearwaterRegData>"
       "<RegistrationState>REGISTERED</RegistrationState>"
       "<IMSSubscription>"
         "<ServiceProfile>"
           "<PublicIdentity>"
              "<Identity>sip:123@example.com</Identity>"
           "</PublicIdentity>"
           "<InitialFilterCriteria>"
             "<Priority>1</Priority>"
             "<TriggerPoint>"
               "<ConditionTypeCNF>0</ConditionTypeCNF>"
               "<SPT>"
                 "<ConditionNegated>0</ConditionNegated>"
                 "<Group>0</Group>"
                 "<Method>INVITE</Method>"
                 "<Extension></Extension>"
               "</SPT>"
             "</TriggerPoint>"
             "<ApplicationServer>"
               "<ServerName>mmtel.narcissi.example.com</ServerName>"
               "<DefaultHandling>0</DefaultHandling>"
             "</ApplicationServer>"
           "</InitialFilterCriteria>"
           "<InitialFilterCriteria>"
             "<Priority>1</Priority>"
             "<TriggerPoint>"
               "<ConditionTypeCNF>0</ConditionTypeCNF>"
               "<SPT>"
                 "<ConditionNegated>0</ConditionNegated>"
                 "<Group>0</Group>"
                 "<Method>INVITE</Method>"
                 "<Extension></Extension>"
               "</SPT>"
             "</TriggerPoint>"
             "<ApplicationServer>"
               "<ServerName>mmtel.narcissi.example2.com</ServerName>"
               "<DefaultHandling>0</DefaultHandling>"
             "</ApplicationServer>"
           "</InitialFilterCriteria>"
           "<InitialFilterCriteria>"
             "<Priority>2</Priority>"
             "<TriggerPoint>"
               "<ConditionTypeCNF>0</ConditionTypeCNF>"
               "<SPT>"
                 "<ConditionNegated>0</ConditionNegated>"
                 "<Group>0</Group>"
                 "<Method>INVITE</Method>"
                 "<Extension></Extension>"
               "</SPT>"
             "</TriggerPoint>"
             "<ApplicationServer>"
               "<ServerName>mmtel.narcissi.example3.com</ServerName>"
               "<DefaultHandling>0</DefaultHandling>"
             "</ApplicationServer>"
           "</InitialFilterCriteria>"
           "<InitialFilterCriteria>"
             "<Priority>3</Priority>"
             "<TriggerPoint>"
               "<ConditionTypeCNF>0</ConditionTypeCNF>"
               "<SPT>"
                 "<ConditionNegated>0</ConditionNegated>"
                 "<Group>0</Group>"
                 "<Method>INVITE</Method>"
                 "<Extension></Extension>"
               "</SPT>"
             "</TriggerPoint>"
             "<ApplicationServer>"
               "<ServerName>mmtel.narcissi.example4.com</ServerName>"
               "<DefaultHandling>0</DefaultHandling>"
             "</ApplicationServer>"
           "</InitialFilterCriteria>"
           "<InitialFilterCriteria>"
             "<Priority>3</Priority>"
             "<TriggerPoint>"
               "<ConditionTypeCNF>0</ConditionTypeCNF>"
               "<SPT>"
                 "<ConditionNegated>0</ConditionNegated>"
                 "<Group>0</Group>"
                 "<Method>INVITE</Method>"
                 "<Extension></Extension>"
               "</SPT>"
             "</TriggerPoint>"
             "<ApplicationServer>"
               "<ServerName>mmtel.narcissi.example5.com</ServerName>"
               "<DefaultHandling>0</DefaultHandling>"
             "</ApplicationServer>"
           "</InitialFilterCriteria>"
           "<InitialFilterCriteria>"
             "<Priority>4</Priority>"
             "<TriggerPoint>"
               "<ConditionTypeCNF>0</ConditionTypeCNF>"
               "<SPT>"
                 "<ConditionNegated>0</ConditionNegated>"
                 "<Group>0</Group>"
                 "<Method>INVITE</Method>"
                 "<Extension></Extension>"
               "</SPT>"
             "</TriggerPoint>"
             "<ApplicationServer>"
               "<ServerName>mmtel.narcissi.example6.com</ServerName>"
               "<DefaultHandling>0</DefaultHandling>"
             "</ApplicationServer>"
           "</InitialFilterCriteria>"
           "<Extension>"
             "<SharedIFCSetID>3</SharedIFCSetID>"
             "<SharedIFCSetID>4</SharedIFCSetID>"
           "</Extension>"
         "</ServiceProfile>"
       "</IMSSubscription>"
       "<ChargingAddresses>"
         "<CCF priority=\"1\">ccf1</CCF>"
         "<CCF priority=\"2\">ccf2</CCF>"
         "<ECF priority=\"2\">ecf2</ECF>"
         "<ECF priority=\"1\">ecf1</ECF>"
       "</ChargingAddresses>"
     "</ClearwaterRegData>";
  }
  virtual ~HssWithSifcTest()
  {
  }
};

// Check that some iFCs are returned when a shared iFC set is encountered.
TEST_F(HssWithSifcTest, SimpleSiFC)
{
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;

  // Mock out the function that converts the list of shared iFC set ids into a
  // list of iFCs - this function is tested elsewhere.
  Ifc* fake_ifc = new Ifc(NULL);
  std::multimap<int32_t, Ifc> ifcs_from_id;
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(1, *fake_ifc));
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(2, *fake_ifc));
  // Expect input of one shared iFC set, with set id 10.
  const std::set<int32_t> ids = {10};
  EXPECT_CALL(_sifc_service, get_ifcs_from_id(_, ids, _))
    .WillOnce(SetArgReferee<0>(std::multimap<int32_t, Ifc>(ifcs_from_id)));

  // Send in a message, and check that two iFCs are now present in the map.
  _sifc_hss.update_registration_state("onesifc", "", HSSConnection::REG, regstate, ifcs_map, uris, 0);
  EXPECT_TRUE(ifcs_map.begin()->second.size() == 2);

  // Clean up.
  delete fake_ifc; fake_ifc = NULL;
}

// Check that SiFCs are compatible with iFCs.
TEST_F(HssWithSifcTest, SifcWithIfc)
{
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;

  // Mock out the function that converts the list of shared iFC set ids into a
  // list of iFCs - this function is tested elsewhere.
  Ifc* fake_ifc = new Ifc(NULL);
  std::multimap<int32_t, Ifc> ifcs_from_id;
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(1, *fake_ifc));
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(2, *fake_ifc));
  // Expect input of one shared iFC set with set id of 0.
  const std::set<int32_t> ids = {0};
  EXPECT_CALL(_sifc_service, get_ifcs_from_id(_, ids, _))
    .WillOnce(SetArgReferee<0>(std::multimap<int32_t, Ifc>(ifcs_from_id)));

  // Send in a message, and check that three iFCs are now present in the map,
  // two from the SiFC set, and one regular iFC.
  _sifc_hss.update_registration_state("sifcandifc", "", HSSConnection::REG, regstate, ifcs_map, uris, 0);
  EXPECT_TRUE(ifcs_map.begin()->second.size() == 3);

  // Clean up.
  delete fake_ifc; fake_ifc = NULL;
}

// Check that an invalid SiFC, that is not an integer, is not accepted.
TEST_F(HssWithSifcTest, NonIntegerSifc)
{
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;

  // Send in a message, and check that the iFC map is still empty.
  _sifc_hss.update_registration_state("invalidsifc", "", HSSConnection::REG, regstate, ifcs_map, uris, 0);
  EXPECT_TRUE(ifcs_map.begin()->second.size() == 0);
}

// Check that shared IFCs are read out from all Extensions present in the XML.
TEST_F(HssWithSifcTest, MultipleExtensions)
{
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;

  // Mock out the function that converts the list of shared iFC set ids into a
  // list of iFCs - this function is tested elsewhere.
  // Expect two calls, one for each "Extension" present.
  Ifc* fake_ifc = new Ifc(NULL);

  std::multimap<int32_t, Ifc> ifc_list_one;
  ifc_list_one.insert(std::pair<int32_t, Ifc>(1, *fake_ifc));
  ifc_list_one.insert(std::pair<int32_t, Ifc>(2, *fake_ifc));
  const std::set<int32_t> set_list_one = {1, 2};
  EXPECT_CALL(_sifc_service, get_ifcs_from_id(_, set_list_one, _))
    .WillOnce(SetArgReferee<0>(std::multimap<int32_t, Ifc>(ifc_list_one)));

  std::multimap<int32_t, Ifc> ifc_list_two;
  ifc_list_two.insert(std::pair<int32_t, Ifc>(1, *fake_ifc));
  ifc_list_two.insert(std::pair<int32_t, Ifc>(2, *fake_ifc));
  ifc_list_two.insert(std::pair<int32_t, Ifc>(2, *fake_ifc));
  const std::set<int32_t> set_list_two = {10};
  EXPECT_CALL(_sifc_service, get_ifcs_from_id(_, set_list_two, _))
    .WillOnce(SetArgReferee<0>(std::multimap<int32_t, Ifc>(ifc_list_two)));

  // Send in a message, and check that three iFCs are now in the iFC map, two
  // from the first set list, and an additional third from the second set list.
  _sifc_hss.update_registration_state("multipleextensions", "", HSSConnection::REG, regstate, ifcs_map, uris, 0);
  EXPECT_TRUE(ifcs_map.begin()->second.size() == 3);

  // Clean up.
  delete fake_ifc; fake_ifc = NULL;
}

// Check that multiple shared iFCs are parsed correctly.
TEST_F(HssWithSifcTest, MultipleSifcs)
{
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;

  // Mock out the function that converts the list of shared iFC set ids into a
  // list of iFCs - this function is tested elsewhere.
  Ifc* fake_ifc = new Ifc(NULL);
  std::multimap<int32_t, Ifc> ifcs_from_id;
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(2, *fake_ifc));
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(2, *fake_ifc));
  // Expect input of two shared iFC sets, with set ids 1 and 2.
  const std::set<int32_t> ids = {1, 2};
  EXPECT_CALL(_sifc_service, get_ifcs_from_id(_, ids, _))
    .WillOnce(SetArgReferee<0>(std::multimap<int32_t, Ifc>(ifcs_from_id)));

  // Send in a message, and check that two iFCs are now in the iFC map.
  _sifc_hss.update_registration_state("multiplesifc", "", HSSConnection::REG, regstate, ifcs_map, uris, 0);
  EXPECT_TRUE(ifcs_map.begin()->second.size() == 2);

  // Clean up.
  delete fake_ifc; fake_ifc = NULL;
}

// Check that shared iFCs are parsed correctly when multiple public ids are
// present, both within the same ServiceProfile, and within seperate
// ServiceProfiles.
TEST_F(HssWithSifcTest, MultiplePubIdsWithSifcs)
{
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;

  // Mock out the function that converts the list of shared iFC set ids into a
  // list of iFCs - this function is tested elsewhere.
  Ifc* fake_ifc = new Ifc(NULL);
  std::multimap<int32_t, Ifc> ifcs_from_id;
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(2, *fake_ifc));
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(2, *fake_ifc));
  // Expect input of one shared iFC set; with an id of 1 for one service
  // profile, and 2 for the other.
  const std::set<int32_t> id_set_one = {1};
  const std::set<int32_t> id_set_two = {2};
  EXPECT_CALL(_sifc_service, get_ifcs_from_id(_, id_set_one, _))
    .WillOnce(SetArgReferee<0>(std::multimap<int32_t, Ifc>(ifcs_from_id)));
  EXPECT_CALL(_sifc_service, get_ifcs_from_id(_, id_set_two, _))
    .WillOnce(SetArgReferee<0>(std::multimap<int32_t, Ifc>(ifcs_from_id)));

  // The iFC map composes of keys, which are public ids, and their values, which
  // are the lists of iFCs that correspond to that public id.
  // Send in a message, and loop through the map checking that the correct
  // number of iFCs are present for each public id.
  _sifc_hss.update_registration_state("multiplepubids", "", HSSConnection::REG, regstate, ifcs_map, uris, 0);
  for(std::pair<std::string, Ifcs> elem : ifcs_map)
  {
    EXPECT_TRUE(elem.second.size() == 2);
  }

  // Clean up.
  delete fake_ifc; fake_ifc = NULL;
}

// Check that shared iFCs are parsed correctly when mixed with a complex set of
// iFCs.
TEST_F(HssWithSifcTest, ComplexSifcIfcMix)
{
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;

  // Create an XML with two mock iFCs in it, one with priority one, the other
  // with priority two.
  rapidxml::xml_document<> doc;

  rapidxml::xml_node<>* ifc_priority_one = doc.allocate_node(
                           rapidxml::node_type::node_element, "IFCPriorityOne");
  rapidxml::xml_node<>* priority_one = doc.allocate_node(
                            rapidxml::node_type::node_element, "Priority", "1");
  ifc_priority_one->append_node(priority_one);
  doc.append_node(ifc_priority_one);

  rapidxml::xml_node<>* ifc_priority_two = doc.allocate_node(
                           rapidxml::node_type::node_element, "IFCPriorityTwo");
  rapidxml::xml_node<>* priority_two = doc.allocate_node(
                            rapidxml::node_type::node_element, "Priority", "2");
  ifc_priority_two->append_node(priority_two);
  doc.append_node(ifc_priority_two);

  // Mock out the function (which is tested elsewhere), that converts the list
  // of shared iFC set ids into a list of iFCs, to return the iFCs created
  // above.
  std::multimap<int32_t, Ifc> ifcs_from_id;
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(1, Ifc(ifc_priority_one)));
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(2, Ifc(ifc_priority_two)));
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(2, Ifc(ifc_priority_two)));
  // Expect input of two shared iFC sets, with ids 3 and 4.
  const std::set<int32_t> id_set_one = {3, 4};
  EXPECT_CALL(_sifc_service, get_ifcs_from_id(_, id_set_one, _))
    .WillOnce(SetArgReferee<0>(std::multimap<int32_t, Ifc>(ifcs_from_id)));

  // Send in a message, and check the expected number of iFCs are present, as
  // well as checking that the expected number with each priority are present.
  _sifc_hss.update_registration_state("sifcifcmix", "", HSSConnection::REG, regstate, ifcs_map, uris, 0);
  int32_t map_size = ifcs_map.begin()->second.size();
  EXPECT_TRUE(map_size == 9);
  std::vector<int32_t> expected_priorities = {1, 1, 1, 2, 2, 2, 3, 3, 4};
  std::vector<int32_t> priorities;
  int32_t ii;
  int32_t priority;
  for (ii = 0; ii < map_size; ii++)
  {
    const Ifc& ifc = ifcs_map.begin()->second[ii];
    if (ifc._ifc->first_node("Priority"))
    {
      priority = std::atoi(ifc._ifc->first_node("Priority")->value());
      priorities.push_back(priority);
    }
  }
  EXPECT_THAT(expected_priorities, UnorderedElementsAreArray(priorities));
}


