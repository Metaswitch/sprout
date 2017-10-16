/**
 * @file hssconnection_test.cpp UT for Sprout HSS connection.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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
         NULL,
         500)
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
    fakecurl_responses["http://10.42.42.42:80/impi/privid69/registration-status?impu=pubid44&sos=true"] = "{\"result-code\": 2001, \"scscf\": \"server-name\"}";
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
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/pubid51/reg-data", "{\"reqtype\": \"call\", \"server_name\": \"sip:scscf.sprout.homedomain;transport=TCP\"}")] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<ClearwaterRegData>"
        "<RegistrationState>REGISTERED</RegistrationState>"
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
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/pubid47/reg-data", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<ClearwaterRegData>"
        "<RegistrationState>REGISTERED</RegistrationState>"
        "<IMSSubscription>"
          "<ServiceProfile>"
            "<PublicIdentity>"
              "<Identity>sip:123@example.com</Identity>"
              "<BarringIndication>0</BarringIndication>"
            "</PublicIdentity>"
            "<PublicIdentity>"
              "<Identity>sip:456@example.com</Identity>"
              "<BarringIndication>1</BarringIndication>"
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
  }

  virtual ~HssConnectionTest()
  {
  }
};

TEST_F(HssConnectionTest, SimpleAssociatedUris)
{
  const HSSConnection::hss_query_param_t hss_query_param("pubid42");
  HSSConnection::hss_query_return_t hss_query_return;
  _hss.get_registration_data(hss_query_param,
                             hss_query_return,
                             0);
  EXPECT_EQ("REGISTERED", hss_query_return.regstate);
  ASSERT_EQ(2u, hss_query_return.associated_uris.get_unbarred_uris().size());
  EXPECT_EQ("sip:123@example.com", hss_query_return.associated_uris.get_unbarred_uris()[0]);
  EXPECT_EQ("sip:456@example.com", hss_query_return.associated_uris.get_unbarred_uris()[1]);
}

TEST_F(HssConnectionTest, SimpleNotRegisteredGet)
{
  const HSSConnection::hss_query_param_t hss_query_param("pubid43");
  HSSConnection::hss_query_return_t hss_query_return;
  _hss.get_registration_data(hss_query_param,
                             hss_query_return,
                             0);
  EXPECT_EQ("NOT_REGISTERED", hss_query_return.regstate);
  EXPECT_EQ(0u, hss_query_return.associated_uris.get_unbarred_uris().size());
}

TEST_F(HssConnectionTest, SimpleUnregistered)
{
  AssociatedURIs uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("pubid50", "", HSSConnection::CALL, regstate, "server_name", ifcs_map, uris, 0);
  EXPECT_EQ("UNREGISTERED", regstate);
}

TEST_F(HssConnectionTest, SimpleNotRegisteredUpdate)
{
  AssociatedURIs uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("pubid50", "", HSSConnection::DEREG_ADMIN, regstate, "server_name", ifcs_map, uris, 0);
  EXPECT_EQ("NOT_REGISTERED", regstate);
}

TEST_F(HssConnectionTest, SimpleIfc)
{
  AssociatedURIs uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("pubid42", "", HSSConnection::REG, regstate, "server_name", ifcs_map, uris, 0);
  EXPECT_FALSE(ifcs_map.empty());
}

TEST_F(HssConnectionTest, SimpleChargingAddrs)
{
  AssociatedURIs uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  std::deque<std::string> ccfs;
  std::deque<std::string> actual_ccfs = {"ccf1", "ccf2"};
  std::deque<std::string> ecfs;
  std::deque<std::string> actual_ecfs = {"ecf1", "ecf2"};
  _hss.update_registration_state("pubid42", "", HSSConnection::REG, regstate, "server_name", ifcs_map, uris, ccfs, ecfs, 0);
  EXPECT_EQ(actual_ccfs, ccfs);
  EXPECT_EQ(actual_ecfs, ecfs);
}

TEST_F(HssConnectionTest, ServerName)
{
  // Checks that we can request a different server name.
  AssociatedURIs uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("pubid51", "", HSSConnection::CALL, regstate, "sip:scscf.sprout.homedomain;transport=TCP", ifcs_map, uris, 0);
  EXPECT_EQ("REGISTERED", regstate);
}

TEST_F(HssConnectionTest, Barring)
{
  // Checks that the BarringIndication field from the HSS is parsed correctly.
  AssociatedURIs uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("pubid47", "", HSSConnection::REG, regstate, "server_name", ifcs_map, uris, 0);
  EXPECT_EQ("REGISTERED", regstate);
  ASSERT_EQ(1u, uris.get_unbarred_uris().size());
  EXPECT_FALSE(uris.is_impu_barred("sip:123@example.com"));
  EXPECT_TRUE(uris.is_impu_barred("sip:456@example.com"));
}

TEST_F(HssConnectionTest, BadXML)
{
  CapturingTestLogger log;
  AssociatedURIs uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("pubid42_malformed", "", HSSConnection::REG, regstate, "server_name", ifcs_map, uris, 0);
  EXPECT_TRUE(uris.get_unbarred_uris().empty());
  EXPECT_TRUE(log.contains("Failed to parse Homestead response"));
}


TEST_F(HssConnectionTest, BadXML2)
{
  CapturingTestLogger log;
  AssociatedURIs uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("pubid43_malformed", "", HSSConnection::REG, regstate, "server_name", ifcs_map, uris, 0);
  EXPECT_TRUE(uris.get_unbarred_uris().empty());
  EXPECT_TRUE(log.contains("Malformed HSS XML"));
}

TEST_F(HssConnectionTest, BadXML_MissingServiceProfile)
{
  CapturingTestLogger log;
  AssociatedURIs uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("missingelement4", "", HSSConnection::REG, regstate, "server_name", ifcs_map, uris, 0);
  EXPECT_TRUE(uris.get_unbarred_uris().empty());
  EXPECT_TRUE(log.contains("Malformed HSS XML"));
}

TEST_F(HssConnectionTest, BadXML_MissingPublicIdentity)
{
  CapturingTestLogger log;
  AssociatedURIs uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("missingelement5", "", HSSConnection::REG, regstate, "server_name", ifcs_map, uris, 0);
  EXPECT_TRUE(uris.get_unbarred_uris().empty());
  EXPECT_TRUE(log.contains("Malformed ServiceProfile XML"));
}

TEST_F(HssConnectionTest, BadXML_MissingIdentity)
{
  CapturingTestLogger log;
  AssociatedURIs uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("missingelement6", "", HSSConnection::REG, regstate, "server_name", ifcs_map, uris, 0);
  EXPECT_TRUE(uris.get_unbarred_uris().empty());
  EXPECT_TRUE(log.contains("Malformed PublicIdentity XML"));
}

TEST_F(HssConnectionTest, BadXML_MissingRegistrationState)
{
  CapturingTestLogger log;
  AssociatedURIs uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("missingelement1", "", HSSConnection::REG, regstate, "server_name", ifcs_map, uris, 0);
  EXPECT_TRUE(uris.get_unbarred_uris().empty());
  EXPECT_TRUE(log.contains("Malformed Homestead XML"));
}

TEST_F(HssConnectionTest, BadXML_MissingClearwaterRegData)
{
  CapturingTestLogger log;
  AssociatedURIs uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("missingelement3", "", HSSConnection::REG, regstate, "server_name", ifcs_map, uris, 0);
  EXPECT_TRUE(uris.get_unbarred_uris().empty());
  EXPECT_TRUE(log.contains("Malformed Homestead XML"));
}

TEST_F(HssConnectionTest, BadXML_MissingIMSSubscription)
{
  CapturingTestLogger log;
  AssociatedURIs uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("missingelement2", "", HSSConnection::REG, regstate, "server_name", ifcs_map, uris, 0);
  EXPECT_TRUE(uris.get_unbarred_uris().empty());
  EXPECT_TRUE(log.contains("Malformed HSS XML"));
}


TEST_F(HssConnectionTest, ServerFailure)
{
  CapturingTestLogger log;
  AssociatedURIs uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;
  _hss.update_registration_state("pubid44", "", HSSConnection::REG, regstate, "server_name", ifcs_map, uris, 0);
  EXPECT_EQ("", regstate);
  EXPECT_TRUE(uris.get_unbarred_uris().empty());
  EXPECT_TRUE(log.contains("http://narcissus/impu/pubid44/reg-data failed"));
}

TEST_F(HssConnectionTest, SimpleUserAuth)
{
  rapidjson::Document* actual;
  _hss.get_user_auth_status("privid69", "pubid44", "", "", false, actual, 0);
  ASSERT_TRUE(actual != NULL);
  EXPECT_EQ(std::string("server-name"), (*actual)["scscf"].GetString());
  delete actual;
}

TEST_F(HssConnectionTest, FullUserAuth)
{
  rapidjson::Document* actual;
  _hss.get_user_auth_status("privid69", "pubid44", "domain", "REG", false, actual, 0);
  ASSERT_TRUE(actual != NULL);
  EXPECT_EQ(2001, (*actual)["result-code"].GetInt());
  delete actual;
}

TEST_F(HssConnectionTest, CorruptAuth)
{
  CapturingTestLogger log;
  rapidjson::Document* actual;
  _hss.get_user_auth_status("privid_corrupt", "pubid44", "", "", false, actual, 0);
  ASSERT_TRUE(actual == NULL);
  EXPECT_TRUE(log.contains("Failed to parse Homestead response"));
  delete actual;
}

TEST_F(HssConnectionTest, EmergencyAuth)
{
  // Checks that when emergency is set to true that we query the HSS with the
  // "sos=true" parameter.
  rapidjson::Document* actual;
  _hss.get_user_auth_status("privid69", "pubid44", "", "", true, actual, 0);
  Request& request = fakecurl_requests["http://narcissus:80/impi/privid69/registration-status?impu=pubid44&sos=true"];
  EXPECT_EQ("GET", request._method);
  ASSERT_TRUE(actual != NULL);
  EXPECT_EQ(std::string("server-name"), (*actual)["scscf"].GetString());
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
  AssociatedURIs unused_uris;
  std::deque<std::string> unused_deque;
  _hss.update_registration_state("pubid46",
                                 "",
                                 HSSConnection::CALL,
                                 regstate,
                                 "server_name",
                                 ifcs_map,
                                 unused_uris,
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
  AssociatedURIs unused_uris;
  std::deque<std::string> unused_deque;
  HTTPCode rc = _hss.update_registration_state("public-needs-private",
                                               "a-private-id",
                                               HSSConnection::REG,
                                               regstate,
                                               "server_name",
                                               ifcs_map,
                                               unused_uris,
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

/// Fake iFCs to use to test Shared iFCs.
std::string ifc_priority_one = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                               "<InitialFilterCriteria>\n"
                               "  <Priority>1</Priority>\n"
                               "  <ApplicationServer>\n"
                               "    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                               "  </ApplicationServer>\n"
                               "</InitialFilterCriteria>";
std::string ifc_priority_two = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                               "<InitialFilterCriteria>\n"
                               "  <Priority>2</Priority>\n"
                               "  <ApplicationServer>\n"
                               "    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                               "  </ApplicationServer>\n"
                               "</InitialFilterCriteria>";

/// Fixture for HssWithSifcTest.
class HssWithSifcTest : public BaseTest
{
  FakeHttpResolver _resolver;
  HSSConnection _sifc_hss;
  MockSIFCService _sifc_service;
  rapidxml::xml_document<>* _root_one;
  rapidxml::xml_document<>* _root_two;
  Ifc* _ifc_one;
  Ifc* _ifc_two;

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
              &_sifc_service,
              500)
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

    _root_one = new rapidxml::xml_document<>;
    _root_one->parse<0>(_root_one->allocate_string(ifc_priority_one.c_str()));
    _ifc_one = new Ifc(_root_one->first_node("InitialFilterCriteria"));
    _root_two = new rapidxml::xml_document<>;
    _root_two->parse<0>(_root_two->allocate_string(ifc_priority_two.c_str()));
    _ifc_two = new Ifc(_root_two->first_node("InitialFilterCriteria"));
  }

  virtual ~HssWithSifcTest()
  {
    delete _root_one;
    delete _ifc_one;
    delete _root_two;
    delete _ifc_two;
  }
};

// In the following tests, the parsing of Shared iFCs from the User-Data AVP is
// teested. It is checked that the correct Shared iFC sets are determined from
// the AVP, however the conversion of these set ids into lists of distinct iFCs
// is not tested here, it is tested in sifcservice_test.cpp. In these tests,
// this functionality is mocked out.

// Check that some iFCs are returned when a shared iFC set is encountered.
TEST_F(HssWithSifcTest, SimpleSiFC)
{
  AssociatedURIs uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;

  std::multimap<int32_t, Ifc> ifcs_from_id;
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(1, *_ifc_one));
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(2, *_ifc_two));
  // Expect input of one shared iFC set, with set id 10.
  const std::set<int32_t> ids = {10};
  EXPECT_CALL(_sifc_service, get_ifcs_from_id(_, ids, _, _))
    .WillOnce(SetArgReferee<0>(std::multimap<int32_t, Ifc>(ifcs_from_id)));

  // Send in a message, and check that two iFCs are now present in the map.
  _sifc_hss.update_registration_state("onesifc", "", HSSConnection::REG, regstate, "server_name", ifcs_map, uris, 0);
  EXPECT_TRUE(ifcs_map.begin()->second.size() == 2);
}

// Check that SiFCs are compatible with iFCs.
TEST_F(HssWithSifcTest, SifcWithIfc)
{
  AssociatedURIs uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;

  std::multimap<int32_t, Ifc> ifcs_from_id;
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(1, *_ifc_one));
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(2, *_ifc_two));
  // Expect input of one shared iFC set with set id of 0.
  const std::set<int32_t> ids = {0};
  EXPECT_CALL(_sifc_service, get_ifcs_from_id(_, ids, _, _))
    .WillOnce(SetArgReferee<0>(std::multimap<int32_t, Ifc>(ifcs_from_id)));

  // Send in a message, and check that three iFCs are now present in the map,
  // two from the SiFC set, and one regular iFC.
  _sifc_hss.update_registration_state("sifcandifc", "", HSSConnection::REG, regstate, "server_name", ifcs_map, uris, 0);
  EXPECT_TRUE(ifcs_map.begin()->second.size() == 3);
}

// Check that an invalid SiFC, that is not an integer, is not accepted.
TEST_F(HssWithSifcTest, NonIntegerSifc)
{
  AssociatedURIs uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;

  // Send in a message, and check that the iFC map is still empty.
  _sifc_hss.update_registration_state("invalidsifc", "", HSSConnection::REG, regstate, "server_name", ifcs_map, uris, 0);
  EXPECT_TRUE(ifcs_map.begin()->second.size() == 0);
}

// Check that shared iFCs are read out from all Extensions present in the XML.
TEST_F(HssWithSifcTest, MultipleExtensions)
{
  AssociatedURIs uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;

  // The list returned here will be passed back into the function when the
  // second Extension is encountered. For this reason, don't bother returning
  // anything at this point.
  std::multimap<int32_t, Ifc> ifc_list_one;
  const std::set<int32_t> set_list_one = {1, 2};
  EXPECT_CALL(_sifc_service, get_ifcs_from_id(_, set_list_one, _, _))
    .WillOnce(SetArgReferee<0>(std::multimap<int32_t, Ifc>(ifc_list_one)));

  // Any iFCs from the first Shared iFC sets will be passed into this function.
  // More iFCs will then be added to this list and returned.
  // So the list returned here represents the iFC from sets 1, 2 and 10.
  std::multimap<int32_t, Ifc> ifc_list_two;
  ifc_list_two.insert(std::pair<int32_t, Ifc>(1, *_ifc_one));
  ifc_list_two.insert(std::pair<int32_t, Ifc>(2, *_ifc_two));
  ifc_list_two.insert(std::pair<int32_t, Ifc>(2, *_ifc_two));
  const std::set<int32_t> set_list_two = {10};
  EXPECT_CALL(_sifc_service, get_ifcs_from_id(_, set_list_two, _, _))
    .WillOnce(SetArgReferee<0>(std::multimap<int32_t, Ifc>(ifc_list_two)));

  // Send in a message, and check that three iFCs are now in the iFC map.
  _sifc_hss.update_registration_state("multipleextensions", "", HSSConnection::REG, regstate, "server_name", ifcs_map, uris, 0);
  EXPECT_TRUE(ifcs_map.begin()->second.size() == 3);
}

// Check that multiple shared iFCs are parsed correctly.
TEST_F(HssWithSifcTest, MultipleSifcs)
{
  AssociatedURIs uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;

  std::multimap<int32_t, Ifc> ifcs_from_id;
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(2, *_ifc_two));
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(2, *_ifc_two));
  // Expect input of two shared iFC sets, with set ids 1 and 2.
  const std::set<int32_t> ids = {1, 2};
  EXPECT_CALL(_sifc_service, get_ifcs_from_id(_, ids, _, _))
    .WillOnce(SetArgReferee<0>(std::multimap<int32_t, Ifc>(ifcs_from_id)));

  // Send in a message, and check that two iFCs are now in the iFC map.
  _sifc_hss.update_registration_state("multiplesifc", "", HSSConnection::REG, regstate, "server_name", ifcs_map, uris, 0);
  EXPECT_TRUE(ifcs_map.begin()->second.size() == 2);
}

// Check that shared iFCs are parsed correctly when multiple public ids are
// present, both within the same ServiceProfile, and within seperate
// ServiceProfiles.
TEST_F(HssWithSifcTest, MultiplePubIdsWithSifcs)
{
  AssociatedURIs uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;

  std::multimap<int32_t, Ifc> ifcs_from_id;
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(2, *_ifc_two));
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(2, *_ifc_two));
  // Expect input of one shared iFC set; with an id of 1 for one service
  // profile, and 2 for the other.
  const std::set<int32_t> id_set_one = {1};
  const std::set<int32_t> id_set_two = {2};
  EXPECT_CALL(_sifc_service, get_ifcs_from_id(_, id_set_one, _, _))
    .WillOnce(SetArgReferee<0>(std::multimap<int32_t, Ifc>(ifcs_from_id)));
  EXPECT_CALL(_sifc_service, get_ifcs_from_id(_, id_set_two, _, _))
    .WillOnce(SetArgReferee<0>(std::multimap<int32_t, Ifc>(ifcs_from_id)));

  // The iFC map composes of keys, which are public ids, and their values, which
  // are the lists of iFCs that correspond to that public id.
  // Send in a message, and loop through the map checking that the correct
  // number of iFCs are present for each public id.
  _sifc_hss.update_registration_state("multiplepubids", "", HSSConnection::REG, regstate, "server_name", ifcs_map, uris, 0);
  for(std::pair<std::string, Ifcs> elem : ifcs_map)
  {
    EXPECT_TRUE(elem.second.size() == 2);
  }
}

// Check that shared iFCs are parsed correctly when mixed with a complex set of
// iFCs.
TEST_F(HssWithSifcTest, ComplexSifcIfcMix)
{
  AssociatedURIs uris;
  std::map<std::string, Ifcs> ifcs_map;
  std::string regstate;

  std::multimap<int32_t, Ifc> ifcs_from_id;
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(1, *_ifc_one));
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(2, *_ifc_two));
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(2, *_ifc_two));
  // Expect input of two shared iFC sets, with ids 3 and 4.
  const std::set<int32_t> id_set_one = {3, 4};
  EXPECT_CALL(_sifc_service, get_ifcs_from_id(_, id_set_one, _, _))
    .WillOnce(SetArgReferee<0>(std::multimap<int32_t, Ifc>(ifcs_from_id)));

  // Send in a message, and check the expected number of iFCs are present, as
  // well as checking that the expected number with each priority are present.
  // 6 distinct iFCs with priorities 1, 1, 2, 3, 3 and 4 should be returned.
  // Additionally 3 iFCs from shared iFCs with priorities 1, 2 and 2 should be
  // returned.
  _sifc_hss.update_registration_state("sifcifcmix", "", HSSConnection::REG, regstate, "server_name", ifcs_map, uris, 0);
  int32_t map_size = ifcs_map.begin()->second.size();
  EXPECT_TRUE(map_size == 9);
  std::vector<int32_t> priorities;
  for (int32_t ii = 0; ii < map_size; ii++)
  {
    const Ifc& ifc = ifcs_map.begin()->second[ii];
    if (ifc._ifc->first_node("Priority"))
    {
      int32_t priority = std::atoi(ifc._ifc->first_node("Priority")->value());
      priorities.push_back(priority);
    }
  }
  std::vector<int32_t> expected_priorities = {1, 1, 1, 2, 2, 2, 3, 3, 4};
  EXPECT_THAT(expected_priorities, UnorderedElementsAreArray(priorities));
}

