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
        "<PreviousRegistrationState>NOT_REGISTERED</PreviousRegistrationState>"
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
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/pubid42_rereg/reg-data", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<ClearwaterRegData>"
        "<RegistrationState>REGISTERED</RegistrationState>"
        "<PreviousRegistrationState>REGISTERED</PreviousRegistrationState>"
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

    std::string missing_ims_subscription =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<ClearwaterRegData>"
        "<RegistrationState>NOT_REGISTERED</RegistrationState>"
      "</ClearwaterRegData>";
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/pubid48/reg-data", "{\"reqtype\": \"dereg-auth-timeout\", \"server_name\": \"server_name\"}")] =
      missing_ims_subscription;
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/pubid48/reg-data", "{\"reqtype\": \"dereg-auth-failed\", \"server_name\": \"server_name\"}")] =
      missing_ims_subscription;

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

    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/missing_ims_subscription/reg-data", "{\"reqtype\": \"reg\", \"server_name\": \"server_name\"}")] =
      missing_ims_subscription;
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/missing_ims_subscription/reg-data", "{\"reqtype\": \"call\", \"server_name\": \"server_name\"}")] =
      missing_ims_subscription;
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/missing_ims_subscription/reg-data", "{\"reqtype\": \"dereg-admin\", \"server_name\": \"server_name\"}")] =
      missing_ims_subscription;
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/missing_ims_subscription/reg-data", "{\"reqtype\": \"dereg-user\", \"server_name\": \"server_name\"}")] =
      missing_ims_subscription;
    fakecurl_responses_with_body[std::make_pair("http://10.42.42.42:80/impu/missing_ims_subscription/reg-data", "{\"reqtype\": \"dereg-timeout\", \"server_name\": \"server_name\"}")] =
      missing_ims_subscription;

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
  HSSConnection::irs_query irs_query;
  HSSConnection::irs_info irs_info;
  
  _hss.get_registration_data("pubid42", irs_info, 0);

  EXPECT_EQ("REGISTERED", irs_info._regstate);
  ASSERT_EQ(2u, irs_info._associated_uris.get_unbarred_uris().size());
  EXPECT_EQ("sip:123@example.com", irs_info._associated_uris.get_unbarred_uris()[0]);
  EXPECT_EQ("sip:456@example.com", irs_info._associated_uris.get_unbarred_uris()[1]);
}

TEST_F(HssConnectionTest, SimpleNotRegisteredGet)
{
  HSSConnection::irs_query irs_query;
  HSSConnection::irs_info irs_info;

  _hss.get_registration_data("pubid43", irs_info, 0);

  EXPECT_EQ("NOT_REGISTERED", irs_info._regstate);
  EXPECT_EQ(0u, irs_info._associated_uris.get_unbarred_uris().size());
}

TEST_F(HssConnectionTest, SimpleAuthenticationTimeout)
{
  HSSConnection::irs_query irs_query;
  irs_query._public_id = "pubid48";
  irs_query._req_type = HSSConnection::AUTH_TIMEOUT;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  HTTPCode rc =_hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_EQ("NOT_REGISTERED", irs_info._regstate);
  EXPECT_TRUE(irs_info._service_profiles.empty());
  EXPECT_TRUE(rc == 200); 
}

TEST_F(HssConnectionTest, SimpleAuthenticationFail)
{
  HSSConnection::irs_query irs_query;
  irs_query._public_id = "pubid48";
  irs_query._req_type = HSSConnection::AUTH_FAIL;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  HTTPCode rc =_hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_EQ("NOT_REGISTERED", irs_info._regstate);
  EXPECT_TRUE(irs_info._service_profiles.empty());
  EXPECT_TRUE(rc == 200); 
}

TEST_F(HssConnectionTest, SimpleUnregistered)
{
  HSSConnection::irs_query irs_query;
  irs_query._public_id = "pubid50";
  irs_query._req_type = HSSConnection::CALL;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  _hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_EQ("UNREGISTERED", irs_info._regstate);
}

TEST_F(HssConnectionTest, SimpleNotRegisteredUpdate)
{
  HSSConnection::irs_query irs_query;
  irs_query._public_id = "pubid50";
  irs_query._req_type = HSSConnection::DEREG_ADMIN;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  _hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_EQ("NOT_REGISTERED", irs_info._regstate);
  EXPECT_TRUE(irs_info._service_profiles.empty());
}

TEST_F(HssConnectionTest, SimpleIfc)
{
  HSSConnection::irs_query irs_query;
  irs_query._public_id = "pubid42";
  irs_query._req_type = HSSConnection::REG;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  _hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_EQ("NOT_REGISTERED", irs_info._prev_regstate);
  EXPECT_EQ("REGISTERED", irs_info._regstate);
  EXPECT_FALSE(irs_info._service_profiles.empty());
}

TEST_F(HssConnectionTest, SimpleIfcReReg)
{
  HSSConnection::irs_query irs_query;
  irs_query._public_id = "pubid42_rereg";
  irs_query._req_type = HSSConnection::REG;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  _hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_EQ("REGISTERED", irs_info._prev_regstate);
  EXPECT_EQ("REGISTERED", irs_info._regstate);
  EXPECT_FALSE(irs_info._service_profiles.empty());
}

TEST_F(HssConnectionTest, SimpleChargingAddrs)
{
  std::deque<std::string> actual_ccfs = {"ccf1", "ccf2"};
  std::deque<std::string> actual_ecfs = {"ecf1", "ecf2"};

  HSSConnection::irs_query irs_query;
  irs_query._public_id = "pubid42";
  irs_query._req_type = HSSConnection::REG;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  _hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_EQ(actual_ccfs, irs_info._ccfs);
  EXPECT_EQ(actual_ecfs, irs_info._ecfs);
}

TEST_F(HssConnectionTest, ServerName)
{
  // Checks that we can request a different server name.
  HSSConnection::irs_query irs_query;
  irs_query._public_id = "pubid51";
  irs_query._req_type = HSSConnection::CALL;
  irs_query._server_name = "sip:scscf.sprout.homedomain;transport=TCP";
  HSSConnection::irs_info irs_info;

  _hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_EQ("REGISTERED", irs_info._regstate);
}

TEST_F(HssConnectionTest, Barring)
{
  // Checks that the BarringIndication field from the HSS is parsed correctly.
  HSSConnection::irs_query irs_query;
  irs_query._public_id = "pubid47";
  irs_query._req_type = HSSConnection::REG;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  _hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_EQ("REGISTERED", irs_info._regstate);
  ASSERT_EQ(1u, irs_info._associated_uris.get_unbarred_uris().size());
  EXPECT_FALSE(irs_info._associated_uris.is_impu_barred("sip:123@example.com"));
  EXPECT_TRUE(irs_info._associated_uris.is_impu_barred("sip:456@example.com"));
}

TEST_F(HssConnectionTest, BadXML)
{
  CapturingTestLogger log;

  HSSConnection::irs_query irs_query;
  irs_query._public_id = "pubid42_malformed";
  irs_query._req_type = HSSConnection::REG;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  _hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_TRUE(irs_info._associated_uris.get_unbarred_uris().empty());
  EXPECT_TRUE(log.contains("Failed to parse Homestead response"));
}


TEST_F(HssConnectionTest, BadXML2)
{
  CapturingTestLogger log;

  HSSConnection::irs_query irs_query;
  irs_query._public_id = "pubid43_malformed";
  irs_query._req_type = HSSConnection::REG;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  _hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_TRUE(irs_info._associated_uris.get_unbarred_uris().empty());
  EXPECT_TRUE(log.contains("Malformed HSS XML"));
}

TEST_F(HssConnectionTest, BadXML_MissingServiceProfile)
{
  CapturingTestLogger log;

  HSSConnection::irs_query irs_query;
  irs_query._public_id = "missingelement4";
  irs_query._req_type = HSSConnection::REG;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  _hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_TRUE(irs_info._associated_uris.get_unbarred_uris().empty());
  EXPECT_TRUE(log.contains("Malformed HSS XML"));
}

TEST_F(HssConnectionTest, BadXML_MissingPublicIdentity)
{
  CapturingTestLogger log;

  HSSConnection::irs_query irs_query;
  irs_query._public_id = "missingelement5";
  irs_query._req_type = HSSConnection::REG;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  _hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_TRUE(irs_info._associated_uris.get_unbarred_uris().empty());
  EXPECT_TRUE(log.contains("Malformed ServiceProfile XML"));
}

TEST_F(HssConnectionTest, BadXML_MissingIdentity)
{
  CapturingTestLogger log;

  HSSConnection::irs_query irs_query;
  irs_query._public_id = "missingelement6";
  irs_query._req_type = HSSConnection::REG;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  _hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_TRUE(irs_info._associated_uris.get_unbarred_uris().empty());
  EXPECT_TRUE(log.contains("Malformed PublicIdentity XML"));
}

TEST_F(HssConnectionTest, BadXML_MissingRegistrationState)
{
  CapturingTestLogger log;

  HSSConnection::irs_query irs_query;
  irs_query._public_id = "missingelement1";
  irs_query._req_type = HSSConnection::REG;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  _hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_TRUE(irs_info._associated_uris.get_unbarred_uris().empty());
  EXPECT_TRUE(log.contains("Malformed Homestead XML"));
}

TEST_F(HssConnectionTest, BadXML_MissingClearwaterRegData)
{
  CapturingTestLogger log;

  HSSConnection::irs_query irs_query;
  irs_query._public_id = "missingelement3";
  irs_query._req_type = HSSConnection::REG;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  _hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_TRUE(irs_info._associated_uris.get_unbarred_uris().empty());
  EXPECT_TRUE(log.contains("Malformed Homestead XML"));
}

TEST_F(HssConnectionTest, BadXML_MissingIMSSubscription_Reg)
{
  HSSConnection::irs_query irs_query;
  irs_query._public_id = "missing_ims_subscription";
  irs_query._req_type = HSSConnection::REG;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  HTTPCode rc = _hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_TRUE(irs_info._service_profiles.empty());
  EXPECT_TRUE(rc == 500);
}

TEST_F(HssConnectionTest, BadXML_MissingIMSSubscription_Call)
{
  HSSConnection::irs_query irs_query;
  irs_query._public_id = "missing_ims_subscription";
  irs_query._req_type = HSSConnection::CALL;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  HTTPCode rc = _hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_TRUE(irs_info._service_profiles.empty());
  EXPECT_TRUE(rc == 500);
}

TEST_F(HssConnectionTest, BadXML_MissingIMSSubscription_DeregAdmin)
{
  HSSConnection::irs_query irs_query;
  irs_query._public_id = "missing_ims_subscription";
  irs_query._req_type = HSSConnection::DEREG_ADMIN;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  HTTPCode rc =_hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_TRUE(irs_info._service_profiles.empty());
  EXPECT_TRUE(rc == 500);
}

TEST_F(HssConnectionTest, BadXML_MissingIMSSubscription_DeregUser)
{
  HSSConnection::irs_query irs_query;
  irs_query._public_id = "missing_ims_subscription";
  irs_query._req_type = HSSConnection::DEREG_USER;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  HTTPCode rc = _hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_TRUE(irs_info._service_profiles.empty());
  EXPECT_TRUE(rc == 500);
}

TEST_F(HssConnectionTest, BadXML_MissingIMSSubscription_DeregTimeout)
{
  HSSConnection::irs_query irs_query;
  irs_query._public_id = "missing_ims_subscription";
  irs_query._req_type = HSSConnection::DEREG_TIMEOUT;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  HTTPCode rc = _hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_TRUE(irs_info._service_profiles.empty());
  EXPECT_TRUE(rc == 500);
}

TEST_F(HssConnectionTest, ServerFailure)
{
  CapturingTestLogger log;

  HSSConnection::irs_query irs_query;
  irs_query._public_id = "pubid44";
  irs_query._req_type = HSSConnection::REG;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  _hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_EQ("", irs_info._regstate);
  EXPECT_TRUE(irs_info._associated_uris.get_unbarred_uris().empty());
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
  HSSConnection::irs_query irs_query;
  irs_query._public_id = "pubid46";
  irs_query._req_type = HSSConnection::CALL;
  irs_query._server_name = "server_name";
  irs_query._cache_allowed = true;
  HSSConnection::irs_info irs_info;

  _hss.update_registration_state(irs_query, irs_info, 0);

  ASSERT_EQ(3u, irs_info._aliases.size());
  EXPECT_EQ("sip:321@example.com", irs_info._aliases[0]);
  EXPECT_EQ("pubid46", irs_info._aliases[1]);
  EXPECT_EQ("tel:321", irs_info._aliases[2]);
}

TEST_F(HssConnectionTest, CacheNotAllowed)
{
  HSSConnection::irs_query irs_query;
  irs_query._public_id = "public-needs-private";
  irs_query._private_id = "a-private-id";
  irs_query._req_type = HSSConnection::REG;
  irs_query._server_name = "server_name";
  irs_query._cache_allowed = false;
  HSSConnection::irs_info irs_info;

  HTTPCode rc = _hss.update_registration_state(irs_query, irs_info, 0);

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
  HSSConnection::irs_query irs_query;
  irs_query._public_id = "onesifc";
  irs_query._req_type = HSSConnection::REG;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  std::multimap<int32_t, Ifc> ifcs_from_id;
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(1, *_ifc_one));
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(2, *_ifc_two));
  // Expect input of one shared iFC set, with set id 10.
  const std::set<int32_t> ids = {10};
  EXPECT_CALL(_sifc_service, get_ifcs_from_id(_, ids, _, _))
    .WillOnce(SetArgReferee<0>(std::multimap<int32_t, Ifc>(ifcs_from_id)));

  // Send in a message, and check that two iFCs are now present in the map.
  _sifc_hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_TRUE(irs_info._service_profiles.begin()->second.size() == 2);
}

// Check that SiFCs are compatible with iFCs.
TEST_F(HssWithSifcTest, SifcWithIfc)
{
  HSSConnection::irs_query irs_query;
  irs_query._public_id = "sifcandifc";
  irs_query._req_type = HSSConnection::REG;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  std::multimap<int32_t, Ifc> ifcs_from_id;
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(1, *_ifc_one));
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(2, *_ifc_two));
  // Expect input of one shared iFC set with set id of 0.
  const std::set<int32_t> ids = {0};
  EXPECT_CALL(_sifc_service, get_ifcs_from_id(_, ids, _, _))
    .WillOnce(SetArgReferee<0>(std::multimap<int32_t, Ifc>(ifcs_from_id)));

  // Send in a message, and check that three iFCs are now present in the map,
  // two from the SiFC set, and one regular iFC.
  _sifc_hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_TRUE(irs_info._service_profiles.begin()->second.size() == 3);
}

// Check that an invalid SiFC, that is not an integer, is not accepted.
TEST_F(HssWithSifcTest, NonIntegerSifc)
{
  HSSConnection::irs_query irs_query;
  irs_query._public_id = "invalidsifc";
  irs_query._req_type = HSSConnection::REG;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  // Send in a message, and check that the iFC map is still empty.
  _sifc_hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_TRUE(irs_info._service_profiles.begin()->second.size() == 0);
}

// Check that shared iFCs are read out from all Extensions present in the XML.
TEST_F(HssWithSifcTest, MultipleExtensions)
{
  HSSConnection::irs_query irs_query;
  irs_query._public_id = "multipleextensions";
  irs_query._req_type = HSSConnection::REG;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

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
  _sifc_hss.update_registration_state(irs_query, irs_info, 0);

  EXPECT_TRUE(irs_info._service_profiles.begin()->second.size() == 3);
}

// Check that multiple shared iFCs are parsed correctly.
TEST_F(HssWithSifcTest, MultipleSifcs)
{
  HSSConnection::irs_query irs_query;
  irs_query._public_id = "multiplesifc";
  irs_query._req_type = HSSConnection::REG;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

  std::multimap<int32_t, Ifc> ifcs_from_id;
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(2, *_ifc_two));
  ifcs_from_id.insert(std::pair<int32_t, Ifc>(2, *_ifc_two));
  // Expect input of two shared iFC sets, with set ids 1 and 2.
  const std::set<int32_t> ids = {1, 2};
  EXPECT_CALL(_sifc_service, get_ifcs_from_id(_, ids, _, _))
    .WillOnce(SetArgReferee<0>(std::multimap<int32_t, Ifc>(ifcs_from_id)));

  // Send in a message, and check that two iFCs are now in the iFC map.
  _sifc_hss.update_registration_state(irs_query, irs_info, 0);
  EXPECT_TRUE(irs_info._service_profiles.begin()->second.size() == 2);
}

// Check that shared iFCs are parsed correctly when multiple public ids are
// present, both within the same ServiceProfile, and within seperate
// ServiceProfiles.
TEST_F(HssWithSifcTest, MultiplePubIdsWithSifcs)
{
  HSSConnection::irs_query irs_query;
  irs_query._public_id = "multiplepubids";
  irs_query._req_type = HSSConnection::REG;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

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
  _sifc_hss.update_registration_state(irs_query, irs_info, 0);
  for(std::pair<std::string, Ifcs> elem : irs_info._service_profiles)
  {
    EXPECT_TRUE(elem.second.size() == 2);
  }
}

// Check that shared iFCs are parsed correctly when mixed with a complex set of
// iFCs.
TEST_F(HssWithSifcTest, ComplexSifcIfcMix)
{
  HSSConnection::irs_query irs_query;
  irs_query._public_id = "sifcifcmix";
  irs_query._req_type = HSSConnection::REG;
  irs_query._server_name = "server_name";
  HSSConnection::irs_info irs_info;

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
  _sifc_hss.update_registration_state(irs_query, irs_info, 0);
  int32_t map_size = irs_info._service_profiles.begin()->second.size();
  EXPECT_TRUE(map_size == 9);
  std::vector<int32_t> priorities;
  for (int32_t ii = 0; ii < map_size; ii++)
  {
    const Ifc& ifc = irs_info._service_profiles.begin()->second[ii];
    if (ifc._ifc->first_node("Priority"))
    {
      int32_t priority = std::atoi(ifc._ifc->first_node("Priority")->value());
      priorities.push_back(priority);
    }
  }
  std::vector<int32_t> expected_priorities = {1, 1, 1, 2, 2, 2, 3, 3, 4};
  EXPECT_THAT(expected_priorities, UnorderedElementsAreArray(priorities));
}

