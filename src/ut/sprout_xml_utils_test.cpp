/**
 * @file sprout_xml_utils_test.cpp
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <string>
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "sprout_xml_utils.h"

//using namespace XMLUtils;

/*std::string COM = ""
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
*/

/// Fixture for SproutXMLUtilsTest.
class SproutXMLUtilsTest : public ::testing::Test
{
  SproutXMLUtilsTest()
  {
  }

  virtual ~SproutXMLUtilsTest()
  {
  }

  // All of these tests

  void check_expectations(std::string xml,
                          bool successful,
                          std::string impu,
                          std::map<std::string, Ifcs> exp_ifcs_map = {},
                          AssociatedURIs exp_associated_uris = {},
                          std::vector<std::string> exp_aliases = {})
  {
    std::shared_ptr<rapidxml::xml_document<> > root (new rapidxml::xml_document<>);
    char* cstr_xml = strdup(xml.c_str());
    root->parse<0>(cstr_xml);
    rapidxml::xml_node<>* node = root->first_node(RegDataXMLUtils::IMS_SUBSCRIPTION);

    std::map<std::string, Ifcs> ifcs_map;
    AssociatedURIs associated_uris;
    std::vector<std::string> aliases;

    bool rc = SproutXmlUtils::parse_ims_subscription(impu,
                                                     root,
                                                     node,
                                                     ifcs_map,
                                                     associated_uris,
                                                     aliases,
                                                     NULL,  // TODO make mock SIFC? Prob not.
                                                     0);

    EXPECT_EQ(successful, rc);

    if (successful)
    {
      // EXPECT_EQ(exp_ifcs_map, ifcs_map);
      // EM-TODO: EXPECT_EQ(exp_associated_uris, associated_uris);

      std::sort(aliases.begin(), aliases.end());
      std::sort(exp_aliases.begin(), exp_aliases.end());
      EXPECT_EQ(exp_aliases, aliases);
    }

    free(cstr_xml);
  }

};

TEST_F(SproutXMLUtilsTest, MissingServiceProfile)
{
  std::string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    "<IMSSubscription>"
                    "NaN"
                    "</IMSSubscription>";
  check_expectations(xml, false, "test");
}

TEST_F(SproutXMLUtilsTest, MissingPublicIdentity)
{
  std::string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    "<IMSSubscription>"
                    "<ServiceProfile>NaN</ServiceProfile>"
                    "</IMSSubscription>";
  check_expectations(xml, false, "test");
}

TEST_F(SproutXMLUtilsTest, MissingPublicIdentityIdentity)
{
  std::string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    "<IMSSubscription>"
                    "<ServiceProfile>"
                    "<PublicIdentity>NaN</PublicIdentity>"
                    "</ServiceProfile>"
                    "</IMSSubscription>";
  check_expectations(xml, false, "test");
}

TEST_F(SproutXMLUtilsTest, SimpleMainline)
{
  std::string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
       "<IMSSubscription>"
         "<ServiceProfile>"
           "<PublicIdentity>"
              "<Identity>sip:123@example.com</Identity>"
           "</PublicIdentity>"
           "<PublicIdentity>"
             "<Identity>sip:1234@example.com</Identity>"
             "<Extension>"
               "<IdentityType>"
                 "3"
               "</IdentityType>"
               "<Extension>"
                 "<Extension>"
                   "<WildcardedIMPU>"
                     "sip:12!.*!@example.com"
                   "</WildcardedIMPU>"
                 "</Extension>"
               "</Extension>"
             "</Extension>"
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
         "</ServiceProfile>"
         "<ServiceProfile>"
           "<PublicIdentity>"
              "<Identity>sip:223@example.com</Identity>"
              "<BarringIndication>0</BarringIndication>"
           "</PublicIdentity>"
           "<PublicIdentity>"
              "<Identity>sip:2234@example.com</Identity>"
              "<BarringIndication>1</BarringIndication>"
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
         "</ServiceProfile>"
         "<ServiceProfile>"
           "<PublicIdentity>"
              "<Identity>sip:12@example.com</Identity>"
              "<BarringIndication>0</BarringIndication>"
           "</PublicIdentity>"
           "<PublicIdentity>"
              "<Identity>sip:2234@example.com</Identity>"
              "<BarringIndication>1</BarringIndication>"
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
         "</ServiceProfile>"
       "</IMSSubscription>";

  std::map<std::string, Ifcs> exp_ifcs_map;
  AssociatedURIs exp_associated_uris;

  std::vector<std::string> exp_aliases;
  exp_aliases.push_back("sip:2234@example.com");
  exp_aliases.push_back("sip:12@example.com");

  check_expectations(xml, true, "sip:12@example.com", exp_ifcs_map, exp_associated_uris, exp_aliases);
}
