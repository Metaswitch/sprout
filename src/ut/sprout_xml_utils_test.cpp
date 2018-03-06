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

/// Fixture for SproutXMLUtilsTest.
class SproutXMLUtilsTest : public ::testing::Test
{
  SproutXMLUtilsTest()
  {
  }

  virtual ~SproutXMLUtilsTest()
  {
  }

  void check_parse_ims_subscription_failure(const std::string& xml,
                                            const std::string& impu)
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
                                                     NULL,
                                                     0);

    EXPECT_FALSE(rc);

    free(cstr_xml);
  }

  void check_parse_ims_subscription_success(const std::string& xml,
                                            const std::string& impu,
                                            const AssociatedURIs& exp_associated_uris,
                                            std::vector<std::string>& exp_aliases)
  {
    std::shared_ptr<rapidxml::xml_document<> > root (new rapidxml::xml_document<>);
    char* cstr_xml = strdup(xml.c_str());
    root->parse<0>(cstr_xml);
    rapidxml::xml_node<>* node = root->first_node(RegDataXMLUtils::IMS_SUBSCRIPTION);

    std::map<std::string, Ifcs> ifcs_map;
    AssociatedURIs associated_uris = AssociatedURIs();
    std::vector<std::string> aliases;

    bool rc = SproutXmlUtils::parse_ims_subscription(impu,
                                                     root,
                                                     node,
                                                     ifcs_map,
                                                     associated_uris,
                                                     aliases,
                                                     NULL,
                                                     0);

    EXPECT_TRUE(rc);

    EXPECT_TRUE(exp_associated_uris == associated_uris);
    std::sort(aliases.begin(), aliases.end());
    std::sort(exp_aliases.begin(), exp_aliases.end());
    EXPECT_EQ(exp_aliases, aliases);

    free(cstr_xml);
  }
};

TEST_F(SproutXMLUtilsTest, MissingServiceProfile)
{
  std::string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    "<IMSSubscription>"
                    "NaN"
                    "</IMSSubscription>";
  check_parse_ims_subscription_failure(xml, "test");
}

TEST_F(SproutXMLUtilsTest, MissingPublicIdentity)
{
  std::string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    "<IMSSubscription>"
                    "<ServiceProfile>NaN</ServiceProfile>"
                    "</IMSSubscription>";
  check_parse_ims_subscription_failure(xml, "test");
}

TEST_F(SproutXMLUtilsTest, MissingPublicIdentityIdentity)
{
  std::string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    "<IMSSubscription>"
                    "<ServiceProfile>"
                    "<PublicIdentity>NaN</PublicIdentity>"
                    "</ServiceProfile>"
                    "</IMSSubscription>";
  check_parse_ims_subscription_failure(xml, "test");
}

TEST_F(SproutXMLUtilsTest, AmbiguousWildcardMatch)
{
  std::string xml =
     "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
       "<IMSSubscription>"
         "<ServiceProfile>"
           "<PublicIdentity>"
              "<Identity>sip:123@example.com</Identity>"
           "</PublicIdentity>"
           "<PublicIdentity>"
             "<Identity>sip:12!.*!@example.com</Identity>"
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
              "<Identity>sip:1235@example.com</Identity>"
           "</PublicIdentity>"
           "<PublicIdentity>"
             "<Identity>sip:123!.*!@example.com</Identity>"
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

  AssociatedURIs exp_associated_uris;
  exp_associated_uris.add_uri("sip:12!.*!@example.com", false);
  exp_associated_uris.add_uri("sip:123@example.com", false);
  exp_associated_uris.add_uri("sip:123!.*!@example.com", false);
  exp_associated_uris.add_uri("sip:1235@example.com", false);
  std::vector<std::string> exp_aliases;
  exp_aliases.push_back("sip:12!.*!@example.com");
  exp_aliases.push_back("sip:123@example.com");

  check_parse_ims_subscription_success(xml, "sip:1234@example.com", exp_associated_uris, exp_aliases);
}

TEST_F(SproutXMLUtilsTest, MultipleServiceProfiles)
{
  std::string xml =
     "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
       "<IMSSubscription>"
         "<ServiceProfile>"
           "<PublicIdentity>"
              "<Identity>sip:123@example.com</Identity>"
           "</PublicIdentity>"
           "<PublicIdentity>"
             "<Identity>sip:124@example.com</Identity>"
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
              "<Identity>sip:1235@example.com</Identity>"
           "</PublicIdentity>"
           "<PublicIdentity>"
             "<Identity>sip:1234@example.com</Identity>"
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

  AssociatedURIs exp_associated_uris;
  exp_associated_uris.add_uri("sip:1235@example.com", false);
  exp_associated_uris.add_uri("sip:124@example.com", false);
  exp_associated_uris.add_uri("sip:123@example.com", false);
  exp_associated_uris.add_uri("sip:1234@example.com", false);

  std::vector<std::string> exp_aliases;
  exp_aliases.push_back("sip:1234@example.com");
  exp_aliases.push_back("sip:1235@example.com");

  check_parse_ims_subscription_success(xml, "sip:1234@example.com", exp_associated_uris, exp_aliases);
}

TEST_F(SproutXMLUtilsTest, MultipleServiceProfilesWildcardMatch)
{
  std::string xml =
     "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
       "<IMSSubscription>"
         "<ServiceProfile>"
           "<PublicIdentity>"
              "<Identity>sip:123@example.com</Identity>"
           "</PublicIdentity>"
           "<PublicIdentity>"
              "<Identity>sip:11!.*!@example.com</Identity>"
           "</PublicIdentity>"
           "<PublicIdentity>"
             "<Identity>sip:124@example.com</Identity>"
             "<Extension>"
               "<IdentityType>"
                 "3"
               "</IdentityType>"
               "<Extension>"
                 "<Extension>"
                   "<WildcardedIMPU>"
                     "sip:11!.*!@example.com"
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
              "<Identity>sip:1235@example.com</Identity>"
           "</PublicIdentity>"
           "<PublicIdentity>"
             "<Identity>sip:123!.*!@example.com</Identity>"
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

  AssociatedURIs exp_associated_uris;
  exp_associated_uris.add_uri("sip:11!.*!@example.com", false);
  exp_associated_uris.add_uri("sip:123@example.com", false);
  exp_associated_uris.add_uri("sip:123!.*!@example.com", false);
  exp_associated_uris.add_uri("sip:1235@example.com", false);

  std::vector<std::string> exp_aliases;
  exp_aliases.push_back("sip:123!.*!@example.com");
  exp_aliases.push_back("sip:1235@example.com");

  check_parse_ims_subscription_success(xml, "sip:1234@example.com", exp_associated_uris, exp_aliases);
}

TEST_F(SproutXMLUtilsTest, BarringStatus)
{
  std::string xml =
     "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
       "<IMSSubscription>"
         "<ServiceProfile>"
           "<PublicIdentity>"
              "<Identity>sip:1234@example.com</Identity>"
           "</PublicIdentity>"
           "<PublicIdentity>"
             "<Identity>sip:12!.*!@example.com</Identity>"
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
             "<Identity>sip:1235@example.com</Identity>"
             "<BarringIndication>1</BarringIndication>"
           "</PublicIdentity>"
           "<PublicIdentity>"
             "<Identity>sip:11!.*!@example.com</Identity>"
             "<BarringIndication>0</BarringIndication>"
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

  AssociatedURIs exp_associated_uris;
  exp_associated_uris.add_uri("sip:12!.*!@example.com", true);
  exp_associated_uris.add_uri("sip:1234@example.com", false);
  exp_associated_uris.add_uri("sip:11!.*!@example.com", false);
  exp_associated_uris.add_uri("sip:1235@example.com", true);
  std::vector<std::string> exp_aliases;
  exp_aliases.push_back("sip:12!.*!@example.com");
  exp_aliases.push_back("sip:1234@example.com");

  check_parse_ims_subscription_success(xml, "sip:1234@example.com", exp_associated_uris, exp_aliases);
}

TEST_F(SproutXMLUtilsTest, NoMatch)
{
  std::string xml =
     "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
       "<IMSSubscription>"
         "<ServiceProfile>"
           "<PublicIdentity>"
              "<Identity>sip:123@example.com</Identity>"
           "</PublicIdentity>"
           "<PublicIdentity>"
             "<Identity>sip:124@example.com</Identity>"
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

  AssociatedURIs exp_associated_uris = AssociatedURIs();
  exp_associated_uris.add_uri("sip:123@example.com", false);
  exp_associated_uris.add_uri("sip:124@example.com", false);
  std::vector<std::string> exp_aliases;

  check_parse_ims_subscription_success(xml, "sip:1234@example.com", exp_associated_uris, exp_aliases);
}

TEST_F(SproutXMLUtilsTest, WildcardMatchOverridden)
{
  std::string xml =
     "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
       "<IMSSubscription>"
         "<ServiceProfile>"
           "<PublicIdentity>"
              "<Identity>sip:1!.*!@example.com</Identity>"
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
              "<Identity>sip:1234@example.com</Identity>"
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

  AssociatedURIs exp_associated_uris;
  exp_associated_uris.add_uri("sip:1!.*!@example.com", false);
  exp_associated_uris.add_uri("sip:1234@example.com", false);
  std::vector<std::string> exp_aliases;
  exp_aliases.push_back("sip:1234@example.com");

  check_parse_ims_subscription_success(xml, "sip:1234@example.com", exp_associated_uris, exp_aliases);
}
