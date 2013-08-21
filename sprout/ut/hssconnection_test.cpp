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
#include "gtest/gtest.h"
#include <json/reader.h>

#include "utils.h"
#include "sas.h"
#include "hssconnection.h"
#include "basetest.hpp"
#include "fakecurl.hpp"
#include "fakelogger.hpp"

using namespace std;

/// Fixture for HssConnectionTest.
class HssConnectionTest : public BaseTest
{
  HSSConnection _hss;

  HssConnectionTest() :
    _hss("narcissus")
  {
    fakecurl_responses.clear();
    fakecurl_responses["http://narcissus/impi/privid69/digest"] = "{\"digest\": \"myhashhere\"}";
    fakecurl_responses["http://narcissus/impi/privid69/digest?public_id=pubid42"] = "{\"digest\": \"myhashhere\"}";
    fakecurl_responses["http://narcissus/impi/privid_corrupt/digest?public_id=pubid42"] = "{\"digest\"; \"myhashhere\"}";
    fakecurl_responses["http://narcissus/impi/privid69/digest?public_id=wrongpubid"] = CURLE_REMOTE_FILE_NOT_FOUND;
    fakecurl_responses["http://narcissus/impu/pubid42"] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
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
      "</IMSSubscription>";
    fakecurl_responses["http://narcissus/impu/pubid44"] = CURLE_REMOTE_FILE_NOT_FOUND;
  }

  virtual ~HssConnectionTest()
  {
  }
};

TEST_F(HssConnectionTest, SimpleDigest)
{
  Json::Value* actual = _hss.get_digest_data("privid69", "pubid42",  0);
  ASSERT_TRUE(actual != NULL);
  EXPECT_EQ("myhashhere", actual->get("digest", "").asString());
  delete actual;
}

TEST_F(HssConnectionTest, CorruptDigest)
{
  Json::Value* actual = _hss.get_digest_data("privid_corrupt", "pubid42", 0);
  ASSERT_TRUE(actual == NULL);
  EXPECT_TRUE(_log.contains("Failed to parse Homestead response"));
  delete actual;
}

TEST_F(HssConnectionTest, SimpleAssociatedUris)
{
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  _hss.get_subscription_data("pubid42", "", &ifcs_map, &uris, 0);
  EXPECT_EQ(2u, uris.size());
  EXPECT_EQ("sip:123@example.com", uris[0]);
  EXPECT_EQ("sip:456@example.com", uris[1]);
}

TEST_F(HssConnectionTest, SimpleIfc)
{
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  _hss.get_subscription_data("pubid42", "", &ifcs_map, &uris, 0);
  EXPECT_FALSE(ifcs_map.empty());
}

TEST_F(HssConnectionTest, ServerFailure)
{
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifcs_map;
  _hss.get_subscription_data("pubid44", "", &ifcs_map, &uris, 0);
  EXPECT_TRUE(uris.empty());
  EXPECT_TRUE(_log.contains("HTTP error response"));
}
