/**
 * @file pjutils_test.cpp UT for PJUtils.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2015 Metaswitch Networks Ltd
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
#include "gmock/gmock.h"

#include "basetest.hpp"
#include "uri_classifier.h"
#include "pjsip.h"
#include "pjutils.h"

class URIClassiferTest : public BaseTest
{
public:
  static pj_caching_pool caching_pool;
  static pj_pool_t* pool;
  static pjsip_endpoint* endpt;

  static void SetUpTestCase()
  {
    pj_init();
    pj_caching_pool_init(&caching_pool, &pj_pool_factory_default_policy, 0);
    pjsip_endpt_create(&caching_pool.factory, NULL, &endpt);
    pool = pj_pool_create(&caching_pool.factory, "contact-filtering-test", 4000, 4000, NULL);
  };


  URIClassiferTest()
  {
    stack_data.home_domains.insert("homedomain");
    stack_data.default_home_domain = pj_str("homedomain");
    URIClassifier::home_domains.push_back(&stack_data.default_home_domain);
  }


  virtual ~URIClassiferTest()
  {
  }

  URIClass classify_uri_helper(std::string uri_str, bool prefer_sip = true, bool check_np = false)
  {
    pjsip_uri* uri = PJUtils::uri_from_string(uri_str, pool);
    return URIClassifier::classify_uri(uri, prefer_sip, check_np);
  }
};

pj_pool_t* URIClassiferTest::pool;
pj_caching_pool URIClassiferTest::caching_pool;
pjsip_endpoint* URIClassiferTest::endpt;

TEST_F(URIClassiferTest, MailtoClassification)
{
  EXPECT_EQ(URIClass::UNKNOWN,
            classify_uri_helper("mailto:abc@example.com"));
}

TEST_F(URIClassiferTest, GlobalNumberClassification)
{
  EXPECT_EQ(URIClass::GLOBAL_PHONE_NUMBER,
            classify_uri_helper("sip:+1234@example.com;user=phone"));
  EXPECT_EQ(URIClass::GLOBAL_PHONE_NUMBER,
            classify_uri_helper("tel:+1234"));
}

TEST_F(URIClassiferTest, LocalNumberClassification)
{
  URIClassifier::enforce_global = true;
  EXPECT_EQ(URIClass::LOCAL_PHONE_NUMBER,
            classify_uri_helper("sip:1234@example.com;user=phone"));
  EXPECT_EQ(URIClass::LOCAL_PHONE_NUMBER,
            classify_uri_helper("tel:1234"));
}

TEST_F(URIClassiferTest, IgnoreLocalNumberClassification)
{
  URIClassifier::enforce_global = false;
  EXPECT_EQ(URIClass::GLOBAL_PHONE_NUMBER,
            classify_uri_helper("sip:1234@example.com;user=phone"));
  EXPECT_EQ(URIClass::GLOBAL_PHONE_NUMBER,
            classify_uri_helper("tel:1234"));
}

TEST_F(URIClassiferTest, IgnoreUserPhone)
{
  URIClassifier::enforce_user_phone = false;
  EXPECT_EQ(URIClass::GLOBAL_PHONE_NUMBER,
            classify_uri_helper("sip:+1234@homedomain", false));
  URIClassifier::enforce_user_phone = true;
  EXPECT_EQ(URIClass::HOME_DOMAIN_SIP_URI,
            classify_uri_helper("sip:+1234@homedomain", false));
}

TEST_F(URIClassiferTest, PreferSip)
{
  URIClassifier::enforce_user_phone = false;
  EXPECT_EQ(URIClass::GLOBAL_PHONE_NUMBER,
            classify_uri_helper("sip:+1234@homedomain", false));
  EXPECT_EQ(URIClass::HOME_DOMAIN_SIP_URI,
            classify_uri_helper("sip:+1234@homedomain", true));
  EXPECT_EQ(URIClass::HOME_DOMAIN_SIP_URI,
            classify_uri_helper("sip:notaphonenumber@homedomain", false));
}


TEST_F(URIClassiferTest, SIPURIs)
{
  EXPECT_EQ(URIClass::HOME_DOMAIN_SIP_URI,
            classify_uri_helper("sip:bob@homedomain"));
  EXPECT_EQ(URIClass::OFFNET_SIP_URI,
            classify_uri_helper("sip:bob@otherdomain"));
}

TEST_F(URIClassiferTest, NPData)
{
  URIClassifier::enforce_global = true;
  // Do an explicit NP check against various NP URIs
  EXPECT_EQ(URIClass::NP_DATA,
            classify_uri_helper("sip:1234;rn=567@example.com;user=phone", true, true));
  EXPECT_EQ(URIClass::NP_DATA,
            classify_uri_helper("tel:1234;rn=567", true, true));

  EXPECT_EQ(URIClass::FINAL_NP_DATA,
            classify_uri_helper("sip:1234;rn=567;npdi@example.com;user=phone", true, true));
  EXPECT_EQ(URIClass::FINAL_NP_DATA,
            classify_uri_helper("tel:1234;rn=567;npdi", true, true));

  // Verify that they are recognised as local phone numbers if no NP check
  EXPECT_EQ(URIClass::LOCAL_PHONE_NUMBER,
            classify_uri_helper("sip:1234;rn=567@example.com;user=phone"));
  EXPECT_EQ(URIClass::LOCAL_PHONE_NUMBER,
            classify_uri_helper("tel:1234;rn=567"));

  EXPECT_EQ(URIClass::LOCAL_PHONE_NUMBER,
            classify_uri_helper("sip:1234;rn=567;npdi@example.com;user=phone"));
  EXPECT_EQ(URIClass::LOCAL_PHONE_NUMBER,
            classify_uri_helper("tel:1234;rn=567;npdi"));

}
