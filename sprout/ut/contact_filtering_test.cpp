/**
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

#include "gtest/gtest.h"
#include "contact_filtering.h"
#include "pjsip.h"

// Defined in sip_parser.c in pjSIP
void init_sip_parser(void);
void deinit_sip_parser(void);

class ContactFilteringTest : public ::testing::Test
{
public:
  static pj_caching_pool caching_pool;
  static pj_pool_t* pool;
  static pjsip_endpoint* endpt;

  static void SetUpTestCase()
  {
    pj_init();
    register_custom_headers();
    pj_caching_pool_init(&caching_pool, &pj_pool_factory_default_policy, 0);
    pjsip_endpt_create(&caching_pool.factory, NULL, &endpt);
    pool = pj_pool_create(&caching_pool.factory, "contact-filtering-test", 4000, 4000, NULL);
  };
  static void TearDownTestCase()
  {
    pj_pool_release(pool); pool = NULL;
    pjsip_endpt_destroy(endpt); endpt = NULL;
    pj_caching_pool_destroy(&caching_pool);
    pj_shutdown();
  };
};
pj_pool_t* ContactFilteringTest::pool;
pj_caching_pool ContactFilteringTest::caching_pool;
pjsip_endpoint* ContactFilteringTest::endpt;

// Tests for match_numerics()
typedef ContactFilteringTest ContactFilteringMatchNumericTest;
TEST_F(ContactFilteringMatchNumericTest, MatchingIntegerWithInteger) { EXPECT_EQ(YES, match_numeric("#1.5", "#1.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingIntegerWithInteger) { EXPECT_EQ(NO, match_numeric("#1.5", "#2.5")); }
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingIntegerWithLessThan) { EXPECT_EQ(UNKNOWN, match_numeric("#1.5", "#<=2.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingIntegerWithLessThan) { EXPECT_EQ(NO, match_numeric("#2.5", "#<=1.5")); }
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingIntegerWithGreaterThan) { EXPECT_EQ(UNKNOWN, match_numeric("#2.5", "#>=1.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingIntegerWithGreaterThan) { EXPECT_EQ(NO, match_numeric("#1.5", "#>=2.5")); }
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingIntegerWithRange) { EXPECT_EQ(UNKNOWN, match_numeric("#1.5", "#0.5..2.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingIntegerWithRange) { EXPECT_EQ(NO, match_numeric("#1.5", "#2.5..3.5")); }

TEST_F(ContactFilteringMatchNumericTest, MatchingGreaterThanWithInteger) { EXPECT_EQ(YES, match_numeric("#>=1.5", "#2.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingGreaterThanWithInteger) { EXPECT_EQ(NO, match_numeric("#>=2.5", "#1.5")); }
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingGreaterThanWithLessThan) { EXPECT_EQ(UNKNOWN, match_numeric("#>=1.5", "#<=2.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingGreaterThanWithLessThan) { EXPECT_EQ(NO, match_numeric("#>=2.5", "#<=1.5")); }
TEST_F(ContactFilteringMatchNumericTest, MatchingGreaterThanWithGreaterThan) { EXPECT_EQ(YES, match_numeric("#>=1.5", "#>=2.5")); }
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingGreaterThanWithGreaterThan) { EXPECT_EQ(UNKNOWN, match_numeric("#>=2.5", "#>=1.5")); }
TEST_F(ContactFilteringMatchNumericTest, MatchingGreaterThanWithRange) { EXPECT_EQ(YES, match_numeric("#>=1.5", "#2.5..3.5")); }
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingGreaterThanWithRange) { EXPECT_EQ(UNKNOWN, match_numeric("#>=1.5", "#0.5..2.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingGreaterThanWithRange) { EXPECT_EQ(NO, match_numeric("#>=2.5", "#0.5..1.5")); }

TEST_F(ContactFilteringMatchNumericTest, MatchingLessThanWithInteger) { EXPECT_EQ(YES, match_numeric("#<=2.5", "#1.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingLessThanWithInteger) { EXPECT_EQ(NO, match_numeric("#<=1.5", "#2.5")); }
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingLessThanWithGreaterThan) { EXPECT_EQ(UNKNOWN, match_numeric("#<=2.5", "#>=1.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingLessThanWithGreaterThan) { EXPECT_EQ(NO, match_numeric("#<=2.5", "#>=3.5")); }
TEST_F(ContactFilteringMatchNumericTest, MatchingLessThanWithLessThan) { EXPECT_EQ(YES, match_numeric("#<=2.5", "#<=1.5")); }
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingLessThanWithLessThan) { EXPECT_EQ(UNKNOWN, match_numeric("#<=2.5", "#<=3.5")); }
TEST_F(ContactFilteringMatchNumericTest, MatchingLessThanWithRange) { EXPECT_EQ(YES, match_numeric("#<=2.5", "#0.5..1.5")); }
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingLessThanWithRange) { EXPECT_EQ(UNKNOWN, match_numeric("#<=1.5", "#0.5..2.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingLessThanWithRange) { EXPECT_EQ(NO, match_numeric("#<=0.5", "#1.5..2.5")); }

TEST_F(ContactFilteringMatchNumericTest, MatchingRangeWithInteger) { EXPECT_EQ(YES, match_numeric("#1.5..3.5", "#2.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingRangeWithInteger) { EXPECT_EQ(NO, match_numeric("#1.5..2.5", "#3.5")); }
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingRangeWithGreaterThan) { EXPECT_EQ(UNKNOWN, match_numeric("#2.5..3.5", "#>=1.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingRangeWithGreaterThan) { EXPECT_EQ(NO, match_numeric("#1.5..2.5", "#>=3.5")); }
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingRangeWithLessThan) { EXPECT_EQ(UNKNOWN, match_numeric("#1.5..2.5", "#<=3.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingRangeWithLessThan) { EXPECT_EQ(NO, match_numeric("#2.5..3.5", "#<=1.5")); }
TEST_F(ContactFilteringMatchNumericTest, MatchingRangeWithRange) { EXPECT_EQ(YES, match_numeric("#1.5..4.5", "#2.5..3.5")); }
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingRangeWithRange) { EXPECT_EQ(UNKNOWN, match_numeric("#1.5..3.5", "#2.5..4.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingRangeWithRange) { EXPECT_EQ(NO, match_numeric("#1.5..2.5", "#3.5..4.5")); }

TEST_F(ContactFilteringMatchNumericTest, InvalidNumericRandom) { EXPECT_THROW(match_numeric("banana", "#1.5"), FeatureParseError); }
TEST_F(ContactFilteringMatchNumericTest, InvalidNumericNoOctothorp) { EXPECT_THROW(match_numeric("2.5..4.5", "#1.0"), FeatureParseError); }
TEST_F(ContactFilteringMatchNumericTest, InvalidNumericNoContents) { EXPECT_THROW(match_numeric("#2.5..4.5", ""), FeatureParseError); }
TEST_F(ContactFilteringMatchNumericTest, InvalidNumericBackwardsRange) { EXPECT_THROW(match_numeric("#4.5..2.5", "#2"), FeatureParseError); }

typedef ContactFilteringTest ContactFilteringMatchTokensTest;
TEST_F(ContactFilteringMatchTokensTest, MatchingTokens) { EXPECT_EQ(YES, match_tokens("hello,world", "goodbye,cruel,world")); }
TEST_F(ContactFilteringMatchTokensTest, NonMatchingTokens) { EXPECT_EQ(NO, match_tokens("hello,dave", "i,cant,let,you,do,that")); }

typedef ContactFilteringTest ContactFilteringMatchFeatureTest;
TEST_F(ContactFilteringMatchFeatureTest, MatchBoolean)
{
  Feature matcher("+sip.boolean", "");
  Feature matchee("+sip.boolean", "");
  EXPECT_EQ(YES, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, MatchNegBoolean)
{
  Feature matcher("!+sip.boolean", "");
  Feature matchee("!+sip.boolean", "");
  EXPECT_EQ(YES, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, NoMatchBoolean)
{
  Feature matcher("!+sip.boolean", "");
  Feature matchee("+sip.boolean", "");
  EXPECT_EQ(NO, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, MatchString)
{
  Feature matcher("+sip.string", "<hello>");
  Feature matchee("+sip.string", "<hello>");
  EXPECT_EQ(YES, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, NoMatchString)
{
  Feature matcher("+sip.string", "<hello>");
  Feature matchee("+sip.string", "<goodbye>");
  EXPECT_EQ(NO, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, NoMatchStringCase)
{
  Feature matcher("+sip.string", "<hello>");
  Feature matchee("+sip.string", "<HELLO>");
  EXPECT_EQ(NO, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, MatchTokens)
{
  Feature matcher("+sip.tokens", "hello");
  Feature matchee("+sip.tokens", "hello");
  EXPECT_EQ(YES, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, NoMatchTokens)
{
  Feature matcher("+sip.tokens", "hello");
  Feature matchee("+sip.tokens", "goodbye");
  EXPECT_EQ(NO, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, MatchNumeric)
{
  Feature matcher("+sip.numeric", "#5");
  Feature matchee("+sip.numeric", "#5");
  EXPECT_EQ(YES, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, MaybeMatchNumeric)
{
  Feature matcher("+sip.numeric", "#5");
  Feature matchee("+sip.numeric", "#>=3");
  EXPECT_EQ(UNKNOWN, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, NoMatchNumeric)
{
  Feature matcher("+sip.numeric", "#5");
  Feature matchee("+sip.numeric", "#6");
  EXPECT_EQ(NO, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, UnknownMatchDifferentTypes)
{
  Feature matcher("+sip.crazy", "#5");
  Feature matchee("+sip.crazy", "<hello>");
  EXPECT_EQ(UNKNOWN, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, UnknownMatchDifferentTypesBool1)
{
  Feature matcher("+sip.crazy", "");
  Feature matchee("+sip.crazy", "<hello>");
  EXPECT_EQ(UNKNOWN, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, UnknownMatchDifferentTypesBool2)
{
  Feature matcher("+sip.crazy", "#5");
  Feature matchee("+sip.crazy", "");
  EXPECT_EQ(UNKNOWN, match_feature(matcher, matchee));
}

class ContactFilteringMatchFeatureSetTest : public ContactFilteringTest
{
public:
  pjsip_accept_contact_hdr* accept_hdr;
  pjsip_reject_contact_hdr* reject_hdr;

  void SetUp()
  {
    pj_str_t header_name = pj_str((char*)"Accept-Contact");
    char* header_value = (char*)"*;+sip.string=\"<hello>\";+sip.numeric=\"#4\";+sip.boolean;+sip.token=hello";
    accept_hdr = (pjsip_accept_contact_hdr*)
      pjsip_parse_hdr(pool,
                      &header_name,
                      header_value,
                      strlen(header_value),
                      NULL);
    ASSERT_NE((pjsip_accept_contact_hdr*)NULL, accept_hdr);
    header_name = pj_str((char*)"Reject-Contact");
    header_value = (char*)"*;+sip.string=\"<hello>\";+sip.numeric=\"#4\";+sip.boolean;+sip.token=hello";
    reject_hdr = (pjsip_reject_contact_hdr*)
      pjsip_parse_hdr(pool,
                      &header_name,
                      header_value,
                      strlen(header_value),
                      NULL);
    ASSERT_NE((pjsip_reject_contact_hdr*)NULL, reject_hdr);
  }

  void TearDown()
  {
  }
};

TEST_F(ContactFilteringMatchFeatureSetTest, MatchingNormalAccept)
{
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["+sip.boolean"] = "";
  contact_feature_set["+sip.token"] = "hello";

  EXPECT_EQ(YES, match_feature_sets(contact_feature_set, accept_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, MaybeMatchingNormalAccept)
{
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["+sip.boolean"] = "";

  EXPECT_EQ(YES, match_feature_sets(contact_feature_set, accept_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, NonMatchingNormalAccept)
{
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["!+sip.boolean"] = "";
  contact_feature_set["+sip.token"] = "hello";

  EXPECT_EQ(UNKNOWN, match_feature_sets(contact_feature_set, accept_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, MatchingExplicitAccept)
{
  accept_hdr->explicit_match = true;
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["+sip.boolean"] = "";
  contact_feature_set["+sip.token"] = "hello";

  EXPECT_EQ(YES, match_feature_sets(contact_feature_set, accept_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, MaybeMatchingExplicitAccept)
{
  accept_hdr->explicit_match = true;
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["+sip.boolean"] = "";

  EXPECT_EQ(UNKNOWN, match_feature_sets(contact_feature_set, accept_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, NonMatchingExplicitAccept)
{
  accept_hdr->explicit_match = true;
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["!+sip.boolean"] = "";
  contact_feature_set["+sip.token"] = "hello";

  EXPECT_EQ(UNKNOWN, match_feature_sets(contact_feature_set, accept_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, MatchingRequiredAccept)
{
  accept_hdr->required_match = true;
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["+sip.boolean"] = "";
  contact_feature_set["+sip.token"] = "hello";

  EXPECT_EQ(YES, match_feature_sets(contact_feature_set, accept_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, MaybeMatchingRequiredAccept)
{
  accept_hdr->required_match = true;
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["+sip.boolean"] = "";

  EXPECT_EQ(UNKNOWN, match_feature_sets(contact_feature_set, accept_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, NonMatchingRequiredAccept)
{
  accept_hdr->required_match = true;
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["!+sip.boolean"] = "";
  contact_feature_set["+sip.token"] = "hello";

  EXPECT_EQ(NO, match_feature_sets(contact_feature_set, accept_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, MatchingRequiredExplicitAccept)
{
  accept_hdr->required_match = true;
  accept_hdr->explicit_match = true;
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["+sip.boolean"] = "";
  contact_feature_set["+sip.token"] = "hello";

  EXPECT_EQ(YES, match_feature_sets(contact_feature_set, accept_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, MaybeMatchingRequiredExplicitAccept)
{
  accept_hdr->required_match = true;
  accept_hdr->explicit_match = true;
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["+sip.boolean"] = "";

  EXPECT_EQ(NO, match_feature_sets(contact_feature_set, accept_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, NonMatchingRequiredExplicitAccept)
{
  accept_hdr->required_match = true;
  accept_hdr->explicit_match = true;
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["!+sip.boolean"] = "";
  contact_feature_set["+sip.token"] = "hello";

  EXPECT_EQ(NO, match_feature_sets(contact_feature_set, accept_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, MatchingNormalReject)
{
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["+sip.boolean"] = "";
  contact_feature_set["+sip.token"] = "hello";

  EXPECT_EQ(YES, match_feature_sets(contact_feature_set, reject_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, MaybeMatchingNormalReject)
{
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["+sip.boolean"] = "";

  EXPECT_EQ(NO, match_feature_sets(contact_feature_set, reject_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, NonMatchingNormalReject)
{
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["!+sip.boolean"] = "";
  contact_feature_set["+sip.token"] = "hello";

  EXPECT_EQ(NO, match_feature_sets(contact_feature_set, reject_hdr));
}

