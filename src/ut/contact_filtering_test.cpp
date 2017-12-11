/**
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "gtest/gtest.h"
#include "contact_filtering.h"
#include "pjsip.h"
#include "pjutils.h"

// Defined in sip_parser.c in pjSIP
void init_sip_parser(void);
void deinit_sip_parser(void);

class ContactFilteringTest : public ::testing::Test
{
public:
  static pj_caching_pool caching_pool;
  static pj_pool_t* pool;
  static pjsip_endpoint* endpt;
  pjsip_msg* msg;
  std::string aor;
  pjsip_uri* aor_uri;

  ContactFilteringTest()
  {
    msg = pjsip_msg_create(pool, PJSIP_REQUEST_MSG);
    aor = "sip:user@domain.com";
    aor_uri = PJUtils::uri_from_string(aor, pool);
    msg->line.req.uri = aor_uri;
  };

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
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingIntegerWithLessThan) { EXPECT_EQ(YES, match_numeric("#1.5", "#<=2.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingIntegerWithLessThan) { EXPECT_EQ(NO, match_numeric("#2.5", "#<=1.5")); }
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingIntegerWithGreaterThan) { EXPECT_EQ(YES, match_numeric("#2.5", "#>=1.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingIntegerWithGreaterThan) { EXPECT_EQ(NO, match_numeric("#1.5", "#>=2.5")); }
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingIntegerWithRange) { EXPECT_EQ(YES, match_numeric("#1.5", "#0.5:2.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingIntegerWithRange) { EXPECT_EQ(NO, match_numeric("#1.5", "#2.5:3.5")); }

TEST_F(ContactFilteringMatchNumericTest, MatchingGreaterThanWithInteger) { EXPECT_EQ(YES, match_numeric("#>=1.5", "#2.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingGreaterThanWithInteger) { EXPECT_EQ(NO, match_numeric("#>=2.5", "#1.5")); }
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingGreaterThanWithLessThan) { EXPECT_EQ(YES, match_numeric("#>=1.5", "#<=2.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingGreaterThanWithLessThan) { EXPECT_EQ(NO, match_numeric("#>=2.5", "#<=1.5")); }
TEST_F(ContactFilteringMatchNumericTest, MatchingGreaterThanWithGreaterThan) { EXPECT_EQ(YES, match_numeric("#>=1.5", "#>=2.5")); }
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingGreaterThanWithGreaterThan) { EXPECT_EQ(YES, match_numeric("#>=2.5", "#>=1.5")); }
TEST_F(ContactFilteringMatchNumericTest, MatchingGreaterThanWithRange) { EXPECT_EQ(YES, match_numeric("#>=1.5", "#2.5:3.5")); }
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingGreaterThanWithRange) { EXPECT_EQ(YES, match_numeric("#>=1.5", "#0.5:2.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingGreaterThanWithRange) { EXPECT_EQ(NO, match_numeric("#>=2.5", "#0.5:1.5")); }

TEST_F(ContactFilteringMatchNumericTest, MatchingLessThanWithInteger) { EXPECT_EQ(YES, match_numeric("#<=2.5", "#1.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingLessThanWithInteger) { EXPECT_EQ(NO, match_numeric("#<=1.5", "#2.5")); }
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingLessThanWithGreaterThan) { EXPECT_EQ(YES, match_numeric("#<=2.5", "#>=1.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingLessThanWithGreaterThan) { EXPECT_EQ(NO, match_numeric("#<=2.5", "#>=3.5")); }
TEST_F(ContactFilteringMatchNumericTest, MatchingLessThanWithLessThan) { EXPECT_EQ(YES, match_numeric("#<=2.5", "#<=1.5")); }
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingLessThanWithLessThan) { EXPECT_EQ(YES, match_numeric("#<=2.5", "#<=3.5")); }
TEST_F(ContactFilteringMatchNumericTest, MatchingLessThanWithRange) { EXPECT_EQ(YES, match_numeric("#<=2.5", "#0.5:1.5")); }
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingLessThanWithRange) { EXPECT_EQ(YES, match_numeric("#<=1.5", "#0.5:2.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingLessThanWithRange) { EXPECT_EQ(NO, match_numeric("#<=0.5", "#1.5:2.5")); }

TEST_F(ContactFilteringMatchNumericTest, MatchingRangeWithInteger) { EXPECT_EQ(YES, match_numeric("#1.5:3.5", "#2.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingRangeWithInteger) { EXPECT_EQ(NO, match_numeric("#1.5:2.5", "#3.5")); }
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingRangeWithGreaterThan) { EXPECT_EQ(YES, match_numeric("#2.5:3.5", "#>=1.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingRangeWithGreaterThan) { EXPECT_EQ(NO, match_numeric("#1.5:2.5", "#>=3.5")); }
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingRangeWithLessThan) { EXPECT_EQ(YES, match_numeric("#1.5:2.5", "#<=3.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingRangeWithLessThan) { EXPECT_EQ(NO, match_numeric("#2.5:3.5", "#<=1.5")); }
TEST_F(ContactFilteringMatchNumericTest, MatchingRangeWithRange) { EXPECT_EQ(YES, match_numeric("#1.5:4.5", "#2.5:3.5")); }
TEST_F(ContactFilteringMatchNumericTest, MaybeMatchingRangeWithRange) { EXPECT_EQ(YES, match_numeric("#1.5:3.5", "#2.5:4.5")); }
TEST_F(ContactFilteringMatchNumericTest, NonMatchingRangeWithRange) { EXPECT_EQ(NO, match_numeric("#1.5:2.5", "#3.5:4.5")); }

TEST_F(ContactFilteringMatchNumericTest, InvalidNumericRandom) { EXPECT_THROW(match_numeric("banana", "#1.5"), FeatureParseError); }
TEST_F(ContactFilteringMatchNumericTest, InvalidNumericNoOctothorp) { EXPECT_THROW(match_numeric("2.5:4.5", "#1.0"), FeatureParseError); }
TEST_F(ContactFilteringMatchNumericTest, InvalidNumericNoContents) { EXPECT_THROW(match_numeric("#2.5:4.5", ""), FeatureParseError); }
TEST_F(ContactFilteringMatchNumericTest, InvalidNumericBackwardsRange) { EXPECT_THROW(match_numeric("#4.5:2.5", "#2"), FeatureParseError); }

typedef ContactFilteringTest ContactFilteringMatchTokensTest;
TEST_F(ContactFilteringMatchTokensTest, MatchingTokens) { EXPECT_EQ(YES, match_tokens("hello,world", "goodbye,cruel,world")); }
TEST_F(ContactFilteringMatchTokensTest, NonMatchingTokens) { EXPECT_EQ(NO, match_tokens("hello,dave", "i,cant,let,you,do,that")); }
TEST_F(ContactFilteringMatchTokensTest, MatchingTokensCaseInsensitive) { EXPECT_EQ(YES, match_tokens("hello,dave", "Hello,is,it,me,youre,looking,for")); }
TEST_F(ContactFilteringMatchTokensTest, MatchingTokensWithWhitespace)
{
  EXPECT_EQ(YES, match_tokens("hello, goodbye , yes,no ,maybe", "goodbye,norma,jean"));
  EXPECT_EQ(YES, match_tokens("hello, goodbye , yes,no ,maybe", "you,say,yes "));
  EXPECT_EQ(YES, match_tokens("hello, goodbye , yes,no ,maybe", "I, say, no"));
}

typedef ContactFilteringTest ContactFilteringMatchFeatureTest;
TEST_F(ContactFilteringMatchFeatureTest, MatchBoolean)
{
  Feature matcher("+sip.boolean", "");
  Feature matchee("+sip.boolean", "");
  EXPECT_EQ(YES, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, MatchNegBoolean)
{
  Feature matcher("+sip.boolean", "FALSE");
  Feature matchee("+sip.boolean", "FALSE");
  EXPECT_EQ(YES, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, NoMatchBoolean)
{
  Feature matcher("+sip.boolean", "FALSE");
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
  EXPECT_EQ(YES, match_feature(matcher, matchee));
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
  EXPECT_EQ(NO, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, UnknownMatchDifferentTypesBool1)
{
  Feature matcher("+sip.crazy", "");
  Feature matchee("+sip.crazy", "<hello>");
  EXPECT_EQ(NO, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, UnknownMatchDifferentTypesBool2)
{
  Feature matcher("+sip.crazy", "#5");
  Feature matchee("+sip.crazy", "");
  EXPECT_EQ(NO, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, UnknownMatchDifferentTypesString)
{
  Feature matcher("+sip.crazy", "<hello>");
  Feature matchee("+sip.crazy", "hello");
  EXPECT_EQ(NO, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, UnknownMatchDifferentTypesToken)
{
  Feature matcher("+sip.crazy", "hello");
  Feature matchee("+sip.crazy", "<hello>");
  EXPECT_EQ(NO, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, MatchList)
{
  Feature matcher("+sip.crazy", "goldfish,goodbye");
  Feature matchee("+sip.crazy", "hello,goodbye");

  // Expect a match because there's overlap - "goodbye" is in both lists.
  EXPECT_EQ(YES, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, NoMatchList)
{
  Feature matcher("+sip.crazy", "hello");
  Feature matchee("+sip.crazy", "yellow,goodbye");
  EXPECT_EQ(NO, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, NoMatchListNegated)
{
  Feature matcher("+sip.crazy", "!hello,goodbye");
  Feature matchee("+sip.crazy", "hello");
  EXPECT_EQ(NO, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, MatchListNegated)
{
  Feature matcher("+sip.crazy", "!goodbye");
  Feature matchee("+sip.crazy", "hello,goodbye");

  // Expect a match because there's overlap - "!goodbye" matches
  // anything that isn't "goodbye", including "hello".
  EXPECT_EQ(YES, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, MatchListDoubleNegation)
{
  Feature matcher("+sip.crazy", "hello");
  Feature matchee("+sip.crazy", "!goodbye,!hello");

  // Expect a match because there's overlap - "!goodbye" matches
  // anything that isn't "goodbye", including "hello".
  EXPECT_EQ(YES, match_feature(matcher, matchee));

  Feature matcher2("+sip.crazy", "goodbye");
  Feature matchee2("+sip.crazy", "!goodbye,!hello,");

  EXPECT_EQ(YES, match_feature(matcher2, matchee2));
}
TEST_F(ContactFilteringMatchFeatureTest, MatchListNegationInBoth)
{
  Feature matcher("+sip.crazy", "!hello");
  Feature matchee("+sip.crazy", "!goodbye");

  // Expect a match because there's overlap - "!goodbye" matches
  // anything that isn't "goodbye", and "!hello" matches anything that
  // isn't "hello", so anything else (e.g. "wassup") could match both.
  EXPECT_EQ(YES, match_feature(matcher, matchee));
}
TEST_F(ContactFilteringMatchFeatureTest, SubstringMatch)
{
  Feature matcher("+sip.crazy", "iama");
  Feature matchee("+sip.crazy", "iamalongstring");
  EXPECT_EQ(NO, match_feature(matcher, matchee));
}

class ContactFilteringPrebuiltHeadersFixture : public ContactFilteringTest
{
public:
  pjsip_accept_contact_hdr* accept_hdr;
  pjsip_reject_contact_hdr* reject_hdr;

  void SetUp()
  {
    pj_str_t header_name = pj_str((char*)"Accept-Contact");
    char* header_value = (char*)"*;+sip.string=\"<hello>\";+sip.numeric=\"#4\";+sip.boolean;+sip.token=hello;+sip.negated=\"!world\"";
    accept_hdr = (pjsip_accept_contact_hdr*)
      pjsip_parse_hdr(pool,
                      &header_name,
                      header_value,
                      strlen(header_value),
                      NULL);
    ASSERT_NE((pjsip_accept_contact_hdr*)NULL, accept_hdr);
    header_name = pj_str((char*)"Reject-Contact");
    header_value = (char*)"*;+sip.string=\"<hello>\";+sip.numeric=\"#4\";+sip.boolean;+sip.token=hello;+sip.negated=\"!world\"";
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

typedef ContactFilteringPrebuiltHeadersFixture ContactFilteringMatchFeatureSetTest;
TEST_F(ContactFilteringMatchFeatureSetTest, MatchingNormalAccept)
{
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["+sip.boolean"] = "TRUE"; // equivalent to no value
  contact_feature_set["+sip.token"] = "hello";
  contact_feature_set["+sip.negated"] = "!world";

  EXPECT_EQ(YES, match_feature_sets(contact_feature_set, accept_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, QuotedMatchingNormalAccept)
{
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "\"<hello>\"";
  contact_feature_set["+sip.numeric"] = "\"#4\"";
  contact_feature_set["+sip.boolean"] = "";
  contact_feature_set["+sip.token"] = "\"hello\"";
  contact_feature_set["+sip.negated"] = "\"!world\"";

  EXPECT_EQ(YES, match_feature_sets(contact_feature_set, accept_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, MaybeMatchingNormalAccept)
{
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["+sip.boolean"] = "";
  contact_feature_set["+sip.negated"] = "!world";

  EXPECT_EQ(YES, match_feature_sets(contact_feature_set, accept_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, NonMatchingNormalAccept)
{
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["+sip.boolean"] = "FALSE";
  contact_feature_set["+sip.token"] = "hello";
  contact_feature_set["+sip.negated"] = "!world";

  // No match - +sip.boolean does not match
  EXPECT_EQ(NO, match_feature_sets(contact_feature_set, accept_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, MatchingExplicitAccept)
{
  accept_hdr->explicit_match = true;
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["+sip.boolean"] = "";
  contact_feature_set["+sip.token"] = "hello";
  contact_feature_set["+sip.negated"] = "!world";

  EXPECT_EQ(YES, match_feature_sets(contact_feature_set, accept_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, MaybeMatchingExplicitAccept)
{
  accept_hdr->explicit_match = true;
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["+sip.boolean"] = "";
  contact_feature_set["+sip.negated"] = "!world";

  // No match - +sip.token is not present but this is an explicit match
  EXPECT_EQ(NO, match_feature_sets(contact_feature_set, accept_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, NonMatchingExplicitAccept)
{
  accept_hdr->explicit_match = true;
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["+sip.boolean"] = "FALSE";
  contact_feature_set["+sip.token"] = "hello";
  contact_feature_set["+sip.negated"] = "!world";

  EXPECT_EQ(NO, match_feature_sets(contact_feature_set, accept_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, MatchingRequiredAccept)
{
  accept_hdr->required_match = true;
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["+sip.boolean"] = "";
  contact_feature_set["+sip.token"] = "hello";
  contact_feature_set["+sip.negated"] = "!world";

  EXPECT_EQ(YES, match_feature_sets(contact_feature_set, accept_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, MaybeMatchingRequiredAccept)
{
  accept_hdr->required_match = true;
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["+sip.boolean"] = "";
  contact_feature_set["+sip.negated"] = "!world";

  // Match - +sip.token isn't in this feature predicate but explicit
  // isn't present
  EXPECT_EQ(YES, match_feature_sets(contact_feature_set, accept_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, NonMatchingRequiredAccept)
{
  accept_hdr->required_match = true;
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["+sip.boolean"] = "FALSE";
  contact_feature_set["+sip.token"] = "hello";
  contact_feature_set["+sip.negated"] = "!world";

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
  contact_feature_set["+sip.negated"] = "!world";

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
  contact_feature_set["+sip.negated"] = "!world";

  EXPECT_EQ(NO, match_feature_sets(contact_feature_set, accept_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, NonMatchingRequiredExplicitAccept)
{
  accept_hdr->required_match = true;
  accept_hdr->explicit_match = true;
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["+sip.boolean"] = "FALSE";
  contact_feature_set["+sip.token"] = "hello";
  contact_feature_set["+sip.negated"] = "!world";

  EXPECT_EQ(NO, match_feature_sets(contact_feature_set, accept_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, MatchingNormalReject)
{
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["+sip.boolean"] = "";
  contact_feature_set["+sip.token"] = "hello";
  contact_feature_set["+sip.negated"] = "!world";

  EXPECT_EQ(YES, match_feature_sets(contact_feature_set, reject_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, MaybeMatchingNormalReject)
{
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["+sip.boolean"] = "";
  contact_feature_set["+sip.negated"] = "!world";

  // If a term is in the Reject-Contact set but not the Contact set,
  // that Reject-Contact predicate is discarded.

  EXPECT_EQ(NO, match_feature_sets(contact_feature_set, reject_hdr));
}
TEST_F(ContactFilteringMatchFeatureSetTest, NonMatchingNormalReject)
{
  FeatureSet contact_feature_set;
  contact_feature_set["+sip.string"] = "<hello>";
  contact_feature_set["+sip.numeric"] = "#4";
  contact_feature_set["+sip.boolean"] = "FALSE";
  contact_feature_set["+sip.token"] = "hello";
  contact_feature_set["+sip.negated"] = "!world";

  EXPECT_EQ(NO, match_feature_sets(contact_feature_set, reject_hdr));
}

typedef ContactFilteringPrebuiltHeadersFixture ContactFilteringImplicitFiltersTest;
TEST_F(ContactFilteringImplicitFiltersTest, AddImplicitFilter)
{
  std::vector<pjsip_accept_contact_hdr*>accept_headers;
  std::vector<pjsip_reject_contact_hdr*>reject_headers;

  msg->line.req.method.name = pj_str((char*)"INVITE");

  add_implicit_filters(msg, pool, accept_headers, reject_headers);

  ASSERT_EQ((unsigned)1, accept_headers.size());
  EXPECT_EQ((unsigned)0, reject_headers.size());

  pjsip_accept_contact_hdr* new_accept = accept_headers[0];
  EXPECT_TRUE(new_accept->required_match);
  EXPECT_FALSE(new_accept->explicit_match);
  pjsip_param* feature_param = new_accept->feature_set.next;
  ASSERT_NE(&new_accept->feature_set, feature_param);

  std::string feature_name(feature_param->name.ptr, feature_param->name.slen);
  std::string feature_value(feature_param->value.ptr, feature_param->value.slen);
  EXPECT_EQ(feature_name, "methods");
  EXPECT_EQ(feature_value, "INVITE");
}
TEST_F(ContactFilteringImplicitFiltersTest, DontAddImplicitFilterAccept)
{
  std::vector<pjsip_accept_contact_hdr*>accept_headers;
  std::vector<pjsip_reject_contact_hdr*>reject_headers;
  accept_headers.push_back(accept_hdr);

  pjsip_msg* msg = pjsip_msg_create(pool, PJSIP_REQUEST_MSG);
  ASSERT_NE((pjsip_msg*)NULL, msg);
  msg->line.req.method.name = pj_str((char*)"INVITE");

  add_implicit_filters(msg, pool, accept_headers, reject_headers);

  ASSERT_EQ((unsigned)1, accept_headers.size());
  EXPECT_EQ((unsigned)0, reject_headers.size());
}
TEST_F(ContactFilteringImplicitFiltersTest, DontAddImplicitFilterReject)
{
  std::vector<pjsip_accept_contact_hdr*>accept_headers;
  std::vector<pjsip_reject_contact_hdr*>reject_headers;
  reject_headers.push_back(reject_hdr);

  pjsip_msg* msg = pjsip_msg_create(pool, PJSIP_REQUEST_MSG);
  ASSERT_NE((pjsip_msg*)NULL, msg);
  msg->line.req.method.name = pj_str((char*)"INVITE");

  add_implicit_filters(msg, pool, accept_headers, reject_headers);

  ASSERT_EQ((unsigned)0, accept_headers.size());
  EXPECT_EQ((unsigned)1, reject_headers.size());
}
TEST_F(ContactFilteringImplicitFiltersTest, AddImplicitFilterWithEvent)
{
  std::vector<pjsip_accept_contact_hdr*>accept_headers;
  std::vector<pjsip_reject_contact_hdr*>reject_headers;

  pjsip_msg* msg = pjsip_msg_create(pool, PJSIP_REQUEST_MSG);
  ASSERT_NE((pjsip_msg*)NULL, msg);
  msg->line.req.method.name = pj_str((char*)"INVITE");
  pj_str_t event_name = pj_str((char*)"Event");
  pj_str_t event_value = pj_str((char*)"explosion");
  pjsip_generic_string_hdr* event_hdr =
    pjsip_generic_string_hdr_create(pool,
                                    &event_name,
                                    &event_value);
  pjsip_msg_add_hdr(msg, (pjsip_hdr*)event_hdr);

  add_implicit_filters(msg, pool, accept_headers, reject_headers);

  ASSERT_EQ((unsigned)1, accept_headers.size());
  EXPECT_EQ((unsigned)0, reject_headers.size());

  pjsip_accept_contact_hdr* new_accept = accept_headers[0];

  EXPECT_TRUE(new_accept->required_match);
  EXPECT_FALSE(new_accept->explicit_match);

  pj_str_t param_name = pj_str((char*)"methods");
  pjsip_param* feature_param = pjsip_param_find(&new_accept->feature_set, &param_name);
  ASSERT_NE((pjsip_param*)NULL, feature_param);
  std::string feature_value(feature_param->value.ptr, feature_param->value.slen);
  EXPECT_EQ(feature_value, "INVITE");

  param_name = pj_str((char*)"events");
  feature_param = pjsip_param_find(&new_accept->feature_set, &param_name);
  ASSERT_NE((pjsip_param*)NULL, feature_param);
  feature_value = std::string(feature_param->value.ptr, feature_param->value.slen);
  EXPECT_EQ(feature_value, "explosion");
}

class ContactFilteringCreateBindingFixture : public ContactFilteringTest
{
public:
  void create_binding(AoR::Binding& binding)
  {
    binding._uri = "sip:2125551212@192.168.0.1:55491;transport=TCP;rinstance=fad34fbcdea6a931";
    binding._cid = "gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq";
    binding._path_headers.push_back("\"Bob\" <sip:token@domain.com;lr>;tag=j45l");
    binding._path_headers.push_back("\"Alice\" <sip:token2@domain2.com;lr>;tag=g93s");
    binding._path_uris.push_back("sip:token@domain.com;lr");
    binding._path_uris.push_back("sip:token2@domain2.com;lr");
    binding._cseq = 3;
    binding._expires = 300;
    binding._priority = 1234;
    binding._params["+sip.string"] = "<hello>";
    binding._params["+sip.boolean"] = "";
    binding._params["methods"] = "invite,options";
    binding._private_id = "user@domain.com";
    binding._emergency_registration = false;
  }
};

class ContactFilteringBindingToTargetTest : public ContactFilteringCreateBindingFixture {};

TEST_F(ContactFilteringBindingToTargetTest, SimpleConversion)
{
  std::string aor = "sip:user@domain.com";
  AoR::Binding binding(aor);
  create_binding(binding);
  std::string binding_id = "<sip:user@10.1.2.3>";
  Target target;
  EXPECT_TRUE(binding_to_target(aor,
                                binding_id,
                                binding,
                                false,
                                pool,
                                target));
  EXPECT_EQ(PJ_TRUE, target.from_store);
  EXPECT_EQ(PJ_FALSE, target.upstream_route);
  EXPECT_EQ(aor, target.aor);
  EXPECT_EQ(binding_id, target.binding_id);
  EXPECT_NE((pjsip_uri*)NULL, target.uri);
  EXPECT_EQ((unsigned)2, target.paths.size());

  // Check that the target paths are as expected.
  std::list<std::string>::const_iterator j = binding._path_headers.begin();
  for (std::list<pjsip_route_hdr*>::const_iterator i = target.paths.begin();
       i != target.paths.end();
       ++i)
  {
    std::string path = PJUtils::get_header_value((pjsip_hdr*)*i);
    EXPECT_EQ(path, *j);
    ++j;
  }

  EXPECT_EQ((pjsip_transport*)NULL, target.transport);
  EXPECT_EQ(0, target.liveness_timeout);
  EXPECT_EQ(300, target.contact_expiry);
  EXPECT_EQ((unsigned)1234, target.contact_q1000_value);
}
TEST_F(ContactFilteringBindingToTargetTest, SimpleConversionPathUri)
{
  // This test test that the binding_to_target function will work for downlevel
  // Sprout nodes where only the path URIs field will be filled in on the
  // binding.

  std::string aor = "sip:user@domain.com";
  AoR::Binding binding(aor);
  create_binding(binding);
  binding._path_headers.clear();
  std::string binding_id = "<sip:user@10.1.2.3>";
  Target target;
  EXPECT_TRUE(binding_to_target(aor,
                                binding_id,
                                binding,
                                false,
                                pool,
                                target));
  EXPECT_EQ(PJ_TRUE, target.from_store);
  EXPECT_EQ(PJ_FALSE, target.upstream_route);
  EXPECT_EQ(aor, target.aor);
  EXPECT_EQ(binding_id, target.binding_id);
  EXPECT_NE((pjsip_uri*)NULL, target.uri);
  EXPECT_EQ((unsigned)2, target.paths.size());

  // Check that the target paths are as expected. The paths should come from
  // the _path_uris member on the binding.
  std::list<std::string>::const_iterator j = binding._path_uris.begin();
  for (std::list<pjsip_route_hdr*>::const_iterator i = target.paths.begin();
       i != target.paths.end();
       ++i)
  {
    std::string path = PJUtils::get_header_value((pjsip_hdr*)*i);
    EXPECT_EQ(path, "<" + *j + ">");
    ++j;
  }

  EXPECT_EQ((pjsip_transport*)NULL, target.transport);
  EXPECT_EQ(0, target.liveness_timeout);
  EXPECT_EQ(300, target.contact_expiry);
  EXPECT_EQ((unsigned)1234, target.contact_q1000_value);
}
TEST_F(ContactFilteringBindingToTargetTest, InvalidURI)
{
  std::string aor = "sip:user@domain.com";
  AoR::Binding binding(aor);
  create_binding(binding);
  std::string binding_id = "<sip:user@10.1.2.3>";
  binding._uri = "banana";
  Target target;
  EXPECT_FALSE(binding_to_target(aor,
                                binding_id,
                                binding,
                                false,
                                pool,
                                target));
}
TEST_F(ContactFilteringBindingToTargetTest, InvalidPath)
{
  std::string aor = "sip:user@domain.com";
  AoR::Binding binding(aor);
  create_binding(binding);
  std::string binding_id = "<sip:user@10.1.2.3>";
  binding._path_headers.push_back("banana");
  Target target;
  EXPECT_FALSE(binding_to_target(aor,
                                binding_id,
                                binding,
                                false,
                                pool,
                                target));
}
TEST_F(ContactFilteringBindingToTargetTest, InvalidPathDownlevel)
{
  std::string aor = "sip:user@domain.com";
  AoR::Binding binding(aor);
  create_binding(binding);
  binding._path_headers.clear();
  std::string binding_id = "<sip:user@10.1.2.3>";
  binding._path_uris.push_back("banana");
  Target target;
  EXPECT_FALSE(binding_to_target(aor,
                                binding_id,
                                binding,
                                false,
                                pool,
                                target));
}


class ContactFilteringFullStackTest :
  public ContactFilteringCreateBindingFixture {};

TEST_F(ContactFilteringFullStackTest, NoFiltering)
{
  AoR* aor_data = new AoR(aor);
  AoR::Binding* binding = aor_data->get_binding("<sip:user@10.1.2.3>");
  create_binding(*binding);

  msg->line.req.method.name = pj_str((char*)"INVITE");

  TargetList targets;

  filter_bindings_to_targets(aor,
                             aor_data,
                             msg,
                             pool,
                             5,
                             targets,
                             false,
                             1);

  EXPECT_EQ((unsigned)1, targets.size());
  EXPECT_FALSE(targets[0].deprioritized);

  delete aor_data;
}
TEST_F(ContactFilteringFullStackTest, ImplicitFiltering)
{
  AoR* aor_data = new AoR(aor);
  AoR::Binding* binding = aor_data->get_binding("<sip:user@10.1.2.3>");
  create_binding(*binding);

  // Pick a method the contact doesn't support
  msg->line.req.method.name = pj_str((char*)"MESSAGE");

  TargetList targets;

  filter_bindings_to_targets(aor,
                             aor_data,
                             msg,
                             pool,
                             5,
                             targets,
                             false,
                             1);

  // Since we explicitly say that only INVITE and OPTIONS are
  // supported, and implicit preferences have their "require" flag
  // set, this contact is skipped.
  EXPECT_EQ((unsigned)0, targets.size());

  delete aor_data;
}
TEST_F(ContactFilteringFullStackTest, ImplicitFilteringDeprioritize)
{
  AoR* aor_data = new AoR(aor);
  AoR::Binding* binding = aor_data->get_binding("<sip:user@10.1.2.3>");
  create_binding(*binding);
  binding->_params.erase("methods");

  // Pick a method the contact doesn't support
  msg->line.req.method.name = pj_str((char*)"MESSAGE");

  TargetList targets;

  filter_bindings_to_targets(aor,
                             aor_data,
                             msg,
                             pool,
                             5,
                             targets,
                             false,
                             1);

  // Since we don't explicitly include a "methods" parameter, and
  // implicit preferences don't have their explicit flag set, nothing
  // happens to this contact.
  EXPECT_EQ((unsigned)1, targets.size());
  EXPECT_FALSE(targets[0].deprioritized);

  delete aor_data;
}
TEST_F(ContactFilteringFullStackTest, ExplicitFilteringYesMatch)
{
  AoR* aor_data = new AoR(aor);
  AoR::Binding* binding = aor_data->get_binding("<sip:user@10.1.2.3>");
  create_binding(*binding);

  msg->line.req.method.name = pj_str((char*)"INVITE");

  // Add an Accept-Contact header that triggers a YES match
  pj_str_t header_name = pj_str((char*)"Accept-Contact");
  char* header_value = (char*)"*;+sip.string=\"<hello>\"";
  pjsip_accept_contact_hdr* accept_hdr = (pjsip_accept_contact_hdr*)
    pjsip_parse_hdr(pool,
                    &header_name,
                    header_value,
                    strlen(header_value),
                    NULL);
  ASSERT_NE((pjsip_accept_contact_hdr*)NULL, accept_hdr);
  accept_hdr = (pjsip_accept_contact_hdr*)pjsip_accept_contact_hdr_clone(pool, accept_hdr);
  accept_hdr = (pjsip_accept_contact_hdr*)pjsip_accept_contact_hdr_shallow_clone(pool, accept_hdr);
  pjsip_msg_add_hdr(msg, (pjsip_hdr*)accept_hdr);

  TargetList targets;

  filter_bindings_to_targets(aor,
                             aor_data,
                             msg,
                             pool,
                             5,
                             targets,
                             false,
                             1);

  EXPECT_EQ((unsigned)1, targets.size());
  EXPECT_FALSE(targets[0].deprioritized);

  delete aor_data;
}

TEST_F(ContactFilteringFullStackTest, ExplicitFilteringUnknownMatch)
{
  AoR* aor_data = new AoR(aor);
  AoR::Binding* binding = aor_data->get_binding("<sip:user@10.1.2.3>");
  create_binding(*binding);

  msg->line.req.method.name = pj_str((char*)"INVITE");

  // Add an Accept-Contact header that triggers a YES match
  pj_str_t header_name = pj_str((char*)"Accept-Contact");
  char* header_value = (char*)"*;+sip.other=\"#6\";explicit";
  pjsip_accept_contact_hdr* accept_hdr = (pjsip_accept_contact_hdr*)
    pjsip_parse_hdr(pool,
                    &header_name,
                    header_value,
                    strlen(header_value),
                    NULL);
  ASSERT_NE((pjsip_accept_contact_hdr*)NULL, accept_hdr);
  pjsip_msg_add_hdr(msg, (pjsip_hdr*)accept_hdr);

  TargetList targets;

  filter_bindings_to_targets(aor,
                             aor_data,
                             msg,
                             pool,
                             5,
                             targets,
                             false,
                             1);

  // Since the Accept-Header specifies a value that the binding doesn't
  // the target is deprioritized.
  EXPECT_EQ((unsigned)1, targets.size());
  EXPECT_TRUE(targets[0].deprioritized);

  delete aor_data;
}
TEST_F(ContactFilteringFullStackTest, ExplicitFilteringNoMatch)
{
  AoR* aor_data = new AoR(aor);
  AoR::Binding* binding = aor_data->get_binding("<sip:user@10.1.2.3>");
  create_binding(*binding);

  msg->line.req.method.name = pj_str((char*)"INVITE");

  // Add an Accept-Contact header that triggers a YES match
  pj_str_t header_name = pj_str((char*)"Accept-Contact");
  char* header_value = (char*)"*;+sip.other=\"#6\";explicit;require";
  pjsip_accept_contact_hdr* accept_hdr = (pjsip_accept_contact_hdr*)
    pjsip_parse_hdr(pool,
                    &header_name,
                    header_value,
                    strlen(header_value),
                    NULL);
  ASSERT_NE((pjsip_accept_contact_hdr*)NULL, accept_hdr);
  pjsip_msg_add_hdr(msg, (pjsip_hdr*)accept_hdr);

  TargetList targets;

  filter_bindings_to_targets(aor,
                             aor_data,
                             msg,
                             pool,
                             5,
                             targets,
                             false,
                             1);

  // Since the Accept-Header specifies a value that the binding doesn't
  // the target is deprioritized.
  EXPECT_EQ((unsigned)0, targets.size());

  delete aor_data;
}
TEST_F(ContactFilteringFullStackTest, RejectFilteringMatch)
{
  AoR* aor_data = new AoR(aor);
  AoR::Binding* binding = aor_data->get_binding("<sip:user@10.1.2.3>");
  create_binding(*binding);

  msg->line.req.method.name = pj_str((char*)"INVITE");

  // Add an Accept-Contact header that triggers a YES match
  pj_str_t header_name = pj_str((char*)"Reject-Contact");
  char* header_value = (char*)"*;+sip.string=\"<hello>\"";
  pjsip_reject_contact_hdr* reject_hdr = (pjsip_reject_contact_hdr*)
    pjsip_parse_hdr(pool,
                    &header_name,
                    header_value,
                    strlen(header_value),
                    NULL);
  ASSERT_NE((pjsip_reject_contact_hdr*)NULL, reject_hdr);
  reject_hdr = (pjsip_reject_contact_hdr*)pjsip_reject_contact_hdr_clone(pool, reject_hdr);
  reject_hdr = (pjsip_reject_contact_hdr*)pjsip_reject_contact_hdr_shallow_clone(pool, reject_hdr);
  pjsip_msg_add_hdr(msg, (pjsip_hdr*)reject_hdr);

  TargetList targets;

  filter_bindings_to_targets(aor,
                             aor_data,
                             msg,
                             pool,
                             5,
                             targets,
                             false,
                             1);

  // Since the Accept-Header specifies a value that the binding doesn't
  // the target is deprioritized.
  EXPECT_EQ((unsigned)0, targets.size());

  delete aor_data;
}
TEST_F(ContactFilteringFullStackTest, RejectFilteringNoMatch)
{
  AoR* aor_data = new AoR(aor);
  AoR::Binding* binding = aor_data->get_binding("<sip:user@10.1.2.3>");
  create_binding(*binding);

  msg->line.req.method.name = pj_str((char*)"INVITE");

  // Add an Accept-Contact header that triggers a YES match
  pj_str_t header_name = pj_str((char*)"Reject-Contact");
  char* header_value = (char*)"*;+sip.string=\"<goodbye>\"";
  pjsip_reject_contact_hdr* reject_hdr = (pjsip_reject_contact_hdr*)
    pjsip_parse_hdr(pool,
                    &header_name,
                    header_value,
                    strlen(header_value),
                    NULL);
  ASSERT_NE((pjsip_reject_contact_hdr*)NULL, reject_hdr);
  pjsip_msg_add_hdr(msg, (pjsip_hdr*)reject_hdr);

  TargetList targets;

  filter_bindings_to_targets(aor,
                             aor_data,
                             msg,
                             pool,
                             5,
                             targets,
                             false,
                             1);

  // Since the Accept-Header specifies a value that the binding doesn't
  // the target is deprioritized.
  EXPECT_EQ((unsigned)1, targets.size());

  delete aor_data;
}

TEST_F(ContactFilteringFullStackTest, LotsOfBindings)
{
  AoR* aor_data = new AoR(aor);

  for (int ii = 0;
       ii < 20;
       ii++)
  {
    std::string binding_id = "sip:user" + std::to_string(ii) + "@domain.com";
    AoR::Binding* binding = aor_data->get_binding(binding_id);
    create_binding(*binding);

    // Change the features on some of the bindings.
    if (ii % 2 == 0)
    {
      binding->_params["+sip.other"] = "<string>";
    }
    if (ii % 3 == 0)
    {
      binding->_params["+sip.other2"] = "#5";
    }
    if (ii % 7 == 0)
    {
      binding->_priority += ii;
    }

    binding->_expires = ii * 100;
  }

  msg->line.req.method.name = pj_str((char*)"INVITE");

  // Add some Accept headers to eliminate some bindings and
  // de-prioritize others.
  pj_str_t header_name = pj_str((char*)"Accept-Contact");
  char* header_value = (char*)"*;+sip.other2=\"#5\";explicit";
  pjsip_accept_contact_hdr* accept_hdr = (pjsip_accept_contact_hdr*)
    pjsip_parse_hdr(pool,
                    &header_name,
                    header_value,
                    strlen(header_value),
                    NULL);
  ASSERT_NE((pjsip_accept_contact_hdr*)NULL, accept_hdr);
  pjsip_msg_add_hdr(msg, (pjsip_hdr*)accept_hdr);
  header_value = (char*)"*;+sip.other=\"<string>\";explicit;require";
  accept_hdr = (pjsip_accept_contact_hdr*)
    pjsip_parse_hdr(pool,
                    &header_name,
                    header_value,
                    strlen(header_value),
                    NULL);
  ASSERT_NE((pjsip_accept_contact_hdr*)NULL, accept_hdr);
  pjsip_msg_add_hdr(msg, (pjsip_hdr*)accept_hdr);

  TargetList targets;

  filter_bindings_to_targets(aor,
                             aor_data,
                             msg,
                             pool,
                             5,
                             targets,
                             false,
                             1);

  EXPECT_EQ((unsigned)5, targets.size());

  delete aor_data;
}

TEST_F(ContactFilteringFullStackTest, GRUUNoMatch)
{
  AoR* aor_data = new AoR(aor);

  for (int ii = 0;
       ii < 20;
       ii++)
  {
    std::string binding_id = "sip:user" + std::to_string(ii) + "@domain.com";
    AoR::Binding* binding = aor_data->get_binding(binding_id);
    create_binding(*binding);

    binding->_expires = ii * 100;
  }

  msg->line.req.method.name = pj_str((char*)"INVITE");
  msg->line.req.uri = PJUtils::uri_from_string("sip:user@domain.com;gr=abcd", pool);

  TargetList targets;

  filter_bindings_to_targets(aor,
                             aor_data,
                             msg,
                             pool,
                             5,
                             targets,
                             false,
                             1);

  EXPECT_EQ((unsigned)0, targets.size());

  delete aor_data;
}

TEST_F(ContactFilteringFullStackTest, GRUUMatch)
{
  AoR* aor_data = new AoR(aor);

  for (int ii = 0;
       ii < 20;
       ii++)
  {
    std::string binding_id = "sip:user" + std::to_string(ii) + "@domain.com";
    AoR::Binding* binding = aor_data->get_binding(binding_id);
    create_binding(*binding);

    // Change the features on some of the bindings.
    if (ii == 2)
    {
      binding->_params["+sip.instance"] = "<abcd>";
    }
    if (ii == 3)
    {
      binding->_params["+sip.instance"] = "<abcde>";
    }
    binding->_expires = ii * 100;
  }

  msg->line.req.method.name = pj_str((char*)"INVITE");
  msg->line.req.uri = PJUtils::uri_from_string("sip:user@domain.com;gr=abcd", pool);

  TargetList targets;

  filter_bindings_to_targets(aor,
                             aor_data,
                             msg,
                             pool,
                             5,
                             targets,
                             false,
                             1);

  EXPECT_EQ((unsigned)1, targets.size());

  delete aor_data;
}
