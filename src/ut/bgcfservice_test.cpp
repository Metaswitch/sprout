/**
 * @file bgcfservice_test.cpp UT for Sprout BGCF service.
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <string>
#include <vector>
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "utils.h"
#include "sas.h"
#include "bgcfservice.h"
#include "fakelogger.h"
#include "test_utils.hpp"

using namespace std;

enum RoutingType { DOMAIN_ROUTE, NUMBER_ROUTE };

/// Fixture for BgcfServiceTest.
class BgcfServiceTest : public ::testing::Test
{
  BgcfServiceTest()
  {
  }

  virtual ~BgcfServiceTest()
  {
  }
};

/// A single test case.
class ET
{
public:
  ET(string in, string out) :
    _in(in),
    _out(out)
  {
  }

  void test(BgcfService& bgcf_, RoutingType rt)
  {
    SCOPED_TRACE(_in);
    vector<string> ret; 

    if (rt == RoutingType::DOMAIN_ROUTE)
    {
      ret = bgcf_.get_route_from_domain(_in, 0);
    }
    else
    {
      ret = bgcf_.get_route_from_number(_in, 0);
    }

    std::stringstream store_strings;

    for(size_t ii = 0; ii < ret.size(); ++ii)
    {
      if (ii != 0)
      {
        store_strings << ",";
      }

      store_strings << ret[ii];
    }

    EXPECT_EQ(_out, store_strings.str());
  }

private:
  string _in; //^ input
  string _out; //^ expected output
};


TEST_F(BgcfServiceTest, SimpleTests)
{
  BgcfService bgcf_(string(UT_DIR).append("/test_bgcf.json"));

  ET("198.147.226.2",              "ec2-54-243-253-10.compute-1.amazonaws.com").test(bgcf_, RoutingType::DOMAIN_ROUTE);
  ET("ec2-54-243-253-10.compute-1.amazonaws.com", "").test(bgcf_, RoutingType::DOMAIN_ROUTE);
  ET("",                           ""                  ).test(bgcf_, RoutingType::DOMAIN_ROUTE);
  ET("billy2",                     ""                  ).test(bgcf_, RoutingType::DOMAIN_ROUTE);
  ET("198.147.226.",               ""                  ).test(bgcf_, RoutingType::DOMAIN_ROUTE);
  ET("foreign-domain.example.com", "sip.example.com"   ).test(bgcf_, RoutingType::DOMAIN_ROUTE);
  ET("198.147.226.99",             "fd3.amazonaws.com" ).test(bgcf_, RoutingType::DOMAIN_ROUTE);
  ET("multiple-nodes.example.com", "sip2.example.com,sip3.example.com").test(bgcf_, RoutingType::DOMAIN_ROUTE);
}

TEST_F(BgcfServiceTest, DefaultRoute)
{
  BgcfService bgcf_(string(UT_DIR).append("/test_bgcf_default_route.json"));

  ET("198.147.226.2",              "ec2-54-243-253-10.compute-1.amazonaws.com").test(bgcf_, RoutingType::DOMAIN_ROUTE);
  ET("ec2-54-243-253-10.compute-1.amazonaws.com", "sip.example.com").test(bgcf_, RoutingType::DOMAIN_ROUTE);
  ET("",                           "sip.example.com"   ).test(bgcf_, RoutingType::DOMAIN_ROUTE);
  ET("billy2",                     "sip.example.com"   ).test(bgcf_, RoutingType::DOMAIN_ROUTE);
  ET("198.147.226.",               "sip.example.com"   ).test(bgcf_, RoutingType::DOMAIN_ROUTE);
}

TEST_F(BgcfServiceTest, ParseError)
{
  BgcfService bgcf_(string(UT_DIR).append("/test_bgcf_parse_error.json"));
  ET("+15108580271", "").test(bgcf_, RoutingType::DOMAIN_ROUTE);
}

TEST_F(BgcfServiceTest, MissingParts)
{
  BgcfService bgcf_(string(UT_DIR).append("/test_bgcf_missing_parts.json"));
  ET("foreign-domain.example.com", "").test(bgcf_, RoutingType::DOMAIN_ROUTE);
  ET("198.147.226.99", "").test(bgcf_, RoutingType::DOMAIN_ROUTE);
  ET("198.147.226.98", "fd4.amazonaws.com").test(bgcf_, RoutingType::DOMAIN_ROUTE);
}

TEST_F(BgcfServiceTest, ExtraParts)
{
  // Test that entries with both domain and number values are invalid
  BgcfService bgcf_(string(UT_DIR).append("/test_bgcf_extra_parts.json"));
  ET("198.147.226.98", "").test(bgcf_, RoutingType::DOMAIN_ROUTE);
  ET("198.147.226.98", "").test(bgcf_, RoutingType::NUMBER_ROUTE);
}

TEST_F(BgcfServiceTest, MissingBlock)
{
  BgcfService bgcf_(string(UT_DIR).append("/test_bgcf_missing_block.json"));
  ET("+15108580271", "").test(bgcf_, RoutingType::DOMAIN_ROUTE);
}

TEST_F(BgcfServiceTest, MisspeltRoute)
{
  BgcfService bgcf_(string(UT_DIR).append("/test_bgcf_misspelt_route.json"));
  ET("+15108580271", "").test(bgcf_, RoutingType::DOMAIN_ROUTE);
}

TEST_F(BgcfServiceTest, MissingFile)
{
  BgcfService bgcf_(string(UT_DIR).append("/NONEXISTENT_FILE.json"));
  ET("+15108580271", "").test(bgcf_, RoutingType::DOMAIN_ROUTE);
}

TEST_F(BgcfServiceTest, NumberRouteTests)
{
  BgcfService bgcf_(string(UT_DIR).append("/test_bgcf.json"));

  // Test that visual separators are stripped out, but other invalid
  // characters aren't. Test that valid prefixes are picked up, 
  // prioritizing the longest ones, and that incorrect matches aren't 
  // chosen
  ET("+123-123", "sip.example.com").test(bgcf_, RoutingType::NUMBER_ROUTE);
  ET("+123123", "sip.example.com").test(bgcf_, RoutingType::NUMBER_ROUTE);
  ET("123123", "").test(bgcf_, RoutingType::NUMBER_ROUTE);
  ET("+123", "sip2.example.com").test(bgcf_, RoutingType::NUMBER_ROUTE);
  ET("+654-(3.21)", "sip3.example.com").test(bgcf_, RoutingType::NUMBER_ROUTE);
  ET("+654!-(321)", "").test(bgcf_, RoutingType::NUMBER_ROUTE);
}
