/**
 * @file bgcfservice_test.cpp UT for Sprout BGCF service.
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
