/**
 * @file utils_test.cpp UT for Sprout utils.
 *
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <math.h>
#include <string>
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <time.h>
#include <dlfcn.h>

#include "utils.h"
#include "sas.h"
#include "test_utils.hpp"
#include "test_interposer.hpp"

using namespace std;

using ::testing::Matcher;
using ::testing::AllOf;
using ::testing::Gt;
using ::testing::Lt;

/// Fixture for UtilsTest.
class UtilsTest : public ::testing::Test
{
  UtilsTest()
  {
  }

  virtual ~UtilsTest()
  {
  }

  double nCm(int n, int m)
  {
    double r = 1.0;
    for (int i = 1; i <= m; i++)
    {
      r *= (double)(n - i + 1)/(double)i;
    }
    return r;
  }
};

TEST_F(UtilsTest, Split)
{
  list<string> tokens;
  Utils::split_string(" , really,long,,string,alright , ",
                      ',',
                      tokens);
  list<string> expected;
  expected.push_back(" ");
  expected.push_back(" really");
  expected.push_back("long");
  expected.push_back("string");
  expected.push_back("alright ");
  expected.push_back(" ");
  EXPECT_EQ(expected, tokens);

  tokens.clear();
  expected.clear();
  Utils::split_string("  long,g; string ",
                      ';',
                      tokens,
                      999,
                      true);
  expected.push_back("long,g");
  expected.push_back(" string");
  EXPECT_EQ(expected, tokens);

  tokens.clear();
  expected.clear();
  Utils::split_string(",,,",
                      ',',
                      tokens,
                      0,
                      true);
  EXPECT_EQ(expected, tokens);

  tokens.clear();
  expected.clear();
  Utils::split_string("",
                      ',',
                      tokens,
                      999,
                      false);
  EXPECT_EQ(expected, tokens);

  tokens.clear();
  expected.clear();
  Utils::split_string("a,b,,d,e",
                      ',',
                      tokens,
                      3,
                      false);
  expected.push_back("a");
  expected.push_back("b");
  expected.push_back(",d,e");
  EXPECT_EQ(expected, tokens);
}

TEST_F(UtilsTest, Escape)
{
  string actual = Utils::url_escape("");
  EXPECT_EQ("", actual);

  actual = Utils::url_escape("The quick brown fox \";'$?&=%\n\377");
  EXPECT_EQ("The%20quick%20brown%20fox%20%22%3B%27%24%3F%26%3D%25\n\377", actual);

  string input;
  string expected;
  for (unsigned int i = 32; i <= 127; i++)
  {
    char c = (char)i;
    input.push_back(c);
    if ((string("!#$&'()*+,/:;=?@[]").find(c) == string::npos) &&
        (string(" \"%<>\\^`{|}~").find(c) == string::npos))
    {
      expected.push_back(c);
    }
    else
    {
      char buf[4];
      sprintf(buf, "%%%02X", i);
      expected.append(buf);
    }
  }

  actual = Utils::url_escape(input);
  EXPECT_EQ(expected, actual);
}

TEST_F(UtilsTest, Unescape)
{
  // The only rule for url_unescape is that it should do the opposite
  // of url_escape.

  for (char c = 1; c < 127; c++)
  {
    std::string original(10, c);
    EXPECT_EQ(original, Utils::url_unescape(Utils::url_escape(original)));
  }
}

TEST_F(UtilsTest, XmlEscape)
{
  string actual = Utils::xml_escape("");
  EXPECT_EQ("", actual);

  actual = Utils::xml_escape("The quick brown fox &\"'<>\n\377");
  EXPECT_EQ("The quick brown fox &amp;&quot;&apos;&lt;&gt;\n\377", actual);
}

TEST_F(UtilsTest, Trim)
{
  string s = "    floop  ";
  string& t = Utils::ltrim(s);
  EXPECT_EQ(&s, &t);  // should return the same string
  EXPECT_EQ("floop  ", s);

  s = "  barp   ";
  t = Utils::rtrim(s);
  EXPECT_EQ(&s, &t);
  EXPECT_EQ("  barp", s);

  s = "";
  Utils::ltrim(s);
  EXPECT_EQ("", s);
  Utils::rtrim(s);
  EXPECT_EQ("", s);

  s = "xx   ";
  Utils::ltrim(s);
  EXPECT_EQ("xx   ", s);
  s = "   xx";
  Utils::rtrim(s);
  EXPECT_EQ("   xx", s);

  s = "    ";
  Utils::ltrim(s);
  EXPECT_EQ("", s);
  s = "    ";
  Utils::rtrim(s);
  EXPECT_EQ("", s);

  s = "   floop   ";
  t = Utils::trim(s);
  EXPECT_EQ(&s, &t);
  EXPECT_EQ("floop", s);

  s = "xy  zzy";
  Utils::trim(s);
  EXPECT_EQ("xy  zzy", s);

  s = "";
  Utils::trim(s);
  EXPECT_EQ("", s);
}


TEST_F(UtilsTest, ExponentialDistribution)
{
  double lambda = 1.0 / (double)300;
  Utils::ExponentialDistribution e(lambda);

  // Use a fixed seed to make the test deterministic.
  srand(2013);

  // Sample the distribution 10000 times.
  std::vector<double> x(10000);
  for (int i = 0; i < 10000; ++i)
  {
    x[i] = e();
    if (x[i] < 0)
    {
      printf("Bad value %g\n", x[i]);
      exit(1);
    }
  }

  // Calculate the observed mean and variance.
  double observed_mean = 0.0;
  for (int i = 0; i < 10000; ++i)
  {
    observed_mean += x[i];
  }
  observed_mean /= (double)10000;
  double observed_variance = 0.0;
  for (int i = 0; i < 10000; ++i)
  {
    observed_variance += (x[i] - observed_mean)*(x[i] - observed_mean);
  }
  observed_variance /= (double)10000;

  double expected_mean = 1.0 / lambda;
  double expected_variance = expected_mean*expected_mean;
  EXPECT_THAT(observed_mean, testing::AllOf(testing::Ge(expected_mean * 0.95), testing::Le(expected_mean * 1.05)));
  EXPECT_THAT(observed_variance, testing::AllOf(testing::Ge(expected_variance * 0.95), testing::Le(expected_variance * 1.05)));
}


TEST_F(UtilsTest, BinomialDistribution)
{
  int t = 10;
  double p = 0.1;
  Utils::BinomialDistribution b(t, p);
  std::vector<int> c(t+1);

  // Use a fixed seed to make the test deterministic.
  srand(2013);

  for (int i = 0; i < 10000; ++i)
  {
    int v = b();
    EXPECT_THAT(v, testing::AllOf(testing::Ge(0), testing::Le(t)));
    ++c[v];
  }

  // Test that the resulting distribution is close to the expected one.
  for (int i = 0; i <= t; ++i)
  {
    double expected = nCm(t,i) * pow(p, i) * pow(1-p, t-i);
    double observed = (double)c[i] / (double)10000;
    EXPECT_THAT(observed, testing::AllOf(testing::Ge(expected - 0.05), testing::Le(expected + 0.05)));
  }
}

/// Test the parse_stores_arg function with various input parameters.
TEST_F(UtilsTest, ParseStoresArg)
{
  std::vector<std::string> stores_arg = {"local_site=store0",
                                         "remote_site1=store1",
                                         "remote_site2=store2"};
  std::string local_site_name = "local_site";
  std::string local_store_location;
  std::vector<std::string> remote_stores_locations;

  bool ret = Utils::parse_stores_arg(stores_arg,
                                     local_site_name,
                                     local_store_location,
                                     remote_stores_locations);

  EXPECT_TRUE(ret);
  EXPECT_EQ(local_store_location, "store0");
  EXPECT_EQ(remote_stores_locations.size(), 2);
  EXPECT_EQ(remote_stores_locations[0], "store1");
  EXPECT_EQ(remote_stores_locations[1], "store2");

  // Vector is invalid since one of the stores is not identfied by a site.
  local_store_location = "";
  remote_stores_locations.clear();
  stores_arg = {"local_site=store0",
                "store1",
                "remote_site2=store2"};

  ret = Utils::parse_stores_arg(stores_arg,
                                local_site_name,
                                local_store_location,
                                remote_stores_locations);

  EXPECT_FALSE(ret);

  // Single site deployment.
  local_store_location = "";
  remote_stores_locations.clear();
  stores_arg = {"local_site=store0"};

  ret = Utils::parse_stores_arg(stores_arg,
                                local_site_name,
                                local_store_location,
                                remote_stores_locations);

  EXPECT_TRUE(ret);
  EXPECT_EQ(local_store_location, "store0");
  EXPECT_EQ(remote_stores_locations.size(), 0);

  // Single site deployment where no site is specified - parse_stores_arg
  // assumes it is the local site.
  local_store_location = "";
  remote_stores_locations.clear();
  stores_arg = {"store0"};

  ret = Utils::parse_stores_arg(stores_arg,
                                local_site_name,
                                local_store_location,
                                remote_stores_locations);

  EXPECT_TRUE(ret);
  EXPECT_EQ(local_store_location, "store0");
  EXPECT_EQ(remote_stores_locations.size(), 0);
}

class StopWatchTest : public ::testing::Test
{
public:
  StopWatchTest()
  {
    cwtest_completely_control_time();
  }

  virtual ~StopWatchTest()
  {
    cwtest_reset_time();
  }

  unsigned long ms_to_us(int ms) { return (unsigned long)(ms * 1000); }

  Utils::StopWatch _sw;
};

TEST_F(StopWatchTest, Mainline)
{
  EXPECT_TRUE(_sw.start());
  cwtest_advance_time_ms(11);
  EXPECT_TRUE(_sw.stop());

  unsigned long elapsed_us;
  EXPECT_TRUE(_sw.read(elapsed_us));
  EXPECT_EQ(ms_to_us(11), elapsed_us);
}

TEST_F(StopWatchTest, StopIsIdempotent)
{
  EXPECT_TRUE(_sw.start());
  cwtest_advance_time_ms(11);
  EXPECT_TRUE(_sw.stop());
  cwtest_advance_time_ms(11);
  EXPECT_TRUE(_sw.stop());

  unsigned long elapsed_us;
  EXPECT_TRUE(_sw.read(elapsed_us));
  EXPECT_EQ(ms_to_us(11), elapsed_us);
}

TEST_F(StopWatchTest, ReadGetsLatestValueWhenNotStopped)
{
  EXPECT_TRUE(_sw.start());

  unsigned long elapsed_us;
  cwtest_advance_time_ms(11);
  EXPECT_TRUE(_sw.read(elapsed_us));
  EXPECT_EQ(ms_to_us(11), elapsed_us);

  cwtest_advance_time_ms(11);
  EXPECT_TRUE(_sw.read(elapsed_us));
  // The returned value is greater on the second read.
  EXPECT_EQ(ms_to_us(22), elapsed_us);
}
