/**
 * @file utils_test.cpp UT for Sprout utils.
 *
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by post at
 * Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 */

///
///----------------------------------------------------------------------------

#include <string>
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <json/reader.h>

#include "utils.h"
#include "sas.h"
#include "test_utils.hpp"

using namespace std;

/// Fixture for UtilsTest.
class UtilsTest : public ::testing::Test
{
  UtilsTest()
  {
  }

  virtual ~UtilsTest()
  {
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
  EXPECT_EQ("The%20quick%20brown%20fox%20%22%3B'%24%3F%26%3D%25\n\377", actual);

  string input;
  string expected;
  for (unsigned int i = 32; i <= 127; i++)
  {
    char c = (char)i;
    input.push_back(c);
    if (string(" \"$#%&+,/:;<=>?@[\\]^`{|}~").find(c) == string::npos)
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

