/**
 * @file sessioncase_test.cpp UT for Sprout SessionCase module
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
#include "gtest/gtest.h"

#include "utils.h"
#include "siptest.hpp"
#include "fakelogger.hpp"

#include "sessioncase.h"

using namespace std;

/// Fixture
class SessionCaseTest : public SipTest
{
public:
  FakeLogger _log;

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
  }

  static void TearDownTestCase()
  {
    SipTest::TearDownTestCase();
  }

  SessionCaseTest() : SipTest(NULL)
  {
  }

  ~SessionCaseTest()
  {
  }
};

TEST_F(SessionCaseTest, Names)
{
  EXPECT_EQ("orig", SessionCase::Originating.to_string());
  EXPECT_EQ("orig-cdiv", SessionCase::OriginatingCdiv.to_string());
  EXPECT_EQ("term", SessionCase::Terminating.to_string());
}


