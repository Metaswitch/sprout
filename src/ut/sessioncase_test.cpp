/**
 * @file sessioncase_test.cpp UT for Sprout SessionCase module
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

///
///----------------------------------------------------------------------------

#include <string>
#include "gtest/gtest.h"

#include "utils.h"
#include "siptest.hpp"

#include "sessioncase.h"

using namespace std;

/// Fixture
class SessionCaseTest : public SipTest
{
public:
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


