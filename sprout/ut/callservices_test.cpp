/**
 * @file callservices_test.cpp UT for Sprout call services.
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
#include "aschain.h"
#include "ifchandler.h"
#include "callservices.h"
#include "fakelogger.hpp"
#include "fakehssconnection.hpp"
#include "fakexdmconnection.hpp"
#include "siptest.hpp"
#include "stack.h"
#include "test_utils.hpp"

using namespace std;

/// Fixture for CallServicesTest.
class CallServicesTest : public SipTest
{
  IfcHandler _ifcs;
  CallServices _calls;

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();

    _hss_connection = new FakeHSSConnection();
    _xdm_connection = new FakeXDMConnection();
  }

  static void TearDownTestCase()
  {
    delete _xdm_connection;
    delete _hss_connection;

    SipTest::TearDownTestCase();
  }

  CallServicesTest() :
    _ifcs(_hss_connection),
    _calls(_xdm_connection)
  {
  }

  virtual ~CallServicesTest()
  {
  }

protected:
  static FakeHSSConnection* _hss_connection;
  static FakeXDMConnection* _xdm_connection;
};

FakeHSSConnection* CallServicesTest::_hss_connection;
FakeXDMConnection* CallServicesTest::_xdm_connection;

TEST_F(CallServicesTest, UserFromUri)
{
  char* s = "sip:bob:secret@example.org:9876;user=john;method=urk;lr;wotsit=thingy";
  pjsip_uri* uri = pjsip_parse_uri(stack_data.pool, s, strlen(s), 0);
  string actual = IfcHandler::user_from_uri(uri);
  EXPECT_EQ("sip:bob@example.org", actual);
}

TEST_F(CallServicesTest, IsOurs)
{
  EXPECT_TRUE(_calls.is_mmtel("sip:mmtel.homedomain"));
  EXPECT_FALSE(_calls.is_mmtel("sip:homedomain"));
  EXPECT_FALSE(_calls.is_mmtel("sip:mmtel.otherdomain"));
  EXPECT_FALSE(_calls.is_mmtel("sip:mmtel"));
  EXPECT_FALSE(_calls.is_mmtel("sips:mmtel.homedomain"));
  EXPECT_FALSE(_calls.is_mmtel("tel:+12125551212"));
  EXPECT_FALSE(_calls.is_mmtel(""));
}
