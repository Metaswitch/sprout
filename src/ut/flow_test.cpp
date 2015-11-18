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

///
///----------------------------------------------------------------------------

#include <string>
#include "gtest/gtest.h"
#include <boost/algorithm/string/replace.hpp>
#include <boost/lexical_cast.hpp>

#include "stack.h"
#include "utils.h"
#include "siptest.hpp"
#include "dialog_tracker.hpp"
#include "snmp_scalar.h"

using namespace std;

//This can only be statically initialised in UT, because we're stubbing out netsnmp - in production code, net-snmp needs to be initialized before creating any tables
static SNMP::U32Scalar fake_connection_count("", "");

/// Fixture for IfcHandlerTest
class FlowTest : public SipTest
{
public:
  static FlowTable* ft;
  static QuiescingManager* qm;
  Flow* flow;
  static pj_sockaddr addr;

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
    qm = NULL;
    ft = new FlowTable(qm, &fake_connection_count);
    addr.addr.sa_family = PJ_AF_INET;
  }

  static void TearDownTestCase()
  {
    delete ft;
    ft = NULL;
    delete qm;
    qm = NULL;

    SipTest::TearDownTestCase();
  }

  FlowTest() : SipTest(NULL)
  {
    // Restore a clean state
    ft->unquiesce();
    flow = ft->find_create_flow(TransportFlow::udp_transport(stack_data.pcscf_untrusted_port),
                                &addr);
  }

  ~FlowTest()
  {
    ft->remove_flow(flow);
  }
};

QuiescingManager* FlowTest::qm;
FlowTable* FlowTest::ft;
pj_sockaddr FlowTest::addr;

TEST_F(FlowTest, EmptyFlowNoQuiesce)
{
  EXPECT_FALSE(flow->should_quiesce());
}

TEST_F(FlowTest, EmptyFlowQuiesce)
{
  ft->quiesce();
  EXPECT_TRUE(flow->should_quiesce());
}


TEST_F(FlowTest, FlowQuiesceWithDialogs)
{
  ft->quiesce();
  flow->increment_dialogs();
  EXPECT_FALSE(flow->should_quiesce());
}

TEST_F(FlowTest, FlowQuiesceMidDialogs)
{
  EXPECT_FALSE(flow->should_quiesce());
  flow->increment_dialogs();
  EXPECT_FALSE(flow->should_quiesce());
  ft->quiesce();
  EXPECT_FALSE(flow->should_quiesce());
}

TEST_F(FlowTest, FlowQuiesceWhenDialogsEnd)
{
  ft->quiesce();
  EXPECT_TRUE(flow->should_quiesce());
  flow->increment_dialogs();
  EXPECT_FALSE(flow->should_quiesce());
  flow->decrement_dialogs();
  EXPECT_TRUE(flow->should_quiesce());
}


TEST_F(FlowTest, EmptyFlowUnquiesce)
{
  ft->quiesce();
  EXPECT_TRUE(flow->should_quiesce());
  ft->unquiesce();
  EXPECT_FALSE(flow->should_quiesce());
}


TEST_F(FlowTest, FlowUnQuiesceMidDialog)
{
  ft->quiesce();
  EXPECT_TRUE(flow->should_quiesce());
  flow->increment_dialogs();
  EXPECT_FALSE(flow->should_quiesce());
  ft->unquiesce();
  EXPECT_FALSE(flow->should_quiesce());
  flow->decrement_dialogs();
  EXPECT_FALSE(flow->should_quiesce());
}

