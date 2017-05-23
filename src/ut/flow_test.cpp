/**
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

