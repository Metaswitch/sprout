/**
 * Copyright (C) Metaswitch Networks
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
class DialogTrackerTest : public SipTest
{
public:
  static DialogTracker* dialog_tracker;
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
    dialog_tracker = new DialogTracker(ft);
  }

  static void TearDownTestCase()
  {
    delete dialog_tracker;
    dialog_tracker = NULL;
    delete ft;
    ft = NULL;

    SipTest::TearDownTestCase();
  }

  DialogTrackerTest() : SipTest(NULL)
  {
    // Restore a clean state
    ft->unquiesce();
    flow = ft->find_create_flow(TransportFlow::udp_transport(stack_data.pcscf_untrusted_port),
                                &addr);
  }

  ~DialogTrackerTest()
  {
    ft->remove_flow(flow);
  }
};

QuiescingManager* DialogTrackerTest::qm;
FlowTable* DialogTrackerTest::ft;
DialogTracker* DialogTrackerTest::dialog_tracker;
pj_sockaddr DialogTrackerTest::addr;

TEST_F(DialogTrackerTest, MainlineDialogTracking)
{
  pjsip_tx_data tdata;
  pjsip_transaction tsx;
  tsx.transport = TransportFlow::udp_transport(stack_data.pcscf_untrusted_port);
  tsx.addr = addr;
  pjsip_msg* msg = pjsip_msg_create(stack_data.pool, PJSIP_REQUEST_MSG);
  pjsip_to_hdr* to = pjsip_to_hdr_create(stack_data.pool);
  to->tag = pj_str("");
  pjsip_msg_insert_first_hdr(msg, (pjsip_hdr*)to);
  pjsip_event event;
  tdata.msg = msg;

  tsx.method.id = PJSIP_INVITE_METHOD;
  tsx.status_code = 200;

  ft->quiesce();
  EXPECT_TRUE(flow->should_quiesce());

  // Track the start of a dialog, and check that we keep the flow alive
  dialog_tracker->on_uas_tsx_complete(&tdata, &tsx, &event, true);
  EXPECT_FALSE(flow->should_quiesce());

  // Track the end of a dialog, and check that the flow can now be quiesced
  tsx.method.id = PJSIP_BYE_METHOD;
  tsx.status_code = 200;
  dialog_tracker->on_uas_tsx_complete(&tdata, &tsx, &event, true);
  EXPECT_TRUE(flow->should_quiesce());
}

TEST_F(DialogTrackerTest, ReinviteDialogTracking)
{
  pjsip_tx_data tdata;
  pjsip_transaction tsx;
  tsx.transport = TransportFlow::udp_transport(stack_data.pcscf_untrusted_port);
  tsx.addr = addr;
  pjsip_msg* msg = pjsip_msg_create(stack_data.pool, PJSIP_REQUEST_MSG);
  pjsip_to_hdr* to = pjsip_to_hdr_create(stack_data.pool);
  to->tag = pj_str("existing-tag");
  pjsip_msg_insert_first_hdr(msg, (pjsip_hdr*)to);
  pjsip_event event;
  tdata.msg = msg;

  tsx.method.id = PJSIP_INVITE_METHOD;
  tsx.status_code = 200;

  ft->quiesce();
  EXPECT_TRUE(flow->should_quiesce());

  // Track a reINVITE, and check that this does not affect our
  // decision on quiescing
  dialog_tracker->on_uas_tsx_complete(&tdata, &tsx, &event, true);
  EXPECT_TRUE(flow->should_quiesce());
}


TEST_F(DialogTrackerTest, DialogTrackingWithErrorOnBYE)
{
  pjsip_tx_data tdata;
  pjsip_transaction tsx;
  tsx.transport = TransportFlow::udp_transport(stack_data.pcscf_untrusted_port);
  tsx.addr = addr;
  pjsip_msg* msg = pjsip_msg_create(stack_data.pool, PJSIP_REQUEST_MSG);
  pjsip_to_hdr* to = pjsip_to_hdr_create(stack_data.pool);
  to->tag = pj_str("");
  pjsip_msg_insert_first_hdr(msg, (pjsip_hdr*)to);
  pjsip_event event;
  tdata.msg = msg;

  tsx.method.id = PJSIP_INVITE_METHOD;
  tsx.status_code = 200;

  ft->quiesce();
  EXPECT_TRUE(flow->should_quiesce());

  // Track the start of a dialog, and check that we keep the flow alive
  dialog_tracker->on_uas_tsx_complete(&tdata, &tsx, &event, true);
  EXPECT_FALSE(flow->should_quiesce());

  // Check that an error response to a BYE still ends the dialog
  tsx.method.id = PJSIP_BYE_METHOD;
  tsx.status_code = 408;
  dialog_tracker->on_uas_tsx_complete(&tdata, &tsx, &event, true);
  EXPECT_TRUE(flow->should_quiesce());
}
