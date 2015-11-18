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
