/**
 * @file aschain_test.cpp UT for Sprout AsChain module
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

///
///----------------------------------------------------------------------------

#include <string>
#include "gtest/gtest.h"

#include "utils.h"
#include "siptest.hpp"
#include "fakelogger.hpp"
#include "pjutils.h"
#include "stack.h"

#include "aschain.h"

using namespace std;

/// Fixture for AsChainTest
class AsChainTest : public SipTest
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

  AsChainTest() : SipTest(NULL)
  {
  }

  ~AsChainTest()
  {
  }
};

TEST_F(AsChainTest, Basics)
{
  std::vector<AsInvocation> as_list;
  AsChain as_chain(SessionCase::Originating, "sip:5755550011@homedomain", as_list);

  AsInvocation as1;
  as1.server_name = "sip:pancommunicon.cw-ngv.com";
  as_list.push_back(as1);
  AsChain as_chain2(SessionCase::Originating, "sip:5755550011@homedomain", as_list);

  AsInvocation as2;
  as2.server_name = "sip:mmtel.homedomain";
  as_list.push_back(as2);
  AsChain as_chain3(SessionCase::Originating, "sip:5755550011@homedomain", as_list);

  EXPECT_EQ("orig", as_chain.to_string());
  EXPECT_EQ(SessionCase::Originating, as_chain.session_case());
  EXPECT_EQ("sip:5755550011@homedomain", as_chain.served_user());

  EXPECT_TRUE(as_chain.complete());
  EXPECT_FALSE(as_chain2.complete());
  EXPECT_FALSE(as_chain3.complete());

  CallServices calls(NULL);  // Not valid, but good enough for this UT.

  EXPECT_FALSE(as_chain.is_mmtel(&calls));
  EXPECT_FALSE(as_chain2.is_mmtel(&calls));
  EXPECT_TRUE(as_chain3.is_mmtel(&calls));
}

TEST_F(AsChainTest, AsInvocation)
{
  std::vector<AsInvocation> as_list;
  AsChain as_chain(SessionCase::Originating, "sip:5755550011@homedomain", as_list);

  AsInvocation as1;
  as1.server_name = "sip:pancommunicon.cw-ngv.com";
  as_list.push_back(as1);
  AsChain as_chain2(SessionCase::Originating, "sip:5755550011@homedomain", as_list);

  as_list.clear();
  AsInvocation as2;
  as2.server_name = "::invalid:pancommunicon.cw-ngv.com";
  as_list.push_back(as2);
  AsChain as_chain3(SessionCase::Originating, "sip:5755550011@homedomain", as_list);

  // @@@ not testing MMTEL AS yet - leave that to CallServices UTs.

  string str("INVITE sip:5755550099@homedomain SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.64.90.97:50693;rport;branch=z9hG4bKPjPtKqxhkZnvVKI2LUEWoZVFjFaqo.cOzf;alias\n"
             "Max-Forwards: 69\n"
             "From: <sip:5755550018@homedomain>;tag=13919SIPpTag0011234\n"
             "To: <sip:5755550099@homedomain>\n"
             "Contact: <sip:5755550018@10.16.62.109:58309;transport=TCP;ob>\n"
             "Call-ID: 1-13919@10.151.20.48\n"
             "CSeq: 4 INVITE\n"
             "Route: <sip:nextnode;transport=TCP;lr;orig>\n"
             "Content-Length: 0\n\n");
  pjsip_rx_data* rdata = build_rxdata(str);
  parse_rxdata(rdata);

  pjsip_tx_data* tdata = NULL;
  pj_status_t status = PJUtils::create_request_fwd(stack_data.endpt, rdata, NULL, NULL, 0, &tdata);
  ASSERT_EQ(PJ_SUCCESS, status);

  target *target;
  AsChain::Disposition disposition;

  // Nothing to invoke. Just proceed.
  target = NULL;
  disposition = as_chain.on_initial_request(NULL, NULL, NULL, tdata, &target);
  EXPECT_EQ(AsChain::Disposition::Next, disposition);
  EXPECT_TRUE(target == NULL);
  EXPECT_EQ("Route: <sip:nextnode;transport=TCP;lr;orig>", get_headers(tdata->msg, "Route"));

  // Invoke external AS on originating side.
  target = NULL;
  disposition = as_chain2.on_initial_request(NULL, NULL, NULL, tdata, &target);
  EXPECT_EQ(AsChain::Disposition::Skip, disposition);
  ASSERT_TRUE(target != NULL);
  EXPECT_FALSE(target->from_store);
  EXPECT_EQ("sip:5755550099@homedomain", str_uri(target->uri));
  ASSERT_EQ(2, target->paths.size());
  std::list<pjsip_uri*>::iterator it = target->paths.begin();
  EXPECT_EQ("sip:pancommunicon.cw-ngv.com;lr", str_uri(*it));
  ++it;
  EXPECT_EQ("sip:odi_unity@testnode:5058;lr;orig", str_uri(*it));
  EXPECT_EQ("sip:5755550099@homedomain", str_uri(tdata->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:nextnode;transport=TCP;lr;orig>",
            get_headers(tdata->msg, "Route"));

  // Invalid AS URI. This should probably return an error, but for now the AS is ignored.
  target = NULL;
  disposition = as_chain3.on_initial_request(NULL, NULL, NULL, tdata, &target);
  EXPECT_EQ(AsChain::Disposition::Next, disposition);
  EXPECT_TRUE(target == NULL);
  EXPECT_EQ("Route: <sip:nextnode;transport=TCP;lr;orig>", get_headers(tdata->msg, "Route"));

  // MMTEL cases can't easily be tested here, because they construct
  // real CallServices objects.
}

// ++@@@ aschain.to_string
// @@@ initial request: has MMTEL, orig and term
// ++@@@ has ASs but URI is invalid.
// ++@@@ no ASs configured.- next
// ++@@@ is_mmtel
// ++@@@ get served user

