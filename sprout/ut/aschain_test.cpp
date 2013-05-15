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
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "utils.h"
#include "siptest.hpp"
#include "fakelogger.hpp"
#include "pjutils.h"
#include "stack.h"

#include "aschain.h"

using namespace std;
using testing::MatchesRegex;

/// Fixture for AsChainTest
class AsChainTest : public SipTest
{
public:
  FakeLogger _log;
  AsChainTable* _as_chain_table;

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
    _as_chain_table = new AsChainTable();
  }

  ~AsChainTest()
  {
    delete _as_chain_table; _as_chain_table = NULL;
  }
};

TEST_F(AsChainTest, Basics)
{
  std::vector<std::string> as_list;
  AsChain as_chain(_as_chain_table, SessionCase::Originating, "sip:5755550011@homedomain", true, as_list);

  as_list.push_back("sip:pancommunicon.cw-ngv.com");
  AsChain as_chain2(_as_chain_table, SessionCase::Originating, "sip:5755550011@homedomain", true, as_list);

  as_list.push_back("sip:mmtel.homedomain");
  AsChain as_chain3(_as_chain_table, SessionCase::Originating, "sip:5755550011@homedomain", true, as_list);

  EXPECT_THAT(as_chain.to_string(), testing::MatchesRegex("AsChain-orig\\[[+/A-Za-z0-9]+\\]:1/0"));
  EXPECT_EQ(SessionCase::Originating, as_chain.session_case());
  EXPECT_EQ("sip:5755550011@homedomain", as_chain.served_user());

  EXPECT_TRUE(as_chain.complete()) << as_chain.to_string();
  EXPECT_FALSE(as_chain2.complete()) << as_chain2.to_string();
  EXPECT_FALSE(as_chain3.complete()) << as_chain3.to_string();

  CallServices calls(NULL);  // Not valid, but good enough for this UT.
}

TEST_F(AsChainTest, AsInvocation)
{
  std::vector<std::string> as_list;
  AsChain as_chain(_as_chain_table, SessionCase::Originating, "sip:5755550011@homedomain", true, as_list);

  as_list.push_back("sip:pancommunicon.cw-ngv.com");
  AsChain as_chain2(_as_chain_table, SessionCase::Originating, "sip:5755550011@homedomain", true, as_list);

  as_list.clear();
  as_list.push_back("::invalid:pancommunicon.cw-ngv.com");
  AsChain as_chain3(_as_chain_table, SessionCase::Originating, "sip:5755550011@homedomain", true, as_list);

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
  EXPECT_TRUE(as_chain2.complete());
  ASSERT_TRUE(target != NULL);
  EXPECT_FALSE(target->from_store);
  EXPECT_EQ("sip:5755550099@homedomain", str_uri(target->uri));
  ASSERT_EQ(2u, target->paths.size());
  std::list<pjsip_uri*>::iterator it = target->paths.begin();
  EXPECT_EQ("sip:pancommunicon.cw-ngv.com;lr", str_uri(*it));
  ++it;
  EXPECT_EQ("sip:odi_" + as_chain2._odi_token + "@testnode:5058;lr", str_uri(*it));
  EXPECT_EQ("sip:5755550099@homedomain", str_uri(tdata->msg->line.req.uri));
  EXPECT_EQ("Route: <sip:nextnode;transport=TCP;lr;orig>",
            get_headers(tdata->msg, "Route"));
  delete target; target = NULL;

  // MMTEL cases can't easily be tested here, because they construct
  // real CallServices objects.
}

// ++@@@ aschain.to_string
// @@@ initial request: has MMTEL, orig and term
// ++@@@ has ASs but URI is invalid.
// ++@@@ no ASs configured.- next
// ++@@@ is_mmtel
// ++@@@ get served user

