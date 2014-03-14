/**
 * @file subscription_test.cpp
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

#include <string>
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "siptest.hpp"
#include "utils.h"
#include "analyticslogger.h"
#include "stack.h"
#include "subscription.h"
#include "fakelogger.hpp"
#include "fakehssconnection.hpp"
#include "test_interposer.hpp"
#include "fakechronosconnection.hpp"

using namespace std;
using testing::MatchesRegex;

/// Fixture for SubscriptionTest.
class SubscriptionTest : public SipTest
{
public:

  FakeLogger _log;

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
    cwtest_add_host_mapping("sprout.example.com", "10.8.8.1");

    _chronos_connection = new FakeChronosConnection();
    _local_data_store = new LocalStore();
    _remote_data_store = new LocalStore();
    _store = new RegStore((Store*)_local_data_store, _chronos_connection);
    _remote_store = new RegStore((Store*)_remote_data_store, _chronos_connection);
    _analytics = new AnalyticsLogger("foo");
    _hss_connection = new FakeHSSConnection();
    delete _analytics->_logger;
    _analytics->_logger = NULL;
    pj_status_t ret = init_subscription(_store, _remote_store, _hss_connection, _analytics);
    ASSERT_EQ(PJ_SUCCESS, ret);
    stack_data.sprout_cluster_domain = pj_str("all.the.sprout.nodes");

    _hss_connection->set_impu_result("sip:6505550231@homedomain", "", HSSConnection::STATE_REGISTERED, "");
  }

  static void TearDownTestCase()
  {
    destroy_subscription();
    delete _hss_connection; _hss_connection = NULL;
    delete _analytics; _analytics = NULL;
    delete _remote_store; _remote_store = NULL;
    delete _store; _store = NULL;
    delete _remote_data_store; _remote_data_store = NULL;
    delete _local_data_store; _local_data_store = NULL;
    delete _chronos_connection; _chronos_connection = NULL;
    SipTest::TearDownTestCase();
  }

  SubscriptionTest() : SipTest(&mod_subscription)
  {
    _analytics->_logger = &_log;
    _local_data_store->flush_all();  // start from a clean slate on each test
    _remote_data_store->flush_all();
  }

  ~SubscriptionTest()
  {
    _analytics->_logger = NULL;
  }

protected:
  static LocalStore* _local_data_store;
  static LocalStore* _remote_data_store;
  static RegStore* _store;
  static RegStore* _remote_store;
  static AnalyticsLogger* _analytics;
  static FakeHSSConnection* _hss_connection;
  static FakeChronosConnection* _chronos_connection;

  void check_subscriptions(std::string aor, uint32_t expected);
  void check_standard_OK();
};

LocalStore* SubscriptionTest::_local_data_store;
LocalStore* SubscriptionTest::_remote_data_store;
RegStore* SubscriptionTest::_store;
RegStore* SubscriptionTest::_remote_store;
AnalyticsLogger* SubscriptionTest::_analytics;
FakeHSSConnection* SubscriptionTest::_hss_connection;
FakeChronosConnection* SubscriptionTest::_chronos_connection;

class SubscribeMessage
{
public:
  string _method;
  string _user;
  string _domain;
  string _content_type;
  string _body;
  string _contact;
  string _event;
  string _accepts;
  string _expires;
  string _route;
  string _auth;
  string _record_route;


  SubscribeMessage() :
    _method("SUBSCRIBE"),
    _user("6505550231"),
    _domain("homedomain"),
    _contact("sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob"),
    _event("Event: reg"),
    _accepts("Accept: application/reginfo+xml"),
    _expires(""),
    _route(""),
    _auth(""),
    _record_route("Record-Route: <sip:sprout.example.com;transport=tcp;lr>")
  {
  }

  string get();
};

string SubscribeMessage::get()
{
  char buf[16384];

  int n = snprintf(buf, sizeof(buf),
                   "%1$s sip:%3$s SIP/2.0\r\n"
                   "%8$s"
                   "Via: SIP/2.0/TCP 10.83.18.38:36530;rport;branch=z9hG4bKPjmo1aimuq33BAI4rjhgQgBr4sY5e9kSPI\r\n"
                   "Via: SIP/2.0/TCP 10.114.61.213:5061;received=23.20.193.43;branch=z9hG4bK+7f6b263a983ef39b0bbda2135ee454871+sip+1+a64de9f6\r\n"
                   "From: <sip:%2$s@%3$s>;tag=10.114.61.213+1+8c8b232a+5fb751cf\r\n"
                   "To: <sip:%2$s@%3$s>\r\n"
                   "Max-Forwards: 68\r\n"
                   "Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqsUOO4ohntC@10.114.61.213\r\n"
                   "CSeq: 16567 %1$s\r\n"
                   "User-Agent: Accession 2.0.0.0\r\n"
                   "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n"
                   "%9$s"
                   "Contact: %7$s\r\n"
                   "Route: <sip:sprout.example.com;transport=tcp;lr>\r\n"
                   "P-Access-Network-Info: DUMMY\r\n"
                   "P-Visited-Network-ID: DUMMY\r\n"
                   "%10$s"
                   "%11$s"
                   "%12$s"
                   "%13$s"
                   "%4$s"
                   "Content-Length:  %5$d\r\n"
                   "\r\n"
                   "%6$s",

                   /*  1 */ _method.c_str(),
                   /*  2 */ _user.c_str(),
                   /*  3 */ _domain.c_str(),
                   /*  4 */ _content_type.empty() ? "" : string("Content-Type: ").append(_content_type).append("\r\n").c_str(),
                   /*  5 */ (int)_body.length(),
                   /*  6 */ _body.c_str(),
                   /*  7 */ (_contact == "*") ? "*" : string("<").append(_contact).append(">").c_str(),
                   /*  8 */ _route.empty() ? "" : string(_route).append("\r\n").c_str(),
                   /*  9 */ _expires.empty() ? "" : string(_expires).append("\r\n").c_str(),
                   /* 10 */ _auth.empty() ? "" : string(_auth).append("\r\n").c_str(),
                   /* 11 */ _event.empty() ? "" : string(_event).append("\r\n").c_str(),
                   /* 12 */ _accepts.empty() ? "" : string(_accepts).append("\r\n").c_str(),
                   /* 13 */ _record_route.empty() ? "" : string(_record_route).append("\r\n").c_str()
    );

  EXPECT_LT(n, (int)sizeof(buf));

  string ret(buf, n);
  return ret;
}


TEST_F(SubscriptionTest, NotSubscribe)
{
  SubscribeMessage msg;
  msg._method = "INVITE";
  pj_bool_t ret = inject_msg_direct(msg.get());
  EXPECT_EQ(PJ_FALSE, ret);
  check_subscriptions("sip:6505550231@homedomain", 0u);
}

TEST_F(SubscriptionTest, NotOurs)
{
  SubscribeMessage msg;
  msg._domain = "not-us.example.org";
  pj_bool_t ret = inject_msg_direct(msg.get());
  EXPECT_EQ(PJ_FALSE, ret);
  check_subscriptions("sip:6505550231@homedomain", 0u);
}

/// Simple correct example
TEST_F(SubscriptionTest, SimpleMainline)
{
  // Get an initial empty AoR record and add a binding.
  int now = time(NULL);

  RegStore::AoR* aor_data1 = _store->get_aor_data(std::string("sip:6505550231@homedomain"));
  RegStore::AoR::Binding* b1 = aor_data1->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  b1->_uri = std::string("<sip:6505550231@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  b1->_params.push_back(std::make_pair("+sip.instance", "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\""));
  b1->_params.push_back(std::make_pair("reg-id", "1"));
  b1->_params.push_back(std::make_pair("+sip.ice", ""));

  // Add the AoR record to the store.
  _store->set_aor_data(std::string("sip:6505550231@homedomain"), aor_data1, true);
  delete aor_data1; aor_data1 = NULL;

  check_subscriptions("sip:6505550231@homedomain", 0u);

  SubscribeMessage msg;
  inject_msg(msg.get());
  check_standard_OK();
  check_subscriptions("sip:6505550231@homedomain", 1u);
}

// Test the Event Header
// Missing Event header should be rejected
TEST_F(SubscriptionTest, MissingEventHeader)
{
  check_subscriptions("sip:6505550231@homedomain", 0u);

  SubscribeMessage msg;
  msg._event = "";
  pj_bool_t ret = inject_msg_direct(msg.get());
  EXPECT_EQ(PJ_FALSE, ret);
  check_subscriptions("sip:6505550231@homedomain", 0u);
}

// Test the Event Header
// Event that isn't reg should be rejected
TEST_F(SubscriptionTest, IncorrectEventHeader)
{
  check_subscriptions("sip:6505550231@homedomain", 0u);

  SubscribeMessage msg;
  msg._event = "Event: Not Reg";
  pj_bool_t ret = inject_msg_direct(msg.get());
  EXPECT_EQ(PJ_FALSE, ret);
  check_subscriptions("sip:6505550231@homedomain", 0u);

  SubscribeMessage msg2;
  msg2._event = "Event: Reg";
  ret = inject_msg_direct(msg2.get());
  EXPECT_EQ(PJ_FALSE, ret);
  check_subscriptions("sip:6505550231@homedomain", 0u);
}

// Test Accept Header. A message with no accepts header should be accepted
TEST_F(SubscriptionTest, EmptyAcceptsHeader)
{
  check_subscriptions("sip:6505550231@homedomain", 0u);

  SubscribeMessage msg;
  msg._accepts = "";
  inject_msg(msg.get());
  check_standard_OK();

  check_subscriptions("sip:6505550231@homedomain", 1u);
}

// Test Accept Header.
// A message with an accept header, but where it doesn't contain
// application/reginfo+xml shouldn't be accepted
TEST_F(SubscriptionTest, IncorrectAcceptsHeader)
{
  check_subscriptions("sip:6505550231@homedomain", 0u);

  SubscribeMessage msg;
  msg._accepts = "Accept: notappdata";
  pj_bool_t ret = inject_msg_direct(msg.get());
  EXPECT_EQ(PJ_FALSE, ret);
  check_subscriptions("sip:6505550231@homedomain", 0u);
}

// Test Accept Header.
// A message with an accept header, which contains
// application/reginfo+xml and others should be accepted
TEST_F(SubscriptionTest, CorrectAcceptsHeader)
{
  check_subscriptions("sip:6505550231@homedomain", 0u);

  SubscribeMessage msg;
  msg._accepts = "Accept: otherstuff,application/reginfo+xml";
  inject_msg(msg.get());
  check_standard_OK();

  check_subscriptions("sip:6505550231@homedomain", 1u);
}

/// Homestead fails associated URI request
TEST_F(SubscriptionTest, ErrorAssociatedUris)
{
  SubscribeMessage msg;
  msg._user = "6505550232";

  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(403, out->line.status.code);
  EXPECT_EQ("Forbidden", str_pj(out->line.status.reason));
  check_subscriptions("sip:6505550231@homedomain", 0u);
}

/// Register with non-primary P-Associated-URI
TEST_F(SubscriptionTest, NonPrimaryAssociatedUri)
{
  SubscribeMessage msg;
  msg._user = "6505550234";
  _hss_connection->set_impu_result("sip:6505550234@homedomain", "", HSSConnection::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550233@homedomain</Identity></PublicIdentity>\n"
                              "  <PublicIdentity><Identity>sip:6505550234@homedomain</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>");

  inject_msg(msg.get());
  check_standard_OK();
  check_subscriptions("sip:6505550233@homedomain", 1u);
}

void SubscriptionTest::check_subscriptions(std::string aor, uint32_t expected)
{
  // Check that we registered the correct URI (0233, not 0234).
  RegStore::AoR* aor_data = _store->get_aor_data(aor);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(expected, aor_data->_subscriptions.size());
  delete aor_data; aor_data = NULL;
}

void SubscriptionTest::check_standard_OK()
{
  ASSERT_EQ(2, txdata_count());
  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));

  out = current_txdata()->msg;
  EXPECT_EQ("NOTIFY", str_pj(out->line.status.reason));
  inject_msg(respond_to_current_txdata(200));
  //free_txdata();
}

