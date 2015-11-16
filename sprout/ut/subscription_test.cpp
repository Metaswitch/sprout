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
#include "fakehssconnection.hpp"
#include "test_interposer.hpp"
#include "fakechronosconnection.hpp"
#include "mock_store.h"

using ::testing::MatchesRegex;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::_;
using ::testing::Return;

/// Fixture for SubscriptionTest.
class SubscriptionTest : public SipTest
{
public:
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
    add_host_mapping("sprout.example.com", "10.8.8.1");

    _chronos_connection = new FakeChronosConnection();
    _local_data_store = new LocalStore();
    _store = new RegStore((Store*)_local_data_store, _chronos_connection);
    _analytics = new AnalyticsLogger(&PrintingTestLogger::DEFAULT);
    _hss_connection = new FakeHSSConnection();
    _acr_factory = new ACRFactory();
    pj_status_t ret = init_subscription(_store, _hss_connection, _acr_factory, _analytics, 300);
    ASSERT_EQ(PJ_SUCCESS, ret);
    stack_data.scscf_uri = pj_str("sip:all.the.sprout.nodes:5058;transport=TCP");

    _hss_connection->set_impu_result("sip:6505550231@homedomain", "", HSSConnection::STATE_REGISTERED, "");
    _hss_connection->set_impu_result("tel:6505550231", "", HSSConnection::STATE_REGISTERED, "");
  }

  static void TearDownTestCase()
  {
    destroy_subscription();
    delete _acr_factory; _acr_factory = NULL;
    delete _hss_connection; _hss_connection = NULL;
    delete _analytics; _analytics = NULL;
    delete _store; _store = NULL;
    delete _local_data_store; _local_data_store = NULL;
    delete _chronos_connection; _chronos_connection = NULL;
    SipTest::TearDownTestCase();
  }

  SubscriptionTest() : SipTest(&mod_subscription)
  {
    _local_data_store->flush_all();  // start from a clean slate on each test

    _log_traffic = PrintingTestLogger::DEFAULT.isPrinting();
  }

  ~SubscriptionTest()
  {
  }

protected:
  static LocalStore* _local_data_store;
  static RegStore* _store;
  static AnalyticsLogger* _analytics;
  static ACRFactory* _acr_factory;
  static FakeHSSConnection* _hss_connection;
  static FakeChronosConnection* _chronos_connection;

  void check_subscriptions(std::string aor, uint32_t expected);
  void check_OK_and_NOTIFY(bool terminated = false);
};

LocalStore* SubscriptionTest::_local_data_store;
RegStore* SubscriptionTest::_store;
AnalyticsLogger* SubscriptionTest::_analytics;
ACRFactory* SubscriptionTest::_acr_factory;
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
  string _scheme;

  SubscribeMessage() :
    _method("SUBSCRIBE"),
    _user("6505550231"),
    _domain("homedomain"),
    _contact("sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob"),
    _event("Event: reg"),
    _accepts("Accept: application/reginfo+xml"),
    _expires(""),
    _route("homedomain"),
    _auth(""),
    _record_route("Record-Route: <sip:sprout.example.com;transport=tcp;lr>"),
    _scheme("sip")
  {
  }

  string get();
};

string SubscribeMessage::get()
{
  char buf[16384];

  int n = snprintf(buf, sizeof(buf),
                   "%1$s sip:%3$s SIP/2.0\r\n"
                   "Via: SIP/2.0/TCP 10.83.18.38:36530;rport;branch=z9hG4bKPjmo1aimuq33BAI4rjhgQgBr4sY5e9kSPI\r\n"
                   "Via: SIP/2.0/TCP 10.114.61.213:5061;received=23.20.193.43;branch=z9hG4bK+7f6b263a983ef39b0bbda2135ee454871+sip+1+a64de9f6\r\n"
                   "From: <%2$s>;tag=10.114.61.213+1+8c8b232a+5fb751cf\r\n"
                   "To: <%2$s>\r\n"
                   "Max-Forwards: 68\r\n"
                   "Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqsUOO4ohntC@10.114.61.213\r\n"
                   "CSeq: 16567 %1$s\r\n"
                   "User-Agent: Accession 2.0.0.0\r\n"
                   "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n"
                   "%9$s"
                   "Contact: %7$s\r\n"
                   "Route: <sip:%8$s;transport=tcp;lr>\r\n"
                   "P-Access-Network-Info: DUMMY\r\n"
                   "P-Visited-Network-ID: DUMMY\r\n"
                   "P-Charging-Vector: icid-value=100\r\n"
                   "P-Charging-Function-Addresses: ccf=1.2.3.4; ecf=5.6.7.8\r\n"
                   "%10$s"
                   "%11$s"
                   "%12$s"
                   "%13$s"
                   "%4$s"
                   "Content-Length:  %5$d\r\n"
                   "\r\n"
                   "%6$s",

                   /*  1 */ _method.c_str(),
                   /*  2 */ (_scheme == "tel") ? string(_scheme).append(":").append(_user).c_str() : string(_scheme).append(":").append(_user).append("@").append(_domain).c_str(),
                   /*  3 */ _domain.c_str(),
                   /*  4 */ _content_type.empty() ? "" : string("Content-Type: ").append(_content_type).append("\r\n").c_str(),
                   /*  5 */ (int)_body.length(),
                   /*  6 */ _body.c_str(),
                   /*  7 */ (_contact == "*") ? "*" : string("<").append(_contact).append(">").c_str(),
                   /*  8 */ _route.c_str(),
                   /*  9 */ _expires.empty() ? "" : string("Expires: ").append(_expires).append("\r\n").c_str(),
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

TEST_F(SubscriptionTest, RouteHeaderNotMatching)
{
  SubscribeMessage msg;
  msg._route = "notthehomedomain";
  pj_bool_t ret = inject_msg_direct(msg.get());
  EXPECT_EQ(PJ_FALSE, ret);
  check_subscriptions("sip:6505550231@homedomain", 0u);
}

TEST_F(SubscriptionTest, BadScheme)
{
  SubscribeMessage msg;
  msg._scheme = "sips";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  out = pop_txdata()->msg;
  EXPECT_EQ(404, out->line.status.code);
  EXPECT_EQ("Not Found", str_pj(out->line.status.reason));
}

TEST_F(SubscriptionTest, EmergencySubscription)
{
  SubscribeMessage msg;
  msg._contact = "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob";
  inject_msg(msg.get());

  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(489, out->line.status.code);
  EXPECT_EQ("Bad Event", str_pj(out->line.status.reason));
  EXPECT_THAT(get_headers(out, "Allow-Events"), testing::MatchesRegex("Allow-Events: reg"));

  check_subscriptions("sip:6505550231@homedomain", 0u);
}

/// Simple correct example
TEST_F(SubscriptionTest, SimpleMainline)
{
  // Get an initial empty AoR record and add a binding.
  int now = time(NULL);

  RegStore::AoR* aor_data1 = _store->get_aor_data(std::string("sip:6505550231@homedomain"), 0);
  RegStore::AoR::Binding* b1 = aor_data1->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  b1->_uri = std::string("<sip:6505550231@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_emergency_registration = false;

  // Add the AoR record to the store.
  _store->set_aor_data(std::string("sip:6505550231@homedomain"), aor_data1, true, 0);
  delete aor_data1; aor_data1 = NULL;

  check_subscriptions("sip:6505550231@homedomain", 0u);

  SubscribeMessage msg;
  inject_msg(msg.get());
  check_OK_and_NOTIFY();
  check_subscriptions("sip:6505550231@homedomain", 1u);

  msg._expires = "0";
  inject_msg(msg.get());
  check_OK_and_NOTIFY(true);
}

/// Simple correct example with Tel URIs
TEST_F(SubscriptionTest, SimpleMainlineWithTelURI)
{
  // Get an initial empty AoR record and add a binding.
  int now = time(NULL);

  RegStore::AoR* aor_data1 = _store->get_aor_data(std::string("tel:6505550231"), 0);
  RegStore::AoR::Binding* b1 = aor_data1->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  b1->_uri = std::string("<sip:6505550231@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_emergency_registration = false;

  // Add the AoR record to the store.
  _store->set_aor_data(std::string("tel:6505550231"), aor_data1, true, 0);
  delete aor_data1; aor_data1 = NULL;

  check_subscriptions("tel:6505550231", 0u);

  SubscribeMessage msg;
  msg._scheme = "tel";
  inject_msg(msg.get());
  check_OK_and_NOTIFY();
  check_subscriptions("tel:6505550231", 1u);
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
  check_OK_and_NOTIFY();

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
  check_OK_and_NOTIFY();

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
  check_subscriptions("sip:6505550232@homedomain", 0u);
}

/// Homestead fails associated URI request
TEST_F(SubscriptionTest, AssociatedUrisTimeOut)
{
  SubscribeMessage msg;
  msg._user = "6505550232";
  _hss_connection->set_rc("/impu/sip%3A6505550232%40homedomain/reg-data",
                          503);

  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(504, out->line.status.code);
  EXPECT_EQ("Server Timeout", str_pj(out->line.status.reason));
  check_subscriptions("sip:6505550232@homedomain", 0u);

  _hss_connection->delete_rc("/impu/sip%3A6505550232%40homedomain/reg-data");
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
  check_OK_and_NOTIFY();
  check_subscriptions("sip:6505550233@homedomain", 1u);
}

/// Test that a NOTIFy doesn't include any emergency bindings
TEST_F(SubscriptionTest, NoNotificationsForEmergencyRegistrations)
{
  // Get an initial empty AoR record and add a standard and an emergency binding.
  int now = time(NULL);

  RegStore::AoR* aor_data1 = _store->get_aor_data(std::string("sip:6505550231@homedomain"), 0);
  RegStore::AoR::Binding* b1 = aor_data1->get_binding(std::string("sos<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1"));
  b1->_uri = std::string("<sip:6505550231@192.91.191.29:59934;transport=tcp;sos;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_emergency_registration = true;

  RegStore::AoR::Binding* b2 = aor_data1->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  b2->_uri = std::string("<sip:6505550231@192.91.191.29:59934;transport=tcp;ob>");
  b2->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b2->_cseq = 17038;
  b2->_expires = now + 300;
  b2->_priority = 0;
  b2->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  b2->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b2->_params["reg-id"] = "1";
  b2->_params["+sip.ice"] = "";
  b2->_emergency_registration = false;

  // Add the AoR record to the store.
  _store->set_aor_data(std::string("sip:6505550231@homedomain"), aor_data1, true, 0);
  delete aor_data1; aor_data1 = NULL;

  check_subscriptions("sip:6505550231@homedomain", 0u);

  SubscribeMessage msg;
  inject_msg(msg.get());

  ASSERT_EQ(2, txdata_count());
  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));

  // The NOTIFY should only contain the non-emergency binding
  out = current_txdata()->msg;
  EXPECT_EQ("NOTIFY", str_pj(out->line.status.reason));
  char buf[16384];
  int n = out->body->print_body(out->body, buf, sizeof(buf));
  string body(buf, n);
  EXPECT_THAT(body, HasSubstr("&lt;sip:6505550231@192.91.191.29:59934;transport=tcp;ob&gt;"));
  EXPECT_THAT(body, Not(HasSubstr("sos")));
  inject_msg(respond_to_current_txdata(200));

  check_subscriptions("sip:6505550231@homedomain", 1u);
}

void SubscriptionTest::check_subscriptions(std::string aor, uint32_t expected)
{
  // Check that we registered the correct URI (0233, not 0234).
  RegStore::AoR* aor_data = _store->get_aor_data(aor, 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(expected, aor_data->_subscriptions.size());
  delete aor_data; aor_data = NULL;
}


/// Check that subsequent NOTIFYs have updated CSeqs
TEST_F(SubscriptionTest, CheckNotifyCseqs)
{
  // Get an initial empty AoR record and add a binding.
  int now = time(NULL);

  RegStore::AoR* aor_data1 = _store->get_aor_data(std::string("sip:6505550231@homedomain"), 0);
  RegStore::AoR::Binding* b1 = aor_data1->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  b1->_uri = std::string("<sip:6505550231@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = now + 300;
  b1->_priority = 0;
  b1->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_emergency_registration = false;

  // Add the AoR record to the store.
  _store->set_aor_data(std::string("sip:6505550231@homedomain"), aor_data1, true, 0);
  delete aor_data1; aor_data1 = NULL;

  SubscribeMessage msg;
  inject_msg(msg.get());

  // Receive the SUBSCRIBE 200 OK and NOTIFY, then send NOTIFY 200 OK.
  ASSERT_EQ(2, txdata_count());
  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);

  out = current_txdata()->msg;
  EXPECT_EQ("NOTIFY", str_pj(out->line.status.reason));
  // Store off CSeq for later checking.
  std::string first_cseq = get_headers(out, "CSeq");
  inject_msg(respond_to_current_txdata(200));

  msg._expires = "0";
  inject_msg(msg.get());

  // Receive another SUBSCRIBE 200 OK and NOTIFY, then send NOTIFY 200 OK.
  ASSERT_EQ(2, txdata_count());
  out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  out = current_txdata()->msg;
  EXPECT_EQ("NOTIFY", str_pj(out->line.status.reason));
  std::string second_cseq = get_headers(out, "CSeq");
  inject_msg(respond_to_current_txdata(200));

  // Check the NOTIFY CSeq has increased.
  int first_cseq_val = strtol(&(first_cseq.c_str()[5]), NULL, 0);
  int second_cseq_val = strtol(&(second_cseq.c_str()[5]), NULL, 0);
  EXPECT_GT(second_cseq_val, first_cseq_val);
}

void SubscriptionTest::check_OK_and_NOTIFY(bool terminated)
{
  ASSERT_EQ(2, txdata_count());
  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_THAT(get_headers(out, "From"), testing::MatchesRegex("From: .*;tag=10.114.61.213\\+1\\+8c8b232a\\+5fb751cf"));

  // Pull out the to tag on the OK - check later that this matches the from tag on the Notify
  std::vector<std::string> to_params;
  Utils::split_string(get_headers(out, "To"), ';', to_params, 0, true);
  std::string to_tag = "No to tag in 200 OK";

  for (unsigned ii = 0; ii < to_params.size(); ii++)
  {
    if (to_params[ii].find("tag=") != string::npos)
    {
      to_tag = string(".*").append(to_params[ii]);
    }
  }

  EXPECT_EQ("P-Charging-Vector: icid-value=\"100\"", get_headers(out, "P-Charging-Vector"));
  EXPECT_EQ("P-Charging-Function-Addresses: ccf=1.2.3.4;ecf=5.6.7.8", get_headers(out, "P-Charging-Function-Addresses"));
  out = current_txdata()->msg;
  EXPECT_EQ("NOTIFY", str_pj(out->line.status.reason));
  EXPECT_EQ("Event: reg", get_headers(out, "Event"));

  if (terminated)
  {
    EXPECT_EQ("Subscription-State: terminated;reason=timeout", get_headers(out, "Subscription-State"));
  }
  else
  {
    EXPECT_EQ("Subscription-State: active;expires=300", get_headers(out, "Subscription-State"));
  }

  EXPECT_THAT(get_headers(out, "To"), testing::MatchesRegex("To: .*;tag=10.114.61.213\\+1\\+8c8b232a\\+5fb751cf"));
  EXPECT_THAT(get_headers(out, "From"), testing::MatchesRegex(to_tag));

  inject_msg(respond_to_current_txdata(200));
}


/// Fixture for Subscription tests that use a mock store instead of a fake one.
class SubscriptionTestMockStore : public SipTest
{
public:
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
    add_host_mapping("sprout.example.com", "10.8.8.1");
  }

  void SetUp()
  {
    _chronos_connection = new FakeChronosConnection();
    _local_data_store = new MockStore();
    _store = new RegStore((Store*)_local_data_store, _chronos_connection);
    _analytics = new AnalyticsLogger(&PrintingTestLogger::DEFAULT);
    _hss_connection = new FakeHSSConnection();
    _acr_factory = new ACRFactory();
    pj_status_t ret = init_subscription(_store, _hss_connection, _acr_factory, _analytics, 300);
    ASSERT_EQ(PJ_SUCCESS, ret);
    stack_data.scscf_uri = pj_str("sip:all.the.sprout.nodes:5058;transport=TCP");

    _hss_connection->set_impu_result("sip:6505550231@homedomain", "", HSSConnection::STATE_REGISTERED, "");
    _hss_connection->set_impu_result("tel:6505550231", "", HSSConnection::STATE_REGISTERED, "");

    _log_traffic = PrintingTestLogger::DEFAULT.isPrinting();
  }

  static void TearDownTestCase()
  {
    SipTest::TearDownTestCase();
  }

  void TearDown()
  {
    destroy_subscription();
    delete _acr_factory; _acr_factory = NULL;
    delete _hss_connection; _hss_connection = NULL;
    delete _analytics; _analytics = NULL;
    delete _store; _store = NULL;
    delete _local_data_store; _local_data_store = NULL;
    delete _chronos_connection; _chronos_connection = NULL;
  }

  SubscriptionTestMockStore() : SipTest(&mod_subscription)
  {
  }

protected:
  MockStore* _local_data_store;
  RegStore* _store;
  AnalyticsLogger* _analytics;
  ACRFactory* _acr_factory;
  FakeHSSConnection* _hss_connection;
  FakeChronosConnection* _chronos_connection;
};


// Check that the subscription module does not infinite loop when the underlying
// store is in an odd state, specifically when it:
// -  Returns NOT_FOUND to all gets
// -  Returns ERROR to all sets.
//
// This is a repro for https://github.com/Metaswitch/sprout/issues/977
TEST_F(SubscriptionTestMockStore, RegStoreWritesFail)
{
  EXPECT_CALL(*_local_data_store, get_data(_, _, _, _, _))
    .WillOnce(Return(Store::NOT_FOUND));

  EXPECT_CALL(*_local_data_store, set_data(_, _, _, _, _, _))
    .WillOnce(Return(Store::ERROR));

  SubscribeMessage msg;
  inject_msg(msg.get());

  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(500, out->line.status.code);
  free_txdata();
}
