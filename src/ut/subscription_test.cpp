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
#include <list>
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "siptest.hpp"
#include "utils.h"
#include "analyticslogger.h"
#include "mock_analytics_logger.h"
#include "stack.h"
#include "subscriptionsproutlet.h"
#include "sproutletproxy.h"
#include "fakehssconnection.hpp"
#include "test_interposer.hpp"
#include "fakechronosconnection.hpp"
#include "mock_store.h"
#include "rapidxml/rapidxml.hpp"

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
    SipTest::SetScscfUri("sip:all.the.sprout.nodes:5058;transport=TCP");
    add_host_mapping("sprout.example.com", "10.8.8.1");

    _chronos_connection = new FakeChronosConnection();
    _local_data_store = new LocalStore();
    _remote_data_store = new LocalStore();
    _sdm = new SubscriberDataManager((Store*)_local_data_store, _chronos_connection, true);
    _remote_sdm = new SubscriberDataManager((Store*)_remote_data_store, _chronos_connection, false);
    _analytics = new MockAnalyticsLogger();
    _hss_connection = new FakeHSSConnection();
    _acr_factory = new ACRFactory();

    _hss_connection->set_impu_result("sip:6505550231@homedomain", "", RegDataXMLUtils::STATE_REGISTERED, "");
    _hss_connection->set_impu_result("tel:6505550231", "", RegDataXMLUtils::STATE_REGISTERED, "");
  }

  static void TearDownTestCase()
  {
    // Shut down the transaction module first, before we destroy the
    // objects that might handle any callbacks!
    pjsip_tsx_layer_destroy();
    delete _acr_factory; _acr_factory = NULL;
    delete _hss_connection; _hss_connection = NULL;
    delete _analytics; _analytics = NULL;
    delete _remote_sdm; _remote_sdm = NULL;
    delete _sdm; _sdm = NULL;
    delete _remote_data_store; _remote_data_store = NULL;
    delete _local_data_store; _local_data_store = NULL;
    delete _chronos_connection; _chronos_connection = NULL;
    SipTest::TearDownTestCase();
  }

  SubscriptionTest()
  {
    _local_data_store->flush_all();  // start from a clean slate on each test
    _remote_data_store->flush_all();

    _subscription_sproutlet = new SubscriptionSproutlet("subscription",
                                                        5058,
                                                        "sip:subscription.homedomain:5058;transport=tcp",
                                                        "scscf-proxy",
                                                        _sdm,
                                                        {_remote_sdm},
                                                        _hss_connection,
                                                        _acr_factory,
                                                        _analytics,
                                                        300);
    EXPECT_TRUE(_subscription_sproutlet->init());

    std::list<Sproutlet*> sproutlets;
    sproutlets.push_back(_subscription_sproutlet);

    _subscription_proxy = new SproutletProxy(stack_data.endpt,
                                             PJSIP_MOD_PRIORITY_UA_PROXY_LAYER,
                                             "homedomain",
                                             std::unordered_set<std::string>(),
                                             sproutlets,
                                             std::set<std::string>());

    // Get an initial empty AoR record and add a binding.
    int now = time(NULL);
    SubscriberDataManager::AoRPair* aor_pair = _sdm->get_aor_data(std::string("sip:6505550231@homedomain"), 0);
    SubscriberDataManager::AoR::Binding* b1 = aor_pair->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
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
    std::vector<std::string> irs_impus;
    irs_impus.push_back("sip:6505550231@homedomain");
    _sdm->set_aor_data(irs_impus[0], irs_impus, aor_pair, 0);
    delete aor_pair; aor_pair = NULL;

    _log_traffic = PrintingTestLogger::DEFAULT.isPrinting();
  }

  ~SubscriptionTest()
  {
    pjsip_tsx_layer_dump(true);

    // Terminate all transactions
    std::list<pjsip_transaction*> tsxs = get_all_tsxs();
    for (std::list<pjsip_transaction*>::iterator it2 = tsxs.begin();
         it2 != tsxs.end();
         ++it2)
    {
      pjsip_tsx_terminate(*it2, PJSIP_SC_SERVICE_UNAVAILABLE);
    }

    // PJSIP transactions aren't actually destroyed until a zero ms
    // timer fires (presumably to ensure destruction doesn't hold up
    // real work), so poll for that to happen. Otherwise we leak!
    // Allow a good length of time to pass too, in case we have
    // transactions still open. 32s is the default UAS INVITE
    // transaction timeout, so we go higher than that.
    cwtest_advance_time_ms(33000L);
    poll();
    // Stop and restart the transaction layer just in case
    pjsip_tsx_layer_instance()->stop();
    pjsip_tsx_layer_instance()->start();

    delete _subscription_proxy; _subscription_proxy = NULL;
    delete _subscription_sproutlet; _subscription_sproutlet = NULL;

    ::testing::Mock::VerifyAndClearExpectations(_analytics);
  }

void subscription_sproutlet_handle_200()
{
  ASSERT_EQ(1, txdata_count());
  inject_msg(respond_to_current_txdata(200));
  ASSERT_EQ(1, txdata_count());
  EXPECT_EQ(200, current_txdata()->msg->line.status.code);
  free_txdata();
}

protected:
  static LocalStore* _local_data_store;
  static LocalStore* _remote_data_store;
  static SubscriberDataManager* _sdm;
  static SubscriberDataManager* _remote_sdm;
  static MockAnalyticsLogger* _analytics;
  static ACRFactory* _acr_factory;
  static FakeHSSConnection* _hss_connection;
  static FakeChronosConnection* _chronos_connection;
  SubscriptionSproutlet* _subscription_sproutlet;
  SproutletProxy* _subscription_proxy;

  void check_subscriptions(std::string aor, uint32_t expected);
  std::string check_OK_and_NOTIFY(std::string reg_state,
                                  std::pair<std::string, std::string> contact_values,
                                  std::vector<std::pair<std::string, bool>> irs_impus,
                                  bool terminated = false,
                                  std::string reason = "");
};

LocalStore* SubscriptionTest::_local_data_store;
LocalStore* SubscriptionTest::_remote_data_store;
SubscriberDataManager* SubscriptionTest::_sdm;
SubscriberDataManager* SubscriptionTest::_remote_sdm;
MockAnalyticsLogger* SubscriptionTest::_analytics;
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
  string _branch;
  string _scheme;
  string _to_tag;
  int _unique; //< unique to this dialog; inserted into Call-ID

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
    _branch(""),
    _scheme("sip"),
    _to_tag("")
  {
    static int unique = 1042;
    _unique = unique;
    unique += 10; // leave room for manual increments
  }

  string get();
};

string SubscribeMessage::get()
{
  char buf[16384];

  std::string branch = _branch.empty() ? "Pjmo1aimuq33BAI4rjhgQgBr4sY" + std::to_string(_unique) : _branch;

  int n = snprintf(buf, sizeof(buf),
                   "%1$s sip:%3$s SIP/2.0\r\n"
                   "Via: SIP/2.0/TCP 10.83.18.38:36530;rport;branch=z9hG4bK%15$s\r\n"
                   "Via: SIP/2.0/TCP 10.114.61.213:5061;received=23.20.193.43;branch=z9hG4bK+7f6b263a983ef39b0bbda2135ee454871+sip+1+a64de9f6\r\n"
                   "From: <%2$s>;tag=10.114.61.213+1+8c8b232a+5fb751cf\r\n"
                   "To: <%2$s>%14$s\r\n"
                   "Max-Forwards: 68\r\n"
                   "Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs%16$04dohntC@10.114.61.213\r\n"
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
                   /* 13 */ _record_route.empty() ? "" : string(_record_route).append("\r\n").c_str(),
                   /* 14 */ _to_tag.empty() ? "": string(";tag=").append(_to_tag).c_str(),
                   /* 15 */ branch.c_str(),
                   /* 16 */ _unique
    );

  EXPECT_LT(n, (int)sizeof(buf));

  string ret(buf, n);
  return ret;
}


TEST_F(SubscriptionTest, NotSubscribe)
{
  SubscribeMessage msg;
  msg._method = "PUBLISH";
  inject_msg(msg.get());
  subscription_sproutlet_handle_200();
  check_subscriptions("sip:6505550231@homedomain", 0u);
}

TEST_F(SubscriptionTest, NotOurs)
{
  SubscribeMessage msg;
  msg._domain = "not-us.example.org";
  inject_msg(msg.get());
  subscription_sproutlet_handle_200();
  check_subscriptions("sip:6505550231@homedomain", 0u);
}

TEST_F(SubscriptionTest, RouteHeaderNotMatching)
{
  SubscribeMessage msg;
  msg._route = "notthehomedomain";
  inject_msg(msg.get());
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
  check_subscriptions("sip:6505550231@homedomain", 0u);

  // Set up a single subscription - this should generate a 200 OK then
  // a NOTIFY
  EXPECT_CALL(*(this->_analytics),
              subscription("sip:6505550231@homedomain",
                           _,
                           "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob",
                           300)).Times(1);
  SubscribeMessage msg;
  inject_msg(msg.get());

  std::vector<std::pair<std::string, bool>> irs_impus;
  irs_impus.push_back(std::make_pair("sip:6505550231@homedomain", false));

  std::string to_tag = check_OK_and_NOTIFY("active", std::make_pair("active", "registered"), irs_impus);
  check_subscriptions("sip:6505550231@homedomain", 1u);

  // Actively expire the subscription - this generates a 200 OK and a
  // final NOTIFY
  EXPECT_CALL(*(this->_analytics),
              subscription("sip:6505550231@homedomain",
                           _,
                           "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob",
                           0)).Times(1);
  msg._to_tag = to_tag;
  msg._unique += 1;
  msg._expires = "0";
  inject_msg(msg.get());
  check_OK_and_NOTIFY("active", std::make_pair("active", "registered"), irs_impus, true, "timeout");

  check_subscriptions("sip:6505550231@homedomain", 0u);
}

/// Simple correct example with Tel URIs
TEST_F(SubscriptionTest, SimpleMainlineWithTelURI)
{
  // Get an initial empty AoR record and add a binding (with the Tel URI)
  int now = time(NULL);
  SubscriberDataManager::AoRPair* aor_pair = _sdm->get_aor_data(std::string("tel:6505550231"), 0);
  SubscriberDataManager::AoR::Binding* b1 = aor_pair->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
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
  std::vector<std::string> irs_impus;
  irs_impus.push_back("tel:6505550231");
  _sdm->set_aor_data(irs_impus[0], irs_impus, aor_pair, 0);
  delete aor_pair; aor_pair = NULL;

  check_subscriptions("tel:6505550231", 0u);

  SubscribeMessage msg;
  msg._scheme = "tel";
  EXPECT_CALL(*(this->_analytics),
              subscription("tel:6505550231",
                           _,
                           "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob",
                           300)).Times(1);
  inject_msg(msg.get());

  std::vector<std::pair<std::string, bool>> irs_impus_check;
  irs_impus_check.push_back(std::make_pair("tel:6505550231", false));

  std::string to_tag = check_OK_and_NOTIFY("active", std::make_pair("active", "registered"), irs_impus_check);
  check_subscriptions("tel:6505550231", 1u);

  // Actively expire the subscription - this generates a 200 OK and a
  // final NOTIFY
  msg._to_tag = to_tag;
  msg._unique += 1;
  msg._expires = "0";
  EXPECT_CALL(*(this->_analytics),
              subscription("tel:6505550231",
                           _,
                           "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob",
                           0)).Times(1);
  inject_msg(msg.get());
  check_OK_and_NOTIFY("active", std::make_pair("active", "registered"), irs_impus_check, true, "timeout");
}

/// Check that a subscription with immediate expiry is treated correctly
TEST_F(SubscriptionTest, OneShotSubscription)
{
  check_subscriptions("sip:6505550231@homedomain", 0u);

  // Set up a single subscription - this should generate a 200 OK then
  // a NOTIFY
  SubscribeMessage msg;
  msg._expires = "0";
  EXPECT_CALL(*(this->_analytics),
              subscription("sip:6505550231@homedomain",
                           _,
                           "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob",
                           0)).Times(1);
  inject_msg(msg.get());

  std::vector<std::pair<std::string, bool>> irs_impus;
  irs_impus.push_back(std::make_pair("sip:6505550231@homedomain", false));

  check_OK_and_NOTIFY("active", std::make_pair("active", "registered"), irs_impus, true, "timeout");

  // Check there's no subscriptions stored
  check_subscriptions("sip:6505550231@homedomain", 0u);
}

/// Check that a subscription where there are no bindings is treated
/// correctly (note, this isn't a particularly realistic scenario)
TEST_F(SubscriptionTest, SubscriptionWithNoBindings)
{
  _local_data_store->flush_all();
  _remote_data_store->flush_all();

  check_subscriptions("sip:6505550231@homedomain", 0u);

  // Set up a single subscription - this should generate a 200 OK then
  // a NOTIFY
  SubscribeMessage msg;
  EXPECT_CALL(*(this->_analytics),
              subscription("sip:6505550231@homedomain",
                           _,
                           "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob",
                           300)).Times(1);
  inject_msg(msg.get());

  // Check the NOTIFY
  EXPECT_EQ(2, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ("NOTIFY", str_pj(out->line.status.reason));
  EXPECT_EQ("Subscription-State: terminated;reason=deactivated", get_headers(out, "Subscription-State"));
  char buf[16384];
  int n = out->body->print_body(out->body, buf, sizeof(buf));
  string body(buf, n);

  // Parse the XML document, saving off the passed in string first (as parsing
  // is destructive)
  rapidxml::xml_document<> doc;
  char* xml_str = doc.allocate_string(body.c_str());

  try
  {
    doc.parse<rapidxml::parse_strip_xml_namespaces>(xml_str);
  }
  catch (rapidxml::parse_error err)
  {
    printf("Parse error in NOTIFY: %s\n\n%s", err.what(), body.c_str());
    doc.clear();
  }

  rapidxml::xml_node<> *reg_info = doc.first_node("reginfo");
  EXPECT_TRUE(reg_info);
  rapidxml::xml_node<> *registration = reg_info->first_node("registration");
  EXPECT_TRUE(registration);
  rapidxml::xml_node<> *contact = registration->first_node("contact");
  EXPECT_FALSE(contact);

  EXPECT_EQ("full", std::string(reg_info->first_attribute("state")->value()));
  EXPECT_EQ("terminated", std::string(registration->first_attribute("state")->value()));
  inject_msg(respond_to_current_txdata(200));

  // Get OK
  out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));

  // Check there's no subscriptions stored
  check_subscriptions("sip:6505550231@homedomain", 0u);
}

/// Check that a subscription where there is data contention doesn't
/// generate any duplicate NOTIFYs
TEST_F(SubscriptionTest, SubscriptionWithDataContention)
{
  _local_data_store->force_contention();

  // Set up a single subscription - this should generate a 200 OK then
  // a NOTIFY
  SubscribeMessage msg;
  EXPECT_CALL(*(this->_analytics),
              subscription("sip:6505550231@homedomain",
                           _,
                           "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob",
                           300)).Times(1);
  inject_msg(msg.get());

  std::vector<std::pair<std::string, bool>> irs_impus;
  irs_impus.push_back(std::make_pair("sip:6505550231@homedomain", false));

  check_OK_and_NOTIFY("active", std::make_pair("active", "registered"), irs_impus);

  // Check there's one subscription stored
  check_subscriptions("sip:6505550231@homedomain", 1u);
}

// Test the Event Header
// Missing Event header should be rejected
TEST_F(SubscriptionTest, MissingEventHeader)
{
  check_subscriptions("sip:6505550231@homedomain", 0u);

  SubscribeMessage msg;
  msg._event = "";
  inject_msg(msg.get());
  check_subscriptions("sip:6505550231@homedomain", 0u);
}

// Test the Event Header
// Event that isn't reg should be rejected
TEST_F(SubscriptionTest, IncorrectEventHeader)
{
  check_subscriptions("sip:6505550231@homedomain", 0u);

  SubscribeMessage msg;
  msg._event = "Event: Not Reg";
  inject_msg(msg.get());
  check_subscriptions("sip:6505550231@homedomain", 0u);

  SubscribeMessage msg2;
  msg2._event = "Event: Reg";
  inject_msg(msg2.get());
  check_subscriptions("sip:6505550231@homedomain", 0u);
}

// Test Accept Header. A message with no accepts header should be accepted
TEST_F(SubscriptionTest, EmptyAcceptsHeader)
{
  check_subscriptions("sip:6505550231@homedomain", 0u);

  SubscribeMessage msg;
  msg._accepts = "";
  EXPECT_CALL(*(this->_analytics),
              subscription("sip:6505550231@homedomain",
                           _,
                           "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob",
                           300)).Times(1);
  inject_msg(msg.get());

  std::vector<std::pair<std::string, bool>> irs_impus;
  irs_impus.push_back(std::make_pair("sip:6505550231@homedomain", false));

  check_OK_and_NOTIFY("active", std::make_pair("active", "registered"), irs_impus);

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
  inject_msg(msg.get());
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
  EXPECT_CALL(*(this->_analytics),
              subscription("sip:6505550231@homedomain",
                           _,
                           "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob",
                           300)).Times(1);
  inject_msg(msg.get());

  std::vector<std::pair<std::string, bool>> irs_impus;
  irs_impus.push_back(std::make_pair("sip:6505550231@homedomain", false));

  check_OK_and_NOTIFY("active", std::make_pair("active", "registered"), irs_impus);

  check_subscriptions("sip:6505550231@homedomain", 1u);
}

/// Homestead fails associated URI request as the subscriber doesn't exist
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
TEST_F(SubscriptionTest, AssociatedUrisFailure)
{
  SubscribeMessage msg;
  msg._user = "6505550232";
  _hss_connection->set_rc("/impu/sip%3A6505550232%40homedomain/reg-data",
                          500);

  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(500, out->line.status.code);
  EXPECT_EQ("Internal Server Error", str_pj(out->line.status.reason));
  check_subscriptions("sip:6505550232@homedomain", 0u);

  _hss_connection->delete_rc("/impu/sip%3A6505550232%40homedomain/reg-data");
}

/// Homestead times out associated URI request
TEST_F(SubscriptionTest, AssociatedUrisTimeOut)
{
  SubscribeMessage msg;
  msg._user = "6505550232";
  _hss_connection->set_rc("/impu/sip%3A6505550232%40homedomain/reg-data",
                          503);

  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(504, out->line.status.code);
  EXPECT_EQ("Server Timeout", str_pj(out->line.status.reason));
  check_subscriptions("sip:6505550232@homedomain", 0u);

  _hss_connection->delete_rc("/impu/sip%3A6505550232%40homedomain/reg-data");
}

/// Register with non-primary P-Associated-URI
TEST_F(SubscriptionTest, NonPrimaryAssociatedUri)
{
  // Get an initial empty AoR record and add a binding.
  int now = time(NULL);
  SubscriberDataManager::AoRPair* aor_pair = _sdm->get_aor_data(std::string("sip:6505550233@homedomain"), 0);
  SubscriberDataManager::AoR::Binding* b1 = aor_pair->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
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
  std::vector<std::string> irs_impus;
  irs_impus.push_back("sip:6505550233@homedomain");
  _sdm->set_aor_data(irs_impus[0], irs_impus, aor_pair, 0);
  delete aor_pair; aor_pair = NULL;

  SubscribeMessage msg;
  msg._user = "6505550234";
  _hss_connection->set_impu_result("sip:6505550234@homedomain",
                                   "",
                                   RegDataXMLUtils::STATE_REGISTERED,
                                   "<IMSSubscription><ServiceProfile>\n"
                                   "  <PublicIdentity><Identity>sip:6505550233@homedomain</Identity></PublicIdentity>\n"
                                   "  <PublicIdentity><Identity>sip:6505550234@homedomain</Identity></PublicIdentity>\n"
                                   "  <InitialFilterCriteria>\n"
                                   "  </InitialFilterCriteria>\n"
                                   "</ServiceProfile></IMSSubscription>");

  EXPECT_CALL(*(this->_analytics),
              subscription("sip:6505550233@homedomain",
                           _,
                           "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob",
                           300)).Times(1);
  inject_msg(msg.get());

  // We expect one registration element per IMPU in the Implicit Registration Set
  std::vector<std::pair<std::string, bool>> irs_impus_check;
  irs_impus_check.push_back(std::make_pair("sip:6505550233@homedomain", false));
  irs_impus_check.push_back(std::make_pair("sip:6505550234@homedomain", false));

  check_OK_and_NOTIFY("active", std::make_pair("active", "registered"), irs_impus_check);
  check_subscriptions("sip:6505550233@homedomain", 1u);
}

/// Test that a NOTIFy doesn't include any emergency bindings
TEST_F(SubscriptionTest, NoNotificationsForEmergencyRegistrations)
{
  // Get an initial empty AoR record and add a standard and an emergency binding.
  int now = time(NULL);

  SubscriberDataManager::AoRPair* aor_data1 = _sdm->get_aor_data(std::string("sip:6505550231@homedomain"), 0);
  SubscriberDataManager::AoR::Binding* b1 = aor_data1->get_current()->get_binding(std::string("sos<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1"));
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

  SubscriberDataManager::AoR::Binding* b2 = aor_data1->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
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
  std::vector<std::string> irs_impus;
  irs_impus.push_back("sip:6505550231@homedomain");
  _sdm->set_aor_data(irs_impus[0], irs_impus, aor_data1, 0);
  delete aor_data1; aor_data1 = NULL;

  check_subscriptions("sip:6505550231@homedomain", 0u);

  SubscribeMessage msg;
  EXPECT_CALL(*(this->_analytics),
              subscription("sip:6505550231@homedomain",
                           _,
                           "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob",
                           300)).Times(1);
  inject_msg(msg.get());

  // The NOTIFY should only contain the non-emergency binding
  ASSERT_EQ(2, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ("NOTIFY", str_pj(out->line.status.reason));
  char buf[16384];
  int n = out->body->print_body(out->body, buf, sizeof(buf));
  string body(buf, n);
  EXPECT_THAT(body, HasSubstr("&lt;sip:6505550231@192.91.191.29:59934;transport=tcp;ob&gt;"));
  EXPECT_THAT(body, Not(HasSubstr("sos")));
  inject_msg(respond_to_current_txdata(200));

  // Get OK
  out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));

  check_subscriptions("sip:6505550231@homedomain", 1u);
}

/// Check that subsequent NOTIFYs have updated CSeqs
TEST_F(SubscriptionTest, CheckNotifyCseqs)
{
  SubscribeMessage msg;
  EXPECT_CALL(*(this->_analytics),
              subscription("sip:6505550231@homedomain",
                           _,
                           "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob",
                           300)).Times(1);
  inject_msg(msg.get());

  // Receive the SUBSCRIBE 200 OK and NOTIFY, then send NOTIFY 200 OK.
  ASSERT_EQ(2, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ("NOTIFY", str_pj(out->line.status.reason));

  // Store off CSeq for later checking.
  std::string first_cseq = get_headers(out, "CSeq");
  inject_msg(respond_to_current_txdata(200));

  // Receive OK
  out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  std::vector<std::string> to_params;
  Utils::split_string(get_headers(out, "To"), ';', to_params, 0, true);
  std::string to_tag = "No to tag in 200 OK";
  for (unsigned ii = 0; ii < to_params.size(); ii++)
  {
    if (to_params[ii].find("tag=") != string::npos)
    {
      to_tag = to_params[ii].substr(4);
    }
  }

  msg._expires = "0";
  msg._unique += 1;
  msg._to_tag = to_tag;
  EXPECT_CALL(*(this->_analytics),
              subscription("sip:6505550231@homedomain",
                           _,
                           "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob",
                           0)).Times(1);
  inject_msg(msg.get());

  // Receive another SUBSCRIBE 200 OK and NOTIFY, then send NOTIFY 200 OK.
  ASSERT_EQ(2, txdata_count());
  out = current_txdata()->msg;
  EXPECT_EQ("NOTIFY", str_pj(out->line.status.reason));
  std::string second_cseq = get_headers(out, "CSeq");
  inject_msg(respond_to_current_txdata(200));
  out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);

  // Check the NOTIFY CSeq has increased.
  int first_cseq_val = strtol(&(first_cseq.c_str()[5]), NULL, 0);
  int second_cseq_val = strtol(&(second_cseq.c_str()[5]), NULL, 0);
  EXPECT_GT(second_cseq_val, first_cseq_val);
}

/// Check that a subscription with a wildcard has the correct NOTIFY format
TEST_F(SubscriptionTest, SubscriptionWithWildcard)
{
  // Get an initial empty AoR record and add a binding.
  int now = time(NULL);
  SubscriberDataManager::AoRPair* aor_pair = _sdm->get_aor_data(std::string("sip:6505551231@homedomain"), 0);
  SubscriberDataManager::AoR::Binding* b1 = aor_pair->get_current()->get_binding(std::string("urn:uuid:00000000-0000-0000-0000-b4dd32817622:1"));
  b1->_uri = std::string("<sip:6505551231@192.91.191.29:59934;transport=tcp;ob>");
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
  std::vector<std::string> irs_impus_aor;
  irs_impus_aor.push_back("sip:6505551231@homedomain");
  _sdm->set_aor_data(irs_impus_aor[0], irs_impus_aor, aor_pair, 0);
  delete aor_pair; aor_pair = NULL;

  _hss_connection->set_impu_result("sip:6505551231@homedomain", "", RegDataXMLUtils::STATE_REGISTERED,
                                   "<IMSSubscription><ServiceProfile>\n"
                                   "<PublicIdentity><Identity>sip:6505551231@homedomain</Identity></PublicIdentity>"
                                   "<PublicIdentity><Identity>sip:6505551!.*!@homedomain</Identity><Extension><IdentityType>4</IdentityType><WildcardedIMPU>sip:6505551!.*!@homedomain</WildcardedIMPU></Extension></PublicIdentity>"
                                   "<PublicIdentity><Identity>sip:650555!.*!@homedomain</Identity><Extension><IdentityType>4</IdentityType><WildcardedIMPU>sip:650555!.*!@homedomain</WildcardedIMPU></Extension></PublicIdentity>"
                                   "<PublicIdentity><Identity>sip:6505551232@homedomain</Identity></PublicIdentity>"
                                   "<PublicIdentity><Identity>sip:6505551233@homedomain</Identity><Extension><IdentityType>3</IdentityType><Extension><Extension><WildcardedIMPU>sip:650555!.*!@homedomain</WildcardedIMPU></Extension></Extension></Extension></PublicIdentity>"
                                   "  <InitialFilterCriteria>\n"
                                   "  </InitialFilterCriteria>\n"
                                   "</ServiceProfile></IMSSubscription>");

  // Set up a single subscription - this should generate a 200 OK then
  // a NOTIFY
  SubscribeMessage msg;
  msg._user = "6505551231";
  EXPECT_CALL(*(this->_analytics),
              subscription("sip:6505551231@homedomain",
                           _,
                           "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob",
                           300)).Times(1);
  inject_msg(msg.get());

  std::vector<std::pair<std::string, bool>> irs_impus;
  irs_impus.push_back(std::make_pair("sip:6505551231@homedomain", false));
  irs_impus.push_back(std::make_pair("sip:6505551!.*!@homedomain", true));
  irs_impus.push_back(std::make_pair("sip:650555!.*!@homedomain", true));
  irs_impus.push_back(std::make_pair("sip:6505551232@homedomain", false));

  check_OK_and_NOTIFY("active", std::make_pair("active", "registered"), irs_impus);

  // Check there's one subscription stored
  check_subscriptions("sip:6505551231@homedomain", 1u);
}

void SubscriptionTest::check_subscriptions(std::string aor, uint32_t expected)
{
  // Check that we registered the correct URI (0233, not 0234).
  SubscriberDataManager::AoRPair* aor_data = _sdm->get_aor_data(aor, 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(expected, aor_data->get_current()->_subscriptions.size());
  delete aor_data; aor_data = NULL;
}

std::string SubscriptionTest::check_OK_and_NOTIFY(std::string reg_state,
                                                  std::pair<std::string, std::string> contact_values,
                                                  std::vector<std::pair<std::string, bool>> irs_impus,
                                                  bool terminated,
                                                  std::string reason)
{
  EXPECT_EQ(2, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ("NOTIFY", str_pj(out->line.status.reason));
  EXPECT_EQ("Event: reg", get_headers(out, "Event"));

  if (terminated)
  {
    EXPECT_EQ(std::string("Subscription-State: terminated;reason=").append(reason), get_headers(out, "Subscription-State"));
  }
  else
  {
    EXPECT_EQ("Subscription-State: active;expires=300", get_headers(out, "Subscription-State"));
  }

  char buf[16384];
  int n = out->body->print_body(out->body, buf, sizeof(buf));
  string body(buf, n);

  // Parse the XML document, saving off the passed in string first (as parsing
  // is destructive)
  rapidxml::xml_document<> doc;
  char* xml_str = doc.allocate_string(body.c_str());

  try
  {
    doc.parse<rapidxml::parse_strip_xml_namespaces>(xml_str);
  }
  catch (rapidxml::parse_error err)
  {
    printf("Parse error in NOTIFY: %s\n\n%s", err.what(), body.c_str());
    doc.clear();
  }

  rapidxml::xml_node<> *reg_info = doc.first_node("reginfo");
  EXPECT_TRUE(reg_info);

  int num_reg = 0;

  for (rapidxml::xml_node<> *registration = reg_info->first_node("registration");
       registration;
       registration = registration->next_sibling("registration"), num_reg++)
  {
    // Check if the registration element should have a wildcard identity. We pass
    // this in as a simple bool rather than use is_wildcard_identity, as using
    // the function in UT and production code will mask any issues with it.
    if (irs_impus.at(num_reg).second)
    {
      // In the wildcard case the aor value should be set to the default value,
      // and the wildcard identity is in its own element (note that the ere: namespace
      // has been stripped off already when we parse this in UT).
      EXPECT_EQ("sip:wildcardimpu@wildcard", std::string(registration->first_attribute("aor")->value()));
      rapidxml::xml_node<> *wildcard = registration->first_node("wildcardedIdentity");
      EXPECT_TRUE(wildcard);
      EXPECT_EQ(irs_impus.at(num_reg).first, std::string(wildcard->value()));
    }
    else
    {
      EXPECT_EQ(irs_impus.at(num_reg).first, std::string(registration->first_attribute("aor")->value()));
    }

    rapidxml::xml_node<> *contact = registration->first_node("contact");
    EXPECT_TRUE(contact);

    EXPECT_EQ("full", std::string(reg_info->first_attribute("state")->value()));
    EXPECT_EQ(reg_state, std::string(registration->first_attribute("state")->value()));
    EXPECT_EQ(contact_values.first, std::string(contact->first_attribute("state")->value()));
    EXPECT_EQ(contact_values.second, std::string(contact->first_attribute("event")->value()));
  }

  // We should have found one registration element for each IMPU
  EXPECT_EQ(irs_impus.size(), num_reg);

  EXPECT_THAT(get_headers(out, "To"), testing::MatchesRegex("To: .*;tag=10.114.61.213\\+1\\+8c8b232a\\+5fb751cf"));

  // Store off From header for later.
  std::string from_hdr = get_headers(out, "From");
  inject_msg(respond_to_current_txdata(200));

  out = pop_txdata()->msg;
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
      to_tag = to_params[ii].substr(4);
    }
  }

  EXPECT_EQ("P-Charging-Vector: icid-value=\"100\"", get_headers(out, "P-Charging-Vector"));
  EXPECT_EQ("P-Charging-Function-Addresses: ccf=1.2.3.4;ecf=5.6.7.8", get_headers(out, "P-Charging-Function-Addresses"));

  EXPECT_THAT(from_hdr, testing::MatchesRegex(string(".*tag=").append(to_tag)));

  return to_tag;
}


/// Fixture for Subscription tests that use a mock store instead of a fake one.
/// Also use a real analyticslogger to get UT coverage of that.
class SubscriptionTestMockStore : public SipTest
{
public:
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
    SipTest::SetScscfUri("sip:all.the.sprout.nodes:5058;transport=TCP");
    add_host_mapping("sprout.example.com", "10.8.8.1");
  }

  void SetUp()
  {
    _chronos_connection = new FakeChronosConnection();
    _local_data_store = new MockStore();
    _sdm = new SubscriberDataManager((Store*)_local_data_store, _chronos_connection, true);
    _analytics = new AnalyticsLogger();
    _hss_connection = new FakeHSSConnection();
    _acr_factory = new ACRFactory();

    _hss_connection->set_impu_result("sip:6505550231@homedomain", "", RegDataXMLUtils::STATE_REGISTERED, "");
    _hss_connection->set_impu_result("tel:6505550231", "", RegDataXMLUtils::STATE_REGISTERED, "");

    _log_traffic = PrintingTestLogger::DEFAULT.isPrinting();

    _subscription_sproutlet = new SubscriptionSproutlet("subscription",
                                                        5058,
                                                        "sip:subscription.homedomain:5058;transport=tcp",
                                                        "scscf-proxy",
                                                        _sdm,
                                                        {},
                                                        _hss_connection,
                                                        _acr_factory,
                                                        _analytics,
                                                        300);

    std::list<Sproutlet*> sproutlets;
    sproutlets.push_back(_subscription_sproutlet);

    _subscription_proxy = new SproutletProxy(stack_data.endpt,
                                             PJSIP_MOD_PRIORITY_UA_PROXY_LAYER,
                                             "homedomain",
                                             std::unordered_set<std::string>(),
                                             sproutlets,
                                             std::set<std::string>());
  }

  static void TearDownTestCase()
  {
    // Shut down the transaction module first, before we destroy the
    // objects that might handle any callbacks!
    pjsip_tsx_layer_destroy();
    SipTest::TearDownTestCase();
  }

  void TearDown()
  {
    delete _acr_factory; _acr_factory = NULL;
    delete _hss_connection; _hss_connection = NULL;
    delete _analytics; _analytics = NULL;
    delete _sdm; _sdm = NULL;
    delete _local_data_store; _local_data_store = NULL;
    delete _chronos_connection; _chronos_connection = NULL;
  }

  ~SubscriptionTestMockStore()
  {
    pjsip_tsx_layer_dump(true);

    // Terminate all transactions
    std::list<pjsip_transaction*> tsxs = get_all_tsxs();
    for (std::list<pjsip_transaction*>::iterator it2 = tsxs.begin();
         it2 != tsxs.end();
         ++it2)
    {
      pjsip_tsx_terminate(*it2, PJSIP_SC_SERVICE_UNAVAILABLE);
    }

    // PJSIP transactions aren't actually destroyed until a zero ms
    // timer fires (presumably to ensure destruction doesn't hold up
    // real work), so poll for that to happen. Otherwise we leak!
    // Allow a good length of time to pass too, in case we have
    // transactions still open. 32s is the default UAS INVITE
    // transaction timeout, so we go higher than that.
    cwtest_advance_time_ms(33000L);
    poll();
    // Stop and restart the transaction layer just in case
    pjsip_tsx_layer_instance()->stop();
    pjsip_tsx_layer_instance()->start();

    delete _subscription_proxy; _subscription_proxy = NULL;
    delete _subscription_sproutlet; _subscription_sproutlet = NULL;
  }

protected:
  MockStore* _local_data_store;
  SubscriberDataManager* _sdm;
  AnalyticsLogger* _analytics;
  ACRFactory* _acr_factory;
  FakeHSSConnection* _hss_connection;
  FakeChronosConnection* _chronos_connection;
  SubscriptionSproutlet* _subscription_sproutlet;
  SproutletProxy* _subscription_proxy;
};


// Check that the subscription module does not infinite loop when the underlying
// store is in an odd state, specifically when it:
// -  Returns NOT_FOUND to all gets
// -  Returns ERROR to all sets.
//
// This is a repro for https://github.com/Metaswitch/sprout/issues/977
TEST_F(SubscriptionTestMockStore, SubscriberDataManagerWritesFail)
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
