/**
 * @file subscription_test.cpp
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <string>
#include <list>
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "siptest.hpp"
#include "utils.h"
#include "stack.h"
#include "subscriptionsproutlet.h"
#include "sproutletproxy.h"
#include "test_interposer.hpp"
#include "mock_subscriber_manager.h"
#include "rapidxml/rapidxml.hpp"

using ::testing::MatchesRegex;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::_;
using ::testing::Return;
using ::testing::An;

class SubscribeMessage
{
public:
  string _method;
  string _user;
  string _subscribing_user;
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
  string _req_uri_scheme;
  int _unique; //< unique to this dialog; inserted into Call-ID

  SubscribeMessage() :
    _method("SUBSCRIBE"),
    _user("6505550231"),
    _subscribing_user("6505550231"),
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
    _to_tag(""),
    _req_uri_scheme("sip")
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
  char from_uri[256];
  char to_uri[256];

  char req_uri[256];

  if (_req_uri_scheme == "tel")
  {
    snprintf(req_uri, sizeof(req_uri),
             "%s:%s",
             _req_uri_scheme.c_str(),
             _subscribing_user.c_str());

    snprintf(from_uri, sizeof(from_uri),
             "%s:%s",
             _scheme.c_str(),
             _domain.c_str());

    snprintf(to_uri, sizeof(to_uri),
             "%s:%s",
             _req_uri_scheme.c_str(),
             _subscribing_user.c_str());
  }
  else
  {
    snprintf(req_uri, sizeof(req_uri),
             "%s:%s",
             _req_uri_scheme.c_str(),
             _domain.c_str());

    if (_scheme == "tel")
    {
      snprintf(from_uri, sizeof(from_uri),
               "%s:%s",
               _scheme.c_str(),
               _subscribing_user.c_str());
      snprintf(to_uri, sizeof(to_uri),
               "%s:%s",
               _scheme.c_str(),
               _user.c_str());
    }
    else
    {
      snprintf(from_uri, sizeof(from_uri),
               "%s:%s@%s",
               _scheme.c_str(),
               _subscribing_user.c_str(),
               _domain.c_str());
      snprintf(to_uri, sizeof(to_uri),
               "%s:%s@%s",
               _scheme.c_str(),
               _user.c_str(),
               _domain.c_str());
    }
  }

  int n = snprintf(buf, sizeof(buf),
                   "%1$s %3$s SIP/2.0\r\n"
                   "Via: SIP/2.0/TCP 10.83.18.38:36530;rport;branch=z9hG4bK%15$s\r\n"
                   "Via: SIP/2.0/TCP 10.114.61.213:5061;received=23.20.193.43;branch=z9hG4bK+7f6b263a983ef39b0bbda2135ee454871+sip+1+a64de9f6\r\n"
                   "From: <%17$s>;tag=10.114.61.213+1+8c8b232a+5fb751cf\r\n"
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
                   /*  2 */ to_uri,
                   /*  3 */ req_uri,
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
                   /* 16 */ _unique,
                   /* 17 */ from_uri
    );

  EXPECT_LT(n, (int)sizeof(buf));

  string ret(buf, n);
  return ret;
}

/// Fixture for Subscription tests that use a mock store instead of a fake one.
/// Also use a real analyticslogger to get UT coverage of that.
class SubscriptionTest : public SipTest
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
    _sm = new MockSubscriberManager();
    _acr_factory = new ACRFactory();

    _log_traffic = PrintingTestLogger::DEFAULT.isPrinting();

    _subscription_sproutlet = new SubscriptionSproutlet("subscription",
                                                        5058,
                                                        "sip:subscription.homedomain:5058;transport=tcp",
                                                        "scscf",
                                                        "scscf-proxy",
                                                        _sm,
                                                        _acr_factory,
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
    delete _sm; _sm = NULL;
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
  }

  void not_handled_by_subscription_sproutlet()
  {
    ASSERT_EQ(1, txdata_count());
    inject_msg(respond_to_current_txdata(200));
    ASSERT_EQ(1, txdata_count());
    EXPECT_EQ(200, current_txdata()->msg->line.status.code);
    free_txdata();
  }

  std::string do_OK_flow()
  {
    EXPECT_EQ(1, txdata_count());
    pjsip_msg* out = pop_txdata()->msg;
    EXPECT_EQ(200, out->line.status.code);
    EXPECT_EQ("OK", str_pj(out->line.status.reason));
    EXPECT_THAT(get_headers(out, "From"), testing::MatchesRegex("From: .*;tag=10.114.61.213\\+1\\+8c8b232a\\+5fb751cf"));
    EXPECT_EQ("P-Charging-Vector: icid-value=\"100\"", get_headers(out, "P-Charging-Vector"));
    EXPECT_EQ("P-Charging-Function-Addresses: ccf=1.2.3.4;ecf=5.6.7.8", get_headers(out, "P-Charging-Function-Addresses"));

    // Pull out the to tag on the OK
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

    return to_tag;
  }

  void handle_response(int rc, std::string reason)
  {
    ASSERT_EQ(1, txdata_count());
    pjsip_msg* out = pop_txdata()->msg;
    EXPECT_EQ(rc, out->line.status.code);
    EXPECT_EQ(reason, str_pj(out->line.status.reason));
  }

protected:
  MockSubscriberManager* _sm;
  ACRFactory* _acr_factory;
  SubscriptionSproutlet* _subscription_sproutlet;
  SproutletProxy* _subscription_proxy;
};

TEST_F(SubscriptionTest, NotSubscribe)
{
  SubscribeMessage msg;
  msg._method = "PUBLISH";
  inject_msg(msg.get());
  not_handled_by_subscription_sproutlet();
}

TEST_F(SubscriptionTest, NotOurs)
{
  SubscribeMessage msg;
  msg._domain = "not-us.example.org";
  add_host_mapping("not-us.example.org", "5.6.7.8");
  inject_msg(msg.get());
  not_handled_by_subscription_sproutlet();
}

TEST_F(SubscriptionTest, RouteHeaderNotMatching)
{
  SubscribeMessage msg;
  msg._route = "notthehomedomain";
  inject_msg(msg.get());
  handle_response(503, "Service Unavailable");
}

TEST_F(SubscriptionTest, BadScheme)
{
  SubscribeMessage msg;
  msg._scheme = "sips";
  inject_msg(msg.get());
  handle_response(404, "Not Found"); // Is this correct?
}

TEST_F(SubscriptionTest, NoContact)
{
  SubscribeMessage msg;
  msg._contact = "";
  inject_msg(msg.get());
  handle_response(400, "Bad Request"); // Is this correct?
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
}

// Test the Event Header
// Missing Event header should be rejected
TEST_F(SubscriptionTest, MissingEventHeader)
{
  SubscribeMessage msg;
  msg._event = "";
  inject_msg(msg.get());
  not_handled_by_subscription_sproutlet();
}

// Test the Event Header
// Event that isn't reg should be rejected
TEST_F(SubscriptionTest, IncorrectEventHeader)
{
  SubscribeMessage msg;
  msg._event = "Event: Not Reg";
  inject_msg(msg.get());
  not_handled_by_subscription_sproutlet();

  SubscribeMessage msg2;
  msg2._event = "Event: Reg";
  inject_msg(msg2.get());
  not_handled_by_subscription_sproutlet();
}

// Test Accept Header. A message with no accepts header should be accepted
TEST_F(SubscriptionTest, EmptyAcceptsHeader)
{
  EXPECT_CALL(*_sm, update_subscription(_, _, _, _)).WillOnce(Return(HTTP_OK));

  SubscribeMessage msg;
  msg._accepts = "";
  inject_msg(msg.get());

  do_OK_flow();
}

// Test Accept Header.
// A message with an accept header, but where it doesn't contain
// application/reginfo+xml shouldn't be accepted
TEST_F(SubscriptionTest, IncorrectAcceptsHeader)
{
  SubscribeMessage msg;
  msg._accepts = "Accept: notappdata";
  inject_msg(msg.get());
  not_handled_by_subscription_sproutlet();
}

// Test Accept Header.
// A message with an accept header, which contains
// application/reginfo+xml and others should be accepted
TEST_F(SubscriptionTest, CorrectAcceptsHeader)
{
  EXPECT_CALL(*_sm, update_subscription(_, _, _, _)).WillOnce(Return(HTTP_OK));

  SubscribeMessage msg;
  msg._accepts = "Accept: otherstuff,application/reginfo+xml";
  inject_msg(msg.get());

  do_OK_flow();
}

TEST_F(SubscriptionTest, UpdateSubscription)
{
  EXPECT_CALL(*_sm, update_subscription(_, _, _, _)).WillOnce(Return(HTTP_OK));

  SubscribeMessage msg;
  inject_msg(msg.get());

  do_OK_flow();
}

TEST_F(SubscriptionTest, UpdateSubscriptionError)
{
  EXPECT_CALL(*_sm, update_subscription(_, _, _, _)).WillOnce(Return(HTTP_SERVER_ERROR));

  SubscribeMessage msg;
  inject_msg(msg.get());

  handle_response(500, "Internal Server Error"); // Is this correct?
}

TEST_F(SubscriptionTest, UpdateSubscriptionError2)
{
  EXPECT_CALL(*_sm, update_subscription(_, _, _, _)).WillOnce(Return(HTTP_TEMP_UNAVAILABLE));

  SubscribeMessage msg;
  inject_msg(msg.get());

  handle_response(480, "Temporarily Unavailable"); // Is this correct?
}

TEST_F(SubscriptionTest, UpdateSubscriptionError3)
{
  EXPECT_CALL(*_sm, update_subscription(_, _, _, _)).WillOnce(Return(HTTP_FORBIDDEN));

  SubscribeMessage msg;
  inject_msg(msg.get());

  handle_response(403, "Forbidden"); // Is this correct?
}

TEST_F(SubscriptionTest, UpdateSubscriptionError4)
{
  EXPECT_CALL(*_sm, update_subscription(_, _, _, _)).WillOnce(Return(HTTP_NOT_FOUND));

  SubscribeMessage msg;
  inject_msg(msg.get());

  handle_response(403, "Forbidden"); // Is this correct?
}

TEST_F(SubscriptionTest, UpdateSubscriptionError5)
{
  EXPECT_CALL(*_sm, update_subscription(_, _, _, _)).WillOnce(Return(HTTP_SERVER_UNAVAILABLE));

  SubscribeMessage msg;
  inject_msg(msg.get());

  handle_response(504, "Server Timeout"); // Is this correct?
}

TEST_F(SubscriptionTest, RemoteStoreGetError)
{
  // Set up a single subscription - this should generate a 200 OK then
  // a NOTIFY
  EXPECT_CALL(*_sm, update_subscription(_, _, _, _)).WillOnce(Return(HTTP_OK));

  SubscribeMessage msg;
  inject_msg(msg.get());

  std::string to_tag = do_OK_flow();

  // Actively expire the subscription - this generates a 200 OK and a
  // final NOTIFY
  EXPECT_CALL(*_sm, remove_subscription(_, _, _, _)).WillOnce(Return(HTTP_OK));
  msg._to_tag = to_tag;
  msg._unique += 1;
  msg._expires = "0";
  inject_msg(msg.get());
  do_OK_flow();
}

TEST_F(SubscriptionTest, SimpleMainlineWithReqUriTelUri)
{
  EXPECT_CALL(*_sm, update_subscription(_, _, _, _)).WillOnce(Return(HTTP_OK));

  SubscribeMessage msg;
  msg._domain = "example.domain.org";
  msg._req_uri_scheme = "tel";
  msg._subscribing_user = "6505550231;sescase=term;regstate=reg";
  add_host_mapping("example.domain.org", "5.6.7.8");
  inject_msg(msg.get());

  do_OK_flow();
}

/// Simple correct example with Tel URIs
TEST_F(SubscriptionTest, SimpleMainlineWithTelURI)
{
  EXPECT_CALL(*_sm, update_subscription(_, _, _, _)).WillOnce(Return(HTTP_OK));

  SubscribeMessage msg;
  msg._scheme = "tel";
  inject_msg(msg.get());

  do_OK_flow();
}
