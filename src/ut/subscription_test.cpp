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
using ::testing::InSequence;
using ::testing::DoAll;
using ::testing::SaveArg;
using ::testing::SetArgReferee;
using ::testing::ElementsAre;

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

/// Save off the SubscriptionPair. We can't just use SaveArg, as this only
/// saves off the SubscriptionPair, not the SubscriptionPair members. This
/// means that the subscription object has been deleted before we can
/// check it. This allows us to create a copy of the Subscription object
/// we can check against. The caller is responsible for deleting the copied
/// object.
ACTION_P2(SaveSubscriptionPair, first, second)
{
  *first = arg1.first;
  *second = Subscription(*(arg1.second));
}

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

  // Handle the case where the request isn't absorbed by the subscription
  // sproutlet. Finish the transaction by returning 200 to the request.
  void request_not_handled_by_subscription_sproutlet()
  {
    ASSERT_EQ(1, txdata_count());
    inject_msg(respond_to_current_txdata(200));
    ASSERT_EQ(1, txdata_count());
    EXPECT_EQ(200, current_txdata()->msg->line.status.code);
    free_txdata();
  }

  // Check the return code and the reason. This function covers basic checking
  // of the subscription sproutlets response - the mainline tests cover checking
  // the response in much more detail.
  void check_subscribe_response(int rc, std::string reason)
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

// This test adds a subscription then expires it. It checks in detail the
// created subscription object and the headers on the 200 OKs.
TEST_F(SubscriptionTest, MainlineAddAndRemoveSubscription)
{
  // Add a subscription. Save off the created subscription, then check that
  // and the headers on the 200 OK.
  std::string subscription_id;
  Subscription subscription;
  HSSConnection::irs_info irs_info;
  irs_info._ccfs.push_back("CCF TEST");
  irs_info._ecfs.push_back("ECF TEST");

  EXPECT_CALL(*_sm, update_subscription("sip:6505550231@homedomain", _, _, _))
    .WillOnce(DoAll(SaveSubscriptionPair(&subscription_id, &subscription),
                    SetArgReferee<2>(irs_info),
                    Return(HTTP_OK)));

  SubscribeMessage msg;
  inject_msg(msg.get());

  // Check that we got a 200 OK.
  EXPECT_EQ(1, txdata_count());
  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));

  // Check the Charging, From and Expires headers.
  EXPECT_THAT(get_headers(out, "From"), testing::MatchesRegex("From: .*;tag=10.114.61.213\\+1\\+8c8b232a\\+5fb751cf"));
  EXPECT_EQ("P-Charging-Function-Addresses: ccf=\"CCF TEST\";ecf=\"ECF TEST\"", get_headers(out, "P-Charging-Function-Addresses"));
  EXPECT_EQ("Expires: 300", get_headers(out, "Expires"));

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

  // Check the created subscription object.
  int now = time(NULL);
  std::list<std::string> rrs;
  rrs.push_back("sip:sprout.example.com;transport=tcp;lr");
  EXPECT_EQ(subscription_id, to_tag);
  EXPECT_EQ(subscription._req_uri, "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob");
  EXPECT_EQ(subscription._from_uri, "<sip:6505550231@homedomain>");
  EXPECT_EQ(subscription._from_tag, "10.114.61.213+1+8c8b232a+5fb751cf");
  EXPECT_EQ(subscription._to_uri, "<sip:6505550231@homedomain>");
  EXPECT_EQ(subscription._cid, "0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs1042ohntC@10.114.61.213");
  EXPECT_EQ(subscription._route_uris, rrs);
  EXPECT_EQ(subscription._expires, now + 300);

  // Now expire the same subscription. The subscription ID is the to tag from
  // 200 OK.
  EXPECT_CALL(*_sm, remove_subscription("sip:6505550231@homedomain", to_tag, _, _))
    .WillOnce(DoAll(SetArgReferee<2>(irs_info),
                    Return(HTTP_OK)));

  msg._to_tag = to_tag;
  msg._unique += 1;
  msg._expires = "0";

  inject_msg(msg.get());

  // Check that we got a 200 OK.
  EXPECT_EQ(1, txdata_count());
  out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));

  // Check the Charging, From and Expires headers.
  EXPECT_THAT(get_headers(out, "From"), testing::MatchesRegex("From: .*;tag=10.114.61.213\\+1\\+8c8b232a\\+5fb751cf"));
  EXPECT_EQ("P-Charging-Function-Addresses: ccf=\"CCF TEST\";ecf=\"ECF TEST\"", get_headers(out, "P-Charging-Function-Addresses"));
  EXPECT_EQ("Expires: 0", get_headers(out, "Expires"));
}

// Test that a request that isn't a subscribe isn't handled by the subscription
// sproutlet.
TEST_F(SubscriptionTest, NotSubscribe)
{
  SubscribeMessage msg;
  msg._method = "PUBLISH";
  inject_msg(msg.get());
  request_not_handled_by_subscription_sproutlet();
}

// Test that a request that isn't targeted to us (wrong domain) isn't handled
// by the subscription sproutlet.
TEST_F(SubscriptionTest, NotOurs)
{
  SubscribeMessage msg;
  msg._domain = "not-us.example.org";
  add_host_mapping("not-us.example.org", "5.6.7.8");
  inject_msg(msg.get());
  request_not_handled_by_subscription_sproutlet();
}

// Test that a request that isn't targeted to us (wrong hostname on the route
// header) isn't handled by the subscription sproutlet.
TEST_F(SubscriptionTest, RouteHeaderNotMatching)
{
  SubscribeMessage msg;
  msg._route = "notthehomedomain";
  add_host_mapping("notthehomedomain", "5.6.7.8");
  inject_msg(msg.get());
  request_not_handled_by_subscription_sproutlet();
}

// Test that a subscribe with a bad scheme is rejected.
TEST_F(SubscriptionTest, BadScheme)
{
  SubscribeMessage msg;
  msg._scheme = "sips";
  inject_msg(msg.get());
  check_subscribe_response(404, "Not Found");
}

// Test that a subscribe with no contact headers is rejected.
TEST_F(SubscriptionTest, NoContact)
{
  SubscribeMessage msg;
  msg._contact = "";
  inject_msg(msg.get());
  check_subscribe_response(400, "Bad Request");
}

// Test that a subscribe that's from a binding that was accepted for emergency
// registration is rejected.
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

// Test that a subscribe with a missing Event header isn't handled by the
// subscription sproutlet.
TEST_F(SubscriptionTest, MissingEventHeader)
{
  SubscribeMessage msg;
  msg._event = "";
  inject_msg(msg.get());
  request_not_handled_by_subscription_sproutlet();
}

// Test that a subscribe that has an Event header that doesn't case-sensitive
// match 'reg' isn't handled by the subscription sproutlet.
TEST_F(SubscriptionTest, IncorrectEventHeader)
{
  SubscribeMessage msg;
  msg._event = "Event: Not Reg";
  inject_msg(msg.get());
  request_not_handled_by_subscription_sproutlet();

  SubscribeMessage msg2;
  msg2._event = "Event: Reg";
  inject_msg(msg2.get());
  request_not_handled_by_subscription_sproutlet();
}

// Test that a subscribe that has an Accept header but where it doesn't contain
// application/reginfo+xml isn't handled by the subscription sproutlet.
TEST_F(SubscriptionTest, IncorrectAcceptsHeader)
{
  SubscribeMessage msg;
  msg._accepts = "Accept: notappdata";
  inject_msg(msg.get());
  request_not_handled_by_subscription_sproutlet();
}

// Test that a subscribe with no Accept header is processed successfully.
TEST_F(SubscriptionTest, EmptyAcceptsHeader)
{
  EXPECT_CALL(*_sm, update_subscription(_, _, _, _)).WillOnce(Return(HTTP_OK));

  SubscribeMessage msg;
  msg._accepts = "";
  inject_msg(msg.get());

  check_subscribe_response(200, "OK");
}

// Test that a subscribe with a complicated Accept header but it does contain
// application/reginfo+xml is processed succesfully
TEST_F(SubscriptionTest, CorrectAcceptsHeader)
{
  EXPECT_CALL(*_sm, update_subscription(_, _, _, _)).WillOnce(Return(HTTP_OK));

  SubscribeMessage msg;
  msg._accepts = "Accept: otherstuff,application/reginfo+xml";
  inject_msg(msg.get());

  check_subscribe_response(200, "OK");
}

// Test that errors from the subscriber manager are correctly converted into
// client responses (Server Error).
TEST_F(SubscriptionTest, ErrorConversionSMToCallerServerError)
{
  SubscribeMessage msg;
  EXPECT_CALL(*_sm, update_subscription(_, _, _, _)).WillOnce(Return(HTTP_SERVER_ERROR));
  inject_msg(msg.get());
  check_subscribe_response(500, "Internal Server Error");
}

// Test that errors from the subscriber manager are correctly converted into
// client responses (Unavailable).
TEST_F(SubscriptionTest, ErrorConversionSMToCallerUnavailable)
{
  SubscribeMessage msg;
  EXPECT_CALL(*_sm, update_subscription(_, _, _, _)).WillOnce(Return(HTTP_TEMP_UNAVAILABLE));
  inject_msg(msg.get());
  check_subscribe_response(480, "Temporarily Unavailable");
}

// Test that errors from the subscriber manager are correctly converted into
// client responses (Forbidden).
TEST_F(SubscriptionTest, ErrorConversionSMToCallerForbidden)
{
  SubscribeMessage msg;
  EXPECT_CALL(*_sm, update_subscription(_, _, _, _)).WillOnce(Return(HTTP_FORBIDDEN));
  inject_msg(msg.get());
  check_subscribe_response(403, "Forbidden");
}

// Test that errors from the subscriber manager are correctly converted into
// client responses (Not Found).
TEST_F(SubscriptionTest, ErrorConversionSMToCallerNotFound)
{
  SubscribeMessage msg;
  EXPECT_CALL(*_sm, update_subscription(_, _, _, _)).WillOnce(Return(HTTP_FORBIDDEN));
  inject_msg(msg.get());
  check_subscribe_response(403, "Forbidden");
}

// Test that errors from the subscriber manager are correctly converted into
// client responses (Timeout).
TEST_F(SubscriptionTest, ErrorConversionSMToCallerTimeout)
{
  SubscribeMessage msg;
  EXPECT_CALL(*_sm, update_subscription(_, _, _, _)).WillOnce(Return(HTTP_SERVER_UNAVAILABLE));
  inject_msg(msg.get());
  check_subscribe_response(504, "Server Timeout");
}

// Test that nothing goes wrong if the subscribe is from a Tel URI
TEST_F(SubscriptionTest, TelURI)
{
  EXPECT_CALL(*_sm, update_subscription(_, _, _, _)).WillOnce(Return(HTTP_OK));

  SubscribeMessage msg;
  msg._scheme = "tel";
  inject_msg(msg.get());

  check_subscribe_response(200, "OK");
}

// Test that nothing goes wrong if the ReqURI is a Tel URI
TEST_F(SubscriptionTest, ReqUriTelUri)
{
  EXPECT_CALL(*_sm, update_subscription(_, _, _, _)).WillOnce(Return(HTTP_OK));

  SubscribeMessage msg;
  msg._domain = "example.domain.org";
  msg._req_uri_scheme = "tel";
  msg._subscribing_user = "6505550231;sescase=term;regstate=reg";
  add_host_mapping("example.domain.org", "5.6.7.8");
  inject_msg(msg.get());

  check_subscribe_response(200, "OK");
}
