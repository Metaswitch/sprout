/**
 * @file notify_sender_test.cpp
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "gtest/gtest.h"

#include "aor_test_utils.h"
#include "siptest.hpp"
#include "test_interposer.hpp"
#include "notify_sender.h"
#include "rapidxml/rapidxml.hpp"

using ::testing::_;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgReferee;
using ::testing::SetArgPointee;
using ::testing::InSequence;
using ::testing::SaveArgPointee;

// Constants for checking NOTIFY bodies.
static const std::string ACTIVE = "active";
static const std::string TERMINATED = "terminated";
static const std::pair<std::string, std::string> ACTIVE_REGISTERED = std::make_pair("active", "registered");
static const std::pair<std::string, std::string> ACTIVE_CREATED = std::make_pair("active", "created");
static const std::pair<std::string, std::string> ACTIVE_REFRESHED = std::make_pair("active", "refreshed");
static const std::pair<std::string, std::string> ACTIVE_SHORTENED = std::make_pair("active", "shortened");
static const std::pair<std::string, std::string> TERMINATED_EXPIRED = std::make_pair("terminated", "expired");
static const std::pair<std::string, std::string> TERMINATED_UNREGISTERED = std::make_pair("terminated", "unregistered");
static const std::pair<std::string, std::string> TERMINATED_DEACTIVATED = std::make_pair("terminated", "deactivated");

/// Fixture for NotifySenderTest.
class NotifySenderTest : public SipTest
{
public:
  NotifySenderTest()
  {
    _notify_sender = new NotifySender();
  };

  virtual ~NotifySenderTest()
  {
    pjsip_tsx_layer_dump(true);

    // Terminate all transactions
    terminate_all_tsxs(PJSIP_SC_SERVICE_UNAVAILABLE);

    // PJSIP transactions aren't actually destroyed until a zero ms
    // timer fires (presumably to ensure destruction doesn't hold up
    // real work), so poll for that to happen. Otherwise we leak!
    // Allow a good length of time to pass too, in case we have
    // transactions still open. 32s is the default UAS INVITE
    // transaction timeout, so we go higher than that.
    cwtest_advance_time_ms(33000L);
    poll();

    delete _notify_sender; _notify_sender = NULL;
  };

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();

    // Schedule timers.
    SipTest::poll();
  }

  static void TearDownTestCase()
  {
    // Shut down the transaction module first, before we destroy the
    // objects that might handle any callbacks!
    pjsip_tsx_layer_destroy();

    SipTest::TearDownTestCase();
  }

  // Check that the subscription state is correct.
  void check_subscription_state_header(pjsip_msg* notify, std::string state)
  {
    EXPECT_EQ("Subscription-State: " + state, get_headers(notify, "Subscription-State"));
  }

  // Parse out the NOTIFY body into an XML document.
  rapidxml::xml_document<>* parse_notify_body(pjsip_msg* notify)
  {
    std::string body;
    char buf[16384];
    int n = notify->body->print_body(notify->body, buf, sizeof(buf));
    body.assign(buf, n);

    rapidxml::xml_document<>* doc = new rapidxml::xml_document<>;
    char* xml_str = doc->allocate_string(body.c_str());

    try
    {
      doc->parse<rapidxml::parse_strip_xml_namespaces>(xml_str);
    }
    catch (rapidxml::parse_error err)
    {
      printf("Parse error in NOTIFY: %s\n\n%s", err.what(), body.c_str());
      doc->clear();
    }

    return doc;
  }

  // Check that the NOTIFY has the correct attributes. We only check this in
  // one UT, as the logic to populate this is very simple, and the result
  // never changes between each UT case.
  void check_notify_general_info(rapidxml::xml_document<>* doc)
  {
    rapidxml::xml_node<>* reg_info = doc->first_node("reginfo");
    ASSERT_TRUE(reg_info);

    EXPECT_EQ("urn:ietf:params:xml:ns:reginfo", std::string(reg_info->first_attribute("xmlns")->value()));
    EXPECT_EQ("urn:ietf:params:xml:ns:gruuinfo", std::string(reg_info->first_attribute("gr")->value()));
    EXPECT_EQ("http://www.w3.org/2001/XMLSchema-instance", std::string(reg_info->first_attribute("xsi")->value()));
    EXPECT_EQ("urn:3gpp:ns:extRegExp:1.0", std::string(reg_info->first_attribute("ere")->value()));
    EXPECT_EQ("0", std::string(reg_info->first_attribute("version")->value()));
    EXPECT_EQ("full", std::string(reg_info->first_attribute("state")->value()));
  }

  // Check the registration nodes in the NOTIFY. The elements of these nodes
  // change depending on the AoRs passed into send_notifys, so this function
  // is called by most UTs.
  void check_notify_registration_nodes(
                         rapidxml::xml_document<>* doc,
                         std::string reg_state,
                         std::vector<std::pair<std::string, std::string>> contact_values,
                         std::vector<std::pair<std::string, bool>> impus_with_wildcard_status)
  {
    rapidxml::xml_node<>* reg_info = doc->first_node("reginfo");
    ASSERT_TRUE(reg_info);

    int num_reg = 0;

    // There should be a registration node for each AssociatedURI (in the new
    // AoR).
    for (rapidxml::xml_node<> *registration = reg_info->first_node("registration");
         registration;
         registration = registration->next_sibling("registration"), num_reg++)
    {
      // Check if the registration element should have a wildcard identity. We pass
      // this in as a simple bool rather than use is_wildcard_identity, as using
      // the function in UT and production code will mask any issues with it.
      if (impus_with_wildcard_status.at(num_reg).second)
      {
        // In the wildcard case the aor value should be set to the default value,
        // and the wildcard identity is in its own element (note that the ere: namespace
        // has been stripped off already when we parse this in UT).
        EXPECT_EQ("sip:wildcardimpu@wildcard", std::string(registration->first_attribute("aor")->value()));
        rapidxml::xml_node<>* wildcard = registration->first_node("wildcardedIdentity");
        EXPECT_TRUE(wildcard);
        EXPECT_EQ(impus_with_wildcard_status.at(num_reg).first, std::string(wildcard->value()));
      }
      else
      {
        EXPECT_EQ(impus_with_wildcard_status.at(num_reg).first, std::string(registration->first_attribute("aor")->value()));
      }

      // Check the state of the contact and registration. There should be a
      // contact node for each binding (in the old and new AoRs).
      EXPECT_EQ(reg_state, std::string(registration->first_attribute("state")->value()));

      int num_contacts = 0;

      for (rapidxml::xml_node<> *contact = registration->first_node("contact");
           contact;
           contact = contact->next_sibling("contact"), num_contacts++)
      {
        EXPECT_EQ(contact_values[num_contacts].first, std::string(contact->first_attribute("state")->value()));
        EXPECT_EQ(contact_values[num_contacts].second, std::string(contact->first_attribute("event")->value()));
      }

      EXPECT_EQ(contact_values.size(), num_contacts);
    }

    // We should have found one registration element for each IMPU
    EXPECT_EQ(impus_with_wildcard_status.size(), num_reg);
  }

  // Check the contact nodes in the NOTIFY. These are extra entries that
  // depend on the subscription objects. As such, they're only checked in
  // one set of UTs.
  void check_notify_contact_nodes(
                         rapidxml::xml_document<>* doc,
                         std::string uri_values,
                         std::string gruu_values,
                         std::map<std::string, std::string> unknown_params)
  {
    rapidxml::xml_node<>* reg_info = doc->first_node("reginfo");
    ASSERT_TRUE(reg_info);

    rapidxml::xml_node<>* registration = reg_info->first_node("registration");
    ASSERT_TRUE(registration);

    rapidxml::xml_node<>* contact = registration->first_node("contact");
    ASSERT_TRUE(contact);

    ASSERT_TRUE(contact->first_node("uri"));
    EXPECT_EQ(uri_values, std::string(contact->first_node("uri")->value()));

    ASSERT_TRUE(contact->first_node("pub-gruu"));
    ASSERT_TRUE(contact->first_node("pub-gruu")->first_attribute("uri"));
    EXPECT_EQ(gruu_values, std::string(contact->first_node("pub-gruu")->first_attribute("uri")->value()));

    std::map<std::string, std::string> params;

    for (rapidxml::xml_node<>* param = contact->first_node("unknown-param");
         param;
         param = param->next_sibling("unknown-param"))
    {
      ASSERT_TRUE(param->first_attribute("name"));
      std::string name = param->first_attribute("name")->value();
      std::string value = param->value();
      params.insert(std::make_pair(name, value));
    }

    EXPECT_EQ(unknown_params, params);
  }

private:
  NotifySender* _notify_sender;

};

// This test covers a mainline NOTIFY case. It checks the NOTIFY in detail,
// covering the headers and the NOTIFY body.
TEST_F(NotifySenderTest, NotifyCheckInDetails)
{
  // Create the two AoRs to pass in. The original AoR is empty, the new AoR
  // has a single binding and single subscription. We set the interesting
  // values in the subscription object explicitly here so that we can
  // confidently expect exact matches.
  AoR* orig_aor = new AoR();
  std::string aor_id = "sip:1234567890@homedomain";
  AoR* updated_aor = AoRTestUtils::create_simple_aor(aor_id);
  int now = time(NULL);

  Subscription* s = updated_aor->get_subscription(AoRTestUtils::SUBSCRIPTION_ID);
  s->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s->_from_tag = std::string("4321");
  s->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s->_to_tag = "1234";
  s->_route_uris.clear();
  s->_route_uris.push_back(std::string("sip:abcdefgh@bono1.homedomain;lr"));
  s->_route_uris.push_back(std::string("sip:12345678@bono1.homedomain;lr"));
  s->_expires = now + 200;

  Binding* b = updated_aor->get_binding(AoRTestUtils::BINDING_ID);
  b->_params["unknown1"] = "test1";
  b->_params["q"] = "";

  _notify_sender->send_notifys(aor_id,
                               *orig_aor,
                               *updated_aor,
                               SubscriberDataUtils::EventTrigger::USER,
                               time(NULL),
                               0);

  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;

  // Check that the Notify headers are valid. These headers are populated
  // directly from the subscription object. They're only checked in this
  // UT, as the logic behind them is very simple.
  EXPECT_EQ("NOTIFY", str_pj(out->line.status.reason));
  EXPECT_EQ("Event: reg", get_headers(out, "Event"));
  EXPECT_EQ("To: <sip:5102175698@cw-ngv.com>;tag=4321", get_headers(out, "To"));
  EXPECT_EQ("From: <sip:5102175698@cw-ngv.com>;tag=1234", get_headers(out, "From"));
  EXPECT_EQ("Route: <sip:abcdefgh@bono1.homedomain;lr>\r\nRoute: <sip:12345678@bono1.homedomain;lr>", get_headers(out, "Route"));

  // Check that the NOTIFY body is correct, and that the state of the
  // subscription is correct.
  check_subscription_state_header(out, "active;expires=200");
  rapidxml::xml_document<>* doc = parse_notify_body(out);
  check_notify_general_info(doc);
  std::vector<std::pair<std::string, bool>> impus;
  impus.push_back(std::make_pair("sip:1234567890@homedomain", false));
  check_notify_registration_nodes(doc, ACTIVE, {ACTIVE_CREATED}, impus);

  // Check the first contact node. This should include the URI, the GRUU, and
  // the unknown params (but not the 'q' we added).
  std::map<std::string, std::string> params;
  params.insert(std::make_pair("+sip.ice", ""));
  params.insert(std::make_pair("+sip.instance", "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\""));
  params.insert(std::make_pair("reg-id", "1"));
  params.insert(std::make_pair("unknown1", "test1"));
  check_notify_contact_nodes(doc, "sip:6505550231@192.91.191.29:59934;transport=tcp;ob", "sip:1234567890@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b4dd32817622", params);

  // Tidy up
  inject_msg(respond_to_current_txdata(200));
  delete doc;
  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;
}

// Remove a subscription when we've removed a binding that has the same contact
// URI. In this test this is triggered by an admin action, so we should send
// NOTIFYs.
TEST_F(NotifySenderTest, NotifySubscriberAdminDeregister)
{
  std::string aor_id = "sip:1234567890@homedomain";
  AoR* orig_aor = AoRTestUtils::create_simple_aor(aor_id);
  AoR* updated_aor = new AoR(aor_id);

  _notify_sender->send_notifys(aor_id,
                               *orig_aor,
                               *updated_aor,
                               SubscriberDataUtils::EventTrigger::ADMIN,
                               time(NULL),
                               0);

  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;

  // Check that the NOTIFY body is correct, and that the state of the
  // subscription is correct.
  check_subscription_state_header(out, "terminated;reason=deactivated");
  rapidxml::xml_document<>* doc = parse_notify_body(out);
  check_notify_general_info(doc);
  std::vector<std::pair<std::string, bool>> impus;
  impus.push_back(std::make_pair("sip:1234567890@homedomain", false));
  check_notify_registration_nodes(doc, TERMINATED, {TERMINATED_DEACTIVATED}, impus);

  // Tidy up
  inject_msg(respond_to_current_txdata(200));
  delete doc;
  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;
}

// Remove a subscription when we've removed a binding that has the same contact
// URI. In this test this is triggered by a user action, so we should not send
// NOTIFYs.
TEST_F(NotifySenderTest, MainlineSubscriberUserDeregister)
{
  std::string aor_id = "sip:1234567890@homedomain";
  AoR* orig_aor = AoRTestUtils::create_simple_aor(aor_id);
  AoR* updated_aor = new AoR(aor_id);

  _notify_sender->send_notifys(aor_id,
                               *orig_aor,
                               *updated_aor,
                               SubscriberDataUtils::EventTrigger::USER,
                               time(NULL),
                               0);

  ASSERT_EQ(0, txdata_count());

  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;
}

// Remove a subscription when we've removed a binding that has the same contact
// URI. In this test this is triggered by a timeout action, so we should not
// send NOTIFYs.
TEST_F(NotifySenderTest, MainlineSubscriberTimeoutDeregister)
{
  // Create the two AoRs to pass in. This test case creates the
  std::string aor_id = "sip:1234567890@homedomain";
  AoR* orig_aor = AoRTestUtils::create_simple_aor(aor_id);
  AoR* updated_aor = new AoR(aor_id);

  _notify_sender->send_notifys(aor_id,
                               *orig_aor,
                               *updated_aor,
                               SubscriberDataUtils::EventTrigger::TIMEOUT,
                               time(NULL),
                               0);

  ASSERT_EQ(0, txdata_count());

  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;
}

// Call send_notifys when there's not been any changes - we shouldn't send any
// NOTIFYs in this case.
TEST_F(NotifySenderTest, MainlineNoChanges)
{
  // Create the two AoRs to pass in. This test case creates the
  std::string aor_id = "sip:1234567890@homedomain";
  AoR* orig_aor = AoRTestUtils::create_simple_aor(aor_id);
  AoR* updated_aor = AoRTestUtils::create_simple_aor(aor_id);

  _notify_sender->send_notifys(aor_id,
                               *orig_aor,
                               *updated_aor,
                               SubscriberDataUtils::EventTrigger::USER,
                               time(NULL),
                               0);

  ASSERT_EQ(0, txdata_count());

  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;
}

// Change the Associated URIs - the NOTIFY should contain the correct
// associated URIs, and the bindings should be unchanged.
TEST_F(NotifySenderTest, NotifyChangedAssociatedURIs)
{
  std::string aor_id = "sip:1234567890@homedomain";
  AoR* orig_aor = AoRTestUtils::create_simple_aor(aor_id);
  AoR* updated_aor = AoRTestUtils::create_simple_aor(aor_id);
  updated_aor->_associated_uris.add_uri("sip:1234567891@homedomain", true);

  _notify_sender->send_notifys(aor_id,
                               *orig_aor,
                               *updated_aor,
                               SubscriberDataUtils::EventTrigger::USER,
                               time(NULL),
                               0);

  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;

  // Check that the NOTIFY body is correct, and that the state of the
  // subscription is correct.
  check_subscription_state_header(out, "active;expires=300");
  rapidxml::xml_document<>* doc = parse_notify_body(out);
  check_notify_general_info(doc);
  std::vector<std::pair<std::string, bool>> impus;
  impus.push_back(std::make_pair("sip:1234567890@homedomain", false));
  check_notify_registration_nodes(doc, ACTIVE, {ACTIVE_REGISTERED}, impus);

  // Tidy up
  inject_msg(respond_to_current_txdata(200));
  delete doc;
  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;
}

// Test NOTIFYs when some of the Associated URIs are barred (so they shouldn't
// end up in the NOTIFY).
TEST_F(NotifySenderTest, NotifyBarredAssociatedURIs)
{
  std::string aor_id = "sip:1234567890@homedomain";
  AoR* orig_aor = AoRTestUtils::create_simple_aor(aor_id);
  AoR* updated_aor = AoRTestUtils::create_simple_aor(aor_id);
  updated_aor->_associated_uris.add_uri("sip:1234567891@homedomain", true);
  updated_aor->_associated_uris.add_uri("sip:1234567892@homedomain", false);
  updated_aor->_associated_uris.add_uri("sip:1234567893@homedomain", true);
  updated_aor->_associated_uris.add_uri("sip:1234567894@homedomain", false);

  _notify_sender->send_notifys(aor_id,
                               *orig_aor,
                               *updated_aor,
                               SubscriberDataUtils::EventTrigger::USER,
                               time(NULL),
                               0);

  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;

  // Check that the NOTIFY body is correct, and that the state of the
  // subscription is correct.
  check_subscription_state_header(out, "active;expires=300");
  rapidxml::xml_document<>* doc = parse_notify_body(out);
  check_notify_general_info(doc);
  std::vector<std::pair<std::string, bool>> impus;
  impus.push_back(std::make_pair("sip:1234567890@homedomain", false));
  impus.push_back(std::make_pair("sip:1234567892@homedomain", false));
  impus.push_back(std::make_pair("sip:1234567894@homedomain", false));
  check_notify_registration_nodes(doc, ACTIVE, {ACTIVE_REGISTERED}, impus);

  // Tidy up
  inject_msg(respond_to_current_txdata(200));
  delete doc;
  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;
}

// Test NOTIFYs when some of the Associated URIs are wildcards (where they
// should be displayed in the NOTIFY as a wildcard).
TEST_F(NotifySenderTest, NotifyWildcardAssociatedURIs)
{
  std::string aor_id = "sip:1234567890@homedomain";
  AoR* orig_aor = AoRTestUtils::create_simple_aor(aor_id);
  AoR* updated_aor = AoRTestUtils::create_simple_aor(aor_id);
  updated_aor->_associated_uris.add_uri("sip:!.*!", false);
  updated_aor->_associated_uris.add_wildcard_mapping("sip:!.*!", "sip:1234567893@homedomain");

  _notify_sender->send_notifys(aor_id,
                               *orig_aor,
                               *updated_aor,
                               SubscriberDataUtils::EventTrigger::USER,
                               time(NULL),
                               0);

  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;

  // Check that the NOTIFY body is correct, and that the state of the
  // subscription is correct.
  check_subscription_state_header(out, "active;expires=300");
  rapidxml::xml_document<>* doc = parse_notify_body(out);
  check_notify_general_info(doc);
  std::vector<std::pair<std::string, bool>> impus;
  impus.push_back(std::make_pair("sip:1234567890@homedomain", false));
  impus.push_back(std::make_pair("sip:!.*!", true));
  check_notify_registration_nodes(doc, ACTIVE, {ACTIVE_REGISTERED}, impus);

  // Tidy up
  inject_msg(respond_to_current_txdata(200));
  delete doc;
  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;
}

// Test NOTIFYs when there's a mix of barred and wildcarded Associated URIs
// to check that there's no interaction between them.
TEST_F(NotifySenderTest, NotifyBarredAndWildcardedAssociatedURIs)
{
  std::string aor_id = "sip:1234567890@homedomain";
  AoR* orig_aor = AoRTestUtils::create_simple_aor(aor_id);
  AoR* updated_aor = AoRTestUtils::create_simple_aor(aor_id);
  updated_aor->_associated_uris.add_uri("sip:1234567891@homedomain", true);
  updated_aor->_associated_uris.add_uri("sip:1234567892@homedomain", false);
  updated_aor->_associated_uris.add_uri("sip:!1.*!", false);
  updated_aor->_associated_uris.add_wildcard_mapping("sip:!1.*!", "sip:1234567893@homedomain");
  updated_aor->_associated_uris.add_uri("sip:!2.*!", true);
  updated_aor->_associated_uris.add_wildcard_mapping("sip:!2.*!", "sip:1234567894@homedomain");

  _notify_sender->send_notifys(aor_id,
                               *orig_aor,
                               *updated_aor,
                               SubscriberDataUtils::EventTrigger::USER,
                               time(NULL),
                               0);

  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;

  // Check that the NOTIFY body is correct, and that the state of the
  // subscription is correct.
  check_subscription_state_header(out, "active;expires=300");
  rapidxml::xml_document<>* doc = parse_notify_body(out);
  check_notify_general_info(doc);
  std::vector<std::pair<std::string, bool>> impus;
  impus.push_back(std::make_pair("sip:1234567890@homedomain", false));
  impus.push_back(std::make_pair("sip:1234567892@homedomain", false));
  impus.push_back(std::make_pair("sip:!1.*!", true));
  check_notify_registration_nodes(doc, ACTIVE, {ACTIVE_REGISTERED}, impus);

  // Tidy up
  inject_msg(respond_to_current_txdata(200));
  delete doc;
  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;
}

// Test a NOTIFy with a binding that has a reduced expiry.
TEST_F(NotifySenderTest, NotifySubscriberShortenedBinding)
{
  std::string aor_id = "sip:1234567890@homedomain";
  AoR* orig_aor = AoRTestUtils::create_simple_aor(aor_id);
  AoR* updated_aor = AoRTestUtils::create_simple_aor(aor_id);
  updated_aor->get_binding(AoRTestUtils::BINDING_ID)->_expires -= 10;

  _notify_sender->send_notifys(aor_id,
                               *orig_aor,
                               *updated_aor,
                               SubscriberDataUtils::EventTrigger::ADMIN,
                               time(NULL),
                               0);

  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;

  // Check that the NOTIFY body is correct, and that the state of the
  // subscription is correct.
  check_subscription_state_header(out, "active;expires=300");
  rapidxml::xml_document<>* doc = parse_notify_body(out);
  check_notify_general_info(doc);
  std::vector<std::pair<std::string, bool>> impus;
  impus.push_back(std::make_pair("sip:1234567890@homedomain", false));
  check_notify_registration_nodes(doc, ACTIVE, {ACTIVE_SHORTENED}, impus);

  // Tidy up
  inject_msg(respond_to_current_txdata(200));
  delete doc;
  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;
}

// Test a NOTIFy with a binding that has a increased expiry.
TEST_F(NotifySenderTest, NotifySubscriberRefreshedBinding)
{
  std::string aor_id = "sip:1234567890@homedomain";
  AoR* orig_aor = AoRTestUtils::create_simple_aor(aor_id);
  AoR* updated_aor = AoRTestUtils::create_simple_aor(aor_id);
  updated_aor->get_binding(AoRTestUtils::BINDING_ID)->_expires += 10;

  _notify_sender->send_notifys(aor_id,
                               *orig_aor,
                               *updated_aor,
                               SubscriberDataUtils::EventTrigger::ADMIN,
                               time(NULL),
                               0);

  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;

  // Check that the NOTIFY body is correct, and that the state of the
  // subscription is correct.
  check_subscription_state_header(out, "active;expires=300");
  rapidxml::xml_document<>* doc = parse_notify_body(out);
  check_notify_general_info(doc);
  std::vector<std::pair<std::string, bool>> impus;
  impus.push_back(std::make_pair("sip:1234567890@homedomain", false));
  check_notify_registration_nodes(doc, ACTIVE, {ACTIVE_REFRESHED}, impus);

  // Tidy up
  inject_msg(respond_to_current_txdata(200));
  delete doc;
  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;
}

// Test a NOTIFy with a binding that has expired (removed in a TIMEOUT event).
TEST_F(NotifySenderTest, NotifySubscriberExpiredBinding)
{
  std::string aor_id = "sip:1234567890@homedomain";
  int now = time(NULL);
  AoR* orig_aor = AoRTestUtils::create_simple_aor(aor_id);
  Binding* b = AoRTestUtils::build_binding(aor_id, now, "<sip:6505550231@192.91.191.29:59935;transport=tcp;ob>", now + 10);
  orig_aor->_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID + "2", b));

  AoR* updated_aor = AoRTestUtils::create_simple_aor(aor_id);

  _notify_sender->send_notifys(aor_id,
                               *orig_aor,
                               *updated_aor,
                               SubscriberDataUtils::EventTrigger::TIMEOUT,
                               time(NULL),
                               0);

  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;

  // Check that the NOTIFY body is correct, and that the state of the
  // subscription is correct.
  check_subscription_state_header(out, "active;expires=300");
  rapidxml::xml_document<>* doc = parse_notify_body(out);
  check_notify_general_info(doc);
  std::vector<std::pair<std::string, bool>> impus;
  impus.push_back(std::make_pair("sip:1234567890@homedomain", false));
  check_notify_registration_nodes(doc, ACTIVE, {TERMINATED_EXPIRED, ACTIVE_REGISTERED}, impus);

  // Tidy up
  inject_msg(respond_to_current_txdata(200));
  delete doc;
  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;
}

// Test a NOTIFY where a binding has been removed by the user.
TEST_F(NotifySenderTest, NotifySubscriberUnregisteredBinding)
{
  std::string aor_id = "sip:1234567890@homedomain";
  int now = time(NULL);
  AoR* orig_aor = AoRTestUtils::create_simple_aor(aor_id);
  Binding* b = AoRTestUtils::build_binding(aor_id, now, "<sip:6505550231@192.91.191.29:59935;transport=tcp;ob>", now + 10);
  orig_aor->_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID + "2", b));

  AoR* updated_aor = AoRTestUtils::create_simple_aor(aor_id);

  _notify_sender->send_notifys(aor_id,
                               *orig_aor,
                               *updated_aor,
                               SubscriberDataUtils::EventTrigger::USER,
                               time(NULL),
                               0);

  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;

  // Check that the NOTIFY body is correct, and that the state of the
  // subscription is correct.
  check_subscription_state_header(out, "active;expires=300");
  rapidxml::xml_document<>* doc = parse_notify_body(out);
  check_notify_general_info(doc);
  std::vector<std::pair<std::string, bool>> impus;
  impus.push_back(std::make_pair("sip:1234567890@homedomain", false));
  check_notify_registration_nodes(doc, ACTIVE, {TERMINATED_UNREGISTERED, ACTIVE_REGISTERED}, impus);

  // Tidy up
  inject_msg(respond_to_current_txdata(200));
  delete doc;
  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;
}

// Test a NOTIFY where the user has removed a subscription.
TEST_F(NotifySenderTest, NotifySubscriberUserRemoveSubscription)
{
  std::string aor_id = "sip:1234567890@homedomain";
  AoR* orig_aor = AoRTestUtils::create_simple_aor(aor_id);
  AoR* updated_aor = AoRTestUtils::create_simple_aor(aor_id);
  updated_aor->remove_subscription(AoRTestUtils::SUBSCRIPTION_ID);

  _notify_sender->send_notifys(aor_id,
                               *orig_aor,
                               *updated_aor,
                               SubscriberDataUtils::EventTrigger::USER,
                               time(NULL),
                               0);

  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;

  // Check that the NOTIFY body is correct, and that the state of the
  // subscription is correct.
  check_subscription_state_header(out, "terminated;reason=timeout");
  rapidxml::xml_document<>* doc = parse_notify_body(out);
  check_notify_general_info(doc);
  std::vector<std::pair<std::string, bool>> impus;
  impus.push_back(std::make_pair("sip:1234567890@homedomain", false));
  check_notify_registration_nodes(doc, ACTIVE, {ACTIVE_REGISTERED}, impus);

  // Tidy up
  inject_msg(respond_to_current_txdata(200));
  delete doc;
  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;
}

// Test a NOTIFy with a subscription that has expired.
TEST_F(NotifySenderTest, NotifySubscriberExpiredSubscription)
{
  std::string aor_id = "sip:1234567890@homedomain";
  AoR* orig_aor = AoRTestUtils::create_simple_aor(aor_id);
  AoR* updated_aor = AoRTestUtils::create_simple_aor(aor_id);
  updated_aor->remove_subscription(AoRTestUtils::SUBSCRIPTION_ID);

  _notify_sender->send_notifys(aor_id,
                               *orig_aor,
                               *updated_aor,
                               SubscriberDataUtils::EventTrigger::TIMEOUT,
                               time(NULL),
                               0);

  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;

  // Check that the NOTIFY body is correct, and that the state of the
  // subscription is correct.
  check_subscription_state_header(out, "terminated;reason=timeout");
  rapidxml::xml_document<>* doc = parse_notify_body(out);
  check_notify_general_info(doc);
  std::vector<std::pair<std::string, bool>> impus;
  impus.push_back(std::make_pair("sip:1234567890@homedomain", false));
  check_notify_registration_nodes(doc, ACTIVE, {ACTIVE_REGISTERED}, impus);

  // Tidy up
  inject_msg(respond_to_current_txdata(200));
  delete doc;
  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;
}

// Test a NOTIFY with an emergency binding (the emergency binding shouldn't
// be in the NOTIFY.
TEST_F(NotifySenderTest, NotifyEmergencyBinding)
{
  std::string aor_id = "sip:1234567890@homedomain";
  int now = time(NULL);
  AoR* orig_aor = AoRTestUtils::create_simple_aor(aor_id, false);
  Binding* b1 = AoRTestUtils::build_binding(aor_id, now, "<sip:6505550231@192.91.191.29:59935;transport=tcp;ob>", now + 10);
  b1->_emergency_registration = true;
  orig_aor->_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID + "2", b1));
  AoR* updated_aor = AoRTestUtils::create_simple_aor(aor_id);
  Binding* b2 = AoRTestUtils::build_binding(aor_id, now, "<sip:6505550231@192.91.191.29:59935;transport=tcp;ob>", now + 10);
  b2->_emergency_registration = true;
  updated_aor->_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID + "2", b2));

  _notify_sender->send_notifys(aor_id,
                               *orig_aor,
                               *updated_aor,
                               SubscriberDataUtils::EventTrigger::USER,
                               time(NULL),
                               0);

  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;

  // Check that the NOTIFY body is correct, and that the state of the
  // subscription is correct.
  check_subscription_state_header(out, "active;expires=300");
  rapidxml::xml_document<>* doc = parse_notify_body(out);
  check_notify_general_info(doc);
  std::vector<std::pair<std::string, bool>> impus;
  impus.push_back(std::make_pair("sip:1234567890@homedomain", false));
  check_notify_registration_nodes(doc, ACTIVE, {ACTIVE_REGISTERED}, impus);

  // Tidy up
  inject_msg(respond_to_current_txdata(200));
  delete doc;
  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;
}

// Test a NOTIFY where there are multiple binding changes, so multiple contact
// nodes in the NOTIFY.
TEST_F(NotifySenderTest, NotifyMultipleBindingChanges)
{
  std::string aor_id = "sip:1234567890@homedomain";
  int now = time(NULL);
  AoR* orig_aor = AoRTestUtils::create_simple_aor(aor_id);
  Binding* b1 = AoRTestUtils::build_binding(aor_id, now, "<sip:6505550231@192.91.191.29:59935;transport=tcp;ob>", now + 10);
  orig_aor->_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID + "2", b1));
  AoR* updated_aor = AoRTestUtils::create_simple_aor(aor_id);
  Binding* b2 = AoRTestUtils::build_binding(aor_id, now, "<sip:6505550231@192.91.191.29:59936;transport=tcp;ob>", now + 10);
  updated_aor->_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID + "3", b2));

  _notify_sender->send_notifys(aor_id,
                               *orig_aor,
                               *updated_aor,
                               SubscriberDataUtils::EventTrigger::USER,
                               time(NULL),
                               0);

  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;

  // Check that the NOTIFY body is correct, and that the state of the
  // subscription is correct.
  check_subscription_state_header(out, "active;expires=300");
  rapidxml::xml_document<>* doc = parse_notify_body(out);
  check_notify_general_info(doc);
  std::vector<std::pair<std::string, bool>> impus;
  impus.push_back(std::make_pair("sip:1234567890@homedomain", false));
  check_notify_registration_nodes(doc, ACTIVE, {TERMINATED_UNREGISTERED, ACTIVE_REGISTERED, ACTIVE_CREATED}, impus);

  // Tidy up
  inject_msg(respond_to_current_txdata(200));
  delete doc;
  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;
}

// Test adding two Subscriptions - this should trigger two NOTIFYs
TEST_F(NotifySenderTest, NotifyTwoSubscriptions)
{
  std::string aor_id = "sip:1234567890@homedomain";
  int now = time(NULL);
  AoR* orig_aor = AoRTestUtils::create_simple_aor(aor_id, false);
  AoR* updated_aor = AoRTestUtils::create_simple_aor(aor_id);
  Subscription* s = AoRTestUtils::build_subscription(AoRTestUtils::SUBSCRIPTION_ID, now);
  updated_aor->_subscriptions.insert(std::make_pair(AoRTestUtils::SUBSCRIPTION_ID + "2", s));

  _notify_sender->send_notifys(aor_id,
                               *orig_aor,
                               *updated_aor,
                               SubscriberDataUtils::EventTrigger::USER,
                               time(NULL),
                               0);

  ASSERT_EQ(2, txdata_count());
  pjsip_msg* out = current_txdata()->msg;

  // Check that the NOTIFY body is correct, and that the state of the
  // subscription is correct.
  check_subscription_state_header(out, "active;expires=300");
  rapidxml::xml_document<>* doc = parse_notify_body(out);
  check_notify_general_info(doc);
  std::vector<std::pair<std::string, bool>> impus;
  impus.push_back(std::make_pair("sip:1234567890@homedomain", false));
  check_notify_registration_nodes(doc, ACTIVE, {ACTIVE_REGISTERED}, impus);

  inject_msg(respond_to_current_txdata(200));
  delete doc;
  out = current_txdata()->msg;

  // Check that the NOTIFY body is correct, and that the state of the
  // subscription is correct.
  check_subscription_state_header(out, "active;expires=300");
  doc = parse_notify_body(out);
  check_notify_general_info(doc);
  check_notify_registration_nodes(doc, ACTIVE, {ACTIVE_REGISTERED}, impus);

  // Tidy up
  inject_msg(respond_to_current_txdata(200));
  delete doc;
  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;
}

// Test adding a subscription when there's already an existing subscription.
// We should only send one NOTIFY for the new subscription.
TEST_F(NotifySenderTest, NotifyOneNotifyIfOneSubscriptionChanged)
{
  std::string aor_id = "sip:1234567890@homedomain";
  int now = time(NULL);
  AoR* orig_aor = AoRTestUtils::create_simple_aor(aor_id);
  AoR* updated_aor = AoRTestUtils::create_simple_aor(aor_id);
  Subscription* s = AoRTestUtils::build_subscription(AoRTestUtils::SUBSCRIPTION_ID, now);
  s->_from_uri = std::string("<sip:12345@cw-ngv.com>");
  s->_from_tag = std::string("4321");
  s->_to_uri = std::string("<sip:12345@cw-ngv.com>");
  s->_to_tag = "1234";
  updated_aor->_subscriptions.insert(std::make_pair(AoRTestUtils::SUBSCRIPTION_ID + "2", s));

  _notify_sender->send_notifys(aor_id,
                               *orig_aor,
                               *updated_aor,
                               SubscriberDataUtils::EventTrigger::USER,
                               time(NULL),
                               0);

  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;

  // Check that the NOTIFY body is correct, and that the state of the
  // subscription is correct. Also check that the one NOTIFY got sent to the
  // new subscription.
  EXPECT_EQ("To: <sip:12345@cw-ngv.com>;tag=4321", get_headers(out, "To"));
  EXPECT_EQ("From: <sip:12345@cw-ngv.com>;tag=1234", get_headers(out, "From"));
  check_subscription_state_header(out, "active;expires=300");
  rapidxml::xml_document<>* doc = parse_notify_body(out);
  check_notify_general_info(doc);
  std::vector<std::pair<std::string, bool>> impus;
  impus.push_back(std::make_pair("sip:1234567890@homedomain", false));
  check_notify_registration_nodes(doc, ACTIVE, {ACTIVE_REGISTERED}, impus);

  // Tidy up
  inject_msg(respond_to_current_txdata(200));
  delete doc;
  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;
}

// Test if a binding changes if there are two subscriptions - this should
// trigger two NOTIFYs.
TEST_F(NotifySenderTest, NotifyTwoSubscriptionsBindingChange)
{
  std::string aor_id = "sip:1234567890@homedomain";
  int now = time(NULL);
  AoR* orig_aor = AoRTestUtils::create_simple_aor(aor_id);
  Subscription* s1 = AoRTestUtils::build_subscription(AoRTestUtils::SUBSCRIPTION_ID, now);
  orig_aor->_subscriptions.insert(std::make_pair(AoRTestUtils::SUBSCRIPTION_ID + "2", s1));
  AoR* updated_aor = AoRTestUtils::create_simple_aor(aor_id);
  Binding* b = AoRTestUtils::build_binding(aor_id, now, "<sip:6505550231@192.91.191.29:59935;transport=tcp;ob>", now + 10);
  updated_aor->_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID + "2", b));
  Subscription* s2 = AoRTestUtils::build_subscription(AoRTestUtils::SUBSCRIPTION_ID, now);
  updated_aor->_subscriptions.insert(std::make_pair(AoRTestUtils::SUBSCRIPTION_ID + "2", s2));

  _notify_sender->send_notifys(aor_id,
                               *orig_aor,
                               *updated_aor,
                               SubscriberDataUtils::EventTrigger::USER,
                               time(NULL),
                               0);

  ASSERT_EQ(2, txdata_count());
  pjsip_msg* out = current_txdata()->msg;

  // Check that the NOTIFY body is correct, and that the state of the
  // subscription is correct.
  check_subscription_state_header(out, "active;expires=300");
  rapidxml::xml_document<>* doc = parse_notify_body(out);
  check_notify_general_info(doc);
  std::vector<std::pair<std::string, bool>> impus;
  impus.push_back(std::make_pair("sip:1234567890@homedomain", false));
  check_notify_registration_nodes(doc, ACTIVE, {ACTIVE_REGISTERED, ACTIVE_CREATED}, impus);

  inject_msg(respond_to_current_txdata(200));
  delete doc;
  out = current_txdata()->msg;

  // Check that the NOTIFY body is correct, and that the state of the
  // subscription is correct.
  check_subscription_state_header(out, "active;expires=300");
  doc = parse_notify_body(out);
  check_notify_general_info(doc);
  check_notify_registration_nodes(doc, ACTIVE, {ACTIVE_REGISTERED, ACTIVE_CREATED}, impus);

  // Tidy up
  inject_msg(respond_to_current_txdata(200));
  delete doc;
  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;
}
