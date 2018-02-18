/**
 * @file registrar_test.cpp UT for Sprout registrar module.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <string>
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "siptest.hpp"
#include "test_utils.hpp"
#include "utils.h"
#include "stack.h"
#include "registrarsproutlet.h"
#include "sproutletproxy.h"
#include "test_interposer.hpp"
#include "mock_subscriber_manager.h"
#include "fakesnmp.hpp"
#include "aor_test_utils.h"
#include "mock_snmp_counter_table.hpp"
#include "aor_utils.h"
#include "aor_test_utils.h"

using ::testing::MatchesRegex;
using ::testing::_;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::InSequence;
using ::testing::SetArgReferee;
using ::testing::SetArgPointee;
using ::testing::HasSubstr;
using ::testing::An;

class Message
{
public:
  string _method;
  string _user;
  string _domain;
  string _content_type;
  string _body;
  string _contact;
  string _contact_instance;
  string _contact_params;
  string _expires;
  string _path;
  string _auth;
  string _cseq;
  string _branch;
  string _scheme;
  string _route;
  bool _gruu_support;
  int _unique; //< unique to this dialog; inserted into Call-ID
  string _cid;

  Message() :
    _method("REGISTER"),
    _user("6505550231"),
    _domain("homedomain"),
    _contact("sip:6505550231@192.91.191.29:59934;transport=tcp;ob"),
    _contact_instance(";+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\""),
    _contact_params(";expires=300;+sip.ice;reg-id=1"),
    _expires(""),
    _path("Path: <sip:abcdefgh@bono1.homedomain;transport=tcp;lr>"),
    _auth(""),
    _cseq("17038"),
    _branch(""),
    _scheme("sip"),
    _route("sprout.homedomain"),
    _gruu_support(true)
  {
    static int unique = 1042;
    _unique = unique;
    unique += 10;
    _cid = "0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs" + std::to_string(_unique) + "04dohntC@10.114.61.213";
  }

  string get();

  void inc_cseq()
  {
    _cseq = std::to_string(std::stoi(_cseq) + 1);
  }
};

string Message::get()
{
  char buf[16384];
  char contact[1024];
  int n = 0;

  // Contact header is optional
  contact[0] = 0;
  if (!_contact.empty())
  {
    n = snprintf(contact, sizeof(contact),
                 "Contact: %1$s%2$s%3$s\r\n",
                 /*  1 */ (_contact == "*") ? "*" : string("<").append(_contact).append(">").c_str(),
                 /*  2 */ _contact_params.c_str(),
                 /*  3 */ _contact_instance.c_str()
                 );
    EXPECT_LT(n, (int)sizeof(buf));
  }

  std::string branch = _branch.empty() ? "Pjmo1aimuq33BAI4rjhgQgBr4sY" + std::to_string(_unique) + _cseq : _branch;
  std::string route = _route.empty() ? "" : "Route: <sip:" + _route + ";transport=tcp;lr;service=registrar>\r\n";

  n = snprintf(buf, sizeof(buf),
               "%1$s sip:%3$s SIP/2.0\r\n"
               "%8$s"
               "Via: SIP/2.0/TCP 10.83.18.38:36530;rport;branch=z9hG4bK%14$s\r\n"
               "Via: SIP/2.0/TCP 10.114.61.213:5061;received=23.20.193.43;branch=z9hG4bK+7f6b263a983ef39b0bbda2135ee454871+sip+1+a64de9f6\r\n"
               "From: <%2$s>;tag=10.114.61.213+1+8c8b232a+5fb751cf\r\n"
               "Supported: outbound, path%13$s\r\n"
               "To: <%2$s>\r\n"
               "Max-Forwards: 68\r\n"
               "Call-ID: %15$s\r\n"
               "CSeq: %11$s %1$s\r\n"
               "User-Agent: Accession 2.0.0.0\r\n"
               "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n"
               "%9$s"
               "%7$s"
               "%12$s"
               "P-Access-Network-Info: DUMMY\r\n"
               "P-Visited-Network-ID: DUMMY\r\n"
               "P-Charging-Vector: icid-value=100\r\n"
               "%10$s"
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
               /*  7 */ contact,
               /*  8 */ _path.empty() ? "" : string(_path).append("\r\n").c_str(),
               /*  9 */ _expires.empty() ? "" : string(_expires).append("\r\n").c_str(),
               /* 10 */ _auth.empty() ? "" : string(_auth).append("\r\n").c_str(),
               /* 11 */ _cseq.c_str(),
               /* 12 */ route.c_str(),
               /* 13 */ _gruu_support ? ", gruu" : "",
               /* 14 */ branch.c_str(),
               /* 15 */ _cid.c_str()
    );

  EXPECT_LT(n, (int)sizeof(buf));

  string ret(buf, n);

  TRC_DEBUG("REGISTER message\n%s", ret.c_str());
  return ret;
}

/// Save off the bindings. We can't just use SaveArg, as this only
/// saves off the BindingMap, not the BindingMap members. This
/// means that the binding objects have been deleted before we can
/// check it. This allows us to create a copy of the Bindings
/// we can check against. The caller is responsible for deleting the copied
/// object.
ACTION_P(SaveBindingsRegister, bindings)
{
  *bindings = SubscriberDataUtils::copy_bindings(arg3);
}

ACTION_P(SaveBindingsReRegister, bindings)
{
  *bindings = SubscriberDataUtils::copy_bindings(arg3);
}

/// Fixture for RegistrarTest.
class RegistrarTest : public SipTest
{
public:

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
    SipTest::SetScscfUri("sip:scscf.sprout.homedomain:5058;transport=TCP");

    _sm = new MockSubscriberManager();
    _acr_factory = new ACRFactory();
  }

  static void TearDownTestCase()
  {
    // Shut down the transaction module first, before we destroy the
    // objects that might handle any callbacks!
    pjsip_tsx_layer_destroy();
    delete _acr_factory; _acr_factory = NULL;
    delete _sm; _sm = NULL;
    SipTest::TearDownTestCase();
  }

  void SetUp()
  {
  }

  void TearDown()
  {
  }

  RegistrarTest()
  {
    _registrar_sproutlet = new RegistrarSproutlet("registrar",
                                                  5058,
                                                  "sip:registrar.homedomain:5058;transport=tcp",
                                                  { "scscf" },
                                                  "scscf",
                                                  "subscription",
                                                  _sm,
                                                  _acr_factory,
                                                  300,
                                                  &SNMP::FAKE_REGISTRATION_STATS_TABLES);

    EXPECT_TRUE(_registrar_sproutlet->init());

    std::list<Sproutlet*> sproutlets;
    sproutlets.push_back(_registrar_sproutlet);

    std::unordered_set<std::string> additional_home_domains;
    additional_home_domains.insert("sprout.homedomain");
    additional_home_domains.insert("sprout-site2.homedomain");

    _registrar_proxy = new SproutletProxy(stack_data.endpt,
                                          PJSIP_MOD_PRIORITY_UA_PROXY_LAYER,
                                          "homedomain",
                                          additional_home_domains,
                                          std::unordered_set<std::string>(),
                                          true,
                                          sproutlets,
                                          std::set<std::string>(),
                                          nullptr,
                                          nullptr);
  }

  ~RegistrarTest()
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

    ((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->reset_count();
    ((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->reset_count();
    ((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->reset_count();
    ((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->reset_count();
    ((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.re_reg_tbl)->reset_count();
    ((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.de_reg_tbl)->reset_count();

    delete _registrar_proxy; _registrar_proxy = NULL;
    delete _registrar_sproutlet; _registrar_sproutlet = NULL;
  }

  void request_not_handled_by_registrar_sproutlet()
  {
    ASSERT_EQ(1, txdata_count());
    inject_msg(respond_to_current_txdata(200));
    ASSERT_EQ(1, txdata_count());
    EXPECT_EQ(200, current_txdata()->msg->line.status.code);
    free_txdata();
  }

  // This sets up a basic IRS Info to be returned on the get_subscriber_state
  // call.
  void set_up_basic_irs_info(HSSConnection::irs_info& irs_info)
  {
    AssociatedURIs associated_uris;
    associated_uris.add_uri("sip:6505550231@homedomain", false);
    irs_info._regstate = RegDataXMLUtils::STATE_REGISTERED;
    irs_info._associated_uris = associated_uris;
    irs_info._ccfs.push_back("CCF reg test");
    irs_info._ecfs.push_back("ECF reg test");
  }

  void set_up_single_returned_binding(Bindings& all_bindings, std::string cid)
  {
    Binding* binding = AoRTestUtils::build_binding("sip:6505550231@homedomain", time(NULL));
    binding->_cid = cid;
    all_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID, binding));
  }

  void expectations_for_successful_get_subscriber_state(HSSConnection::irs_info& irs_info)
  {
    set_up_basic_irs_info(irs_info);
    EXPECT_CALL(*_sm, get_subscriber_state(_, _, _))
      .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                      Return(HTTP_OK)));
  }

  void expectations_for_not_found_get_bindings()
  {
    EXPECT_CALL(*_sm, get_bindings(_, _, _))
      .WillOnce(Return(HTTP_NOT_FOUND));
  }

  void expectations_for_registration_sender()
  {
    EXPECT_CALL(*_sm, register_with_application_servers(_, _, _, _, _, _, _));
  }

  void expectations_for_get_single_binding()
  {
    Bindings get_bindings;
    set_up_single_returned_binding(get_bindings, "different cid");
    EXPECT_CALL(*_sm, get_bindings(_, _, _))
      .WillOnce(DoAll(SetArgReferee<1>(get_bindings),
                      Return(HTTP_OK)));
  }

protected:
  static MockSubscriberManager* _sm;
  static ACRFactory* _acr_factory;
  RegistrarSproutlet* _registrar_sproutlet;
  SproutletProxy* _registrar_proxy;
};

MockSubscriberManager* RegistrarTest::_sm;
ACRFactory* RegistrarTest::_acr_factory;

// This test registers a subscriber by adding a single binding. It checks in
// detail the created binding object, the headers on the 200 OKs, and the call
// to the registration sender.
TEST_F(RegistrarTest, RegisterSubscriber)
{
  // Set up message with an expiry time of 300, a valid Authorization header
  // with a private ID, and with a sip-instance (so that we create a GRUU).
  Message msg;
  msg._expires = "Expires: 300";
  msg._auth = "Authorization: Digest username=\"6505550231\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact_params = ";+sip.ice;reg-id=1";

  // When a subscriber registers, it calls get_subscriber_state to get the
  // default IMPU for the subscriber, get_bindings to get the current bindings,
  // register_subscriber to actually register the subscriber, and finally
  // register_with_application_servers to deal with third party application
  // servers.

  // Catch the irs_query and the bindings object set on the calls to SM.
  HSSConnection::irs_query irs_query;
  Bindings bindings;

  // Set up the irs_info and all_bindings objects returned by the SM.
  HSSConnection::irs_info irs_info;
  set_up_basic_irs_info(irs_info);
  Bindings all_bindings;
  set_up_single_returned_binding(all_bindings, msg._cid);

  // Set up the expect calls.
  EXPECT_CALL(*_sm, get_subscriber_state(_, _, _))
    .WillOnce(DoAll(SaveArg<0>(&irs_query),
                    SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_sm, get_bindings("sip:6505550231@homedomain", _, _))
    .WillOnce(Return(HTTP_NOT_FOUND));
  EXPECT_CALL(*_sm, register_subscriber("sip:6505550231@homedomain", "sip:scscf.sprout.homedomain:5058;transport=TCP", irs_info._associated_uris, _, _, _, _))
    .WillOnce(DoAll(SaveBindingsRegister(&bindings),
                    SetArgReferee<4>(all_bindings),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_sm, register_with_application_servers(_, _, "sip:6505550231@homedomain", _, 300, true, _));

  // Send register.
  inject_msg(msg.get());

  // Expect 200 OK and check the headers.
  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:6505550231@192.91.191.29:59934;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b4dd32817622\"", get_headers(out, "Contact"));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ("P-Charging-Function-Addresses: ccf=\"CCF reg test\";ecf=\"ECF reg test\"", get_headers(out, "P-Charging-Function-Addresses"));
  free_txdata();

  // Check the created binding object is correct, and that we called
  // get_subscriber_state with the right parameters.
  ASSERT_FALSE(bindings[AoRTestUtils::BINDING_ID] == NULL);
  Binding* expected_binding = AoRTestUtils::build_binding("sip:6505550231@homedomain", time(NULL));
  expected_binding->_cid = msg._cid;
  EXPECT_TRUE(*(bindings[AoRTestUtils::BINDING_ID]) == *expected_binding);
  EXPECT_EQ(irs_query._public_id, "sip:6505550231@homedomain");
  EXPECT_EQ(irs_query._private_id, "6505550231");
  EXPECT_EQ(irs_query._req_type, "reg");
  EXPECT_EQ(irs_query._server_name, "sip:scscf.sprout.homedomain:5058;transport=TCP");

  // Check the stats are correct
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);

  // Tidy up.
  SubscriberDataUtils::delete_bindings(bindings);
  delete expected_binding;
}

// Test an initial register where there's no private ID on the message. This
// should be processed successfully, but have a different ID stored on the
// binding.
TEST_F(RegistrarTest, RegisterSubscriberNoPrivateID)
{
  Message msg;

  // Catch the irs_query and the bindings object set on the calls to SM.
  HSSConnection::irs_query irs_query;
  Bindings bindings;

  // Set up the irs_info and all_bindings objects returned by the SM.
  HSSConnection::irs_info irs_info;
  set_up_basic_irs_info(irs_info);
  Bindings all_bindings;
  set_up_single_returned_binding(all_bindings, msg._cid);

  // Set up the expect calls.
  EXPECT_CALL(*_sm, get_subscriber_state(_, _, _))
    .WillOnce(DoAll(SaveArg<0>(&irs_query),
                    SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  expectations_for_not_found_get_bindings();
  EXPECT_CALL(*_sm, register_subscriber(_, _, _, _, _, _, _))
    .WillOnce(DoAll(SaveBindingsRegister(&bindings),
                    SetArgReferee<4>(all_bindings),
                    Return(HTTP_OK)));
  expectations_for_registration_sender();

  // Send register.
  inject_msg(msg.get());

  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));

  free_txdata();

  // Check the private ID on the stored binding and on the irs query.
  ASSERT_FALSE(bindings[AoRTestUtils::BINDING_ID] == NULL);
  EXPECT_EQ(bindings[AoRTestUtils::BINDING_ID]->_private_id, "6505550231@homedomain");
  EXPECT_EQ(irs_query._private_id, "");

  // Tidy up.
  SubscriberDataUtils::delete_bindings(bindings);
}

// Test reregistering a subscriber. We don't check much in this test (as the
// code is the same as the register case) - check the reregister call in detail,
// that the correct stats are called, and that the
// register_with_application_servers call is not for an initial register.
TEST_F(RegistrarTest, ReRegisterSubscriber)
{
  Message msg;
  msg._auth = "Authorization: Digest username=\"6505550231\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact_params = ";+sip.ice;reg-id=1";

  // Set up the irs_info and all_bindings objects returned by the SM.
  Bindings bindings;
  HSSConnection::irs_info irs_info;
  Bindings all_bindings;
  set_up_single_returned_binding(all_bindings, msg._cid);

  expectations_for_successful_get_subscriber_state(irs_info);
  expectations_for_get_single_binding();
  EXPECT_CALL(*_sm, reregister_subscriber("sip:6505550231@homedomain", "sip:scscf.sprout.homedomain:5058;transport=TCP", irs_info._associated_uris, _, std::vector<std::string>(), _, _, _))
    .WillOnce(DoAll(SaveBindingsReRegister(&bindings),
                    SetArgReferee<6>(irs_info),
                    SetArgReferee<5>(all_bindings),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_sm, register_with_application_servers(_, _, _, _, _, false, _));

  inject_msg(msg.get());

  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  ASSERT_FALSE(bindings[AoRTestUtils::BINDING_ID] == NULL);
  Binding* expected_binding = AoRTestUtils::build_binding("sip:6505550231@homedomain", time(NULL));
  expected_binding->_cid = msg._cid;
  EXPECT_TRUE(*(bindings[AoRTestUtils::BINDING_ID]) == *expected_binding);

  free_txdata();

  // Check the stats are correct
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes);

  // Tidy up.
  SubscriberDataUtils::delete_bindings(bindings);
  delete expected_binding;
}

// Test a fetch request for an existing subscriber. This shouldn't pass in any
// changes on the reregister request, or increment any stats.
TEST_F(RegistrarTest, FetchBindingsRegisterExistingSubscriber)
{
  Message msg;
  msg._contact = "";

  // Set up the irs_info and all_bindings objects returned by the SM.
  Bindings bindings;
  HSSConnection::irs_info irs_info;
  Bindings all_bindings;
  set_up_single_returned_binding(all_bindings, msg._cid);

  expectations_for_successful_get_subscriber_state(irs_info);
  expectations_for_get_single_binding();
  EXPECT_CALL(*_sm, reregister_subscriber(_, _, _, Bindings(), std::vector<std::string>(), _, _, _))
    .WillOnce(DoAll(SetArgReferee<6>(irs_info),
                    SetArgReferee<5>(all_bindings),
                    Return(HTTP_OK)));

  inject_msg(msg.get());

  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));

  free_txdata();

  // Check the stats are correct
  EXPECT_EQ(0,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts);
}

// Test a fetch request for an unregisteredsubscriber. This shouldn't pass in any
// changes on the register request, or increment any stats.
TEST_F(RegistrarTest, FetchBindingsUnregisteredSubscriber)
{
  Message msg;
  msg._contact = "";

  // Set up the irs_info and all_bindings objects returned by the SM.
  Bindings bindings;
  HSSConnection::irs_info irs_info;
  Bindings all_bindings = Bindings();

  expectations_for_successful_get_subscriber_state(irs_info);
  expectations_for_not_found_get_bindings();
  EXPECT_CALL(*_sm, register_subscriber(_, _, _, Bindings(), _, _, _))
    .WillOnce(DoAll(SetArgReferee<4>(all_bindings),
                    Return(HTTP_OK)));

  inject_msg(msg.get());

  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));

  free_txdata();

  // Check the stats are correct
  EXPECT_EQ(0,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
}

// Test deregistering a subscriber. We don't check much in this test (as the
// code is the same as the register case) - check the reregister call in detail,
// that the correct stats are called, and that the
// register_with_application_servers call is not for an initial register.
TEST_F(RegistrarTest, DeregisterSubscriber)
{
  Message msg;
  msg._expires = "Expires: 0";
  msg._contact = "sip:6505550231@192.91.191.29:59934;transport=tcp;ob";
  msg._contact_params = "";

  HSSConnection::irs_info irs_info;
  Bindings all_bindings = Bindings();
  std::vector<std::string> removed_bindings;
  expectations_for_successful_get_subscriber_state(irs_info);
  expectations_for_get_single_binding();
  EXPECT_CALL(*_sm, reregister_subscriber(_, _, _, Bindings(), _, _, _, _))
    .WillOnce(DoAll(SaveArg<4>(&removed_bindings),
                    SetArgReferee<6>(irs_info),
                    SetArgReferee<5>(all_bindings),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_sm, register_with_application_servers(_, _, _, _, 0, false, _));

  inject_msg(msg.get());

  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));

  ASSERT_EQ(removed_bindings.size(), 1);
  EXPECT_EQ(removed_bindings[0], "<urn:uuid:00000000-0000-0000-0000-b4dd32817622>");

  // Check the stats are correct
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_successes);
}

// Test deregistering a subscriber with the wildcard contact header.
TEST_F(RegistrarTest, DeregisterSubscriberWithWildcard)
{
  Message msg;
  msg._expires = "Expires: 0";
  msg._contact = "*";
  msg._contact_instance = "";
  msg._contact_params = "";

  HSSConnection::irs_info irs_info;
  Bindings all_bindings = Bindings();
  std::vector<std::string> removed_bindings;
  expectations_for_successful_get_subscriber_state(irs_info);
  expectations_for_get_single_binding();
  EXPECT_CALL(*_sm, reregister_subscriber(_, _, _, Bindings(), _, _, _, _))
    .WillOnce(DoAll(SaveArg<4>(&removed_bindings),
                    SetArgReferee<6>(irs_info),
                    SetArgReferee<5>(all_bindings),
                    Return(HTTP_OK)));
  expectations_for_registration_sender();

  inject_msg(msg.get());

  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));

  ASSERT_EQ(removed_bindings.size(), 1);
  EXPECT_EQ(removed_bindings[0], "<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1");

  // Check the stats are correct
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_successes);
}

// Test that a register fails correctly if we're unable to get the subscriber
// state.
TEST_F(RegistrarTest, GetSubscriberStateFail)
{
  Message msg;

  EXPECT_CALL(*_sm, get_subscriber_state(_, _, _))
    .WillOnce(Return(HTTP_NOT_FOUND));

  inject_msg(msg.get());

  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(403, out->line.status.code);
  EXPECT_EQ("Forbidden", str_pj(out->line.status.reason));

  free_txdata();
}

// Test that a register fails correctly if we're unable to get the current
// bindings.
TEST_F(RegistrarTest, GetBindingsFail)
{
  Message msg;
  HSSConnection::irs_info irs_info;
  expectations_for_successful_get_subscriber_state(irs_info);
  EXPECT_CALL(*_sm, get_bindings(_, _, _))
    .WillOnce(Return(HTTP_SERVER_ERROR));

  inject_msg(msg.get());

  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(500, out->line.status.code);
  EXPECT_EQ("Internal Server Error", str_pj(out->line.status.reason));

  free_txdata();
}

// Test that an initial register fails correctly if the register call fails.
TEST_F(RegistrarTest, RegisterFail)
{
  Message msg;
  HSSConnection::irs_info irs_info;
  Bindings all_bindings = Bindings();
  std::vector<std::string> removed_bindings;
  expectations_for_successful_get_subscriber_state(irs_info);
  expectations_for_not_found_get_bindings();
  EXPECT_CALL(*_sm, register_subscriber(_, _, _, _, _, _, _))
    .WillOnce(Return(HTTP_SERVER_ERROR));
  expectations_for_registration_sender();

  inject_msg(msg.get());

  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(500, out->line.status.code);
  EXPECT_EQ("Internal Server Error", str_pj(out->line.status.reason));

  free_txdata();
}

// Test that an reregister fails correctly if the reregister call fails.
TEST_F(RegistrarTest, ReRegisterFail)
{
  Message msg;
  HSSConnection::irs_info irs_info;
  expectations_for_successful_get_subscriber_state(irs_info);
  expectations_for_get_single_binding();
  EXPECT_CALL(*_sm, reregister_subscriber(_, _, _, _, _, _, _, _))
    .WillOnce(Return(HTTP_SERVER_ERROR));
  expectations_for_registration_sender();

  inject_msg(msg.get());

  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(500, out->line.status.code);
  EXPECT_EQ("Internal Server Error", str_pj(out->line.status.reason));
}

// Test that an deregister fails correctly if the reregister call fails.
TEST_F(RegistrarTest, DeregisterFail)
{
  Message msg;
  msg._expires = "Expires: 0";
  msg._contact = "sip:6505550231@192.91.191.29:59934;transport=tcp;ob";
  msg._contact_params = "";

  HSSConnection::irs_info irs_info;
  expectations_for_successful_get_subscriber_state(irs_info);
  expectations_for_get_single_binding();
  EXPECT_CALL(*_sm, reregister_subscriber(_, _, _, _, _, _, _, _))
    .WillOnce(Return(HTTP_SERVER_ERROR));
  expectations_for_registration_sender();

  inject_msg(msg.get());

  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(500, out->line.status.code);
  EXPECT_EQ("Internal Server Error", str_pj(out->line.status.reason));
}

// Test the behaviour when the request isn't a register.
TEST_F(RegistrarTest, NotRegister)
{
  Message msg;
  msg._method = "PUBLISH";
  inject_msg(msg.get());
  request_not_handled_by_registrar_sproutlet();
}

// Test the behaviour when the request isn't targeted at the home domain.
TEST_F(RegistrarTest, NotOurs)
{
  Message msg;
  msg._domain = "not-us.example.org";
  add_host_mapping("not-us.example.org", "5.6.7.8");
  inject_msg(msg.get());
  request_not_handled_by_registrar_sproutlet();
}

// Test the behaviour when the route header on the request isn't us.
TEST_F(RegistrarTest, RouteHeaderNotMatching)
{
  Message msg;
  msg._route = "notthehomedomain";
  add_host_mapping("notthehomedomain", "5.6.7.8");
  inject_msg(msg.get());
  request_not_handled_by_registrar_sproutlet();
}

// Test the behaviouor when the register has an unsupported scheme.
TEST_F(RegistrarTest, BadScheme)
{
  Message msg;
  msg._scheme = "sips";
  inject_msg(msg.get());

  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  out = pop_txdata()->msg;
  EXPECT_EQ(404, out->line.status.code);
  EXPECT_EQ("Not Found", str_pj(out->line.status.reason));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_failures);
}

// Test that a subscriber is unable to do a normal register if all of the
// associated URIs are barred.
TEST_F(RegistrarTest, AllIMPUsBarred)
{
  Message msg;

  AssociatedURIs associated_uris;
  associated_uris.add_uri("sip:6505550231@homedomain", true);
  HSSConnection::irs_info irs_info;
  irs_info._regstate = RegDataXMLUtils::STATE_REGISTERED;
  irs_info._associated_uris = associated_uris;

  EXPECT_CALL(*_sm, get_subscriber_state(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));

  inject_msg(msg.get());

  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(400, out->line.status.code);
  EXPECT_EQ("Bad Request", str_pj(out->line.status.reason));

  free_txdata();
}

// Test that an emergency registration is successful.
TEST_F(RegistrarTest, EmergencyRegistration)
{
  Message msg;
  msg._contact += ";sos";

  HSSConnection::irs_info irs_info;
  Bindings all_bindings;
  Binding* binding = AoRTestUtils::build_binding("sip:6505550231@homedomain", time(NULL));
  binding->_cid = msg._cid;
  binding->_emergency_registration = true;
  all_bindings.insert(std::make_pair("sos" + AoRTestUtils::BINDING_ID, binding));
  Bindings bindings;
  std::vector<std::string> removed_bindings;
  expectations_for_successful_get_subscriber_state(irs_info);
  expectations_for_not_found_get_bindings();
  EXPECT_CALL(*_sm, register_subscriber(_, _, _, _, _, _, _))
    .WillOnce(DoAll(SaveBindingsRegister(&bindings),
                    SetArgReferee<4>(all_bindings),
                    Return(HTTP_OK)));

  inject_msg(msg.get());

  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  free_txdata();

  ASSERT_EQ(bindings.size(), 1);
  EXPECT_TRUE(bindings["sos" + AoRTestUtils::BINDING_ID]->_emergency_registration);

  // Tidy up
  SubscriberDataUtils::delete_bindings(bindings);
}

// Test that an emergency registration is successful even when all the IMPUs
// are barred.
TEST_F(RegistrarTest, EmergencyRegistrationAllIMPUsBarred)
{
  Message msg;
  msg._contact += ";sos";

  Bindings bindings;
  Bindings all_bindings;
  Binding* binding = AoRTestUtils::build_binding("sip:6505550231@homedomain", time(NULL));
  binding->_cid = msg._cid;
  binding->_emergency_registration = true;
  all_bindings.insert(std::make_pair("sos" + AoRTestUtils::BINDING_ID, binding));
  AssociatedURIs associated_uris;
  associated_uris.add_uri("sip:6505550231@homedomain", true);
  HSSConnection::irs_info irs_info;
  irs_info._regstate = RegDataXMLUtils::STATE_REGISTERED;
  irs_info._associated_uris = associated_uris;

  EXPECT_CALL(*_sm, get_subscriber_state(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  expectations_for_not_found_get_bindings();
  EXPECT_CALL(*_sm, register_subscriber(_, _, _, _, _, _, _))
    .WillOnce(DoAll(SaveBindingsRegister(&bindings),
                    SetArgReferee<4>(all_bindings),
                    Return(HTTP_OK)));

  inject_msg(msg.get());

  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));

  ASSERT_EQ(bindings.size(), 1);
  EXPECT_TRUE(bindings["sos" + AoRTestUtils::BINDING_ID]->_emergency_registration);

  free_txdata();

  // Tidy up
  SubscriberDataUtils::delete_bindings(bindings);
}

TEST_F(RegistrarTest, ReduceTimeForEmergencyBinding)
{
  Message msg;
  msg._expires = "Expires: 200";
  msg._contact = "sip:6505550231@192.91.191.29:59934;transport=tcp;sos;ob";
  msg._contact_params = ";+sip.ice;reg-id=1";

  Bindings get_bindings;
  Binding* get_binding = AoRTestUtils::build_binding("sip:6505550231@homedomain", time(NULL));
  get_binding->_cid = msg._cid;
  get_binding->_emergency_registration = true;
  get_binding->_expires = 300 + time(NULL);
  get_bindings.insert(std::make_pair("sos" + AoRTestUtils::BINDING_ID, get_binding));

  Bindings all_bindings;
  Binding* get_binding2 = AoRTestUtils::build_binding("sip:6505550231@homedomain", time(NULL));
  get_binding2->_cid = msg._cid;
  get_binding2->_emergency_registration = true;
  all_bindings.insert(std::make_pair("sos" + AoRTestUtils::BINDING_ID, get_binding2));

  AssociatedURIs associated_uris;
  associated_uris.add_uri("sip:6505550231@homedomain", false);
  HSSConnection::irs_info irs_info;
  irs_info._regstate = RegDataXMLUtils::STATE_REGISTERED;
  irs_info._associated_uris = associated_uris;

  Bindings bindings;

  EXPECT_CALL(*_sm, get_subscriber_state(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_sm, get_bindings(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(get_bindings),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_sm, reregister_subscriber(_, _, _, _, _, _, _, _))
    .WillOnce(DoAll(SaveBindingsReRegister(&bindings),
                    SetArgReferee<6>(irs_info),
                    SetArgReferee<5>(all_bindings),
                    Return(HTTP_OK)));

  inject_msg(msg.get());

  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  free_txdata();

  ASSERT_EQ(bindings.size(), 1);
  EXPECT_TRUE(bindings["sos" + AoRTestUtils::BINDING_ID]->_emergency_registration);
  EXPECT_EQ(300 + time(NULL), bindings["sos" + AoRTestUtils::BINDING_ID]->_expires);

  // Tidy up
  SubscriberDataUtils::delete_bindings(bindings);
}

// Test that the correct P-Associated-URI headers are set if there's a complex
// set of associated URIs.
TEST_F(RegistrarTest, ComplexAssociatedURIs)
{
  Message msg;

  // Add a binding. Save off the created binding, then check that
  // and the headers on the 200 OK.
  HSSConnection::irs_info irs_info;
  set_up_basic_irs_info(irs_info);
  irs_info._associated_uris.add_uri("sip:6505550232@homedomain", false);
  irs_info._associated_uris.add_uri("sip:6505550233@homedomain", true);
  irs_info._associated_uris.add_uri("sip:6505550234@homedomain", false);
  irs_info._associated_uris.add_uri("sip:6505550235@homedomain", true);
  irs_info._associated_uris.add_uri("6505550231@homedomain", false);
  irs_info._associated_uris.add_uri("6505550232@homedomain", false);
  irs_info._associated_uris.add_wildcard_mapping("6!.*!@homedomain", "6505550232@homedomain");
  irs_info._associated_uris.add_wildcard_mapping("6!.*!@homedomain", "6505550232@homedomain");
  irs_info._associated_uris.add_wildcard_mapping("sip:6!.*!@homedomain", "sip:6505550234@homedomain");
  irs_info._associated_uris.add_wildcard_mapping("sip:6!.*!@homedomain", "sip:6505550235@homedomain");

  Bindings all_bindings;
  set_up_single_returned_binding(all_bindings, msg._cid);
  std::vector<std::string> removed_bindings;
  EXPECT_CALL(*_sm, get_subscriber_state(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  expectations_for_not_found_get_bindings();
  EXPECT_CALL(*_sm, register_subscriber(_, _, _, _, _, _, _))
    .WillOnce(DoAll(SetArgReferee<4>(all_bindings),
                    Return(HTTP_OK)));
  expectations_for_registration_sender();

  inject_msg(msg.get());

  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>\r\nP-Associated-URI: <sip:6505550232@homedomain>\r\nP-Associated-URI: <sip:6505550234@homedomain>", get_headers(out, "P-Associated-URI"));

  free_txdata();
}

// Test a register that fails basic validation, as the only thing it's trying to
// do is deregister an emergency registration.
TEST_F(RegistrarTest, DeregisterEmergencyBinding)
{
  Message msg;
  msg._expires = "Expires: 0";
  msg._contact = "sip:6505550231@192.91.191.29:59934;transport=tcp;sos;ob";
  msg._contact_params = "";

  inject_msg(msg.get());

  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(501, out->line.status.code);
  EXPECT_EQ("Not Implemented", str_pj(out->line.status.reason));

  free_txdata();
}

// Test a register that fails basic validation as it's got a star in the contact
// header but the expiry isn't 0.
TEST_F(RegistrarTest, InvalidContactStar)
{
  Message msg;
  msg._expires = "Expires: 1";
  msg._contact = "*";
  msg._contact_instance = "";
  msg._contact_params = "";

  inject_msg(msg.get());

  pjsip_msg* out = pop_txdata()->msg;
  EXPECT_EQ(400, out->line.status.code);
  EXPECT_EQ("Bad Request", str_pj(out->line.status.reason));

  free_txdata();
}

// Test that the behaviour is sensible if the UE has a bad GRUU.
TEST_F(RegistrarTest, BadGRUU)
{
  Message msg;
  msg._contact_instance = ";+sip.instance=1";
  msg._contact_params = "";

  Bindings all_bindings;
  HSSConnection::irs_info irs_info;
  Binding* binding = AoRTestUtils::build_binding("sip:6505550231@homedomain", time(NULL));
  binding->_cid = msg._cid;
  binding->_params["+sip.instance"] = "1";
  all_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID, binding));

  expectations_for_successful_get_subscriber_state(irs_info);
  expectations_for_not_found_get_bindings();
  EXPECT_CALL(*_sm, register_subscriber(_, _, _, _, _, _, _))
    .WillOnce(DoAll(SetArgReferee<4>(all_bindings),
                    Return(HTTP_OK)));
  expectations_for_registration_sender();

  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);

  // Check that there's no GRUU on the response.
  EXPECT_EQ("Contact: <sip:6505550231@192.91.191.29:59934;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=1;reg-id=1", get_headers(out, "Contact"));
  free_txdata();
}

/// Test that no GRUU is created if the UE doesn't support GRUUs
TEST_F(RegistrarTest, GRUUNotSupported)
{
  Message msg;
  msg._expires = "Expires: 300";
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact_params = ";+sip.ice;reg-id=1";
  msg._gruu_support = false;

  HSSConnection::irs_info irs_info;
  Bindings all_bindings;
  set_up_single_returned_binding(all_bindings, msg._cid);
  std::vector<std::string> removed_bindings;
  expectations_for_successful_get_subscriber_state(irs_info);
  expectations_for_not_found_get_bindings();
  EXPECT_CALL(*_sm, register_subscriber(_, _, _, _, _, _, _))
    .WillOnce(DoAll(SetArgReferee<4>(all_bindings),
                    Return(HTTP_OK)));
  expectations_for_registration_sender();

  inject_msg(msg.get());

  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  // No pub-gruu as UE doesn't support GRUUs.
  EXPECT_EQ("Contact: <sip:6505550231@192.91.191.29:59934;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\";reg-id=1", get_headers(out, "Contact"));

  free_txdata();
}

// Test that the behaviour is correct when the original register doesn't have a path header.
TEST_F(RegistrarTest, NoPath)
{
  Message msg;
  msg._path = "";

  HSSConnection::irs_info irs_info;
  Bindings all_bindings;
  set_up_single_returned_binding(all_bindings, msg._cid);
  expectations_for_successful_get_subscriber_state(irs_info);
  expectations_for_not_found_get_bindings();
  EXPECT_CALL(*_sm, register_subscriber(_, _, _, _, _, _, _))
    .WillOnce(DoAll(SetArgReferee<4>(all_bindings),
                    Return(HTTP_OK)));
  expectations_for_registration_sender();

  inject_msg(msg.get());

  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("", get_headers(out, "Path"));

  free_txdata();
}

// EM-TODO: Extra Coverage TODOs - consider for FV tests.
// Register with non primary IMPU
// Register with multiple associated URIs (same as above?) - also Tel URIs
// Associated-URIS in PAU header with wildcards
// Registrations with Tel URIs (including emergency)
// Emergency reg with no sip instance (gruu?)
// Expires in the contact headers
// Contact with *
// Expires set to 0 in contact headers
// No expiry header or contact parameter
// Binding rinstance?
// Test with no route header?
