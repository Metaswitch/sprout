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
#include "registration_utils.h"
#include "fakehssconnection.hpp"
#include "fakechronosconnection.hpp"
#include "test_interposer.hpp"
#include "mock_store.h"
#include "fakesnmp.hpp"
#include "rapidxml/rapidxml.hpp"
#include "mock_hss_connection.h"
#include "hssconnection.h"

using ::testing::MatchesRegex;
using ::testing::_;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::InSequence;
using ::testing::SetArgReferee;
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

  Message() :
    _method("REGISTER"),
    _user("6505550231"),
    _domain("homedomain"),
    _contact("sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob"),
    _contact_instance(";+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\""),
    _contact_params(";expires=3600;+sip.ice;reg-id=1"),
    _expires(""),
    _path("Path: <sip:GgAAAAAAAACYyAW4z38AABcUwStNKgAAa3WOL+1v72nFJg==@ec2-107-22-156-220.compute-1.amazonaws.com:5060;lr;ob>"),
    _auth(""),
    _cseq("16567"),
    _branch(""),
    _scheme("sip"),
    _route("sprout.homedomain"),
    _gruu_support(true)
  {
    static int unique = 1042;
    _unique = unique;
    unique += 10;
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
               "Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs%15$04dohntC@10.114.61.213\r\n"
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
               /* 15 */ _unique
    );

  EXPECT_LT(n, (int)sizeof(buf));

  string ret(buf, n);

  TRC_DEBUG("REGISTER message\n%s", ret.c_str());
  return ret;
}

/// Fixture for RegistrarTest.
class RegistrarTest : public SipTest
{
public:

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
    SipTest::SetScscfUri("sip:scscf.sprout.homedomain:5058;transport=TCP");

    _chronos_connection = new FakeChronosConnection();
    _local_data_store = new LocalStore();
    _local_aor_store = new AstaireAoRStore(_local_data_store);
    _sdm = new SubscriberDataManager((AoRStore*)_local_aor_store, _chronos_connection, NULL, true);
    _remote_data_store = new LocalStore();
    _remote_aor_store = new AstaireAoRStore(_remote_data_store);
    _remote_sdm = new SubscriberDataManager((AoRStore*)_remote_aor_store, _chronos_connection, NULL, false);
    _remote_sdms = {_remote_sdm};
    _acr_factory = new ACRFactory();
    _hss_connection = new FakeHSSConnection();
    _fifc_service = new FIFCService(NULL, string(UT_DIR).append("/test_registrar_fifc.xml"));
  }

  static void TearDownTestCase()
  {
    // Shut down the transaction module first, before we destroy the
    // objects that might handle any callbacks!
    pjsip_tsx_layer_destroy();
    delete _fifc_service; _fifc_service = NULL;
    delete _acr_factory; _acr_factory = NULL;
    delete _hss_connection; _hss_connection = NULL;
    delete _remote_sdm; _remote_sdm = NULL;
    delete _remote_aor_store; _remote_aor_store = NULL;
    delete _remote_data_store; _remote_data_store = NULL;
    delete _sdm; _sdm = NULL;
    delete _local_aor_store; _local_aor_store = NULL;
    delete _local_data_store; _local_data_store = NULL;
    delete _chronos_connection; _chronos_connection = NULL;
    SipTest::TearDownTestCase();
  }

  void SetUp()
  {
    hss_connection()->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, "");
    hss_connection()->set_impu_result("tel:6505550231", "reg", RegDataXMLUtils::STATE_REGISTERED, "");
    hss_connection()->set_rc("/impu/sip%3A6505550231%40homedomain/reg-data", HTTP_OK);
    _chronos_connection->set_result("", HTTP_OK);
    _chronos_connection->set_result("post_identity", HTTP_OK);
  }

  void TearDown()
  {
    _hss_connection->flush_all();
    _chronos_connection->flush_all();
  }

  RegistrarTest() : RegistrarTest(_hss_connection)
  {
  }

  virtual FakeHSSConnection* hss_connection()
  {
    return _hss_connection;
  }

  RegistrarTest(FakeHSSConnection* hss_connection)
  {
    _local_data_store->flush_all();  // start from a clean slate on each test
    _remote_data_store->flush_all();

    IFCConfiguration ifc_configuration(false,
                                       false,
                                       "sip:dummyas",
                                       &SNMP::FAKE_COUNTER_TABLE,
                                       &SNMP::FAKE_COUNTER_TABLE);
    _registrar_sproutlet = new RegistrarSproutlet("registrar",
                                                  5058,
                                                  "sip:registrar.homedomain:5058;transport=tcp",
                                                  { "scscf" },
                                                  "scscf",
                                                  "subscription",
                                                  _sdm,
                                                  _remote_sdms,
                                                  hss_connection,
                                                  _acr_factory,
                                                  300,
                                                  false,
                                                  &SNMP::FAKE_REGISTRATION_STATS_TABLES,
                                                  &SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES,
                                                  _fifc_service,
                                                  ifc_configuration);

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
                                          sproutlets,
                                          std::set<std::string>());
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

  void check_notify(pjsip_msg* out,
                    std::string expected_aor,
                    std::string reg_state,
                    std::pair<std::string, std::string> contact_values,
                    int check_contact = 0)
  {
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
    ASSERT_TRUE(reg_info);
    rapidxml::xml_node<> *registration = reg_info->first_node("registration");
    ASSERT_TRUE(registration);
    rapidxml::xml_node<> *contact;
    contact = registration->first_node("contact");
    for (int ii = 0; ii < check_contact; ii++)
    {
      contact = contact->next_sibling();
    }

    ASSERT_TRUE(contact);

    ASSERT_EQ(expected_aor, std::string(registration->first_attribute("aor")->value()));
    ASSERT_EQ("full", std::string(reg_info->first_attribute("state")->value()));
    ASSERT_EQ(reg_state, std::string(registration->first_attribute("state")->value()));
    ASSERT_EQ(contact_values.first, std::string(contact->first_attribute("state")->value()));
    ASSERT_EQ(contact_values.second, std::string(contact->first_attribute("event")->value()));
  }

  void registrar_sproutlet_handle_200()
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
  static FIFCService* _fifc_service;
  static AstaireAoRStore* _local_aor_store;
  static AstaireAoRStore* _remote_aor_store;
  static SubscriberDataManager* _sdm;
  static SubscriberDataManager* _remote_sdm;
  static std::vector<SubscriberDataManager*> _remote_sdms;
  static IfcHandler* _ifc_handler;
  static ACRFactory* _acr_factory;
  static FakeHSSConnection* _hss_connection;
  static FakeChronosConnection* _chronos_connection;
  RegistrarSproutlet* _registrar_sproutlet;
  SproutletProxy* _registrar_proxy;
};

/// Fixture for RegistrarTest, which observes a HSS Connection
class RegistrarObservedHssTest : public RegistrarTest
{
public:

  static void SetUpTestCase()
  {
    RegistrarTest::SetUpTestCase();
    _hss_connection_observer = new MockHSSConnection();
    _observed_hss_connection = new FakeHSSConnection(_hss_connection_observer);
  }

  static void TearDownTestCase()
  {
    RegistrarTest::TearDownTestCase();
    delete _observed_hss_connection; _observed_hss_connection = NULL;
    delete _hss_connection_observer; _hss_connection_observer = NULL;
  }

  RegistrarObservedHssTest() : RegistrarTest(_observed_hss_connection)
  {
  }

  virtual FakeHSSConnection* hss_connection()
  {
    return _observed_hss_connection;
  }

  void TearDown()
  {
    RegistrarTest::TearDown();
    ::testing::Mock::VerifyAndClear(_hss_connection_observer);
  }

protected:
  static MockHSSConnection* _hss_connection_observer;
  static FakeHSSConnection* _observed_hss_connection;

private:

  /// Common test of multiple REGISTERs followed by "fetch bindings" query
  /// REGISTERS and deregistrations
  void MultipleRegistrationTest()
  {
    // First registration OK.
    Message msg;
    HSSConnection::irs_query irs_query;

    EXPECT_CALL(*_hss_connection_observer, update_registration_state(_, _, _))
      .WillOnce(DoAll(SaveArg<0>(&irs_query),
                      Return(HTTP_OK)));

    hss_connection()->set_impu_result_with_prev("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, RegDataXMLUtils::STATE_NOT_REGISTERED, "");

    inject_msg(msg.get());
    ASSERT_EQ(1, txdata_count());
    pjsip_msg* out = current_txdata()->msg;

    ASSERT_EQ(irs_query._public_id, "sip:6505550231@homedomain");
    //TODO:ASSERT_EQ(irs_query._req_type, HSSConnection::REG);

    EXPECT_EQ(200, out->line.status.code);
    EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
    EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
    free_txdata();

    // Second registration also OK.  Bindings are ordered by binding ID.
    Message msg0;
    msg = msg0;
    msg._contact = "sip:eeeebbbbaaaa11119c661a7acf228ed7@10.114.61.111:5061;transport=tcp;ob";
    msg._contact_instance = ";+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-a55444444440>\"";
    msg._path = "Path: <sip:XxxxxxxXXXXXXAW4z38AABcUwStNKgAAa3WOL+1v72nFJg==@ec2-107-22-156-119.compute-1.amazonaws.com:5060;lr;ob>";

    EXPECT_CALL(*_hss_connection_observer, update_registration_state(_, _, _))
      .WillOnce(Return(HTTP_OK));

    hss_connection()->set_impu_result_with_prev("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, RegDataXMLUtils::STATE_REGISTERED, "");

    inject_msg(msg.get());
    ASSERT_EQ(1, txdata_count());
    out = current_txdata()->msg;
    EXPECT_EQ(200, out->line.status.code);
    EXPECT_EQ("OK", str_pj(out->line.status.reason));
    EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
    // Expires timer for first contact may have ticked down, so give it some leeway.
    EXPECT_THAT(get_headers(out, "Contact"),
                MatchesRegex("Contact: <sip:eeeebbbbaaaa11119c661a7acf228ed7@10.114.61.111:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-a55444444440>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-a55444444440\"\r\n"
                             "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\""));
    EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
    EXPECT_EQ(msg._path, get_headers(out, "Path"));
    EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
    EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
    // Creating a new binding for an existing URI is counted as a re-registration,
    // not an initial registration.
    EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts);
    EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes);
    free_txdata();

    // Reregistration of first binding is OK but doesn't add a new one.
    msg0._unique += 1;
    msg = msg0;
    EXPECT_CALL(*_hss_connection_observer, update_registration_state(_, _, _))
      .WillOnce(Return(HTTP_OK));

    hss_connection()->set_impu_result_with_prev("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, RegDataXMLUtils::STATE_REGISTERED, "");

    inject_msg(msg.get());
    ASSERT_EQ(1, txdata_count());
    out = current_txdata()->msg;
    EXPECT_EQ(200, out->line.status.code);
    EXPECT_EQ("OK", str_pj(out->line.status.reason));
    EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
    EXPECT_THAT(get_headers(out, "Contact"),
                MatchesRegex("Contact: <sip:eeeebbbbaaaa11119c661a7acf228ed7@10.114.61.111:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-a55444444440>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-a55444444440\"\r\n"
                             "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\""));
    EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
    EXPECT_EQ(msg._path, get_headers(out, "Path"));
    EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
    EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
    EXPECT_EQ(2,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts);
    EXPECT_EQ(2,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes);
    free_txdata();

    // Registering the first binding again but without the binding ID counts as a separate binding (named by the contact itself).  Bindings are ordered by binding ID.
    msg0._unique += 1;
    msg = msg0;
    msg._contact_instance = "";
    EXPECT_CALL(*_hss_connection_observer, update_registration_state(_, _, _))
      .WillOnce(Return(HTTP_OK));

    hss_connection()->set_impu_result_with_prev("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, RegDataXMLUtils::STATE_REGISTERED, "");

    inject_msg(msg.get());
    ASSERT_EQ(1, txdata_count());
    out = current_txdata()->msg;
    EXPECT_EQ(200, out->line.status.code);
    EXPECT_EQ("OK", str_pj(out->line.status.reason));
    EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
    EXPECT_THAT(get_headers(out, "Contact"),
                MatchesRegex("Contact: <sip:eeeebbbbaaaa11119c661a7acf228ed7@10.114.61.111:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-a55444444440>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-a55444444440\"\r\n"
                             "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"\r\n"
                             "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;reg-id=1"));

    EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
    EXPECT_EQ(msg._path, get_headers(out, "Path"));
    EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
    EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
    EXPECT_EQ(3,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts);
    EXPECT_EQ(3,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes);
    free_txdata();

    // Reregistering that yields no change.
    msg._unique += 1;
    EXPECT_CALL(*_hss_connection_observer, update_registration_state(_, _, _))
      .WillOnce(Return(HTTP_OK));

    hss_connection()->set_impu_result_with_prev("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, RegDataXMLUtils::STATE_REGISTERED, "");

    inject_msg(msg.get());
    ASSERT_EQ(1, txdata_count());
    out = current_txdata()->msg;
    EXPECT_EQ(200, out->line.status.code);
    EXPECT_EQ("OK", str_pj(out->line.status.reason));
    EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
    EXPECT_THAT(get_headers(out, "Contact"),
                MatchesRegex("Contact: <sip:eeeebbbbaaaa11119c661a7acf228ed7@10.114.61.111:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-a55444444440>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-a55444444440\"\r\n"
                             "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"\r\n"
                             "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;reg-id=1"));
    EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
    EXPECT_EQ(msg._path, get_headers(out, "Path"));
    EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
    EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
    EXPECT_EQ(4,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts);
    EXPECT_EQ(4,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes);
    free_txdata();

    // A fetch bindings registration (no Contact headers).  Should just return current state.
    string save_contact = msg._contact;
    msg._unique += 1;
    msg._contact = "";
    EXPECT_CALL(*_hss_connection_observer, update_registration_state(_, _, _))
      .WillOnce(Return(HTTP_OK));

    hss_connection()->set_impu_result_with_prev("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, RegDataXMLUtils::STATE_REGISTERED, "");

    inject_msg(msg.get());
    ASSERT_EQ(1, txdata_count());
    out = current_txdata()->msg;
    EXPECT_EQ(200, out->line.status.code);
    EXPECT_EQ("OK", str_pj(out->line.status.reason));
    EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
    EXPECT_THAT(get_headers(out, "Contact"),
                MatchesRegex("Contact: <sip:eeeebbbbaaaa11119c661a7acf228ed7@10.114.61.111:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-a55444444440>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-a55444444440\"\r\n"
                             "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"\r\n"
                             "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;reg-id=1"));
    EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
    EXPECT_EQ(msg._path, get_headers(out, "Path"));
    EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
    EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
    EXPECT_EQ(4,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts);
    EXPECT_EQ(4,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes);
    free_txdata();
    msg._contact = save_contact;

    // Reregistering again with an updated cseq triggers an update of the binding.
    msg._unique += 1;
    msg._cseq = "16568";
    EXPECT_CALL(*_hss_connection_observer, update_registration_state(_, _, _))
      .WillOnce(Return(HTTP_OK));

    hss_connection()->set_impu_result_with_prev("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, RegDataXMLUtils::STATE_REGISTERED, "");

    inject_msg(msg.get());
    ASSERT_EQ(1, txdata_count());
    out = current_txdata()->msg;
    EXPECT_EQ(200, out->line.status.code);
    EXPECT_EQ("OK", str_pj(out->line.status.reason));
    EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
    EXPECT_THAT(get_headers(out, "Contact"),
                MatchesRegex("Contact: <sip:eeeebbbbaaaa11119c661a7acf228ed7@10.114.61.111:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-a55444444440>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-a55444444440\"\r\n"
                             "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"\r\n"
                             "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;reg-id=1"));
    EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
    EXPECT_EQ(msg._path, get_headers(out, "Path"));
    EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
    EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
    EXPECT_EQ(5,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts);
    EXPECT_EQ(5,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes);
    free_txdata();

    // Registration of star but with a non zero expiry means the request is rejected with a 400.
    msg0._unique += 4;
    msg = msg0;
    msg._contact = "*";
    msg._contact_instance = "";
    msg._contact_params = "";

    EXPECT_CALL(*_hss_connection_observer, update_registration_state(_, _, _))
      .WillOnce(Return(HTTP_OK));
    hss_connection()->set_impu_result_with_prev("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, RegDataXMLUtils::STATE_REGISTERED, "");

    inject_msg(msg.get());
    ASSERT_EQ(1, txdata_count());
    out = current_txdata()->msg;
    EXPECT_EQ(400, out->line.status.code);
    EXPECT_EQ("Bad Request", str_pj(out->line.status.reason));
    EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts);
    EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_failures);
    free_txdata();

    // Registration of star with expiry = 0 clears all bindings.
    msg0._unique += 1;
    msg = msg0;
    msg._expires = "Expires: 0";
    msg._contact = "*";
    msg._contact_instance = "";
    msg._contact_params = "";
    EXPECT_CALL(*_hss_connection_observer, update_registration_state(_, _, _))
      .WillOnce(Return(HTTP_OK))
      .WillOnce(DoAll(SaveArg<0>(&irs_query),
                      Return(HTTP_OK)));

    hss_connection()->set_impu_result_with_prev("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, RegDataXMLUtils::STATE_REGISTERED, "");
    hss_connection()->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, "");

    inject_msg(msg.get());
    ASSERT_EQ(1, txdata_count());
    ASSERT_EQ(irs_query._req_type, HSSConnection::DEREG_USER);
    out = current_txdata()->msg;
    EXPECT_EQ(200, out->line.status.code);
    EXPECT_EQ("OK", str_pj(out->line.status.reason));
    EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
    EXPECT_EQ("", get_headers(out, "Contact"));
    EXPECT_EQ("", get_headers(out, "Require")); // even though we have path, we have no bindings
    EXPECT_EQ(msg._path, get_headers(out, "Path"));
    EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
    EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
    EXPECT_EQ(2,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts);
    EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_successes);

    free_txdata();
  }
};

/// SDM that doesn't return any bindings
class SDMNoBindings : public SubscriberDataManager
{
public:
  SDMNoBindings(AoRStore* aor_store,
                ChronosConnection* chronos_connection,
                bool is_primary) :
    SubscriberDataManager(aor_store, chronos_connection, NULL, is_primary)
  {
  }

  AoRPair* get_aor_data(const std::string& aor_id,
                        SAS::TrailId trail)
  {
    // Call the real get_data function, but delete any bindings from the AoRPair
    // returned (if any)
    AoRPair* aor_pair = SubscriberDataManager::get_aor_data(aor_id, trail);

    if ((aor_pair != NULL) && aor_pair->current_contains_bindings())
    {
      aor_pair->get_current()->clear_bindings();
    }
    return aor_pair;
  }
};


/// Fixture for RegistrarTestRemoteSDM (for REGISTER tests that use the remote
/// store by artificially causing the local SDM and first remote SDM lookups to
/// return nothing)
class RegistrarTestRemoteSDM : public RegistrarObservedHssTest
{
public:
  // Similar to RegistrarTest, but we deliberately give it a dummy local sdm
  // and first remote sdm that never return bindings.
  static void SetUpTestCase()
  {
    RegistrarObservedHssTest::SetUpTestCase();

    _remote_data_store_no_bindings = new LocalStore();
    _remote_aor_store_no_bindings = new AstaireAoRStore(_remote_data_store_no_bindings);
    _remote_sdm_no_bindings = new SDMNoBindings((AoRStore*)_remote_aor_store_no_bindings, _chronos_connection, false);
    _remote_sdms = {_remote_sdm_no_bindings, _remote_sdm};

    if (_sdm)
    {
      delete _sdm;
      _sdm = NULL;
    }

    _sdm = new SDMNoBindings((AoRStore*)_local_aor_store, _chronos_connection, true);
  }

  RegistrarTestRemoteSDM() : RegistrarObservedHssTest()
  {
    // Start from a clean slate on each test
    _remote_data_store_no_bindings->flush_all();
  }

  static void TearDownTestCase()
  {
    RegistrarObservedHssTest::TearDownTestCase();

    delete _remote_sdm_no_bindings; _remote_sdm_no_bindings = NULL;
    delete _remote_aor_store_no_bindings; _remote_aor_store_no_bindings = NULL;
    delete _remote_data_store_no_bindings; _remote_data_store_no_bindings = NULL;
  }

protected:
  static LocalStore* _remote_data_store_no_bindings;
  static AstaireAoRStore* _remote_aor_store_no_bindings;
  static SubscriberDataManager* _remote_sdm_no_bindings;
};

LocalStore* RegistrarTest::_local_data_store;
LocalStore* RegistrarTest::_remote_data_store;
LocalStore* RegistrarTestRemoteSDM::_remote_data_store_no_bindings;
AstaireAoRStore* RegistrarTest::_local_aor_store;
AstaireAoRStore* RegistrarTest::_remote_aor_store;
AstaireAoRStore* RegistrarTestRemoteSDM::_remote_aor_store_no_bindings;
SubscriberDataManager* RegistrarTest::_sdm;
SubscriberDataManager* RegistrarTest::_remote_sdm;
SubscriberDataManager* RegistrarTestRemoteSDM::_remote_sdm_no_bindings;
std::vector<SubscriberDataManager*> RegistrarTest::_remote_sdms;
IfcHandler* RegistrarTest::_ifc_handler;
ACRFactory* RegistrarTest::_acr_factory;
FakeHSSConnection* RegistrarTest::_hss_connection;
FakeHSSConnection* RegistrarObservedHssTest::_observed_hss_connection;
MockHSSConnection* RegistrarObservedHssTest::_hss_connection_observer;
FakeChronosConnection* RegistrarTest::_chronos_connection;
FIFCService* RegistrarTest::_fifc_service;

TEST_F(RegistrarTest, NotRegister)
{
  Message msg;
  msg._method = "PUBLISH";
  inject_msg(msg.get());
  registrar_sproutlet_handle_200();
}

TEST_F(RegistrarTest, NotOurs)
{
  Message msg;
  msg._domain = "not-us.example.org";
  add_host_mapping("not-us.example.org", "5.6.7.8");
  inject_msg(msg.get());
  registrar_sproutlet_handle_200();
}

TEST_F(RegistrarTest, RouteHeaderNotMatching)
{
  Message msg;
  msg._domain = "notthehomedomain";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
}

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
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_failures);
}

TEST_F(RegistrarTest, DeRegBadScheme)
{
  Message msg;
  msg._scheme = "sips";
  msg._expires = "Expires: 0";
  msg._contact = "*";
  msg._contact_instance = "";
  msg._contact_params = "";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  out = pop_txdata()->msg;
  EXPECT_EQ(404, out->line.status.code);
  EXPECT_EQ("Not Found", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_failures);
}

///----------------------------------------------------------------------------
/// Check that a bare +sip.instance keyword doesn't break contact parsing
///----------------------------------------------------------------------------
TEST_F(RegistrarTest, BadGRUU)
{
  Message msg;
  msg._contact_instance = ";+sip.instance";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

/// Simple correct example with Authorization header
TEST_F(RegistrarTest, SimpleMainlineAuthHeader)
{
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result_with_prev("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, RegDataXMLUtils::STATE_NOT_REGISTERED, "", "?private_id=Alice");

  Message msg;
  msg._expires = "Expires: 300";
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact_params = ";+sip.ice;reg-id=1";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();

  // Fetch this binding by sending in the same request with no Contact header
  msg.inc_cseq(); // This also updates the branch parameter
  _hss_connection->set_impu_result_with_prev("sip:6505550231@homedomain", "", RegDataXMLUtils::STATE_REGISTERED, RegDataXMLUtils::STATE_REGISTERED, "", "?private_id=Alice");

  msg._contact = "";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

// Check that something sensible happens if there is no route header on the request.
TEST_F(RegistrarTest, SimpleMainlineAuthHeaderNoRoute)
{
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result_with_prev("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, RegDataXMLUtils::STATE_NOT_REGISTERED, "", "?private_id=Alice");

  Message msg;
  msg._route = "";
  msg._expires = "Expires: 300";
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact_params = ";+sip.ice;reg-id=1";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();

  // Fetch this binding by sending in the same request with no Contact header
  msg.inc_cseq(); // This also updates the branch parameter
  _hss_connection->set_impu_result_with_prev("sip:6505550231@homedomain", "", RegDataXMLUtils::STATE_REGISTERED, RegDataXMLUtils::STATE_REGISTERED, "", "?private_id=Alice");

  msg._contact = "";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

/// Simple correct example with Authorization header and Tel URIs
TEST_F(RegistrarTest, SimpleMainlineAuthHeaderWithTelURI)
{
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result_with_prev("tel:6505550231", "reg", RegDataXMLUtils::STATE_REGISTERED, RegDataXMLUtils::STATE_NOT_REGISTERED, "", "?private_id=Alice");
  Message msg;
  msg._expires = "Expires: 300";
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact_params = ";+sip.ice;reg-id=1";
  msg._scheme = "tel";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <tel:6505550231>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

/// Make sure that if the route header identifies a site, that the site-specific
/// URI is preserved in the service route and the SAR.
TEST_F(RegistrarTest, SimpleMainlineAuthHeaderRemoteSite)
{
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result_with_prev("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, RegDataXMLUtils::STATE_NOT_REGISTERED, "", "?private_id=Alice");

  Message msg;
  msg._expires = "Expires: 300";
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact_params = ";+sip.ice;reg-id=1";
  msg._route = "sprout-site2.homedomain";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout-site2.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));

  // Make sure that the HTTP request sent to homestead contains the correct S-CSCF URI.
  EXPECT_TRUE(_hss_connection->url_was_requested("/impu/sip%3A6505550231%40homedomain/reg-data?private_id=Alice", "{\"reqtype\": \"reg\", \"server_name\": \"sip:scscf.sprout-site2.homedomain:5058;transport=TCP\"}"));
  free_txdata();
}

/// Simple correct example with Expires header
TEST_F(RegistrarTest, SimpleMainlineExpiresHeader)
{
  _hss_connection->set_impu_result_with_prev("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, RegDataXMLUtils::STATE_NOT_REGISTERED, "", "?private_id=Alice");

  Message msg;
  msg._expires = "Expires: 300";
  msg._contact_params = ";+sip.ice;reg-id=1";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

/// Simple correct example with Expires header - check that
/// appropriate headers are passed through
TEST_F(RegistrarTest, SimpleMainlinePassthrough)
{
  _hss_connection->set_impu_result_with_prev("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, RegDataXMLUtils::STATE_NOT_REGISTERED, "", "?private_id=Alice");
  // Set some interesting Charging Function values
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, "", "", "",
    "<ChargingAddresses>\n"
    "  <CCF priority=\"1\">token%</CCF>\n"
    "  <CCF priority=\"2\">aaa://example.host;transport=TCP</CCF>\n"
    "  <ECF priority=\"1\">\"aaa://example.host;transport=UDP\"</ECF>\n"
    "  <ECF priority=\"2\">[fd2c:de55:7690:7777::ac12:aa6]</ECF>\n"
    "  <ECF priority=\"3\">&quot;aaa://another.example.host;transport=TCP&quot;</ECF>\n"
    "</ChargingAddresses>"
  );
  Message msg;
  msg._expires = "Expires: 300";
  msg._contact_params = ";+sip.ice;reg-id=1";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("P-Charging-Vector: icid-value=\"100\"", get_headers(out, "P-Charging-Vector"));
  // Check the contents of the PCFA header.  Only the 2nd value above should be quoted, as the 1st and 4th values match
  // the required spec for a "token" or IPv6 address, and the 3rd value was already quoted.
  EXPECT_EQ("P-Charging-Function-Addresses: ccf=token%;ccf=\"aaa://example.host;transport=TCP\";ecf=\"aaa://example.host;transport=UDP\";ecf=[fd2c:de55:7690:7777::ac12:aa6];ecf=\"aaa://another.example.host;transport=TCP\"", get_headers(out, "P-Charging-Function-Addresses"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);

  free_txdata();
}


/// Simple correct example with Expires parameter
TEST_F(RegistrarTest, SimpleMainlineExpiresParameter)
{
  _hss_connection->set_impu_result_with_prev("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, RegDataXMLUtils::STATE_NOT_REGISTERED, "", "?private_id=Alice");

  Message msg;
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

/// Simple correct example with Expires parameter set to 0
TEST_F(RegistrarTest, SimpleMainlineDeregister)
{
  _hss_connection->set_impu_result_with_prev("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, RegDataXMLUtils::STATE_REGISTERED, "", "?private_id=Alice");

  Message msg;
  msg._contact_params = ";expires=0;+sip.ice;reg-id=1";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("", get_headers(out, "Contact"));  // no existing bindings
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_successes);
  free_txdata();
}

/// Simple correct example with no expiry header or parameter.
TEST_F(RegistrarTest, SimpleMainlineNoExpiresHeaderParameter)
{
  _hss_connection->set_impu_result_with_prev("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, RegDataXMLUtils::STATE_REGISTERED, "", "?private_id=Alice");
  Message msg;
  msg._contact_params = ";+sip.ice;reg-id=1";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

/// UE without support for GRUUs
TEST_F(RegistrarTest, GRUUNotSupported)
{
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result_with_prev("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, RegDataXMLUtils::STATE_REGISTERED, "", "?private_id=Alice");

  Message msg;
  msg._expires = "Expires: 300";
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact_params = ";+sip.ice;reg-id=1";
  msg._gruu_support = false;
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  // No pub-gruu as UE doesn't support GRUUs.
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1",
            get_headers(out, "Contact"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

TEST_F(RegistrarObservedHssTest, MultipleRegistrations)
{
  MultipleRegistrationTest();
}

// Check that a sensible result (no bindings) is returned on a "fetch bindings"
// REGISTER if the subscriber isn't actually registered
TEST_F(RegistrarTest, DISABLED_FetchBindingsUnregistered)
{
  Message msg;
  msg._contact = "";
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "", RegDataXMLUtils::STATE_NOT_REGISTERED, "");
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("", get_headers(out, "Contact"));
  EXPECT_EQ("", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(0,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts);
  EXPECT_EQ(0,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes);
  free_txdata();
}

TEST_F(RegistrarTest, NoPath)
{
  Message msg;
  msg._path = "";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));
  EXPECT_EQ("", get_headers(out, "Require")); // because we have no path
  EXPECT_EQ("", get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

// Generate a REGISTER flow to app servers from the iFC.
// First case - REGISTER is generated with a multipart body
TEST_F(RegistrarTest, AppServersWithMultipartBody)
{
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "    <Priority>1</Priority>\n"
                              "    <TriggerPoint>\n"
                              "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                              "    <SPT>\n"
                              "      <ConditionNegated>0</ConditionNegated>\n"
                              "      <Group>0</Group>\n"
                              "      <Method>REGISTER</Method>\n"
                              "      <Extension></Extension>\n"
                              "    </SPT>\n"
                              "  </TriggerPoint>\n"
                              "  <ApplicationServer>\n"
                              "    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                              "    <DefaultHandling>0</DefaultHandling>\n"
                              "    <ServiceInfo>banana</ServiceInfo>\n"
                              "      <Extension><IncludeRegisterRequest/><IncludeRegisterResponse/></Extension>\n"
                              "  </ApplicationServer>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  SCOPED_TRACE("REGISTER (1)");
  Message msg;
  msg._expires = "Expires: 800";
  msg._contact_params = ";+sip.ice;reg-id=1";
  SCOPED_TRACE("REGISTER (about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (injected)");
  ASSERT_EQ(2, txdata_count());

  SCOPED_TRACE("REGISTER (forwarded)");
  // INVITE passed on to AS
  SCOPED_TRACE("REGISTER (S)");
  pjsip_msg* out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  pj_str_t multipart = pj_str("multipart");
  pj_str_t mixed = pj_str("mixed");
  EXPECT_EQ(0, pj_strcmp(&multipart, &out->body->content_type.type));
  EXPECT_EQ(0, pj_strcmp(&mixed, &out->body->content_type.subtype));
  EXPECT_EQ("Contact: <sip:scscf.sprout.homedomain:5058;transport=TCP>",
            get_headers(out, "Contact"));

  tpAS.expect_target(current_txdata(), false);
  inject_msg(respond_to_current_txdata(200));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);

  SCOPED_TRACE("REGISTER (200 OK)");
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

// Generate a REGISTER flow to app servers from the iFC.
// First case - REGISTER is generated with a multipart body
TEST_F(RegistrarTest, AppServersWithMultipartBodyWithTelURI)
{
  _hss_connection->set_impu_result("tel:6505550231", "reg", RegDataXMLUtils::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>tel:6505550231</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "    <Priority>1</Priority>\n"
                              "    <TriggerPoint>\n"
                              "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                              "    <SPT>\n"
                              "      <ConditionNegated>0</ConditionNegated>\n"
                              "      <Group>0</Group>\n"
                              "      <Method>REGISTER</Method>\n"
                              "      <Extension></Extension>\n"
                              "    </SPT>\n"
                              "  </TriggerPoint>\n"
                              "  <ApplicationServer>\n"
                              "    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                              "    <DefaultHandling>0</DefaultHandling>\n"
                              "    <ServiceInfo>banana</ServiceInfo>\n"
                              "      <Extension><IncludeRegisterRequest/><IncludeRegisterResponse/></Extension>\n"
                              "  </ApplicationServer>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  SCOPED_TRACE("REGISTER (1)");
  Message msg;
  msg._expires = "Expires: 800";
  msg._contact_params = ";+sip.ice;reg-id=1";
  msg._scheme = "tel";
  SCOPED_TRACE("REGISTER (about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (injected)");
  ASSERT_EQ(2, txdata_count());
  SCOPED_TRACE("REGISTER (forwarded)");
  // INVITE passed on to AS
  SCOPED_TRACE("REGISTER (S)");
  pjsip_msg* out = current_txdata()->msg;
  // Verify that Content-Type headers are inserted into multipart message parts
  ReqMatcher r1("REGISTER", "", ".*--\\S+\r\nContent-Type: message/sip\r\n\r\n.*");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  r1.body_regex_matches(out);
  pj_str_t multipart = pj_str("multipart");
  pj_str_t mixed = pj_str("mixed");
  EXPECT_EQ(0, pj_strcmp(&multipart, &out->body->content_type.type));
  EXPECT_EQ(0, pj_strcmp(&mixed, &out->body->content_type.subtype));

  tpAS.expect_target(current_txdata(), false);
  inject_msg(respond_to_current_txdata(200));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);

  SCOPED_TRACE("REGISTER (200 OK)");
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <tel:6505550231>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

/// Second case - REGISTER is generated with a non-multipart body
TEST_F(RegistrarTest, AppServersWithOneBody)
{
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "    <Priority>1</Priority>\n"
                              "    <TriggerPoint>\n"
                              "      <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                              "      <SPT>\n"
                              "        <ConditionNegated>0</ConditionNegated>\n"
                              "        <Group>0</Group>\n"
                              "        <Method>REGISTER</Method>\n"
                              "        <Extension></Extension>\n"
                              "      </SPT>\n"
                              "    </TriggerPoint>\n"
                              "    <ApplicationServer>\n"
                              "      <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                              "      <DefaultHandling>0</DefaultHandling>\n"
                              "      <Extension><IncludeRegisterRequest/></Extension>\n"
                              "    </ApplicationServer>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  SCOPED_TRACE("REGISTER (1)");
  Message msg;
  msg._expires = "Expires: 800";
  msg._contact_params = ";+sip.ice;reg-id=1";
  SCOPED_TRACE("REGISTER (about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (injected)");
  ASSERT_EQ(2, txdata_count());
  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER passed on to AS
  pjsip_msg* out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  pj_str_t message = pj_str("message");
  pj_str_t sip = pj_str("sip");
  EXPECT_EQ(0, pj_strcmp(&message, &out->body->content_type.type));
  EXPECT_EQ(0, pj_strcmp(&sip, &out->body->content_type.subtype));

  tpAS.expect_target(current_txdata(), false);
  inject_msg(respond_to_current_txdata(200));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);

  SCOPED_TRACE("REGISTER (200 OK)");
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

/// Third case - REGISTER is generated with no body
TEST_F(RegistrarTest, AppServersWithNoBody)
{
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "    <Priority>1</Priority>\n"
                              "    <TriggerPoint>\n"
                              "      <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                              "      <SPT>\n"
                              "        <ConditionNegated>0</ConditionNegated>\n"
                              "        <Group>0</Group>\n"
                              "        <Method>REGISTER</Method>\n"
                              "        <Extension></Extension>\n"
                              "      </SPT>\n"
                              "    </TriggerPoint>\n"
                              "    <ApplicationServer>\n"
                              "      <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                              "      <DefaultHandling>0</DefaultHandling>\n"
                              "    </ApplicationServer>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  SCOPED_TRACE("REGISTER (1)");
  Message msg;
  msg._expires = "Expires: 800";
  msg._contact_params = ";+sip.ice;reg-id=1";
  SCOPED_TRACE("REGISTER (about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (injected)");
  ASSERT_EQ(2, txdata_count());
  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER passed on to AS
  pjsip_msg* out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  EXPECT_EQ(NULL, out->body);

  tpAS.expect_target(current_txdata(), false);
  inject_msg(respond_to_current_txdata(200));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);

  SCOPED_TRACE("REGISTER (200 OK)");
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

/// Verify that third-party REGISTERs have appropriate headers passed through
TEST_F(RegistrarTest, AppServersPassthrough)
{
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "    <Priority>1</Priority>\n"
                              "    <TriggerPoint>\n"
                              "      <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                              "      <SPT>\n"
                              "        <ConditionNegated>0</ConditionNegated>\n"
                              "        <Group>0</Group>\n"
                              "        <Method>REGISTER</Method>\n"
                              "        <Extension></Extension>\n"
                              "      </SPT>\n"
                              "    </TriggerPoint>\n"
                              "    <ApplicationServer>\n"
                              "      <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                              "      <DefaultHandling>0</DefaultHandling>\n"
                              "    </ApplicationServer>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>",
                              "",
                              "",
                              // Set some more sample Charging Function names to exercise quoting logic
                              "<ChargingAddresses>\n"
                              "  <CCF priority=\"1\">4.3.2.1</CCF>\n"
                              "  <CCF priority=\"2\">\\\"\\</CCF>\n"
                              "  <ECF priority=\"1\">quote=this</CCF>\n"
                              "  <ECF priority=\"2\">quote;this;as;well</CCF>\n"
                              "</ChargingAddresses>"
                          );

  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  SCOPED_TRACE("REGISTER (1)");
  Message msg;
  msg._expires = "Expires: 800";
  msg._contact_params = ";+sip.ice;reg-id=1";
  SCOPED_TRACE("REGISTER (about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (injected)");
  ASSERT_EQ(2, txdata_count());
  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER passed on to AS
  pjsip_msg* out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  // Test the headers we expect to have passed through
  EXPECT_EQ("P-Charging-Vector: icid-value=\"100\"", get_headers(out, "P-Charging-Vector"));
  // Check quoting.  Note that IP addresses don't need to be quoted in the PCFA.
  EXPECT_EQ("P-Charging-Function-Addresses: ccf=4.3.2.1;ccf=\"\\\\\\\"\\\\\";ecf=\"quote=this\";ecf=\"quote;this;as;well\"", get_headers(out, "P-Charging-Function-Addresses"));

  tpAS.expect_target(current_txdata(), false);
  inject_msg(respond_to_current_txdata(200));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);

  SCOPED_TRACE("REGISTER (200 OK)");
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

/// Verify that third-party REGISTERs have appropriate headers passed through
/// when the first IMPU is barred.
TEST_F(RegistrarTest, AppServersBarredIMPU)
{
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity><BarringIndication>1</BarringIndication></PublicIdentity>\n"
                              "  <PublicIdentity><Identity>sip:6505550232@homedomain</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "    <Priority>1</Priority>\n"
                              "    <TriggerPoint>\n"
                              "      <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                              "      <SPT>\n"
                              "        <ConditionNegated>0</ConditionNegated>\n"
                              "        <Group>0</Group>\n"
                              "        <Method>REGISTER</Method>\n"
                              "        <Extension></Extension>\n"
                              "      </SPT>\n"
                              "    </TriggerPoint>\n"
                              "    <ApplicationServer>\n"
                              "      <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                              "      <DefaultHandling>0</DefaultHandling>\n"
                              "    </ApplicationServer>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  SCOPED_TRACE("REGISTER (1)");
  Message msg;
  msg._expires = "Expires: 800";
  msg._contact_params = ";+sip.ice;reg-id=1";
  SCOPED_TRACE("REGISTER (about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (injected)");
  ASSERT_EQ(2, txdata_count());
  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER passed on to AS
  pjsip_msg* out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  // Test the To header identifies the fisrt unbarred IMPU.
  EXPECT_EQ("To: <sip:6505550232@homedomain>", get_headers(out, "To"));

  tpAS.expect_target(current_txdata(), false);
  inject_msg(respond_to_current_txdata(200));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);

  // Test that the pub gruu identifies the first unbarred IMPU.
  SCOPED_TRACE("REGISTER (200 OK)");
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550232@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

/// Check that the network-initiated deregistration code works as expected
TEST_F(RegistrarTest, DeregisterAppServersWithNoBody)
{
  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  std::string user = "sip:6505550231@homedomain";
  register_uri(_sdm, _hss_connection, "6505550231", "homedomain", "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213", 30);

  _hss_connection->set_impu_result("sip:6505550231@homedomain", "dereg-admin", RegDataXMLUtils::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "    <Priority>1</Priority>\n"
                              "    <TriggerPoint>\n"
                              "      <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                              "      <SPT>\n"
                              "        <ConditionNegated>0</ConditionNegated>\n"
                              "        <Group>0</Group>\n"
                              "        <Method>REGISTER</Method>\n"
                              "        <Extension></Extension>\n"
                              "      </SPT>\n"
                              "    </TriggerPoint>\n"
                              "    <ApplicationServer>\n"
                              "      <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                              "      <DefaultHandling>1</DefaultHandling>\n"
                              "    </ApplicationServer>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>");

  AoRPair* aor_data;
  aor_data = _sdm->get_aor_data(user, 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(1u, aor_data->get_current()->_bindings.size());
  delete aor_data; aor_data = NULL;

  RegistrationUtils::remove_bindings(_sdm,
                                     _remote_sdms,
                                     _hss_connection,
                                     NULL,
                                     IFCConfiguration(false, false, "", NULL, NULL),
                                     user,
                                     "*",
                                     HSSConnection::DEREG_ADMIN,
                                     SubscriberDataManager::EventTrigger::ADMIN,
                                     0);

  SCOPED_TRACE("deREGISTER");
  // Check that we send a REGISTER to the AS on network-initiated deregistration
  ASSERT_TRUE(current_txdata() != NULL);
  pjsip_msg* out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  EXPECT_EQ(NULL, out->body);

  tpAS.expect_target(current_txdata(), false);
  inject_msg(respond_to_current_txdata(200));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.de_reg_tbl)->_successes);

  free_txdata();
  // Check that we deleted the binding
  aor_data = _sdm->get_aor_data(user, 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(0u, aor_data->get_current()->_bindings.size());
  delete aor_data; aor_data = NULL;
}

TEST_F(RegistrarTest, AppServersInitialRegistration)
{
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED,
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                                "  <InitialFilterCriteria>\n"
                                "    <Priority>1</Priority>\n"
                                "    <TriggerPoint>\n"
                                "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                                "    <SPT>\n"
                                "      <ConditionNegated>0</ConditionNegated>\n"
                                "      <Group>0</Group>\n"
                                "      <Method>REGISTER</Method>\n"
                                "      <Extension><RegistrationType>0</RegistrationType></Extension>\n"
                                "    </SPT>\n"
                                "  </TriggerPoint>\n"
                                "  <ApplicationServer>\n"
                                "    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                                "    <DefaultHandling>0</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile></IMSSubscription>");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  SCOPED_TRACE("REGISTER (1)");
  Message msg;
  msg._expires = "Expires: 800";
  msg._contact_params = ";+sip.ice;reg-id=1";
  SCOPED_TRACE("REGISTER (about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (injected)");
  ASSERT_EQ(2, txdata_count());
  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER passed on to AS
  pjsip_msg* out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  EXPECT_EQ(NULL, out->body);

  tpAS.expect_target(current_txdata(), false);
  inject_msg(respond_to_current_txdata(200));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);


  SCOPED_TRACE("REGISTER (200 OK)");
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
  ASSERT_EQ(0, txdata_count());

  SCOPED_TRACE("REGISTER (reregister)");
  msg._unique += 1;
  SCOPED_TRACE("REGISTER (reregister, about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (reregister, injected)");
  ASSERT_EQ(1, txdata_count());
  SCOPED_TRACE("REGISTER (200 OK)");
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes);
  free_txdata();

  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER not passed on to AS
  ASSERT_EQ(0, txdata_count());
}

TEST_F(RegistrarTest, AppServersInitialRegistrationFailure)
{
  std::string user = "sip:6505550231@homedomain";
  std::string xml =            ("<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                                "  <InitialFilterCriteria>\n"
                                "    <Priority>1</Priority>\n"
                                "    <TriggerPoint>\n"
                                "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                                "    <SPT>\n"
                                "      <ConditionNegated>0</ConditionNegated>\n"
                                "      <Group>0</Group>\n"
                                "      <Method>REGISTER</Method>\n"
                                "    </SPT>\n"
                                "  </TriggerPoint>\n"
                                "  <ApplicationServer>\n"
                                "    <ServerName>sip:app-server:56789;transport=UDP</ServerName>\n"
                                "    <DefaultHandling>1</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile></IMSSubscription>");

  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, xml);

  // We add two identical IP addresses so that we hit the retry behaviour,
  // but we don't have to worry about which IP address is selected first.
  add_host_mapping("app-server", "1.2.3.4, 1.2.3.4");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  SCOPED_TRACE("REGISTER (1)");
  Message msg;
  msg._expires = "Expires: 800";
  msg._contact_params = ";+sip.ice;reg-id=1";
  SCOPED_TRACE("REGISTER (about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (injected)");
  ASSERT_EQ(2, txdata_count());

  // Check that we create a binding
  AoRPair* aor_data;
  aor_data = _sdm->get_aor_data(user, 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(1u, aor_data->get_current()->_bindings.size());
  delete aor_data; aor_data = NULL;

  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER passed on to AS
  pjsip_msg* out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  EXPECT_EQ(NULL, out->body);

  tpAS.expect_target(current_txdata(), false);
  // Respond with a 500 - this should trigger a deregistration since
  // DEFAULT_HANDLING is 1
  inject_msg(respond_to_current_txdata(500));

  SCOPED_TRACE("REGISTER (200 OK)");
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();

  tpAS.expect_target(current_txdata(), false);
  // Respond with a 500 - this should trigger a deregistration since
  // DEFAULT_HANDLING is 1
  inject_msg(respond_to_current_txdata(500));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_failures);

  // Check that we deleted the binding
  aor_data = _sdm->get_aor_data(user, 0);
  ASSERT_TRUE(aor_data != NULL);
  ASSERT_EQ(0u, aor_data->get_current()->_bindings.size());
  delete aor_data; aor_data = NULL;

  SCOPED_TRACE("deREGISTER");
  // Check that we send a deREGISTER to the AS on network-initiated deregistration
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  EXPECT_EQ(NULL, out->body);

  tpAS.expect_target(current_txdata(), false);
  inject_msg(respond_to_current_txdata(200));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.de_reg_tbl)->_successes);
}

TEST_F(RegistrarTest, AppServersDeRegistrationFailure)
{
  std::string user = "sip:6505550231@homedomain";
  std::string xml =            ("<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                                "  <InitialFilterCriteria>\n"
                                "    <Priority>1</Priority>\n"
                                "    <TriggerPoint>\n"
                                "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                                "    <SPT>\n"
                                "      <ConditionNegated>0</ConditionNegated>\n"
                                "      <Group>0</Group>\n"
                                "      <Method>REGISTER</Method>\n"
                                "    </SPT>\n"
                                "  </TriggerPoint>\n"
                                "  <ApplicationServer>\n"
                                "    <ServerName>sip:app-server:56789;transport=UDP</ServerName>\n"
                                "    <DefaultHandling>0</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile></IMSSubscription>");

  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, xml);

  // We add two identical IP addresses so that we hit the retry behaviour,
  // but we don't have to worry about which IP address is selected first.
  add_host_mapping("app-server", "1.2.3.4, 1.2.3.4");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  SCOPED_TRACE("REGISTER (1)");
  Message msg;
  msg._expires = "Expires: 0";
  msg._contact = "*";
  msg._contact_instance = "";
  msg._contact_params = "";
  SCOPED_TRACE("REGISTER (about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (injected)");
  ASSERT_EQ(2, txdata_count());

  // Check that we create a binding
  AoRPair* aor_data;
  aor_data = _sdm->get_aor_data(user, 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(0u, aor_data->get_current()->_bindings.size());
  delete aor_data; aor_data = NULL;


  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER passed on to AS
  pjsip_msg* out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  EXPECT_EQ(NULL, out->body);

  tpAS.expect_target(current_txdata(), false);
  // Respond with a 500 - this should trigger a deregistration since
  // DEFAULT_HANDLING is 1
  inject_msg(respond_to_current_txdata(500));

  SCOPED_TRACE("REGISTER (200 OK)");
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_successes);
  free_txdata();

  tpAS.expect_target(current_txdata(), false);
  // Respond with a 500 - this should trigger a deregistration since
  // DEFAULT_HANDLING is 1
  inject_msg(respond_to_current_txdata(500));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.de_reg_tbl)->_failures);

  // Check that we deleted the binding
  aor_data = _sdm->get_aor_data(user, 0);
  ASSERT_TRUE(aor_data != NULL);
  ASSERT_EQ(0u, aor_data->get_current()->_bindings.size());
  delete aor_data; aor_data = NULL;
}

TEST_F(RegistrarTest, AppServersReRegistrationFailure)
{
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED,
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                                "  <InitialFilterCriteria>\n"
                                "    <Priority>1</Priority>\n"
                                "    <TriggerPoint>\n"
                                "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                                "    <SPT>\n"
                                "      <ConditionNegated>0</ConditionNegated>\n"
                                "      <Group>0</Group>\n"
                                "      <Method>REGISTER</Method>\n"
                                "      <Extension><RegistrationType>1</RegistrationType></Extension>\n"
                                "    </SPT>\n"
                                "  </TriggerPoint>\n"
                                "  <ApplicationServer>\n"
                                "    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                                "    <DefaultHandling>1</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile></IMSSubscription>");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  SCOPED_TRACE("REGISTER (1)");
  Message msg;
  msg._expires = "Expires: 800";
  msg._contact_params = ";+sip.ice;reg-id=1";
  SCOPED_TRACE("REGISTER (about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (injected)");
  ASSERT_EQ(1, txdata_count());
  SCOPED_TRACE("REGISTER (200 OK)");
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();

  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER not passed on to AS
  ASSERT_EQ(0, txdata_count());

  SCOPED_TRACE("REGISTER (reregister)");
  msg._unique += 1;
  SCOPED_TRACE("REGISTER (reregister, about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (reregister, injected)");
  ASSERT_EQ(2, txdata_count());
  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER passed on to AS
  out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  EXPECT_EQ(NULL, out->body);

  tpAS.expect_target(current_txdata(), false);
  inject_msg(respond_to_current_txdata(500));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.re_reg_tbl)->_failures);

  SCOPED_TRACE("REGISTER (200 OK)");
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes);
  free_txdata();
}

TEST_F(RegistrarTest, AppServersReRegistration)
{
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED,
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                                "  <InitialFilterCriteria>\n"
                                "    <Priority>1</Priority>\n"
                                "    <TriggerPoint>\n"
                                "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                                "    <SPT>\n"
                                "      <ConditionNegated>0</ConditionNegated>\n"
                                "      <Group>0</Group>\n"
                                "      <Method>REGISTER</Method>\n"
                                "      <Extension><RegistrationType>1</RegistrationType></Extension>\n"
                                "    </SPT>\n"
                                "  </TriggerPoint>\n"
                                "  <ApplicationServer>\n"
                                "    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                                "    <DefaultHandling>0</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile></IMSSubscription>");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  SCOPED_TRACE("REGISTER (1)");
  Message msg;
  msg._expires = "Expires: 800";
  msg._contact_params = ";+sip.ice;reg-id=1";
  SCOPED_TRACE("REGISTER (about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (injected)");
  ASSERT_EQ(1, txdata_count());
  SCOPED_TRACE("REGISTER (200 OK)");
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();

  SCOPED_TRACE("REGISTER (forwarded)");
  ASSERT_EQ(0, txdata_count());

  SCOPED_TRACE("REGISTER (reregister)");
  msg._unique += 1;
  SCOPED_TRACE("REGISTER (reregister, about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (reregister, injected)");
  ASSERT_EQ(2, txdata_count());
  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER passed on to AS
  out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  EXPECT_EQ(NULL, out->body);

  tpAS.expect_target(current_txdata(), false);
  inject_msg(respond_to_current_txdata(200));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes);

  SCOPED_TRACE("REGISTER (200 OK)");
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes);
  free_txdata();
}


/// Homestead fails associated URI request
TEST_F(RegistrarTest, AssociatedUrisNotFound)
{
  Message msg;
  msg._user = "6505550232";
  msg._expires = "Expires: 0";
  msg._contact = "*";
  msg._contact_instance = "";
  msg._contact_params = "";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(403, out->line.status.code);
  EXPECT_EQ("Forbidden", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_failures);
}

// Test that application servers that match the dummy application server don't
// get forwarded registrations
TEST_F(RegistrarTest, AppServersInitialRegistrationDummyAppServer)
{
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED,
                                   "<IMSSubscription><ServiceProfile>\n"
                                   "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                                   "  <InitialFilterCriteria>\n"
                                   "    <Priority>1</Priority>\n"
                                   "    <TriggerPoint>\n"
                                   "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                                   "    <SPT>\n"
                                   "      <ConditionNegated>0</ConditionNegated>\n"
                                   "      <Group>0</Group>\n"
                                   "      <Method>REGISTER</Method>\n"
                                   "      <Extension><RegistrationType>0</RegistrationType></Extension>\n"
                                   "    </SPT>\n"
                                   "  </TriggerPoint>\n"
                                   "  <ApplicationServer>\n"
                                   "    <ServerName>sip:dummyas</ServerName>\n"
                                   "    <DefaultHandling>0</DefaultHandling>\n"
                                   "  </ApplicationServer>\n"
                                   "  </InitialFilterCriteria>\n"
                                   "</ServiceProfile></IMSSubscription>");

  Message msg;
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

// Test that fallback iFCs are applied if there are no matching standard iFCs
// and fallback iFCs are enabled.
TEST_F(RegistrarTest, FallbackiFCs)
{
  _registrar_sproutlet->_ifc_configuration._apply_fallback_ifcs = true;
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED,
                                   "<IMSSubscription><ServiceProfile>\n"
                                   "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                                   "</ServiceProfile></IMSSubscription>");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  SCOPED_TRACE("REGISTER (1)");
  Message msg;
  msg._expires = "Expires: 800";
  msg._contact_params = ";+sip.ice;reg-id=1";
  SCOPED_TRACE("REGISTER (about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (injected)");
  ASSERT_EQ(2, txdata_count());
  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER passed on to AS
  pjsip_msg* out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  EXPECT_EQ(NULL, out->body);

  tpAS.expect_target(current_txdata(), false);
  inject_msg(respond_to_current_txdata(200));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);

  SCOPED_TRACE("REGISTER (200 OK)");
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

// Test that fallback iFCs aren't applied if there are no matching standard iFCs
// but fallback iFCs aren't enabled.
TEST_F(RegistrarTest, FallbackiFCsNotEnabled)
{
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED,
                                   "<IMSSubscription><ServiceProfile>\n"
                                   "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                                   "</ServiceProfile></IMSSubscription>");

  Message msg;
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

// Test that fallback iFCs aren't applied if they match a dummy AS
TEST_F(RegistrarTest, FallbackiFCsDummyAS)
{
  _registrar_sproutlet->_ifc_configuration._apply_fallback_ifcs = true;
  _registrar_sproutlet->_ifc_configuration._dummy_as = "sip:1.2.3.4:56789;transport=UDP";
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED,
                                   "<IMSSubscription><ServiceProfile>\n"
                                   "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                                   "</ServiceProfile></IMSSubscription>");

  Message msg;
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

// Test that fallback iFCs aren't applied if they don't match
TEST_F(RegistrarTest, FallbackiFCsNoMatching)
{
  _registrar_sproutlet->_ifc_configuration._apply_fallback_ifcs = true;
  _hss_connection->set_impu_result("sip:6505551111@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED,
                                   "<IMSSubscription><ServiceProfile>\n"
                                   "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                                   "</ServiceProfile></IMSSubscription>");

  Message msg;
  msg._user = "6505551111";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

// Test that fallback iFCs aren't applied if they match a dummy AS, but that
// we don't then tear down the registration
TEST_F(RegistrarTest, FallbackiFCsMatchingDummyReject)
{
  _registrar_sproutlet->_ifc_configuration._apply_fallback_ifcs = true;
  _registrar_sproutlet->_ifc_configuration._dummy_as = "sip:1.2.3.4:56789;transport=UDP";
  _registrar_sproutlet->_ifc_configuration._reject_if_no_matching_ifcs = true;

  _hss_connection->set_impu_result("sip:6505551111@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED,
                                   "<IMSSubscription><ServiceProfile>\n"
                                   "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                                   "</ServiceProfile></IMSSubscription>");

  Message msg;
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

// Test that if there are no matching fallback iFCs we tear down the registration
TEST_F(RegistrarTest, FallbackiFCsNoMatchingReject)
{
  _registrar_sproutlet->_ifc_configuration._apply_fallback_ifcs = true;
  _registrar_sproutlet->_ifc_configuration._reject_if_no_matching_ifcs = true;
  _hss_connection->set_impu_result("sip:6505551111@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED,
                                   "<IMSSubscription><ServiceProfile>\n"
                                   "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                                   "</ServiceProfile></IMSSubscription>");

  Message msg;
  msg._user = "6505551111";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

// Test that if there are no matching iFCs and we're not using fallback iFCs we tear down the registration
TEST_F(RegistrarTest, iFCsNoMatchingReject)
{
  _registrar_sproutlet->_ifc_configuration._reject_if_no_matching_ifcs = true;
  _hss_connection->set_impu_result("sip:6505551111@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED,
                                   "<IMSSubscription><ServiceProfile>\n"
                                   "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                                   "</ServiceProfile></IMSSubscription>");

  Message msg;
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

/// Homestead fails associated URI request
TEST_F(RegistrarTest, DeRegAssociatedUrisNotFound)
{
  Message msg;
  msg._user = "6505550232";
  msg._expires = "Expires: 0";
  msg._contact = "*";
  msg._contact_instance = "";
  msg._contact_params = "";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(403, out->line.status.code);
  EXPECT_EQ("Forbidden", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_failures);
}

/// Homestead fails to interpret URI request
TEST_F(RegistrarTest, AssociatedUriFails)
{
  Message msg;
  msg._user = "6505550232";
  _hss_connection->set_rc("/impu/sip%3A6505550232%40homedomain/reg-data",
                          500);

  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(500, out->line.status.code);
  EXPECT_EQ("Internal Server Error", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_failures);

  _hss_connection->delete_rc("/impu/sip%3A6505550232%40homedomain/reg-data");
}

/// Homestead times out associated URI request
TEST_F(RegistrarTest, AssociatedUrisTimeOut)
{
  Message msg;
  msg._user = "6505550232";
  _hss_connection->set_rc("/impu/sip%3A6505550232%40homedomain/reg-data",
                          503);

  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(504, out->line.status.code);
  EXPECT_EQ("Server Timeout", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_failures);

  _hss_connection->delete_rc("/impu/sip%3A6505550232%40homedomain/reg-data");
}

/// Homestead fails associated URI request with unexpected failure
TEST_F(RegistrarTest, AssociatedUrisUnexpectedFailure)
{
  Message msg;
  msg._user = "6505550232";

  // We don't expected to get Not Implemented back from Homstead
  _hss_connection->set_rc("/impu/sip%3A6505550232%40homedomain/reg-data",
                          501);

  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(504, out->line.status.code);
  EXPECT_EQ("Server Timeout", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_failures);

  _hss_connection->delete_rc("/impu/sip%3A6505550232%40homedomain/reg-data");
}

/// Multiple P-Associated-URIs
TEST_F(RegistrarTest, MultipleAssociatedUris)
{
  Message msg;
  msg._user = "6505550233";

  _hss_connection->set_impu_result("sip:6505550233@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550233@homedomain</Identity></PublicIdentity>\n"
                              "  <PublicIdentity><Identity>sip:6505550234@homedomain</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>");

  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);

  EXPECT_EQ("P-Associated-URI: <sip:6505550233@homedomain>\r\n"
            "P-Associated-URI: <sip:6505550234@homedomain>",
            get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

/// Multiple P-Associated-URIs with Tel URIs
TEST_F(RegistrarTest, MultipleAssociatedUrisWithTelURI)
{
  Message msg;
  msg._user = "6505550233";
  msg._scheme = "tel";

  // Add a bad tel URI (the one with the domain) to the set of Identities.  This
  // should be ignored in the constructions of the P-Associated-URI headers.
  _hss_connection->set_impu_result("tel:6505550233", "reg", RegDataXMLUtils::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>tel:6505550233</Identity></PublicIdentity>\n"
                              "  <PublicIdentity><Identity>tel:6505550234</Identity></PublicIdentity>\n"
                              "  <PublicIdentity><Identity>tel:6505550235@baddomain.com</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>");

  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);

  EXPECT_EQ("P-Associated-URI: <tel:6505550233>\r\n"
            "P-Associated-URI: <tel:6505550234>",
            get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

/// Register with non-primary P-Associated-URI
TEST_F(RegistrarTest, NonPrimaryAssociatedUri)
{
  Message msg;
  msg._user = "6505550234";

  _hss_connection->set_impu_result("sip:6505550234@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550233@homedomain</Identity></PublicIdentity>\n"
                              "  <PublicIdentity><Identity>sip:6505550234@homedomain</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>");

  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("P-Associated-URI: <sip:6505550233@homedomain>\r\n"
            "P-Associated-URI: <sip:6505550234@homedomain>",
            get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();

  // Check that we registered the correct URI (0233, not 0234).
  AoRPair* aor_data = _sdm->get_aor_data("sip:6505550233@homedomain", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(1u, aor_data->get_current()->_bindings.size());
  delete aor_data; aor_data = NULL;
  aor_data = _sdm->get_aor_data("sip:6505550234@homedomain", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(0u, aor_data->get_current()->_bindings.size());
  delete aor_data; aor_data = NULL;
}

/// Register with an IMPU that has wildcarded identities in its IRS - check that
/// they don't get included in the P-Associated-URI headers.
TEST_F(RegistrarTest, AssociatedURIWithWildcardedIdentity)
{
  Message msg;
  msg._user = "6505550234";

  _hss_connection->set_impu_result("sip:6505550234@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED,
                                   "<IMSSubscription><ServiceProfile>\n"
                                   "  <PublicIdentity><Identity>sip:6505550234@homedomain</Identity></PublicIdentity>\n"
                                   "  <PublicIdentity><Identity>sip:650555023!.*!@homedomain</Identity></PublicIdentity>\n"
                                   "  <InitialFilterCriteria>\n"
                                   "  </InitialFilterCriteria>\n"
                                   "</ServiceProfile></IMSSubscription>");

  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  // There should only be the one Associated-URI
  EXPECT_EQ("P-Associated-URI: <sip:6505550234@homedomain>",
            get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

/// Test for issue 356
TEST_F(RegistrarTest, AppServersWithNoExtension)
{
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "    <Priority>1</Priority>\n"
                              "    <TriggerPoint>\n"
                              "      <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                              "      <SPT>\n"
                              "        <ConditionNegated>0</ConditionNegated>\n"
                              "        <Group>0</Group>\n"
                              "        <Method>REGISTER</Method>\n"
                              "      </SPT>\n"
                              "    </TriggerPoint>\n"
                              "    <ApplicationServer>\n"
                              "      <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                              "      <DefaultHandling>0</DefaultHandling>\n"
                              "    </ApplicationServer>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  SCOPED_TRACE("REGISTER (1)");
  Message msg;
  msg._expires = "Expires: 800";
  msg._contact_params = ";+sip.ice;reg-id=1";
  SCOPED_TRACE("REGISTER (about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (injected)");
  ASSERT_EQ(2, txdata_count());
  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER passed on to AS
  pjsip_msg* out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  EXPECT_EQ(NULL, out->body);

  tpAS.expect_target(current_txdata(), false);
  inject_msg(respond_to_current_txdata(200));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);

  SCOPED_TRACE("REGISTER (200 OK)");
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

/// Test for issue 358 - iFCs match on SDP but REGISTER doesn't have any - should be no match
TEST_F(RegistrarTest, AppServersWithSDPiFCs)
{
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "    <Priority>2</Priority>\n"
                              "    <TriggerPoint>\n"
                              "      <ConditionTypeCNF>1</ConditionTypeCNF>\n"
                              "      <SPT>\n"
                              "        <Group>1</Group>\n"
                              "        <SessionDescription>\n"
                              "          <Line>m</Line>\n"
                              "          <Content>audio</Content>\n"
                              "        </SessionDescription>\n"
                              "      </SPT>\n"
                              "    </TriggerPoint>\n"
                              "    <ApplicationServer>\n"
                              "      <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                              "      <DefaultHandling>0</DefaultHandling>\n"
                              "    </ApplicationServer>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>");

  SCOPED_TRACE("REGISTER (1)");
  Message msg;
  msg._expires = "Expires: 800";
  msg._contact_params = ";+sip.ice;reg-id=1";
  SCOPED_TRACE("REGISTER (about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (injected)");
  ASSERT_EQ(1, txdata_count());
  SCOPED_TRACE("REGISTER (200 OK)");
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

// Test that an emergency registration is successful, and creates an emergency binding
TEST_F(RegistrarTest, MainlineEmergencyRegistration)
{
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, "", "?private_id=Alice");

  // Make a emergency registration
  Message msg;
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact = "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob";
  inject_msg(msg.get());

  // Check the 200 OK
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();

  // There should be one binding, and it is an emergency registration. The emergency binding should have 'sos' prepended to its key.
  AoRPair* aor_data = _sdm->get_aor_data("sip:6505550231@homedomain", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(1u, aor_data->get_current()->_bindings.size());
  EXPECT_TRUE(aor_data->get_current()->get_binding(std::string("sos<urn:uuid:00000000-0000-0000-0000-b665231f1213>:1"))->_emergency_registration);
  delete aor_data; aor_data = NULL;
}

// Test that an emergency registration is successful, and creates an emergency binding, with Tel URIs
TEST_F(RegistrarTest, MainlineEmergencyRegistrationWithTelURI)
{
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result("tel:6505550231", "reg", RegDataXMLUtils::STATE_REGISTERED, "", "?private_id=Alice");

  // Make a emergency registration
  Message msg;
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact = "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob";
  msg._scheme = "tel";
  inject_msg(msg.get());

  // Check the 200 OK
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1",
            get_headers(out, "Contact"));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <tel:6505550231>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();

  // There should be one binding, and it is an emergency registration. The emergency binding should have 'sos' prepended to its key.
  AoRPair* aor_data = _sdm->get_aor_data("tel:6505550231", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(1u, aor_data->get_current()->_bindings.size());
  EXPECT_TRUE(aor_data->get_current()->get_binding(std::string("sos<urn:uuid:00000000-0000-0000-0000-b665231f1213>:1"))->_emergency_registration);
  delete aor_data; aor_data = NULL;
}

// Test that an emergency registration is successful, and creates an emergency binding.
// The Contact header doesn't include a +sip_instance, so the binding id is the contact URI containing 'sos'
TEST_F(RegistrarTest, MainlineEmergencyRegistrationNoSipInstance)
{
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, "", "?private_id=Alice");

  // Make a emergency registration
  Message msg;
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact = "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob";
  msg._contact_instance = "";
  inject_msg(msg.get());

  // Check the 200 OK
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob>;expires=300;+sip.ice;reg-id=1",
            get_headers(out, "Contact"));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();

  // There should be one binding, and it is an emergency registration
  AoRPair* aor_data = _sdm->get_aor_data("sip:6505550231@homedomain", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(1u, aor_data->get_current()->_bindings.size());
  EXPECT_TRUE(aor_data->get_current()->get_binding(std::string("sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob"))->_emergency_registration);
  delete aor_data; aor_data = NULL;
}


// Test that an emergency registration can't be deregistered
TEST_F(RegistrarTest, EmergencyDeregistration)
{
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, "", "?private_id=Alice");

  // Make a emergency registration
  Message msg;
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact = "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob";
  inject_msg(msg.get());

  // Check the 200 OK
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_THAT(get_headers(out, "Contact"),
              MatchesRegex("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\""));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();

  // There should be one binding, and it is an emergency registration. The emergency binding should have 'sos' prepended to its key.
  AoRPair* aor_data = _sdm->get_aor_data("sip:6505550231@homedomain", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(1u, aor_data->get_current()->_bindings.size());
  EXPECT_TRUE(aor_data->get_current()->get_binding(std::string("sos<urn:uuid:00000000-0000-0000-0000-b665231f1213>:1"))->_emergency_registration);
  delete aor_data; aor_data = NULL;

  // Attempt to deregister a single emergency binding
  msg._contact = "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob";
  msg._unique += 1;
  msg._cseq = "16568";
  msg._contact_params = ";expires=0;+sip.ice;reg-id=1";
  inject_msg(msg.get());

  // This should be rejected with a 501
  out = current_txdata()->msg;
  EXPECT_EQ(501, out->line.status.code);
  EXPECT_EQ("Not Implemented", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_failures);
  free_txdata();

  // Attempt to reduce the expiry time of an emergency binding.
  msg._expires = "Expires: 100";
  msg._unique += 1;
  msg._cseq = "16569";
  msg._contact = "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob";
  msg._contact_params = ";expires=100;+sip.ice;reg-id=1";
  inject_msg(msg.get());

  // Emergency binding isn't changed
  out = current_txdata()->msg;
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_THAT(get_headers(out, "Contact"),
              MatchesRegex("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\""));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes);
  free_txdata();
}

// Test multiple emergency and standard registrations.
TEST_F(RegistrarTest, MultipleEmergencyRegistrations)
{
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, "", "?private_id=Alice");

  // Make a standard registration
  Message msg;
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  inject_msg(msg.get());

  // Check the 200 OK
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_THAT(get_headers(out, "Contact"),
              MatchesRegex("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\""));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();

  // There should be one binding, and it isn't an emergency registration
  AoRPair* aor_data = _sdm->get_aor_data("sip:6505550231@homedomain", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(1u, aor_data->get_current()->_bindings.size());
  EXPECT_FALSE(aor_data->get_current()->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b665231f1213>:1"))->_emergency_registration);
  delete aor_data; aor_data = NULL;

  // Make an emergency registration
  msg._contact = "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob";
  msg._unique += 1;
  inject_msg(msg.get());

  // Check the 200 OK - the contact header should contain the sos URI parameter
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_THAT(get_headers(out, "Contact"),
              MatchesRegex("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"\r\n"
                           "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\""));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes);
  free_txdata();

  // There should be two bindings. The emergency binding should have 'sos' prepended to its key.
  aor_data = _sdm->get_aor_data("sip:6505550231@homedomain", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(2u, aor_data->get_current()->_bindings.size());
  EXPECT_TRUE(aor_data->get_current()->get_binding(std::string("sos<urn:uuid:00000000-0000-0000-0000-b665231f1213>:1"))->_emergency_registration);
  delete aor_data; aor_data = NULL;

  // Make an emergency registration
  msg._contact = "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob";
  msg._contact_instance = "";
  msg._unique += 1;
  inject_msg(msg.get());

  // Check the 200 OK - the contact header should contain the sos URI parameter
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_THAT(get_headers(out, "Contact"),
              MatchesRegex("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"\r\n"
                           "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]);\\+sip.ice;reg-id=1\r\n"
                           "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\""));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(2,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts);
  EXPECT_EQ(2,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes);
  free_txdata();

  // There should be three bindings.
  aor_data = _sdm->get_aor_data("sip:6505550231@homedomain", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(3u, aor_data->get_current()->_bindings.size());
  EXPECT_TRUE(aor_data->get_current()->get_binding(std::string("sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob"))->_emergency_registration);
  delete aor_data; aor_data = NULL;

  // Attempt to deregister all bindings
  msg._expires = "Expires: 0";
  msg._contact = "*";
  msg._contact_instance = "";
  msg._contact_params = "";
  msg._unique += 1;
  inject_msg(msg.get());

  // Check the 200 OK. The emergency bindings shouldn't have been deregistered, but the standard one has
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_THAT(get_headers(out, "Contact"),
              MatchesRegex("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]);\\+sip.ice;reg-id=1\r\n"
                           "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\""));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_successes);
  free_txdata();

  // There should be two emergency bindings
  aor_data = _sdm->get_aor_data("sip:6505550231@homedomain", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(2u, aor_data->get_current()->_bindings.size());
  EXPECT_TRUE(aor_data->get_current()->get_binding(std::string("sos<urn:uuid:00000000-0000-0000-0000-b665231f1213>:1"))->_emergency_registration);
  EXPECT_TRUE(aor_data->get_current()->get_binding(std::string("sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob"))->_emergency_registration);
  delete aor_data; aor_data = NULL;

  // Wait 5 mins and the emergency bindings should have expired
  cwtest_advance_time_ms(300100);
  aor_data = _sdm->get_aor_data("sip:6505550231@homedomain", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(0u, aor_data->get_current()->_bindings.size());
  delete aor_data; aor_data = NULL;
}

/// Simple correct example with rinstance parameter in Contact URI
TEST_F(RegistrarTest, RinstanceParameter)
{
  Message msg;
  msg._contact = "sip:6505550138@172.18.42.27:46826;transport=tcp;rinstance=7690e89fc4105d1e";
  msg._contact_instance = "";
  msg._contact_params = ";Expires=390";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:6505550138@172.18.42.27:46826;transport=tcp;rinstance=7690e89fc4105d1e>;expires=300",
            get_headers(out, "Contact"));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();
}

// Make registers with a subscription and check the correct NOTIFYs
// are sent
TEST_F(RegistrarTest, RegistrationWithSubscription)
{
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, "", "?private_id=Alice");
  std::string aor = "sip:6505550231@homedomain";
  std::string aor_brackets = "<" + aor + ">";
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result(aor, "reg", RegDataXMLUtils::STATE_REGISTERED, "", "?private_id=Alice");

  // Register a binding
  Message msg;
  msg._contact_params = ";+sip.ice;reg-id=1";
  msg._expires = "Expires: 200";
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  free_txdata();

  // Now add a subscription to the store
  AoRPair* aor_pair = _sdm->get_aor_data(aor, 0);
  AssociatedURIs associated_uris = {};
  aor_pair->get_current()->_associated_uris = associated_uris;
  AoR::Subscription* s1 = aor_pair->get_current()->get_subscription("1234");
  s1->_req_uri = std::string("sip:6505550231@192.91.191.29:59934;transport=tcp");
  s1->_from_uri = aor_brackets;
  s1->_from_tag = std::string("4321");
  s1->_to_uri = aor_brackets;
  s1->_to_tag = std::string("1234");
  s1->_cid = std::string("xyzabc@192.91.191.29");
  s1->_route_uris.push_back(std::string("sip:abcdefgh@bono1.homedomain;lr"));
  int now = time(NULL);
  s1->_expires = now + 300;

  aor_pair->get_current()->_associated_uris.add_uri(aor, false);
  pj_status_t rc = _sdm->set_aor_data(aor, SubscriberDataManager::EventTrigger::USER, aor_pair, 0);
  EXPECT_TRUE(rc);
  delete aor_pair; aor_pair = NULL;

  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  EXPECT_EQ("NOTIFY", str_pj(out->line.status.reason));

  check_notify(out, aor, "active", std::make_pair("active", "registered"));
  inject_msg(respond_to_current_txdata(200));
  free_txdata();

  // Extend the registration
  msg._expires = "Expires: 300";
  msg._cseq = "16568";
  msg._unique += 1;
  inject_msg(msg.get());
  ASSERT_EQ(2, txdata_count());
  out = pop_txdata()->msg;
  EXPECT_EQ("NOTIFY", str_pj(out->line.status.reason));
  check_notify(out, aor, "active", std::make_pair("active", "refreshed"));
  inject_msg(respond_to_current_txdata(200));
  free_txdata();

  // Shorten the registration
  msg._expires = "Expires: 200";
  msg._cseq = "16569";
  msg._unique += 1;
  inject_msg(msg.get());
  ASSERT_EQ(2, txdata_count());
  out = pop_txdata()->msg;
  EXPECT_EQ("NOTIFY", str_pj(out->line.status.reason));
  check_notify(out, aor, "active", std::make_pair("active", "shortened"));
  inject_msg(respond_to_current_txdata(200));
  free_txdata();

  // Change the Contact URI on the registration
  msg._contact = "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.214:5061;transport=tcp;ob";
  msg._cseq = "16570";
  msg._unique += 1;
  inject_msg(msg.get());
  ASSERT_EQ(2, txdata_count());
  out = pop_txdata()->msg;
  EXPECT_EQ("NOTIFY", str_pj(out->line.status.reason));
  check_notify(out, aor, "active", std::make_pair("terminated", "deactivated"));
  check_notify(out, aor, "active", std::make_pair("active", "created"), 1);
  inject_msg(respond_to_current_txdata(200));
  free_txdata();

  // Delete the registration
  msg._expires = "Expires: 0";
  msg._cseq = "16571";
  msg._unique += 1;
  inject_msg(msg.get());
  ASSERT_EQ(2, txdata_count());
  out = pop_txdata()->msg;
  EXPECT_EQ("NOTIFY", str_pj(out->line.status.reason));
  check_notify(out, aor, "terminated", std::make_pair("terminated", "unregistered"));
  inject_msg(respond_to_current_txdata(200));
  free_txdata();
}


// Make registers with a subscription and check the correct NOTIFYs
// are sent. Specifically, check that a NOTIFY is not sent to a UE to tell it that it no longer
// exists.
TEST_F(RegistrarTest, NoNotifyToUnregisteredUser)
{
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, "", "?private_id=Alice");
  std::string aor = "sip:6505550231@homedomain";
  std::string aor_brackets = "<" + aor + ">";
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result(aor, "reg", RegDataXMLUtils::STATE_REGISTERED, "", "?private_id=Alice");

  // Register a binding
  Message msg;
  msg._contact_params = ";+sip.ice;reg-id=1";
  msg._expires = "Expires: 200";
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  free_txdata();

  // Now add a subscription to the store
  AoRPair* aor_pair = _sdm->get_aor_data(aor, 0);
  AssociatedURIs associated_uris = {};
  aor_pair->get_current()->_associated_uris = associated_uris;
  AoR::Subscription* s1 = aor_pair->get_current()->get_subscription("1234");
  s1->_req_uri = msg._contact;
  s1->_from_uri = aor_brackets;
  s1->_from_tag = std::string("4321");
  s1->_to_uri = aor_brackets;
  s1->_to_tag = std::string("1234");
  s1->_cid = std::string("xyzabc@192.91.191.29");
  s1->_route_uris.push_back(std::string("sip:abcdefgh@bono1.homedomain;lr"));
  int now = time(NULL);
  s1->_expires = now + 300;

  aor_pair->get_current()->_associated_uris.add_uri(aor, false);
  pj_status_t rc = _sdm->set_aor_data(aor, SubscriberDataManager::EventTrigger::USER, aor_pair, 0);
  EXPECT_TRUE(rc);
  delete aor_pair; aor_pair = NULL;

  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  EXPECT_EQ("NOTIFY", str_pj(out->line.status.reason));

  check_notify(out, aor, "active", std::make_pair("active", "registered"));
  inject_msg(respond_to_current_txdata(200));
  free_txdata();

  // Delete the registration. We shouldn't get a NOTIFY - it's coming over the unregistered binding.
  msg._expires = "Expires: 0";
  msg._cseq = "16570";
  msg._unique += 1;
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  free_txdata();
}

TEST_F(RegistrarTest, MultipleRegistrationsWithSubscription)
{
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, "", "?private_id=Alice");
  std::string aor = "sip:6505550231@homedomain";
  std::string aor_brackets = "<" + aor + ">";
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result(aor, "reg", RegDataXMLUtils::STATE_REGISTERED, "", "?private_id=Alice");

  // Register a binding
  Message msg;
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  free_txdata();

  // Now add a subscription to the store
  AoRPair* aor_pair = _sdm->get_aor_data(aor, 0);
  AssociatedURIs associated_uris = {};
  aor_pair->get_current()->_associated_uris = associated_uris;
  AoR::Subscription* s1 = aor_pair->get_current()->get_subscription("1234");
  s1->_req_uri = std::string("sip:6505550231@192.91.191.29:59934;transport=tcp");
  s1->_from_uri = aor_brackets;
  s1->_from_tag = std::string("4321");
  s1->_to_uri = aor_brackets;
  s1->_to_tag = std::string("1234");
  s1->_cid = std::string("xyzabc@192.91.191.29");
  s1->_route_uris.push_back(std::string("sip:abcdefgh@bono1.homedomain;lr"));
  int now = time(NULL);
  s1->_expires = now + 300;

  aor_pair->get_current()->_associated_uris.add_uri(aor, false);
  pj_status_t rc = _sdm->set_aor_data(aor, SubscriberDataManager::EventTrigger::USER, aor_pair, 0);
  EXPECT_TRUE(rc);
  delete aor_pair; aor_pair = NULL;
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  EXPECT_EQ("NOTIFY", str_pj(out->line.status.reason));
  check_notify(out, aor, "active", std::make_pair("active", "registered"));
  inject_msg(respond_to_current_txdata(200));
  free_txdata();

  // Register a second binding.
  msg._contact = "sip:eeeebbbbaaaa11119c661a7acf228ed7@10.114.61.111:5061;transport=tcp;ob";
  msg._contact_instance = ";+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-a55444444440>\"";
  msg._path = "Path: <sip:XxxxxxxXXXXXXAW4z38AABcUwStNKgAAa3WOL+1v72nFJg==@ec2-107-22-156-119.compute-1.amazonaws.com:5060;lr;ob>";
  msg._unique += 1;
  inject_msg(msg.get());
  ASSERT_EQ(2, txdata_count());
  out = pop_txdata()->msg;
  EXPECT_EQ("NOTIFY", str_pj(out->line.status.reason));
  check_notify(out, aor, "active", std::make_pair("active", "created"));
  inject_msg(respond_to_current_txdata(200));
  free_txdata();

  // Expire the second binding
  msg._contact_params = ";expires=0;+sip.ice;reg-id=1";
  msg._cseq = "16570";
  msg._unique += 1;
  inject_msg(msg.get());
  ASSERT_EQ(2, txdata_count());
  out = pop_txdata()->msg;
  EXPECT_EQ("NOTIFY", str_pj(out->line.status.reason));
  check_notify(out, aor, "active", std::make_pair("terminated", "unregistered"));
  inject_msg(respond_to_current_txdata(200));
  free_txdata();
}

/// Sends in a REGISTER with a Path header that contains a display name and
/// some parameters. Chck that we store the full path header on the binding.
TEST_F(RegistrarTest, StoreFullPathHeader)
{
  // Send in a REGISTER.
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, "", "?private_id=Alice");

  Message msg;
  msg._expires = "Expires: 300";
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact_params = ";+sip.ice;reg-id=1";
  msg._path = "Path: \"Bob\" <sip:GgAAAAAAAACYyAW4z38AABcUwStNKgAAa3WOL+1v72nFJg==@ec2-107-22-156-220.compute-1.amazonaws.com:5060;lr;ob>;tag=7hf8";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  free_txdata();

  // Get the binding.
  AoRPair* aor_data;
  aor_data = _sdm->get_aor_data("sip:6505550231@homedomain", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(1u, aor_data->get_current()->_bindings.size());
  AoR::Binding* binding = aor_data->get_current()->bindings().begin()->second;

  // Chck that the path header fields are filled in correctly.
  EXPECT_EQ(1u, binding->_path_headers.size());
  EXPECT_EQ(std::string("\"Bob\" <sip:GgAAAAAAAACYyAW4z38AABcUwStNKgAAa3WOL+1v72nFJg==@ec2-107-22-156-220.compute-1.amazonaws.com:5060;lr;ob>;tag=7hf8"), binding->_path_headers.front());
  EXPECT_EQ(1u, binding->_path_uris.size());
  EXPECT_EQ(std::string("sip:GgAAAAAAAACYyAW4z38AABcUwStNKgAAa3WOL+1v72nFJg==@ec2-107-22-156-220.compute-1.amazonaws.com:5060;lr;ob"), binding->_path_uris.front());

  delete aor_data;
}

// Test that an emergency registration is successful, and creates an emergency binding,
// even if all IMPUs in the IRS are barred.
TEST_F(RegistrarTest, BarredEmergencyRegistration)
{
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED,
                                   "<IMSSubscription><ServiceProfile>\n"
                                   "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity><BarringIndication>1</BarringIndicaton></PublicIdentity>"
                                   "  <InitialFilterCriteria>\n"
                                   "  </InitialFilterCriteria>\n"
                                   "</ServiceProfile></IMSSubscription>",
                                   "?private_id=Alice");

  // Make a emergency registration
  Message msg;
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact = "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob";
  inject_msg(msg.get());

  // Check the 200 OK
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();

  // There should be one binding, and it is an emergency registration. The
  // emergency binding should have 'sos' prepended to its key.
  AoRPair* aor_data = _sdm->get_aor_data("sip:6505550231@homedomain", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(1u, aor_data->get_current()->_bindings.size());
  EXPECT_TRUE(aor_data->get_current()->get_binding(std::string("sos<urn:uuid:00000000-0000-0000-0000-b665231f1213>:1"))->_emergency_registration);
  delete aor_data; aor_data = NULL;
}

// Test that a bad URI in the HSS response is not added to the P-Associated-URI
// even for an emergency registration when all identities are barred.
TEST_F(RegistrarTest, BarredEmergencyRegistrationBadURI)
{
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result("tel:6505550231", "reg", RegDataXMLUtils::STATE_REGISTERED,
                                   "<IMSSubscription><ServiceProfile>\n"
                                   "<PublicIdentity><Identity>tel:6505550232@badhomedomain</Identity><BarringIndication>1</BarringIndicaton></PublicIdentity>"
                                   "<PublicIdentity><Identity>tel:6505550231</Identity><BarringIndication>1</BarringIndicaton></PublicIdentity>"
                                   "  <InitialFilterCriteria>\n"
                                   "  </InitialFilterCriteria>\n"
                                   "</ServiceProfile></IMSSubscription>",
                                   "?private_id=Alice");

  // Make an emergency registration
  Message msg;
  msg._scheme = "tel";
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact = "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob";
  inject_msg(msg.get());

  // Check the 200 OK
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1",
            get_headers(out, "Contact"));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));

  // We shouldn't have anything in the P-Associated-URI
  EXPECT_EQ("", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:scscf.sprout.homedomain:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);
  free_txdata();

  // There should be one binding, and it is an emergency registration. The
  // emergency binding should have 'sos' prepended to its key.
  AoRPair* aor_data = _sdm->get_aor_data("tel:6505550232@badhomedomain", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(1u, aor_data->get_current()->_bindings.size());
  EXPECT_TRUE(aor_data->get_current()->get_binding(std::string("sos<urn:uuid:00000000-0000-0000-0000-b665231f1213>:1"))->_emergency_registration);
  delete aor_data; aor_data = NULL;
}


// Test that if all IMPUs are barred, and this is not an emergency registration
// that the REGISTER will fail.
TEST_F(RegistrarTest, AllIMPUsBarred)
{
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED,
                                   "<IMSSubscription><ServiceProfile>\n"
                                   "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity><BarringIndication>1</BarringIndicaton></PublicIdentity>"
                                   "  <InitialFilterCriteria>\n"
                                   "  </InitialFilterCriteria>\n"
                                   "</ServiceProfile></IMSSubscription>",
                                   "?private_id=Alice");

  // Make a registration
  Message msg;
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact = "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob";
  inject_msg(msg.get());

  // Check the error
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(400, out->line.status.code);
}

/// Fixture for RegistrarTest.
class RegistrarTestMockStore : public SipTest
{
public:

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
    SipTest::SetScscfUri("sip:scscf.sprout.homedomain:5058;transport=TCP");
  }

  void SetUp()
  {
    _chronos_connection = new FakeChronosConnection();
    _local_data_store = new MockStore();
    _local_aor_store = new AstaireAoRStore(_local_data_store);
    _sdm = new SubscriberDataManager((AoRStore*)_local_aor_store, _chronos_connection, NULL, true);
    _hss_connection = new FakeHSSConnection();
    _acr_factory = new ACRFactory();

    _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, "");
    _hss_connection->set_impu_result("tel:6505550231", "reg", RegDataXMLUtils::STATE_REGISTERED, "");
    _hss_connection->set_rc("/impu/sip%3A6505550231%40homedomain/reg-data", HTTP_OK);
    _chronos_connection->set_result("", HTTP_OK);
    _chronos_connection->set_result("post_identity", HTTP_OK);

    IFCConfiguration ifc_configuration(false ,false, "", NULL, NULL);
    _registrar_sproutlet = new RegistrarSproutlet("registrar",
                                                  5058,
                                                  "sip:registrar.homedomain:5058;transport=tcp",
                                                  { "scscf" },
                                                  "scscf",
                                                  "subscription",
                                                  _sdm,
                                                  {},
                                                  _hss_connection,
                                                  _acr_factory,
                                                  300,
                                                  false,
                                                  &SNMP::FAKE_REGISTRATION_STATS_TABLES,
                                                  &SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES,
                                                  NULL,
                                                  ifc_configuration);

    _registrar_sproutlet->init();

    std::list<Sproutlet*> sproutlets;
    sproutlets.push_back(_registrar_sproutlet);

    std::unordered_set<std::string> additional_home_domains;
    additional_home_domains.insert("sprout.homedomain");

    _registrar_proxy = new SproutletProxy(stack_data.endpt,
                                          PJSIP_MOD_PRIORITY_UA_PROXY_LAYER,
                                          "homedomain",
                                          additional_home_domains,
                                          sproutlets,
                                          std::set<std::string>());

    _log_traffic = PrintingTestLogger::DEFAULT.isPrinting();
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
    delete _sdm; _sdm = NULL;
    delete _local_aor_store; _local_aor_store = NULL;
    delete _local_data_store; _local_data_store = NULL;
    delete _chronos_connection; _chronos_connection = NULL;
  }

  ~RegistrarTestMockStore()
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



protected:
  MockStore* _local_data_store;
  AstaireAoRStore* _local_aor_store;
  SubscriberDataManager* _sdm;
  IfcHandler* _ifc_handler;
  ACRFactory* _acr_factory;
  FakeHSSConnection* _hss_connection;
  FakeChronosConnection* _chronos_connection;
  RegistrarSproutlet* _registrar_sproutlet;
  SproutletProxy* _registrar_proxy;
};


// Check that the registrar does not infinite loop when the underlying store is
// in an odd state, specifically when it:
// -  Returns NOT_FOUND to all gets
// -  Returns ERROR to all sets.
//
// This is a repro for https://github.com/Metaswitch/sprout/issues/977
TEST_F(RegistrarTestMockStore, SubscriberDataManagerWritesFail)
{
  EXPECT_CALL(*_local_data_store, get_data(_, _, _, _, _, An<Store::Format>()))
    .WillOnce(Return(Store::NOT_FOUND));

  EXPECT_CALL(*_local_data_store, set_data(_, _, _, _, _, _, An<Store::Format>()))
    .WillOnce(Return(Store::ERROR));

  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, "", "?private_id=Alice");

  Message msg;
  msg._expires = "Expires: 300";
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact_params = ";+sip.ice;reg-id=1";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(500, out->line.status.code);
  free_txdata();
}

TEST_F(RegistrarTestMockStore, SubscriberDataManagerGetsFail)
{
  EXPECT_CALL(*_local_data_store, get_data(_, _, _, _, _, An<Store::Format>()))
    .WillOnce(Return(Store::ERROR));

  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, "", "?private_id=Alice");

  Message msg;
  msg._expires = "Expires: 300";
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact_params = ";+sip.ice;reg-id=1";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(500, out->line.status.code);
  free_txdata();
}

// Test that if Homestead tells us that the subscriber was not previously
// registered that we simply try to ADD it to the store instead of querying for
// existing records first.
TEST_F(RegistrarTestMockStore, DontReadOnInitialRegister)
{
  // Homestead returns a PreviousRegisterState indicating that this is an
  // initial register.
  _hss_connection->set_impu_result_with_prev("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, RegDataXMLUtils::STATE_NOT_REGISTERED, "", "?private_id=Alice");

  // Expect the data to be set with a CAS of 0.
  EXPECT_CALL(*_local_data_store, set_data(_, _, _, 0, _, _, An<Store::Format>()))
    .WillOnce(Return(Store::OK));

  Message msg;
  msg._expires = "Expires: 300";
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact_params = ";+sip.ice;reg-id=1";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  free_txdata();
}

// Test that if Homestead tells us that the subscriber was not previously
// registered that we simply try to ADD it to the store instead of querying for
// existing records first, but that when that ADD fails (because there actually
// was already data in the store) we fall back to querying the existing data and
// correctly updating it instead.
TEST_F(RegistrarTestMockStore, InitialRegisterAddFailure)
{
  // Homestead returns a PreviousRegisterState indicating that this is an
  // initial register.
  _hss_connection->set_impu_result_with_prev("sip:6505550231@homedomain", "reg", RegDataXMLUtils::STATE_REGISTERED, RegDataXMLUtils::STATE_NOT_REGISTERED, "", "?private_id=Alice");

  InSequence s;

  // Check that the registrar initially tries to ADD the data (set_data with cas=0). Simulate
  // this ADD failing with a DATA_CONTENTION error.
  EXPECT_CALL(*_local_data_store, set_data("reg", "sip:6505550231@homedomain", _, 0, _, _, An<Store::Format>()))
    .WillOnce(Return(Store::DATA_CONTENTION));

  // The ADD failed because there was data and so the Registrar should now try
  // to get the existing data. Return example data with a cas value of 1 that might be present if
  // there was a single binding for sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.214:5061.
  std::string expiry_time = std::to_string(time(NULL) + 300);
  std::string initial_data = (
      "{\"bindings\":{"
          "\"<urn:uuid:00000000-0000-0000-0000-777777777777>:1\":{\"uri\":\"sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.214:5061;transport=tcp;ob\",\"cid\":\"0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs1042ohntC@10.114.61.213\",\"cseq\":10000,\"expires\":" + expiry_time + ",\"priority\":0,\"params\":{\"+sip.ice\":\"\",\"+sip.instance\":\"\\\"<urn:uuid:00000000-0000-0000-0000-777777777777>\\\"\",\"reg-id\":\"1\"},\"path_headers\":[\"<sip:GgAAAAAAAACYyAW4z38AABcUwStNKgAAa3WOL+1v72nFJg==@ec2-107-22-156-220.compute-1.amazonaws.com:5060;lr;ob>\"],\"paths\":[\"sip:GgAAAAAAAACYyAW4z38AABcUwStNKgAAa3WOL+1v72nFJg==@ec2-107-22-156-220.compute-1.amazonaws.com:5060;lr;ob\"],\"private_id\":\"Alice\",\"emergency_reg\":false}"
       "},"
       "\"subscriptions\":{},"
       "\"associated-uris\":{\"uris\":[{\"uri\":\"sip:6505550231@homedomain\",\"barring\":false}],\"wildcard-mapping\":{}},\"notify_cseq\":2,\"timer_id\":\"post_identity\",\"scscf-uri\":\"sip:scscf.sprout.homedomain:5058;transport=TCP\"}");
  EXPECT_CALL(*_local_data_store, get_data("reg", "sip:6505550231@homedomain", _, _, _, An<Store::Format>()))
    .WillOnce(DoAll(SetArgReferee<2>(initial_data), // Returned data
                    SetArgReferee<3>(1), // Returned CAS value
                    Return(Store::OK)));

  // Now the registrar should try and write back updated data including both
  // the binding we returned on the get above (10.114.61.214) + the new binding
  // we've just registered (10.114.61.213). Don't bother trying to work out
  // exactly what data will be present -- just check for the 2 bindings.
  EXPECT_CALL(*_local_data_store, set_data("reg",
                                           "sip:6505550231@homedomain",
                                           AllOf(HasSubstr("10.114.61.214"),
                                                 HasSubstr("10.114.61.213")), // Updated data should contain both contacts
                                           1, // CAS Value
                                           _, _, An<Store::Format>()))
    .WillOnce(Return(Store::OK));

  Message msg;
  msg._expires = "Expires: 300";
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact_params = ";+sip.ice;reg-id=1";
  msg._contact = "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.214:5061;transport=tcp;ob";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  free_txdata();
}

// Test multiple registrations with a local and first remote SDM that are not
// returning bindings (so that the bindings are returned by the second remote
// SDM)
TEST_F(RegistrarTestRemoteSDM, MultipleRegistrations)
{
  MultipleRegistrationTest();
}
