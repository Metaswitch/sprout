/**
 * @file registration_sender_test.cpp
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "gtest/gtest.h"
#include "test_utils.hpp"
#include "siptest.hpp"
#include "test_interposer.hpp"
#include "testingcommon.h"

#include "registration_sender.h"
#include "mock_subscriber_manager.h"

using ::testing::_;

class RegistrationSenderTest : public SipTest
{
public:
  RegistrationSenderTest()
  {
    IFCConfiguration ifc_configuration(true,
                                       true,
                                       "dummy-as",
                                       &SNMP::FAKE_NO_MATCHING_IFCS_TABLE,
                                       &SNMP::FAKE_NO_MATCHING_FALLBACK_IFCS_TABLE);
    _subscriber_manager = new MockSubscriberManager();
    _fifc_service = new FIFCService(NULL, string(UT_DIR).append("/test_registrar_fifc.xml"));
    _registration_sender = new RegistrationSender(ifc_configuration,
                                                  _fifc_service,
                                                  &SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES,
                                                  true);
    _registration_sender->register_dereg_event_consumer(_subscriber_manager);
  }

  virtual ~RegistrationSenderTest()
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

    // Reset SNMP statistics.
    ((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->reset_count();
    ((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.re_reg_tbl)->reset_count();
    ((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.de_reg_tbl)->reset_count();
    SNMP::FAKE_NO_MATCHING_IFCS_TABLE.reset_count();
    SNMP::FAKE_NO_MATCHING_FALLBACK_IFCS_TABLE.reset_count();

    delete _subscriber_manager; _subscriber_manager = NULL;
    delete _fifc_service; _fifc_service = NULL;
    delete _registration_sender; _registration_sender = NULL;
  }

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

private:
  RegistrationSender* _registration_sender;
  FIFCService* _fifc_service;
  MockSubscriberManager* _subscriber_manager;

  char* build_ifcs(Ifcs& ifcs,
                   std::string as_uri = "sip:1.2.3.4:56789;transport=TCP");

  // Set up a base message that looks more like a register.
  class RegisterMessage : public TestingCommon::Message
  {
  public:
    RegisterMessage()
    {
      Message::_method = "REGISTER";
      Message::_to = Message::_from;
      Message::_extra = "P-Access-Network-Info: homedomain\r\n"
                        "P-Visited-Network-ID: homedomain\r\n"
                        "P-Charging-Vector: icid-value=100\r\n"
                        "P-Charging-Function-Addresses: ccf=cdf.homedomain";
    };

    ~RegisterMessage() {};
  };
};

char* RegistrationSenderTest::build_ifcs(Ifcs& ifcs,
                                         std::string as_uri)
{
  // Create a service profile with a single iFC.
  TestingCommon::ServiceProfileBuilder sp = TestingCommon::ServiceProfileBuilder()
    .addIdentity("sip:6505551000@homedomain")
    .addIfc(1, {"<Method>REGISTER</Method>"}, as_uri, 0, 1);
  std::string sp_str = sp.return_profile();

  // Convert the service profile to XML.
  std::shared_ptr<rapidxml::xml_document<>> root (new rapidxml::xml_document<>);
  char* sp_cstr = strdup(sp_str.c_str());
  root->parse<0>(sp_cstr);

  // Parse out the Ifcs struct from the XML.
  ifcs = Ifcs(root, root->first_node("ServiceProfile"), NULL, 0);

  return sp_cstr;
}

// Set up a single iFC and check that a 3rd party register is sent to the
// application server.
TEST_F(RegistrationSenderTest, 3rdPartyRegisterIFC)
{
  RegisterMessage msg;
  pjsip_msg* received_register = parse_msg(msg.get_request());
  pjsip_msg* sent_response = parse_msg(msg.get_response());

  Ifcs ifcs;
  char* cstr = build_ifcs(ifcs);

  bool unused_deregister_subscriber;
  _registration_sender->register_with_application_servers(received_register,
                                                          sent_response,
                                                          "sip:6505551000@homedomain",
                                                          ifcs,
                                                          300,
                                                          true,
                                                          unused_deregister_subscriber,
                                                          0);

  ASSERT_EQ(1, txdata_count());
  // TODO detailed message checking.
  inject_msg(respond_to_current_txdata(200));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes);

  free(cstr);
}

// Set up a single iFC and check that a 3rd party register is sent to the
// application server. Return an error and verify that the subscriber is
// deregistered.
TEST_F(RegistrationSenderTest, 3rdPartyRegisterIFCErrorResponse)
{
  RegisterMessage msg;
  pjsip_msg* received_register = parse_msg(msg.get_request());
  pjsip_msg* sent_response = parse_msg(msg.get_response());

  Ifcs ifcs;
  char* cstr = build_ifcs(ifcs);

  // Expect the subscriber to be dergistered.
  EXPECT_CALL(*_subscriber_manager, deregister_subscriber("sip:6505551000@homedomain",
                                                          _));

  bool unused_deregister_subscriber;
  _registration_sender->register_with_application_servers(received_register,
                                                          sent_response,
                                                          "sip:6505551000@homedomain",
                                                          ifcs,
                                                          300,
                                                          true,
                                                          unused_deregister_subscriber,
                                                          0);

  ASSERT_EQ(1, txdata_count());
  inject_msg(respond_to_current_txdata(500));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_failures);

  free(cstr);
}

// Don't set up any iFCs and check that a 3rd party register is sent to the
// fallback application server.
TEST_F(RegistrationSenderTest, 3rdPartyRegisterFallbackIFC)
{
  RegisterMessage msg;
  pjsip_msg* received_register = parse_msg(msg.get_request());
  pjsip_msg* sent_response = parse_msg(msg.get_response());

  bool unused_deregister_subscriber;
  _registration_sender->register_with_application_servers(received_register,
                                                          sent_response,
                                                          "sip:6505551000@homedomain",
                                                          {},
                                                          300,
                                                          false,
                                                          unused_deregister_subscriber,
                                                          0);

  ASSERT_EQ(1, txdata_count());
  inject_msg(respond_to_current_txdata(200));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes);
}

// Don't set up any iFCs and check that a 3rd party register is sent to the
// fallback application server. Return an error and check that the subscriber is
// deregistered.
TEST_F(RegistrationSenderTest, 3rdPartyRegisterFallbackIFCErrorResponse)
{
  RegisterMessage msg;
  pjsip_msg* received_register = parse_msg(msg.get_request());
  pjsip_msg* sent_response = parse_msg(msg.get_response());

  // Expect the subscriber to be dergistered.
  EXPECT_CALL(*_subscriber_manager, deregister_subscriber("sip:6505551000@homedomain",
                                                          _));

  bool unused_deregister_subscriber;
  _registration_sender->register_with_application_servers(received_register,
                                                          sent_response,
                                                          "sip:6505551000@homedomain",
                                                          {},
                                                          300,
                                                          false,
                                                          unused_deregister_subscriber,
                                                          0);

  ASSERT_EQ(1, txdata_count());
  inject_msg(respond_to_current_txdata(500));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.re_reg_tbl)->_failures);
}

// Set up a single iFC that matches a dummy iFC. Check that this does not result
// in a 3rd party register.
TEST_F(RegistrationSenderTest, 3rdPartyRegisterDummyIFC)
{
  RegisterMessage msg;
  pjsip_msg* received_register = parse_msg(msg.get_request());
  pjsip_msg* sent_response = parse_msg(msg.get_response());

  Ifcs ifcs;
  char* cstr = build_ifcs(ifcs, "dummy-as");

  bool unused_deregister_subscriber;
  _registration_sender->register_with_application_servers(received_register,
                                                          sent_response,
                                                          "sip:6505551000@homedomain",
                                                          ifcs,
                                                          300,
                                                          true,
                                                          unused_deregister_subscriber,
                                                          0);

  ASSERT_EQ(0, txdata_count());

  free(cstr);
}

// Match a fallback iFC that is the same as a dummy iFC. Check that this does
// not result in a 3rd party register.
TEST_F(RegistrationSenderTest, 3rdPartyRegisterDummyFIFC)
{
  RegisterMessage msg;
  msg._from = "6505551234";
  msg._to = "6505551234";
  pjsip_msg* received_register = parse_msg(msg.get_request());
  pjsip_msg* sent_response = parse_msg(msg.get_response());

  bool unused_deregister_subscriber;
  _registration_sender->register_with_application_servers(received_register,
                                                          sent_response,
                                                          "sip:6505551234@homedomain",
                                                          {},
                                                          300,
                                                          true,
                                                          unused_deregister_subscriber,
                                                          0);

  ASSERT_EQ(0, txdata_count());
}

// No iFCs are matched (noraml, fallback or dummy). We are configured to reject
// the request if no iFCs are matched so check that that information is passed
// back.
// TODO actually check this parameter.
TEST_F(RegistrationSenderTest, 3rdPartyRegisterNoIFC)
{
  RegisterMessage msg;
  msg._from = "6505559999";
  msg._to = "6505559999";
  pjsip_msg* received_register = parse_msg(msg.get_request());
  pjsip_msg* sent_response = parse_msg(msg.get_response());

  bool deregister_subscriber;
  _registration_sender->register_with_application_servers(received_register,
                                                          sent_response,
                                                          "sip:6505559999@homedomain",
                                                          {},
                                                          300,
                                                          true,
                                                          deregister_subscriber,
                                                          0);

  ASSERT_EQ(0, txdata_count());
  EXPECT_TRUE(deregister_subscriber);

  EXPECT_EQ(1,(SNMP::FAKE_NO_MATCHING_IFCS_TABLE)._count);
  EXPECT_EQ(1,(SNMP::FAKE_NO_MATCHING_FALLBACK_IFCS_TABLE)._count);
}

// Check that a 3rd party deregister is triggered.
TEST_F(RegistrationSenderTest, 3rdPartyDeregister)
{
  Ifcs ifcs;
  char* cstr = build_ifcs(ifcs);
  _registration_sender->deregister_with_application_servers("sip:6505551000@homedomain",
                                                            ifcs,
                                                            0);

  ASSERT_EQ(1, txdata_count());
  inject_msg(respond_to_current_txdata(200));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.de_reg_tbl)->_successes);

  free(cstr);
}

// Check that a 3rd party deregister is triggered.
TEST_F(RegistrationSenderTest, 3rdPartyDeregisterErrorResponse)
{
  Ifcs ifcs;
  char* cstr = build_ifcs(ifcs);

  _registration_sender->deregister_with_application_servers("sip:6505551000@homedomain",
                                                            ifcs,
                                                            0);

  ASSERT_EQ(1, txdata_count());
  inject_msg(respond_to_current_txdata(500));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.de_reg_tbl)->_failures);

  free(cstr);
}
