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

class RegistrationSenderTest : public SipTest
{
public:
  RegistrationSenderTest()
  {
    IFCConfiguration ifc_configuration(false, false, "", NULL, NULL); // TODO fake snmp tables.
    _subscriber_manager = new MockSubscriberManager();
    _fifc_service = new FIFCService(NULL, string(UT_DIR).append("/test_fifc.xml")); // TODO mock this out?
    _registration_sender = new RegistrationSender(_subscriber_manager,
                                                  ifc_configuration,
                                                  NULL,
                                                  &SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES,
                                                  true);
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

  char* build_ifcs(Ifcs& ifcs);

  // Set up a base message that looks more like a register.
  class RegisterMessage : public TestingCommon::Message
  {
  public:
    RegisterMessage()
    {
      Message::_method = "REGISTER";
      Message::_to = Message::_from;
    };

    ~RegisterMessage() {};
  };
};

char* RegistrationSenderTest::build_ifcs(Ifcs& ifcs)
{
  // Create a service profile with a single iFC.
  TestingCommon::ServiceProfileBuilder sp = TestingCommon::ServiceProfileBuilder()
    .addIdentity("sip:6505551000@homedomain")
    .addIfc(1, {"<Method>REGISTER</Method>"}, "sip:1.2.3.4:56789;transport=TCP");
  std::string sp_str = sp.return_profile();

  // Convert the service profile to XML.
  std::shared_ptr<rapidxml::xml_document<>> root (new rapidxml::xml_document<>);
  char* sp_cstr = strdup(sp_str.c_str());
  root->parse<0>(sp_cstr);

  // Parse out the Ifcs struct from the XML.
  ifcs = Ifcs(root, root->first_node("ServiceProfile"), NULL, 0);

  return sp_cstr;
}

TEST_F(RegistrationSenderTest, 3rdPartyRegisterMainline)
{
  RegisterMessage msg;
  pjsip_msg* received_register = parse_msg(msg.get_request());
  pjsip_msg* sent_response = parse_msg(msg.get_response());

  Ifcs ifcs;
  char* cstr = build_ifcs(ifcs);

  _registration_sender->register_with_application_servers(received_register,
                                                          sent_response,
                                                          "sip:6505551000@homedomain",
                                                          ifcs,
                                                          300,
                                                          true,
                                                          0);

  ASSERT_EQ(1, txdata_count());
  inject_msg(respond_to_current_txdata(200));

  free(cstr);
}

TEST_F(RegistrationSenderTest, 3rdPartyDeregisterMainline)
{
  Ifcs ifcs;
  char* cstr = build_ifcs(ifcs);
  _registration_sender->deregister_with_application_servers("sip:6505551000@homedomain",
                                                            ifcs,
                                                            0);

  ASSERT_EQ(1, txdata_count());
  inject_msg(respond_to_current_txdata(200));

  free(cstr);
}
