/**
 * @file handlers_test.cpp UT for Handlers module.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "test_utils.hpp"
#include <curl/curl.h>

#include "mockhttpstack.hpp"
#include "handlers.h"
#include "chronoshandlers.h"
#include "gtest/gtest.h"
#include "basetest.hpp"
#include "siptest.hpp"
#include "localstore.h"
#include "fakehssconnection.hpp"
#include "fakechronosconnection.hpp"
#include "test_interposer.hpp"
#include "mock_subscriber_data_manager.h"
#include "mock_impi_store.h"
#include "mock_hss_connection.h"
#include "rapidjson/document.h"
#include "handlers_test.h"

using namespace std;
using ::testing::_;
using ::testing::Return;
using ::testing::InSequence;
using ::testing::SetArgReferee;
using ::testing::SaveArg;

const std::string HSS_REG_STATE = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                                  "<ClearwaterRegData>"
                                    "<RegistrationState>REGISTERED</RegistrationState>"
                                    "<IMSSubscription>"
                                      "<ServiceProfile>"
                                        "<PublicIdentity>"
                                          "<Identity>sip:6505550001@homedomain</Identity>"
                                        "</PublicIdentity>"
                                      "</ServiceProfile>"
                                    "</IMSSubscription>"
                                  "</ClearwaterRegData>";
const std::string HSS_NOT_REG_STATE = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                                      "<ClearwaterRegData>"
                                        "<RegistrationState>NOT_REGISTERED</RegistrationState>"
                                      "</ClearwaterRegData>";

class DeregistrationTaskTest : public SipTest
{
  MockSubscriberDataManager* _subscriber_data_manager;
  MockImpiStore* _local_impi_store;
  MockImpiStore* _remote_impi_store;
  MockHttpStack* _httpstack;
  FakeHSSConnection* _hss;
  MockHttpStack::Request* _req;
  DeregistrationTask::Config* _cfg;
  DeregistrationTask* _task;

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
    SipTest::SetScscfUri("sip:all.the.sprout.nodes:5058;transport=TCP");
  }

  void SetUp()
  {
    _local_impi_store = new MockImpiStore();
    _remote_impi_store = new MockImpiStore();
    _httpstack = new MockHttpStack();
    _subscriber_data_manager = new MockSubscriberDataManager();
    _hss = new FakeHSSConnection();
  }

  void TearDown()
  {
    delete _req;
    delete _cfg;
    delete _hss;
    delete _subscriber_data_manager;
    delete _httpstack;
    delete _local_impi_store; _local_impi_store = NULL;
    delete _remote_impi_store; _remote_impi_store = NULL;
  }

  // Build the deregistration request
  void build_dereg_request(std::string body,
                           std::string notify = "true",
                           htp_method method = htp_method_DELETE)
  {
    _req = new MockHttpStack::Request(_httpstack,
         "/registrations?send-notifications=" + notify,
         "",
         "send-notifications=" + notify,
         body,
         method);
     IFCConfiguration ifc_configuration(false, false, "", NULL, NULL);
     _cfg = new DeregistrationTask::Config(_subscriber_data_manager,
                                           {},
                                           _hss,
                                           NULL,
                                           ifc_configuration,
                                           NULL,
                                          _local_impi_store,
                                          {_remote_impi_store});
    _task = new DeregistrationTask(*_req, _cfg, 0);
  }

  void expect_sdm_updates(std::vector<std::string> aor_ids,
                          std::vector<AoRPair*> aors)
  {
    for (uint32_t ii = 0; ii < aor_ids.size(); ++ii)
    {
      // Get the information from the local store
      EXPECT_CALL(*_subscriber_data_manager, get_aor_data(aor_ids[ii], _)).WillOnce(Return(aors[ii]));

      if (aors[ii] != NULL)
      {
        // Write the information to the local store
        EXPECT_CALL(*_subscriber_data_manager,
                    set_aor_data(aor_ids[ii],
                                 SubscriberDataManager::EventTrigger::ADMIN,
                                 _, _, _))
          .WillOnce(Return(Store::OK));
      }
    }
  }

  void expect_impi_deletes(std::string private_id, MockImpiStore* impi_store)
  {
    ImpiStore::Impi* impi = new ImpiStore::Impi(private_id);
    EXPECT_CALL(*impi_store, get_impi(private_id, _, false)).WillOnce(Return(impi));
    EXPECT_CALL(*impi_store, delete_impi(impi, _)).WillOnce(Return(Store::OK));
  }

  void expect_gr_impi_deletes(std::string private_id)
  {
    expect_impi_deletes(private_id, _local_impi_store);
    expect_impi_deletes(private_id, _remote_impi_store);
  }
};

// Mainline case
TEST_F(DeregistrationTaskTest, MainlineTest)
{
  // Set HSS result
  _hss->set_impu_result("sip:6505550231@homedomain", "", RegDataXMLUtils::STATE_REGISTERED,
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

  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\", \"impi\": \"6505550231\"}]}";
  build_dereg_request(body);

  // Get an initial empty AoR record and add a standard binding
  std::string aor_id = "sip:6505550231@homedomain";
  AoR* aor = new AoR(aor_id);
  int now = time(NULL);
  AoR::Binding* b1 = aor->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1"));
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
  b1->_private_id = "6505550231";

  // Set up the subscriber_data_manager expectations
  AoR* aor2 = new AoR(*aor);
  AoRPair* aor_pair = new AoRPair(aor, aor2);
  std::vector<std::string> aor_ids = {aor_id};
  std::vector<AoRPair*> aors = {aor_pair};

  expect_sdm_updates(aor_ids, aors);

  // The IMPI is also deleted from the local and remote stores.
  expect_gr_impi_deletes("6505550231");

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();

  _hss->flush_all();
}

// Test where there are multiple pairs of AoRs and Private IDs and single AoRs
TEST_F(DeregistrationTaskTest, AoRPrivateIdPairsTest)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505552001@homedomain\", \"impi\": \"6505552001\"}, {\"primary-impu\": \"sip:6505552002@homedomain\", \"impi\": \"6505552002\"}, {\"primary-impu\": \"sip:6505552003@homedomain\"}, {\"primary-impu\": \"sip:6505552004@homedomain\"}]}";
  build_dereg_request(body, "false");

  // Set up the subscriber_data_manager expectations
  std::string aor_id_1 = "sip:6505552001@homedomain";
  std::string aor_id_2 = "sip:6505552002@homedomain";
  std::string aor_id_3 = "sip:6505552003@homedomain";
  std::string aor_id_4 = "sip:6505552004@homedomain";
  AoR* aor_1 = new AoR(aor_id_1);
  AoR* aor_11 = new AoR(*aor_1);
  AoRPair* aor_pair_1 = new AoRPair(aor_1, aor_11);
  AoR* aor_2 = new AoR(aor_id_2);
  AoR* aor_22 = new AoR(*aor_2);
  AoRPair* aor_pair_2 = new AoRPair(aor_2, aor_22);
  AoR* aor_3 = new AoR(aor_id_3);
  AoR* aor_33 = new AoR(*aor_3);
  AoRPair* aor_pair_3 = new AoRPair(aor_3, aor_33);
  AoR* aor_4 = new AoR(aor_id_4);
  AoR* aor_44 = new AoR(*aor_4);
  AoRPair* aor_pair_4 = new AoRPair(aor_4, aor_44);
  std::vector<std::string> aor_ids = {aor_id_1, aor_id_2, aor_id_3, aor_id_4};
  std::vector<AoRPair*> aors = {aor_pair_1, aor_pair_2, aor_pair_3, aor_pair_4};

  expect_sdm_updates(aor_ids, aors);

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();
}

// Test when the SubscriberDataManager can't be accessed.
TEST_F(DeregistrationTaskTest, SubscriberDataManagerFailureTest)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505552001@homedomain\"}]}";
  build_dereg_request(body, "false");

  // Set up the subscriber_data_manager expectations
  std::string aor_id = "sip:6505552001@homedomain";
  AoRPair* aor_pair = NULL;
  std::vector<std::string> aor_ids = {aor_id};
  std::vector<AoRPair*> aors = {aor_pair};

  expect_sdm_updates(aor_ids, aors);

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 500, _));
  _task->run();
}

// Test that an invalid SIP URI doesn't get sent on third party registers.
TEST_F(DeregistrationTaskTest, InvalidIMPUTest)
{
  _hss->set_result("/impu/notavalidsipuri/reg-data", HSS_NOT_REG_STATE);
  CapturingTestLogger log;

  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"notavalidsipuri\"}]}";
  build_dereg_request(body, "false");

  // Set up the subscriber_data_manager expectations
  std::string aor_id = "notavalidsipuri";
  AoR* aor = new AoR(aor_id);
  AoR* aor2 = new AoR(*aor);
  AoRPair* aor_pair = new AoRPair(aor, aor2);
  std::vector<std::string> aor_ids = {aor_id};
  std::vector<AoRPair*> aors = {aor_pair};

  expect_sdm_updates(aor_ids, aors);

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();

  EXPECT_TRUE(log.contains("Unable to create third party registration"));
  _hss->flush_all();
}

// Test that a dereg request that isn't a delete gets rejected.
TEST_F(DeregistrationTaskTest, InvalidMethodTest)
{
  build_dereg_request("", "", htp_method_GET);
  EXPECT_CALL(*_httpstack, send_reply(_, 405, _));
  _task->run();
}

// Test that a dereg request that doesn't have a valid send-notifications param gets rejected.
TEST_F(DeregistrationTaskTest, InvalidParametersTest)
{
  build_dereg_request("", "nottrueorfalse");
  EXPECT_CALL(*_httpstack, send_reply(_, 400, _));
  _task->run();
}

// Test that a dereg request with invalid JSON gets rejected.
TEST_F(DeregistrationTaskTest, InvalidJSONTest)
{
  build_dereg_request("{[}");
  EXPECT_CALL(*_httpstack, send_reply(_, 400, _));
  _task->run();
}

// Test that a dereg request where the JSON is missing the registration element get rejected.
TEST_F(DeregistrationTaskTest, MissingRegistrationsJSONTest)
{
  CapturingTestLogger log;
  build_dereg_request("{\"primary-impu\": \"sip:6505552001@homedomain\", \"impi\": \"6505552001\"}");
  EXPECT_CALL(*_httpstack, send_reply(_, 400, _));
  _task->run();
  EXPECT_TRUE(log.contains("Registrations not available in JSON"));
}

// Test that a dereg request where the JSON is missing the primary impu element get rejected.
TEST_F(DeregistrationTaskTest, MissingPrimaryIMPUJSONTest)
{
  CapturingTestLogger log;
  build_dereg_request("{\"registrations\": [{\"primary-imp\": \"sip:6505552001@homedomain\", \"impi\": \"6505552001\"}]}");
  EXPECT_CALL(*_httpstack, send_reply(_, 400, _));
  _task->run();
  EXPECT_TRUE(log.contains("Invalid JSON - registration doesn't contain primary-impu"));
}

TEST_F(DeregistrationTaskTest, SubscriberDataManagerWritesFail)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\", \"impi\": \"6505550231\"}]}";
  build_dereg_request(body);

  AoR* aor = new AoR("sip:6505550231@homedomain");
  AoR* aor2 = new AoR(*aor);
  AoRPair* aor_pair = new AoRPair(aor, aor2);
  EXPECT_CALL(*_subscriber_data_manager, get_aor_data(_, _)).WillOnce(Return(aor_pair));
  EXPECT_CALL(*_subscriber_data_manager, set_aor_data(_, _, _, _, _)).WillOnce(Return(Store::ERROR));

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 500, _));
  _task->run();
}

TEST_F(DeregistrationTaskTest, ImpiNotClearedWhenBindingNotDeregistered)
{
  // Build a request that will not deregister any bindings.
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\", \"impi\": \"wrong-impi\"}]}";
  build_dereg_request(body);

  // Create an AoR with a minimal binding.
  std::string aor_id = "sip:6505550231@homedomain";
  AoR* aor = new AoR(aor_id);
  int now = time(NULL);
  AoR::Binding* b1 = aor->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1"));
  b1->_expires = now + 300;
  b1->_emergency_registration = false;
  b1->_private_id = "impi1";

  AoR* aor2 = new AoR(*aor);
  AoRPair* aor_pair = new AoRPair(aor, aor2);
  std::vector<std::string> aor_ids = {aor_id};
  std::vector<AoRPair*> aors = {aor_pair};

  expect_sdm_updates(aor_ids, aors);

  // Nothing is deleted from the IMPI store.

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();
}

TEST_F(DeregistrationTaskTest, ImpiClearedWhenBindingUnconditionallyDeregistered)
{
  // Build a request that deregisters all bindings for an IMPU regardless of
  // IMPI.
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\"}]}";
  build_dereg_request(body);

  // Create an AoR with a minimal binding.
  std::string aor_id = "sip:6505550231@homedomain";
  AoR* aor = new AoR(aor_id);
  int now = time(NULL);
  AoR::Binding* b1 = aor->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1"));
  b1->_expires = now + 300;
  b1->_emergency_registration = false;
  b1->_private_id = "impi1";

  AoR* aor2 = new AoR(*aor);
  AoRPair* aor_pair = new AoRPair(aor, aor2);
  std::vector<std::string> aor_ids = {aor_id};
  std::vector<AoRPair*> aors = {aor_pair};

  expect_sdm_updates(aor_ids, aors);

  // The corresponding IMPI is also deleted.
  expect_gr_impi_deletes("impi1");

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();
}

TEST_F(DeregistrationTaskTest, ClearMultipleImpis)
{
  // Set HSS result
  _hss->set_impu_result("sip:6505550231@homedomain", "", RegDataXMLUtils::STATE_REGISTERED,
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
  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\"}, {\"primary-impu\": \"sip:6505550232@homedomain\"}]}";
  build_dereg_request(body);

  int now = time(NULL);

  // Create an AoR with two bindings.
  std::string aor_id = "sip:6505550231@homedomain";
  AoR* aor = new AoR(aor_id);

  AoR::Binding* b1 = aor->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1"));
  b1->_expires = now + 300;
  b1->_emergency_registration = false;
  b1->_private_id = "impi1";

  AoR::Binding* b2 = aor->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:2"));
  b2->_expires = now + 300;
  b2->_emergency_registration = false;
  b2->_private_id = "impi2";

  AoR* backup_aor = new AoR(*aor);
  AoRPair* aor_pair = new AoRPair(aor, backup_aor);

  // create another AoR with one binding.
  std::string aor_id2 = "sip:6505550232@homedomain";
  AoR* aor2 = new AoR(aor_id2);

  AoR::Binding* b3 = aor2->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:3"));
  b3->_expires = now + 300;
  b3->_emergency_registration = false;
  b3->_private_id = "impi3";

  AoR* backup_aor2 = new AoR(*aor2);
  AoRPair* aor_pair2 = new AoRPair(aor2, backup_aor2);

  std::vector<std::string> aor_ids = {aor_id, aor_id2};
  std::vector<AoRPair*> aors = {aor_pair, aor_pair2};
  expect_sdm_updates(aor_ids, aors);

  // The corresponding IMPIs are also deleted.
  expect_gr_impi_deletes("impi1");
  expect_gr_impi_deletes("impi2");
  expect_gr_impi_deletes("impi3");

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();

  // Expect a 3rd-party deregister to be sent to the AS in the iFCs
  ASSERT_EQ(1, txdata_count());
  // REGISTER passed on to AS
  pjsip_msg* out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  tpAS.expect_target(current_txdata(), false);
  inject_msg(respond_to_current_txdata(200));
  free_txdata();

  _hss->flush_all();
}

TEST_F(DeregistrationTaskTest, CannotFindImpiToDelete)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\"}]}";
  build_dereg_request(body);

  // Create an AoR with a minimal binding.
  std::string aor_id = "sip:6505550231@homedomain";
  AoR* aor = new AoR(aor_id);
  int now = time(NULL);
  AoR::Binding* b1 = aor->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1"));
  b1->_expires = now + 300;
  b1->_emergency_registration = false;
  b1->_private_id = "impi1";

  AoR* aor2 = new AoR(*aor);
  AoRPair* aor_pair = new AoRPair(aor, aor2);
  std::vector<std::string> aor_ids = {aor_id};
  std::vector<AoRPair*> aors = {aor_pair};
  expect_sdm_updates(aor_ids, aors);

  // Simulate the IMPI not being found in the store. The handler does not go on
  // to try and delete the IMPI.
  ImpiStore::Impi* impi1 = NULL;
  EXPECT_CALL(*_local_impi_store, get_impi("impi1", _, false)).WillOnce(Return(impi1));
  expect_impi_deletes("impi1", _remote_impi_store);

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();
}

TEST_F(DeregistrationTaskTest, ImpiStoreFailure)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\"}]}";
  build_dereg_request(body);

  // Create an AoR with a minimal binding.
  std::string aor_id = "sip:6505550231@homedomain";
  AoR* aor = new AoR(aor_id);
  int now = time(NULL);
  AoR::Binding* b1 = aor->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1"));
  b1->_expires = now + 300;
  b1->_emergency_registration = false;
  b1->_private_id = "impi1";

  AoR* aor2 = new AoR(*aor);
  AoRPair* aor_pair = new AoRPair(aor, aor2);
  std::vector<std::string> aor_ids = {aor_id};
  std::vector<AoRPair*> aors = {aor_pair};
  expect_sdm_updates(aor_ids, aors);

  // Simulate the IMPI store failing when deleting the IMPI. The handler does
  // not retry the delete.
  ImpiStore::Impi* impi1 = new ImpiStore::Impi("impi1");
  EXPECT_CALL(*_local_impi_store, get_impi("impi1", _, false)).WillOnce(Return(impi1));
  EXPECT_CALL(*_local_impi_store, delete_impi(impi1, _)).WillOnce(Return(Store::ERROR));
  expect_impi_deletes("impi1", _remote_impi_store);

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();
}

TEST_F(DeregistrationTaskTest, ImpiStoreDataContention)
{
  // Build the request
  std::string body = "{\"registrations\": [{\"primary-impu\": \"sip:6505550231@homedomain\"}]}";
  build_dereg_request(body);

  // Create an AoR with a minimal binding.
  std::string aor_id = "sip:6505550231@homedomain";
  AoR* aor = new AoR(aor_id);
  int now = time(NULL);
  AoR::Binding* b1 = aor->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1"));
  b1->_expires = now + 300;
  b1->_emergency_registration = false;
  b1->_private_id = "impi1";

  AoR* aor2 = new AoR(*aor);
  AoRPair* aor_pair = new AoRPair(aor, aor2);
  std::vector<std::string> aor_ids = {aor_id};
  std::vector<AoRPair*> aors = {aor_pair};
  expect_sdm_updates(aor_ids, aors);

  // We need to create two IMPIs when we return one on a call to get_impi we
  // lose ownership of it.
  ImpiStore::Impi* impi1 = new ImpiStore::Impi("impi1");
  ImpiStore::Impi* impi1a = new ImpiStore::Impi("impi1");
  {
    // Simulate the IMPI store returning data contention on the first delete.
    // The handler tries again.
    InSequence s;
    EXPECT_CALL(*_local_impi_store, get_impi("impi1", _, false)).WillOnce(Return(impi1));
    EXPECT_CALL(*_local_impi_store, delete_impi(impi1, _)).WillOnce(Return(Store::DATA_CONTENTION));
    EXPECT_CALL(*_local_impi_store, get_impi("impi1", _, false)).WillOnce(Return(impi1a));
    EXPECT_CALL(*_local_impi_store, delete_impi(impi1a, _)).WillOnce(Return(Store::OK));
  }
  expect_impi_deletes("impi1", _remote_impi_store);

  // Run the task
  EXPECT_CALL(*_httpstack, send_reply(_, 200, _));
  _task->run();
}

//
// Test reading sprout's bindings.
//

class GetBindingsTest : public TestWithMockSdms
{
};

// Test getting an IMPU that does not have any bindings.
TEST_F(GetBindingsTest, NoBindings)
{
  // Build request
  MockHttpStack::Request req(stack, "/impu/sip%3A6505550231%40homedomain/bindings", "");
  GetBindingsTask::Config config(store, {remote_store1});
  GetBindingsTask* task = new GetBindingsTask(req, &config, 0);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  AoRPair* aor = new AoRPair(new AoR(aor_id),
                             new AoR(aor_id));
  AoRPair* remote_aor = new AoRPair(new AoR(aor_id),
                                    new AoR(aor_id));

  {
    InSequence s;
      // Neither store has any bindings so the backup store is checked.
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor));
      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _)).WillOnce(Return(remote_aor));

      // The handler returns a 404.
      EXPECT_CALL(*stack, send_reply(_, 404, _));
  }

  task->run();
}

// Test getting an IMPU with one binding.
TEST_F(GetBindingsTest, OneBinding)
{
  // Build request
  MockHttpStack::Request req(stack, "/impu/sip%3A6505550231%40homedomain/bindings", "");
  GetBindingsTask::Config config(store, {remote_store1});
  GetBindingsTask* task = new GetBindingsTask(req, &config, 0);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  AoRPair* aor = build_aor(aor_id);
  std::string id = aor->get_current()->bindings().begin()->first;
  std::string contact = aor->get_current()->bindings().begin()->second->_uri;

  {
    InSequence s;
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor));
      EXPECT_CALL(*stack, send_reply(_, 200, _));
  }

  task->run();

  // Check that the JSON document is correct.
  rapidjson::Document document;
  document.Parse(req.content().c_str());

  // The document should be of the form {"bindings":{...}}
  EXPECT_TRUE(document.IsObject());
  EXPECT_TRUE(document.HasMember("bindings"));
  EXPECT_TRUE(document["bindings"].IsObject());

  // Check there is only one  binding.
  EXPECT_EQ(1, document["bindings"].MemberCount());
  const rapidjson::Value& binding_id = document["bindings"].MemberBegin()->name;
  const rapidjson::Value& binding = document["bindings"].MemberBegin()->value;

  // Check the fields in the binding. Don't check every value. It makes the
  // test unnecessarily verbose.
  EXPECT_TRUE(binding.HasMember("uri"));
  EXPECT_TRUE(binding.HasMember("cid"));
  EXPECT_TRUE(binding.HasMember("cseq"));
  EXPECT_TRUE(binding.HasMember("expires"));
  EXPECT_TRUE(binding.HasMember("priority"));
  EXPECT_TRUE(binding.HasMember("params"));
  EXPECT_TRUE(binding.HasMember("paths"));
  EXPECT_TRUE(binding.HasMember("private_id"));
  EXPECT_TRUE(binding.HasMember("emergency_reg"));

  // Do check the binding ID and URI as a representative test.
  EXPECT_EQ(id, binding_id.GetString());
  EXPECT_EQ(contact, binding["uri"].GetString());
}

// Test getting an IMPU with one binding.
TEST_F(GetBindingsTest, TwoBindings)
{
  int now = time(NULL);

  // Build request
  MockHttpStack::Request req(stack, "/impu/sip%3A6505550231%40homedomain/bindings", "");
  GetBindingsTask::Config config(store, {remote_store1});
  GetBindingsTask* task = new GetBindingsTask(req, &config, 0);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  AoR* aor = new AoR(aor_id);
  build_binding(aor, now, "123");
  build_binding(aor, now, "456");
  AoR* aor2 = new AoR(*aor);
  AoRPair* aor_pair = new AoRPair(aor, aor2);

  {
    InSequence s;
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor_pair));
      EXPECT_CALL(*stack, send_reply(_, 200, _));
  }

  task->run();

  // Check that the JSON document has two bindings.
  rapidjson::Document document;
  document.Parse(req.content().c_str());
  EXPECT_EQ(2, document["bindings"].MemberCount());
  EXPECT_TRUE(document["bindings"].HasMember("123"));
  EXPECT_TRUE(document["bindings"].HasMember("456"));
}

// Test getting an IMPU when the local store is down.
TEST_F(GetBindingsTest, LocalStoreDown)
{
  // Build request
  MockHttpStack::Request req(stack, "/impu/sip%3A6505550231%40homedomain/bindings", "");
  GetBindingsTask::Config config(store, {remote_store1});
  GetBindingsTask* task = new GetBindingsTask(req, &config, 0);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  {
    InSequence s;
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(nullptr));
      EXPECT_CALL(*stack, send_reply(_, 500, _));
  }

  task->run();
}

// Test getting an IMPU with one binding.
TEST_F(GetBindingsTest, BadMethod)
{
  // Build request
  MockHttpStack::Request req(stack,
                             "/impu/sip%3A6505550231%40homedomain/bindings",
                             "",
                             "",
                             "",
                             htp_method_PUT);
  GetBindingsTask::Config config(store, {remote_store1});
  GetBindingsTask* task = new GetBindingsTask(req, &config, 0);

  EXPECT_CALL(*stack, send_reply(_, 405, _));
  task->run();
}

//
// Test fetching sprout's subscriptions.
//

class GetSubscriptionsTest : public TestWithMockSdms
{
};

// Test getting an IMPU that does not have any bindings.
TEST_F(GetSubscriptionsTest, NoSubscriptions)
{
  // Build request
  MockHttpStack::Request req(stack, "/impu/sip%3A6505550231%40homedomain/subscriptions", "");
  GetSubscriptionsTask::Config config(store, {remote_store1});
  GetSubscriptionsTask* task = new GetSubscriptionsTask(req, &config, 0);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  AoRPair* aor = new AoRPair(new AoR(aor_id),
                             new AoR(aor_id));
  AoRPair* remote_aor = new AoRPair(new AoR(aor_id),
                                    new AoR(aor_id));

  {
    InSequence s;
      // Neither store has any bindings so the backup store is checked.
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor));
      EXPECT_CALL(*remote_store1, has_servers()).WillOnce(Return(true));
      EXPECT_CALL(*remote_store1, get_aor_data(aor_id, _)).WillOnce(Return(remote_aor));

      // The handler returns a 404.
      EXPECT_CALL(*stack, send_reply(_, 404, _));
  }

  task->run();
}

// Test getting an IMPU with one binding.
TEST_F(GetSubscriptionsTest, OneSubscription)
{
  // Build request
  MockHttpStack::Request req(stack, "/impu/sip%3A6505550231%40homedomain/subscriptions", "");
  GetSubscriptionsTask::Config config(store, {remote_store1});
  GetSubscriptionsTask* task = new GetSubscriptionsTask(req, &config, 0);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  AoRPair* aor = build_aor(aor_id);
  std::string id = aor->get_current()->subscriptions().begin()->first;
  std::string uri = aor->get_current()->subscriptions().begin()->second->_req_uri;

  {
    InSequence s;
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor));
      EXPECT_CALL(*stack, send_reply(_, 200, _));
  }

  task->run();

  // Check that the JSON document is correct.
  rapidjson::Document document;
  document.Parse(req.content().c_str());

  // The document should be of the form {"subscriptions":{...}}
  EXPECT_TRUE(document.IsObject());
  EXPECT_TRUE(document.HasMember("subscriptions"));
  EXPECT_TRUE(document["subscriptions"].IsObject());

  // Check there is only one subscription.
  EXPECT_EQ(1, document["subscriptions"].MemberCount());
  const rapidjson::Value& subscription_id = document["subscriptions"].MemberBegin()->name;
  const rapidjson::Value& subscription = document["subscriptions"].MemberBegin()->value;

  // Check the fields in the subscription. Don't check every value. It makes the
  // test unnecessarily verbose.
  EXPECT_TRUE(subscription.HasMember("req_uri"));
  EXPECT_TRUE(subscription.HasMember("from_uri"));
  EXPECT_TRUE(subscription.HasMember("from_tag"));
  EXPECT_TRUE(subscription.HasMember("to_uri"));
  EXPECT_TRUE(subscription.HasMember("to_tag"));
  EXPECT_TRUE(subscription.HasMember("cid"));
  EXPECT_TRUE(subscription.HasMember("routes"));
  EXPECT_TRUE(subscription.HasMember("expires"));

  // Do check the subscription ID and URI as a representative test.
  EXPECT_EQ(id, subscription_id.GetString());
  EXPECT_EQ(uri, subscription["req_uri"].GetString());
}

// Test getting an IMPU with two subscriptions.
TEST_F(GetSubscriptionsTest, TwoSubscriptions)
{
  int now = time(NULL);

  // Build request
  MockHttpStack::Request req(stack, "/impu/sip%3A6505550231%40homedomain/subscriptions", "");
  GetSubscriptionsTask::Config config(store, {remote_store1});
  GetSubscriptionsTask* task = new GetSubscriptionsTask(req, &config, 0);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  AoR* aor = new AoR(aor_id);
  build_binding(aor, now, "123");
  build_subscription(aor, now, "456");
  build_subscription(aor, now, "789");
  AoR* aor2 = new AoR(*aor);
  AoRPair* aor_pair = new AoRPair(aor, aor2);

  {
    InSequence s;
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(aor_pair));
      EXPECT_CALL(*stack, send_reply(_, 200, _));
  }

  task->run();

  // Check that the JSON document has two bindings.
  rapidjson::Document document;
  document.Parse(req.content().c_str());
  EXPECT_EQ(2, document["subscriptions"].MemberCount());
  EXPECT_TRUE(document["subscriptions"].HasMember("456"));
  EXPECT_TRUE(document["subscriptions"].HasMember("789"));
}

// Test getting an IMPU when the local store is down.
TEST_F(GetSubscriptionsTest, LocalStoreDown)
{
  // Build request
  MockHttpStack::Request req(stack, "/impu/sip%3A6505550231%40homedomain/subscriptions", "");
  GetSubscriptionsTask::Config config(store, {remote_store1});
  GetSubscriptionsTask* task = new GetSubscriptionsTask(req, &config, 0);

  // Set up subscriber_data_manager expectations
  std::string aor_id = "sip:6505550231@homedomain";
  {
    InSequence s;
      EXPECT_CALL(*store, get_aor_data(aor_id, _)).WillOnce(Return(nullptr));
      EXPECT_CALL(*stack, send_reply(_, 500, _));
  }

  task->run();
}

// Test getting an IMPU with one binding.
TEST_F(GetSubscriptionsTest, BadMethod)
{
  // Build request
  MockHttpStack::Request req(stack,
                             "/impu/sip%3A6505550231%40homedomain/subscriptions",
                             "",
                             "",
                             "",
                             htp_method_PUT);
  GetSubscriptionsTask::Config config(store, {remote_store1});
  GetSubscriptionsTask* task = new GetSubscriptionsTask(req, &config, 0);

  EXPECT_CALL(*stack, send_reply(_, 405, _));
  task->run();
}

//
// Tests for deleting sprout's cached data.
//

class DeleteImpuTaskTest : public TestWithMockSdms
{
  MockHttpStack::Request* req;
  DeleteImpuTask::Config* cfg;
  DeleteImpuTask* task;

  static void SetUpTestCase()
  {
    TestWithMockSdms::SetUpTestCase();
    TestWithMockSdms::SetScscfUri("sip:all.the.sprout.nodes:5058;transport=TCP");
  }

  void SetUp()
  {
    TestWithMockSdms::SetUp();
  }

  void TearDown()
  {
    delete req;
    delete cfg;
    TestWithMockSdms::TearDown();
  }

  // Build the deregistration request
  void build_task(const std::string& impu,
                  htp_method method = htp_method_DELETE,
                  bool configure_remote_store = false)
  {
    req = new MockHttpStack::Request(stack,
                                     "/impu/" + impu,
                                     "",
                                     "",
                                     "",
                                     method);
    std::vector<SubscriberDataManager*> remote_stores;
    if (configure_remote_store)
    {
      remote_stores.push_back(remote_store1);
    }

    IFCConfiguration ifc_configuration(false, false, "", NULL, NULL);
    cfg = new DeleteImpuTask::Config(store, remote_stores, mock_hss, NULL, ifc_configuration);
    task = new DeleteImpuTask(*req, cfg, 0);
  }
};

MATCHER(EmptyAoR, "")
{
  return !arg->current_contains_bindings();
}

TEST_F(DeleteImpuTaskTest, Mainline)
{
  std::string impu = "sip:6505550231@homedomain";
  std::string impu_escaped =  "sip%3A6505550231%40homedomain";

  AoRPair* aor = build_aor(impu, false);
  build_task(impu_escaped);

  HSSConnection::irs_query irs_query;

  {
    InSequence s;
      // Neither store has any bindings so the backup store is checked.
      EXPECT_CALL(*mock_hss, get_registration_data(_, _, _));
      EXPECT_CALL(*store, get_aor_data(impu, _)).WillOnce(Return(aor));
      EXPECT_CALL(*store, set_aor_data(impu,
                                       SubscriberDataManager::EventTrigger::ADMIN,
                                       EmptyAoR(), _, _))
        .WillOnce(DoAll(SetArgReferee<4>(true), // All bindings are expired.
                        Return(Store::OK)));
      EXPECT_CALL(*mock_hss, update_registration_state(_, _, _))
        .WillOnce(DoAll(SaveArg<0>(&irs_query),
                        Return(200)));
      EXPECT_CALL(*stack, send_reply(_, 200, _));
  }

  task->run();

  ASSERT_EQ(irs_query._public_id, impu);
  ASSERT_EQ(irs_query._req_type, HSSConnection::DEREG_ADMIN);
  ASSERT_EQ(irs_query._server_name,
            "sip:scscf.sprout.homedomain:5058;transport=TCP");
}

TEST_F(DeleteImpuTaskTest, StoreFailure)
{
  std::string impu = "sip:6505550231@homedomain";
  std::string impu_escaped =  "sip%3A6505550231%40homedomain";

  AoRPair* aor = build_aor(impu, true);
  build_task(impu_escaped);

  {
    InSequence s;
      // Neither store has any bindings so the backup store is checked.
      EXPECT_CALL(*mock_hss, get_registration_data(_, _, _));
      EXPECT_CALL(*store, get_aor_data(impu, _)).WillOnce(Return(aor));
      EXPECT_CALL(*store, set_aor_data(impu, _, _, _, _))
        .WillOnce(DoAll(SetArgReferee<4>(false), // Fail to expire bindings.
                        Return(Store::ERROR)));
      EXPECT_CALL(*stack, send_reply(_, 500, _));
  }

  task->run();
}

TEST_F(DeleteImpuTaskTest, HomesteadFailsWith404)
{
  std::string impu = "sip:6505550231@homedomain";
  std::string impu_escaped =  "sip%3A6505550231%40homedomain";

  AoRPair* aor = build_aor(impu, true);
  build_task(impu_escaped);

  HSSConnection::irs_query irs_query;

  {
    InSequence s;
      // Neither store has any bindings so the backup store is checked.
      EXPECT_CALL(*mock_hss, get_registration_data(_, _, _));
      EXPECT_CALL(*store, get_aor_data(impu, _)).WillOnce(Return(aor));
      EXPECT_CALL(*store, set_aor_data(impu, _, _, _, _))
        .WillOnce(DoAll(SetArgReferee<4>(true), // All bindings expired
                        Return(Store::OK)));
      EXPECT_CALL(*mock_hss, update_registration_state(_, _, _))
        .WillOnce(DoAll(SaveArg<0>(&irs_query),
                  Return(404)));
      EXPECT_CALL(*stack, send_reply(_, 404, _));
  }

  task->run();

  ASSERT_EQ(irs_query._public_id, impu);
  ASSERT_EQ(irs_query._server_name,
            "sip:scscf.sprout.homedomain:5058;transport=TCP");
}

TEST_F(DeleteImpuTaskTest, HomesteadFailsWith5xx)
{
  std::string impu = "sip:6505550231@homedomain";
  std::string impu_escaped =  "sip%3A6505550231%40homedomain";

  AoRPair* aor = build_aor(impu, true);
  build_task(impu_escaped);

  HSSConnection::irs_query irs_query;

  {
    InSequence s;
      // Neither store has any bindings so the backup store is checked.
      EXPECT_CALL(*mock_hss, get_registration_data(_, _, _));
      EXPECT_CALL(*store, get_aor_data(impu, _)).WillOnce(Return(aor));
      EXPECT_CALL(*store, set_aor_data(impu, _, _, _, _))
        .WillOnce(DoAll(SetArgReferee<4>(true), // All bindings expired
                        Return(Store::OK)));
      EXPECT_CALL(*mock_hss, update_registration_state(_, _, _))
        .WillOnce(DoAll(SaveArg<0>(&irs_query),
                  Return(500)));
      EXPECT_CALL(*stack, send_reply(_, 502, _));
  }

  task->run();

  ASSERT_EQ(irs_query._public_id, impu);
  ASSERT_EQ(irs_query._server_name,
            "sip:scscf.sprout.homedomain:5058;transport=TCP");
}

TEST_F(DeleteImpuTaskTest, HomesteadFailsWith4xx)
{
  std::string impu = "sip:6505550231@homedomain";
  std::string impu_escaped =  "sip%3A6505550231%40homedomain";

  AoRPair* aor = build_aor(impu, true);
  build_task(impu_escaped);

  HSSConnection::irs_query irs_query;

  {
    InSequence s;
      // Neither store has any bindings so the backup store is checked.
      EXPECT_CALL(*mock_hss, get_registration_data(_, _, _));
      EXPECT_CALL(*store, get_aor_data(impu, _)).WillOnce(Return(aor));
      EXPECT_CALL(*store, set_aor_data(impu, _, _, _, _))
        .WillOnce(DoAll(SetArgReferee<4>(true), // All bindings expired
                        Return(Store::OK)));
      EXPECT_CALL(*mock_hss, update_registration_state(_, _, _))
        .WillOnce(DoAll(SaveArg<0>(&irs_query),
                  Return(400)));
      EXPECT_CALL(*stack, send_reply(_, 400, _));
  }

  task->run();

  ASSERT_EQ(irs_query._public_id, impu);
  ASSERT_EQ(irs_query._server_name,
            "sip:scscf.sprout.homedomain:5058;transport=TCP");
}

TEST_F(DeleteImpuTaskTest, WritingToRemoteStores)
{
  std::string impu = "sip:6505550231@homedomain";
  std::string impu_escaped =  "sip%3A6505550231%40homedomain";

  AoRPair* aor = build_aor(impu);
  AoRPair* remote_aor = build_aor(impu);
  build_task(impu_escaped, htp_method_DELETE, true);

  HSSConnection::irs_query irs_query;

  {
    InSequence s;
      // Neither store has any bindings so the backup store is checked.
      EXPECT_CALL(*mock_hss, get_registration_data(_, _, _));
      EXPECT_CALL(*store, get_aor_data(impu, _)).WillOnce(Return(aor));
      EXPECT_CALL(*store, set_aor_data(impu, _, EmptyAoR(), _, _))
        .WillOnce(DoAll(SetArgReferee<4>(true), // All bindings expired
                        Return(Store::OK)));
      EXPECT_CALL(*mock_hss, update_registration_state(_, _, _))
        .WillOnce(DoAll(SaveArg<0>(&irs_query),
                  Return(200)));

      EXPECT_CALL(*remote_store1, get_aor_data(impu, _)).WillOnce(Return(remote_aor));
      EXPECT_CALL(*remote_store1, set_aor_data(impu, _, EmptyAoR(), _, _))
        .WillOnce(DoAll(SetArgReferee<4>(true), // All bindings expired
                        Return(Store::OK)));

      EXPECT_CALL(*stack, send_reply(_, 200, _));
  }

  task->run();

  ASSERT_EQ(irs_query._public_id, impu);
  ASSERT_EQ(irs_query._server_name,
            "sip:scscf.sprout.homedomain:5058;transport=TCP");
}

TEST_F(DeleteImpuTaskTest, BadMethod)
{
  std::string impu = "sip:6505550231@homedomain";
  std::string impu_escaped =  "sip%3A6505550231%40homedomain";

  build_task(impu_escaped, htp_method_PUT);
  EXPECT_CALL(*stack, send_reply(_, 405, _));

  task->run();
}




class PushProfileTaskTest : public TestWithMockSdms
{
  MockHttpStack::Request* req;
  PushProfileTask::Config* cfg;
  PushProfileTask* task;

  static void SetUpTestCase()
  {
    TestWithMockSdms::SetUpTestCase();
    TestWithMockSdms::SetScscfUri("sip:all.the.sprout.nodes:5058;transport=TCP");
  }

  void SetUp()
  {
    TestWithMockSdms::SetUp();
  }

  void TearDown()
  {
    delete req;
    delete cfg;
    TestWithMockSdms::TearDown();
  }

  // Build the push profile request
  void build_pushprofile_request(std::string body,
                                 std::string default_uri,
                                 htp_method method = htp_method_PUT,
                                 bool configure_remote_store = false)
  {
    req = new MockHttpStack::Request(stack,
                                     "/registrations/" + default_uri,
                                     "",
                                     "",
                                     body,
                                     method);
    std::vector<SubscriberDataManager*> remote_stores;
    if (configure_remote_store)
    {
      remote_stores.push_back(remote_store1);
    }

    cfg = new PushProfileTask::Config(store, remote_stores, mock_hss);
    task = new PushProfileTask(*req, cfg, 0);
  }
};

// Mainline Case. Complicated XML to make sure all components can be handled correctly
TEST_F(PushProfileTaskTest, MainlineTest)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string user_data =     "<IMSSubscription><ServiceProfile>"
                              "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                              "<PublicIdentity><Identity>sip:6505550232@homedomain</Identity><BarringIndication>1</BarringIndication></PublicIdentity>"
                              "<InitialFilterCriteria>"
                              "<Priority>1</Priority>"
                              "<TriggerPoint>"
                              "<ConditionTypeCNF>0</ConditionTypeCNF>"
                              "<SPT>"
                              "<ConditionNegated>0</ConditionNegated>"
                              "<Group>0</Group>"
                              "<Method>REGISTER</Method>"
                              "<Extension></Extension>"
                              "</SPT>"
                              "</TriggerPoint>"
                              "<ApplicationServer>"
                              "<ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>"
                              "<DefaultHandling>1</DefaultHandling>"
                              "</ApplicationServer>"
                              "</InitialFilterCriteria>"
                              "</ServiceProfile></IMSSubscription>";
  std::string body =          "{\"user-data-xml\":\"" + user_data + "\"}";

  AoR* aor = new AoR(default_uri);
  AoR* aor2 = new AoR(*aor);
  AoRPair* aor_pair = new AoRPair(aor, aor2);
  build_pushprofile_request(body, default_uri);

  EXPECT_CALL(*store, get_aor_data(default_uri, _)).WillOnce(Return(aor_pair));
  EXPECT_CALL(*store, set_aor_data(default_uri, _, aor_pair, _, _)).WillOnce(Return(Store::OK));
  EXPECT_CALL(*stack, send_reply(_, 200, _));
  task->run();
}

// The method is not a put, and therefore is invalid. Sends HTTP_BAD_REQUEST.
TEST_F(PushProfileTaskTest, InvalidMethod)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string user_data =     "<IMSSubscription><ServiceProfile>"
                              "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                              "</ServiceProfile></IMSSubscription>";
  std::string body =          "{\"user-data-xml\":\"" + user_data + "\"}";

  build_pushprofile_request(body, default_uri, htp_method_GET);

  EXPECT_CALL(*stack, send_reply(_, 405, _));
  task->run();
}

// The JSON is not valid, and therefore not able to be parsed. Sends HTTP_BAD_REQUEST.
TEST_F(PushProfileTaskTest, InvalidJSON)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string user_data =     "<IMSSubscription><ServiceProfile>"
                              "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                              "</ServiceProfile></IMSSubscription>";
  std::string body = " {{\"user-data-xml\":\"" + user_data + "\"}";

  build_pushprofile_request(body, default_uri);

  EXPECT_CALL(*stack, send_reply(_, 400, _));
  task->run();
}

// The JSON is valid JSON, but does not contain the xml component as expected Sends HTTP_BAD_REQUEST
TEST_F(PushProfileTaskTest, MissingXMLfromJSON)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string user_data =     "<IMSSubscription><ServiceProfile>"
                              "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                              "</ServiceProfile></IMSSubscription>";
  std::string body = "{\"public-identity\":\""+ default_uri + "\"}";

  build_pushprofile_request(body, default_uri);

  EXPECT_CALL(*stack, send_reply(_, 400, _));
  task->run();
}


// The XML is not valid and therefore not able to be parsed. Sends HTTP_BAD_REQUEST.
TEST_F(PushProfileTaskTest, InvalidXML)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string user_data =     "<IMSSubscription><ServiceProfile>"
                              "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                              "<<"
                              "</ServiceProfile></IMSSubscription>";
  std::string body =          "{\"user-data-xml\":\"" + user_data + "\"}";

  build_pushprofile_request(body, default_uri);

  EXPECT_CALL(*stack, send_reply(_, 400, _));
  task->run();
}

// The XML does not contain any service profiles. Sends HTTP_BAD_REQUEST
TEST_F(PushProfileTaskTest, MissingServiceProfileXML)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string user_data =     "<IMSSubscription>"
                              "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                              "</IMSSubscription>";
  std::string body = "{\"user-data-xml\":\"" + user_data + "\"}";

  build_pushprofile_request(body, default_uri);

  EXPECT_CALL(*stack, send_reply(_, 400, _));
  task->run();
}



// The XML does not contain the relevant Public Identities. Sends HTTP_BAD_REQUEST.
TEST_F(PushProfileTaskTest, MissingPublicIdentityXML)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string user_data =  "<IMSSubscription><ServiceProfile>"
                           "</ServiceProfile></IMSSubscription>";
  std::string body =       "{\"user-data-xml\":\"" + user_data + "\"}";

  build_pushprofile_request(body, default_uri);

  EXPECT_CALL(*stack, send_reply(_, 400, _));
  task->run();
}

// get_aor_data returns a NULL pointer. Sends HTTP_SERVER_ERROR
TEST_F(PushProfileTaskTest, SubscriberDataManagerFails)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string user_data =     "<IMSSubscription><ServiceProfile>"
                              "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                              "</ServiceProfile></IMSSubscription>";
  std::string body =          "{\"user-data-xml\":\"" + user_data + "\"}";

  AoRPair* aor_pair;
  aor_pair = NULL;
  build_pushprofile_request(body, default_uri);

  EXPECT_CALL(*store, get_aor_data(default_uri, _)).WillOnce(Return(aor_pair));
  EXPECT_CALL(*stack, send_reply(_, 500, _));
  task->run();
}

// set_aor_data fails. Sends HTTP_SERVER_ERROR
TEST_F(PushProfileTaskTest, SubscriberDataManagerWriteFails)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string user_data =     "<IMSSubscription><ServiceProfile>"
                              "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                              "</ServiceProfile></IMSSubscription>";
  std::string body =          "{\"user-data-xml\":\"" + user_data + "\"}";

  AoR* aor = new AoR(default_uri);
  AoR* aor2 = new AoR(*aor);
  AoRPair* aor_pair = new AoRPair(aor, aor2);
  build_pushprofile_request(body, default_uri);

  EXPECT_CALL(*store, get_aor_data(default_uri, _)).WillOnce(Return(aor_pair));
  EXPECT_CALL(*store, set_aor_data(default_uri, _, aor_pair, _, _)).WillOnce(Return(Store::ERROR));
  EXPECT_CALL(*stack, send_reply(_, 500, _));
  task->run();
}

// all bindings are expired - triggers a deregistration
TEST_F(PushProfileTaskTest, AllBindingExpired)
{
  std::string default_uri = "sip:6505550231@homedomain";
  std::string user_data =     "<IMSSubscription><ServiceProfile>"
                              "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                              "</ServiceProfile></IMSSubscription>";
  std::string body =          "{\"user-data-xml\":\"" + user_data + "\"}";

  AoR* aor = new AoR(default_uri);
  AoR* aor2 = new AoR(*aor);
  AoRPair* aor_pair = new AoRPair(aor, aor2);
  build_pushprofile_request(body, default_uri);

  HSSConnection::irs_query irs_query;

  {
    InSequence s;

    EXPECT_CALL(*store, get_aor_data(default_uri, _)).WillOnce(Return(aor_pair));
    EXPECT_CALL(*store, set_aor_data(default_uri, _, aor_pair,_, _))
      .WillOnce(DoAll(SetArgReferee<4>(true), // All bindings are expired.
                      Return(Store::OK)));
    EXPECT_CALL(*mock_hss, update_registration_state(_, _, _))
      .WillOnce(DoAll(SaveArg<0>(&irs_query),
                      Return(200)));
    EXPECT_CALL(*stack, send_reply(_, 200, _));
  }

  task->run();

  ASSERT_EQ(irs_query._public_id, default_uri);
  ASSERT_EQ(irs_query._req_type, HSSConnection::DEREG_TIMEOUT);
}
