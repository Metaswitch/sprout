/**
 * @file s4_test.cpp
 *
 * Copyright (C) Metaswitch Networks 2018
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
#include "sas.h"
#include "localstore.h"
#include "s4.h"
#include "astaire_aor_store.h"
#include "test_utils.hpp"
#include "test_interposer.hpp"
#include "mock_store.h"
#include "aor_test_utils.h"
#include "mock_chronos_connection.h"

// SDM-REFACTOR-TODO:
// Full UTs
// Comments explaining what each UT does

using ::testing::_;
using ::testing::InSequence;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::SaveArg;
using ::testing::An;

std::string empty_aor = "{\"bindings\": {}, \"subscriptions\": {}, \"notify_cseq\": 1}";
std::string aor_with_binding = "{\"timer_id\": \"123\", \"bindings\": {\"<urn:uuid:00000000-0000-0000-0000-777777777777>:1\":{\"uri\":\"sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.214:5061;transport=tcp;ob\",\"cid\":\"0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs1042ohntC@10.114.61.213\",\"cseq\":10000,\"expires\":1000000,\"priority\":0,\"params\":{\"+sip.ice\":\"\",\"+sip.instance\":\"\\\"<urn:uuid:00000000-0000-0000-0000-777777777777>\\\"\",\"reg-id\":\"1\"},\"path_headers\":[\"<sip:GgAAAAAAAACYyAW4z38AABcUwStNKgAAa3WOL+1v72nFJg==@ec2-107-22-156-220.compute-1.amazonaws.com:5060;lr;ob>\"],\"paths\":[\"sip:GgAAAAAAAACYyAW4z38AABcUwStNKgAAa3WOL+1v72nFJg==@ec2-107-22-156-220.compute-1.amazonaws.com:5060;lr;ob\"],\"private_id\":\"Alice\",\"emergency_reg\":false}}, \"subscriptions\": {}, \"notify_cseq\": 1}";
std::string aor_with_binding_subscription_associated_uris = "{\"bindings\": {\"<urn:uuid:00000000-0000-0000-0000-777777777777>:1\":{\"uri\":\"sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.214:5061;transport=tcp;ob\",\"cid\":\"0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs1042ohntC@10.114.61.213\",\"cseq\":10000,\"expires\":1000000,\"priority\":0,\"params\":{\"+sip.ice\":\"\",\"+sip.instance\":\"\\\"<urn:uuid:00000000-0000-0000-0000-777777777777>\\\"\",\"reg-id\":\"1\"},\"path_headers\":[\"<sip:GgAAAAAAAACYyAW4z38AABcUwStNKgAAa3WOL+1v72nFJg==@ec2-107-22-156-220.compute-1.amazonaws.com:5060;lr;ob>\"],\"paths\":[\"sip:GgAAAAAAAACYyAW4z38AABcUwStNKgAAa3WOL+1v72nFJg==@ec2-107-22-156-220.compute-1.amazonaws.com:5060;lr;ob\"],\"private_id\":\"Alice\",\"emergency_reg\":false}}, \"subscriptions\": {}, \"notify_cseq\": 5}";

/// Fixture for BasicS4Test.
class BasicS4Test : public ::testing::Test
{
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
  }

  static void TearDownTestCase()
  {
    SipTest::TearDownTestCase();
  }

  BasicS4Test()
  {
    _mock_store = new MockStore();
    _aor_store = new AstaireAoRStore(_mock_store);
    _chronos_connection = new MockChronosConnection("chronos");
    _remote_s4_1 = new S4("site2", _chronos_connection, _aor_store, {});
    _remote_s4_2 = new S4("site3", _chronos_connection, _aor_store, {});
    _s4 = new S4("site1", _chronos_connection, _aor_store, {_remote_s4_1, _remote_s4_2});
  }

  virtual ~BasicS4Test()
  {
    delete _s4; _s4 = NULL;
    delete _remote_s4_1, _remote_s4_1 = NULL;
    delete _remote_s4_2, _remote_s4_2 = NULL;
    delete _chronos_connection; _chronos_connection = NULL;
    delete _aor_store; _aor_store = NULL;
    delete _mock_store; _mock_store = NULL;
  }

  // Set up a single expectation for getting data from a store where the store
  // responds successfully
  void get_data_expect_call_success(std::string aor_data,
                                    int cas,
                                    int times)
  {
    EXPECT_CALL(*_mock_store, get_data(_, _, _, _, _, An<Store::Format>()))
      .Times(times)
      .WillRepeatedly(DoAll(SetArgReferee<2>(std::string(aor_data)),
                            SetArgReferee<3>(cas),
                            Return(Store::OK)));
  }

  // Set up a single expectation for getting data from a store where there's a
  // store error
  void get_data_expect_call_failure(Store::Status rc,
                                    int times)
  {
    EXPECT_CALL(*_mock_store, get_data(_, _, _, _, _, An<Store::Format>()))
      .Times(times)
      .WillOnce(Return(rc));
  }

  // Set up a single expectation for writing data to the store.
  void set_data_expect_call(Store::Status rc,
                            int times)
  {
    EXPECT_CALL(*_mock_store, set_data(_, _, _, _, _, _, An<Store::Format>()))
      .Times(times)
      .WillRepeatedly(Return(rc));
  }

  // Set up a single expectation for getting data from a store where the store
  // responds successfully
  void set_data_expect_call_save_data(Store::Status rc,
                                      std::string& aor_str)
  {
    EXPECT_CALL(*_mock_store, set_data(_, _, _, _, _, _, An<Store::Format>()))
      .WillOnce(DoAll(SaveArg<2>(&aor_str),
                      Return(rc)));
  }

  // Fixture variables.  Note that as the fixture is a C++ template, these must
  // be accessed in the individual tests using the this pointer (e.g. use
  // `this->store` rather than `_store`).
  MockStore* _mock_store;
  AstaireAoRStore* _aor_store;
  MockChronosConnection* _chronos_connection;
  S4* _remote_s4_1;
  S4* _remote_s4_2;
  S4* _s4;
};

// This test covers a GET where the subscriber is found in the local site
TEST_F(BasicS4Test, GETSubscriberFoundInLocalSite)
{
  get_data_expect_call_success(aor_with_binding,
                               1,
                               1);

  AoR* get_aor = NULL;
  uint64_t version;
  HTTPCode rc = this->_s4->handle_get("aor_id", &get_aor, version, 0);

  EXPECT_EQ(rc, 200);
  ASSERT_FALSE(get_aor == NULL);
  EXPECT_EQ(1, get_aor->bindings().size());

  delete get_aor; get_aor = NULL;
}

// This test covers a GET where there's a local site failure
TEST_F(BasicS4Test, GETLocalSiteFailure)
{
  get_data_expect_call_failure(Store::Status::ERROR, 1);

  AoR* get_aor = NULL;
  uint64_t version;
  HTTPCode rc = this->_s4->handle_get("aor_id", &get_aor, version, 0);

  EXPECT_EQ(rc, 500);
  EXPECT_TRUE(get_aor == NULL);
}

// This test covers a GET where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, GETNotFoundInAllStores)
{
  get_data_expect_call_success(empty_aor,
                               1,
                               3);

  AoR* get_aor = NULL;
  uint64_t version;
  HTTPCode rc = this->_s4->handle_get("aor_id", &get_aor, version, 0);

  EXPECT_EQ(rc, 404);
  ASSERT_TRUE(get_aor == NULL);
}

// This test covers a GET where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, GETFoundInRemoteStore)
{
  std::string aor_str;

  {
    InSequence s;
    get_data_expect_call_success(empty_aor,
                                 1,
                                 1);

    get_data_expect_call_success(aor_with_binding,
                                 1,
                                 1);

    EXPECT_CALL(*(this->_chronos_connection), send_put(_, _, _, _, _, _))
      .WillOnce(Return(0));

    EXPECT_CALL(*_mock_store, set_data(_, _, _, _, 1000000 + 10, _, An<Store::Format>()))
      .WillOnce(DoAll(SaveArg<2>(&aor_str),
                      Return(Store::Status::OK)));
  }

  AoR* get_aor = NULL;
  uint64_t version;
  HTTPCode rc = this->_s4->handle_get("aor_id", &get_aor, version, 0);

  EXPECT_EQ(rc, 200);
  ASSERT_FALSE(get_aor == NULL);
  EXPECT_FALSE(get_aor->bindings().empty());
  // EM-TODO! EXPECT_EQ(aor_str, aor_with_binding);

  delete get_aor; get_aor = NULL;
}

// This test covers a GET where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, GETFoundInRemoteStoreErrorOnWrite)
{
  {
    InSequence s;
    get_data_expect_call_success(empty_aor,
                                 1,
                                 1);
    get_data_expect_call_success(aor_with_binding,
                                 1,
                                 1);
    EXPECT_CALL(*(this->_chronos_connection), send_put(_, _, _, _, _, _))
      .WillRepeatedly(Return(HTTP_OK));

    set_data_expect_call(Store::Status::ERROR, 1);

  }

  AoR* get_aor = NULL;
  uint64_t version;
  HTTPCode rc = this->_s4->handle_get("aor_id", &get_aor, version, 0);

  EXPECT_EQ(rc, 500);
  ASSERT_TRUE(get_aor == NULL);
}

// This test covers a GET where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, GETFoundInRemoteStoreContentionOnWrite)
{
  {
    InSequence s;
    get_data_expect_call_success(empty_aor,
                                 1,
                                 1);
    get_data_expect_call_success(aor_with_binding,
                                 1,
                                 1);
    EXPECT_CALL(*(this->_chronos_connection), send_put(_, _, _, _, _, _))
      .WillRepeatedly(Return(HTTP_OK));
    set_data_expect_call(Store::Status::DATA_CONTENTION, 1);
    get_data_expect_call_success(aor_with_binding,
                                 1,
                                 1);
  }

  AoR* get_aor = NULL;
  uint64_t version;
  HTTPCode rc = this->_s4->handle_get("aor_id", &get_aor, version, 0);

  EXPECT_EQ(rc, 200);
  ASSERT_FALSE(get_aor == NULL);
  EXPECT_FALSE(get_aor->bindings().empty());

  delete get_aor; get_aor = NULL;
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, DELETENotFoundOnGet)
{
  get_data_expect_call_success(empty_aor,
                               1,
                               1);
  uint64_t version = 0;
  HTTPCode rc = this->_s4->handle_delete("aor_id", version, 0);

  EXPECT_EQ(rc, 412);
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, DELETENErrorOnGet)
{
  get_data_expect_call_failure(Store::Status::ERROR, 1);
  uint64_t version = 0;
  HTTPCode rc = this->_s4->handle_delete("aor_id", version, 0);
  EXPECT_EQ(rc, 500);
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, DELETEFoundOnGetValidVersion)
{
  get_data_expect_call_success(aor_with_binding,
                               1,
                               3);
  set_data_expect_call(Store::Status::OK, 3);

  EXPECT_CALL(*(this->_chronos_connection), send_delete(_, _))
    .WillOnce(Return(HTTP_OK));

  uint64_t version = 1;

  HTTPCode rc = this->_s4->handle_local_delete("aor_id", version, 0);

  EXPECT_EQ(rc, 204);
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, DELETEContentionOnLocalSet)
{
  get_data_expect_call_success(aor_with_binding,
                               1,
                               1);
  set_data_expect_call(Store::Status::DATA_CONTENTION, 1);

  EXPECT_CALL(*(this->_chronos_connection), send_delete(_, _))
    .WillOnce(Return(HTTP_OK));

  uint64_t version = 1;

  HTTPCode rc = this->_s4->handle_delete("aor_id", version, 0);

  EXPECT_EQ(rc, 412);
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, DELETEErrorOnLocalSet)
{
  get_data_expect_call_success(aor_with_binding,
                               1,
                               1);
  set_data_expect_call(Store::Status::ERROR, 1);

  EXPECT_CALL(*(this->_chronos_connection), send_delete(_, _))
    .WillOnce(Return(HTTP_OK));

  uint64_t version = 1;

  HTTPCode rc = this->_s4->handle_delete("aor_id", version, 0);

  EXPECT_EQ(rc, 500);
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, DELETEContentionOnGet)
{
  get_data_expect_call_success(aor_with_binding,
                               10,
                               1);

  uint64_t version = 1;

  HTTPCode rc = this->_s4->handle_delete("aor_id", version, 0);

  EXPECT_EQ(rc, 412);
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, DELETEFoundOnGetErrorOnRemoteGet)
{
  {
    InSequence s;
    get_data_expect_call_success(aor_with_binding, 1, 1);
    //EXPECT_CALL(*(this->_chronos_connection), send_delete(_, _))
     // .WillOnce(Return(HTTP_OK));
    set_data_expect_call(Store::Status::OK, 1);

    get_data_expect_call_failure(Store::Status::ERROR, 1);
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
  }

  uint64_t version = 1;
  HTTPCode rc = this->_s4->handle_delete("aor_id", version, 0);

  EXPECT_EQ(rc, 204);
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, DELETEFoundOnGetNotFoundOnRemoteGet)
{
  {
    InSequence s;
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_failure(Store::Status::NOT_FOUND, 1);
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
  }

  uint64_t version = 1;
  HTTPCode rc = this->_s4->handle_delete("aor_id", version, 0);

  EXPECT_EQ(rc, 204);
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, DELETEFoundOnGetContentionOnRemoteSet)
{
  {
    InSequence s;
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_data_expect_call(Store::Status::DATA_CONTENTION, 1);
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
  }

  uint64_t version = 1;
  HTTPCode rc = this->_s4->handle_delete("aor_id", version, 0);

  EXPECT_EQ(rc, 204);
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, DELETEFoundOnGetErrorOnRemoteSet)
{
  {
    InSequence s;
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_data_expect_call(Store::Status::ERROR, 1);
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
  }

  uint64_t version = 1;
  HTTPCode rc = this->_s4->handle_delete("aor_id", version, 0);

  EXPECT_EQ(rc, 204);
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, PUTFoundOnGet)
{
  set_data_expect_call(Store::Status::DATA_CONTENTION, 1);

  AoR* aor = AoRTestUtils::build_aor("sip:6505550231@homedomain");
  HTTPCode rc = this->_s4->handle_put("aor_id", *aor, 0);

  EXPECT_EQ(rc, 412);

  delete aor; aor = NULL;
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, PUTErrorOnSet)
{
  get_data_expect_call_success(empty_aor, 1, 1);
  EXPECT_CALL(*(this->_chronos_connection), send_post(_, _, _, _, _, _))
    .WillOnce(Return(HTTP_SERVER_ERROR));
  set_data_expect_call(Store::Status::ERROR, 1);

  AoR* aor = AoRTestUtils::build_aor("sip:6505550231@homedomain");
  HTTPCode rc = this->_s4->handle_put("aor_id", *aor, 0);

  EXPECT_EQ(rc, 500);

  delete aor; aor = NULL;
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, PUTContentionOnSet)
{
  get_data_expect_call_success(empty_aor, 1, 1);
  EXPECT_CALL(*(this->_chronos_connection), send_post(_, _, _, _, _, _))
    .WillOnce(Return(HTTP_PRECONDITION_FAILED));
  set_data_expect_call(Store::Status::DATA_CONTENTION, 1);

  AoR* aor = AoRTestUtils::build_aor("sip:6505550231@homedomain");
  HTTPCode rc = this->_s4->handle_put("aor_id", aor, 0);

  EXPECT_EQ(rc, 412);

  delete aor; aor = NULL;
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, PUTSuccess)
{
  set_data_expect_call(Store::Status::OK, 3);
  EXPECT_CALL(*(this->_chronos_connection), send_post(_, _, _, _, _, _))
    .WillOnce(Return(0));

  AoR* aor = AoRTestUtils::build_aor("sip:6505550231@homedomain");
  HTTPCode rc = this->_s4->handle_put("aor_id", *aor, 0);

  EXPECT_EQ(rc, 200);

  delete aor; aor = NULL;
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, PATCHNotFoundOnGet)
{
  get_data_expect_call_success(empty_aor, 1, 1);

  PatchObject* po = AoRTestUtils::build_po("sip:6505550231@homedomain");
  AoR* aor = NULL;
  HTTPCode rc = this->_s4->handle_patch("aor_id", *po, &aor, 0);

  EXPECT_EQ(rc, 412);

  delete po; po = NULL;
  delete aor; aor = NULL;
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, PATCHErrorOnGet)
{
  get_data_expect_call_failure(Store::Status::ERROR, 1);

  PatchObject* po = AoRTestUtils::build_po("sip:6505550231@homedomain");
  AoR* aor = NULL;
  HTTPCode rc = this->_s4->handle_patch("aor_id", *po, &aor, 0);

  EXPECT_EQ(rc, 500);

  delete po; po = NULL;
  delete aor; aor = NULL;
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, PATCHErrorOnLocalSet)
{
  get_data_expect_call_success(aor_with_binding, 1, 1);
  EXPECT_CALL(*(this->_chronos_connection), send_put(_, _, _, _, _, _))
    .WillRepeatedly(Return(HTTP_OK));
  set_data_expect_call(Store::Status::ERROR, 1);

  PatchObject* po = AoRTestUtils::build_po("sip:6505550231@homedomain");
  AoR* aor = NULL;
  HTTPCode rc = this->_s4->handle_patch("aor_id", *po, &aor, 0);

  EXPECT_EQ(rc, 500);

  delete po; po = NULL;
  delete aor; aor = NULL;
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, PATCHContentionOnLocalSet)
{
  {
    InSequence s;
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_data_expect_call(Store::Status::DATA_CONTENTION, 1);

    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);

    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);

    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
  }

  PatchObject* po = AoRTestUtils::build_po("sip:6505550231@homedomain");
  AoR* aor = NULL;
  HTTPCode rc = this->_s4->handle_patch("aor_id", *po, &aor, 0);

  EXPECT_EQ(rc, 200);

  delete po; po = NULL;
  delete aor; aor = NULL;
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, PATCHSuccess)
{
  get_data_expect_call_success(aor_with_binding_subscription_associated_uris, 1, 3);
  set_data_expect_call(Store::Status::OK, 3);

  EXPECT_CALL(*(this->_chronos_connection), send_post(_, _, _, _, _, _))
    .WillOnce(Return(0));

  PatchObject* po = new PatchObject();

  Binding* b1 = new Binding("aor_id");
  b1->_uri = std::string("<sip:6505550231@192.91.191.29:59934;transport=tcp;ob>");
  b1->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
  b1->_cseq = 17038;
  b1->_expires = 1000005;
  b1->_priority = 0;
  b1->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  b1->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
  b1->_params["reg-id"] = "1";
  b1->_params["+sip.ice"] = "";
  b1->_emergency_registration = false;
  b1->_private_id = "6505550231";

  Subscription* s1 = new Subscription();
  s1->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
  s1->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_from_tag = std::string("4321");
  s1->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
  s1->_to_tag = std::string("1234");
  s1->_cid = std::string("xyzabc@192.91.191.29");
  s1->_route_uris.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
  s1->_expires = 1000300;

  po->_update_bindings.insert(std::make_pair("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1", b1));
  po->_update_subscriptions.insert(std::make_pair("1234", s1));
  po->_increment_cseq = true;
  AoR* aor = NULL;
  HTTPCode rc = this->_s4->handle_patch("aor_id", *po, &aor, 0);

  EXPECT_EQ(rc, 200);
  ASSERT_TRUE(aor != NULL);
  EXPECT_EQ(aor->_notify_cseq, 6);
  EXPECT_EQ(aor->_bindings.size(), 2);
  EXPECT_EQ(aor->_subscriptions.size(), 1);

  delete po; po = NULL;
  delete aor; aor = NULL;
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, PUTFlipToPatch)
{
  {
    InSequence s;
    get_data_expect_call_success(empty_aor, 1, 1);
    EXPECT_CALL(*(this->_chronos_connection), send_post(_, _, _, _, _, _));
    set_data_expect_call(Store::Status::OK, 1);

    get_data_expect_call_success(empty_aor, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);

    get_data_expect_call_success(aor_with_binding, 1, 1);
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
  }

  AoR* aor = AoRTestUtils::build_aor("sip:6505550231@homedomain");
  HTTPCode rc = this->_s4->handle_put("aor_id", *aor, 0);

  EXPECT_EQ(rc, 200);

  delete aor; aor = NULL;
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, PATCHFlipToPut)
{
  {
    InSequence s;
    get_data_expect_call_success(aor_with_binding, 1, 1);
    EXPECT_CALL(*(this->_chronos_connection), send_post(_, _, _, _, _, _));
    set_data_expect_call(Store::Status::OK, 1);

    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);

    get_data_expect_call_success(empty_aor, 1, 1);
    get_data_expect_call_success(empty_aor, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
  }

  PatchObject* po = AoRTestUtils::build_po("sip:6505550231@homedomain");
  AoR* aor = NULL;
  HTTPCode rc = this->_s4->handle_patch("aor_id", *po, &aor, 0);

  EXPECT_EQ(rc, 200);

  delete po; po = NULL;
  delete aor; aor = NULL;
}
