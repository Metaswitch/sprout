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

using ::testing::_;
using ::testing::InSequence;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::SaveArg;
using ::testing::An;

// Timer ID - only set in existing AoRs.
std::string TIMER_ID = "123";

// An AoR with a single binding
std::string aor_with_binding = "{\"timer_id\": \"" + TIMER_ID + "\", \"bindings\": {\"<urn:uuid:00000000-0000-0000-0000-777777777777>:1\":{\"uri\":\"sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.214:5061;transport=tcp;ob\",\"cid\":\"0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs1042ohntC@10.114.61.213\",\"cseq\":10000,\"expires\":1000000,\"priority\":0,\"params\":{\"+sip.ice\":\"\",\"+sip.instance\":\"\\\"<urn:uuid:00000000-0000-0000-0000-777777777777>\\\"\",\"reg-id\":\"1\"},\"path_headers\":[\"<sip:GgAAAAAAAACYyAW4z38AABcUwStNKgAAa3WOL+1v72nFJg==@ec2-107-22-156-220.compute-1.amazonaws.com:5060;lr;ob>\"],\"paths\":[\"sip:GgAAAAAAAACYyAW4z38AABcUwStNKgAAa3WOL+1v72nFJg==@ec2-107-22-156-220.compute-1.amazonaws.com:5060;lr;ob\"],\"private_id\":\"Alice\",\"emergency_reg\":false}}, \"subscriptions\": {}, \"notify_cseq\": 1}";

// An AoR with a binding, subscription and associated URIs
std::string aor_with_binding_subscription_associated_uris = "{\"timer_id\": \"" + TIMER_ID + "\", \"bindings\": {\"<urn:uuid:00000000-0000-0000-0000-777777777777>:1\":{\"uri\":\"sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.214:5061;transport=tcp;ob\",\"cid\":\"0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs1042ohntC@10.114.61.213\",\"cseq\":10000,\"expires\":1000000,\"priority\":0,\"params\":{\"+sip.ice\":\"\",\"+sip.instance\":\"\\\"<urn:uuid:00000000-0000-0000-0000-777777777777>\\\"\",\"reg-id\":\"1\"},\"path_headers\":[\"<sip:GgAAAAAAAACYyAW4z38AABcUwStNKgAAa3WOL+1v72nFJg==@ec2-107-22-156-220.compute-1.amazonaws.com:5060;lr;ob>\"],\"paths\":[\"sip:GgAAAAAAAACYyAW4z38AABcUwStNKgAAa3WOL+1v72nFJg==@ec2-107-22-156-220.compute-1.amazonaws.com:5060;lr;ob\"],\"private_id\":\"Alice\",\"emergency_reg\":false}}, \"subscriptions\": {}, \"notify_cseq\": 5}";

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
    _mock_chronos = new MockChronosConnection("chronos");
    _remote_s4_1 = new S4("site2", _aor_store);
    _remote_s4_2 = new S4("site3", _aor_store);
    _s4 = new S4("site1",
                 _mock_chronos,
                 "callback_uri",
                 _aor_store,
                 {_remote_s4_1, _remote_s4_2});
  }

  virtual ~BasicS4Test()
  {
    delete _s4; _s4 = NULL;
    delete _remote_s4_1, _remote_s4_1 = NULL;
    delete _remote_s4_2, _remote_s4_2 = NULL;
    delete _mock_chronos; _mock_chronos = NULL;
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
      .WillRepeatedly(Return(rc));
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

  // Set up the Chronos expectations for a successful POST
  void set_chronos_post_expectations()
  {
    EXPECT_CALL(*(this->_mock_chronos), send_post(_, _, _, _, _, _))
      .WillOnce(Return(HTTP_OK));
  }

  // Set up the Chronos expectations for a successful PUT
  void set_chronos_put_expectations()
  {
    EXPECT_CALL(*(this->_mock_chronos), send_put(_, _, _, _, _, _))
      .WillOnce(Return(HTTP_OK));
  }

  // Set up the Chronos expectations for a successful DELETE
  void set_chronos_delete_expectations()
  {
    EXPECT_CALL(*(this->_mock_chronos), send_delete(_, _))
      .WillOnce(Return(HTTP_OK));
  }

  // Fixture variables.  Note that as the fixture is a C++ template, these must
  // be accessed in the individual tests using the this pointer (e.g. use
  // `this->store` rather than `_store`).
  MockStore* _mock_store;
  AstaireAoRStore* _aor_store;
  MockChronosConnection* _mock_chronos;
  S4* _remote_s4_1;
  S4* _remote_s4_2;
  S4* _s4;
};

// This test covers getting subscriber information where the subscriber is
// present on the local site.
TEST_F(BasicS4Test, GetSubscriberInfoFoundInLocalSite)
{
  // Expect one get call to the local site only.
  get_data_expect_call_success(aor_with_binding, 1, 1);

  AoR* get_aor = NULL;
  uint64_t version;
  HTTPCode rc = this->_s4->handle_get("aor_id", &get_aor, version, 0);

  // Check the return code, and check that the returned AoR is as expected.
  // EM-TODO, check AoR.
  EXPECT_EQ(rc, 200);
  ASSERT_FALSE(get_aor == NULL);
  EXPECT_EQ(1, get_aor->bindings().size());

  delete get_aor; get_aor = NULL;
}

// This test covers getting subscriber information where there's a store error
// on the local site.
TEST_F(BasicS4Test, GetSubscriberInfoLocalSiteStoreError)
{
  // Expect one get call to the local site only.
  get_data_expect_call_failure(Store::Status::ERROR, 1);

  AoR* get_aor = NULL;
  uint64_t version;
  HTTPCode rc = this->_s4->handle_get("aor_id", &get_aor, version, 0);

  EXPECT_EQ(rc, 500);
  EXPECT_TRUE(get_aor == NULL);
}

// This test covers getting subscriber information where the subscriber isn't
// present on any site.
TEST_F(BasicS4Test, GetSubscriberInfoNotOnAnySite)
{
  // Expect get calls to each site.
  get_data_expect_call_failure(Store::Status::NOT_FOUND, 3);

  AoR* get_aor = NULL;
  uint64_t version;
  HTTPCode rc = this->_s4->handle_get("aor_id", &get_aor, version, 0);

  EXPECT_EQ(rc, 404);
  ASSERT_TRUE(get_aor == NULL);
}

// This test covers getting subscriber information where the subscriber doesn't
// exist in the local store, but it is found on the first remote store.
// This test checks the order of expectations, to ensure that the local and
// remote stores are called in the right order.
TEST_F(BasicS4Test, GetSubscriberInfoFoundOnRemoteSite)
{
  // Set up the expectations. The local store should be called once, which
  // returns an empty AoR. The first remote store is then called - this returns
  // an AoR with a binding. We should then write this back to the local store,
  // so expect a Chronos call and a set_data call. No other calls are expected,
  // we shouldn't contact any other remote stores.
  {
    InSequence s;
    get_data_expect_call_failure(Store::Status::NOT_FOUND, 1);
    get_data_expect_call_failure(Store::Status::NOT_FOUND, 1);
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_chronos_put_expectations();
    EXPECT_CALL(*_mock_store, set_data(_, _, _, _, _, _, An<Store::Format>()))
      .WillOnce(Return(Store::Status::OK));
  }

  AoR* get_aor = NULL;
  uint64_t version;
  HTTPCode rc = this->_s4->handle_get("aor_id", &get_aor, version, 0);

  // Check the return code, and check that the returned AoR is as expected.
  EXPECT_EQ(rc, 200);
  ASSERT_FALSE(get_aor == NULL);
  EXPECT_FALSE(get_aor->bindings().empty());
  // EM-TODO! EXPECT_EQ(aor_str, aor_with_binding);

  delete get_aor; get_aor = NULL;
}

// This test covers getting subscriber information where the subscriber doesn't
// exist in the local store, but it is found on the first remote store. There's
// a store error writing the subscriber information back on the local site.
// This test checks the order of expectations, to ensure that the local and
// remote stores are called in the right order.
TEST_F(BasicS4Test, GetSubscriberInfoFoundOnRemoteSiteErrorOnWrite)
{
  // Set up the expectations. The local store should be called once, which
  // returns an empty AoR. The first remote store is then called - this returns
  // an AoR with a binding. We should then write this back to the local store,
  // so expect a Chronos call and a set_data call. This fails, no other calls
  // are expected, we shouldn't contact any other remote stores.
  {
    InSequence s;

    get_data_expect_call_failure(Store::Status::NOT_FOUND, 1);
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_chronos_put_expectations();
    set_data_expect_call(Store::Status::ERROR, 1);
  }

  AoR* get_aor = NULL;
  uint64_t version;
  HTTPCode rc = this->_s4->handle_get("aor_id", &get_aor, version, 0);

  EXPECT_EQ(rc, 500);
  ASSERT_TRUE(get_aor == NULL);
}

// This test covers getting subscriber information where the subscriber doesn't
// exist in the local store, but it is found on the first remote store. There's
// contention writing the subscriber information back on the local site.
// This test checks the order of expectations, to ensure that the local and
// remote stores are called in the right order.
TEST_F(BasicS4Test, GetSubscriberInfoFoundOnRemoteSiteContentionOnWrite)
{
  // Set up the expectations. The local store should be called once, which
  // returns an empty AoR. The first remote store is then called - this returns
  // an AoR with a binding. We should then write this back to the local store,
  // so expect a Chronos call and a set_data call. This fails due to contention,
  // we should then get from the local site again.
  {
    InSequence s;
    get_data_expect_call_failure(Store::Status::NOT_FOUND, 1);
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_chronos_put_expectations();
    set_data_expect_call(Store::Status::DATA_CONTENTION, 1);
    get_data_expect_call_success(aor_with_binding, 1, 1);
  }

  AoR* get_aor = NULL;
  uint64_t version;
  HTTPCode rc = this->_s4->handle_get("aor_id", &get_aor, version, 0);

  EXPECT_EQ(rc, 200);
  ASSERT_FALSE(get_aor == NULL);
  EXPECT_FALSE(get_aor->bindings().empty());

  delete get_aor; get_aor = NULL;
}

// This test covers deleting a subscriber successfully from each site.
TEST_F(BasicS4Test, DeleteSubscriber)
{
  get_data_expect_call_success(aor_with_binding, 1, 3);
  set_data_expect_call(Store::Status::OK, 3);
  set_chronos_delete_expectations();

  HTTPCode rc = this->_s4->handle_delete("aor_id", 1, 0);

  EXPECT_EQ(rc, 204);
}

// This test covers attempting to delete a subscriber where the subscriber
// doesn't exist on the local site - the delete is rejected with a 412.
TEST_F(BasicS4Test, DeleteSubscriberNotFoundOnLocalSite)
{
  get_data_expect_call_failure(Store::Status::NOT_FOUND, 1);

  HTTPCode rc = this->_s4->handle_delete("aor_id", 1, 0);

  EXPECT_EQ(rc, 412);
}

// This test covers attempting to delete a subscriber where there's a store
// error on trying to get the subscriber's information.
TEST_F(BasicS4Test, DeleteSubscriberStoreErrorOnGet)
{
  get_data_expect_call_failure(Store::Status::ERROR, 1);

  HTTPCode rc = this->_s4->handle_delete("aor_id", 1, 0);

  EXPECT_EQ(rc, 500);
}

// This test covers attempting to delete a subscriber where there's contention
// on trying to write the delete to the local store.
TEST_F(BasicS4Test, DeleteSubscriberContentionOnWrite)
{
  get_data_expect_call_success(aor_with_binding, 1, 1);
  set_data_expect_call(Store::Status::DATA_CONTENTION, 1);
  set_chronos_delete_expectations();

  HTTPCode rc = this->_s4->handle_delete("aor_id", 1, 0);

  EXPECT_EQ(rc, 412);
}

// This test covers attempting to delete a subscriber where there's a store
// error on trying to write the delete to the local store.
TEST_F(BasicS4Test, DeleteSubscriberStoreErrorOnWrite)
{
  get_data_expect_call_success(aor_with_binding, 1, 1);
  set_data_expect_call(Store::Status::ERROR, 1);
  set_chronos_delete_expectations();

  uint64_t version = 1;

  HTTPCode rc = this->_s4->handle_delete("aor_id", version, 0);

  EXPECT_EQ(rc, 500);
}

// This test covers attempting to delete a subscriber where the version
// to delete doesn't match the subscriber to delete.
TEST_F(BasicS4Test, DeleteSubscriberVersionMismatch)
{
  get_data_expect_call_success(aor_with_binding, 10, 1);

  uint64_t version = 1;

  HTTPCode rc = this->_s4->handle_delete("aor_id", version, 0);

  EXPECT_EQ(rc, 412);
}

// This test covers attempting to delete a subscriber where the subscriber
// is successfully deleted off the local site, but there's a store error
// on one of the remote sites when getting the subscriber information.
// This test checks the order of expectations, to ensure that the local and
// remote stores are called in the right order.
TEST_F(BasicS4Test, DeleteSubscriberStoreErrorOnGetOnRemoteSite)
{
  // Set up the expectations. The local store should be called once, which
  // returns an AoR with a binding. This is then deleted from the local site,
  // so there's a chronos delete call and a set_data call. On the first remote
  // store there's an error on the get, so there's no further processing on that
  // site. The second remote site is still processed.
  {
    InSequence s;
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_chronos_delete_expectations();
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_failure(Store::Status::ERROR, 1);
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
  }

  uint64_t version = 1;
  HTTPCode rc = this->_s4->handle_delete("aor_id", version, 0);

  EXPECT_EQ(rc, 204);
}

// This test covers attempting to delete a subscriber where the subscriber
// is successfully deleted off the local site, but the subscriber isn't found
// on one of the remote sites.
// This test checks the order of expectations, to ensure that the local and
// remote stores are called in the right order.
TEST_F(BasicS4Test, DeleteSubscriberNotFoundOnRemoteSite)
{
  // Set up the expectations. The local store should be called once, which
  // returns an AoR with a binding. This is then deleted from the local site,
  // so there's a chronos delete call and a set_data call. On the first remote
  // store the subscriber isn't found, so there's no further processing on that
  // site. The second remote site is still processed.
  {
    InSequence s;
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_chronos_delete_expectations();
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_failure(Store::Status::NOT_FOUND, 1);
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
  }

  uint64_t version = 1;
  HTTPCode rc = this->_s4->handle_delete("aor_id", version, 0);

  EXPECT_EQ(rc, 204);
}

// This test covers attempting to delete a subscriber where the subscriber
// is successfully deleted off the local site, but there's contention when
// deleting the subscriber on one of the remote sites.
// This test checks the order of expectations, to ensure that the local and
// remote stores are called in the right order.
TEST_F(BasicS4Test, DeleteSubscriberContentionOnDeleteOnRemoteSite)
{
  // Set up the expectations. The local store should be called once, which
  // returns an AoR with a binding. This is then deleted from the local site,
  // so there's a chronos delete call and a set_data call. On the first remote
  // store there's the same calls, but the write fails due to contention.
  // There's no further processing on that site. The second remote site is still
  // processed.
  {
    InSequence s;
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_chronos_delete_expectations();
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

// This test covers attempting to delete a subscriber where the subscriber
// is successfully deleted off the local site, but there's a store error
// on one of the remote sites when deleting the subscriber.
// This test checks the order of expectations, to ensure that the local and
// remote stores are called in the right order.
TEST_F(BasicS4Test, DeleteSubscriberStoreErrorOnDeleteOnRemoteSite)
{
  // Set up the expectations. The local store should be called once, which
  // returns an AoR with a binding. This is then deleted from the local site,
  // so there's a chronos delete call and a set_data call. On the first remote
  // store there's the same calls, but the write fails due a store error.
  // There's no further processing on that site. The second remote site is still
  // processed.
  {
    InSequence s;
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_chronos_delete_expectations();
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

// This test covers adding a subscriber successfully to each site
TEST_F(BasicS4Test, AddSubscriber)
{
  set_data_expect_call(Store::Status::OK, 3);
  set_chronos_post_expectations();

  // EM TODO Check expectations on the various sets.

  AoR* aor = AoRTestUtils::build_aor("sip:6505550231@homedomain");
  HTTPCode rc = this->_s4->handle_put("aor_id", *aor, 0);

  EXPECT_EQ(rc, 200);

  delete aor; aor = NULL;
}

// This test covers adding a subscriber where the write fails on the local site.
TEST_F(BasicS4Test, AddSubscriberStoreErrorOnLocalSite)
{
  set_chronos_post_expectations();
  set_data_expect_call(Store::Status::ERROR, 1);

  AoR* aor = AoRTestUtils::build_aor("sip:6505550231@homedomain");
  HTTPCode rc = this->_s4->handle_put("aor_id", *aor, 0);

  EXPECT_EQ(rc, 500);

  delete aor; aor = NULL;
}

// This test covers adding a subscriber where the write fails on the local site
// due to contention
TEST_F(BasicS4Test, AddSubscriberContentionOnLocalSite)
{
  set_chronos_post_expectations();
  set_data_expect_call(Store::Status::DATA_CONTENTION, 1);

  AoR* aor = AoRTestUtils::build_aor("sip:6505550231@homedomain");
  HTTPCode rc = this->_s4->handle_put("aor_id", *aor, 0);

  EXPECT_EQ(rc, 412);

  delete aor; aor = NULL;
}

// This test covers a DELETE where the AoR doesn't exist in any store.
// This test checks the order of expectations, to ensure that the local and
// remote stores are called in the right order.
TEST_F(BasicS4Test, AddSubscriberThatAlreadyExistsOnRemoteSite)
{
  // Set up the expectations. The local store should be called once where we
  // successfully set the AoR. The AoR is then successfully set on the first
  // remote site, but fails on the second remote site with contention. This then
  // triggers the local site to send a patch command, where the remote site
  // then gets the data, applies the patch, then sets the data.
  {
    InSequence s;

    set_chronos_post_expectations();
    set_data_expect_call(Store::Status::OK, 1);
    set_data_expect_call(Store::Status::OK, 1);
    set_data_expect_call(Store::Status::DATA_CONTENTION, 1);
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
  }

  // EM TODO Check expectations on the various sets.
  AoR* aor = AoRTestUtils::build_aor("sip:6505550231@homedomain");
  HTTPCode rc = this->_s4->handle_put("aor_id", *aor, 0);

  EXPECT_EQ(rc, 200);

  delete aor; aor = NULL;
}

// This test covers adding a subscriber where the write fails on a remote store.
// This test checks the order of expectations, to ensure that the local and
// remote stores are called in the right order.
TEST_F(BasicS4Test, AddSubscriberStoreErrorOnRemoteSite)
{
  // Set up the expectations. The local store should be called once where we
  // successfully set the AoR. The AoR is then successfully set on the first
  // remote site, but fails on the second remote site with a store error. We
  // don't do any further processing on the remote site, and this doesn't
  // affect the return code.
  {
    InSequence s;

    set_chronos_post_expectations();
    set_data_expect_call(Store::Status::OK, 1);
    set_data_expect_call(Store::Status::OK, 1);
    set_data_expect_call(Store::Status::ERROR, 1);
  }

  AoR* aor = AoRTestUtils::build_aor("sip:6505550231@homedomain");
  HTTPCode rc = this->_s4->handle_put("aor_id", *aor, 0);

  EXPECT_EQ(rc, 200);

  delete aor; aor = NULL;
}

// This test updating a subscriber where the subscriber exists on all sites.
TEST_F(BasicS4Test, UpdateSubscriber)
{
  get_data_expect_call_success(aor_with_binding_subscription_associated_uris, 1, 3);
  set_data_expect_call(Store::Status::OK, 3);
  set_chronos_put_expectations();

  // EM-TODO. Make this tidier. Check the AoRs being sent.
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

// This test covers updating a subscriber where the subscriber doesn't exist on
// the local site.
TEST_F(BasicS4Test, UpdateSubscriberNotFoundOnLocalStore)
{
  get_data_expect_call_failure(Store::Status::NOT_FOUND, 1);

  PatchObject* po = AoRTestUtils::build_po("sip:6505550231@homedomain");
  AoR* aor = NULL;
  HTTPCode rc = this->_s4->handle_patch("aor_id", *po, &aor, 0);

  EXPECT_EQ(rc, 412);

  delete po; po = NULL;
  delete aor; aor = NULL;
}

// This test covers updating a subscriber where there's a store error on the local
// site when getting the subscriber's information.
TEST_F(BasicS4Test, UpdateSubscriberErrorOnGetOnLocalStore)
{
  get_data_expect_call_failure(Store::Status::ERROR, 1);

  PatchObject* po = AoRTestUtils::build_po("sip:6505550231@homedomain");
  AoR* aor = NULL;
  HTTPCode rc = this->_s4->handle_patch("aor_id", *po, &aor, 0);

  EXPECT_EQ(rc, 500);

  delete po; po = NULL;
  delete aor; aor = NULL;
}

// This test covers updating a subscriber where there's a store error on the local
// site when setting the subscriber's information.
TEST_F(BasicS4Test, UpdateSubscriberErrorOnWriteOnLocalStore)
{
  get_data_expect_call_success(aor_with_binding, 1, 1);
  set_chronos_put_expectations();
  set_data_expect_call(Store::Status::ERROR, 1);

  PatchObject* po = AoRTestUtils::build_po("sip:6505550231@homedomain");
  AoR* aor = NULL;
  HTTPCode rc = this->_s4->handle_patch("aor_id", *po, &aor, 0);

  EXPECT_EQ(rc, 500);

  delete po; po = NULL;
  delete aor; aor = NULL;
}

// This test covers updating a subscriber where there's data contention on the
// local site when setting the subscriber's information.
// This test checks the order of expectations, to ensure that the local and
// remote stores are called in the right order.
TEST_F(BasicS4Test, UpdateSubscriberContentionOnWriteOnLocalStore)
{
  // Set up the expectations. The local store should be called to get the
  // subscriber information, then there's contention on the write. The
  // processing is then repeated on the local site, then the remote sites
  // are processed successfully.
  {
    InSequence s;
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_chronos_put_expectations();
    set_data_expect_call(Store::Status::DATA_CONTENTION, 1);
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_chronos_put_expectations();
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

// This test covers updating a subscriber where there's data contention on a
// remote site when setting the subscriber's information.
// This test checks the order of expectations, to ensure that the local and
// remote stores are called in the right order.
TEST_F(BasicS4Test, UpdateSubscriberContentionOnWriteOnRemoteStore)
{
  // Set up the expectations. The subscriber is updated successfully on the
  // local site. There's contention on the first remote site, so the processing
  // is repeated. The second remote site is then processed successfully.
  {
    InSequence s;
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_chronos_put_expectations();
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_data_expect_call(Store::Status::DATA_CONTENTION, 1);
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

// This test covers updating a subscriber where there's a store error on a
// remote site when getting the subscriber's information.
// This test checks the order of expectations, to ensure that the local and
// remote stores are called in the right order.
TEST_F(BasicS4Test, UpdateSubscriberErrorOnGetOnRemoteStore)
{
  // Set up the expectations. The subscriber is updated successfully on the
  // local site. There's a store error on getting the subscriber information
  // on the first remote site, so no further processing is done for that site.
  // The second remote site is then processed successfully.
  {
    InSequence s;
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_chronos_put_expectations();
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_failure(Store::Status::ERROR, 1);
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

// This test covers updating a subscriber where there's a store error on a
// remote site when setting the subscriber's information.
// This test checks the order of expectations, to ensure that the local and
// remote stores are called in the right order.
TEST_F(BasicS4Test, UpdateSubscriberErrorOnWriteOnRemoteStore)
{
  // Set up the expectations. The subscriber is updated successfully on the
  // local site. There's a store error on writing the subscriber information
  // on the first remote site, so no further processing is done for that site.
  // The second remote site is then processed successfully.
  {
    InSequence s;
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_chronos_put_expectations();
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_data_expect_call(Store::Status::ERROR, 1);
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

// This test covers updating a subscriber where the subscriber doesn't exist on
// one of the remote stores.
// This test checks the order of expectations, to ensure that the local and
// remote stores are called in the right order.
TEST_F(BasicS4Test, UpdateSubscriberNotFoundOnRemoteStore)
{
  // Set up the expectations. The subscriber is updated successfully on the
  // local site. There subscriber isn't found on the first remote site, so
  // this rejects the patch with a 412. The local site then sends a put to the
  // remote site which is processed successfully. The second remote site is then
  // processed successfully.
  {
    InSequence s;
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_chronos_put_expectations();
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_failure(Store::Status::NOT_FOUND, 1);
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_success(aor_with_binding, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
  }

  PatchObject po;

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

  po._update_bindings.insert(std::make_pair("<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1", b1));
  po._update_subscriptions.insert(std::make_pair("1234", s1));
  po._increment_cseq = true;

  AoR* aor = NULL;
  HTTPCode rc = this->_s4->handle_patch("aor_id", po, &aor, 0);

  EXPECT_EQ(rc, 200);

  delete aor; aor = NULL;
}

// This tests that the right expiry time is set when writing data to the stores.
TEST_F(BasicS4Test, CheckExpiryTimeOnWrite)
{
  // EM-TODO Make sure the expiry time is correct.
  //int now = time(NULL);

  EXPECT_CALL(*_mock_store, set_data(_, _, _, _, _,  _, An<Store::Format>()))
//  EXPECT_CALL(*_mock_store, set_data(_, _, _, _, now + 100000 + 10, _, An<Store::Format>()))
    .Times(3)
    .WillRepeatedly(Return(Store::Status::OK));
  set_chronos_post_expectations();

  AoR* aor = AoRTestUtils::build_aor("sip:6505550231@homedomain");
  HTTPCode rc = this->_s4->handle_put("aor_id", *aor, 0);

  EXPECT_EQ(rc, 200);

  delete aor; aor = NULL;
}

/// The following tests check the Chronos sending timer when S4 writes to AoR.

// This test sends POST successfully to Chronos when S4 creates a new AoR.
TEST_F(BasicS4Test, ChronosTimerOnSubscriberCreation)
{
  // Build AoR
  std::string aor_id = "sip:6505550231@homedomain";
  AoR* aor = AoRTestUtils::build_aor(aor_id);

  // Build various arguments for Chronos call
  std::string opaque = "{\"aor_id\": \"" + aor_id + "\"}";
  std::string default_callback_uri = "/timers";
  std::map<std::string, uint32_t> tag_map;
  tag_map["REG"] = 1;
  tag_map["BIND"] = aor->get_bindings_count();
  tag_map["SUB"] = aor->get_subscriptions_count();

  // SM and Chronos expectations
  set_data_expect_call(Store::Status::OK, 3);
  EXPECT_CALL(*(this->_mock_chronos), send_post(_, 
                                                AoRTestUtils::EXPIRY, 
                                                default_callback_uri, 
                                                opaque, 
                                                _, 
                                                tag_map))
    .WillOnce(DoAll(SetArgReferee<0>(TIMER_ID),
                    Return(HTTP_OK)));

  HTTPCode rc = this->_s4->handle_put(aor_id, *aor, 0);

  // Check the timer id created during Chronos POST is written to AoR
  EXPECT_EQ(rc, 200);
  ASSERT_FALSE(aor == NULL);
  EXPECT_EQ(aor->_timer_id, TIMER_ID);

  delete aor; aor = NULL;
}

// This test sends PUT successfully to Chronos when S4 updates an existing AoR.
TEST_F(BasicS4Test, ChronosTimerOnSubscriberUpdate)
{
  // Build AoR
  std::string aor_id = "sip:6505550231@homedomain";
  AoR* aor = AoRTestUtils::build_aor(aor_id);

  // Build various arguments for Chronos call
  std::string opaque = "{\"aor_id\": \"" + aor_id + "\"}";
  std::string default_callback_uri = "/timers";
  std::map<std::string, uint32_t> tag_map;
  tag_map["REG"] = 1;
  tag_map["BIND"] = aor->get_bindings_count();
  tag_map["SUB"] = aor->get_subscriptions_count();

  // SM and Chronos expectations
  set_data_expect_call(Store::Status::OK, 3);
  EXPECT_CALL(*(this->_mock_chronos), send_put(TIMER_ID, 
                                               AoRTestUtils::EXPIRY, 
                                               default_callback_uri, 
                                               opaque, 
                                               _, 
                                               tag_map))
    .WillOnce(DoAll(SetArgReferee<0>(TIMER_ID),
                    Return(HTTP_OK)));

  HTTPCode rc = this->_s4->handle_put(aor_id, *aor, 0);

  EXPECT_EQ(rc, 200);

  delete aor; aor = NULL;
}

// This test sends DELETE unsuccessfully to Chronos when S4 deletes an AoR.
TEST_F(BasicS4Test, ChronosTimerOnSubscriberDeleteFail)
{
  get_data_expect_call_success(aor_with_binding, 1, 3);
  set_data_expect_call(Store::Status::OK, 3);
  set_chronos_delete_expectations();

  HTTPCode rc = this->_s4->handle_delete("aor_id", 1, 0);

  EXPECT_EQ(rc, 204);
}

