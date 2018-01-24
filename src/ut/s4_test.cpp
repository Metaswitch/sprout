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

// An AoR with a single binding, subscription, and Associated URIs. This is
// used in tests where we want to return a valid AoR, but there's no
// thorough testing of the exact get/set calls.
std::string AOR_WITH_BINDING = "{\"bindings\":{\"" + AoRTestUtils::BINDING_ID + "\":{\"uri\":\"<sip:6505550231@192.91.191.29:59934;transport=tcp;ob>\",\"cid\":\"gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq\",\"cseq\":17038,\"expires\":1516813835,\"priority\":0,\"params\":{\"+sip.ice\":\"\",\"+sip.instance\":\"\\\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\\\"\",\"reg-id\":\"1\"},\"path_headers\":[\"<sip:abcdefgh@bono1.homedomain;lr>\"],\"private_id\":\"6505550231\",\"emergency_reg\":false}},\"subscriptions\":{\"" + AoRTestUtils::SUBSCRIPTION_ID + "\":{\"req_uri\":\"<sip:6505550231@192.91.191.29:59934;transport=tcp;ob>\",\"from_uri\":\"<sip:5102175698@cw-ngv.com>\",\"from_tag\":\"4321\",\"to_uri\":\"<sip:5102175698@cw-ngv.com>\",\"to_tag\":\"1234\",\"cid\":\"xyzabc@192.91.191.29\",\"routes\":[\"sip:abcdefgh@bono1.homedomain;lr\"],\"expires\":1516813835}},\"associated-uris\":{\"uris\":[{\"uri\":\"aor_id\",\"barring\":false},{\"uri\":\"aor_id-wildcard!.*!\",\"barring\":false},{\"uri\":\"aor_id-barred\",\"barring\":true}],\"wildcard-mapping\":{\"distinct\":\"aor_id-wildcard!.*!\",\"wildcard\":\"aor_id-wildcard\"}},\"notify_cseq\":20,\"timer_id\":\"" + AoRTestUtils::TIMER_ID + "\",\"scscf-uri\":\"sip:scscf.sprout.homedomain:5058;transport=TCP\"}";

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

    cwtest_completely_control_time();
  }

  virtual ~BasicS4Test()
  {
    cwtest_reset_time();

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
  AstaireAoRStore::JsonSerializerDeserializer _serializer_deserializer;
  MockChronosConnection* _mock_chronos;
  S4* _remote_s4_1;
  S4* _remote_s4_2;
  S4* _s4;
};


// This test covers getting subscriber information where the subscriber is
// present on the local site.
TEST_F(BasicS4Test, GetSubscriberInfoFoundInLocalSite)
{
  AoR* expect_aor = AoRTestUtils::create_simple_aor("aor_id");
  std::string expect_str = _serializer_deserializer.serialize_aor(expect_aor);

  // Expect one get call to the local site only.
  get_data_expect_call_success(expect_str, 5, 1);

  AoR* get_aor = NULL;
  uint64_t version;
  HTTPCode rc = this->_s4->handle_get("aor_id", &get_aor, version, 0);

  // Check the return code, the version, and that the returned AoR matches
  // what we expected.
  EXPECT_EQ(rc, 200);
  ASSERT_FALSE(get_aor == NULL);
  EXPECT_EQ(version, 5);
  EXPECT_EQ(_serializer_deserializer.serialize_aor(get_aor), expect_str);

  delete get_aor; get_aor = NULL;
  delete expect_aor; expect_aor = NULL;
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
  AoR* expect_aor = AoRTestUtils::create_simple_aor("aor_id");
  std::string expect_str = _serializer_deserializer.serialize_aor(expect_aor);

  // Set up the expectations. The local store should be called once, which
  // returns an empty AoR. The first remote store is then called - this returns
  // an AoR with a binding. We should then write this back to the local store,
  // so expect a Chronos call and a set_data call. No other calls are expected,
  // we shouldn't contact any other remote stores.
  {
    InSequence s;
    get_data_expect_call_failure(Store::Status::NOT_FOUND, 1);
    get_data_expect_call_failure(Store::Status::NOT_FOUND, 1);
    get_data_expect_call_success(expect_str, 5, 1);
    set_chronos_put_expectations();
    EXPECT_CALL(*_mock_store, set_data(_, _, _, _, _, _, An<Store::Format>()))
      .WillOnce(Return(Store::Status::OK));
  }

  AoR* get_aor = NULL;
  uint64_t version;
  HTTPCode rc = this->_s4->handle_get("aor_id", &get_aor, version, 0);

  // Check the return code, and check that the returned AoR is as expected. Note
  // that the version number is 0 rather than 5 (as the CAS is reset on the
  // empty site).
  EXPECT_EQ(rc, 200);
  ASSERT_FALSE(get_aor == NULL);
  EXPECT_EQ(version, 0);
  EXPECT_EQ(_serializer_deserializer.serialize_aor(get_aor), expect_str);

  delete expect_aor; expect_aor = NULL;
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
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
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
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_chronos_put_expectations();
    set_data_expect_call(Store::Status::DATA_CONTENTION, 1);
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
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
  get_data_expect_call_success(AOR_WITH_BINDING, 1, 3);
  EXPECT_CALL(*_mock_store, set_data(_, "aor_id", _, _, 10, _, An<Store::Format>()))
    .Times(3)
    .WillRepeatedly(Return(Store::Status::OK));
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
  get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
  set_data_expect_call(Store::Status::DATA_CONTENTION, 1);
  set_chronos_delete_expectations();

  HTTPCode rc = this->_s4->handle_delete("aor_id", 1, 0);

  EXPECT_EQ(rc, 412);
}

// This test covers attempting to delete a subscriber where there's a store
// error on trying to write the delete to the local store.
TEST_F(BasicS4Test, DeleteSubscriberStoreErrorOnWrite)
{
  get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
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
  get_data_expect_call_success(AOR_WITH_BINDING, 10, 1);

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
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_chronos_delete_expectations();
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_failure(Store::Status::ERROR, 1);
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
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
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_chronos_delete_expectations();
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_failure(Store::Status::NOT_FOUND, 1);
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
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
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_chronos_delete_expectations();
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_data_expect_call(Store::Status::DATA_CONTENTION, 1);
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
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
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_chronos_delete_expectations();
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_data_expect_call(Store::Status::ERROR, 1);
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
  }

  uint64_t version = 1;
  HTTPCode rc = this->_s4->handle_delete("aor_id", version, 0);

  EXPECT_EQ(rc, 204);
}

// This test covers adding a subscriber successfully to each site
TEST_F(BasicS4Test, AddSubscriber)
{
  AoR* aor = AoRTestUtils::create_simple_aor("aor_id", true, false);
  std::string expect_str = _serializer_deserializer.serialize_aor(aor);

  EXPECT_CALL(*_mock_store, set_data(_, "aor_id", expect_str, 0, _, _, An<Store::Format>()))
    .Times(3)
    .WillRepeatedly(Return(Store::Status::OK));
  set_chronos_post_expectations();

  HTTPCode rc = this->_s4->handle_put("aor_id", *aor, 0);

  EXPECT_EQ(rc, 200);

  delete aor; aor = NULL;
}

// This test covers adding a subscriber where the write fails on the local site.
TEST_F(BasicS4Test, AddSubscriberStoreErrorOnLocalSite)
{
  set_chronos_post_expectations();
  set_data_expect_call(Store::Status::ERROR, 1);

  AoR* aor = AoRTestUtils::create_simple_aor("aor_id", true, false);
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

  AoR* aor = AoRTestUtils::create_simple_aor("aor_id", true, false);
  HTTPCode rc = this->_s4->handle_put("aor_id", *aor, 0);

  EXPECT_EQ(rc, 412);

  delete aor; aor = NULL;
}

// This test covers a DELETE where the AoR doesn't exist in any store.
// This test checks the order of expectations, to ensure that the local and
// remote stores are called in the right order.
TEST_F(BasicS4Test, AddSubscriberThatAlreadyExistsOnRemoteSite)
{
  AoR* aor = AoRTestUtils::create_simple_aor("aor_id", true, false);
  std::string expect_str = _serializer_deserializer.serialize_aor(aor);

  // Set up the expectations. The local store should be called once where we
  // successfully set the AoR. The AoR is then successfully set on the first
  // remote site, but fails on the second remote site with contention. This then
  // triggers the local site to send a patch command, where the remote site
  // then gets the data, applies the patch, then sets the data.
  {
    InSequence s;

    set_chronos_post_expectations();
    EXPECT_CALL(*_mock_store, set_data(_, "aor_id", expect_str, 0, _, _, An<Store::Format>()))
     .WillOnce(Return(Store::Status::OK));
    EXPECT_CALL(*_mock_store, set_data(_, "aor_id", expect_str, 0, _, _, An<Store::Format>()))
     .WillOnce(Return(Store::Status::OK));
    set_data_expect_call(Store::Status::DATA_CONTENTION, 1);
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
  }

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

  AoR* aor = AoRTestUtils::create_simple_aor("aor_id", true, false);
  HTTPCode rc = this->_s4->handle_put("aor_id", *aor, 0);

  EXPECT_EQ(rc, 200);

  delete aor; aor = NULL;
}

// This test updating a subscriber where the subscriber exists on all sites.
TEST_F(BasicS4Test, UpdateSubscriber)
{
  PatchObject* po = AoRTestUtils::create_simple_patch("aor_id");

  AoR* aor = AoRTestUtils::create_simple_aor("aor_id");
  std::string current_str = _serializer_deserializer.serialize_aor(aor);

  // The patch above acts to increment the CSeq, and change the expiry of the
  // binding and subscription. Make the corresponding changes to the AoR (this
  // replicates the function patch_aor).
  aor->_notify_cseq++;
  aor->get_binding(AoRTestUtils::BINDING_ID)->_expires += 300;
  aor->get_subscription(AoRTestUtils::SUBSCRIPTION_ID)->_expires += 300;
  std::string changed_str = _serializer_deserializer.serialize_aor(aor);

  // Expect to get the original AoR on each get call, and expect that this has
  // been changed to the changed_str on the set calls.
  get_data_expect_call_success(current_str, 1, 3);
  EXPECT_CALL(*_mock_store, set_data(_, "aor_id", changed_str, _, _, _, An<Store::Format>()))
   .Times(3)
   .WillRepeatedly(Return(Store::Status::OK));
  set_chronos_put_expectations();

  AoR* patched_aor = NULL;
  HTTPCode rc = this->_s4->handle_patch("aor_id", *po, &patched_aor, 0);

  EXPECT_EQ(rc, 200);
  ASSERT_TRUE(patched_aor != NULL);
  EXPECT_EQ(_serializer_deserializer.serialize_aor(patched_aor), changed_str);

  delete po; po = NULL;
  delete aor; aor = NULL;
  delete patched_aor; patched_aor = NULL;
}

// This test updating a subscriber where the subscriber exists on all sites with
// a complicated patch.
// This test checks the order of expectations, to ensure that the local and
// remote stores are called in the right order.
TEST_F(BasicS4Test, UpdateSubscriberComplexPatch)
{
  int now = time(NULL);

  PatchObject* po = AoRTestUtils::create_complex_patch("aor_id");

  // Create a simple AoR, and add a binding and subscription to it
  AoR* aor = AoRTestUtils::create_simple_aor("aor_id");
  Binding* b3 = AoRTestUtils::build_binding("aor_id", now, AoRTestUtils::CONTACT_URI, 600);
  aor->_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID + "3", b3));
  Subscription* s3 = AoRTestUtils::build_subscription(AoRTestUtils::SUBSCRIPTION_ID + "3", now, 600);
  aor->_subscriptions.insert(std::make_pair(AoRTestUtils::SUBSCRIPTION_ID + "3", s3));
  std::string current_str = _serializer_deserializer.serialize_aor(aor);

  // On one of the remote sites have the CSeq be larger than the CSeq on the local site
  aor->_notify_cseq = 25;
  std::string current_remote_str = _serializer_deserializer.serialize_aor(aor);

  // The patch above acts to increase the expiry of binding/subscription 1, add
  // binding/subscription 2, remove binding/subscription 3, set the cseq to 11,
  // and update the associated URIs. It also attempts to remove
  // binding/subscription 4, but these don't exist.
  aor->_notify_cseq = 11;
  aor->get_binding(AoRTestUtils::BINDING_ID)->_expires += 300;
  aor->get_subscription(AoRTestUtils::SUBSCRIPTION_ID)->_expires += 300;
  Binding* b2 = AoRTestUtils::build_binding("aor_id", now, AoRTestUtils::CONTACT_URI, 600);
  aor->_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID + "2", b2));
  Subscription* s2 = AoRTestUtils::build_subscription(AoRTestUtils::SUBSCRIPTION_ID + "2", now, 600);
  aor->_subscriptions.insert(std::make_pair(AoRTestUtils::SUBSCRIPTION_ID + "2", s2));
  aor->remove_binding(AoRTestUtils::BINDING_ID + "3");
  aor->remove_subscription(AoRTestUtils::SUBSCRIPTION_ID + "3");
  aor->_associated_uris.add_uri("aor_id-wildcard!.*!", false);
  aor->_associated_uris.add_uri("aor_id-barred", true);
  aor->_associated_uris.add_wildcard_mapping("aor_id-wildcard", "aor_id-wildcard!.*!");
  std::string changed_str = _serializer_deserializer.serialize_aor(aor);

  // The remote site shouldn't have decreased its CSeq
  aor->_notify_cseq = 25;
  std::string changed_remote_str = _serializer_deserializer.serialize_aor(aor);

  // Set up the expectations. The local store and the first remote store should
  // get the current_str, and set the changed_str. The second remote store
  // get the current_remote_str which has an increased CSeq. Its set should also
  // have the increased CSeq.
  {
    InSequence s;

    get_data_expect_call_success(current_str, 1, 1);
    set_chronos_put_expectations();
    EXPECT_CALL(*_mock_store, set_data(_, "aor_id", changed_str, _, _, _, An<Store::Format>()))
     .WillOnce(Return(Store::Status::OK));
    get_data_expect_call_success(current_str, 1, 1);
    EXPECT_CALL(*_mock_store, set_data(_, "aor_id", changed_str, _, _, _, An<Store::Format>()))
     .WillOnce(Return(Store::Status::OK));
    get_data_expect_call_success(current_remote_str, 1, 1);
    EXPECT_CALL(*_mock_store, set_data(_, "aor_id", changed_remote_str, _, _, _, An<Store::Format>()))
     .WillOnce(Return(Store::Status::OK));
  }

  AoR* patched_aor = NULL;
  HTTPCode rc = this->_s4->handle_patch("aor_id", *po, &patched_aor, 0);

  EXPECT_EQ(rc, 200);
  ASSERT_TRUE(patched_aor != NULL);
  EXPECT_EQ(_serializer_deserializer.serialize_aor(patched_aor), changed_str);

  delete po; po = NULL;
  delete aor; aor = NULL;
  delete patched_aor; patched_aor = NULL;
}

// This test covers updating a subscriber where the subscriber doesn't exist on
// the local site.
TEST_F(BasicS4Test, UpdateSubscriberNotFoundOnLocalStore)
{
  get_data_expect_call_failure(Store::Status::NOT_FOUND, 1);

  PatchObject* po = AoRTestUtils::create_simple_patch("sip:6505550231@homedomain");
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

  PatchObject* po = AoRTestUtils::create_simple_patch("sip:6505550231@homedomain");
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
  get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
  set_chronos_put_expectations();
  set_data_expect_call(Store::Status::ERROR, 1);

  PatchObject* po = AoRTestUtils::create_simple_patch("sip:6505550231@homedomain");
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
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_chronos_put_expectations();
    set_data_expect_call(Store::Status::DATA_CONTENTION, 1);
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_chronos_put_expectations();
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
  }

  PatchObject* po = AoRTestUtils::create_simple_patch("sip:6505550231@homedomain");
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
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_chronos_put_expectations();
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_data_expect_call(Store::Status::DATA_CONTENTION, 1);
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
  }

  PatchObject* po = AoRTestUtils::create_simple_patch("sip:6505550231@homedomain");
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
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_chronos_put_expectations();
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_failure(Store::Status::ERROR, 1);
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
  }

  PatchObject* po = AoRTestUtils::create_simple_patch("sip:6505550231@homedomain");
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
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_chronos_put_expectations();
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_data_expect_call(Store::Status::ERROR, 1);
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
  }

  PatchObject* po = AoRTestUtils::create_simple_patch("sip:6505550231@homedomain");
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
  // local site. The subscriber isn't found on the first remote site, so
  // this rejects the patch with a 412. The local site then sends a put to the
  // remote site which is processed successfully. The second remote site is then
  // processed successfully.
  {
    InSequence s;
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_chronos_put_expectations();
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_failure(Store::Status::NOT_FOUND, 1);
    set_data_expect_call(Store::Status::OK, 1);
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    set_data_expect_call(Store::Status::OK, 1);
  }

  PatchObject po;

  AoR* aor = NULL;
  HTTPCode rc = this->_s4->handle_patch("aor_id", po, &aor, 0);

  EXPECT_EQ(rc, 200);

  delete aor; aor = NULL;
}

// This tests that the right expiry time is set when writing data to the stores.
TEST_F(BasicS4Test, CheckExpiryTimeOnWrite)
{
  int now = time(NULL);

  // The expiry time should be the current time, plus the longest expiry time
  // from the AoR, plus a 10 second buffer time.
  EXPECT_CALL(*_mock_store, set_data(_, _, _, _, now + 300 + 10, _, An<Store::Format>()))
    .Times(3)
    .WillRepeatedly(Return(Store::Status::OK));
  set_chronos_post_expectations();

  AoR* aor = AoRTestUtils::create_simple_aor("aor_id", true, false);
  HTTPCode rc = this->_s4->handle_put("aor_id", *aor, 0);

  EXPECT_EQ(rc, 200);

  delete aor; aor = NULL;
}

// This tests that if the last binding in an AoR is removed, the AoR is cleared
TEST_F(BasicS4Test, ClearUpEmptyAoR)
{
  // The get call returns an AoR with one binding and one subscription. The
  // patch removes the binding. S4 then removes the subscription, as shown
  // by the expiry time of 10 on the set call, and the send_delete chronos
  // call. We then have the local store return an error to stop the
  // processing.
  get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
  EXPECT_CALL(*_mock_store, set_data(_, _, _, _, 10, _, An<Store::Format>()))
    .WillOnce(Return(Store::Status::ERROR));
  set_chronos_delete_expectations();

  PatchObject po;
  po._remove_bindings.push_back(AoRTestUtils::BINDING_ID);
  AoR* aor = NULL;
  HTTPCode rc = this->_s4->handle_patch("aor_id", po, &aor, 0);

  EXPECT_EQ(rc, 500);

  delete aor; aor = NULL;
}

// YH-TODO
// Comments explaining what each test does
// Tests where the Chronos call fails
// Check the timer ID in the AoR
TEST_F(BasicS4Test, ChronosTimerOnSubscriberCreation)
{
  std::string timer_str;
  std::string aor_id = "aor_id";
  std::string opaque = "{\"aor_id\": \"" + aor_id + "\"}";

  {
    InSequence s;
    get_data_expect_call_failure(Store::Status::NOT_FOUND, 1);
    get_data_expect_call_success(AOR_WITH_BINDING, 1, 1);
    EXPECT_CALL(*(this->_mock_chronos), send_put(_, _, _, opaque, _, _))
      .WillOnce(Return(HTTP_OK));
    EXPECT_CALL(*_mock_store, set_data(_, _, _, _, _, _, An<Store::Format>()))
      .WillOnce(DoAll(SaveArg<0>(&timer_str),
                      Return(Store::Status::OK)));
  }

  AoR* get_aor = NULL;
  uint64_t version;
  HTTPCode rc = this->_s4->handle_get("aor_id", &get_aor, version, 0);

  EXPECT_EQ(rc, 200);
  ASSERT_FALSE(get_aor == NULL);
  EXPECT_FALSE(get_aor->bindings().empty());

  delete get_aor; get_aor = NULL;
}

TEST_F(BasicS4Test, ChronosTimerOnSubscriberUpdate)
{
  std::string aor_id = "aor_id";
  std::string opaque = "{\"aor_id\": \"" + aor_id + "\"}";

  EXPECT_CALL(*(this->_mock_chronos), send_post(_, _, "/timers", opaque, _, _))
    .WillOnce(DoAll(SetArgReferee<0>(AoRTestUtils::TIMER_ID),
                    Return(HTTP_OK)));
  set_data_expect_call(Store::Status::DATA_CONTENTION, 1);

  AoR* aor = AoRTestUtils::create_simple_aor("aor_id", true, false);
  HTTPCode rc = this->_s4->handle_put(aor_id, *aor, 0);

  EXPECT_EQ(rc, 412);

  delete aor; aor = NULL;
}
