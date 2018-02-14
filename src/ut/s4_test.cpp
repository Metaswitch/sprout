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
#include "mock_subscriber_manager.h"

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
std::string aor_template(std::string expires)
{
  return "{\"bindings\":{\"" + AoRTestUtils::BINDING_ID + "\":{\"uri\":\"<sip:6505550231@192.91.191.29:59934;transport=tcp;ob>\",\"cid\":\"gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq\",\"cseq\":17038,\"expires\":" + expires + ",\"priority\":0,\"params\":{\"+sip.ice\":\"\",\"+sip.instance\":\"\\\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\\\"\",\"reg-id\":\"1\"},\"path_headers\":[\"<sip:abcdefgh@bono1.homedomain;lr>\"],\"private_id\":\"6505550231\",\"emergency_reg\":false}},\"subscriptions\":{\"" + AoRTestUtils::SUBSCRIPTION_ID + "\":{\"req_uri\":\"<sip:6505550231@192.91.191.29:59934;transport=tcp;ob>\",\"from_uri\":\"<sip:5102175698@cw-ngv.com>\",\"from_tag\":\"4321\",\"to_uri\":\"<sip:5102175698@cw-ngv.com>\",\"to_tag\":\"1234\",\"cid\":\"xyzabc@192.91.191.29\",\"routes\":[\"sip:abcdefgh@bono1.homedomain;lr\"],\"expires\":" + expires + "}},\"associated-uris\":{\"uris\":[{\"uri\":\"aor_id\",\"barring\":false},{\"uri\":\"aor_id-wildcard!.*!\",\"barring\":false},{\"uri\":\"aor_id-barred\",\"barring\":true}],\"wildcard-mapping\":{\"distinct\":\"aor_id-wildcard!.*!\",\"wildcard\":\"aor_id-wildcard\"}},\"notify_cseq\":20,\"timer_id\":\"" + AoRTestUtils::TIMER_ID + "\",\"scscf-uri\":\"sip:scscf.sprout.homedomain:5058;transport=TCP\"}";
}

// Leave buffer time to ensure this expiry time hasn't passed when reading AoR
// from remote site. All tests using this AoR will not have mimic timer pop.
std::string not_expired = std::to_string(time(NULL) + 500);
std::string AOR_WITH_BINDING = aor_template(not_expired);

// Tests that use this expired binding will have mimic timer pop.
std::string expired = std::to_string(time(NULL) - 1);
std::string AOR_WITH_BINDING_EXPIRED = aor_template(expired);

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
    _mock_store1 = new MockStore();
    _mock_store2 = new MockStore();
    _mock_store3 = new MockStore();
    _aor_store1 = new AstaireAoRStore(_mock_store1);
    _aor_store2 = new AstaireAoRStore(_mock_store2);
    _aor_store3 = new AstaireAoRStore(_mock_store3);
    _mock_chronos = new MockChronosConnection("chronos");
    _remote_s4_1 = new S4("site2", _aor_store2);
    _remote_s4_2 = new S4("site3", _aor_store3);
    _s4 = new S4("site1",
                 _mock_chronos,
                 "/timers",
                 _aor_store1,
                 {_remote_s4_1, _remote_s4_2});
    _mock_sm = new MockSubscriberManager();
    _s4->register_timer_pop_consumer(_mock_sm);

    cwtest_completely_control_time();
  }

  virtual ~BasicS4Test()
  {
    cwtest_reset_time();

    delete _mock_sm; _mock_sm = NULL;
    delete _s4; _s4 = NULL;
    delete _remote_s4_1, _remote_s4_1 = NULL;
    delete _remote_s4_2, _remote_s4_2 = NULL;
    delete _mock_chronos; _mock_chronos = NULL;
    delete _aor_store1; _aor_store1 = NULL;
    delete _aor_store2; _aor_store2 = NULL;
    delete _aor_store3; _aor_store3 = NULL;
    delete _mock_store1; _mock_store1 = NULL;
    delete _mock_store2; _mock_store2 = NULL;
    delete _mock_store3; _mock_store3 = NULL;
  }

  // Set up a single expectation for getting data from a store where the store
  // responds successfully
  void get_data_expect_call_success(MockStore* mock_store,
                                    std::string aor_data,
                                    int cas)
  {
    EXPECT_CALL(*mock_store, get_data(_, _, _, _, _, An<Store::Format>()))
      .WillOnce(DoAll(SetArgReferee<2>(std::string(aor_data)),
                      SetArgReferee<3>(cas),
                      Return(Store::OK)));
  }

  // Set up a single expectation for getting data from a store where there's a
  // store error
  void get_data_expect_call_failure(MockStore* mock_store,
                                    Store::Status rc)
  {
    EXPECT_CALL(*mock_store, get_data(_, _, _, _, _, An<Store::Format>()))
      .WillOnce(Return(rc));
  }

  // Set up a single expectation for writing data to the store.
  void set_data_expect_call(MockStore* mock_store,
                            Store::Status rc)
  {
    EXPECT_CALL(*mock_store, set_data(_, _, _, _, _, _, An<Store::Format>()))
      .WillOnce(Return(rc));
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
  MockStore* _mock_store1;
  MockStore* _mock_store2;
  MockStore* _mock_store3;
  AstaireAoRStore* _aor_store1;
  AstaireAoRStore* _aor_store2;
  AstaireAoRStore* _aor_store3;
  AstaireAoRStore::JsonSerializerDeserializer _serializer_deserializer;
  MockChronosConnection* _mock_chronos;
  S4* _remote_s4_1;
  S4* _remote_s4_2;
  S4* _s4;
  MockSubscriberManager* _mock_sm;
};


// This test covers getting subscriber information where the subscriber is
// present on the local site.
TEST_F(BasicS4Test, GetSubscriberInfoFoundInLocalSite)
{
  AoR* expect_aor = AoRTestUtils::create_simple_aor("aor_id");
  std::string expect_str = _serializer_deserializer.serialize_aor(expect_aor);

  // Expect one get call to the local site only.
  get_data_expect_call_success(_mock_store1, expect_str, 5);

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
  get_data_expect_call_failure(_mock_store1, Store::Status::ERROR);

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
  get_data_expect_call_failure(_mock_store1, Store::Status::NOT_FOUND);
  get_data_expect_call_failure(_mock_store2, Store::Status::NOT_FOUND);
  get_data_expect_call_failure(_mock_store3, Store::Status::NOT_FOUND);

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
  // returns not found. The first remote store is then called - this returns
  // an AoR with a binding. We should then write this back to the local store,
  // so expect a Chronos call and a set_data call. No other calls are expected,
  // we shouldn't contact any other remote stores.
  {
    InSequence s;
    get_data_expect_call_failure(_mock_store1, Store::Status::NOT_FOUND);
    get_data_expect_call_success(_mock_store2, expect_str, 5);
    set_chronos_put_expectations();
    EXPECT_CALL(*_mock_store1, set_data(_, _, expect_str, _, _, _, An<Store::Format>()))
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

    get_data_expect_call_failure(_mock_store1, Store::Status::NOT_FOUND);
    get_data_expect_call_success(_mock_store2, AOR_WITH_BINDING, 1);
    set_chronos_put_expectations();
    set_data_expect_call(_mock_store1, Store::Status::ERROR);
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
    get_data_expect_call_failure(_mock_store1, Store::Status::NOT_FOUND);
    get_data_expect_call_success(_mock_store2, AOR_WITH_BINDING, 1);
    set_chronos_put_expectations();
    set_data_expect_call(_mock_store1, Store::Status::DATA_CONTENTION);
    get_data_expect_call_success(_mock_store1, AOR_WITH_BINDING, 1);
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
  get_data_expect_call_success(_mock_store1, AOR_WITH_BINDING, 1);
  get_data_expect_call_success(_mock_store2, AOR_WITH_BINDING, 1);
  get_data_expect_call_success(_mock_store3, AOR_WITH_BINDING, 1);
  EXPECT_CALL(*_mock_store1, set_data(_, "aor_id", _, _, 0, _, An<Store::Format>()))
    .WillOnce(Return(Store::Status::OK));
  EXPECT_CALL(*_mock_store2, set_data(_, "aor_id", _, _, 0, _, An<Store::Format>()))
    .WillOnce(Return(Store::Status::OK));
  EXPECT_CALL(*_mock_store3, set_data(_, "aor_id", _, _, 0, _, An<Store::Format>()))
    .WillOnce(Return(Store::Status::OK));
  set_chronos_delete_expectations();

  HTTPCode rc = this->_s4->handle_delete("aor_id", 1, 0);

  EXPECT_EQ(rc, 204);
}

// This test covers attempting to delete a subscriber where the subscriber
// doesn't exist on the local site - the delete is rejected with a 412.
TEST_F(BasicS4Test, DeleteSubscriberNotFoundOnLocalSite)
{
  get_data_expect_call_failure(_mock_store1, Store::Status::NOT_FOUND);

  HTTPCode rc = this->_s4->handle_delete("aor_id", 1, 0);

  EXPECT_EQ(rc, 412);
}

// This test covers attempting to delete a subscriber where there's a store
// error on trying to get the subscriber's information.
TEST_F(BasicS4Test, DeleteSubscriberStoreErrorOnGet)
{
  get_data_expect_call_failure(_mock_store1, Store::Status::ERROR);

  HTTPCode rc = this->_s4->handle_delete("aor_id", 1, 0);

  EXPECT_EQ(rc, 500);
}

// This test covers attempting to delete a subscriber where there's contention
// on trying to write the delete to the local store.
TEST_F(BasicS4Test, DeleteSubscriberContentionOnWrite)
{
  get_data_expect_call_success(_mock_store1, AOR_WITH_BINDING, 1);
  set_data_expect_call(_mock_store1, Store::Status::DATA_CONTENTION);
  set_chronos_delete_expectations();

  HTTPCode rc = this->_s4->handle_delete("aor_id", 1, 0);

  EXPECT_EQ(rc, 412);
}

// This test covers attempting to delete a subscriber where there's a store
// error on trying to write the delete to the local store.
TEST_F(BasicS4Test, DeleteSubscriberStoreErrorOnWrite)
{
  get_data_expect_call_success(_mock_store1, AOR_WITH_BINDING, 1);
  set_data_expect_call(_mock_store1, Store::Status::ERROR);
  set_chronos_delete_expectations();

  uint64_t version = 1;

  HTTPCode rc = this->_s4->handle_delete("aor_id", version, 0);

  EXPECT_EQ(rc, 500);
}

// This test covers attempting to delete a subscriber where the version
// to delete doesn't match the subscriber to delete.
TEST_F(BasicS4Test, DeleteSubscriberVersionMismatch)
{
  get_data_expect_call_success(_mock_store1, AOR_WITH_BINDING, 10);

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
    get_data_expect_call_success(_mock_store1, AOR_WITH_BINDING, 1);
    set_chronos_delete_expectations();
    set_data_expect_call(_mock_store1, Store::Status::OK);
    get_data_expect_call_failure(_mock_store2, Store::Status::ERROR);
    get_data_expect_call_success(_mock_store3, AOR_WITH_BINDING, 1);
    set_data_expect_call(_mock_store3, Store::Status::OK);
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
    get_data_expect_call_success(_mock_store1, AOR_WITH_BINDING, 1);
    set_chronos_delete_expectations();
    set_data_expect_call(_mock_store1, Store::Status::OK);
    get_data_expect_call_failure(_mock_store2, Store::Status::NOT_FOUND);
    get_data_expect_call_success(_mock_store3, AOR_WITH_BINDING, 1);
    set_data_expect_call(_mock_store3, Store::Status::OK);
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
  // The delete is retried, then the second remote site is processed.
  {
    InSequence s;
    get_data_expect_call_success(_mock_store1, AOR_WITH_BINDING, 1);
    set_chronos_delete_expectations();
    set_data_expect_call(_mock_store1, Store::Status::OK);
    get_data_expect_call_success(_mock_store2, AOR_WITH_BINDING, 1);
    set_data_expect_call(_mock_store2, Store::Status::DATA_CONTENTION);
    get_data_expect_call_success(_mock_store2, AOR_WITH_BINDING, 1);
    set_data_expect_call(_mock_store2, Store::Status::OK);
    get_data_expect_call_success(_mock_store3, AOR_WITH_BINDING, 1);
    set_data_expect_call(_mock_store3, Store::Status::OK);
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
    get_data_expect_call_success(_mock_store1, AOR_WITH_BINDING, 1);
    set_chronos_delete_expectations();
    set_data_expect_call(_mock_store1, Store::Status::OK);
    get_data_expect_call_success(_mock_store2, AOR_WITH_BINDING, 1);
    set_data_expect_call(_mock_store2, Store::Status::ERROR);
    get_data_expect_call_success(_mock_store3, AOR_WITH_BINDING, 1);
    set_data_expect_call(_mock_store3, Store::Status::OK);
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

  EXPECT_CALL(*_mock_store1, set_data(_, "aor_id", expect_str, 0, _, _, An<Store::Format>()))
    .WillOnce(Return(Store::Status::OK));
  EXPECT_CALL(*_mock_store2, set_data(_, "aor_id", expect_str, 0, _, _, An<Store::Format>()))
    .WillOnce(Return(Store::Status::OK));
  EXPECT_CALL(*_mock_store3, set_data(_, "aor_id", expect_str, 0, _, _, An<Store::Format>()))
    .WillOnce(Return(Store::Status::OK));
  set_chronos_post_expectations();

  HTTPCode rc = this->_s4->handle_put("aor_id", *aor, 0);

  EXPECT_EQ(rc, 200);

  delete aor; aor = NULL;
}

// This test covers adding a subscriber where the write fails on the local site.
TEST_F(BasicS4Test, AddSubscriberStoreErrorOnLocalSite)
{
  set_chronos_post_expectations();
  set_data_expect_call(_mock_store1, Store::Status::ERROR);

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
  set_data_expect_call(_mock_store1, Store::Status::DATA_CONTENTION);

  AoR* aor = AoRTestUtils::create_simple_aor("aor_id", true, false);
  HTTPCode rc = this->_s4->handle_put("aor_id", *aor, 0);

  EXPECT_EQ(rc, 412);

  delete aor; aor = NULL;
}

// This test covers adding a subscriber where the subscriber already exists on
// the remote site.
// This test checks the order of expectations, to ensure that the local and
// remote stores are called in the right order.
TEST_F(BasicS4Test, AddSubscriberThatAlreadyExistsOnRemoteSite)
{
  AoR* aor = AoRTestUtils::create_simple_aor("aor_id", true);
  std::string expect_str = _serializer_deserializer.serialize_aor(aor);
  aor->_notify_cseq = 21;
  std::string expect_patched_str = _serializer_deserializer.serialize_aor(aor);
  aor->_timer_id = "";

  std::string exp;
  // Set up the expectations. The local store should be called once where we
  // successfully set the AoR. The AoR is then successfully set on the first
  // remote site, but fails on the second remote site with contention. This then
  // triggers the local site to send a patch command, where the remote site
  // then gets the data, applies the patch, then sets the data.
  {
    InSequence s;

    set_chronos_post_expectations();
    set_data_expect_call(_mock_store1, Store::Status::OK);
    set_data_expect_call(_mock_store2, Store::Status::OK);
    set_data_expect_call(_mock_store3, Store::Status::DATA_CONTENTION);
    get_data_expect_call_success(_mock_store3, AOR_WITH_BINDING, 1);
    EXPECT_CALL(*_mock_store3, set_data(_, "aor_id", expect_patched_str, _, _, _, An<Store::Format>()))
     .WillOnce(Return(Store::Status::OK));
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
    set_data_expect_call(_mock_store1, Store::Status::OK);
    set_data_expect_call(_mock_store2, Store::Status::OK);
    set_data_expect_call(_mock_store3, Store::Status::ERROR);
  }

  AoR* aor = AoRTestUtils::create_simple_aor("aor_id", true, false);
  HTTPCode rc = this->_s4->handle_put("aor_id", *aor, 0);

  EXPECT_EQ(rc, 200);

  delete aor; aor = NULL;
}

// This tests updating a subscriber where the subscriber exists on all sites.
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
  get_data_expect_call_success(_mock_store1, current_str, 1);
  get_data_expect_call_success(_mock_store2, current_str, 1);
  get_data_expect_call_success(_mock_store3, current_str, 1);
  EXPECT_CALL(*_mock_store1, set_data(_, "aor_id", changed_str, _, _, _, An<Store::Format>()))
   .WillOnce(Return(Store::Status::OK));
  EXPECT_CALL(*_mock_store2, set_data(_, "aor_id", changed_str, _, _, _, An<Store::Format>()))
   .WillOnce(Return(Store::Status::OK));
  EXPECT_CALL(*_mock_store3, set_data(_, "aor_id", changed_str, _, _, _, An<Store::Format>()))
   .WillOnce(Return(Store::Status::OK));
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

// This tests updating a subscriber where the subscriber exists on all sites with
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

    get_data_expect_call_success(_mock_store1, current_str, 1);
    set_chronos_put_expectations();
    EXPECT_CALL(*_mock_store1, set_data(_, "aor_id", changed_str, _, _, _, An<Store::Format>()))
     .WillOnce(Return(Store::Status::OK));
    get_data_expect_call_success(_mock_store2, current_str, 1);
    EXPECT_CALL(*_mock_store2, set_data(_, "aor_id", changed_str, _, _, _, An<Store::Format>()))
     .WillOnce(Return(Store::Status::OK));
    get_data_expect_call_success(_mock_store3, current_remote_str, 1);
    EXPECT_CALL(*_mock_store3, set_data(_, "aor_id", changed_remote_str, _, _, _, An<Store::Format>()))
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
  get_data_expect_call_failure(_mock_store1, Store::Status::NOT_FOUND);

  PatchObject* po = AoRTestUtils::create_simple_patch("sip:6505550231@homedomain");
  AoR* aor = NULL;
  HTTPCode rc = this->_s4->handle_patch("aor_id", *po, &aor, 0);

  EXPECT_EQ(rc, 404);

  delete po; po = NULL;
  delete aor; aor = NULL;
}

// This test covers updating a subscriber where there's a store error on the local
// site when getting the subscriber's information.
TEST_F(BasicS4Test, UpdateSubscriberErrorOnGetOnLocalStore)
{
  get_data_expect_call_failure(_mock_store1, Store::Status::ERROR);

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
  get_data_expect_call_success(_mock_store1, AOR_WITH_BINDING, 1);
  set_chronos_put_expectations();
  set_data_expect_call(_mock_store1, Store::Status::ERROR);

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
    get_data_expect_call_success(_mock_store1, AOR_WITH_BINDING, 1);
    set_chronos_put_expectations();
    set_data_expect_call(_mock_store1, Store::Status::DATA_CONTENTION);
    get_data_expect_call_success(_mock_store1, AOR_WITH_BINDING, 1);
    set_chronos_put_expectations();
    set_data_expect_call(_mock_store1, Store::Status::OK);
    get_data_expect_call_success(_mock_store2, AOR_WITH_BINDING, 1);
    set_data_expect_call(_mock_store2, Store::Status::OK);
    get_data_expect_call_success(_mock_store3, AOR_WITH_BINDING, 1);
    set_data_expect_call(_mock_store3, Store::Status::OK);
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
    get_data_expect_call_success(_mock_store1, AOR_WITH_BINDING, 1);
    set_chronos_put_expectations();
    set_data_expect_call(_mock_store1, Store::Status::OK);
    get_data_expect_call_success(_mock_store2, AOR_WITH_BINDING, 1);
    set_data_expect_call(_mock_store2, Store::Status::DATA_CONTENTION);
    get_data_expect_call_success(_mock_store2, AOR_WITH_BINDING, 1);
    set_data_expect_call(_mock_store2, Store::Status::OK);
    get_data_expect_call_success(_mock_store3, AOR_WITH_BINDING, 1);
    set_data_expect_call(_mock_store3, Store::Status::OK);
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
    get_data_expect_call_success(_mock_store1, AOR_WITH_BINDING, 1);
    set_chronos_put_expectations();
    set_data_expect_call(_mock_store1, Store::Status::OK);
    get_data_expect_call_failure(_mock_store2, Store::Status::ERROR);
    get_data_expect_call_success(_mock_store3, AOR_WITH_BINDING, 1);
    set_data_expect_call(_mock_store3, Store::Status::OK);
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
    get_data_expect_call_success(_mock_store1, AOR_WITH_BINDING, 1);
    set_chronos_put_expectations();
    set_data_expect_call(_mock_store1, Store::Status::OK);
    get_data_expect_call_success(_mock_store2, AOR_WITH_BINDING, 1);
    set_data_expect_call(_mock_store2, Store::Status::ERROR);
    get_data_expect_call_success(_mock_store3, AOR_WITH_BINDING, 1);
    set_data_expect_call(_mock_store3, Store::Status::OK);
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
    get_data_expect_call_success(_mock_store1, AOR_WITH_BINDING, 1);
    set_chronos_put_expectations();
    set_data_expect_call(_mock_store1, Store::Status::OK);
    get_data_expect_call_failure(_mock_store2, Store::Status::NOT_FOUND);
    set_data_expect_call(_mock_store2, Store::Status::OK);
    get_data_expect_call_success(_mock_store3, AOR_WITH_BINDING, 1);
    set_data_expect_call(_mock_store3, Store::Status::OK);
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
  EXPECT_CALL(*_mock_store1, set_data(_, _, _, _, now + 300 + 10, _, An<Store::Format>()))
    .WillOnce(Return(Store::Status::OK));
  EXPECT_CALL(*_mock_store2, set_data(_, _, _, _, now + 300 + 10, _, An<Store::Format>()))
    .WillOnce(Return(Store::Status::OK));
  EXPECT_CALL(*_mock_store3, set_data(_, _, _, _, now + 300 + 10, _, An<Store::Format>()))
    .WillOnce(Return(Store::Status::OK));
  set_chronos_post_expectations();

  AoR* aor = AoRTestUtils::create_simple_aor("aor_id", true, false);
  HTTPCode rc = this->_s4->handle_put("aor_id", *aor, 0);

  EXPECT_EQ(rc, 200);

  delete aor; aor = NULL;
}

// This test covers getting subscriber information from S4, but where the
// subscriber information is corrupt.
TEST_F(BasicS4Test, GetCorruptSubscriberInfoInvalidJSON)
{
  get_data_expect_call_success(_mock_store1, "{\"invalidJSON}", 1);

  AoR* get_aor = NULL;
  uint64_t version;
  HTTPCode rc = this->_s4->handle_get("aor_id", &get_aor, version, 0);

  EXPECT_EQ(rc, 500);
  ASSERT_TRUE(get_aor == NULL);
}

// This test covers getting subscriber information from S4, but where the
// subscriber information is corrupt.
TEST_F(BasicS4Test, GetCorruptSubscriberInfoMissingValues)
{
  get_data_expect_call_success(_mock_store1, "{}", 1);

  AoR* get_aor = NULL;
  uint64_t version;
  HTTPCode rc = this->_s4->handle_get("aor_id", &get_aor, version, 0);

  EXPECT_EQ(rc, 500);
  ASSERT_TRUE(get_aor == NULL);
}

// This tests that if the last binding in an AoR is removed, the AoR is cleared
TEST_F(BasicS4Test, ClearUpEmptyAoR)
{
  // The get call returns an AoR with one binding and one subscription. The
  // patch removes the binding. S4 then removes the subscription, as shown
  // by the expiry time of 0 on the set call, and the send_delete chronos
  // call.
  get_data_expect_call_success(_mock_store1, AOR_WITH_BINDING, 1);
  EXPECT_CALL(*_mock_store1, set_data(_, _, _, _, 0, _, An<Store::Format>()))
    .WillOnce(Return(Store::Status::OK));
  get_data_expect_call_success(_mock_store2, AOR_WITH_BINDING, 1);
  EXPECT_CALL(*_mock_store2, set_data(_, _, _, _, 0, _, An<Store::Format>()))
    .WillOnce(Return(Store::Status::OK));
  get_data_expect_call_success(_mock_store3, AOR_WITH_BINDING, 1);
  EXPECT_CALL(*_mock_store3, set_data(_, _, _, _, 0, _, An<Store::Format>()))
    .WillOnce(Return(Store::Status::OK));
  set_chronos_delete_expectations();

  PatchObject po;
  po._remove_bindings.push_back(AoRTestUtils::BINDING_ID);
  AoR* aor = NULL;
  HTTPCode rc = this->_s4->handle_patch("aor_id", po, &aor, 0);

  EXPECT_EQ(rc, 200);

  delete aor; aor = NULL;
}

// This tests that if the last non-emergency binding in an AoR is removed, any
// subscriptions are removed.
TEST_F(BasicS4Test, ClearUpSubscriptionsInAoR)
{
  // Create an AoR with one binding, one emergency binding, and one
  // subscription.
  AoR* get_aor = AoRTestUtils::create_simple_aor("aor_id");
  get_aor->get_binding(AoRTestUtils::BINDING_ID)->_emergency_registration = true;
  Binding* binding = AoRTestUtils::build_binding("aor_id", time(NULL));
  get_aor->_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID + "2", binding));
  std::string get_str = _serializer_deserializer.serialize_aor(get_aor);

  // Create an AoR with one binding, and no subscriptions. The binding should be
  // an emergency binding.
  AoR* expect_aor = AoRTestUtils::create_simple_aor("aor_id", false);
  expect_aor->get_binding(AoRTestUtils::BINDING_ID)->_emergency_registration = true;
  std::string expect_str = _serializer_deserializer.serialize_aor(expect_aor);

  // The get call returns an AoR with one regular binding, one emergency
  // binding, and one subscription. The patch removes the regular binding.
  // S4 then removes the subscription, as tested by the set_data call.
  get_data_expect_call_success(_mock_store1, get_str, 1);
  EXPECT_CALL(*_mock_store1, set_data(_, _, expect_str, _, _, _, An<Store::Format>()))
    .WillOnce(Return(Store::Status::OK));
  set_chronos_put_expectations();
  get_data_expect_call_success(_mock_store2, get_str, 1);
  EXPECT_CALL(*_mock_store2, set_data(_, _, expect_str, _, _, _, An<Store::Format>()))
    .WillOnce(Return(Store::Status::OK));
  get_data_expect_call_success(_mock_store3, get_str, 1);
  EXPECT_CALL(*_mock_store3, set_data(_, _, expect_str, _, _, _, An<Store::Format>()))
    .WillOnce(Return(Store::Status::OK));

  PatchObject po;
  po._remove_bindings.push_back(AoRTestUtils::BINDING_ID + "2");
  AoR* aor = NULL;
  HTTPCode rc = this->_s4->handle_patch("aor_id", po, &aor, 0);

  EXPECT_EQ(rc, 200);

  delete aor; aor = NULL;
  delete expect_aor; expect_aor = NULL;
  delete get_aor; get_aor = NULL;
}

/// The following tests check the Chronos sending timer when S4 writes to AoR.

// This test sends POST successfully to Chronos when S4 creates a new AoR, and
// checks all the argument for send_post.
TEST_F(BasicS4Test, ChronosTimerOnSubscriberCreation)
{
  // Build AoR with set_timer_id = false
  std::string aor_id = "sip:6505550231@homedomain";
  int expiry = 200;
  AoR* aor = AoRTestUtils::create_simple_aor(aor_id, true, false, expiry);
  std::string callback_uri;

  // Build various arguments for Chronos call
  std::string opaque = "{\"aor_id\": \"" + aor_id + "\"}";
  std::map<std::string, uint32_t> tag_map;
  tag_map["BIND"] = aor->get_bindings_count();
  tag_map["REG"] = 1;
  tag_map["SUB"] = aor->get_subscriptions_count();

  // S4 and Chronos expectations. S4 sends POST when timer_id is empty.
  set_data_expect_call(_mock_store1, Store::Status::OK);
  set_data_expect_call(_mock_store2, Store::Status::OK);
  set_data_expect_call(_mock_store3, Store::Status::OK);
  EXPECT_CALL(*(this->_mock_chronos), send_post(_,
                                                expiry,
                                                _,
                                                opaque,
                                                _,
                                                tag_map))
    .WillOnce(DoAll(SetArgReferee<0>(AoRTestUtils::TIMER_ID),
                    SaveArg<2>(&callback_uri),
                    Return(HTTP_OK)));

  HTTPCode rc = this->_s4->handle_put(aor_id, *aor, 0);

  // Check the timer_id created during Chronos POST is written to AoR
  EXPECT_EQ(rc, 200);
  ASSERT_FALSE(aor == NULL);
  EXPECT_EQ(aor->_timer_id, AoRTestUtils::TIMER_ID);
  EXPECT_EQ(callback_uri, "/timers");

  delete aor; aor = NULL;
}

// This test sends POST unsuccessfully to Chronos when S4 creates a new AoR. The
// overall flow remains the same as the success case, but the timer_id will be
// left empty in AoR.
TEST_F(BasicS4Test, ChronosTimerOnSubscriberCreationFail)
{
  // Build AoR with set_timer_id = false
  std::string aor_id = "sip:6505550231@homedomain";
  AoR* aor = AoRTestUtils::create_simple_aor(aor_id, true, false);

  // SM and Chronos expectations
  set_data_expect_call(_mock_store1, Store::Status::OK);
  set_data_expect_call(_mock_store2, Store::Status::OK);
  set_data_expect_call(_mock_store3, Store::Status::OK);
  EXPECT_CALL(*(this->_mock_chronos), send_post(_, _, _, _, _, _))
    .WillOnce(Return(HTTP_SERVER_ERROR));

  HTTPCode rc = this->_s4->handle_put(aor_id, *aor, 0);

  // Check that Chronos send failure won't impact the overall flow, but leaves
  // timer_id empty in AoR
  EXPECT_EQ(rc, 200);
  ASSERT_FALSE(aor == NULL);
  EXPECT_EQ(aor->_timer_id, "");

  delete aor; aor = NULL;
}

// This test sends PUT successfully to Chronos when S4 updates an existing AoR,
// and checks all the arguments for send_put.
TEST_F(BasicS4Test, ChronosTimerOnSubscriberUpdate)
{
  // Build AoR with set_timer_id = true
  std::string aor_id = "sip:6505550231@homedomain";
  int expiry = 200;
  AoR* aor = AoRTestUtils::create_simple_aor(aor_id, true, true, expiry);
  std::string timer_id;
  std::string callback_uri;

  // Build various arguments for Chronos call
  std::string opaque = "{\"aor_id\": \"" + aor_id + "\"}";
  std::map<std::string, uint32_t> tag_map;
  tag_map["BIND"] = aor->get_bindings_count();
  tag_map["REG"] = 1;
  tag_map["SUB"] = aor->get_subscriptions_count();

  // S4 and Chronos expectations. S4 sends PUT when timer_id is not empty.
  set_data_expect_call(_mock_store1, Store::Status::OK);
  set_data_expect_call(_mock_store2, Store::Status::OK);
  set_data_expect_call(_mock_store3, Store::Status::OK);
  EXPECT_CALL(*(this->_mock_chronos), send_put(_,
                                               expiry,
                                               _,
                                               opaque,
                                               _,
                                               tag_map))
    .WillOnce(DoAll(SaveArg<0>(&timer_id),
                    SaveArg<2>(&callback_uri),
                    Return(HTTP_OK)));

  HTTPCode rc = this->_s4->handle_put(aor_id, *aor, 0);

  // Check the correct timer_id was used.
  EXPECT_EQ(rc, 200);
  EXPECT_EQ(timer_id, AoRTestUtils::TIMER_ID);
  EXPECT_EQ(callback_uri, "/timers");

  delete aor; aor = NULL;
}

// This test sends PUT unsuccessfully to Chronos when S4 updates an existing AoR.
// The overall flow remains the same.
TEST_F(BasicS4Test, ChronosTimerOnSubscriberUpdateFail)
{
  // Build AoR with set_timer_id = true
  std::string aor_id = "sip:6505550231@homedomain";
  AoR* aor = AoRTestUtils::create_simple_aor(aor_id, true, true);

  // SM and Chronos expectations
  set_data_expect_call(_mock_store1, Store::Status::OK);
  set_data_expect_call(_mock_store2, Store::Status::OK);
  set_data_expect_call(_mock_store3, Store::Status::OK);
  EXPECT_CALL(*(this->_mock_chronos), send_put(_, _, _, _, _, _))
    .WillOnce(Return(HTTP_SERVER_ERROR));

  HTTPCode rc = this->_s4->handle_put(aor_id, *aor, 0);

  // Check that Chronos send failure won't impact the overall flow.
  EXPECT_EQ(rc, 200);
  ASSERT_FALSE(aor == NULL);
  EXPECT_EQ(aor->_timer_id, AoRTestUtils::TIMER_ID);

  delete aor; aor = NULL;
}


// This test sends DELETE successfully to Chronos when S4 deletes an AoR. The
// argument for send_delete is too simple to worth checking.
TEST_F(BasicS4Test, ChronosTimerOnSubscriberDelete)
{
  get_data_expect_call_success(_mock_store1, AOR_WITH_BINDING, 1);
  get_data_expect_call_success(_mock_store2, AOR_WITH_BINDING, 1);
  get_data_expect_call_success(_mock_store3, AOR_WITH_BINDING, 1);
  set_data_expect_call(_mock_store1, Store::Status::OK);
  set_data_expect_call(_mock_store2, Store::Status::OK);
  set_data_expect_call(_mock_store3, Store::Status::OK);
  EXPECT_CALL(*(this->_mock_chronos), send_delete(AoRTestUtils::TIMER_ID, _))
    .WillOnce(Return(HTTP_OK));

  HTTPCode rc = this->_s4->handle_delete("aor_id", 1, 0);

  EXPECT_EQ(rc, 204);
}

// This test sends DELETE unsuccessfully to Chronos when S4 deletes an AoR. As
// S4 does not check return code for send_delete, behaviour remains identical to
// the test above.
TEST_F(BasicS4Test, ChronosTimerOnSubscriberDeleteFail)
{
  get_data_expect_call_success(_mock_store1, AOR_WITH_BINDING, 1);
  get_data_expect_call_success(_mock_store2, AOR_WITH_BINDING, 1);
  get_data_expect_call_success(_mock_store3, AOR_WITH_BINDING, 1);
  set_data_expect_call(_mock_store1, Store::Status::OK);
  set_data_expect_call(_mock_store2, Store::Status::OK);
  set_data_expect_call(_mock_store3, Store::Status::OK);
  EXPECT_CALL(*(this->_mock_chronos), send_delete(_, _))
    .WillOnce(Return(HTTP_SERVER_ERROR));

  HTTPCode rc = this->_s4->handle_delete("aor_id", 1, 0);

  EXPECT_EQ(rc, 204);
}

// This test covers handling a Chronos timer pop.
TEST_F(BasicS4Test, HandleTimerPop)
{
  std::string aor_id = "sip:6505550231@homedomain";
  std::string actual_aor_id;
  EXPECT_CALL(*(this->_mock_sm), handle_timer_pop(_, _))
    .WillOnce(SaveArg<0>(&actual_aor_id));

  // No return code for this function, therefore no error case.
  this->_s4->handle_timer_pop(aor_id, 0);

  EXPECT_EQ(actual_aor_id, aor_id);
}

// This test checks that a mimic timer pop will be sent when binding is found to
// have expired. The simplest way to test writing expired data is to do a GET
// where there's no data on the local site.
TEST_F(BasicS4Test, MimicTimerPop)
{
  std::string actual_aor_id;

  {
    InSequence s;
    get_data_expect_call_failure(_mock_store1, Store::Status::NOT_FOUND);
    get_data_expect_call_success(_mock_store2, AOR_WITH_BINDING_EXPIRED, 1);
    set_chronos_put_expectations();

    // Unlike the test above, this timer pop comes from mimic_timer_pop rather
    // than handle_timer_pop. It can also be verified by looking at log.
    EXPECT_CALL(*(this->_mock_sm), handle_timer_pop(_, _))
      .WillOnce(SaveArg<0>(&actual_aor_id));

    set_data_expect_call(_mock_store1, Store::Status::OK);
  }

  AoR* get_aor = NULL;
  uint64_t version;
  HTTPCode rc = this->_s4->handle_get("aor_id", &get_aor, version, 0);
  EXPECT_EQ(rc, 200);

  EXPECT_EQ(actual_aor_id, "aor_id");

  delete get_aor; get_aor = NULL;
}
