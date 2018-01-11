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

// SDM-REFACTOR-TODO:
// Full UTs
// Comments explaining what each UT does

using ::testing::_;
using ::testing::InSequence;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgReferee;

std::string empty_aor = "{\"bindings\": {}, \"subscriptions\": {}, \"notify_cseq\": 1}";
std::string aor_with_binding = "{\"bindings\": {\"<urn:uuid:00000000-0000-0000-0000-777777777777>:1\":{\"uri\":\"sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.214:5061;transport=tcp;ob\",\"cid\":\"0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs1042ohntC@10.114.61.213\",\"cseq\":10000,\"expires\":1000000,\"priority\":0,\"params\":{\"+sip.ice\":\"\",\"+sip.instance\":\"\\\"<urn:uuid:00000000-0000-0000-0000-777777777777>\\\"\",\"reg-id\":\"1\"},\"path_headers\":[\"<sip:GgAAAAAAAACYyAW4z38AABcUwStNKgAAa3WOL+1v72nFJg==@ec2-107-22-156-220.compute-1.amazonaws.com:5060;lr;ob>\"],\"paths\":[\"sip:GgAAAAAAAACYyAW4z38AABcUwStNKgAAa3WOL+1v72nFJg==@ec2-107-22-156-220.compute-1.amazonaws.com:5060;lr;ob\"],\"private_id\":\"Alice\",\"emergency_reg\":false}}, \"subscriptions\": {}, \"notify_cseq\": 1}";

/// Fixture for BasicS4Test.
class BasicS4Test : public SipTest
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
    _remote_s4_1 = new S4("site2", _aor_store, {});
    _remote_s4_2 = new S4("site3", _aor_store, {});
    _s4 = new S4("site1", _aor_store, {_remote_s4_1, _remote_s4_2});
  }

  virtual ~BasicS4Test()
  {
    delete _s4; _s4 = NULL;
    delete _remote_s4_1, _remote_s4_1 = NULL;
    delete _remote_s4_2, _remote_s4_2 = NULL;
    delete _aor_store; _aor_store = NULL;
    delete _mock_store; _mock_store = NULL;
  }

  // Set up a single expectation for getting data from a store where the store
  // responds successfully
  void get_data_expect_call_success(std::string aor_data,
                                    int cas,
                                    int times)
  {
    EXPECT_CALL(*_mock_store, get_data(_, _, _, _, _))
      .Times(times)
      .WillRepeatedly(DoAll(SetArgReferee<2>(std::string(aor_data)),
                            SetArgReferee<3>(cas),
                            Return(Store::OK)));
  }

  // Set up a single expectation for getting data from a store where the store
  // responds successfully
  void set_data_expect_call(Store::Status rc,
                            int times)
  {
    EXPECT_CALL(*_mock_store, set_data(_, _, _, _, _, _))
      .Times(times)
      .WillRepeatedly(Return(rc));
  }

  // Set up a single expectation for getting data from a store where there's a
  // store error
  void get_data_expect_call_failure(Store::Status rc,
                                    int times)
  {
    EXPECT_CALL(*_mock_store, get_data(_, _, _, _, _))
      .Times(times)
      .WillOnce(Return(rc));
  }

  // Fixture variables.  Note that as the fixture is a C++ template, these must
  // be accessed in the individual tests using the this pointer (e.g. use
  // `this->store` rather than `_store`).
  MockStore* _mock_store;
  AstaireAoRStore* _aor_store;
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
  HTTPCode rc = this->_s4->handle_get("aor_id", &get_aor, 0);

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
  HTTPCode rc = this->_s4->handle_get("aor_id", &get_aor, 0);

  EXPECT_EQ(rc, 500);
  EXPECT_TRUE(get_aor == NULL);

  delete get_aor; get_aor = NULL;
}

// This test covers a GET where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, GETNotFoundInAllStores)
{
  get_data_expect_call_success(empty_aor,
                               1,
                               3);

  AoR* get_aor = NULL;
  HTTPCode rc = this->_s4->handle_get("aor_id", &get_aor, 0);

  EXPECT_EQ(rc, 404);
  ASSERT_FALSE(get_aor == NULL);
  EXPECT_TRUE(get_aor->bindings().empty());

  delete get_aor; get_aor = NULL;
}

// This test covers a GET where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, GETFoundInRemoteStore)
{
  {
    InSequence s;
    get_data_expect_call_success(empty_aor,
                                 1,
                                 1);
    get_data_expect_call_success(aor_with_binding,
                                 1,
                                 1);
    set_data_expect_call(Store::Status::OK, 1);
  }

  AoR* get_aor = NULL;
  HTTPCode rc = this->_s4->handle_get("aor_id", &get_aor, 0);

  EXPECT_EQ(rc, 200);
  ASSERT_FALSE(get_aor == NULL);
  EXPECT_FALSE(get_aor->bindings().empty());

  delete get_aor; get_aor = NULL;
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, DELETENotFoundInAllStores)
{
  get_data_expect_call_success(empty_aor,
                               1,
                               3);

  HTTPCode rc = this->_s4->handle_delete("aor_id", 0);

  EXPECT_EQ(rc, 200);
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, DELETEFoundInAllStores)
{
  get_data_expect_call_success(aor_with_binding,
                               1,
                               3);
  set_data_expect_call(Store::Status::OK, 3);

  HTTPCode rc = this->_s4->handle_delete("aor_id", 0);

  EXPECT_EQ(rc, 200);
}

// This test covers a DELETE where the AoR doesn't exist in any store.
TEST_F(BasicS4Test, DELETEErrorOnLocalSet)
{
  get_data_expect_call_success(aor_with_binding,
                               1,
                               1);
  set_data_expect_call(Store::Status::ERROR, 1);

  HTTPCode rc = this->_s4->handle_delete("aor_id", 0);

  EXPECT_EQ(rc, 500);
}
