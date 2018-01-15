/**
 * @file subscriber_manager_test.cpp
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

//#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "subscriber_manager.h"
//#include "mock_s4.h"
#include "mock_hss_connection.h"

using ::testing::_;
using ::testing::Return;
using ::testing::SetArgReferee;

static const int DUMMY_TRAIL_ID = 0;

/// Fixture for SubscriberManagerTest.
class SubscriberManagerTest : public ::testing::Test
{
  SubscriberManagerTest()
  {
    //_s4 = new MockS4();
    _hss_connection = new MockHSSConnection();
    _subscriber_manager = new SubscriberManager(NULL,//_s4,
                                                _hss_connection,
                                                NULL);
  };

  virtual ~SubscriberManagerTest()
  {
    delete _subscriber_manager; _subscriber_manager = NULL;
    //delete _s4; _s4 = NULL;
    delete _hss_connection; _hss_connection = NULL;
  };

  SubscriberManager* _subscriber_manager;
  //MockS4* _s4;
  MockHSSConnection* _hss_connection;
};

TEST_F(SubscriberManagerTest, TestTest)
{
  HSSConnection::irs_info irs_info;
  EXPECT_EQ(_subscriber_manager->remove_subscription("", "", irs_info, DUMMY_TRAIL_ID), HTTP_OK);
}

TEST_F(SubscriberManagerTest, TestUpdateBindings)
{
  // Set up an IRS to be returned by the mocked update_registration_state()
  // call.
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri("sip:example.com", false);
  HSSConnection::irs_info irs_info;
  irs_info._associated_uris = associated_uris;
  EXPECT_CALL(*_hss_connection, update_registration_state(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  //EXPECT_CALL(*_s4, get(_)); TODO this doesn't actually work yet, but it's
  //only worth bothering with when S4 is tied down.

  std::vector<SubscriberManager::Binding> updated_bindings;
  SubscriberManager::Binding binding = SubscriberManager::Binding();
  updated_bindings.push_back(binding);
  std::vector<std::string> binding_ids_to_remove = std::vector<std::string>();
  std::vector<SubscriberManager::Binding> all_bindings;
  HSSConnection::irs_query irs_query;
  HSSConnection::irs_info irs_info_out;
  HTTPCode rc = _subscriber_manager->update_bindings(irs_query,
                                                     updated_bindings,
                                                     binding_ids_to_remove,
                                                     all_bindings,
                                                     irs_info_out,
                                                     DUMMY_TRAIL_ID);

  EXPECT_EQ(rc, HTTP_OK);
}

TEST_F(SubscriberManagerTest, TestGetBindings)
{
  // What should happen here?
  //  - The S-CSCF has asked for to return all bindings for a pub ID so that we
  //    can route the request to the UE bindings.
  //      - There is no implicit expiry of bindings, S4 handles returning
  //        bindings that are active.
  //  - The SM should receive this request and query S4 for the whole AoR with
  //    the provided pub ID.
  //  - SM should get the bindings out of the returned data and return them.
  //  - Analytics logs?

  std::vector<SubscriberManager::Binding> bindings;

  // Expect call to S4 API, pass back dummy data.

  EXPECT_EQ(_subscriber_manager->get_bindings("1",
                                              bindings,
                                              DUMMY_TRAIL_ID), HTTP_OK);

  // Check bindings are as expected.
}

TEST_F(SubscriberManagerTest, TestUpdateSubscription)
{
  // Set up an IRS to be returned by the mocked update_registration_state()
  // call.
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri("sip:example.com", false);
  HSSConnection::irs_info irs_info;
  irs_info._associated_uris = associated_uris;
  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));

  SubscriberManager::Subscription subscription = SubscriberManager::Subscription();
  HSSConnection::irs_info irs_info_out;
  HTTPCode rc = _subscriber_manager->update_subscription("",
                                                         subscription,
                                                         irs_info_out,
                                                         DUMMY_TRAIL_ID);

  EXPECT_EQ(rc, HTTP_OK);
}

TEST_F(SubscriberManagerTest, TestGetCachedSubscriberState)
{
  HSSConnection::irs_info irs_info;
  HSSConnection::irs_query irs_query;
  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, DUMMY_TRAIL_ID)).WillOnce(Return(HTTP_OK));
  EXPECT_EQ(_subscriber_manager->get_cached_subscriber_state("",
                                                             irs_info,
                                                             DUMMY_TRAIL_ID), HTTP_OK);

  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, DUMMY_TRAIL_ID)).WillOnce(Return(HTTP_NOT_FOUND));
  EXPECT_EQ(_subscriber_manager->get_cached_subscriber_state("",
                                                             irs_info,
                                                             DUMMY_TRAIL_ID), HTTP_NOT_FOUND);
}

TEST_F(SubscriberManagerTest, TestGetSubscriberState)
{
  HSSConnection::irs_info irs_info;
  HSSConnection::irs_query irs_query;
  EXPECT_CALL(*_hss_connection, update_registration_state(_, _, DUMMY_TRAIL_ID)).WillOnce(Return(HTTP_OK));
  EXPECT_EQ(_subscriber_manager->get_subscriber_state(irs_query,
                                                      irs_info,
                                                      DUMMY_TRAIL_ID), HTTP_OK);

  EXPECT_CALL(*_hss_connection, update_registration_state(_, _, DUMMY_TRAIL_ID)).WillOnce(Return(HTTP_NOT_FOUND));
  EXPECT_EQ(_subscriber_manager->get_subscriber_state(irs_query,
                                                      irs_info,
                                                      DUMMY_TRAIL_ID), HTTP_NOT_FOUND);
}
