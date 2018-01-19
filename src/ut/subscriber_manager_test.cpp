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
#include "mock_s4.h"
#include "mock_hss_connection.h"

using ::testing::_;
using ::testing::Return;
using ::testing::SaveArgPointee;
using ::testing::SetArgReferee;
using ::testing::SetArgPointee;
using ::testing::InSequence;

static const int DUMMY_TRAIL_ID = 0;

/// Fixture for SubscriberManagerTest.
class SubscriberManagerTest : public ::testing::Test
{
  SubscriberManagerTest()
  {
    _s4 = new MockS4();
    _hss_connection = new MockHSSConnection();
    _subscriber_manager = new SubscriberManager(_s4,
                                                _hss_connection,
                                                NULL);
  };

  virtual ~SubscriberManagerTest()
  {
    delete _subscriber_manager; _subscriber_manager = NULL;
    delete _s4; _s4 = NULL;
    delete _hss_connection; _hss_connection = NULL;
  };

  SubscriberManager* _subscriber_manager;
  MockS4* _s4;
  MockHSSConnection* _hss_connection;
};

TEST_F(SubscriberManagerTest, TestAddNewBinding)
{
  // Set up an IRS to be returned by the mocked update_registration_state()
  // call.
  std::string default_id = "sip:example.com";
  HSSConnection::irs_info irs_info;
  irs_info._associated_uris.add_uri(default_id, false);

  // Set up AoRs to be returned by S4.
  AoR* get_aor = new AoR(default_id);
  AoR* patch_aor = new AoR(*get_aor);
  patch_aor->get_binding("binding_id");

  // Create an empty patch object to save off the one provided by handle patch.
  PatchObject patch_object;

  // Set up expect calls to the HSS and S4.
  {
    InSequence s;
    EXPECT_CALL(*_hss_connection, update_registration_state(_, _, _))
      .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                      Return(HTTP_OK)));
    EXPECT_CALL(*_s4, handle_get(default_id, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                      Return(HTTP_OK)));
    EXPECT_CALL(*_s4, handle_patch(default_id, _, _, _))
      .WillOnce(DoAll(SaveArgPointee<1>(&patch_object),
                      SetArgPointee<2>(patch_aor),
                      Return(HTTP_OK)));
  }

  HSSConnection::irs_query irs_query;
  AoR::Bindings updated_bindings;
  Binding* binding = new Binding("");
  binding->_emergency_registration = false;
  updated_bindings.insert(std::make_pair("binding_id", binding));
  AoR::Bindings all_bindings;
  HSSConnection::irs_info irs_info_out;
  HTTPCode rc = _subscriber_manager->update_bindings(irs_query,
                                                     updated_bindings,
                                                     std::vector<std::string>(),
                                                     all_bindings,
                                                     irs_info_out,
                                                     DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_OK);

  // Check that the patch object contains the expected binding.
  EXPECT_TRUE(patch_object._update_bindings.find("binding_id") != patch_object._update_bindings.end());

  // Reset the bindings in the patch object so that we don't double free them.
  patch_object._update_bindings = std::map<std::string, Binding*>();

  // Check that the binding we set is returned in all bindings.
  EXPECT_TRUE(all_bindings.find("binding_id") != all_bindings.end());

  // Delete the bindings we've been passed.
  for (std::pair<std::string, Binding*> b : all_bindings)
  {
    delete b.second;
  }
}


TEST_F(SubscriberManagerTest, TestAddNewSubscription)
{
  // Set up an IRS to be returned by the mocked get_registration_data()
  // call.
  std::string default_id = "sip:example.com";
  HSSConnection::irs_info irs_info;
  irs_info._associated_uris.add_uri(default_id, false);

  // Set up AoRs to be returned by S4.
  AoR* get_aor = new AoR(default_id);
  get_aor->get_binding("binding_id");
  AoR* patch_aor = new AoR(*get_aor);
  patch_aor->get_subscription("subscription_id");

  // Create an empty patch object to save off the one provided by handle patch.
  PatchObject patch_object;

  // Set up expect calls to the HSS and S4.
  {
    InSequence s;
    EXPECT_CALL(*_hss_connection, get_registration_data(default_id, _, _))
      .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                      Return(HTTP_OK)));
    EXPECT_CALL(*_s4, handle_get(default_id, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                      Return(HTTP_OK)));
    EXPECT_CALL(*_s4, handle_patch(default_id, _, _, _))
      .WillOnce(DoAll(SaveArgPointee<1>(&patch_object),
                      SetArgPointee<2>(patch_aor),
                      Return(HTTP_OK)));
  }

  std::pair<std::string, Subscription*> updated_subscription;
  Subscription* subscription = new Subscription();
  updated_subscription = std::make_pair("subscription_id", subscription);
  HSSConnection::irs_info irs_info_out;
  HTTPCode rc = _subscriber_manager->update_subscription(default_id,
                                                         updated_subscription,
                                                         irs_info_out,
                                                         DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_OK);

  // Check that the patch object contains the expected subscription.
  EXPECT_TRUE(patch_object._update_subscriptions.find("subscription_id") != patch_object._update_subscriptions.end());

  // Reset the subscriptions in the patch object so that we don't double free them.
  patch_object._update_subscriptions = std::map<std::string, Subscription*>();
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

  std::map<std::string, Binding*> bindings;

  // Expect call to S4 API, pass back dummy data.

  //EXPECT_EQ(_subscriber_manager->get_bindings("1",
  //                                            bindings,
  //                                            DUMMY_TRAIL_ID), HTTP_OK);

  // Check bindings are as expected.
}

/*TEST_F(SubscriberManagerTest, TestUpdateSubscription)
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

  Subscription* subscription = new Subscription();
  HSSConnection::irs_info irs_info_out;
  HTTPCode rc = _subscriber_manager->update_subscription("",
                                                         std::make_pair(subscription->get_id(), subscription),
                                                         irs_info_out,
                                                         DUMMY_TRAIL_ID);

  EXPECT_EQ(rc, HTTP_OK);
  delete subscription; subscription = NULL;
}*/

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

TEST_F(SubscriberManagerTest, TestGetSubscriptions)
{
  // Set up a default ID.
  std::string default_id = "sip:example.com";

  // Set up AoRs to be returned by S4 - these are deleted by the handler
  AoR* get_aor = new AoR(default_id);
  get_aor->get_binding("binding_id");
  get_aor->get_subscription("subscription_id");

  // Set up expect calls to S4.
  {
    InSequence s;
    EXPECT_CALL(*_s4, handle_get(default_id, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                      Return(HTTP_OK)));
  }

  // Call get subscriptions on SM.
  std::map<std::string, Subscription*> subscriptions;
  HTTPCode rc = _subscriber_manager->get_subscriptions(default_id,
                                                       subscriptions,
                                                       DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_OK);

  // Check that there is one subscription with the correct IDs.
  EXPECT_TRUE(subscriptions.find("subscription_id") != subscriptions.end());

  // Delete the subscriptions we've been passed.
  for (std::pair<std::string, Subscription*> s : subscriptions)
  {
    delete s.second;
  }
}

TEST_F(SubscriberManagerTest, TestUpdateAssociatedURIs)
{
  // Set up a default ID and a second ID in the IRS.
  std::string default_id = "sip:example.com";
  std::string other_id = "sip:another.com";

  // Set up AoRs to be returned by S4.
  AoR* get_aor = new AoR(default_id);
  get_aor->_associated_uris.add_uri(default_id, false);

  // Create an empty patch object to save off the one provided by handle patch.
  PatchObject patch_object;

  // Set up expect calls to S4.
  {
    InSequence s;
    EXPECT_CALL(*_s4, handle_get(default_id, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                      Return(HTTP_OK)));
    EXPECT_CALL(*_s4, handle_patch(default_id, _, _, _))
      .WillOnce(DoAll(SaveArgPointee<1>(&patch_object),
                      Return(HTTP_OK)));
  }

  // Set up new associated URIs.
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri(default_id, false);
  associated_uris.add_uri(other_id, false);

  // Call update associated URIs on SM.
  HTTPCode rc = _subscriber_manager->update_associated_uris(default_id,
                                                            associated_uris,
                                                            DUMMY_TRAIL_ID);

  // Check that the patch object contains the expected associated URIs.
  EXPECT_TRUE(patch_object._associated_uris.contains_uri(default_id));
  EXPECT_TRUE(patch_object._associated_uris.contains_uri(other_id));

  EXPECT_EQ(rc, HTTP_OK);
}
