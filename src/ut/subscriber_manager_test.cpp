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

#include "gtest/gtest.h"

#include "subscriber_manager.h"
#include "aor_test_utils.h"
#include "mock_s4.h"
#include "mock_hss_connection.h"
#include "mock_analytics_logger.h"
#include "mock_notify_sender.h"
#include "mock_registration_sender.h"
#include "rapidxml/rapidxml.hpp"

using ::testing::_;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgReferee;
using ::testing::SetArgPointee;
using ::testing::SaveArgPointee;

static const int DUMMY_TRAIL_ID = 0;
static const std::string DEFAULT_ID = "sip:example.com";
static const std::string OTHER_ID = "sip:another.com";
static const std::string WILDCARD_ID = "sip:65055!.*!@example.com";

/// Fixture for SubscriberManagerTest.
class SubscriberManagerTest : public ::testing::Test
{
public:
  SubscriberManagerTest()
  {
    _s4 = new MockS4();
    _hss_connection = new MockHSSConnection();
    _analytics_logger = new MockAnalyticsLogger();
    _notify_sender = new MockNotifySender();
    _registration_sender = new MockRegistrationSender();
    _subscriber_manager = new SubscriberManager(_s4,
                                                _hss_connection,
                                                _analytics_logger,
                                                _notify_sender,
                                                _registration_sender);
  };

  virtual ~SubscriberManagerTest()
  {
    delete _subscriber_manager; _subscriber_manager = NULL;
    delete _notify_sender; _notify_sender = NULL;
    delete _registration_sender; _registration_sender = NULL;
    delete _analytics_logger; _analytics_logger = NULL;
    delete _hss_connection; _hss_connection = NULL;
    delete _s4; _s4 = NULL;
  };

private:
  SubscriberManager* _subscriber_manager;
  MockS4* _s4;
  MockHSSConnection* _hss_connection;
  MockAnalyticsLogger* _analytics_logger;
  MockNotifySender* _notify_sender;
  MockRegistrationSender* _registration_sender;
};

// Custom matcher to check that the passed in AoR is as expected.
MATCHER_P(AoRsMatch, expected_aor, "")
{
  return (arg == expected_aor);
}

// This test covers registering a subscriber. It checks the expect calls in
// detail, as well as the returned AoR.
TEST_F(SubscriberManagerTest, TestRegisterSubscriber)
{
  // Set up the expected calls. We expect an analytics log for the added
  // bindings, and a write to S4. On the write to S4 we match against an
  // expected AoR that has the single added binding.
  AoR* expected_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID, false, false);
  expected_aor->_notify_cseq = 1;
  EXPECT_CALL(*_s4, handle_put(DEFAULT_ID, AoRsMatch(*expected_aor), _))
    .WillOnce(Return(HTTP_OK));
  EXPECT_CALL(*_analytics_logger, registration(DEFAULT_ID,
                                               AoRTestUtils::BINDING_ID,
                                               AoRTestUtils::CONTACT_URI,
                                               300));

  // Build the updated bindings to pass in.
  Binding* binding = AoRTestUtils::build_binding(DEFAULT_ID, time(NULL));
  Bindings updated_bindings;
  updated_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID, binding));
  AssociatedURIs associated_uris;
  associated_uris.add_uri(DEFAULT_ID, false);
  Bindings all_bindings;

  // Register subscriber on SM.
  HSSConnection::irs_info irs_info;
  HTTPCode rc = _subscriber_manager->register_subscriber(DEFAULT_ID,
                                                         "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                                         associated_uris,
                                                         updated_bindings,
                                                         all_bindings,
                                                         irs_info,
                                                         DUMMY_TRAIL_ID);

  // Now check the results. The SM call should have been successful, and the
  // returned bindings should include the binding we just added.
  EXPECT_EQ(rc, HTTP_OK);
  ASSERT_EQ(all_bindings.size(), 1);
  EXPECT_TRUE(*(all_bindings[AoRTestUtils::BINDING_ID]) == *binding);

  // Tidy up.
  SubscriberDataUtils::delete_bindings(updated_bindings);
  SubscriberDataUtils::delete_bindings(all_bindings);
  delete expected_aor; expected_aor = NULL;
}

// Test that registering a subscriber fails if the write to S4 fails.
TEST_F(SubscriberManagerTest, TestRegisterSubscriberWriteFail)
{
  EXPECT_CALL(*_s4, handle_put(_, _, _)).WillOnce(Return(HTTP_SERVER_ERROR));

  // Build the updated bindings to pass in.
  Binding* binding = AoRTestUtils::build_binding(DEFAULT_ID, time(NULL));
  Bindings updated_bindings;
  updated_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID, binding));
  AssociatedURIs associated_uris;
  associated_uris.add_uri(DEFAULT_ID, false);
  Bindings all_bindings;

  // Register subscriber on SM.
  HSSConnection::irs_info irs_info;
  HTTPCode rc = _subscriber_manager->register_subscriber(DEFAULT_ID,
                                                         "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                                         associated_uris,
                                                         updated_bindings,
                                                         all_bindings,
                                                         irs_info,
                                                         DUMMY_TRAIL_ID);

  EXPECT_EQ(rc, HTTP_SERVER_ERROR);

  // Delete the bindings we put in.
  SubscriberDataUtils::delete_bindings(updated_bindings);
}

// Test attempting to register a subscriber that already exists. SM should
// retry the write to S4, so from the clients POV this succeeds.
TEST_F(SubscriberManagerTest, TestRegisterSubscriberAlreadyExists)
{
  // Set up the expected calls. We expect an analytics log for the added
  // bindings, a write to S4 (which fails with a 412), a get to S4, then
  // another write to S4, and finally a call out to the Notify Sender.
  // On the second write to S4 we match against an expected AoR that has the
  // single added binding.
  PatchObject patch_object;
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID, false, false);
  AoR* patch_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID, false, false);
  EXPECT_CALL(*_s4, handle_put(_, _, _)).WillOnce(Return(HTTP_PRECONDITION_FAILED));
  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_patch(_, _, _, _))
   .WillOnce(DoAll(SaveArg<1>(&patch_object),
                   SetArgPointee<2>(patch_aor),
                   Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, registration(_, _, _, _));
  EXPECT_CALL(*_notify_sender, send_notifys(_, _, _, _, _, _));

  // Build the updated bindings to pass in.
  Binding* binding = AoRTestUtils::build_binding(DEFAULT_ID, time(NULL));
  Bindings updated_bindings;
  updated_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID, binding));
  AssociatedURIs associated_uris;
  associated_uris.add_uri(DEFAULT_ID, false);
  Bindings all_bindings;

  // Register subscriber on SM.
  HSSConnection::irs_info irs_info;
  HTTPCode rc = _subscriber_manager->register_subscriber(DEFAULT_ID,
                                                         "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                                         associated_uris,
                                                         updated_bindings,
                                                         all_bindings,
                                                         irs_info,
                                                         DUMMY_TRAIL_ID);

  // Finally, check that the call was successful. This also checks the patch
  // object.
  EXPECT_EQ(rc, HTTP_OK);
  ASSERT_NE(patch_object._update_bindings.find(AoRTestUtils::BINDING_ID),
            patch_object._update_bindings.end());
  EXPECT_TRUE(*(patch_object._update_bindings[AoRTestUtils::BINDING_ID]) ==
              *(updated_bindings[AoRTestUtils::BINDING_ID]));

  // Delete the bindings we put in.
  SubscriberDataUtils::delete_bindings(updated_bindings);
  SubscriberDataUtils::delete_bindings(all_bindings);
}

// Test attempting to register a subscriber that already exists. SM should
// retry the write to S4 - in this test the second write fails, so the
// register fails.
TEST_F(SubscriberManagerTest, TestRegisterSubscriberAlreadyExistsWriteFails)
{
  // Set up the expected calls. We expect an analytics log for the added
  // bindings, a write to S4 (which fails with a 412), then another write
  // to S4.
  // On the second write, we return 404. This should result in a failure, not
  // a loop.
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID, false, false);
  EXPECT_CALL(*_s4, handle_put(_, _, _)).WillOnce(Return(HTTP_PRECONDITION_FAILED));
  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_patch(_, _, _, _)).WillOnce(Return(HTTP_NOT_FOUND));

  // Build the updated bindings to pass in.
  Binding* binding = AoRTestUtils::build_binding(DEFAULT_ID, time(NULL));
  Bindings updated_bindings;
  updated_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID, binding));
  AssociatedURIs associated_uris;
  associated_uris.add_uri(DEFAULT_ID, false);
  Bindings all_bindings;

  // Register subscriber on SM.
  HSSConnection::irs_info irs_info;
  HTTPCode rc = _subscriber_manager->register_subscriber(DEFAULT_ID,
                                                         "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                                         associated_uris,
                                                         updated_bindings,
                                                         all_bindings,
                                                         irs_info,
                                                         DUMMY_TRAIL_ID);

  EXPECT_EQ(rc, HTTP_NOT_FOUND);

  // Delete the bindings we put in.
  SubscriberDataUtils::delete_bindings(updated_bindings);
}

// This test covers registering a subscriber with no bindings e.g. for a fetch
// bindings register where the subscriber is not currently registered.
TEST_F(SubscriberManagerTest, TestRegisterNoBindings)
{
  // Set up the expected calls. We expect a call to the HSS to deregister the
  // subscriber.
  EXPECT_CALL(*_hss_connection, update_registration_state(_, _, _))
      .WillOnce(Return(HTTP_OK));

  // Build the updated bindings to pass in.
  AssociatedURIs associated_uris;
  associated_uris.add_uri(DEFAULT_ID, false);
  Bindings all_bindings;

  // Register subscriber on SM.
  HSSConnection::irs_info irs_info;
  HTTPCode rc = _subscriber_manager->register_subscriber(DEFAULT_ID,
                                                         "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                                         associated_uris,
                                                         Bindings(),
                                                         all_bindings,
                                                         irs_info,
                                                         DUMMY_TRAIL_ID);


  // Now check the results. The SM call should have been successful, and the
  // returned binding should be empty.
  EXPECT_EQ(all_bindings.size(), 0);
  EXPECT_EQ(rc, HTTP_OK);
}

// This test covers registering a subscriber with no bindings e.g. for a fetch
// bindings register where the subscriber is not registered and the request to
// the HSS fails.
TEST_F(SubscriberManagerTest, TestRegisterNoBindingsHSSFail)
{
  // Set up the expected calls. We expect a call to the HSS to deregister the
  // subscriber.
  EXPECT_CALL(*_hss_connection, update_registration_state(_, _, _))
      .WillOnce(Return(HTTP_SERVER_ERROR));

  // Build the updated bindings to pass in.
  AssociatedURIs associated_uris;
  associated_uris.add_uri(DEFAULT_ID, false);
  Bindings all_bindings;

  // Register subscriber on SM.
  HSSConnection::irs_info irs_info;
  HTTPCode rc = _subscriber_manager->register_subscriber(DEFAULT_ID,
                                                         "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                                         associated_uris,
                                                         Bindings(),
                                                         all_bindings,
                                                         irs_info,
                                                         DUMMY_TRAIL_ID);

  // Check the call to SM failed.
  EXPECT_EQ(rc, HTTP_SERVER_ERROR);
}

// Test that reregistering a subscriber is successful. The test adds a binding
// and removes a bindings (which is an edge case for a reregister, but it's
// useful to have a complicated case and then check everything about it).
TEST_F(SubscriberManagerTest, TestReregisterSubscriber)
{
  // Set up the expected calls. We expect a get to S4, an analytics log for the
  // removed binding, a write to S4, a log for the added binding, a log for the
  // removed subscription and finally a call out to the Notify Sender.
  // The AoR we return on the lookup has a binding and subscription with the
  // same contact URI - this allows us to test that the subscription is removed
  // if the binding is removed.
  // The AoR we return on the write we set up to have the expected bindings -
  // this means we can test the analytics logs.
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID);
  AoR* patch_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID, false);
  Binding* p_b = AoRTestUtils::build_binding(DEFAULT_ID, time(NULL), AoRTestUtils::CONTACT_URI, 300);
  patch_aor->_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID + "2", p_b));
  patch_aor->remove_binding(AoRTestUtils::BINDING_ID);
  PatchObject patch_object;

  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, registration(DEFAULT_ID,
                                               AoRTestUtils::BINDING_ID,
                                               AoRTestUtils::CONTACT_URI,
                                               0));
  EXPECT_CALL(*_s4, handle_patch(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SaveArg<1>(&patch_object),
                    SetArgPointee<2>(patch_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, registration(DEFAULT_ID,
                                               AoRTestUtils::BINDING_ID + "2",
                                               AoRTestUtils::CONTACT_URI,
                                               300));
  EXPECT_CALL(*_analytics_logger, subscription(DEFAULT_ID,
                                               AoRTestUtils::SUBSCRIPTION_ID,
                                               AoRTestUtils::CONTACT_URI,
                                               0));
  EXPECT_CALL(*_notify_sender, send_notifys(DEFAULT_ID,
                                            AoRsMatch(*get_aor),
                                            AoRsMatch(*patch_aor),
                                            SubscriberDataUtils::EventTrigger::USER,
                                            _,
                                            _));

  // Build the updated bindings to pass in.
  AssociatedURIs associated_uris;
  associated_uris.add_uri(DEFAULT_ID, false);
  Binding* binding = AoRTestUtils::build_binding(DEFAULT_ID, time(NULL));
  Bindings updated_bindings;
  updated_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID + "2", binding));
  std::vector<std::string> removed_bindings;
  removed_bindings.push_back(AoRTestUtils::BINDING_ID);
  Bindings all_bindings;
  HSSConnection::irs_info irs_info;

  // Reregister subscriber on SM.
  HTTPCode rc = _subscriber_manager->reregister_subscriber(DEFAULT_ID,
                                                           "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                                           associated_uris,
                                                           updated_bindings,
                                                           removed_bindings,
                                                           all_bindings,
                                                           irs_info,
                                                           DUMMY_TRAIL_ID);

  // Finally, we carry out some more checks. Most of the checks are done by the
  // expect calls; we also check that the reregister call was successful, and
  // that the patch sent up to S4 contained the correct bindings/subscriptions to
  // update/remove.
  EXPECT_EQ(rc, HTTP_OK);
  ASSERT_NE(patch_object._update_bindings.find(AoRTestUtils::BINDING_ID + "2"),
            patch_object._update_bindings.end());
  EXPECT_TRUE(*(patch_object._update_bindings[AoRTestUtils::BINDING_ID + "2"]) ==
              *(binding));
  ASSERT_FALSE(patch_object._remove_bindings.empty());
  EXPECT_EQ(patch_object._remove_bindings[0], AoRTestUtils::BINDING_ID);
  ASSERT_FALSE(patch_object._remove_subscriptions.empty());
  EXPECT_EQ(patch_object._remove_subscriptions[0], AoRTestUtils::SUBSCRIPTION_ID);
  EXPECT_TRUE(patch_object._increment_cseq);

  // Delete the bindings we put in.
  SubscriberDataUtils::delete_bindings(updated_bindings);
  SubscriberDataUtils::delete_bindings(all_bindings);
}

// Tests that reregistering a subscriber with a changed contact is successful.
TEST_F(SubscriberManagerTest, TestReregisterSubscriberContactChanged)
{
  // Set up the expected calls. We expect a get to S4, a write to S4, a log for
  // the added binding, a log for the removed subscription and finally a call
  // out to the Notify Sender.
  // The binding we reregister has changed its contact URI - this allows us to
  // check that the corresponding subscription is removed.
  // The AoR we return on the write we set up to have the expected bindings -
  // this means we can test the analytics logs.
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID);
  AoR* patch_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID, false);
  Binding* p_b = patch_aor->get_binding(DEFAULT_ID);
  p_b->_uri = AoRTestUtils::CONTACT_URI + "2";
  PatchObject patch_object;

  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_patch(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SaveArg<1>(&patch_object),
                    SetArgPointee<2>(patch_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, registration(DEFAULT_ID,
                                               AoRTestUtils::BINDING_ID,
                                               AoRTestUtils::CONTACT_URI + "2",
                                               300));
  EXPECT_CALL(*_analytics_logger, subscription(DEFAULT_ID,
                                               AoRTestUtils::SUBSCRIPTION_ID,
                                               AoRTestUtils::CONTACT_URI,
                                               0));
  EXPECT_CALL(*_notify_sender, send_notifys(DEFAULT_ID,
                                            AoRsMatch(*get_aor),
                                            AoRsMatch(*patch_aor),
                                            SubscriberDataUtils::EventTrigger::USER,
                                            _,
                                            _));

  // Build the updated bindings to pass in.
  AssociatedURIs associated_uris;
  associated_uris.add_uri(DEFAULT_ID, false);
  Binding* binding = AoRTestUtils::build_binding(DEFAULT_ID, time(NULL), AoRTestUtils::CONTACT_URI + "2", 300);
  Bindings updated_bindings;
  updated_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID, binding));
  Bindings all_bindings;
  HSSConnection::irs_info irs_info;

  // Reregister subscriber on SM.
  HTTPCode rc = _subscriber_manager->reregister_subscriber(DEFAULT_ID,
                                                           "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                                           associated_uris,
                                                           updated_bindings,
                                                           {},
                                                           all_bindings,
                                                           irs_info,
                                                           DUMMY_TRAIL_ID);

  // Finally, we carry out some more checks. Most of the checks are done by the
  // expect calls; we also check that the reregister call was successful, and
  // that the patch sent up to S4 contained the correct bindings/subscriptions to
  // update/remove.
  EXPECT_EQ(rc, HTTP_OK);
  ASSERT_NE(patch_object._update_bindings.find(AoRTestUtils::BINDING_ID),
            patch_object._update_bindings.end());
  EXPECT_TRUE(*(patch_object._update_bindings[AoRTestUtils::BINDING_ID]) ==
              *(binding));
  ASSERT_FALSE(patch_object._remove_subscriptions.empty());
  EXPECT_EQ(patch_object._remove_subscriptions[0], AoRTestUtils::SUBSCRIPTION_ID);
  EXPECT_TRUE(patch_object._increment_cseq);

  // Delete the bindings we put in.
  SubscriberDataUtils::delete_bindings(updated_bindings);
  SubscriberDataUtils::delete_bindings(all_bindings);
}

// Test that a reregister that no longer exists results in the subscriber
// being recreated. This reregister fails during the get to S4.
TEST_F(SubscriberManagerTest, TestReregisterRemovedSubscriber)
{
  // Set up the expected calls. We expect a get to S4 (which fails with 404),
  // a put to S4, and an analytics log for the added binding.
  // The AoR we return on the write we set up to have the expected bindings -
  // this means we can test the analytics logs.
  AoR* expected_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID, false, false);
  expected_aor->_notify_cseq = 1;
  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(Return(HTTP_NOT_FOUND));
  EXPECT_CALL(*_s4, handle_put(DEFAULT_ID, AoRsMatch(*expected_aor), _))
    .WillOnce(Return(HTTP_OK));
  EXPECT_CALL(*_analytics_logger, registration(DEFAULT_ID,
                                               AoRTestUtils::BINDING_ID,
                                               AoRTestUtils::CONTACT_URI,
                                               300));

  // Build the updated bindings to pass in.
  AssociatedURIs associated_uris;
  associated_uris.add_uri(DEFAULT_ID, false);
  Binding* binding = AoRTestUtils::build_binding(DEFAULT_ID, time(NULL));
  Bindings updated_bindings;
  updated_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID, binding));
  Bindings all_bindings;
  HSSConnection::irs_info irs_info;

  // Reregister subscriber on SM.
  HTTPCode rc = _subscriber_manager->reregister_subscriber(DEFAULT_ID,
                                                           "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                                           associated_uris,
                                                           updated_bindings,
                                                           {},
                                                           all_bindings,
                                                           irs_info,
                                                           DUMMY_TRAIL_ID);

  EXPECT_EQ(rc, HTTP_OK);
  EXPECT_EQ(all_bindings.size(), 1);

  // Delete the bindings we put in.
  SubscriberDataUtils::delete_bindings(updated_bindings);
  SubscriberDataUtils::delete_bindings(all_bindings);
  delete expected_aor; expected_aor = NULL;
}

// Test that a reregister that no longer exists results in the subscriber
// being recreated. This reregister fails during the patch to S4.
TEST_F(SubscriberManagerTest, TestReregisterRemovedSubscriber2)
{
  // Set up the expected calls. We expect a get to S4, a patch to S4 (which
  // fails with 404), a put to S4, and an analytics log for the added binding.
  // The AoR we return on the write we set up to have the expected bindings -
  // this means we can test the analytics logs.
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID, false);
  AoR* expected_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID, false, false);
  expected_aor->_notify_cseq = 1;

  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_patch(DEFAULT_ID, _, _, _))
    .WillOnce(Return(HTTP_NOT_FOUND));
  EXPECT_CALL(*_s4, handle_put(DEFAULT_ID, AoRsMatch(*expected_aor), _))
    .WillOnce(Return(HTTP_OK));
  EXPECT_CALL(*_analytics_logger, registration(DEFAULT_ID,
                                               AoRTestUtils::BINDING_ID,
                                               AoRTestUtils::CONTACT_URI,
                                               300));

  // Build the updated bindings to pass in.
  AssociatedURIs associated_uris;
  associated_uris.add_uri(DEFAULT_ID, false);
  Binding* binding = AoRTestUtils::build_binding(DEFAULT_ID, time(NULL));
  Bindings updated_bindings;
  updated_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID, binding));
  Bindings all_bindings;
  HSSConnection::irs_info irs_info;

  // Reregister subscriber on SM.
  HTTPCode rc = _subscriber_manager->reregister_subscriber(DEFAULT_ID,
                                                           "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                                           associated_uris,
                                                           updated_bindings,
                                                           {},
                                                           all_bindings,
                                                           irs_info,
                                                           DUMMY_TRAIL_ID);

  EXPECT_EQ(rc, HTTP_OK);
  EXPECT_EQ(all_bindings.size(), 1);

  // Delete the bindings we put in.
  SubscriberDataUtils::delete_bindings(updated_bindings);
  SubscriberDataUtils::delete_bindings(all_bindings);
  delete expected_aor; expected_aor = NULL;
}

// Tests the edge case where a reregister call fails because the subscriber is
// not present on the get, SM retries by registering but now the subscriber has
// magically reappeared and the put fails. Check that we don't get into a loop.
TEST_F(SubscriberManagerTest, TestReregisterRemovedSubscriberReappears)
{
  // Set up the expected calls. We expect a get to S4 (which fails with 404),
  // and a put to S4 (which fails with 412).
  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(Return(HTTP_NOT_FOUND));
  EXPECT_CALL(*_s4, handle_put(DEFAULT_ID, _, _))
    .WillOnce(Return(HTTP_PRECONDITION_FAILED));

  // Build the updated bindings to pass in.
  AssociatedURIs associated_uris;
  associated_uris.add_uri(DEFAULT_ID, false);
  Binding* binding = AoRTestUtils::build_binding(DEFAULT_ID, time(NULL));
  Bindings updated_bindings;
  updated_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID, binding));
  Bindings all_bindings;
  HSSConnection::irs_info irs_info;

  // Reregister subscriber on SM.
  HTTPCode rc = _subscriber_manager->reregister_subscriber(DEFAULT_ID,
                                                           "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                                           associated_uris,
                                                           updated_bindings,
                                                           {},
                                                           all_bindings,
                                                           irs_info,
                                                           DUMMY_TRAIL_ID);

  EXPECT_EQ(rc, HTTP_PRECONDITION_FAILED);
  EXPECT_EQ(all_bindings.size(), 0);

  // Delete the bindings we put in.
  SubscriberDataUtils::delete_bindings(updated_bindings);
  SubscriberDataUtils::delete_bindings(all_bindings);
}

// Tests the edge case where a reregister call fails because the subscriber is
// not present on the patch, SM retries by registering but now the subscriber has
// magically reappeared and the put fails. Check that we don't get into a loop.
TEST_F(SubscriberManagerTest, TestReregisterRemovedSubscriberReappears2)
{
  // Set up the expected calls. We expect a get to S4, a patch to S4 (which
  // fails with 404), and a put to S4 (which fails with 412).
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID, false);

  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_patch(DEFAULT_ID, _, _, _))
    .WillOnce(Return(HTTP_NOT_FOUND));
  EXPECT_CALL(*_s4, handle_put(DEFAULT_ID, _, _))
    .WillOnce(Return(HTTP_PRECONDITION_FAILED));

  // Build the updated bindings to pass in.
  AssociatedURIs associated_uris;
  associated_uris.add_uri(DEFAULT_ID, false);
  Binding* binding = AoRTestUtils::build_binding(DEFAULT_ID, time(NULL));
  Bindings updated_bindings;
  updated_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID, binding));
  Bindings all_bindings;
  HSSConnection::irs_info irs_info;

  // Reregister subscriber on SM.
  HTTPCode rc = _subscriber_manager->reregister_subscriber(DEFAULT_ID,
                                                           "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                                           associated_uris,
                                                           updated_bindings,
                                                           {},
                                                           all_bindings,
                                                           irs_info,
                                                           DUMMY_TRAIL_ID);

  EXPECT_EQ(rc, HTTP_PRECONDITION_FAILED);
  EXPECT_EQ(all_bindings.size(), 0);

  // Delete the bindings we put in.
  SubscriberDataUtils::delete_bindings(updated_bindings);
}

// Test that removing the final binding deregisters the subscriber.
TEST_F(SubscriberManagerTest, TestReregisterSubscriberRemoveLastBinding)
{
  // Set up the expected calls. We expect a get to S4, an analytics log for the
  // removed binding, a write to S4, a log for the added binding, a log for the
  // removed subscription, a call out to the Notify Sender, and finally a call
  // to the HSS connection.
  // The AoR we return on the lookup has a binding and subscription with the
  // same contact URI - this allows us to test that the subscription is removed
  // if the binding is removed.
  // The AoR we return on the write we set up to have the expected bindings -
  // this means we can test the analytics logs.
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID);
  AoR* empty_aor = new AoR();

  EXPECT_CALL(*_s4, handle_get(_, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, registration(_, _, _, _));
  EXPECT_CALL(*_s4, handle_patch(_, _, _, _))
    .WillOnce(DoAll(SetArgPointee<2>(empty_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, subscription(_, _, _, _));
  EXPECT_CALL(*_notify_sender, send_notifys(_, _, _, _, _, _));
  EXPECT_CALL(*_hss_connection, update_registration_state(_, _, _))
      .WillOnce(Return(HTTP_OK));

  AssociatedURIs associated_uris;
  associated_uris.add_uri(DEFAULT_ID, false);
  Bindings updated_bindings;
  Bindings all_bindings;
  HSSConnection::irs_info irs_info;
  std::vector<std::string> removed_bindings;
  removed_bindings.push_back(AoRTestUtils::BINDING_ID);

  // Reregister subscriber on SM.
  HTTPCode rc = _subscriber_manager->reregister_subscriber(DEFAULT_ID,
                                                           "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                                           associated_uris,
                                                           updated_bindings,
                                                           removed_bindings,
                                                           all_bindings,
                                                           irs_info,
                                                           DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_OK);

  // Delete the bindings we put in.
  SubscriberDataUtils::delete_bindings(updated_bindings);
  SubscriberDataUtils::delete_bindings(all_bindings);
}

// Test that removing the final binding deregisters the subscriber. In this test,
// deregistering with the HSS fails.
TEST_F(SubscriberManagerTest, TestReregisterSubscriberRemoveLastBindingHSSFail)
{
  // Set up the expected calls. We expect a get to S4, an analytics log for the
  // removed binding, a write to S4, a log for the added binding, a call out to
  // the Notify Sender and a call to the HSS connection which fails.
  // The AoR we return on the lookup has a binding and subscription with the
  // same contact URI - this allows us to test that the subscription is removed
  // if the binding is removed.
  // The AoR we return on the write we set up to have the expected bindings -
  // this means we can test the analytics logs.
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID);
  AoR* empty_aor = new AoR();

  EXPECT_CALL(*_s4, handle_get(_, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, registration(_, _, _, _));
  EXPECT_CALL(*_s4, handle_patch(_, _, _, _))
    .WillOnce(DoAll(SetArgPointee<2>(empty_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, subscription(_, _, _, _));
  EXPECT_CALL(*_notify_sender, send_notifys(_, _, _, _, _, _));
  EXPECT_CALL(*_hss_connection, update_registration_state(_, _, _))
      .WillOnce(Return(HTTP_SERVER_ERROR));

  AssociatedURIs associated_uris;
  associated_uris.add_uri(DEFAULT_ID, false);
  Bindings updated_bindings;
  Bindings all_bindings;
  HSSConnection::irs_info irs_info;
  std::vector<std::string> removed_bindings;
  removed_bindings.push_back(AoRTestUtils::BINDING_ID);

  // Reregister subscriber on SM.
  HTTPCode rc = _subscriber_manager->reregister_subscriber(DEFAULT_ID,
                                                           "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                                           associated_uris,
                                                           updated_bindings,
                                                           removed_bindings,
                                                           all_bindings,
                                                           irs_info,
                                                           DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_SERVER_ERROR);

  // Delete the bindings we put in.
  SubscriberDataUtils::delete_bindings(updated_bindings);
  SubscriberDataUtils::delete_bindings(all_bindings);
}

// Test that attempting to reregister a subscriber fails if the S4 lookup fails.
TEST_F(SubscriberManagerTest, TestReregisterSubscriberS4LookupFails)
{
  // Set up the expected calls. We expect a get to S4 that fails.
  EXPECT_CALL(*_s4, handle_get(_, _, _, _)).WillOnce(Return(HTTP_SERVER_ERROR));

  // No need to set up real bindings as we should fail before these are used.
  AssociatedURIs associated_uris;
  associated_uris.add_uri(DEFAULT_ID, false);
  Bindings updated_bindings;
  Bindings all_bindings;
  HSSConnection::irs_info irs_info;

  HTTPCode rc = _subscriber_manager->reregister_subscriber(DEFAULT_ID,
                                                           "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                                           associated_uris,
                                                           updated_bindings,
                                                           std::vector<std::string>(),
                                                           all_bindings,
                                                           irs_info,
                                                           DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_SERVER_ERROR);

  // Delete the bindings we put in.
  SubscriberDataUtils::delete_bindings(updated_bindings);
  SubscriberDataUtils::delete_bindings(all_bindings);
}

// Test that attempting to reregister a subscriber fails if the S4 write fails.
TEST_F(SubscriberManagerTest, TestReregisterSubscriberS4WriteFails)
{
  // Set up the expected calls. We expect a get to S4, an analytics log for the
  // removed binding, and then a failed write to S4
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID);

  EXPECT_CALL(*_s4, handle_get(_, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, registration(_, _, _, _));
  EXPECT_CALL(*_s4, handle_patch(_, _, _, _))
    .WillOnce(Return(HTTP_SERVER_ERROR));

  AssociatedURIs associated_uris;
  associated_uris.add_uri(DEFAULT_ID, false);
  Bindings updated_bindings;
  Bindings all_bindings;
  HSSConnection::irs_info irs_info;
  std::vector<std::string> removed_bindings;
  removed_bindings.push_back(AoRTestUtils::BINDING_ID);

  // Reregister subscriber on SM.
  HTTPCode rc = _subscriber_manager->reregister_subscriber(DEFAULT_ID,
                                                           "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                                           associated_uris,
                                                           updated_bindings,
                                                           removed_bindings,
                                                           all_bindings,
                                                           irs_info,
                                                           DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_SERVER_ERROR);

  // Delete the bindings we put in.
  SubscriberDataUtils::delete_bindings(updated_bindings);
  SubscriberDataUtils::delete_bindings(all_bindings);
}

TEST_F(SubscriberManagerTest, TestRemoveOnlyBinding)
{
  // Set up the expected calls. We expect a get to the HSS, a get to S4, an
  // analytics log for the removed binding, a write to S4, a call out to the
  // Notify Sender, a call out to the HSS, and finally a call out to the
  // registration sender.
  HSSConnection::irs_info irs_info;
  irs_info._associated_uris.add_uri(DEFAULT_ID, false);
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID);
  AoR* patch_aor = new AoR(DEFAULT_ID);
  PatchObject patch_object;

  EXPECT_CALL(*_hss_connection, get_registration_data(DEFAULT_ID, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, registration(DEFAULT_ID,
                                               AoRTestUtils::BINDING_ID,
                                               AoRTestUtils::CONTACT_URI,
                                               0));
  EXPECT_CALL(*_s4, handle_patch(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SaveArg<1>(&patch_object),
                    SetArgPointee<2>(patch_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, subscription(DEFAULT_ID,
                                               AoRTestUtils::SUBSCRIPTION_ID,
                                               AoRTestUtils::CONTACT_URI,
                                               0));
  EXPECT_CALL(*_notify_sender, send_notifys(DEFAULT_ID,
                                            AoRsMatch(*get_aor),
                                            AoRsMatch(*patch_aor),
                                            SubscriberDataUtils::EventTrigger::USER,
                                            _,
                                            _));
  EXPECT_CALL(*_hss_connection, update_registration_state(_, _, _))
    .WillOnce(Return(HTTP_OK));
  EXPECT_CALL(*_registration_sender, deregister_with_application_servers(DEFAULT_ID, _, _));

  std::vector<std::string> binding_ids = {AoRTestUtils::BINDING_ID};
  Bindings all_bindings;
  HTTPCode rc = _subscriber_manager->remove_bindings(DEFAULT_ID,
                                                     binding_ids,
                                                     SubscriberDataUtils::EventTrigger::USER,
                                                     all_bindings,
                                                     DUMMY_TRAIL_ID);

  // Check that the call was successful, that the returned bindings are empty,
  // and that the patch obhect is as expected.
  EXPECT_EQ(rc, HTTP_OK);
  ASSERT_FALSE(patch_object._remove_bindings.empty());
  EXPECT_EQ(patch_object._remove_bindings[0], AoRTestUtils::BINDING_ID);
  EXPECT_TRUE(all_bindings.empty());

  // Delete the bindings we've been passed.
  SubscriberDataUtils::delete_bindings(all_bindings);
}

// Test that removing a binding from a subscriber fails if the HSS lookup fails.
TEST_F(SubscriberManagerTest, TestRemoveBindingHSSFail)
{
  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, _))
    .WillOnce(Return(HTTP_NOT_FOUND));

  std::vector<std::string> binding_ids = {AoRTestUtils::BINDING_ID};
  Bindings all_bindings;

  HTTPCode rc = _subscriber_manager->remove_bindings(DEFAULT_ID,
                                                     binding_ids,
                                                     SubscriberDataUtils::EventTrigger::USER,
                                                     all_bindings,
                                                     DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_NOT_FOUND);

  // Delete the bindings we've been passed.
  SubscriberDataUtils::delete_bindings(all_bindings);
}

// Test that removing a binding from a subscriber fails if the S4 lookup fails
// due to a store error.
TEST_F(SubscriberManagerTest, TestRemoveBindingS4LookupFail)
{
  HSSConnection::irs_info irs_info;
  irs_info._associated_uris.add_uri(DEFAULT_ID, false);
  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_get(_, _, _, _))
    .WillOnce(Return(HTTP_SERVER_ERROR));

  std::vector<std::string> binding_ids = {AoRTestUtils::BINDING_ID};
  Bindings all_bindings;
  HTTPCode rc = _subscriber_manager->remove_bindings(DEFAULT_ID,
                                                     binding_ids,
                                                     SubscriberDataUtils::EventTrigger::USER,
                                                     all_bindings,
                                                     DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_SERVER_ERROR);

  // Delete the bindings we've been passed.
  SubscriberDataUtils::delete_bindings(all_bindings);
}

// Test that removing a binding from a subscriber succeeds if the S4 lookup
// doesn't find the subscriber.
TEST_F(SubscriberManagerTest, TestRemoveBindingS4LookupNotFound)
{
  HSSConnection::irs_info irs_info;
  irs_info._associated_uris.add_uri(DEFAULT_ID, false);
  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_get(_, _, _, _))
    .WillOnce(Return(HTTP_NOT_FOUND));

  std::vector<std::string> binding_ids = {AoRTestUtils::BINDING_ID};
  Bindings all_bindings;
  HTTPCode rc = _subscriber_manager->remove_bindings(DEFAULT_ID,
                                                     binding_ids,
                                                     SubscriberDataUtils::EventTrigger::USER,
                                                     all_bindings,
                                                     DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_OK);

  // Delete the bindings we've been passed.
  SubscriberDataUtils::delete_bindings(all_bindings);
}

// Test that removing a binding fails if the write to S4 fails.
TEST_F(SubscriberManagerTest, TestRemoveBindingS4WriteFail)
{
  // Set up the expected calls. We expect a get to the HSS, a get to S4, an
  // analytics log for the removed binding, a write to S4, a call out to the
  // Notify Sender, and finally a call out to the HSS.
  HSSConnection::irs_info irs_info;
  irs_info._associated_uris.add_uri(DEFAULT_ID, false);
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID);

  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_get(_, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, registration(_, _, _, _));
  EXPECT_CALL(*_s4, handle_patch(_, _, _, _))
    .WillOnce(Return(HTTP_SERVER_ERROR));

  std::vector<std::string> binding_ids = {AoRTestUtils::BINDING_ID};
  Bindings all_bindings;
  HTTPCode rc = _subscriber_manager->remove_bindings(DEFAULT_ID,
                                                     binding_ids,
                                                     SubscriberDataUtils::EventTrigger::USER,
                                                     all_bindings,
                                                     DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_SERVER_ERROR);

  // Delete the bindings we've been passed.
  SubscriberDataUtils::delete_bindings(all_bindings);
}

// Test that removing a binding from a subscriber fails if the HSS update
// after the subscriber is removed fails.
TEST_F(SubscriberManagerTest, TestRemoveOnlyBindingHSSFail)
{
  // Set up the expected calls. We expect a get to the HSS, a get to S4, an
  // analytics log for the removed binding, a write to S4, a call out to the
  // Notify Sender, and finally a call out to the HSS.
  HSSConnection::irs_info irs_info;
  irs_info._associated_uris.add_uri(DEFAULT_ID, false);
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID);
  AoR* patch_aor = new AoR(DEFAULT_ID);
  PatchObject patch_object;

  EXPECT_CALL(*_hss_connection, get_registration_data(DEFAULT_ID, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, registration(_, _, _, _));
  EXPECT_CALL(*_s4, handle_patch(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<2>(patch_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, subscription(_, _, _, _));
  EXPECT_CALL(*_notify_sender, send_notifys(_, _, _, _, _, _));
  EXPECT_CALL(*_hss_connection, update_registration_state(_, _, _))
    .WillOnce(Return(HTTP_SERVER_ERROR));

  std::vector<std::string> binding_ids = {AoRTestUtils::BINDING_ID};
  Bindings all_bindings;
  HTTPCode rc = _subscriber_manager->remove_bindings(DEFAULT_ID,
                                                     binding_ids,
                                                     SubscriberDataUtils::EventTrigger::USER,
                                                     all_bindings,
                                                     DUMMY_TRAIL_ID);

  EXPECT_EQ(rc, HTTP_SERVER_ERROR);

  // Delete the bindings we've been passed.
  SubscriberDataUtils::delete_bindings(all_bindings);
}

// Test adding a subscription. This test covers detailed checking of the calls
// made to S4, the analytics logger, and to the notify sender.
TEST_F(SubscriberManagerTest, TestAddSubscription)
{
  // Set up the objects to be returned on the mock calls. We want an irs_info
  // that does have a default IMPU, and two basic AoR objects (they can be as
  // simple as possible, as we're not going to do any testing involving the
  // objects, beyond having them exist so that the SM will write to S4).
  HSSConnection::irs_info irs_info;
  irs_info._associated_uris.add_uri(DEFAULT_ID, false);
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID);
  AoR* patch_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID);
  PatchObject patch_object;

  // Set up the expect calls. We expect that SM calls out to the HSS to get
  // the default IMPU and the associated URIs. It will then call out to S4
  // to get the current state of the subscriber, then to patch the subscriber.
  // The SM will then log the changed subscription, and finally call out to
  // the notify sender to send any NOTIFYs.
  EXPECT_CALL(*_hss_connection, get_registration_data(DEFAULT_ID, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_patch(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SaveArg<1>(&patch_object),
                    SetArgPointee<2>(patch_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, subscription(DEFAULT_ID,
                                               AoRTestUtils::SUBSCRIPTION_ID,
                                               AoRTestUtils::CONTACT_URI,
                                               300));
  EXPECT_CALL(*_notify_sender, send_notifys(DEFAULT_ID,
                                            AoRsMatch(*get_aor),
                                            AoRsMatch(*patch_aor),
                                            SubscriberDataUtils::EventTrigger::USER,
                                            _,
                                            _));

  // Create a subscription object that we want SM to update the stored data
  // with.
  Subscription* subscription = AoRTestUtils::build_subscription(AoRTestUtils::SUBSCRIPTION_ID, time(NULL));
  Subscriptions updated_subscriptions;
  updated_subscriptions.insert(std::make_pair(AoRTestUtils::SUBSCRIPTION_ID, subscription));

  // Call into SM to update the subscriber.
  HTTPCode rc = _subscriber_manager->update_subscriptions(DEFAULT_ID,
                                                          updated_subscriptions,
                                                          irs_info,
                                                          DUMMY_TRAIL_ID);

  // Finally, we carry out some more checks. Most of the checks are done by the
  // expect calls; we also check that the update call was successful, and that
  // the patch sent up to S4 contained the subscription object we want updating.
  EXPECT_EQ(rc, HTTP_OK);
  ASSERT_NE(patch_object._update_subscriptions.find(AoRTestUtils::SUBSCRIPTION_ID),
            patch_object._update_subscriptions.end());
  EXPECT_TRUE(*(patch_object._update_subscriptions[AoRTestUtils::SUBSCRIPTION_ID]) ==
              *(updated_subscriptions.begin()->second));
  EXPECT_TRUE(patch_object._increment_cseq);

  // Tidy up. The get/patch AoRs have been deleted by SM already.
  delete subscription; subscription = NULL;
}

// Test removing a subscription. Other tests have covered detailed checking of
// the external calls - this test checks the patch sent to S4 is to remove
// a subscription, and that the analytics log is for removing a subscription.
TEST_F(SubscriberManagerTest, TestRemoveSubscription)
{
  // Set up the objects to be returned on the mock calls. We want an irs_info
  // that does have a default IMPU, and two AoR objects. The AoR returned on
  // first lookup should contain the subscription SM is asking to remove, the
  // AoR returned after the update has succeeded should not contain the
  // subscription.
  HSSConnection::irs_info irs_info;
  irs_info._associated_uris.add_uri(DEFAULT_ID, false);
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID);
  AoR* patch_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID, false);
  PatchObject patch_object;

  // Set up the expect calls. We expect that SM calls out to the HSS to get
  // the default IMPU and the associated URIs. It will then call out to S4
  // to get the current state of the subscriber, then to patch the subscriber.
  // The SM will then log the changed subscription, and finally call out to
  // the notify sender to send any NOTIFYs.
  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_get(_, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_patch(_, _, _, _))
    .WillOnce(DoAll(SaveArg<1>(&patch_object),
                    SetArgPointee<2>(patch_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, subscription(_, _, _, 0));
  EXPECT_CALL(*_notify_sender, send_notifys(_, _, _, _, _, _));

  // Call into SM to remove the subscription
  HTTPCode rc = _subscriber_manager->remove_subscriptions(DEFAULT_ID,
                                                          {AoRTestUtils::SUBSCRIPTION_ID},
                                                          irs_info,
                                                          DUMMY_TRAIL_ID);

  // Check that the remove call was successful, and that the patch sent up to S4
  // contained the subscription ID we want removing.
  EXPECT_EQ(rc, HTTP_OK);
  ASSERT_EQ(patch_object._remove_subscriptions.size(), 1);
  EXPECT_EQ(patch_object._remove_subscriptions[0], AoRTestUtils::SUBSCRIPTION_ID);
}

// Test that updating a subscription fails when the initial lookup to the HSS
// fails.
TEST_F(SubscriberManagerTest, TestUpdateSubscriptionHSSFail)
{
  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, _))
    .WillOnce(Return(HTTP_NOT_FOUND));
  HSSConnection::irs_info irs_info;
  Subscriptions subscriptions; // Blank object to use as placeholder.
  HTTPCode rc = _subscriber_manager->update_subscriptions(DEFAULT_ID,
                                                          subscriptions,
                                                          irs_info,
                                                          DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_NOT_FOUND);
}

// Test that removing a subscription fails when the initial lookup to the HSS
// fails.
TEST_F(SubscriberManagerTest, TestRemoveSubscriptionHSSFail)
{
  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, _))
    .WillOnce(Return(HTTP_NOT_FOUND));
  HSSConnection::irs_info irs_info;
  HTTPCode rc = _subscriber_manager->remove_subscriptions(DEFAULT_ID,
                                                          {AoRTestUtils::SUBSCRIPTION_ID},
                                                          irs_info,
                                                          DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_NOT_FOUND);
}

// Test that updating a subscription fails if there's no default IMPU for the
// subscriber attempting to subscribe.
TEST_F(SubscriberManagerTest, TestUpdateSubscriptionNoDefaultIMPU)
{
  // Return an empty irs_info, so that we won't get any default IMPU.
  HSSConnection::irs_info irs_info;
  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  Subscriptions subscriptions; // Blank object to use as placeholder.
  HTTPCode rc = _subscriber_manager->update_subscriptions(DEFAULT_ID,
                                                          subscriptions,
                                                          irs_info,
                                                          DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_BAD_REQUEST);
}

// Test that removing a subscription fails if there's no default IMPU for the
// subscriber attempting to subscribe.
TEST_F(SubscriberManagerTest, TestRemoveSubscriptionNoDefaultIMPU)
{
  // Return an empty irs_info, so that we won't get any default IMPU.
  HSSConnection::irs_info irs_info;
  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  HTTPCode rc = _subscriber_manager->remove_subscriptions(DEFAULT_ID,
                                                          {AoRTestUtils::SUBSCRIPTION_ID},
                                                          irs_info,
                                                          DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_BAD_REQUEST);
}

// Test that updating a subscription fails if the initial lookup to S4 fails.
TEST_F(SubscriberManagerTest, TestUpdateSubscriptionS4LookupFail)
{
  // Set up an irs_info with a valid default IMPU.
  HSSConnection::irs_info irs_info;
  irs_info._associated_uris.add_uri(DEFAULT_ID, false);
  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_get(_, _, _, _))
    .WillOnce(Return(HTTP_SERVER_ERROR));
  Subscriptions subscriptions; // Blank object to use as placeholder.
  HTTPCode rc = _subscriber_manager->update_subscriptions(DEFAULT_ID,
                                                          subscriptions,
                                                          irs_info,
                                                          DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_SERVER_ERROR);
}

// Test that removing a subscription fails if the initial lookup to S4 fails.
TEST_F(SubscriberManagerTest, TestRemoveSubscriptionS4LookupFail)
{
  // Set up an irs_info with a valid default IMPU.
  HSSConnection::irs_info irs_info;
  irs_info._associated_uris.add_uri(DEFAULT_ID, false);
  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_get(_, _, _, _))
    .WillOnce(Return(HTTP_SERVER_ERROR));
  HTTPCode rc = _subscriber_manager->remove_subscriptions(DEFAULT_ID,
                                                          {AoRTestUtils::SUBSCRIPTION_ID},
                                                          irs_info,
                                                          DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_SERVER_ERROR);
}

// Test that updating a subscription fails if the write request to S4 fails.
TEST_F(SubscriberManagerTest, TestUpdateSubscriptionS4WriteFail)
{
  // Set up an irs_info that does have a default IMPU, and a simple AoR object
  // that SM can patch.
  HSSConnection::irs_info irs_info;
  irs_info._associated_uris.add_uri(DEFAULT_ID, false);
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID);
  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_get(_, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_patch(_, _, _, _))
    .WillOnce(Return(HTTP_SERVER_ERROR));
  Subscription* subscription = AoRTestUtils::build_subscription(AoRTestUtils::SUBSCRIPTION_ID, time(NULL));
  Subscriptions updated_subscriptions;
  updated_subscriptions.insert(std::make_pair(AoRTestUtils::SUBSCRIPTION_ID, subscription));
  HSSConnection::irs_info irs_info_out;
  HTTPCode rc = _subscriber_manager->update_subscriptions(DEFAULT_ID,
                                                          updated_subscriptions,
                                                          irs_info_out,
                                                          DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_SERVER_ERROR);
  delete subscription; subscription = NULL;
}

// Test that removing a subscription fails if the write request to S4 fails.
TEST_F(SubscriberManagerTest, TestRemoveSubscriptionS4WriteFail)
{
  // Set up an irs_info that does have a default IMPU, and a simple AoR object
  // that SM can patch.
  HSSConnection::irs_info irs_info;
  irs_info._associated_uris.add_uri(DEFAULT_ID, false);
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID);
  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_get(_, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_patch(_, _, _, _))
    .WillOnce(Return(HTTP_SERVER_ERROR));
  HSSConnection::irs_info irs_info_out;
  HTTPCode rc = _subscriber_manager->remove_subscriptions(DEFAULT_ID,
                                                          {AoRTestUtils::SUBSCRIPTION_ID},
                                                          irs_info_out,
                                                          DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_SERVER_ERROR);
}

// Test that deregistering a subscriber calls out to the correct components
TEST_F(SubscriberManagerTest, TestDeregisterSubscriber)
{
  // Set up the expected calls. We expect a get to the HSS, a get to S4, an
  // analytics log for the removed binding, a write to S4, a call out to the
  // Notify Sender, and finally a call out to the HSS.
  HSSConnection::irs_info irs_info;
  irs_info._associated_uris.add_uri(DEFAULT_ID, false);
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID);
  Binding* g_b = AoRTestUtils::build_binding(DEFAULT_ID, time(NULL), AoRTestUtils::CONTACT_URI, 300);
  get_aor->_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID + "2", g_b));
  AoR* empty_aor = new AoR();

  int version = 12;
  EXPECT_CALL(*_hss_connection, get_registration_data(DEFAULT_ID, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    SetArgReferee<2>(version),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, registration(DEFAULT_ID,
                                               AoRTestUtils::BINDING_ID,
                                               AoRTestUtils::CONTACT_URI,
                                               0));
  EXPECT_CALL(*_analytics_logger, registration(DEFAULT_ID,
                                               AoRTestUtils::BINDING_ID + "2",
                                               AoRTestUtils::CONTACT_URI,
                                               0));
  EXPECT_CALL(*_s4, handle_delete(DEFAULT_ID, version, _))
    .WillOnce(Return(HTTP_NO_CONTENT));
  EXPECT_CALL(*_notify_sender, send_notifys(DEFAULT_ID,
                                            AoRsMatch(*get_aor),
                                            AoRsMatch(*empty_aor),
                                            SubscriberDataUtils::EventTrigger::ADMIN,
                                            _,
                                            _));
  EXPECT_CALL(*_hss_connection, update_registration_state(_, _, _))
    .WillOnce(Return(HTTP_OK));
  EXPECT_CALL(*_registration_sender, deregister_with_application_servers(DEFAULT_ID, _, _));

  HTTPCode rc = _subscriber_manager->deregister_subscriber(DEFAULT_ID,
                                                           DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_OK);

  // We created empty_aor for a MATCHER - delete it now.
  delete empty_aor; empty_aor = NULL;
}

// Test that deregistering a subscriber fails if the initial HSS lookup fails.
TEST_F(SubscriberManagerTest, TestDeregisterSubscriberHSSFail)
{
  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, _))
    .WillOnce(Return(HTTP_NOT_FOUND));
  HTTPCode rc = _subscriber_manager->deregister_subscriber(DEFAULT_ID,
                                                           DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_NOT_FOUND);
}

// Test that deregistering a subscriber fails if the S4 lookup fails
TEST_F(SubscriberManagerTest, TestDeregisterSubscriberS4LookupFail)
{
  HSSConnection::irs_info irs_info;
  irs_info._associated_uris.add_uri(DEFAULT_ID, false);
  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_get(_, _, _, _)).WillOnce(Return(HTTP_SERVER_ERROR));
  HTTPCode rc = _subscriber_manager->deregister_subscriber(DEFAULT_ID,
                                                           DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_SERVER_ERROR);
}

// Test that deregistering a subscriber succeeds if the S4 lookup returns not found.
TEST_F(SubscriberManagerTest, TestDeregisterSubscriberS4LookupNotFound)
{
  HSSConnection::irs_info irs_info;
  irs_info._associated_uris.add_uri(DEFAULT_ID, false);
  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_get(_, _, _, _)).WillOnce(Return(HTTP_NOT_FOUND));
  HTTPCode rc = _subscriber_manager->deregister_subscriber(DEFAULT_ID,
                                                           DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_OK);
}

// Test that deregistering a subscriber fails if the S4 write fails.
TEST_F(SubscriberManagerTest, TestDeregisterSubscriberS4WriteFail)
{
  HSSConnection::irs_info irs_info;
  irs_info._associated_uris.add_uri(DEFAULT_ID, false);
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID);
  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    SetArgReferee<2>(1),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, registration(_, _, _, _));
  EXPECT_CALL(*_s4, handle_delete(_, _, _)).WillOnce(Return(HTTP_SERVER_ERROR));

  HTTPCode rc = _subscriber_manager->deregister_subscriber(DEFAULT_ID,
                                                           DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_SERVER_ERROR);
}

// Test that deregistering a subscriber fails if updating the HSS state fails.
TEST_F(SubscriberManagerTest, TestDeregisterSubscriberHSSFail2)
{
  // Set up the expected calls. We expect a get to the HSS, a get to S4, an
  // analytics log for the removed binding, a write to S4, a call out to the
  // Notify Sender, and finally a call out to the HSS.
  HSSConnection::irs_info irs_info;
  irs_info._associated_uris.add_uri(DEFAULT_ID, false);
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID);
  Binding* g_b = AoRTestUtils::build_binding(DEFAULT_ID, time(NULL), AoRTestUtils::CONTACT_URI, 300);
  get_aor->_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID + "2", g_b));

  int version = 12;
  EXPECT_CALL(*_hss_connection, get_registration_data(DEFAULT_ID, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    SetArgReferee<2>(version),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, registration(_, _, _, _))
    .Times(2);
  EXPECT_CALL(*_s4, handle_delete(DEFAULT_ID, version, _))
    .WillOnce(Return(HTTP_NO_CONTENT));
  EXPECT_CALL(*_notify_sender, send_notifys(_, _, _, _, _, _));
  EXPECT_CALL(*_hss_connection, update_registration_state(_, _, _))
    .WillOnce(Return(HTTP_SERVER_ERROR));

  HTTPCode rc = _subscriber_manager->deregister_subscriber(DEFAULT_ID,
                                                           DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_SERVER_ERROR);
}

// Tests getting bindings.
TEST_F(SubscriberManagerTest, TestGetBindings)
{
  // Set up AoRs to be returned by S4 - these are deleted by the handler
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID, true);

  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));

  // Call get bindings on SM.
  Bindings all_bindings;
  HTTPCode rc = _subscriber_manager->get_bindings(DEFAULT_ID,
                                                  all_bindings,
                                                  DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_OK);

  // Check that there is one binding with the correct ID.
  EXPECT_EQ(all_bindings.size(), 1);
  EXPECT_TRUE(all_bindings.find(AoRTestUtils::BINDING_ID) != all_bindings.end());

  // Delete the bindings passed out.
  SubscriberDataUtils::delete_bindings(all_bindings);
}

// Tests that an expired binding is not returned.
TEST_F(SubscriberManagerTest, TestGetExpiredBindings)
{
  // Set up AoRs to be returned by S4 - these are deleted by the handler
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID, true);
  Binding* binding = get_aor->get_binding(AoRTestUtils::BINDING_ID);
  binding->_expires -= 10000;

  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));

  // Call get bindings on SM.
  Bindings all_bindings;
  HTTPCode rc = _subscriber_manager->get_bindings(DEFAULT_ID,
                                                  all_bindings,
                                                  DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_OK);

  // Check that there is one binding with the correct ID.
  EXPECT_EQ(all_bindings.size(), 0);
}

// Tests when getting bindings from SM fails.
TEST_F(SubscriberManagerTest, TestGetBindingsFail)
{
  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(Return(HTTP_NOT_FOUND));

  // Call get bindings on SM.
  Bindings all_bindings;
  HTTPCode rc = _subscriber_manager->get_bindings(DEFAULT_ID,
                                                  all_bindings,
                                                  DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_NOT_FOUND);
}

// Tests getting subscriptions from SM.
TEST_F(SubscriberManagerTest, TestGetSubscriptions)
{
  // Set up AoRs to be returned by S4 - these are deleted by the handler
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID, true);

  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));

  // Call get subscriptions on SM.
  Subscriptions all_subscriptions;
  HTTPCode rc = _subscriber_manager->get_subscriptions(DEFAULT_ID,
                                                       all_subscriptions,
                                                       DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_OK);

  // Check that there is one subscription with the correct IDs.
  EXPECT_EQ(all_subscriptions.size(), 1);
  EXPECT_TRUE(all_subscriptions.find(AoRTestUtils::SUBSCRIPTION_ID) != all_subscriptions.end());

  // Delete the subscriptions passed out.
  SubscriberDataUtils::delete_subscriptions(all_subscriptions);
}

// Tests that expired subscriptions are not returned.
TEST_F(SubscriberManagerTest, TestGetExpiredSubscriptions)
{
  // Set up AoRs to be returned by S4 - these are deleted by the handler
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID, true);
  Subscription* subscription = get_aor->get_subscription(AoRTestUtils::SUBSCRIPTION_ID);
  subscription->_expires -= 10000;

  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));

  // Call get subscriptions on SM.
  Subscriptions all_subscriptions;
  HTTPCode rc = _subscriber_manager->get_subscriptions(DEFAULT_ID,
                                                       all_subscriptions,
                                                       DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_OK);

  // Check that there is one subscription with the correct IDs.
  EXPECT_EQ(all_subscriptions.size(), 0);
}

// Tests when getting subscriptions from SM fails.
TEST_F(SubscriberManagerTest, TestGetSubscriptionsFail)
{
  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(Return(HTTP_NOT_FOUND));

  // Call get bindings on SM.
  Subscriptions all_subscriptions;
  HTTPCode rc = _subscriber_manager->get_subscriptions(DEFAULT_ID,
                                                       all_subscriptions,
                                                       DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_NOT_FOUND);
}

// Test that updating the associated URIs is successful, and calls into the
// expected components.
TEST_F(SubscriberManagerTest, TestUpdateAssociatedURIs)
{
  // Set up AoRs to be returned by S4.
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID, true);
  AoR* patch_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID, true);
  patch_aor->_associated_uris.add_uri(OTHER_ID, false);
  PatchObject patch_object;
  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_patch(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SaveArg<1>(&patch_object),
                    SetArgPointee<2>(patch_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_notify_sender, send_notifys(DEFAULT_ID,
                                            AoRsMatch(*get_aor),
                                            AoRsMatch(*patch_aor),
                                            SubscriberDataUtils::EventTrigger::ADMIN,
                                            _,
                                            _));

  // Set up new associated URIs.
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri(DEFAULT_ID, false);
  associated_uris.add_uri(OTHER_ID, false);

  // Call update associated URIs on SM.
  HTTPCode rc = _subscriber_manager->update_associated_uris(DEFAULT_ID,
                                                            associated_uris,
                                                            DUMMY_TRAIL_ID);

  // Check that the call was successful, and the patch object contains the
  // expected associated URIs.
  EXPECT_EQ(rc, HTTP_OK);
  ASSERT_TRUE(patch_object.get_associated_uris());
  EXPECT_TRUE(((AssociatedURIs)(patch_object.get_associated_uris().get())) == associated_uris);
}

// Test that updating the associated URIs fails if the S4 lookup fails.
TEST_F(SubscriberManagerTest, TestUpdateAssociatedURIsS4LookupFail)
{
  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _)).WillOnce(Return(HTTP_SERVER_ERROR));
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri(DEFAULT_ID, false);
  associated_uris.add_uri(OTHER_ID, false);
  HTTPCode rc = _subscriber_manager->update_associated_uris(DEFAULT_ID,
                                                            associated_uris,
                                                            DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_SERVER_ERROR);
}

// Test that updating the associated URIs fails if the S4 write fails.
TEST_F(SubscriberManagerTest, TestUpdateAssociatedURIsS4WriteFail)
{
  // Set up AoRs to be returned by S4.
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID, true);
  EXPECT_CALL(*_s4, handle_get(_, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_patch(_, _, _, _)).WillOnce(Return(HTTP_SERVER_ERROR));
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri(DEFAULT_ID, false);
  associated_uris.add_uri(OTHER_ID, false);
  HTTPCode rc = _subscriber_manager->update_associated_uris(DEFAULT_ID,
                                                            associated_uris,
                                                            DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_SERVER_ERROR);
}

// Test that SM expires bindings/subscriptions on a timer pop.
TEST_F(SubscriberManagerTest, TestHandleTimerPop)
{
  int now = time(NULL);

  // Set up an AoR with one expired binding and one expired subscription.
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID);
  Binding* binding = get_aor->get_binding(AoRTestUtils::BINDING_ID);
  binding->_expires = now;
  Subscription* subscription = get_aor->get_subscription(AoRTestUtils::SUBSCRIPTION_ID);
  subscription->_expires = now;
  AoR* empty_aor = new AoR(DEFAULT_ID);
  PatchObject patch_object;

  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, registration(DEFAULT_ID,
                                               AoRTestUtils::BINDING_ID,
                                               AoRTestUtils::CONTACT_URI,
                                               0));
  EXPECT_CALL(*_s4, handle_patch(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SaveArg<1>(&patch_object),
                    SetArgPointee<2>(empty_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, subscription(DEFAULT_ID,
                                               AoRTestUtils::SUBSCRIPTION_ID,
                                               AoRTestUtils::CONTACT_URI,
                                               0));
  EXPECT_CALL(*_notify_sender, send_notifys(DEFAULT_ID,
                                            AoRsMatch(*get_aor),
                                            AoRsMatch(*empty_aor),
                                            SubscriberDataUtils::EventTrigger::TIMEOUT,
                                            _,
                                            _));
  EXPECT_CALL(*_hss_connection, update_registration_state(_, _, _))
    .WillOnce(Return(HTTP_OK));
  EXPECT_CALL(*_registration_sender, deregister_with_application_servers(DEFAULT_ID, _, _));

  // Call handle timer pops on SM.
  _subscriber_manager->handle_timer_pop(DEFAULT_ID, DUMMY_TRAIL_ID);

  // Check the patch object.
  ASSERT_FALSE(patch_object._remove_bindings.empty());
  ASSERT_FALSE(patch_object._remove_subscriptions.empty());
  EXPECT_EQ(patch_object._remove_bindings[0], AoRTestUtils::BINDING_ID);
  EXPECT_EQ(patch_object._remove_subscriptions[0], AoRTestUtils::SUBSCRIPTION_ID);
}

// Test that if the S4 lookup fails when handling a timer pop, no further action
// is taken.
TEST_F(SubscriberManagerTest, TestHandleTimerPopS4LookupFail)
{
  EXPECT_CALL(*_s4, handle_get(_, _, _, _)).WillOnce(Return(HTTP_SERVER_ERROR));
  _subscriber_manager->handle_timer_pop(DEFAULT_ID, DUMMY_TRAIL_ID);
}

// Test that if the S4 write fails when handling a timer pop, no further action
// is taken.
TEST_F(SubscriberManagerTest, TestHandleTimerPopS4WriteFail)
{
  int now = time(NULL);

  // Set up an AoR with one expired binding and one expired subscription.
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID);
  Binding* binding = get_aor->get_binding(AoRTestUtils::BINDING_ID);
  binding->_expires = now;

  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, registration(_, _, _, _));
  EXPECT_CALL(*_s4, handle_patch(_, _, _, _)).WillOnce(Return(HTTP_SERVER_ERROR));
  _subscriber_manager->handle_timer_pop(DEFAULT_ID, DUMMY_TRAIL_ID);
}

// Test what happens when SM expires bindings/subscriptions due to a timer pop
// and the HSS connection fails.
TEST_F(SubscriberManagerTest, TestHandleTimerPopHSSFail)
{
  int now = time(NULL);

  // Set up an AoR with one expired binding and one expired subscription.
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID);
  Binding* binding = get_aor->get_binding(AoRTestUtils::BINDING_ID);
  binding->_expires = now;
  Subscription* subscription = get_aor->get_subscription(AoRTestUtils::SUBSCRIPTION_ID);
  subscription->_expires = now;
  AoR* empty_aor = new AoR(DEFAULT_ID);
  PatchObject patch_object;

  // Set up expect calls. The HSS inteaction fails so we don't see any 3rd party
  // deregisters.
  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, registration(_, _, _, _));
  EXPECT_CALL(*_s4, handle_patch(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<2>(empty_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, subscription(_, _, _, _));
  EXPECT_CALL(*_notify_sender, send_notifys(_, _, _, _, _, _));
  EXPECT_CALL(*_hss_connection, update_registration_state(_, _, _))
    .WillOnce(Return(HTTP_SERVER_ERROR));

  // Call handle timer pops on SM.
  _subscriber_manager->handle_timer_pop(DEFAULT_ID, DUMMY_TRAIL_ID);
}

// Test that when SM handles a timer pop where nothing is due to expire, then
// no further action is taken.
TEST_F(SubscriberManagerTest, TestHandleTimerPopNoExpire)
{
  // Set up an AoR with no expired bindings or subscriptions.
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID);
  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    Return(HTTP_OK)));
  _subscriber_manager->handle_timer_pop(DEFAULT_ID, DUMMY_TRAIL_ID);
}

// Test that SM registers with an application server when called. SM doesn't
// touch most of the variables passed to it so don't bother checking them or
// creating realistic e.g. SIP messages.
TEST_F(SubscriberManagerTest, TestRegisterWithAS)
{
  // Set up expect calls.
  EXPECT_CALL(*_registration_sender, register_with_application_servers(_, _, _, _, _, _, _, _))
    .WillOnce(SetArgReferee<6>(false));

  _subscriber_manager->register_with_application_servers(NULL,
                                                         NULL,
                                                         DEFAULT_ID,
                                                         {},
                                                         300,
                                                         true,
                                                         DUMMY_TRAIL_ID);
}

// Test that SM registers with an application server when called. In this test
// the registraiton sender returns that the subscriber should be deregistered.
// Check that that happens.
TEST_F(SubscriberManagerTest, TestRegisterWithASDeregSub)
{
  // Set up expect calls. The subscriber should be deregistered so expect calls
  // that deregister the subscriber as well.
  EXPECT_CALL(*_registration_sender, register_with_application_servers(_, _, _, _, _, _, _, _))
    .WillOnce(SetArgReferee<6>(true));

  // The subscriber should be deregistered so expect calls that deregister the
  // subscriber as well. Don't bother checking anything though. That has been
  // done in previous tests.
  HSSConnection::irs_info irs_info;
  irs_info._associated_uris.add_uri(DEFAULT_ID, false);
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID);
  Binding* g_b = AoRTestUtils::build_binding(DEFAULT_ID, time(NULL), AoRTestUtils::CONTACT_URI, 300);
  get_aor->_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID + "2", g_b));

  int version = 12;
  EXPECT_CALL(*_hss_connection, get_registration_data(DEFAULT_ID, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(irs_info),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(get_aor),
                    SetArgReferee<2>(version),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_analytics_logger, registration(_, _, _, _))
    .Times(2);
  EXPECT_CALL(*_s4, handle_delete(DEFAULT_ID, version, _))
    .WillOnce(Return(HTTP_NO_CONTENT));
  EXPECT_CALL(*_notify_sender, send_notifys(_, _, _, _, _, _));
  EXPECT_CALL(*_hss_connection, update_registration_state(_, _, _))
    .WillOnce(Return(HTTP_OK));
  EXPECT_CALL(*_registration_sender, deregister_with_application_servers(DEFAULT_ID, _, _));

  _subscriber_manager->register_with_application_servers(NULL,
                                                         NULL,
                                                         DEFAULT_ID,
                                                         {},
                                                         300,
                                                         true,
                                                         DUMMY_TRAIL_ID);
}

TEST_F(SubscriberManagerTest, TestGetCachedSubscriberState)
{
  HSSConnection::irs_info irs_info_out;
  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, DUMMY_TRAIL_ID)).WillOnce(Return(HTTP_OK));
  EXPECT_EQ(_subscriber_manager->get_cached_subscriber_state("",
                                                             irs_info_out,
                                                             DUMMY_TRAIL_ID), HTTP_OK);

  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, DUMMY_TRAIL_ID)).WillOnce(Return(HTTP_NOT_FOUND));
  EXPECT_EQ(_subscriber_manager->get_cached_subscriber_state("",
                                                             irs_info_out,
                                                             DUMMY_TRAIL_ID), HTTP_NOT_FOUND);
}

TEST_F(SubscriberManagerTest, TestGetSubscriberState)
{
  HSSConnection::irs_info irs_info_out;
  EXPECT_CALL(*_hss_connection, update_registration_state(_, _, DUMMY_TRAIL_ID)).WillOnce(Return(HTTP_OK));
  EXPECT_EQ(_subscriber_manager->get_subscriber_state({},
                                                      irs_info_out,
                                                      DUMMY_TRAIL_ID), HTTP_OK);

  EXPECT_CALL(*_hss_connection, update_registration_state(_, _, DUMMY_TRAIL_ID)).WillOnce(Return(HTTP_NOT_FOUND));
  EXPECT_EQ(_subscriber_manager->get_subscriber_state({},
                                                      irs_info_out,
                                                      DUMMY_TRAIL_ID), HTTP_NOT_FOUND);
}
