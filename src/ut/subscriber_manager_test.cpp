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
#include "siptest.hpp"
#include "test_interposer.hpp"
#include "mock_s4.h"
#include "mock_hss_connection.h"
#include "mock_analytics_logger.h"
#include "mock_notify_sender.h"
#include "rapidxml/rapidxml.hpp"

using ::testing::_;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgReferee;
using ::testing::SetArgPointee;
using ::testing::InSequence;
using ::testing::SaveArgPointee;

static const int DUMMY_TRAIL_ID = 0;
static const std::string DEFAULT_ID = "sip:example.com";
static const std::string OTHER_ID = "sip:another.com";
static const std::string WILDCARD_ID = "sip:65055!.*!@example.com";

/// Fixture for SubscriberManagerTest.
class SubscriberManagerTest : public SipTest
{
public:
  SubscriberManagerTest()
  {
    _s4 = new MockS4();
    _hss_connection = new MockHSSConnection();
    _analytics_logger = new MockAnalyticsLogger();
    _notify_sender = new MockNotifySender();
    _subscriber_manager = new SubscriberManager(_s4,
                                                _hss_connection,
                                                _analytics_logger,
                                                _notify_sender);

    // Log all traffic
    _log_traffic = PrintingTestLogger::DEFAULT.isPrinting();
  };

  virtual ~SubscriberManagerTest()
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
    delete _notify_sender; _notify_sender = NULL;
    delete _analytics_logger; _analytics_logger = NULL;
    delete _hss_connection; _hss_connection = NULL;
    delete _s4; _s4 = NULL;
  };

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
  void delete_bindings(Bindings& bindings);
  void delete_subscriptions(Subscriptions& subscriptions);

  SubscriberManager* _subscriber_manager;
  MockS4* _s4;
  MockHSSConnection* _hss_connection;
  MockAnalyticsLogger* _analytics_logger;
  MockNotifySender* _notify_sender;

  // Common variables used by all tests.
  AoR* _get_aor = NULL;
  AoR* _patch_aor = NULL;
  HSSConnection::irs_query _irs_query;
  HSSConnection::irs_info _irs_info;
  HSSConnection::irs_info _irs_info_out;
  PatchObject _patch_object;
  Bindings _updated_bindings;
  std::vector<std::string> _remove_bindings;
  Bindings _all_bindings;
  Subscriptions _all_subscriptions;
};

void SubscriberManagerTest::delete_bindings(Bindings& bindings)
{
  for (BindingPair b : bindings)
  {
    delete b.second;
  }
}

void SubscriberManagerTest::delete_subscriptions(Subscriptions& subscriptions)
{
  for (SubscriptionPair s : subscriptions)
  {
    delete s.second;
  }
}

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
  // bindings, a write to S4, and a call out to the Notify Sender. On the write
  // to S4 we match against an expected AoR that has the single added binding.
  // The notify call should also use this expected AoR, and an empty AoR as
  // the original AoR.
  AoR empty_aor;
  AoR* expected_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID, false, false);
  expected_aor->_notify_cseq = 2;
  EXPECT_CALL(*_s4, handle_put(DEFAULT_ID, AoRsMatch(*expected_aor), _))
    .WillOnce(Return(HTTP_OK));
  EXPECT_CALL(*_analytics_logger, registration(DEFAULT_ID,
                                               AoRTestUtils::BINDING_ID,
                                               AoRTestUtils::CONTACT_URI,
                                               300));
  EXPECT_CALL(*_notify_sender, send_notifys(DEFAULT_ID,
                                            AoRsMatch(empty_aor),
                                            AoRsMatch(*expected_aor),
                                            SubscriberDataUtils::EventTrigger::USER,
                                            _,
                                            _));

  // Build the updated bindings to pass in.
  Binding* binding = AoRTestUtils::build_binding(DEFAULT_ID, time(NULL));
  Bindings updated_bindings;
  updated_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID, binding));
  AssociatedURIs associated_uris;
  associated_uris.add_uri(DEFAULT_ID, false);
  Bindings all_bindings;

  // Register subscriber on SM.
  HTTPCode rc = _subscriber_manager->register_subscriber(DEFAULT_ID,
                                                         "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                                         associated_uris,
                                                         updated_bindings,
                                                         all_bindings,
                                                         DUMMY_TRAIL_ID);


  // Now check the results. The SM call should have been successful, and the
  // returned bindings should include the binding we just added.
  EXPECT_EQ(rc, HTTP_OK);
  ASSERT_EQ(all_bindings.size(), 1);
  EXPECT_TRUE(*(all_bindings[AoRTestUtils::BINDING_ID]) == *binding);

  // Tidy up.
  delete_bindings(updated_bindings);
  delete_bindings(all_bindings);
  delete expected_aor; expected_aor = NULL;
}

// Test that registering a subscriber fails if the write to S4 fails.
TEST_F(SubscriberManagerTest, TestRegisterSubscriberWriteFail)
{
  // Set up expect calls to the HSS and S4.
  EXPECT_CALL(*_s4, handle_put(_, _, _)).WillOnce(Return(HTTP_SERVER_ERROR));

  // Build the updated bindings to pass in.
  Binding* binding = AoRTestUtils::build_binding(DEFAULT_ID, time(NULL));
  Bindings updated_bindings;
  updated_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID, binding));
  AssociatedURIs associated_uris;
  associated_uris.add_uri(DEFAULT_ID, false);
  Bindings all_bindings;

  // Register subscriber on SM.
  HTTPCode rc = _subscriber_manager->register_subscriber(DEFAULT_ID,
                                                         "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                                         associated_uris,
                                                         updated_bindings,
                                                         all_bindings,
                                                         DUMMY_TRAIL_ID);

  EXPECT_EQ(rc, HTTP_SERVER_ERROR);

  // Delete the bindings we put in.
  delete_bindings(updated_bindings);
}

// Test attempting to register a subscriber that already exists. SM should
// retry the write to S4, so from the clients POV this succeeds.
TEST_F(SubscriberManagerTest, TestRegisterSubscriberAlreadyExists)
{
  // Set up the expected calls. We expect an analytics log for the added
  // bindings, a write to S4 (which fails with a 412), then another write
  // to S4, and finally a call out to the Notify Sender. On the second write
  // to S4 we match against an expected AoR that has the single added binding.
  PatchObject patch_object;
  AoR* patch_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID, false, false);
  EXPECT_CALL(*_s4, handle_put(_, _, _)).WillOnce(Return(HTTP_PRECONDITION_FAILED));
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
  HTTPCode rc = _subscriber_manager->register_subscriber(DEFAULT_ID,
                                                         "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                                         associated_uris,
                                                         updated_bindings,
                                                         all_bindings,
                                                         DUMMY_TRAIL_ID);

  // Finally, check that the call was successful. This also checks the patch
  // object.
  EXPECT_EQ(rc, HTTP_OK);
  ASSERT_NE(patch_object._update_bindings.find(AoRTestUtils::BINDING_ID),
            patch_object._update_bindings.end());
  EXPECT_TRUE(*(patch_object._update_bindings[AoRTestUtils::BINDING_ID]) ==
              *(updated_bindings[AoRTestUtils::BINDING_ID]));
  EXPECT_TRUE(patch_object._increment_cseq);

  // Delete the bindings we put in.
  delete_bindings(updated_bindings);
  delete_bindings(all_bindings);
}

// Test attempting to register a subscriber that already exists. SM should
// retry the write to S4 - in this test the second write fails, so the
// register fails.
TEST_F(SubscriberManagerTest, TestRegisterSubscriberAlreadyExistsWriteFails)
{
  // Set up the expected calls. We expect an analytics log for the added
  // bindings, a write to S4 (which fails with a 412), then another write
  // to S4, and finally a call out to the Notify Sender. On the second write
  // to S4 we match against an expected AoR that has the single added binding.
  //AoR* expected_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID, false, false);
  //expected_aor->_notify_cseq = 2;
  EXPECT_CALL(*_s4, handle_put(_, _, _)).WillOnce(Return(HTTP_PRECONDITION_FAILED));
  EXPECT_CALL(*_s4, handle_patch(_, _, _, _)).WillOnce(Return(HTTP_SERVER_ERROR));

  // Build the updated bindings to pass in.
  Binding* binding = AoRTestUtils::build_binding(DEFAULT_ID, time(NULL));
  Bindings updated_bindings;
  updated_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID, binding));
  AssociatedURIs associated_uris;
  associated_uris.add_uri(DEFAULT_ID, false);
  Bindings all_bindings;

  // Register subscriber on SM.
  HTTPCode rc = _subscriber_manager->register_subscriber(DEFAULT_ID,
                                                         "sip:scscf.sprout.homedomain:5058;transport=TCP",
                                                         associated_uris,
                                                         updated_bindings,
                                                         all_bindings,
                                                         DUMMY_TRAIL_ID);

  EXPECT_EQ(rc, HTTP_SERVER_ERROR);

  // Delete the bindings we put in.
  delete_bindings(updated_bindings);
}

// Test that reregistering a subscriber is successful. The test adds a binding
// and removes a bindings (which is an edge case for a reregister, but it's
// useful to have a complicated case and then check everything about it).
TEST_F(SubscriberManagerTest, TestReregisterSubscriber)
{
  // Set up the expected calls. We expect a get to S4, an analytics log for the
  // removed binding, a write to S4, a log for the added binding, and finally
  // a call out to the Notify Sender.
  // The AoR we return on the lookup has a binding and subscription with the
  // same contact URI - this allows us to test that the subscription is removed
  // if the binding is removed.
  // The AoR we return on the write we set up to have the expected bindings -
  // this means we can test the analytics logs.
  AoR* get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID);
  AoR* patch_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID);
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
                                                           associated_uris,
                                                           updated_bindings,
                                                           removed_bindings,
                                                           all_bindings,
                                                           irs_info,
                                                           DUMMY_TRAIL_ID);

  // Finally, we carry out some more checks. Most of the checks are done by the
  // expect calls; we also check that the reregistere call was successful, and
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
  delete_bindings(updated_bindings);
  delete_bindings(all_bindings);
}

// Test that removing the final binding deregisters the subscriber.
TEST_F(SubscriberManagerTest, TestReregisterSubscriberRemoveLastBinding)
{
  // Set up the expected calls. We expect a get to S4, an analytics log for the
  // removed binding, a write to S4, a log for the added binding, and finally
  // a call out to the Notify Sender.
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
                                                           associated_uris,
                                                           updated_bindings,
                                                           removed_bindings,
                                                           all_bindings,
                                                           irs_info,
                                                           DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_OK);

  // Delete the bindings we put in.
  delete_bindings(updated_bindings);
  delete_bindings(all_bindings);
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
                                                           associated_uris,
                                                           updated_bindings,
                                                           std::vector<std::string>(),
                                                           all_bindings,
                                                           irs_info,
                                                           DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_SERVER_ERROR);

  // Delete the bindings we put in.
  delete_bindings(updated_bindings);
  delete_bindings(all_bindings);
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
                                                           associated_uris,
                                                           updated_bindings,
                                                           removed_bindings,
                                                           all_bindings,
                                                           irs_info,
                                                           DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_SERVER_ERROR);

  // Delete the bindings we put in.
  delete_bindings(updated_bindings);
  delete_bindings(all_bindings);
}


TEST_F(SubscriberManagerTest, TestRemoveOnlyBinding)
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
  EXPECT_CALL(*_analytics_logger, registration(DEFAULT_ID,
                                               AoRTestUtils::BINDING_ID,
                                               AoRTestUtils::CONTACT_URI,
                                               0));
  EXPECT_CALL(*_s4, handle_patch(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SaveArg<1>(&patch_object),
                    SetArgPointee<2>(patch_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_notify_sender, send_notifys(DEFAULT_ID,
                                            AoRsMatch(*get_aor),
                                            AoRsMatch(*patch_aor),
                                            SubscriberDataUtils::EventTrigger::USER,
                                            _,
                                            _));
  EXPECT_CALL(*_hss_connection, update_registration_state(_, _, _))
    .WillOnce(Return(HTTP_OK));

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
  delete_bindings(all_bindings);
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
  delete_bindings(all_bindings);
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
  delete_bindings(all_bindings);
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
  delete_bindings(all_bindings);
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
  delete_bindings(all_bindings);
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
  SubscriptionPair updated_subscription = std::make_pair(AoRTestUtils::SUBSCRIPTION_ID, subscription);

  // Call into SM to update the subscriber.
  HTTPCode rc = _subscriber_manager->update_subscription(DEFAULT_ID,
                                                         updated_subscription,
                                                         irs_info,
                                                         DUMMY_TRAIL_ID);

  // Finally, we carry out some more checks. Most of the checks are done by the
  // expect calls; we also check that the update call was successful, and that
  // the patch sent up to S4 contained the subscription object we want updating.
  EXPECT_EQ(rc, HTTP_OK);
  ASSERT_NE(patch_object._update_subscriptions.find(AoRTestUtils::SUBSCRIPTION_ID),
            patch_object._update_subscriptions.end());
  EXPECT_TRUE(*(patch_object._update_subscriptions[AoRTestUtils::SUBSCRIPTION_ID]) ==
              *(updated_subscription.second));
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
  HTTPCode rc = _subscriber_manager->remove_subscription(DEFAULT_ID,
                                                         AoRTestUtils::SUBSCRIPTION_ID,
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
  HTTPCode rc = _subscriber_manager->update_subscription(DEFAULT_ID,
                                                         SubscriptionPair(),
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
  HTTPCode rc = _subscriber_manager->remove_subscription(DEFAULT_ID,
                                                         AoRTestUtils::SUBSCRIPTION_ID,
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
  HTTPCode rc = _subscriber_manager->update_subscription(DEFAULT_ID,
                                                         SubscriptionPair(),
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
  HTTPCode rc = _subscriber_manager->remove_subscription(DEFAULT_ID,
                                                         AoRTestUtils::SUBSCRIPTION_ID,
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
  HTTPCode rc = _subscriber_manager->update_subscription(DEFAULT_ID,
                                                         SubscriptionPair(),
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
  HTTPCode rc = _subscriber_manager->remove_subscription(DEFAULT_ID,
                                                         AoRTestUtils::SUBSCRIPTION_ID,
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
  SubscriptionPair updated_subscription = std::make_pair(AoRTestUtils::SUBSCRIPTION_ID, subscription);
  HTTPCode rc = _subscriber_manager->update_subscription(DEFAULT_ID,
                                                         updated_subscription,
                                                         _irs_info_out,
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
  HTTPCode rc = _subscriber_manager->remove_subscription(DEFAULT_ID,
                                                         AoRTestUtils::SUBSCRIPTION_ID,
                                                         _irs_info_out,
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

  HTTPCode rc = _subscriber_manager->deregister_subscriber(DEFAULT_ID,
                                                           SubscriberDataUtils::EventTrigger::ADMIN,
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
                                                           SubscriberDataUtils::EventTrigger::ADMIN,
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
                                                           SubscriberDataUtils::EventTrigger::ADMIN,
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
                                                           SubscriberDataUtils::EventTrigger::ADMIN,
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
                                                           SubscriberDataUtils::EventTrigger::ADMIN,
                                                           DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_SERVER_ERROR);
}

// SS5-TODO add test for precondition failed (data contention)

TEST_F(SubscriberManagerTest, TestGetBindingsFail)
{
  // Set up expect calls to S4.
  {
    InSequence s;
    EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
      .WillOnce(Return(HTTP_NOT_FOUND));
  }

  // Call get bindings on SM.
  HTTPCode rc = _subscriber_manager->get_bindings(DEFAULT_ID,
                                                  _all_bindings,
                                                  DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_NOT_FOUND);
}


TEST_F(SubscriberManagerTest, TestGetBindings)
{
  // Set up AoRs to be returned by S4 - these are deleted by the handler
  _get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID, true);

  // Set up expect calls to S4.
  {
    InSequence s;
    EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(_get_aor),
                      Return(HTTP_OK)));
  }

  // Call get bindings on SM.
  HTTPCode rc = _subscriber_manager->get_bindings(DEFAULT_ID,
                                                  _all_bindings,
                                                  DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_OK);

  // Check that there is one subscription with the correct IDs.
  EXPECT_TRUE(_all_bindings.find(AoRTestUtils::BINDING_ID) != _all_bindings.end());

  // Delete the bindings passed out.
  delete_bindings(_all_bindings);
}

TEST_F(SubscriberManagerTest, TestGetSubscriptionsFail)
{
  // Set up expect calls to S4.
  {
    InSequence s;
    EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
      .WillOnce(Return(HTTP_NOT_FOUND));
  }

  // Call get bindings on SM.
  HTTPCode rc = _subscriber_manager->get_subscriptions(DEFAULT_ID,
                                                       _all_subscriptions,
                                                       DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_NOT_FOUND);
}

TEST_F(SubscriberManagerTest, TestGetSubscriptions)
{
  // Set up AoRs to be returned by S4 - these are deleted by the handler
  _get_aor = AoRTestUtils::create_simple_aor(DEFAULT_ID, true);

  // Set up expect calls to S4.
  {
    InSequence s;
    EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(_get_aor),
                      Return(HTTP_OK)));
  }

  // Call get subscriptions on SM.
  HTTPCode rc = _subscriber_manager->get_subscriptions(DEFAULT_ID,
                                                       _all_subscriptions,
                                                       DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_OK);

  // Check that there is one subscription with the correct IDs.
  EXPECT_TRUE(_all_subscriptions.find(AoRTestUtils::SUBSCRIPTION_ID) != _all_subscriptions.end());

  // Delete the subscriptions passed out.
  delete_subscriptions(_all_subscriptions);
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
// SS5-TODO: Why doesn't this call out to the HSS.
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
  EXPECT_CALL(*_notify_sender, send_notifys(DEFAULT_ID,
                                            AoRsMatch(*get_aor),
                                            AoRsMatch(*empty_aor),
                                            SubscriberDataUtils::EventTrigger::USER,
                                            _,
                                            _));
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

TEST_F(SubscriberManagerTest, TestGetCachedSubscriberState)
{
  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, DUMMY_TRAIL_ID)).WillOnce(Return(HTTP_OK));
  EXPECT_EQ(_subscriber_manager->get_cached_subscriber_state("",
                                                             _irs_info_out,
                                                             DUMMY_TRAIL_ID), HTTP_OK);

  EXPECT_CALL(*_hss_connection, get_registration_data(_, _, DUMMY_TRAIL_ID)).WillOnce(Return(HTTP_NOT_FOUND));
  EXPECT_EQ(_subscriber_manager->get_cached_subscriber_state("",
                                                             _irs_info_out,
                                                             DUMMY_TRAIL_ID), HTTP_NOT_FOUND);
}

TEST_F(SubscriberManagerTest, TestGetSubscriberState)
{
  EXPECT_CALL(*_hss_connection, update_registration_state(_, _, DUMMY_TRAIL_ID)).WillOnce(Return(HTTP_OK));
  EXPECT_EQ(_subscriber_manager->get_subscriber_state(_irs_query,
                                                      _irs_info_out,
                                                      DUMMY_TRAIL_ID), HTTP_OK);

  EXPECT_CALL(*_hss_connection, update_registration_state(_, _, DUMMY_TRAIL_ID)).WillOnce(Return(HTTP_NOT_FOUND));
  EXPECT_EQ(_subscriber_manager->get_subscriber_state(_irs_query,
                                                      _irs_info_out,
                                                      DUMMY_TRAIL_ID), HTTP_NOT_FOUND);
}
