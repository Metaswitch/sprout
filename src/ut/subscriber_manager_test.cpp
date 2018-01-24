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
#include "aor_test_utils.h"
#include "siptest.hpp"
#include "test_interposer.hpp"
#include "mock_s4.h"
#include "mock_hss_connection.h"
#include "mock_analytics_logger.h"

using ::testing::_;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgReferee;
using ::testing::SetArgPointee;
using ::testing::InSequence;

static const int DUMMY_TRAIL_ID = 0;
static const std::string DEFAULT_ID = "sip:example.com";
static const std::string OTHER_ID = "sip:another.com";

/// Fixture for SubscriberManagerTest.
class SubscriberManagerTest : public SipTest
{
public:
  SubscriberManagerTest()
  {
    _s4 = new MockS4();
    _hss_connection = new MockHSSConnection();
    _analytics_logger = new MockAnalyticsLogger();
    _subscriber_manager = new SubscriberManager(_s4,
                                                _hss_connection,
                                                _analytics_logger);

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
    delete _s4; _s4 = NULL;
    delete _hss_connection; _hss_connection = NULL;
    delete _analytics_logger; _analytics_logger = NULL;
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
  void set_up_irs_and_aor();

  void add_binding_expect_calls();
  void update_bindings_expect_calls(bool binding_changed = true,
                                    int expiry = 300);
  void registration_log_expect_call(int expiry = 300,
                                    std::string contact = AoRTestUtils::CONTACT_URI,
                                    std::string binding_id = AoRTestUtils::BINDING_ID,
                                    std::string aor_id = DEFAULT_ID);
  void update_bindings();

  void subscription_expect_calls(bool subscription_changed = true,
                                 int expiry = 300);
  void subscription_log_expect_call(int expiry = 300,
                                    std::string contact = AoRTestUtils::CONTACT_URI,
                                    std::string subscription_id = AoRTestUtils::SUBSCRIPTION_ID,
                                    std::string aor_id = DEFAULT_ID);

  void update_subscription();

  void delete_bindings(Bindings& bindings);
  void delete_subscriptions(Subscriptions& subscriptions);

  SubscriberManager* _subscriber_manager;
  MockS4* _s4;
  MockHSSConnection* _hss_connection;
  MockAnalyticsLogger* _analytics_logger;

  // Common variables used by all tests.
  AoR* _get_aor = NULL;
  AoR* _patch_aor = NULL;
  HSSConnection::irs_query _irs_query;
  HSSConnection::irs_info _irs_info;
  HSSConnection::irs_info _irs_info_out;
  PatchObject _patch_object;
  Bindings _updated_bindings;
  SubscriptionPair _updated_subscription;
  Bindings _all_bindings;
  Subscriptions _all_subscriptions;

};

// Sets up an IRS with a single public ID and a
void SubscriberManagerTest::set_up_irs_and_aor()
{
  // Set up an IRS to be returned by the mocked update_registration_state()
  // call.
  _irs_info._associated_uris.add_uri(DEFAULT_ID, false);

  // Set up AoRs to be returned by S4.
  _get_aor = AoRTestUtils::build_aor(DEFAULT_ID);
  _patch_aor = AoRTestUtils::build_aor(DEFAULT_ID);
}

void SubscriberManagerTest::add_binding_expect_calls()
{
  InSequence s;
  EXPECT_CALL(*_hss_connection, update_registration_state(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(_irs_info),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(_get_aor),
                    Return(HTTP_NOT_FOUND)));
  EXPECT_CALL(*_s4, handle_put(DEFAULT_ID, _, _)) // TODO save off the AoR here and check it.
    .WillOnce(Return(HTTP_OK));
  EXPECT_CALL(*_analytics_logger, registration(DEFAULT_ID,
                                               AoRTestUtils::BINDING_ID,
                                               AoRTestUtils::CONTACT_URI,
                                               300)).Times(1);
}

// Sets up the expect calls to the HSS and S4 when update_binding() is called.
void SubscriberManagerTest::update_bindings_expect_calls(bool binding_changed,
                                                         int expiry)
{
  InSequence s;
  EXPECT_CALL(*_hss_connection, update_registration_state(_, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(_irs_info),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(_get_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_patch(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SaveArg<1>(&_patch_object),
                    SetArgPointee<2>(_patch_aor),
                    Return(HTTP_OK)));
  if (binding_changed)
  {
    registration_log_expect_call(expiry);
  }
}

void SubscriberManagerTest::registration_log_expect_call(
                              int expiry,
                              std::string contact,
                              std::string binding_id,
                              std::string aor_id)
{
  EXPECT_CALL(*_analytics_logger, registration(aor_id,
                                               binding_id,
                                               contact,
                                               expiry)).Times(1);
}

// Calls update_bindings() and checks what is returned.
void SubscriberManagerTest::update_bindings()
{
  // Update binding on SM.
  HTTPCode rc = _subscriber_manager->update_bindings(_irs_query,
                                                     _updated_bindings,
                                                     std::vector<std::string>(),
                                                     _all_bindings,
                                                     _irs_info_out,
                                                     DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_OK);

  // Check that the patch object contains the expected binding.
  Bindings ub = _patch_object.get_update_bindings();
  EXPECT_EQ(ub.size(), 1);
  EXPECT_TRUE(ub.find(AoRTestUtils::BINDING_ID) != ub.end());

  // Check that the binding we set is returned in all bindings.
  EXPECT_EQ(_all_bindings.size(), 1);
  EXPECT_TRUE(_all_bindings.find(AoRTestUtils::BINDING_ID) != _all_bindings.end());

  // Delete the bindings we put in and the ones passed out.
  delete_bindings(_updated_bindings);
  delete_bindings(_all_bindings);
}


void SubscriberManagerTest::subscription_expect_calls(bool subscription_changed,
                                                      int expiry)
{
  InSequence s;
  EXPECT_CALL(*_hss_connection, get_registration_data(DEFAULT_ID, _, _))
    .WillOnce(DoAll(SetArgReferee<1>(_irs_info),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SetArgPointee<1>(_get_aor),
                    Return(HTTP_OK)));
  EXPECT_CALL(*_s4, handle_patch(DEFAULT_ID, _, _, _))
    .WillOnce(DoAll(SaveArg<1>(&_patch_object),
                    SetArgPointee<2>(_patch_aor),
                    Return(HTTP_OK)));
  if (subscription_changed)
  {
    subscription_log_expect_call(expiry);
  }
}

void SubscriberManagerTest::subscription_log_expect_call(
                              int expiry,
                              std::string contact,
                              std::string subscription_id,
                              std::string aor_id)
{
  EXPECT_CALL(*_analytics_logger, subscription(aor_id,
                                               subscription_id,
                                               contact,
                                               expiry)).Times(1);
}

void SubscriberManagerTest::update_subscription()
{
  // Update subscription on SM.
  HTTPCode rc = _subscriber_manager->update_subscription(DEFAULT_ID,
                                                         _updated_subscription,
                                                         _irs_info_out,
                                                         DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_OK);

  // Check that the patch object contains the expected subscription.
  EXPECT_TRUE(_patch_object._update_subscriptions.find(AoRTestUtils::SUBSCRIPTION_ID) != _patch_object._update_subscriptions.end());

  // Delete the subscription we put in.
  delete _updated_subscription.second; _updated_subscription.second = NULL;
}

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

TEST_F(SubscriberManagerTest, TestAddFirstBinding)
{
  // Set up an IRS to be returned by the mocked update_registration_state()
  // call.
  _irs_info._associated_uris.add_uri(DEFAULT_ID, false);

  // Set up AoRs to be returned by S4.
  _get_aor = NULL;

  // Set up expect calls to the HSS and S4.
  add_binding_expect_calls();

  // Build the updated bindings to pass in.
  Binding* binding = AoRTestUtils::build_binding(DEFAULT_ID, time(NULL));
  _updated_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID, binding));

  // Update bindings on SM.
  HTTPCode rc = _subscriber_manager->update_bindings(_irs_query,
                                                     _updated_bindings,
                                                     std::vector<std::string>(),
                                                     _all_bindings,
                                                     _irs_info_out,
                                                     DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_OK);

  // Check that the PUT AoR is correct. TODO

  // Check that the bindings we set is returned in all bindings.
  EXPECT_EQ(_all_bindings.size(), 1);
  EXPECT_TRUE(_all_bindings.find(AoRTestUtils::BINDING_ID) != _all_bindings.end());

  // Delete the bindings we put in and the ones passed out.
  delete_bindings(_updated_bindings);
  delete_bindings(_all_bindings);
}

TEST_F(SubscriberManagerTest, TestAddBinding)
{
  // Set up an IRS to be returned by the mocked update_registration_state()
  // call.
  _irs_info._associated_uris.add_uri(DEFAULT_ID, false);

  // Set up AoRs to be returned by S4.
  _get_aor = new AoR(DEFAULT_ID);
  _patch_aor = AoRTestUtils::build_aor(DEFAULT_ID, false);

  update_bindings_expect_calls();

  // Build the updated bindings to pass in.
  Binding* binding = AoRTestUtils::build_binding(DEFAULT_ID, time(NULL));
  _updated_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID, binding));

  update_bindings();

  // No subscriptions so there should be no NOTIFYs.
  ASSERT_EQ(0, txdata_count());
}

TEST_F(SubscriberManagerTest, TestRefreshBinding)
{
  set_up_irs_and_aor();

  // Modify the binding in the patch AoR to give it a longer expiry time.
  Binding* refreshed_binding = _patch_aor->get_binding(AoRTestUtils::BINDING_ID);
  refreshed_binding->_expires += 10;

  update_bindings_expect_calls(true, 310);

  // Build the updated bindings to pass in.
  Binding* binding = AoRTestUtils::build_binding(DEFAULT_ID, time(NULL));
  binding->_expires += 10;
  _updated_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID, binding));

  // Update binding on SM.
  update_bindings();

  // We should have a NOTIFY.
  ASSERT_EQ(1, txdata_count());
  free_txdata();
}

TEST_F(SubscriberManagerTest, TestShortenBinding)
{
  set_up_irs_and_aor();

  // Modify the binding in the patch AoR to give it a shorter expiry time.
  Binding* shortened_binding = _patch_aor->get_binding(AoRTestUtils::BINDING_ID);
  shortened_binding->_expires -= 10;

  update_bindings_expect_calls(true, 290);

  // Build the updated bindings to pass in.
  Binding* binding = AoRTestUtils::build_binding(DEFAULT_ID, time(NULL));
  binding->_expires -= 10;
  _updated_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID, binding));

  // Update binding on SM.
  update_bindings();

  // We should have a NOTIFY.
  ASSERT_EQ(1, txdata_count());
  free_txdata();
}

TEST_F(SubscriberManagerTest, TestUnchangedBinding)
{
  set_up_irs_and_aor();

  update_bindings_expect_calls(false);

  // Build the updated bindings to pass in.
  Binding* binding = AoRTestUtils::build_binding(DEFAULT_ID, time(NULL));
  _updated_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID, binding));

  // Update binding on SM.
  update_bindings();

  // We should not have a NOTIFY since the binding is unchanged.
  ASSERT_EQ(0, txdata_count());
}

TEST_F(SubscriberManagerTest, TestContactChangedBinding)
{
  set_up_irs_and_aor();

  // Modify the binding in the patch AoR to give it a different contact.
  Binding* refreshed_binding = _patch_aor->get_binding(AoRTestUtils::BINDING_ID);
  refreshed_binding->_uri = "<sip:6505550231@10.225.20.18:5991;transport=tcp;ob>;";

  update_bindings_expect_calls(false);

  // Build the updated bindings to pass in.
  Binding* binding = AoRTestUtils::build_binding(DEFAULT_ID, time(NULL));
  binding->_uri = "<sip:6505550231@10.225.20.18:5991;transport=tcp;ob>;";
  _updated_bindings.insert(std::make_pair(AoRTestUtils::BINDING_ID, binding));

  // Update binding on SM.
  update_bindings();

  // We should have a NOTIFYs. TODO need to check that it contains both the
  // deactived binding and the new binding.
  ASSERT_EQ(1, txdata_count());
  free_txdata();
}

TEST_F(SubscriberManagerTest, TestRemoveBinding)
{
  // Set up an IRS to be returned by the mocked update_registration_state()
  // call.
  _irs_info._associated_uris.add_uri(DEFAULT_ID, false);

  // Set up AoRs to be returned by S4.
  _get_aor = AoRTestUtils::build_aor(DEFAULT_ID, false);
  _patch_aor = new AoR(DEFAULT_ID);

  // Set up expect calls to the HSS and S4.
  {
    InSequence s;
    EXPECT_CALL(*_hss_connection, get_registration_data(DEFAULT_ID, _, _))
      .WillOnce(DoAll(SetArgReferee<1>(_irs_info),
                      Return(HTTP_OK)));
    EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(_get_aor),
                      Return(HTTP_OK)));
    EXPECT_CALL(*_s4, handle_patch(DEFAULT_ID, _, _, _))
      .WillOnce(DoAll(SaveArg<1>(&_patch_object),
                      SetArgPointee<2>(_patch_aor),
                      Return(HTTP_OK)));
    EXPECT_CALL(*_hss_connection, update_registration_state(_, _, _))
      .WillOnce(Return(HTTP_OK));
  }

  std::vector<std::string> binding_ids = {AoRTestUtils::BINDING_ID};
  HTTPCode rc = _subscriber_manager->remove_bindings(DEFAULT_ID,
                                                     binding_ids,
                                                     SubscriberManager::EventTrigger::USER,
                                                     _all_bindings,
                                                     DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_OK);

  // Check that the patch object contains the expected bindings.
  std::vector<std::string> rb = _patch_object._remove_bindings;
  EXPECT_EQ(rb.size(), 1);
  EXPECT_TRUE(std::find(rb.begin(), rb.end(), AoRTestUtils::BINDING_ID) != rb.end());

  // Check that the bindings we removed are not returned in _all_bindings.
  EXPECT_TRUE(_all_bindings.empty());

  // Delete the bindings we've been passed.
  delete_bindings(_all_bindings);
}

TEST_F(SubscriberManagerTest, TestAddNewSubscription)
{
  // Set up an IRS to be returned by the mocked get_registration_data()
  // call.
  _irs_info._associated_uris.add_uri(DEFAULT_ID, false);

  // Set up AoRs to be returned by S4.
  _get_aor = AoRTestUtils::build_aor(DEFAULT_ID, false);
  _patch_aor = AoRTestUtils::build_aor(DEFAULT_ID, true);

  subscription_expect_calls();

  Subscription* subscription = AoRTestUtils::build_subscription(AoRTestUtils::SUBSCRIPTION_ID, time(NULL));
  _updated_subscription = std::make_pair(AoRTestUtils::SUBSCRIPTION_ID, subscription);

  // Update subscriptions on SM.
  update_subscription();

  // Subscription has been added so expect a NOTIFY.
  ASSERT_EQ(1, txdata_count());
  free_txdata();
}

TEST_F(SubscriberManagerTest, TestRemoveSubscription)
{
  // Set up an IRS to be returned by the mocked get_registration_data()
  // call.
  _irs_info._associated_uris.add_uri(DEFAULT_ID, false);

  // Set up AoRs to be returned by S4.
  _get_aor = AoRTestUtils::build_aor(DEFAULT_ID, true);
  _patch_aor = AoRTestUtils::build_aor(DEFAULT_ID, false);

  subscription_expect_calls(true, 0);

  HTTPCode rc = _subscriber_manager->remove_subscription(DEFAULT_ID,
                                                         AoRTestUtils::SUBSCRIPTION_ID,
                                                         _irs_info_out,
                                                         DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_OK);

  // Check that the patch object contains the expected subscription.
  std::vector<std::string> rs = _patch_object._remove_subscriptions;
  EXPECT_TRUE(std::find(rs.begin(), rs.end(), AoRTestUtils::SUBSCRIPTION_ID) != rs.end());

  // Subscription has been removed so expect a final NOTIFY.
  ASSERT_EQ(1, txdata_count());
  free_txdata();
}

TEST_F(SubscriberManagerTest, TestRefreshSubscription)
{
  set_up_irs_and_aor();

  // Modify the subscription in the patch AoR to give it a longer expiry time.
  Subscription* refreshed_subscription = _patch_aor->get_subscription(AoRTestUtils::SUBSCRIPTION_ID);
  refreshed_subscription->_refreshed = true;
  refreshed_subscription->_expires += 10;

  subscription_expect_calls(true, 310);

  Subscription* subscription = AoRTestUtils::build_subscription(AoRTestUtils::SUBSCRIPTION_ID, time(NULL));
  subscription->_refreshed = true;
  subscription->_expires += 10;
  _updated_subscription = std::make_pair(AoRTestUtils::SUBSCRIPTION_ID, subscription);

  // Update subscriptions on SM.
  update_subscription();

  // Subscription has been refreshed so expect a NOTIFY.
  ASSERT_EQ(1, txdata_count());
  free_txdata();
}

TEST_F(SubscriberManagerTest, TestShortenSubscription)
{
  set_up_irs_and_aor();

  // Modify the subscription in the patch AoR to give it a longer expiry time.
  Subscription* shortened_subscription = _patch_aor->get_subscription(AoRTestUtils::SUBSCRIPTION_ID);
  shortened_subscription->_expires -= 10;

  subscription_expect_calls(true, 290);

  Subscription* subscription = AoRTestUtils::build_subscription(AoRTestUtils::SUBSCRIPTION_ID, time(NULL));
  subscription->_expires -= 10;
  _updated_subscription = std::make_pair(AoRTestUtils::SUBSCRIPTION_ID, subscription);

  // Update subscriptions on SM.
  update_subscription();

  // Subscription has been shortened so expect a NOTIFY.
  ASSERT_EQ(1, txdata_count());
  free_txdata();
}

TEST_F(SubscriberManagerTest, TestUnchangedSubscription)
{
  set_up_irs_and_aor();

  subscription_expect_calls(false);

  Subscription* subscription = AoRTestUtils::build_subscription(AoRTestUtils::SUBSCRIPTION_ID, time(NULL));
  _updated_subscription = std::make_pair(AoRTestUtils::SUBSCRIPTION_ID, subscription);

  // Update subscriptions on SM.
  update_subscription();

  // Subscription unchanged so do NOT expect a NOTIFY.
  ASSERT_EQ(0, txdata_count());
}

TEST_F(SubscriberManagerTest, TestDeregisterSubscriber)
{
  // Set up an IRS to be returned by the mocked update_registration_state()
  // call.
  _irs_info._associated_uris.add_uri(DEFAULT_ID, false);

  // Set up AoRs to be returned by S4.
  _get_aor = AoRTestUtils::build_aor(DEFAULT_ID, true);;

  // Set up expect calls to the HSS and S4.
  {
    InSequence s;
    EXPECT_CALL(*_hss_connection, get_registration_data(DEFAULT_ID, _, _))
      .WillOnce(DoAll(SetArgReferee<1>(_irs_info),
                      Return(HTTP_OK)));
    EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(_get_aor),
                      Return(HTTP_OK)));
    EXPECT_CALL(*_s4, handle_delete(DEFAULT_ID, _, _))
      .WillOnce(Return(HTTP_OK));
    EXPECT_CALL(*_hss_connection, update_registration_state(_, _, _))
      .WillOnce(Return(HTTP_OK));
  }

  HTTPCode rc = _subscriber_manager->deregister_subscriber(DEFAULT_ID,
                                                           SubscriberManager::EventTrigger::ADMIN,
                                                           DUMMY_TRAIL_ID);
  EXPECT_EQ(rc, HTTP_OK);

  // Expect a final NOTIFY for the subscription.
  ASSERT_EQ(1, txdata_count());
  free_txdata();
}

TEST_F(SubscriberManagerTest, TestGetBindings)
{
  // Set up AoRs to be returned by S4 - these are deleted by the handler
  _get_aor = AoRTestUtils::build_aor(DEFAULT_ID, true);

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

TEST_F(SubscriberManagerTest, TestGetSubscriptions)
{
  // Set up AoRs to be returned by S4 - these are deleted by the handler
  _get_aor = AoRTestUtils::build_aor(DEFAULT_ID, true);

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

TEST_F(SubscriberManagerTest, TestUpdateAssociatedURIs)
{
  // Set up AoRs to be returned by S4.
  //AoR* get_aor = new AoR(DEFAULT_ID);
  //get_aor->_associated_uris.add_uri(DEFAULT_ID, false);
  _get_aor = AoRTestUtils::build_aor(DEFAULT_ID, true);
  _patch_aor = AoRTestUtils::build_aor(DEFAULT_ID, true);
  _patch_aor->_associated_uris.add_uri(OTHER_ID, false);

  // Set up expect calls to S4.
  {
    InSequence s;
    EXPECT_CALL(*_s4, handle_get(DEFAULT_ID, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(_get_aor),
                      Return(HTTP_OK)));
    EXPECT_CALL(*_s4, handle_patch(DEFAULT_ID, _, _, _))
      .WillOnce(DoAll(SaveArg<1>(&_patch_object),
                      SetArgPointee<2>(_patch_aor),
                      Return(HTTP_OK)));
  }

  // Set up new associated URIs.
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri(DEFAULT_ID, false);
  associated_uris.add_uri(OTHER_ID, false);

  // Call update associated URIs on SM.
  HTTPCode rc = _subscriber_manager->update_associated_uris(DEFAULT_ID,
                                                            associated_uris,
                                                            DUMMY_TRAIL_ID);

  // Check that the patch object contains the expected associated URIs.
  ASSERT_TRUE(_patch_object.get_associated_uris());
  EXPECT_TRUE(((AssociatedURIs)(_patch_object.get_associated_uris().get())).contains_uri(DEFAULT_ID));
  EXPECT_TRUE(((AssociatedURIs)(_patch_object.get_associated_uris().get())).contains_uri(OTHER_ID));

  EXPECT_EQ(rc, HTTP_OK);
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
