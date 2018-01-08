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

/// Fixture for SubscriberManagerTest.
class SubscriberManagerTest : public ::testing::Test
{
  SubscriberManagerTest()
  {
    _subscriber_manager = new SubscriberManager(NULL, NULL);
  };

  virtual ~SubscriberManagerTest()
  {
    delete _subscriber_manager; _subscriber_manager = NULL;
  };

  SubscriberManager* _subscriber_manager;
};

TEST_F(SubscriberManagerTest, TestTest)
{
  EXPECT_TRUE(_subscriber_manager->remove_subscription("", 0));
}
