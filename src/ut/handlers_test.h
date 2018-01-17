/**
 * @file handlers_test.h
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef HANDLERSTEST_H__
#define HANDLERSTEST_H__

#include "test_utils.hpp"
#include <curl/curl.h>

#include "mockhttpstack.hpp"
#include "handlers.h"
#include "basetest.hpp"
#include "siptest.hpp"
#include "fakehssconnection.hpp"
#include "fakechronosconnection.hpp"
#include "mock_subscriber_data_manager.h"
#include "mock_subscriber_manager.h"
#include "mock_impi_store.h"
#include "mock_hss_connection.h"
#include "aor_test_utils.h"
#include "gtest/gtest.h"


// Base class used for testing handlers with Mock SDMs.
class TestWithMockSdms : public SipTest
{
  MockSubscriberManager* sm;

  MockSubscriberDataManager* store;
  MockSubscriberDataManager* remote_store1;
  MockSubscriberDataManager* remote_store2;
  MockHttpStack* stack;
  MockHSSConnection* mock_hss;

  virtual void SetUp()
  {
    sm = new MockSubscriberManager();

    store = new MockSubscriberDataManager();
    remote_store1 = new MockSubscriberDataManager();
    remote_store2 = new MockSubscriberDataManager();
    mock_hss = new MockHSSConnection();
    stack = new MockHttpStack();
  }

  virtual void TearDown()
  {
    delete stack;
    delete sm; sm = NULL;
    delete remote_store1; remote_store1 = NULL;
    delete remote_store2; remote_store2 = NULL;
    delete store; store = NULL;
    delete mock_hss;
  }

  AoRPair* build_aor_pair(std::string aor_id,
                          bool include_subscription = true)
  {
    AoR* aor = new AoR(aor_id);
    int now = time(NULL);
    AoRTestUtils::build_binding(aor, now);
    if (include_subscription)
    {
      AoRTestUtils::build_subscription(aor, now);
    }
    aor->_scscf_uri = "sip:scscf.sprout.homedomain:5058;transport=TCP";
    AoR* aor2 = new AoR(*aor);
    AoRPair* aor_pair = new AoRPair(aor, aor2);

    return aor_pair;
  }
};

class AuthTimeoutTest : public SipTest
{
  MockImpiStore* store;
  FakeHSSConnection* fake_hss;
  MockHttpStack stack;

  void SetUp()
  {
    store = new MockImpiStore();
    fake_hss = new FakeHSSConnection();
  }

  void TearDown()
  {
    delete fake_hss; fake_hss = NULL;
    delete store; store = NULL;
  }
};

#endif
