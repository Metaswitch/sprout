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
#include "mock_subscriber_manager.h"
#include "mock_impi_store.h"
#include "mock_hss_connection.h"
#include "aor_test_utils.h"
#include "gtest/gtest.h"


// Base class used for testing handlers with Mock Subscriber Manager.
class TestWithMockSM : public BaseTest
{
  MockSubscriberManager* sm;
  MockHttpStack* stack;

  virtual void SetUp()
  {
    sm = new MockSubscriberManager();
    stack = new MockHttpStack();
  }

  virtual void TearDown()
  {
    delete stack; stack = NULL;
    delete sm; sm = NULL;
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
