/**
 * @file thread_dispatcher_test.cpp UT for classes defined in
 *       thread_dispatcher.cpp
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "gtest/gtest.h"
#include "mock_load_monitor.h"
#include "mock_pjsip_module.h"
#include "siptest.hpp"
#include "stack.h"

#include "thread_dispatcher.h"

using ::testing::DefaultValue;

class ThreadDispatcherTest : public SipTest
{
public:

  ThreadDispatcherTest()
  {
    mod_mock = new MockPJSipModule(stack_data.endpt,
                                   "test-module",
                                   PJSIP_MOD_PRIORITY_TRANSPORT_LAYER);
    init_thread_dispatcher(1, NULL, NULL, &load_monitor, NULL, NULL);
    mod_thread_dispatcher = get_mod_thread_dispatcher();
  }

  void inject_msg_thread(const std::string& msg)
  {
    inject_msg_direct(msg, mod_thread_dispatcher);
  }

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
  }

  static void TearDownTestCase()
  {
    SipTest::TearDownTestCase();
  }

  virtual ~ThreadDispatcherTest()
  {
    unregister_thread_dispatcher();
    delete mod_mock;
  }

  MockPJSipModule* mod_mock;
  MockLoadMonitor load_monitor;
  pjsip_module* mod_thread_dispatcher;
};
