/**
 * @file test_main.cpp Unit test main module
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

///
/// Includes portions copyright Google per the below notice.

// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Author: wan@google.com (Zhanyong Wan)

#include <iostream>
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <sys/prctl.h>
#include <stdexcept>
#include <string>

#include "test_utils.hpp"
#include "test_interposer.hpp"

void test_main_handle_signal(int xiSigNum);

static const std::string UT_FILE(__FILE__);
const std::string UT_DIR = UT_FILE.substr(0, UT_FILE.rfind("/"));

int main(int argc, char** argv)
{
  std::cout << "Running main() from gmock_main.cc\n";
  // Since Google Mock depends on Google Test, InitGoogleMock() is
  // also responsible for initializing Google Test.  Therefore there's
  // no need for calling testing::InitGoogleTest() separately.
  testing::InitGoogleMock(&argc, argv);

  // Set up a signal handler to catch SIGSEGV.
  struct sigaction lsigaction;
  memset(&lsigaction, 0, sizeof(lsigaction));
  lsigaction.sa_handler = test_main_handle_signal;
  sigaction(SIGSEGV, &lsigaction, NULL);

  return RUN_ALL_TESTS();
}

/// Signal handler that reports failure to test framework.
void test_main_handle_signal(int xiSigNum)
{
  int pid = getpid();

#ifdef PR_SET_PTRACER
  // Allow children to debug this process
  // (because debugging is restricted under Ubuntu: search ptrace_scope).
  prctl(PR_SET_PTRACER, pid, 0, 0, 0);
#endif

  // Explain we're recovering from a signal.
  printf("*** handling signal %d ***\n", xiSigNum);

  // Get a backtrace.
  std::stringstream s;
  s << "/usr/bin/gdb -nx --batch /proc/" << getpid() << "/exe "
    << getpid() << " -ex 'thread apply all bt'";
  (void)system(s.str().c_str());

  // Throw an exception to abort the current test.  The content seems to
  // be ignored by Google Test, so output it separately too.
  std::stringstream ss;
  ss << "Hit signal " << xiSigNum;
  ADD_FAILURE() << ss.str();
  throw new std::runtime_error(ss.str());
}
