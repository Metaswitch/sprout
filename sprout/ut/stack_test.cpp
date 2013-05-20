/**
 * @file stack_test.cpp UT for Sprout BGCF service.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version, along with the "Special Exception" for use of
 * the program along with SSL, set forth below. This program is distributed
 * in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details. You should have received a copy of the GNU General Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by
 * post at Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 *
 * Special Exception
 * Metaswitch Networks Ltd  grants you permission to copy, modify,
 * propagate, and distribute a work formed by combining OpenSSL with The
 * Software, or a work derivative of such a combination, even if such
 * copying, modification, propagation, or distribution would otherwise
 * violate the terms of the GPL. You must comply with the GPL in all
 * respects for all of the code used other than OpenSSL.
 * "OpenSSL" means OpenSSL toolkit software distributed by the OpenSSL
 * Project and licensed under the OpenSSL Licenses, or a work based on such
 * software and licensed under the OpenSSL Licenses.
 * "OpenSSL Licenses" means the OpenSSL License and Original SSLeay License
 * under which the OpenSSL Project distributes the OpenSSL toolkit software,
 * as those licenses appear in the file LICENSE-OPENSSL.
 */

///
///----------------------------------------------------------------------------

#include <string>
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <json/reader.h>
#include <sys/types.h>
#include <dirent.h>
#include <netdb.h>
#include <unistd.h>

#include "utils.h"
#include "sas.h"
#include "stack.h"
#include "fakelogger.hpp"
#include "test_utils.hpp"
#include "siptest.hpp"

using namespace std;

/// Fixture for StackTest.
class StackTest : public ::testing::Test
{
  FakeLogger _log;

  StackTest()
  {
    Log::setLoggingLevel(99);
  }

  virtual ~StackTest()
  {
  }
};

/// Count how many threads the current process has (on Linux)
int get_thread_count()
{
  int ret = 0;
  DIR* dir = opendir("/proc/self/task");
  struct dirent ent_buf;

  if (dir == NULL)
  {
    return 0;
  }

  struct dirent* ent;
  int rc;

  for (;;)
  {
    rc = readdir_r(dir, &ent_buf, &ent);
    if (rc != 0 || ent == NULL)
    {
      break;
    }
    ++ret;
  }

  closedir(dir);

  return ret;
}


TEST_F(StackTest, DISABLED_SimpleLifeCycle)
{
  // Work out who we are
  char buf[200];
  int rv = gethostname(buf, sizeof(buf));
  ASSERT_EQ(0, rv);
  struct hostent* ent = gethostbyname(buf);
  ASSERT_TRUE(ent != NULL) << buf << ": gethostbyname failed with " << h_errno;
  char ip[20];
  char dns[200];
  int index = 0;
  for (int i = 0; ent->h_addr_list[i] != NULL; i++)
  {
    if (ent->h_addr_list[i][0] != 127)  // reject loopback addresses
    {
      index = i;
      break;
    }
  }
  sprintf(ip, "%d.%d.%d.%d",
          (int)(unsigned char)ent->h_addr_list[index][0],
          (int)(unsigned char)ent->h_addr_list[index][1],
          (int)(unsigned char)ent->h_addr_list[index][2],
          (int)(unsigned char)ent->h_addr_list[index][3]);
  strcpy(dns, ent->h_name);

  // Now do test
  pj_status_t rc = init_stack("plural@zalpha.example.com",  // system name
                              "192.168.0.3",                // SAS address
                              9408,                         // trusted port
                              9409,                         // untrusted port
                              dns,                          // local host
                              "woot.example.com",           // home domain
                              "all-the-sprouts",            //sprout cluster hostname
                              "thatone.zalpha.example.com,other.example.org,192.168.0.4",  // alias hosts
                              7,                            // #PJsip threads
                              9);                           // #worker threads
  ASSERT_EQ(PJ_SUCCESS, rc) << PjStatus(rc);
  EXPECT_TRUE(_log.contains("Listening on port 9408"));
  EXPECT_TRUE(_log.contains("Local host aliases:"));
  EXPECT_TRUE(_log.contains(dns)) << dns << endl << _log._lastlog;
  EXPECT_TRUE(_log.contains(ip)) << ip << endl << _log._lastlog;
  EXPECT_TRUE(_log.contains("127.0.0.1"));
  EXPECT_TRUE(_log.contains("localhost"));
  EXPECT_TRUE(_log.contains("thatone.zalpha.example.com"));
  EXPECT_TRUE(_log.contains("other.example.org"));
  EXPECT_TRUE(_log.contains("192.168.0.4"));
  EXPECT_EQ(7u, stack_data.name_cnt);
  EXPECT_EQ(string(dns), str_pj(stack_data.name[0]));

  // Threads shouldn't have started yet.
  int baseline = get_thread_count();

  // Now start them
  rc = start_stack();
  ASSERT_EQ(PJ_SUCCESS, rc) << PjStatus(rc);
  EXPECT_EQ(baseline + 9 + 7, get_thread_count());

  stop_stack();
  EXPECT_EQ(baseline, get_thread_count());

  destroy_stack();
}
