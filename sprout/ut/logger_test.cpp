/**
 * @file logger_test.cpp UT for Sprout logger.
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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "utils.h"
#include "sas.h"
#include "logger.h"
#include "test_utils.hpp"

using namespace std;

/// Fixture for LoggerTest.
class LoggerTest : public ::testing::Test
{
  LoggerTest()
  {
    system("rm -f /tmp/logtest*");
  }

  virtual ~LoggerTest()
  {
    system("rm -f /tmp/logtest*");
  }
};

/// Subclass the class under test so we can override the current time.
class Logger2 : public Logger
{
  Logger2(const std::string& directory, const std::string& filename) :
    Logger(directory, filename),
    _time_sec(0),
    _time_nsec(0)
  {
  }

  virtual ~Logger2()
  {
  }

  void gettime(struct timespec* ts)
  {
    if (_time_sec == 0 && _time_nsec == 0)
    {
      Logger::gettime(ts);
    }
    else
    {
      ts->tv_sec = _time_sec;
      ts->tv_nsec = _time_nsec;
    }
  }

  void settime(time_t time_sec, long time_nsec)
  {
    _time_sec = time_sec;
    _time_nsec = time_nsec;
  }

private:
  time_t _time_sec;
  long _time_nsec;
};


TEST_F(LoggerTest, Mainline)
{
  Logger2 log("/tmp", "logtest");
  time_t midnight = 1356048000u; // 2012-12-21T00:00:00 UTC
  log.settime(midnight - 30, 123456789l);
  log.write("Some data goes here\n");
  EXPECT_EQ((int)Logger::ADD_TIMESTAMPS, log.get_flags());
  log.set_flags(0);
  log.settime(midnight - 20, 234567890l);
  log.write("Some more data goes there\n");
  log.set_flags(Logger::ADD_TIMESTAMPS);
  log.settime(midnight + 10, 345678901l);
  log.write("And on the next day\n");
  log.settime(midnight + 360, 456789012l);
  log.write("And yet more of course\n");
  log.flush();

  FILE* f;
  char linebuf[1024];
  char* line;

  f = fopen("/tmp/logtest_20121220T230000Z.txt", "r");
  ASSERT_TRUE(f != NULL);
  line = fgets(linebuf, sizeof(linebuf), f);
  EXPECT_STREQ("20-12-2012 23:59:30.123 UTC Some data goes here\n", line);
  line = fgets(linebuf, sizeof(linebuf), f);
  EXPECT_STREQ("Some more data goes there\n", line);
  line = fgets(linebuf, sizeof(linebuf), f);
  EXPECT_TRUE(line == NULL);
  fclose(f);

  f = fopen("/tmp/logtest_20121221T000000Z.txt", "r");
  ASSERT_TRUE(f != NULL);
  line = fgets(linebuf, sizeof(linebuf), f);
  EXPECT_STREQ("21-12-2012 00:00:10.345 UTC And on the next day\n", line);
  line = fgets(linebuf, sizeof(linebuf), f);
  EXPECT_STREQ("21-12-2012 00:06:00.456 UTC And yet more of course\n", line);
  line = fgets(linebuf, sizeof(linebuf), f);
  EXPECT_TRUE(line == NULL);
  fclose(f);

  log.write("Foo\n");
  // Not flushed yet
  f = fopen("/tmp/logtest_20121221T000000Z.txt", "r");
  ASSERT_TRUE(f != NULL);
  line = fgets(linebuf, sizeof(linebuf), f);
  ASSERT_TRUE(line != NULL);
  line = fgets(linebuf, sizeof(linebuf), f);
  ASSERT_TRUE(line != NULL);
  line = fgets(linebuf, sizeof(linebuf), f);
  EXPECT_TRUE(line == NULL);
  fclose(f);

  log.settime(midnight + 730, 0);
  log.set_flags(Logger::ADD_TIMESTAMPS | Logger::FLUSH_ON_WRITE);
  log.write("Bar\n");
  EXPECT_EQ(Logger::ADD_TIMESTAMPS | Logger::FLUSH_ON_WRITE, log.get_flags());

  f = fopen("/tmp/logtest_20121221T000000Z.txt", "r");
  ASSERT_TRUE(f != NULL);
  line = fgets(linebuf, sizeof(linebuf), f);
  ASSERT_TRUE(line != NULL);
  line = fgets(linebuf, sizeof(linebuf), f);
  ASSERT_TRUE(line != NULL);
  line = fgets(linebuf, sizeof(linebuf), f);
  EXPECT_STREQ("21-12-2012 00:06:00.456 UTC Foo\n", line);
  line = fgets(linebuf, sizeof(linebuf), f);
  EXPECT_STREQ("21-12-2012 00:12:10.000 UTC Bar\n", line);
  line = fgets(linebuf, sizeof(linebuf), f);
  EXPECT_TRUE(line == NULL);
  fclose(f);
}

TEST_F(LoggerTest, RealTime)
{
  Logger2 log("/tmp", "logtest");
  log.write("Wossat it sez for da test\n");
  log.flush();

  int rc = system("grep '^[0-3][0-9]-[0-1][0-9]-[0-9][0-9][0-9][0-9] ..:..:..\\.... UTC Wossat it sez for da test' /tmp/logtest_*.txt >/dev/null");
  EXPECT_EQ(0, WEXITSTATUS(rc));
}
