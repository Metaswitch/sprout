/**
 * @file logger.cpp
 *
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by post at
 * Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 */

#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <pthread.h>
#include <execinfo.h>

// Common STL includes.
#include <cassert>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <queue>
#include <string>


#include "logger.h"

Logger::Logger() :
  _flags(ADD_TIMESTAMPS),
  _last_hour(0),
  _rotate(false),
  _fd(stdout)
{
  pthread_mutex_init(&_lock, NULL);
};

Logger::Logger(const std::string& directory, const std::string& filename) :
  _flags(ADD_TIMESTAMPS),
  _last_hour(0),
  _rotate(true),
  _fd(NULL)
{
  pthread_mutex_init(&_lock, NULL);
  _prefix = directory + "/" + filename;
}


Logger::~Logger()
{
}


int Logger::get_flags() const
{
  return _flags;
}


void Logger::set_flags(int flags)
{
  _flags = flags;
}


void Logger::gettime(struct timespec* ts)
{
  clock_gettime(CLOCK_REALTIME, ts);
}

void Logger::write(const char* data)
{
  // Writes logger output to a series of hourly files.
  struct timespec ts;
  gettime(&ts);
  struct tm* dt = gmtime(&ts.tv_sec);

  // Take the lock before we operate on member variables.
  pthread_mutex_lock(&_lock);

  // Convert the date/time into a rough number of hours since some base date.
  // This doesn't have to be exact, but it does have to be monotonically
  // increasing, so assume every year is a leap year.
  int hour = dt->tm_year * 366 * 24 + dt->tm_yday * 24 + dt->tm_hour;
  if (_rotate && ((hour > _last_hour) || (_fd == NULL)))
  {
    // Time to switch to a new log file.
    if (_fd != NULL)
    {
      fclose(_fd);
    }
    char fname[100];
    sprintf(fname, "%s_%4.4d%2.2d%2.2d_%2.2d00.txt",
            _prefix.c_str(),
            (dt->tm_year + 1900),
            (dt->tm_mon + 1),
            dt->tm_mday,
            dt->tm_hour);
    _fd = fopen(fname, "a");
    _last_hour = hour;
  }

  if (_flags & ADD_TIMESTAMPS)
  {
    char timestamp[100];
    sprintf(timestamp, "%2.2d-%2.2d-%4.4d %2.2d:%2.2d:%2.2d.%3.3ld ",
            dt->tm_mday, (dt->tm_mon+1), (dt->tm_year + 1900),
            dt->tm_hour, dt->tm_min, dt->tm_sec, (ts.tv_nsec / 1000000));
    fputs(timestamp, _fd);
  }

  // Write the log to the current file.
  fputs(data, _fd);

  if (_flags & FLUSH_ON_WRITE)
  {
    fflush(_fd);
  }

  pthread_mutex_unlock(&_lock);
}

// LCOV_EXCL_START Only used in exceptional signal handlers - not hit in UT

// Maximum number of stack entries to trace out.
#define MAX_BACKTRACE_STACK_ENTRIES 32

// Dump a backtrace.  This function is called from a signal handler and so can
// only use functions that are safe to be called from one.  In particular,
// locking functions are _not_ safe to call from signal handlers, so this
// function is not thread-safe.
void Logger::backtrace(const char *data)
{
  // If the file exists, dump a header and then the backtrace.
  if (_fd != NULL)
  {
    fprintf(_fd, "\n%s", data);

    // First dump the backtrace ourselves.  This is robust but not very good.
    // In particular, it doesn't include good function names or other threads.
    fprintf(_fd, "\nBasic stack dump:\n");
    fflush(_fd);
    void *stack[MAX_BACKTRACE_STACK_ENTRIES];
    size_t num_entries = ::backtrace(stack, MAX_BACKTRACE_STACK_ENTRIES);
    backtrace_symbols_fd(stack, num_entries, fileno(_fd));

    // Now try dumping with gdb.  This might not work (e.g. because gdb isn't
    // installed), but it gives much better output.  We need to swap some file
    // descriptors around before and after invoking gdb to make sure that
    // stdout and stderr from gdb go to the log file.
    fprintf(_fd, "\nAdvanced stack dump (requires gdb):\n");
    fflush(_fd);
    int fd1 = dup(1);
    dup2(fileno(_fd), 1);
    int fd2 = dup(2);
    dup2(fileno(_fd), 2);
    char gdb_cmd[256];
    sprintf(gdb_cmd, "/usr/bin/gdb -nx --batch /proc/%d/exe %d -ex 'thread apply all bt'", getpid(), getpid());
    int rc = system(gdb_cmd);
    dup2(fd1, 1);
    close(fd1);
    dup2(fd2, 2);
    close(fd2);
    fprintf(_fd, "\n");
    if (rc != 0)
    {
      fprintf(_fd, "gdb failed with return code %d\n", rc);
    }
    fflush(_fd);
  }
}

// LCOV_EXCL_STOP


void Logger::flush()
{
  fflush(_fd);
}
