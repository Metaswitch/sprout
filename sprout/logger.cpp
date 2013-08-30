/**
 * @file logger.cpp
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
#include <string.h>

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
  _fd(NULL),
  _discards(0),       
  _saved_errno(0)             
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


/// Writes a log to the logfile, cycling or opening the log file when
/// necessary.
void Logger::write(const char* data)
{
  // Writes logger output to a series of hourly files.
  timestamp_t ts;
  get_timestamp(ts);

  pthread_mutex_lock(&_lock);

  if ((_fd != NULL) ||
      ((_discards % LOGFILE_CHECK_FREQUENCY) == 0))
  {
    // We have a valid file handle, or it is time to try opening the file
    // again.

    // Convert the date/time into a rough number of hours since some base date.
    // This doesn't have to be exact, but it does have to be monotonically
    // increasing, so assume every year is a leap year.
    int hour = ts.year * 366 * 24 + ts.yday * 24 + ts.hour;

    if ((_rotate && (hour > _last_hour)) ||
        (_fd == NULL))
    {
      // Open a new log file.
      cycle_log_file(ts);
      _last_hour = hour;

      if ((_fd != NULL) &&
          (_discards != 0))
      {
        // LCOV_EXCL_START Currently don't force fopen failures in UT
        char discard_msg[100];
        sprintf(discard_msg,
                "Failed to open logfile (%d - %s), %d logs discarded", 
                _saved_errno, ::strerror(_saved_errno), _discards);
        write_log_file(discard_msg, ts);
        _discards = 0;
        _saved_errno = 0;
        // LCOV_EXCL_STOP
      }
    }
  }

  if (_fd != NULL) 
  {
    // We have a valid log file open, so write the log.
    write_log_file(data, ts);
  }
  else
  {
    // No valid log file, so count this as a discard.
    // LCOV_EXCL_START Currently don't force fopen failures in UT
    ++_discards;
    // LCOV_EXCL_STOP
  }

  pthread_mutex_unlock(&_lock);
}


/// Gets a timestamp in the form required by the logger.
void Logger::get_timestamp(timestamp_t& ts)
{
  struct timespec timespec;
  gettime(&timespec);
  struct tm* dt = gmtime(&timespec.tv_sec);
  ts.year = dt->tm_year;
  ts.mon = dt->tm_mon;
  ts.mday = dt->tm_mday;
  ts.hour = dt->tm_hour;
  ts.min = dt->tm_min;
  ts.sec = dt->tm_sec;
  ts.msec = (int)(timespec.tv_nsec / 1000000);
  ts.yday = dt->tm_yday;
}


/// Writes a log to the file with timestamp if configured.
void Logger::write_log_file(const char *data, const timestamp_t& ts)
{
  if (_flags & ADD_TIMESTAMPS)
  {
    char timestamp[100];
    sprintf(timestamp, "%2.2d-%2.2d-%4.4d %2.2d:%2.2d:%2.2d.%3.3d ",
            ts.mday, (ts.mon+1), (ts.year + 1900),
            ts.hour, ts.min, ts.sec, ts.msec);
    fputs(timestamp, _fd);
  }

  // Write the log to the current file.
  fputs(data, _fd);

  if (_flags & FLUSH_ON_WRITE)
  {
    fflush(_fd);
  }
}


void Logger::cycle_log_file(const timestamp_t& ts)
{
  if (_fd != NULL)
  {
    fclose(_fd);
  }
  char fname[100];
  sprintf(fname, "%s_%4.4d%2.2d%2.2d_%2.2d00.txt",
          _prefix.c_str(),
          (ts.year + 1900),
          (ts.mon + 1),
          ts.mday,
          ts.hour);
  _fd = fopen(fname, "a");

  if (_fd == NULL) 
  {
    // Failed to open logfile, so save errno until we can log it.
    // LCOV_EXCL_START Currently don't force fopen failures in UT
    _saved_errno = errno;
    // LCOV_EXCL_STOP
  }
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
