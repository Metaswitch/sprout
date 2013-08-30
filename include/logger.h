/**
 * @file logger.h Definitions for Sprout logger class.
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
///

#ifndef LOGGER_H__
#define LOGGER_H__

#include <string>
#include <pthread.h>

class Logger
{
public:
  Logger();
  Logger(const std::string& directory, const std::string& filename);
  virtual ~Logger();

  static const int ADD_TIMESTAMPS = 1;
  static const int FLUSH_ON_WRITE = 2;
  int get_flags() const;
  void set_flags(int flags);

  virtual void gettime(struct timespec* ts);

  virtual void write(const char* data);
  virtual void flush();

  // Dumps a backtrace.  Note that this is not thread-safe and should only be
  // called when no other threads are running - generally from a signal
  // handler.
  virtual void backtrace(const char* data);

private:
  /// Encodes the time as needed by the logger.
  typedef struct
  {
    int year;
    int mon;
    int mday;
    int hour;
    int min;
    int sec;
    int msec;      
    int yday;
  } timestamp_t;

  void get_timestamp(timestamp_t& ts);
  void write_log_file(const char* data, const timestamp_t& ts);
  void cycle_log_file(const timestamp_t& ts);

  int _flags;
  std::string _prefix;
  int _last_hour;
  bool _rotate;
  FILE* _fd;
  int _discards;
  int _saved_errno;
  pthread_mutex_t _lock;

  /// Defines how frequently (in terms of log attempts) we will try to 
  /// open the log file if we failed to open it previously.
  static const int LOGFILE_CHECK_FREQUENCY = 1000;
};


#endif
