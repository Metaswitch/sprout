/**
 * @file logger.h Definitions for Sprout logger class.
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
  int _flags;
  std::string _prefix;
  int _last_hour;
  bool _rotate;
  FILE* _fd;
  pthread_mutex_t _lock;
};


#endif
