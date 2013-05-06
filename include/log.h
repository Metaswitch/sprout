/**
 * @file log.h
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


#ifndef LOG_H__
#define LOG_H__

#include "logger.h"

#define LOG_ERROR(...) Log::write(0, __FILE__, __VA_ARGS__)
#define LOG_WARNING(...) Log::write(1, __FILE__, __VA_ARGS__)
#define LOG_STATUS(...) Log::write(2, __FILE__, __VA_ARGS__)
#define LOG_INFO(...) Log::write(3, __FILE__, __VA_ARGS__)
#define LOG_VERBOSE(...) Log::write(4, __FILE__, __VA_ARGS__)
#define LOG_DEBUG(...) Log::write(5, __FILE__, __VA_ARGS__)
#define LOG_BACKTRACE(...) Log::backtrace(__VA_ARGS__)

namespace Log
{
  void setLoggingLevel(int level);
  void setLogger(Logger *log);
  void write(int level, const char *module, const char *fmt, ...);
  void backtrace(const char *fmt, ...);
};  

#endif
