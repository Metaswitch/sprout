/**
 * @file log.h
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


#ifndef LOG_H__
#define LOG_H__

#include "logger.h"

#define LOG_ERROR(...) Log::write(0, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARNING(...) Log::write(1, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_STATUS(...) Log::write(2, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_INFO(...) Log::write(3, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_VERBOSE(...) Log::write(4, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_DEBUG(...) Log::write(5, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_BACKTRACE(...) Log::backtrace(__VA_ARGS__)

namespace Log
{
  void setLoggingLevel(int level);
  void setLogger(Logger *log);
  void write(int level, const char *module, int line_number, const char *fmt, ...);
  void backtrace(const char *fmt, ...);
};  

#endif
