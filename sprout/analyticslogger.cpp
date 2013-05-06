/**
 * @file analyticslogger.cpp
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

#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Common STL includes.
#include <cassert>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <queue>
#include <string>


#include "analyticslogger.h"


AnalyticsLogger::AnalyticsLogger(const std::string& directory)
{
  _logger = new Logger(directory, std::string("log"));
  _logger->set_flags(Logger::ADD_TIMESTAMPS|Logger::FLUSH_ON_WRITE);
}


AnalyticsLogger::~AnalyticsLogger()
{
  delete _logger;
}


void AnalyticsLogger::registration(const std::string& aor,
                                   const std::string& binding_id,
                                   const std::string& contact,
                                   int expires)
{
  char buf[BUFFER_SIZE];
  snprintf(buf, sizeof(buf),
           "Registration: USER_URI=%s BINDING_ID=%s CONTACT_URI=%s EXPIRES=%d\n",
           aor.c_str(),
           binding_id.c_str(),
           contact.c_str(),
           expires);
  _logger->write(buf);
}


void AnalyticsLogger::auth_failure(const std::string& uri)
{
  char buf[BUFFER_SIZE];
  snprintf(buf, sizeof(buf),
           "Auth-Failure: USER_URI=%s\n",
           uri.c_str());
  _logger->write(buf);
}


void AnalyticsLogger::call_connected(const std::string& from,
                                     const std::string& to,
                                     const std::string& call_id)
{
  char buf[BUFFER_SIZE];
  snprintf(buf, sizeof(buf),
           "Call-Connected: FROM=%s TO=%s CALL_ID=%s\n",
           from.c_str(),
           to.c_str(),
           call_id.c_str());
  _logger->write(buf);
}


void AnalyticsLogger::call_not_connected(const std::string& from,
                                         const std::string& to,
                                         const std::string& call_id,
                                         int reason)
{
  char buf[BUFFER_SIZE];
  snprintf(buf, sizeof(buf),
           "Call-Not-Connected: FROM=%s TO=%s CALL_ID=%s REASON=%d\n",
           from.c_str(),
           to.c_str(),
           call_id.c_str(),
           reason);
  _logger->write(buf);
}


void AnalyticsLogger::call_disconnected(const std::string& call_id,
                                        int reason)
{
  char buf[BUFFER_SIZE];
  snprintf(buf, sizeof(buf),
           "Call-Disconnected: CALL_ID=%s REASON=%d\n",
           call_id.c_str(),
           reason);
  _logger->write(buf);
}

