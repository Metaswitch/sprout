/**
 * @file fakelogger.cpp Fake logger (for testing).
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

#include <iostream>
#include <stdlib.h>
#include <string.h>

#include "fakelogger.hpp"

using namespace std;

FakeLogger::FakeLogger() :
  _noisy(isNoisy())
{
  Log::setLogger(this);
  Log::setLoggingLevel(4);
}

FakeLogger::FakeLogger(bool noisy) :
  _noisy(noisy)
{
  Log::setLogger(this);
  Log::setLoggingLevel(4);
}

FakeLogger::~FakeLogger()
{
  Log::setLogger(NULL);
}

void FakeLogger::write(const char* data)
{
  string line(data);

  if (*line.rbegin() != '\n') {
    line.push_back('\n');
  }

  _lastlog.append(line);

  if (_noisy)
  {
    cout << line;
  }
}

void FakeLogger::flush()
{
}

bool FakeLogger::contains(const char* needle)
{
  return _lastlog.find(needle) != string::npos;
}

bool FakeLogger::isNoisy()
{
  // Turn on noisy logging iff NOISY=T or NOISY=Y in the environment.
  char* val = getenv("NOISY");
  return ((val != NULL) && (strchr("TtYy", val[0]) != NULL));
}

