/**
 * @file fakelogger.cpp Fake logger (for testing).
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

