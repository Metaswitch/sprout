/**
 * @file sas.cpp Dummy implementation of SAS class used for reporting events
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

/// and markers to Service Assurance Server - does not actually do so
///
///

#include <string.h>

#include "log.h"
#include "sas.h"

void SAS::init(int system_name_length, const char* system_name, const std::string& sas_address)
{
  // Do nothing.
}

void SAS::term()
{
  // Do nothing.
}

SAS::TrailId SAS::new_trail(unsigned long instance)
{
  // Return non-zero - returning 0 would cause error messages as we'd expect
  // to have a SAS trail but not get one.
  return 1;
}

void SAS::report_event(const Event& event)
{
  // Do nothing.
}

void SAS::report_marker(const Marker& marker)
{
  // Do nothing.
}

void SAS::report_marker(const Marker& marker, Marker::Scope scope)
{
  // Do nothing.
}
