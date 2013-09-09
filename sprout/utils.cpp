/**
 * @file utils.cpp Utility functions.
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

// Common STL includes.
#include <cassert>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <queue>
#include <string>

#include "utils.h"

std::string Utils::url_escape(const std::string& s)
{
  std::string r;
  r.reserve(2*s.length());  // Reserve enough space to avoid continually reallocating.

  for (size_t ii = 0; ii < s.length(); ++ii)
  {
    switch (s[ii])
    {
      case 0x20: r.append("%20"); break; // space
      case 0x22: r.append("%22"); break; // "
      case 0x23: r.append("%23"); break; // #
      case 0x24: r.append("%24"); break; // $
      case 0x25: r.append("%25"); break; // %
      case 0x26: r.append("%26"); break; // &
      case 0x2b: r.append("%2B"); break; // +
      case 0x2c: r.append("%2C"); break; // ,
      case 0x2f: r.append("%2F"); break; // forward slash
      case 0x3a: r.append("%3A"); break; // :
      case 0x3b: r.append("%3B"); break; // ;
      case 0x3c: r.append("%3C"); break; // <
      case 0x3d: r.append("%3D"); break; // =
      case 0x3e: r.append("%3E"); break; // >
      case 0x3f: r.append("%3F"); break; // ?
      case 0x40: r.append("%40"); break; // @
      case 0x5b: r.append("%5B"); break; // [
      case 0x5c: r.append("%5C"); break; // backslash
      case 0x5d: r.append("%5D"); break; // ]
      case 0x5e: r.append("%5E"); break; // ^
      case 0x60: r.append("%60"); break; // `
      case 0x7b: r.append("%7B"); break; // {
      case 0x7c: r.append("%7C"); break; // |
      case 0x7d: r.append("%7D"); break; // }
      case 0x7e: r.append("%7E"); break; // ~
      default: r.push_back(s[ii]); break;
    }
  }
  return r;
}

bool Utils::StopWatch::_already_logged = false;
