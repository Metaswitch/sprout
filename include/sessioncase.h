/**
 * @file sessioncase.h The session case data type.
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

#ifndef SESSIONCASE_H__
#define SESSIONCASE_H__

#include <string>

/// The session case (sescase; see RFC5502 and 3GPP TS 29.228).  This
/// is a closed class, so pointer equality may be used between its
/// instances.
class SessionCase
{
public:
  std::string to_string() const;

  static SessionCase Originating;
  static SessionCase Terminating;
  static SessionCase OriginatingCdiv;

  inline bool is_originating() const
  {
    return ((this == &Originating) || (this == &OriginatingCdiv));
  }

  inline bool is_terminating() const
  {
    return (this == &Terminating);
  }

protected:
  SessionCase(std::string name);

  std::string _name;

private:
  // Prevent copying.
  SessionCase(const SessionCase&);
  const SessionCase& operator=(const SessionCase&);
};

#endif
