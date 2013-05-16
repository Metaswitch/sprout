/**
 * @file sessioncase.h The session case data type.
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

  inline bool operator==(const SessionCase& that) const
  {
    return (this == &that);
  }

  inline bool operator!=(const SessionCase& that) const
  {
    return (this != &that);
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
