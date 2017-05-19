/**
 * @file sessioncase.h The session case data type.
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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

  const static SessionCase Originating;
  const static SessionCase Terminating;
  const static SessionCase OriginatingCdiv;

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
