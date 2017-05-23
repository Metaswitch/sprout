/**
 * @file sessioncase.cpp The session case data type.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


#include <string>

#include "sessioncase.h"

SessionCase::SessionCase(std::string name) :
  _name(name)
{
}

std::string SessionCase::to_string() const
{
  return _name;
}

const SessionCase SessionCase::Originating("orig");
const SessionCase SessionCase::Terminating("term");
const SessionCase SessionCase::OriginatingCdiv("orig-cdiv");

