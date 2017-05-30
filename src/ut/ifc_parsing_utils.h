/**
 * @file ifc_parsing_utils.h
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#pragma once

#include <string>
#include <vector>
#include "ifc.h"

inline std::string get_server_name(Ifc ifc)
{
  return std::string(ifc._ifc->first_node("ApplicationServer")->
                                             first_node("ServerName")->value());
}

inline int32_t get_priority(Ifc ifc)
{
  if (ifc._ifc->first_node("Priority"))
  {
    return std::atoi(ifc._ifc->first_node("Priority")->value());
  }

  return 0;
}
