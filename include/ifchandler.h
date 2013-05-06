/**
 * @file ifchandler.h The iFC handler data type.
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

#pragma once

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

#include <string>
#include <vector>

#include "rapidxml/rapidxml.hpp"

#include "hssconnection.h"
#include "sessioncase.h"

/// iFC handler.
class IfcHandler
{
public:
  IfcHandler(HSSConnection* hss);
  ~IfcHandler();

  void lookup_ifcs(const SessionCase& session_case,
                   pjsip_msg* msg,
                   SAS::TrailId trail,
                   std::string& served_user,
                   std::vector<std::string>& application_servers);

private:
  static bool filter_matches(const SessionCase& session_case,
                             pjsip_msg* msg,
                             rapidxml::xml_node<>* ifc);
  static void calculate_application_servers(const SessionCase& session_case,
                                            pjsip_msg* msg,
                                            std::string& ifc_xml,
                                            std::vector<std::string>& as_list);
  static std::string served_user_from_msg(const SessionCase& session_case, pjsip_msg *msg);
  static std::string user_from_uri(pjsip_uri *uri);

  HSSConnection* _hss;
};


