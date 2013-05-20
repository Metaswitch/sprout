/**
 * @file ifchandler.h The iFC handler data type.
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
#include "regdata.h"
#include "sessioncase.h"

struct AsInvocation
{
    std::string server_name;
    intptr_t default_handling;
    std::string service_info;
    bool include_register_request;
    bool include_register_response;
};

/// iFC handler.
class IfcHandler
{
public:
  IfcHandler(HSSConnection* hss, RegData::Store* store);
  ~IfcHandler();

  static std::string served_user_from_msg(const SessionCase& session_case,
                                          pjsip_rx_data* rdata);

  void lookup_ifcs(const SessionCase& session_case,
                   const std::string& served_user,
                   bool is_registered,
                   pjsip_msg* msg,
                   SAS::TrailId trail,
                   std::vector<AsInvocation>& application_servers);

private:
  static bool spt_matches(const SessionCase& session_case,
                          bool is_registered,
                          pjsip_msg *msg,
                          rapidxml::xml_node<>* spt);
  static bool filter_matches(const SessionCase& session_case,
                             bool is_registered,
                             pjsip_msg* msg,
                             rapidxml::xml_node<>* ifc);
  static void calculate_application_servers(const SessionCase& session_case,
                                            bool is_registered,
                                            pjsip_msg* msg,
                                            std::string& ifc_xml,
                                            std::vector<AsInvocation>& as_list);
  static std::string user_from_uri(pjsip_uri *uri);

  HSSConnection* _hss;
  RegData::Store* _store;
};
