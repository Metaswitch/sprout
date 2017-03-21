/**
 * @file ifc.h The iFC handler data type.
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

#pragma once

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

#include <string>
#include <vector>
#include <memory>

#include "rapidxml/rapidxml.hpp"
#include "sessioncase.h"

#include "sas.h"
#include "xml_utils.h"

typedef enum {SESSION_CONTINUED=0, SESSION_TERMINATED=1} DefaultHandling;

/// An invocation of an AS - the result of a matching iFC.
//
// Has no dependency on the iFCs used to create it.
struct AsInvocation
{
  std::string server_name;
  DefaultHandling default_handling;
  std::string service_info;
  bool include_register_request;
  bool include_register_response;
};

/// A single Initial Filter Criterion (iFC).
class Ifc
{
public:
  Ifc(rapidxml::xml_node<>* ifc) :
    _ifc(ifc)
  {
  }

  bool filter_matches(const SessionCase& session_case,
                      bool is_registered,
                      bool is_initial_registration,
                      pjsip_msg* msg,
                      SAS::TrailId trail) const;

  AsInvocation as_invocation() const;

private:
  static bool spt_matches(const SessionCase& session_case,
                          bool is_registered,
                          bool is_initial_registration,
                          pjsip_msg *msg,
                          rapidxml::xml_node<>* spt,
                          std::string ifc_str,
                          std::string server_name,
                          SAS::TrailId trail);

  static void invalid_ifc(std::string error,
                          std::string server_name,
                          int sas_event_id,
                          int instance_id,
                          SAS::TrailId trail);

  rapidxml::xml_node<>* _ifc;
  std::string _server_name;
};
