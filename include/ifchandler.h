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
#include "ifc.h"
#include "sifcservice.h"

/// A set of iFCs.
//
// Owns the iFCs document, and provides access to each iFC within it.
class Ifcs
{
public:
  Ifcs();
  Ifcs(std::shared_ptr<rapidxml::xml_document<>> ifc_doc,
       rapidxml::xml_node<>* sp,
       SIFCService* sifc_service,
       SAS::TrailId trail);
  ~Ifcs();

  size_t size() const
  {
    return _ifcs.size();
  }

  const Ifc& operator[](size_t index) const
  {
    return _ifcs[index];
  }

  const std::vector<Ifc> ifcs_list() const
  {
    return _ifcs;
  }

  void interpret(const SessionCase& session_case,
                 bool is_registered,
                 bool is_initial_registration,
                 pjsip_msg *msg,
                 std::vector<AsInvocation>& application_servers,
                 SAS::TrailId trail) const;

private:
  std::shared_ptr<rapidxml::xml_document<> > _ifc_doc;
  std::vector<Ifc> _ifcs;
};


/// iFC handler.
class IfcHandler
{
public:
  IfcHandler();
  ~IfcHandler();

  static std::string served_user_from_msg(const SessionCase& session_case,
                                          pjsip_msg* msg,
                                          pj_pool_t* pool);

private:
  static std::string user_from_uri(pjsip_uri *uri);
};
