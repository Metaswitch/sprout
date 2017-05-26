/**
 * @file ifchandler.h The iFC handler data type.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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
