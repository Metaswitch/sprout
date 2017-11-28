/**
 * @file ifc.h The iFC handler data type.
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
#include "xml_utils.h"
#include "snmp_counter_table.h"

typedef enum {SESSION_CONTINUED=0, SESSION_TERMINATED=1} DefaultHandling;

/// Structure that holds iFC configuration that isn't covered by the TS specs
// (e.g. fallback and dummy iFCs).
struct IFCConfiguration
{
  bool _apply_fallback_ifcs;
  bool _reject_if_no_matching_ifcs;
  std::string _dummy_as;
  SNMP::CounterTable* _no_matching_ifcs_tbl;
  SNMP::CounterTable* _no_matching_fallback_ifcs_tbl;

  IFCConfiguration()
  {}

  IFCConfiguration(bool apply_fallback_ifcs,
                   bool reject_if_no_matching_ifcs,
                   std::string dummy_as,
                   SNMP::CounterTable* no_matching_ifcs_tbl,
                   SNMP::CounterTable* no_matching_fallback_ifcs_tbl) :
    _apply_fallback_ifcs(apply_fallback_ifcs),
    _reject_if_no_matching_ifcs(reject_if_no_matching_ifcs),
    _dummy_as(dummy_as),
    _no_matching_ifcs_tbl(no_matching_ifcs_tbl),
    _no_matching_fallback_ifcs_tbl(no_matching_fallback_ifcs_tbl)
  {}
};

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

  /// This constructor creates an Ifc and makes sure that all of its
  // associated memory is owned by the passed in XML document.
  Ifc(std::string ifc_str,
      rapidxml::xml_document<>* ifc_doc);

  bool filter_matches(const SessionCase& session_case,
                      const bool is_registered,
                      const bool is_initial_registration,
                      pjsip_msg* msg,
                      SAS::TrailId trail) const;

  AsInvocation as_invocation() const;

private:

class ifc_error : public std::exception {};

  static bool spt_matches(const SessionCase& session_case,
                          const bool is_registered,
                          const bool is_initial_registration,
                          pjsip_msg *msg,
                          rapidxml::xml_node<>* spt,
                          std::string ifc_str,
                          std::string server_name,
                          SAS::TrailId trail);

  static void handle_invalid_ifc(std::string error,
                                 std::string server_name,
                                 int sas_event_id,
                                 int instance_id,
                                 SAS::TrailId trail);

  static void handle_unusual_ifc(std::string error,
                                 std::string server_name,
                                 int sas_event_id,
                                 int instance_id,
                                 SAS::TrailId trail);

  rapidxml::xml_node<>* _ifc;
  std::string _server_name;
};
