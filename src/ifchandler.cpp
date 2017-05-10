/**
 * @file ifchandler.cpp The iFC handler data type.
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

#include <boost/regex.hpp>
#include <cassert>

extern "C" {
#include <pjlib-util.h>
#include <pjlib.h>
}

#include "log.h"
#include "constants.h"
#include "stack.h"
#include "pjutils.h"
#include "pjmedia.h"

#include "ifchandler.h"

#include "sas.h"
#include "sproutsasevent.h"
#include "uri_classifier.h"
#include "xml_utils.h"

#include "rapidxml/rapidxml_print.hpp"
using namespace rapidxml;

IfcHandler::IfcHandler()
{
}


IfcHandler::~IfcHandler()
{
  // nothing to do
}

/// Construct an empty set of iFCs.
Ifcs::Ifcs() :
  _ifc_doc(NULL)
{
}


/// Construct a set of iFCs. Takes ownership of the ifc_doc.
//
// If there are any errors, yields an empty iFC doc (but does not fail).
Ifcs::Ifcs(std::shared_ptr<xml_document<> > ifc_doc,
           xml_node<>* sp,
           SIFCService* sifc_service,
           SAS::TrailId trail) :
  _ifc_doc(ifc_doc)
{
  // List sorted by priority (smallest should be handled first).
  // Priority is xs:int restricted to be positive, i.e., 0..2147483647.
  std::multimap<int32_t, Ifc> ifc_map;

  if (sp)
  {

    for (xml_node<>* ext = sp->first_node(RegDataXMLUtils::EXTENSION);
         ext;
         ext = ext->next_sibling(RegDataXMLUtils::EXTENSION))
    {
      std::set<int32_t> ids;
      for (xml_node<>* sifc = ext->first_node(RegDataXMLUtils::SIFC);
           sifc;
           sifc = sifc->next_sibling(RegDataXMLUtils::SIFC))
      {
        try
        {
          ids.insert(XMLUtils::parse_integer(sifc,
                                             "SharedIFCSetID",
                                             0,
                                             std::numeric_limits<int32_t>::max()));
        }
        catch (xml_error err)
        {
          // Ignore a shared IFC set ID which can't be parsed, and keep
          // going with the rest.
          TRC_ERROR("SiFC evaluation error %s", err.what());
        }
      }

      if ((sifc_service) && (!ids.empty()))
      {
        sifc_service->get_ifcs_from_id(ifc_map, ids, ifc_doc, trail);
      }
    }

    // Spin through the list of filter criteria, adding each to the list.
    for (xml_node<>* ifc = sp->first_node(RegDataXMLUtils::IFC);
         ifc;
         ifc = ifc->next_sibling(RegDataXMLUtils::IFC))
    {
      try
      {
        xml_node<>* priority_node = ifc->first_node(RegDataXMLUtils::PRIORITY);
        int32_t priority = (int32_t)((priority_node) ?
                                     XMLUtils::parse_integer(priority_node,
                                                             "iFC priority",
                                                             0,
                                                             std::numeric_limits<int32_t>::max()) :
                                     0);
        ifc_map.insert(std::pair<int32_t, Ifc>(priority, Ifc(ifc)));
      }
      catch (xml_error err)
      {
        // Ignore individual criteria which can't be parsed, and keep
        // going with the rest.
        TRC_ERROR("iFC evaluation error %s", err.what());
      }
    }

    for (std::multimap<int32_t, Ifc>::iterator it = ifc_map.begin();
         it != ifc_map.end();
         ++it)
    {
      _ifcs.push_back(it->second);
    }
  }
  else
  {
    TRC_ERROR("No ServiceProfile node in iFC!");
  }
}


Ifcs::~Ifcs()
{
}


/// Get the list of application servers that should apply to this
// message, given a list of iFCs to consider.
//
// Only for use in third-party registration; in the normal case, an
// iFC should be evaluated according to the message as processed by
// all ASs so far, rather than the initial message as it arrived at
// Sprout.  See 3GPP TS 23.218, especially s5.2 and s6.
void Ifcs::interpret(const SessionCase& session_case,  //< The session case
                     bool is_registered,               //< Whether the served user is registered
                     bool is_initial_registration,
                     pjsip_msg* msg,                   //< The message starting the dialog
                     std::vector<AsInvocation>& application_servers, //< OUT: the list of application servers
                     SAS::TrailId trail) const  //< SAS trail
{
  TRC_DEBUG("Interpreting %s IFC information", session_case.to_string().c_str());
  for (std::vector<Ifc>::const_iterator it = _ifcs.begin();
       it != _ifcs.end();
       ++it)
  {
    if (it->filter_matches(session_case, is_registered, is_initial_registration, msg, trail))
    {
      application_servers.push_back(it->as_invocation());
    }
  }

  // TODO - waiting on spec finalization for third party registrations
}


/// Extracts the served user from a SIP message.  Behaviour depends on
/// the session case.
//
// @returns The username, ready to look up in HSS, or empty if no
// local served user.
std::string IfcHandler::served_user_from_msg(const SessionCase& session_case,
                                             pjsip_msg* msg,
                                             pj_pool_t* pool)
{
  // For originating:
  //
  // We determine the served user as described in 3GPP TS 24.229 s5.4.3.2,
  // step 1. This first relies on P-Served-User (RFC5502), if present
  // (step 1a). If not (step 1b), we then look at P-Asserted-Identity.
  // For compliance with non-IMS devices (and contrary to the IMS spec),
  // if there is no P-Asserted-Identity we then look at the From header
  // or the request URI as appropriate for the session case.  Per 24.229,
  // we ignore the session case and registration state parameters of
  // P-Served-User; these are intended for the AS, not the S-CSCF (which
  // has other means of determining these).

  // For terminating:
  //
  // We determine the served user as described in 3GPP TS 24.229
  // s5.4.3.3, step 1, i.e., purely on the Request-URI.

  // For originating after retargeting (orig-cdiv), we normally don't
  // call this method at all, because we can pick up the served user
  // from the existing AsChain. If this method is called, however, the
  // following logic applies:
  //
  // We could determine the served user as described in 3GPP TS
  // 24.229 s5.4.3.3 step 3b. This relies on History-Info (RFC4244)
  // and P-Served-User (RFC5502) in step 3b. We should never respect
  // P-Asserted-Identity.
  //
  // We implement P-Served-User, and fall back on the From
  // header. However, the History-Info mechanism has fundamental
  // problems as outlined in RFC5502 appendix A, and we do not
  // implement it.
  pjsip_uri* uri;
  std::string user;

  if (session_case.is_originating())  // (includes orig-cdiv)
  {
    uri = PJUtils::orig_served_user(msg);
  }
  else
  {
    uri = PJUtils::term_served_user(msg);
  }

  if ((PJSIP_URI_SCHEME_IS_SIP(uri)) &&
      (URIClassifier::classify_uri(uri) != OFFNET_SIP_URI))
  {
    user = PJUtils::public_id_from_uri(uri);
  }
  else if (PJSIP_URI_SCHEME_IS_TEL(uri))
  {
    user = PJUtils::public_id_from_uri(uri);
  }
  else
  {
    TRC_DEBUG("URI is not locally hosted");
  }

  return user;
}
