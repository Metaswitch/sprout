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


#include "log.h"
#include "hssconnection.h"
#include "stack.h"
#include "pjutils.h"

#include "ifchandler.h"

using namespace rapidxml;


IfcHandler::IfcHandler(HSSConnection* hss) :
  _hss(hss)
{
}


IfcHandler::~IfcHandler()
{
  // nothing to do
}


/// Check whether the message matches the specified filter.
//
// @returns true if the message matches, false if not.
bool IfcHandler::filter_matches(const SessionCase& session_case, pjsip_msg *msg, xml_node<>* ifc)
{
  // TODO: Calculate the message matching properly.
  return (msg->line.req.method.id == PJSIP_INVITE_METHOD);
}


/// Determines the list of application servers to apply this message to, given
// the supplied incoming filter criteria.
void IfcHandler::calculate_application_servers(const SessionCase& session_case,
                                               pjsip_msg *msg,
                                               std::string& ifc_xml,
                                               std::vector<std::string>& as_list)
{
  xml_document<> ifc_doc;
  try
  {
    ifc_doc.parse<0>(ifc_doc.allocate_string(ifc_xml.c_str()));
  }
  catch (parse_error err)
  {
    LOG_ERROR("IFC parse error: %s", err.what());
    ifc_doc.clear();
  }

  xml_node<>* sp = ifc_doc.first_node("ServiceProfile");
  if (!sp)
  {
    // Failed to find the ServiceProfile node so this document is invalid.
    return;
  }

  // Spin through the list of filter criteria, checking whether each matches
  // and adding the application server to the list if so.
  for (xml_node<>* ifc = sp->first_node("InitialFilterCriteria");
       ifc;
       ifc = ifc->next_sibling("InitialFilterCriteria"))
  {
    if (filter_matches(session_case, msg, ifc))
    {
      xml_node<>* as = ifc->first_node("ApplicationServer");
      if (as)
      {
        xml_node<>* server_name = as->first_node("ServerName");
        if (server_name)
        {
          LOG_DEBUG("Found (triggered) server %s", server_name->value());
          as_list.push_back(server_name->value());
        }
      }
    }
  }
}


/// Get the list of application servers that should apply to this message,
// by inspecting the relevant subscriber's iFCs. If there are no iFCs,
// the list will be empty.
void IfcHandler::lookup_ifcs(const SessionCase& session_case,
                             pjsip_msg *msg,
                             SAS::TrailId trail,
                             std::string& served_user, //< OUT
                             std::vector<std::string>& application_servers)  //< OUT
{
  served_user = served_user_from_msg(session_case, msg);

  if (served_user.empty())
  {
    LOG_INFO("No served user");
  }
  else
  {
    LOG_DEBUG("Fetching IFC information for %s", served_user.c_str());
    std::string ifc_xml;
    if (!_hss->get_user_ifc(served_user, ifc_xml, trail))
    {
      LOG_INFO("No iFC found - no processing will be applied");
    }
    else
    {
      calculate_application_servers(session_case, msg, ifc_xml, application_servers);
    }
  }
}


/// Extracts the served user from a SIP message.  Behaviour depends on
/// the session case.
//
// @returns The username, ready to look up in HSS, or empty if no
// local served user.
std::string IfcHandler::served_user_from_msg(const SessionCase& session_case, pjsip_msg *msg)
{
  pjsip_uri* uri = NULL;
  std::string user;

  if (session_case.is_originating())
  {
    // For originating services, the user is parsed from the from header.
    uri = PJSIP_MSG_FROM_HDR(msg)->uri;
  }
  else
  {
    // For terminating services, the user is parsed from the request URI.
    uri = msg->line.req.uri;
  }

  // PJSIP URIs might have an irritating wrapper around them.
  uri = (pjsip_uri*)pjsip_uri_get_uri(uri);

  if ((PJUtils::is_home_domain(uri)) ||
      (PJUtils::is_uri_local(uri)))
  {
    user = user_from_uri(uri);
  }

  return user;
}


// Determines the user ID string from a URI.
//
// @returns the user ID
std::string IfcHandler::user_from_uri(pjsip_uri *uri)
{
  // Get the base URI, ignoring any display name.
  uri = (pjsip_uri*)pjsip_uri_get_uri(uri);

  // If this is a SIP URI, copy the user and host (only) out into a temporary
  // structure SIP URI and use this instead.  This strips any parameters.
  pjsip_sip_uri local_sip_uri;
  if (PJSIP_URI_SCHEME_IS_SIP(uri))
  {
    pjsip_sip_uri* sip_uri = (pjsip_sip_uri*)uri;
    pjsip_sip_uri_init(&local_sip_uri, PJSIP_URI_SCHEME_IS_SIPS(uri));
    local_sip_uri.user = sip_uri->user;
    local_sip_uri.host = sip_uri->host;
    uri = (pjsip_uri*)&local_sip_uri;
  }

  // Return the resulting string.
  return PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, uri);
}
