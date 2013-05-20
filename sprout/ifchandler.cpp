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

#include <boost/lexical_cast.hpp>

extern "C" {
#include <pjlib-util.h>
#include <pjlib.h>
}

#include "log.h"
#include "constants.h"
#include "hssconnection.h"
#include "stack.h"
#include "pjutils.h"

#include "ifchandler.h"

using namespace rapidxml;

// Forward declarations.
long parse_integer(xml_node<>* node, std::string description, long min_value, long max_value);
bool parse_bool(xml_node<>* node, std::string description);


/// Exception thrown internally during interpretation of filter
/// criteria.
class ifc_error : public std::exception
{
public:
  ifc_error(std::string what)
    : _what(what)
  {
  }

  virtual ~ifc_error() throw ()
  {
  }

  virtual const char* what() const throw()
  { // LCOV_EXCL_LINE work around unexplained gcov behaviour
    return _what.c_str();
  }

private:
  std::string _what;
};


IfcHandler::IfcHandler(HSSConnection* hss, RegData::Store* store) :
  _hss(hss),
  _store(store)
{
}


IfcHandler::~IfcHandler()
{
  // nothing to do
}

/// Test if the SPT matches. Ignores grouping and negation, and just
// evaluates the service point trigger in the node.
// @return true if the SPT matches, false if not
// @throw ifc_error if there is a problem evaluating the trigger.
bool IfcHandler::spt_matches(const SessionCase& session_case,  //< The session case
                             bool is_registered,               //< The registration state
                             pjsip_msg *msg,                   //< The message being matched
                             xml_node<>* spt)                  //< The Service Point Trigger node
{
  // Find the class node.
  xml_node<>* node = spt->first_node();
  const char* name = NULL;

  for (; node; node = node->next_sibling())
  {
    name = node->name();

    if ((strcmp(name, "ConditionNegated") != 0) &&
        (strcmp(name, "Group") != 0))
    {
      if (strcmp(name, "Extension") == 0)
      {
        throw ifc_error("Missing class for service point trigger");
      }
      else
      {
        break;
      }
    }
  }

  if (!node)
  {
    throw ifc_error("Missing class for service point trigger");
  }

  // Now interpret the node depending on its class.
  bool ret = false;

  if (strcmp("Method", name) == 0)
  {
    // @@@KSW TODO if node->value() is REGISTER, inspect
    // spt_node/Extension/RegistrationType (0, 1, or 2 values) and
    // check to see if they match the registration type.
    ret = (pj_strcmp2(&msg->line.req.method.name, node->value()) == 0);
  }
  else if (strcmp("SessionCase", name) == 0)
  {
    // Enum values are per CxData_Type_Rel11.xsd.
    int direction = parse_integer(node, "session case", 0, 4);
    switch (direction)
    {
    case 0: // ORIGINATING_REGISTERED
    {
      ret = (session_case == SessionCase::Originating) && is_registered;
    }
    break;
    case 1: // TERMINATING_REGISTERED
    {
      ret = (session_case == SessionCase::Terminating) && is_registered;
    }
    break;
    case 2: // TERMINATING_UNREGISTERED
    {
      ret = (session_case == SessionCase::Terminating) && !is_registered;
    }
    break;
    case 3: // ORIGINATING_UNREGISTERED
    {
      ret = (session_case == SessionCase::Originating) && !is_registered;
    }
    break;
    case 4: // ORIGINATING_CDIV
    {
      ret = (session_case == SessionCase::OriginatingCdiv);
    }
    break;
    default:
      // LCOV_EXCL_START Unreachable
    {
      LOG_WARNING("Impossible case %d", direction);
      ret = false;
    }
    break;
      // LCOV_EXCL_STOP
    }
  }
  else
  {
    LOG_WARNING("Unimplemented iFC service point trigger class: %s", name);
    ret = false;
  }

  LOG_DEBUG("SPT class %s: result %s", name, ret ? "true" : "false");
  return ret;
}

/// Check whether the message matches the specified criterion.
// Refer to CxData_Type_Rel11.xsd in 3GPP TS 29.228, and also Annexes
// B, C, and F in that document for details.
//
// @return true if the message matches, false if not.
// @throw ifc_error if there is a problem evaluating the criterion.
bool IfcHandler::filter_matches(const SessionCase& session_case, bool is_registered, pjsip_msg *msg, xml_node<>* ifc)
{
  xml_node<>* profile_part_indicator = ifc->first_node("ProfilePartIndicator");
  if (profile_part_indicator)
  {
    bool reg = parse_integer(profile_part_indicator, "ProfilePartIndicator", 0, 1) == 0;
    if (reg != is_registered)
    {
      LOG_DEBUG("iFC ProfilePartIndicator %s doesn't match", reg ? "reg" : "unreg");
      return false;
    }
  }

  xml_node<>* trigger = ifc->first_node("TriggerPoint");
  if (!trigger)
  {
    LOG_DEBUG("iFC has no trigger point - unconditional match");  // 3GPP TS 29.228 sB.2.2
    return true;
  }

  bool cnf = parse_bool(trigger->first_node("ConditionTypeCNF"), "ConditionTypeCNF");

  // In CNF (conjunct-of-disjuncts, i.e., big-AND of ORs), as we
  // work through each SPT we OR it into its group(s). At the end,
  // we AND all the groups together. In DNF we do the converse.
  std::map<int32_t, bool> groups;

  for (xml_node<>* spt = trigger->first_node("SPT");
     spt;
     spt = spt->next_sibling("SPT"))
  {
    xml_node<>* neg_node = spt->first_node("ConditionNegated");
    bool neg = neg_node && parse_bool(neg_node, "ConditionNegated");
    bool val = spt_matches(session_case, is_registered, msg, spt) != neg;

    for (xml_node<>* group_node = spt->first_node("Group");
         group_node;
         group_node = group_node->next_sibling("Group"))
    {
      int32_t group = parse_integer(group_node, "Group ID", 0, std::numeric_limits<int32_t>::max());
      LOG_DEBUG("Add to group %d val %s", (int)group, val ? "true" : "false");
      if (groups.find(group) == groups.end())
      {
        groups[group] = val;
      }
      else
      {
        groups[group] = cnf ? (groups[group] || val) : (groups[group] && val);
      }
    }
  }

  bool ret = cnf;

  for (std::map<int32_t, bool>::iterator it = groups.begin();
       it != groups.end();
       ++it)
  {
    LOG_DEBUG("Result group %d val %s", (int)it->first, it->second ? "true" : "false");
    ret = cnf ? (ret && it->second) : (ret || it->second);
  }

  LOG_DEBUG("iFC %s", ret ? "matches" : "does not match");
  return ret;
}

// Gets the first child node of "node" with name "name". Returns an empty string if there
// is no such node, otherwise returns its value (which is the empty string if
// it has no value).
std::string get_first_node_value(xml_node<>* node, std::string name) {
  xml_node<>* first_node = node->first_node(name.c_str());
  if (first_node == NULL)
  {
    return "";
  };
  return first_node->value();
}

bool does_child_node_exist(xml_node<>* parent_node, std::string child_node_name) {
  xml_node<>* child_node = parent_node->first_node(child_node_name.c_str());
   if (child_node == NULL)
   {
     return false;
   } else {
     return true;
   };
}


/// Determines the list of application servers to apply this message to, given
// the supplied incoming filter criteria.
void IfcHandler::calculate_application_servers(const SessionCase& session_case,
                                               bool is_registered,
                                               pjsip_msg *msg,
                                               std::string& ifc_xml,
                                               std::vector<AsInvocation>& as_list)
{
  xml_document<> ifc_doc;
  try
  {
    ifc_doc.parse<0>(ifc_doc.allocate_string(ifc_xml.c_str()));
  }
  catch (parse_error err)
  {
    LOG_ERROR("iFCs parse error: %s", err.what());
    ifc_doc.clear();
  }

  xml_node<>* sp = ifc_doc.first_node("ServiceProfile");
  if (!sp)
  {
    // Failed to find the ServiceProfile node so this document is invalid.
    return;
  }

  // List sorted by priority (smallest should be handled first).
  // Priority is xs:int restricted to be positive, i.e., 0..2147483647.
  std::multimap<int32_t, AsInvocation> as_map;

  // Spin through the list of filter criteria, checking whether each matches
  // and adding the application server to the list if so.
  for (xml_node<>* ifc = sp->first_node("InitialFilterCriteria");
       ifc;
       ifc = ifc->next_sibling("InitialFilterCriteria"))
  {
    try
    {
      if (filter_matches(session_case, is_registered, msg, ifc))
      {
        xml_node<>* priority_node = ifc->first_node("Priority");
        xml_node<>* as = ifc->first_node("ApplicationServer");
        if (as)
        {
          AsInvocation as_invocation;
          int32_t priority = (int32_t)parse_integer(priority_node, "iFC priority", 0, std::numeric_limits<int32_t>::max());
          as_invocation.server_name = get_first_node_value(as, "ServerName");
          as_invocation.default_handling = boost::lexical_cast<intptr_t>(get_first_node_value(as, "DefaultHandling"));
          as_invocation.service_info = get_first_node_value(as, "ServiceInfo");

          xml_node<>* as_ext = as->first_node("Extension");
          if (as_ext)
          {
            as_invocation.include_register_request = does_child_node_exist(as_ext, "IncludeRegisterRequest");
            as_invocation.include_register_response = does_child_node_exist(as_ext, "IncludeRegisterResponse");
          } else {
            as_invocation.include_register_request = false;
            as_invocation.include_register_response = false;
          };

          if (!as_invocation.server_name.empty())
          {
            LOG_INFO("Found (triggered) server %s at priority %d", as_invocation.server_name.c_str(), (int)priority);
            as_map.insert(std::pair<int32_t, AsInvocation>(priority, as_invocation));
            // @@@ KSW Parse the URI and ensure it is parsable and a
            // SIP URI here. If it's invalid, ignore it (seems the
            // only sensible option).
          }
        }
      } else {
        LOG_INFO("Filter did not match!");
     }
    }
    catch (ifc_error err)
    {
      // Ignore individual criteria which can't be parsed, and keep
      // going with the rest.
      LOG_ERROR("iFC evaluation error %s", err.what());
    }
  }

  for (std::multimap<int32_t, AsInvocation>::iterator it = as_map.begin();
       it != as_map.end();
       ++it)
  {
    as_list.push_back(it->second);
  }
}


/// Get the served user and list of application servers that should
// apply to this message, by inspecting the relevant subscriber's
// iFCs. If there are no iFCs, the list will be empty.
void IfcHandler::lookup_ifcs(const SessionCase& session_case,  //< The session case
                             const std::string& served_user,   //< The served user
                             bool is_registered,               //< Whether the served user is registered
                             pjsip_msg *msg,                   //< The message starting the dialog
                             SAS::TrailId trail,               //< The SAS trail ID
                             std::vector<AsInvocation>& application_servers)  //< OUT the AS list
{
  LOG_DEBUG("Fetching %s IFC information for %s", session_case.to_string().c_str(), served_user.c_str());
  std::string ifc_xml;
  if (!_hss->get_user_ifc(served_user, ifc_xml, trail))
  {
    LOG_INFO("No iFC found - no processing will be applied");
  }
  else
  {
    calculate_application_servers(session_case, is_registered, msg, ifc_xml, application_servers);
  }
}


/// Extracts the served user from a SIP message.  Behaviour depends on
/// the session case.
//
// @returns The username, ready to look up in HSS, or empty if no
// local served user.
std::string IfcHandler::served_user_from_msg(
  const SessionCase& session_case,
  pjsip_rx_data* rdata)
{
  pjsip_uri* uri = NULL;
  std::string user;

  // For originating:
  //
  // Ultimately we should determine the served user as described in
  // 3GPP TS 24.229 s5.4.3.2, step 1. This first relies on
  // P-Served-User (RFC5502), if present (step 1a). We do implement
  // this part. However, until sto125 (support for multiple identities
  // for the same line) is implemented, bono doesn't set the
  // P-Asserted-Identity header so it makes no sense to rely on it,
  // let alone to select one of the identities based on local policy
  // (step 1.b.ii). We therefore ignore P-Asserted-Identity entirely
  // for now. Instead, we look at the From header or the request URI
  // as appropriate for the session case.  Per 24.229, we ignore the
  // session case and registration state parameters of P-Served-User;
  // these are intended for the AS, not the S-CSCF (which has other
  // means of determining these).

  // For terminating:
  //
  // We determine the served user as described in 3GPP TS 24.229
  // s5.4.3.3, step 1, i.e., purely on the Request-URI.

  // For originating after retargeting (orig-cdiv):
  //
  // We should determine the served user as described in 3GPP TS
  // 24.229 s5.4.3.3 step 3b. This relies on History-Info (RFC4244)
  // and P-Served-User (RFC5502) in step 3b. We should never respect
  // P-Asserted-Identity.
  //
  // We implement P-Served-User, and fall back on the From
  // header. However, the History-Info mechanism has fundamental
  // problems as outlined in RFC5502 appendix A, and we do not
  // implement it.

  if (session_case.is_originating())  // (includes orig-cdiv)
  {
    // Inspect P-Served-User header. Format is name-addr or addr-spec
    // (containing a URI), followed by optional parameters.
    pjsip_generic_string_hdr* served_user_hdr = (pjsip_generic_string_hdr*)
      pjsip_msg_find_hdr_by_name(rdata->msg_info.msg, &STR_P_SERVED_USER, NULL);

    if (served_user_hdr != NULL)
    {
      uri = PJUtils::uri_from_string_header(served_user_hdr, rdata->tp_info.pool);

      if (uri == NULL)
      {
        LOG_WARNING("Unable to parse P-Served-User header: %.*s",
                    served_user_hdr->hvalue.slen, served_user_hdr->hvalue.ptr);
      }
    }
  }

  if (uri == NULL)
  {
    if (session_case.is_originating())
    {
      // For originating services, the user is parsed from the from header.
      uri = PJSIP_MSG_FROM_HDR(rdata->msg_info.msg)->uri;
    }
    else
    {
      // For terminating services, the user is parsed from the request URI.
      uri = rdata->msg_info.msg->line.req.uri;
    }
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

/// Attempt to parse the content of the node as a bounded integer
// returning the result or throwing.
long parse_integer(xml_node<>* node, std::string description, long min_value, long max_value)
{
  if (!node)
  {
    throw ifc_error("Missing mandatory value for " + description);
  }

  const char* nptr = node->value();
  char* endptr = NULL;
  long int n = strtol(nptr, &endptr, 10);

  if ((*nptr == '\0') || (*endptr != '\0'))
  {
    throw ifc_error("Can't parse " + description + " as integer");
  }

  if ((n < min_value) || (n > max_value))
  {
    throw ifc_error(description + " out of allowable range " +
                    boost::lexical_cast<std::string>(min_value) + ".." +
                    boost::lexical_cast<std::string>(max_value));
  }

  return n;
}

/// Parse an xs:boolean value.
bool parse_bool(xml_node<>* node, std::string description)
{
  if (!node)
  {
    throw ifc_error("Missing mandatory value for " + description);
  }

  const char* nptr = node->value();

  return ((strcmp("true", nptr) == 0) || (strcmp("1", nptr) == 0));
}

