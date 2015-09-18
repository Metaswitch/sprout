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

#include "rapidxml/rapidxml_print.hpp"
using namespace rapidxml;

// Enum values for registration type, as per 3GPP TS 29.228.
#define INITIAL_REGISTRATION 0
#define REREGISTRATION 1
#define DEREGISTRATION 2

// Enum values for session case, as per CxData_Type_Rel11.xsd.
#define ORIGINATING_REGISTERED 0
#define TERMINATING_REGISTERED 1
#define TERMINATING_UNREGISTERED 2
#define ORIGINATING_UNREGISTERED 3
#define ORIGINATING_CDIV 4


// Forward declarations.
static long parse_integer(xml_node<>* node, std::string description, long min_value, long max_value);
static bool parse_bool(xml_node<>* node, std::string description);
static std::string get_first_node_value(xml_node<>* node, std::string name);
static std::string get_text_or_cdata(xml_node<>* node);
static bool does_child_node_exist(xml_node<>* parent_node, std::string child_node_name);

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
  // LCOV_EXCL_START work around unexplained gcov behaviour
  {
    // LCOV_EXCL_STOP
    return _what.c_str();
  }

private:
  std::string _what;
};


IfcHandler::IfcHandler()
{
}


IfcHandler::~IfcHandler()
{
  // nothing to do
}

void Ifc::invalid_ifc(std::string error,
                      std::string server_name,
                      int sas_event_id,
                      int instance_id,
                      SAS::TrailId trail)
{
    SAS::Event event(trail, sas_event_id, instance_id);
    event.add_var_param(server_name);
    event.add_var_param(error);
    SAS::report_event(event);
    throw ifc_error(error.c_str());
}

/// Test if the SPT matches. Ignores grouping and negation, and just
// evaluates the service point trigger in the node.
// @return true if the SPT matches, false if not
// @throw ifc_error if there is a problem evaluating the trigger.
bool Ifc::spt_matches(const SessionCase& session_case,  //< The session case
                      bool is_registered,               //< The registration state
                      bool is_initial_registration,
                      pjsip_msg* msg,                   //< The message being matched
                      xml_node<>* spt,                  //< The Service Point Trigger node
                      std::string ifc_str,
                      std::string server_name,
                      SAS::TrailId trail)
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
        invalid_ifc("Missing class for service point trigger", server_name, SASEvent::IFC_INVALID, 0, trail);
      }
      else
      {
        break;
      }
    }
  }

  if (!node)
  {
    invalid_ifc("Missing class for service point trigger", server_name, SASEvent::IFC_INVALID, 0, trail);
  }

  // Now interpret the node depending on its class.
  bool ret = false;

  if (strcmp("Method", name) == 0)
  {
    // If we have a REGISTER we may need to match on RegistrationType.
    if ((strcmp("REGISTER", node->value()) == 0) &&
        (pj_strcmp2(&msg->line.req.method.name, node->value()) == 0))
    {
      ret = true;
      node = node->next_sibling();
      if (node)
      {
        name = node->name();
        if (strcmp(name, "Extension") == 0)
        {
          for (xml_node<>* reg_type_node = node->first_node("RegistrationType");
               reg_type_node;
               reg_type_node = reg_type_node->next_sibling("RegistrationType"))
          {
            name = reg_type_node->name();
            int reg_type = parse_integer(reg_type_node, "registration type", 0, 2);

            // Find expiry value from SIP message if it is present to determine
            // whether we have a de-registration.  Set an arbitrary default value of
            // an hour.
            int expiry = PJUtils::max_expires(msg, 3600);

            switch (reg_type)
            {
            case INITIAL_REGISTRATION:
              ret = (is_initial_registration && (expiry > 0));
              break;
            case REREGISTRATION:
              ret = (!is_initial_registration && (expiry > 0));
              break;
            case DEREGISTRATION:
              ret = (expiry == 0);
              break;
            default:
              // LCOV_EXCL_START Unreachable
              TRC_WARNING("Impossible case %d", reg_type);
              ret = false;
              break;
              // LCOV_EXCL_STOP
            }

            // If we've found a match, break out of the for loop.
            if (ret)
            {
              break;
            }
          }
        }
      }
    }
    else
    {
      ret = (pj_strcmp2(&msg->line.req.method.name, node->value()) == 0);
    }
  }
  else if (strcmp("SIPHeader", name) == 0)
  {
    xml_node<>* spt_header = node->first_node("Header");
    xml_node<>* spt_content = node->first_node("Content");
    boost::regex header_regex;
    boost::regex content_regex;
    pjsip_hdr* header = NULL;

    if (!spt_header)
    {
      invalid_ifc("Missing Header element for SIPHeader service point trigger",
                  server_name, SASEvent::IFC_INVALID, 0, trail);
    }

    header_regex = boost::regex(get_text_or_cdata(spt_header),
                                boost::regex_constants::icase |
                                boost::regex_constants::no_except);
    if (header_regex.status())
    {
      invalid_ifc("Invalid regular expression in Header element for SIPHeader service point trigger",
                  server_name, SASEvent::IFC_INVALID, 0, trail);
    }

    for (header = msg->hdr.next; header != &msg->hdr; header = header->next)
    {
      if (boost::regex_search(PJUtils::pj_str_to_string(&(header->name)), header_regex))
      {
        if (!spt_content)
        {
          // We've found a matching header, and don't have to match on content
          ret = true;
        }
        else
        {
          std::string header_value = PJUtils::get_header_value(header);
          // status() is nonzero for an uninitialised regex, so we check this in order to only compile it once
          if (content_regex.status())
          {
            content_regex = boost::regex(get_text_or_cdata(spt_content), boost::regex_constants::no_except);
            if (content_regex.status())
            {
              invalid_ifc("Invalid regular expression in Content element for SIPHeader service point trigger",
                          server_name, SASEvent::IFC_INVALID, 0, trail);
            }
          }

          if (boost::regex_search(header_value, content_regex))
          {
            // We've found a matching header, and have matching content in one field
            ret = true;
          }
        }
      }
      if (ret)
      {
        // Stop processing other headers once we have a match
        break;
      }
    }
  }
  else if (strcmp("SessionCase", name) == 0)
  {
    int direction = parse_integer(node, "session case", 0, 4);
    switch (direction)
    {
    case ORIGINATING_REGISTERED:
      ret = (session_case == SessionCase::Originating) && is_registered;
      break;
    case TERMINATING_REGISTERED:
      ret = (session_case == SessionCase::Terminating) && is_registered;
      break;
    case TERMINATING_UNREGISTERED:
      ret = (session_case == SessionCase::Terminating) && !is_registered;
      break;
    case ORIGINATING_UNREGISTERED:
      ret = (session_case == SessionCase::Originating) && !is_registered;
      break;
    case ORIGINATING_CDIV:
      ret = (session_case == SessionCase::OriginatingCdiv);
      break;
    default:
      // LCOV_EXCL_START Unreachable
      TRC_WARNING("Impossible case %d", direction);
      ret = false;
      break;
    // LCOV_EXCL_STOP
    }
  }
  else if (strcmp("RequestURI", name) == 0)
  {
    boost::regex req_uri_regex;
    std::string test_string;

    if (PJSIP_URI_SCHEME_IS_TEL(msg->line.req.uri))
    {
      pjsip_tel_uri* req_uri =  (pjsip_tel_uri*)pjsip_uri_get_uri(msg->line.req.uri);

      // Match against the telephone-subscriber part of the Req URI, as per Table F.1
      // of 3GPP TS 29.228.
      test_string = PJUtils::pj_str_to_string(&req_uri->number);
    }
    else
    {
      pjsip_sip_uri* req_uri = (pjsip_sip_uri*)pjsip_uri_get_uri(msg->line.req.uri);

      // Compare against the hostport part of the Req URI, as per Table F.1
      // of 3GPP TS 29.228.
      std::string hostport = PJUtils::pj_str_to_string(&req_uri->host);

      if (req_uri->port != 0)
      {
        hostport += ":" + std::to_string(req_uri->port);
      }

      test_string = hostport;
    }

    req_uri_regex = boost::regex(get_text_or_cdata(node), boost::regex_constants::no_except);
    if (req_uri_regex.status())
    {
      invalid_ifc("Invalid regular expression in Request URI service point trigger",
                  server_name, SASEvent::IFC_INVALID, 0, trail);
    }
    ret = boost::regex_search(test_string, req_uri_regex);
  }
  else if (strcmp("SessionDescription", name) == 0)
  {
    xml_node<>* spt_line = node->first_node("Line");
    xml_node<>* spt_content = node->first_node("Content");
    boost::regex line_regex;
    boost::regex content_regex;
    char newline = '\n';

    if (!spt_line)
    {
      invalid_ifc("Missing Line element for SessionDescription service point trigger",
                  server_name, SASEvent::IFC_INVALID, 0, trail);
    }

    line_regex = boost::regex(get_text_or_cdata(spt_line), boost::regex_constants::no_except);
    if (line_regex.status())
    {
      invalid_ifc("Invalid regular expression in Line element for Session Description service point trigger",
                  server_name, SASEvent::IFC_INVALID, 0, trail);
    }

    // Check if the message body is SDP.
    if (msg->body &&
        (!pj_stricmp2(&msg->body->content_type.type, "application")) &&
        (!pj_stricmp2(&msg->body->content_type.subtype, "sdp")))
    {
      if (msg->body->data != NULL)
      {
        // Split the message body into each SDP line.
        std::stringstream sdp((char *)msg->body->data);
        std::string sdp_line;
        while((std::getline(sdp, sdp_line, newline)) && (ret == false))
        {
          // Match the line regex on the first character of the SDP line.
          std::string sdp_identifier(1, sdp_line[0]);
          if (boost::regex_search(sdp_identifier, line_regex))
          {
            if (!spt_content)
            {
              // We've found a matching line type, and don't have to match on content.
              ret = true;
            }
            else
            {
              // status() is nonzero for an uninitialised regex, so we check this in order to only compile it once.
              if (content_regex.status())
              {
                content_regex = boost::regex(get_text_or_cdata(spt_content), boost::regex_constants::no_except);
                if (content_regex.status())
                {
                  invalid_ifc("Invalid regular expression in Content element for Session Description service point trigger",
                              server_name, SASEvent::IFC_INVALID, 0, trail);
                }
              }

              // Check the second character of the line is an equals sign, and then
              // consider the content of the SDP line.
              if (sdp_line.find_first_of("=") == 1)
              {
                sdp_line.erase(0,2);
                if (boost::regex_search(sdp_line, content_regex))
                {
                  // We've found a matching line.
                  ret = true;
                }
              }
              else
              {
                TRC_WARNING("Found badly formatted SDP line: %s", sdp_line.c_str());
              }
            }
          }
        }
      }
    }
  }
  else
  {
    TRC_WARNING("Unimplemented iFC service point trigger class: %s", name);
    ret = false;
  }

  TRC_DEBUG("SPT class %s: result %s", name, ret ? "true" : "false");
  return ret;
}

/// Check whether the message matches the specified criterion.
// Refer to CxData_Type_Rel11.xsd in 3GPP TS 29.228, and also Annexes
// B, C, and F in that document for details.
//
// @return true if the message matches, false if not.
bool Ifc::filter_matches(const SessionCase& session_case,
                         bool is_registered,
                         bool is_initial_registration,
                         pjsip_msg* msg,
                         SAS::TrailId trail) const
{
  std::string ifc_str;
  rapidxml::print(std::back_inserter(ifc_str), *_ifc, 0);

  SAS::Event event(trail, SASEvent::IFC_TESTING, 0);
  event.add_compressed_param(ifc_str, &SASEvent::PROFILE_SERVICE_PROFILE);
  SAS::report_event(event);
  std::string server_name;

  try
  {
    xml_node<>* as = _ifc->first_node("ApplicationServer");
    if (as == NULL)
    {
      std::string error_msg = "iFC missing ApplicationServer element";

      SAS::Event event(trail, SASEvent::IFC_INVALID_NOAS, 0);
      SAS::report_event(event);

      throw ifc_error(error_msg);
    }

    server_name = get_first_node_value(as, "ServerName");
    if (server_name.empty())
    {
      std::string error_msg = "iFC has no ServerName";

      SAS::Event event(trail, SASEvent::IFC_INVALID_NOAS, 0);
      SAS::report_event(event);

      throw ifc_error(error_msg);
    }

    xml_node<>* profile_part_indicator = _ifc->first_node("ProfilePartIndicator");
    if (profile_part_indicator)
    {
      bool reg = parse_integer(profile_part_indicator, "ProfilePartIndicator", 0, 1) == 0;
      if (reg != is_registered)
      {
        std::string reg_state = reg ? "reg" : "unreg";
        std::string reason = "iFC ProfilePartIndicator " + reg_state + " doesn't match";
        TRC_DEBUG(reason.c_str());

        SAS::Event event(trail, SASEvent::IFC_NOT_MATCHED_PPI, 0);
        event.add_var_param(server_name);
        SAS::report_event(event);

        return false;
      }
    }

    // @@@ KSW Parse the URI and ensure it is parsable and a SIP URI
    // here. If it's invalid, ignore it (seems the only sensible
    // option).
    //
    // That means each AsInvocation would have to belong to a pool,
    // though, and that's not easy in the current architecture.

    xml_node<>* trigger = _ifc->first_node("TriggerPoint");
    if (!trigger)
    {
      TRC_DEBUG("iFC has no trigger point - unconditional match");  // 3GPP TS 29.228 sB.2.2

      SAS::Event event(trail, SASEvent::IFC_MATCHED, 0);
      event.add_var_param(server_name);
      SAS::report_event(event);

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
      bool val = spt_matches(session_case, is_registered, is_initial_registration, msg, spt, ifc_str, server_name, trail) != neg;

      for (xml_node<>* group_node = spt->first_node("Group");
           group_node;
           group_node = group_node->next_sibling("Group"))
      {
        int32_t group = parse_integer(group_node, "Group ID", 0, std::numeric_limits<int32_t>::max());
        TRC_DEBUG("Add to group %d val %s", (int)group, val ? "true" : "false");
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
      TRC_DEBUG("Result group %d val %s", (int)it->first, it->second ? "true" : "false");
      ret = cnf ? (ret && it->second) : (ret || it->second);
    }

    if (ret)
    {
      TRC_DEBUG("iFC matches");
      SAS::Event event(trail, SASEvent::IFC_MATCHED, 0);
      event.add_var_param(server_name);
      SAS::report_event(event);
    }
    else
    {
      TRC_DEBUG("iFC does not match");
      SAS::Event event(trail, SASEvent::IFC_NOT_MATCHED, 0);
      event.add_var_param(server_name);
      SAS::report_event(event);
    }

    return ret;
  }
  catch (ifc_error err)
  {
    // Ignore individual criteria which can't be parsed. SAS logging
    // should already have happened by this point.
    std::string err_str = "iFC evaluation error: " + std::string(err.what());
    TRC_ERROR(err_str.c_str());
    return false;
  }
}


/// Gets the first child node of "node" with name "name". Returns an empty string if there
// is no such node, otherwise returns its value (which is the empty string if
// it has no value).
static std::string get_first_node_value(xml_node<>* node, std::string name)
{
  xml_node<>* first_node = node->first_node(name.c_str());
  if (!first_node)
  {
    return "";
  }
  else
  {
    return get_text_or_cdata(first_node);
  }
}

// Takes an XML node containing ONLY text or CDATA (not both) and returns the value of that text or
// CDATA.
//
// This is necesary because RapidXML's value() function only returns the text of the first data node,
// not the first CDATA node.
static std::string get_text_or_cdata(xml_node<>* node)
{
  xml_node<>* first_data_node = node->first_node();
  if (first_data_node && ((first_data_node->type() != node_cdata) || (first_data_node->type() != node_data)))
  {
    return first_data_node->value();
  }
  else
  {
    return "";
  }
}

static bool does_child_node_exist(xml_node<>* parent_node, std::string child_node_name)
{
  xml_node<>* child_node = parent_node->first_node(child_node_name.c_str());
  return (child_node != NULL);
}


/// Return the AsInvocation corresponding to this iFC.
//
// Only safe to call if filter_matches has returned true (to validate
// the iFC).
AsInvocation Ifc::as_invocation() const
{
  xml_node<>* as = _ifc->first_node("ApplicationServer");
  pj_assert(as != NULL);

  AsInvocation as_invocation;
  as_invocation.server_name = get_first_node_value(as, "ServerName");

  // @@@ KSW Parse the URI and ensure it is parsable and a SIP URI
  // here. If it's invalid, ignore it (seems the only sensible
  // option).
  //
  // That means each AsInvocation would have to belong to a pool,
  // though, and that's not easy in the current architecture.

  std::string default_handling = get_first_node_value(as, "DefaultHandling");
  if (default_handling == "0")
  {
    // DefaultHandling is present and set to 0, which is SESSION_CONTINUED.
    as_invocation.default_handling = SESSION_CONTINUED;
  }
  else if (default_handling == "1")
  {
    // DefaultHandling is present and set to 1, which is SESSION_TERMINATED.
    as_invocation.default_handling = SESSION_TERMINATED;
  }
  else
  {
    // If the DefaultHandling attribute isn't present, or is malformed, default
    // to SESSION_CONTINUED.
    TRC_WARNING("Badly formed DefaultHandling element in IFC (%s), defaulting to SESSION_CONTINUED",
                default_handling.c_str());
    as_invocation.default_handling = SESSION_CONTINUED;
  }
  as_invocation.service_info = get_first_node_value(as, "ServiceInfo");

  xml_node<>* as_ext = as->first_node("Extension");
  if (as_ext)
  {
    as_invocation.include_register_request = does_child_node_exist(as_ext, "IncludeRegisterRequest");
    as_invocation.include_register_response = does_child_node_exist(as_ext, "IncludeRegisterResponse");
  }
  else
  {
    as_invocation.include_register_request = false;
    as_invocation.include_register_response = false;
  };

  TRC_INFO("Found (triggered) server %s", as_invocation.server_name.c_str());
  return as_invocation;
}


/// Construct an empty set of iFCs.
Ifcs::Ifcs() :
  _ifc_doc(NULL)
{
}


/// Construct a set of iFCs. Takes ownership of the ifc_doc.
//
// If there are any errors, yields an empty iFC doc (but does not fail).
Ifcs::Ifcs(std::shared_ptr<xml_document<> > ifc_doc, xml_node<>* sp) :
  _ifc_doc(ifc_doc)
{
  // List sorted by priority (smallest should be handled first).
  // Priority is xs:int restricted to be positive, i.e., 0..2147483647.
  std::multimap<int32_t, Ifc> ifc_map;

  if (sp)
  {

    // Spin through the list of filter criteria, adding each to the list.
    for (xml_node<>* ifc = sp->first_node("InitialFilterCriteria");
         ifc;
         ifc = ifc->next_sibling("InitialFilterCriteria"))
    {
      try
      {
        xml_node<>* priority_node = ifc->first_node("Priority");
        int32_t priority = (int32_t)((priority_node) ?
                                     parse_integer(priority_node, "iFC priority", 0, std::numeric_limits<int32_t>::max()) :
                                     0);
        ifc_map.insert(std::pair<int32_t, Ifc>(priority, Ifc(ifc)));
      }
      catch (ifc_error err)
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


/// Attempt to parse the content of the node as a bounded integer
// returning the result or throwing.
static long parse_integer(xml_node<>* node, std::string description, long min_value, long max_value)
{
  // Node must be non-NULL - caller should check for this prior to calling
  // this method.
  assert(node != NULL);

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
                    std::to_string(min_value) + ".." + std::to_string(max_value));
  }

  return n;
}

/// Parse an xs:boolean value.
static bool parse_bool(xml_node<>* node, std::string description)
{
  if (!node)
  {
    throw ifc_error("Missing mandatory value for " + description);
  }

  const char* nptr = node->value();

  return ((strcmp("true", nptr) == 0) || (strcmp("1", nptr) == 0));
}

