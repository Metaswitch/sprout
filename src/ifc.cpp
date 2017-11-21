/**
 * @file ifc.cpp The iFC handler data type.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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

#include "ifc.h"

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

Ifc::Ifc(std::string ifc_str,
         rapidxml::xml_document<>* ifc_doc) :
  _ifc(NULL)
{
  rapidxml::xml_document<>* new_document = new rapidxml::xml_document<>();

  // We must use a new XML document to parse the string (as it's destructive).
  // We allocate the string from the passed in document, and then clone the
  // node into that document, ensuring that the passed in document owns
  // everything associated with the IFC.
  char* xml_str = ifc_doc->allocate_string(ifc_str.c_str());
  new_document->parse<0>(xml_str);
  _ifc = ifc_doc->clone_node(new_document->first_node());

  delete new_document;
}

void Ifc::handle_invalid_ifc(std::string error,
                             std::string server_name,
                             int sas_event_id,
                             int instance_id,
                             SAS::TrailId trail)
{
  TRC_ERROR("Skip processing invalid iFC for %s: %s", 
            server_name.c_str(), 
            error.c_str());
  SAS::Event event(trail, sas_event_id, instance_id);
  event.add_var_param(server_name);
  event.add_var_param(error);
  SAS::report_event(event);
  throw ifc_error();
}

void Ifc::handle_unusual_ifc(std::string error,
                             std::string server_name,
                             int sas_event_id,
                             int instance_id,
                             SAS::TrailId trail)
{
  TRC_INFO("Continue processing unusual iFC for %s: %s", 
           server_name.c_str(), 
           error.c_str());
  SAS::Event event(trail, sas_event_id, instance_id);
  event.add_var_param(server_name);
  event.add_var_param(error);
  SAS::report_event(event);
}

// Test if the SPT matches. Ignores grouping and negation, and just
// evaluates the service point trigger in the node.
// @return true if the SPT matches, false if not
// @throw xml_error if there is a problem evaluating the trigger.
bool Ifc::spt_matches(const SessionCase& session_case,  //< The session case
                      const bool is_registered,               //< The registration state
                      const bool is_initial_registration,
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

    if ((strcmp(name, RegDataXMLUtils::CONDITION_NEGATED) != 0) &&
        (strcmp(name, RegDataXMLUtils::GROUP) != 0))
    {
      if (strcmp(name, RegDataXMLUtils::EXTENSION) == 0)
      {
        handle_invalid_ifc("Missing class for service point trigger", server_name, SASEvent::INVALID_IFC_IGNORED, 0, trail);
      }
      else
      {
        break;
      }
    }
  }

  if (!node)
  {
    handle_invalid_ifc("Missing class for service point trigger", server_name, SASEvent::INVALID_IFC_IGNORED, 0, trail);
  }

  // Now interpret the node depending on its class.
  bool ret = false;

  if (strcmp(RegDataXMLUtils::METHOD, name) == 0)
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
        if (strcmp(name, RegDataXMLUtils::EXTENSION) == 0)
        {
          for (xml_node<>* reg_type_node = node->first_node(RegDataXMLUtils::REGISTRATION_TYPE);
               reg_type_node;
               reg_type_node = reg_type_node->next_sibling(RegDataXMLUtils::REGISTRATION_TYPE))
          {
            name = reg_type_node->name();
            int reg_type = XMLUtils::parse_integer(reg_type_node,
                                                   "registration type",
                                                   0,
                                                   2);

            // Find expiry value from SIP message if it is present to determine
            // whether we have a de-registration.  Set an arbitrary default value of
            // an hour.
            pj_bool_t dereg = PJUtils::is_deregistration(msg);

            switch (reg_type)
            {
            case INITIAL_REGISTRATION:
              ret = (is_initial_registration && !dereg);
              break;
            case REREGISTRATION:
              ret = (!is_initial_registration && !dereg);
              break;
            case DEREGISTRATION:
              ret = dereg;
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
  else if (strcmp(RegDataXMLUtils::SIP_HEADER, name) == 0)
  {
    xml_node<>* spt_header = node->first_node(RegDataXMLUtils::HEADER);
    xml_node<>* spt_content = node->first_node(RegDataXMLUtils::CONTENT);
    boost::regex header_regex;
    boost::regex content_regex;
    pjsip_hdr* header = NULL;

    if (!spt_header)
    {
      handle_invalid_ifc("Missing Header element for SIPHeader service point trigger",
                         server_name, SASEvent::INVALID_IFC_IGNORED, 0, trail);
    }

    header_regex = boost::regex(XMLUtils::get_text_or_cdata(spt_header),
                                boost::regex_constants::icase |
                                boost::regex_constants::no_except);
    if (header_regex.status())
    {
      handle_invalid_ifc("Invalid regular expression in Header element for SIPHeader service point trigger",
                         server_name, SASEvent::INVALID_IFC_IGNORED, 0, trail);
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
            content_regex = boost::regex(XMLUtils::get_text_or_cdata(spt_content),
                                         boost::regex_constants::no_except);
            if (content_regex.status())
            {
              handle_invalid_ifc("Invalid regular expression in Content element for SIPHeader service point trigger",
                                 server_name, SASEvent::INVALID_IFC_IGNORED, 0, trail);
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
  else if (strcmp(RegDataXMLUtils::SESSION_CASE, name) == 0)
  {
    int direction = XMLUtils::parse_integer(node, "session case", 0, 4);
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
  else if (strcmp(RegDataXMLUtils::REQUEST_URI, name) == 0)
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
    else if (PJSIP_URI_SCHEME_IS_URN(msg->line.req.uri))
    {
      pjsip_other_uri* req_uri = (pjsip_other_uri*)pjsip_uri_get_uri(msg->line.req.uri);

      // There is nothing in TS 29.228 about what to match against in the case
      // of a urn URI. So just pull out the entire content (which is everything
      // after "urn:").
      test_string = PJUtils::pj_str_to_string(&req_uri->content);
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

    std::string req_uri = XMLUtils::get_text_or_cdata(node);
    if ((req_uri.compare(0, 4, "sip:") == 0) ||
        (req_uri.compare(0, 4, "tel:") == 0))
    {
      handle_unusual_ifc("Request URI should be a regex that matches either on "
                         "the hostport of a SIP URI or a telephone number.",
                         server_name, SASEvent::IFC_UNUSUAL, 0, trail);
    }
    
    req_uri_regex = boost::regex(req_uri,
                                 boost::regex_constants::no_except);
    if (req_uri_regex.status())
    {
      handle_invalid_ifc("Invalid regular expression in Request URI service point trigger",
                         server_name, SASEvent::INVALID_IFC_IGNORED, 0, trail);
    }
      ret = boost::regex_search(test_string, req_uri_regex);
  }
  else if (strcmp(RegDataXMLUtils::SESSION_DESCRIPTION, name) == 0)
  {
    xml_node<>* spt_line = node->first_node(RegDataXMLUtils::LINE);
    xml_node<>* spt_content = node->first_node(RegDataXMLUtils::CONTENT);
    boost::regex line_regex;
    boost::regex content_regex;
    char newline = '\n';

    if (!spt_line)
    {
      handle_invalid_ifc("Missing Line element for SessionDescription service point trigger",
                         server_name, SASEvent::INVALID_IFC_IGNORED, 0, trail);
    }

    line_regex = boost::regex(XMLUtils::get_text_or_cdata(spt_line),
                              boost::regex_constants::no_except);
    if (line_regex.status())
    {
      handle_invalid_ifc("Invalid regular expression in Line element for Session Description service point trigger",
                         server_name, SASEvent::INVALID_IFC_IGNORED, 0, trail);
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
                content_regex = boost::regex(XMLUtils::get_text_or_cdata(spt_content),
                                             boost::regex_constants::no_except);
                if (content_regex.status())
                {
                  handle_invalid_ifc("Invalid regular expression in Content element for Session Description service point trigger",
                                     server_name, SASEvent::INVALID_IFC_IGNORED, 0, trail);
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

// Check whether the message matches the specified criterion.
// Refer to CxData_Type_Rel11.xsd in 3GPP TS 29.228, and also Annexes
// B, C, and F in that document for details.
//
// @return true if the message matches, false if not.
bool Ifc::filter_matches(const SessionCase& session_case,
                         const bool is_registered,
                         const bool is_initial_registration,
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
    xml_node<>* as = _ifc->first_node(RegDataXMLUtils::APPLICATION_SERVER);
    if (as == NULL)
    {
      handle_invalid_ifc("iFC missing ApplicationServer element", server_name, 
                         SASEvent::INVALID_IFC_IGNORED, 0, trail);
    }

    server_name = XMLUtils::get_first_node_value(as, RegDataXMLUtils::SERVER_NAME);
    if (server_name.empty())
    {
      handle_invalid_ifc("iFC has no ServerName", server_name, 
                         SASEvent::INVALID_IFC_IGNORED, 0, trail);
    }

    xml_node<>* profile_part_indicator = _ifc->first_node(RegDataXMLUtils::PROFILE_PART_INDICATOR);
    if (profile_part_indicator)
    {
      bool reg = XMLUtils::parse_integer(profile_part_indicator,
                                         "ProfilePartIndicator",
                                         0,
                                         1) == 0;
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

    xml_node<>* trigger = _ifc->first_node(RegDataXMLUtils::TRIGGER_POINT);
    if (!trigger)
    {
      TRC_DEBUG("iFC has no trigger point - unconditional match");  // 3GPP TS 29.228 sB.2.2

      SAS::Event event(trail, SASEvent::IFC_MATCHED, 0);
      event.add_var_param(server_name);
      SAS::report_event(event);

      return true;
    }

    bool cnf = XMLUtils::parse_bool(trigger->first_node(RegDataXMLUtils::CONDITION_TYPE_CNF),
                                    RegDataXMLUtils::CONDITION_TYPE_CNF);

    // In CNF (conjunct-of-disjuncts, i.e., big-AND of ORs), as we
    // work through each SPT we OR it into its group(s). At the end,
    // we AND all the groups together. In DNF we do the converse.
    std::map<int32_t, bool> groups;

    std:: string spt_relation = cnf ? "OR" : "AND";
    std:: string group_relation = cnf ? "AND" : "OR";
    std:: string ifc_match = "";
    ifc_match.append(spt_relation).append(" each SPT match result to determine group result.\n");
    ifc_match.append(group_relation).append(" each group result to determine overall iFC match.\n\n");

    for (xml_node<>* spt = trigger->first_node(RegDataXMLUtils::SPT);
         spt;
         spt = spt->next_sibling(RegDataXMLUtils::SPT))
    {
      xml_node<>* neg_node = spt->first_node(RegDataXMLUtils::CONDITION_NEGATED);
      bool neg = neg_node && XMLUtils::parse_bool(neg_node, RegDataXMLUtils::CONDITION_NEGATED);
      bool spt_matched = spt_matches(session_case,
                                     is_registered,
                                     is_initial_registration,
                                     msg,
                                     spt,
                                     ifc_str,
                                     server_name,
                                     trail) != neg;

      for (xml_node<>* group_node = spt->first_node(RegDataXMLUtils::GROUP);
           group_node;
           group_node = group_node->next_sibling(RegDataXMLUtils::GROUP))
      {
        int32_t group_id = XMLUtils::parse_integer(group_node,
                                                   "Group ID",
                                                   0,
                                                   std::numeric_limits<int32_t>::max());
        if (groups.find(group_id) == groups.end())
        {
          groups[group_id] = spt_matched;
        }
        else
        {
          groups[group_id] = cnf ? (groups[group_id] || spt_matched) : 
            (groups[group_id] && spt_matched);
        }

        ifc_match.append("SPT in group ").append(std::to_string(group_id))
          .append(" is ").append(spt_matched ? "matched.\n" : "not matched.\n");
      }
    }

    bool ret = cnf;

    for (std::map<int32_t, bool>::iterator group = groups.begin();
         group != groups.end();
         ++group)
    {
      std::string group_result = group->second ? "matched" : "not matched";
      ifc_match.append("Group ").append(std::to_string(group->first))
        .append(" is ").append(group_result).append(".\n");

      ret = cnf ? (ret && group->second) : (ret || group->second);
    }

    if (ret)
    {
      TRC_DEBUG("iFC matches");
      SAS::Event event(trail, SASEvent::IFC_MATCHED, 0);
      event.add_var_param(server_name);
      event.add_var_param(ifc_match);
      SAS::report_event(event);
    }
    else
    {
      TRC_DEBUG("iFC does not match");
      SAS::Event event(trail, SASEvent::IFC_NOT_MATCHED, 0);
      event.add_var_param(server_name);
      event.add_var_param(ifc_match);
      SAS::report_event(event);
    }

    TRC_DEBUG("%s", ifc_match.c_str());
    return ret;
  }
  catch (xml_error err)
  {
    // Generic SAS event to log skipping iFC due to syntactic error in parsing
    // XML, most likely thrown by utility libraries. 
    std::string err_str = "iFC XML is syntactically invalid: " 
      + std::string(err.what());
    TRC_ERROR(err_str.c_str());
    SAS::Event event(trail, SASEvent::INVALID_XML_IGNORED, 0);
    event.add_var_param(std::string(err.what()));
    SAS::report_event(event);
    return false;
  }
  catch (ifc_error err)
  {
    // Skip processing iFC due to semantic error. Specific SAS event and
    // TRC_ERROR is logged by handle_invalid_ifc.
    return false;
  }
}

/// Return the AsInvocation corresponding to this iFC.
//
// Only safe to call if filter_matches has returned true (to validate
// the iFC).
AsInvocation Ifc::as_invocation() const
{
  xml_node<>* as = _ifc->first_node(RegDataXMLUtils::APPLICATION_SERVER);

  AsInvocation as_invocation;
  as_invocation.server_name = XMLUtils::get_first_node_value(as, RegDataXMLUtils::SERVER_NAME);

  // @@@ KSW Parse the URI and ensure it is parsable and a SIP URI
  // here. If it's invalid, ignore it (seems the only sensible
  // option).
  //
  // That means each AsInvocation would have to belong to a pool,
  // though, and that's not easy in the current architecture.

  std::string default_handling =
                          XMLUtils::get_first_node_value(as, RegDataXMLUtils::DEFAULT_HANDLING);
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
    TRC_WARNING("Badly formed DefaultHandling element in iFC (%s), defaulting to SESSION_CONTINUED",
                default_handling.c_str());
    as_invocation.default_handling = SESSION_CONTINUED;
  }
  as_invocation.service_info = XMLUtils::get_first_node_value(as, RegDataXMLUtils::SERVICE_INFO);

  xml_node<>* as_ext = as->first_node(RegDataXMLUtils::EXTENSION);
  if (as_ext)
  {
    as_invocation.include_register_request =
              XMLUtils::does_child_node_exist(as_ext, RegDataXMLUtils::INC_REG_REQ);
    as_invocation.include_register_response =
             XMLUtils::does_child_node_exist(as_ext, RegDataXMLUtils::INC_REG_RSP);
  }
  else
  {
    as_invocation.include_register_request = false;
    as_invocation.include_register_response = false;
  };

  TRC_INFO("Found (triggered) server %s", as_invocation.server_name.c_str());
  return as_invocation;
}
