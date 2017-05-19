/**
 * @file simservs.cpp The simservs XML parser
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

///
/// This uses rapidxml to parse the XDM MMtel config, per
/// http://metacom/docs/DOC-78476.
///
///----------------------------------------------------------------------------

#include <iostream>
#include <string>
#include "simservs.h"
#include "log.h"

using namespace rapidxml;

/// @class simservs
///
/// Encapsulates the service configuration of an individual subscriber.

/// Constructor: Parse the configuration from an XML string. The XML string is
/// expected to be a document containing a <simservs> element at the root.
simservs::simservs(std::string xml) : _oip_enabled(false),
                                      _oir_enabled(false),
                                      _oir_presentation_restricted(true),
                                      _cdiv_enabled(false),
                                      _cdiv_no_reply_timer(20),
                                      _inbound_cb_enabled(false),
                                      _outbound_cb_enabled(false)
{
  // Parse the XML document, saving off the passed in string first (as parsing
  // is destructive)
  xml_document<> doc;
  char* xml_str = doc.allocate_string(xml.c_str());

  try
  {
    doc.parse<parse_strip_xml_namespaces>(xml_str);
  }
  catch (parse_error err)
  {
    TRC_ERROR("Parse error in simservs document: %s\n\n%s", err.what(), xml.c_str());
    doc.clear();
  }

  // Skip into the <simservs> element
  xml_node<> *current_node = doc.first_node("simservs");
  if (!current_node)
  {
    // Failed to find the simservs node, this document is invalid.  In reality
    // this should not happen (the XDM should have policed the format of the
    // simservs document) but we're better safe than sorry.
    return;
  }

  // Walk the services, looking for the ones we're interested in
  current_node = current_node->first_node();
  while (current_node)
  {
    std::string current_node_name = current_node->name();
    TRC_DEBUG("Processing simservs node: '%s'", current_node_name.c_str());
    if (current_node_name == "originating-identity-presentation")
    {
      if (check_active(current_node))
      {
        _oip_enabled = true;
        TRC_DEBUG("OIP enabled");
      }
    }
    else if (current_node_name ==
             "originating-identity-presentation-restriction")
    {
      // OIR service is defined, check specific configuration
      if (check_active(current_node))
      {
        _oir_enabled = true;
        TRC_DEBUG("OIR enabled");

        // Check if the OIR rules are allowing or disallowing presentation
        xml_node<> *oir_def_behaviour = current_node->first_node("default-behaviour");
        if ((oir_def_behaviour != NULL) &&
            ((std::string)oir_def_behaviour->value() == "presentation-not-restricted"))
        {
          _oir_presentation_restricted = false;
        }
      }
    }
    else if (current_node_name == "communication-diversion")
    {
      // CDIV service is defined, check specific configuration
      if (check_active(current_node))
      {
        _cdiv_enabled = true;
        TRC_DEBUG("CDIV enabled");

        // Get the NoReplyTimer value, if it exists
        xml_node<>* no_reply_timer = current_node->first_node("NoReplyTimer");
        if (no_reply_timer)
        {
          _cdiv_no_reply_timer = atoi(no_reply_timer->value());
        }

        // Get the ruleset node and parse its rules.
        xml_node<>* ruleset = current_node->first_node("ruleset");
        if (ruleset)
        {
          for (xml_node<>* rule = ruleset->first_node();
               rule;
               rule = rule->next_sibling())
          {
            _cdiv_rules.push_back(simservs::CDIVRule(rule));
          }
        }
      }
    }
    else if (current_node_name == "incoming-communication-barring")
    {
      if (check_active(current_node))
      {
        _inbound_cb_enabled = true;
        TRC_DEBUG("Inbound Call Barring enabled");

        // Extract the rules in use
        xml_node<>* ruleset = current_node->first_node("ruleset");
        if (ruleset)
        {
          for (xml_node<>* rule = ruleset->first_node();
               rule;
               rule = rule->next_sibling())
          {
            _inbound_cb_rules.push_back(simservs::CBRule(rule));
          }
        }
      }
      else
      {
        TRC_DEBUG("Inbound Call Barring enabled");
      }
    }
    else if (current_node_name == "outgoing-communication-barring")
    {
      if (check_active(current_node))
      {
        _outbound_cb_enabled = true;
        TRC_DEBUG("Outbound Call Barring enabled");

        // Extract the rules in use
        xml_node<>* ruleset = current_node->first_node("ruleset");
        if (ruleset)
        {
          for (xml_node<>* rule = ruleset->first_node();
               rule;
               rule = rule->next_sibling())
          {
            _outbound_cb_rules.push_back(simservs::CBRule(rule));
          }
        }
      }
      else
      {
        TRC_DEBUG("Outbound Call Barring disabled");
      }
    }

    // Check the next service node
    current_node = current_node->next_sibling();
  }
}

/// Constructor: Build configuration representing call diversion to the
/// specified target for _any_ of the specified conditions.
simservs::simservs(const std::string forward_target,
                   unsigned int conditions,
                   unsigned int no_reply_timer) :
                   _oip_enabled(false),
                   _oir_enabled(false),
                   _oir_presentation_restricted(true),
                   _cdiv_enabled(true),
                   _cdiv_no_reply_timer(no_reply_timer),
                   _inbound_cb_enabled(false),
                   _outbound_cb_enabled(false)
{
  if (conditions == 0)
  {
    _cdiv_rules.push_back(simservs::CDIVRule(forward_target, 0));
  }
  else
  {
    // The conditions mask we're provided is such that any condition should
    // invoke diversion.  Rules are only invoked if all conditions are true,
    // so we need to translate this into multiple rules.
    while (conditions != 0)
    {
      // Extract the next least-significant bit from conditions.
      // (A & -A gives the least-significant bit.)
      int condition = (conditions & (-conditions));
      conditions = conditions & ~condition;
      _cdiv_rules.push_back(simservs::CDIVRule(forward_target, condition));
    }
  }
}

simservs::~simservs()
{
}

/// Is OIP (originating identity presentation) enabled?
bool simservs::oip_enabled()
{
  return _oip_enabled;
}

/// Is OIR (originating identity presentation restriction) enabled?
bool simservs::oir_enabled()
{
  return _oir_enabled;
}

/// Is originating identity presentation restricted?  Only valid if oir_enabled().
bool simservs::oir_presentation_restricted()
{
  return _oir_presentation_restricted;
}

/// Is call diversion enabled?
bool simservs::cdiv_enabled() const
{
  return _cdiv_enabled;
}

/// What is the value of the call diversion no-reply timer (in seconds)?
unsigned int simservs::cdiv_no_reply_timer() const
{
  return _cdiv_no_reply_timer;
}

/// What are the call-diversion rules (in order)?
const std::vector<simservs::CDIVRule>* simservs::cdiv_rules() const
{
  return &_cdiv_rules;
}

bool simservs::inbound_cb_enabled() const
{
  return _inbound_cb_enabled;
}

const std::vector<simservs::CBRule>* simservs::inbound_cb_rules() const
{
  return &_inbound_cb_rules;
}

bool simservs::outbound_cb_enabled() const
{
  return _outbound_cb_enabled;
}

const std::vector<simservs::CBRule>* simservs::outbound_cb_rules() const
{
  return &_outbound_cb_rules;
}

/// Helper: Given a service node, is it active?
bool simservs::check_active(xml_node<> *service)
{
  bool result = true;
  xml_attribute<>* active_attr = service->first_attribute("active");

  if (active_attr && ((std::string)active_attr->value() != "true"))
  {
    result = false;
  }

  return result;
}

/// @class simservs::Rule
///
/// Abstract base class encapsulating the condition (i.e., diversion-reason)
/// that triggers the rule.  Format is RFC4745, but only specific conditions
/// (a subset of MMtel) are supported.  See
/// http://metacom/community/teams/cto/blog/2012/02/21/mmtel-and-the-common-policy-ruleset

/// Constructor: create a rule from an XML node.
simservs::Rule::Rule(xml_node<>* rule) : _conditions(0)
{
  // Get the ruleset node and parse its rules.
  xml_node<>* conditions = rule->first_node("conditions");
  if (conditions != NULL)
  {
    for (xml_node<>* condition = conditions->first_node();
         condition != NULL;
         condition = condition->next_sibling())
    {
      std::string condition_name = condition->name();
      TRC_DEBUG("Processing condition: %s", condition_name.c_str());
      if (condition_name == "busy")
      {
        TRC_DEBUG("Adding condition: Busy");
        _conditions |= CONDITION_BUSY;
      }
      else if (condition_name == "not-registered")
      {
        TRC_DEBUG("Adding condition: Not Registered");
        _conditions |= CONDITION_NOT_REGISTERED;
      }
      else if (condition_name == "no-answer")
      {
        TRC_DEBUG("Adding condition: No Answer");
        _conditions |= CONDITION_NO_ANSWER;
      }
      else if (condition_name == "not-reachable")
      {
        TRC_DEBUG("Adding condition: Not Reachable");
        _conditions |= CONDITION_NOT_REACHABLE;
      }
      else if (condition_name == "media")
      {
        std::string media_type = (std::string)condition->value();
        if (media_type == "audio")
        {
          TRC_DEBUG("Adding condition: Audio");
          _conditions |= CONDITION_MEDIA_AUDIO;
        }
        else if (media_type == "video")
        {
          TRC_DEBUG("Adding condition: Video");
          _conditions |= CONDITION_MEDIA_VIDEO;
        }
        else
        {
          TRC_WARNING("Unsupported conditional media type %s", media_type.c_str());
        }
      }
      else if (condition_name == "roaming")
      {
        TRC_DEBUG("Adding condition: Roaming");
        _conditions |= CONDITION_ROAMING;
      }
      else if (condition_name == "international")
      {
        TRC_DEBUG("Adding condition: International");
        _conditions |= CONDITION_INTERNATIONAL;
      }
      else if (condition_name == "international-exHC")
      {
        TRC_DEBUG("Adding condition: International-exHC");
        _conditions |= CONDITION_INTERNATIONAL_EXHC;
      }
      else
      {
        TRC_WARNING("Unsupported conditional %s", condition_name.c_str());
      }
    }
  }
}

simservs::Rule::~Rule()
{
}

/// What are the conditions of this rule?  Result is the OR of 0 or more
/// CONDITION_* constants.
unsigned int simservs::Rule::conditions() const
{
  return _conditions;
}

/// @class simservs::CDIVRule
///
/// A call diversion rule.

/// Constructor: Parse the rule from an XML node.
simservs::CDIVRule::CDIVRule(xml_node<>* rule) : simservs::Rule(rule)
{
  // Get the target.  It should always exist, but we'll ignore it later if it
  // doesn't.
  xml_node<>* actions = rule->first_node("actions");
  if (actions != NULL)
  {
    xml_node<>* forward_to = actions->first_node("forward-to");
    if (forward_to != NULL)
    {
      xml_node<>* target = forward_to->first_node("target");
      if (target != NULL)
      {
        _forward_target = (std::string)target->value();
      }
    }
  }
}

simservs::CDIVRule::~CDIVRule()
{
}

/// What is the target of this rule? Empty string if none configured, else the
/// target (in what format?)
std::string simservs::CDIVRule::forward_target() const
{
  return _forward_target;
}

simservs::CBRule::CBRule(xml_node<>* rule) : simservs::Rule(rule), _allow_call(false)
{
  // Parse the action if present.  If not present, then assume the call is 
  // blocked if the rule applies.  @TODO - check that this is correct default
  // behaviour 
  xml_node<>* actions = rule->first_node("actions");
  if (actions != NULL)
  {
    xml_node<>* allow = actions->first_node("allow");
    if ((allow != NULL) && ((std::string)allow->value() == "true"))
    {
      _allow_call = true;
    }
  }
}

simservs::CBRule::~CBRule()
{
}

bool simservs::CBRule::allow_call() const
{
  return _allow_call;
}
