/**
 * @file mmtel.cpp MMTel call service implementation
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <string>
#include <vector>
#include <boost/algorithm/string/predicate.hpp>

#include "log.h"
#include "stack.h"
#include "pjutils.h"
#include "pjmedia.h"
#include "mmtelsasevent.h"
#include "mmtel.h"
#include "constants.h"
#include "custom_headers.h"

using namespace rapidxml;

// Used in logging

#define PRIVACY_H_ID       0x00000001
#define PRIVACY_H_HEADER   0x00000002
#define PRIVACY_H_SESSION  0x00000004
#define PRIVACY_H_USER     0x00000008
#define PRIVACY_H_NONE     0x00000010
#define PRIVACY_H_CRITICAL 0x00000020


/// Get a new MmtelTsx from the Mmtel AS.
AppServerTsx* Mmtel::get_app_tsx(SproutletHelper* helper,
                                 pjsip_msg* req,
                                 pjsip_sip_uri*& next_hop,
                                 pj_pool_t* pool,
                                 SAS::TrailId trail)
{
  MmtelTsx* mmtel_tsx = NULL;

  // Find the P-Served-User header, look up simservs and construct an MmtelTsx.
  pjsip_routing_hdr* psu_hdr = (pjsip_routing_hdr*)
                     pjsip_msg_find_hdr_by_name(req, &STR_P_SERVED_USER, NULL);
  if (psu_hdr != NULL)
  {
    TRC_DEBUG("Found P-Served-User header: %s",
              PJUtils::hdr_to_string(psu_hdr).c_str());
    pjsip_uri* uri = (pjsip_uri*)pjsip_uri_get_uri(&psu_hdr->name_addr);
    std::string served_user = PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR, uri);

    simservs* user_services = get_user_services(served_user, trail);
    mmtel_tsx = new MmtelTsx(req, user_services, trail);
  }
  else
  {
    TRC_DEBUG("Failed to find P-Served-User header - not invoking MMTEL");
  }

  return mmtel_tsx;
}

// Get the user services (simservs) configuration if relevant and present.
//
// @returns The simservs object if it is relevant and present.  If there is
// no simservs configuration for the user, returns a default simservs object
// with all services disabled.
simservs* Mmtel::get_user_services(std::string public_id, SAS::TrailId trail)
{
  // Fetch the user's simservs configuration from the XDMS
  TRC_DEBUG("Fetching simservs configuration for %s", public_id.c_str());
  {
    SAS::Event event(trail, SASEvent::RETRIEVING_SIMSERVS, 0);
    event.add_var_param(public_id);
    SAS::report_event(event);
  }
  std::string simservs_xml;
  if (!_xdmc->get_simservs(public_id, simservs_xml, "", trail))
  {
    TRC_DEBUG("Failed to fetch simservs configuration for %s, no MMTel services enabled", public_id.c_str());
    SAS::Event event(trail, SASEvent::FAILED_RETRIEVE_SIMSERVS, 0);
    SAS::report_event(event);
    return new simservs("");
  }

  // Parse the retrieved XDMS information
  simservs *user_services = new simservs(simservs_xml);

  return user_services;
}

/// Constructor.
CallDiversionAS::CallDiversionAS(const std::string& service_name) :
  AppServer(service_name),
  _cdiv_total_stat("cdiv_total", stack_data.stats_aggregator),
  _cdiv_unconditional_stat("cdiv_unconditional", stack_data.stats_aggregator),
  _cdiv_busy_stat("cdiv_busy", stack_data.stats_aggregator),
  _cdiv_not_registered_stat("cdiv_not_registered", stack_data.stats_aggregator),
  _cdiv_no_answer_stat("cdiv_no_answer", stack_data.stats_aggregator),
  _cdiv_not_reachable_stat("cdiv_not_reachable", stack_data.stats_aggregator) {};

/// Destructor.
CallDiversionAS::~CallDiversionAS() {}

/// Called on diversion.  Increments statistics.
void CallDiversionAS::cdiv_callback(std::string target, unsigned int conditions)
{
  _cdiv_total_stat.increment();
  if (conditions == 0)
  {
    _cdiv_unconditional_stat.increment();
  }
  if (conditions & simservs::Rule::CONDITION_BUSY)
  {
    _cdiv_busy_stat.increment();
  }
  if (conditions & simservs::Rule::CONDITION_NOT_REGISTERED)
  {
    _cdiv_not_registered_stat.increment();
  }
  if (conditions & simservs::Rule::CONDITION_NO_ANSWER)
  {
    _cdiv_no_answer_stat.increment();
  }
  if (conditions & simservs::Rule::CONDITION_NOT_REACHABLE)
  {
    _cdiv_not_reachable_stat.increment();
  }
}

/// Get a new MmtelTsx from the CallDiversionAS.
AppServerTsx* CallDiversionAS::get_app_tsx(SproutletHelper* helper,
                                           pjsip_msg* req,
                                           pjsip_sip_uri*& next_hop,
                                           pj_pool_t* pool,
                                           SAS::TrailId trail)
{
  MmtelTsx* mmtel_tsx = NULL;

  // Find the Route header, parse the simservs parameters out and construct an MmtelTsx.
  pjsip_route_hdr* route_hdr = (pjsip_route_hdr*)
                                      pjsip_msg_find_hdr(req, PJSIP_H_ROUTE, NULL);
  if (route_hdr != NULL)
  {
    TRC_DEBUG("Found Route header: %s",
              PJUtils::hdr_to_string(route_hdr).c_str());
    pjsip_sip_uri* uri = (pjsip_sip_uri*)pjsip_uri_get_uri(&route_hdr->name_addr);

    {
      SAS::Event event(trail, SASEvent::CALL_DIVERSION_INVOKED, 0);
      event.add_var_param(PJUtils::uri_to_string(PJSIP_URI_IN_CONTACT_HDR, (pjsip_uri*)uri));
      SAS::report_event(event);
    }

    // Get the target parameter - it is required.
    pjsip_param* target_param = pjsip_param_find(&uri->other_param, &STR_TARGET);
    if (target_param != NULL)
    {
      std::string target = PJUtils::pj_str_to_string(&target_param->value);
      TRC_DEBUG("Found target parameter: %s", target.c_str());

      // Now parse the conditions.
      unsigned int conditions = 0;
      pjsip_param* conditions_param = pjsip_param_find(&uri->other_param, &STR_CONDITIONS);
      std::string conditions_str = "unconditional";
      if (conditions_param != NULL)
      {
        conditions_str = PJUtils::pj_str_to_string(&conditions_param->value);
        TRC_DEBUG("Found conditions parameter: %s", conditions_str.c_str());

        // Split the conditions at plus, and then try to match them, ignoring unknown ones.
        std::vector<std::string> conditions_list;
        Utils::split_string(conditions_str, '+', conditions_list);
        for (std::vector<std::string>::iterator it = conditions_list.begin();
             it != conditions_list.end();
             ++it)
        {
          if (*it == "busy")
          {
            conditions |= simservs::Rule::CONDITION_BUSY;
          }
          else if (*it == "not-registered")
          {
            conditions |= simservs::Rule::CONDITION_NOT_REGISTERED;
          }
          else if (*it == "no-answer")
          {
            conditions |= simservs::Rule::CONDITION_NO_ANSWER;
          }
          else if (*it == "not-reachable")
          {
            conditions |= simservs::Rule::CONDITION_NOT_REACHABLE;
          }
          else
          {
            TRC_DEBUG("Unrecognized condition: %s", it->c_str());
            SAS::Event event(trail, SASEvent::UNRECOGNIZED_CONDITION, 0);
            event.add_var_param(*it);
            SAS::report_event(event);
          }
        }
      }

      unsigned int no_reply_timer = 20;
      pjsip_param* no_reply_timer_param = pjsip_param_find(&uri->other_param, &STR_NO_REPLY_TIMER);
      if (no_reply_timer_param != NULL)
      {
        // Construct a std::string from the parameter.  This ensures that the string is
        // NUL-terminated.  Then parse it as an integer.
        std::string no_reply_timer_str = PJUtils::pj_str_to_string(&no_reply_timer_param->value);
        TRC_DEBUG("Found no-reply-timer parameter: %s", no_reply_timer_str.c_str());
        errno = 0;
        unsigned long int_value = strtoul(no_reply_timer_str.c_str(), NULL, 10);
        if (errno == 0)
        {
          no_reply_timer = (unsigned int)int_value;
        }
        else
        {
          TRC_DEBUG("Failed to parse no-reply-timer as integer - ignoring");
          SAS::Event event(trail, SASEvent::UNPARSEABLE_NO_REPLY_TIMER, 0);
          event.add_var_param(no_reply_timer_str);
          SAS::report_event(event);
        }
      }

      simservs* user_services = new simservs(target, conditions, no_reply_timer);
      mmtel_tsx = new MmtelTsx(req, user_services, trail, this);

      {
        SAS::Event event(trail, SASEvent::CALL_DIVERSION_ENABLED, 0);
        event.add_var_param(target);
        event.add_var_param(conditions_str);
        event.add_static_param(no_reply_timer);
        SAS::report_event(event);
      }
    }
    else
    {
      TRC_DEBUG("Failed to find target parameter - not invoking MMTEL");
      SAS::Event event(trail, SASEvent::NO_TARGET_PARAM, 0);
      SAS::report_event(event);
    }
  }
  else
  {
    TRC_DEBUG("Failed to find Route header - not invoking MMTEL");
  }

  return mmtel_tsx;
}

/// Constructor for the MmtelTsx.
MmtelTsx::MmtelTsx(pjsip_msg* req,
                   simservs* user_services,
                   SAS::TrailId trail,
                   CDivCallback* cdiv_callback) :
  AppServerTsx(),
  _user_services(user_services),
  _cdiv_callback(cdiv_callback),
  _no_reply_timer(0),
  _diverted(false)
{
  _country_code = "1";

  pjsip_routing_hdr* psu_hdr = (pjsip_routing_hdr*)
                     pjsip_msg_find_hdr_by_name(req, &STR_P_SERVED_USER, NULL);
  if (psu_hdr != NULL)
  {
    // Inspect the `sescase` parameter to see if it indicates origination.
    TRC_DEBUG("Found P-Served-User header: %s",
              PJUtils::hdr_to_string(psu_hdr).c_str());
    pjsip_param* sescase = pjsip_param_find(&psu_hdr->other_param, &STR_SESCASE);
    bool sescase_orig = false;
    bool sescase_cdiv = false;

    if (sescase != NULL)
    {
      sescase_orig = (pj_stricmp(&sescase->value, &STR_ORIG) == 0);
      sescase_cdiv = (pj_stricmp(&sescase->value, &STR_ORIG_CDIV) == 0);
    }

    // Inspect the `orig-cdiv` parameter.  This takes no value, but its
    // presence indicates originating services applied for call diversion.
    pjsip_param* orig_cdiv_param = pjsip_param_find(&psu_hdr->other_param,
                                                    &STR_ORIG_CDIV);

    if (sescase_orig || sescase_cdiv || (orig_cdiv_param != NULL))
    {
      _originating = true;
    }
    else
    {
      _originating = false;
    }
  }
  else
  {
    TRC_DEBUG("Failed to find P-Served-User header");
    //@TODO
  }

  _method = req->line.req.method.id;

  if (_originating)
  {
    if ((_user_services != NULL) &&
        ((_user_services->oir_enabled()) ||
         (_user_services->outbound_cb_enabled())))
    {
      SAS::Event event(trail, SASEvent::ORIGINATING_SERVICES_ENABLED, 0);
      event.add_static_param(_user_services->oir_enabled());
      event.add_static_param(_user_services->outbound_cb_enabled());
      SAS::report_event(event);
    }
    else
    {
      SAS::Event event(trail, SASEvent::ORIGINATING_SERVICES_DISABLED, 0);
      SAS::report_event(event);
    }
  }
  else
  {
    _ringing = false;
    // Determine the media type conditions, in case they're needed later.
    if (req->line.req.method.id == PJSIP_INVITE_METHOD)
    {
      _media_conditions = get_media_type_conditions(req);
    }
    else
    {
      _media_conditions = 0;
    }

    if ((_user_services != NULL) &&
        ((_user_services->cdiv_enabled()) ||
         (_user_services->inbound_cb_enabled())))
    {
      SAS::Event event(trail, SASEvent::TERMINATING_SERVICES_ENABLED, 0);
      event.add_static_param(_user_services->cdiv_enabled());
      event.add_static_param(_user_services->inbound_cb_enabled());
      SAS::report_event(event);
    }
    else
    {
      SAS::Event event(trail, SASEvent::TERMINATING_SERVICES_DISABLED, 0);
      SAS::report_event(event);
    }
  }
}

/// Destructor for the MmtelTsx.
MmtelTsx::~MmtelTsx()
{
  if (_no_reply_timer != 0)
  {
    cancel_timer(_no_reply_timer);
    _no_reply_timer = 0;
  }

  if (_user_services != NULL)
  {
    delete _user_services;
  }
}

// Apply Mmtel processing on initial invite.
void MmtelTsx::on_initial_request(pjsip_msg* req)
{
  pjsip_status_code rc = PJSIP_SC_OK;
  pj_pool_t* pool = get_pool(req);

  if (_originating)
  {
    rc = apply_ob_privacy(req, pool);

    if (rc == PJSIP_SC_OK)
    {
      rc = apply_ob_call_barring(req);
    }
  }
  else
  {
    rc = apply_ib_privacy(req, pool);

    if (rc == PJSIP_SC_OK)
    {
      rc = apply_cdiv_on_req(req, _media_conditions, PJSIP_SC_TEMPORARILY_UNAVAILABLE);
    }

    if (rc == PJSIP_SC_OK)
    {
      rc = apply_ib_call_barring(req);
    }
  }

  if (rc <= PJSIP_SC_OK)
  {
    send_request(req);
  }
  else
  {
    pjsip_msg* rsp = create_response(req, rc);
    free_msg(req);
    send_response(rsp);
  }
}

// Apply terminating Mmtel processing on receiving a response.
void MmtelTsx::on_response(pjsip_msg* rsp, int fork_id)
{
  // We only do processing on a response if this is the terminating side.
  if (!_originating)
  {
    pjsip_status_code code = (pjsip_status_code)rsp->line.status.code;

    if (code < PJSIP_SC_OK)
    {
      // Forward provisional response.
      TRC_DEBUG("Forward provisional response");
      send_response(rsp);

      if (code == PJSIP_SC_RINGING)
      {
        // Phone is ringing, so consider starting the no-reply timer.
        _ringing = true;

        if ((_no_reply_timer == 0) &&
            (_user_services != NULL) &&
            (_user_services->cdiv_enabled()) &&
            (!_diverted))
        {
          // Now spin through the rules looking for one that requires no answer but
          // is also satisfied by our media conditions.
          const std::vector<simservs::CDIVRule>* cdiv_rules = _user_services->cdiv_rules();
          for (std::vector<simservs::CDIVRule>::const_iterator rule = cdiv_rules->begin();
               rule != cdiv_rules->end();
               rule++)
          {
            TRC_DEBUG("Considering rule - conditions 0x%x, target %s",
                      rule->conditions(), rule->forward_target().c_str());
            if ((rule->conditions() & simservs::Rule::CONDITION_NO_ANSWER) &&
                ((rule->conditions() & ~(_media_conditions | simservs::Rule::CONDITION_NO_ANSWER)) == 0))
            {
              // We found a suitable rule.  Start the no-reply timer.
              bool status = schedule_timer(NULL, _no_reply_timer, _user_services->cdiv_no_reply_timer() * 1000);
              if (!status)
              {
                // Log this failure, but don't fail the call - there's no point.
                TRC_WARNING("Failed to set no-reply timer - status %d", status);
              }
              else
              {
                _late_redirect_fork_id = fork_id;
              }
              break;
            }
          }
        }
      }
    }
    else
    {
      // We've got a final response, so there's no point in running the no-reply timer any longer.
      if (_no_reply_timer != 0)
      {
        cancel_timer(_no_reply_timer);
        _no_reply_timer = 0;
      }

      if ((code == PJSIP_SC_OK) ||
          (!apply_cdiv_on_rsp(rsp, condition_from_status(code) | _media_conditions, code)))
      {
        // The request has not been redirected, so forward the response.
        TRC_DEBUG("Request has not been redirected, so forward response upstream");
        send_response(rsp);
      }
      else
      {
        // The request has been redirected, so discard the response.
        free_msg(rsp);
      }
    }
  }
  else
  {
    send_response(rsp);
  }
}

// Parse a privacy header into a bitfield.
//
// @returns Bitfield of privacy fields that were in the header.
int MmtelTsx::parse_privacy_headers(pjsip_generic_array_hdr *header_array)
{
  int rc = 0;

  TRC_DEBUG("Parsing Privacy: header");

  for (unsigned int ii = 0; ii < header_array->count; ii++)
  {
    pj_str_t *field_str = &header_array->values[ii];
    if (!pj_stricmp2(field_str, "id"))
    {
      TRC_DEBUG("'id' privacy specified");
      rc |= PRIVACY_H_ID;
    }
    else if (!pj_stricmp2(field_str, "header"))
    {
      TRC_DEBUG("'header; privacy specified");
      rc |= PRIVACY_H_HEADER;
    }
    else if (!pj_stricmp2(field_str, "session"))
    {
      TRC_DEBUG("'session' privacy specified");
      rc |= PRIVACY_H_SESSION;
    }
    else if (!pj_stricmp2(field_str, "user"))
    {
      TRC_DEBUG("'user' privacy specified");
      rc |= PRIVACY_H_USER;
    }
    else if (!pj_stricmp2(field_str, "none"))
    {
      TRC_DEBUG("'none' privacy specified");
      rc |= PRIVACY_H_NONE;
    }
    else if (!pj_stricmp2(field_str, "critical"))
    {
      TRC_DEBUG("'critical' privacy specified");
      rc |= PRIVACY_H_CRITICAL;
    }
  }

  return rc;
}

// Create a privacy header from a bitfield of privacy fields.
//
// @returns Nothing.
void MmtelTsx::build_privacy_header(pjsip_msg* req, pj_pool_t* pool, int privacy_fields)
{
  static const pj_str_t privacy_hdr_name = pj_str("Privacy");

  if (!privacy_fields)
  {
    return;
  }

  pjsip_generic_array_hdr *new_header = pjsip_privacy_hdr_create(pool, &privacy_hdr_name);

  if (privacy_fields & PRIVACY_H_ID)
  {
    TRC_DEBUG("Adding 'id' privacy field");
    pj_strdup2(pool,
               &new_header->values[new_header->count],
               "id");
    new_header->count++;
  }

  if (privacy_fields & PRIVACY_H_HEADER)
  {
    TRC_DEBUG("Adding 'header' privacy field");
    pj_strdup2(pool,
               &new_header->values[new_header->count],
               "header");
    new_header->count++;
  }

  if (privacy_fields & PRIVACY_H_SESSION)
  {
    TRC_DEBUG("Adding 'session' privacy field");
    pj_strdup2(pool,
               &new_header->values[new_header->count],
               "session");
    new_header->count++;
  }

  if (privacy_fields & PRIVACY_H_USER)
  {
    TRC_DEBUG("Adding 'user' privacy field");
    pj_strdup2(pool,
               &new_header->values[new_header->count],
               "user");
    new_header->count++;
  }

  if (privacy_fields & PRIVACY_H_NONE)
  {
    TRC_DEBUG("Adding 'none' privacy field");
    pj_strdup2(pool,
               &new_header->values[new_header->count],
               "none");
    new_header->count++;
  }

  if (privacy_fields & PRIVACY_H_CRITICAL)
  {
    TRC_DEBUG("Adding 'critical' privacy field");
    pj_strdup2(pool,
               &new_header->values[new_header->count],
               "critical");
    new_header->count++;
  }

  pjsip_msg_add_hdr(req, (pjsip_hdr *)new_header);
}

// Gets the media types specified in the SDP on the message.
//
// @returns Conditions corresponding to the media types.
unsigned int MmtelTsx::get_media_type_conditions(pjsip_msg *msg)
{
  unsigned int media_type_conditions = 0;

  std::set<pjmedia_type> media_types = PJUtils::get_media_types(msg);

  for(pjmedia_type media_type : media_types)
  {
    switch (media_type)
    {
      case PJMEDIA_TYPE_AUDIO:
        media_type_conditions |= simservs::Rule::CONDITION_MEDIA_AUDIO;
        break;

      case PJMEDIA_TYPE_VIDEO:
        media_type_conditions |= simservs::Rule::CONDITION_MEDIA_VIDEO;
        break;

      default:
        break;
    }
  }

  return media_type_conditions;
}

// Apply call barring, using the supplied rules (as defined in 3GPP TS 24.611 v11.2.0)
//
// @returns true if the call may still proceed, false otherwise.
pjsip_status_code MmtelTsx::apply_call_barring(const std::vector<simservs::CBRule>* ruleset,
                                               pjsip_msg* req)
{
  // If one of the matching rules evaluates to allow=true then the resulting value shall be allow=true
  // and the call continues normally, otherwise the result shall be allow=false and the call will be barred.
  //   -- 3GPP TS 24.611 v11.2.0
  bool rule_matched = false;
  pjsip_status_code rc = PJSIP_SC_DECLINE;
  for (std::vector<simservs::CBRule>::const_iterator rule = ruleset->begin();
       rule != ruleset->end();
       rule++)
  {
    if (check_cb_rule(*rule, req))
    {
      rule_matched = true;
      if (rule->allow_call())
      {
        TRC_DEBUG("Call barring rule allows call to continue");
        rc = PJSIP_SC_OK;
        break;
      }
    }
  }

  // If there are no matching rules then the result shall be allow=true
  //   -- 3GPP TS 24.611 v11.2.0
  if (!rule_matched)
  {
    TRC_DEBUG("No call barring rules matched, call continues");
    rc = PJSIP_SC_OK;
  }

  // When the AS providing the OCB service rejects a communication, the AS shall send an indication to the
  // calling user by sending a 603 (Decline) response.
  //   -- 3GPP TS 25.611 v11.2.0
  if (rc != PJSIP_SC_OK)
  {
    TRC_DEBUG("Call rejected by call barring");
  }

  return rc;
}

// Determine if an arbitary rule's conditions apply to a call.
//
// @return true if the rule should be applied (i.e. the conditions hold)
bool MmtelTsx::check_cb_rule(const simservs::CBRule& rule, pjsip_msg* req)
{
  bool rule_matches = true;
  int conditions = rule.conditions();
  TRC_DEBUG("Testing call against conditions (0x%X)", conditions);

  if (conditions & simservs::Rule::CONDITION_ROAMING)
  {
    // Clearwater doesn't support roaming calls yet, this never applies
    TRC_DEBUG("Roaming condition fails");
    rule_matches = false;
  }
  if (conditions & simservs::Rule::CONDITION_INTERNATIONAL)
  {
    // Detect international calls, this requires the request URI to be a TEL URI or a SIP URI with a 'phone'
    // parameter set.  Then we need to look at the country code to determine if we're going international.
    std::string dialed_number;
    pjsip_uri *uri = req->line.req.uri;
    if (PJSIP_URI_SCHEME_IS_TEL(uri))
    {
      TRC_DEBUG("TEL: Number dialed");
      pj_str_t* tel_number = &((pjsip_tel_uri *)uri)->number;
      dialed_number.assign(pj_strbuf(tel_number), pj_strlen(tel_number));
    }
    else if (PJSIP_URI_SCHEME_IS_SIP(uri))
    {
      TRC_DEBUG("SIP/SIPS: Number dialed");
      pjsip_sip_uri *sip_uri = (pjsip_sip_uri *)uri;

      // According to 3GPP TS 24.611 v11.2.0, only SIP UIRs with user=phone may be treated as international
      // unfortunately neither X-Lite nor Accession ever set this parameter.  Therefore we will look at any SIP username
      // as a potential international number.
      //
      // To restore the specced behaviour, uncomment the below:
      //
      // if (pj_stricmp2(&sip_uri->user_param, "phone") == 0)
      {
        pj_str_t *sip_number = &sip_uri->user;
        dialed_number.assign(pj_strbuf(sip_number), pj_strlen(sip_number));
      }
    }

    // If we have no number or it starts with our country code or doesn't start with '+', '00' or '011' it's
    // non-international.
    if (dialed_number == "")
    {
      TRC_DEBUG("SIP username requested, international number detection not possible");
      rule_matches = false;
    }
    else if (!(boost::starts_with(dialed_number, "+") ||
               boost::starts_with(dialed_number, "00") ||
               boost::starts_with(dialed_number, "011")) ||
             boost::starts_with(dialed_number, "+" + _country_code) ||
             boost::starts_with(dialed_number, "00" + _country_code) ||
             boost::starts_with(dialed_number, "011" + _country_code))
    {
      TRC_DEBUG("International condition fails, dialed number is '%s'", dialed_number.c_str());
      rule_matches = false;
    }
  }
  if (conditions & simservs::Rule::CONDITION_INTERNATIONAL_EXHC)
  {
    // Clearwater does not support roaming calls yet, this never applies
    TRC_DEBUG("International Excluding Home Country rule fails");
    rule_matches = false;
  }

  return rule_matches;
}


// Applies privacy services as an originating AS.
//
// @returns true if the call should proceed, false otherwise
pjsip_status_code MmtelTsx::apply_ob_privacy(pjsip_msg* req, pj_pool_t* pool)
{
  static const pj_str_t privacy_hdr_name = pj_str("Privacy");

  pjsip_generic_array_hdr *privacy_hdr_array = NULL;

  if ((_user_services == NULL) ||
      (!_user_services->oir_enabled()))
  {
    TRC_DEBUG("Originating Identification Presentation Restriction disabled");
  }
  else
  {
    TRC_DEBUG("Originating Identification Presentation Restriction enabled");

    // Extract the privacy header
    privacy_hdr_array = (pjsip_generic_array_hdr *)pjsip_msg_find_hdr_by_name(req, &privacy_hdr_name, NULL);

    int privacy_hdrs = 0;
    if (privacy_hdr_array)
    {
      // Extract the privacy headers that currently exist, unrecognized headers will be stripped out
      privacy_hdrs = MmtelTsx::parse_privacy_headers(privacy_hdr_array);
      pj_list_erase(privacy_hdr_array);
    }

    if (_user_services->oir_presentation_restricted())
    {
      // For an originating user that subscribes to the OIR service in "temporary mode" with default "restricted", if the request
      // does not include a Privacy header field, or the request includes a Privacy header field that is not set to "none", the AS
      // shall insert a Privacy header field set to "id" or "header" based on the subscription option. Additionally based on
      // operator policy, the AS shall either modify the From header field to remove the identification information, or add a
      // Privacy header field set to "user".
      // --  3GPP TS 24.607 v11.0.0
      TRC_DEBUG("Identity presentation is restricted by default");
      if (!(privacy_hdrs & PRIVACY_H_NONE))
      {
        privacy_hdrs |= PRIVACY_H_USER;
        privacy_hdrs |= PRIVACY_H_ID;
        privacy_hdrs |= PRIVACY_H_HEADER;
      }
    }
    else
    {
      // For an originating user that subscribes to the OIR service in "temporary mode" with default "not restricted", if the
      // request includes a Privacy header field is set to "id" or "header", based on operator policy, the AS shall either, may
      // modify the From header field to remove the identification information or add a Privacy header field set to "user".
      //   -- 3GPP TS 24.607 v11.0.0
      TRC_DEBUG("Identity presentation is not restricted by default");
      if ((privacy_hdrs & PRIVACY_H_ID) || (privacy_hdrs & PRIVACY_H_HEADER))
      {
        privacy_hdrs |= PRIVACY_H_USER;
      }
    }

    // Construct the new privacy header
    MmtelTsx::build_privacy_header(req, pool, privacy_hdrs);
  }

  return PJSIP_SC_OK;
}

// Apply originating call barring (as defined in 3GPP TS 24.611 v11.2.0)
//
// @returns true if the call may still proceed, false otherwise.
pjsip_status_code MmtelTsx::apply_ob_call_barring(pjsip_msg* req)
{
  if (!_user_services->outbound_cb_enabled())
  {
    TRC_DEBUG("Outbound call barring disabled");
    return PJSIP_SC_OK;
  }

  return apply_call_barring(_user_services->outbound_cb_rules(), req);
}

// Apply privacy services as a terminating AS.
//
// @returns true if the call may proceed, false otherwise.
pjsip_status_code MmtelTsx::apply_ib_privacy(pjsip_msg* req, pj_pool_t* pool)
{
  static const pj_str_t privacy_hdr_name = pj_str("Privacy");
  static const pj_str_t call_info_hdr_name = pj_str("Call-Info");
  static const pj_str_t server_hdr_name = pj_str("Server");
  static const pj_str_t organization_hdr_name = pj_str("Organization");
  static const pj_str_t subject_hdr_name = pj_str("Subject");
  static const pj_str_t user_agent_hdr_name = pj_str("User-Agent");
  static const pj_str_t reply_to_hdr_name = pj_str("Reply-To");
  static const pj_str_t in_reply_to_hdr_name = pj_str("In-Reply-To");
  static const pj_str_t p_asserted_identity_hdr_name = pj_str("P-Asserted-Identity");
  pjsip_generic_array_hdr *privacy_hdr_array = NULL;

  int privacy_hdrs = 0;
  privacy_hdr_array = (pjsip_generic_array_hdr *)pjsip_msg_find_hdr_by_name(req, &privacy_hdr_name, NULL);
  if (privacy_hdr_array)
  {
    privacy_hdrs = MmtelTsx::parse_privacy_headers(privacy_hdr_array);
    pj_list_erase(privacy_hdr_array);
  }

  if (privacy_hdrs & PRIVACY_H_NONE)
  {
    TRC_DEBUG("Privacy 'none' requested, no prvacy applied");
    MmtelTsx::build_privacy_header(req, pool, privacy_hdrs);
    return PJSIP_SC_OK;
  }

  if (privacy_hdrs & PRIVACY_H_HEADER)
  {
    // If the request includes the Privacy header field set to "header" the AS shall:
    // a) anonymize the contents of all headers containing private information in accordance with IETF RFC 3323 [6] and
    // IETF RFC 3325 [7]; and
    // b) add a Privacy header field with the priv-value set to "id" if not already present in the request
    // -- 3GPP TS 24.607 v11.0.0

    TRC_DEBUG("Applying 'header' privacy");

    // a) Anonymize headers - Since we will be leaving the call path, we cannot perform Via/RR/Contact-stripping (as we can't replace
    // the headers later.  We can remove extraneous identifying headers though.
    const pj_str_t *headers_to_remove[] = { &call_info_hdr_name,
                                            &server_hdr_name,
                                            &organization_hdr_name };
    for (unsigned int ii = 0; ii < sizeof(headers_to_remove) / sizeof(pj_str_t *); ii++)
    {
      pjsip_hdr *hdr = (pjsip_hdr *)pjsip_msg_find_hdr_by_name(req, headers_to_remove[ii], NULL);
      if (hdr)
      {
        pj_list_erase(hdr);
      }
    }

    // b) Add the 'id' priv-value
    privacy_hdrs |= PRIVACY_H_ID;
  }

  // Sprout does not support session level privacy (only a B2BUA can satisfy that).  An edge-proxy/SBC could apply the privacy settings
  // but, for now we're forced to reject the call.
  if ((privacy_hdrs & PRIVACY_H_SESSION) && (privacy_hdrs & PRIVACY_H_CRITICAL))
  {
    TRC_WARNING("Critical session privacy requested but is not supported, call rejected");
    return PJSIP_SC_SERVICE_UNAVAILABLE;
  }

  if (privacy_hdrs & PRIVACY_H_USER)
  {
    // If the request includes the Privacy header field set to "user" the AS shall remove or anonymize the contents of all
    // "user configurable" headers in accordance with IETF RFC 3323 [6] and IETF RFC 3325 [7]. In the latter case, the AS
    // may need to act as transparent back to back user agent as described in IETF RFC 3323 [6].
    // -- 3GPP TS 24.607 v11.0.0

    TRC_DEBUG("Applying 'user' privacy");

    // Strip out the list of user identifying headers from RFC3323.
    const pj_str_t *headers_to_remove[] = { &subject_hdr_name,
                                            &call_info_hdr_name,
                                            &organization_hdr_name,
                                            &user_agent_hdr_name,
                                            &reply_to_hdr_name,
                                            &in_reply_to_hdr_name };
    for (unsigned int ii = 0; ii < sizeof(headers_to_remove) / sizeof(pj_str_t *); ii++)
    {
      pjsip_hdr *hdr = (pjsip_hdr *)pjsip_msg_find_hdr_by_name(req, headers_to_remove[ii], NULL);
      if (hdr)
      {
        pj_list_erase(hdr);
      }
    }

    // Convert the From: header to the anonymous one (as specified in RFC3323), note that we must keep the tag the same so the call can
    // be corellated.
    pjsip_from_hdr *from_header = PJSIP_MSG_FROM_HDR(req);
    pjsip_name_addr *anonymous_name_addr = pjsip_name_addr_create(pool);
    pj_strset2(&anonymous_name_addr->display, "Anonymous");
    anonymous_name_addr->uri = (pjsip_uri *)pjsip_sip_uri_create(pool, 0);
    pjsip_sip_uri *anonymous_sip_uri = (pjsip_sip_uri *)anonymous_name_addr->uri;
    pj_strset2(&anonymous_sip_uri->user, "anonymous");
    pj_strset2(&anonymous_sip_uri->host, "anonymous.invalid");
    pjsip_name_addr_assign(pool, (pjsip_name_addr *)from_header->uri, anonymous_name_addr);
  }

  if (privacy_hdrs & PRIVACY_H_ID)
  {
    TRC_DEBUG("Applying 'id' privacy");
    pjsip_hdr *p_asserted_identity_hdr = (pjsip_hdr *)pjsip_msg_find_hdr_by_name(req, &p_asserted_identity_hdr_name, NULL);
    if (p_asserted_identity_hdr)
    {
      pj_list_erase(p_asserted_identity_hdr);
    }
  }

  // Construct the new privacy header
  MmtelTsx::build_privacy_header(req, pool, privacy_hdrs);

  return PJSIP_SC_OK;
}

// Apply call diversion services to a request as a terminating AS.
//
// @returns PJSIP_SC_OK if the call may proceed as-is, false otherwise.
pjsip_status_code MmtelTsx::apply_cdiv_on_req(pjsip_msg* req,
                                              unsigned int conditions,
                                              pjsip_status_code code)
{
  pjsip_status_code rc = PJSIP_SC_OK;

  std::string target = check_call_diversion_rules(conditions);

  if (!target.empty())
  {
    {
      SAS::Event event(trail(), SASEvent::DIVERTING_CALL, 0);
      event.add_var_param(target);
      SAS::report_event(event);
    }

    // Update the request for the redirect.
    rc = PJUtils::redirect(req, target, get_pool(req), code);

    if (rc == PJSIP_SC_OK)
    {
      // Send a provisional response indicating the call is being forwarded.
      pjsip_msg* rsp = create_response(req, PJSIP_SC_CALL_BEING_FORWARDED);
      send_response(rsp);
      _diverted = true;
    }
  }
  return rc;
}

// Apply call diversion services on receipt of a response.
//
bool MmtelTsx::apply_cdiv_on_rsp(pjsip_msg* rsp,
                                 unsigned int conditions,
                                 pjsip_status_code code)
{
  bool already_diverted = _diverted;
  std::string target;

  if (!already_diverted)
  {
    if ((code == PJSIP_SC_MOVED_TEMPORARILY) &&
        (rsp != NULL))
    {
      // Handle 302 redirect by parsing the contact header and diverting to that
      // address.
      pjsip_contact_hdr* contact_hdr = (pjsip_contact_hdr*)
                                  pjsip_msg_find_hdr(rsp, PJSIP_H_CONTACT, NULL);
      if (contact_hdr != NULL)
      {
        target = PJUtils::uri_to_string(PJSIP_URI_IN_CONTACT_HDR, (pjsip_uri*)pjsip_uri_get_uri(contact_hdr->uri));
      }
    }
    else
    {
      // Check to see if CDIV rules trigger.
      target = check_call_diversion_rules(conditions);
    }

    if (!target.empty())
    {
      // We have a target for the redirect, so get a copy of the original
      // request and update it for the redirect.
      {
        SAS::Event event(trail(), SASEvent::DIVERTING_CALL, 1);
        event.add_var_param(target);
        SAS::report_event(event);
      }

      pjsip_msg* req = original_request();

      if (PJUtils::redirect(req, target, get_pool(req), code) == PJSIP_SC_OK)
      {
        // Send a provisional response flagging that the call is being
        // forwarded.
        TRC_DEBUG("Redirect request");
        rsp = create_response(req, PJSIP_SC_CALL_BEING_FORWARDED);
        send_response(rsp);

        // Send the redirected request.
        send_request(req);

        // The call has been diverted.  Cancel the no-reply timer.
        _diverted = true;
        if (_no_reply_timer != 0)
        {
          cancel_timer(_no_reply_timer);
          _no_reply_timer = 0;
        }
      }
      else
      {
        // Can't redirect the request.
        free_msg(req);
      }
    }
  }

  // Return true only if we're _newly_ diverted.
  return ((_diverted) && (!already_diverted));
}

// Check call diversion rules to see if all conditions of any rule match
//
// @returns The redirect target if a rule triggers, otherwise an empty string.
//
std::string MmtelTsx::check_call_diversion_rules(unsigned int conditions)
{
  if ((_method == PJSIP_INVITE_METHOD) &&
      (_user_services != NULL) &&
      (_user_services->cdiv_enabled()))
  {
    const std::vector<simservs::CDIVRule>* cdiv_rules = _user_services->cdiv_rules();
    for (std::vector<simservs::CDIVRule>::const_iterator rule = cdiv_rules->begin();
         rule != cdiv_rules->end();
         rule++)
    {
      TRC_DEBUG("Considering rule - conditions 0x%x (?= 0x%x), target %s",
                rule->conditions(), conditions, rule->forward_target().c_str());
      if ((rule->conditions() & ~conditions) == 0)
      {
        TRC_INFO("Forwarding to %s", rule->forward_target().c_str());
        if (_cdiv_callback != NULL) {
          _cdiv_callback->cdiv_callback(rule->forward_target(), rule->conditions());
        }
        return rule->forward_target();
      }
    }
  }
  return "";
}

// Determine the condition corresponding to the specified code, as specified by
// 3GPP TS 24.604.
//
// @returns Condition corresponding to the specified code.
unsigned int MmtelTsx::condition_from_status(int code)
{
  unsigned int condition = 0;
  switch (code)
  {
  case PJSIP_SC_NOT_FOUND:
  case PJSIP_SC_TEMPORARILY_UNAVAILABLE:
    condition = simservs::Rule::CONDITION_NOT_REGISTERED;
    break;

  case PJSIP_SC_BUSY_HERE:
    condition = simservs::Rule::CONDITION_BUSY;
    break;

  case PJSIP_SC_REQUEST_TIMEOUT:
    // If the phone timed out before starting ringing, this is considered
    // unreachable.  If it rang first, it's considered no answer.
    if (!_ringing)
    {
      condition = simservs::Rule::CONDITION_NOT_REACHABLE;
    }
    else
    {
      condition = simservs::Rule::CONDITION_NO_ANSWER;
    }
    break;

  case PJSIP_SC_INTERNAL_SERVER_ERROR:
  case PJSIP_SC_SERVICE_UNAVAILABLE:
    if (!_ringing)
    {
      condition = simservs::Rule::CONDITION_NOT_REACHABLE;
    }
    break;
  }
  return condition;
}

void MmtelTsx::on_timer_expiry(void* context)
{
  // Cancel the original attempt and perform call forwarding to
  // try a redirect.
  TRC_INFO("CDIV on no answer timer expired");
  _no_reply_timer = 0;
  cancel_fork(_late_redirect_fork_id, 0, "CDIV no answer timer expired");
  if (!apply_cdiv_on_rsp(NULL,
                         _media_conditions | simservs::Rule::CONDITION_NO_ANSWER,
                         PJSIP_SC_TEMPORARILY_UNAVAILABLE))
  {
    // Failed to redirect the request, so send a failure response.
    pjsip_msg* req = original_request();
    pjsip_msg* rsp = create_response(req, PJSIP_SC_TEMPORARILY_UNAVAILABLE);
    free_msg(req);
    send_response(rsp);
  }
}

pjsip_status_code MmtelTsx::apply_ib_call_barring(pjsip_msg* req)
{
  if (!_user_services)
  {
    TRC_DEBUG("Terminating user not found, no Inbound call barring rules apply");
    return PJSIP_SC_OK;
  }

  if (!_user_services->inbound_cb_enabled())
  {
    TRC_DEBUG("Inbound Call Barring disabled");
    return PJSIP_SC_OK;
  }

  return apply_call_barring(_user_services->inbound_cb_rules(), req);
}
