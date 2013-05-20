/**
 * @file callservices.cpp MMTel call services implementation
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

///

#include <string>
#include <vector>
#include <boost/algorithm/string/predicate.hpp>

#include "log.h"
#include "stack.h"
#include "pjutils.h"
#include "pjmedia.h"
#include "sasevent.h"
#include "stateful_proxy.h"
#include "callservices.h"
#include "simservs.h"
#include "hssconnection.h"

using namespace rapidxml;

// Used in logging

#define PRIVACY_H_ID       0x00000001
#define PRIVACY_H_HEADER   0x00000002
#define PRIVACY_H_SESSION  0x00000004
#define PRIVACY_H_USER     0x00000008
#define PRIVACY_H_NONE     0x00000010
#define PRIVACY_H_CRITICAL 0x00000020

// Call Services constructor
CallServices::CallServices(XDMConnection *xdm_client) : _xdmc(xdm_client)
{
  _mmtel_uri = "sip:mmtel." + std::string(stack_data.home_domain.ptr, stack_data.home_domain.slen);
}


CallServices::~CallServices()
{
}


/// Is this the URI of the MMTEL "callservices" AS?
bool CallServices::is_mmtel(std::string uri)
{
  return (uri == _mmtel_uri);
}


// Get the user services (simservs) configuration if relevant and present.
//
// @returns The simservs object if it is relevant and present.  If there is
// no simservs configuration for the user, returns a default simservs object
// with all services disabled.
simservs *CallServices::get_user_services(pjsip_msg *msg, std::string public_id, SAS::TrailId trail)
{
  // Fetch the user's simservs configuration from the XDMS
  LOG_DEBUG("Fetching simservs configuration for %s", public_id.c_str());
  std::string simservs_xml;
  if (!_xdmc->get_simservs(public_id, simservs_xml, "", trail))
  {
    LOG_DEBUG("Failed to fetch simservs configuration for %s, no MMTel services enabled", public_id.c_str());
    return new simservs("");
  }

  // Parse the retrieved XDMS information
  simservs *user_services = new simservs(simservs_xml);

  return user_services;
}

// Parse a privacy header into a bitfield.
//
// @returns Bitfield of privacy fields that were in the header.
int CallServices::parse_privacy_headers(pjsip_generic_array_hdr *header_array)
{
  int rc = 0;

  LOG_DEBUG("Parsing Privacy: header");

  for (unsigned int ii = 0; ii < header_array->count; ii++)
  {
    pj_str_t *field_str = &header_array->values[ii];
    if (!pj_stricmp2(field_str, "id"))
    {
      LOG_DEBUG("'id' privacy specified");
      rc |= PRIVACY_H_ID;
    }
    else if (!pj_stricmp2(field_str, "header"))
    {
      LOG_DEBUG("'header; privacy specified");
      rc |= PRIVACY_H_HEADER;
    }
    else if (!pj_stricmp2(field_str, "session"))
    {
      LOG_DEBUG("'session' privacy specified");
      rc |= PRIVACY_H_SESSION;
    }
    else if (!pj_stricmp2(field_str, "user"))
    {
      LOG_DEBUG("'user' privacy specified");
      rc |= PRIVACY_H_USER;
    }
    else if (!pj_stricmp2(field_str, "none"))
    {
      LOG_DEBUG("'none' privacy specified");
      rc |= PRIVACY_H_NONE;
    }
    else if (!pj_stricmp2(field_str, "critical"))
    {
      LOG_DEBUG("'critical' privacy specified");
      rc |= PRIVACY_H_CRITICAL;
    }
  }

  return rc;
}

// Create a privacy header from a bitfield of privacy fields.
//
// @returns Nothing.
void CallServices::build_privacy_header(pjsip_tx_data *tx_data, int privacy_fields)
{
  static const pj_str_t privacy_hdr_name = pj_str("Privacy");

  if (!privacy_fields)
  {
    return;
  }

  pjsip_generic_array_hdr *new_header = pjsip_generic_array_hdr_create(tx_data->pool, &privacy_hdr_name);

  if (privacy_fields & PRIVACY_H_ID)
  {
    LOG_DEBUG("Adding 'id' privacy field");
    pj_strdup2(tx_data->pool,
               &new_header->values[new_header->count],
               "id");
    new_header->count++;
  }

  if (privacy_fields & PRIVACY_H_HEADER)
  {
    LOG_DEBUG("Adding 'header' privacy field");
    pj_strdup2(tx_data->pool,
               &new_header->values[new_header->count],
               "header");
    new_header->count++;
  }

  if (privacy_fields & PRIVACY_H_SESSION)
  {
    LOG_DEBUG("Adding 'session' privacy field");
    pj_strdup2(tx_data->pool,
               &new_header->values[new_header->count],
               "session");
    new_header->count++;
  }

  if (privacy_fields & PRIVACY_H_USER)
  {
    LOG_DEBUG("Adding 'user' privacy field");
    pj_strdup2(tx_data->pool,
               &new_header->values[new_header->count],
               "user");
    new_header->count++;
  }

  if (privacy_fields & PRIVACY_H_NONE)
  {
    LOG_DEBUG("Adding 'none' privacy field");
    pj_strdup2(tx_data->pool,
               &new_header->values[new_header->count],
               "none");
    new_header->count++;
  }

  if (privacy_fields & PRIVACY_H_CRITICAL)
  {
    LOG_DEBUG("Adding 'critical' privacy field");
    pj_strdup2(tx_data->pool,
               &new_header->values[new_header->count],
               "critical");
    new_header->count++;
  }

  pjsip_msg_add_hdr(tx_data->msg, (pjsip_hdr *)new_header);
}

// Gets the media types specified in the SDP on the message.
//
// @returns Conditions corresponding to the media types.
unsigned int CallServices::get_media_type_conditions(pjsip_msg *msg)
{
  unsigned int media_type_conditions = 0;

  // First, check if the message body is SDP - if not, we can't tell what the
  // media types are (and assume they're 0).
  if (msg->body &&
      (!pj_stricmp2(&msg->body->content_type.type, "application")) &&
      (!pj_stricmp2(&msg->body->content_type.subtype, "sdp")))
  {
    // Parse the SDP, using a temporary pool.
    pj_pool_t* tmp_pool = pj_pool_create(&stack_data.cp.factory, "CallServices", 1024, 512, NULL);
    pjmedia_sdp_session *sdp_sess;
    if (pjmedia_sdp_parse(tmp_pool, (char *)msg->body->data, msg->body->len, &sdp_sess) == PJ_SUCCESS)
    {
      // Spin through the media types, looking for those we're interested in.
      for (unsigned int media_idx = 0; media_idx < sdp_sess->media_count; media_idx++)
      {
        LOG_DEBUG("Examining media type \"%.*s\"",
                  sdp_sess->media[media_idx]->desc.media.slen,
                  sdp_sess->media[media_idx]->desc.media.ptr);
        if (pj_strcmp2(&sdp_sess->media[media_idx]->desc.media, "audio") == 0)
        {
          media_type_conditions |= simservs::Rule::CONDITION_MEDIA_AUDIO;
        }
        else if (pj_strcmp2(&sdp_sess->media[media_idx]->desc.media, "video") == 0)
        {
          media_type_conditions |= simservs::Rule::CONDITION_MEDIA_VIDEO;
        }
      }
    }

    // Tidy up.
    pj_pool_release(tmp_pool);
  }

  return media_type_conditions;
}

// Call services base constructor
CallServices::CallServiceBase::CallServiceBase(std::string country_code, UASTransaction* uas_data) :
  _country_code(country_code),
  _uas_data(uas_data)
{
}

// Call services base destructor
CallServices::CallServiceBase::~CallServiceBase()
{
}

// Apply call barring, using the supplied rules (as defined in 3GPP TS 24.611 v11.2.0)
//
// @returns true if the call may still proceed, false otherwise.
bool CallServices::CallServiceBase::apply_call_barring(const std::vector<simservs::CBRule>* ruleset,
                                                       pjsip_tx_data *tx_data)
{
  // If one of the matching rules evaluates to allow=true then the resulting value shall be allow=true
  // and the call continues normally, otherwise the result shall be allow=false and the call will be barred.
  //   -- 3GPP TS 24.611 v11.2.0
  bool rule_matched = false;
  bool allow_call = false;
  for (std::vector<simservs::CBRule>::const_iterator rule = ruleset->begin();
       rule != ruleset->end();
       rule++)
  {
    if (check_cb_rule(*rule, tx_data->msg))
    {
      rule_matched = true;
      if (rule->allow_call())
      {
        LOG_DEBUG("Call barring rule allows call to continue");
        allow_call = true;
        break;
      }
    }
  }

  // If there are no matching rules then the result shall be allow=true
  //   -- 3GPP TS 24.611 v11.2.0
  if (!rule_matched)
  {
    LOG_DEBUG("No call barring rules matched, call continues");
    allow_call = true;
  }

  // When the AS providing the OCB service rejects a communication, the AS shall send an indication to the
  // calling user by sending a 603 (Decline) response.
  //   -- 3GPP TS 25.611 v11.2.0
  if (!allow_call)
  {
    LOG_DEBUG("Call rejected by call barring");
    _uas_data->send_response(PJSIP_SC_DECLINE);
  }

  return allow_call;
}

// Determine if an arbitary rule's conditions apply to a call.
//
// @return true if the rule should be applied (i.e. the conditions hold)
bool CallServices::CallServiceBase::check_cb_rule(const simservs::CBRule& rule, pjsip_msg* msg)
{
  bool rule_matches = true;
  int conditions = rule.conditions();
  LOG_DEBUG("Testing call against conditions (0x%X)", conditions);

  if (conditions & simservs::Rule::CONDITION_ROAMING)
  {
    // Clearwater doesn't support roaming calls yet, this never applies
    LOG_DEBUG("Roaming condition fails");
    rule_matches = false;
  }
  if (conditions & simservs::Rule::CONDITION_INTERNATIONAL)
  {
    // Detect international calls, this requires the request URI to be a TEL URI or a SIP URI with a 'phone'
    // parameter set.  Then we need to look at the country code to determine if we're going international.
    std::string dialed_number;
    pjsip_uri *uri = msg->line.req.uri;
    if (PJSIP_URI_SCHEME_IS_TEL(uri))
    {
      LOG_DEBUG("TEL: Number dialed");
      pj_str_t* tel_number = &((pjsip_tel_uri *)uri)->number;
      dialed_number.assign(pj_strbuf(tel_number), pj_strlen(tel_number));
    }
    else if (PJSIP_URI_SCHEME_IS_SIP(uri))
    {
      LOG_DEBUG("SIP/SIPS: Number dialed");
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
      LOG_DEBUG("SIP username requested, international number detection not possible");
      rule_matches = false;
    }
    else if (!(boost::starts_with(dialed_number, "+") ||
               boost::starts_with(dialed_number, "00") ||
               boost::starts_with(dialed_number, "011")) ||
             boost::starts_with(dialed_number, "+" + _country_code) ||
             boost::starts_with(dialed_number, "00" + _country_code) ||
             boost::starts_with(dialed_number, "011" + _country_code))
    {
      LOG_DEBUG("International condition fails, dialed number is '%s'", dialed_number.c_str());
      rule_matches = false;
    }
  }
  if (conditions & simservs::Rule::CONDITION_INTERNATIONAL_EXHC)
  {
    // Clearwater does not support roaming calls yet, this never applies
    LOG_DEBUG("International Excluding Home Country rule fails");
    rule_matches = false;
  }

  return rule_matches;
}

// Originating Call Services constructor.
CallServices::Originating::Originating(CallServices* callServices,
                                       UASTransaction* uas_data,
                                       pjsip_msg* msg,
                                       std::string served_user) :  //< Public ID of served user
  CallServices::CallServiceBase("1", uas_data)
{
  _user_services = callServices->get_user_services(msg, served_user, uas_data->trail());
}

CallServices::Originating::~Originating()
{
  delete _user_services;
}

// Apply originating call service processing on initial invite.
//
// @returns true if the call should proceed, false otherwise.
bool CallServices::Originating::on_initial_invite(pjsip_tx_data* tx_data)
{
  return apply_privacy(tx_data) && apply_ob_call_barring(tx_data);
}

// Applies privacy services as an originating AS.
//
// @returns true if the call should proceed, false otherwise
bool CallServices::Originating::apply_privacy(pjsip_tx_data *tx_data)
{
  static const pj_str_t privacy_hdr_name = pj_str("Privacy");

  pjsip_generic_array_hdr *privacy_hdr_array = NULL;

  if ((_user_services == NULL) ||
      (!_user_services->oir_enabled()))
  {
    LOG_DEBUG("Originating Identification Presentation Restriction disabled");
  }
  else
  {
    LOG_DEBUG("Originating Identification Presentation Restriction enabled");

    // Extract the privacy header
    privacy_hdr_array = (pjsip_generic_array_hdr *)pjsip_msg_find_hdr_by_name(tx_data->msg, &privacy_hdr_name, NULL);

    int privacy_hdrs = 0;
    if (privacy_hdr_array)
    {
      // Extract the privacy headers that currently exist, unrecognized headers will be stripped out
      privacy_hdrs = CallServices::parse_privacy_headers(privacy_hdr_array);
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
      LOG_DEBUG("Identity presentation is restricted by default");
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
      LOG_DEBUG("Identity presentation is not restricted by default");
      if ((privacy_hdrs & PRIVACY_H_ID) || (privacy_hdrs & PRIVACY_H_HEADER))
      {
        privacy_hdrs |= PRIVACY_H_USER;
      }
    }

    // Construct the new privacy header
    CallServices::build_privacy_header(tx_data, privacy_hdrs);
  }

  return true;
}

// Apply originating call barring (as defined in 3GPP TS 24.611 v11.2.0)
//
// @returns true if the call may still proceed, false otherwise.
bool CallServices::Originating::apply_ob_call_barring(pjsip_tx_data *tx_data)
{
  if (!_user_services->outbound_cb_enabled())
  {
    LOG_DEBUG("Outbound call barring disabled");
    return true;
  }

  return apply_call_barring(_user_services->outbound_cb_rules(), tx_data);
}

// Terminating Call Services constructor.
CallServices::Terminating::Terminating(CallServices* callServices,
                                       UASTransaction* uas_data,
                                       pjsip_msg* msg,
                                       std::string served_user) :  //< Public ID of served user
  CallServices::CallServiceBase("1", uas_data),
  _ringing(false)
{
  _user_services = callServices->get_user_services(msg, served_user, uas_data->trail());

  // Determine the media type conditions, in case they're needed later.
  if (msg->line.req.method.id == PJSIP_INVITE_METHOD)
  {
    _media_conditions = CallServices::get_media_type_conditions(msg);
  }
  else
  {
    _media_conditions = 0;
  }

  // Set up the no-reply timer.
  memset(&_no_reply_timer, 0, sizeof(pj_timer_entry));
  _no_reply_timer.user_data = this;
  _no_reply_timer.cb = no_reply_timer_pop;
}

CallServices::Terminating::~Terminating()
{
  if (_no_reply_timer.id != 0)
  {
    pjsip_endpt_cancel_timer(stack_data.endpt, &_no_reply_timer);
    _no_reply_timer.id = 0;
  }

  if (_user_services != NULL)
  {
    delete _user_services;
  }
}

// Apply terminating call service processing on initial invite.
//
// @returns True if the call should proceed, false otherwise.
bool CallServices::Terminating::on_initial_invite(pjsip_tx_data *tx_data)
{
  return apply_privacy(tx_data) &&
         apply_call_diversion(_media_conditions, 0) &&
         apply_ib_call_barring(tx_data);
}

// Apply terminating call service processing on receiving a response.
//
// @returns True if the call should proceed, false otherwise.
bool CallServices::Terminating::on_response(pjsip_msg *msg)
{
  int code = msg->line.status.code;
  switch (code)
  {
  case PJSIP_SC_RINGING:
    _ringing = true;

    // Consider starting the no-reply timer.  First, check call diversion is
    // enabled.
    if ((_no_reply_timer.id == 0) &&
        (_user_services != NULL) &&
        (_user_services->cdiv_enabled()))
    {
      // Now spin through the rules looking for one that requires no answer but
      // is also satisfied by our media conditions.
      const std::vector<simservs::CDIVRule>* cdiv_rules = _user_services->cdiv_rules();
      for (std::vector<simservs::CDIVRule>::const_iterator rule = cdiv_rules->begin();
           rule != cdiv_rules->end();
           rule++)
      {
        LOG_DEBUG("Considering rule - conditions 0x%x, target %s", rule->conditions(), rule->forward_target().c_str());
        if ((rule->conditions() & simservs::Rule::CONDITION_NO_ANSWER) &&
            ((rule->conditions() & ~(_media_conditions | simservs::Rule::CONDITION_NO_ANSWER)) == 0))
        {
          // We found a suitable rule.  Start the no-reply timer.
          _no_reply_timer.id = 1;
          pj_time_val delay;
          delay.sec = _user_services->cdiv_no_reply_timer();
          delay.msec = 0;
          pj_status_t status = pjsip_endpt_schedule_timer(stack_data.endpt, &_no_reply_timer, &delay);
          if (status != PJ_SUCCESS)
          {
            // Log this failure, but don't fail the call - there's no point.
            LOG_WARNING("Failed to set no-reply timer - status %d", status);
          }
          break;
        }
      }
    }
    break;

  case PJSIP_SC_MOVED_TEMPORARILY:
    // Handle 302 redirect by parsing the contact header and diverting to that
    // address.
    pjsip_contact_hdr* contact_hdr = (pjsip_contact_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_CONTACT, NULL);;
    if (contact_hdr != NULL)
    {
      return _uas_data->redirect(contact_hdr->uri, code);
    }
    break;
  }
  return true;
}

// Apply terminating call service processing on receiving a final response.
//
// @returns True if the call should proceed, false otherwise.
bool CallServices::Terminating::on_final_response(pjsip_tx_data *tx_data)
{
  // We've got a final response, so there's no point in running the no-reply timer any longer.
  if (_no_reply_timer.id != 0)
  {
    pjsip_endpt_cancel_timer(stack_data.endpt, &_no_reply_timer);
    _no_reply_timer.id = 0;
  }

  int code = tx_data->msg->line.status.code;
  return apply_call_diversion(condition_from_status(code) | _media_conditions, code);
}

// Apply privacy services as a terminating AS.
//
// @returns true if the call may proceed, false otherwise.
bool CallServices::Terminating::apply_privacy(pjsip_tx_data *tx_data)
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
  privacy_hdr_array = (pjsip_generic_array_hdr *)pjsip_msg_find_hdr_by_name(tx_data->msg, &privacy_hdr_name, NULL);
  if (privacy_hdr_array)
  {
    privacy_hdrs = CallServices::parse_privacy_headers(privacy_hdr_array);
    pj_list_erase(privacy_hdr_array);
  }

  if (privacy_hdrs & PRIVACY_H_NONE)
  {
    LOG_DEBUG("Privacy 'none' requested, no prvacy applied");
    CallServices::build_privacy_header(tx_data, privacy_hdrs);
    return true;
  }

  if (privacy_hdrs & PRIVACY_H_HEADER)
  {
    // If the request includes the Privacy header field set to "header" the AS shall:
    // a) anonymize the contents of all headers containing private information in accordance with IETF RFC 3323 [6] and
    // IETF RFC 3325 [7]; and
    // b) add a Privacy header field with the priv-value set to "id" if not already present in the request
    // -- 3GPP TS 24.607 v11.0.0

    LOG_DEBUG("Applying 'header' privacy");

    // a) Anonymize headers - Since we will be leaving the call path, we cannot perform Via/RR/Contact-stripping (as we can't replace
    // the headers later.  We can remove extraneous identifying headers though.
    const pj_str_t *headers_to_remove[] = { &call_info_hdr_name,
                                            &server_hdr_name,
                                            &organization_hdr_name };
    for (unsigned int ii = 0; ii < sizeof(headers_to_remove) / sizeof(pj_str_t *); ii++)
    {
      pjsip_hdr *hdr = (pjsip_hdr *)pjsip_msg_find_hdr_by_name(tx_data->msg, headers_to_remove[ii], NULL);
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
    LOG_WARNING("Critical session privacy requested but is not supported, call rejected");
    _uas_data->send_response(PJSIP_SC_SERVICE_UNAVAILABLE);
    return false;
  }

  if (privacy_hdrs & PRIVACY_H_USER)
  {
    // If the request includes the Privacy header field set to "user" the AS shall remove or anonymize the contents of all
    // "user configurable" headers in accordance with IETF RFC 3323 [6] and IETF RFC 3325 [7]. In the latter case, the AS
    // may need to act as transparent back to back user agent as described in IETF RFC 3323 [6].
    // -- 3GPP TS 24.607 v11.0.0

    LOG_DEBUG("Applying 'user' privacy");

    // Strip out the list of user identifying headers from RFC3323.
    const pj_str_t *headers_to_remove[] = { &subject_hdr_name,
                                            &call_info_hdr_name,
                                            &organization_hdr_name,
                                            &user_agent_hdr_name,
                                            &reply_to_hdr_name,
                                            &in_reply_to_hdr_name };
    for (unsigned int ii = 0; ii < sizeof(headers_to_remove) / sizeof(pj_str_t *); ii++)
    {
      pjsip_hdr *hdr = (pjsip_hdr *)pjsip_msg_find_hdr_by_name(tx_data->msg, headers_to_remove[ii], NULL);
      if (hdr)
      {
        pj_list_erase(hdr);
      }
    }

    // Convert the From: header to the anonymous one (as specified in RFC3323), note that we must keep the tag the same so the call can
    // be corellated.
    pjsip_from_hdr *from_header = PJSIP_MSG_FROM_HDR(tx_data->msg);
    pjsip_name_addr *anonymous_name_addr = pjsip_name_addr_create(tx_data->pool);
    pj_strset2(&anonymous_name_addr->display, "Anonymous");
    anonymous_name_addr->uri = (pjsip_uri *)pjsip_sip_uri_create(tx_data->pool, 0);
    pjsip_sip_uri *anonymous_sip_uri = (pjsip_sip_uri *)anonymous_name_addr->uri;
    pj_strset2(&anonymous_sip_uri->user, "anonymous");
    pj_strset2(&anonymous_sip_uri->host, "anonymous.invalid");
    pjsip_name_addr_assign(tx_data->pool, (pjsip_name_addr *)from_header->uri, anonymous_name_addr);
  }

  if (privacy_hdrs & PRIVACY_H_ID)
  {
    LOG_DEBUG("Applying 'id' privacy");
    pjsip_hdr *p_asserted_identity_hdr = (pjsip_hdr *)pjsip_msg_find_hdr_by_name(tx_data->msg, &p_asserted_identity_hdr_name, NULL);
    if (p_asserted_identity_hdr)
    {
      pj_list_erase(p_asserted_identity_hdr);
    }
  }

  // Construct the new privacy header
  CallServices::build_privacy_header(tx_data, privacy_hdrs);

  return true;
}

// Apply call diversion services as a terminating AS.
//
// @returns true if the call may proceed as-is, false otherwise.
bool CallServices::Terminating::apply_call_diversion(unsigned int conditions, int code)
{
  bool rc = true;
  // If this is an INVITE and call diversion is enabled, check the rules.
  if ((_uas_data->method() == PJSIP_INVITE_METHOD) &&
      (_user_services != NULL) &&
      (_user_services->cdiv_enabled()))
  {
    rc = check_call_diversion_rules(conditions, code);
  }
  return rc;
}

// Check call diversion rules to see if all conditions of any rule match, and
// divert the call if so.
//
// @returns true if the call may proceed as-is, false otherwise.
bool CallServices::Terminating::check_call_diversion_rules(unsigned int conditions, int code)
{
  const std::vector<simservs::CDIVRule>* cdiv_rules = _user_services->cdiv_rules();
  for (std::vector<simservs::CDIVRule>::const_iterator rule = cdiv_rules->begin();
       rule != cdiv_rules->end();
       rule++)
  {
    LOG_DEBUG("Considering rule - conditions 0x%x (?= 0x%x), target %s", rule->conditions(), conditions, rule->forward_target().c_str());
    if ((rule->conditions() & ~conditions) == 0)
    {
      LOG_INFO("Forwarding to %s", rule->forward_target().c_str());
      return _uas_data->redirect(rule->forward_target(), code);
    }
  }
  return true;
}

// Determine the condition corresponding to the specified code, as specified by
// 3GPP TS 24.604.
//
// @returns Condition corresponding to the specified code.
unsigned int CallServices::Terminating::condition_from_status(int code)
{
  unsigned int condition = 0;
  switch (code)
  {
  case PJSIP_SC_NOT_FOUND:
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

// Handles the no-reply timer popping.
void CallServices::Terminating::no_reply_timer_pop()
{
  _uas_data->enter_context();
  _no_reply_timer.id = 0;
  apply_call_diversion(_media_conditions | simservs::Rule::CONDITION_NO_ANSWER, PJSIP_SC_TEMPORARILY_UNAVAILABLE);
  _uas_data->exit_context();
}

// Handles the no-reply timer popping.
//
// This is just a wrapper for the member function.
void CallServices::Terminating::no_reply_timer_pop(pj_timer_heap_t *timer_heap, pj_timer_entry *entry)
{
  ((CallServices::Terminating *)entry->user_data)->no_reply_timer_pop();
}

bool CallServices::Terminating::apply_ib_call_barring(pjsip_tx_data* tx_data)
{
  if (!_user_services)
  {
    LOG_DEBUG("Terminating user not found, no Inbound call barring rules apply");
    return true;
  }

  if (!_user_services->inbound_cb_enabled())
  {
    LOG_DEBUG("Inbound Call Barring disabled");
    return true;
  }

  return apply_call_barring(_user_services->inbound_cb_rules(), tx_data);
}
