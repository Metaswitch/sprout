/**
 * @file session_expires_helper.cpp Class that implements the relevant parts of
 * session expires processing (RFC 4028)
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "log.h"
#include "constants.h"
#include "custom_headers.h"
#include "sproutsasevent.h"
#include "session_expires_helper.h"

// The RFC states that the minimum session expiry defaults to 90s if no Min-SE
// header is present.
const static SessionExpiresHelper::SessionInterval DEFAULT_MIN_SE = 90;


SessionExpiresHelper::SessionExpiresHelper(SessionInterval target_se) :
  _target_se(target_se)
{}


bool SessionExpiresHelper::timer_supported(pjsip_msg* msg)
{
  pjsip_supported_hdr* supported_hdr = (pjsip_supported_hdr*)
    pjsip_msg_find_hdr(msg, PJSIP_H_SUPPORTED, NULL);

  if (supported_hdr != NULL)
  {
    for (unsigned ii = 0; ii < supported_hdr->count; ++ii)
    {
      if (pj_strcmp(&supported_hdr->values[ii], &STR_TIMER) == 0)
      {
        return true;
      }
    }
  }

  return false;
}


void SessionExpiresHelper::process_request(pjsip_msg* req,
                                           pj_pool_t* pool,
                                           SAS::TrailId trail)
{
  // Session expires is only allowed on INVITE and UPDATE methods.
  pjsip_method* method = &req->line.req.method;

  if ((pjsip_method_cmp(method, pjsip_get_invite_method()) != 0) &&
      (pjsip_method_cmp(method, &METHOD_UPDATE) != 0))
  {
    return;
  }

  // Store if this is the initial transaction on a dialog, and if the UAC
  // supports session timers. We need both of these when processing the
  // response.
  _initial_request = (PJSIP_MSG_TO_HDR(req)->tag.slen == 0);
  _uac_supports_timer = timer_supported(req);

  // Find the session-expires header (if present) and the minimum
  // session-expires. Note that the latter has a default value.
  pjsip_session_expires_hdr* se_hdr = (pjsip_session_expires_hdr*)
    pjsip_msg_find_hdr_by_name(req, &STR_SESSION_EXPIRES, NULL);

  pjsip_min_se_hdr* min_se_hdr = (pjsip_min_se_hdr*)
    pjsip_msg_find_hdr_by_name(req, &STR_MIN_SE, NULL);

  SessionInterval min_se = (min_se_hdr != NULL) ?
                            min_se_hdr->expires :
                            DEFAULT_MIN_SE;

  if ((se_hdr != NULL) && (se_hdr->expires < _target_se))
  {
    // The request already has a session expires that is below our target. We
    // don't need to change the value.
    TRC_DEBUG("Session expires already set to %d", se_hdr->expires);
  }
  else
  {
    // No pre-existing session expires, or the current value is greater than
    // our target. Set it to as close to our target as possible, but don't set
    // it below the min-SE.
    if (se_hdr == NULL)
    {
      se_hdr = pjsip_session_expires_hdr_create(pool);
      pjsip_msg_add_hdr(req, (pjsip_hdr*)se_hdr);
    }

    se_hdr->expires = std::max(_target_se, min_se);

    TRC_DEBUG("Set session expires to %d", se_hdr->expires);
  }

  // Make a note of the session expires (we may need it when processing the
  // response)
  _se_on_req = se_hdr->expires;
}


void SessionExpiresHelper::process_response(pjsip_msg* rsp,
                                            pj_pool_t* pool,
                                            SAS::TrailId trail)
{
  // Session expires is only allowed on INVITE and UPDATE methods.
  pjsip_method* method = &PJSIP_MSG_CSEQ_HDR(rsp)->method;

  if ((pjsip_method_cmp(method, pjsip_get_invite_method()) != 0) &&
      (pjsip_method_cmp(method, &METHOD_UPDATE) != 0))
  {
    return;
  }

  // We only need to process successful final responses.
  if (!PJSIP_IS_STATUS_IN_CLASS(rsp->line.status.code, 200))
  {
    return;
  }

  pjsip_session_expires_hdr* se_hdr = (pjsip_session_expires_hdr*)
    pjsip_msg_find_hdr_by_name(rsp, &STR_SESSION_EXPIRES, NULL);

  if (se_hdr == NULL)
  {
    // There is no session-expires header. This means we are most downstream
    // device that supports session timers, and in particular the UAS does not
    // support them.
    //
    // If the UAC does not support session timers, there's nothing more we can
    // do - session timers will not be used for this dialog.
    //
    // If the UAC *does* support session timers, re-add a session-expires header
    // that instructs the UAC to be the refresher.
    if (_uac_supports_timer)
    {
      se_hdr = pjsip_session_expires_hdr_create(pool);
      pjsip_msg_add_hdr(rsp, (pjsip_hdr*)se_hdr);
      se_hdr->expires = _se_on_req;
      se_hdr->refresher = SESSION_REFRESHER_UAC;

      // Also update (or add) the require header to force the UAC to do session
      // refreshes.
      pjsip_require_hdr* require_hdr = (pjsip_require_hdr*)
        pjsip_msg_find_hdr(rsp, PJSIP_H_REQUIRE, NULL);

      if (require_hdr == NULL)
      {
        require_hdr = (pjsip_require_hdr*)pjsip_require_hdr_create(pool);
        pjsip_msg_add_hdr(rsp, (pjsip_hdr*)require_hdr);
      }

      pj_strdup(pool, &require_hdr->values[require_hdr->count], &STR_TIMER);
      require_hdr->count++;
    }
  }

  if (_initial_request)
  {
    if (se_hdr == NULL)
    {
      SAS::Event event(trail, SASEvent::SESS_TIMER_NO_UA_SUPPORT, 0);
      SAS::report_event(event);
    }
    else if (se_hdr->expires > _target_se)
    {
      SAS::Event event(trail, SASEvent::SESS_TIMER_INTERVAL_TOO_LONG, 0);
      event.add_static_param(_target_se);
      event.add_static_param(se_hdr->expires);
      SAS::report_event(event);
    }
  }
}
