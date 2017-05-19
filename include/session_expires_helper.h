/**
 * @file session_expires_helper.h Class that implements the relevant parts of
 * session expires processing (RFC 4028)
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef SESSION_EXPIRES_HELPER_H__
#define SESSION_EXPIRES_HELPER_H__

#include "sas.h"

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}

class SessionExpiresHelper
{
public:
  typedef pj_int32_t SessionInterval;

  /// Constructor
  ///
  /// @param target_se - The session interval we would like to set on the
  ///                    dialog. Specified in seconds.
  SessionExpiresHelper(SessionInterval target_se);

  ~SessionExpiresHelper() {}

  /// Do session expiry processing on a request. This attempts to set the
  /// target session interval subject to the constraints of the RFC.
  ///
  /// @param req   - The request to process. This method mutates the request in
  ///                place.
  /// @param pool  - The pool associated with the request.
  /// @param trail - SAS trail ID.
  void process_request(pjsip_msg* req,
                       pj_pool_t* pool,
                       SAS::TrailId trail);

  /// Do session expiry processing on a response. This carries out the
  /// processing required by the RFC.
  ///
  /// @param rsp   - The response to process. This method mutates the response
  ///                in place.
  /// @param pool  - The pool associated with the response.
  /// @param trail - SAS trail ID.
  void process_response(pjsip_msg* rsp,
                        pj_pool_t* pool,
                        SAS::TrailId trail);

private:
  /// Utility method to tell if the sender of a message supports session
  /// timers.
  bool timer_supported(pjsip_msg* msg);

  // The session expiry we would like to use for this dialog.
  SessionInterval _target_se;

  // Whether this transaction forms an initial request for the dialog. This
  // affects what SAS logging we produce.
  bool _initial_request;

  // Whether the UAC supports session timers.
  bool _uac_supports_timer;

  // The value of the session expires header on the request when we had
  // finished processing. This is needed to restore the value on the response
  // in case the UAS does not support session timers.
  SessionInterval _se_on_req;
};

#endif
