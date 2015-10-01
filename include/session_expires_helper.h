/**
 * @file session_expires_helper.h Class that implements the relevant parts of
 * session expires processing (RFC 4028)
 *
 * project clearwater - ims in the cloud
 * copyright (c) 2015  metaswitch networks ltd
 *
 * this program is free software: you can redistribute it and/or modify it
 * under the terms of the gnu general public license as published by the
 * free software foundation, either version 3 of the license, or (at your
 * option) any later version, along with the "special exception" for use of
 * the program along with ssl, set forth below. this program is distributed
 * in the hope that it will be useful, but without any warranty;
 * without even the implied warranty of merchantability or fitness for
 * a particular purpose.  see the gnu general public license for more
 * details. you should have received a copy of the gnu general public
 * license along with this program.  if not, see
 * <http://www.gnu.org/licenses/>.
 *
 * the author can be reached by email at clearwater@metaswitch.com or by
 * post at metaswitch networks ltd, 100 church st, enfield en2 6bq, uk
 *
 * special exception
 * metaswitch networks ltd  grants you permission to copy, modify,
 * propagate, and distribute a work formed by combining openssl with the
 * software, or a work derivative of such a combination, even if such
 * copying, modification, propagation, or distribution would otherwise
 * violate the terms of the gpl. you must comply with the gpl in all
 * respects for all of the code used other than openssl.
 * "openssl" means openssl toolkit software distributed by the openssl
 * project and licensed under the openssl licenses, or a work based on such
 * software and licensed under the openssl licenses.
 * "openssl licenses" means the openssl license and original ssleay license
 * under which the openssl project distributes the openssl toolkit software,
 * as those licenses appear in the file license-openssl.
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

  // Whether the UAC support session timers.
  bool _uac_supports_timer;

  // The value of the session expires header on the request when we had
  // finished processing. This is needed to restore the value on the response
  // in case the UAS does not support session timers.
  SessionInterval _se_on_req;
};

#endif
