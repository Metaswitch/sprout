/**
 * @file sm_sip_mapping.h Map SM responses to SIP responses
 *
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef SM_SIP_MAPPING_H__
#define SM_SIP_MAPPING_H__

extern "C" {
#include <pjsip.h>
}

#include "httpconnection.h"

/// Work out what SIP response code to use following an SM operation.
///
/// @param http_code[in]    - The HTTP response code from SM.
/// @param reg_state[in]    - The state of the subscriber's registration in the
///                           HSS.
/// @param sip_msg_type[in] - The SIP Method being processed.
///
/// @return                 - The chosen SIP status code.
pjsip_status_code determine_sm_sip_response(HTTPCode http_code,
                                            std::string& reg_state,
                                            const char* sip_msg_type);

#endif
