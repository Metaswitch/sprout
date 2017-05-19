/**
 * @file hss_sip_mapping.h Map HSS responses to SIP responses
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


#ifndef HSS_SIP_MAPPING_H__
#define HSS_SIP_MAPPING_H__

extern "C" {
#include <pjsip.h>
}

#include "acr.h"

/// Work out what SIP response code to use following a failure to perform an
/// operation at the HSS.
///
/// @param http_code    - The HTTP response code from the HSS.
/// @param reg_state    - The state of the subscriber's registration in the HSS.
/// @param sip_msg_type - The SIP Method being processed.
///
/// @return             - The chosen SIP status code.
pjsip_status_code determine_hss_sip_response(HTTPCode http_code,
                                             std::string& reg_state,
                                             const char* sip_msg_type);

#endif
