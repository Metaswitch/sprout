/**
 * @file hss_sip_mapping.h Map HSS responses to SIP responses
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2016  Metaswitch Networks Ltd
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


#ifndef HSS_SIP_MAPPING_H__
#define HSS_SIP_MAPPING_H__

extern "C" {
#include <pjsip.h>
}

#include "acr.h"

/// Process failures following making a request to the HSS
//
// If the response from the HSS represents a failure to register, then an
// appropriate SIP response will be sent to the provided request.
// @param sip_msg_type Type of SIP Message being responded to for logging
// purposes
// @returns true if the response was a failure that has been handled, else
// false.
bool process_hss_sip_failure(HTTPCode http_code,
                             std::string& reg_state,
                             pjsip_rx_data* rdata,
                             struct stack_data_struct& stack_data,
                             ACR* acr,
                             const char* sip_msg_type);

#endif
