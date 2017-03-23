/*
 * @file hss_sip_mapping.cpp
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

#include "hss_sip_mapping.h"

#include "hssconnection.h"
#include "pjutils.h"
#include "stack.h"

pjsip_status_code determine_hss_sip_response(HTTPCode http_code,
                                             std::string& regstate,
                                             const char* sip_msg_type)
{
  pjsip_status_code st_code = PJSIP_SC_OK;

  if ((http_code != HTTP_OK) || (regstate != RegDataXMLUtils::STATE_REGISTERED))
  {
    // We failed to register this subscriber at the HSS. This may be because
    // the HSS is unavilable, the public identity doesn't exist, the public
    // identity doesn't belong to the private identity, or there was an error
    // communicating with the HSS.
    switch (http_code)
    {
      case HTTP_OK:
        // LCOV_EXCL_START
        TRC_ERROR("Rejecting %s request following failure to register on the HSS: %s",
                  sip_msg_type, regstate.c_str());

        st_code = PJSIP_SC_SERVER_TIMEOUT;
        break;
        // LCOV_EXCL_STOP

      case HTTP_NOT_FOUND:
        // The client shouldn't retry when the subscriber isn't present in the
        // HSS; reject with a 403 in this case.
        TRC_ERROR("Rejecting %s request as subscriber not present on the HSS",
                  sip_msg_type);

        st_code = PJSIP_SC_FORBIDDEN;
        break;

      case HTTP_SERVER_UNAVAILABLE:
      case HTTP_GATEWAY_TIMEOUT:
        // The HSS is unavailable - the client should retry on timeout but no
        // other Clearwater nodes should (as Sprout will already have retried on
        // timeout). Reject with a 504 (503 is used for overload).
        TRC_ERROR("Rejecting %s request as unable to contact HSS: %d",
                  sip_msg_type, http_code);

        st_code = PJSIP_SC_SERVER_TIMEOUT;
        break;

      case HTTP_SERVER_ERROR:
        // This is either a server error on the HSS, or a error decoding the
        // response
        TRC_ERROR("Rejecting %s request following error communicating with the HSS",
                  sip_msg_type);

        st_code = PJSIP_SC_INTERNAL_SERVER_ERROR;
        break;

      default:
        TRC_ERROR("Rejecting %s request following response %d from HSS",
                  sip_msg_type, http_code);

        st_code = PJSIP_SC_SERVER_TIMEOUT;
        break;
    }
  }

  return st_code;
}
