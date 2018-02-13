/*
 * @file hss_sip_mapping.cpp
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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
        TRC_ERROR("Rejecting %s request following failure to register on the HSS: %s",
                  sip_msg_type, regstate.c_str());

        if (strcmp(sip_msg_type, "SUBSCRIBE") == 0)
        {
          // We successfully contacted Homestead, but the user wasn't registered
          // TS 24.229 says:
          // "if the Request-URI of the SUBSCRIBE request contains a URI for
          // which currently no binding exists, then send a 480 (Temporarily
          // Unavailable) response"
          st_code = PJSIP_SC_TEMPORARILY_UNAVAILABLE;
        }
        else
        {
          // LCOV_EXCL_START
          st_code = PJSIP_SC_SERVER_TIMEOUT;
          // LCOV_EXCL_STOP
        }
        break;

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
