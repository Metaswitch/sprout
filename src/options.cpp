/**
 * @file options.cpp
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

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

#include "log.h"
#include "stack.h"
#include "sproutsasevent.h"
#include "pjutils.h"
#include "uri_classifier.h"

//
// mod_options handles SIP OPTIONS polls targeted at this system.
//
static pj_bool_t on_rx_request(pjsip_rx_data *rdata);

pjsip_module mod_options =
{
  NULL, NULL,                         // prev, next
  pj_str("mod-options"),               // Name
  -1,                                 // Id
  PJSIP_MOD_PRIORITY_TSX_LAYER-2,     // Priority
  NULL,                               // load()
  NULL,                               // start()
  NULL,                               // stop()
  NULL,                               // unload()
  &on_rx_request,                     // on_rx_request()
  NULL,                               // on_rx_response()
  NULL,                               // on_tx_request()
  NULL,                               // on_tx_response()
  NULL,                               // on_tsx_state()
};


pj_bool_t on_rx_request(pjsip_rx_data* rdata)
{
  // SAS log the start of processing by this module
  SAS::Event event(get_trail(rdata), SASEvent::BEGIN_OPTIONS_MODULE, 0);
  SAS::report_event(event);

  URIClass uri_class = URIClassifier::classify_uri(rdata->msg_info.msg->line.req.uri);
  if (rdata->msg_info.msg->line.req.method.id == PJSIP_OPTIONS_METHOD)
  {
    if ((uri_class == NODE_LOCAL_SIP_URI) &&
        PJUtils::check_route_headers(rdata))
    {
      // OPTIONS targetted at this node/home domain, and there's either no route
      // header or a single local route header. espond statelessly.
      PJUtils::respond_stateless(stack_data.endpt, rdata, 200, NULL, NULL, NULL);
      return PJ_TRUE;
    }
  }

  return PJ_FALSE;
}


pj_status_t init_options()
{
  pj_status_t status;

  // Register the options module.
  status = pjsip_endpt_register_module(stack_data.endpt, &mod_options);

  return status;
}


void destroy_options()
{
  pjsip_endpt_unregister_module(stack_data.endpt, &mod_options);
}

