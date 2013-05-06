/**
 * @file options.cpp
 *
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by post at
 * Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 */

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

#include "log.h"
#include "stack.h"
#include "sasevent.h"
#include "pjutils.h"

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
  if (rdata->msg_info.msg->line.req.method.id == PJSIP_OPTIONS_METHOD)
  {
    if ((PJUtils::is_uri_local(rdata->msg_info.msg->line.req.uri)) ||
        (PJUtils::is_home_domain(rdata->msg_info.msg->line.req.uri)))
    {
      // OPTIONS targetted at this node or at the home domain, so respond
      // statelessly.
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

