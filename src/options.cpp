/**
 * @file options.cpp
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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

