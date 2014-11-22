/**
 * @file common_sip_processing.cpp
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * Parts of this module were derived from GPL licensed PJSIP sample code
 * with the following copyrights.
 *   Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 *   Copyright (C) 2003-2008 Benny Prijono <benny@prijono.org>
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
#include "pjsip-simple/evsub.h"
}
#include <arpa/inet.h>

// Common STL includes.
#include <cassert>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <queue>
#include <string>

#include "constants.h"
#include "pjutils.h"
#include "log.h"
#include "sas.h"
#include "saslogger.h"
#include "sproutsasevent.h"
#include "stack.h"
#include "utils.h"
#include "custom_headers.h"
#include "utils.h"
#include "accumulator.h"
#include "load_monitor.h"
#include "counter.h"

static Counter* requests_counter = NULL;
static Counter* overload_counter = NULL;
static LoadMonitor* load_monitor = NULL;

static pj_bool_t process_on_rx_msg(pjsip_rx_data* rdata);
static pj_status_t process_on_tx_msg(pjsip_tx_data* tdata);

// Module handling common processing for all SIP messages - logging,
// overload control, and rejection of bad requests.

// Priority of PJSIP_MOD_PRIORITY_TRANSPORT_LAYER-2 allows this to run
// as early as possible in incoming message processing (e.g. for
// overload control), and as late as possible in outgoing message
// processing (in particular, after the transport layer has printed
// the message into the bytes that will go over the wire, so that we
// can log out those bytes).
static pjsip_module mod_common_processing =
{
  NULL, NULL,                           /* prev, next.          */
  pj_str("mod-common-processing"),      /* Name.                */
  -1,                                   /* Id                   */
  PJSIP_MOD_PRIORITY_TRANSPORT_LAYER-2, /* Priority             */
  NULL,                                 /* load()               */
  NULL,                                 /* start()              */
  NULL,                                 /* stop()               */
  NULL,                                 /* unload()             */
  &process_on_rx_msg,                   /* on_rx_request()      */
  &process_on_rx_msg,                   /* on_rx_response()     */
  &process_on_tx_msg,                   /* on_tx_request()      */
  &process_on_tx_msg,                   /* on_tx_response()     */
  NULL,                                 /* on_tsx_state()       */
};

static void local_log_rx_msg(pjsip_rx_data* rdata)
{
  LOG_VERBOSE("RX %d bytes %s from %s %s:%d:\n"
              "--start msg--\n\n"
              "%.*s\n"
              "--end msg--",
              rdata->msg_info.len,
              pjsip_rx_data_get_info(rdata),
              rdata->tp_info.transport->type_name,
              rdata->pkt_info.src_name,
              rdata->pkt_info.src_port,
              (int)rdata->msg_info.len,
              rdata->msg_info.msg_buf);
}


static void local_log_tx_msg(pjsip_tx_data* tdata)
{
  LOG_VERBOSE("TX %d bytes %s to %s %s:%d:\n"
              "--start msg--\n\n"
              "%.*s\n"
              "--end msg--",
              (tdata->buf.cur - tdata->buf.start),
              pjsip_tx_data_get_info(tdata),
              tdata->tp_info.transport->type_name,
              tdata->tp_info.dst_name,
              tdata->tp_info.dst_port,
              (int)(tdata->buf.cur - tdata->buf.start),
              tdata->buf.start);
}

// LCOV_EXCL_START - can't meaningfully test SAS in UT
static void sas_log_rx_msg(pjsip_rx_data* rdata)
{
  SAS::TrailId trail = 0;

  if (rdata->msg_info.msg->type == PJSIP_RESPONSE_MSG)
  {
    // Message is a response, so try to correlate to an existing UAC
    // transaction using the top-most Via header.
    pj_str_t key;
    pjsip_tsx_create_key(rdata->tp_info.pool, &key, PJSIP_ROLE_UAC,
                         &rdata->msg_info.cseq->method, rdata);
    pjsip_transaction* tsx = pjsip_tsx_layer_find_tsx(&key, PJ_TRUE);
    if (tsx)
    {
      // Found the UAC transaction, so get the trail if there is one.
      trail = get_trail(tsx);

      // Unlock tsx because it is locked in find_tsx()
      pj_grp_lock_release(tsx->grp_lock);
    }
  }
  else if (rdata->msg_info.msg->line.req.method.id == PJSIP_ACK_METHOD)
  {
    // Message is an ACK, so try to correlate it to the existing UAS
    // transaction using the top-most Via header.
    pj_str_t key;
    pjsip_tsx_create_key(rdata->tp_info.pool, &key, PJSIP_UAS_ROLE,
                         &rdata->msg_info.cseq->method, rdata);
    pjsip_transaction* tsx = pjsip_tsx_layer_find_tsx(&key, PJ_TRUE);
    if (tsx)
    {
      // Found the UAS transaction, so get the trail if there is one.
      trail = get_trail(tsx);

      // Unlock tsx because it is locked in find_tsx()
      pj_grp_lock_release(tsx->grp_lock);
    }
  }
  else if (rdata->msg_info.msg->line.req.method.id == PJSIP_CANCEL_METHOD)
  {
    // Message is a CANCEL request chasing an INVITE, so we want to try to
    // correlate it to the INVITE trail for the purposes of SAS tracing.
    pj_str_t key;
    pjsip_tsx_create_key(rdata->tp_info.pool, &key, PJSIP_UAS_ROLE,
                         pjsip_get_invite_method(), rdata);
    pjsip_transaction* tsx = pjsip_tsx_layer_find_tsx(&key, PJ_TRUE);
    if (tsx)
    {
      // Found the INVITE UAS transaction, so get the trail if there is one.
      trail = get_trail(tsx);

      // Unlock tsx because it is locked in find_tsx()
      pj_grp_lock_release(tsx->grp_lock);
    }
  }

  if (trail == 0)
  {
    // The message doesn't correlate to an existing trail, so create a new
    // one.
    trail = SAS::new_trail(1u);
  }

  // Store the trail in the message as it gets passed up the stack.
  set_trail(rdata, trail);

  // Log the message event.
  SAS::Event event(trail, SASEvent::RX_SIP_MSG, 0);
  event.add_static_param(pjsip_transport_get_type_from_flag(rdata->tp_info.transport->flag));
  event.add_static_param(rdata->pkt_info.src_port);
  event.add_var_param(rdata->pkt_info.src_name);
  event.add_compressed_param(rdata->msg_info.len, rdata->msg_info.msg_buf, &SASEvent::PROFILE_SIP);
  SAS::report_event(event);
}


static void sas_log_tx_msg(pjsip_tx_data *tdata)
{
  // For outgoing messages always use the trail identified in the module data
  SAS::TrailId trail = get_trail(tdata);

  if (trail != 0)
  {
    // Log the message event.
    SAS::Event event(trail, SASEvent::TX_SIP_MSG, 0);
    event.add_static_param(pjsip_transport_get_type_from_flag(tdata->tp_info.transport->flag));
    event.add_static_param(tdata->tp_info.dst_port);
    event.add_var_param(tdata->tp_info.dst_name);
    event.add_compressed_param((int)(tdata->buf.cur - tdata->buf.start),
                               tdata->buf.start,
                               &SASEvent::PROFILE_SIP);
    SAS::report_event(event);
  }
  else
  {
    LOG_ERROR("Transmitting message with no SAS trail identifier\n%.*s",
              (int)(tdata->buf.cur - tdata->buf.start),
              tdata->buf.start);
  }
}
// LCOV_EXCL_STOP

static pj_bool_t process_on_rx_msg(pjsip_rx_data* rdata)
{
  // Do logging.
  local_log_rx_msg(rdata);
  sas_log_rx_msg(rdata);

  requests_counter->increment();

  // Check whether the request should be processed
  if (!(load_monitor->admit_request()) &&
      (rdata->msg_info.msg->type == PJSIP_REQUEST_MSG) &&
      (rdata->msg_info.msg->line.req.method.id != PJSIP_ACK_METHOD))
  {
    // Discard non-ACK requests if there are no available tokens.
    // Respond statelessly with a 503 Service Unavailable, including a
    // Retry-After header with a zero length timeout.
    LOG_DEBUG("Rejected request due to overload");

    pjsip_cid_hdr* cid = (pjsip_cid_hdr*)rdata->msg_info.cid;

    // LCOV_EXCL_START - can't meaningfully verify SAS in UT
    SAS::TrailId trail = get_trail(rdata);

    SAS::Marker start_marker(trail, MARKER_ID_START, 1u);
    SAS::report_marker(start_marker);

    SAS::Event event(trail, SASEvent::SIP_OVERLOAD, 0);
    event.add_static_param(load_monitor->get_target_latency());
    event.add_static_param(load_monitor->get_current_latency());
    event.add_static_param(load_monitor->get_rate_limit());
    SAS::report_event(event);

    PJUtils::report_sas_to_from_markers(trail, rdata->msg_info.msg);

    if ((rdata->msg_info.msg->line.req.method.id == PJSIP_REGISTER_METHOD) ||
        ((pjsip_method_cmp(&rdata->msg_info.msg->line.req.method, pjsip_get_subscribe_method())) == 0) ||
        ((pjsip_method_cmp(&rdata->msg_info.msg->line.req.method, pjsip_get_notify_method())) == 0))
    {
      // Omit the Call-ID for these requests, as the same Call-ID can be
      // reused over a long period of time and produce huge SAS trails.
      PJUtils::mark_sas_call_branch_ids(trail, NULL, rdata->msg_info.msg);
    }
    else
    {
      PJUtils::mark_sas_call_branch_ids(trail, cid, rdata->msg_info.msg);
    }

    SAS::Marker end_marker(trail, MARKER_ID_END, 1u);
    SAS::report_marker(end_marker);

    // LCOV_EXCL_STOP

    pjsip_retry_after_hdr* retry_after = pjsip_retry_after_hdr_create(rdata->tp_info.pool, 0);
    PJUtils::respond_stateless(stack_data.endpt,
                               rdata,
                               PJSIP_SC_SERVICE_UNAVAILABLE,
                               NULL,
                               (pjsip_hdr*)retry_after,
                               NULL);

    // We no longer terminate TCP connections on overload as the shutdown has
    // to wait for existing transactions to end and therefore it takes too
    // long to get feedback to the downstream node.  We expect downstream nodes
    // to rebalance load if possible triggered by receipt of the 503 responses.

    overload_counter->increment();
    return PJ_TRUE;
  }

  // If a message has parse errors, reject it (if it's a request) or
  // drop it (if it's a response).
  if (!pj_list_empty((pj_list_type*)&rdata->msg_info.parse_err))
  {
    SAS::TrailId trail = get_trail(rdata);
    LOG_DEBUG("Report SAS start marker - trail (%llx)", trail);
    SAS::Marker start_marker(trail, MARKER_ID_START, 1u);
    SAS::report_marker(start_marker);

    PJUtils::report_sas_to_from_markers(trail, rdata->msg_info.msg);
    PJUtils::mark_sas_call_branch_ids(trail, rdata->msg_info.cid, rdata->msg_info.msg);
    
    pjsip_parser_err_report *err = rdata->msg_info.parse_err.next;
    while (err != &rdata->msg_info.parse_err)
    {
      LOG_ERROR("Error parsing header %.*s", (int)err->hname.slen, err->hname.ptr);
      //SAS::Event event(trail, SASEvent::UNPARSEABLE_HEADER, 0);
      //event.add_var_param((int)err->hname.slen, err->hname.ptr);
      //SAS::report_event(event);
      err = err->next;
    }

    if (rdata->msg_info.msg->type == PJSIP_REQUEST_MSG)
    {
      LOG_WARNING("Rejecting malformed request with a 400 error");
      PJUtils::respond_stateless(stack_data.endpt,
                                 rdata,
                                 PJSIP_SC_BAD_REQUEST,
                                 NULL,
                                 NULL,
                                 NULL);
    }
    else
    {
      LOG_WARNING("Dropping malformed response");
    }

    // As this message is malformed, return PJ_TRUE to absorb it and
    // stop later modules from processing it.
    return PJ_TRUE;
  }
  return PJ_FALSE;
}

static pj_status_t process_on_tx_msg(pjsip_tx_data* tdata)
{
  // Do logging.
  local_log_tx_msg(tdata);
  sas_log_tx_msg(tdata);

  // Return success so the message gets transmitted.
  return PJ_SUCCESS;
}


pj_status_t
init_common_sip_processing(LoadMonitor* load_monitor_arg,
			   Counter* requests_counter_arg,
			   Counter* overload_counter_arg)
{
  // Register the stack modules.
  pjsip_endpt_register_module(stack_data.endpt, &mod_common_processing);
  stack_data.common_processing_module_id = mod_common_processing.id;

  overload_counter = overload_counter_arg;
  requests_counter = requests_counter_arg;

  load_monitor = load_monitor_arg;

  return PJ_SUCCESS;
}


void unregister_common_processing_module(void)
{
  pjsip_endpt_unregister_module(stack_data.endpt, &mod_common_processing);
}
