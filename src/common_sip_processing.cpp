/**
 * @file common_sip_processing.cpp
 *
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

extern "C" {
#include <pjlib-util.h>
#include <pjlib.h>
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

#include "common_sip_processing.h"
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
#include "health_checker.h"
#include "uri_classifier.h"

static SNMP::CounterByScopeTable* requests_counter = NULL;
static HealthChecker* health_checker = NULL;

static pj_bool_t process_on_rx_msg(pjsip_rx_data* rdata);
static pj_status_t process_on_tx_msg(pjsip_tx_data* tdata);

static SAS::TrailId DONT_LOG_TO_SAS = 0xFFFFFFFF;

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
  TRC_VERBOSE("RX %d bytes %s from %s %s:%d:\n"
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
  TRC_VERBOSE("TX %d bytes %s to %s %s:%d:\n"
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
  bool first_message_in_trail = false;
  SAS::TrailId trail = 0;

  // Look for the SAS Trail ID for the corresponding transaction object.
  //
  // Note that we are NOT locking the transaction object before we fetch the
  // trail ID from it.  This is deliberate - we cannot get a group lock from
  // this routine as we may already have obtained the IO lock (which is lower
  // in the locking hierarchy) higher up the stack.
  // (e.g. from ioqueue_common_abs::ioqueue_dispatch_read_event) and grabbing
  // the group lock here may cause us to deadlock with a thread using the locks
  // in the right order.
  //
  // This is safe for the following reasons
  // - The transaction objects are only ever invalidated by the current thread
  //   (i.e. the transport thread), so we don't need to worry about the tsx
  //   pointers being invalid.
  // - In principle, the trail IDs (which are 64 bit numbers stored as void*s
  //   since thats the format of the generic PJSIP user data area) might be
  //   being written to as we are reading them, thereby invalidating them.
  //   However, the chances of this happening are exceedingly remote and, if it
  //   ever happened, the worst that could happen is that the trail ID would be
  //   invalid and the log we're about to make unreachable by SAS.  This is
  //   assumed to be sufficiently low impact as to be ignorable for practical
  //   purposes.
  if (rdata->msg_info.msg->type == PJSIP_RESPONSE_MSG)
  {
    // Message is a response, so try to correlate to an existing UAC
    // transaction using the top-most Via header.
    pj_str_t key;
    pjsip_tsx_create_key(rdata->tp_info.pool, &key, PJSIP_ROLE_UAC,
                         &rdata->msg_info.cseq->method, rdata);
    pjsip_transaction* tsx = pjsip_tsx_layer_find_tsx(&key, PJ_FALSE);
    if (tsx)
    {
      // Found the UAC transaction, so get the trail if there is one.
      trail = get_trail(tsx);
    }
  }
  else if (rdata->msg_info.msg->line.req.method.id == PJSIP_ACK_METHOD)
  {
    // Message is an ACK, so try to correlate it to the existing UAS
    // transaction using the top-most Via header.
    pj_str_t key;
    pjsip_tsx_create_key(rdata->tp_info.pool, &key, PJSIP_UAS_ROLE,
                         &rdata->msg_info.cseq->method, rdata);
    pjsip_transaction* tsx = pjsip_tsx_layer_find_tsx(&key, PJ_FALSE);
    if (tsx)
    {
      // Found the UAS transaction, so get the trail if there is one.
      trail = get_trail(tsx);
    }
  }
  else if (rdata->msg_info.msg->line.req.method.id == PJSIP_CANCEL_METHOD)
  {
    // Message is a CANCEL request chasing an INVITE, so we want to try to
    // correlate it to the INVITE trail for the purposes of SAS tracing.
    pj_str_t key;
    pjsip_tsx_create_key(rdata->tp_info.pool, &key, PJSIP_UAS_ROLE,
                         pjsip_get_invite_method(), rdata);
    pjsip_transaction* tsx = pjsip_tsx_layer_find_tsx(&key, PJ_FALSE);
    if (tsx)
    {
      // Found the INVITE UAS transaction, so get the trail if there is one.
      trail = get_trail(tsx);
    }
  }
  else if ((rdata->msg_info.msg->line.req.method.id == PJSIP_OPTIONS_METHOD) &&
           (URIClassifier::classify_uri(rdata->msg_info.msg->line.req.uri) == NODE_LOCAL_SIP_URI))
  {
    // This is an OPTIONS poll directed at this node. Don't log it to SAS, and set the trail ID to a sentinel value so we don't log the response either.
    TRC_DEBUG("Skipping SAS logging for OPTIONS request");
    set_trail(rdata, DONT_LOG_TO_SAS);
    return;
  }

  if (trail == 0)
  {
    // The message doesn't correlate to an existing trail, so create a new
    // one.

    // If SAS::new_trail returns 0 or DONT_LOG_TO_SAS, keep going.
    while ((trail == 0) || (trail == DONT_LOG_TO_SAS))
    {
      trail = SAS::new_trail(1u);
    }
    first_message_in_trail = true;
  }

  // Store the trail in the message as it gets passed up the stack.
  set_trail(rdata, trail);

  // Raise SAS markers on the first message in a trail only - subsequent
  // messages with the same trail ID don't need additional markers
  if (first_message_in_trail)
  {
    PJUtils::report_sas_to_from_markers(trail, rdata->msg_info.msg);

    std::vector<std::string> call_ids;

    pjsip_cid_hdr* cid = (pjsip_cid_hdr*)rdata->msg_info.cid;

    if (cid != NULL)
    {
      call_ids.push_back(PJUtils::pj_str_to_string(&cid->id));
    }

    // If this is a SIP MESSAGE then also pull out any In-Reply-To
    // headers in order to correlate this trail with the trails
    // for the calls identified in those headers.
    pjsip_method* method = &rdata->msg_info.msg->line.req.method;

    if ((method->id == PJSIP_OTHER_METHOD) &&
        (pj_strcmp2(&method->name, "MESSAGE") == 0))
    {
      TRC_DEBUG("MESSAGE method - pull out In-Reply-To headers");
      pjsip_in_reply_to_hdr* in_reply_to;

      for (in_reply_to = (pjsip_in_reply_to_hdr*)pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                                          &STR_IN_REPLY_TO,
                                                                          NULL);
           in_reply_to != NULL;
           in_reply_to = (pjsip_in_reply_to_hdr*)pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                                          &STR_IN_REPLY_TO,
                                                                          in_reply_to->next))
      {
        TRC_DEBUG("Found In-Reply-To header %.*s", in_reply_to->hvalue.slen, in_reply_to->hvalue.ptr);

        // Split the header value by commas. Each resulting value is a Call-ID.
        std::vector<std::string> in_reply_to_call_ids;
        Utils::split_string(PJUtils::pj_str_to_string(&in_reply_to->hvalue),
                            ',',
                            in_reply_to_call_ids);

        for (std::string cid : in_reply_to_call_ids)
        {
          // Strip any leading and trailing whitespace.
          cid.erase(0, cid.find_first_not_of(' '));
          cid.erase(cid.find_last_not_of(' ') + 1);

          // Append to list of all Call-IDs found so far.
          call_ids.push_back(cid);
        }
      }
    }

    PJUtils::mark_sas_call_branch_ids(trail, rdata->msg_info.msg, call_ids);
  }

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

  if (trail == DONT_LOG_TO_SAS)
  {
    TRC_DEBUG("Skipping SAS logging for OPTIONS response");
    return;
  }
  else if (trail != 0)
  {
    // Raise SAS markers on initial requests only - responses in the same
    // transaction will have the same trail ID so don't need additional markers
    if (tdata->msg->type == PJSIP_REQUEST_MSG)
    {
      PJUtils::report_sas_to_from_markers(trail, tdata->msg);
      PJUtils::mark_sas_call_branch_ids(trail, tdata->msg);
    }

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
    TRC_ERROR("Transmitting message with no SAS trail identifier\n%.*s",
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

  // If a message has parse errors, reject it (if it's a request other than ACK)
  // or drop it (if it's a response or an ACK request).
  if (!pj_list_empty((pj_list_type*)&rdata->msg_info.parse_err))
  {
    SAS::TrailId trail = get_trail(rdata);
    TRC_DEBUG("Report SAS start marker - trail (%llx)", trail);
    SAS::Marker start_marker(trail, MARKER_ID_START, 1u);
    SAS::report_marker(start_marker);

    pjsip_parser_err_report *err = rdata->msg_info.parse_err.next;
    while (err != &rdata->msg_info.parse_err)
    {
      TRC_VERBOSE("Error parsing header %.*s", (int)err->hname.slen, err->hname.ptr);
      SAS::Event event(trail, SASEvent::UNPARSEABLE_HEADER, 0);
      event.add_var_param((int)err->hname.slen, err->hname.ptr);
      SAS::report_event(event);
      err = err->next;
    }

    if (rdata->msg_info.msg->type == PJSIP_REQUEST_MSG)
    {
      if (rdata->msg_info.msg->line.req.method.id == PJSIP_ACK_METHOD)
      {
        TRC_WARNING("Dropping malformed ACK request");
      }
      else
      {
        TRC_WARNING("Rejecting malformed request with a 400 error");
        PJUtils::respond_stateless(stack_data.endpt,
                                   rdata,
                                   PJSIP_SC_BAD_REQUEST,
                                   NULL,
                                   NULL,
                                   NULL);
      }
    }
    else
    {
      TRC_WARNING("Dropping malformed response");
    }

    // As this message is malformed, return PJ_TRUE to absorb it and
    // stop later modules from processing it.
    return PJ_TRUE;
  }
  return PJ_FALSE;
}

static pj_status_t process_on_tx_msg(pjsip_tx_data* tdata)
{
  if ((health_checker != NULL) &&
      (PJSIP_MSG_CSEQ_HDR(tdata->msg)->method.id == PJSIP_INVITE_METHOD) &&
      (tdata->msg->line.status.code == 200))
  {
    // 200 OK to an INVITE - meets S-CSCF health check criteria
    health_checker->health_check_passed();
  }

  // Do logging.
  local_log_tx_msg(tdata);
  sas_log_tx_msg(tdata);

  // Return success so the message gets transmitted.
  return PJ_SUCCESS;
}


pj_status_t
init_common_sip_processing(SNMP::CounterByScopeTable* requests_counter_arg,
                           HealthChecker* health_checker_arg)
{
  // Register the stack modules.
  pjsip_endpt_register_module(stack_data.endpt, &mod_common_processing);
  stack_data.sas_logging_module_id = mod_common_processing.id;

  requests_counter = requests_counter_arg;

  health_checker = health_checker_arg;

  return PJ_SUCCESS;
}


void unregister_common_processing_module(void)
{
  pjsip_endpt_unregister_module(stack_data.endpt, &mod_common_processing);
}
