/**
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "dialog_tracker.hpp"
#include "pjutils.h"
#include "log.h"

// Called when a UASTransaction completes in edge proxy mode.
// Checks whether this transaction starts or ends a dialog, and takes
// appropriate action.

// The check is only heuristic - we aren't actually dialog-stateful,
// and this could produce erroneous results if there are spurious BYEs
// outside a dialog or if both endpoints fail (and so never send BYEs).
void DialogTracker::on_uas_tsx_complete(const pjsip_tx_data* original_request,
                                        // The original INVITE sent or
                                        // received
                                        const pjsip_transaction* tsx,
                                        // Current transaction
                                        const pjsip_event* event,
                                        // Transaction event which
                                        // triggered this call to DialogTracker
                                        bool is_client
                                        // true if the endpoint is a
                                        // client, false if it is Sprout,
                                        // an IBCF peer, or if we
                                        // can't tell
  )
{
  // Consider a dialog started if we have a 200 OK response to an
  // INVITE, and there was no To tag on the initial INVITE (in other
  // words, if it's not a reINVITE).
  if ((tsx->method.id == PJSIP_INVITE_METHOD) &&
      (tsx->status_code == 200) &&
      (PJSIP_MSG_TO_HDR(original_request->msg)->tag.slen == 0))
  {
    on_dialog_start(original_request, tsx, event, is_client);
  }
  // Consider a dialog finished whenever we respond to a BYE - any
  // response to a BYE, even an error, is considered to end a dialog.
  else if (tsx->method.id == PJSIP_BYE_METHOD)
  {
    on_dialog_end(original_request, tsx, event, is_client);
  }
}

void DialogTracker::on_dialog_start(const pjsip_tx_data* original_request,
                                    const pjsip_transaction* tsx,
                                    const pjsip_event* event,
                                    bool is_client)
{
  // Note that getting the flow increments its reference count, so we
  // need to call dec_ref before we return.
  Flow* client_flow = get_client_flow(original_request, tsx, event, is_client);
  if (client_flow != NULL) {
    client_flow->increment_dialogs();
    client_flow->dec_ref();
  }
}

void DialogTracker::on_dialog_end(const pjsip_tx_data* original_request,
                                  const pjsip_transaction* tsx,
                                  const pjsip_event* event,
                                  bool is_client)
{
  // Note that getting the flow increments its reference count, so we
  // need to call dec_ref before we return.
  Flow* client_flow = get_client_flow(original_request, tsx, event, is_client);
  if (client_flow != NULL) {
    client_flow->decrement_dialogs();
    client_flow->dec_ref();
  }
}

Flow* DialogTracker::get_client_flow(const pjsip_tx_data* original_request,
                                     const pjsip_transaction* tsx,
                                     const pjsip_event* event,
                                     bool is_client)
{
  if (!is_client)
  {
    // We expect to find our flow token on the Route header (for
    // requests) or the Record-Route header (for responses), so check both.
    pjsip_routing_hdr* route_hdr = (pjsip_routing_hdr*)pjsip_msg_find_hdr(original_request->msg,
                                                                          PJSIP_H_ROUTE,
                                                                          NULL);
    if (route_hdr == NULL)
    {
      route_hdr = (pjsip_routing_hdr*)pjsip_msg_find_hdr(original_request->msg,
                                                         PJSIP_H_RECORD_ROUTE,
                                                         NULL);
    }

    if (route_hdr == NULL) {
      // LCOV_EXCL_START - doesn't happen in UT, and would require a
      // carefully constructed 200 OK message.
      TRC_ERROR("No Route or Record-Route header found - cannot deduce the flow");
      return NULL;
      // LCOV_EXCL_STOP
    }

    pjsip_sip_uri* sip_path_uri = (pjsip_sip_uri*)route_hdr->name_addr.uri;
    return _ft->find_flow(PJUtils::pj_str_to_string(&sip_path_uri->user));
  }
  else
  {
    return _ft->find_flow(tsx->transport,
                          &tsx->addr);
  }

}
