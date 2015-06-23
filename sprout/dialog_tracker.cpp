/**
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
