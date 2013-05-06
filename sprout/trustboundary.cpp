/**
 * @file trustboundary.cpp Trust boundary processing
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
#include <stdint.h>
}

#include <string>

#include "log.h"
#include "constants.h"
#include "trustboundary.h"

/// Strip headers as appropriate when crossing a trust boundary.
static void proxy_strip_trusted(pjsip_tx_data *tdata)
{
  LOG_DEBUG("Strip trusted headers");

  // Strip P-Access-Network-Info header if present.
  pjsip_generic_string_hdr* hdr = (pjsip_generic_string_hdr*)
    pjsip_msg_find_hdr_by_name(tdata->msg, &STR_P_A_N_I, NULL);

  if (hdr != NULL)
  {
    pj_list_erase(hdr);
  }
}

TrustBoundary::TrustBoundary(std::string description, pj_bool_t strip_request, pj_bool_t strip_response) :
  _strip_request(strip_request),
  _strip_response(strip_response),
  _description(description)
{
}

void TrustBoundary::process_request(pjsip_tx_data* tdata)
{
  if (_strip_request)
  {
    proxy_strip_trusted(tdata);
  }
}

void TrustBoundary::process_response(pjsip_tx_data* tdata)
{
  if (_strip_response)
  {
    proxy_strip_trusted(tdata);
  }
}

void TrustBoundary::process_stateless_message(pjsip_tx_data* tdata)
{
  LOG_DEBUG("Strip trusted headers - stateless");
  proxy_strip_trusted(tdata);
}

std::string TrustBoundary::to_string()
{
  return _description + "(" + (_strip_request  ? "-req" : "") +
                        "," + (_strip_response ? "-rsp" : "") + ")";
}

/// Trust boundary instance: no boundary;
TrustBoundary TrustBoundary::TRUSTED("TRUSTED", false, false);

/// Trust boundary instance: from client to core.  Allow client to
/// provide trusted data to the core, but don't allow it to see
/// the core's internal data. I.e., strip from responses.
TrustBoundary TrustBoundary::INBOUND_EDGE_CLIENT("INBOUND_EDGE_CLIENT", false, true);

/// Trust boundary instance: from core to client.  Allow client to
/// provide trusted data to the core, but don't allow it to see
/// the core's internal data. I.e., strip from requests.
TrustBoundary TrustBoundary::OUTBOUND_EDGE_CLIENT("OUTBOUND_EDGE_CLIENT", true, false);

/// Trust boundary instance: edge processing, but we don't know which
/// direction. Don't allow trusted data to pass in either direction.
TrustBoundary TrustBoundary::UNKNOWN_EDGE_CLIENT("UNKNOWN_EDGE_CLIENT", true, true);

/// Trust boundary instance: from trunk to core.  Don't allow
/// trusted data to pass in either direction.
TrustBoundary TrustBoundary::INBOUND_TRUNK("INBOUND_TRUNK", true, true);

/// Trust boundary instance: from core to trunk.  Don't allow
/// trusted data to pass in either direction.
TrustBoundary TrustBoundary::OUTBOUND_TRUNK("OUTBOUND_TRUNK", true, true);

