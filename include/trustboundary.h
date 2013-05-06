/**
 * @file trustboundary.h Trust boundary processing.
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

///
///

#pragma once

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}

#include <string>

/// Encapsulates the transformations applied as we cross a potential
/// trust boundary.
class TrustBoundary
{
public:
  TrustBoundary(std::string description, pj_bool_t strip_request, pj_bool_t strip_response);

  /// Strip as necessary for request from server to client.
  void process_request(pjsip_tx_data* tdata);

  /// Strip as necessary for response from client to server.
  void process_response(pjsip_tx_data* tdata);

  /// Printable description of boundary, for debugging.
  std::string to_string();

  /// Stateless message: we don't know how much to strip, so play it
  /// safe.
  static void process_stateless_message(pjsip_tx_data* tdata);

  static TrustBoundary TRUSTED;
  static TrustBoundary INBOUND_EDGE_CLIENT;
  static TrustBoundary OUTBOUND_EDGE_CLIENT;
  static TrustBoundary UNKNOWN_EDGE_CLIENT;
  static TrustBoundary INBOUND_TRUNK;
  static TrustBoundary OUTBOUND_TRUNK;

protected:
  pj_bool_t _strip_request;
  pj_bool_t _strip_response;
  std::string _description;

 private:
  // Prevent copying and assignment.
  TrustBoundary(const TrustBoundary&);
  const TrustBoundary& operator=(const TrustBoundary&);
};

