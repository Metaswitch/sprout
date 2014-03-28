/**
 * @file trustboundary.h Trust boundary processing.
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
  TrustBoundary(std::string description,
                pj_bool_t strip_request,
                pj_bool_t strip_response,
                pj_bool_t strip_p_charging,
                pj_bool_t add_p_charging,
                pj_bool_t add_p_charging_rsp);

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
  pj_bool_t _strip_p_charging;
  pj_bool_t _add_p_charging;
  pj_bool_t _add_p_charging_rsp;
  std::string _description;

 private:
  // Prevent copying and assignment.
  TrustBoundary(const TrustBoundary&);
  const TrustBoundary& operator=(const TrustBoundary&);
};

