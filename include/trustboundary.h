/**
 * @file trustboundary.h Trust boundary processing.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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

