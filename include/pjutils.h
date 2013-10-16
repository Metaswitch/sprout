/**
 * @file pjutils.h Helper functions for working with pjsip types.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * Parts of this header were derived from GPL licensed PJSIP sample code
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

#ifndef PJUTILS_H__
#define PJUTILS_H__

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}

#include <string>
#include <map>
#include "sas.h"

namespace PJUtils {

static const char _b64[64] =
  {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
  };

pj_bool_t is_home_domain(const pjsip_uri* uri);
pj_bool_t is_uri_local(const pjsip_uri* uri);

pj_bool_t is_e164(const pj_str_t* user);
pj_bool_t is_e164(const pjsip_uri* uri);

pj_str_t uri_to_pj_str(pjsip_uri_context_e context,
                       const pjsip_uri* uri,
                       pj_pool_t* pool);

std::string uri_to_string(pjsip_uri_context_e context,
                          const pjsip_uri* uri);

pjsip_uri* uri_from_string(const std::string& uri_s,
                           pj_pool_t* pool,
                           pj_bool_t force_name_addr=false);

std::string pj_str_to_string(const pj_str_t* pjstr);

std::string pj_status_to_string(const pj_status_t status);

std::string aor_from_uri(const pjsip_sip_uri* uri);

std::string public_id_from_uri(const pjsip_uri* uri);

typedef enum {NO, YES, TLS_YES, TLS_PENDING, IP_ASSOC_YES, IP_ASSOC_PENDING, AUTH_DONE} Integrity;
void add_integrity_protected_indication(pjsip_tx_data* tdata, PJUtils::Integrity integrity);

void add_asserted_identity(pjsip_tx_data* tdata, const std::string& aid);

pjsip_routing_hdr* identity_hdr_create(pj_pool_t* pool, const pj_str_t& name);

pjsip_uri* next_hop(pjsip_msg* msg);

pj_bool_t is_next_route_local(const pjsip_msg* msg, pjsip_route_hdr* start, pjsip_route_hdr** hdr);

/// Checks whether the top route header in the message refers to this node,
/// and optionally returns the headers.  If there no Route headers it returns
/// false.
inline pj_bool_t is_top_route_local(const pjsip_msg* msg, pjsip_route_hdr** hdr)
{
  return is_next_route_local(msg, NULL, hdr);
}

void add_record_route(pjsip_tx_data* tdata, const char* transport, int port, const char* user, const pj_str_t& host);

void delete_header(pjsip_msg* msg,
                   const pj_str_t* name);

void set_generic_header(pjsip_tx_data* tdata,
                        const pj_str_t* name,
                        const pj_str_t* value);

pj_bool_t msg_supports_extension(pjsip_msg* msg, const char* extension);

pj_bool_t is_first_hop(pjsip_msg* msg);

int max_expires(pjsip_msg* msg, int default_expires);

pj_status_t create_response(pjsip_endpoint *endpt,
      		      const pjsip_rx_data *rdata,
      		      int st_code,
      		      const pj_str_t *st_text,
      		      pjsip_tx_data **p_tdata);

pj_status_t create_request_fwd(pjsip_endpoint *endpt,
                               pjsip_rx_data *rdata,
                               const pjsip_uri *uri,
                               const pj_str_t *branch,
                               unsigned options,
                               pjsip_tx_data **p_tdata);

pj_status_t create_response_fwd(pjsip_endpoint *endpt,
                                pjsip_rx_data *rdata,
                                unsigned options,
                                pjsip_tx_data **p_tdata);

pj_status_t send_request(pjsip_endpoint* endpt,
                         pjsip_tx_data* tdata);

pj_status_t respond_stateless(pjsip_endpoint* endpt,
                              pjsip_rx_data* rdata,
                              int st_code,
                              const pj_str_t* st_text,
                              const pjsip_hdr* hdr_list,
                              const pjsip_msg_body* body);

pj_status_t respond_stateful(pjsip_endpoint* endpt,
                             pjsip_transaction* uas_tsx,
                             pjsip_rx_data* rdata,
                             int st_code,
                             const pj_str_t* st_text,
                             const pjsip_hdr* hdr_list,
                             const pjsip_msg_body* body);

pjsip_tx_data *clone_tdata(pjsip_tx_data *tdata);
void clone_header(const pj_str_t* hdr_name, pjsip_msg* old_msg, pjsip_msg* new_msg, pj_pool_t* pool);

bool compare_pj_sockaddr(const pj_sockaddr& lhs, const pj_sockaddr& rhs);

typedef std::map<pj_sockaddr, bool, bool(*)(const pj_sockaddr&, const pj_sockaddr&)> host_list_t;

void create_random_token(size_t length, std::string& token);

std::string get_header_value(pjsip_hdr*);

} // namespace PJUtils

#endif
