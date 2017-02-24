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
#include <pjmedia.h>
#include <stdint.h>
}

#include <string>
#include <map>
#include <deque>
#include "sas.h"
#include "sipresolver.h"
#include "enumservice.h"
#include "uri_classifier.h"
#include "acr.h"

namespace PJUtils {

pj_status_t init();
void term();

pj_bool_t is_e164(const pj_str_t* user);
pj_bool_t is_e164(const pjsip_uri* uri);

pj_str_t uri_to_pj_str(pjsip_uri_context_e context,
                       const pjsip_uri* uri,
                       pj_pool_t* pool);

std::string uri_to_string(pjsip_uri_context_e context,
                          const pjsip_uri* uri);

std::string strip_uri_scheme(const std::string& uri);

pjsip_uri* uri_from_string(const std::string& uri_s,
                           pj_pool_t* pool,
                           pj_bool_t force_name_addr=false);

std::string pj_str_to_string(const pj_str_t* pjstr);

std::string pj_str_to_unquoted_string(const pj_str_t* pjstr);

std::string pj_status_to_string(const pj_status_t status);

std::string hdr_to_string(void* hdr);

std::string extract_username(pjsip_authorization_hdr* auth_hdr, pjsip_uri* impu_uri);

std::string public_id_from_uri(const pjsip_uri* uri);

std::string default_private_id_from_uri(const pjsip_uri* uri);

pj_str_t domain_from_uri(const std::string& uri_str, pj_pool_t* pool);

pjsip_uri* orig_served_user(pjsip_msg* msg);

pjsip_uri* term_served_user(pjsip_msg* msg);

typedef enum {NO, YES, TLS_YES, TLS_PENDING, IP_ASSOC_YES, IP_ASSOC_PENDING, AUTH_DONE} Integrity;
void add_integrity_protected_indication(pjsip_tx_data* tdata, PJUtils::Integrity integrity);
void add_proxy_auth_for_pbx(pjsip_tx_data* tdata);
void add_pvni(pjsip_tx_data* tdata, pj_str_t* network_id);

void add_asserted_identity(pjsip_msg* msg, pj_pool_t* pool, const std::string& aid, const pj_str_t& display_name);
void add_asserted_identity(pjsip_tx_data* tdata, const std::string& aid);

void get_impi_and_impu(pjsip_msg* req, std::string& impi_out, std::string& impu_out);

pjsip_uri* next_hop(pjsip_msg* msg);

pj_bool_t is_next_route_local(const pjsip_msg* msg, pjsip_route_hdr* start, pjsip_route_hdr** hdr);

pj_bool_t is_top_rr_local(const pjsip_msg* msg);

/// Checks whether the top route header in the message refers to this node,
/// and optionally returns the headers.  If there no Route headers it returns
/// false.
inline pj_bool_t is_top_route_local(const pjsip_msg* msg, pjsip_route_hdr** hdr)
{
  return is_next_route_local(msg, NULL, hdr);
}

void add_record_route(pjsip_tx_data* tdata, const char* transport, int port, const char* user, const pj_str_t& host);

void add_top_route_header(pjsip_msg* msg, pjsip_sip_uri* uri, pj_pool_t* pool);

void add_route_header(pjsip_msg* msg, pjsip_sip_uri* uri, pj_pool_t* pool);

void remove_hdr(pjsip_msg* msg,
                const pj_str_t* name);

void set_generic_header(pjsip_tx_data* tdata,
                        const pj_str_t* name,
                        const pj_str_t* value);

pj_bool_t msg_supports_extension(pjsip_msg* msg, const char* extension);

pj_bool_t is_first_hop(pjsip_msg* msg);

bool get_max_expires(pjsip_msg* msg, int default_expires, int& max_expires);

bool is_deregistration(pjsip_msg* msg);

pjsip_tx_data* clone_msg(pjsip_endpoint* endpt,
                         pjsip_rx_data* rdata);

pjsip_tx_data* clone_msg(pjsip_endpoint* endpt,
                         pjsip_tx_data* tdata);

pj_status_t create_response(pjsip_endpoint *endpt,
                      const pjsip_rx_data *rdata,
                      int st_code,
                      const pj_str_t* st_text,
                      pjsip_tx_data **p_tdata);

pj_status_t create_response(pjsip_endpoint *endpt,
                            const pjsip_tx_data *tdata,
                            int st_code,
                      const pj_str_t* st_text,
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

pjsip_tx_data* create_cancel(pjsip_endpoint* endpt,
                             pjsip_tx_data* tdata,
                             int reason_code);

pjsip_tx_data* create_ack(pjsip_endpoint* endpt,
                          pjsip_msg* req,
                          pjsip_msg* rsp);

void resolve(const std::string& name,
             int port,
             int transport,
             int retries,
             std::vector<AddrInfo>& servers);

void resolve_next_hop(pjsip_tx_data* tdata,
                      int retries,
                      std::vector<AddrInfo>& servers,
                      SAS::TrailId trail);

void blacklist_server(AddrInfo& server);

void set_dest_info(pjsip_tx_data* tdata, const AddrInfo& ai);

void generate_new_branch_id(pjsip_tx_data* tdata);

pj_status_t send_request(pjsip_tx_data* tdata,
                         int retries=0,
                         void* token=NULL,
                         pjsip_endpt_send_callback cb=NULL,
                         bool log_sas_branch = false);

pj_status_t send_request_stateless(pjsip_tx_data* tdata,
                                   int retries=0);

pj_status_t respond_stateless(pjsip_endpoint* endpt,
                              pjsip_rx_data* rdata,
                              int st_code,
                              const pj_str_t* st_text = NULL,
                              const pjsip_hdr* hdr_list = NULL,
                              const pjsip_msg_body* body = NULL,
                              ACR* acr = NULL);

pj_status_t respond_stateful(pjsip_endpoint* endpt,
                             pjsip_transaction* uas_tsx,
                             pjsip_rx_data* rdata,
                             int st_code,
                             const pj_str_t* st_text = NULL,
                             const pjsip_hdr* hdr_list = NULL,
                             const pjsip_msg_body* body = NULL,
                             ACR* acr = NULL);

pjsip_tx_data *clone_tdata(pjsip_tx_data* tdata);
void clone_header(const pj_str_t* hdr_name, pjsip_msg* old_msg, pjsip_msg* new_msg, pj_pool_t* pool);

void add_top_via(pjsip_tx_data* tdata);

void remove_top_via(pjsip_tx_data* tdata);

void add_reason(pjsip_tx_data* tdata, int reason_code);

bool compare_pj_sockaddr(const pj_sockaddr& lhs, const pj_sockaddr& rhs);

typedef std::map<pj_sockaddr, bool, bool(*)(const pj_sockaddr&, const pj_sockaddr&)> host_list_t;

void create_random_token(size_t length, std::string& token);

std::string get_header_value(pjsip_hdr*);

void mark_sas_call_branch_ids(const SAS::TrailId trail, pjsip_cid_hdr* cid_hdr, pjsip_msg* msg);

bool is_emergency_registration(pjsip_contact_hdr* contact_hdr);

bool check_route_headers(pjsip_msg* msg);
bool check_route_headers(pjsip_rx_data* rdata);

void put_unary_param(pjsip_param* params_list,
                     const pj_str_t* name,
                     pj_pool_t* pool);

pjsip_status_code redirect(pjsip_msg* msg, std::string target, pj_pool_t* pool, pjsip_status_code code);
pjsip_status_code redirect(pjsip_msg* msg, pjsip_uri* target, pj_pool_t* pool, pjsip_status_code code);
pjsip_status_code redirect_int(pjsip_msg* msg, pjsip_uri* target, pj_pool_t* pool, pjsip_status_code code);

pjsip_history_info_hdr* create_history_info_hdr(pjsip_uri* target, pj_pool_t* pool);
void update_history_info_reason(pjsip_uri* history_info_uri, pj_pool_t* pool, int code);

pj_str_t user_from_uri(const pjsip_uri* uri);

void report_sas_to_from_markers(SAS::TrailId trail, pjsip_msg* msg);

void add_pcfa_header(pjsip_msg* msg,
                     pj_pool_t* pool,
                     const std::deque<std::string>& ccfs,
                     const std::deque<std::string>& ecfs,
                     const bool replace);

pjsip_uri* translate_sip_uri_to_tel_uri(const pjsip_sip_uri* sip_uri,
                                        pj_pool_t* pool);

std::string remove_visual_separators(const std::string& user);
std::string remove_visual_separators(const pj_str_t& number);

bool get_npdi(pjsip_uri* uri);
bool get_rn(pjsip_uri* uri, std::string& routing_value);
pjsip_param* get_userpart_param(pjsip_uri* uri, pj_str_t param);

void translate_request_uri(pjsip_msg* req,
                           pj_pool_t* pool,
                           EnumService* enum_service,
                           bool should_override_npdi,
                           SAS::TrailId trail);

void update_request_uri_np_data(pjsip_msg* req,
                                pj_pool_t* pool,
                                EnumService* enum_service,
                                bool should_override_npdi,
                                SAS::TrailId trail);

bool should_update_np_data(URIClass old_uri_class,
                           URIClass new_uri_class,
                           std::string& new_uri_str,
                           bool should_override_npdi,
                           SAS::TrailId trail);

// Get a string representation of the top routing header (or the
// request URI if there's no route headers). This can return
// an empty string (if the header isn't a valid URI), so callers
// should validate the result.
std::string get_next_routing_header(const pjsip_msg* msg);

// Gets the media types specified in the SDP on the message.  Currently only
// looks for Audio and Video media types.
std::set<pjmedia_type> get_media_types(const pjsip_msg *msg);

// Get the next routing URI - this is the top routing header (or the
// request URI if there's no route headers), and it's context.
// The URI returned is only valid while the passed in PJSIP message is valid
pjsip_uri* get_next_routing_uri(const pjsip_msg* msg,
                                pjsip_uri_context_e* context);
} // namespace PJUtils

#endif
