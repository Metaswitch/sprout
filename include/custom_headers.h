/**
 * @file custom_headers.h PJSIP custom header definitions and functions.
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

#ifndef CUSTOM_HEADERS_H__
#define CUSTOM_HEADERS_H__

extern "C" {
#include <pjsip.h>
}

// Main entry point
pj_status_t register_custom_headers();

// Utility macro from sip_parser.c
#define copy_advance(buf,str)                   \
  do {                                          \
    if ((str).slen >= (endbuf-buf)) return -1;  \
    pj_memcpy(buf, (str).ptr, (str).slen);      \
    buf += (str).slen;                          \
  } while (0)

/// Custom header structures.

enum session_refresher_t
{
  SESSION_REFRESHER_UNKNOWN,
  SESSION_REFRESHER_UAC,
  SESSION_REFRESHER_UAS,
};

typedef struct pjsip_session_expires_hdr {
  PJSIP_DECL_HDR_MEMBER(struct pjsip_session_expires_hdr);
  pj_int32_t expires;
  session_refresher_t refresher;
  pjsip_param other_param;
} pjsip_session_expires_hdr;

typedef struct pjsip_min_se_hdr {
  PJSIP_DECL_HDR_MEMBER(struct pjsip_min_se_hdr);
  pj_int32_t expires;
  session_refresher_t refresher;
  pjsip_param other_param;
} pjsip_min_se_hdr;

typedef struct pjsip_p_c_v_hdr {
  PJSIP_DECL_HDR_MEMBER(struct pjsip_p_c_v_hdr);
  pj_str_t icid;
  pj_str_t icid_gen_addr;
  pj_str_t orig_ioi;
  pj_str_t term_ioi;
  pjsip_param other_param;
} pjsip_p_c_v_hdr;

typedef struct pjsip_p_c_f_a_hdr {
  PJSIP_DECL_HDR_MEMBER(struct pjsip_p_c_f_a_hdr);
  pjsip_param ccf;
  pjsip_param ecf;
  pjsip_param other_param;
} pjsip_p_c_f_a_hdr;

typedef struct pjsip_accept_contact_hdr {
  PJSIP_DECL_HDR_MEMBER(struct pjsip_accept_contact_hdr);
  bool required_match;
  bool explicit_match;
  pjsip_param feature_set;
} pjsip_accept_contact_hdr;

typedef struct pjsip_reject_contact_hdr {
  PJSIP_DECL_HDR_MEMBER(struct pjsip_reject_contact_hdr);
  pjsip_param feature_set;
} pjsip_reject_contact_hdr;

/// Utility functions (parse, create, init, clone, print_on)

// Privacy
pjsip_hdr* parse_hdr_privacy(pjsip_parse_ctx* ctx);

// Assocciated URI
pjsip_hdr* parse_hdr_p_associated_uri(pjsip_parse_ctx* ctx);

// Session-Expires
pjsip_hdr* parse_hdr_session_expires(pjsip_parse_ctx* ctx);
pjsip_session_expires_hdr* pjsip_session_expires_hdr_create(pj_pool_t* pool);
pjsip_session_expires_hdr* pjsip_session_expires_hdr_init(pj_pool_t* pool, void* mem);
void* pjsip_session_expires_hdr_clone(pj_pool_t* pool, const void* o);
void* pjsip_session_expires_hdr_shallow_clone(pj_pool_t* pool, const void* o);
int pjsip_session_expires_hdr_print_on(void *hdr, char* buf, pj_size_t len);

// Min-SE
pjsip_hdr* parse_hdr_min_se(pjsip_parse_ctx* ctx);
pjsip_min_se_hdr* pjsip_min_se_hdr_create(pj_pool_t* pool);
pjsip_min_se_hdr* pjsip_min_se_hdr_init(pj_pool_t* pool, void* mem);
void* pjsip_min_se_hdr_clone(pj_pool_t* pool, const void* o);
void* pjsip_min_se_hdr_shallow_clone(pj_pool_t* pool, const void* o);
int pjsip_min_se_hdr_print_on(void *hdr, char* buf, pj_size_t len);

// Preferred/Asserted Identity
pjsip_hdr* parse_hdr_p_asserted_identity(pjsip_parse_ctx* ctx);
pjsip_hdr* parse_hdr_p_preferred_identity(pjsip_parse_ctx* ctx);
pjsip_routing_hdr* identity_hdr_create(pj_pool_t* pool, const pj_str_t name);
pjsip_routing_hdr* identity_hdr_init(pj_pool_t* pool, void* mem, const pj_str_t name);
void* identity_hdr_clone(pj_pool_t* pool, const void* rhs);
void* identity_hdr_shallow_clone(pj_pool_t* pool, const void* rhs);
int identity_hdr_print(void* hdr, char* buf, pj_size_t size);

// Service-Route
pjsip_hdr* parse_hdr_service_route(pjsip_parse_ctx* ctx);

// Path
pjsip_hdr* parse_hdr_path(pjsip_parse_ctx *ctx);

// Charging Vector
pjsip_hdr* parse_hdr_p_charging_vector(pjsip_parse_ctx* ctx);
pjsip_p_c_v_hdr* pjsip_p_c_v_hdr_create(pj_pool_t* pool);
pjsip_p_c_v_hdr* pjsip_p_c_v_hdr_init(pj_pool_t* pool, void* mem);
void* pjsip_p_c_v_hdr_clone(pj_pool_t* pool, const void* o);
void* pjsip_p_c_v_hdr_shallow_clone(pj_pool_t* pool, const void* o);
int pjsip_p_c_v_hdr_print_on(void *hdr, char* buf, pj_size_t len);

// Charging Function Address
pjsip_hdr* parse_hdr_p_charging_function_addresses(pjsip_parse_ctx* ctx);
pjsip_p_c_f_a_hdr* pjsip_p_c_f_a_hdr_create(pj_pool_t* pool);
pjsip_p_c_f_a_hdr* pjsip_p_c_f_a_hdr_init(pj_pool_t* pool, void* mem);
void* pjsip_p_c_f_a_hdr_clone(pj_pool_t* pool, const void* o);
void* pjsip_p_c_f_a_hdr_shallow_clone(pj_pool_t* pool, const void* o);
int pjsip_p_c_f_a_hdr_print_on(void *hdr, char* buf, pj_size_t len);

// Reject-Contact
pjsip_hdr* parse_hdr_reject_contact(pjsip_parse_ctx* ctx);
pjsip_reject_contact_hdr* pjsip_reject_contact_hdr_create(pj_pool_t* pool);
pjsip_reject_contact_hdr* pjsip_reject_contact_hdr_init(pj_pool_t* pool, void* mem);
void* pjsip_reject_contact_hdr_clone(pj_pool_t* pool, const void* o);
void* pjsip_reject_contact_hdr_shallow_clone(pj_pool_t* pool, const void* o);
int pjsip_reject_contact_hdr_print_on(void* hdr, char* buf, pj_size_t len);

// Accept-Contact
pjsip_hdr* parse_hdr_accept_contact(pjsip_parse_ctx* ctx);
pjsip_accept_contact_hdr* pjsip_accept_contact_hdr_create(pj_pool_t* pool);
pjsip_accept_contact_hdr* pjsip_accept_contact_hdr_init(pj_pool_t* pool, void* mem);
void* pjsip_accept_contact_hdr_clone(pj_pool_t* pool, const void* o);
void* pjsip_accept_contact_hdr_shallow_clone(pj_pool_t* pool, const void* o);
int pjsip_accept_contact_hdr_print_on(void* hdr, char* buf, pj_size_t len);

#endif
