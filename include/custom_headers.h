/**
 * @file custom_headers.h PJSIP custom header definitions and functions.
 *
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef CUSTOM_HEADERS_H__
#define CUSTOM_HEADERS_H__

extern "C" {
#include <pjsip.h>
#include <pjsip/print_util.h>
}

// Main entry point
pj_status_t register_custom_headers();

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
pjsip_generic_array_hdr* pjsip_privacy_hdr_create( pj_pool_t *pool, const pj_str_t *hnames);
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

// Common method for parsing Accept-Contact and Reject-Contact headers
pjsip_hdr* parse_hdr_accept_or_reject_contact(pjsip_parse_ctx* ctx, bool accept);

// Resource-Priority
pjsip_hdr* parse_hdr_resource_priority(pjsip_parse_ctx* ctx);
pjsip_generic_array_hdr* pjsip_resource_priority_hdr_create(pj_pool_t* pool);

#endif
