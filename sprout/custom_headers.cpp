/**
 * @file custom_headers.cpp Implementations for custom SIP header handling
 * functions.
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

extern "C" {
  #include <pjsip.h>
}

#include "pjutils.h"
#include "constants.h"
#include "custom_headers.h"


/// Custom parser for Privacy header.  This is registered with PJSIP when
/// we initialize the stack.
pjsip_hdr* parse_hdr_privacy(pjsip_parse_ctx *ctx)
{
  pjsip_generic_array_hdr *privacy = pjsip_generic_array_hdr_create(ctx->pool, &STR_PRIVACY);
  pjsip_parse_generic_array_hdr_imp(privacy, ctx->scanner);
  return (pjsip_hdr*)privacy;
}

typedef void* (*clone_fptr)(pj_pool_t *, const void*);
typedef int   (*print_fptr)(void *hdr, char *buf, pj_size_t len);

pjsip_hdr_vptr identity_hdr_vptr =
{
  (clone_fptr) &identity_hdr_clone,
  (clone_fptr) &identity_hdr_shallow_clone,
  (print_fptr) &identity_hdr_print,
};


/// Custom create, clone and print functions used for the P-Associated-URI,
/// P-Asserted-Identity and P-Preferred-Identity headers
int identity_hdr_print(pjsip_routing_hdr *hdr,
                              char *buf,
                              pj_size_t size)
{
  int printed;
  char *startbuf = buf;
  char *endbuf = buf + size;
  const pjsip_parser_const_t *pc = pjsip_parser_const();

  /* Route and Record-Route don't compact forms */
  copy_advance(buf, hdr->name);
  *buf++ = ':';
  *buf++ = ' ';

  printed = pjsip_uri_print(PJSIP_URI_IN_FROMTO_HDR,
                            &hdr->name_addr,
                            buf,
                            endbuf-buf);
  if (printed < 1)
  {
    return -1;
  }
  buf += printed;

  printed = pjsip_param_print_on(&hdr->other_param, buf, endbuf-buf,
                                 &pc->pjsip_TOKEN_SPEC,
                                 &pc->pjsip_TOKEN_SPEC, ';');
  if (printed < 0)
  {
    return -1;
  }
  buf += printed;

  return buf-startbuf;
}


pjsip_routing_hdr* identity_hdr_clone(pj_pool_t *pool,
                                      const pjsip_routing_hdr *rhs)
{
  pjsip_routing_hdr *hdr = PJUtils::identity_hdr_create(pool, rhs->name);
  pjsip_name_addr_assign(pool, &hdr->name_addr, &rhs->name_addr);
  pjsip_param_clone(pool, &hdr->other_param, &rhs->other_param);
  return hdr;
}


pjsip_routing_hdr* identity_hdr_shallow_clone(pj_pool_t *pool,
                                              const pjsip_routing_hdr *rhs)
{
  pjsip_routing_hdr *hdr = PJ_POOL_ALLOC_T(pool, pjsip_routing_hdr);
  pj_memcpy(hdr, rhs, sizeof(*hdr));
  pjsip_param_shallow_clone(pool, &hdr->other_param, &rhs->other_param);
  return hdr;
}


/// Custom parser for P-Associated-URI header.  This is registered with PJSIP when
/// we initialize the stack.
pjsip_hdr* parse_hdr_p_associated_uri(pjsip_parse_ctx *ctx)
{
  // The P-Associated-URI header is a comma separated list of name-addrs
  // with optional parameters, so we parse it to multiple header structures,
  // using the pjsip_route_hdr structure for each.
  pjsip_route_hdr *first = NULL;
  pj_scanner *scanner = ctx->scanner;

  do
  {
    pjsip_route_hdr *hdr = PJUtils::identity_hdr_create(ctx->pool, STR_P_ASSOCIATED_URI);
    if (!first)
    {
      first = hdr;
    }
    else
    {
      pj_list_insert_before(first, hdr);
    }
    pjsip_name_addr *temp = pjsip_parse_name_addr_imp(scanner, ctx->pool);

    pj_memcpy(&hdr->name_addr, temp, sizeof(*temp));

    while (*scanner->curptr == ';')
    {
      pjsip_param *p = PJ_POOL_ALLOC_T(ctx->pool, pjsip_param);
      pjsip_parse_param_imp(scanner, ctx->pool, &p->name, &p->value, 0);
      pj_list_insert_before(&hdr->other_param, p);
    }

    if (*scanner->curptr == ',')
    {
      pj_scan_get_char(scanner);
    }
    else
    {
      break;
    }
  } while (1);
  pjsip_parse_end_hdr_imp(scanner);

  return (pjsip_hdr*)first;
}


/// Custom parser for P-Asserted-Identity header.  This is registered with PJSIP when
/// we initialize the stack.
pjsip_hdr* parse_hdr_p_asserted_identity(pjsip_parse_ctx *ctx)
{
  // The P-Asserted-Identity header is a comma separated list of name-addrs
  // so we parse it to multiple header structures, using the pjsip_route_hdr
  // structure for each.  Note that P-Asserted-Identity cannot have parameters
  // after the name-addr.
  pjsip_route_hdr *first = NULL;
  pj_scanner *scanner = ctx->scanner;

  do
  {
    pjsip_route_hdr *hdr = PJUtils::identity_hdr_create(ctx->pool, STR_P_ASSERTED_IDENTITY);
    if (!first)
    {
      first = hdr;
    }
    else
    {
      pj_list_insert_before(first, hdr);
    }
    pjsip_name_addr *temp = pjsip_parse_name_addr_imp(scanner, ctx->pool);

    pj_memcpy(&hdr->name_addr, temp, sizeof(*temp));

    if (*scanner->curptr == ',')
    {
      pj_scan_get_char(scanner);
    }
    else
    {
      break;
    }
  } while (1);
  pjsip_parse_end_hdr_imp(scanner);

  return (pjsip_hdr*)first;
}


/// Custom parser for P-Preferred-Identity header.  This is registered with PJSIP when
/// we initialize the stack.
pjsip_hdr* parse_hdr_p_preferred_identity(pjsip_parse_ctx *ctx)
{
  // The P-Preferred-Identity header is a comma separated list of name-addrs
  // so we parse it to multiple header structures, using the pjsip_route_hdr
  // structure for each.  Note that P-Preferred-Identity cannot have parameters
  // after the name-addr.
  pjsip_route_hdr *first = NULL;
  pj_scanner *scanner = ctx->scanner;

  do
  {
    pjsip_route_hdr *hdr = PJUtils::identity_hdr_create(ctx->pool, STR_P_PREFERRED_IDENTITY);
    if (!first)
    {
      first = hdr;
    }
    else
    {
      pj_list_insert_before(first, hdr);
    }
    pjsip_name_addr *temp = pjsip_parse_name_addr_imp(scanner, ctx->pool);

    pj_memcpy(&hdr->name_addr, temp, sizeof(*temp));

    if (*scanner->curptr == ',')
    {
      pj_scan_get_char(scanner);
    }
    else
    {
      break;
    }
  } while (1);
  pjsip_parse_end_hdr_imp(scanner);

  return (pjsip_hdr*)first;
}

pjsip_hdr* parse_hdr_p_charging_vector(pjsip_parse_ctx* ctx)
{
  // The P-Charging-Vector header has the following ABNF:
  //
  // P-Charging-Vector     = "P-Charging-Vector" HCOLON icid-value
  //                         *(SEMI charge-params)
  // charge-params         = icid-gen-addr / orig-ioi /
  //                         term-ioi / generic-param
  // icid-value            = "icid-value" EQUAL gen-value
  // icid-gen-addr         = "icid-generated-at" EQUAL host
  // orig-ioi              = "orig-ioi" EQUAL gen-value
  // term-ioi              = "term-ioi" EQUAL gen-value
  //
  // With the proviso that the ICID parameter must be set.

  pj_pool_t* pool = ctx->pool;
  pj_scanner* scanner = ctx->scanner;
  pjsip_p_c_v_hdr* hdr = pjsip_p_c_v_hdr_create(pool);
  pj_str_t temp_newline;

  do {
    pj_scan_peek_n(scanner, 1, &temp_newline);
    if ((*temp_newline.ptr == '\r') || (*temp_newline.ptr == '\n')) {
      break;
    } else if (pj_scan_stricmp(scanner, "orig-ioi", 8) == 0) {
      pj_scan_advance_n(scanner, 8, PJ_TRUE);
      pj_scan_get_char(scanner);
      pj_scan_skip_whitespace(scanner);
      pj_scan_get_until_ch(scanner, ';', &hdr->orig_ioi);
    } else if (pj_scan_stricmp(scanner, "term-ioi", 8) == 0) {
      pj_scan_advance_n(scanner, 8, PJ_TRUE);
      pj_scan_get_char(scanner);
      pj_scan_skip_whitespace(scanner);
      pj_scan_get_until_ch(scanner, ';', &hdr->term_ioi);
    } else if (pj_scan_stricmp(scanner, "icid", 4) == 0) {
      pj_scan_advance_n(scanner, 4, PJ_TRUE);
      
      // We could have read the icid of icid= or of icid-generated-at=.
      if (*scanner->curptr == '=') {
        pj_scan_get_char(scanner);
        pj_scan_skip_whitespace(scanner);
        pj_scan_get_until_ch(scanner, ';', &hdr->icid);
      } else if (pj_scan_stricmp(scanner, "-generated-at", 13) == 0) {
        pj_scan_advance_n(scanner, 13, PJ_TRUE);
        pj_scan_get_char(scanner);
        pj_scan_skip_whitespace(scanner);
        pj_scan_get_until_ch(scanner, ';', &hdr->icid_gen_addr);
      } else {
        PJ_THROW(PJSIP_SYN_ERR_EXCEPTION);
      }
    } else {
      PJ_THROW(PJSIP_SYN_ERR_EXCEPTION);
    }

    // Swallow whitespace and the ';' character.
    pj_scan_skip_whitespace(scanner);
    pj_scan_get_char(scanner);
    pj_scan_skip_whitespace(scanner);

  } while (1);

  // We're done parsing this header.
  pjsip_parse_end_hdr_imp(scanner);

  return (pjsip_hdr*)hdr;
}

pjsip_p_c_v_hdr* pjsip_p_c_v_hdr_create(pj_pool_t* pool)
{
  void* mem = pj_pool_alloc(pool, sizeof(pjsip_p_c_v_hdr));
  return pjsip_p_c_v_hdr_init(pool, mem);
}

pjsip_hdr_vptr pjsip_p_c_v_vptr = {
  pjsip_p_c_v_hdr_clone,
  pjsip_p_c_v_hdr_shallow_clone,
  pjsip_p_c_v_hdr_print_on
};

pjsip_p_c_v_hdr* pjsip_p_c_v_hdr_init(pj_pool_t* pool, void* mem)
{
  pjsip_p_c_v_hdr* hdr = (pjsip_p_c_v_hdr*)mem;
  PJ_UNUSED_ARG(pool);
  
  // Based on init_hdr from sip_msg.c
  hdr->type = PJSIP_H_OTHER;
  hdr->name = STR_P_C_V;
  hdr->sname = STR_P_C_V;
  hdr->vptr = &pjsip_p_c_v_vptr;
  pj_list_init((pjsip_hdr*)hdr);

  return hdr;
}

void *pjsip_p_c_v_hdr_clone(pj_pool_t* pool, const void* o)
{
  pjsip_p_c_v_hdr* hdr = pjsip_p_c_v_hdr_create(pool);
  pjsip_p_c_v_hdr* other = (pjsip_p_c_v_hdr*)o;
  pj_strdup(pool, &hdr->icid, &other->icid);
  pj_strdup(pool, &hdr->orig_ioi, &other->orig_ioi);
  pj_strdup(pool, &hdr->term_ioi, &other->term_ioi);
  pj_strdup(pool, &hdr->icid_gen_addr, &other->icid_gen_addr);
  return hdr;
}

void *pjsip_p_c_v_hdr_shallow_clone(pj_pool_t* pool, const void* o)
{
  pjsip_p_c_v_hdr* hdr = pjsip_p_c_v_hdr_create(pool);
  pjsip_p_c_v_hdr* other = (pjsip_p_c_v_hdr*)o;
  hdr->icid = other->icid;
  hdr->orig_ioi = other->orig_ioi;
  hdr->term_ioi = other->term_ioi;
  hdr->icid_gen_addr = other->icid_gen_addr;
  return hdr;
}

int pjsip_p_c_v_hdr_print_on(void* h, char* buf, pj_size_t len)
{
  pjsip_p_c_v_hdr* hdr = (pjsip_p_c_v_hdr*)h;
  char* p = buf;

  // Check the header will fit.
  int needed = 0;
  needed += hdr->name.slen; // Header name
  needed += 2;              // : and space
  needed += 5;              // icid=
  needed += hdr->icid.slen; // <icid>
  needed += 2;              // ; and space
  if (hdr->orig_ioi.slen) {
    needed += 9;              // orig-ioi=
    needed += hdr->orig_ioi.slen; // <orig-ioi>
    needed += 2;              // ; and space
  }
  if (hdr->term_ioi.slen) {
    needed += 9;              // term-ioi=
    needed += hdr->term_ioi.slen; // <term-ioi>
    needed += 2;              // ; and space
  }
  if (hdr->icid_gen_addr.slen) {
    needed += 18;              // icid-generated-at=
    needed += hdr->icid_gen_addr.slen; // <icid-generated-at>
    needed += 2;              // ; and space
  }

  if (needed > (pj_ssize_t)len) {
    return -1;
  }
  
  // Now write the header out.
  pj_memcpy(p, hdr->name.ptr, hdr->name.slen);
  p += hdr->name.slen;
  *p++ = ':';
  *p++ = ' ';
  pj_memcpy(p, "icid=", 5);
  p += 5;
  pj_memcpy(p, hdr->icid.ptr, hdr->icid.slen);
  p += hdr->icid.slen;
  *p++ = ';';
  *p++ = ' ';
  if (hdr->orig_ioi.slen) {
    pj_memcpy(p, "orig-ioi=", 9);
    p += 9;
    pj_memcpy(p, hdr->orig_ioi.ptr, hdr->orig_ioi.slen);
    p += hdr->orig_ioi.slen;
    *p++ = ';';
    *p++ = ' ';
  }
  if (hdr->term_ioi.slen) {
    pj_memcpy(p, "term-ioi=", 9);
    p += 9;
    pj_memcpy(p, hdr->term_ioi.ptr, hdr->term_ioi.slen);
    p += hdr->term_ioi.slen;
    *p++ = ';';
    *p++ = ' ';
  }
  if (hdr->icid_gen_addr.slen) {
    pj_memcpy(p, "icid-generated-at=", 18);
    p += 18;
    pj_memcpy(p, hdr->icid_gen_addr.ptr, hdr->icid_gen_addr.slen);
    p += hdr->icid_gen_addr.slen;
    *p++ = ';';
    *p++ = ' ';
  }
  *p = '\0';

  return p - buf;
}

pjsip_hdr* parse_hdr_p_charging_function_addresses(pjsip_parse_ctx* ctx)
{
  // The P-Charging-Function-Addresses header has the following ABNF:
  //
  // P-Charging-Addr        = "P-Charging-Function-Addresses" HCOLON
  //                          charge-addr-params
  //                          *(SEMI charge-addr-params)
  // charge-addr-params     = ccf / ecf / generic-param
  // ccf                    = "ccf" EQUAL gen-value
  // ecf                    = "ecf" EQUAL gen-value
  //
  // Where the ccf and ecf elements may be repeated to specify backup CDFs
  // for redundancy.

  pj_pool_t* pool = ctx->pool;
  pj_scanner* scanner = ctx->scanner;
  pjsip_p_c_f_a_hdr* hdr = pjsip_p_c_f_a_hdr_create(pool);

  do {
    if (pj_scan_stricmp(scanner, "ccf", 3) == 0) {
      pj_scan_advance_n(scanner, 3, PJ_TRUE);
      pj_scan_get_char(scanner);
      pj_scan_skip_whitespace(scanner);
      if (hdr->ccf_count < PJ_P_C_F_A_MAX_ADDRS) {
        pj_scan_get_until_ch(scanner, ';', &hdr->ccf[hdr->ccf_count]);
        hdr->ccf_count++;
      }
      else {
        pj_scan_get_until_ch(scanner, ';', NULL);
      }
    } else if (pj_scan_stricmp(scanner, "ecf", 3) == 0) {
      pj_scan_advance_n(scanner, 3, PJ_TRUE);
      pj_scan_get_char(scanner);
      pj_scan_skip_whitespace(scanner);
      if (hdr->ecf_count < PJ_P_C_F_A_MAX_ADDRS) {
        pj_scan_get_until_ch(scanner, ';', &hdr->ecf[hdr->ecf_count]);
        hdr->ecf_count++;
      } else {
        pj_scan_get_until_ch(scanner, ';', NULL);
      }
    } else {
      break;
    }

    // Swallow whitespace and the ';' character.
    pj_scan_skip_whitespace(scanner);
    pj_scan_get_char(scanner);
    pj_scan_skip_whitespace(scanner);

  } while (1);

  // We're done parsing this header.
  pjsip_parse_end_hdr_imp(scanner);

  return (pjsip_hdr*)hdr;
}

pjsip_p_c_f_a_hdr* pjsip_p_c_f_a_hdr_create(pj_pool_t* pool)
{
  void* mem = pj_pool_alloc(pool, sizeof(pjsip_p_c_f_a_hdr));
  return pjsip_p_c_f_a_hdr_init(pool, mem);
}

pjsip_hdr_vptr pjsip_p_c_f_a_vptr = {
  pjsip_p_c_f_a_hdr_clone,
  pjsip_p_c_f_a_hdr_shallow_clone,
  pjsip_p_c_f_a_hdr_print_on
};

pjsip_p_c_f_a_hdr* pjsip_p_c_f_a_hdr_init(pj_pool_t* pool, void* mem)
{
  pjsip_p_c_f_a_hdr* hdr = (pjsip_p_c_f_a_hdr*)mem;
  PJ_UNUSED_ARG(pool);

  // Based on init_hdr from sip_msg.c
  hdr->type = PJSIP_H_OTHER;
  hdr->name = STR_P_C_F_A;
  hdr->sname = STR_P_C_F_A;
  hdr->vptr = &pjsip_p_c_f_a_vptr;
  pj_list_init((pjsip_hdr*)hdr);

  return hdr;
}

void *pjsip_p_c_f_a_hdr_clone(pj_pool_t* pool, const void* o)
{
  pjsip_p_c_f_a_hdr* hdr = pjsip_p_c_f_a_hdr_create(pool);
  pjsip_p_c_f_a_hdr* other = (pjsip_p_c_f_a_hdr*)o;

  hdr->ccf_count = other->ccf_count;
  hdr->ecf_count = other->ecf_count;
  for (int i = 0; i < PJ_P_C_F_A_MAX_ADDRS; i++) {
    pj_strdup(pool, &hdr->ccf[i], &other->ccf[i]);
    pj_strdup(pool, &hdr->ecf[i], &other->ecf[i]);
  }
  return hdr;
}

void *pjsip_p_c_f_a_hdr_shallow_clone(pj_pool_t* pool, const void* o)
{
  pjsip_p_c_f_a_hdr* hdr = pjsip_p_c_f_a_hdr_create(pool);
  pjsip_p_c_f_a_hdr* other = (pjsip_p_c_f_a_hdr*)o;

  hdr->ccf_count = other->ccf_count;
  hdr->ecf_count = other->ecf_count;
  for (int i = 0; i < PJ_P_C_F_A_MAX_ADDRS; i++) {
    hdr->ccf[i] = other->ccf[i];
    hdr->ecf[i] = other->ecf[i];
  }
  return hdr;
}

int pjsip_p_c_f_a_hdr_print_on(void *h, char* buf, pj_size_t len)
{
  pjsip_p_c_f_a_hdr* hdr = (pjsip_p_c_f_a_hdr*)h;
  char* p = buf;

  // Check the header will fit.
  int needed = 0;
  needed += hdr->name.slen; // Header name
  needed += 2;                // : and space
  for (int i = 0; i < PJ_P_C_F_A_MAX_ADDRS; i++) {
    if (i < hdr->ccf_count) {
      needed += 4;            // ccf=
      needed += hdr->ccf[i].slen; // data
      needed += 2;            // ; and space
    }
    if (i < hdr->ecf_count) {
      needed += 4;            // ecf=
      needed += hdr->ecf[i].slen; // data
      needed += 2;            // ; and space
    }
  }

  if (needed > (pj_ssize_t)len) {
    return -1;
  }
  
  // Now write the header out.
  pj_memcpy(p, hdr->name.ptr, hdr->name.slen);
  p += hdr->name.slen;
  *p++ = ':';
  *p++ = ' ';
  for (int i = 0; i < hdr->ccf_count; i++) {
    pj_memcpy(p, "ccf=", 4);
    p += 4;
    pj_memcpy(p, hdr->ccf[i].ptr, hdr->ccf[i].slen);
    p += hdr->ccf[i].slen;
    *p++ = ';';
    *p++ = ' ';
  }
  for (int i = 0; i < hdr->ecf_count; i++) {
    pj_memcpy(p, "ecf=", 4);
    p += 4;
    pj_memcpy(p, hdr->ecf[i].ptr, hdr->ecf[i].slen);
    p += hdr->ecf[i].slen;
    *p++ = ';';
    *p++ = ' ';
  }
  *p = '\0';

  return p - buf;
}
