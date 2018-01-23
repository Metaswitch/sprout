/**
 * @file custom_headers.cpp Implementations for custom SIP header handling
 * functions.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}

#include "log.h"
#include "constants.h"
#include "custom_headers.h"

/// Custom parser for Privacy header. This is registered with PJSIP below
/// in register_custom_headers().
///
/// The privacy header is delimited by semicolons. We want to use pjsip's
/// generic array header, however it splits on commas. We therefore override
/// the default parser and print function in the generic array header with a
/// custom constructor.
static int pjsip_privacy_hdr_print(pjsip_generic_array_hdr *hdr,
                      char *buf, pj_size_t size)
{
  pj_str_t semicolon_delimiter = {"; ", 2};
  return pjsip_delimited_array_hdr_print(hdr, buf, size, &semicolon_delimiter);
}

static pjsip_hdr_vptr privacy_hdr_vptr =
{
 (pjsip_hdr_clone_fptr) &pjsip_generic_array_hdr_clone,
 (pjsip_hdr_clone_fptr) &pjsip_generic_array_hdr_shallow_clone,
 (pjsip_hdr_print_fptr) &pjsip_privacy_hdr_print,
};

pjsip_generic_array_hdr* pjsip_privacy_hdr_create(pj_pool_t *pool,
                                 const pj_str_t *hnames)
{
  void *mem = pj_pool_alloc(pool, sizeof(pjsip_generic_array_hdr));
  pjsip_generic_array_hdr *hdr = pjsip_generic_array_hdr_init(pool, mem, hnames);
  hdr->vptr = &privacy_hdr_vptr;
  return hdr;
}

pjsip_hdr* parse_hdr_privacy(pjsip_parse_ctx* ctx)
{
  const pjsip_parser_const_t* pconst = pjsip_parser_const();
  pjsip_generic_array_hdr *privacy = pjsip_privacy_hdr_create(ctx->pool, &STR_PRIVACY);
  pjsip_parse_delimited_array_hdr(privacy, ctx->scanner, ';',
                                  &(pconst->pjsip_NOT_SEMICOLON_OR_NEWLINE));
  return (pjsip_hdr*)privacy;
}

typedef void* (*clone_fptr)(pj_pool_t *, const void*);
typedef int   (*print_fptr)(void *hdr, char *buf, pj_size_t len);

/*****************************************************************************/
/* Session-Expires                                                           */
/*****************************************************************************/
pjsip_hdr_vptr session_expires_hdr_vptr =
{
   &pjsip_session_expires_hdr_clone,
   &pjsip_session_expires_hdr_shallow_clone,
   &pjsip_session_expires_hdr_print_on,
};

pjsip_session_expires_hdr* pjsip_session_expires_hdr_create(pj_pool_t* pool)
{
  void* mem = pj_pool_alloc(pool, sizeof(pjsip_session_expires_hdr));
  return pjsip_session_expires_hdr_init(pool, mem);
}

pjsip_session_expires_hdr* pjsip_session_expires_hdr_init(pj_pool_t* pool, void* mem)
{
  pjsip_session_expires_hdr* hdr = (pjsip_session_expires_hdr*)mem;
  PJ_UNUSED_ARG(pool);

  hdr->type = PJSIP_H_OTHER;
  hdr->name = STR_SESSION_EXPIRES;
  hdr->sname = STR_SESSION_EXPIRES;
  hdr->vptr = &session_expires_hdr_vptr;
  pj_list_init(hdr);
  hdr->expires = 0;
  hdr->refresher = SESSION_REFRESHER_UNKNOWN;
  pj_list_init(&hdr->other_param);
  return hdr;
}

pjsip_hdr* parse_hdr_session_expires(pjsip_parse_ctx* ctx)
{
  pj_pool_t* pool = ctx->pool;
  pj_scanner* scanner = ctx->scanner;
  pjsip_session_expires_hdr* hdr = pjsip_session_expires_hdr_create(pool);
  const pjsip_parser_const_t* pc = pjsip_parser_const();

  // Parse the expiry number
  pj_str_t int_str;
  pj_scan_get(scanner, &pc->pjsip_DIGIT_SPEC, &int_str);
  hdr->expires = pj_strtoul(&int_str);
  pj_scan_skip_whitespace(scanner);

  // Parse the rest of the params, looking for the refresher param
  while (*scanner->curptr == ';')
  {
    // Consume the ';'.
    pj_scan_get_char(scanner);
    pj_scan_skip_whitespace(scanner);

    // Parse the param.
    pj_str_t name;
    pj_str_t value;
    pjsip_parse_param_imp(scanner, pool, &name, &value,
                          PJSIP_PARSE_REMOVE_QUOTE);
    if (!pj_stricmp2(&name, "refresher"))
    {
      if (!pj_stricmp2(&value, "uac"))
      {
        hdr->refresher = SESSION_REFRESHER_UAC;
      }
      else if (!pj_stricmp2(&value, "uas"))
      {
        hdr->refresher = SESSION_REFRESHER_UAS;
      }
      else
      {
        PJ_THROW(PJSIP_SYN_ERR_EXCEPTION); // LCOV_EXCL_LINE
      }
    }
    else
    {
      pjsip_param* param = PJ_POOL_ALLOC_T(pool, pjsip_param);
      param->name = name;
      param->value = value;
      pj_list_insert_before(&hdr->other_param, param);
    }
  }

  // We're done parsing this header.
  pjsip_parse_end_hdr_imp(scanner);

  return (pjsip_hdr*)hdr;
}

void* pjsip_session_expires_hdr_clone(pj_pool_t* pool, const void* o)
{
  pjsip_session_expires_hdr* hdr = pjsip_session_expires_hdr_create(pool);
  pjsip_session_expires_hdr* other = (pjsip_session_expires_hdr*)o;
  hdr->expires = other->expires;
  hdr->refresher = other->refresher;
  pjsip_param_clone(pool, &hdr->other_param, &other->other_param);
  return hdr;
}

void* pjsip_session_expires_hdr_shallow_clone(pj_pool_t* pool, const void* o)
{
  pjsip_session_expires_hdr* hdr = pjsip_session_expires_hdr_create(pool);
  pjsip_session_expires_hdr* other = (pjsip_session_expires_hdr*)o;
  hdr->expires = other->expires;
  hdr->refresher = other->refresher;
  pjsip_param_shallow_clone(pool, &hdr->other_param, &other->other_param);
  return hdr;
}

int pjsip_session_expires_hdr_print_on(void* h, char* buf, pj_size_t len)
{
  char* p = buf;
  const pjsip_session_expires_hdr* hdr = (pjsip_session_expires_hdr*)h;
  const pjsip_parser_const_t *pc = pjsip_parser_const();

  // As per pjsip_generic_int_hdr_print, integers are fewer then 15 characters long.
  if ((pj_ssize_t)len < hdr->name.slen + 15)
  {
    return -1;
  }

  pj_memcpy(p, hdr->name.ptr, hdr->name.slen);
  p += hdr->name.slen;
  *p++ = ':';
  *p++ = ' ';
  p += pj_utoa(hdr->expires, p);

  if (hdr->refresher != SESSION_REFRESHER_UNKNOWN)
  {
    // Check the refresher parameter will fit.
    if (buf+len-p < 14)
    {
      return -1;
    }

    // Fill it in
    *p++ = ';';
    pj_memcpy(p, "refresher=", 10);
    p += 10;

    if (hdr->refresher == SESSION_REFRESHER_UAC)
    {
      pj_memcpy(p, "uac", 3);
    }
    else
    {
      pj_memcpy(p, "uas", 3);
    }
    p += 3;
  }

  // Try to add the other params.
  pj_ssize_t printed = pjsip_param_print_on(&hdr->other_param, p, buf+len-p,
                                            &pc->pjsip_TOKEN_SPEC,
                                            &pc->pjsip_TOKEN_SPEC, ';');
  if (printed < 0)
  {
    return -1;
  }
  p += printed;
  *p = '\0';

  return p - buf;
}

pjsip_hdr_vptr identity_hdr_vptr =
{
   &identity_hdr_clone,
   &identity_hdr_shallow_clone,
   &identity_hdr_print,
};


/*****************************************************************************/
/* Min-SE                                                                    */
/*****************************************************************************/
pjsip_hdr_vptr min_se_hdr_vptr =
{
   &pjsip_min_se_hdr_clone,
   &pjsip_min_se_hdr_shallow_clone,
   &pjsip_min_se_hdr_print_on,
};

pjsip_min_se_hdr* pjsip_min_se_hdr_create(pj_pool_t* pool)
{
  void* mem = pj_pool_alloc(pool, sizeof(pjsip_min_se_hdr));
  return pjsip_min_se_hdr_init(pool, mem);
}

pjsip_min_se_hdr* pjsip_min_se_hdr_init(pj_pool_t* pool, void* mem)
{
  pjsip_min_se_hdr* hdr = (pjsip_min_se_hdr*)mem;
  PJ_UNUSED_ARG(pool);

  hdr->type = PJSIP_H_OTHER;
  hdr->name = STR_MIN_SE;
  hdr->vptr = &min_se_hdr_vptr;
  pj_list_init(hdr);
  hdr->expires = 0;
  pj_list_init(&hdr->other_param);
  return hdr;
}

pjsip_hdr* parse_hdr_min_se(pjsip_parse_ctx* ctx)
{
  pj_pool_t* pool = ctx->pool;
  pj_scanner* scanner = ctx->scanner;
  pjsip_min_se_hdr* hdr = pjsip_min_se_hdr_create(pool);
  const pjsip_parser_const_t* pc = pjsip_parser_const();

  // Parse the expiry number
  pj_str_t int_str;
  pj_scan_get(scanner, &pc->pjsip_DIGIT_SPEC, &int_str);
  hdr->expires = pj_strtoul(&int_str);
  pj_scan_skip_whitespace(scanner);

  // Parse the rest of the params, looking for the refresher param
  while (*scanner->curptr == ';')
  {
    // Consume the ';'.
    pj_scan_get_char(scanner);
    pj_scan_skip_whitespace(scanner);

    // Parse the param.
    pj_str_t name;
    pj_str_t value;
    pjsip_parse_param_imp(scanner, pool, &name, &value,
                          PJSIP_PARSE_REMOVE_QUOTE);

    pjsip_param* param = PJ_POOL_ALLOC_T(pool, pjsip_param);
    param->name = name;
    param->value = value;
    pj_list_insert_before(&hdr->other_param, param);
  }

  // We're done parsing this header.
  pjsip_parse_end_hdr_imp(scanner);

  return (pjsip_hdr*)hdr;
}

void* pjsip_min_se_hdr_clone(pj_pool_t* pool, const void* o)
{
  pjsip_min_se_hdr* hdr = pjsip_min_se_hdr_create(pool);
  pjsip_min_se_hdr* other = (pjsip_min_se_hdr*)o;
  hdr->expires = other->expires;
  pjsip_param_clone(pool, &hdr->other_param, &other->other_param);
  return hdr;
}

void* pjsip_min_se_hdr_shallow_clone(pj_pool_t* pool, const void* o)
{
  pjsip_min_se_hdr* hdr = pjsip_min_se_hdr_create(pool);
  pjsip_min_se_hdr* other = (pjsip_min_se_hdr*)o;
  hdr->expires = other->expires;
  pjsip_param_shallow_clone(pool, &hdr->other_param, &other->other_param);
  return hdr;
}

int pjsip_min_se_hdr_print_on(void* h, char* buf, pj_size_t len)
{
  char* p = buf;
  const pjsip_min_se_hdr* hdr = (pjsip_min_se_hdr*)h;
  const pjsip_parser_const_t *pc = pjsip_parser_const();

  // As per pjsip_generic_int_hdr_print, integers are fewer then 15 characters long.
  if ((pj_ssize_t)len < hdr->name.slen + 15)
  {
    return -1;
  }

  pj_memcpy(p, hdr->name.ptr, hdr->name.slen);
  p += hdr->name.slen;
  *p++ = ':';
  *p++ = ' ';
  p += pj_utoa(hdr->expires, p);

  // Try to add the other params.
  pj_ssize_t printed = pjsip_param_print_on(&hdr->other_param, p, buf+len-p,
                                            &pc->pjsip_TOKEN_SPEC,
                                            &pc->pjsip_TOKEN_SPEC, ';');
  if (printed < 0)
  {
    return -1;
  }
  p += printed;
  *p = '\0';

  return p - buf;
}

/// Custom create, clone and print functions used for the P-Associated-URI,
/// P-Asserted-Identity, P-Preferred-Identity, P-Served-User, and P-Profile-Key
/// headers
pjsip_routing_hdr* identity_hdr_create(pj_pool_t* pool, const pj_str_t name)
{
  void* mem = pj_pool_alloc(pool, sizeof(pjsip_routing_hdr));
  return identity_hdr_init(pool, mem, name);
}


pjsip_routing_hdr* identity_hdr_init(pj_pool_t* pool, void* mem, const pj_str_t name)
{
  pjsip_routing_hdr* hdr = (pjsip_routing_hdr*)mem;
  PJ_UNUSED_ARG(pool);

  pj_list_init(hdr);
  hdr->vptr = &identity_hdr_vptr;
  hdr->type = PJSIP_H_OTHER;
  hdr->name = name;
  hdr->sname = pj_str("");
  pjsip_name_addr_init(&hdr->name_addr);
  pj_list_init(&hdr->other_param);

  return hdr;
}


void* identity_hdr_clone(pj_pool_t* pool, const void* o)
{
  const pjsip_routing_hdr* rhs = (pjsip_routing_hdr*)o;
  pjsip_routing_hdr *hdr = identity_hdr_create(pool, rhs->name);
  pjsip_name_addr_assign(pool, &hdr->name_addr, &rhs->name_addr);
  pjsip_param_clone(pool, &hdr->other_param, &rhs->other_param);
  return hdr;
}


void* identity_hdr_shallow_clone(pj_pool_t* pool, const void* o)
{
  const pjsip_routing_hdr* rhs = (pjsip_routing_hdr*)o;
  pjsip_routing_hdr *hdr = PJ_POOL_ALLOC_T(pool, pjsip_routing_hdr);
  pj_memcpy(hdr, rhs, sizeof(*hdr));
  pjsip_param_shallow_clone(pool, &hdr->other_param, &rhs->other_param);
  return hdr;
}


int identity_hdr_print(void* h,
                       char* buf,
                       pj_size_t size)
{
  int printed;
  char *startbuf = buf;
  char *endbuf = buf + size;
  const pjsip_parser_const_t *pc = pjsip_parser_const();
  pjsip_routing_hdr* hdr = (pjsip_routing_hdr*)h;

  /* Route and Record-Route don't compact forms */
  copy_advance(buf, hdr->name);
  *buf++ = ':';
  *buf++ = ' ';

  printed = pjsip_uri_print(PJSIP_URI_IN_ROUTING_HDR,
                            &hdr->name_addr,
                            buf,
                            endbuf-buf);
  if (printed < 1)
  {
    return -1; // LCOV_EXCL_LINE
  }
  buf += printed;

  printed = pjsip_param_print_on(&hdr->other_param, buf, endbuf-buf,
                                 &pc->pjsip_TOKEN_SPEC,
                                 &pc->pjsip_TOKEN_SPEC, ';');
  if (printed < 0)
  {
    return -1; // LCOV_EXCL_LINE
  }
  buf += printed;

  return buf-startbuf;
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
    pjsip_route_hdr *hdr = identity_hdr_create(ctx->pool, STR_P_ASSOCIATED_URI);
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
      pj_scan_get_char(scanner);    // Consume ;
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
    pjsip_route_hdr *hdr = identity_hdr_create(ctx->pool, STR_P_ASSERTED_IDENTITY);
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
    pjsip_route_hdr *hdr = identity_hdr_create(ctx->pool, STR_P_PREFERRED_IDENTITY);
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


/// Custom parser for P-Served-User.  This is registered with PJSIP when
/// we initialize the stack.
pjsip_hdr* parse_hdr_p_served_user(pjsip_parse_ctx *ctx)
{
  // The P-Served-User header is a single name-addr followed by optional
  // parameters, so we parse it to a single pjsip_route_hdr structure.
  pj_scanner *scanner = ctx->scanner;

  pjsip_route_hdr *hdr = identity_hdr_create(ctx->pool, STR_P_SERVED_USER);
  pjsip_name_addr *temp = pjsip_parse_name_addr_imp(scanner, ctx->pool);
  pj_memcpy(&hdr->name_addr, temp, sizeof(*temp));

  while (*scanner->curptr == ';')
  {
    pj_scan_get_char(scanner);    // Consume ;
    pjsip_param *p = PJ_POOL_ALLOC_T(ctx->pool, pjsip_param);
    pjsip_parse_param_imp(scanner, ctx->pool, &p->name, &p->value, 0);
    pj_list_insert_before(&hdr->other_param, p);
  }
  pjsip_parse_end_hdr_imp(scanner);

  return (pjsip_hdr*)hdr;
}

/// Custom parser for P-Profile-Key. This is registered with PJSIP when
/// we initialize the stack.
pjsip_hdr* parse_hdr_p_profile_key(pjsip_parse_ctx *ctx)
{
  // The P-Profile-Key header is a single name-addr followed by optional
  // parameters, so we parse it to a single pjsip_route_hdr structure.
  pj_scanner *scanner = ctx->scanner;

  pjsip_route_hdr *hdr = identity_hdr_create(ctx->pool, STR_P_PROFILE_KEY);
  pjsip_name_addr *temp = pjsip_parse_name_addr_imp(scanner, ctx->pool);
  pj_memcpy(&hdr->name_addr, temp, sizeof(*temp));

  while (*scanner->curptr == ';')
  {
    pj_scan_get_char(scanner); // Consume the params (split by ;s)
    pjsip_param *p = PJ_POOL_ALLOC_T(ctx->pool, pjsip_param);
    pjsip_parse_param_imp(scanner, ctx->pool, &p->name, &p->value, 0);
    pj_list_insert_before(&hdr->other_param, p);
  }
  pjsip_parse_end_hdr_imp(scanner);

  return (pjsip_hdr*)hdr;
}

/// Custom parser for Service-Route header.  This is registered with PJSIP when
/// we initialize the stack.
pjsip_hdr* parse_hdr_service_route(pjsip_parse_ctx *ctx)
{
  // The Service-Route header is a comma separated list of name-addrs
  // so we parse it to multiple header structures, using the pjsip_route_hdr
  // structure for each.  Note that Service-Route may have parameters
  // after the name-addr.
  pjsip_route_hdr *first = NULL;
  pj_scanner *scanner = ctx->scanner;

  do
  {
    pjsip_route_hdr *hdr = identity_hdr_create(ctx->pool, STR_SERVICE_ROUTE);
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
      pj_scan_get_char(scanner);    // Consume ;
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


/// Custom parser for Path header.  This is registered with PJSIP when
/// we initialize the stack.
pjsip_hdr* parse_hdr_path(pjsip_parse_ctx *ctx)
{
  // The Path header is a comma separated list of name-addrs so we parse it
  // to multiple header structures, using the pjsip_route_hdr structure for
  // each.  Note that Path may have parameters after the name-addr.
  pjsip_route_hdr *first = NULL;
  pj_scanner *scanner = ctx->scanner;

  do
  {
    pjsip_route_hdr *hdr = identity_hdr_create(ctx->pool, STR_PATH);
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
      pj_scan_get_char(scanner);    // Consume ;
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

  pj_pool_t* pool = ctx->pool;
  pj_scanner* scanner = ctx->scanner;
  pjsip_p_c_v_hdr* hdr = pjsip_p_c_v_hdr_create(pool);
  pj_str_t name;
  pj_str_t value;

  // Parse the required icid-value parameter first.
  pjsip_parse_param_imp(scanner, pool, &name, &value,
                        0);

  // Strip the quotes off manually instead of using
  // PJ_PARSE_REMOVE_QUOTE. This preserves the square bracket on IPv6
  // addresses.
  if (value.slen > 1 &&
      value.ptr[0] == '"' &&
      value.ptr[value.slen-1] == '"')
  {
    value.ptr++;
    value.slen -= 2;
  }


  if (!pj_stricmp2(&name, "icid-value")) {
    hdr->icid = value;
  } else {
    PJ_THROW(PJSIP_SYN_ERR_EXCEPTION); // LCOV_EXCL_LINE
  }

  for (;;) {
    pj_scan_skip_whitespace(scanner);

    // If we just parsed the last parameter we will have reached the end of the
    // header and have nothing more to do.
    if (pj_scan_is_eof(scanner) ||
        (*scanner->curptr == '\r') ||
        (*scanner->curptr == '\n')) {
      break;
    }

    // There's more content in the header so the next character must be the ";"
    // separator.
    if (*scanner->curptr == ';') {
      pj_scan_get_char(scanner);
    } else {
      PJ_THROW(PJSIP_SYN_ERR_EXCEPTION); // LCOV_EXCL_LINE
    }

    pjsip_parse_param_imp(scanner, pool, &name, &value,
                          PJSIP_PARSE_REMOVE_QUOTE);

    if (!pj_stricmp2(&name, "orig-ioi")) {
      hdr->orig_ioi = value;
    } else if (!pj_stricmp2(&name, "term-ioi")) {
      hdr->term_ioi = value;
    } else if (!pj_stricmp2(&name, "icid-generated-at")) {
      hdr->icid_gen_addr = value;
    } else {
      pjsip_param *param = PJ_POOL_ALLOC_T(pool, pjsip_param);
      param->name = name;
      param->value = value;
      pj_list_insert_before(&hdr->other_param, param);
    }
  }

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
  pj_list_init(hdr);
  hdr->icid = pj_str("");
  hdr->orig_ioi = pj_str("");
  hdr->term_ioi = pj_str("");
  hdr->icid_gen_addr = pj_str("");
  pj_list_init(&hdr->other_param);

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
  pjsip_param_clone(pool, &hdr->other_param, &other->other_param);
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
  pjsip_param_shallow_clone(pool, &hdr->other_param, &other->other_param);
  return hdr;
}

int pjsip_p_c_v_hdr_print_on(void* h, char* buf, pj_size_t len)
{
  const pjsip_parser_const_t *pc = pjsip_parser_const();
  pjsip_p_c_v_hdr* hdr = (pjsip_p_c_v_hdr*)h;
  char* p = buf;

  // Check the fixed parts of the header will fit.
  int needed = 0;
  needed += hdr->name.slen; // Header name
  needed += 2;              // : and space
  needed += 11;             // icid-value=
  needed += 2;              // Quote the icid-value
  needed += hdr->icid.slen; // <icid>
  needed += 1;              // ;
  if (hdr->orig_ioi.slen) {
    needed += 9;              // orig-ioi=
    needed += hdr->orig_ioi.slen; // <orig-ioi>
    needed += 1;              // ;
  }
  if (hdr->term_ioi.slen) {
    needed += 9;              // term-ioi=
    needed += hdr->term_ioi.slen; // <term-ioi>
    needed += 1;              // ;
  }
  if (hdr->icid_gen_addr.slen) {
    needed += 18;              // icid-generated-at=
    needed += hdr->icid_gen_addr.slen; // <icid-generated-at>
  }

  if (needed > (pj_ssize_t)len) {
    return -1;
  }

  // Now write the fixed header out.
  pj_memcpy(p, hdr->name.ptr, hdr->name.slen);
  p += hdr->name.slen;
  *p++ = ':';
  *p++ = ' ';
  pj_memcpy(p, "icid-value=", 11);
  p += 11;
  *p++ = '"';
  if (hdr->icid.slen) {
    pj_memcpy(p, hdr->icid.ptr, hdr->icid.slen);
  }
  p += hdr->icid.slen;
  *p++ = '"';
  if (hdr->orig_ioi.slen) {
    *p++ = ';';
    pj_memcpy(p, "orig-ioi=", 9);
    p += 9;
    pj_memcpy(p, hdr->orig_ioi.ptr, hdr->orig_ioi.slen);
    p += hdr->orig_ioi.slen;
  }
  if (hdr->term_ioi.slen) {
    *p++ = ';';
    pj_memcpy(p, "term-ioi=", 9);
    p += 9;
    pj_memcpy(p, hdr->term_ioi.ptr, hdr->term_ioi.slen);
    p += hdr->term_ioi.slen;
  }
  if (hdr->icid_gen_addr.slen) {
    *p++ = ';';
    pj_memcpy(p, "icid-generated-at=", 18);
    p += 18;
    pj_memcpy(p, hdr->icid_gen_addr.ptr, hdr->icid_gen_addr.slen);
    p += hdr->icid_gen_addr.slen;
  }

  // Attempt to write out the other params.
  pj_ssize_t printed = pjsip_param_print_on(&hdr->other_param, p, buf+len-p,
                                            &pc->pjsip_TOKEN_SPEC,
                                            &pc->pjsip_TOKEN_SPEC, ';');
  if (printed < 0) {
    return -1;
  }
  p += printed;
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
  pj_str_t name;
  pj_str_t value;
  pjsip_param *param;

  for (;;) {
    pjsip_parse_uri_param_imp(scanner, pool, &name, &value, 0);
    param = PJ_POOL_ALLOC_T(pool, pjsip_param);
    param->name = name;
    param->value = value;
    if (!pj_stricmp2(&name, "ccf")) {
      pj_list_insert_before(&hdr->ccf, param);
    } else if (!pj_stricmp2(&name, "ecf")) {
      pj_list_insert_before(&hdr->ecf, param);
    } else {
      pj_list_insert_before(&hdr->other_param, param);
    }

    // We might need to swallow the ';'.
    if (!pj_scan_is_eof(scanner) && *scanner->curptr == ';') {
      pj_scan_get_char(scanner);
    }

    // If we're EOF or looking at a newline, we're done.
    pj_scan_skip_whitespace(scanner);
    if (pj_scan_is_eof(scanner) ||
        (*scanner->curptr == '\r') ||
        (*scanner->curptr == '\n')) {
      break;
    }
  }

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
  pj_list_init(hdr);
  pj_list_init(&hdr->ccf);
  pj_list_init(&hdr->ecf);
  pj_list_init(&hdr->other_param);

  return hdr;
}

void *pjsip_p_c_f_a_hdr_clone(pj_pool_t* pool, const void* o)
{
  pjsip_p_c_f_a_hdr* hdr = pjsip_p_c_f_a_hdr_create(pool);
  pjsip_p_c_f_a_hdr* other = (pjsip_p_c_f_a_hdr*)o;

  pjsip_param_clone(pool, &hdr->ccf, &other->ccf);
  pjsip_param_clone(pool, &hdr->ecf, &other->ecf);
  pjsip_param_clone(pool, &hdr->other_param, &other->other_param);

  return hdr;
}

void *pjsip_p_c_f_a_hdr_shallow_clone(pj_pool_t* pool, const void* o)
{
  pjsip_p_c_f_a_hdr* hdr = pjsip_p_c_f_a_hdr_create(pool);
  pjsip_p_c_f_a_hdr* other = (pjsip_p_c_f_a_hdr*)o;

  pjsip_param_shallow_clone(pool, &hdr->ccf, &other->ccf);
  pjsip_param_shallow_clone(pool, &hdr->ecf, &other->ecf);
  pjsip_param_shallow_clone(pool, &hdr->other_param, &other->other_param);

  return hdr;
}

int pjsip_p_c_f_a_hdr_print_on(void *h, char* buf, pj_size_t len)
{
  const pjsip_parser_const_t *pc = pjsip_parser_const();
  pjsip_p_c_f_a_hdr* hdr = (pjsip_p_c_f_a_hdr*)h;
  char* p = buf;

  // Check that at least the header name will fit.
  int needed = 0;
  needed += hdr->name.slen; // Header name
  needed += 2;              // : and space

  if (needed > (pj_ssize_t)len) {
    return -1;
  }

  // Now write the header name out.
  pj_memcpy(p, hdr->name.ptr, hdr->name.slen);
  p += hdr->name.slen;
  *p++ = ':';
  *p++ = ' ';

  // Now try to write out the three parameter lists.  Annoyingly,
  // pjsip_param_print_on() will always print the separator before each
  // parameter, including the first parameter in this case.
  //
  // The P-Charging-Function-Addresses header has no body (technically
  // invalid SIP) and thus we need to print the first parameter without the
  // separator.  Since this first parameter could be in any of the parameter
  // lists, we have to track (with the found_first_param flag) when we've
  // handled it.
  bool found_first_param = false;
  int printed;

  pjsip_param* param_list = NULL;
  for (int i = 0; i < 3; i++) {
    switch (i) {
      case 0:
        param_list = &hdr->ccf;
        break;
      case 1:
        param_list = &hdr->ecf;
        break;
      case 2:
        param_list = &hdr->other_param;
        break;
    }

    if (pj_list_empty(param_list)) {
      continue; // LCOV_EXCL_LINE
    }

    if (found_first_param) {
      // Simply write out the parameters
      printed = pjsip_param_print_on(param_list, p, buf+len-p,
                                     &pc->pjsip_TOKEN_SPEC,
                                     &pc->pjsip_PARAM_CHAR_SPEC, ';');
      if (printed < 0) {
        return -1;
      }
      p += printed;
    } else {
      // We print the first parameter manually then print the rest.
      pjsip_param* first_param = param_list->next;
      pj_list_erase(first_param);

      // Check we have space for the first param before printing it out.
      needed = pj_strlen(&first_param->name);
      if (first_param->value.slen) {
        needed += 1 + pj_strlen(&first_param->value);
      }
      if (needed > buf+len-p) {
        pj_list_insert_after(param_list, first_param);
        return -1;
      }

      pj_memcpy(p, first_param->name.ptr, first_param->name.slen);
      p += first_param->name.slen;
      if (first_param->value.slen) {
        *p++ = '=';
        pj_memcpy(p, first_param->value.ptr, first_param->value.slen);
        p += first_param->value.slen;
      }

      // Now print the rest of this parameter list (may be empty).
      printed = pjsip_param_print_on(param_list, p, buf+len-p,
                                     &pc->pjsip_TOKEN_SPEC,
                                     &pc->pjsip_PARAM_CHAR_SPEC, ';');
      if (printed < 0) {
        pj_list_insert_after(param_list, first_param);
        return -1;
      }
      p += printed;

      // Finally, restore the first param to the head of the parameter list.
      pj_list_insert_after(param_list, first_param);

      // We've found the first parameter, everything else is simple.
      found_first_param = true;
    }
  }

  *p = '\0';

  return p - buf;
}

pjsip_hdr* parse_hdr_reject_contact(pjsip_parse_ctx* ctx)
{
  return parse_hdr_accept_or_reject_contact(ctx, false);
}

pjsip_reject_contact_hdr* pjsip_reject_contact_hdr_create(pj_pool_t* pool)
{
  void* mem = pj_pool_alloc(pool, sizeof(pjsip_reject_contact_hdr));
  return pjsip_reject_contact_hdr_init(pool, mem);
}

pjsip_hdr_vptr pjsip_reject_contact_vptr = {
  pjsip_reject_contact_hdr_clone,
  pjsip_reject_contact_hdr_shallow_clone,
  pjsip_reject_contact_hdr_print_on
};

pjsip_reject_contact_hdr* pjsip_reject_contact_hdr_init(pj_pool_t* pool, void* mem)
{
  pjsip_reject_contact_hdr* hdr = (pjsip_reject_contact_hdr*)mem;
  PJ_UNUSED_ARG(pool);

  // Based on init_hdr from sip_msg.c
  hdr->type = PJSIP_H_OTHER;
  hdr->name = STR_REJECT_CONTACT;
  hdr->sname = STR_REJECT_CONTACT_SHORT;
  hdr->vptr = &pjsip_reject_contact_vptr;
  pj_list_init(hdr);
  pj_list_init(&hdr->feature_set);

  return hdr;
}

void *pjsip_reject_contact_hdr_clone(pj_pool_t* pool, const void* o)
{
  pjsip_reject_contact_hdr* hdr = pjsip_reject_contact_hdr_create(pool);
  pjsip_reject_contact_hdr* other = (pjsip_reject_contact_hdr*)o;

  pjsip_param_clone(pool, &hdr->feature_set, &other->feature_set);

  return hdr;
}

void *pjsip_reject_contact_hdr_shallow_clone(pj_pool_t* pool, const void* o)
{
  pjsip_reject_contact_hdr* hdr = pjsip_reject_contact_hdr_create(pool);
  pjsip_reject_contact_hdr* other = (pjsip_reject_contact_hdr*)o;

  pjsip_param_shallow_clone(pool, &hdr->feature_set, &other->feature_set);

  return hdr;
}

int pjsip_reject_contact_hdr_print_on(void* void_hdr,
                                      char* buf,
                                      pj_size_t size)
{
  int printed;
  char *startbuf = buf;
  char *endbuf = buf + size;
  pjsip_reject_contact_hdr* hdr = (pjsip_reject_contact_hdr *)void_hdr;
  const pjsip_parser_const_t *pc = pjsip_parser_const();

  /* Route and Record-Route don't compact forms */
  copy_advance(buf, hdr->name);
  *buf++ = ':';
  *buf++ = ' ';
  *buf++ = '*';

  printed = pjsip_param_print_on(&hdr->feature_set, buf, endbuf-buf,
                                 &pc->pjsip_TOKEN_SPEC,
                                 &pc->pjsip_TOKEN_SPEC, ';');
  if (printed < 0)
  {
    return -1;
  }
  buf += printed;

  return buf-startbuf;
}

pjsip_hdr* parse_hdr_accept_contact(pjsip_parse_ctx* ctx)
{
  return parse_hdr_accept_or_reject_contact(ctx, true);
}

pjsip_accept_contact_hdr* pjsip_accept_contact_hdr_create(pj_pool_t* pool)
{
  void* mem = pj_pool_alloc(pool, sizeof(pjsip_accept_contact_hdr));
  return pjsip_accept_contact_hdr_init(pool, mem);
}

pjsip_hdr_vptr pjsip_accept_contact_vptr = {
  pjsip_accept_contact_hdr_clone,
  pjsip_accept_contact_hdr_shallow_clone,
  pjsip_accept_contact_hdr_print_on
};

pjsip_accept_contact_hdr* pjsip_accept_contact_hdr_init(pj_pool_t* pool, void* mem)
{
  pjsip_accept_contact_hdr* hdr = (pjsip_accept_contact_hdr*)mem;
  PJ_UNUSED_ARG(pool);

  // Based on init_hdr from sip_msg.c
  hdr->type = PJSIP_H_OTHER;
  hdr->name = STR_ACCEPT_CONTACT;
  hdr->sname = STR_ACCEPT_CONTACT_SHORT;
  hdr->vptr = &pjsip_accept_contact_vptr;
  pj_list_init(hdr);
  hdr->required_match = false;
  hdr->explicit_match = false;
  pj_list_init(&hdr->feature_set);

  return hdr;
}

void *pjsip_accept_contact_hdr_clone(pj_pool_t* pool, const void* o)
{
  pjsip_accept_contact_hdr* hdr = pjsip_accept_contact_hdr_create(pool);
  pjsip_accept_contact_hdr* other = (pjsip_accept_contact_hdr*)o;

  hdr->required_match = other->required_match;
  hdr->explicit_match = other->explicit_match;

  pjsip_param_clone(pool, &hdr->feature_set, &other->feature_set);

  return hdr;
}

void *pjsip_accept_contact_hdr_shallow_clone(pj_pool_t* pool, const void* o)
{
  pjsip_accept_contact_hdr* hdr = pjsip_accept_contact_hdr_create(pool);
  pjsip_accept_contact_hdr* other = (pjsip_accept_contact_hdr*)o;

  hdr->required_match = other->required_match;
  hdr->explicit_match = other->explicit_match;

  pjsip_param_shallow_clone(pool, &hdr->feature_set, &other->feature_set);

  return hdr;
}

int pjsip_accept_contact_hdr_print_on(void* void_hdr,
                                      char* buf,
                                      pj_size_t size)
{
  int printed;
  char *startbuf = buf;
  char *endbuf = buf + size;
  pjsip_accept_contact_hdr* hdr = (pjsip_accept_contact_hdr *)void_hdr;
  const pjsip_parser_const_t *pc = pjsip_parser_const();

  /* Route and Record-Route don't compact forms */
  copy_advance(buf, hdr->name);
  copy_advance(buf, pj_str(": *"));

  printed = pjsip_param_print_on(&hdr->feature_set, buf, endbuf-buf,
                                 &pc->pjsip_TOKEN_SPEC,
                                 &pc->pjsip_TOKEN_SPEC, ';');
  if (printed < 0)
  {
    return -1;
  }
  buf += printed;

  if (hdr->explicit_match)
  {
    copy_advance(buf, pj_str(";explicit"));
  }

  if (hdr->required_match)
  {
    copy_advance(buf, pj_str(";require"));
  }

  return buf-startbuf;
}

pjsip_hdr* parse_hdr_accept_or_reject_contact(pjsip_parse_ctx* ctx, bool accept)
{
  // The Accept-Contact header has the following ABNF:
  //
  // Accept-Contact  =  ("Accept-Contact" / "j") HCOLON ac-value
  //                       *(COMMA ac-value)
  // ac-value        =  "*" *(SEMI ac-params)
  // ac-params       =  feature-param / req-param / explicit-param / generic-param
  // req-param       =  "require"
  // explicit-param  =  "explicit"
  //
  // The Reject-Contact header has the following ABNF:
  //
  // Reject-Contact  =  ("Reject-Contact" / "j") HCOLON rc-value
  //                       *(COMMA rc-value)
  // rc-value        =  "*" *(SEMI rc-params)
  // rc-params       =  feature-param / generic-param
  //
  // But we allow any value for the header (not just *).

  pjsip_hdr* first = NULL;
  pjsip_hdr* hdr = NULL;

  pj_pool_t* pool = ctx->pool;
  pj_scanner* scanner = ctx->scanner;
  const pjsip_parser_const_t* pc = pjsip_parser_const();
  pj_str_t name;
  pj_str_t value;
  pjsip_param *param;

  while (true)
  {
    hdr = accept ? (pjsip_hdr*)pjsip_accept_contact_hdr_create(pool) : (pjsip_hdr*)pjsip_reject_contact_hdr_create(pool);
    if (first == NULL)
    {
      first = hdr;
    }
    else
    {
      pj_list_insert_before(first, hdr);
    }

    // Read and ignore the value.
    pj_str_t header_value;
    pj_scan_get(scanner, &pc->pjsip_TOKEN_SPEC, &header_value);

    // If we're EOF or looking at a newline, we're done.
    while (!pj_scan_is_eof(scanner) &&
           (*scanner->curptr != ',') &&
           (*scanner->curptr != '\r') &&
           (*scanner->curptr != '\n'))
    {
      // We might need to swallow the ';'.
      if (!pj_scan_is_eof(scanner) && *scanner->curptr == ';')
      {
        pj_scan_get_char(scanner);
      }

      pjsip_parse_param_imp(scanner, pool, &name, &value, 0);
      param = PJ_POOL_ALLOC_T(pool, pjsip_param);
      param->name = name;
      param->value = value;

      if (accept)
      {
        pjsip_accept_contact_hdr* achdr = (pjsip_accept_contact_hdr*)hdr;
        if (!pj_stricmp2(&name, "require"))
        {
          achdr->required_match = true;
        }
        else if (!pj_stricmp2(&name, "explicit"))
        {
          achdr->explicit_match = true;
        }
        else
        {
          pj_list_insert_before(&achdr->feature_set, param);
        }
      }
      else
      {
        pj_list_insert_before(&((pjsip_reject_contact_hdr*)hdr)->feature_set, param);
      }

      // Skip any following whitespace (to the end of the line)
      pj_scan_skip_whitespace(scanner);
    }

    if (*scanner->curptr != ',')
    {
      break;
    }

    pj_scan_get_char(scanner);
  }

  // We're done parsing this header.
  pjsip_parse_end_hdr_imp(scanner);
  return (pjsip_hdr*)first;
}

static pjsip_hdr_vptr pjsip_resource_priority_vptr = {
  (pjsip_hdr_clone_fptr) &pjsip_generic_array_hdr_clone,
  (pjsip_hdr_clone_fptr) &pjsip_generic_array_hdr_shallow_clone,
  (pjsip_hdr_print_fptr) &pjsip_generic_array_hdr_print
};

pjsip_generic_array_hdr* pjsip_resource_priority_hdr_create(pj_pool_t *pool)
{
  void *mem = pj_pool_alloc(pool, sizeof(pjsip_generic_array_hdr));
  pjsip_generic_array_hdr *hdr = pjsip_generic_array_hdr_init(pool, mem, &STR_RESOURCE_PRIORITY);
  hdr->vptr = &pjsip_resource_priority_vptr;
  return hdr;
}

pjsip_hdr* parse_hdr_resource_priority(pjsip_parse_ctx* ctx)
{
  // The Resource-Priority header has the following ABNF (as defined in RFC 4412
  // section 3.1):
  //
  //    Resource-Priority  = "Resource-Priority" HCOLON
  //                         r-value *(COMMA r-value)
  //    r-value            = namespace "." r-priority
  //    namespace          = token-nodot
  //    r-priority         = token-nodot
  //    token-nodot        = 1*( alphanum / "-"  / "!" / "%" / "*"
  //                                / "_" / "+" / "`" / "'" / "~" )
  const pjsip_parser_const_t* pc = pjsip_parser_const();
  pjsip_generic_array_hdr* hdr = pjsip_resource_priority_hdr_create(ctx->pool);
  pjsip_parse_delimited_array_hdr(hdr, ctx->scanner, ',',
                                  &(pc->pjsip_NOT_COMMA_OR_NEWLINE));
  return (pjsip_hdr*)hdr;
}

/// Register all of our custom header parsers with pjSIP.  This should be
// called once during startup.
pj_status_t register_custom_headers()
{
  pj_status_t status;

  status = pjsip_register_hdr_parser("Privacy", NULL, &parse_hdr_privacy);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
  status = pjsip_register_hdr_parser("P-Associated-URI", NULL, &parse_hdr_p_associated_uri);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
  status = pjsip_register_hdr_parser("P-Asserted-Identity", NULL, &parse_hdr_p_asserted_identity);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
  status = pjsip_register_hdr_parser("P-Preferred-Identity", NULL, &parse_hdr_p_preferred_identity);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
  status = pjsip_register_hdr_parser("P-Charging-Vector", NULL, &parse_hdr_p_charging_vector);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
  status = pjsip_register_hdr_parser("P-Charging-Function-Addresses", NULL, &parse_hdr_p_charging_function_addresses);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
  status = pjsip_register_hdr_parser("P-Served-User", NULL, &parse_hdr_p_served_user);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
  status = pjsip_register_hdr_parser("P-Profile-Key", NULL, &parse_hdr_p_profile_key);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
  status = pjsip_register_hdr_parser("Service-Route", NULL, &parse_hdr_service_route);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
  status = pjsip_register_hdr_parser("Path", NULL, &parse_hdr_path);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
  status = pjsip_register_hdr_parser("Session-Expires", NULL, &parse_hdr_session_expires);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
  status = pjsip_register_hdr_parser("Min-SE", NULL, &parse_hdr_min_se);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
  status = pjsip_register_hdr_parser("Reject-Contact", "j", &parse_hdr_reject_contact);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
  status = pjsip_register_hdr_parser("Accept-Contact", "a", &parse_hdr_accept_contact);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
  status = pjsip_register_hdr_parser("Resource-Priority", NULL, &parse_hdr_resource_priority);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);

  return PJ_SUCCESS;
}
