/**
 * @file pjutils.cpp Helper functions for working with pjsip types.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * Parts of this module were derived from GPL licensed PJSIP sample code
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

#include "pjutils.h"

extern "C" {
#include <pjlib-util.h>
#include <pjlib.h>
}

#include "stack.h"
#include "log.h"
#include "constants.h"
#include "custom_headers.h"

static const int DEFAULT_RETRIES = 5;
static const int DEFAULT_BLACKLIST_DURATION = 30;

static void on_tsx_state(pjsip_transaction*, pjsip_event*);

/// Dummy transaction user module used for send_request method.
static pjsip_module mod_sprout_util =
{
  NULL, NULL,                     // prev, next
  { "mod-sprout-util", 15 },      // Name
  -1,                             // Id
  PJSIP_MOD_PRIORITY_APPLICATION, // Priority
  NULL,                           // load()
  NULL,                           // start()
  NULL,                           // stop()
  NULL,                           // unload()
  NULL,                           // on_rx_request()
  NULL,                           // on_rx_response()
  NULL,                           // on_tx_request()
  NULL,                           // on_tx_response()
  &on_tsx_state,                  // on_tsx_state()
};

/// Initialization
pj_status_t PJUtils::init()
{
  pj_status_t status = pjsip_endpt_register_module(stack_data.endpt, &mod_sprout_util);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);
  return status;
}


/// Termination
void PJUtils::term()
{
  pjsip_endpt_unregister_module(stack_data.endpt, &mod_sprout_util);
}


/// Utility to determine if this URI belongs to the home domain.
pj_bool_t PJUtils::is_home_domain(const pjsip_uri* uri)
{
  if (PJSIP_URI_SCHEME_IS_SIP(uri))
  {
    std::string host = pj_str_to_string(&((pjsip_sip_uri*)uri)->host);
    return is_home_domain(host);
  }
  return PJ_FALSE;
}


/// Utility to determine if this domain is a home domain
pj_bool_t PJUtils::is_home_domain(const std::string& domain)
{
  return (stack_data.home_domains.find(domain) != stack_data.home_domains.end()) ?
         PJ_TRUE : PJ_FALSE;
}


/// Utility to determine if URI is local to this host.
pj_bool_t PJUtils::is_uri_local(const pjsip_uri* uri)
{
  if (PJSIP_URI_SCHEME_IS_SIP(uri))
  {
    // Check the list of host names.
    pj_str_t host = ((pjsip_sip_uri*)uri)->host;
    unsigned i;
    for (i=0; i<stack_data.name_cnt; ++i)
    {
      if (pj_stricmp(&host, &stack_data.name[i])==0)
      {
        /* Match */
        return PJ_TRUE;
      }
    }
  }
  else
  {
    LOG_INFO("URI scheme is not SIP - treating as not locally hosted");
  }

  /* Doesn't match */
  return PJ_FALSE;
}


/// Utility to determine if a user field contains a valid E.164 number
pj_bool_t PJUtils::is_e164(const pj_str_t* user)
{
  if ((user->slen < 1) || (user->ptr[0] != '+'))
  {
    // Field is too short to contain a valid E.164 number, or does not
    // start with a +.
    return PJ_FALSE;
  }

  for (int ii = 1; ii < user->slen; ++ii)
  {
    if ((user->ptr[ii] < '0') || (user->ptr[ii] > '9'))
    {
      return PJ_FALSE;
    }
  }

  return PJ_TRUE;
}


/// Utility to determine if URI contains a valid E.164 number
pj_bool_t PJUtils::is_e164(const pjsip_uri* uri)
{
  if (PJSIP_URI_SCHEME_IS_SIP(uri))
  {
    return PJUtils::is_e164(&((pjsip_sip_uri*)uri)->user);
  }
  return PJ_FALSE;
}


pj_str_t PJUtils::uri_to_pj_str(pjsip_uri_context_e context,
                                const pjsip_uri* uri,
                                pj_pool_t* pool)
{
  pj_str_t s;
  char buf[500];
  s.slen = pjsip_uri_print(context, uri, buf, sizeof(buf));
  s.ptr = (char*)pj_pool_alloc(pool, s.slen);
  memcpy(s.ptr, buf, s.slen);
  return s;
}


std::string PJUtils::uri_to_string(pjsip_uri_context_e context,
                                   const pjsip_uri* uri)
{
  int uri_clen = 0;
  char uri_cstr[500];
  if (uri != NULL)
  {
    uri_clen = pjsip_uri_print(context, uri, uri_cstr, sizeof(uri_cstr));
  }
  return std::string(uri_cstr, uri_clen);
}


/// Parse the supplied string to a PJSIP URI structure.  Note that if this
/// finds a name-addr instead of a URI it will parse it to a pjsip_name_addr
/// structure, so you must use pjsip_uri_get_uri to get to the URI piece.
pjsip_uri* PJUtils::uri_from_string(const std::string& uri_s,
                                    pj_pool_t* pool,
                                    pj_bool_t force_name_addr)
{
  // We must duplicate the string into memory from the specified pool first as
  // pjsip_parse_uri does not clone the actual strings within the URI.
  size_t len = uri_s.length();
  char* buf = (char*)pj_pool_alloc(pool, len + 1);
  memcpy(buf, uri_s.data(), len);
  buf[len] = 0;
  return pjsip_parse_uri(pool, buf, len, (force_name_addr) ? PJSIP_PARSE_URI_AS_NAMEADDR : 0);
}


std::string PJUtils::pj_str_to_string(const pj_str_t* pjstr)
{
  return (pjstr != NULL) ? std::string(pj_strbuf(pjstr), pj_strlen(pjstr)) : std::string("");
}


std::string PJUtils::pj_status_to_string(const pj_status_t status)
{
  char errmsg[PJ_ERR_MSG_SIZE];

  pj_strerror(status, errmsg, sizeof(errmsg));
  return std::string(errmsg);
}


/// Returns a canonical SIP address of record from a URI, as per the rules
/// in RFC3261 s10.3 step 5.  In particular, strip all parameters and the
/// password before rendering the URI to a string.
std::string PJUtils::aor_from_uri(const pjsip_sip_uri* uri)
{
  std::string input_uri = uri_to_string(PJSIP_URI_IN_FROMTO_HDR, (pjsip_uri*)uri);
  std::string returned_aor;
  pjsip_sip_uri aor;
  memcpy((char*)&aor, (char*)uri, sizeof(pjsip_sip_uri));
  aor.passwd.slen = 0;
  aor.port = 0;
  aor.user_param.slen = 0;
  aor.method_param.slen = 0;
  aor.transport_param.slen = 0;
  aor.ttl_param = -1;
  aor.lr_param = 0;
  aor.maddr_param.slen = 0;
  aor.other_param.next = NULL;
  aor.header_param.next = NULL;
  returned_aor = uri_to_string(PJSIP_URI_IN_FROMTO_HDR, (pjsip_uri*)&aor);
  LOG_DEBUG("aor_from_uri converted %s to %s", input_uri.c_str(), returned_aor.c_str());
  return returned_aor;
}


/// Returns a canonical IMS public user identity from a URI as per TS 23.003
/// 13.4.
std::string PJUtils::public_id_from_uri(const pjsip_uri* uri)
{
  if (PJSIP_URI_SCHEME_IS_SIP(uri))
  {
    pjsip_sip_uri public_id;
    memcpy((char*)&public_id, (char*)uri, sizeof(pjsip_sip_uri));
    public_id.passwd.slen = 0;
    public_id.port = 0;
    public_id.user_param.slen = 0;
    public_id.method_param.slen = 0;
    public_id.transport_param.slen = 0;
    public_id.ttl_param = -1;
    public_id.lr_param = 0;
    public_id.maddr_param.slen = 0;
    public_id.other_param.next = NULL;
    public_id.header_param.next = NULL;
    return uri_to_string(PJSIP_URI_IN_FROMTO_HDR, (pjsip_uri*)&public_id);
  }
  else if (PJSIP_URI_SCHEME_IS_TEL(uri))
  {
    pjsip_tel_uri public_id;
    memcpy((char*)&public_id, (char*)uri, sizeof(pjsip_tel_uri));
    public_id.context.slen = 0;
    public_id.ext_param.slen = 0;
    public_id.isub_param.slen = 0;
    public_id.other_param.next = NULL;
    return uri_to_string(PJSIP_URI_IN_FROMTO_HDR, (pjsip_uri*)&public_id);
  }
  else
  {
    return std::string();
  }
}

// Determine the default private ID for a public ID contained in a URI.  This
// is calculated as specified by the 3GPP specs by effectively stripping the
// scheme.
std::string PJUtils::default_private_id_from_uri(const pjsip_uri* uri)
{
  std::string id;
  if (PJSIP_URI_SCHEME_IS_SIP(uri) ||
      PJSIP_URI_SCHEME_IS_SIPS(uri))
  {
    pjsip_sip_uri* sip_uri = (pjsip_sip_uri*)uri;
    if (sip_uri->user.slen > 0)
    {
      id = PJUtils::pj_str_to_string(&sip_uri->user) + "@" + PJUtils::pj_str_to_string(&sip_uri->host);
    }
    else
    {
      id = PJUtils::pj_str_to_string(&sip_uri->host);
    }
  }
  else
  {
    const pj_str_t* scheme = pjsip_uri_get_scheme(uri);
    LOG_WARNING("Unsupported scheme \"%.*s\" in To header when determining private ID - ignoring",
                scheme->slen, scheme->ptr);
  }
  return id;
}

/// Extract the domain from a SIP URI.  If none is present, return the default
/// home domain.
pj_str_t PJUtils::domain_from_uri(const std::string& uri_str, pj_pool_t* pool)
{
  pjsip_uri* uri = PJUtils::uri_from_string(uri_str, pool);
  if (PJSIP_URI_SCHEME_IS_SIP(uri) ||
      PJSIP_URI_SCHEME_IS_SIPS(uri))
  {
    return ((pjsip_sip_uri*)uri)->host;
  }
  else
  {
    return stack_data.default_home_domain;
  }
}

/// Determine the served user for originating requests.
pjsip_uri* PJUtils::orig_served_user(pjsip_msg* msg)
{
  // The served user for originating requests is determined from the
  // P-Served-User or P-Asserted-Identity headers.  For extra compatibility,
  // we will also look at the From header if neither of the IMS headers is
  // present.
  pjsip_uri* uri = NULL;
  pjsip_routing_hdr* served_user = (pjsip_routing_hdr*)
                     pjsip_msg_find_hdr_by_name(msg, &STR_P_SERVED_USER, NULL);

  if (served_user != NULL)
  {
    uri = (pjsip_uri*)pjsip_uri_get_uri(&served_user->name_addr);
    LOG_DEBUG("Served user from P-Served-User header");
  }

  if (uri == NULL)
  {
    // No P-Served-User header present, so check for P-Asserted-Identity
    // header.
    pjsip_routing_hdr* asserted_id = (pjsip_routing_hdr*)
               pjsip_msg_find_hdr_by_name(msg, &STR_P_ASSERTED_IDENTITY, NULL);

    if (asserted_id != NULL)
    {
      uri = (pjsip_uri*)pjsip_uri_get_uri(&asserted_id->name_addr);
      LOG_DEBUG("Served user from P-Asserted-Identity header");
    }
  }

  if (uri == NULL)
  {
    // Neither IMS header is present, so use the From header.  This isn't
    // strictly speaking IMS compliant.
    LOG_DEBUG("From header %p", PJSIP_MSG_FROM_HDR(msg));
    uri = (pjsip_uri*)pjsip_uri_get_uri(PJSIP_MSG_FROM_HDR(msg)->uri);
    LOG_DEBUG("Served user from From header (%p)", uri);
  }

  return uri;
}


/// Determine the served user for terminating requests.
pjsip_uri* PJUtils::term_served_user(pjsip_msg* msg)
{
  // The served user for terminating requests is always determined from the
  // Request URI.
  return msg->line.req.uri;
}


void PJUtils::add_integrity_protected_indication(pjsip_tx_data* tdata, Integrity integrity)
{
  pjsip_authorization_hdr* auth_hdr = (pjsip_authorization_hdr*)
                                      pjsip_msg_find_hdr(tdata->msg, PJSIP_H_AUTHORIZATION, NULL);

  if (auth_hdr == NULL)
  {
    auth_hdr = pjsip_authorization_hdr_create(tdata->pool);
    auth_hdr->scheme = pj_str("Digest");
    // Construct a default private identifier from the URI in the To header.
    LOG_DEBUG("Construct default private identity");
    pjsip_uri* to_uri = (pjsip_uri*)pjsip_uri_get_uri(PJSIP_MSG_TO_HDR(tdata->msg)->uri);
    std::string private_id = PJUtils::default_private_id_from_uri(to_uri);
    pj_strdup2(tdata->pool, &auth_hdr->credential.digest.username, private_id.c_str());
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)auth_hdr);
  }
  pjsip_param* new_param = (pjsip_param*) pj_pool_alloc(tdata->pool, sizeof(pjsip_param));
  new_param->name = STR_INTEGRITY_PROTECTED;
  switch (integrity)
  {
  case Integrity::YES:
    new_param->value = STR_YES;
    break;

  case Integrity::NO:
    new_param->value = STR_NO;
    break;

  case Integrity::TLS_YES:
    new_param->value = STR_TLS_YES;
    break;

  case Integrity::TLS_PENDING:
    new_param->value = STR_TLS_PENDING;
    break;

  case Integrity::IP_ASSOC_YES:
    new_param->value = STR_IP_ASSOC_YES;
    break;

  case Integrity::IP_ASSOC_PENDING:
    new_param->value = STR_IP_ASSOC_PENDING;
    break;

  case Integrity::AUTH_DONE:
    new_param->value = STR_AUTH_DONE;
    break;

  default:
    break;
  }
  LOG_INFO("Adding integrity-protected=%.*s indicator to message",
           new_param->value.slen, new_param->value.ptr);
  pj_list_insert_before(&auth_hdr->credential.common.other_param, new_param);
}

void PJUtils::get_impi_and_impu(pjsip_rx_data* rdata, std::string& impi_out, std::string& impu_out)
{
  // Check to see if the request has already been integrity protected?
  pjsip_authorization_hdr* auth_hdr = (pjsip_authorization_hdr*)
           pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_AUTHORIZATION, NULL);

  pjsip_uri* to_uri = (pjsip_uri*)pjsip_uri_get_uri(PJSIP_MSG_TO_HDR(rdata->msg_info.msg)->uri);
  impu_out = PJUtils::public_id_from_uri(to_uri);
  if ((auth_hdr != NULL) &&
      (auth_hdr->credential.digest.username.slen != 0))
  {
    // private user identity is supplied in the Authorization header so use it.
    impi_out = PJUtils::pj_str_to_string(&auth_hdr->credential.digest.username);
    LOG_DEBUG("Private identity from authorization header = %s", impi_out.c_str());
  }
  else
  {
    // private user identity not supplied, so construct a default from the
    // public user identity by stripping the sip: prefix.
    impi_out = PJUtils::default_private_id_from_uri(to_uri);
    LOG_DEBUG("Private identity defaulted from public identity = %s", impi_out.c_str());
  }
}

/// Adds a P-Asserted-Identity header to the message.
void PJUtils::add_asserted_identity(pjsip_tx_data* tdata, const std::string& aid)
{
  LOG_DEBUG("Adding P-Asserted-Identity header: %s", aid.c_str());
  pjsip_routing_hdr* p_asserted_id =
                     identity_hdr_create(tdata->pool, STR_P_ASSERTED_IDENTITY);

  pjsip_name_addr* temp = (pjsip_name_addr*)uri_from_string(aid, tdata->pool, true);
  memcpy(&p_asserted_id->name_addr, temp, sizeof(pjsip_name_addr));

  pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)p_asserted_id);
}


/// Returns the next hop for a SIP request.  This will either be the
/// URI in the top-most Route header, or the RequestURI if there are no
/// Route headers.
pjsip_uri* PJUtils::next_hop(pjsip_msg* msg)
{
  pjsip_route_hdr* route_hdr = (pjsip_route_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_ROUTE, NULL);
  LOG_DEBUG("Next hop node is encoded in %s", (route_hdr != NULL) ? "top route header" : "Request-URI");
  return (route_hdr != NULL) ? route_hdr->name_addr.uri : msg->line.req.uri;
}


/// Checks whether the next Route header in the message refers to this node,
/// and optionally returns the header.  If there are no Route headers it
/// returns false.
pj_bool_t PJUtils::is_next_route_local(const pjsip_msg* msg, pjsip_route_hdr* start, pjsip_route_hdr** hdr)
{
  bool rc = false;
  pjsip_route_hdr* route_hdr = (pjsip_route_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_ROUTE, (start != NULL) ? start->next : NULL);

  if (route_hdr != NULL)
  {
    // Found the next Route header, so check whether the URI corresponds to
    // this node or one of its aliases.
    pjsip_uri* uri = route_hdr->name_addr.uri;
    LOG_DEBUG("Found Route header, URI = %s", uri_to_string(PJSIP_URI_IN_ROUTING_HDR, uri).c_str());
    if ((is_home_domain(uri)) || (is_uri_local(uri)))
    {
      LOG_DEBUG("Route header is local");
      rc = true;
      if (hdr != NULL)
      {
        *hdr = route_hdr;
      }
    }
  }
  return rc;
}


/// Adds a Record-Route header to the message with the specified user name,
/// host, port and transport.  If the user parameter is NULL the user field is
/// left blank. If the top Record-Route header already matches the
/// added one, does nothing.
void PJUtils::add_record_route(pjsip_tx_data* tdata,
                               const char* transport,
                               int port,
                               const char* user,
                               const pj_str_t& host)
{
  pjsip_rr_hdr* top_rr_hdr = (pjsip_rr_hdr*)pjsip_msg_find_hdr(tdata->msg, PJSIP_H_RECORD_ROUTE, NULL);
  if (top_rr_hdr != NULL && PJSIP_URI_SCHEME_IS_SIP(top_rr_hdr->name_addr.uri))
  {
    pjsip_sip_uri* top_rr_uri = (pjsip_sip_uri*)top_rr_hdr->name_addr.uri;
    pj_str_t top_host = top_rr_uri->host;
    pj_str_t top_user = top_rr_uri->user;
    pj_str_t top_transport = top_rr_uri->transport_param;
    int top_port = top_rr_uri->port;
    if ((pj_strcmp2(&top_user, user) == 0) &&
        (pj_strcmp(&top_host, &host) == 0) &&
        (pj_strcmp2(&top_transport, transport) == 0) &&
        (port == top_port))
    {
      LOG_DEBUG("Top Record-Route header is already identical to the one we're adding; doing nothing");
      return;
    }
  }

  pjsip_rr_hdr* rr = pjsip_rr_hdr_create(tdata->pool);
  pjsip_sip_uri* uri = pjsip_sip_uri_create(tdata->pool, PJ_FALSE);
  uri->host = host;
  uri->port = port;
  pj_strdup2(tdata->pool, &uri->transport_param, transport);
  uri->lr_param = PJ_TRUE;

  if (user != NULL)
  {
    pj_strdup2(tdata->pool, &uri->user, user);
  }

  rr->name_addr.uri = (pjsip_uri*)uri;
  pjsip_msg_insert_first_hdr(tdata->msg, (pjsip_hdr*)rr);

  LOG_DEBUG("Added Record-Route header, URI = %s", uri_to_string(PJSIP_URI_IN_ROUTING_HDR, rr->name_addr.uri).c_str());
}


/// Remove all existing copies of a header.  The header to delete must
/// not be one that has an abbreviation.
void PJUtils::remove_hdr(pjsip_msg* msg,
                         const pj_str_t* name)
{
  while (pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(msg, name, NULL))
  {
    pj_list_erase(hdr);
  }
}


/// Delete all existing copies of a header and replace with a new one.
/// The header to delete must not be one that has an abbreviation.
void PJUtils::set_generic_header(pjsip_tx_data* tdata,
                                 const pj_str_t* name,
                                 const pj_str_t* value)
{
  remove_hdr(tdata->msg, name);
  pjsip_generic_string_hdr* new_hdr = pjsip_generic_string_hdr_create(tdata->pool, name, value);
  pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)new_hdr);
}


/// Checks whether the supplied message contains the extension in the
/// Supported header.
pj_bool_t PJUtils::msg_supports_extension(pjsip_msg* msg, const char* extension)
{
  pjsip_supported_hdr* supported_hdr = (pjsip_supported_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_SUPPORTED, NULL);
  if (!supported_hdr)
  {
    return PJ_FALSE;
  }
  for (unsigned ii = 0; ii < supported_hdr->count; ++ii)
  {
    if (pj_strcmp2(&supported_hdr->values[ii], extension) == 0)
    {
      return PJ_TRUE;
    }
  }
  return PJ_FALSE;
}


/// @return PJ_TRUE if the message is reaching us on its first hop.
pj_bool_t PJUtils::is_first_hop(pjsip_msg* msg)
{
  // We're the first hop if there's exactly one Via header in the
  // message we received.
  pjsip_via_hdr* via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr(msg,
                           PJSIP_H_VIA,
                           NULL);
  pj_bool_t first_hop = via_hdr && !pjsip_msg_find_hdr(msg,
                        PJSIP_H_VIA,
                        via_hdr->next);
  return first_hop;
}


/// Gets the maximum expires value from all contacts in a REGISTER message
/// (request or response).
int PJUtils::max_expires(pjsip_msg* msg, int default_expires)
{
  int max_expires = 0;

  // Check for an expires header (this will specify the default expiry for
  // any contacts that don't specify their own expiry).
  pjsip_expires_hdr* expires_hdr = (pjsip_expires_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_EXPIRES, NULL);
  if (expires_hdr != NULL)
  {
    default_expires = expires_hdr->ivalue;
  }

  pjsip_contact_hdr* contact = (pjsip_contact_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_CONTACT, NULL);

  while (contact != NULL)
  {
    int expires = (contact->expires != -1) ? contact->expires : default_expires;
    if (expires > max_expires)
    {
      max_expires = expires;
    }
    contact = (pjsip_contact_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_CONTACT, contact->next);
  }

  return max_expires;
}


pj_status_t PJUtils::create_response(pjsip_endpoint* endpt,
                                     const pjsip_rx_data* rdata,
                                     int st_code,
                                     const pj_str_t* st_text,
                                     pjsip_tx_data** p_tdata)
{
  pj_status_t status = pjsip_endpt_create_response(endpt,
                       rdata,
                       st_code,
                       st_text,
                       p_tdata);
  if (status == PJ_SUCCESS)
  {
    // Copy the SAS trail across from the request.
    set_trail(*p_tdata, get_trail(rdata));
  }
  return status;
}


pj_status_t PJUtils::create_request_fwd(pjsip_endpoint* endpt,
                                        pjsip_rx_data* rdata,
                                        const pjsip_uri* uri,
                                        const pj_str_t* branch,
                                        unsigned options,
                                        pjsip_tx_data** p_tdata)
{
  pj_status_t status = pjsip_endpt_create_request_fwd(endpt,
                                                      rdata,
                                                      uri,
                                                      branch,
                                                      options,
                                                      p_tdata);
  if (status == PJ_SUCCESS)
  {
    // Copy the SAS trail across from the request.
    set_trail(*p_tdata, get_trail(rdata));
  }
  return status;
}


pj_status_t PJUtils::create_response_fwd(pjsip_endpoint* endpt,
                                         pjsip_rx_data* rdata,
                                         unsigned options,
                                         pjsip_tx_data** p_tdata)
{
  pj_status_t status = pjsip_endpt_create_response_fwd(endpt,
                                                       rdata,
                                                       options,
                                                       p_tdata);
  if (status == PJ_SUCCESS)
  {
    // Copy the SAS trail across from the request.
    set_trail(*p_tdata, get_trail(rdata));
  }
  return status;
}


/// Resolves a destination.
void PJUtils::resolve(const std::string& name,
                      int port,
                      int transport,
                      int retries,
                      std::vector<AddrInfo>& servers)
{
  stack_data.sipresolver->resolve(name,
                                  stack_data.addr_family,
                                  port,
                                  transport,
                                  retries,
                                  servers);
}


/// Resolves the next hop target of the SIP message
void PJUtils::resolve_next_hop(pjsip_tx_data* tdata, int retries, std::vector<AddrInfo>& servers)
{
  // Get the next hop URI from the message and parse out the destination, port
  // and transport.
  pjsip_sip_uri* next_hop = (pjsip_sip_uri*)PJUtils::next_hop(tdata->msg);
  std::string name = std::string(next_hop->host.ptr, next_hop->host.slen);
  int port = next_hop->port;
  int transport = -1;
  if (pj_stricmp2(&next_hop->transport_param, "TCP") == 0)
  {
    transport = IPPROTO_TCP;
  }
  else if (pj_stricmp2(&next_hop->transport_param, "UDP") == 0)
  {
    transport = IPPROTO_UDP;
  }

  if (retries == 0)
  {
    // Used default number of retries.
    retries = DEFAULT_RETRIES;
  }

  stack_data.sipresolver->resolve(name,
                                  stack_data.addr_family,
                                  port,
                                  transport,
                                  retries,
                                  servers);
  LOG_INFO("Resolved destination URI %s to %d servers",
           PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                  (pjsip_uri*)next_hop).c_str(),
           servers.size());
}


/// Blacklists the specified server so it will not be preferred in subsequent
/// resolve calls.
void PJUtils::blacklist_server(AddrInfo& server)
{
  stack_data.sipresolver->blacklist(server, DEFAULT_BLACKLIST_DURATION);
}


/// Substitutes the branch identifier in the top Via header with a new unique
/// identifier.  This is used when forking requests and when retrying requests
/// to alternate servers.  This code is taken from pjsip_generate_branch_id
/// for the case when the branch ID is calculated from a GUID.
void PJUtils::generate_new_branch_id(pjsip_tx_data* tdata)
{
  pjsip_via_hdr* via = (pjsip_via_hdr*)
                             pjsip_msg_find_hdr(tdata->msg, PJSIP_H_VIA, NULL);
  via->branch_param.ptr = (char*)
                              pj_pool_alloc(tdata->pool, PJSIP_MAX_BRANCH_LEN);
  via->branch_param.slen = PJSIP_RFC3261_BRANCH_LEN;
  pj_memcpy(via->branch_param.ptr,
            PJSIP_RFC3261_BRANCH_ID,
            PJSIP_RFC3261_BRANCH_LEN);

  pj_str_t tmp;
  tmp.ptr = via->branch_param.ptr + PJSIP_RFC3261_BRANCH_LEN + 2;
  // Add "Pj" between the RFC3261 prefix and the random string to be consistent
  // with branch IDs generated by PJSIP.
  *(tmp.ptr-2) = 'P';
  *(tmp.ptr-1) = 'j';
  pj_generate_unique_string(&tmp);

  via->branch_param.slen = PJSIP_MAX_BRANCH_LEN;
}


/// Sets the dest_info structure in a pjsip_tx_data structure to the IP address,
/// port and transport in the specified AddrInfo structure.
void PJUtils::set_dest_info(pjsip_tx_data* tdata, const AddrInfo& ai)
{
  tdata->dest_info.cur_addr = 0;
  tdata->dest_info.addr.count = 1;
  tdata->dest_info.addr.entry[0].priority = 0;
  tdata->dest_info.addr.entry[0].weight = 0;

  if (ai.address.af == AF_INET)
  {
    // IPv4 address.
    tdata->dest_info.addr.entry[0].type =
                          (ai.transport == IPPROTO_TCP) ? PJSIP_TRANSPORT_TCP :
                                                          PJSIP_TRANSPORT_UDP;
    tdata->dest_info.addr.entry[0].addr.ipv4.sin_family = pj_AF_INET();
    tdata->dest_info.addr.entry[0].addr.ipv4.sin_addr.s_addr = ai.address.addr.ipv4.s_addr;
    tdata->dest_info.addr.entry[0].addr_len = sizeof(pj_sockaddr_in);
  }
  else if (ai.address.af == AF_INET6)
  {
    // IPv6 address.
    tdata->dest_info.addr.entry[0].type =
                         (ai.transport == IPPROTO_TCP) ? PJSIP_TRANSPORT_TCP6 :
                                                         PJSIP_TRANSPORT_UDP6;
    tdata->dest_info.addr.entry[0].addr.ipv6.sin6_family = pj_AF_INET6();
    tdata->dest_info.addr.entry[0].addr.ipv6.sin6_flowinfo = 0;
    memcpy((char*)&tdata->dest_info.addr.entry[0].addr.ipv6.sin6_addr,
           (char*)&ai.address.addr.ipv6,
           sizeof(pj_in6_addr));
    tdata->dest_info.addr.entry[0].addr.ipv6.sin6_scope_id = 0;
    tdata->dest_info.addr.entry[0].addr_len = sizeof(pj_sockaddr_in6);
  }
  pj_sockaddr_set_port(&tdata->dest_info.addr.entry[0].addr, ai.port);
}


struct StatefulSendState
{
  pjsip_tx_data* tdata;

  std::vector<AddrInfo> servers;
  int current_server;

  void* user_token;
  pjsip_endpt_send_callback user_cb;
};


static void on_tsx_state(pjsip_transaction* tsx, pjsip_event* event)
{
  StatefulSendState* sss;
  bool retrying = false;

  if ((mod_sprout_util.id < 0) ||
      (event->type != PJSIP_EVENT_TSX_STATE))
  {
    return;
  }

  sss = (StatefulSendState*)tsx->mod_data[mod_sprout_util.id];

  if (sss == NULL)
  {
    return;
  }

  if (!sss->servers.empty())
  {
    // The target for the request came from the resolver, so check to see
    // if the request failed.
    if ((tsx->state == PJSIP_TSX_STATE_COMPLETED) ||
        (tsx->state == PJSIP_TSX_STATE_TERMINATED))
    {
      // Transaction has completed or terminated.  We need to look at both
      // states as
      // -  timeouts and transport errors cause an immediate transition
      //    to terminated state, bypassing completed state
      // -  a 5xx response causes a transition to completed state, with a
      //    possible delay until the transition to terminated state (5 seconds
      //    for UDP transport), which would needlessly delay any retry.
      if ((event->body.tsx_state.type == PJSIP_EVENT_TIMER) ||
          (event->body.tsx_state.type == PJSIP_EVENT_TRANSPORT_ERROR) ||
          (PJSIP_IS_STATUS_IN_CLASS(tsx->status_code, 500)))
      {
        // Either transaction failed on a timeout, transport error or received
        // 5xx error, so blacklist the failed target.
        LOG_DEBUG("Transaction failed with retriable error");
        if ((event->body.tsx_state.type == PJSIP_EVENT_TIMER) ||
            (event->body.tsx_state.type == PJSIP_EVENT_TRANSPORT_ERROR))
        {
          // Either the connection failed, or the server didn't respond within
          // the timeout, so blacklist it.  We don't blacklist servers that
          // return 5xx errors as this may indicate a transient overload.
          PJUtils::blacklist_server(sss->servers[sss->current_server]);
        }

        // Can we do a retry?
        ++sss->current_server;
        if (sss->current_server < (int)sss->servers.size())
        {
          // More servers to try, so allocate a new branch ID and transaction.
          LOG_DEBUG("Attempt to resend request to next destination server");
          pjsip_tx_data* tdata = sss->tdata;
          pjsip_transaction* retry_tsx;
          PJUtils::generate_new_branch_id(tdata);
          pj_status_t status = pjsip_tsx_create_uac(&mod_sprout_util,
                                                    tdata,
                                                    &retry_tsx);

          if (status == PJ_SUCCESS)
          {
            // The new transaction has been set up.

            // Set the trail ID in the transaction from the message.
            set_trail(retry_tsx, get_trail(tdata));

            // Set up the module data for the new transaction to reference
            // the state information.
            retry_tsx->mod_data[mod_sprout_util.id] = sss;

            // Increment the reference count of the request as we are passing
            // it to a new transaction.
            pjsip_tx_data_add_ref(tdata);

            // Copy across the destination information for a retry and try to
            // resend the request.
            PJUtils::set_dest_info(tdata, sss->servers[sss->current_server]);
            status = pjsip_tsx_send_msg(retry_tsx, tdata);

            if (status == PJ_SUCCESS)
            {
              // Successfully sent a retry.  Make sure this callback isn't
              // invoked again for the previous transaction.
              tsx->mod_data[mod_sprout_util.id] = NULL;
              retrying = true;
            }
          }
        }
      }
    }
  }

  if ((!retrying) &&
      (tsx->status_code >= 200))
  {
    // Call the user callback, if any, and prevent the callback to be called again
    // by clearing the transaction's module_data.
    LOG_DEBUG("Request transaction completed, status code = %d", tsx->status_code);
    tsx->mod_data[mod_sprout_util.id] = NULL;

    if (sss->user_cb != NULL)
    {
      (*sss->user_cb)(sss->user_token, event);
    }

    // The transaction has completed, so decrement our reference to the tx_data
    // and free the state data.
    pjsip_tx_data_dec_ref(sss->tdata);
    delete sss;
  }
}


/// This provides function similar to the pjsip_endpt_send_request method
/// but includes setting the SAS trail.
pj_status_t PJUtils::send_request(pjsip_tx_data* tdata,
                                  int retries,
                                  void* token,
                                  pjsip_endpt_send_callback cb)
{
  pjsip_transaction* tsx;
  pj_status_t status = PJ_SUCCESS;

  LOG_DEBUG("Sending standalone request statefully");

  // Allocate temporary storage for the request.
  StatefulSendState* sss = new StatefulSendState;

  // Store the user supplied callback and token.
  sss->user_token = token;
  sss->user_cb = cb;

  if (tdata->tp_sel.type != PJSIP_TPSELECTOR_TRANSPORT)
  {
    // No transport determined, so resolve the next hop for the message.
    resolve_next_hop(tdata, retries, sss->servers);

    if (!sss->servers.empty())
    {
      // Set up the destination information for the first server.
      sss->current_server = 0;
      set_dest_info(tdata, sss->servers[sss->current_server]);
    }
    else
    {
      // No servers found.
      status = PJ_ENOTFOUND;
    }
  }

  if (status == PJ_SUCCESS)
  {
    // We have servers to send the request to, so allocate a transaction.
    status = pjsip_tsx_create_uac(&mod_sprout_util, tdata, &tsx);

    if (status == PJ_SUCCESS)
    {
      // Set the trail ID in the transaction from the message.
      set_trail(tsx, get_trail(tdata));

      // Set up the module data for the new transaction to reference
      // the state information.
      tsx->mod_data[mod_sprout_util.id] = sss;

      if (tdata->tp_sel.type == PJSIP_TPSELECTOR_TRANSPORT)
      {
        // Transport has already been determined, so copy it across to the
        // transaction.
        LOG_DEBUG("Transport already determined");
        pjsip_tsx_set_transport(tsx, &tdata->tp_sel);
      }

      // Store the message and add a reference to prevent the transaction layer
      // freeing it.
      sss->tdata = tdata;
      pjsip_tx_data_add_ref(tdata);

      LOG_DEBUG("Sending request");
      status = pjsip_tsx_send_msg(tsx, tdata);
    }
  }

  if (status != PJ_SUCCESS)
  {
    // The assumption here is that, if pjsip_tsx_send_msg returns an error
    // the on_tsx_state callback will not get called, so it is safe to free
    // off the state data and request here.  Also, this is an unexpected
    // error rather than an indication that the destination server is down,
    // so we don't blacklist.
    LOG_ERROR("Failed to send request to %s",
              PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                     PJUtils::next_hop(tdata->msg)).c_str());
    pjsip_tx_data_dec_ref(tdata);
    delete sss;
  }

  return status;
}


/// Data structure used to hold temporary status when statelessly sending
/// a request.
struct StatelessSendState
{
  std::vector<AddrInfo> servers;
  int current_server;
};


/// Callback used for PJUtils::send_request_stateless
static void stateless_send_cb(pjsip_send_state *st,
                              pj_ssize_t sent,
                              pj_bool_t *cont)
{
  *cont = PJ_FALSE;
  bool retrying = false;

  StatelessSendState* sss = (StatelessSendState*)st->token;

  if ((sent <= 0) &&
      (!sss->servers.empty()))
  {
    // Request to a resolved server failed.  When sending statelessly
    // this means we couldn't get a transport, so couldn't connect to the
    // selected target, so we always blacklist.
    PJUtils::blacklist_server(sss->servers[sss->current_server]);

    // Can we do a retry?
    pj_status_t status = PJ_ENOTFOUND;
    ++sss->current_server;
    if (sss->current_server < (int)sss->servers.size())
    {
      pjsip_tx_data* tdata = st->tdata;

      // According to RFC3263 we should generate a new branch identifier for
      // the message so there is no possibility of it being confused with
      // previous attempts.  Not clear this is really necessary in this case,
      // but just in case ...
      PJUtils::generate_new_branch_id(tdata);

      // Set up destination info for the new server and resend the request.
      PJUtils::set_dest_info(tdata, sss->servers[sss->current_server]);
      status = pjsip_endpt_send_request_stateless(stack_data.endpt,
                                                  tdata,
                                                  (void*)sss,
                                                  &stateless_send_cb);

      if (status == PJ_SUCCESS)
      {
        // Add a reference to the tdata to stop PJSIP releasing it when we
        // return the callback.
        pjsip_tx_data_add_ref(tdata);
        retrying = true;
      }
    }
  }

  if ((sent > 0) ||
      (!retrying))
  {
    // Either the request was sent successfully, or we couldn't retry.
    delete sss;
  }
}


/// Sends a request statelessly, possibly retrying the specified number of
/// times if the
pj_status_t PJUtils::send_request_stateless(pjsip_tx_data* tdata, int retries)
{
  pj_status_t status = PJ_SUCCESS;
  StatelessSendState* sss = new StatelessSendState;
  sss->current_server = 0;

  if (tdata->tp_sel.type != PJSIP_TPSELECTOR_TRANSPORT)
  {
    // No transport pre-selected so resolve the next hop to a set of servers.
    resolve_next_hop(tdata, retries, sss->servers);

    if (!sss->servers.empty())
    {
      // Select the next target set up the destination info in the tdata and
      // send the request.
      sss->current_server = 0;
      set_dest_info(tdata, sss->servers[sss->current_server]);
    }
    else
    {
      // No servers found.
      status = PJ_ENOTFOUND;
    }
  }

  if (status == PJ_SUCCESS)
  {
    status = pjsip_endpt_send_request_stateless(stack_data.endpt,
                                                tdata,
                                                (void*)sss,
                                                stateless_send_cb);
  }

  if (status != PJ_SUCCESS)
  {
    // The assumption is that if pjsip_endpt_send_request_stateless fails
    // the callback is not called, so it is safe to free off the state data
    // and the request here.  Also, this would be an unexpected error rather
    // than an indication that the selected destination server is down, so we
    // don't blacklist.
    LOG_ERROR("Failed to send request to %s",
              PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                     PJUtils::next_hop(tdata->msg)).c_str());
    pjsip_tx_data_dec_ref(tdata);
    delete sss;
  }

  return status;
}


/// This is a clone of the PJSIP pjsip_endpt_respond_stateless function,
/// with the addition of code to reflect the trail on the request on to the
/// response.  All sprout application code should use this method instead.
pj_status_t PJUtils::respond_stateless(pjsip_endpoint* endpt,
                                       pjsip_rx_data* rdata,
                                       int st_code,
                                       const pj_str_t* st_text,
                                       const pjsip_hdr* hdr_list,
                                       const pjsip_msg_body* body)
{
  pj_status_t status;
  pjsip_response_addr res_addr;
  pjsip_tx_data* tdata;

  // Create response message
  status = create_response(endpt, rdata, st_code, st_text, &tdata);
  if (status != PJ_SUCCESS)
  {
    return status;
  }

  // Add the message headers, if any
  if (hdr_list)
  {
    const pjsip_hdr* hdr = hdr_list->next;
    while (hdr != hdr_list)
    {
      pjsip_msg_add_hdr(tdata->msg,
                        (pjsip_hdr*) pjsip_hdr_clone(tdata->pool, hdr) );
      hdr = hdr->next;
    }
  }

  // Add the message body, if any.
  if (body)
  {
    tdata->msg->body = pjsip_msg_body_clone(tdata->pool, body);
    if (tdata->msg->body == NULL)
    {
      pjsip_tx_data_dec_ref(tdata);
      return status;
    }
  }

  // Get where to send request.
  status = pjsip_get_response_addr(tdata->pool, rdata, &res_addr);
  if (status != PJ_SUCCESS)
  {
    pjsip_tx_data_dec_ref(tdata);
    return status;
  }

  // Send!
  status = pjsip_endpt_send_response(endpt, &res_addr, tdata, NULL, NULL);
  if (status != PJ_SUCCESS)
  {
    pjsip_tx_data_dec_ref(tdata);
    return status;
  }

  return PJ_SUCCESS;
}


/// This is analogous to respond_stateless, although in this case to
/// respond statefully on an existing transaction.  Strangely there is
/// no equivalent PJSIP API.
pj_status_t PJUtils::respond_stateful(pjsip_endpoint* endpt,
                                      pjsip_transaction* uas_tsx,
                                      pjsip_rx_data* rdata,
                                      int st_code,
                                      const pj_str_t* st_text,
                                      const pjsip_hdr* hdr_list,
                                      const pjsip_msg_body* body)
{
  pj_status_t status;
  pjsip_tx_data* tdata;

  status = create_response(stack_data.endpt, rdata, st_code, st_text, &tdata);
  if (status != PJ_SUCCESS)
  {
    return status;
  }

  // Add the message headers, if any
  if (hdr_list)
  {
    const pjsip_hdr* hdr = hdr_list->next;
    while (hdr != hdr_list)
    {
      pjsip_msg_add_hdr(tdata->msg,
                        (pjsip_hdr*) pjsip_hdr_clone(tdata->pool, hdr) );
      hdr = hdr->next;
    }
  }

  // Add the message body, if any.
  if (body)
  {
    tdata->msg->body = pjsip_msg_body_clone(tdata->pool, body);
    if (tdata->msg->body == NULL)
    {
      pjsip_tx_data_dec_ref(tdata);
      return status;
    }
  }

  status = pjsip_tsx_send_msg(uas_tsx, tdata);

  return status;
}


pjsip_tx_data* PJUtils::clone_tdata(pjsip_tx_data* tdata)
{
  pjsip_tx_data* cloned_tdata;
  pj_status_t status;

  status = pjsip_endpt_create_tdata(stack_data.endpt, &cloned_tdata);
  if (status != PJ_SUCCESS)
  {
    return NULL;
  }

  // Always increment ref counter to 1.
  pjsip_tx_data_add_ref(cloned_tdata);

  // Clone the message from the supplied tdata.
  cloned_tdata->msg = pjsip_msg_clone(cloned_tdata->pool, tdata->msg);

  if (cloned_tdata->msg == NULL)
  {
    pjsip_tx_data_dec_ref(cloned_tdata);
    cloned_tdata = NULL;
  }

  // Copy the trail identifier to the cloned message.
  set_trail(cloned_tdata, get_trail(tdata));

  if (tdata->msg->type == PJSIP_REQUEST_MSG)
  {
    // Substitute the branch value in the top Via header with a unique
    // branch identifier.
    generate_new_branch_id(cloned_tdata);
  }

  // If the original message already had a specified transport set this
  // on the clone.  (Must use pjsip_tx_data_set_transport to ensure
  // reference counts get updated.)
  if (tdata->tp_sel.type == PJSIP_TPSELECTOR_TRANSPORT)
  {
    pjsip_tx_data_set_transport(cloned_tdata, &tdata->tp_sel);
  }

  // If the message has any addr in dest_info, copy that
  if (tdata->dest_info.addr.count != 0)
  {
    pj_memcpy(&cloned_tdata->dest_info, &tdata->dest_info, sizeof(cloned_tdata->dest_info));
  }

  return cloned_tdata;
}


bool PJUtils::compare_pj_sockaddr(const pj_sockaddr& lhs, const pj_sockaddr& rhs)
{
  return (pj_sockaddr_cmp(&lhs, &rhs) < 0);
}


/// Generate a random base64-encoded token.
void PJUtils::create_random_token(size_t length,       //< Number of characters.
                                  std::string& token)  //< Destination. Must be empty.
{
  token.reserve(length);

  for (size_t ii = 0; ii < length; ++ii)
  {
    token += _b64[rand() % 64];
  }
}


void PJUtils::clone_header(const pj_str_t* hdr_name, pjsip_msg* old_msg, pjsip_msg* new_msg, pj_pool_t* pool)
{
  pjsip_hdr* original_hdr = NULL;
  pjsip_hdr* last_hdr = NULL;
  while ((original_hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(old_msg, hdr_name, original_hdr)) && (last_hdr != original_hdr))
  {
    LOG_INFO("Cloning header! %ld", (long int)original_hdr);
    pjsip_hdr* new_hdr = (pjsip_hdr*)pjsip_hdr_clone(pool, original_hdr);
    pjsip_msg_add_hdr(new_msg, new_hdr);
    last_hdr = original_hdr;
  }
}

std::string PJUtils::get_header_value(pjsip_hdr* header)
{
#define MAX_HDR_SIZE 4096
  char buf[MAX_HDR_SIZE] = "";
  char* buf2 = buf;

  int len = pjsip_hdr_print_on(header, buf2, MAX_HDR_SIZE);
  // pjsip_hdr_print_on doesn't appear to null-terminate the string - do this by hand
  buf2[len] = '\0';

  // Skip over all text up to the colon, then any whitespace following it
  while ((*buf2 != ':') || (*buf2 == ' '))
  {
    buf2++;
  }
  return std::string(buf2, len);
}

/// Add SAS markers for the specified call ID and branch IDs on the message (either may be omitted).
void PJUtils::mark_sas_call_branch_ids(const SAS::TrailId trail, pjsip_cid_hdr* cid_hdr, pjsip_msg* msg)
{
  // If we have a call ID, log it.
  if (cid_hdr != NULL)
  {
    SAS::Marker cid_marker(trail, MARKER_ID_SIP_CALL_ID, 1u);
    cid_marker.add_var_param(cid_hdr->id.slen, cid_hdr->id.ptr);
    SAS::report_marker(cid_marker, SAS::Marker::Scope::Trace);
  }

  // If we have a message, look for branch IDs too.
  if (msg != NULL)
  {
    // First find the top Via header.  This was added by us.
    pjsip_via_hdr* top_via = (pjsip_via_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_VIA, NULL);

    // If we found the top header (and we really should have done), log its branch ID.
    if (top_via != NULL)
    {
      {
        SAS::Marker via_marker(trail, MARKER_ID_VIA_BRANCH_PARAM, 1u);
        via_marker.add_var_param(top_via->branch_param.slen, top_via->branch_param.ptr);
        SAS::report_marker(via_marker, SAS::Marker::Scope::Trace);
      }

      // Now see if we can find the next Via header and log it if so.  This will have been added by
      // the previous server.  This means we'll be able to correlate with its trail.
      pjsip_via_hdr* second_via = (pjsip_via_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_VIA, top_via);
      if (second_via != NULL)
      {
        SAS::Marker via_marker(trail, MARKER_ID_VIA_BRANCH_PARAM, 2u);
        via_marker.add_var_param(second_via->branch_param.slen, second_via->branch_param.ptr);
        SAS::report_marker(via_marker, SAS::Marker::Scope::Trace);
      }
    }
  }
}

