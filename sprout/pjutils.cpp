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

#include <boost/algorithm/string.hpp>
#include "stack.h"
#include "log.h"
#include "constants.h"


/// Utility to determine if this URI belongs to the home domain.
pj_bool_t PJUtils::is_home_domain(const pjsip_uri* uri)
{
  if ((PJSIP_URI_SCHEME_IS_SIP(uri)) &&
      (pj_stricmp(&((pjsip_sip_uri*)uri)->host, &stack_data.home_domain)==0))
  {
    return PJ_TRUE;
  }
  return PJ_FALSE;
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
  return uri_to_string(PJSIP_URI_IN_FROMTO_HDR, (pjsip_uri*)&aor);
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


void PJUtils::add_integrity_protected_indication(pjsip_tx_data* tdata, Integrity integrity)
{
  LOG_INFO("Adding integrity-protected indicator to message");
  pjsip_authorization_hdr* auth_hdr = (pjsip_authorization_hdr*)
                                      pjsip_msg_find_hdr(tdata->msg, PJSIP_H_AUTHORIZATION, NULL);

  if (auth_hdr == NULL)
  {
    auth_hdr = pjsip_authorization_hdr_create(tdata->pool);
    auth_hdr->scheme = pj_str("Digest");
    auth_hdr->credential.digest.realm = stack_data.home_domain;
    auth_hdr->credential.digest.username = PJUtils::uri_to_pj_str(PJSIP_URI_IN_FROMTO_HDR, tdata->msg->line.req.uri, tdata->pool);
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
  pj_list_insert_before(&auth_hdr->credential.common.other_param, new_param);
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


extern pjsip_hdr_vptr identity_hdr_vptr;

/// Creates an identity header (so either P-Associated-URI, P-Asserted-Identity
/// or P-Preferred-Identity)
pjsip_routing_hdr* PJUtils::identity_hdr_create(pj_pool_t* pool, const pj_str_t& name)
{
  pjsip_routing_hdr* hdr = (pjsip_routing_hdr*)pj_pool_alloc(pool, sizeof(pjsip_routing_hdr));

  pj_list_init(hdr);
  hdr->vptr = &identity_hdr_vptr;
  hdr->type = PJSIP_H_OTHER;
  hdr->name = name;
  hdr->sname = pj_str("");
  pjsip_name_addr_init(&hdr->name_addr);
  pj_list_init(&hdr->other_param);

  return hdr;
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
/// port and transport.  If the user parameter is NULL the user field is left
/// blank.
void PJUtils::add_record_route(pjsip_tx_data* tdata,
                               const char* transport,
                               int port,
                               const char* user)
{
  pjsip_rr_hdr* rr = pjsip_rr_hdr_create(tdata->pool);
  pjsip_sip_uri* uri = pjsip_sip_uri_create(tdata->pool, PJ_FALSE);
  uri->host = stack_data.name[0];
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


/// Delete all existing copies of a header.  The header to delete must
/// not be one that has an abbreviation.
void PJUtils::delete_header(pjsip_msg* msg,
                            const pj_str_t* name)
{
  while (1)
  {
    pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(msg, name, NULL);
    if (hdr)
    {
      pj_list_erase(hdr);
    }
    else
    {
      break;
    }
  }
}


/// Delete all existing copies of a header and replace with a new one.
/// The header to delete must not be one that has an abbreviation.
void PJUtils::set_generic_header(pjsip_tx_data* tdata,
                                 const pj_str_t* name,
                                 const pj_str_t* value)
{
  delete_header(tdata->msg, name);
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
int PJUtils::max_expires(pjsip_msg* msg)
{
  int max_expires = 0;

  // Check for an expires header (this will specify the default expiry for
  // any contacts that don't specify their own expiry).
  pjsip_expires_hdr* expires_hdr = (pjsip_expires_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_EXPIRES, NULL);
  int default_expires = (expires_hdr != NULL) ? expires_hdr->ivalue : 300;

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
  NULL,                           // on_tsx_state()
};

/// This provides function similar to the pjsip_endpt_send_request method
/// but includes setting the SAS trail.  It does not support the timeout, token
/// or callback options.
pj_status_t PJUtils::send_request(pjsip_endpoint* endpt,
                                  pjsip_tx_data* tdata)
{
  pjsip_transaction* tsx;
  pj_status_t status;

  status = pjsip_tsx_create_uac(&mod_sprout_util, tdata, &tsx);
  if (status != PJ_SUCCESS)
  {
    pjsip_tx_data_dec_ref(tdata);
    return status;
  }

  pjsip_tsx_set_transport(tsx, &tdata->tp_sel);

  // Set the trail ID in the transaction from the message.
  set_trail(tsx, get_trail(tdata));

  status = pjsip_tsx_send_msg(tsx, NULL);
  if (status != PJ_SUCCESS)
  {
    pjsip_tx_data_dec_ref(tdata);
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
    pjsip_via_hdr* via = (pjsip_via_hdr*)
                         pjsip_msg_find_hdr(cloned_tdata->msg, PJSIP_H_VIA, NULL);
    via->branch_param.ptr = (char*)
                            pj_pool_alloc(cloned_tdata->pool, PJSIP_MAX_BRANCH_LEN);
    via->branch_param.slen = PJSIP_RFC3261_BRANCH_LEN;
    pj_memcpy(via->branch_param.ptr,
              PJSIP_RFC3261_BRANCH_ID, PJSIP_RFC3261_BRANCH_LEN);

    pj_str_t tmp;
    tmp.ptr = via->branch_param.ptr + PJSIP_RFC3261_BRANCH_LEN + 2;
    // I have absolutely no idea what the following two lines do, but it
    // doesn't seem to work without them!
    *(tmp.ptr-2) = (pj_int8_t)(via->branch_param.slen+73);
    *(tmp.ptr-1) = (pj_int8_t)(via->branch_param.slen+99);
    pj_generate_unique_string( &tmp );

    via->branch_param.slen = PJSIP_MAX_BRANCH_LEN;
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
