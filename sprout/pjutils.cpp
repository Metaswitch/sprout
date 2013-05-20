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

///

#include "pjutils.h"

extern "C" {
#include <pjlib-util.h>
#include <pjlib.h>
}

#include "stack.h"
#include "log.h"
#include "constants.h"


// Utility to determine if this URI belongs to the home domain.
pj_bool_t PJUtils::is_home_domain(const pjsip_uri* uri)
{
  if ((PJSIP_URI_SCHEME_IS_SIP(uri)) &&
      (pj_stricmp(&((pjsip_sip_uri*)uri)->host, &stack_data.home_domain)==0))
  {
    return PJ_TRUE;
  }
  return PJ_FALSE;
}


// Utility to determine if URI is local to this host.
pj_bool_t PJUtils::is_uri_local(const pjsip_uri* uri)
{
  if (PJSIP_URI_SCHEME_IS_SIP(uri))
  {
    int port = (((pjsip_sip_uri*)uri)->port != 0) ? ((pjsip_sip_uri*)uri)->port : 5060;
    pj_str_t host = ((pjsip_sip_uri*)uri)->host;

    if ((port == stack_data.trusted_port) ||
        (port == stack_data.untrusted_port))
    {
      // Port matches, check the list of host names.
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
  }

  /* Doesn't match */
  return PJ_FALSE;
}


// Utility to determine if a user field contains a valid E.164 number
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


// Utility to determine if URI contains a valid E.164 number
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


pjsip_uri* PJUtils::uri_from_string(const std::string& uri_s,
                                    pj_pool_t *pool)
{
  // We must duplicate the string into memory from the specified pool first as
  // pjsip_parse_uri does not clone the actual strings within the URI.
  size_t len = uri_s.length();
  char* buf = (char*)pj_pool_alloc(pool, len + 1);
  memcpy(buf, uri_s.data(), len);
  buf[len] = 0;
  return pjsip_parse_uri(pool, buf, len, 0);
}


/// Get the URI (either name-addr or addr-spec) from the string header
/// (e.g., P-Served-User), ignoring any parameters. If it's a bare
/// addr-spec, assume (like Contact) that parameters belong to the
/// header, not to the URI.
///
/// @return URI, or NULL if cannot be parsed.
pjsip_uri* PJUtils::uri_from_string_header(pjsip_generic_string_hdr* hdr,
                                           pj_pool_t *pool)
{
  // We must duplicate the string into memory from the specified pool first as
  // pjsip_parse_uri does not clone the actual strings within the URI.
  pj_str_t hvalue;
  pj_strdup_with_null(pool, &hvalue, &hdr->hvalue);
  char* end = strchr(hvalue.ptr, '>');
  if (end != NULL)
  {
    *(end + 1) = '\0';
    hvalue.slen = (end + 1 - hvalue.ptr);
  }
  return pjsip_parse_uri(pool, hvalue.ptr, hvalue.slen, 0);
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


/// Adds a header indicating the message is integrity protected because it
/// was received on a transport that has already been authenticated.
void PJUtils::add_integrity_protected_indication(pjsip_tx_data* tdata)
{
  LOG_INFO("Adding integrity-protected indicator to message");
  pjsip_authorization_hdr* auth_hdr = (pjsip_authorization_hdr*)
                   pjsip_msg_find_hdr(tdata->msg, PJSIP_H_AUTHORIZATION, NULL);

  if (auth_hdr == NULL)
  {
    auth_hdr = pjsip_authorization_hdr_create(tdata->pool);
    auth_hdr->scheme = pj_str("Digest");
    auth_hdr->credential.digest.realm = pj_str("");
    auth_hdr->credential.digest.username = PJUtils::uri_to_pj_str(PJSIP_URI_IN_FROMTO_HDR, tdata->msg->line.req.uri, tdata->pool);
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)auth_hdr);
  }
  pjsip_param* new_param = (pjsip_param*) pj_pool_alloc(tdata->pool, sizeof(pjsip_param));
  new_param->name = STR_INTEGRITY_PROTECTED;
  new_param->value = pj_str("\"yes\"");
  pj_list_insert_before(&auth_hdr->credential.common.other_param, new_param);
}


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


pj_status_t PJUtils::create_response(pjsip_endpoint *endpt,
                                     const pjsip_rx_data *rdata,
                                     int st_code,
                                     const pj_str_t *st_text,
                                     pjsip_tx_data **p_tdata)
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


pj_status_t PJUtils::create_request_fwd(pjsip_endpoint *endpt,
                                        pjsip_rx_data *rdata,
                                        const pjsip_uri *uri,
                                        const pj_str_t *branch,
                                        unsigned options,
                                        pjsip_tx_data **p_tdata)
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


pj_status_t PJUtils::create_response_fwd(pjsip_endpoint *endpt,
                                         pjsip_rx_data *rdata,
                                         unsigned options,
                                         pjsip_tx_data **p_tdata)
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


// This is a clone of the PJSIP pjsip_endpt_respond_stateless function,
// with the addition of code to reflect the trail on the request on to the
// response.  All sprout application code should use this method instead.
pj_status_t PJUtils::respond_stateless(pjsip_endpoint *endpt,
                                       pjsip_rx_data *rdata,
                                       int st_code,
                                       const pj_str_t *st_text,
                                       const pjsip_hdr *hdr_list,
                                       const pjsip_msg_body *body)
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
    const pjsip_hdr *hdr = hdr_list->next;
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


// This is analogous to respond_stateless, although in this case to
// respond statefully on an existing transaction.  Strangely there is
// equivalent PJSIP API.
pj_status_t PJUtils::respond_stateful(pjsip_endpoint* endpt,
                                      pjsip_transaction* uas_tsx,
                                      pjsip_rx_data* rdata,
                                      int st_code,
                                      const pj_str_t *st_text,
                                      const pjsip_hdr *hdr_list,
                                      const pjsip_msg_body *body)
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
    const pjsip_hdr *hdr = hdr_list->next;
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


pjsip_tx_data *PJUtils::clone_tdata(pjsip_tx_data *tdata)
{
  pjsip_tx_data *cloned_tdata;
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
    pjsip_via_hdr *via = (pjsip_via_hdr*)
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
  if (tdata->dest_info.addr.count != 0) {
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

void PJUtils::clone_header(const pj_str_t* hdr_name, pjsip_msg* old_msg, pjsip_msg* new_msg, pj_pool_t* pool) {
  pjsip_hdr *original_hdr = NULL;
  pjsip_hdr *last_hdr = NULL;
  while ((original_hdr = (pjsip_hdr *)pjsip_msg_find_hdr_by_name(old_msg, hdr_name, original_hdr)) && (last_hdr != original_hdr)) {
    LOG_INFO("Cloning header! %ld", (long int)original_hdr);
    pjsip_hdr *new_hdr = (pjsip_hdr *)pjsip_hdr_clone(pool, original_hdr);
    pjsip_msg_add_hdr(new_msg, new_hdr);
    last_hdr = original_hdr;
  }
}
