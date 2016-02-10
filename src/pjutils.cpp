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
#include <pjsip.h>
#include "pjsip-simple/evsub.h"
}

#include "sprout_pd_definitions.h"

#include "stack.h"
#include "log.h"
#include "constants.h"
#include "custom_headers.h"
#include "sasevent.h"
#include "sproutsasevent.h"
#include "enumservice.h"
#include "uri_classifier.h"


static const int DEFAULT_RETRIES = 5;

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


std::string PJUtils::strip_uri_scheme(const std::string& uri)
{
  std::string s(uri);
  size_t colon = s.find(':');
  if (colon != std::string::npos)
  {
    s.erase(0, colon + 1);
  }
  return s;
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
  return ((pjstr != NULL) && (pj_strlen(pjstr) > 0)) ? std::string(pj_strbuf(pjstr), pj_strlen(pjstr)) : std::string("");
}

std::string PJUtils::pj_str_to_unquoted_string(const pj_str_t* pjstr)
{
  std::string ret = pj_str_to_string(pjstr);

  if ((ret.front() == '"') && (ret.back() == '"'))
  {
    ret = ret.substr(1, (ret.size() - 2));
  }

  return ret;
}

std::string PJUtils::pj_status_to_string(const pj_status_t status)
{
  char errmsg[PJ_ERR_MSG_SIZE];

  pj_strerror(status, errmsg, sizeof(errmsg));
  return std::string(errmsg);
}


std::string PJUtils::hdr_to_string(void* hdr)
{
  char buf[500];
  int len = pjsip_hdr_print_on((pjsip_hdr*)hdr, buf, sizeof(buf));
  return std::string(buf, len);
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
    public_id.userinfo_param.next = NULL;
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
  else if (PJSIP_URI_SCHEME_IS_TEL(uri))
  {
    id = PJUtils::pj_str_to_string(&((pjsip_tel_uri*)uri)->number) +
               "@" + PJUtils::pj_str_to_string(&stack_data.default_home_domain);
  }
  else
  {
    const pj_str_t* scheme = pjsip_uri_get_scheme(uri);
    TRC_WARNING("Unsupported scheme \"%.*s\" in To header when determining private ID - ignoring",
                scheme->slen, scheme->ptr);
  }

  return id;
}

/// Extract the domain from a SIP URI, or if its another type of URI, return
/// the default home domain.
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
    TRC_DEBUG("Served user from P-Served-User header");
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
      TRC_DEBUG("Served user from P-Asserted-Identity header");
    }
  }

  if (uri == NULL)
  {
    // Neither IMS header is present, so use the From header.  This isn't
    // strictly speaking IMS compliant.
    TRC_DEBUG("From header %p", PJSIP_MSG_FROM_HDR(msg));
    uri = (pjsip_uri*)pjsip_uri_get_uri(PJSIP_MSG_FROM_HDR(msg)->uri);
    TRC_DEBUG("Served user from From header (%p)", uri);
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

void PJUtils::add_pvni(pjsip_tx_data* tdata, pj_str_t* network_id)
{
  pjsip_generic_string_hdr* pvni_hdr = pjsip_generic_string_hdr_create(tdata->pool,
                                                                       &STR_P_V_N_I,
                                                                       network_id);
  pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)pvni_hdr);
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
    TRC_DEBUG("Construct default private identity");
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
  TRC_INFO("Adding integrity-protected=%.*s indicator to message",
           new_param->value.slen, new_param->value.ptr);
  pj_list_insert_before(&auth_hdr->credential.common.other_param, new_param);
}

// Add an empty Proxy-Authorization header to signal to Sprout that this needs to be challenged
void PJUtils::add_proxy_auth_for_pbx(pjsip_tx_data* tdata)
{
  pjsip_proxy_authorization_hdr* auth_hdr = (pjsip_proxy_authorization_hdr*)
                                      pjsip_msg_find_hdr(tdata->msg, PJSIP_H_PROXY_AUTHORIZATION, NULL);

  if (auth_hdr == NULL)
  {
    // Creates a minimal Authorization header (which PJSIP prints with just an empty 'nonce' and
    // 'response' field).
    auth_hdr = pjsip_proxy_authorization_hdr_create(tdata->pool);
    auth_hdr->scheme = pj_str("Digest");
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)auth_hdr);
  }
}

std::string PJUtils::extract_username(pjsip_authorization_hdr* auth_hdr, pjsip_uri* impu_uri)
{
  std::string impi;
  // Check to see if the request has an explicit IMPI in the Proxy-Authorization header
  if ((auth_hdr != NULL) &&
      (auth_hdr->credential.digest.username.slen != 0))
  {
    impi = PJUtils::pj_str_to_string(&auth_hdr->credential.digest.username);
    TRC_DEBUG("Private identity from authorization header = %s", impi.c_str());
  }
  else
  {
    // IMPI not supplied, so construct a default from the IMPU by stripping the sip: prefix.
    impi = PJUtils::default_private_id_from_uri(impu_uri);
    TRC_DEBUG("Private identity defaulted from public identity = %s", impi.c_str());
  }
  return impi;
}

void PJUtils::get_impi_and_impu(pjsip_rx_data* rdata, std::string& impi_out, std::string& impu_out)
{
  pjsip_authorization_hdr* auth_hdr;
  pjsip_uri* impu_uri;
  if (rdata->msg_info.msg->line.req.method.id == PJSIP_REGISTER_METHOD)
  {
    impu_uri = (pjsip_uri*)pjsip_uri_get_uri(PJSIP_MSG_TO_HDR(rdata->msg_info.msg)->uri);

    auth_hdr = (pjsip_authorization_hdr*)pjsip_msg_find_hdr(rdata->msg_info.msg,
                                                            PJSIP_H_AUTHORIZATION,
                                                            NULL);
  }
  else
  {
    // Retrieve the IMPU for a non-REGISTER request by determining the originating served user, and
    // the IMPI from the Proxy-Authorization header.
    impu_uri = orig_served_user(rdata->msg_info.msg);

    auth_hdr = (pjsip_proxy_authorization_hdr*)pjsip_msg_find_hdr(rdata->msg_info.msg,
                                                                  PJSIP_H_PROXY_AUTHORIZATION,
                                                                  NULL);
  }

  impu_out = PJUtils::public_id_from_uri(impu_uri);
  impi_out = PJUtils::extract_username(auth_hdr, impu_uri);
}

/// Adds a P-Asserted-Identity header to the message.
void PJUtils::add_asserted_identity(pjsip_msg* msg,
                                    pj_pool_t* pool,
                                    const std::string& aid,
                                    const pj_str_t& display_name)
{
  TRC_DEBUG("Adding P-Asserted-Identity header: %s", aid.c_str());
  pjsip_routing_hdr* p_asserted_id =
                     identity_hdr_create(pool, STR_P_ASSERTED_IDENTITY);

  pjsip_name_addr* temp = (pjsip_name_addr*)uri_from_string(aid, pool, true);
  if (display_name.slen > 0)
  {
    temp->display = display_name;
  }
  memcpy(&p_asserted_id->name_addr, temp, sizeof(pjsip_name_addr));

  pjsip_msg_add_hdr(msg, (pjsip_hdr*)p_asserted_id);
}

void PJUtils::add_asserted_identity(pjsip_tx_data* tdata,
                                    const std::string& aid)
{
  pj_str_t display_name;
  display_name.slen = 0;
  add_asserted_identity(tdata->msg, tdata->pool, aid, display_name);
}


/// Returns the next hop for a SIP request.  This will either be the
/// URI in the top-most Route header, or the RequestURI if there are no
/// Route headers.
pjsip_uri* PJUtils::next_hop(pjsip_msg* msg)
{
  pjsip_route_hdr* route_hdr = (pjsip_route_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_ROUTE, NULL);
  TRC_DEBUG("Next hop node is encoded in %s", (route_hdr != NULL) ? "top route header" : "Request-URI");
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
    URIClass uri_class = URIClassifier::classify_uri(uri);
    TRC_DEBUG("Found Route header, URI = %s", uri_to_string(PJSIP_URI_IN_ROUTING_HDR, uri).c_str());
    if ((uri_class == NODE_LOCAL_SIP_URI) ||
        (uri_class == HOME_DOMAIN_SIP_URI))
    {
      TRC_DEBUG("Route header is local");
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

  TRC_DEBUG("Added Record-Route header, URI = %s", uri_to_string(PJSIP_URI_IN_ROUTING_HDR, rr->name_addr.uri).c_str());
}

/// Add a Route header with the specified URI.
void PJUtils::add_top_route_header(pjsip_msg* msg,
                                   pjsip_sip_uri* uri,
                                   pj_pool_t* pool)
{
  pjsip_route_hdr* hroute = pjsip_route_hdr_create(pool);
  hroute->name_addr.uri = (pjsip_uri*)uri;
  uri->lr_param = 1;            // Always use loose routing.
  pjsip_msg_insert_first_hdr(msg, (pjsip_hdr*)hroute);
}

/// Add a Route header with the specified URI.
void PJUtils::add_route_header(pjsip_msg* msg,
                               pjsip_sip_uri* uri,
                               pj_pool_t* pool)
{
  pjsip_route_hdr* hroute = pjsip_route_hdr_create(pool);
  hroute->name_addr.uri = (pjsip_uri*)uri;
  uri->lr_param = 1;            // Always use loose routing.
  pjsip_msg_add_hdr(msg, (pjsip_hdr*)hroute);
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


pjsip_tx_data* PJUtils::clone_msg(pjsip_endpoint* endpt,
                                  pjsip_rx_data* rdata)
{
  pjsip_tx_data* clone = NULL;
  pj_status_t status = pjsip_endpt_create_tdata(endpt, &clone);
  if (status == PJ_SUCCESS)
  {
    pjsip_tx_data_add_ref(clone);
    clone->msg = pjsip_msg_clone(clone->pool, rdata->msg_info.msg);
    set_trail(clone, get_trail(rdata));
    TRC_DEBUG("Cloned %s to %s", pjsip_rx_data_get_info(rdata), clone->obj_name);

  }
  return clone;
}


pjsip_tx_data* PJUtils::clone_msg(pjsip_endpoint* endpt,
                                  pjsip_tx_data* tdata)
{
  pjsip_tx_data* clone = NULL;
  pj_status_t status = pjsip_endpt_create_tdata(endpt, &clone);
  if (status == PJ_SUCCESS)
  {
    pjsip_tx_data_add_ref(clone);
    clone->msg = pjsip_msg_clone(clone->pool, tdata->msg);
    set_trail(clone, get_trail(tdata));
    TRC_DEBUG("Cloned %s to %s", tdata->obj_name, clone->obj_name);
  }
  return clone;
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

    // Some headers should always be copied onto responses, like
    // charging headers
    PJUtils::clone_header(&STR_P_C_V, rdata->msg_info.msg, (*p_tdata)->msg, (*p_tdata)->pool);
    PJUtils::clone_header(&STR_P_C_F_A, rdata->msg_info.msg, (*p_tdata)->msg, (*p_tdata)->pool);

  }
  return status;
}


/// Creates a response to the message in the supplied pjsip_tx_data structure.
pj_status_t PJUtils::create_response(pjsip_endpoint *endpt,
                                     const pjsip_tx_data *req_tdata,
                                     int st_code,
                                     const pj_str_t* st_text,
                                     pjsip_tx_data **p_tdata)
{
  pjsip_msg* req_msg = req_tdata->msg;

  // Create a new transmit buffer.
  pjsip_tx_data *tdata;
  pj_status_t status = pjsip_endpt_create_tdata(endpt, &tdata);
  if (status != PJ_SUCCESS)
  {
    return status;
  }

  // Set initial reference count to 1.
  pjsip_tx_data_add_ref(tdata);

  // Copy the SAS trail across from the request.
  set_trail(tdata, get_trail(req_tdata));

  // Create new response message.
  pjsip_msg* msg = pjsip_msg_create(tdata->pool, PJSIP_RESPONSE_MSG);
  tdata->msg = msg;

  // Set status code and reason text.
  msg->line.status.code = st_code;
  if (st_text != NULL)
  {
    pj_strdup(tdata->pool, &msg->line.status.reason, st_text);
  }
  else
  {
    msg->line.status.reason = *pjsip_get_status_text(st_code);
  }

  // Set TX data attributes.
  tdata->rx_timestamp = req_tdata->rx_timestamp;

  // Copy all the via headers in order.
  pjsip_via_hdr* top_via = NULL;
  pjsip_via_hdr* via = (pjsip_via_hdr*)pjsip_msg_find_hdr(req_msg, PJSIP_H_VIA, NULL);
  while (via)
  {
    pjsip_via_hdr *new_via;

    new_via = (pjsip_via_hdr*)pjsip_hdr_clone(tdata->pool, via);
    if (top_via == NULL)
    {
      top_via = new_via;
    }

    pjsip_msg_add_hdr(msg, (pjsip_hdr*)new_via);
    via = (pjsip_via_hdr*)pjsip_msg_find_hdr(req_msg, PJSIP_H_VIA, via->next);
  }

  // Copy all Record-Route headers, in order.
  pjsip_rr_hdr* rr = (pjsip_rr_hdr*)pjsip_msg_find_hdr(req_msg, PJSIP_H_RECORD_ROUTE, NULL);
  while (rr)
  {
    pjsip_msg_add_hdr(msg, (pjsip_hdr*)pjsip_hdr_clone(tdata->pool, rr));
    rr = (pjsip_rr_hdr*)pjsip_msg_find_hdr(req_msg, PJSIP_H_RECORD_ROUTE, rr->next);
  }

  // Copy Call-ID header.
  pjsip_msg_add_hdr(msg, (pjsip_hdr*)pjsip_hdr_clone(tdata->pool, PJSIP_MSG_CID_HDR(req_msg)));

  // Copy From header.
  pjsip_msg_add_hdr(msg, (pjsip_hdr*)pjsip_hdr_clone(tdata->pool, PJSIP_MSG_FROM_HDR(req_msg)));

  // Copy To header. */
  pjsip_msg_add_hdr(msg, (pjsip_hdr*)pjsip_hdr_clone(tdata->pool, PJSIP_MSG_TO_HDR(req_msg)));

  // Must add To tag in the response (Section 8.2.6.2), except if this is
  // 100 (Trying) response. Same tag must be created for the same request
  // (e.g. same tag in provisional and final response). The easiest way
  // to do this is to derive the tag from Via branch parameter (or to
  // use it directly).
  pjsip_to_hdr* to_hdr = PJSIP_MSG_TO_HDR(msg);
  if ((to_hdr->tag.slen == 0) &&
      (st_code > 100) &&
      (top_via))
  {
    to_hdr->tag = top_via->branch_param;
  }

  // Copy CSeq header. */
  pjsip_msg_add_hdr(msg, (pjsip_hdr*)pjsip_hdr_clone(tdata->pool, PJSIP_MSG_CSEQ_HDR(req_msg)));

  // Some headers should always be copied onto responses, like charging headers
  PJUtils::clone_header(&STR_P_C_V, req_msg, msg, tdata->pool);
  PJUtils::clone_header(&STR_P_C_F_A, req_msg, msg, tdata->pool);

  *p_tdata = tdata;

  return PJ_SUCCESS;
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


pjsip_tx_data* PJUtils::create_cancel(pjsip_endpoint* endpt,
                                      pjsip_tx_data* tdata,
                                      int reason_code)
{
  pjsip_tx_data* cancel;
  pj_status_t status = pjsip_endpt_create_cancel(endpt, tdata, &cancel);

  if (status != PJ_SUCCESS)
  {
    return NULL;
  }

  if (reason_code != 0)
  {
    add_reason(cancel, reason_code);
  }

  return cancel;
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
void PJUtils::resolve_next_hop(pjsip_tx_data* tdata,
                               int retries,
                               std::vector<AddrInfo>& servers,
                               SAS::TrailId trail)
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
                                  servers,
                                  trail);

  TRC_INFO("Resolved destination URI %s to %d servers",
           PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                  (pjsip_uri*)next_hop).c_str(),
           servers.size());
}


/// Blacklists the specified server so it will not be preferred in subsequent
/// resolve calls.
void PJUtils::blacklist_server(AddrInfo& server)
{
  stack_data.sipresolver->blacklist(server);
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
        TRC_DEBUG("Transaction failed with retriable error");
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
          TRC_DEBUG("Attempt to resend request to next destination server");
          pjsip_tx_data* tdata = sss->tdata;

          // In congestion cases, the old tdata might still be held by PJSIP's
          // transport layer waiting to be sent.  Therefore it's not safe to re-send
          // the same tdata, so we should clone it first.
          // LCOV_EXCL_START - No congestion in UTs
          if (tdata->is_pending)
          {
            pjsip_tx_data* old_tdata = tdata;
            tdata = PJUtils::clone_tdata(tdata);

            // We no longer care about the old tdata.
            pjsip_tx_data_dec_ref(old_tdata);
          }
          // LCOV_EXCL_STOP

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
    TRC_DEBUG("Request transaction completed, status code = %d", tsx->status_code);
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
                                  pjsip_endpt_send_callback cb,
                                  bool log_sas_branch)
{
  pjsip_transaction* tsx;
  pj_status_t status = PJ_SUCCESS;

  TRC_DEBUG("Sending standalone request statefully");

  // Allocate temporary storage for the request.
  StatefulSendState* sss = new StatefulSendState;

  // Store the user supplied callback and token.
  sss->user_token = token;
  sss->user_cb = cb;

  if (tdata->tp_sel.type != PJSIP_TPSELECTOR_TRANSPORT)
  {
    // No transport determined, so resolve the next hop for the message.
    resolve_next_hop(tdata, retries, sss->servers, get_trail(tdata));

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
  }

  if (status == PJ_SUCCESS)
  {
    // Set the trail ID in the transaction from the message.
    set_trail(tsx, get_trail(tdata));
    if (log_sas_branch)
    {
      PJUtils::mark_sas_call_branch_ids(get_trail(tdata), NULL, tdata->msg);
    }

    // Set up the module data for the new transaction to reference
    // the state information.
    tsx->mod_data[mod_sprout_util.id] = sss;

    if (tdata->tp_sel.type == PJSIP_TPSELECTOR_TRANSPORT)
    {
      // Transport has already been determined, so copy it across to the
      // transaction.
      TRC_DEBUG("Transport already determined");
      pjsip_tsx_set_transport(tsx, &tdata->tp_sel);
    }

    // Store the message and add a reference to prevent the transaction layer
    // freeing it.
    sss->tdata = tdata;
    pjsip_tx_data_add_ref(tdata);

    TRC_DEBUG("Sending request");
    status = pjsip_tsx_send_msg(tsx, tdata);

    if (status != PJ_SUCCESS)
    {
      // If pjsip_tsx_send_msg fails when the UAC transaction is in NULL
      // state it will always call the on_tsx_state callback terminating
      // the transaction, so no clean-up left to do, and must return
      // PJ_SUCCESS to caller to avoid potential double-free errors.  It's
      // also not safe to access the request here, and logging of the error
      // will have happened in the callback.
      status = PJ_SUCCESS;
    }
  }
  else
  {
    // Failed to resolve the destination or failed to create a PJSIP UAC
    // transaction.
    CL_SPROUT_SIP_SEND_REQUEST_ERR.log(PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                       PJUtils::next_hop(tdata->msg)).c_str(),
                                       PJUtils::pj_status_to_string(status).c_str());

    TRC_ERROR("Failed to send request to %s",
              PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                     PJUtils::next_hop(tdata->msg)).c_str());

    // Since the on_tsx_state callback will not have been called we must
    // clean up resources here.
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

      // Add a reference to the tdata to stop PJSIP releasing it when we
      // return the callback.
      pjsip_tx_data_add_ref(tdata);

      // Set up destination info for the new server and resend the request.
      PJUtils::set_dest_info(tdata, sss->servers[sss->current_server]);
      status = pjsip_endpt_send_request_stateless(stack_data.endpt,
                                                  tdata,
                                                  (void*)sss,
                                                  &stateless_send_cb);

      if (status == PJ_SUCCESS)
      {
        retrying = true;
      }
      else
      {
        pjsip_tx_data_dec_ref(tdata);
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
    resolve_next_hop(tdata, retries, sss->servers, get_trail(tdata));

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
    CL_SPROUT_SIP_SEND_REQUEST_ERR.log(PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                       PJUtils::next_hop(tdata->msg)).c_str(),
                                       PJUtils::pj_status_to_string(status).c_str());
    TRC_ERROR("Failed to send request to %s",
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
    do {
      pjsip_msg_add_hdr(tdata->msg,
                        (pjsip_hdr*) pjsip_hdr_clone(tdata->pool, hdr) );
      hdr = hdr->next;
    } while (hdr != hdr_list);
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

void PJUtils::add_top_via(pjsip_tx_data* tdata)
{
  // Add a new Via header with a unique branch identifier.
  pjsip_via_hdr *hvia = pjsip_via_hdr_create(tdata->pool);
  pjsip_msg_insert_first_hdr(tdata->msg, (pjsip_hdr*)hvia);
  generate_new_branch_id(tdata);
}

void PJUtils::remove_top_via(pjsip_tx_data* tdata)
{
  // Removes the top Via header.
  pjsip_via_hdr *hvia = (pjsip_via_hdr*)pjsip_msg_find_hdr(tdata->msg, PJSIP_H_VIA, NULL);
  if (hvia != NULL)
  {
    pj_list_erase(hvia);
  }
}

static std::string build_reason_value(int code)
{
  std::stringstream value_builder;
  std::string reason_text = PJUtils::pj_str_to_string(pjsip_get_status_text(code));

  value_builder << "SIP;cause=" << code << ";text=\"" << reason_text << "\"";

  return value_builder.str();
}

void PJUtils::add_reason(pjsip_tx_data* tdata, int reason_code)
{
  pj_str_t reason_name = pj_str("Reason");
  pj_str_t reason_val;

  std::string reason_value_string = build_reason_value(reason_code);
  pj_strdup2(tdata->pool,
             &reason_val,
             reason_value_string.c_str());

  pjsip_hdr* reason_hdr =
                      (pjsip_hdr*)pjsip_generic_string_hdr_create(tdata->pool,
                                                                  &reason_name,
                                                                  &reason_val);
  pjsip_msg_add_hdr(tdata->msg, reason_hdr);
}

bool PJUtils::compare_pj_sockaddr(const pj_sockaddr& lhs, const pj_sockaddr& rhs)
{
  return (pj_sockaddr_cmp(&lhs, &rhs) < 0);
}


void PJUtils::clone_header(const pj_str_t* hdr_name, pjsip_msg* old_msg, pjsip_msg* new_msg, pj_pool_t* pool)
{
  pjsip_hdr* original_hdr = NULL;
  pjsip_hdr* last_hdr = NULL;
  while ((original_hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(old_msg, hdr_name, original_hdr)) && (last_hdr != original_hdr))
  {
    TRC_INFO("Cloning header! %ld", (long int)original_hdr);
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

  // Eat up to the first colon
  while (*buf2 != ':') { buf2++; len--; }

  // Now eat the colon.
  buf2++; len --;

  // Eat any leading whitespace.
  while (*buf2 == ' ') { buf2++; len--; }

  return std::string(buf2, len);
}

/// Add SAS markers for the specified call ID and branch IDs on the message (either may be omitted).
void PJUtils::mark_sas_call_branch_ids(const SAS::TrailId trail, pjsip_cid_hdr* cid_hdr, pjsip_msg* msg)
{
    SAS::Marker::Scope scope;
    if ((msg->type != PJSIP_REQUEST_MSG) ||
        (msg->line.req.method.id == PJSIP_REGISTER_METHOD) ||
        (pjsip_method_cmp(&msg->line.req.method, pjsip_get_subscribe_method()) == 0) ||
        (pjsip_method_cmp(&msg->line.req.method, pjsip_get_notify_method()) == 0))
  {
    // Don't correlate flows based on Call-ID for REGISTER/SUBSCRIBE/NOTIFY - you get massive trace
    // files.
    scope = SAS::Marker::Scope::None;
  }
  else
  {
    scope = SAS::Marker::Scope::Trace;
  }

  if (cid_hdr != NULL)
  {
    TRC_DEBUG("Logging SAS Call-ID marker, Call-ID %.*s", cid_hdr->id.slen, cid_hdr->id.ptr);
    SAS::Marker cid_marker(trail, MARKER_ID_SIP_CALL_ID, 1u);
    cid_marker.add_var_param(cid_hdr->id.slen, cid_hdr->id.ptr);
    SAS::report_marker(cid_marker, scope);
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
    }
  }
}

bool PJUtils::is_emergency_registration(pjsip_contact_hdr* contact_hdr)
{
  // Contact header must be a SIP URI
  pjsip_sip_uri* uri = (contact_hdr->uri != NULL) ?
                     (pjsip_sip_uri*)pjsip_uri_get_uri(contact_hdr->uri) : NULL;
  return ((uri != NULL) && (PJSIP_URI_SCHEME_IS_SIP(uri)) &&
          (pjsip_param_find(&uri->other_param, &STR_SOS) != NULL));
}

// Return true if there are no route headers, or there is exactly one,
// which is local
bool PJUtils::check_route_headers(pjsip_rx_data* rdata)
{
  // Get all the route headers
  int count = 0;
  bool local = true;
  pjsip_route_hdr* route_hdr = (pjsip_route_hdr*)pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_ROUTE, NULL);

  while (route_hdr != NULL)
  {
    count++;
    URIClass uri_class = URIClassifier::classify_uri(route_hdr->name_addr.uri);
    local = (uri_class == NODE_LOCAL_SIP_URI) || (uri_class == HOME_DOMAIN_SIP_URI);
    route_hdr = (pjsip_route_hdr*)pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_ROUTE, route_hdr->next);
  }

  return (count < 2 && local);
}

void PJUtils::put_unary_param(pjsip_param* params_list,
                              const pj_str_t* name,
                              pj_pool_t* pool)
{
  pjsip_param* param = pjsip_param_find(params_list, name);

  if (param == NULL)
  {
    param = PJ_POOL_ZALLOC_T(pool, pjsip_param);
    param->name = *name;
    pj_list_push_back(params_list, param);
  }
}

/// Redirects the call to the specified target, for the reason specified in the
// status code.
//
// @returns whether the call should continue as it was.
pjsip_status_code PJUtils::redirect(pjsip_msg* msg, std::string target, pj_pool_t* pool, pjsip_status_code code)
{
  pjsip_uri* target_uri = PJUtils::uri_from_string(target, pool);

  if (target_uri == NULL)
  {
    // Target URI was badly formed, so continue processing the call without
    // the redirect.
    return code;
  }

  return redirect_int(msg, target_uri, pool, code);
}

/// Redirects the call to the specified target, for the reason specified in the
// status code.
//
// @returns whether the call should continue as it was (always false).
pjsip_status_code PJUtils::redirect(pjsip_msg* msg, pjsip_uri* target, pj_pool_t* pool, pjsip_status_code code)
{
  return redirect_int(msg, (pjsip_uri*)pjsip_uri_clone(pool, target), pool, code);
}

pjsip_status_code PJUtils::redirect_int(pjsip_msg* msg, pjsip_uri* target, pj_pool_t* pool, pjsip_status_code code)
{
  static const pj_str_t STR_HISTORY_INFO = pj_str("History-Info");
  static const int MAX_HISTORY_INFOS = 5;

  // Default the code to 480 Temporarily Unavailable.
  code = (code != 0) ? code : PJSIP_SC_TEMPORARILY_UNAVAILABLE;
  pjsip_status_code rc = code;

  // Count the number of existing History-Info headers.
  int num_history_infos = 0;
  pjsip_history_info_hdr* prev_history_info_hdr = NULL;
  for (pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(msg, &STR_HISTORY_INFO, NULL);
       hdr != NULL;
       hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(msg, &STR_HISTORY_INFO, hdr->next))
  {
    ++num_history_infos;
    prev_history_info_hdr = (pjsip_history_info_hdr*)hdr;
  }

  // If we haven't already had too many redirections (i.e. History-Info
  // headers), do the redirect.
  if (num_history_infos < MAX_HISTORY_INFOS)
  {
    rc = PJSIP_SC_OK;

    // Add a Diversion header with the original request URI and the reason
    // for the diversion.
    std::string div = PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, msg->line.req.uri);
    div += ";reason=";
    div += (code == PJSIP_SC_BUSY_HERE) ? "user-busy" :
      (code == PJSIP_SC_TEMPORARILY_UNAVAILABLE) ? "no-answer" :
      (code == PJSIP_SC_NOT_FOUND) ? "out-of-service" :
      (code == 0) ? "unconditional" :
      "unknown";
    pj_str_t sdiv;
    pjsip_generic_string_hdr* diversion =
      pjsip_generic_string_hdr_create(pool,
                                      &STR_DIVERSION,
                                      pj_cstr(&sdiv, div.c_str()));
    pjsip_msg_add_hdr(msg, (pjsip_hdr*)diversion);

    // Create or update a History-Info header for the old target.
    if (prev_history_info_hdr == NULL)
    {
      prev_history_info_hdr = create_history_info_hdr(msg->line.req.uri, pool);
      prev_history_info_hdr->index = pj_str("1");
      pjsip_msg_add_hdr(msg, (pjsip_hdr*)prev_history_info_hdr);
    }

    update_history_info_reason(((pjsip_name_addr*)(prev_history_info_hdr->uri))->uri, pool, code);

    // Set up the new target URI.
    msg->line.req.uri = target;

    // Create a History-Info header for the new target.
    pjsip_history_info_hdr* history_info_hdr = create_history_info_hdr(target, pool);

    // Set up the index parameter.  This is the previous value suffixed with ".1".
    history_info_hdr->index.slen = prev_history_info_hdr->index.slen + 2;
    history_info_hdr->index.ptr = (char*)pj_pool_alloc(pool, history_info_hdr->index.slen);
    pj_memcpy(history_info_hdr->index.ptr, prev_history_info_hdr->index.ptr, prev_history_info_hdr->index.slen);
    pj_memcpy(history_info_hdr->index.ptr + prev_history_info_hdr->index.slen, ".1", 2);

    pjsip_msg_add_hdr(msg, (pjsip_hdr*)history_info_hdr);
  }

  return rc;
}

pjsip_history_info_hdr* PJUtils::create_history_info_hdr(pjsip_uri* target, pj_pool_t* pool)
{
  // Create a History-Info header.
  pjsip_history_info_hdr* history_info_hdr = pjsip_history_info_hdr_create(pool);

  // Clone the URI and set up its parameters.
  pjsip_uri* history_info_uri = (pjsip_uri*)pjsip_uri_clone(pool, (pjsip_uri*)pjsip_uri_get_uri(target));
  pjsip_name_addr* history_info_name_addr_uri = pjsip_name_addr_create(pool);
  history_info_name_addr_uri->uri = history_info_uri;
  history_info_hdr->uri = (pjsip_uri*)history_info_name_addr_uri;

  return history_info_hdr;
}

void PJUtils::update_history_info_reason(pjsip_uri* history_info_uri, pj_pool_t* pool, int code)
{
  static const pj_str_t STR_REASON = pj_str("Reason");

  if (PJSIP_URI_SCHEME_IS_SIP(history_info_uri))
  {
    // Set up the Reason parameter - this is always "SIP".
    pjsip_sip_uri* history_info_sip_uri = (pjsip_sip_uri*)history_info_uri;
    if (pj_list_empty(&history_info_sip_uri->other_param))
    {
      pj_str_t reason_value;

      // As per RFC 3261, the contents of a parameter must contain a limited
      // set of characters.
      std::string reason_value_string = Utils::url_escape(build_reason_value(code));

      pj_strdup2(pool,
                 &reason_value,
                 reason_value_string.c_str());

      // Create a parameter and copy in the details.
      pjsip_param *param = PJ_POOL_ALLOC_T(pool, pjsip_param);
      param->name = STR_REASON;
      param->value = reason_value;

      pj_list_insert_after(&history_info_sip_uri->other_param,
                           (pj_list_type*)param);
    }
  }
}

pj_str_t PJUtils::user_from_uri(const pjsip_uri* uri)
{
  if (PJSIP_URI_SCHEME_IS_SIP(uri) ||
      PJSIP_URI_SCHEME_IS_SIPS(uri))
  {
    return ((pjsip_sip_uri*)uri)->user;
  }
  else if (PJSIP_URI_SCHEME_IS_TEL(uri))
  {
    return ((pjsip_tel_uri*)uri)->number;
  }
  else
  {
    // If it's neither of the above, just use the URI's "content".
    return ((pjsip_other_uri*)uri)->content;
  }
}

void PJUtils::report_sas_to_from_markers(SAS::TrailId trail, pjsip_msg* msg)
{
  // Get the method.  On the request, this is on the request line.  On the
  // response, it is in the CSeq header.
  pjsip_method* method = NULL;
  if (msg->type == PJSIP_REQUEST_MSG)
  {
    method = &msg->line.req.method;
  }
  else
  {
    pjsip_cseq_hdr* cseq_hdr = PJSIP_MSG_CSEQ_HDR(msg);
    if (cseq_hdr != NULL)
    {
      method = &cseq_hdr->method;
    }
  }

  // Work out which method we have.
  bool is_register = false;
  bool is_subscribe = false;
  bool is_notify = false;
  if (method != NULL)
  {
    is_register = (method->id == PJSIP_REGISTER_METHOD);
    is_subscribe = ((method->id == PJSIP_OTHER_METHOD) &&
                    (pj_strcmp2(&method->name, "SUBSCRIBE") == 0));
    is_notify = ((method->id == PJSIP_OTHER_METHOD) &&
                 (pj_strcmp2(&method->name, "NOTIFY") == 0));
  }

  // Get the To and From URIs.
  pjsip_uri* to_uri = NULL;
  bool has_to_tag = false;
  pjsip_to_hdr* to_hdr = PJSIP_MSG_TO_HDR(msg);
  if (to_hdr != NULL)
  {
    to_uri = (pjsip_uri*)pjsip_uri_get_uri(to_hdr->uri);
    has_to_tag = (to_hdr->tag.slen != 0);
  }
  pjsip_uri* from_uri = NULL;
  pjsip_from_hdr* from_hdr = PJSIP_MSG_FROM_HDR(msg);
  if (from_hdr != NULL)
  {
    from_uri = (pjsip_uri*)pjsip_uri_get_uri(from_hdr->uri);
  }

  // Look at the method to decide which marker to use.
  if (is_register)
  {
    // For REGISTERs, report the To URI in the SIP_ALL_REGISTER marker.
    if (to_uri != NULL)
    {
      std::string to_uri_str = uri_to_string(PJSIP_URI_IN_FROMTO_HDR, to_uri);
      pj_str_t to_user = user_from_uri(to_uri);

      SAS::Marker sip_all_register(trail, MARKER_ID_SIP_ALL_REGISTER, 1u);
      sip_all_register.add_var_param(strip_uri_scheme(to_uri_str));
      // Add the DN parameter. If the user part is not numeric just log it in
      // its entirety.
      sip_all_register.add_var_param(URIClassifier::is_user_numeric(to_user) ?
                                     remove_visual_separators(to_user) :
                                     pj_str_to_string(&to_user));
      SAS::report_marker(sip_all_register);
    }
  }
  else if (is_subscribe || is_notify)
  {
    // For SUBSCRIBEs and NOTIFYs, report the To URI in the SIP_SUBSCRIBE_NOTIFY marker.
    if (to_uri != NULL)
    {
      std::string to_uri_str = uri_to_string(PJSIP_URI_IN_FROMTO_HDR, to_uri);
      pj_str_t to_user = user_from_uri(to_uri);

      SAS::Marker sip_subscribe_notify(trail, MARKER_ID_SIP_SUBSCRIBE_NOTIFY, 1u);
      // The static parameter contains the type of request - 1 for SUBSCRIBE and 2 for
      // NOTIFY.
      sip_subscribe_notify.add_static_param(is_subscribe ?
                                            SASEvent::SubscribeNotifyType::SUBSCRIBE :
                                            SASEvent::SubscribeNotifyType::NOTIFY);
      sip_subscribe_notify.add_var_param(strip_uri_scheme(to_uri_str));
      // Add the DN parameter. If the user part is not numeric just log it in
      // its entirety.
      sip_subscribe_notify.add_var_param(URIClassifier::is_user_numeric(to_user) ?
                                         remove_visual_separators(to_user) :
                                         pj_str_to_string(&to_user));
      SAS::report_marker(sip_subscribe_notify);
    }
  }
  else
  {
    // For all other methods, just default to reporting the To URI in the CALLED_DN and
    // the From URI in the CALLING_DN marker.  However, only do this if we're not in
    // dialog (check the To tag).
    if (!has_to_tag)
    {
      if (to_uri != NULL)
      {
        pj_str_t to_user = user_from_uri(to_uri);
        if (URIClassifier::is_user_numeric(to_user))
        {
          SAS::Marker called_dn(trail, MARKER_ID_CALLED_DN, 1u);
          called_dn.add_var_param(remove_visual_separators(to_user));
          SAS::report_marker(called_dn);
        }

        SAS::Marker called_uri(trail, MARKER_ID_INBOUND_CALLED_URI, 1u);
        called_uri.add_var_param(strip_uri_scheme(
                                   uri_to_string(PJSIP_URI_IN_FROMTO_HDR, to_uri)));
        SAS::report_marker(called_uri);
      }

      if (from_uri != NULL)
      {
        pj_str_t from_user = user_from_uri(from_uri);
        if (URIClassifier::is_user_numeric(from_user))
        {
          SAS::Marker calling_dn(trail, MARKER_ID_CALLING_DN, 1u);
          calling_dn.add_var_param(remove_visual_separators(from_user));
          SAS::report_marker(calling_dn);
        }

        SAS::Marker calling_uri(trail, MARKER_ID_INBOUND_CALLING_URI, 1u);
        calling_uri.add_var_param(strip_uri_scheme(
                                    uri_to_string(PJSIP_URI_IN_FROMTO_HDR, from_uri)));
        SAS::report_marker(calling_uri);
      }
    }
  }
}

// Add a P-Charging-Function-Addresses header to a SIP message. The header is
// added if it doesn't already exist, and replaced when the replace flag is
// set to TRUE.
void PJUtils::add_pcfa_header(pjsip_msg* msg,
                              pj_pool_t* pool,
                              const std::deque<std::string>& ccfs,
                              const std::deque<std::string>& ecfs,
                              const bool replace)
{
  pjsip_p_c_f_a_hdr* pcfa_hdr =
    (pjsip_p_c_f_a_hdr*)pjsip_msg_find_hdr_by_name(msg, &STR_P_C_F_A, NULL);

  if (((pcfa_hdr == NULL) || (replace)) &&
      ((!ccfs.empty()) || (!ecfs.empty())))
  {
    if (pcfa_hdr != NULL)
    {
      TRC_INFO("Replacing existing PCFA header");
      PJUtils::remove_hdr(msg, &STR_P_C_F_A);
      pcfa_hdr = NULL;
    }
    else
    {
      TRC_INFO("Adding new PCFA header");
    }

    pcfa_hdr = pjsip_p_c_f_a_hdr_create(pool);

    for (std::deque<std::string>::const_iterator it = ccfs.begin();
         it != ccfs.end();
         ++it)
    {
      TRC_DEBUG("Adding CCF %s to PCFA header", it->c_str());
      pjsip_param* new_param =
        (pjsip_param*)pj_pool_alloc(pool, sizeof(pjsip_param));
      new_param->name = STR_CCF;
      new_param->value = pj_strdup3(pool, it->c_str());

      pj_list_insert_before(&pcfa_hdr->ccf, new_param);
    }

    for (std::deque<std::string>::const_iterator it = ecfs.begin();
         it != ecfs.end();
         ++it)
    {
      TRC_DEBUG("Adding ECF %s to PCFA header", it->c_str());
      pjsip_param* new_param =
        (pjsip_param*)pj_pool_alloc(pool, sizeof(pjsip_param));
      new_param->name = STR_ECF;
      new_param->value = pj_strdup3(pool, it->c_str());

      pj_list_insert_before(&pcfa_hdr->ecf, new_param);
    }
    pjsip_msg_add_hdr(msg, (pjsip_hdr*)pcfa_hdr);
  }
}

/// Takes a SIP URI and turns it into its equivalent tel URI. This is used
/// for SIP URIs that actually represent phone numbers, i.e. SIP URIs that
/// contain the user=phone parameter.
///
/// @returns                      A pointer to the new tel URI object.
/// @param sip_uri                The SIP URI to convert.
/// @param pool                   A pool.
pjsip_uri* PJUtils::translate_sip_uri_to_tel_uri(const pjsip_sip_uri* sip_uri,
                                                 pj_pool_t* pool)
{
  pjsip_tel_uri* tel_uri = pjsip_tel_uri_create(pool);

  tel_uri->number = sip_uri->user;
  tel_uri->context.slen = 0;
  tel_uri->isub_param.slen = 0;
  tel_uri->ext_param.slen = 0;

  pjsip_param* isub = pjsip_param_find(&sip_uri->other_param, &STR_ISUB);
  if (isub != NULL)
  {
    tel_uri->isub_param.slen = isub->value.slen;
    tel_uri->isub_param.ptr = isub->value.ptr;
  }

  pjsip_param* ext = pjsip_param_find(&sip_uri->other_param, &STR_EXT);
  if (ext != NULL)
  {
    tel_uri->ext_param.slen = ext->value.slen;
    tel_uri->ext_param.ptr = ext->value.ptr;
  }

  return (pjsip_uri*)tel_uri;
}

static const boost::regex CHARS_TO_STRIP = boost::regex("[.)(-]");

// Strip any visual separators from the number
std::string PJUtils::remove_visual_separators(const std::string& number)
{
  return boost::regex_replace(number, CHARS_TO_STRIP, std::string(""));
};

// Strip any visual separators from the number
std::string PJUtils::remove_visual_separators(const pj_str_t& number)
{
  std::string s = pj_str_to_string(&number);
  return remove_visual_separators(s);
};

bool PJUtils::get_npdi(pjsip_uri* uri)
{
  bool npdi = false;

  if (PJSIP_URI_SCHEME_IS_TEL(uri))
  {
    // If the URI is a tel URI, pull out the information from the other_params
    npdi = (pjsip_param_find(&((pjsip_tel_uri*)uri)->other_param, &STR_NPDI) != NULL);
  }
  else if (PJSIP_URI_SCHEME_IS_SIP(uri))
  {
    // If the URI is a tel URI, pull out the information from the userinfo_params
    npdi = (pjsip_param_find(&((pjsip_sip_uri*)uri)->userinfo_param, &STR_NPDI) != NULL);
  }

  return npdi;
}

bool PJUtils::get_rn(pjsip_uri* uri, std::string& routing_value)
{
  bool rn_set = false;
  pjsip_param* rn = NULL;

  if (PJSIP_URI_SCHEME_IS_TEL(uri))
  {
    // If the URI is a tel URI, pull out the information from the other_params
    rn = pjsip_param_find(&((pjsip_tel_uri*)uri)->other_param, &STR_RN);
  }
  else if (PJSIP_URI_SCHEME_IS_SIP(uri))
  {
    // If the URI is a SIP URI, pull out the information from the userinfo_params
    rn = pjsip_param_find(&((pjsip_sip_uri*)uri)->userinfo_param, &STR_RN);
  }

  if (rn != NULL)
  {
    routing_value = pj_str_to_string(&rn->value);
    rn_set = (routing_value.size() > 0);
  }

  return rn_set;
}

/// Attempt ENUM lookup if appropriate.
static std::string query_enum(pjsip_msg* req,
                              EnumService* enum_service,
                              SAS::TrailId trail)
{
  std::string user;
  std::string new_uri;
  pjsip_uri* uri = req->line.req.uri;

  if (enum_service != NULL)
  {
    // ENUM is enabled.
    TRC_DEBUG("ENUM is enabled");


    // Check whether we have a global number or whether we allow
    // ENUM lookups for local numbers

    {
      // Perform an ENUM lookup if we have a tel URI, or if we have
      // a SIP URI which is being treated as a phone number.
      pj_str_t pj_user = PJUtils::user_from_uri(uri);
      user = PJUtils::pj_str_to_string(&pj_user);
      TRC_DEBUG("Performing ENUM lookup for user %s", user.c_str());
      new_uri = enum_service->lookup_uri_from_user(user, trail);
    }
  }
  else
  {
    // If we have no ENUM server configured, we act as if all ENUM lookups
    // return a successful response and perform the following mappings:
    //  - tel:<number> to sip:<number>@<homedomain>
    //  - sip:<number>@<homedomain> to itself
    //
    // We do this in order to avoid needing to setup an ENUM server on test
    // systems just to allow local calls to work.
    TRC_DEBUG("No ENUM server configured, perform default translation");
    SAS::Event event(trail, SASEvent::ENUM_NOT_ENABLED, 0);
    SAS::report_event(event);

    if (PJSIP_URI_SCHEME_IS_TEL(uri))
    {
      new_uri = "sip:";
      new_uri += PJUtils::pj_str_to_string(&((pjsip_tel_uri*)uri)->number);
      new_uri += "@";
      new_uri += PJUtils::pj_str_to_string(&stack_data.default_home_domain);
      TRC_DEBUG("Translate tel URI to SIP URI %s", new_uri.c_str());
    }
    else
    {
      new_uri = PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, uri);
      TRC_DEBUG("Translate SIP URI %s to itself", new_uri.c_str());
    }
  }

  return new_uri;
}

void PJUtils::translate_request_uri(pjsip_msg* req,
                                    pj_pool_t* pool,
                                    EnumService* enum_service,
                                    bool should_override_npdi,
                                    SAS::TrailId trail)
{
  pjsip_uri* uri = req->line.req.uri;
  URIClass uri_class = URIClassifier::classify_uri(uri, false);

  if ((uri_class == GLOBAL_PHONE_NUMBER) ||
      (uri_class == NP_DATA) ||
      (uri_class == FINAL_NP_DATA))
  {

    // Request is either to a URI in this domain, or a Tel URI, so attempt
    // to translate it according to 5.4.3.2 section 10.
    TRC_DEBUG("Translating URI");
    std::string new_uri_str = query_enum(req,
                                         enum_service,
                                         trail);

    if (!new_uri_str.empty())
    {
      pjsip_uri* new_uri = (pjsip_uri*)PJUtils::uri_from_string(new_uri_str,
                                                                pool);

      if (new_uri == NULL)
      {
        // The ENUM lookup has returned an invalid URI. Reject the
        // request.
        TRC_WARNING("Invalid ENUM response: %s", new_uri_str.c_str());
        SAS::Event event(trail, SASEvent::ENUM_INVALID, 0);
        event.add_var_param(new_uri_str);
        SAS::report_event(event);
        return;
      }

      // The URI was successfully translated, so see what it is.
      URIClass new_uri_class = URIClassifier::classify_uri(new_uri, false);
      std::string rn;

      if ((new_uri_class == HOME_DOMAIN_SIP_URI) ||
          (new_uri_class == NODE_LOCAL_SIP_URI) ||
          (new_uri_class == OFFNET_SIP_URI))
      {
        // Translation to a real SIP URI - this always takes priority.
        TRC_DEBUG("Translated URI %s is a real SIP URI - replacing Request-URI",
                  new_uri_str.c_str());
        req->line.req.uri = new_uri;
        SAS::Event event(trail, SASEvent::SIP_URI_FROM_ENUM, 0);
        event.add_var_param(new_uri_str);
        SAS::report_event(event);
      }
      else if ((new_uri_class == NP_DATA) || (new_uri_class == FINAL_NP_DATA))
      {
        if (should_update_np_data(uri_class, new_uri_class, new_uri_str, should_override_npdi, trail))
        {
          req->line.req.uri = new_uri;
        }
      }
      else
      {
        // We got a TEL URI of some description - update the Request-URI anyway and expect a
        // downstream MGCF to sort it out.
        TRC_DEBUG("Translated URI %s is not a SIP URI - replacing Request-URI anyway",
                  new_uri_str.c_str());
        req->line.req.uri = new_uri;
        SAS::Event event(trail, SASEvent::NON_SIP_URI_FROM_ENUM, 0);
        event.add_var_param(new_uri_str);
        SAS::report_event(event);
      }
    }
  }
}

void PJUtils::update_request_uri_np_data(pjsip_msg* req,
                                    pj_pool_t* pool,
                                    EnumService* enum_service,
                                    bool should_override_npdi,
                                    SAS::TrailId trail)
{
  pjsip_uri* uri = req->line.req.uri;
  URIClass uri_class = URIClassifier::classify_uri(uri);

  if ((uri_class == GLOBAL_PHONE_NUMBER) ||
      (uri_class == NP_DATA) ||
      (uri_class == FINAL_NP_DATA))
  {

    // Request is either to a URI in this domain, or a Tel URI, so attempt
    // to translate it according to 5.4.3.2 section 10.
    TRC_DEBUG("Translating URI");
    std::string new_uri_str = query_enum(req,
                                         enum_service,
                                         trail);

    if (!new_uri_str.empty())
    {
      pjsip_uri* new_uri = (pjsip_uri*)PJUtils::uri_from_string(new_uri_str,
                                                                pool);

      if (new_uri == NULL)
      {
        // The ENUM lookup has returned an invalid URI. Reject the
        // request.
        TRC_WARNING("Invalid ENUM response: %s", new_uri_str.c_str());
        SAS::Event event(trail, SASEvent::ENUM_INVALID, 0);
        event.add_var_param(new_uri_str);
        SAS::report_event(event);
        return;
      }

      // The URI was successfully translated, so see what it is.
      URIClass new_uri_class = URIClassifier::classify_uri(new_uri, false);

      if ((new_uri_class == NP_DATA) || (new_uri_class == FINAL_NP_DATA))
      {
        if (should_update_np_data(uri_class, new_uri_class, new_uri_str, should_override_npdi, trail))
        {
          req->line.req.uri = new_uri;
        }
      }
    }
  }
  else
  {
    TRC_DEBUG("Not translating URI");
  }
}


bool PJUtils::should_update_np_data(URIClass old_uri_class,
                           URIClass new_uri_class,
                           std::string& new_uri_str,
                           bool should_override_npdi,
                           SAS::TrailId trail)
{
  if ((new_uri_class == NP_DATA) || (new_uri_class == FINAL_NP_DATA))
  {
    if (old_uri_class != FINAL_NP_DATA)
    {
      // No NPDI flag on the original URI, so use the number portability data.
      TRC_DEBUG("Translated URI %s has NP data and the npdi flag is not set - replacing Request-URI",
                new_uri_str.c_str());
      SAS::Event event(trail, SASEvent::NP_DATA_FROM_ENUM, 0);
      event.add_var_param(new_uri_str);
      SAS::report_event(event);
      return true;
    }
    else if (should_override_npdi)
    {
      // Configured to ignore the NPDI flag on the original URI, so use the number portability data.
      TRC_DEBUG("Translated URI %s has NP data and the npdi flag is ignored - replacing Request-URI",
                new_uri_str.c_str());
      SAS::Event event(trail, SASEvent::NP_DATA_FROM_ENUM_IGNORING_NPDI, 0);
      event.add_var_param(new_uri_str);
      SAS::report_event(event);
      return true;
    }
    else
    {
      // The NPDI flag is set on the original URI and not overriden by local policy, so ignore the number portability data.
      TRC_DEBUG("Translated URI %s has NP data and the npdi flag is set - not replacing Request-URI",
                new_uri_str.c_str());
      SAS::Event event(trail, SASEvent::IGNORED_NP_DATA_FROM_ENUM, 0);
      event.add_var_param(new_uri_str);
      SAS::report_event(event);
      return false;
    }
  }
  else
  {
    return false;
  }
}
