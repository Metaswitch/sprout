/**
 * @file mangelwurzel.cpp Implementation of mangelwurzel.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2014  Metaswitch Networks Ltd
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

#include "log.h"
#include "constants.h"
#include "mangelwurzel.h"

static const pj_str_t DIALOG_PARAM = pj_str((char *)"dialog");
static const pj_str_t REQ_URI_PARAM = pj_str((char *)"req-uri");
static const pj_str_t CONTACT_PARAM = pj_str((char *)"contact");
static const pj_str_t TO_PARAM = pj_str((char *)"to");
static const pj_str_t ROUTES_PARAM = pj_str((char *)"routes");
static const pj_str_t DOMAIN_PARAM = pj_str((char *)"change-domain");
static const pj_str_t ORIG_PARAM = pj_str((char *)"orig");
static const pj_str_t OOTB_PARAM = pj_str((char *)"ootb");
static const pj_str_t MANGALGORITHM_PARAM = pj_str((char *)"mangalgorithm");
static const pj_str_t REVERSE_MANGALGORITHM = pj_str((char *)"reverse");

/// Creates a MangelwurzelTsx instance.
SproutletTsx* Mangelwurzel::get_tsx(SproutletTsxHelper* helper,
                                    const std::string& alias,
                                    pjsip_msg* req)
{
  MangelwurzelTsx::Config config;

  // Find the Route header, parse the parameters out and construct a
  // MangelwurzelTsx.
  pjsip_route_hdr* route_hdr = (pjsip_route_hdr*)helper->route_hdr();

  if (route_hdr != NULL)
  {
    pjsip_sip_uri* route_hdr_uri = (pjsip_sip_uri*)route_hdr->name_addr.uri;

    if (pjsip_param_find(&route_hdr_uri->other_param, &DIALOG_PARAM) != NULL)
    {
      config.dialog = true;
    }
    if (pjsip_param_find(&route_hdr_uri->other_param, &REQ_URI_PARAM) != NULL)
    {
      config.req_uri = true;
    }
    if (pjsip_param_find(&route_hdr_uri->other_param, &CONTACT_PARAM) != NULL)
    {
      config.contact = true;
    }
    if (pjsip_param_find(&route_hdr_uri->other_param, &TO_PARAM) != NULL)
    {
      config.to = true;
    }
    if (pjsip_param_find(&route_hdr_uri->other_param, &ROUTES_PARAM) != NULL)
    {
      config.routes = true;
    }
    if (pjsip_param_find(&route_hdr_uri->other_param, &DOMAIN_PARAM) != NULL)
    {
      config.change_domain = true;
    }
    if (pjsip_param_find(&route_hdr_uri->other_param, &ORIG_PARAM) != NULL)
    {
      config.orig = true;
    }
    if (pjsip_param_find(&route_hdr_uri->other_param, &OOTB_PARAM) != NULL)
    {
      config.ootb = true;
    }
    pjsip_param* mangalgorithm_param = pjsip_param_find(&route_hdr_uri->other_param,
                                                        &MANGALGORITHM_PARAM);
    if ((mangalgorithm_param != NULL) &&
        (pj_strcmp(&mangalgorithm_param->value, &REVERSE_MANGALGORITHM) == 0))
    {
      config.mangalgorithm = MangelwurzelTsx::REVERSE;
    }

    return new MangelwurzelTsx(helper, config);
  }
  else
  {
    LOG_DEBUG("Failed to find Route header - not invoking mangelwurzel");
    return NULL;
  }
}

void MangelwurzelTsx::on_rx_initial_request(pjsip_msg* req)
{
  pj_pool_t* pool = get_pool(req);

  if (_config.req_uri)
  {
    mangle_req_uri(req, pool);
  }

  if (_config.dialog)
  {
    mangle_dialog_identifiers(req, pool);
  }

  if (_config.contact)
  {
    mangle_contact(req, pool);
  }

  if (_config.to)
  {
    mangle_to(req, pool);
  }

  edit_scscf_route_hdr(req, pool);

  if (_config.routes)
  {
    mangle_record_routes(req, pool);
  }

  strip_via_hdrs(req);

  record_route(req, pool);

  send_request(req);
}

void MangelwurzelTsx::on_rx_response(pjsip_msg* rsp, int fork_id)
{
  pj_pool_t* pool = get_pool(rsp);

  if (_config.dialog)
  {
    mangle_dialog_identifiers(rsp, pool);
  }

  if (_config.req_uri)
  {
    mangle_contact(rsp, pool);
  }

  if (_config.routes)
  {
    mangle_record_routes(rsp, pool);
    mangle_routes(rsp, pool);
  }

  add_via_hdrs(rsp, pool);

  send_response(rsp);
}

void MangelwurzelTsx::on_rx_in_dialog_request(pjsip_msg* req)
{
  pj_pool_t* pool = get_pool(req);

  if (_config.req_uri)
  {
    mangle_req_uri(req, pool);
  }

  if (_config.dialog)
  {
    mangle_dialog_identifiers(req, pool);
  }

  if (_config.contact)
  {
    mangle_contact(req, pool);
  }

  if (_config.to)
  {
    mangle_to(req, pool);
  }

  edit_scscf_route_hdr(req, pool);

  if (_config.routes)
  {
    mangle_routes(req, pool);
  }

  strip_via_hdrs(req);

  send_request(req);
}

void MangelwurzelTsx::mangle_dialog_identifiers(pjsip_msg* req, pj_pool_t* pool)
{
  pjsip_from_hdr* from_hdr = PJSIP_MSG_FROM_HDR(req);

  if (from_hdr != NULL)
  {
    std::string from_tag = PJUtils::pj_str_to_string(&from_hdr->tag);
    mangle_string(from_tag);
    from_hdr->tag = pj_strdup3(pool, from_tag.c_str());
  }

  pjsip_to_hdr* to_hdr = PJSIP_MSG_TO_HDR(req);

  if (to_hdr != NULL)
  {
    std::string to_tag = PJUtils::pj_str_to_string(&to_hdr->tag);
    mangle_string(to_tag);
    to_hdr->tag = pj_strdup3(pool, to_tag.c_str());
  }

  pjsip_cid_hdr* cid_hdr = (pjsip_cid_hdr*)pjsip_msg_find_hdr(req,
                                                              PJSIP_H_CALL_ID,
                                                              NULL);
  if (cid_hdr != NULL)
  {
    std::string call_id = PJUtils::pj_str_to_string(&cid_hdr->id);
    mangle_string(call_id);
    cid_hdr->id = pj_strdup3(pool, call_id.c_str());

    LOG_DEBUG("Logging SAS Call-ID marker, Call-ID %.*s",
              cid_hdr->id.slen,
              cid_hdr->id.ptr);
    SAS::Marker cid_marker(trail(), MARKER_ID_SIP_CALL_ID, 1u);
    cid_marker.add_var_param(cid_hdr->id.slen, cid_hdr->id.ptr);
    SAS::report_marker(cid_marker, SAS::Marker::Scope::Trace);
  }
}

void MangelwurzelTsx::mangle_req_uri(pjsip_msg* req, pj_pool_t* pool)
{
  mangle_uri(req->line.req.uri, pool, false);
}

void MangelwurzelTsx::mangle_contact(pjsip_msg* msg, pj_pool_t* pool)
{
  pjsip_contact_hdr* contact_hdr =
    (pjsip_contact_hdr*)pjsip_msg_find_hdr(msg,
                                           PJSIP_H_CONTACT,
                                           NULL);
  if (contact_hdr != NULL)
  {
    mangle_uri((pjsip_uri*)pjsip_uri_get_uri(contact_hdr->uri), pool, false);
  }
}

void MangelwurzelTsx::mangle_to(pjsip_msg* req, pj_pool_t* pool)
{
  pjsip_to_hdr* to_hdr = PJSIP_MSG_TO_HDR(req);

  if (to_hdr != NULL)
  {
    mangle_uri((pjsip_uri*)pjsip_uri_get_uri(to_hdr->uri), pool, false);
  }
}

void MangelwurzelTsx::mangle_uri(pjsip_uri* uri,
                                 pj_pool_t* pool,
                                 bool force_mangle_domain)
{
  if (PJSIP_URI_SCHEME_IS_SIP(uri))
  {
    pjsip_sip_uri* sip_uri = (pjsip_sip_uri*)uri;
    std::string user = PJUtils::pj_str_to_string(&sip_uri->user);
    mangle_string(user);
    sip_uri->user = pj_strdup3(pool, user.c_str());

    if ((force_mangle_domain) || (_config.change_domain))
    {
      std::string host = PJUtils::pj_str_to_string(&sip_uri->host);
      mangle_string(host);
      sip_uri->host = pj_strdup3(pool, host.c_str());
    }
  }
  else if (PJSIP_URI_SCHEME_IS_TEL(uri))
  {
    pjsip_tel_uri* tel_uri = (pjsip_tel_uri*)uri;
    std::string number = PJUtils::pj_str_to_string(&tel_uri->number);
    mangle_string(number);
    tel_uri->number = pj_strdup3(pool, number.c_str());
  }
}

void MangelwurzelTsx::mangle_string(std::string& str)
{
  if (_config.mangalgorithm == REVERSE)
  {
    reverse(str);
  }
  else
  {
    rot13(str);
  }
}

void MangelwurzelTsx::rot13(std::string& str)
{
  for (std::string::iterator it = str.begin(); it != str.end(); it++)
  {
    if (((*it >= 'a') && (*it <= 'm')) || ((*it >= 'A') && (*it <= 'M')))
    {
      (*it) += 13;
    }
    else if (((*it >= 'n') && (*it <= 'z')) || ((*it >= 'N') && (*it <= 'Z')))
    {
      (*it) -= 13;
    }
    else if ((*it >= '0') && (*it <= '4'))
    {
      (*it) += 5;
    }
    else if ((*it >= '5') && (*it <= '9'))
    {
      (*it) -= 5;
    }
  }
}

void MangelwurzelTsx::reverse(std::string& str)
{
  std::reverse(str.begin(), str.end());
}

void MangelwurzelTsx::strip_via_hdrs(pjsip_msg* req)
{
  // Remove all the via headers from the request.
  pjsip_via_hdr* via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr(req,
                                                              PJSIP_H_VIA,
                                                              NULL);
  while (via_hdr != NULL)
  {
    pjsip_via_hdr* prev_via_hdr = via_hdr;
    via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr(req,
                                                 PJSIP_H_VIA,
                                                 prev_via_hdr->next);
    pj_list_erase(prev_via_hdr);
  }
}

void MangelwurzelTsx::add_via_hdrs(pjsip_msg* rsp, pj_pool_t* pool)
{
  // Copy all the via headers from the original request back onto the response
  // in the correct order.
  pjsip_msg* req = original_request();
  pjsip_via_hdr* via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr(req,
                                                              PJSIP_H_VIA,
                                                              NULL);
  while (via_hdr != NULL)
  {
    pjsip_via_hdr* cloned_via_hdr = (pjsip_via_hdr*)pjsip_hdr_clone(pool,
                                                                    via_hdr);
    pjsip_msg_add_hdr(rsp, (pjsip_hdr*)cloned_via_hdr);

    via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr(req,
                                                 PJSIP_H_VIA,
                                                 via_hdr->next);
  }
}

void MangelwurzelTsx::edit_scscf_route_hdr(pjsip_msg* req, pj_pool_t* pool)
{
  pjsip_route_hdr* route_hdr =
    (pjsip_route_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_ROUTE, NULL);

  if (route_hdr != NULL)
  {
    pjsip_sip_uri* scscf_uri = (pjsip_sip_uri*)route_hdr->name_addr.uri;

    pjsip_param* orig_param = pjsip_param_find(&scscf_uri->other_param,
                                               &STR_ORIG);

    if ((_config.orig) && (orig_param == NULL))
    {
      orig_param = PJ_POOL_ALLOC_T(pool, pjsip_param);
      pj_strdup(pool, &orig_param->name, &STR_ORIG);
      orig_param->value.slen = 0;
      pj_list_insert_after(&scscf_uri->other_param, orig_param);
    }
    else if ((!_config.orig) && (orig_param != NULL))
    {
      pj_list_erase(orig_param);
    }

    if (_config.ootb)
    {
      scscf_uri->user.ptr = NULL;
      scscf_uri->user.slen = 0;
    }
  }
}

void MangelwurzelTsx::mangle_record_routes(pjsip_msg* msg, pj_pool_t* pool)
{
  pjsip_msg* original_req = original_request();
  int mangelwurzel_rr_index = 1;

  pjsip_rr_hdr* rr_hdr =
    (pjsip_rr_hdr*)pjsip_msg_find_hdr(original_req,
                                      PJSIP_H_RECORD_ROUTE,
                                      NULL);

  while (rr_hdr != NULL)
  {
    mangelwurzel_rr_index++;
    rr_hdr = (pjsip_rr_hdr*)pjsip_msg_find_hdr(original_req,
                                               PJSIP_H_RECORD_ROUTE,
                                               rr_hdr->next);
  }

  rr_hdr = (pjsip_rr_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_RECORD_ROUTE, NULL);
  int rr_index = 0;

  while (rr_hdr != NULL)
  {
    rr_index++;

    if (rr_index != mangelwurzel_rr_index)
    {
      mangle_uri(rr_hdr->name_addr.uri, pool, true);
    }

    rr_hdr = (pjsip_rr_hdr*)pjsip_msg_find_hdr(msg,
                                               PJSIP_H_RECORD_ROUTE,
                                               rr_hdr->next);
  }
}

void MangelwurzelTsx::mangle_routes(pjsip_msg* msg, pj_pool_t* pool)
{
  pjsip_route_hdr* route_hdr =
    (pjsip_route_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_ROUTE, NULL);

  while (route_hdr != NULL)
  {
    mangle_uri(route_hdr->name_addr.uri, pool, true);
    route_hdr = (pjsip_route_hdr*)pjsip_msg_find_hdr(msg,
                                                     PJSIP_H_ROUTE,
                                                     route_hdr->next);
  }
}

void MangelwurzelTsx::record_route(pjsip_msg* req, pj_pool_t* pool)
{
  const pjsip_route_hdr* mangelwurzel_route_hdr = route_hdr();
  pjsip_uri* mangelwurzel_uri =
    (pjsip_uri*)pjsip_uri_clone(pool, mangelwurzel_route_hdr->name_addr.uri);

  pjsip_rr_hdr* rr_hdr = pjsip_rr_hdr_create(pool);
  rr_hdr->name_addr.uri = mangelwurzel_uri;

  pjsip_msg_insert_first_hdr(req, (pjsip_hdr*)rr_hdr);
}
