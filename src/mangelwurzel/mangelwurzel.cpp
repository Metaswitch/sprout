/**
 * @file mangelwurzel.cpp Implementation of mangelwurzel, the B2BUA emulator.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "log.h"
#include "constants.h"
#include "mangelwurzel.h"
#include "mangelwurzelsasevent.h"

/// Mangelwurzel URI parameter constants.
static const pj_str_t DIALOG_PARAM = pj_str((char *)"dialog");
static const pj_str_t REQ_URI_PARAM = pj_str((char *)"req-uri");
static const pj_str_t TO_PARAM = pj_str((char *)"to");
static const pj_str_t ROUTES_PARAM = pj_str((char *)"routes");
static const pj_str_t DOMAIN_PARAM = pj_str((char *)"change-domain");
static const pj_str_t ORIG_PARAM = pj_str((char *)"orig");
static const pj_str_t OOTB_PARAM = pj_str((char *)"ootb");
static const pj_str_t MANGALGORITHM_PARAM = pj_str((char *)"mangalgorithm");
static const char* REVERSE_MANGALGORITHM = "reverse";
static const char* ROT_13_MANGALGORITHM = "rot13";

/// Creates a MangelwurzelTsx instance.
SproutletTsx* Mangelwurzel::get_tsx(SproutletHelper* helper,
                                    const std::string& alias,
                                    pjsip_msg* req,
                                    pjsip_sip_uri*& next_hop,
                                    pj_pool_t* pool,
                                    SAS::TrailId trail)
{
  MangelwurzelTsx::Config config;

  // Find the mangewurzel Route header, parse the parameters and use them to
  // build a Config object. Then construct the MangelwurzelTsx.
  pjsip_route_hdr* route_hdr = (pjsip_route_hdr*)
                                 pjsip_msg_find_hdr(req, PJSIP_H_ROUTE, NULL);
  pjsip_sip_uri* mangelwurzel_uri;

  if (route_hdr != NULL)
  {
    mangelwurzel_uri = (pjsip_sip_uri*)route_hdr->name_addr.uri;
  }
  else
  {
    mangelwurzel_uri = (pjsip_sip_uri*)req->line.req.uri;
  }

  if (pjsip_param_find(&mangelwurzel_uri->other_param, &DIALOG_PARAM) != NULL)
  {
    config.dialog = true;
  }
  if (pjsip_param_find(&mangelwurzel_uri->other_param, &REQ_URI_PARAM) != NULL)
  {
    config.req_uri = true;
  }
  if (pjsip_param_find(&mangelwurzel_uri->other_param, &TO_PARAM) != NULL)
  {
    config.to = true;
  }
  if (pjsip_param_find(&mangelwurzel_uri->other_param, &ROUTES_PARAM) != NULL)
  {
    config.routes = true;
  }
  if (pjsip_param_find(&mangelwurzel_uri->other_param, &DOMAIN_PARAM) != NULL)
  {
    config.change_domain = true;
  }
  if (pjsip_param_find(&mangelwurzel_uri->other_param, &ORIG_PARAM) != NULL)
  {
    config.orig = true;
  }
  if (pjsip_param_find(&mangelwurzel_uri->other_param, &OOTB_PARAM) != NULL)
  {
    config.ootb = true;
  }

  // The mangalgorithm defaults to ROT_13, so only change it if REVERSE is
  // specified, but raise a log if an invalid mangalgorithm is specified.
  pjsip_param* mangalgorithm_param =
    pjsip_param_find(&mangelwurzel_uri->other_param,
                     &MANGALGORITHM_PARAM);
  if (mangalgorithm_param != NULL)
  {
    std::string mangalgorithm =
      PJUtils::pj_str_to_string(&mangalgorithm_param->value);

    if (mangalgorithm == REVERSE_MANGALGORITHM)
    {
      config.mangalgorithm = MangelwurzelTsx::REVERSE;
    }
    else if (mangalgorithm != ROT_13_MANGALGORITHM)
    {
      TRC_ERROR("Invalid mangalgorithm specified: %s",
                mangalgorithm.c_str());
      SAS::Event event(trail, SASEvent::INVALID_MANGALGORITHM, 0);
      event.add_var_param(mangalgorithm);
      SAS::report_event(event);
    }
  }

  return new MangelwurzelTsx(this, config);
}

/// Mangelwurzel receives an initial request. It will Record-Route itself,
/// strip off all the Via headers and send the request on. It can also change
/// the request in various ways depending on the configuration in its Route
/// header.
/// - It can mangle the dialog identifiers using its mangalgorithm.
/// - It can mangle the Request URI and Contact URI using its mangalgorithm.
/// - It can mangle the To URI using its mangalgorithm.
/// - It can edit the S-CSCF Route header to turn the request into either an
///   originating or terminating request.
/// - It can edit the S-CSCF Route header to turn the request into an out of
///   the blue request.
/// - It can mangle the Record-Route headers URIs.
void MangelwurzelTsx::on_rx_initial_request(pjsip_msg* req)
{
  // Store off the unmodified request.
  _unmodified_request = original_request();

  // If Mangelwurzel receives a REGISTER, we need to respond with a 200 OK
  // rather than mangling the request and forwarding it on.
  if (req->line.req.method.id == PJSIP_REGISTER_METHOD)
  {
    pjsip_msg* rsp = create_response(req, PJSIP_SC_OK);
    send_response(rsp);
    free_msg(req);
    return;
  }

  pj_pool_t* pool = get_pool(req);

  // Get Mangelwurzel's route header and clone the URI. We use this in the SAS
  // event logging that we've received a request, and then we use it to
  // Record-Route ourselves.
  const pjsip_route_hdr* mangelwurzel_route_hdr = route_hdr();
  pjsip_uri* mangelwurzel_uri =
    (pjsip_uri*)pjsip_uri_clone(pool, mangelwurzel_route_hdr->name_addr.uri);

  SAS::Event event(trail(), SASEvent::MANGELWURZEL_INITIAL_REQ, 0);
  event.add_var_param(PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                             mangelwurzel_uri));
  SAS::report_event(event);

  if (_config.dialog)
  {
    mangle_dialog_identifiers(req, pool);
  }

  if (_config.req_uri)
  {
    mangle_req_uri(req, pool);
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

  record_route(req, pool, mangelwurzel_uri);

  send_request(req);
}

/// Mangelwurzel receives a response. It will add all the Via headers from the
/// original request back on and send the response on. It can also change
/// the response in various ways depending on the configuration that was
/// specified in the Route header of the original request.
/// - It can mangle the dialog identifiers using its mangalgorithm.
/// - It can mangle the Contact URI using its mangalgorithm.
/// - It can mangle the Record-Route and Route headers URIs.
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

/// Mangelwurzel receives an in dialog request. It will strip off all the Via
/// headers and send the request on. It can also change the request in various
/// ways depending on the configuration in its Route header.
/// - It can mangle the dialog identifiers using its mangalgorithm.
/// - It can mangle the Request URI and Contact URI using its mangalgorithm.
/// - It can mangle the To URI using its mangalgorithm.
/// - It can edit the S-CSCF Route header to turn the request into either an
///   originating or terminating request.
/// - It can edit the S-CSCF Route header to turn the request into an out of
///   the blue request.
/// - It can mangle the Record-Route headers URIs.
void MangelwurzelTsx::on_rx_in_dialog_request(pjsip_msg* req)
{
  // Store off the unmodified request.
  _unmodified_request = original_request();

  pj_pool_t* pool = get_pool(req);

  // Get the URI from the Route header. We use it in the SAS event logging that
  // we've received an in dialog request.
  const pjsip_route_hdr* mangelwurzel_route_hdr = route_hdr();
  pjsip_uri* mangelwurzel_uri = mangelwurzel_route_hdr->name_addr.uri;

  SAS::Event event(trail(), SASEvent::MANGELWURZEL_IN_DIALOG_REQ, 0);
  event.add_var_param(PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                             mangelwurzel_uri));
  SAS::report_event(event);

  if (_config.dialog)
  {
    mangle_dialog_identifiers(req, pool);
  }

  if (_config.req_uri)
  {
    mangle_req_uri(req, pool);
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

/// Apply the mangalgorithm to the From tag, To tag (if present) and call ID of
/// req.
void MangelwurzelTsx::mangle_dialog_identifiers(pjsip_msg* req, pj_pool_t* pool)
{
  pjsip_from_hdr* from_hdr = PJSIP_MSG_FROM_HDR(req);

  if (from_hdr != NULL)
  {
    std::string from_tag = PJUtils::pj_str_to_string(&from_hdr->tag);
    mangle_string(from_tag);
    TRC_DEBUG("From tag mangled to %s", from_tag.c_str());
    from_hdr->tag = pj_strdup3(pool, from_tag.c_str());
  }

  pjsip_to_hdr* to_hdr = PJSIP_MSG_TO_HDR(req);

  if (to_hdr != NULL)
  {
    std::string to_tag = PJUtils::pj_str_to_string(&to_hdr->tag);
    mangle_string(to_tag);
    TRC_DEBUG("To tag mangled to %s", to_tag.c_str());
    to_hdr->tag = pj_strdup3(pool, to_tag.c_str());
  }

  pjsip_cid_hdr* cid_hdr = (pjsip_cid_hdr*)pjsip_msg_find_hdr(req,
                                                              PJSIP_H_CALL_ID,
                                                              NULL);
  if (cid_hdr != NULL)
  {
    std::string call_id = PJUtils::pj_str_to_string(&cid_hdr->id);
    mangle_string(call_id);
    TRC_DEBUG("Call ID manged to %s", call_id.c_str());
    cid_hdr->id = pj_strdup3(pool, call_id.c_str());

    // Report a SAS marker for the new call ID so that the two dialogs can be
    // correlated in SAS.
    TRC_DEBUG("Logging SAS Call-ID marker, Call-ID %.*s",
              cid_hdr->id.slen,
              cid_hdr->id.ptr);
    SAS::Marker cid_marker(trail(), MARKER_ID_SIP_CALL_ID, 1u);
    cid_marker.add_var_param(cid_hdr->id.slen, cid_hdr->id.ptr);
    SAS::report_marker(cid_marker, SAS::Marker::Scope::Trace);
  }
}

/// Apply the mangalgorithm to the Request URI of req.
void MangelwurzelTsx::mangle_req_uri(pjsip_msg* req, pj_pool_t* pool)
{
  mangle_uri(req->line.req.uri, pool, false);
}

/// Apply the mangalgorithm to the Contact URI of req.
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

/// Apply the mangalgorithm to the To URI of req.
void MangelwurzelTsx::mangle_to(pjsip_msg* req, pj_pool_t* pool)
{
  pjsip_to_hdr* to_hdr = PJSIP_MSG_TO_HDR(req);

  if (to_hdr != NULL)
  {
    mangle_uri((pjsip_uri*)pjsip_uri_get_uri(to_hdr->uri), pool, false);
  }
}

/// Apply the mangalgorithm to the specified URI. The user part of the URI is
/// always mangled. The domain is mangled separately, and is only mangled if
/// mangelwurzel's change_domain flag is set, or if the function's
/// force_mangle_domain flag is set (we use this flag to make sure we always
/// mangle the domains for Routes and Record-Routes). We don't mangle
/// anything else (e.g. port number, SIP parameters).
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

/// Decide which mangalgorithm to use.
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

/// Implementation of the rot13 mangalgorithm. Alphabet characters are rotated
/// through the alphabet by 13, numeric characters are rotated through the
/// single digit numbers by 5.
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

/// Implementation of the reverse mangalgorithm. Reverse the string.
void MangelwurzelTsx::reverse(std::string& str)
{
  std::reverse(str.begin(), str.end());
}

/// Remove all the Via headers from the request. We do this on all requests,
/// and we add them back on on responses.
void MangelwurzelTsx::strip_via_hdrs(pjsip_msg* req)
{
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

/// Add the Via headers that we removed from the request back on the response.
/// We do this by looking at the original request.
void MangelwurzelTsx::add_via_hdrs(pjsip_msg* rsp, pj_pool_t* pool)
{
  // Copy all the via headers from the original request back onto the response
  // in the correct order.
  pjsip_via_hdr* via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr(_unmodified_request,
                                                              PJSIP_H_VIA,
                                                              NULL);
  while (via_hdr != NULL)
  {
    pjsip_via_hdr* cloned_via_hdr = (pjsip_via_hdr*)pjsip_hdr_clone(pool,
                                                                    via_hdr);
    pjsip_msg_add_hdr(rsp, (pjsip_hdr*)cloned_via_hdr);

    via_hdr = (pjsip_via_hdr*)pjsip_msg_find_hdr(_unmodified_request,
                                                 PJSIP_H_VIA,
                                                 via_hdr->next);
  }
}

/// Mangelwurzel can be configured to generate originating or terminating
/// requests, and out of the blue requests. This requires manipulation of the
/// S-CSCF Route header, which will be the top Route header. Mangelwurzel
/// adds the orig parameter for originating requests, removes it for
/// terminating requests and removes the ODI token from the URI for out of
/// the blue requests.
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
      TRC_DEBUG("Add orig param to S-CSCF Route header");
      orig_param = PJ_POOL_ALLOC_T(pool, pjsip_param);
      pj_strdup(pool, &orig_param->name, &STR_ORIG);
      orig_param->value.slen = 0;
      pj_list_insert_after(&scscf_uri->other_param, orig_param);
    }
    else if ((!_config.orig) && (orig_param != NULL))
    {
      TRC_DEBUG("Remove orig param from S-CSCF Route header");
      pj_list_erase(orig_param);
    }

    // Ensure there is no ODI token by clearing the user part of the URI.
    if (_config.ootb)
    {
      TRC_DEBUG("Remove ODI token from S-CSCF Route header");
      scscf_uri->user.ptr = NULL;
      scscf_uri->user.slen = 0;
    }
  }
}

/// Apply the mangalgorithm to all the Record-Routes except mangelwurzel's own
/// one.
void MangelwurzelTsx::mangle_record_routes(pjsip_msg* msg, pj_pool_t* pool)
{
  // Calculate which Record-Route header might be mangelwurzel's.
  int mangelwurzel_rr_index = 1;

  pjsip_rr_hdr* rr_hdr =
    (pjsip_rr_hdr*)pjsip_msg_find_hdr(_unmodified_request,
                                      PJSIP_H_RECORD_ROUTE,
                                      NULL);

  while (rr_hdr != NULL)
  {
    // For each Record-Route header on the original request, increment
    // mangelwurzel_rr_index. Once we've found all the original Record-Routes
    // we'll have the index of mangelwurzel's Record-Route on our message.
    mangelwurzel_rr_index++;
    rr_hdr = (pjsip_rr_hdr*)pjsip_msg_find_hdr(_unmodified_request,
                                               PJSIP_H_RECORD_ROUTE,
                                               rr_hdr->next);
  }

  // Now go through the Record-Routes again mangling them.
  rr_hdr = (pjsip_rr_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_RECORD_ROUTE, NULL);
  int rr_index = 0;

  while (rr_hdr != NULL)
  {
    rr_index++;

    // Don't mangle mangelwurzel's Record-Route header.
    if (rr_index != mangelwurzel_rr_index)
    {
      mangle_uri(rr_hdr->name_addr.uri, pool, true);
    }

    rr_hdr = (pjsip_rr_hdr*)pjsip_msg_find_hdr(msg,
                                               PJSIP_H_RECORD_ROUTE,
                                               rr_hdr->next);
  }
}

/// Apply the mangalgorithm to all the Route headers. We only do this for
/// responses and in dialog requests, and it will unmangle the Routes that were
/// mangled in the endpoint's Route-set.
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

/// Record-route ourselves, preserving the parameters on our original Route
/// header.
void MangelwurzelTsx::record_route(pjsip_msg* req,
                                   pj_pool_t* pool,
                                   pjsip_uri* uri)
{
  pjsip_rr_hdr* rr_hdr = pjsip_rr_hdr_create(pool);
  rr_hdr->name_addr.uri = uri;

  pjsip_msg_insert_first_hdr(req, (pjsip_hdr*)rr_hdr);
}
