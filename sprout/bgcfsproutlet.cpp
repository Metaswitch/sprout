/**
 * @file bgcfsproutlet.cpp  BGCF Sproutlet classes, implementing BGCF
 *                          specific SIP proxy functions.
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
#include "sproutsasevent.h"
#include "bgcfsproutlet.h"
#include <fstream>

/// BGCFSproutlet constructor.
BGCFSproutlet::BGCFSproutlet(int port,
                             BgcfService* bgcf_service,
                             ACRFactory* acr_factory) :
  Sproutlet("bgcf", port),
  _bgcf_service(bgcf_service),
  _acr_factory(acr_factory)
{
}


/// BGCFSproutlet destructor.
BGCFSproutlet::~BGCFSproutlet()
{
}


/// Creates a BGCFSproutletTsx instance for performing BGCF service processing
/// on a request.
SproutletTsx* BGCFSproutlet::get_tsx(SproutletTsxHelper* helper, pjsip_msg* req)
{
  return (SproutletTsx*)new BGCFSproutletTsx(helper, this);
}


/// Look up a route from the configured rules.
///
/// @return            - The URIs to route the message on to (in order).
/// @param domain      - The domain to find a route for.
std::vector<std::string> BGCFSproutlet::get_route(const std::string &domain,
                                                  SAS::TrailId trail) const
{
  return _bgcf_service->get_route(domain, trail);
}

/// Get an ACR instance from the factory.
///
/// @param trail                SAS trail identifier to use for the ACR.
ACR* BGCFSproutlet::get_acr(SAS::TrailId trail)
{
  return _acr_factory->get_acr(trail, CALLING_PARTY, NODE_ROLE_TERMINATING);
}


/// Individual Tsx constructor.
BGCFSproutletTsx::BGCFSproutletTsx(SproutletTsxHelper* helper,
                                   BGCFSproutlet* bgcf) :
  SproutletTsx(helper),
  _bgcf(bgcf)
{
}

/// Tsx destructor (may also cause ACRs to be sent).
BGCFSproutletTsx::~BGCFSproutletTsx()
{
  if (_acr != NULL)
  {
    _acr->send_message();
  }

  delete _acr;
}


void BGCFSproutletTsx::on_rx_initial_request(pjsip_msg* req)
{
  // Create an ACR for this transaction.
  _acr = _bgcf->get_acr(trail());
  _acr->rx_request(req);

  // Extract the domain from the ReqURI if this is a SIP URI.
  pjsip_uri* req_uri = (pjsip_uri*)req->line.req.uri;
  std::string domain;
  if (!PJUtils::is_uri_phone_number(req_uri))
  {
    domain = PJUtils::pj_str_to_string(&((pjsip_sip_uri*)req_uri)->host);
  }

  // Find the downstream routes based on the domain.
  std::vector<std::string> bgcf_routes = _bgcf->get_route(domain, trail());

  if (!bgcf_routes.empty())
  {
    for (std::vector<std::string>::iterator ii = bgcf_routes.begin();
         ii != bgcf_routes.end();
         ++ii)
    {
      pjsip_uri* route_uri = PJUtils::uri_from_string(*ii, get_pool(req), PJ_TRUE);
      route_uri = (route_uri == NULL) ? route_uri :
                                        (pjsip_uri*)pjsip_uri_get_uri(route_uri);

      if (route_uri != NULL && PJSIP_URI_SCHEME_IS_SIP(route_uri))
      {
        PJUtils::add_route_header(req, (pjsip_sip_uri*)route_uri, get_pool(req));
      }
      else
      {
        LOG_WARNING("Configured route (%s) isn't a valid SIP URI", (*ii).c_str());

        pjsip_msg* rsp = create_response(req, PJSIP_SC_INTERNAL_SERVER_ERROR);
        send_response(rsp);
        free_msg(req);

        return;
      }
    }

    send_request(req);
  }
  else
  {
    LOG_DEBUG("No route configured for %s", domain.c_str());
#if 0
    // TS 24.229 doesn't cover the behavior if the domain is not routable
    // from the BGCF.  Simply response 404 and explain why in the reason.
    pjsip_msg* rsp = create_response(req, PJSIP_SC_NOT_FOUND, "No route to target");
    send_response(rsp);
    free_msg(req);
#else
    // Previous behaviour on no route was to try to forward the request as-is,
    // (so trying to route to the domain in the request URI directly).
    send_request(req);
#endif
  }
}


void BGCFSproutletTsx::on_tx_request(pjsip_msg* req)
{
  if (_acr != NULL)
  {
    // Pass the transmitted request to the ACR to update the accounting
    // information.
    _acr->tx_request(req);
  }
}


void BGCFSproutletTsx::on_rx_response(pjsip_msg* rsp, int fork_id)
{
  if (_acr != NULL)
  {
    // Pass the received response to the ACR.
    // @TODO - timestamp from response???
    _acr->rx_response(rsp);
  }

  // Forward the response upstream.  The proxy layer will aggregate responses
  // if required.
  send_response(rsp);
}


void BGCFSproutletTsx::on_tx_response(pjsip_msg* rsp)
{
  if (_acr != NULL)
  {
    // Pass the transmitted response to the ACR to update the accounting
    // information.
    _acr->tx_response(rsp);
  }
}


void BGCFSproutletTsx::on_cancel(int status_code, pjsip_msg* cancel_req)
{
  if ((status_code == PJSIP_SC_REQUEST_TERMINATED) &&
      (cancel_req != NULL))
  {
    // Create and send an ACR for the CANCEL request.
    ACR* acr = _bgcf->get_acr(trail());

    // @TODO - timestamp from request.
    acr->rx_request(cancel_req);
    acr->send_message();

    delete acr;
  }
}
