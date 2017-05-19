/**
 * @file bgcfsproutlet.cpp  BGCF Sproutlet classes, implementing BGCF
 *                          specific SIP proxy functions.
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "log.h"
#include "sproutsasevent.h"
#include "bgcfsproutlet.h"
#include "constants.h"
#include <fstream>

/// BGCFSproutlet constructor.
BGCFSproutlet::BGCFSproutlet(const std::string& bgcf_name,
                             int port,
                             const std::string& uri,
                             BgcfService* bgcf_service,
                             EnumService* enum_service,
                             ACRFactory* acr_factory,
                             SNMP::SuccessFailCountByRequestTypeTable* incoming_sip_transactions_tbl,
                             SNMP::SuccessFailCountByRequestTypeTable* outgoing_sip_transactions_tbl,
                             bool override_npdi) :
  Sproutlet(bgcf_name, port, uri, "", incoming_sip_transactions_tbl, outgoing_sip_transactions_tbl),
  _bgcf_service(bgcf_service),
  _enum_service(enum_service),
  _acr_factory(acr_factory),
  _override_npdi(override_npdi)
{
}


/// BGCFSproutlet destructor.
BGCFSproutlet::~BGCFSproutlet()
{
}


/// Creates a BGCFSproutletTsx instance for performing BGCF service processing
/// on a request.
SproutletTsx* BGCFSproutlet::get_tsx(SproutletHelper* helper,
                                     const std::string& alias,
                                     pjsip_msg* req,
                                     pjsip_sip_uri*& next_hop,
                                     pj_pool_t* pool,
                                     SAS::TrailId trail)
{
  return (SproutletTsx*)new BGCFSproutletTsx(this);
}


/// Look up a route from the configured rules.
///
/// @return            - The URIs to route the message on to (in order).
/// @param domain      - The domain to find a route for.
std::vector<std::string> BGCFSproutlet::get_route_from_domain(
                                                  const std::string &domain,
                                                  SAS::TrailId trail) const
{
  return _bgcf_service->get_route_from_domain(domain, trail);
}

/// Look up a route from the configured rules.
///
/// @return            - The URIs to route the message on to (in order).
/// @param domain      - The domain to find a route for.
std::vector<std::string> BGCFSproutlet::get_route_from_number(
                                                  const std::string &number,
                                                  SAS::TrailId trail) const
{
  return _bgcf_service->get_route_from_number(number, trail);
}

/// Get an ACR instance from the factory.
///
/// @param trail                SAS trail identifier to use for the ACR.
ACR* BGCFSproutlet::get_acr(SAS::TrailId trail)
{
  return _acr_factory->get_acr(trail,
                               ACR::CALLING_PARTY,
                               ACR::NODE_ROLE_TERMINATING);
}

/// Individual Tsx constructor.
BGCFSproutletTsx::BGCFSproutletTsx(BGCFSproutlet* bgcf) :
  SproutletTsx(bgcf),
  _bgcf(bgcf),
  _acr(NULL)
{
}

/// Tsx destructor (may also cause ACRs to be sent).
BGCFSproutletTsx::~BGCFSproutletTsx()
{
  if (_acr != NULL)
  {
    _acr->send();
  }

  delete _acr;
}


void BGCFSproutletTsx::on_rx_initial_request(pjsip_msg* req)
{
  // Create an ACR for this transaction.
  _acr = _bgcf->get_acr(trail());
  _acr->rx_request(req);

  std::vector<std::string> bgcf_routes;
  std::string routing_value;
  bool routing_with_number = false;
  PJUtils::update_request_uri_np_data(req,
                                      get_pool(req),
                                      _bgcf->_enum_service,
                                      _bgcf->_override_npdi,
                                      trail());
  pjsip_uri* req_uri = (pjsip_uri*)req->line.req.uri;
  URIClass uri_class = URIClassifier::classify_uri(req_uri);

  if (PJUtils::get_rn(req_uri, routing_value))
  {
    // Find the downstream routes based on the number.
    bgcf_routes = _bgcf->get_route_from_number(routing_value, trail());

    // If there are no matching routes, just route based on the domain - this
    // only matches any wild card routing set up
    if (bgcf_routes.empty())
    {
      routing_value = "";
      bgcf_routes = _bgcf->get_route_from_domain(routing_value, trail());
    }
    else
    {
      routing_with_number = true;
    }
  }
  else if ((uri_class == LOCAL_PHONE_NUMBER) ||
           (uri_class == GLOBAL_PHONE_NUMBER))
  {
    // Try to route based on the phone number first
    pj_str_t pj_user = PJUtils::user_from_uri(req_uri);
    routing_value = PJUtils::pj_str_to_string(&pj_user);
    bgcf_routes = _bgcf->get_route_from_number(routing_value, trail());

    // If there are no matching routes, just route based on the domain - this
    // only matches any wild card routing set up
    if (bgcf_routes.empty())
    {
      routing_value = "";
      bgcf_routes = _bgcf->get_route_from_domain(routing_value, trail());
    }
    else
    {
      routing_with_number = true;
    }
  }
  else
  {
    routing_value = PJUtils::pj_str_to_string(&((pjsip_sip_uri*)req_uri)->host);

    // Find the downstream routes based on the domain.
    bgcf_routes = _bgcf->get_route_from_domain(routing_value, trail());
  }

  if (!bgcf_routes.empty())
  {
    // The BGCF should be in control of what routes get added - delete existing
    // ones first.
    PJUtils::remove_hdr(req, &STR_ROUTE);

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
        TRC_WARNING("Configured route (%s) isn't a valid SIP URI", (*ii).c_str());

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
    TRC_DEBUG("No route configured for %s", routing_value.c_str());

    if ((routing_value == "") || (routing_with_number))
    {
      // If the routing_value is blank we were trying to route a telephone number and
      // there are no more routes to try. If we had an rn value and this failed then
      // there are also no more routes to try.
      pjsip_msg* rsp = create_response(req,
                                       PJSIP_SC_NOT_FOUND,
                                       "No route to target");
      send_response(rsp);
      free_msg(req);
    }
    else
    {
      // Previous behaviour on no route was to try to forward the request as-is,
      // (so trying to route to the domain in the request URI directly).
      send_request(req);
    }
  }
}


void BGCFSproutletTsx::on_tx_request(pjsip_msg* req, int fork_id)
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


// LCOV_EXCL_START - TODO add to UTs
void BGCFSproutletTsx::on_rx_cancel(int status_code, pjsip_msg* cancel_req)
{
  if ((status_code == PJSIP_SC_REQUEST_TERMINATED) &&
      (cancel_req != NULL))
  {
    // Create and send an ACR for the CANCEL request.
    ACR* acr = _bgcf->get_acr(trail());

    // @TODO - timestamp from request.
    acr->rx_request(cancel_req);
    acr->send();

    delete acr;
  }
}
// LCOV_EXCL_STOP
