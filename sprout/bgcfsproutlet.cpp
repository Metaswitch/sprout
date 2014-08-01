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
BGCFSproutlet::BGCFSproutlet(const std::string& bgcf_file,
                             ACRFactory* acr_factory) :
  Sproutlet("BGCF"),
  _bgcf_file(bgcf_file),
  _acr_factory(acr_factory)
{
  // Create an updater to keep the bgcf routes configured appropriately.
  _updater = new Updater<void, BGCFSproutlet>(this, std::mem_fun(&BGCFSproutlet::update_routes));
}


/// BGCFSproutlet destructor.
BGCFSproutlet::~BGCFSproutlet()
{
  delete _updater; _updater = NULL;
}


/// Creates a BGCFSproutletTsx instance for performing BGCF service processing
/// on a request.
SproutletTsx* BGCFSproutlet::get_app_tsx(SproutletTsxHelper* helper, pjsip_msg* req)
{
  return (SproutletTsx*)new BGCFSproutletTsx(helper, this);
}


/// Callback function to load updated routing rules.
void BGCFSproutlet::update_routes()
{
  Json::Value root;
  Json::Reader reader;

  std::string jsonData;
  std::ifstream file;

  LOG_STATUS("Loading BGCF configuration from %s", _bgcf_file.c_str());

  std::map<std::string, std::vector<std::string>> new_routes;

  file.open(_bgcf_file.c_str());
  if (file.is_open())
  {
    if (!reader.parse(file, root))
    {
      LOG_WARNING("Failed to read BGCF configuration data, %s",
                  reader.getFormattedErrorMessages().c_str());
      return;
    }

    file.close();

    if (root["routes"].isArray())
    {
      Json::Value routes = root["routes"];

      for (size_t ii = 0; ii < routes.size(); ++ii)
      {
        Json::Value route = routes[(int)ii];
        if ((route["domain"].isString()) &&
            (route["route"].isArray()))
        {
          std::vector<std::string> route_vec;
          Json::Value route_vals = route["route"];
          std::string domain = route["domain"].asString();

          for (size_t jj = 0; jj < route_vals.size(); ++jj)
          {
            Json::Value route_val = route_vals[(int)jj];
            route_vec.push_back(route_val.asString());
          }

          new_routes.insert(std::make_pair(domain, route_vec));
          route_vec.clear();
        }
        else
        {
          LOG_WARNING("Badly formed BGCF route entry %s", route.toStyledString().c_str());
        }
      }

      _routes = new_routes;
    }
    else
    {
      LOG_WARNING("Badly formed BGCF configuration file - missing routes object");
    }
  }
  else
  {
    LOG_WARNING("Failed to read BGCF configuration data %d", file.rdstate());
  }
}

/// Look up a route from the configured rules.
///
/// @return            - The URIs to route the message on to (in order).
/// @param domain      - The domain to find a route for.
std::vector<std::string> BGCFSproutlet::get_route(const std::string &domain,
                                                  SAS::TrailId trail) const
{
  LOG_DEBUG("Getting route for URI domain %s via BGCF lookup", domain.c_str());

  // First try the specified domain.
  std::map<std::string, std::vector<std::string>>::const_iterator ii = _routes.find(domain);
  if (ii != _routes.end())
  {
    LOG_INFO("Found route to domain %s", domain.c_str());

    SAS::Event event(trail, SASEvent::BGCF_FOUND_ROUTE, 0);
    event.add_var_param(domain);
    std::string route_string;

    for (std::vector<std::string>::const_iterator jj = ii->second.begin();
         jj != ii->second.end();
         ++jj)
    {
      route_string = route_string + *jj + ";";
    }

    event.add_var_param(route_string);
    SAS::report_event(event);

    return ii->second;
  }

  // Then try the default domain (*).
  ii = _routes.find("*");
  if (ii != _routes.end())
  {
    LOG_INFO("Found default route");

    SAS::Event event(trail, SASEvent::BGCF_DEFAULT_ROUTE, 0);
    event.add_var_param(domain);
    std::string route_string;

    for (std::vector<std::string>::const_iterator jj = ii->second.begin();
         jj != ii->second.end();
         ++jj)
    {
      route_string = route_string + *jj + ";";
    }

    event.add_var_param(route_string);
    SAS::report_event(event);

    return ii->second;
  }

  SAS::Event event(trail, SASEvent::BGCF_NO_ROUTE, 0);
  event.add_var_param(domain);
  SAS::report_event(event);

  return std::vector<std::string>();
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
      pjsip_uri* route_uri = PJUtils::uri_from_string(*ii, get_pool(req));
      if (route_uri != NULL)
      {
        PJUtils::add_route_header(req, (pjsip_sip_uri*)route_uri, get_pool(req));
      }
      else
      {
        pjsip_msg* rsp = create_response(req, PJSIP_SC_INTERNAL_SERVER_ERROR);
        send_response(rsp);
        free_msg(req);
      }
    }
    send_request(req);
  }
  else
  {
    // TS 24.229 doesn't cover the behavior if the domain is not routable
    // from the BGCF.  Simply response 404 and explain why in the reason.
    pjsip_msg* rsp = create_response(req, PJSIP_SC_NOT_FOUND, "No route to target");
    send_response(rsp);
    free_msg(req);
  }
}


void BGCFSproutletTsx::on_tx_request(pjsip_msg* req)
{
  // Pass the transmitted request to the ACR to update the accounting
  // information.
  _acr->tx_request(req);
}


void BGCFSproutletTsx::on_rx_response(pjsip_msg* rsp, int fork_id)
{
  // Pass the received response to the ACR.
  // @TODO - timestamp from response???
  _acr->rx_response(rsp);

  // Forward the response upstream.  The proxy layer will aggregate responses
  // if required.
  send_response(rsp);
}


void BGCFSproutletTsx::on_tx_response(pjsip_msg* rsp) 
{
  // Pass the transmitted response to the ACR to update the accounting
  // information.
  _acr->tx_response(rsp);
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
