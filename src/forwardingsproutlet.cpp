/**
 * @file forwardingsproutlet.h
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "forwardingsproutlet.h"
#include "pjutils.h"

ForwardingSproutletTsx::ForwardingSproutletTsx(Sproutlet* sproutlet,
                                               const std::string& upstream_service_name) :
  SproutletTsx(sproutlet),
  _upstream_service_name(upstream_service_name)
{}

void ForwardingSproutletTsx::forward_request(pjsip_msg* req)
{
  pjsip_sip_uri* base_uri = get_routing_uri(req);
  pjsip_sip_uri* uri = next_hop_uri(_upstream_service_name,
                                    base_uri,
                                    get_pool(req));
  PJUtils::add_top_route_header(req, uri, get_pool(req));
  send_request(req);
}
