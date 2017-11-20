/**
 * @file compositesproutlet.h
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "compositesproutlet.h"
#include "pjutils.h"
#include "baseresolver.h"

CompositeSproutletTsx::CompositeSproutletTsx(
                                         Sproutlet* sproutlet,
                                         const std::string& next_hop_service) :
  SproutletTsx(sproutlet),
  _next_hop_service(next_hop_service)
{}

int CompositeSproutletTsx::send_request(pjsip_msg*& req,
                                        int allowed_host_state)
{
  pjsip_to_hdr* to_hdr = PJSIP_MSG_TO_HDR(req);
  bool in_dialog = ((to_hdr != NULL) && (to_hdr->tag.slen != 0));

  if (!in_dialog && !_next_hop_service.empty())
  {
    // This is a standalone or dialog-creating request, and we have a next hop
    // configured - use it.
    pjsip_sip_uri* base_uri = get_routing_uri(req);

    if (!PJSIP_URI_SCHEME_IS_SIP(base_uri))
    {
      // There is no SIP URI available for this message.  We mustn't pass in
      // any other form of URI (e.g. Tel URI), as we need a SIP URI for routing
      // to the next hop.  Passing in null will use the node's root URI.
      base_uri = nullptr;
    }

    pjsip_sip_uri* uri = next_hop_uri(_next_hop_service,
                                      base_uri,
                                      get_pool(req));
    PJUtils::add_top_route_header(req, uri, get_pool(req));
  }

  return _helper->send_request(req, allowed_host_state);
}
