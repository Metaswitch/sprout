/**
 * @file scscf_utils.cpp Helper functions for S-CSCF sproutlets.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "scscf_utils.h"

void SCSCFUtils::get_scscf_uri(pjsip_msg* req,
                               pj_pool_t* pool,
                               pjsip_sip_uri* scscf_uri,
                               SproutletTsxHelper* tsx)
{
  // Get the local hostname part of the URI that routed to this Sproutlet. We
  // will use this in the S-CSCF URI.
  //
  // This is so that we preserve the URI of the S-CSCF that we originally tried
  // to route to so that we then send it on the SAR to the HSS.
  const pjsip_route_hdr* original_route = tsx->route_hdr();
  pjsip_sip_uri* original_uri;
  if (original_route != NULL)
  {
    original_uri = (pjsip_sip_uri*)original_route->name_addr.uri;
  }
  else
  {
    original_uri = (pjsip_sip_uri*)req->line.req.uri;
  }

  // Get the local hostname part of the URI that routed the request here.
  std::string received_local_hostname = tsx->get_local_hostname(original_uri);

  // Get the local hostname part of the S-CSCF URI;
  std::string scscf_local_hostname = tsx->get_local_hostname(scscf_uri);


  // Replace the local hostname part of the configured S-CSCF URI with the
  // local hostname part of the URI that caused us to be routed here.
  std::string new_scscf_hostname = PJUtils::pj_str_to_string(&scscf_uri->host);
  size_t pos = new_scscf_hostname.rfind(scscf_local_hostname);
  new_scscf_hostname.replace(pos, scscf_local_hostname.length(), received_local_hostname);

  pj_strdup2(pool, &scscf_uri->host, new_scscf_hostname.c_str());
}
