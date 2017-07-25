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
                               pjsip_sip_uri* scscf_uri,
                               pj_str_t* local_hostname,
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
  pj_pool_t* pool = tsx->get_pool(req);
  pj_str_t unused_service_name;
  tsx->get_local_hostname(original_uri, local_hostname, &unused_service_name, pool);

  // Replace the local hostname part of the configured S-CSCF URI with the
  // local hostname part of the URI that caused us to be routed here.
  pj_str_t unused_local_hostname, service_name;
  tsx->get_local_hostname(scscf_uri, &unused_local_hostname, &service_name, pool);

  pj_str_t hostname;
  construct_hostname(pool, &service_name, local_hostname, &hostname);
  scscf_uri->host = hostname;
}

void SCSCFUtils::construct_hostname(pj_pool_t* pool,
                                    pj_str_t* service_name,
                                    pj_str_t* local_hostname,
                                    pj_str_t* hostname)
{
  if (pj_strcmp2(service_name, ""))
  {
    pj_str_t period = pj_str((char*)".");
    pj_strdup(pool, hostname, service_name);
    PJUtils::pj_str_concatenate(hostname, &period, pool);
    PJUtils::pj_str_concatenate(hostname, local_hostname, pool);
  }
  else
  {
    pj_strdup(pool, hostname, local_hostname); // LCOV_EXCL_LINE
  }
}
