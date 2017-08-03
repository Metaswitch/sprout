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

// This function creates an S-CSCF URI for the request that has been received.
// This URI is based on the configured S-CSCF URI and is allocated in the
// provided pool. Its purpose is to maintain the local hostname part of the URI
// that caused the request to be routed here on the S-CSCF URI that it returns.
// This ensures that the URI that we send on the SAR to the HSS matches the
// site-specific URI that the request was originally routed to.
//
// For example, if the configured S-CSCF URI is "scscf.sprout-site2.homedomain"
// and the routing URI is "sprout-site1.homedonain;service=scscf-proxy", then
// the we will construct the S-CSCF URI "scscf.sprout-site1.homedomain". This
// is so that a re-registration through a different site to the original
// registration will work.
void SCSCFUtils::get_scscf_uri(pj_pool_t* pool,
                               std::string received_local_hostname,
                               std::string scscf_local_hostname,
                               pjsip_sip_uri* scscf_uri)
{
  // Replace the local hostname part of the configured S-CSCF URI with the
  // local hostname part of the URI that caused us to be routed here.
  std::string new_scscf_hostname = PJUtils::pj_str_to_string(&scscf_uri->host);
  size_t pos = new_scscf_hostname.rfind(scscf_local_hostname);
  new_scscf_hostname.replace(pos, scscf_local_hostname.length(), received_local_hostname);

  pj_strdup2(pool, &scscf_uri->host, new_scscf_hostname.c_str());
}
