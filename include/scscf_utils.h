/**
 * @file scscf_utils.h Helper functions for S-CSCF sproutlets.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef SCSCFUTILS_H__
#define SCSCFUTILS_H__

#include <sproutlet.h>
#include <pjutils.h>

namespace SCSCFUtils {

/// Creates an S-CSCF URI for the request provided.
///
/// @param  pool       - The pool to allocate the S-CSCF URI in.
/// @param  received_local_hostname
///                    - The local hostname part of the received request.
/// @param scscf_local_hostname
///                    - The local hostname part of the configured S-CSCF URI.
/// @param  scscf_uri  - Return parameter containing the S-CSCF URI.
void get_scscf_uri(pj_pool_t* pool,
                   std::string received_local_hostname,
                   std::string scscf_local_hostname,
                   pjsip_sip_uri* scscf_uri);
}

#endif
