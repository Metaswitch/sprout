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

void get_scscf_uri(pjsip_msg* req,
                   pjsip_sip_uri* scscf_uri,
                   std::string* local_hostname,
                   SproutletTsxHelper* tsx);

std::string construct_hostname(std::string received_local_hostname,
                               std::string scscf_local_hostname,
                               pj_str_t* scscf_hostname);
}

#endif
