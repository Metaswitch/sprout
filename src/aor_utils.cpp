/**
 * @file aor_utils.h Aor utililty functions
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "constants.h"
#include "log.h"
#include "pjutils.h"
#include "aor_utils.h"

namespace AoRUtils {

pjsip_sip_uri* pub_gruu(const Binding* binding, pj_pool_t* pool)
{
  pjsip_sip_uri* uri = (pjsip_sip_uri*)PJUtils::uri_from_string(binding->_address_of_record, pool);

  if ((binding->_params.find("+sip.instance") == binding->_params.cend()) ||
      (uri == NULL) ||
      !PJSIP_URI_SCHEME_IS_SIP(uri))
  {
    // GRUUs are only valid for SIP URIs with an instance-id.
    return NULL;
  }

  // The instance parameter might be too short to be a valid GRUU. Specifically
  // if its less than 2 characters in length, the stripping function will give
  // us a buffer underrun, so exit now.
  std::string sip_instance = binding->_params.at("+sip.instance");

  if (sip_instance.length() < 2)
  {
    // instance ID too short to be parsed
    return NULL;
  }

  pjsip_param* gr_param = (pjsip_param*) pj_pool_alloc(pool, sizeof(pjsip_param));
  gr_param->name = STR_GR;
  pj_strdup2(pool, &gr_param->value, sip_instance.c_str());

  // instance-ids are often of the form '"<urn:..."' - convert that to
  // just 'urn:...'
  if (*(gr_param->value.ptr) == '"')
  {
    gr_param->value.ptr++;
    gr_param->value.slen -= 2;
  }

  if (*(gr_param->value.ptr) == '<')
  {
    gr_param->value.ptr++;
    gr_param->value.slen -= 2;
  }

  pj_list_push_back((pj_list_type*)&(uri->other_param), (pj_list_type*)gr_param);
  return uri;
}

std::string pub_gruu_str(const Binding* binding, pj_pool_t* pool)
{
  pjsip_sip_uri* pub_gruu_uri = pub_gruu(binding, pool);

  if (pub_gruu_uri == NULL)
  {
    return "";
  }

  return PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, (pjsip_uri*)pub_gruu_uri);
}

std::string pub_gruu_quoted_string(const Binding* binding, pj_pool_t* pool)
{
  std::string unquoted_pub_gruu = pub_gruu_str(binding, pool);

  if (unquoted_pub_gruu.length() == 0)
  {
    return "";
  }

  std::string ret = "\"" + unquoted_pub_gruu + "\"";
  return ret;
}

}; // namespace AoRUtils
