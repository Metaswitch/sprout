/**
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <vector>
#include "uri_classifier.h"
#include "stack.h"
#include "constants.h"

std::vector<pj_str_t*> URIClassifier::home_domains;
bool URIClassifier::enforce_global;
bool URIClassifier::enforce_user_phone;

bool URIClassifier::is_user_numeric(pj_str_t user)
{
  const char* uri = user.ptr;

  for (int i = 0; i < user.slen; i++)
  {
    if ((uri[i] == '+') ||
        (uri[i] == '-') ||
        (uri[i] == '.') ||
        (uri[i] == '(') ||
        (uri[i] == ')') ||
        (uri[i] == '[') ||
        (uri[i] == ']') ||
        ((uri[i] >= '0') &&
         (uri[i] <= '9')))
    {
      continue;
    }
    else
    {
      return false;
    }
  }
  return true;
}

static bool is_home_domain(pj_str_t host)
{
    for (unsigned int i = 0; i < URIClassifier::home_domains.size(); ++i)
    {
      if (pj_stricmp(&host, URIClassifier::home_domains[i]) == 0)
      {
        return true;
      }
    }

  // Doesn't match
  return false;
}

static bool is_local_name(pj_str_t host)
{
  for (std::vector<pj_str_t>::iterator it = stack_data.name.begin();
       it != stack_data.name.end();
       ++it)
  {
    if (pj_stricmp(&host, &(*it)) == 0)
    {
      return true;
    }
  }

  // Doesn't match
  return false;
}

// Determine the type of a URI.
//
// Parameters:
//
// - uri - the URI to classify
// - prefer_sip - for ambiguous URIs like sip:+1234@example.com (which could be a global phone
// number or just a SIP URI), prefer to interpret it as SIP
// - check_np - check for the presence of Number Portability parameters and
// classify accordingly
//
URIClass URIClassifier::classify_uri(const pjsip_uri* uri, bool prefer_sip, bool check_np)
{
  URIClass ret = URIClass::UNKNOWN;

  // First, check to see if this URI has number portability data - this takes priority
  bool has_rn = false;
  bool has_npdi = false;

  if (check_np)
  {
    if (PJSIP_URI_SCHEME_IS_TEL(uri))
    {
      // If the URI is a tel URI, pull out the information from the other_params
      has_rn = (pjsip_param_find(&((pjsip_tel_uri*)uri)->other_param, &STR_RN) != NULL);
      has_npdi = (pjsip_param_find(&((pjsip_tel_uri*)uri)->other_param, &STR_NPDI) != NULL);
    }
    else if (PJSIP_URI_SCHEME_IS_SIP(uri))
    {
      // If the URI is a tel URI, pull out the information from the userinfo_params
      has_rn = (pjsip_param_find(&((pjsip_sip_uri*)uri)->userinfo_param, &STR_RN) != NULL);
      has_npdi = (pjsip_param_find(&((pjsip_sip_uri*)uri)->userinfo_param, &STR_NPDI) != NULL);
    }
  }

  if (has_rn)
  {
    if (has_npdi)
    {
      ret = FINAL_NP_DATA;
    }
    else
    {
      ret = NP_DATA;
    }
  }
  // No number portability data
  else if (PJSIP_URI_SCHEME_IS_TEL(uri))
  {
    // TEL URIs can only represent phone numbers - decide if it's a global (E.164) number or not
    pjsip_tel_uri* tel_uri = (pjsip_tel_uri*)uri;
    if (tel_uri->number.slen > 0 && tel_uri->number.ptr[0] == '+')
    {
      ret = GLOBAL_PHONE_NUMBER;
    }
    else
    {
      ret = enforce_global ? LOCAL_PHONE_NUMBER : GLOBAL_PHONE_NUMBER;
    }
  }
  else if (PJSIP_URI_SCHEME_IS_SIP(uri))
  {
    pjsip_sip_uri* sip_uri = (pjsip_sip_uri*)uri;
    pj_str_t host = sip_uri->host;
    bool home_domain = is_home_domain(host);
    bool local_to_node = is_local_name(host);
    bool is_gruu = (pjsip_param_find(&((pjsip_sip_uri*)uri)->other_param, &STR_GR) != NULL);
    bool treat_number_as_phone = !enforce_user_phone && !prefer_sip;

    TRC_DEBUG("home domain: %s, local_to_node: %s, is_gruu: %s, enforce_user_phone: %s, prefer_sip: %s, treat_number_as_phone: %s",
              home_domain ? "true" : "false",
              local_to_node ? "true" : "false",
              is_gruu ? "true" : "false",
              enforce_user_phone ? "true" : "false",
              prefer_sip ? "true" : "false",
              treat_number_as_phone ? "true" : "false");

    // SIP URI that's 'really' a phone number - apply the same logic as for TEL URIs
    if ((!pj_strcmp(&((pjsip_sip_uri*)uri)->user_param, &STR_USER_PHONE) ||
         (home_domain && treat_number_as_phone && !is_gruu)))
    {
      if (sip_uri->user.slen > 0 && sip_uri->user.ptr[0] == '+')
      {
        ret = GLOBAL_PHONE_NUMBER;
      }
      else
      {
        ret = enforce_global ? LOCAL_PHONE_NUMBER : GLOBAL_PHONE_NUMBER;
      }
    }
    // Not a phone number - classify it based on domain
    else if (home_domain)
    {
      ret = HOME_DOMAIN_SIP_URI;
    }
    else if (local_to_node)
    {
      ret = NODE_LOCAL_SIP_URI;
    }
    else
    {
      ret = OFFNET_SIP_URI;
    }
  }

  TRC_DEBUG("Classified URI as %d", (int)ret);
  return ret;
}
