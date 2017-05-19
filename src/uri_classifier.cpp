/**
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2015  Metaswitch Networks Ltd
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

#include <vector>
#include <boost/regex.hpp>
#include "uri_classifier.h"
#include "stack.h"
#include "constants.h"

// Regexes that match global and local numbers:
// - A global number starts with "+" followed by a combination of digits "0-9"
//   and visual separators ",-()".
// - A local number can contain a combination of hexdigits "0-9A-F", "*#" and
//   visual separators ",-()".
static const boost::regex CHARS_ALLOWED_IN_GLOBAL_NUM = boost::regex("\\+[0-9,\\-\\(\\)]*");
static const boost::regex CHARS_ALLOWED_IN_LOCAL_NUM = boost::regex("[0-9A-F\\*#,\\-\\(\\)]*");

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
    std::string user = PJUtils::pj_str_to_string(&tel_uri->number);
    boost::match_results<std::string::const_iterator> results;
    if (boost::regex_match(user, results, CHARS_ALLOWED_IN_GLOBAL_NUM))
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
      // Get the user part minus any parameters.
      std::string user = PJUtils::pj_str_to_string(&sip_uri->user);
      std::vector<std::string> user_tokens;
      Utils::split_string(user, ';', user_tokens, 0, true);
      boost::match_results<std::string::const_iterator> results;
      if (boost::regex_match(user_tokens[0], results, CHARS_ALLOWED_IN_GLOBAL_NUM))
      {
        ret = GLOBAL_PHONE_NUMBER;
      }
      else if (boost::regex_match(user_tokens[0], results, CHARS_ALLOWED_IN_LOCAL_NUM))
      {
        ret = enforce_global ? LOCAL_PHONE_NUMBER : GLOBAL_PHONE_NUMBER;
      }
      else
      {
        ret = HOME_DOMAIN_SIP_URI;
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
