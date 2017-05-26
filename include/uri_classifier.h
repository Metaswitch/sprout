/**
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef URI_CLASSIFIER_H
#define URI_CLASSIFIER_H

#include <string>

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

// Forward declaration of PJUtils function.
namespace PJUtils {

std::string pj_str_to_string(const pj_str_t* pjstr);

}

enum URIClass
{
  UNKNOWN = 0,
  LOCAL_PHONE_NUMBER,
  GLOBAL_PHONE_NUMBER,
  NODE_LOCAL_SIP_URI,
  HOME_DOMAIN_SIP_URI,
  OFFNET_SIP_URI,
  NP_DATA,
  FINAL_NP_DATA
};

namespace URIClassifier
{
  URIClass classify_uri(const pjsip_uri* uri, bool prefer_sip = true, bool check_np = false);

  bool is_user_numeric(pj_str_t user);

  extern bool enforce_user_phone;
  extern bool enforce_global;
  extern std::vector<pj_str_t*> home_domains;
};

#endif
