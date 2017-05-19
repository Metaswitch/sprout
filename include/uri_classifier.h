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
