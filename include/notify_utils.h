/**
 * @file notify_utils.h
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
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

#ifndef NOTIFY_UTILS_H__
#define NOTIFY_UTILS_H__

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
#include <pjsip/sip_msg.h>
}

#include <string>
#include "regstore.h"
#include "ifchandler.h"
#include "hssconnection.h"
#include "pjsip-simple/evsub.h"

namespace NotifyUtils
{
  enum DocState { FULL, PARTIAL };
  enum RegContactState { ACTIVE, TERMINATED };
  enum ContactEvent { REGISTERED, CREATED, REFRESHED, EXPIRED, DEACTIVATED, UNREGISTERED };

  pj_status_t create_request_from_subscription(pjsip_tx_data** tdata, RegStore::AoR::Subscription* subscription, int cseq, pj_str_t* body);
//  pj_str_t create_contact(pj_str_t aor, std::string id, pj_str_t state, std::string uri, std::string display_name, std::string unknown_param);
  pj_status_t notify_create_body(pjsip_msg_body* body, 
                                 pj_pool_t* pool, 
                                 std::string& aor, 
                                 RegStore::AoR::Subscription* subscription, 
                                 const RegStore::AoR::Bindings& bindings, 
                                 DocState doc_state,
                                 RegContactState reg_state,
                                 RegContactState contact_state, 
                                 ContactEvent contact_event);

  pj_status_t create_notify(pjsip_tx_data** tdata_notify,
                            RegStore::AoR::Subscription* subscription,
                            std::string aor, 
                            int cseq,
                            const RegStore::AoR::Bindings& bindings,
                            NotifyUtils::DocState doc_state,
                            NotifyUtils::RegContactState reg_state,
                            NotifyUtils::RegContactState contact_state,
                            NotifyUtils::ContactEvent contact_event);
};

#endif
