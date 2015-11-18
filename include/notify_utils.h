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
#include "subscriber_data_manager.h"
#include "ifchandler.h"
#include "hssconnection.h"
#include "pjsip-simple/evsub.h"

namespace NotifyUtils
{
  // See RFC 3265 
  enum class DocState { FULL, PARTIAL };
  enum class RegistrationState { ACTIVE, TERMINATED };
  enum class ContactState { ACTIVE, TERMINATED };
  enum class SubscriptionState { ACTIVE, TERMINATED };
  enum class ContactEvent { REGISTERED, CREATED, REFRESHED, EXPIRED, SHORTENED };

  // Wrapper for the bindings in a NOTIFY. The information needed is
  // the binding itself, a unique ID for it and the contact event
  struct BindingNotifyInformation {
    BindingNotifyInformation(std::string id,
                             SubscriberDataManager::AoR::Binding* b,
                             NotifyUtils::ContactEvent event) :
      _id(id),
      _b(b),
      _contact_event(event)
    {}

    std::string _id;
    SubscriberDataManager::AoR::Binding* _b;
    NotifyUtils::ContactEvent _contact_event;
  };

  pj_status_t create_subscription_notify(pjsip_tx_data** tdata_notify,
                                         SubscriberDataManager::AoR::Subscription* s,
                                         std::string aor,
                                         SubscriberDataManager::AoR* aor_data,
                                         std::vector<BindingNotifyInformation*> bnis,
                                         NotifyUtils::RegistrationState reg_state,
                                         int now);

  pj_status_t create_notify(pjsip_tx_data** tdata_notify,
                            SubscriberDataManager::AoR::Subscription* subscription,
                            std::string aor, 
                            int cseq,
                            std::vector<BindingNotifyInformation*> bnis,
                            NotifyUtils::RegistrationState reg_state,
                            NotifyUtils::SubscriptionState subscription_state,
                            int expiry);
};

#endif
