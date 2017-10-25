/**
 * @file notify_utils.h
 *
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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
  enum class ContactEvent { 
    REGISTERED, 
    CREATED, 
    REFRESHED, 
    SHORTENED,
    EXPIRED, 
    DEACTIVATED, 
    UNREGISTERED
  };

  // Wrapper for the bindings in a NOTIFY. The information needed is
  // the binding itself, a unique ID for it and the contact event
  struct BindingNotifyInformation {
    BindingNotifyInformation(std::string id,
                             AoR::Binding* b,
                             NotifyUtils::ContactEvent event) :
      _id(id),
      _b(b),
      _contact_event(event)
    {}

    std::string _id;
    AoR::Binding* _b;
    NotifyUtils::ContactEvent _contact_event;
  };

  pj_status_t create_subscription_notify(pjsip_tx_data** tdata_notify,
                                         AoR::Subscription* s,
                                         std::string aor,
                                         AssociatedURIs* associated_uris,
                                         AoR* aor_data,
                                         std::vector<BindingNotifyInformation*> bnis,
                                         NotifyUtils::RegistrationState reg_state,
                                         int now,
                                         SAS::TrailId trail);

  pj_status_t create_notify(pjsip_tx_data** tdata_notify,
                            AoR::Subscription* subscription,
                            std::string aor,
                            AssociatedURIs* associated_uris,
                            int cseq,
                            std::vector<BindingNotifyInformation*> bnis,
                            NotifyUtils::RegistrationState reg_state,
                            NotifyUtils::SubscriptionState subscription_state,
                            int expiry,
                            SAS::TrailId trail);
};

#endif
