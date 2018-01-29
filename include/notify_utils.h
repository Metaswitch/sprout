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
#include "ifchandler.h"
#include "hssconnection.h"
#include "pjsip-simple/evsub.h"
#include "subscriber_data_utils.h"

namespace NotifyUtils
{
  // See RFC 3265
  enum class DocState { FULL, PARTIAL };
  enum class RegistrationState { ACTIVE, TERMINATED };
  enum class ContactState { ACTIVE, TERMINATED };
  enum class SubscriptionState { ACTIVE, TERMINATED };

  enum class ContactEvent
  {
    REGISTERED,
    CREATED,
    REFRESHED,
    SHORTENED,
    EXPIRED,
    DEACTIVATED,
    UNREGISTERED
  };

  pj_status_t create_subscription_notify(pjsip_tx_data** tdata_notify,
                                         Subscription* s,
                                         std::string aor,
                                         AssociatedURIs& associated_uris,
                                         int cseq,
                                         SubscriberDataUtils::ClassifiedBindings bnis,
                                         NotifyUtils::RegistrationState reg_state,
                                         int now,
                                         SAS::TrailId trail);

  pj_status_t create_notify(pjsip_tx_data** tdata_notify,
                            Subscription* subscription,
                            std::string aor,
                            AssociatedURIs& associated_uris,
                            int cseq,
                            SubscriberDataUtils::ClassifiedBindings bnis,
                            NotifyUtils::RegistrationState reg_state,
                            NotifyUtils::SubscriptionState subscription_state,
                            int expiry,
                            SAS::TrailId trail);
};

#endif
