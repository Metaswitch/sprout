/**
 * @file notify.h
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef NOTIFY_H__
#define NOTIFY_H__

extern "C" {
#include <pjsip.h>
}

#include <string>
#include <list>
#include <map>
#include <stdio.h>
#include <stdlib.h>

#include "sas.h"
#include "associated_uris.h"
#include "notify_utils.h"
#include "subscriber_data_utils.h"

class NotifySender
{
public:
  NotifySender();

  virtual ~NotifySender();

  /// Create and send any appropriate NOTIFYs
  ///
  /// @param aor_id       The AoR ID
  /// @param associated_uris
  ///                     The IMPUs associated with this IRS
  /// @param aor_pair     The AoR pair to send NOTIFYs for
  /// @param now          The current time
  /// @param trail        SAS trail
  void send_notifys(const std::string& aor_id,
                    const SubscriberDataUtils::ClassifiedBindings& classified_bindings,
                    const SubscriberDataUtils::ClassifiedSubscriptions& classified_subscriptions,
                    AssociatedURIs& associated_uris, // EM-TODO should be condst?
                    int cseq,
                    int now,
                    SAS::TrailId trail);

 private:
//NotifyUtils::ContactEvent determine_contact_event(
//                                           const EventTrigger& event_trigger);

};

#endif
