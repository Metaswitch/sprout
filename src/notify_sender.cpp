/**
 * @file subscriber_manager.cpp
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "notify_sender.h"
#include "pjutils.h"


NotifySender::NotifySender()
{
}

NotifySender::~NotifySender()
{
}

void NotifySender::send_notifys(const std::string& aor_id,
                                const SubscriberDataUtils::ClassifiedBindings& classified_bindings,
                                const SubscriberDataUtils::ClassifiedSubscriptions& classified_subscriptions,
                                AssociatedURIs& associated_uris,
                                int cseq,
                                int now,
                                SAS::TrailId trail)
{
  // The registration state is ACTIVE if we have at least one active binding,
  // otherwise it is TERMINATED.
  NotifyUtils::RegistrationState reg_state = NotifyUtils::RegistrationState::TERMINATED;
  for (SubscriberDataUtils::ClassifiedBinding* classified_binding : classified_bindings)
  {
    if (classified_binding->_contact_event == SubscriberDataUtils::ContactEvent::REGISTERED ||
        classified_binding->_contact_event == SubscriberDataUtils::ContactEvent::CREATED ||
        classified_binding->_contact_event == SubscriberDataUtils::ContactEvent::REFRESHED ||
        classified_binding->_contact_event == SubscriberDataUtils::ContactEvent::SHORTENED)
    {
      TRC_DEBUG("Registration state ACTIVE on NOTIFY");
      reg_state = NotifyUtils::RegistrationState::ACTIVE;
      break;
    }
  }

  for (SubscriberDataUtils::ClassifiedSubscription* classified_subscription : classified_subscriptions)
  {
    if (classified_subscription->_notify_required)
    {
      // TODO NotifyUtils needs to use make sure it doesn't send the emergency
      // bindings in its NOTIFYs.
      TRC_DEBUG("Sending NOTIFY for subscription %s: %s",
                classified_subscription->_id.c_str(),
                classified_subscription->_reasons.c_str());

      if (classified_subscription->_subscription_event == SubscriberDataUtils::SubscriptionEvent::TERMINATED)
      {
        // This is a terminated subscription - set the expiry time to now
        classified_subscription->_subscription->_expires = now;
      }

      pjsip_tx_data* tdata_notify = NULL;
      pj_status_t status = NotifyUtils::create_subscription_notify(
                                              &tdata_notify,
                                              classified_subscription->_subscription,
                                              aor_id,
                                              associated_uris,
                                              cseq,
                                              classified_bindings,
                                              reg_state,
                                              now,
                                              trail);

      if (status == PJ_SUCCESS)
      {
        status = PJUtils::send_request(tdata_notify, 0, NULL, NULL, true);
      }
    }
    else
    {
      TRC_DEBUG("Not sending NOTIFY for subscription %s",
                classified_subscription->_id.c_str());
    }
  }
}
