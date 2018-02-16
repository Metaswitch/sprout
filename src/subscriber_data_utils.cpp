/**
 * @file subscriber_data_utils.cpp
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <set>

#include "subscriber_data_utils.h"
#include "log.h"

SubscriberDataUtils::ContactEvent
  SubscriberDataUtils::determine_contact_event(const EventTrigger& event_trigger)
{
  ContactEvent contact_event;
  switch(event_trigger)
  {
    case EventTrigger::TIMEOUT:
      contact_event = ContactEvent::EXPIRED;
      break;
    case EventTrigger::USER:
      contact_event = ContactEvent::UNREGISTERED;
      break;
    case EventTrigger::ADMIN:
    case EventTrigger::HSS:
      contact_event = ContactEvent::DEACTIVATED;
      break;
    // LCOV_EXCL_START - not hittable as all cases of event_trigger are covered
    default:
      contact_event = ContactEvent::EXPIRED;
      break;
    // LCOV_EXCL_STOP
  }
  return contact_event;
}

void SubscriberDataUtils::classify_bindings(const std::string& aor_id,
                                          const SubscriberDataUtils::EventTrigger& event_trigger,
                                          const Bindings& orig_bindings,
                                          const Bindings& updated_bindings,
                                          ClassifiedBindings& classified_bindings)
{
  // We should have been given an empty classified_bindings vector, but clear
  // it just in case.
  delete_bindings(classified_bindings);

  // 1/2: Iterate over the original bindings and record those not in the updated
  // bindings.
  for (BindingPair orig_b : orig_bindings)
  {
    if (updated_bindings.find(orig_b.first) == updated_bindings.end())
    {
      ClassifiedBinding* binding_record =
        new ClassifiedBinding(orig_b.first,
                              orig_b.second,
                              determine_contact_event(event_trigger));
      classified_bindings.push_back(binding_record);
      TRC_DEBUG("Binding %s in AoR %s is no longer present",
                orig_b.first.c_str(),
                aor_id.c_str());
    }
  }

  // 2/2: Iterate over the updated bindings.
  for (BindingPair updated_b : updated_bindings)
  {
    SubscriberDataUtils::ContactEvent event;
    Bindings::const_iterator orig_b_match = orig_bindings.find(updated_b.first);

    std::string binding_id = updated_b.first;
    Binding* binding = updated_b.second;

    if (orig_b_match == orig_bindings.end())
    {
      TRC_DEBUG("Binding %s in AoR %s is new",
                binding_id.c_str(),
                aor_id.c_str());
      event = SubscriberDataUtils::ContactEvent::CREATED;
    }
    else
    {
      // The binding is in both sets.
      if (orig_b_match->second->_uri.compare(binding->_uri) != 0)
      {
        // Change of Contact URI. If the contact URI has been changed, we need to
        // terminate the old contact (ref TS24.229 - NOTE 2 in 5.4.2.1.2
        // "Notification about registration state") and create a new one.
        // We do this by adding a DEACTIVATED and then a CREATED ClassifiedBinding.
        TRC_DEBUG("Binding %s in AoR %s has changed contact URI",
                  binding_id.c_str(),
                  aor_id.c_str());
        ClassifiedBinding* deactivated_record =
           new ClassifiedBinding(orig_b_match->first,
                                 orig_b_match->second,
                                 SubscriberDataUtils::ContactEvent::DEACTIVATED);
        classified_bindings.push_back(deactivated_record);
        event = SubscriberDataUtils::ContactEvent::CREATED;
      }
      else if (orig_b_match->second->_expires < binding->_expires)
      {
        TRC_DEBUG("Binding %s in AoR %s has been refreshed",
                  binding_id.c_str(),
                  aor_id.c_str());
        event = SubscriberDataUtils::ContactEvent::REFRESHED;
      }
      else if (orig_b_match->second->_expires > binding->_expires)
      {
        TRC_DEBUG("Binding %s in AoR %s has been shortened",
                  binding_id.c_str(),
                  aor_id.c_str());
        event = SubscriberDataUtils::ContactEvent::SHORTENED;
      }
      else
      {
        TRC_DEBUG("Binding %s in AoR %s is unchanged",
                  binding_id.c_str(),
                  aor_id.c_str());
        event = SubscriberDataUtils::ContactEvent::REGISTERED;
      }
    }

    ClassifiedBinding* binding_record =
      new ClassifiedBinding(binding_id,
                            binding,
                            event);
    classified_bindings.push_back(binding_record);
  }
}

void SubscriberDataUtils::classify_subscriptions(const std::string& aor_id,
                                               const SubscriberDataUtils::EventTrigger& event_trigger,
                                               const Subscriptions& orig_subscriptions,
                                               const Subscriptions& updated_subscriptions,
                                               const ClassifiedBindings& classified_bindings,
                                               const bool& associated_uris_changed,
                                               ClassifiedSubscriptions& classified_subscriptions)
{
  // We should have been given an empty classified_subscriptions vector, but
  // clear it just in case
  delete_subscriptions(classified_subscriptions);

  // Determine if any bindings have changed
  bool bindings_changed = false;
  for (ClassifiedBinding* classified_binding : classified_bindings)
  {
    if (classified_binding->_contact_event != SubscriberDataUtils::ContactEvent::REGISTERED)
    {
      bindings_changed = true;
    }
  }

  // Decide if we should send a NOTIFY for all subscriptions. We do this if either:
  //  - Any bindings have changed.
  //  - The associated URIs have changed.
  bool base_notify_required = false;
  std::string base_reasons = "Reason(s): - ";
  if (bindings_changed)
  {
    TRC_DEBUG("Bindings changed");
    base_notify_required = true;
    base_reasons += "Bindings changed - ";
  }
  if (associated_uris_changed)
  {
    TRC_DEBUG("Associated URIs changed");
    base_notify_required = true;
    base_reasons += "Associated URIs changed - ";
  }

  // Store the contact URIs of any bindings that have been removed. If there
  // are any subscriptions that share the same contact URI, we may want to send
  // a final NOTIFY.
  std::set<std::string> missing_binding_uris;
  for (ClassifiedBinding* classified_binding : classified_bindings)
  {
    if (classified_binding->_contact_event == SubscriberDataUtils::ContactEvent::EXPIRED ||
        classified_binding->_contact_event == SubscriberDataUtils::ContactEvent::DEACTIVATED ||
        classified_binding->_contact_event == SubscriberDataUtils::ContactEvent::UNREGISTERED)
    {
      missing_binding_uris.insert(classified_binding->_binding->_uri);
    }
  }

  // 1/2: Iterate over the original subscriptions and classify those that aren't
  // in the updated subscriptions.
  for (SubscriptionPair orig_s : orig_subscriptions)
  {
    std::string subscription_id = orig_s.first;
    Subscription* subscription = orig_s.second;

    std::string reasons = base_reasons;
    if ((missing_binding_uris.find(subscription->_req_uri) !=
         missing_binding_uris.end()) &&
        (event_trigger != SubscriberDataUtils::EventTrigger::ADMIN &&
         event_trigger != SubscriberDataUtils::EventTrigger::HSS))
    {
      // Binding is missing, and this event is not triggered by admin or hss.
      // The binding no longer exists due to user deregestration or timeout, so
      // classify the subscription as EXPIRED.
      TRC_DEBUG("Subscription %s in AoR %s has been expired since the binding that"
                " shares its contact URI %s has expired or changed contact URI",
                subscription_id.c_str(),
                aor_id.c_str(),
                subscription->_req_uri.c_str());

      ClassifiedSubscription* classified_subscription =
        new ClassifiedSubscription(aor_id,
                                   subscription_id,
                                   subscription,
                                   SubscriberDataUtils::SubscriptionEvent::EXPIRED);

      classified_subscription->_notify_required = false;
      classified_subscriptions.push_back(classified_subscription);
    }
    else if (updated_subscriptions.find(subscription_id) == updated_subscriptions.end())
    {
      // The subscription has either been deleted by the user or has expired, so
      // classify it as TERMINATED.
      TRC_DEBUG("Subscription %s in AoR %s has been terminated",
                subscription_id.c_str(),
                aor_id.c_str());

      reasons += "Subscription terminated - ";

      ClassifiedSubscription* classified_subscription =
        new ClassifiedSubscription(aor_id,
                                   subscription_id,
                                   subscription,
                                   SubscriberDataUtils::SubscriptionEvent::TERMINATED);

      classified_subscription->_notify_required = true;
      classified_subscription->_reasons = reasons;
      classified_subscriptions.push_back(classified_subscription);
    }
  }

  // 2/2: Iterate over the updated subscriptions and classify them.
  for (SubscriptionPair updated_s : updated_subscriptions)
  {

    std::string subscription_id = updated_s.first;
    Subscription* subscription = updated_s.second;

    // Find the subscription in the set if original subscriptions to determine
    // if the current subscription has been changed.
    Subscriptions::const_iterator orig_s_match = orig_subscriptions.find(subscription_id);

    SubscriberDataUtils::SubscriptionEvent event;
    bool notify_required = base_notify_required;
    std::string reasons = base_reasons;
    if (orig_s_match == orig_subscriptions.end())
    {
      TRC_DEBUG("Subscription %s in AoR %s is new",
                subscription_id.c_str(),
                aor_id.c_str());
      event = SubscriberDataUtils::SubscriptionEvent::CREATED;
      notify_required = true;
      reasons += "Subscription created - ";
    }
    else if (subscription->_refreshed)
    {
      TRC_DEBUG("Subscription %s in aor %s has been refreshed",
                subscription_id.c_str(),
                aor_id.c_str());
      event = SubscriberDataUtils::SubscriptionEvent::REFRESHED;
      notify_required = true;
      reasons += "Subscription refreshed - ";
    }
    else if (subscription->_expires < orig_s_match->second->_expires)
    {
      TRC_DEBUG("Subscription %s in AoR %s has been shortened",
                subscription_id.c_str(),
                aor_id.c_str());
      event = SubscriberDataUtils::SubscriptionEvent::SHORTENED;
      notify_required = true;
      reasons += "Subscription shortened - ";
    }
    else
    {
      TRC_DEBUG("Subscription %s in AoR %s is unchanged",
                subscription_id.c_str(),
                aor_id.c_str());
      event = SubscriberDataUtils::SubscriptionEvent::UNCHANGED;
    }

    ClassifiedSubscription* classified_subscription =
      new ClassifiedSubscription(aor_id,
                                 subscription_id,
                                 subscription,
                                 event);
    classified_subscription->_notify_required = notify_required;
    classified_subscription->_reasons = reasons;
    classified_subscriptions.push_back(classified_subscription);
  }
}

void SubscriberDataUtils::delete_bindings(ClassifiedBindings& classified_bindings)
{
  for (ClassifiedBinding* binding : classified_bindings)
  {
    delete binding;
  }

  classified_bindings.clear();
}

void SubscriberDataUtils::delete_bindings(Bindings& bindings)
{
  for (BindingPair binding : bindings)
  {
    delete binding.second;
  }
}

void SubscriberDataUtils::delete_subscriptions(ClassifiedSubscriptions& classified_subscriptions)
{
  for (ClassifiedSubscription* subscription : classified_subscriptions)
  {
    delete subscription;
  }

  classified_subscriptions.clear();
}

void SubscriberDataUtils::delete_subscriptions(Subscriptions& subscriptions)
{
  for (SubscriptionPair subscription : subscriptions)
  {
    delete subscription.second;
  }
}
