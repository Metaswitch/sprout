/**
 * @file subscriber_data_utils.h
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef SUBSCRIBER_DATA_UTILS_H__
#define SUBSCRIBER_DATA_UTILS_H__

#include <string>

#include "aor.h"

namespace SubscriberDataUtils
{

enum class EventTrigger
{
  USER,
  HSS,
  ADMIN,
  TIMEOUT
};

enum class SubscriptionEvent
{
  CREATED,
  REFRESHED,
  UNCHANGED,
  SHORTENED,
  EXPIRED,
  TERMINATED
};

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

// Wrapper for the bindings in a NOTIFY. The information needed is
// the binding itself, a unique ID for it and the contact event
struct ClassifiedBinding
{
  ClassifiedBinding(std::string id,
                    Binding* binding,
                    ContactEvent event) :
    _id(id),
    _binding(binding),
    _contact_event(event)
  {}

  std::string _id;
  Binding* _binding;
  ContactEvent _contact_event;
};

struct ClassifiedSubscription
{
  ClassifiedSubscription(std::string aor_id,
                         std::string id,
                         Subscription* subscription,
                         SubscriptionEvent event) :
    _aor_id(aor_id),
    _id(id),
    _subscription(subscription),
    _subscription_event(event),
    _notify_required(false),
    _reasons()
  {}

  std::string _aor_id;
  std::string _id;
  Subscription* _subscription;
  SubscriptionEvent _subscription_event;
  bool _notify_required;
  std::string _reasons; // Stores reasons for requiring a notify (for logging)
};

/// Iterate over all original and current bindings and classify them as removed
/// ("EXPIRED"), created ("CREATED"), refreshed ("REFRESHED"), shortened
/// ("SHORTENED") or unchanged ("REGISTERED").
///
/// @param aor_id[in]               - The AoR ID.
/// @param event_trigger[in]        - What triggered the change.
/// @param orig_bindings[in]        - The original bindings.
/// @param updated_bindings[in]     - The changed bindings.
/// @param classified_bindings[out] - Output vector of classified bindings.
void classify_bindings(
     const std::string& aor_id,
     const EventTrigger& event_trigger,
     const Bindings& orig_bindings,
     const Bindings& updated_bindings,
     std::vector<SubscriberDataUtils::ClassifiedBinding*>& classified_bindings);

/// Iterate over all original and current subscriptions and classifies each
/// subscription as one of SubscriptionEvent type, whether the subscription
/// needs a NOTIFY, and if so why it needs a NOTIFY.
///
/// @param aor_id[in]                  - The AoR ID.
/// @param event_trigger[in]           - What triggered the change.
/// @param orig_subscriptions[in]      - The original subscriptions.
/// @param updated_subscriptions[in]   - The changed subscriptions.
/// @param classified_bindings[in]     - The classified bindings for the same
///                                      subscriber data change.
/// @param associated_uris_changed[in] - Whether the associated URIs changed in
///                                      the subscriber data change.
/// @param classified_bindings[out]    - Output vector of classified
///                                      subscriptions.
void classify_subscriptions(
                     const std::string& aor_id,
                     const EventTrigger& event_trigger,
                     const Subscriptions& orig_subscriptions,
                     const Subscriptions& updated_subscriptions,
                     const std::vector<SubscriberDataUtils::ClassifiedBinding*>&
                       classified_bindings,
                     const bool& associated_uris_changed,
                     std::vector<SubscriberDataUtils::ClassifiedSubscription*>&
                       classified_subscriptions);

/// Helper functions to delete bindings.
void delete_bindings(std::vector<SubscriberDataUtils::ClassifiedBinding*>&
                                                           classified_bindings);
void delete_bindings(Bindings& bindings);

/// Helper functions to delete subscriptions.
void delete_subscriptions(std::vector<SubscriberDataUtils::ClassifiedSubscription*>&
                                                      classified_subscriptions);
void delete_subscriptions(Subscriptions& subscriptions);

ContactEvent determine_contact_event(const EventTrigger& event_trigger);
};

typedef std::vector<SubscriberDataUtils::ClassifiedBinding*> ClassifiedBindings;
typedef std::vector<SubscriberDataUtils::ClassifiedSubscription*> ClassifiedSubscriptions;

#endif
