/**
 * @file notify_utils2.h
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef NOTIFY_UTILS2_H__
#define NOTIFY_UTILS2_H__

#include <string>

#include "aor.h"

namespace SubscriberDataUtils
{

enum class EventTrigger
{
  USER,
  HSS,
  ADMIN,
  TIMEOUT // EM-TODO ???
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

// Iterate over all original and current bindings in an AoR pair and
// classify them as removed ("EXPIRED"), created ("CREATED"), refreshed ("REFRESHED"),
// shortened ("SHORTENED") or unchanged ("REGISTERED").
//
// @param aor_id                The AoR ID
// @param aor_pair              The AoR pair to compare and classify bindings for
// @param classified_bindings   Output vector of classified bindings
void classify_bindings(const std::string& aor_id,
                       const EventTrigger& event_trigger,
                       const Bindings& orig_bindings,
                       const Bindings& updated_bindings,
                       std::vector<SubscriberDataUtils::ClassifiedBinding*>& classified_bindings);

void classify_subscriptions(const std::string& aor_id,
                            const EventTrigger& event_trigger,
                            const Subscriptions& orig_subscriptions,
                            const Subscriptions& updated_subscriptions,
                            const std::vector<SubscriberDataUtils::ClassifiedBinding*>& classified_bindings,
                            const bool& associated_uris_changed,
                            std::vector<SubscriberDataUtils::ClassifiedSubscription*>& classified_subscriptions);

void delete_bindings(std::vector<SubscriberDataUtils::ClassifiedBinding*>& classified_bindings);
void delete_subscriptions(std::vector<SubscriberDataUtils::ClassifiedSubscription*>& classified_subscriptions);

ContactEvent determine_contact_event(const EventTrigger& event_trigger);
};

typedef std::vector<SubscriberDataUtils::ClassifiedBinding*> ClassifiedBindings;
typedef std::vector<SubscriberDataUtils::ClassifiedSubscription*> ClassifiedSubscriptions;

#endif
