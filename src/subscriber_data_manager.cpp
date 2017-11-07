/**
 * @file subscriber_data_manager.cpp
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


// Common STL includes.
#include <cassert>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <queue>
#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <time.h>

#include "log.h"
#include "utils.h"
#include "subscriber_data_manager.h"
#include "astaire_aor_store.h"
#include "notify_utils.h"
#include "stack.h"
#include "chronosconnection.h"
#include "sproutsasevent.h"
#include "constants.h"


/// Helper to delete vectors of bindings safely
void delete_bindings(ClassifiedBindings& cbs)
{
  for (ClassifiedBinding* cb : cbs)
  {
    delete cb;
  }

  cbs.clear();
}

/// Helper to delete vectors of ClassifiedSubscriptions safely
void SubscriberDataManager::delete_subscriptions(ClassifiedSubscriptions& css)
{
  for (ClassifiedSubscription* cs: css)
  {
    delete cs;
  }

  css.clear();
}

/// Helper to map SDM EventTrigger to ContactEvent for Notify
NotifyUtils::ContactEvent determine_contact_event(
                       const SubscriberDataManager::EventTrigger& event_trigger)
{
  NotifyUtils::ContactEvent contact_event;
  switch(event_trigger){
    case SubscriberDataManager::EventTrigger::TIMEOUT:
      contact_event = NotifyUtils::ContactEvent::EXPIRED;
      break;
    case SubscriberDataManager::EventTrigger::USER:
      contact_event = NotifyUtils::ContactEvent::UNREGISTERED;
      break;
    case SubscriberDataManager::EventTrigger::ADMIN:
      contact_event = NotifyUtils::ContactEvent::DEACTIVATED;
      break;
    // LCOV_EXCL_START - not hittable as all cases of event_trigger are covered
    default:
      contact_event = NotifyUtils::ContactEvent::EXPIRED;
      break;
    // LCOV_EXCL_STOP
  }
  return contact_event;
}

/// SubscriberDataManager Methods
SubscriberDataManager::SubscriberDataManager(AoRStore* aor_store,
                                             ChronosConnection* chronos_connection,
                                             AnalyticsLogger* analytics_logger,
                                             bool is_primary) :
  _primary_sdm(is_primary)
{
  _aor_store = aor_store;
  _chronos_timer_request_sender = new ChronosTimerRequestSender(chronos_connection);
  _notify_sender = new NotifySender();
  _analytics = analytics_logger;
}


SubscriberDataManager::~SubscriberDataManager()
{
  delete _notify_sender;
  delete _chronos_timer_request_sender;
}

/// Retrieve the registration data for a given SIP Address of Record.
///
/// @param aor_id       The SIP Address of Record for the registration
AoRPair* SubscriberDataManager::get_aor_data(const std::string& aor_id,
                                             SAS::TrailId trail)
{
  AoR* aor_data = _aor_store->get_aor_data(aor_id, trail);

  if (aor_data != NULL)
  {
    // We got some data from the store. Copy the AoR, expire the copy,
    // and return both AoRs as an AoR pair.
    AoR* aor_copy = new AoR(*aor_data);
    int now = time(NULL);
    AoRPair* aor_pair = new AoRPair(aor_data, aor_copy);
    expire_aor_members(aor_pair, now, trail);
    return aor_pair;
  }
  else
  {
    // We hit some kind of error in the store.
    return NULL;
  }
}

/// Update the data for a particular address of record.  Writes the data
/// atomically.  Returns the code returned by the underlying store, one of:
/// -  OK:              the AoR was writen successfully.
/// -  DATA_CONTENTION: the AoR was not written to the store because the CAS is
///                     out of date. The caller can refetch the AoR and try again.
/// -  ERROR:           the AoR was not written successfully and the caller
///                     should not retry.
///
/// @param aor_id     The SIP Address of Record for the registration
/// @param aor_pair   The registration data record.
/// @param trail      The SAS trail
bool SubscriberDataManager::unused_bool = false;

Store::Status SubscriberDataManager::set_aor_data(
                                     const std::string& aor_id,
                                     const SubscriberDataManager::EventTrigger& event_trigger,
                                     AoRPair* aor_pair,
                                     SAS::TrailId trail,
                                     bool& all_bindings_expired)
  {
  // The ordering of this function is quite important.
  //
  // 1. Expire any old bindings/subscriptions.
  // 2. Log removed or shortened bindings
  // 3. Send any Chronos timer requests
  // 4. Prepare to send NOTIFYs; increment CSeq values
  // 4. Write the data to memcached. If this fails, bail out here
  // 5. Log new or extended bindings
  // 6. Send any messages we were asked to by the caller
  // 7. Send any NOTIFYs
  //
  // This ordering is important to ensure that we don't send
  // duplicate NOTIFYs (so we send these after writing to memcached) and
  // so that only one piece of code has responsibility for this. Furthermore,
  // we want registration logs used for licensing counts to undercount in edge
  // cases where a Chronos or memcached call fails and we're in an uncertain
  // state. Therefore, we log removed or shortened bindings before any such calls,
  // and we log new or extended bindings afterwards.

  // 1. Expire any old bindings/subscriptions.
  all_bindings_expired = false;

  // Expire old subscriptions and bindings before writing to the server. If
  // there were no bindings left we could delete the entry, but this may
  // cause concurrency problems because memcached does not support
  // cas on delete operations.  In this case we do a memcached_cas with
  // an effectively immediate expiry time.
  int now = time(NULL);

  // Set the max expires to be greater than the longest binding expiry time.
  // This prevents a window condition where Chronos can return a binding to
  // expire, but memcached has already deleted the aor data (meaning that
  // no NOTIFYs could be sent)
  int orig_max_expires = expire_aor_members(aor_pair, now, trail);
  int max_expires = orig_max_expires + 10;

  // expire_aor_members returns "now" if there are no remaining bindings,
  // so test for that.
  if (orig_max_expires == now)
  {
    TRC_DEBUG("All bindings have expired, so this is a deregistration for AOR %s",
              aor_id.c_str());
    all_bindings_expired = true;
  }

  TRC_DEBUG("Set AoR data for %s, CAS=%ld, expiry = %d",
            aor_id.c_str(), aor_pair->get_current()->_cas, max_expires);

  ClassifiedBindings classified_bindings;

  if (_primary_sdm)
  {
    // 2. Log removed or shortened bindings
    classify_bindings(aor_id, event_trigger, aor_pair, classified_bindings);

    if (_analytics != NULL)
    {
      log_removed_or_shortened_bindings(classified_bindings, now);
    }

    // 3. Send any Chronos timer requests
    if (_chronos_timer_request_sender->_chronos_conn)
    {
      _chronos_timer_request_sender->send_timers(aor_id, aor_pair, now, trail);
    }
  }


  // 4. Prepare to send NOTIFYs. Determine which subscriptions require
  // notification, update subscription CSeqs, and log. We need to update the
  // CSeqs before writing to the store.
  ClassifiedSubscriptions classified_subscriptions;

  if (_primary_sdm)
  {
    classify_subscriptions(event_trigger,
                           aor_pair,
                           classified_bindings,
                           classified_subscriptions);

    prepare_subscriptions(aor_pair,
                          classified_bindings,
                          classified_subscriptions,
                          trail);
  }

  // 5. Write the data to memcached. If this fails, bail out here
  Store::Status rc = _aor_store->set_aor_data(aor_id,
                                              aor_pair,
                                              max_expires - now,
                                              trail);

  if (rc != Store::Status::OK)
  {
    // We were unable to write to the store - return to the caller and
    // send no further messages
    delete_bindings(classified_bindings);
    delete_subscriptions(classified_subscriptions);
    return rc;
  }

  if (_primary_sdm)
  {
    // 6. Log new / extended bindings
    if (_analytics != NULL)
    {
      log_new_or_extended_bindings(classified_bindings, now);
    }

    // 7. Send any NOTIFYs
    _notify_sender->send_notifys(aor_id,
                                 aor_pair,
                                 classified_bindings,
                                 classified_subscriptions,
                                 now,
                                 trail);
  }

  delete_bindings(classified_bindings);
  delete_subscriptions(classified_subscriptions);

  return Store::Status::OK;
}

void SubscriberDataManager::classify_bindings(const std::string& aor_id,
                                              const SubscriberDataManager::EventTrigger& event_trigger,
                                              AoRPair* aor_pair,
                                              ClassifiedBindings& classified_bindings)
{
  // We should have been given an empty classified_bindings vector, but clear
  // it just in case
  delete_bindings(classified_bindings);

  // 1/2: Iterate over original bindings and record those not in current AoR.
  // The reason they are missing is determined from EventTrigger.
  for (std::pair<std::string, AoR::Binding*> aor_orig_b :
         aor_pair->get_orig()->bindings())
  {
    // Emergency bindings are excluded from notifications.
    if (aor_orig_b.second->_emergency_registration)
    {
      continue;
    }

    // Determine if this binding is not in the current AoR.
    if (aor_pair->get_current()->bindings().find(aor_orig_b.first) ==
        aor_pair->get_current()->bindings().end())
    {
      TRC_DEBUG("Binding %s is missing from current AoR", aor_orig_b.first.c_str());
      ClassifiedBinding* binding_record =
        new ClassifiedBinding(aor_orig_b.first,
                              aor_orig_b.second,
                              determine_contact_event(event_trigger));
      classified_bindings.push_back(binding_record);
    }
  }

  // 2/2: Iterate over the bindings in the current AoR. Determine if the
  // bindings have been CREATED, REFRESHED, REGISTERED or SHORTENED.
  for (std::pair<std::string, AoR::Binding*> aor_current_b :
         aor_pair->get_current()->bindings())
  {
    // Emergency bindings are excluded from notifications.
    if (aor_current_b.second->_emergency_registration)
    {
      continue;
    }

    AoR::Bindings::const_iterator aor_orig_b_match =
      aor_pair->get_orig()->bindings().find(aor_current_b.first);

    NotifyUtils::ContactEvent event;

    if (aor_orig_b_match == aor_pair->get_orig()->bindings().end())
    {
      // The binding is only in the current AoR, so has been CREATED
      TRC_DEBUG("Binding %s has been CREATED", aor_current_b.first.c_str());
      event = NotifyUtils::ContactEvent::CREATED;
    }
    else
    {
      // The binding is in both AoRs. Check if the expiry time has changed at all
      if (aor_orig_b_match->second->_expires < aor_current_b.second->_expires)
      {
        // The expires value has increased, so the binding has been REFRESHED
        TRC_DEBUG("Binding %s has been REFRESHED", aor_current_b.first.c_str());
        event = NotifyUtils::ContactEvent::REFRESHED;
      }
      else if (aor_orig_b_match->second->_expires > aor_current_b.second->_expires)
      {
        // The expires value has decreased, so the binding has been SHORTENED
        TRC_DEBUG("Binding %s has been SHORTENED", aor_current_b.first.c_str());
        event = NotifyUtils::ContactEvent::SHORTENED;
      }
      else
      {
        // The expires value has not changed, so the binding has been
        // (re)REGISTERED
        TRC_DEBUG("Binding %s has been REGISTERED", aor_current_b.first.c_str());
        event = NotifyUtils::ContactEvent::REGISTERED;
      }
    }

    ClassifiedBinding* binding_record =
      new ClassifiedBinding(aor_current_b.first,
                            aor_current_b.second,
                            event);
    classified_bindings.push_back(binding_record);
  }
}

void SubscriberDataManager::classify_subscriptions(const SubscriberDataManager::EventTrigger& event_trigger,
                                                   AoRPair* aor_pair,
                                                   ClassifiedBindings& classified_bindings,
                                                   ClassifiedSubscriptions& classified_subscriptions)
{
  // We should have been given an empty classified_subscriptions vector, but
  // clear it just in case
  delete_subscriptions(classified_subscriptions);

  // 1/2: Iterate over the subscriptions in the original AoR and classify those that
  // aren't in the current AoR.

  std::vector<std::string> missing_binding_uris;
  for (ClassifiedBinding* cb : classified_bindings)
  {
    if (cb->_contact_event == NotifyUtils::ContactEvent::EXPIRED ||
        cb->_contact_event == NotifyUtils::ContactEvent::DEACTIVATED ||
        cb->_contact_event == NotifyUtils::ContactEvent::UNREGISTERED)
    {
      missing_binding_uris.push_back(cb->_b->_uri);
    }
  }

  for (AoR::Subscriptions::const_iterator aor_orig_s =
         aor_pair->get_orig()->subscriptions().begin();
       aor_orig_s != aor_pair->get_orig()->subscriptions().end();
       ++aor_orig_s)
  {
    AoR::Subscription* s = aor_orig_s->second;
    std::string s_id = aor_orig_s->first;


    if ((std::find(missing_binding_uris.begin(),
                    missing_binding_uris.end(),
                    s->_req_uri)
         != missing_binding_uris.end())
        && (event_trigger != SubscriberDataManager::EventTrigger::ADMIN))
    {
      // Binding is missing, and this event is not triggered by admin. The
      // binding no longer exists due to user deregestration or timeout, so
      // classify the subscription as EXPIRED.
      TRC_DEBUG("Subscription %s classified as EXPIRED as binding %s has expired",
                s_id.c_str(), (s->_req_uri).c_str());

      ClassifiedSubscription* classified_subscription =
        new ClassifiedSubscription(s_id, s, SubscriptionEvent::EXPIRED);

      classified_subscriptions.push_back(classified_subscription);
      continue;
    }

    // Is this subscription present in the new AoR?
    AoR::Subscriptions::const_iterator aor_current =
      aor_pair->get_current()->subscriptions().find(s_id);

    // The subscription has been deleted, so classify it as TERMINATED.
    if (aor_current == aor_pair->get_current()->subscriptions().end())
    {
      TRC_DEBUG("Subscription %s classified as TERMINATED", s_id.c_str());

      ClassifiedSubscription* classified_subscription =
        new ClassifiedSubscription(s_id, s, SubscriptionEvent::TERMINATED);

      classified_subscriptions.push_back(classified_subscription);
    }
  }

  // 2/2: Iterate over subscriptions in the current AoR and classify them.
  for (AoR::Subscriptions::const_iterator current_sub =
        aor_pair->get_current()->subscriptions().begin();
      current_sub != aor_pair->get_current()->subscriptions().end();
      ++current_sub)
  {
    AoR::Subscription* s = current_sub->second;
    std::string s_id = current_sub->first;

    // Find the subscription in the original AoR to determine if the current
    // subscription has been created.
    AoR::Subscriptions::const_iterator orig_sub =
      aor_pair->get_orig()->subscriptions().find(s_id);

    if (orig_sub == aor_pair->get_orig()->subscriptions().end())
    {
      // The subscription is not in the original AoR, so classify it as CREATED.
      TRC_DEBUG("Subscription %s classified as CREATED", s_id.c_str());

      ClassifiedSubscription* classified_subscription =
        new ClassifiedSubscription(s_id, s, SubscriptionEvent::CREATED);

      classified_subscriptions.push_back(classified_subscription);
    }
    else if (s->_refreshed)
    {
      TRC_DEBUG("Subscription %s classified as REFRESHED", s_id.c_str());

      ClassifiedSubscription* classified_subscription =
        new ClassifiedSubscription(s_id, s, SubscriptionEvent::REFRESHED);

      classified_subscriptions.push_back(classified_subscription);
    }
    else
    {
      TRC_DEBUG("Subscription %s classified as UNCHANGED", s_id.c_str());

      ClassifiedSubscription* classified_subscription =
        new ClassifiedSubscription(s_id, s, SubscriptionEvent::UNCHANGED);

      classified_subscriptions.push_back(classified_subscription);
    }
  }
}

void SubscriberDataManager::prepare_subscriptions(AoRPair* aor_pair,
                                                  ClassifiedBindings& classified_bindings,
                                                  ClassifiedSubscriptions& classified_subscriptions,
                                                  SAS::TrailId trail)
{
  bool bindings_changed = false;
  bool associated_uris_changed = false;

  // Determine if any bindings have changed
  for (ClassifiedBinding* cb : classified_bindings)
  {
    if (cb->_contact_event != NotifyUtils::ContactEvent::REGISTERED)
    {
      bindings_changed = true;
    }
  }

  // Determine if the associated URIs have changed.
  associated_uris_changed = (aor_pair->get_current()->_associated_uris !=
                             aor_pair->get_orig()->_associated_uris);

  // Determine which subscribers to notify, and increment the corresponding
  // CSeq values.
  for (ClassifiedSubscriptions::const_iterator csp = classified_subscriptions.begin();
       csp != classified_subscriptions.end();
       ++csp)
  {
    ClassifiedSubscription* cs = *csp;
    cs->_reasons = "Reason(s): - ";

    // If the bindings on this AoR have changed, notify all subscribers.
    if (bindings_changed)
    {
      cs->_notify_required = true;
      cs->_reasons += "Bindings changed - ";
    }

    // If the URIs associated with this AoR have changed, notify all
    // subscribers.
    if (associated_uris_changed)
    {
      cs->_notify_required = true;
      cs->_reasons += "Associated URIs changed - ";
    }

    switch(cs->_subscription_event)
    {
    case SubscriptionEvent::CREATED:
      cs->_notify_required = true;
      cs->_reasons += "Subscription created - ";
      break;
    case SubscriptionEvent::REFRESHED:
      cs->_notify_required = true;
      cs->_reasons += "Subscription refreshed - ";
      break;
    case SubscriptionEvent::TERMINATED:
      cs->_notify_required = true;
      cs->_reasons += "Subscription terminated - ";
      break;
    case SubscriptionEvent::UNCHANGED:
      break;
    case SubscriptionEvent::EXPIRED:
      // NOTIFYs should not be sent over an unregistered binding.
      cs->_notify_required = false;
      TRC_DEBUG("Subscription %s skipped as binding has expired", cs->_id.c_str());

      SAS::Event event(trail, SASEvent::NO_NOTIFY_REMOVED_BINDING, 0);
      event.add_var_param(cs->_s->_req_uri);
      break;
    }

    // If a NOTIFY is required on this subscription, increment the CSeq.
    if (cs->_notify_required)
    {
      cs->_s->_notify_cseq += 1;
    }
  }
}

void SubscriberDataManager::log_removed_or_shortened_bindings(ClassifiedBindings& classified_bindings,
                                                              int now)
{
  for (ClassifiedBinding* classified_binding : classified_bindings)
  {
    if ((classified_binding->_contact_event == NotifyUtils::ContactEvent::EXPIRED)     ||
        (classified_binding->_contact_event == NotifyUtils::ContactEvent::DEACTIVATED) ||
        (classified_binding->_contact_event == NotifyUtils::ContactEvent::UNREGISTERED))
    {
      _analytics->registration(classified_binding->_b->_address_of_record,
                               classified_binding->_id,
                               classified_binding->_b->_uri,
                               0);
    }
    else if (classified_binding->_contact_event == NotifyUtils::ContactEvent::SHORTENED)
    {
      _analytics->registration(classified_binding->_b->_address_of_record,
                               classified_binding->_id,
                               classified_binding->_b->_uri,
                               classified_binding->_b->_expires - now);
    }
  }
}

void SubscriberDataManager::log_new_or_extended_bindings(ClassifiedBindings& classified_bindings,
                                                         int now)
{
  for (ClassifiedBinding* classified_binding : classified_bindings)
  {
    if (classified_binding->_contact_event == NotifyUtils::ContactEvent::CREATED ||
        classified_binding->_contact_event == NotifyUtils::ContactEvent::REFRESHED)
    {
      _analytics->registration(classified_binding->_b->_address_of_record,
                               classified_binding->_id,
                               classified_binding->_b->_uri,
                               classified_binding->_b->_expires - now);
    }
  }
}

int SubscriberDataManager::expire_aor_members(AoRPair* aor_pair,
                                              int now,
                                              SAS::TrailId trail)
{
  int max_expires = expire_bindings(aor_pair->get_current(), now, trail);

  // N.B. Subscriptions are not factored into the returned expiry time on the
  // store record because, according to 5.4.2.1.2/TS 24.229, all subscriptions
  // automatically expire when the last binding expires.
  expire_subscriptions(aor_pair, now, (max_expires == now), trail);

  return max_expires;
}

/// Expire any old subscriptions. Expire all subscriptions if requested
/// (e.g. when all the bindings have expired)
///
/// @param aor_data      The registration data record.
/// @param now           The current time in seconds since the epoch.
/// @param force_expire  Whether we should always remove the subscriptions
void SubscriberDataManager::expire_subscriptions(AoRPair* aor_pair,
                                                 int now,
                                                 bool force_expire,
                                                 SAS::TrailId trail)
{
  for (AoR::Subscriptions::iterator i =
         aor_pair->get_current()->_subscriptions.begin();
       i != aor_pair->get_current()->_subscriptions.end();
      )
  {
    AoR::Subscription* s = i->second;

    if ((force_expire) || (s->_expires <= now))
    {
      if (trail != 0)
      {
        SAS::Event event(trail, SASEvent::REGSTORE_SUBSCRIPTION_EXPIRED, 0);
        event.add_var_param(s->_from_uri);
        event.add_static_param(force_expire);
        event.add_static_param(s->_expires);
        event.add_static_param(now);
        SAS::report_event(event);
      }

      // The subscription has expired, so remove it. This could be
      // a single one shot subscription though - if so pretend it was
      // part of the original AoR
      AoR::Subscriptions::const_iterator aor_orig_s =
        aor_pair->get_orig()->subscriptions().find(i->first);

      if (aor_orig_s == aor_pair->get_orig()->subscriptions().end())
      {
        AoR::Subscription* s_copy = aor_pair->get_orig()->get_subscription(i->first);
        *s_copy = *i->second;
      }

      delete i->second;
      aor_pair->get_current()->_subscriptions.erase(i++);
    }
    else
    {
      ++i;
    }
  }
}

/// Expire any old bindings, and calculates the latest outstanding expiry time,
/// or now if none.
///
/// @returns             The latest expiry time from all unexpired bindings.
/// @param aor_data      The registration data record.
/// @param now           The current time in seconds since the epoch.
/// @param trail         SAS trail
int SubscriberDataManager::expire_bindings(AoR* aor_data,
                                           int now,
                                           SAS::TrailId trail)
{
  int max_expires = now;
  for (AoR::Bindings::iterator i = aor_data->_bindings.begin();
       i != aor_data->_bindings.end();
      )
  {
    AoR::Binding* b = i->second;
    std::string b_id = i->first;

    if (b->_expires <= now)
    {
      if (trail != 0)
      {
        SAS::Event event(trail, SASEvent::REGSTORE_BINDING_EXPIRED, 0);
        event.add_var_param(b->_address_of_record);
        event.add_var_param(b->_uri);
        event.add_var_param(b->_cid);
        event.add_static_param(b->_expires);
        event.add_static_param(now);
        SAS::report_event(event);
      }

      delete i->second;
      aor_data->_bindings.erase(i++);
    }
    else
    {
      if (b->_expires > max_expires)
      {
        max_expires = b->_expires;
      }

      ++i;
    }
  }

  return max_expires;
}


/// ChronosTimerRequestSender Methods

SubscriberDataManager::ChronosTimerRequestSender::
     ChronosTimerRequestSender(ChronosConnection* chronos_conn) :
  _chronos_conn(chronos_conn)
{
}

SubscriberDataManager::ChronosTimerRequestSender::~ChronosTimerRequestSender()
{
}

void SubscriberDataManager::ChronosTimerRequestSender::build_tag_info (
                                                AoR* aor,
                                                std::map<std::string, uint32_t>& tag_map)
{
  // Each timer is built to represent a single registration i.e. an AoR.
  tag_map["REG"] = 1;
  tag_map["BIND"] = aor->get_bindings_count();
  tag_map["SUB"] = aor->get_subscriptions_count();
}


void SubscriberDataManager::ChronosTimerRequestSender::send_timers(
                             const std::string& aor_id,
                             AoRPair* aor_pair,
                             int now,
                             SAS::TrailId trail)
{
  std::map<std::string, uint32_t> old_tags;
  std::map<std::string, uint32_t> new_tags;
  AoR* orig_aor = aor_pair->get_orig();
  AoR* current_aor = aor_pair->get_current();
  std::string& timer_id = current_aor->_timer_id;

  // An AoR with no bindings is invalid, and the timer should be deleted.
  // We do this before getting next_expires to save on processing.
  if (current_aor->get_bindings_count() == 0)
  {
    if (timer_id != "")
    {
      _chronos_conn->send_delete(timer_id, trail);
    }
  return;
  }

  build_tag_info(orig_aor, old_tags);
  build_tag_info(current_aor, new_tags);
  int old_next_expires = orig_aor->get_next_expires();
  int new_next_expires = current_aor->get_next_expires();

  if ((old_next_expires == 0) || (new_next_expires == 0))
  {
    // This should never happen, as an empty AoR should never reach get_next_expires
    TRC_DEBUG("get_next_expires returned 0. The expiry of AoR members is corrupt, or an empty (invalid) AoR was passed in.");
  }

  if ((new_tags != old_tags)                 ||
      (new_next_expires != old_next_expires) ||
      (timer_id == ""))
  {
    // Set the expiry time to be relative to now.
    int expiry = (new_next_expires > now) ? (new_next_expires - now) : (now);

    set_timer(aor_id,
              timer_id,
              expiry,
              new_tags,
              trail);
  }
}

void SubscriberDataManager::ChronosTimerRequestSender::set_timer(
                                    const std::string& aor_id,
                                    std::string& timer_id,
                                    int expiry,
                                    std::map<std::string, uint32_t> tags,
                                    SAS::TrailId trail)
{
  std::string temp_timer_id = "";
  HTTPCode status;
  std::string opaque = "{\"aor_id\": \"" + aor_id + "\"}";
  std::string callback_uri = "/timers";

  // If a timer has been previously set for this binding, send a PUT.
  // Otherwise sent a POST.
  if (timer_id == "")
  {
    status = _chronos_conn->send_post(temp_timer_id,
                                      expiry,
                                      callback_uri,
                                      opaque,
                                      trail,
                                      tags);
  }
  else
  {
    temp_timer_id = timer_id;
    status = _chronos_conn->send_put(temp_timer_id,
                                     expiry,
                                     callback_uri,
                                     opaque,
                                     trail,
                                     tags);
  }

  // Update the timer id. If the update to Chronos failed, that's OK,
  // don't reject the request or update the stored timer id.
  if (status == HTTP_OK)
  {
    timer_id = temp_timer_id;
  }
}

/// NotifySender Methods

SubscriberDataManager::NotifySender::NotifySender()
{
}

SubscriberDataManager::NotifySender::~NotifySender()
{
}

void SubscriberDataManager::NotifySender::send_notifys(
                               const std::string& aor_id,
                               AoRPair* aor_pair,
                               ClassifiedBindings classified_bindings,
                               ClassifiedSubscriptions classified_subscriptions,
                               int now,
                               SAS::TrailId trail)
{
  // The registration state to send is ACTIVE if we have at least one active binding,
  // otherwise TERMINATED.
  NotifyUtils::RegistrationState reg_state = (!aor_pair->get_current()->bindings().empty()) ?
    NotifyUtils::RegistrationState::ACTIVE :
    NotifyUtils::RegistrationState::TERMINATED;

  // Iterate over the subscriptions in the current AoR and send NOTIFYs.
  // If the bindings have changed, or the Associated URIs has changed,
  // then send NOTIFYs to all subscribers; otherwise, only send them
  // when the subscription has been created or updated.
  for (ClassifiedSubscriptions::const_iterator csp = classified_subscriptions.begin();
      csp != classified_subscriptions.end();
      ++csp)
  {
    ClassifiedSubscription* cs = *csp;

    if (cs->_notify_required)
    {
      TRC_DEBUG("Sending NOTIFY for subscription %s: %s",
                cs->_id.c_str(),
                cs->_reasons.c_str());
      if (cs->_subscription_event == SubscriptionEvent::TERMINATED)
      {
        // This is a terminated subscription - set the expiry time to now
        cs->_s->_expires = now;
      }

      pjsip_tx_data* tdata_notify = NULL;
      pj_status_t status = NotifyUtils::create_subscription_notify(
                                            &tdata_notify,
                                            cs->_s,
                                            aor_id,
                                            &aor_pair->get_current()->_associated_uris,
                                            aor_pair->get_orig(),
                                            classified_bindings,
                                            reg_state,
                                            now,
                                            trail);

      if (status == PJ_SUCCESS)
      {
        set_trail(tdata_notify, trail);

        uint32_t sas_event;
        if (cs->_subscription_event == SubscriptionEvent::TERMINATED)
        {
          sas_event = SASEvent::SENDING_FINAL_NOTIFY;
        }
        else
        {
          sas_event = SASEvent::SENDING_NOTIFICATION;
        }

        SAS::Event event(trail, sas_event, 0);
        event.add_var_param(cs->_s->_req_uri);
        event.add_var_param(cs->_reasons);
        SAS::report_event(event);

        status = PJUtils::send_request(tdata_notify, 0, NULL, NULL, true);

        if (status == PJ_SUCCESS)
        {
          cs->_s->_refreshed = false;
        }
        else
        {
          // LCOV_EXCL_START
          SAS::Event event(trail, SASEvent::NOTIFICATION_FAILED, 0);
          std::string error_msg = "Failed to send NOTIFY - error: " +
                                        PJUtils::pj_status_to_string(status);
          event.add_var_param(error_msg);
          SAS::report_event(event);
          // LCOV_EXCL_STOP
        }
      }
    }
  }
}
