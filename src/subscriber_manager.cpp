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

#include "subscriber_manager.h"
#include "aor_utils.h"
#include "pjutils.h"

SubscriberManager::SubscriberManager(S4* s4,
                                     HSSConnection* hss_connection,
                                     AnalyticsLogger* analytics_logger) :
  _s4(s4),
  _hss_connection(hss_connection),
  _analytics(analytics_logger),
  _notify_sender(new NotifySender())
{
}

SubscriberManager::~SubscriberManager()
{
  delete _notify_sender; _notify_sender = NULL;
}

HTTPCode SubscriberManager::update_bindings(const HSSConnection::irs_query& irs_query,
                                            const Bindings& updated_bindings,
                                            const std::vector<std::string>& binding_ids_to_remove,
                                            Bindings& all_bindings,
                                            HSSConnection::irs_info& irs_info,
                                            SAS::TrailId trail)
{
  bool success;

  // Get subscriber information from the HSS.
  HTTPCode rc = get_subscriber_state(irs_query,
                                     irs_info,
                                     trail);
  if (rc != HTTP_OK)
  {
    return rc;
  }

  // Get the aor_id from the associated URIs.
  std::string aor_id;
  bool emergency;
  // Can any of the deleted bindings be for emergencies - yes so need to pass
  // that information along with the binding IDs to delete. TODO
  for (BindingPair b : updated_bindings)
  {
    if (b.second->_emergency_registration)
    {
      emergency = true;
      break;
    }
  }

  success = irs_info._associated_uris.get_default_impu(aor_id,
                                                       emergency);
  if (!success)
  {
    // No default IMPU so send an error response.
    return HTTP_BAD_REQUEST; // TODO Figure out the return code here..
  }

  // Get the current AoR from S4, if one exists.
  AoR* orig_aor = NULL;
  uint64_t unused_version;
  rc = _s4->handle_get(aor_id,
                       &orig_aor,
                       unused_version,
                       trail);

  // It is valid to return HTTP_NOT_FOUND since there will not be a stored AoR
  // when an IRS is first registered.
  AoR* updated_aor = NULL;
  if ((rc != HTTP_OK) && (rc != HTTP_NOT_FOUND))
  {
    delete orig_aor; orig_aor = NULL;
    return rc;
  }
  else if (rc == HTTP_NOT_FOUND)
  {
    // If the GET returned NOT_FOUND, there is no AoR for this IRS so we
    // should PUT one. The S-CSCF URI is also set the first time the IRS is
    // registered.
    rc = put_bindings(aor_id,
                      updated_bindings,
                      binding_ids_to_remove,
                      irs_info._associated_uris,
                      irs_query._server_name,
                      updated_aor,
                      trail);
  }
  else
  {
    // There is an existing AoR in the store, so patch it. The S-CSCF URI should
    // only be set when the AoR is first created, so do not try to update it.
    // Check if there are any subscriptions that share the same contact as
    // the removed bindings, and delete them too.
    std::vector<std::string> subscription_ids_to_remove =
                               subscriptions_to_remove(orig_aor->bindings(),
                                                       orig_aor->subscriptions(),
                                                       updated_bindings,
                                                       binding_ids_to_remove);
    rc = patch_bindings(aor_id,
                        updated_bindings,
                        binding_ids_to_remove,
                        subscription_ids_to_remove,
                        irs_info._associated_uris,
                        updated_aor,
                        trail);
  }

  // The PUT or PATCH failed, so return.
  if (rc != HTTP_OK)
  {
    delete orig_aor; orig_aor = NULL;
    delete updated_aor; updated_aor = NULL;
    return rc;
  }

  // Get all bindings to return to the caller
  all_bindings = AoRUtils::copy_bindings(updated_aor->bindings());

  // Send NOTIFYs and write audit logs.
  send_notifys_and_write_audit_logs(aor_id,
                                    EventTrigger::USER,
                                    orig_aor,
                                    updated_aor,
                                    trail);

  // Update HSS if all bindings expired.
  if (all_bindings.empty())
  {
    rc = deregister_with_hss(aor_id,
                             HSSConnection::DEREG_USER,
                             irs_query._server_name,
                             irs_info,
                             trail);
  }

  // Send 3rd party REGISTERs.


  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;

  return HTTP_OK;
}

HTTPCode SubscriberManager::remove_bindings(const std::string& public_id,
                                            const std::vector<std::string>& binding_ids,
                                            const EventTrigger& event_trigger,
                                            Bindings& bindings,
                                            SAS::TrailId trail)
{
  // Get cached subscriber information from the HSS.
  std::string aor_id;
  HSSConnection::irs_info irs_info;
  HTTPCode rc = get_cached_default_id(public_id,
                                      aor_id,
                                      irs_info,
                                      trail);
  if (rc != HTTP_OK)
  {
    return rc;
  }

  // Get the original AoR from S4.
  AoR* orig_aor = NULL;
  uint64_t unused_version;
  rc = _s4->handle_get(aor_id,
                       &orig_aor,
                       unused_version,
                       trail);

  // If there is no AoR, we still count that as a success.
  if (rc != HTTP_OK)
  {
    delete orig_aor; orig_aor = NULL;
    if (rc == HTTP_NOT_FOUND)
    {
      return HTTP_OK;
    }

    return rc;
  }

  // Check if there are any subscriptions that share the same contact as
  // the removed bindings, and delete them too.
  std::vector<std::string> subscription_ids_to_remove =
                             subscriptions_to_remove(orig_aor->bindings(),
                                                     orig_aor->subscriptions(),
                                                     Bindings(),
                                                     binding_ids);

  AoR* updated_aor = NULL;
  rc = patch_bindings(aor_id,
                      Bindings(),
                      binding_ids,
                      subscription_ids_to_remove,
                      irs_info._associated_uris,
                      updated_aor,
                      trail);
  if (rc != HTTP_OK)
  {
    delete orig_aor; orig_aor = NULL;
    delete updated_aor; updated_aor = NULL;
    return rc;
  }

  // Get all bindings to return to the caller
  bindings = AoRUtils::copy_bindings(updated_aor->bindings());

  // Send NOTIFYs for removed bindings.
  send_notifys_and_write_audit_logs(aor_id,
                                    event_trigger,
                                    orig_aor,
                                    updated_aor,
                                    trail);

  // Update HSS if all bindings expired.
  if (bindings.empty())
  {
    std::string dereg_reason = (event_trigger == EventTrigger::USER) ?
                                 HSSConnection::DEREG_USER : HSSConnection::DEREG_ADMIN;
    rc = deregister_with_hss(aor_id,
                             dereg_reason,
                             updated_aor->_scscf_uri,
                             irs_info,
                             trail);

    // Send 3rd party deREGISTERs.
  }
  else
  {
    // Send 3rd party REGISTERs
  }

  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;

  return HTTP_OK;
}

HTTPCode SubscriberManager::update_subscription(const std::string& public_id,
                                                const SubscriptionPair& subscription,
                                                HSSConnection::irs_info& irs_info,
                                                SAS::TrailId trail)
{
  return modify_subscription(public_id,
                             subscription,
                             "",
                             irs_info,
                             trail);
}

HTTPCode SubscriberManager::remove_subscription(const std::string& public_id,
                                                const std::string& subscription_id,
                                                HSSConnection::irs_info& irs_info,
                                                SAS::TrailId trail)
{
  return modify_subscription(public_id,
                             SubscriptionPair(),
                             subscription_id,
                             irs_info,
                             trail);
}

HTTPCode SubscriberManager::deregister_subscriber(const std::string& public_id,
                                                  const EventTrigger& event_trigger,
                                                  SAS::TrailId trail)
{
  // Get cached subscriber information from the HSS.
  std::string aor_id;
  HSSConnection::irs_info irs_info;
  HTTPCode rc = get_cached_default_id(public_id,
                                      aor_id,
                                      irs_info,
                                      trail);
  if (rc != HTTP_OK)
  {
    return rc;
  }

  // Get the original AoR from S4.
  AoR* orig_aor = NULL;
  uint64_t version;
  rc = _s4->handle_get(aor_id,
                       &orig_aor,
                       version,
                       trail);

  // If there is no AoR, we still count that as a success.
  if (rc != HTTP_OK)
  {
    delete orig_aor; orig_aor = NULL;
    if (rc == HTTP_NOT_FOUND)
    {
      return HTTP_OK;
    }

    return rc;
  }

  rc = _s4->handle_delete(aor_id,
                          version,
                          trail);

  // Send NOTIFYs and write audit logs.
  send_notifys_and_write_audit_logs(aor_id,
                                    event_trigger,
                                    orig_aor,
                                    NULL,
                                    trail);

  // Deregister with HSS.
  std::string dereg_reason = (event_trigger == EventTrigger::USER) ?
                               HSSConnection::DEREG_USER : HSSConnection::DEREG_ADMIN;
  rc = deregister_with_hss(aor_id,
                           dereg_reason,
                           orig_aor->_scscf_uri,
                           irs_info,
                           trail);

  // Send 3rd party deREGISTERs.

  delete orig_aor; orig_aor = NULL;

  return HTTP_OK;
}

HTTPCode SubscriberManager::get_bindings(const std::string& public_id,
                                         Bindings& bindings,
                                         SAS::TrailId trail)
{
  // Get the current AoR from S4.
  // TODO make sure this only returns not expired bindings.
  AoR* aor = NULL;
  uint64_t unused_version;
  HTTPCode rc = _s4->handle_get(public_id,
                                &aor,
                                unused_version,
                                trail);
  if (rc != HTTP_OK)
  {
    return rc;
  }

  // Set the bindings to return to the caller.
  bindings = AoRUtils::copy_bindings(aor->bindings());

  delete aor; aor = NULL;
  return HTTP_OK;
}

HTTPCode SubscriberManager::get_subscriptions(const std::string& public_id,
                                              Subscriptions& subscriptions,
                                              SAS::TrailId trail)
{
  // Get the current AoR from S4.
  // TODO make sure this only returns not expired subscriptions.
  AoR* aor = NULL;
  uint64_t unused_version;
  HTTPCode rc = _s4->handle_get(public_id,
                                &aor,
                                unused_version,
                                trail);
  if (rc != HTTP_OK)
  {
    return rc;
  }

  // Set the subscriptions to return to the caller.
  subscriptions = AoRUtils::copy_subscriptions(aor->subscriptions());

  delete aor; aor = NULL;
  return HTTP_OK;
}

HTTPCode SubscriberManager::get_cached_subscriber_state(const std::string& public_id,
                                                        HSSConnection::irs_info& irs_info,
                                                        SAS::TrailId trail)
{
  HTTPCode http_code = _hss_connection->get_registration_data(public_id,
                                                              irs_info,
                                                              trail);
  return http_code;
}

HTTPCode SubscriberManager::get_subscriber_state(const HSSConnection::irs_query& irs_query,
                                                 HSSConnection::irs_info& irs_info,
                                                 SAS::TrailId trail)
{
  HTTPCode http_code = _hss_connection->update_registration_state(irs_query,
                                                                  irs_info,
                                                                  trail);
  return http_code;
}

HTTPCode SubscriberManager::update_associated_uris(const std::string& aor_id,
                                                   const AssociatedURIs& associated_uris,
                                                   SAS::TrailId trail)
{
  // Get the original AoR from S4.
  AoR* orig_aor = NULL;
  uint64_t unused_version;
  HTTPCode rc = _s4->handle_get(aor_id,
                                &orig_aor,
                                unused_version,
                                trail);

  if (rc != HTTP_OK)
  {
    return rc;
  }

  AoR* updated_aor = NULL;
  rc = patch_associated_uris(aor_id,
                             associated_uris,
                             updated_aor,
                             trail);

  if (rc != HTTP_OK)
  {
    delete orig_aor; orig_aor = NULL;
    return rc;
  }

  // Send NOTIFYs and write audit logs.
  send_notifys_and_write_audit_logs(aor_id,
                                    EventTrigger::ADMIN,
                                    orig_aor,
                                    updated_aor,
                                    trail);

  // Send 3rd party REGISTERs?

  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;

  return HTTP_OK;
}

HTTPCode SubscriberManager::modify_subscription(const std::string& public_id,
                                                const SubscriptionPair& update_subscription,
                                                const std::string& remove_subscription,
                                                HSSConnection::irs_info& irs_info,
                                                SAS::TrailId trail)
{
  // Get cached subscriber information from the HSS.
  std::string aor_id;
  HTTPCode rc = get_cached_default_id(public_id,
                                      aor_id,
                                      irs_info,
                                      trail);
  if (rc != HTTP_OK)
  {
    return rc;
  }

  // Get the current AoR from S4.
  AoR* orig_aor = NULL;
  uint64_t unused_version;
  rc = _s4->handle_get(aor_id,
                       &orig_aor,
                       unused_version,
                       trail);

  // There must be an existing AoR since there must be bindings to subscribe to.
  if (rc != HTTP_OK)
  {
    return rc;
  }

  AoR* updated_aor = NULL;
  rc = patch_subscription(aor_id,
                          update_subscription,
                          remove_subscription,
                          updated_aor,
                          trail);
  if (rc != HTTP_OK)
  {
    delete orig_aor; orig_aor = NULL;
    return rc;
  }

  // Send NOTIFYs and write audit logs.
  send_notifys_and_write_audit_logs(aor_id,
                                    EventTrigger::USER,
                                    orig_aor,
                                    updated_aor,
                                    trail);

  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;

  return HTTP_OK;
}

HTTPCode SubscriberManager::get_cached_default_id(const std::string& public_id,
                                                  std::string& aor_id,
                                                  HSSConnection::irs_info& irs_info,
                                                  SAS::TrailId trail)
{
  HTTPCode rc = get_cached_subscriber_state(public_id,
                                            irs_info,
                                            trail);
  if (rc != HTTP_OK)
  {
    return rc;
  }

  // Get the aor_id from the associated URIs.
  if (!irs_info._associated_uris.get_default_impu(aor_id, false))
  {
    // TODO No default IMPU - what should we do here? Probably bail out.
    return HTTP_BAD_REQUEST;
  }

  return rc;
}

HTTPCode SubscriberManager::put_bindings(const std::string& aor_id,
                                         const Bindings& update_bindings,
                                         const std::vector<std::string>& remove_bindings,
                                         const AssociatedURIs& associated_uris,
                                         const std::string& scscf_uri,
                                         AoR*& aor,
                                         SAS::TrailId trail)
{
  PatchObject patch_object;
  patch_object.set_update_bindings(AoRUtils::copy_bindings(update_bindings));
  patch_object.set_remove_bindings(remove_bindings);
  patch_object.set_associated_uris(associated_uris);
  patch_object.set_increment_cseq(true);

  aor = new AoR(aor_id);
  aor->patch_aor(patch_object);
  aor->_scscf_uri = scscf_uri;
  HTTPCode rc = _s4->handle_put(aor_id,
                                *aor,
                                trail);

  return rc;
}

HTTPCode SubscriberManager::patch_bindings(const std::string& aor_id,
                                           const Bindings& update_bindings,
                                           const std::vector<std::string>& remove_bindings,
                                           const std::vector<std::string>& remove_subscriptions,
                                           const AssociatedURIs& associated_uris,
                                           AoR*& aor,
                                           SAS::TrailId trail)
{
  PatchObject patch_object;
  patch_object.set_update_bindings(AoRUtils::copy_bindings(update_bindings));
  patch_object.set_remove_bindings(remove_bindings);
  patch_object.set_remove_subscriptions(remove_subscriptions);
  patch_object.set_associated_uris(associated_uris);
  patch_object.set_increment_cseq(true);
  HTTPCode rc = _s4->handle_patch(aor_id,
                                  patch_object,
                                  &aor,
                                  trail);

  return rc;
}

HTTPCode SubscriberManager::patch_subscription(const std::string& aor_id,
                                               const SubscriptionPair& update_subscription,
                                               const std::string& remove_subscription,
                                               AoR*& aor,
                                               SAS::TrailId trail)
{
  PatchObject patch_object;
  Subscriptions subscriptions;
  if (update_subscription.second != NULL)
  {
    subscriptions.insert(update_subscription);
  }
  patch_object.set_update_subscriptions(AoRUtils::copy_subscriptions(subscriptions));
  patch_object.set_remove_subscriptions({remove_subscription});
  patch_object.set_increment_cseq(true);
  HTTPCode rc = _s4->handle_patch(aor_id,
                                  patch_object,
                                  &aor,
                                  trail);

  return rc;
}

HTTPCode SubscriberManager::patch_associated_uris(const std::string& aor_id,
                                                  const AssociatedURIs& associated_uris,
                                                  AoR*& aor,
                                                  SAS::TrailId trail)
{
  PatchObject patch_object;
  patch_object.set_associated_uris(associated_uris);
  patch_object.set_increment_cseq(true);
  HTTPCode rc = _s4->handle_patch(aor_id,
                                  patch_object,
                                  &aor,
                                  trail);

  return rc;
}

std::vector<std::string> SubscriberManager::subscriptions_to_remove(const Bindings& orig_bindings,
                                                                    const Subscriptions& orig_subscriptions,
                                                                    const Bindings& bindings_to_update,
                                                                    const std::vector<std::string> binding_ids_to_remove)
{
  std::vector<std::string> subscription_ids_to_remove;
  std::set<std::string> missing_uris;

  // Store off the contact URIs of bindings to be removed.
  for (std::string binding_id : binding_ids_to_remove)
  {
    Bindings::const_iterator b = orig_bindings.find(binding_id);
    if (b != orig_bindings.end())
    {
      missing_uris.insert(b->second->_uri);
    }
  }

  // Store off the original contact URI of bindings where the contact is about
  // to be changed.
  for (BindingPair bp : bindings_to_update)
  {
    Bindings::const_iterator b = orig_bindings.find(bp.first);
    if ((b != orig_bindings.end()) &&
        (b->second->_uri != bp.second->_uri))
    {
      missing_uris.insert(b->second->_uri);
    }
  }

  // Loop over the subscriptions. If any have the same contact as one of the
  // missing URIs, the subscription should be removed.
  for (SubscriptionPair sp : orig_subscriptions)
  {
    if (missing_uris.find(sp.second->_req_uri) != missing_uris.end())
    {
      TRC_DEBUG("Subscription %s is being removed because the binding that shares"
                " its contact URI %s is being removed or changing contact URI",
                sp.first.c_str(),
                sp.second->_req_uri.c_str());
      subscription_ids_to_remove.push_back(sp.first);
    }
  }

  return subscription_ids_to_remove;
}

void SubscriberManager::send_notifys_and_write_audit_logs(const std::string& aor_id,
                                                          const EventTrigger& event_trigger,
                                                          AoR* orig_aor,
                                                          AoR* updated_aor,
                                                          SAS::TrailId trail)
{
  // Classify bindings.
  ClassifiedBindings classified_bindings;
  classify_bindings(aor_id,
                    event_trigger,
                    (orig_aor != NULL) ? orig_aor->bindings() : Bindings(),
                    (updated_aor != NULL) ? updated_aor->bindings() : Bindings(),
                    classified_bindings);

  // Work out if Associated URIs have changed.
  bool associated_uris_changed = false;
  if ((orig_aor != NULL) && (updated_aor != NULL))
  {
    associated_uris_changed = (orig_aor->_associated_uris !=
                               updated_aor->_associated_uris);
  }
  else
  {
    // One of the AoRs is NULL so we are either creating or deleting an AoR.
    // This isn't a change to Associated URIs so don't set it to true.
  }

  ClassifiedSubscriptions classified_subscriptions;
  classify_subscriptions(aor_id,
                         event_trigger,
                         (orig_aor != NULL) ? orig_aor->subscriptions() : Subscriptions(),
                         (updated_aor != NULL) ? updated_aor->subscriptions() : Subscriptions(),
                         classified_bindings,
                         associated_uris_changed,
                         classified_subscriptions);

  // Write audit logs.
  int now = time(NULL);
  if (_analytics != NULL)
  {
    log_bindings(classified_bindings, now);
    log_subscriptions(classified_subscriptions, now);
  }

  // Send NOTIFYs. If the updated AoR is NULL e.g. if we have deleted a
  // subscriber, the best we can do is use the CSeq on the original AoR and
  // increment it by 1. TODO Check with EM.
  _notify_sender->send_notifys(aor_id,
                               EventTrigger::USER,
                               classified_bindings,
                               classified_subscriptions,
                               (updated_aor != NULL) ? updated_aor->_associated_uris : orig_aor->_associated_uris,
                               (updated_aor != NULL) ? updated_aor->_notify_cseq : orig_aor->_notify_cseq + 1,
                               now,
                               trail);

  delete_bindings(classified_bindings);
  delete_subscriptions(classified_subscriptions);
}

void SubscriberManager::log_bindings(const ClassifiedBindings& classified_bindings,
                                     int now)
{
  for (ClassifiedBinding* cb : classified_bindings)
  {
    if (cb->_contact_event == NotifyUtils::ContactEvent::CREATED ||
        cb->_contact_event == NotifyUtils::ContactEvent::REFRESHED ||
        cb->_contact_event == NotifyUtils::ContactEvent::SHORTENED)

    {
      _analytics->registration(cb->_b->_address_of_record,
                               cb->_id,
                               cb->_b->_uri,
                               cb->_b->_expires - now);
    }
    else if ((cb->_contact_event == NotifyUtils::ContactEvent::EXPIRED)     ||
             (cb->_contact_event == NotifyUtils::ContactEvent::DEACTIVATED) ||
             (cb->_contact_event == NotifyUtils::ContactEvent::UNREGISTERED))
    {
      _analytics->registration(cb->_b->_address_of_record,
                               cb->_id,
                               cb->_b->_uri,
                               0);
    }
  }
}

void SubscriberManager::log_subscriptions(const ClassifiedSubscriptions& classified_subscriptions,
                                          int now)
{
  for (ClassifiedSubscription* cs : classified_subscriptions)
  {
    if (cs->_subscription_event == SubscriptionEvent::CREATED ||
        cs->_subscription_event == SubscriptionEvent::REFRESHED ||
        cs->_subscription_event == SubscriptionEvent::SHORTENED)
    {
      _analytics->subscription(cs->_aor_id,
                               cs->_id,
                               cs->_subscription->_req_uri,
                               cs->_subscription->_expires - now);
    }
    else if(cs->_subscription_event == SubscriptionEvent::EXPIRED ||
            cs->_subscription_event == SubscriptionEvent::TERMINATED)
    {
      _analytics->subscription(cs->_aor_id,
                               cs->_id,
                               cs->_subscription->_req_uri,
                               0);
    }
  }
}

HTTPCode SubscriberManager::deregister_with_hss(const std::string& aor_id,
                                                const std::string& dereg_reason,
                                                const std::string& server_name,
                                                HSSConnection::irs_info& irs_info,
                                                SAS::TrailId trail)
{
  HSSConnection::irs_query irs_query;
  irs_query._public_id = aor_id;
  irs_query._req_type = dereg_reason;
  irs_query._server_name = server_name;

  return get_subscriber_state(irs_query, irs_info, trail);
}

void SubscriberManager::classify_bindings(const std::string& aor_id,
                                          const EventTrigger& event_trigger,
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
    NotifyUtils::ContactEvent event;
    Bindings::const_iterator orig_b_match = orig_bindings.find(updated_b.first);

    std::string binding_id = updated_b.first;
    Binding* binding = updated_b.second;

    if (orig_b_match == orig_bindings.end())
    {
      TRC_DEBUG("Binding %s in AoR %s is new",
                binding_id.c_str(),
                aor_id.c_str());
      event = NotifyUtils::ContactEvent::CREATED;
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
                                 NotifyUtils::ContactEvent::DEACTIVATED);
        classified_bindings.push_back(deactivated_record);
        event = NotifyUtils::ContactEvent::CREATED;
      }
      else if (orig_b_match->second->_expires < binding->_expires)
      {
        TRC_DEBUG("Binding %s in AoR %s has been refreshed",
                  binding_id.c_str(),
                  aor_id.c_str());
        event = NotifyUtils::ContactEvent::REFRESHED;
      }
      else if (orig_b_match->second->_expires > binding->_expires)
      {
        TRC_DEBUG("Binding %s in AoR %s has been shortened",
                  binding_id.c_str(),
                  aor_id.c_str());
        event = NotifyUtils::ContactEvent::SHORTENED;
      }
      else
      {
        TRC_DEBUG("Binding %s in AoR %s is unchanged",
                  binding_id.c_str(),
                  aor_id.c_str());
        event = NotifyUtils::ContactEvent::REGISTERED;
      }
    }

    ClassifiedBinding* binding_record =
      new ClassifiedBinding(binding_id,
                            binding,
                            event);
    classified_bindings.push_back(binding_record);
  }
}

void SubscriberManager::classify_subscriptions(const std::string& aor_id,
                                               const EventTrigger& event_trigger,
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
    if (classified_binding->_contact_event != NotifyUtils::ContactEvent::REGISTERED)
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
    if (classified_binding->_contact_event == NotifyUtils::ContactEvent::EXPIRED ||
        classified_binding->_contact_event == NotifyUtils::ContactEvent::DEACTIVATED ||
        classified_binding->_contact_event == NotifyUtils::ContactEvent::UNREGISTERED)
    {
      missing_binding_uris.insert(classified_binding->_b->_uri);
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
        (event_trigger != EventTrigger::ADMIN))
    {
      // Binding is missing, and this event is not triggered by admin. The
      // binding no longer exists due to user deregestration or timeout, so
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
                                   SubscriptionEvent::EXPIRED);

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
                                   SubscriptionEvent::TERMINATED);

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

    SubscriptionEvent event;
    bool notify_required = base_notify_required;
    std::string reasons = base_reasons;
    if (orig_s_match == orig_subscriptions.end())
    {
      TRC_DEBUG("Subscription %s in AoR %s is new",
                subscription_id.c_str(),
                aor_id.c_str());
      event = SubscriptionEvent::CREATED;
      notify_required = true;
      reasons += "Subscription created - ";
    }
    else if (subscription->_refreshed)
    {
      TRC_DEBUG("Subscription %s in aor %s has been refreshed",
                subscription_id.c_str(),
                aor_id.c_str());
      event = SubscriptionEvent::REFRESHED;
      notify_required = true;
      reasons += "Subscription refreshed - ";
    }
    else if (subscription->_expires < orig_s_match->second->_expires)
    {
      TRC_DEBUG("Subscription %s in AoR %s has been shortened",
                subscription_id.c_str(),
                aor_id.c_str());
      event = SubscriptionEvent::SHORTENED;
      notify_required = true;
      reasons += "Subscription shortened - "; // TODO - is this a valid reason to send a NOTIFY? Check specs
    }
    else
    {
      TRC_DEBUG("Subscription %s in AoR %s is unchanged",
                subscription_id.c_str(),
                aor_id.c_str());
      event = SubscriptionEvent::UNCHANGED;
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

/// Helper to delete vectors of bindings safely
void SubscriberManager::delete_bindings(ClassifiedBindings& classified_bindings)
{
  for (ClassifiedBinding* binding : classified_bindings)
  {
    delete binding;
  }

  classified_bindings.clear();
}

/// Helper to delete vectors of subscriptions safely
void SubscriberManager::delete_subscriptions(ClassifiedSubscriptions& classified_subscriptions)
{
  for (ClassifiedSubscription* subscription : classified_subscriptions)
  {
    delete subscription;
  }

  classified_subscriptions.clear();
}

/// Helper to map SDM EventTrigger to ContactEvent for Notify
NotifyUtils::ContactEvent SubscriberManager::determine_contact_event(const EventTrigger& event_trigger)
{
  NotifyUtils::ContactEvent contact_event;
  switch(event_trigger)
  {
    // TODO Uncomment this when the timer pop interface is added.
    /*case SubscriberDataManager::EventTrigger::TIMEOUT:
      contact_event = NotifyUtils::ContactEvent::EXPIRED;
      break;*/
    case EventTrigger::USER:
      contact_event = NotifyUtils::ContactEvent::UNREGISTERED;
      break;
    case EventTrigger::ADMIN:
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

/// NotifySender Methods

SubscriberManager::NotifySender::NotifySender()
{
}

SubscriberManager::NotifySender::~NotifySender()
{
}

void SubscriberManager::NotifySender::send_notifys(const std::string& aor_id,
                                                   const EventTrigger& event_trigger,
                                                   const ClassifiedBindings& classified_bindings,
                                                   const ClassifiedSubscriptions& classified_subscriptions,
                                                   AssociatedURIs& associated_uris,
                                                   int cseq,
                                                   int now,
                                                   SAS::TrailId trail)
{
  // The registration state is ACTIVE if we have at least one active binding,
  // otherwise it is TERMINATED.
  NotifyUtils::RegistrationState reg_state = NotifyUtils::RegistrationState::TERMINATED;
  for (ClassifiedBinding* classified_binding : classified_bindings)
  {
    if (classified_binding->_contact_event == NotifyUtils::ContactEvent::REGISTERED ||
        classified_binding->_contact_event == NotifyUtils::ContactEvent::CREATED ||
        classified_binding->_contact_event == NotifyUtils::ContactEvent::REFRESHED ||
        classified_binding->_contact_event == NotifyUtils::ContactEvent::SHORTENED)
    {
      TRC_DEBUG("Registration state ACTIVE on NOTIFY");
      reg_state = NotifyUtils::RegistrationState::ACTIVE;
      break;
    }
  }

  for (ClassifiedSubscription* classified_subscription : classified_subscriptions)
  {
    if (classified_subscription->_notify_required)
    {
      TRC_DEBUG("Sending NOTIFY for subscription %s: %s",
                classified_subscription->_id.c_str(),
                classified_subscription->_reasons.c_str());

      if (classified_subscription->_subscription_event == SubscriptionEvent::TERMINATED)
      {
        // This is a terminated subscription - set the expiry time to now
        classified_subscription->_subscription->_expires = now;
      }

      pjsip_tx_data* tdata_notify = NULL;
      pj_status_t status = NotifyUtils::create_subscription_notify(
                                              &tdata_notify,
                                              classified_subscription->_subscription,
                                              aor_id,
                                              &associated_uris,
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
