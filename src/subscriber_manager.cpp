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
                                     AnalyticsLogger* analytics_logger,
                                     NotifySender* notify_sender,
                                     RegistrationSender* registration_sender) :
  _s4(s4),
  _hss_connection(hss_connection),
  _analytics(analytics_logger),
  _notify_sender(notify_sender),
  _registration_sender(registration_sender)
{
  if (_s4 != NULL)
  {
    _s4->register_timer_pop_consumer(this);
  }

  if (_registration_sender != NULL)
  {
    _registration_sender->register_dereg_event_consumer(this);
  }
}

SubscriberManager::~SubscriberManager()
{
}

HTTPCode SubscriberManager::register_subscriber(const std::string& aor_id,
                                                const std::string& server_name,
                                                const AssociatedURIs& associated_uris,
                                                const Bindings& add_bindings,
                                                Bindings& all_bindings,
                                                HSSConnection::irs_info& irs_info,
                                                SAS::TrailId trail)
{
  return register_subscriber_internal(aor_id,
                                      server_name,
                                      associated_uris,
                                      add_bindings,
                                      all_bindings,
                                      irs_info,
                                      true,
                                      trail);
}

HTTPCode SubscriberManager::register_subscriber_internal(const std::string& aor_id,
                                                         const std::string& server_name,
                                                         const AssociatedURIs& associated_uris,
                                                         const Bindings& add_bindings,
                                                         Bindings& all_bindings,
                                                         HSSConnection::irs_info& irs_info,
                                                         bool retry,
                                                         SAS::TrailId trail)
{
  TRC_DEBUG("Registering AoR %s for the first time", aor_id.c_str());

  int now = time(NULL);

  // We are registering a subscriber for the first time, so there is no stored
  // AoR. PUT the new bindings to S4.
  AoR* orig_aor = NULL;
  AoR* updated_aor = NULL;

  // We may have been called with no bindings to update. In that case do not PUT
  // any data to S4.
  if (!add_bindings.empty())
  {
    PatchObject patch_object;
    build_patch(patch_object,
                add_bindings,
                associated_uris);

    updated_aor = new AoR(aor_id);
    updated_aor->patch_aor(patch_object);
    updated_aor->_scscf_uri = server_name;

    // PUT a new AoR.
    HTTPCode rc = _s4->handle_put(aor_id,
                                  *updated_aor,
                                  trail);

    // The PUT failed, so return.
    if ((rc == HTTP_PRECONDITION_FAILED) && (retry))
    {
      TRC_DEBUG("Registering AoR %s failed with 412 PRECONDITION FAILED - retry with reregister",
                aor_id.c_str());
      delete updated_aor; updated_aor = NULL;
      return reregister_subscriber_internal(aor_id,
                                            server_name,
                                            associated_uris,
                                            add_bindings,
                                            {},
                                            all_bindings,
                                            irs_info,
                                            false,
                                            trail);
    }
    else if (rc != HTTP_OK)
    {
      TRC_DEBUG("Registering AoR %s failed with return code %d",
                aor_id.c_str(),
                rc);

      delete updated_aor; updated_aor = NULL;
      return rc;
    }

    log_updated_bindings(updated_aor, add_bindings, now);

    // Get all bindings to return to the caller
    all_bindings = AoRUtils::copy_active_bindings(updated_aor->bindings(),
                                                  now);

    // Send any NOTIFYs. Normally we expect no NOTIFYs to be sent, as this was
    // triggered by an initial register. However, there's a chance if we had to
    // retry the write to S4. Either way, we let the Notify Sender decide.
    send_notifys(aor_id,
                 orig_aor,
                 updated_aor,
                 SubscriberDataUtils::EventTrigger::USER,
                 now,
                 trail);
  }
  else
  {
    // The was nothing to store for this subscriber so we should deregister the
    // subscriber with the HSS since they will have previously been registered
    // incorrectly.
    if (all_bindings.empty())
    {
      HTTPCode rc = deregister_with_hss(aor_id,
                                        HSSConnection::DEREG_USER,
                                        server_name,
                                        irs_info,
                                        trail);
      if (rc != HTTP_OK)
      {
        TRC_DEBUG("Failed to deregister subscriber %s with HSS",
                  aor_id.c_str());
        delete orig_aor; orig_aor = NULL;
        delete updated_aor; updated_aor = NULL;
        return rc;
      }
    }
  }

  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;

  return HTTP_OK;
}

HTTPCode SubscriberManager::reregister_subscriber(const std::string& aor_id,
                                                  const std::string& server_name,
                                                  const AssociatedURIs& associated_uris,
                                                  const Bindings& updated_bindings,
                                                  const std::vector<std::string>& binding_ids_to_remove,
                                                  Bindings& all_bindings,
                                                  HSSConnection::irs_info& irs_info,
                                                  SAS::TrailId trail)
{
  return reregister_subscriber_internal(aor_id,
                                        server_name,
                                        associated_uris,
                                        updated_bindings,
                                        binding_ids_to_remove,
                                        all_bindings,
                                        irs_info,
                                        true,
                                        trail);
}

HTTPCode SubscriberManager::reregister_subscriber_internal(const std::string& aor_id,
                                                           const std::string& server_name,
                                                           const AssociatedURIs& associated_uris,
                                                           const Bindings& updated_bindings,
                                                           const std::vector<std::string>& binding_ids_to_remove,
                                                           Bindings& all_bindings,
                                                           HSSConnection::irs_info& irs_info,
                                                           bool retry,
                                                           SAS::TrailId trail)
{

  TRC_DEBUG("Reregistering AoR %s", aor_id.c_str());

  int now = time(NULL);

  // Get the current AoR from S4.
  AoR* orig_aor = NULL;
  uint64_t unused_version;
  HTTPCode rc = _s4->handle_get(aor_id,
                                &orig_aor,
                                unused_version,
                                trail);

  // We are reregistering a subscriber, so there must be an existing AoR in the
  // store.
  AoR* updated_aor = NULL;
  if ((rc == HTTP_NOT_FOUND) && (retry))
  {
    TRC_DEBUG("Reregistering AoR %s failed with 404 NOT FOUND - retry with register",
              aor_id.c_str());
    return register_subscriber_internal(aor_id,
                                        server_name,
                                        associated_uris,
                                        updated_bindings,
                                        all_bindings,
                                        irs_info,
                                        false,
                                        trail);
  }
  else if (rc != HTTP_OK)
  {
    TRC_DEBUG("Reregistering AoR %s failed during GET with return code %d",
              aor_id.c_str(),
              rc);
    delete orig_aor; orig_aor = NULL;
    return rc;
  }

  // Check if there are any subscriptions that share the same contact as
  // the removed bindings, and delete them too.
  std::vector<std::string> subscription_ids_to_remove =
                             subscriptions_to_remove(orig_aor->bindings(),
                                                     orig_aor->subscriptions(),
                                                     updated_bindings,
                                                     binding_ids_to_remove);

  log_removed_bindings(orig_aor,
                       binding_ids_to_remove);

  PatchObject patch_object;
  build_patch(patch_object,
              updated_bindings,
              binding_ids_to_remove,
              subscription_ids_to_remove,
              associated_uris);

  // PATCH the existing AoR.
  rc = _s4->handle_patch(aor_id,
                         patch_object,
                         &updated_aor,
                         trail);

  // The PATCH failed, so return.
  if ((rc == HTTP_NOT_FOUND) && (retry))
  {
    TRC_DEBUG("Reregistering AoR %s failed with 404 NOT FOUND - retry with register",
              aor_id.c_str());
    delete orig_aor; orig_aor = NULL;
    return register_subscriber_internal(aor_id,
                                        server_name,
                                        associated_uris,
                                        updated_bindings,
                                        all_bindings,
                                        irs_info,
                                        false,
                                        trail);
  }
  else if (rc != HTTP_OK)
  {
    TRC_DEBUG("Reregistering AoR %s failed during PATCH with return code %d",
              aor_id.c_str(),
              rc);
    delete orig_aor; orig_aor = NULL;
    delete updated_aor; updated_aor = NULL;
    return rc;
  }

  log_updated_bindings(updated_aor, updated_bindings, now);

  log_subscriptions(aor_id,
                    orig_aor,
                    updated_aor,
                    subscription_ids_to_remove,
                    now);

  // Get all bindings to return to the caller
  all_bindings = AoRUtils::copy_active_bindings(updated_aor->bindings(),
                                                now);

  send_notifys(aor_id,
               orig_aor,
               updated_aor,
               SubscriberDataUtils::EventTrigger::USER,
               now,
               trail);

  // Update HSS if all bindings expired.
  if (all_bindings.empty())
  {
    rc = deregister_with_hss(aor_id,
                             HSSConnection::DEREG_USER,
                             updated_aor->_scscf_uri,
                             irs_info,
                             trail);
    if (rc != HTTP_OK)
    {
      TRC_DEBUG("Failed to deregister subscriber %s with HSS",
                aor_id.c_str());
      delete orig_aor; orig_aor = NULL;
      delete updated_aor; updated_aor = NULL;
      return rc;
    }

    // Send 3rd party deREGISTERs.
    _registration_sender->deregister_with_application_servers(aor_id,
                                                              irs_info._service_profiles[aor_id],
                                                              trail);
  }

  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;

  return HTTP_OK;
}

HTTPCode SubscriberManager::remove_bindings(const std::string& public_id,
                                            const std::vector<std::string>& binding_ids,
                                            const SubscriberDataUtils::EventTrigger& event_trigger,
                                            Bindings& bindings,
                                            SAS::TrailId trail)
{
  TRC_DEBUG("Removing bindings from IMPU %s", public_id.c_str());

  int now = time(NULL);

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

    TRC_DEBUG("Removing bindings for AoR %s failed during GET with return code %s",
              aor_id.c_str(),
              rc);
    return rc;
  }

  log_removed_bindings(orig_aor,
                       binding_ids);

  // Check if there are any subscriptions that share the same contact as
  // the removed bindings, and delete them too.
  std::vector<std::string> subscription_ids_to_remove =
                             subscriptions_to_remove(orig_aor->bindings(),
                                                     orig_aor->subscriptions(),
                                                     Bindings(),
                                                     binding_ids);


  PatchObject patch_object;
  build_patch(patch_object,
              binding_ids,
              subscription_ids_to_remove,
              irs_info._associated_uris);

  // PATCH the existing AoR.
  AoR* updated_aor = NULL;
  rc = _s4->handle_patch(aor_id,
                         patch_object,
                         &updated_aor,
                         trail);

  if (rc != HTTP_OK)
  {
    TRC_DEBUG("Removing bindings for AoR %s failed during PATCH with return code %s",
              aor_id.c_str(),
              rc);
    delete orig_aor; orig_aor = NULL;
    delete updated_aor; updated_aor = NULL;
    return rc;
  }

  log_subscriptions(aor_id,
                    orig_aor,
                    updated_aor,
                    subscription_ids_to_remove,
                    now);

  // Get all bindings to return to the caller
  bindings = AoRUtils::copy_active_bindings(updated_aor->bindings(),
                                            now);

  send_notifys(aor_id,
               orig_aor,
               updated_aor,
               event_trigger,
               now,
               trail);

  // Update HSS if all bindings expired.
  if (bindings.empty())
  {
    // If this action was not triggered by the HSS e.g. because of an RTR, we
    // should dergister with the HSS.
    if (event_trigger != SubscriberDataUtils::EventTrigger::HSS)
    {
      std::string dereg_reason = (event_trigger == SubscriberDataUtils::EventTrigger::USER) ?
                                   HSSConnection::DEREG_USER : HSSConnection::DEREG_ADMIN;
      rc = deregister_with_hss(aor_id,
                               dereg_reason,
                               updated_aor->_scscf_uri,
                               irs_info,
                               trail);
      if (rc != HTTP_OK)
      {
        TRC_DEBUG("Failed to deregister subscriber %s with HSS",
                  aor_id.c_str());
        delete orig_aor; orig_aor = NULL;
        delete updated_aor; updated_aor = NULL;
        return rc;
      }
    }

    // Send 3rd party deREGISTERs.
    _registration_sender->deregister_with_application_servers(public_id,
                                                              irs_info._service_profiles[public_id],
                                                              trail);
  }

  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;

  return HTTP_OK;
}

HTTPCode SubscriberManager::update_subscription(
                                           const std::string& public_id,
                                           const SubscriptionPair& subscription,
                                           HSSConnection::irs_info& irs_info,
                                           SAS::TrailId trail)
{
  TRC_DEBUG("Updating subscription for IMPU %s", public_id.c_str());

  return modify_subscription(public_id,
                             {subscription},
                             "",
                             irs_info,
                             trail);
}

HTTPCode SubscriberManager::remove_subscription(
                                             const std::string& public_id,
                                             const std::string& subscription_id,
                                             HSSConnection::irs_info& irs_info,
                                             SAS::TrailId trail)
{
  TRC_DEBUG("Removing subscription for IMPU %s", public_id.c_str());

  return modify_subscription(public_id,
                             Subscriptions(),
                             subscription_id,
                             irs_info,
                             trail);
}

HTTPCode SubscriberManager::modify_subscription(
                                    const std::string& public_id,
                                    const Subscriptions& update_subscriptions,
                                    const std::string& remove_subscription,
                                    HSSConnection::irs_info& irs_info,
                                    SAS::TrailId trail)
{
  int now = time(NULL);

  // Get cached subscriber information from the HSS.
  std::string aor_id;
  HTTPCode rc = get_cached_default_id(public_id,
                                      aor_id,
                                      irs_info,
                                      trail);
  if (rc != HTTP_OK)
  {
    TRC_DEBUG("Unable to modify subscription for %s - HSS lookup failed with "
              " return code %s",
              public_id.c_str(), rc);
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
    TRC_DEBUG("Modifying subscription for AoR %s failed during S4 lookup "
              "with return code %s",
              aor_id.c_str(),
              rc);
    return rc;
  }

  PatchObject patch_object;
  build_patch(patch_object,
              update_subscriptions,
              {remove_subscription},
              irs_info._associated_uris);

  // PATCH the existing AoR.
  AoR* updated_aor = NULL;
  rc = _s4->handle_patch(aor_id,
                         patch_object,
                         &updated_aor,
                         trail);

  if (rc != HTTP_OK)
  {
    TRC_DEBUG("Modifying subscription for AoR %s failed during S4 update with "
              "return code %s",
              aor_id.c_str(),
              rc);
  }
  else
  {
    // At this point modifying the subscription has been successful - we'll return
    // OK to the client.

    // Write an analytics log for the modified subscription.
    std::string subscription_id = (remove_subscription == "") ?
                                    update_subscriptions.begin()->first :
                                    remove_subscription;
    log_subscriptions(aor_id,
                      orig_aor,
                      updated_aor,
                      {subscription_id},
                      now);

    // Finally, send any NOTIFYs.
    send_notifys(aor_id,
                 orig_aor,
                 updated_aor,
                 SubscriberDataUtils::EventTrigger::USER,
                 now,
                 trail);
  }

  // Delete both AoRs - the client doesn't need either of these.
  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;

  return rc;
}

HTTPCode SubscriberManager::deregister_subscriber(const std::string& public_id,
                                                  SAS::TrailId trail)
{
  TRC_DEBUG("Deregistering subscriber with IMPU %s", public_id.c_str());

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

  // DELETEs to S4 are CAS'd so we loop for as long as we get back
  // HTTP_PRECONDITION_FAILED.
  AoR* orig_aor = NULL;
  do
  {
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

      TRC_DEBUG("Deregistering AoR %s failed during GET with return code %d",
                aor_id.c_str(),
                rc);
      return rc;
    }

    // Save off the bindings IDs we are about to remove for logging purposes.
    std::vector<std::string> binding_ids;
    for (BindingPair binding : orig_aor->bindings())
    {
      binding_ids.push_back(binding.first);
    }

    log_removed_bindings(orig_aor,
                         binding_ids);

    rc = _s4->handle_delete(aor_id,
                            version,
                            trail);
  } while (rc == HTTP_PRECONDITION_FAILED);

  if ((rc != HTTP_OK) && (rc != HTTP_NO_CONTENT))
  {
    TRC_DEBUG("Deregistering AoR %s failed during DELETE with return code %d",
              aor_id.c_str(),
              rc);
    delete orig_aor; orig_aor = NULL;
    return rc;
  }

  send_notifys(aor_id,
               orig_aor,
               NULL,
               SubscriberDataUtils::EventTrigger::ADMIN,
               time(NULL),
               trail);

  // Deregister with HSS.
  rc = deregister_with_hss(aor_id,
                           HSSConnection::DEREG_ADMIN,
                           orig_aor->_scscf_uri,
                           irs_info,
                           trail);

  if (rc != HTTP_OK)
  {
    TRC_DEBUG("Failed to deregister subscriber %s with HSS",
              aor_id.c_str());
    delete orig_aor; orig_aor = NULL;
    return rc;
  }

  // Send 3rd party deREGISTERs.
  _registration_sender->deregister_with_application_servers(public_id,
                                                            irs_info._service_profiles[public_id],
                                                            trail);

  delete orig_aor; orig_aor = NULL;

  return HTTP_OK;
}

HTTPCode SubscriberManager::get_bindings(const std::string& aor_id,
                                         Bindings& bindings,
                                         SAS::TrailId trail)
{
  TRC_DEBUG("Retrieving bindings for AoR %s",
            aor_id.c_str());

  // Get the current AoR from S4.
  AoR* aor = NULL;
  uint64_t unused_version;
  HTTPCode rc = _s4->handle_get(aor_id,
                                &aor,
                                unused_version,
                                trail);
  if (rc != HTTP_OK)
  {
    TRC_DEBUG("Retrieving bindings for AoR %s failed during GET with return code %d",
              aor_id.c_str(),
              rc);
    return rc;
  }

  // Set the bindings to return to the caller.
  bindings = AoRUtils::copy_active_bindings(aor->bindings(),
                                            time(NULL));

  delete aor; aor = NULL;
  return HTTP_OK;
}

HTTPCode SubscriberManager::get_subscriptions(const std::string& aor_id,
                                              Subscriptions& subscriptions,
                                              SAS::TrailId trail)
{
  TRC_DEBUG("Retrieving subscriptions for AoR %s",
            aor_id.c_str());

  // Get the current AoR from S4.
  AoR* aor = NULL;
  uint64_t unused_version;
  HTTPCode rc = _s4->handle_get(aor_id,
                                &aor,
                                unused_version,
                                trail);
  if (rc != HTTP_OK)
  {
    TRC_DEBUG("Retrieving subscriptions for AoR %s failed during GET with return code %d",
              aor_id.c_str(),
              rc);
    return rc;
  }

  // Set the subscriptions to return to the caller.
  subscriptions = AoRUtils::copy_active_subscriptions(aor->subscriptions(),
                                                      time(NULL));

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
  TRC_DEBUG("Updating associted URIs for AoR %s", aor_id.c_str());

  // Get the original AoR from S4.
  AoR* orig_aor = NULL;
  uint64_t unused_version;
  HTTPCode rc = _s4->handle_get(aor_id,
                                &orig_aor,
                                unused_version,
                                trail);

  if (rc != HTTP_OK)
  {
    TRC_DEBUG("Updating associated URIs for AoR %s failed during GET with return code %d",
              aor_id.c_str(),
              rc);
    return rc;
  }

  PatchObject patch_object;
  build_patch(patch_object,
              associated_uris);

  // PATCH the existing AoR.
  AoR* updated_aor = NULL;
  rc = _s4->handle_patch(aor_id,
                         patch_object,
                         &updated_aor,
                         trail);

  if (rc != HTTP_OK)
  {
    TRC_DEBUG("Updating associated URIs for AoR %s failed during PATCH with return code %d",
              aor_id.c_str(),
              rc);
    delete orig_aor; orig_aor = NULL;
    return rc;
  }

  // Send NOTIFYs.
  send_notifys(aor_id,
               orig_aor,
               updated_aor,
               SubscriberDataUtils::EventTrigger::ADMIN,
               time(NULL),
               trail);

  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;

  return HTTP_OK;
}

void SubscriberManager::handle_timer_pop(const std::string& aor_id,
                                         SAS::TrailId trail)
{
  PJUtils::run_callback_on_worker_thread([this, aor_id, trail]() {
    return handle_timer_pop_internal(aor_id, trail);
  });
}

void SubscriberManager::handle_timer_pop_internal(const std::string& aor_id,
                                                  SAS::TrailId trail)
{
  TRC_DEBUG("Handling a timer pop for AoR %s", aor_id.c_str());

  // Get the original AoR from S4.
  AoR* orig_aor = NULL;
  uint64_t unused_version;
  HTTPCode rc = _s4->handle_get(aor_id,
                                &orig_aor,
                                unused_version,
                                trail);
  if (rc != HTTP_OK)
  {
    TRC_DEBUG("Handling timer pop for AoR %s failed during GET with return code %d",
              aor_id.c_str(),
              rc);
    delete orig_aor; orig_aor = NULL;
    return;
  }

  // Find any expired bindings in the original AoR.
  int now = time(NULL);
  std::vector<std::string> binding_ids_to_remove;
  for (BindingPair bp : orig_aor->bindings())
  {
    if (bp.second->_expires <= now)
    {
      binding_ids_to_remove.push_back(bp.first);
    }
  }

  // Find any expired subscriptions in the original AoR.
  std::vector<std::string> subscription_ids_to_remove;
  for (SubscriptionPair sp : orig_aor->subscriptions())
  {
    if (sp.second->_expires <= now)
    {
      subscription_ids_to_remove.push_back(sp.first);
    }
  }

  log_removed_bindings(orig_aor,
                       binding_ids_to_remove);

  // Send a PATCH to remove any expired bindings and subscriptions. We only do
  // this if there any bindings or subscriptions to remove.
  AoR* updated_aor = NULL;
  if ((!binding_ids_to_remove.empty()) ||
      (!subscription_ids_to_remove.empty()))
  {
    PatchObject patch_object;
    build_patch(patch_object,
                binding_ids_to_remove,
                subscription_ids_to_remove);

    // PATCH the existing AoR.
    rc = _s4->handle_patch(aor_id,
                           patch_object,
                           &updated_aor,
                           trail);

    if (rc != HTTP_OK)
    {
      TRC_DEBUG("Handling timer pop for AoR %s failed during PATCH with return code %d",
                aor_id.c_str(),
                rc);
      delete orig_aor; orig_aor = NULL;
      return;
    }
  }
  else
  {
    TRC_DEBUG("Timer pop for AoR %s didn't result in any removed bindings or subscriptions",
              aor_id.c_str());
    delete orig_aor; orig_aor = NULL;
    return;
  }

  log_subscriptions(aor_id,
                    orig_aor,
                    updated_aor,
                    subscription_ids_to_remove,
                    now);

  send_notifys(aor_id,
               orig_aor,
               updated_aor,
               SubscriberDataUtils::EventTrigger::TIMEOUT,
               now,
               trail);

  if ((updated_aor != NULL) &&
      (updated_aor->bindings().empty()))
  {
    HSSConnection::irs_info irs_info;
    rc = deregister_with_hss(aor_id,
                             HSSConnection::DEREG_TIMEOUT,
                             updated_aor->_scscf_uri,
                             irs_info,
                             trail);

    if (rc != HTTP_OK)
    {
      TRC_DEBUG("Failed to deregister subscriber %s with HSS",
                aor_id.c_str());
      delete orig_aor; orig_aor = NULL;
      delete updated_aor; updated_aor = NULL;
      return;
    }

    // Send 3rd party deREGISTERs.
    _registration_sender->deregister_with_application_servers(aor_id,
                                                              irs_info._service_profiles[aor_id],
                                                              trail);
  }


  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;
}

void SubscriberManager::register_with_application_servers(pjsip_msg* received_register_message,
                                                          pjsip_msg* ok_response_msg,
                                                          const std::string& served_user,
                                                          const Ifcs& ifcs,
                                                          int expires,
                                                          bool is_initial_registration,
                                                          SAS::TrailId trail)
{
  bool dereg_subscriber;
  _registration_sender->register_with_application_servers(received_register_message,
                                                          ok_response_msg,
                                                          served_user,
                                                          ifcs,
                                                          expires,
                                                          is_initial_registration,
                                                          dereg_subscriber,
                                                          trail);

  if (dereg_subscriber)
  {
    deregister_subscriber(served_user,
                          trail);
  }
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
    TRC_DEBUG("Failed to get cached default ID for IMPU %s with return code %d",
              public_id.c_str(),
              rc);
    return rc;
  }

  // Get the aor_id from the associated URIs.
  if (!irs_info._associated_uris.get_default_impu(aor_id, false))
  {
    TRC_ERROR("No Default ID in IRS for IMPU %s", public_id.c_str());
    return HTTP_BAD_REQUEST;
  }

  return rc;
}

std::vector<std::string> SubscriberManager::subscriptions_to_remove(const Bindings& orig_bindings,
                                                                    const Subscriptions& orig_subscriptions,
                                                                    const Bindings& bindings_to_update,
                                                                    const std::vector<std::string> binding_ids_to_remove)
{
  std::vector<std::string> subscription_ids_to_remove;
  std::set<std::string> missing_uris;

  // Store off the contact URIs of bindings to be removed. Any subscriptions
  // sharing any of these contact URIs will be removed.
  for (std::string binding_id : binding_ids_to_remove)
  {
    Bindings::const_iterator b = orig_bindings.find(binding_id);
    if (b != orig_bindings.end())
    {
      missing_uris.insert(b->second->_uri);
    }
  }

  // Store off the original contact URI of bindings where the contact is about
  // to be changed. Any subscriptions that share any of the original contact
  // URIs will be removed.
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

void SubscriberManager::send_notifys(
                         const std::string& aor_id,
                         AoR* orig_aor,
                         AoR* updated_aor,
                         const SubscriberDataUtils::EventTrigger& event_trigger,
                         int now,
                         SAS::TrailId trail)
{
  TRC_DEBUG("Sending NOTIFYs for %s", aor_id.c_str());

  AoR orig = AoR("");
  AoR current = AoR("");

  if (orig_aor != NULL)
  {
    orig.copy_aor(*orig_aor);
  }

  if (updated_aor != NULL)
  {
    current.copy_aor(*updated_aor);
  }

  _notify_sender->send_notifys(aor_id,
                               orig,
                               current,
                               event_trigger,
                               now,
                               trail);
}

HTTPCode SubscriberManager::deregister_with_hss(const std::string& aor_id,
                                                const std::string& dereg_reason,
                                                const std::string& server_name,
                                                HSSConnection::irs_info& irs_info,
                                                SAS::TrailId trail)
{
  TRC_DEBUG("All bindings removed for AoR %s - deregister with HSS",
            aor_id.c_str());

  HSSConnection::irs_query irs_query;
  irs_query._public_id = aor_id;
  irs_query._req_type = dereg_reason;
  irs_query._server_name = server_name;

  return get_subscriber_state(irs_query, irs_info, trail);
}

void SubscriberManager::log_removed_bindings(
                                    const AoR* orig_aor,
                                    const std::vector<std::string>& binding_ids)
{
  if (_analytics != NULL)
  {
    for (std::string binding_id : binding_ids)
    {
      for (BindingPair binding_pair : orig_aor->bindings())
      {
        if (binding_pair.first == binding_id)
        {
          _analytics->registration(binding_pair.second->_address_of_record,
                                   binding_id,
                                   binding_pair.second->_uri,
                                   0);

          break;
        }
      }
    }
  }
}

void SubscriberManager::log_updated_bindings(const AoR* updated_aor,
                                             const Bindings& binding_pairs,
                                             int now)
{
  if (_analytics != NULL)
  {
    for (BindingPair binding_pair : binding_pairs)
    {
      if (updated_aor->_bindings.find(binding_pair.first) !=
          updated_aor->_bindings.end())
      {
        _analytics->registration(binding_pair.second->_address_of_record,
                                 binding_pair.first,
                                 binding_pair.second->_uri,
                                 binding_pair.second->_expires - now);
      }
    }
  }
}

void SubscriberManager::log_subscriptions(std::string default_impu,
                                          const AoR* orig_aor,
                                          const AoR* updated_aor,
                                          const std::vector<std::string>& subscription_ids,
                                          int now)
{
  if (_analytics != NULL)
  {
    for (std::string subscription_id : subscription_ids)
    {
      Subscriptions::const_iterator subscription =
                                updated_aor->_subscriptions.find(subscription_id);

      // We need to find the subscription in the AoR in order to pull out
      // sufficient information to make a log about the changes.
      if (subscription != updated_aor->_subscriptions.end())
      {
        _analytics->subscription(default_impu,
                                 (*subscription).second->_to_tag,
                                 (*subscription).second->_req_uri,
                                 (*subscription).second->_expires - now);
      }
      else
      {
        Subscriptions::const_iterator subscription =
                                   orig_aor->_subscriptions.find(subscription_id);

        if (subscription != orig_aor->_subscriptions.end())
        {
          _analytics->subscription(default_impu,
                                   (*subscription).second->_to_tag,
                                   (*subscription).second->_req_uri,
                                   0);
        }
      }
    }
  }
}

void SubscriberManager::build_patch(PatchObject& po,
                                    const Bindings& update_bindings,
                                    const std::vector<std::string>& remove_bindings,
                                    const std::vector<std::string>& remove_subscriptions,
                                    const AssociatedURIs& associated_uris)
{
  po.set_update_bindings(AoRUtils::copy_bindings(update_bindings));
  po.set_remove_bindings(remove_bindings);
  po.set_remove_subscriptions(remove_subscriptions);
  po.set_associated_uris(associated_uris);
  po.set_increment_cseq(true);
}

void SubscriberManager::build_patch(PatchObject& po,
                                    const Bindings& update_bindings,
                                    const AssociatedURIs& associated_uris)
{
  po.set_update_bindings(AoRUtils::copy_bindings(update_bindings));
  po.set_associated_uris(associated_uris);
}

void SubscriberManager::build_patch(PatchObject& po,
                                    const Subscriptions& update_subscriptions,
                                    const std::vector<std::string>& remove_subscriptions,
                                    const AssociatedURIs& associated_uris)
{
  po.set_update_subscriptions(AoRUtils::copy_subscriptions(update_subscriptions));
  po.set_remove_subscriptions(remove_subscriptions);
  po.set_associated_uris(associated_uris);
  po.set_increment_cseq(true);
}

void SubscriberManager::build_patch(PatchObject& po,
                                    const std::vector<std::string>& remove_bindings,
                                    const std::vector<std::string>& remove_subscriptions,
                                    const AssociatedURIs& associated_uris)
{
  po.set_remove_bindings(remove_bindings);
  po.set_remove_subscriptions(remove_subscriptions);
  po.set_associated_uris(associated_uris);
  po.set_increment_cseq(true);
}

void SubscriberManager::build_patch(PatchObject& po,
                                    const std::vector<std::string>& remove_bindings,
                                    const std::vector<std::string>& remove_subscriptions)
{
  po.set_remove_bindings(remove_bindings);
  po.set_remove_subscriptions(remove_subscriptions);
  po.set_increment_cseq(true);
}

void SubscriberManager::build_patch(PatchObject& po,
                                    const AssociatedURIs& associated_uris)
{
  po.set_associated_uris(associated_uris);
  po.set_increment_cseq(true);
}
