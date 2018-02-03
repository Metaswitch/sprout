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

#include "base_subscriber_manager.h"
#include "subscriber_manager.h"
#include "aor_utils.h"
#include "pjutils.h"

SubscriberManager::SubscriberManager(S4* s4,
                                     HSSConnection* hss_connection,
                                     AnalyticsLogger* analytics_logger,
                                     NotifySender* notify_sender) :
  _s4(s4),
  _hss_connection(hss_connection),
  _analytics(analytics_logger),
  _notify_sender(notify_sender)
{
  if (_s4 != NULL)
  {
    TRC_DEBUG("Initialising S4 with reference to this subscriber manager");
    _s4->initialise(this);
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
                                                SAS::TrailId trail)
{
  TRC_DEBUG("Registering AoR %s for the first time", aor_id.c_str());

  // We are registering a subscriber for the first time, so there is no stored
  // AoR. PUT the new bindings to S4.
  AoR* orig_aor = NULL;
  AoR* updated_aor = NULL;
  HTTPCode rc = put_bindings(aor_id,
                             add_bindings,
                             associated_uris,
                             server_name,
                             updated_aor,
                             trail);

  // The PUT failed, so return.
  if (rc != HTTP_OK)
  {
    TRC_DEBUG("Registering AoR %s failed with return code %d",
              aor_id.c_str(),
              rc);

    delete orig_aor; orig_aor = NULL;
    delete updated_aor; updated_aor = NULL;
    return rc;
  }

  // Get all bindings to return to the caller
  all_bindings = AoRUtils::copy_bindings(updated_aor->bindings());

  // Send NOTIFYs and write audit logs.
  //send_notifys_and_write_audit_logs(aor_id,
    //                                EventTrigger::USER,
      //                              orig_aor,
        //                            updated_aor,
         //                           trail);

  // Update HSS if all bindings expired.
  // TODO make sure this is impossible before deleting.
  /*if (all_bindings.empty())
  {
    rc = deregister_with_hss(aor_id,
                             HSSConnection::DEREG_USER,
                             irs_query._server_name,
                             irs_info,
                             trail);
  }*/

  // Send 3rd party REGISTERs.

  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;

  return HTTP_OK;
}

HTTPCode SubscriberManager::reregister_subscriber(const std::string& aor_id,
                                                  const AssociatedURIs& associated_uris,
                                                  const Bindings& updated_bindings,
                                                  const std::vector<std::string>& binding_ids_to_remove,
                                                  Bindings& all_bindings,
                                                  HSSConnection::irs_info& irs_info,
                                                  SAS::TrailId trail)
{
  TRC_DEBUG("Reregistering AoR %s", aor_id.c_str());

  // Get the current AoR from S4.
  AoR* orig_aor = NULL;
  uint64_t unused_version;
  HTTPCode rc = _s4->handle_get(aor_id,
                                &orig_aor,
                                unused_version,
                                trail);

  // We are reregistering a subscriber, so there must be an existing AoR in the
  // store.
  // TODO retry with PUT if GET returns 404 Not Found
  if (rc != HTTP_OK)
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

  // PATCH the existing AoR.
  AoR* updated_aor = NULL;
  rc = patch_bindings(aor_id,
                      updated_bindings,
                      binding_ids_to_remove,
                      subscription_ids_to_remove,
                      associated_uris,
                      updated_aor,
                      trail);

  // The PATCH failed, so return.
  if (rc != HTTP_OK)
  {
    TRC_DEBUG("Reregistering AoR %s failed during PATCH with return code %d",
              aor_id.c_str(),
              rc);
    delete orig_aor; orig_aor = NULL;
    delete updated_aor; updated_aor = NULL;
    return rc;
  }

  // SS5-TODO: log increased bindings/subscriptions.

  // Get all bindings to return to the caller
  all_bindings = AoRUtils::copy_bindings(updated_aor->bindings());

  // Send NOTIFYs and write audit logs.
//  send_notifys(aor_id,
  //             SubscriberDataUtils::EventTrigger::USER,
    //           orig_aor,
      //         updated_aor,
        //       trail);

  // Update HSS if all bindings expired.
  if (all_bindings.empty())
  {
    rc = deregister_with_hss(aor_id,
                             HSSConnection::DEREG_USER,
                             updated_aor->_scscf_uri,
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
                                            const SubscriberDataUtils::EventTrigger& event_trigger,
                                            Bindings& bindings,
                                            SAS::TrailId trail)
{
  TRC_DEBUG("Removing bindings from IMPU %s", public_id.c_str());

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
    TRC_DEBUG("Removing bindings for AoR %s failed during PATCH with return code %s",
              aor_id.c_str(),
              rc);
    delete orig_aor; orig_aor = NULL;
    delete updated_aor; updated_aor = NULL;
    return rc;
  }

  // Get all bindings to return to the caller
  bindings = AoRUtils::copy_bindings(updated_aor->bindings());

  // Send NOTIFYs for removed bindings.
//  send_notifys_and_write_audit_logs(aor_id,
 //                                   event_trigger,
  //                                  orig_aor,
   //                                 updated_aor,
    //                                trail);

  // Update HSS if all bindings expired.
  if (bindings.empty())
  {
    std::string dereg_reason = (event_trigger == SubscriberDataUtils::EventTrigger::USER) ?
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
  TRC_DEBUG("Updating subscription for IMPU %s", public_id.c_str());
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
  TRC_DEBUG("Removing subscription for IMPU %s", public_id.c_str());
  return modify_subscription(public_id,
                             SubscriptionPair(),
                             subscription_id,
                             irs_info,
                             trail);
}

HTTPCode SubscriberManager::deregister_subscriber(const std::string& public_id,
                                                  const SubscriberDataUtils::EventTrigger& event_trigger,
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

  // Get the original AoR from S4.
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

  // Send NOTIFYs and write audit logs.
//  send_notifys_and_write_audit_logs(aor_id,
//                                    event_trigger,
//                                    orig_aor,
//                                    NULL,
 //                                   trail);

  // Deregister with HSS.
  std::string dereg_reason = (event_trigger == SubscriberDataUtils::EventTrigger::USER) ?
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

HTTPCode SubscriberManager::get_bindings(const std::string& aor_id,
                                         Bindings& bindings,
                                         SAS::TrailId trail)
{
  TRC_DEBUG("Retrieving bindings for AoR %s",
            aor_id.c_str());

  // TODO make sure all client call this function with the AoR ID.

  // Get the current AoR from S4.
  // TODO make sure this only returns not expired bindings.
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
  bindings = AoRUtils::copy_bindings(aor->bindings());

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
  // TODO make sure this only returns not expired subscriptions.
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

  AoR* updated_aor = NULL;
  rc = patch_associated_uris(aor_id,
                             associated_uris,
                             updated_aor,
                             trail);

  if (rc != HTTP_OK)
  {
    TRC_DEBUG("Updating associated URIs for AoR %s failed during PATCH with return code %d",
              aor_id.c_str(),
              rc);
    delete orig_aor; orig_aor = NULL;
    return rc;
  }

  // Send NOTIFYs and write audit logs.
//  send_notifys_and_write_audit_logs(aor_id,
 //                                   SubscriberDataUtils::EventTrigger::ADMIN,
  //                                  orig_aor,
   //                                 updated_aor,
    //                                trail);

  // Send 3rd party REGISTERs?

  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;

  return HTTP_OK;
}

void SubscriberManager::handle_timer_pop(const std::string& aor_id,
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

  // Send a PATCH to remove any expired bindings and subscriptions.
  AoR* updated_aor = NULL;
  if ((!binding_ids_to_remove.empty()) ||
      (!subscription_ids_to_remove.empty()))
  {
    rc = patch_bindings_and_subscriptions(aor_id,
                                          binding_ids_to_remove,
                                          subscription_ids_to_remove,
                                          updated_aor,
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

  // TODO NOTIFYs, 3rd party (de)registrations, update HSS.

  delete orig_aor; orig_aor = NULL;
  delete updated_aor; updated_aor = NULL;
}

HTTPCode SubscriberManager::modify_subscription(const std::string& public_id,
                                                const SubscriptionPair& update_subscription,
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
    TRC_DEBUG("Modifying subscription for AoR %s failed during GET with return code %s",
              aor_id.c_str(),
              rc);
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
    TRC_DEBUG("Modifying subscription for AoR %s failed during PATCH with return code %s",
              aor_id.c_str(),
              rc);
    delete orig_aor; orig_aor = NULL;
    return rc;
  }

  log_subscriptions(aor_id,
                    orig_aor,
                    updated_aor,
                    (remove_subscription == "") ? update_subscription.first : remove_subscription,
                    now);

  // Finally, send any NOTIFYs.
  send_notifys(aor_id,
               orig_aor,
               updated_aor,
               SubscriberDataUtils::EventTrigger::USER,
               now,
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
    TRC_DEBUG("Failed to get cached default ID for IMPU %s with return code %d",
              public_id.c_str(),
              rc);
    return rc;
  }

  // Get the aor_id from the associated URIs.
  if (!irs_info._associated_uris.get_default_impu(aor_id, false))
  {
    // TODO No default IMPU - what should we do here? Probably bail out.
    TRC_ERROR("No Default ID in IRS for IMPU %s", public_id.c_str());
    return HTTP_BAD_REQUEST;
  }

  return rc;
}

HTTPCode SubscriberManager::put_bindings(const std::string& aor_id,
                                         const Bindings& update_bindings,
                                         const AssociatedURIs& associated_uris,
                                         const std::string& scscf_uri,
                                         AoR*& aor,
                                         SAS::TrailId trail)
{
  // Create a patch object and apply it to an AoR, then PUT the AoR to S4.
  PatchObject patch_object;
  patch_object.set_update_bindings(AoRUtils::copy_bindings(update_bindings));
  patch_object.set_associated_uris(associated_uris);
  patch_object.set_increment_cseq(true);

  aor = new AoR(aor_id);
  aor->patch_aor(patch_object);
  aor->_scscf_uri = scscf_uri;
  HTTPCode rc = _s4->handle_put(aor_id,
                                *aor,
                                trail);

  // TODO don't we need the original AoR for Audit logs?
  // If the PUT returned 412 Precondition Failed, something must have added data
  // for this AoR since we decided to send a PUT. Retry with a PATCH.
  if (rc == HTTP_PRECONDITION_FAILED)
  {
    TRC_DEBUG("PUT for AoR %s failed with 412 Precondition Failed - retry with PATCH",
              aor_id.c_str());

    // Delete the AoR we created. S4 will retun an AoR once the patch is applied.
    delete aor; aor = NULL;
    rc = _s4->handle_patch(aor_id,
                           patch_object,
                           &aor,
                           trail);
  }

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

HTTPCode SubscriberManager::patch_bindings_and_subscriptions(const std::string& aor_id,
                                                             const std::vector<std::string>& remove_bindings,
                                                             const std::vector<std::string>& remove_subscriptions,
                                                             AoR*& aor,
                                                             SAS::TrailId trail)
{
  PatchObject patch_object;
  patch_object.set_remove_bindings(remove_bindings);
  patch_object.set_remove_subscriptions(remove_subscriptions);
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

  _notify_sender->send_notifys(aor_id,
                               orig_aor,
                               updated_aor,
                               event_trigger,
                               now,
                               trail);
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
                                          std::string subscription_id,
                                          int now)
{
  if (_analytics != NULL)
  {
    Subscriptions::const_iterator subscription =
                              updated_aor->_subscriptions.find(subscription_id);

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
