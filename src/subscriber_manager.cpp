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

SubscriberManager::SubscriberManager(S4* s4,
                                     HSSConnection* hss_connection,
                                     AnalyticsLogger* analytics_logger) :
  _s4(s4),
  _hss_connection(hss_connection),
  _analytics(analytics_logger)
{
}

SubscriberManager::~SubscriberManager()
{
}

HTTPCode SubscriberManager::update_bindings(const HSSConnection::irs_query& irs_query,
                                            const std::map<std::string, Binding*>& updated_bindings,
                                            const std::vector<std::string>& binding_ids_to_remove,
                                            std::map<std::string, Binding*>& all_bindings,
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
  for (std::pair<std::string, Binding*> b : updated_bindings)
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
  AoR* aor = NULL;
  uint64_t version;
  rc = _s4->handle_get(aor_id,
                       &aor,
                       version,
                       trail);

  // It is valid to return HTTP_NOT_FOUND since there will not be a stored AoR
  // when an IRS is first registered.
  if ((rc != HTTP_OK) && (rc != HTTP_NOT_FOUND))
  {
    return rc;
  }

  delete aor; aor = NULL;

  rc = patch_bindings(aor_id,
                      updated_bindings,
                      binding_ids_to_remove,
                      aor,
                      trail);
  if (rc != HTTP_OK)
  {
    return rc;
  }

  // Get all bindings to return to the caller
  populate_bindings(aor, all_bindings);

  // Send NOTIFYs

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

  delete aor; aor = NULL;

  return HTTP_OK;
}

HTTPCode SubscriberManager::remove_bindings(const std::string& public_id,
                                            const std::vector<std::string>& binding_ids,
                                            const EventTrigger& event_trigger,
                                            std::map<std::string, Binding*>& bindings,
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

  // Get the current AoR from S4.
  AoR* aor = NULL;
  uint64_t version;
  rc = _s4->handle_get(aor_id,
                       &aor,
                       version,
                       trail);

  // If there is no AoR, we still count that as a success.
  if ((rc != HTTP_OK) && (rc != HTTP_NOT_FOUND))
  {
    return rc;
  }

  delete aor; aor = NULL;

  rc = patch_bindings(aor_id,
                      {},
                      binding_ids,
                      aor,
                      trail);
  if (rc != HTTP_OK)
  {
    return rc;
  }

  // Get all bindings to return to the caller
  populate_bindings(aor, bindings);

  // Send NOTIFYs for removed bindings.

  // Update HSS if all bindings expired.
  if (bindings.empty())
  {
    std::string dereg_reason = (event_trigger == EventTrigger::USER) ?
                                 HSSConnection::DEREG_USER : HSSConnection::DEREG_ADMIN;
    rc = deregister_with_hss(aor_id,
                             dereg_reason,
                             aor->_scscf_uri,
                             irs_info,
                             trail);

    // Send 3rd party deREGISTERs.
  }
  else
  {
    // Send 3rd party REGISTERs
  }

  delete aor; aor = NULL;

  return HTTP_OK;
}

HTTPCode SubscriberManager::update_subscription(const std::string& public_id,
                                                const std::pair<std::string, Subscription*>& subscription,
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
                             {},
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

  // Get the current AoR from S4.
  AoR* aor = NULL;
  uint64_t version;
  rc = _s4->handle_get(aor_id,
                       &aor,
                       version,
                       trail);

  // If there is no AoR, we still count that as a success.
  if ((rc != HTTP_OK) && (rc != HTTP_NOT_FOUND))
  {
    if (rc == HTTP_NOT_FOUND)
    {
      return HTTP_OK;
    }

    return rc;
  }

  rc = _s4->handle_local_delete(aor_id,
                                version,
                                trail);

  // Send NOTIFYs for removed binding.

  // Deregister with HSS.
  std::string dereg_reason = (event_trigger == EventTrigger::USER) ?
                               HSSConnection::DEREG_USER : HSSConnection::DEREG_ADMIN;
  rc = deregister_with_hss(aor_id,
                           dereg_reason,
                           aor->_scscf_uri,
                           irs_info,
                           trail);

  // Send 3rd party deREGISTERs.

  delete aor; aor = NULL;
  return HTTP_OK;
}

HTTPCode SubscriberManager::get_bindings(const std::string& public_id,
                                         std::map<std::string, Binding*>& bindings,
                                         SAS::TrailId trail)
{
  // Get the current AoR from S4.
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
  populate_bindings(aor, bindings);

  delete aor; aor = NULL;
  return HTTP_OK;
}

HTTPCode SubscriberManager::get_subscriptions(const std::string& public_id,
                                              std::map<std::string, Subscription*>& subscriptions,
                                              SAS::TrailId trail)
{
  // Get the current AoR from S4.
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
  populate_subscriptions(aor, subscriptions);

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
  // Get the current AoR from S4.
  AoR* aor = NULL;
  uint64_t version;
  HTTPCode rc = _s4->handle_get(aor_id,
                                &aor,
                                version,
                                trail);

  if (rc != HTTP_OK)
  {
    // TODO error handling.
    return rc;
  }

  rc = patch_associated_uris(aor_id,
                             associated_uris,
                             aor,
                             trail);
  if (rc != HTTP_OK)
  {
    return rc;
  }

  delete aor; aor = NULL;

  // Send NOTIFYs since associated URIs are changed.

  return HTTP_OK;
}

HTTPCode SubscriberManager::modify_subscription(const std::string& public_id,
                                                const std::pair<std::string, Subscription*>& update_subscription,
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
  AoR* aor = NULL;
  uint64_t version;
  rc = _s4->handle_get(aor_id,
                       &aor,
                       version,
                       trail);

  // There must be an existing AoR since there must be bindings to subscribe to.
  if (rc != HTTP_OK)
  {
    return rc;
  }

  delete aor; aor = NULL;

  rc = patch_subscription(aor_id,
                          update_subscription,
                          remove_subscription,
                          aor,
                          trail);
  if (rc != HTTP_OK)
  {
    return rc;
  }

  // Send NOTIFYs

  delete aor; aor = NULL;

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

HTTPCode SubscriberManager::patch_bindings(const std::string& aor_id,
                                           const std::map<std::string, Binding*>& update_bindings,
                                           const std::vector<std::string>& remove_bindings,
                                           AoR*& aor,
                                           SAS::TrailId trail)
{
  PatchObject* patch_object = new PatchObject();
  patch_object->set_update_bindings(update_bindings);
  patch_object->set_remove_bindings(remove_bindings);
  HTTPCode rc = _s4->handle_patch(aor_id,
                                  patch_object,
                                  &aor,
                                  trail);
  delete patch_object; patch_object = NULL;

  return rc;
}

HTTPCode SubscriberManager::patch_subscription(const std::string& aor_id,
                                               const std::pair<std::string, Subscription*>& update_subscription,
                                               const std::string& remove_subscription,
                                               AoR*& aor,
                                               SAS::TrailId trail)
{
  PatchObject* patch_object = new PatchObject();
  patch_object->set_update_subscriptions({update_subscription});
  patch_object->set_remove_subscriptions({remove_subscription});
  HTTPCode rc = _s4->handle_patch(aor_id,
                                  patch_object,
                                  &aor,
                                  trail);
  delete patch_object; patch_object = NULL;

  return rc;
}

HTTPCode SubscriberManager::patch_associated_uris(const std::string& aor_id,
                                                  const AssociatedURIs& associated_uris,
                                                  AoR*& aor,
                                                  SAS::TrailId trail)
{
  PatchObject* patch_object = new PatchObject();
  patch_object->set_associated_uris(associated_uris);
  HTTPCode rc = _s4->handle_patch(aor_id,
                                  patch_object,
                                  &aor,
                                  trail);
  delete patch_object; patch_object = NULL;

  return rc;
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

void SubscriberManager::populate_bindings(AoR* aor,
                                          std::map<std::string, Binding*>& bindings)
{
   for (std::pair<std::string, Binding*> b : aor->bindings())
  {
    Binding* copy_b = new Binding(*(b.second));
    bindings.insert(std::make_pair(b.first, copy_b));
  }
}

void SubscriberManager::populate_subscriptions(AoR* aor,
                                               std::map<std::string, Subscription*>& subscriptions)
{
  for (std::pair<std::string, Subscription*> s : aor->subscriptions())
  {
    Subscription* copy_s = new Subscription(*(s.second));
    subscriptions.insert(std::make_pair(s.first, copy_s));
  }
}
