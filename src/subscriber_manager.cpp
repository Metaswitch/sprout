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

  // Sequence of events:
  //  - Lookup in HSS to get default public ID.
  //  - Get current AoR.
  //  - Write audit logs.
  //  - Make changes to AoR object.
  //  - Write back to store.
  //  - Write audit logs. TODO
  //  - Send NOTIFYs. TODO
  //  - Update HSS if all bindings expired. TODO
  //  - Send 3rd party registers. TODO

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
  for (AoR::Bindings::const_iterator it = updated_bindings.begin();
       it != updated_bindings.end();
       ++it)
  {
    if (it->second->_emergency_registration)
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
  if ((rc != HTTP_OK) || (rc != HTTP_NOT_FOUND))
  {
    // TODO error handling
  }

  PatchObject* patch_object = new PatchObject();
  patch_object->set_update_bindings(updated_bindings);
  patch_object->set_remove_bindings(binding_ids_to_remove);

  rc = _s4->handle_patch(aor_id,
                         patch_object,
                         &aor,
                         trail);

  // Send NOTIFYs

  // Update HSS if all bindings expired.
  if (false)
  {
    HSSConnection::irs_query irs_query_2 = irs_query;
    irs_query_2._req_type = HSSConnection::DEREG_USER;
    get_subscriber_state(irs_query,
                         irs_info,
                         trail); // Can't do anything with the return code here.
  }

  // Send 3rd party REGISTERs.

  return HTTP_OK;
}

HTTPCode SubscriberManager::remove_bindings_with_default_id(const std::string& aor_id,
                                                            const std::vector<std::string>& binding_ids,
                                                            const EventTrigger& event_trigger,
                                                            std::map<std::string, Binding*>& bindings,
                                                            SAS::TrailId trail)
{
  return HTTP_OK;
}

HTTPCode SubscriberManager::update_subscription(const std::string& public_id,
                                                Subscription* subscription,
                                                HSSConnection::irs_info& irs_info,
                                                SAS::TrailId trail)
{
  // Steps:
  //  - Get cached HSS data from public_id
  //  - Get data from S4
  //  - Update AoR with new subscription.
  //    - Maybe this should take into account whether the SUBSCRIBE event
  //      is acutally removing a subscription and not add it but delete it.
  //    - Or the Client could be responsible for this by looking at the expiry time.
  //  - Write back to S4.
  //  - Analytics.
  //  - Send NOTIFYs

  // Get HSS cached data
  HTTPCode rc = get_cached_subscriber_state(public_id,
                                            irs_info,
                                            trail);

  if (rc != HTTP_OK)
  {
    return rc;
  }

  std::string aor_id;
  if (!irs_info._associated_uris.get_default_impu(aor_id, false))
  {
    // No default IMPU so send an error response.
    return HTTP_BAD_REQUEST; // TODO - what should the return code be here?
  }

  // Get the current AoR from S4, if one exists.
  /*AoR* aor = _s4->get(aor_id);
  if (aor == NULL)
  {
    // Create a brand new AoR.
  }*/

  //aor->add_subscription(subscription.get_id(), TODO add this method to the AoR.
                        //subscription);

  // Write back to S4.
  // SDM-REFACTOR-TODO: We're going to write to memcached in sequence if we have
  // multiple bindings. Surely that's wrong?
  /*bool success = _s4->send_patch(aor_id, aor);
  if (!success)
  {
    // We can't do anything if we fail to write to memcached, so break out.
    return HTTP_SERVER_ERROR;
  }*/

  // Send NOTIFYs

  return HTTP_OK;
}

HTTPCode SubscriberManager::remove_subscription(const std::string& public_id,
                                                const std::string& subscription_id,
                                                HSSConnection::irs_info& irs_info,
                                                SAS::TrailId trail)
{
  // Same as update_subscription, except:
  //  - Subscription is removed from AoR by subscription_id index before
  //    writing back.

  return HTTP_OK;
}

HTTPCode SubscriberManager::deregister_subscriber(const std::string& public_id,
                                                  const EventTrigger& event_trigger,
                                                  SAS::TrailId trail)
{
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
  for (std::pair<std::string, Binding*> b : aor->bindings())
  {
    Binding* copy_b = new Binding(*(b.second));
    bindings.insert(std::make_pair(b.first, copy_b));
  }

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
  for (std::pair<std::string, Subscription*> s : aor->subscriptions())
  {
    Subscription* copy_s = new Subscription(*(s.second));
    subscriptions.insert(std::make_pair(s.first, copy_s));
  }

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

  PatchObject* patch_object = new PatchObject();
  patch_object->set_associated_uris(associated_uris);

  rc = _s4->handle_patch(aor_id,
                         patch_object,
                         &aor,
                         trail);

  delete patch_object; patch_object = NULL;
  delete aor; aor = NULL;

  // Send NOTIFYs since associated URIs are changed.

  return HTTP_OK;
}
