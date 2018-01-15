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

HTTPCode SubscriberManager::update_bindings(HSSConnection::irs_query irs_query,
                                            const std::vector<Binding>& updated_bindings,
                                            std::vector<std::string> binding_ids_to_remove,
                                            std::vector<Binding>& all_bindings,
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
  for (Binding b : updated_bindings)
  {
    if (b._emergency_registration)
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
  AoR* aor = _s4->get(aor_id);
  if (aor == NULL)
  {
    // Create a brand new AoR.
  }

  //aor->add_binding(binding.get_id(), TODO add this method to the AoR.
                   //binding);

  // Write back to S4.
  // SDM-REFACTOR-TODO: We're going to write to memcached in sequence if we have
  // multiple bindings. Surely that's wrong?
  success = _s4->send_patch(aor_id, aor);
  if (!success)
  {
    // We can't do anything if we fail to write to memcached, so break out.
    return HTTP_SERVER_ERROR;
  }

  // Send NOTIFYs

  // Update HSS if all bindings expired.
  if (false)
  {
    irs_query._req_type = HSSConnection::DEREG_USER;
    get_subscriber_state(irs_query,
                         irs_info,
                         trail); // Can't do anything with the return code here.
  }

  // Send 3rd party REGISTERs.

  return HTTP_OK;
}

HTTPCode SubscriberManager::remove_bindings(std::vector<std::string> binding_ids,
                                            EventTrigger event_trigger,
                                            std::vector<Binding>& bindings,
                                            SAS::TrailId trail)
{
  return HTTP_OK;
}

HTTPCode SubscriberManager::update_subscription(std::string public_id,
                                                const Subscription& subscription,
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
  AoR* aor = _s4->get(aor_id);
  if (aor == NULL)
  {
    // Create a brand new AoR.
  }

  //aor->add_subscription(subscription.get_id(), TODO add this method to the AoR.
                        //subscription);

  // Write back to S4.
  // SDM-REFACTOR-TODO: We're going to write to memcached in sequence if we have
  // multiple bindings. Surely that's wrong?
  bool success = _s4->send_patch(aor_id, aor);
  if (!success)
  {
    // We can't do anything if we fail to write to memcached, so break out.
    return HTTP_SERVER_ERROR;
  }

  // Send NOTIFYs

  return HTTP_OK;
}

HTTPCode SubscriberManager::remove_subscription(std::string public_id,
                                                std::string subscription_id,
                                                HSSConnection::irs_info& irs_info,
                                                SAS::TrailId trail)
{
  // Same as update_subscription, except:
  //  - Subscription is removed from AoR by subscription_id index before
  //    writing back.

  return HTTP_OK;
}

HTTPCode SubscriberManager::deregister_subscriber(std::string public_id,
                                                  EventTrigger event_trigger,
                                                  SAS::TrailId trail)
{
  return HTTP_OK;
}

HTTPCode SubscriberManager::get_bindings(std::string public_id,
                                         std::vector<Binding>& bindings,
                                         SAS::TrailId trail)
{
  return HTTP_OK;
}

HTTPCode SubscriberManager::get_bindings_and_subscriptions(std::string aor_id,
                                                           std::vector<Binding>& bindings,
                                                           std::vector<Subscription>& subscriptions,
                                                           SAS::TrailId trail)
{
  // Sequence:
  // - Admin tasks will(should) provide the default public_id
  // - Lookup AoR from S4.
  // - Get bindings/subscriptions off AoR and return.

  // Get the current AoR from S4, if one exists.
  AoR* aor = _s4->get(aor_id);
  if (aor != NULL)
  {
    // Get bindings off the AoR.
    /*for (std::map<std::string, Binding*>::iterator b_it = aor->bindings().begin();
         b_it != aor->bindings().end();
         b_it++)
    {
      bindings.push_back(*b_it->second);
    }

    // Get subscriptions off the AoR.
    for (std::map<std::string, Subscription*>::iterator s_it = aor->subscriptions().begin();
         s_it != aor->subscriptions().end();
         s_it++)
    {
      subscriptions.push_back(*s_it->second);
    }*/
  }
  else
  {
    return HTTP_SERVER_ERROR;
  }

  return HTTP_OK;
}

HTTPCode SubscriberManager::get_cached_subscriber_state(std::string public_id,
                                                        HSSConnection::irs_info& irs_info,
                                                        SAS::TrailId trail)
{
  HTTPCode http_code = _hss_connection->get_registration_data(public_id,
                                                              irs_info,
                                                              trail);
  return http_code;
}

HTTPCode SubscriberManager::get_subscriber_state(HSSConnection::irs_query irs_query,
                                                 HSSConnection::irs_info& irs_info,
                                                 SAS::TrailId trail)
{
  HTTPCode http_code = _hss_connection->update_registration_state(irs_query,
                                                                  irs_info,
                                                                  trail);
  return http_code;
}

HTTPCode SubscriberManager::update_associated_uris(std::string aor_id,
                                                   AssociatedURIs associated_uris,
                                                   SAS::TrailId trail)
{
  // Sequence:
  // - PPR from HSS will provide the default public_id
  // - Lookup AoR from S4.
  // - Update associated URIs in AoR
  // - Write back to store.
  // - Send NOTIFYs

  // Get the current AoR from S4, if one exists.
  AoR* aor = _s4->get(aor_id);
  if (aor != NULL)
  {
    aor->_associated_uris = associated_uris;
  }
  else
  {
    // TODO error handling - there should be an AoR.
  }

  // Write back to S4.
  // SDM-REFACTOR-TODO: We're going to write to memcached in sequence if we have
  // multiple bindings. Surely that's wrong?
  bool success = _s4->send_patch(aor_id, aor);
  if (!success)
  {
    // We can't do anything if we fail to write to memcached, so break out.
    return HTTP_SERVER_ERROR;
  }

  // Send NOTIFYs since associated URIs are changed.

  return HTTP_OK;
}
