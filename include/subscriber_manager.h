/**
 * @file subscriber_manager.h
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef SUBSCRIBER_MANAGER_H__
#define SUBSCRIBER_MANAGER_H__

extern "C" {
#include <pjsip.h>
}

#include <string>
#include <list>
#include <map>
#include <stdio.h>
#include <stdlib.h>

#include "sas.h"
#include "analyticslogger.h"
#include "associated_uris.h"
#include "hssconnection.h"
#include "ifchandler.h"
#include "aor.h"

// SDM-REFACTOR-TODO: Add Doxygen comments.
class SubscriberManager
{
public:
  enum EventTrigger
  {
    USER,
    ADMIN
  };

  /// SubscriberManager constructor.
  ///
  /// @param s4                 - Pointer to the underlying data store interface
  ///                             SDM-REFACTOR-TODO: We don't know what this looks like yet. Add it in when we do.
  /// @param hss_connection     -
  /// @param analytics_logger   - AnalyticsLogger for reporting registration events
  SubscriberManager(HSSConnection* hss_connection,
                    AnalyticsLogger* analytics_logger) {}

  /// Destructor.
  virtual ~SubscriberManager() {}

  virtual HTTPCode update_bindings(HSSConnection::irs_query irs_query,
                                   const std::vector<Binding>& updated_bindings,
                                   std::vector<std::string> binding_ids_to_remove,
                                   std::vector<Binding>& all_bindings,
                                   HSSConnection::irs_info& irs_info,
                                   SAS::TrailId trail) { return HTTP_OK; }

  virtual HTTPCode remove_bindings(std::vector<std::string> binding_ids,
                                   EventTrigger event_trigger,
                                   std::vector<Binding>& bindings,
                                   SAS::TrailId trail) { return HTTP_OK; }

  virtual HTTPCode update_subscription(std::string public_id,
                                       const Subscription& subscription,
                                       HSSConnection::irs_info& irs_info,
                                       SAS::TrailId trail) { return HTTP_OK; }

  virtual HTTPCode remove_subscription(std::string public_id,
                                       std::string subscription_id,
                                       HSSConnection::irs_info& irs_info,
                                       SAS::TrailId trail) { return HTTP_OK; }

  virtual HTTPCode deregister_subscriber(std::string public_id,
                                         EventTrigger event_trigger,
                                         SAS::TrailId trail) { return HTTP_OK; }

  virtual HTTPCode get_bindings(std::string public_id,
                                std::vector<Binding>& bindings,
                                SAS::TrailId trail) { return HTTP_OK; }

  virtual HTTPCode get_bindings_and_subscriptions(std::string public_id,
                                                  std::vector<Binding>& bindings,
                                                  std::vector<Subscription>& subscriptions,
                                                  SAS::TrailId trail) { return HTTP_OK; }

  virtual HTTPCode get_cached_subscriber_state(std::string public_id,
                                               HSSConnection::irs_info& irs_info,
                                               SAS::TrailId trail) { return HTTP_OK; }

  virtual HTTPCode get_subscriber_state(HSSConnection::irs_query irs_query,
                                        HSSConnection::irs_info& irs_info,
                                        SAS::TrailId trail) { return HTTP_OK; }

  virtual HTTPCode update_associated_uris(std::string public_id,
                                          AssociatedURIs associated_uris,
                                          SAS::TrailId trail) { return HTTP_OK; }
private:
  AnalyticsLogger* _analytics;
  HSSConnection* _hss_connection;
};

#endif
