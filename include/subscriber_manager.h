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

// SDM-REFACTOR-TODO: Add Doxygen comments.
class SubscriberManager
{
public:
  enum EventTrigger
  {
    USER,
    ADMIN
  };

  struct SubscriberInfo
  {
    std::string _regstate;
    std::string _prev_regstate;
    std::map<std::string, Ifcs> _service_profiles;
    AssociatedURIs _associated_uris;
    std::vector<std::string> _aliases;
    std::deque<std::string> _ccfs;
    std::deque<std::string> _ecfs;

    SubscriberInfo() :
      _regstate(""),
      _prev_regstate(""),
      _service_profiles(),
      _associated_uris({}),
      _aliases(),
      _ccfs(),
      _ecfs()
    {
    }
  };

  /// SubscriberManager constructor.
  ///
  /// @param s4                 - Pointer to the underlying data store interface
  ///                             SDM-REFACTOR-TODO: We don't know what this looks like yet. Add it in when we do.
  /// @param hss_connection     -
  /// @param analytics_logger   - AnalyticsLogger for reporting registration events
  SubscriberManager(HSSConnection* hss_connection,
                    AnalyticsLogger* analytics_logger);

  /// Destructor.
  virtual ~SubscriberManager();

  bool update_binding(const Binding& binding,
                      std::vector<Binding>& bindings,
                      SAS::TrailId trail) { return true; }

  bool remove_bindings(std::vector<std::string> binding_ids,
                       EventTrigger event_trigger,
                       std::vector<Binding>& bindings,
                       SAS::TrailId trail) { return true; }

  bool update_subscription(const Subscription& subscription,
                           SAS::TrailId trail) { return true; }

  bool remove_subscription(std::string subscription_id,
                           SAS::TrailId trail) { return true; }

  bool deregister_subscriber(std::string public_id,
                             EventTrigger event_trigger,
                             SAS::TrailId trail) { return true; }

  bool get_bindings(std::string public_id,
                    std::vector<Binding>& bindings,
                    SAS::TrailId trail) { return true; }

  bool get_subscriber_state(std::string public_id,
                            SubscriberInfo& subscriber_info,
                            SAS::TrailId trail) { return true; }

private:
  AnalyticsLogger* _analytics;
  HSSConnection* _hss_connection;
};

#endif
