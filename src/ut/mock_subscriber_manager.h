/**
 * @file mock_subscriber_manager.h
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef MOCK_SUBSCRIBER_MANAGER_H_
#define MOCK_SUBSCRIBER_MANAGER_H_

#include "gmock/gmock.h"
#include "subscriber_manager.h"

class MockSubscriberManager : public SubscriberManager
{
public:
  MockSubscriberManager();
  virtual ~MockSubscriberManager();

  MOCK_METHOD6(update_bindings, HTTPCode(const HSSConnection::irs_query& irs_query,
                                         const AoR::Bindings& updated_bindings,
                                         const std::vector<std::string>& binding_ids_to_remove,
                                         AoR::Bindings& all_bindings,
                                         HSSConnection::irs_info& irs_info,
                                         SAS::TrailId trail));

  MOCK_METHOD5(remove_bindings_with_default_id, HTTPCode(const std::string& aor_id,
                                                         const std::vector<std::string>& binding_ids,
                                                         const EventTrigger& event_trigger,
                                                         AoR::Bindings& bindings,
                                                         SAS::TrailId trail));

  MOCK_METHOD4(update_subscription, HTTPCode(const std::string& public_id,
                                             const Subscription& subscription,
                                             HSSConnection::irs_info& irs_info,
                                             SAS::TrailId trail));

  MOCK_METHOD4(remove_subscription, HTTPCode(const std::string& public_id,
                                             const std::string& subscription_id,
                                             HSSConnection::irs_info& irs_info,
                                             SAS::TrailId trail));

  MOCK_METHOD3(deregister_subscriber, HTTPCode(const std::string& public_id,
                                               const EventTrigger& event_trigger,
                                               SAS::TrailId trail));

  MOCK_METHOD3(get_bindings, HTTPCode(const std::string& public_id,
                                      std::map<std::string, Binding*>& bindings,
                                      SAS::TrailId trail));

  MOCK_METHOD3(get_subscriptions, HTTPCode(const std::string& public_id,
                                           std::map<std::string, Subscription*>& subscriptions,
                                           SAS::TrailId trail));

  MOCK_METHOD3(get_cached_subscriber_state, HTTPCode(const std::string& public_id,
                                                     HSSConnection::irs_info& irs_info,
                                                     SAS::TrailId trail));

  MOCK_METHOD3(get_subscriber_state, HTTPCode(const HSSConnection::irs_query& irs_query,
                                              HSSConnection::irs_info& irs_info,
                                              SAS::TrailId trail));

  MOCK_METHOD3(update_associated_uris, HTTPCode(const std::string& aor_id,
                                                const AssociatedURIs& associated_uris,
                                                SAS::TrailId trail));
};

#endif
