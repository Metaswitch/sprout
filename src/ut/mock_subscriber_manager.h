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

  MOCK_METHOD3(get_bindings, HTTPCode(std::string public_id,
                                      std::vector<Binding>& bindings,
                                      SAS::TrailId trail));

  MOCK_METHOD3(update_associated_uris, HTTPCode(std::string aor_id,
                                                AssociatedURIs associated_uris,
                                                SAS::TrailId trail));

  MOCK_METHOD4(remove_bindings, HTTPCode(std::vector<std::string> binding_ids,
                                         EventTrigger event_trigger,
                                         std::vector<Binding>& bindings,
                                         SAS::TrailId trail));

  MOCK_METHOD3(get_cached_subscriber_state, HTTPCode(std::string public_id,
                                                     SubscriberInfo& subscriber_info,
                                                     SAS::TrailId trail));

  MOCK_METHOD4(get_bindings_and_subscriptions, HTTPCode(std::string public_id,
                                                        std::vector<Binding>& bindings,
                                                        std::vector<Subscription>& subscriptions,
                                                        SAS::TrailId trail));
};

#endif

