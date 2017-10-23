/**
 * @file mock_subscriber_data_manager.h
 *
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef MOCK_SUBSCRIBER_DATA_MANAGER_H_
#define MOCK_SUBSCRIBER_DATA_MANAGER_H_

#include "gmock/gmock.h"
#include "subscriber_data_manager.h"

class MockSubscriberDataManager : public SubscriberDataManager
{
public:
  MockSubscriberDataManager();
  virtual ~MockSubscriberDataManager();

  MOCK_METHOD2(get_aor_data, AoRPair*(const std::string& aor_id,
                                      SAS::TrailId trail));
  MOCK_METHOD5(set_aor_data, Store::Status(const std::string& aor_id,
                                           const SubscriberDataManager::EventTrigger& event_trigger,
                                           AoRPair* data,
                                           SAS::TrailId trail,
                                           bool& all_bindings_expired));
  MOCK_METHOD0(has_servers, bool());
};

#endif

