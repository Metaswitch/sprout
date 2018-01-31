/**
 * @file mock_notify_sender.h
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef MOCK_NOTIFY_SENDER_H_
#define MOCK_NOTIFY_SENDER_H_

#include "gmock/gmock.h"
#include "notify_sender.h"

class MockNotifySender : public NotifySender
{
public:
  MockNotifySender();
  virtual ~MockNotifySender();

  MOCK_METHOD7(send_notifys, void(const std::string& aor_id,
                                  const ClassifiedBindings& classified_bindings,
                                  const ClassifiedSubscriptions& classified_subscriptions,
                                  AssociatedURIs& associated_uris, // EM-TODO should be condst?
                                  int cseq,
                                  int now,
                                  SAS::TrailId trail));

  MOCK_METHOD6(send_notifys, void(const std::string& aor_id,
                                  const AoR* orig_aor,
                                  const AoR* updated_aor,
                                  SubscriberDataUtils::EventTrigger event_trigger,
                                  int now,
                                  SAS::TrailId trail));

};

#endif
