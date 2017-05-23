/**
 * @file mock_as_communication_tracker.h
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef MOCK_AS_COMMUNICATION_TRACKER_H__
#define MOCK_AS_COMMUNICATION_TRACKER_H__

#include "gmock/gmock.h"

class MockAsCommunicationTracker : public AsCommunicationTracker
{
public:
  MockAsCommunicationTracker() : AsCommunicationTracker(NULL, NULL, NULL) {};
  ~MockAsCommunicationTracker() {}

  MOCK_METHOD1(on_success, void(const std::string&));
  MOCK_METHOD2(on_failure, void(const std::string&, const std::string&));
};

#endif

