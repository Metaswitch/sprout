/**
 * @file mock_subscriber_manager.cpp
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "mock_subscriber_manager.h"

MockSubscriberManager::MockSubscriberManager() :
  SubscriberManager(NULL, NULL, NULL, NULL)
{}

MockSubscriberManager::~MockSubscriberManager()
{}
