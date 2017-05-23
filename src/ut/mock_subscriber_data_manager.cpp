/**
 * @file mock_subscriber_data_manager.cpp
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "mock_subscriber_data_manager.h"

MockSubscriberDataManager::MockSubscriberDataManager() : 
  SubscriberDataManager(NULL, NULL, true) 
{}

MockSubscriberDataManager::~MockSubscriberDataManager()
{}
