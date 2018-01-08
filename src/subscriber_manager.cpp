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

SubscriberManager::SubscriberManager(HSSConnection* hss_connection,
                                     AnalyticsLogger* analytics_logger) :
  _hss_connection(hss_connection),
  _analytics(analytics_logger)
{
}

SubscriberManager::~SubscriberManager()
{
}
