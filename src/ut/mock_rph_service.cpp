/**
 * @file mock_rph_service.h
 * Mocks out parsing RPH configuration.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "mock_rph_service.h"

MockRPHService::MockRPHService() :
  RPHService(NULL)
{}

MockRPHService::~MockRPHService()
{}
