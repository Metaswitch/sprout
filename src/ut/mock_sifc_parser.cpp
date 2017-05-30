/**
 * @file mock_sifc_parser.cpp
 * Mocks out parsing shared iFC set id into list of iFCs.
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "mock_sifc_parser.h"

MockSIFCService::MockSIFCService() :
  SIFCService(NULL, NULL)
{}

MockSIFCService::~MockSIFCService()
{}

