/**
 * @file mock_sproutletproxy.hpp Mock SproutletProxy
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef MOCKSPROUTLETPROXY_H__
#define MOCKSPROUTLETPROXY_H__

#include "gmock/gmock.h"
#include "sproutletproxy.h"

// Mock class for SproutletProxy.
class MockSproutletProxy : public SproutletProxy
{
public:
  MockSproutletProxy(pjsip_endpoint* endpt) :
    SproutletProxy(endpt, 0, "", {}, {}, {}) {}
};

#endif
