/**
 * @file mock_sproutlet.h Mock Sproutlet
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef MOCKSPROUTLET_H__
#define MOCKSPROUTLET_H__

#include "gmock/gmock.h"
#include "sproutlet.h"

/// Mock class for Sproutlet.
class MockSproutlet : public Sproutlet
{
public:
  MockSproutlet(
      const std::string& service_name="mock-sproutlet",
      int port=0,
      const std::string& service_host="") :
    Sproutlet(service_name, port, service_host) {}

  MOCK_METHOD6(
      get_tsx,
      SproutletTsx*(SproutletProxy*, const std::string&, pjsip_msg*, pjsip_sip_uri*&, pj_pool_t*, SAS::TrailId));
};


/// Mock class for SproutletTsx.
class MockSproutletTsx : public SproutletTsx
{
public:
  MockSproutletTsx() :
    SproutletTsx(NULL)
  {
  }

  void set_helper(SproutletTsxHelper* helper)
  {
    _helper = helper;
  }

  MOCK_METHOD1(on_rx_initial_request, void(pjsip_msg*));
  MOCK_METHOD1(on_rx_in_dialog_request, void(pjsip_msg*));
  MOCK_METHOD2(on_tx_request, void(pjsip_msg*, int));
  MOCK_METHOD2(on_rx_response, void(pjsip_msg*, int));
  MOCK_METHOD1(on_tx_response, void(pjsip_msg*));
  MOCK_METHOD2(on_rx_cancel, void(int, pjsip_msg*));
  MOCK_METHOD1(on_timer_expiry, void(void*));
};

#endif
