/**
 * @file mock_pjsip_module.h Mock PJSip module.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


#ifndef MOCK_PJSIP_MODULE_H__
#define MOCK_PJSIP_MODULE_H__

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

#include "gmock/gmock.h"
#include "pjmodule.h"


class MockPJSipModule
{
public:
  MockPJSipModule(pjsip_endpoint* endpt,
                  std::string name,
                  int priority) :
    _mod_mock(this, endpt, name, priority, PJMODULE_ALL)
  {
  }

  MOCK_METHOD1(on_rx_request, pj_bool_t(pjsip_rx_data *rdata));
  MOCK_METHOD1(on_rx_response, pj_bool_t(pjsip_rx_data *rdata));
  MOCK_METHOD1(on_tx_request, pj_status_t(pjsip_tx_data *tdata));
  MOCK_METHOD1(on_tx_response, pj_status_t(pjsip_tx_data *tdata));
  MOCK_METHOD2(on_tsx_state, void(pjsip_transaction *tsx, pjsip_event *event));

protected:
  static const int PJMODULE_ALL = PJCallback::ON_RX_REQUEST|
                                  PJCallback::ON_RX_RESPONSE|
                                  PJCallback::ON_TX_REQUEST|
                                  PJCallback::ON_TX_RESPONSE|
                                  PJCallback::ON_TSX_STATE;

  PJModule<MockPJSipModule, 1> _mod_mock;
};

#endif
