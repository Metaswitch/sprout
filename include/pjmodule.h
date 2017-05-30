/**
 * @file pjmodule.h  C++ wrapper for PJSIP module interface
 *
 * Copyright (C) Metaswitch Networks 2013
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

#include <utility>
#include <functional>

class PJCallback
{
public:
  static const int ON_RX_REQUEST  = 0x00000010;
  static const int ON_RX_RESPONSE = 0x00000020;
  static const int ON_TX_REQUEST  = 0x00000040;
  static const int ON_TX_RESPONSE = 0x00000080;
  static const int ON_TSX_STATE   = 0x00000100;
};

template <class T, int I>
class PJModule : public PJCallback
{
public:
  PJModule(T* object, pjsip_endpoint* endpt, std::string name, int priority, int cbmask)
  {
    _name = name;
    _obj = object;
    _endpt = endpt;

    pj_cstr(&_mod.name, _name.c_str());
    _mod.priority = priority;
    _mod.id = -1;

    if (cbmask & ON_RX_REQUEST)
    {
      _mod.on_rx_request = &on_rx_request;
    }
    if (cbmask & ON_RX_RESPONSE)
    {
      _mod.on_rx_response = &on_rx_response;
    }
    if (cbmask & ON_TX_REQUEST)
    {
      _mod.on_tx_request = &on_tx_request;
    }
    if (cbmask & ON_TX_RESPONSE)
    {
      _mod.on_tx_response = &on_tx_response;
    }
    if (cbmask & ON_TSX_STATE)
    {
      _mod.on_tsx_state = &on_tsx_state;
    }

    pj_status_t status = pjsip_endpt_register_module(_endpt, &_mod);
    pj_assert(status == PJ_SUCCESS);
  }

  ~PJModule()
  {
    pjsip_endpt_unregister_module(_endpt, &_mod);
  }

  static pj_bool_t on_rx_request(pjsip_rx_data *rdata)
  {
    return _obj->on_rx_request(rdata);
  }

  static pj_bool_t on_rx_response(pjsip_rx_data *rdata)
  {
    return _obj->on_rx_response(rdata);
  }

  static pj_status_t on_tx_request(pjsip_tx_data *tdata)
  {
    return _obj->on_tx_request(tdata);
  }

  static pj_status_t on_tx_response(pjsip_tx_data *tdata)
  {
    return _obj->on_tx_response(tdata);
  }

  static void on_tsx_state(pjsip_transaction *tsx, pjsip_event *event)
  {
    _obj->on_tsx_state(tsx, event);
  }

  static pjsip_module* module() { return &_mod; }
  static int id() { return _mod.id; }

private:
  static std::string _name;
  static T* _obj;
  static pjsip_endpoint* _endpt;

  static pjsip_module _mod;
};

template<class T, int I>
std::string PJModule<T, I>::_name;

template<class T, int I>
T* PJModule<T, I>::_obj;

template<class T, int I>
pjsip_endpoint* PJModule<T, I>::_endpt;

template<class T, int I>
pjsip_module PJModule<T, I>::_mod;
