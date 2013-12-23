/**
 * @file pjmodule.h  C++ wrapper for PJSIP module interface
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * Parts of this module were derived from GPL licensed PJSIP sample code
 * with the following copyrights.
 *   Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 *   Copyright (C) 2003-2008 Benny Prijono <benny@prijono.org>
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version, along with the "Special Exception" for use of
 * the program along with SSL, set forth below. This program is distributed
 * in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details. You should have received a copy of the GNU General Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by
 * post at Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 *
 * Special Exception
 * Metaswitch Networks Ltd  grants you permission to copy, modify,
 * propagate, and distribute a work formed by combining OpenSSL with The
 * Software, or a work derivative of such a combination, even if such
 * copying, modification, propagation, or distribution would otherwise
 * violate the terms of the GPL. You must comply with the GPL in all
 * respects for all of the code used other than OpenSSL.
 * "OpenSSL" means OpenSSL toolkit software distributed by the OpenSSL
 * Project and licensed under the OpenSSL Licenses, or a work based on such
 * software and licensed under the OpenSSL Licenses.
 * "OpenSSL Licenses" means the OpenSSL License and Original SSLeay License
 * under which the OpenSSL Project distributes the OpenSSL toolkit software,
 * as those licenses appear in the file LICENSE-OPENSSL.
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
