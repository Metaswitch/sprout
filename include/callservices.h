/**
 * @file call_services.h Interface declaration for the MMTel call services module
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
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

///
///

#ifndef CALLSERVICES_H__
#define CALLSERVICES_H__

#include <string>

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

#include "rapidxml/rapidxml.hpp"

#include "xdmconnection.h"
#include "simservs.h"

// forward declaration
class UASTransaction;

class CallServices
{
public:
  CallServices(XDMConnection* xdm_client);
  ~CallServices();

  bool is_mmtel(std::string uri);

  class CallServiceBase
  {
  public:
    CallServiceBase(std::string country_code, UASTransaction* uas_data);
    ~CallServiceBase();

  protected:
    std::string _country_code;
    UASTransaction* _uas_data;
    simservs* _user_services;
    bool apply_call_barring(const std::vector<simservs::CBRule>* ruleset,
                            pjsip_tx_data* tx_data);
    bool check_cb_rule(const simservs::CBRule& rule, pjsip_msg* msg);
  };

  class Originating : public CallServiceBase
  {
  public:
    Originating(CallServices* callServices,
                UASTransaction* uas_data,
                pjsip_msg* msg,
                std::string served_user);
    ~Originating();

    bool on_initial_invite(pjsip_tx_data* tx_data);

  private:

    bool apply_privacy(pjsip_tx_data* tx_data);
    bool apply_ob_call_barring(pjsip_tx_data* tx_data);
  };
  friend class Originating;

  class Terminating : public CallServiceBase
  {
  public:
    Terminating(CallServices* callServices,
                UASTransaction* uas_data,
                pjsip_msg* msg,
                std::string served_user);
    ~Terminating();

    bool on_initial_invite(pjsip_tx_data* tx_data);
    bool on_response(pjsip_msg* tx_data);
    bool on_final_response(pjsip_tx_data* tx_data);

  private:
    bool _ringing;
    unsigned int _media_conditions;
    pj_timer_entry _no_reply_timer;

    bool apply_privacy(pjsip_tx_data* tx_data);
    bool apply_call_diversion(unsigned int conditions, int code);
    bool apply_ib_call_barring(pjsip_tx_data* tx_data);
    bool check_call_diversion_rules(unsigned int conditions, int code);
    unsigned int condition_from_status(int code);
    void no_reply_timer_pop();

    static void no_reply_timer_pop(pj_timer_heap_t *timer_heap, pj_timer_entry *entry);
  };
  friend class Terminating;

  static const int DEFAULT_MAX_FORWARDS = 70;

private:
  XDMConnection* _xdmc;
  std::string _mmtel_uri; //< URI of built-in MMTEL AS.

  simservs *get_user_services(pjsip_msg *msg, std::string public_id, SAS::TrailId trail);

  static int parse_privacy_headers(pjsip_generic_array_hdr *header_array);
  static void build_privacy_header(pjsip_tx_data *tx_data, int fields);
  static unsigned int get_media_type_conditions(pjsip_msg *msg);
};

#endif
