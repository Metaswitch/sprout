/**
 * @file mmtel.h Interface declaration for the MMTel call service
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

#ifndef MMTEL_H__
#define MMTEL_H__

#include <string>

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

#include "rapidxml/rapidxml.hpp"

#include "appserver.h"
#include "xdmconnection.h"
#include "simservs.h"
#include "aschain.h"
#include "counter.h"

class CDivCallback
{
public:
  virtual void cdiv_callback(std::string target, unsigned int conditions) = 0;
};

class Mmtel : public AppServer
{
public:
  Mmtel(const std::string& service_name,
        XDMConnection* xdm_client) :
    AppServer(service_name),
    _xdmc(xdm_client) {};

  AppServerTsx* get_app_tsx(SproutletHelper* helper,
                            pjsip_msg* req,
                            pjsip_sip_uri*& next_hop,
                            pj_pool_t* pool,
                            SAS::TrailId trail);

private:
  XDMConnection* _xdmc;

  simservs *get_user_services(std::string public_id, SAS::TrailId trail);
};

// Cut-down AS that invokes MMTEL-style call diversion configured through
// parameters encoded on the AS URI.
class CallDiversionAS : public AppServer, CDivCallback
{
public:
  CallDiversionAS(const std::string& service_name);
  virtual ~CallDiversionAS();

  AppServerTsx* get_app_tsx(SproutletHelper* helper,
                            pjsip_msg* req,
                            pjsip_sip_uri*& next_hop,
                            pj_pool_t* pool,
                            SAS::TrailId trail);
  virtual void cdiv_callback(std::string target,
                             unsigned int conditions);

private:
  StatisticCounter _cdiv_total_stat;
  StatisticCounter _cdiv_unconditional_stat;
  StatisticCounter _cdiv_busy_stat;
  StatisticCounter _cdiv_not_registered_stat;
  StatisticCounter _cdiv_no_answer_stat;
  StatisticCounter _cdiv_not_reachable_stat;
};

class MmtelTsx : public AppServerTsx
{
public:
  MmtelTsx(pjsip_msg* req,
           simservs* user_services,
           SAS::TrailId trail,
           CDivCallback* cdiv_callback = NULL);
  ~MmtelTsx();

  void on_initial_request(pjsip_msg* req);
  void on_response(pjsip_msg* rsp, int fork_id);
  void on_timer_expiry(void* context);

private:
  bool _originating;
  pjsip_method_e _method;
  std::string _country_code;
  simservs* _user_services;
  CDivCallback* _cdiv_callback;
  bool _ringing;
  unsigned int _media_conditions;
  int _late_redirect_fork_id;
  TimerID _no_reply_timer;
  bool _diverted;

  pjsip_status_code apply_ob_call_barring(pjsip_msg* req);
  pjsip_status_code apply_ib_call_barring(pjsip_msg* req);
  pjsip_status_code apply_call_barring(const std::vector<simservs::CBRule>* ruleset,
                                       pjsip_msg* req);
  pjsip_status_code apply_ob_privacy(pjsip_msg* req, pj_pool_t* pool);
  pjsip_status_code apply_ib_privacy(pjsip_msg* req, pj_pool_t* pool);
  pjsip_status_code apply_cdiv_on_req(pjsip_msg* req, unsigned int conditions, pjsip_status_code code);
  bool apply_cdiv_on_rsp(pjsip_msg* rsp, unsigned int conditions, pjsip_status_code code);
  std::string check_call_diversion_rules(unsigned int conditions);
  bool check_cb_rule(const simservs::CBRule& rule, pjsip_msg* req);

  unsigned int condition_from_status(int code);
  static int parse_privacy_headers(pjsip_generic_array_hdr *header_array);
  static void build_privacy_header(pjsip_msg* req, pj_pool_t* pool, int fields);
  static unsigned int get_media_type_conditions(pjsip_msg *req);

  void no_reply_timer_pop();
};

#endif
