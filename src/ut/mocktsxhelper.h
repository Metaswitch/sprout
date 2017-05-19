/**
 * @file mocktsxhelper.h  Mock SproutletTsxHelper interfaces.
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

#ifndef MOCKTSXHELPER_H__
#define MOCKTSXHELPER_H__

#include "gmock/gmock.h"
#include "sproutlet.h"

class MockSproutletTsxHelper : public SproutletTsxHelper
{
public:
  MockSproutletTsxHelper() {}

  const std::string& dialog_id() const {return _dialog_id;}
  std::string _dialog_id;

  SAS::TrailId trail() const {return _trail;}
  SAS::TrailId _trail;

  MOCK_METHOD0(original_request, pjsip_msg*());
  MOCK_METHOD1(copy_original_transport, void(pjsip_msg*));
  MOCK_CONST_METHOD0(route_hdr, const pjsip_route_hdr*());
  MOCK_CONST_METHOD1(get_reflexive_uri, pjsip_sip_uri*(pj_pool_t*));
  MOCK_CONST_METHOD1(is_uri_reflexive, bool(const pjsip_uri*));
  MOCK_METHOD1(add_to_dialog, void(const std::string&));
  MOCK_METHOD0(create_request, pjsip_msg*());
  MOCK_METHOD1(clone_request, pjsip_msg*(pjsip_msg*));
  MOCK_METHOD1(clone_msg, pjsip_msg*(pjsip_msg*));
  MOCK_METHOD3(create_response, pjsip_msg*(pjsip_msg*, pjsip_status_code, const std::string&));
  MOCK_METHOD1(send_request, int(pjsip_msg*&));
  MOCK_METHOD1(send_response, void(pjsip_msg*&));
  MOCK_METHOD2(cancel_fork, void(int, int));
  MOCK_METHOD1(cancel_pending_forks, void(int));
  MOCK_METHOD1(fork_state, const ForkState&(int));
  MOCK_METHOD1(free_msg, void(pjsip_msg*&));
  MOCK_METHOD1(get_pool, pj_pool_t*(const pjsip_msg*));
  MOCK_METHOD1(msg_info, const char*(pjsip_msg*));
  MOCK_METHOD3(schedule_timer, bool(void*, TimerID&, int));
  MOCK_METHOD1(cancel_timer, void(TimerID));
  MOCK_METHOD1(timer_running, bool(TimerID));
  MOCK_CONST_METHOD3(next_hop_uri, pjsip_sip_uri*(const std::string& service,
                                                  const pjsip_route_hdr* route,
                                                  pj_pool_t* pool));
};

#endif
