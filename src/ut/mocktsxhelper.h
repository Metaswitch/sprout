/**
 * @file mocktsxhelper.h  Mock SproutletTsxHelper interfaces.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef MOCKTSXHELPER_H__
#define MOCKTSXHELPER_H__

#include "gmock/gmock.h"
#include "sproutlet.h"

class MockSproutletTsxHelper : public SproutletTsxHelper
{
public:
  MockSproutletTsxHelper();
  ~MockSproutletTsxHelper();

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
  MOCK_METHOD2(send_request, int(pjsip_msg*&, int));
  MOCK_METHOD1(send_response, void(pjsip_msg*&));
  MOCK_METHOD3(cancel_fork, void(int, int, std::string));
  MOCK_METHOD2(cancel_pending_forks, void(int, std::string));
  MOCK_METHOD0(mark_pending_forks_as_abandoned, void());
  MOCK_METHOD1(fork_state, const ForkState&(int));
  MOCK_METHOD1(free_msg, void(pjsip_msg*&));
  MOCK_METHOD1(get_pool, pj_pool_t*(const pjsip_msg*));
  MOCK_METHOD1(msg_info, const char*(pjsip_msg*));
  MOCK_METHOD3(schedule_timer, bool(void*, TimerID&, int));
  MOCK_METHOD1(cancel_timer, void(TimerID));
  MOCK_METHOD1(timer_running, bool(TimerID));
  MOCK_CONST_METHOD1(get_routing_uri, pjsip_sip_uri*(const pjsip_msg* req));
  MOCK_CONST_METHOD3(next_hop_uri, pjsip_sip_uri*(const std::string& service,
                                                  const pjsip_sip_uri* base_uri,
                                                  pj_pool_t* pool));
  MOCK_CONST_METHOD1(get_local_hostname, std::string(const pjsip_sip_uri* uri));
};

#endif
