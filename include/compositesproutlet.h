/**
 * @file compositesproutlet.h
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef COMPOSITESPROUTLET_H__
#define COMPOSITESPROUTLET_H__

#include "sproutlet.h"

///
/// A Sproutlet TSX that is part of a more complicated Network Function.  When
/// it sends outbound standalone or dialog-creating requests, they are routed
/// to the next Sproutlet in the Network Function.  In-dialog requests are
/// routed using standard SIP routing (Record-Route headers).
///

class CompositeSproutletTsx : public SproutletTsx
{
public:
  CompositeSproutletTsx(Sproutlet* sproutlet,
                        const std::string& next_hop_service);
  virtual ~CompositeSproutletTsx() {}

  void on_rx_initial_request(pjsip_msg* req) override { send_request(req); }
  void on_rx_in_dialog_request(pjsip_msg* req) override { send_request(req); }

protected:
  int send_request(pjsip_msg*& req,
                   int allowed_host_state=BaseResolver::ALL_LISTS) override;

  const std::string _next_hop_service;
};

#endif

