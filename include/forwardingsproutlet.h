/**
 * @file forwaringsproutlet.h
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef FORWARINGSPROUTLET_H__
#define FORWARINGSPROUTLET_H__

#include "sproutlet.h"

///
/// A Sproutlet TSX that by default forwards requests to an upstream sproutlet
/// identified by a service name.
///

class ForwardingSproutletTsx : public SproutletTsx
{
public:
  ForwardingSproutletTsx(Sproutlet* sproutlet,
                         const std::string& upstream_service_name);
  virtual ~ForwardingSproutletTsx() {}

  void on_rx_initial_request(pjsip_msg* req) { forward_request(req); }
  void on_rx_in_dialog_request(pjsip_msg* req) { forward_request(req); }

protected:
  void forward_request(pjsip_msg* req);

  std::string _upstream_service_name;
};

#endif

