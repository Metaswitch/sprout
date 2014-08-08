/**
 * @file bgcfsproutlet.cpp  Definition of the BGCF Sproutlet classes,
 *                          implementing BGCF specific SIP proxy functions.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2014  Metaswitch Networks Ltd
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

#ifndef BGCFSPROUTLET_H__
#define BGCFSPROUTLET_H__

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}

#include "pjutils.h"
#include "analyticslogger.h"
#include "stack.h"
#include "acr.h"
#include "bgcfservice.h"
#include "sproutlet.h"

#include <map>
#include <vector>
#include <string>


class BGCFSproutletTsx;

class BGCFSproutlet : public Sproutlet
{
public:
  BGCFSproutlet(int port,
                BgcfService* bgcf_service,
                ACRFactory* acr_factory);
  ~BGCFSproutlet();

  SproutletTsx* get_tsx(SproutletTsxHelper* helper, pjsip_msg* req);

private:

  /// Lookup a route from the configured rules.
  ///
  /// @return            - The URIs to route the message on to (in order).
  /// @param domain      - The domain to find the route to.
  std::vector<std::string> get_route(const std::string &domain,
                                     SAS::TrailId trail) const;

  /// Get an ACR instance from the factory.
  /// @param trail                SAS trail identifier to use for the ACR.
  ACR* get_acr(SAS::TrailId trail);

  friend class BGCFSproutletTsx;

  BgcfService* _bgcf_service;

  ACRFactory* _acr_factory;
};


class BGCFSproutletTsx : public SproutletTsx
{
public:
  BGCFSproutletTsx(SproutletTsxHelper* helper,
                   BGCFSproutlet* bgcf);
  ~BGCFSproutletTsx();

  virtual void on_rx_initial_request(pjsip_msg* req);
  virtual void on_tx_request(pjsip_msg* req);
  virtual void on_rx_response(pjsip_msg* rsp, int fork_id);
  virtual void on_tx_response(pjsip_msg* rsp);
  virtual void on_cancel(int status_code, pjsip_msg* req);

private:
  BGCFSproutlet* _bgcf;

  ACR* _acr;
};

#endif
