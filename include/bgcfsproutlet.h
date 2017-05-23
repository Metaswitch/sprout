/**
 * @file bgcfsproutlet.cpp  Definition of the BGCF Sproutlet classes,
 *                          implementing BGCF specific SIP proxy functions.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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
#include "enumservice.h"

#include <map>
#include <vector>
#include <string>


class BGCFSproutletTsx;

class BGCFSproutlet : public Sproutlet
{
public:
  BGCFSproutlet(const std::string& bgcf_name,
                int port,
                const std::string& uri,
                BgcfService* bgcf_service,
                EnumService* enum_service,
                ACRFactory* acr_factory,
                SNMP::SuccessFailCountByRequestTypeTable* incoming_sip_transactions_tbl,
                SNMP::SuccessFailCountByRequestTypeTable* outgoing_sip_transactions_tbl,
                bool override_npdi);
  ~BGCFSproutlet();

  SproutletTsx* get_tsx(SproutletHelper* helper,
                        const std::string& alias,
                        pjsip_msg* req,
                        pjsip_sip_uri*& next_hop,
                        pj_pool_t* pool,
                        SAS::TrailId trail);

  inline bool should_override_npdi() const
  {
    return _override_npdi;
  }

private:

  /// Lookup a route from the configured rules.
  ///
  /// @return            - The URIs to route the message on to (in order).
  /// @param domain      - The domain to find the route to.
  std::vector<std::string> get_route_from_domain(const std::string &domain,
                                                 SAS::TrailId trail) const;

  /// Lookup a route from the configured rules.
  ///
  /// @return            - The URIs to route the message on to (in order).
  /// @param number      - The number to route on
  std::vector<std::string> get_route_from_number(const std::string &number,
                                                 SAS::TrailId trail) const;

  /// Get an ACR instance from the factory.
  /// @param trail                SAS trail identifier to use for the ACR.
  ACR* get_acr(SAS::TrailId trail);

  /// Do an ENUM lookup .
  ///
  /// @return            - The URI translation.
  /// @param uri         - The URI to translate
  std::string enum_lookup(pjsip_uri* uri, SAS::TrailId trail);

  friend class BGCFSproutletTsx;

  BgcfService* _bgcf_service;

  EnumService* _enum_service;

  ACRFactory* _acr_factory;

  bool _override_npdi;
};


class BGCFSproutletTsx : public SproutletTsx
{
public:
  BGCFSproutletTsx(BGCFSproutlet* bgcf);
  ~BGCFSproutletTsx();

  virtual void on_rx_initial_request(pjsip_msg* req) override;
  virtual void on_tx_request(pjsip_msg* req, int fork_id) override;
  virtual void on_rx_response(pjsip_msg* rsp, int fork_id) override;
  virtual void on_tx_response(pjsip_msg* rsp) override;
  virtual void on_rx_cancel(int status_code, pjsip_msg* req) override;

private:
  BGCFSproutlet* _bgcf;

  ACR* _acr;
};

#endif
