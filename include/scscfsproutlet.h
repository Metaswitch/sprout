/**
 * @file scscfsproutlet.cpp Definition of the S-CSCF Sproutlet classes,
 *                          implementing S-CSCF specific SIP proxy functions.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef SCSCFSPROUTLET_H__
#define SCSCFSPROUTLET_H__

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}

#include <vector>
#include <unordered_map>

#include "pjutils.h"
#include "enumservice.h"
#include "analyticslogger.h"
#include "subscriber_data_manager.h"
#include "stack.h"
#include "sessioncase.h"
#include "ifchandler.h"
#include "mmfservice.h"
#include "hssconnection.h"
#include "aschain.h"
#include "acr.h"
#include "sproutlet.h"
#include "snmp_counter_table.h"
#include "session_expires_helper.h"
#include "as_communication_tracker.h"
#include "authenticationmiddleware.h"
#include "registrartsx.h"
#include "subscriptiontsx.h"
#include "scscfproxytsx.h"

class SCSCFSproutlet : public Sproutlet
{
public:
  SCSCFSproutlet(const std::string& name,
                 int port,
                 const std::string& uri,
                 SNMP::SuccessFailCountByRequestTypeTable* incoming_sip_transactions_tbl,
                 SNMP::SuccessFailCountByRequestTypeTable* outgoing_sip_transactions_tbl,
                 std::list<TsxProvider> tsx_providers,
                 std::list<MiddlewareProvider> middleware_providers);
  ~SCSCFSproutlet();

  bool init();

  // TODO - Needs to return either RegistrarTsx, SubscriptionTsx or
  // SCSCFProxyTsx, depending on context.  This must be wrapped in an
  // AuthenticationMiddleware layer.
  //
  // This can be done by:
  //  - Calling tsx_from_providers() to get an appropriate SproutletTsx
  //  - Calling add_middleware() to wrap the SproutletTsx in Middleware layers
  SproutletTsx* get_tsx(SproutletHelper* helper,
                        const std::string& alias,
                        pjsip_msg* req,
                        pjsip_sip_uri*& next_hop,
                        pj_pool_t* pool,
                        SAS::TrailId trail);

private:
  AuthenticationProvider* _authentication_provider;
  RegistrarProvider* _registrar_provider;
  SubscriptionProvider* _subscription_provider;
  SCSCFProxyProvider* _scscf_proxy_provider;

  AsCommunicationTracker* _sess_term_as_tracker;
  AsCommunicationTracker* _sess_cont_as_tracker;
};

#endif
