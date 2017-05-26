/**
 * @file authenticationsproutlet.h
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef AUTHENTICATIONSPROUTLET_H__
#define AUTHENTICATIONSPROUTLET_H__

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}

#include "pjutils.h"
#include "stack.h"
#include "acr.h"
#include "sproutlet.h"
#include "impistore.h"
#include "hssconnection.h"
#include "chronosconnection.h"
#include "acr.h"
#include "analyticslogger.h"
#include "snmp_success_fail_count_table.h"
#include "cfgoptions.h"
#include "forwardingsproutlet.h"

typedef std::function<int(pjsip_contact_hdr*, pjsip_expires_hdr*)> get_expiry_for_binding_fn;

class AuthenticationSproutletTsx;

class AuthenticationSproutlet : public Sproutlet
{
public:
  AuthenticationSproutlet(const std::string& name,
                          int port,
                          const std::string& uri,
                          const std::string& next_hop_service,
                          const std::list<std::string>& aliases,
                          const std::string& realm_name,
                          ImpiStore* _impi_store,
                          HSSConnection* hss_connection,
                          ChronosConnection* chronos_connection,
                          ACRFactory* rfacr_factory,
                          NonRegisterAuthentication non_register_auth_mode_param,
                          AnalyticsLogger* analytics_logger,
                          SNMP::AuthenticationStatsTables* auth_stats_tbls,
                          bool nonce_count_supported_arg,
                          get_expiry_for_binding_fn get_expiry_for_binding_arg);
  ~AuthenticationSproutlet();

  bool init();

  SproutletTsx* get_tsx(SproutletHelper* helper,
                        const std::string& alias,
                        pjsip_msg* req,
                        pjsip_sip_uri*& next_hop,
                        pj_pool_t* pool,
                        SAS::TrailId trail) override;

  const std::list<std::string> aliases() const override;

private:
  bool needs_authentication(pjsip_msg* req,
                            SAS::TrailId trail);

  friend class AuthenticationSproutletTsx;

  // Realm to use on AKA challenges.
  pj_str_t _aka_realm;

  // Connection to the HSS service for retrieving subscriber credentials.
  HSSConnection* _hss;

  ChronosConnection* _chronos;

  // Factory for creating ACR messages for Rf billing.
  ACRFactory* _acr_factory;

  // IMPI store used to store authentication challenges while waiting for the
  // client to respond.
  ImpiStore* _impi_store;

  // Analytics logger.
  AnalyticsLogger* _analytics;

  // SNMP tables counting authentication successes and failures.
  SNMP::AuthenticationStatsTables* _auth_stats_tables;

  // Whether nonce counts are supported.
  bool _nonce_count_supported = false;

  // A function that the authentication module can use to work out the expiry
  // time for a given binding. This is needed so that it knows how long to
  // authentication challenges for.
  get_expiry_for_binding_fn _get_expiry_for_binding;

  // PJSIP structure for control server authentication functions.
  pjsip_auth_srv _auth_srv;
  pjsip_auth_srv _auth_srv_proxy;

  // Controls when to challenge non-REGISTER messages.
  NonRegisterAuthentication _non_register_auth_mode;

  // The next service to route requests onto if the sproutlet does not handle them
  // itself.
  std::string _next_hop_service;

  // Aliases that this sproutlet registers for.
  const std::list<std::string> _aliases;
};


class AuthenticationSproutletTsx : public ForwardingSproutletTsx
{
public:
  AuthenticationSproutletTsx(AuthenticationSproutlet* authentication,
                             const std::string& next_hop_service);
  ~AuthenticationSproutletTsx();

  virtual void on_rx_initial_request(pjsip_msg* req) override;

protected:
  friend class AuthenticationSproutlet;

  void create_challenge(pjsip_digest_credential* credentials,
                        pj_bool_t stale,
                        std::string resync,
                        pjsip_msg* req,
                        pjsip_msg* rsp);
  int calculate_challenge_expiration_time(pjsip_msg* req);
  bool verify_auth_vector(rapidjson::Document* av,
                          const std::string& impi);
  static pj_status_t user_lookup(pj_pool_t *pool,
                                 const pjsip_auth_lookup_cred_param *param,
                                 pjsip_cred_info *cred_info,
                                 void* auth_challenge_param);
  static pjsip_digest_credential* get_credentials(const pjsip_msg* req);

  AuthenticationSproutlet* _authentication;
};

#endif

