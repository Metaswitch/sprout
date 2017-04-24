/**
 * @file authenticationsproutlet.h
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2016  Metaswitch Networks Ltd
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
                          uint32_t non_register_auth_mode_param,
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

  // Controls when to challenge non-REGISTER messages.  This is a bitmask with
  // values taken from NonRegisterAuthentication.
  uint32_t _non_register_auth_mode;

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

