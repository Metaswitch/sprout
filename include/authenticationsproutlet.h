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

// Classes representing authentication vectors. This allows most of the
// authentication module to be agnostic with respect to where the AV came from
// (the HSS which returns AVs as JSON objects, or the IMPI store which returns
// them as deserialized objects).
class AuthenticationVector
{
public:
  virtual ~AuthenticationVector() {}

  bool is_aka() { return (_type == AKA); }
  bool is_digest() { return (_type == DIGEST); }

protected:
  enum AvType { DIGEST, AKA };

  AuthenticationVector(AvType type) : _type(type) {}

  AvType _type;
};

class DigestAv : public AuthenticationVector
{
public:
  DigestAv() : AuthenticationVector(DIGEST) {}
  virtual ~DigestAv() {}

  std::string ha1;
  std::string qop;
  std::string realm;
};

class AkaAv : public AuthenticationVector
{
public:
  AkaAv() :
    AuthenticationVector(AKA),
    // Defaults to 1, for back-compatibility with pre-AKAv2 Homestead versions.
    akaversion(1)
  {}
  virtual ~AkaAv() {}

  std::string nonce;
  std::string cryptkey;
  std::string integritykey;
  std::string xres;
  int akaversion;
};

class AuthenticationSproutlet : public Sproutlet
{
public:
  AuthenticationSproutlet(const std::string& name,
                          int port,
                          const std::string& uri,
                          const std::string& next_hop_service,
                          const std::list<std::string>& aliases,
                          const std::string& realm_name,
                          ImpiStore* impi_store,
                          std::vector<ImpiStore*> remote_impi_stores,
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

  /// Read an IMPI from the store (preferring the local store, but falling back
  /// to GR stores if necessary).
  ///
  /// @param impi  - The IMPI to read.
  /// @param nonce - The nonce that the caller is in interested in.
  /// @param trail - SAS trail ID.
  ///
  /// @return      - The IMPI object, or NULL if there was a store failure.
  ImpiStore::Impi* read_impi(const std::string& impi,
                             const std::string& nonce,
                             SAS::TrailId trail);

  /// Write a challenge to the IMPI stores. This handles GR replication.
  ///
  /// @param impi           - The IMPI the challenge relates to.
  /// @param auth_challenge - The challenge to write.
  /// @param impi_obj       - Optional IMPI object that has previously been read
  ///                         from the local store. This allows this function to
  ///                         eliminate a superfluous read.
  /// @param trail          - SAS trail ID.
  ///
  /// @return               - The result of writing the challenge to the local
  ///                         store.
  Store::Status write_challenge(const std::string& impi,
                                ImpiStore::AuthChallenge* auth_challenge,
                                ImpiStore::Impi* impi_obj,
                                SAS::TrailId trail);

  /// Write a challenge to a single store.
  ///
  /// @param store          - The store to write to.
  /// @param impi           - The IMPI the challenge relates to.
  /// @param auth_challenge - The challenge to write.
  /// @param impi_obj       - Optional IMPI object that has previously been read
  ///                         from the local store. This allows this function to
  ///                         eliminate a superfluous read.
  /// @param trail          - SAS trail ID.
  ///
  /// @return               - The result of writing the challenge to the local
  ///                         store.
  Store::Status write_challenge_to_store(ImpiStore* store,
                                         const std::string& impi,
                                         ImpiStore::AuthChallenge* auth_challenge,
                                         ImpiStore::Impi* impi_obj,
                                         SAS::TrailId trail);

  friend class AuthenticationSproutletTsx;

  // Realm to use on AKA challenges.
  pj_str_t _aka_realm;

  // Connection to the HSS service for retrieving subscriber credentials.
  HSSConnection* _hss;

  ChronosConnection* _chronos;

  // Factory for creating ACR messages for Rf billing.
  ACRFactory* _acr_factory;

  // IMPI stores used to store authentication challenges while waiting for the
  // client to respond.
  ImpiStore* _impi_store;
  std::vector<ImpiStore*> _remote_impi_stores;

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
  virtual void on_rx_response(pjsip_msg* rsp, int fork_id) override;

protected:
  friend class AuthenticationSproutlet;

  void create_challenge(pjsip_digest_credential* credentials,
                        pj_bool_t stale,
                        std::string resync,
                        pjsip_msg* req,
                        pjsip_msg* rsp);
  int calculate_challenge_expiration_time(pjsip_msg* req);
  AuthenticationVector* verify_auth_vector(rapidjson::Document* av,
                                           const std::string& impi);
  static pj_status_t user_lookup(pj_pool_t *pool,
                                 const pjsip_auth_lookup_cred_param *param,
                                 pjsip_cred_info *cred_info,
                                 void* auth_challenge_param);
  static pjsip_digest_credential* get_credentials(const pjsip_msg* req);
  AuthenticationVector* get_av_from_store(const std::string& impi,
                                          const std::string& nonce,
                                          ImpiStore::Impi** out_impi_obj);

  AuthenticationSproutlet* _authentication;

  // Fields holding the nonce and the IMPI used for this authentication attempt.
  // These are only stored once the user has been successfully authenticated.
  std::string _authenticated_impi;
  std::string _authenticated_nonce;

  // Whether the user has authenticated using the SIP digest mechanism.
  bool _authenticated_using_sip_digest;
};

#endif

