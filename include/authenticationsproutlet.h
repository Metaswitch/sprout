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
#include "compositesproutlet.h"

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
                          const std::list<std::string>& aliases,
                          const std::string& network_function,
                          const std::string& next_hop_service,
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
                          int cfg_max_expires);
  ~AuthenticationSproutlet();

  bool init();

  SproutletTsx* get_tsx(SproutletHelper* helper,
                        const std::string& alias,
                        pjsip_msg* req,
                        pjsip_sip_uri*& next_hop,
                        pj_pool_t* pool,
                        SAS::TrailId trail) override;

private:
  bool needs_authentication(pjsip_msg* req,
                            SAS::TrailId trail);

  /// Read an IMPI from the store (preferring the local store, but falling back
  /// to GR stores if necessary).
  ///
  /// @param impi  - The IMPI to read.
  /// @param trail - SAS trail ID.
  ///
  /// @return      - The IMPI object, or NULL if there was a store failure.
  ImpiStore::Impi* read_impi(const std::string& impi,
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

  /// The maximum time (in seconds) that a device can register for.  We need
  /// this to determine the expiry time of authentication challenges based on
  /// the contact expiry times.
  int _max_expires;

  // PJSIP structure for control server authentication functions.
  pjsip_auth_srv _auth_srv;
  pjsip_auth_srv _auth_srv_proxy;

  // Controls when to challenge non-REGISTER messages.  This is a bitmask with
  // values taken from NonRegisterAuthentication.
  uint32_t _non_register_auth_mode;

  // The next service to route requests onto if the sproutlet does not handle them
  // itself.
  std::string _next_hop_service;
};


class AuthenticationSproutletTsx : public CompositeSproutletTsx
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

  // The S-CSCF URI for this transaction. This is used on the SAR sent to the
  // HSS. This field should not be changed once it has been set by the
  // on_rx_intial_request() call.
  std::string _scscf_uri;
};

#endif

