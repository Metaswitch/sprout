/**
 * @file subscriptionsproutlet.h Definition of the Subscription Sproutlet
 *                               classes, implementing S-CSCF specific
 *                               Subscription functions.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef SUBSCRIPTIONSPROUTLET_H__
#define SUBSCRIPTIONSPROUTLET_H__

#include <vector>
#include <unordered_map>

#include "analyticslogger.h"
#include "aschain.h"
#include "acr.h"
#include "hssconnection.h"
#include "subscriber_data_manager.h"
#include "sproutlet.h"
#include "snmp_counter_table.h"
#include "session_expires_helper.h"
#include "as_communication_tracker.h"
#include "compositesproutlet.h"

class SubscriptionSproutletTsx;

class SubscriptionSproutlet : public Sproutlet
{
public:
  SubscriptionSproutlet(const std::string& name,
                        int port,
                        const std::string& uri,
                        const std::string& network_function,
                        const std::string& next_hop_service,
                        SubscriberDataManager* sdm,
                        std::vector<SubscriberDataManager*> remote_sdms,
                        HSSConnection* hss_connection,
                        ACRFactory* acr_factory,
                        AnalyticsLogger* analytics_logger,
                        int cfg_max_expires);
  ~SubscriptionSproutlet();

  bool init();

  SproutletTsx* get_tsx(SproutletHelper* helper,
                        const std::string& alias,
                        pjsip_msg* req,
                        pjsip_sip_uri*& next_hop,
                        pj_pool_t* pool,
                        SAS::TrailId trail) override;

private:
  bool handle_request(pjsip_msg* req,
                      SAS::TrailId trail);

  friend class SubscriptionSproutletTsx;

  SubscriberDataManager* _sdm;
  std::vector<SubscriberDataManager*> _remote_sdms;

  // Connection to the HSS service for retrieving associated public URIs.
  HSSConnection* _hss;

  /// Factory for generating ACR messages for Rf billing.
  ACRFactory* _acr_factory;

  AnalyticsLogger* _analytics;

  /// The maximum time (in seconds) that a device can subscribe for.
  int _max_expires;

  /// Default value for a subscription expiry. RFC3860 has this as 3761 seconds.
  static const int DEFAULT_SUBSCRIPTION_EXPIRES = 3761;

  // The next service to route requests onto if the sproutlet does not handle
  // them itself.
  std::string _next_hop_service;
};


class SubscriptionSproutletTsx : public CompositeSproutletTsx
{
public:
  SubscriptionSproutletTsx(SubscriptionSproutlet* subscription,
                           const std::string& next_hop_service);
  ~SubscriptionSproutletTsx();

  virtual void on_rx_initial_request(pjsip_msg* req) override;
  virtual void on_rx_in_dialog_request(pjsip_msg* req) override;

protected:
  void on_rx_request(pjsip_msg* req);
  void process_subscription_request(pjsip_msg* req);

  AoR::Subscription create_subscription(pjsip_msg* req, int expiry);

  Store::Status update_subscription_in_stores(SubscriptionSproutlet* _subscription,
                                              AoR::Subscription& new_subscription,
                                              std::string aor,
                                              AssociatedURIs* associated_uris,
                                              pjsip_msg* req,
                                              std::string public_id,
                                              ACR* acr,
                                              std::deque<std::string> ccfs,
                                              std::deque<std::string> ecfs);

  AoRPair* read_and_cache_from_store(SubscriberDataManager* sdm,
                                     std::string aor,
                                     std::map<SubscriberDataManager*, AoRPair*>& _cached_aors);

  void update_subscription(SubscriptionSproutlet* _subscription,
                           AoR::Subscription& new_subscription,
                           std::string aor,
                           AoRPair* aor_pair,
                           std::map<SubscriberDataManager*, AoRPair*>& _cached_aors);

  void log_subscriptions(const std::string& aor_name,
                         AoR* aor_data);

  SubscriptionSproutlet* _subscription;
};

#endif
