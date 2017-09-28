/**
 * @file subscriptiontsx.h Definition of the Subscription Tsx
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

#ifndef SUBSCRIPTIONTSX_H__
#define SUBSCRIPTIONTSX_H__

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
#include "forwardingsproutlet.h"

class SubscriptionTsx;

class SubscriptionProvider
{
public:
  SubscriptionProvider(SubscriberDataManager* sdm,
                       std::vector<SubscriberDataManager*> remote_sdms,
                       HSSConnection* hss_connection,
                       ACRFactory* acr_factory,
                       AnalyticsLogger* analytics_logger,
                       int cfg_max_expires);
  ~SubscriptionProvider();

  bool init() override;
  SproutletTsx* get_tsx(SproutletHelper* helper,
                        const std::string& alias,
                        pjsip_msg* req,
                        pjsip_sip_uri*& next_hop,
                        pj_pool_t* pool,
                        SAS::TrailId trail) override;

private:
  bool handle_request(pjsip_msg* req,
                      SAS::TrailId trail);

  friend class SubscriptionTsx;

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
};


class SubscriptionTsx : public SproutletTsx
{
public:
  SubscriptionTsx(SubscriptionProvider* subscription,
                           const std::string& next_hop_service);
  ~SubscriptionTsx();

  virtual void on_rx_initial_request(pjsip_msg* req) override;
  virtual void on_rx_in_dialog_request(pjsip_msg* req) override;

protected:
  void on_rx_request(pjsip_msg* req);
  void process_subscription_request(pjsip_msg* req);

  AoRPair* write_subscriptions_to_store(
                     SubscriberDataManager* primary_sdm,        ///<store to write to
                     std::string aor,                           ///<address of record to write to
                     AssociatedURIs* associated_uris,
                                                                ///<IMPUs associated with this IRS
                     pjsip_msg* req,                            ///<received request to read headers from
                     int now,                                   ///<time now
                     AoRPair* backup_aor,                       ///<backup data if no entry in store
                     std::vector<SubscriberDataManager*> backup_sdms,
                                                                ///<backup stores to read from if no entry in store and no backup data
                     std::string public_id,                     ///
                     bool send_ok,                              ///<Should we create an OK
                     ACR* acr,                                  ///
                     std::deque<std::string> ccfs,              ///
                     std::deque<std::string> ecfs);             ///

  void log_subscriptions(const std::string& aor_name,
                         AoR* aor_data);

  SubscriptionProvider* _subscription;
};

#endif
