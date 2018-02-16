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

#include "acr.h"
#include "subscriber_manager.h"
#include "sproutlet.h"
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
                        SubscriberManager* sm,
                        ACRFactory* acr_factory,
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

  SubscriberManager* _sm;

  /// Factory for generating ACR messages for Rf billing.
  ACRFactory* _acr_factory;

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

  /// Create a subscription object. This is called if the subscribe processing
  /// is going to add/update a subscription.
  ///
  /// @param req[in]    - The SIP request to create a subscription object from.
  /// @param expiry[in] - The expiry time of the subscription. This is passed in
  ///                     rather than calculated from the request, as we've
  ///                     already had to calculate it in order to know if we're
  ///                     adding/updating or removing a subscription.
  ///
  /// @return The created subscription object
  Subscription* create_subscription(pjsip_msg* req, int expiry);

  SubscriptionSproutlet* _subscription;
};

#endif
