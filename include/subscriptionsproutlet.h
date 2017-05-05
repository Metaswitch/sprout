/**
 * @file subscriptionsproutlet.h Definition of the Subscription Sproutlet
 *                               classes, implementing S-CSCF specific
 *                               Subscription functions.
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
#include "forwardingsproutlet.h"

class SubscriptionSproutletTsx;

class SubscriptionSproutlet : public Sproutlet
{
public:
  SubscriptionSproutlet(const std::string& name,
                        int port,
                        const std::string& uri,
                        const std::string& next_hop_service,
                        SubscriberDataManager* sdm,
                        std::vector<SubscriberDataManager*> remote_sdms,
                        HSSConnection* hss_connection,
                        ACRFactory* acr_factory,
                        AnalyticsLogger* analytics_logger,
                        int cfg_max_expires);
  ~SubscriptionSproutlet();

  bool init();

  SproutletTsx* get_tsx(SproutletTsxHelper* helper,
                        const std::string& alias,
                        pjsip_msg* req) override;

private:
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


class SubscriptionSproutletTsx : public ForwardingSproutletTsx
{
public:
  SubscriptionSproutletTsx(SproutletTsxHelper* helper,
                           const std::string& next_hop_service,
                           SubscriptionSproutlet* sproutlet);
  ~SubscriptionSproutletTsx();

  virtual void on_rx_initial_request(pjsip_msg* req) override;
  virtual void on_rx_in_dialog_request(pjsip_msg* req) override;

protected:
  void on_rx_request(pjsip_msg* req);
  bool handle_request(pjsip_msg* req);
  void process_subscription_request(pjsip_msg* req);

  SubscriberDataManager::AoRPair* write_subscriptions_to_store(
                     SubscriberDataManager* primary_sdm,        ///<store to write to
                     std::string aor,                           ///<address of record to write to
                     std::vector<std::string> unbarred_irs_impus,
                                                                ///<Unbarred IMPUs in Implicit Registration Set
                     pjsip_msg* req,                            ///<received request to read headers from
                     int now,                                   ///<time now
                     SubscriberDataManager::AoRPair* backup_aor,///<backup data if no entry in store
                     std::vector<SubscriberDataManager*> backup_sdms,
                                                                ///<backup stores to read from if no entry in store and no backup data
                     std::string public_id,                     ///
                     bool send_ok,                              ///<Should we create an OK
                     ACR* acr,                                  ///
                     std::deque<std::string> ccfs,              ///
                     std::deque<std::string> ecfs);             ///

  void log_subscriptions(const std::string& aor_name,
                         SubscriberDataManager::AoR* aor_data);

  SubscriptionSproutlet* _sproutlet;
};

#endif
