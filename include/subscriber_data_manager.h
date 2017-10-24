/**
 * @file subscriber_data_manager.h
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


#ifndef SUBSCRIBER_DATA_MANAGER_H__
#define SUBSCRIBER_DATA_MANAGER_H__

#include <string>
#include <list>
#include <map>
#include <stdio.h>
#include <stdlib.h>

#include "astaire_aor_store.h"
#include "chronosconnection.h"
#include "sas.h"
#include "analyticslogger.h"
#include "associated_uris.h"

// We need to declare the parts of NotifyUtils needed below to avoid a
// circular dependency between this and notify_utils.h
namespace NotifyUtils { struct BindingNotifyInformation; };

typedef NotifyUtils::BindingNotifyInformation ClassifiedBinding;
typedef std::vector<ClassifiedBinding*> ClassifiedBindings;

class SubscriberDataManager
{
public:
  enum EventTrigger
  {
    USER,
    ADMIN,
    TIMEOUT
  };

  /// @class SubscriberDataManager::ChronosTimerRequestSender
  ///
  /// Class responsible for sending any requests to Chronos about
  /// registration/subscription expiry
  ///
  /// @param chronos_conn    The underlying chronos connection
  class ChronosTimerRequestSender
  {
  public:
    ChronosTimerRequestSender(ChronosConnection* chronos_conn);

    virtual ~ChronosTimerRequestSender();

    /// Create and send any appropriate Chronos requests
    ///
    /// @param aor_id       The AoR ID
    /// @param aor_pair     The AoR pair to send Chronos requests for
    /// @param now          The current time
    /// @param trail        SAS trail
    virtual void send_timers(const std::string& aor_id,
                             AoRPair* aor_pair,
                             int now,
                             SAS::TrailId trail);

    /// SubscriberDataManager is the only class that can use
    /// ChronosTimerRequestSender
    friend class SubscriberDataManager;

  private:
    ChronosConnection* _chronos_conn;

    /// Build the tag info map from an AoR
    virtual void build_tag_info(AoR* aor,
                                std::map<std::string, uint32_t>& tag_map);

    /// Create the Chronos Timer request
    ///
    /// @param aor_id       The AoR ID
    /// @param timer_id     The Timer ID
    /// @param expiry       Timer length
    /// @param tags         Any tags to add to the Chronos timer
    /// @param trail        SAS trail
    virtual void set_timer(const std::string& aor_id,
                           std::string& timer_id,
                           int expiry,
                           std::map<std::string, uint32_t> tags,
                           SAS::TrailId trail);
  };

  /// @class SubscriberDataManager::NotifySender
  ///
  /// Class responsible for sending any NOTIFYs about registration state
  /// change
  class NotifySender
  {
  public:
    NotifySender();

    virtual ~NotifySender();

    /// Create and send any appropriate NOTIFYs
    ///
    /// @param aor_id       The AoR ID
    /// @param associated_uris
    ///                     The IMPUs associated with this IRS
    /// @param aor_pair     The AoR pair to send NOTIFYs for
    /// @param now          The current time
    /// @param trail        SAS trail
    void send_notifys(const std::string& aor_id,
                      const EventTrigger& event_trigger,
                      AoRPair* aor_pair,
                      int now,
                      SAS::TrailId trail);

    /// SubscriberDataManager is the only class that can use NotifySender
    friend class SubscriberDataManager;

  private:
    // Create and send any appropriate NOTIFYs for any expired subscriptions
    //
    // @param aor_id       The AoR ID
    // @param associated_uris
    //                     The IMPUs associated with this IRS
    // @param aor_pair     The AoR pair to send NOTIFYs for
    // @param binding_info_to_notify
    //                     The list of bindings to include on the NOTIFY
    // @param expired_binding_uris
    //                     A list of URIs of expired bindings
    // @param now          The current time
    // @param trail        SAS trail
    void send_notifys_for_expired_subscriptions(
                                   const std::string& aor_id,
                                   const EventTrigger& event_trigger,
                                   AoRPair* aor_pair,
                                   ClassifiedBindings binding_info_to_notify,
                                   std::vector<std::string> missing_binding_uris,
                                   int now,
                                   SAS::TrailId trail);
  };

  /// Tags to use when setting timers for nothing, for registration and for subscription.
  static const std::vector<std::string> TAGS_NONE;
  static const std::vector<std::string> TAGS_REG;
  static const std::vector<std::string> TAGS_SUB;

  /// SubscriberDataManager constructor.
  ///
  /// @param aor_store          - Pointer to the underlying data store interface.
  /// @param chronos_connection - Chronos connection used to set timers for
  ///                             expiring registrations and subscriptions.
  /// @param analytics_logger   - AnalyticsLogger for reporting registration events.
  /// @param is_primary         - Whether the underlying data store is the local
  ///                             store or remote
  SubscriberDataManager(AoRStore* aor_store,
                        ChronosConnection* chronos_connection,
                        AnalyticsLogger* analytics_logger,
                        bool is_primary);

  /// Destructor.
  virtual ~SubscriberDataManager();

  virtual bool has_servers() { return _aor_store->has_servers(); }

  /// Get the data for a particular address of record (registered SIP URI,
  /// in format "sip:2125551212@example.com"), creating creating it if
  /// necessary.  May return NULL in case of error.  Result is owned
  /// by caller and must be freed with delete.
  ///
  /// @param aor_id    The AoR to retrieve
  /// @param trail     SAS trail
  virtual AoRPair* get_aor_data(const std::string& aor_id,
                                SAS::TrailId trail);

  /// Update the data for a particular address of record.  Writes the data
  /// atomically. If the underlying data has changed since it was last
  /// read, the update is rejected and this returns false; if the update
  /// succeeds, this returns true.
  ///
  /// @param aor_id               The AoR to retrieve
  /// @param associated_uris      The IMPUs associated with this IRS
  /// @param aor_pair             The AoR pair to set
  /// @param trail                SAS trail
  /// @param all_bindings_expired Whether all bindings have expired
  ///                             as a result of the set
  virtual Store::Status set_aor_data(const std::string& aor_id,
                                     const EventTrigger& event_trigger,
                                     AoRPair* aor_pair,
                                     SAS::TrailId trail,
                                     bool& all_bindings_expired = unused_bool);

private:
  // Expire any out of date bindings in the current AoR
  //
  // @param aor_pair  The AoRPair to expire
  // @param now       The current time
  // @param trail     SAS trail
  int expire_aor_members(AoRPair* aor_pair,
                         int now,
                         SAS::TrailId trail);

  // Expire any old bindings, and return the maximum expiry
  //
  // @param aor_pair  The AoRPair to expire
  // @param now       The current time
  // @param trail     SAS trail
  int expire_bindings(AoR* aor_data,
                      int now,
                      SAS::TrailId trail);

  // Expire any old subscriptions.
  //
  // @param aor_pair      The AoRPair to expire
  // @param now           The current time
  // @param force_expires Whether all subscriptions should be expired
  //                      no matter the current time
  // @param trail         SAS trail
  void expire_subscriptions(AoRPair* aor_pair,
                            int now,
                            bool force_expire,
                            SAS::TrailId trail);

  // Iterate over all original and current bindings in an AoR pair and
  // classify them as removed ("EXPIRED"), created ("CREATED"), refreshed ("REFRESHED"),
  // shortened ("SHORTENED") or unchanged ("REGISTERED").
  //
  // @param aor_id                The AoR ID
  // @param aor_pair              The AoR pair to compare and classify bindings for
  // @param classified_bindings   Output vector of classified bindings
  void classify_bindings(const std::string& aor_id,
                         const SubscriberDataManager::EventTrigger& event_trigger,
                         AoRPair* aor_pair,
                         ClassifiedBindings& classified_bindings);

  // Iterate over a list of classified bindings, and emit registration logs for those
  // that are EXPIRED or SHORTENED.
  void log_removed_or_shortened_bindings(ClassifiedBindings& classified_bindings,
                                         int now);

  // Iterate over a list of classified bindings, and emit registration logs for those
  // that are CREATED or REFRESHED.
  void log_new_or_extended_bindings(ClassifiedBindings& classified_bindings,
                                    int now);

  static bool unused_bool;
  AnalyticsLogger* _analytics;
  AoRStore* _aor_store;
  ChronosTimerRequestSender* _chronos_timer_request_sender;
  NotifySender* _notify_sender;
  bool _primary_sdm;
};


#endif
