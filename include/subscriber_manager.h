/**
 * @file subscriber_manager.h
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef SUBSCRIBER_MANAGER_H__
#define SUBSCRIBER_MANAGER_H__

extern "C" {
#include <pjsip.h>
}

#include <string>
#include <list>
#include <map>
#include <stdio.h>
#include <stdlib.h>

#include "aor.h"
#include "sas.h"
#include "analyticslogger.h"
#include "associated_uris.h"
#include "hssconnection.h"
#include "ifchandler.h"
#include "aor.h"
#include "s4.h"
#include "notify_sender.h"
#include "registration_sender.h"
#include "subscriber_data_utils.h"

// SDM-REFACTOR-TODO: Add Doxygen return parameters.
class SubscriberManager : public S4::TimerPopConsumer,
                          public RegistrationSender::DeregistrationEventConsumer
{
public:
  /// SubscriberManager constructor. It calls the S4 to store a reference to
  /// itself, so that local S4 and SM contacts each other in one-to-one mapping.
  ///
  /// @param s4                 - Pointer to the underlying data store interface
  /// @param hss_connection     - Sprout's HSS connection (via homestead)
  /// @param analytics_logger   - AnalyticsLogger for reporting registration events
  /// @param notify_sender      - NotifySender class that knows how to send NOTIFYs
  /// @param registration_sender
  ///                           - RegistrationSender class that knows how to send
  ///                             3rd party REGISTERs.
  SubscriberManager(S4* s4,
                    HSSConnection* hss_connection,
                    AnalyticsLogger* analytics_logger,
                    NotifySender* notify_sender,
                    RegistrationSender* registration_sender);

  /// Destructor.
  virtual ~SubscriberManager();

  /// Registers a subscriber in SM to a given AoR Id.
  ///
  /// @param[in]  aor_id        The default public ID for this subscriber
  /// @param[in]  server_name   The S-CSCF assigned to this subscriber
  /// @param[in]  associated_uris
  ///                           The IMPUs associated with this IRS
  /// @param[in]  add_bindings  The bindings to add
  /// @param[out] all_bindings  All bindings currently stored for this subscriber
  /// @param[in]  trail         The SAS trail ID
  virtual HTTPCode register_subscriber(const std::string& aor_id,
                                       const std::string& server_name,
                                       const AssociatedURIs& associated_uris,
                                       const Bindings& add_bindings,
                                       Bindings& all_bindings,
                                       SAS::TrailId trail);

  /// Reregisters a subscriber in SM to a given AoR Id. This operation can
  /// result in a deregistration if it removes all bindings.
  ///
  /// @param[in]  aor_id        The default public ID for this subscriber
  /// @param[in]  associated_uris
  ///                           The IMPUs associated with this IRS
  /// @param[in]  updated_bindings
  ///                           The bindings to update
  /// @param[in]  binding_ids_to_remove
  ///                           The binding IDs to remove
  /// @param[out] all_bindings  All bindings currently stored for this subscriber
  /// @param[out] irs_info      The IRS information from the HSS. This is only
  ///                           filled out if this operation ends up deregistering
  ///                           the subscriber
  /// @param[in]  trail         The SAS trail ID
  virtual HTTPCode reregister_subscriber(const std::string& aor_id,
                                         const AssociatedURIs& associated_uris,
                                         const Bindings& updated_bindings,
                                         const std::vector<std::string>& binding_ids_to_remove,
                                         Bindings& all_bindings,
                                         HSSConnection::irs_info& irs_info,
                                         SAS::TrailId trail);

  /// Removes bindings stored in SM for a given public ID.
  ///
  /// @param[in]  public_id     The public IDs to remove bindings for
  /// @param[in]  binding_ids   The binding IDs to remove
  /// @param[in]  event_trigger The reason for removing bindings
  /// @param[out] bindings      All bindings currently stores for this public ID
  /// @param[in]  trail         The SAS trail ID
  virtual HTTPCode remove_bindings(const std::string& public_id,
                                   const std::vector<std::string>& binding_ids,
                                   const SubscriberDataUtils::EventTrigger& event_trigger,
                                   Bindings& bindings,
                                   SAS::TrailId trail);

  /// Updates a subscription stored in SM for a given public ID.
  ///
  /// @param[in]  public_id     The public ID being subscribed to
  /// @param[in]  subscription  A pair containing the subscription ID and
  ///                           subscription to update
  /// @param[out] irs_info      The IRS information stored about this public ID
  /// @param[in]  trail         The SAS trail ID
  virtual HTTPCode update_subscription(const std::string& public_id,
                                       const SubscriptionPair& subscription,
                                       HSSConnection::irs_info& irs_info,
                                       SAS::TrailId trail);

  /// Removes a subscription stored in SM for a given public ID.
  ///
  /// @param[in]  public_id     The public ID subscribed to
  /// @param[in]  subscription  The subscription ID to remove
  /// @param[out] irs_info      The IRS information stored about this public ID
  /// @param[in]  trail         The SAS trail ID
  virtual HTTPCode remove_subscription(const std::string& public_id,
                                       const std::string& subscription_id,
                                       HSSConnection::irs_info& irs_info,
                                       SAS::TrailId trail);

  /// Deregisters a subscriber completely.
  ///
  /// @param[in]  public_id     The public ID to deregister
  /// @param[in]  trail         The SAS trail ID
  virtual HTTPCode deregister_subscriber(const std::string& public_id,
                                         SAS::TrailId trail);

  /// Gets all bindings stored for a given AoR ID.
  ///
  /// @param[in]  aor_id        The AoR ID to lookup in the store. It is the
  ///                           client's responsibilty to provide an ID that
  ///                           will be found in the store i.e. a default public
  ///                           ID
  ///                           Providing a non-default IMPU from an IRS will
  ///                           NOT return all binidngs
  /// @param[out] bindings      All bindings stored for this AoR
  /// @param[in]  trail         The SAS trail ID
  virtual HTTPCode get_bindings(const std::string& aor_id,
                                Bindings& bindings,
                                SAS::TrailId trail);

  /// Gets all bindings and subscriptions stored for a given AoR ID.
  ///
  /// @param[in]  aor_id        The AoR ID to lookup in the store. It is the
  ///                           client's responsibilty to provide an ID that
  ///                           will be found in the store i.e. a default public
  ///                           ID
  ///                           Providing a non-default IMPU from an IRS will
  ///                           NOT return all subscriptions
  /// @param[out] subscriptions All subscriptions stored for this AoR
  /// @param[in]  trail         The SAS trail ID
  virtual HTTPCode get_subscriptions(const std::string& aor_id,
                                     Subscriptions& subscriptions,
                                     SAS::TrailId trail);

  /// Gets the cached subscriber state for a given public ID.
  ///
  /// @param[in]  public_id     The public ID to get cached state for
  /// @param[out] irs_info      The cached IRS information for this public ID
  /// @param[in]  trail         The SAS trail ID
  virtual HTTPCode get_cached_subscriber_state(const std::string& public_id,
                                               HSSConnection::irs_info& irs_info,
                                               SAS::TrailId trail);

  /// Gets the subscriber state for a given public ID. This is different to
  /// get_cached_subscriber_state() because it can result in a call to the HSS
  /// if Homestead does not have the information cached.
  ///
  /// @param[in]  public_id     The public ID to get state for
  /// @param[out] irs_info      The IRS information for this public ID
  /// @param[in]  trail         The SAS trail ID
  virtual HTTPCode get_subscriber_state(const HSSConnection::irs_query& irs_query,
                                        HSSConnection::irs_info& irs_info,
                                        SAS::TrailId trail);

  /// Update the associated URIs stored in an AoR.
  ///
  /// @param[in]  aor_id        The AoR ID to lookup in the store. It is the
  ///                           client's responsibilty to provide an ID that
  ///                           will be found in the store i.e. a default public
  ///                           ID
  ///                           Providing a non-default IMPU from an IRS will
  ///                           NOT result in the associated URIs being updated
  /// @param[in]  associated_uris
  ///                           The new associated URIs
  /// @param[in]  trail         The SAS trail ID
  virtual HTTPCode update_associated_uris(const std::string& aor_id,
                                          const AssociatedURIs& associated_uris,
                                          SAS::TrailId trail);

  /// Handle a timer pop.
  ///
  /// @param[in]  aor_id        The AoR ID to handle a timer pop for
  /// @param[in]  trail         The SAS trail ID
  virtual void handle_timer_pop(const std::string& aor_id,
                                SAS::TrailId trail);

  /// Register a subscriber with its application servers
  ///
  /// @param[in]  received_register_message
  ///                           The received register message. This may be
  ///                           included in the body of 3rd party registers
  /// @param[in]  ok_response_msg
  ///                           The response to the REGISTER message. This may
  ///                           be included in teh body of 3rd party registers
  /// @param[in]  served_user   The IMPU we are sending 3rd party registers for
  /// @param[in]  ifcs          The iFCs to parse to determine the 3rd party
  ///                           application servers
  /// @param[in]  expires       The expiry of the received register
  /// @param[in]  is_initial_registration
  ///                           Whether or not the received registraion is an
  ///                           initial registration
  /// @param[in]  trail         The SAS trail ID
  virtual void register_with_application_servers(pjsip_msg* received_register_message,
                                                 pjsip_msg* ok_response_msg,
                                                 const std::string& served_user,
                                                 const Ifcs& ifcs,
                                                 int expires,
                                                 bool is_initial_registration,
                                                 SAS::TrailId trail);

private:
  S4* _s4;
  HSSConnection* _hss_connection;
  AnalyticsLogger* _analytics;
  NotifySender* _notify_sender;
  RegistrationSender* _registration_sender;

  HTTPCode modify_subscription(const std::string& public_id,
                               const SubscriptionPair& update_subscription,
                               const std::string& remove_subscription,
                               HSSConnection::irs_info& irs_info,
                               SAS::TrailId trail);

  HTTPCode get_cached_default_id(const std::string& public_id,
                                 std::string& aor_id,
                                 HSSConnection::irs_info& irs_info,
                                 SAS::TrailId trail);

  HTTPCode put_bindings(const std::string& aor_id,
                        const Bindings& update_bindings,
                        const AssociatedURIs& associated_uris,
                        const std::string& scscf_uri,
                        AoR*& aor,
                        SAS::TrailId trail);

  HTTPCode patch_bindings(const std::string& aor_id,
                          const Bindings& update_bindings,
                          const std::vector<std::string>& remove_bindings,
                          const std::vector<std::string>& remove_subscriptions,
                          const AssociatedURIs& associated_uris,
                          AoR*& aor,
                          SAS::TrailId trail);

  HTTPCode patch_subscription(const std::string& aor_id,
                              const SubscriptionPair& update_subscription,
                              const std::string& remove_subscription,
                              AoR*& aor,
                              SAS::TrailId trail);

  HTTPCode patch_bindings_and_subscriptions(const std::string& aor_id,
                                            const std::vector<std::string>& remove_bindings,
                                            const std::vector<std::string>& remove_subscriptions,
                                            AoR*& aor,
                                            SAS::TrailId trail);

  HTTPCode patch_associated_uris(const std::string& aor_id,
                                 const AssociatedURIs& associated_uris,
                                 AoR*& aor,
                                 SAS::TrailId trail);

  std::vector<std::string> subscriptions_to_remove(const Bindings& orig_bindings,
                                                   const Subscriptions& orig_subscriptions,
                                                   const Bindings& bindings_to_update,
                                                   const std::vector<std::string> binding_ids_to_remove);

  void send_notifys(const std::string& aor_id,
                    AoR* orig_aor,
                    AoR* updated_aor,
                    const SubscriberDataUtils::EventTrigger& event_trigger,
                    int now,
                    SAS::TrailId trail);

  void log_removed_bindings(const AoR* orig_aor,
                            const std::vector<std::string>& binding_ids);

  void log_updated_bindings(const AoR* updated_aor,
                            const Bindings& binding_pairs,
                            int now);

  void log_subscriptions(std::string default_impu,
                         const AoR* orig_aor,
                         const AoR* updated_aor,
                         std::string subscription_id,
                         int now);

  HTTPCode deregister_with_hss(const std::string& aor_id,
                               const std::string& dereg_reason,
                               const std::string& server_name,
                               HSSConnection::irs_info& irs_info,
                               SAS::TrailId trail);

};

#endif
