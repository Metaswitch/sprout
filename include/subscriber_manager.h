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

// SDM-REFACTOR-TODO:
//  - Add Doxygen return
//  - Add overall comment.

/// @class SubscriberManager
///
/// This class manages subscriber state. Its API exposes methods for clients
/// to make changes to subscriber state e.g. register_subscriber(). It owns
/// connections to the HSS, S4, and sends NOTIFYs and 3rd party (de)registers.
class SubscriberManager : public S4::TimerPopConsumer,
                          public RegistrationSender::DeregistrationEventConsumer
{
public:
  /// SubscriberManager constructor.
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

  /// Registers a subscriber in SM to a given AoR Id. This method is by a client
  /// that believes it is registering a subscriber for the first time, or on a
  /// fetch bindings register when the subscriber is unregistered.
  ///
  /// @param[in]  aor_id        The default public ID for this subscriber
  /// @param[in]  server_name   The S-CSCF assigned to this subscriber
  /// @param[in]  associated_uris
  ///                           The IMPUs associated with this IRS
  /// @param[in]  add_bindings  The bindings to add (can be empty in the fetch
  ///                           bindings case)
  /// @param[out] all_bindings  All bindings currently stored for this subscriber.
  ///                           It is the responsibility of the clients to free
  ///                           these bindings
  /// @param[out] irs_info      The IRS information from the HSS.
  /// @param[in]  trail         The SAS trail ID
  virtual HTTPCode register_subscriber(const std::string& aor_id,
                                       const std::string& server_name,
                                       const AssociatedURIs& associated_uris,
                                       const Bindings& add_bindings,
                                       Bindings& all_bindings,
                                       HSSConnection::irs_info& irs_info,
                                       SAS::TrailId trail);

  /// Reregisters a subscriber in SM to a given AoR Id. This method is called by
  /// a client that wants to modify the registration state of a subscriber that
  /// it believes is currently registered. This can be for a reregister or a
  /// deregister (when the registrar ends up removing all bindings).
  ///
  /// @param[in]  aor_id        The default public ID for this subscriber
  /// @param[in]  server_name   The S-CSCF assigned to this subscriber
  /// @param[in]  associated_uris
  ///                           The IMPUs associated with this IRS
  /// @param[in]  updated_bindings
  ///                           The bindings to update
  /// @param[in]  binding_ids_to_remove
  ///                           The binding IDs to remove (binding IDs are
  ///                           formed from the contact URI on a register)
  /// @param[out] all_bindings  All bindings currently stored for this subscriber.
  ///                           It is the responsibility of the clients for free
  ///                           these bindings
  /// @param[out] irs_info      The IRS information from the HSS.
  /// @param[in]  trail         The SAS trail ID
  virtual HTTPCode reregister_subscriber(const std::string& aor_id,
                                         const std::string& server_name,
                                         const AssociatedURIs& associated_uris,
                                         const Bindings& updated_bindings,
                                         const std::vector<std::string>& binding_ids_to_remove,
                                         Bindings& all_bindings,
                                         HSSConnection::irs_info& irs_info,
                                         SAS::TrailId trail);

  /// Removes bindings stored in SM for a given public ID.
  ///
  /// @param[in]  public_id     The public IDs to remove bindings for
  /// @param[in]  binding_ids   The binding IDs to remove (binding IDs are
  ///                           formed from the contact URI on a register)
  /// @param[in]  event_trigger The reason for removing bindings
  /// @param[out] bindings      All bindings currently stores for this public ID.
  ///                           It is the responsibility of the clients to free
  ///                           these bindings
  /// @param[in]  trail         The SAS trail ID
  virtual HTTPCode remove_bindings(const std::string& public_id,
                                   const std::vector<std::string>& binding_ids,
                                   const SubscriberDataUtils::EventTrigger& event_trigger,
                                   Bindings& bindings,
                                   SAS::TrailId trail);

  /// Updates a subscription stored in SM for a given public ID.
  ///
  /// @param[in]  public_id     The public ID being subscribed to
  /// @param[in]  subscription  The subscriptions to update
  /// @param[out] irs_info      The IRS information stored about this public ID
  /// @param[in]  trail         The SAS trail ID
  virtual HTTPCode update_subscriptions(const std::string& public_id,
                                        const Subscriptions& subscriptions,
                                        HSSConnection::irs_info& irs_info,
                                        SAS::TrailId trail);

  /// Removes a subscription stored in SM for a given public ID.
  ///
  /// @param[in]  public_id     The public ID subscribed to
  /// @param[in]  subscription_ids
  ///                           The subscription IDs to remove (subscription ID
  ///                           is formed from the to tag on a subscribe)
  /// @param[out] irs_info      The IRS information stored about this public ID
  /// @param[in]  trail         The SAS trail ID
  virtual HTTPCode remove_subscriptions(const std::string& public_id,
                                        const std::vector<std::string>& subscription_ids,
                                        HSSConnection::irs_info& irs_info,
                                        SAS::TrailId trail);

  /// Deregisters a subscriber completely.
  ///
  /// @param[in]  public_id     The public ID to deregister
  /// @param[in]  trail         The SAS trail ID
  virtual HTTPCode deregister_subscriber(const std::string& public_id,
                                         SAS::TrailId trail);

  /// Gets all bindings stored for a given AoR ID. If there are any expired
  /// bindings, these are not returned.
  ///
  /// @param[in]  aor_id        The AoR ID to lookup in the store. It is the
  ///                           client's responsibilty to provide an ID that
  ///                           will be found in the store i.e. a default public
  ///                           ID
  ///                           Providing a non-default IMPU from an IRS will
  ///                           NOT return all binidngs
  /// @param[out] bindings      All bindings stored for this AoR. It is the
  ///                           responsibility of the clients to free these
  ///                           bindings
  /// @param[in]  trail         The SAS trail ID
  virtual HTTPCode get_bindings(const std::string& aor_id,
                                Bindings& bindings,
                                SAS::TrailId trail);

  /// Gets all subscriptions stored for a given AoR ID. If there are any expired
  /// subscriptions, these are not returned.
  ///
  /// @param[in]  aor_id        The AoR ID to lookup in the store. It is the
  ///                           client's responsibilty to provide an ID that
  ///                           will be found in the store i.e. a default public
  ///                           ID
  ///                           Providing a non-default IMPU from an IRS will
  ///                           NOT return all subscriptions
  /// @param[out] subscriptions All subscriptions stored for this AoR. It is the
  ///                           responsibility of the clients to free these
  ///                           subscriptions
  /// @param[in]  trail         The SAS trail ID
  virtual HTTPCode get_subscriptions(const std::string& aor_id,
                                     Subscriptions& subscriptions,
                                     SAS::TrailId trail);

  /// Gets the cached HSS subscriber state for a given public ID.
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
  ///                           The updated set of associated URIs
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
  ///                           be included in the body of 3rd party registers
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

  /// Internal functions that methods on the interface call.
  HTTPCode register_subscriber_internal(const std::string& aor_id,
                                        const std::string& server_name,
                                        const AssociatedURIs& associated_uris,
                                        const Bindings& add_bindings,
                                        Bindings& all_bindings,
                                        HSSConnection::irs_info& irs_info,
                                        bool retry,
                                        SAS::TrailId trail);
  HTTPCode reregister_subscriber_internal(const std::string& aor_id,
                                          const std::string& server_name,
                                          const AssociatedURIs& associated_uris,
                                          const Bindings& updated_bindings,
                                          const std::vector<std::string>& binding_ids_to_remove,
                                          Bindings& all_bindings,
                                          HSSConnection::irs_info& irs_info,
                                          bool retry,
                                          SAS::TrailId trail);
  HTTPCode modify_subscriptions(const std::string& public_id,
                                const Subscriptions& update_subscriptions,
                                const std::vector<std::string>& remove_subscriptions,
                                HSSConnection::irs_info& irs_info,
                                SAS::TrailId trail);
  void handle_timer_pop_internal(const std::string& aor_id,
                                 SAS::TrailId trail);

  /// Helper function to get the default public ID from the HSS.
  HTTPCode get_cached_default_id(const std::string& public_id,
                                 std::string& aor_id,
                                 HSSConnection::irs_info& irs_info,
                                 SAS::TrailId trail);

  /// Helper function to determine if there are any subscriptions to remove
  /// based on changes to bindings.
  std::vector<std::string> subscriptions_to_remove(const Bindings& orig_bindings,
                                                   const Subscriptions& orig_subscriptions,
                                                   const Bindings& bindings_to_update,
                                                   const std::vector<std::string> binding_ids_to_remove);

  /// Sends NOTIFYs by looking at the original and updated AoRs.
  void send_notifys(const std::string& aor_id,
                    AoR* orig_aor,
                    AoR* updated_aor,
                    const SubscriberDataUtils::EventTrigger& event_trigger,
                    int now,
                    SAS::TrailId trail);

  /// Helper function to deregister a subscriber with the HSS.
  HTTPCode deregister_with_hss(const std::string& aor_id,
                               const std::string& dereg_reason,
                               const std::string& server_name,
                               HSSConnection::irs_info& irs_info,
                               SAS::TrailId trail);

  // Helper functions to write audit logs.
  void log_removed_bindings(const AoR& orig_aor,
                            const std::vector<std::string>& binding_ids);
  void log_updated_bindings(const AoR& updated_aor,
                            const Bindings& binding_pairs,
                            int now);
  void log_subscriptions(std::string default_impu,
                         const AoR& orig_aor,
                         const AoR& updated_aor,
                         const std::vector<std::string>& subscription_ids,
                         int now);

  /// Methods to build patch objects.
  void build_patch(PatchObject& po,
                   const Bindings& update_bindings,
                   const std::vector<std::string>& remove_bindings,
                   const std::vector<std::string>& remove_subscriptions,
                   const AssociatedURIs& associated_uris);
  void build_patch(PatchObject& po,
                   const Bindings& update_bindings,
                   const AssociatedURIs& associated_uris);
  void build_patch(PatchObject& po,
                   const Subscriptions& update_subscriptions,
                   const std::vector<std::string>& remove_subscriptions,
                   const AssociatedURIs& associated_uris);
  void build_patch(PatchObject& po,
                   const std::vector<std::string>& remove_bindings,
                   const std::vector<std::string>& remove_subscriptions,
                   const AssociatedURIs& associated_uris);
  void build_patch(PatchObject& po,
                   const std::vector<std::string>& remove_bindings,
                   const std::vector<std::string>& remove_subscriptions);
  void build_patch(PatchObject& po,
                   const AssociatedURIs& associated_uris);
};

#endif
