/**
 * @file registration_sender.h
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef REGISTRATION_SENDER_H__
#define REGISTRATION_SENDER_H__

#include "ifc.h"
#include "ifchandler.h"
#include "fifcservice.h"
#include "pjutils.h"
#include "snmp_success_fail_count_table.h"

/// @class RegistrationSender
///
/// This class is responsible for sending 3rd party (de)registrations to
/// application servers and running callbacks based on the success or failure
/// of these registrations.
class RegistrationSender
{
public:
  /// @class DeregistrationEventConsumer
  ///
  /// If 3rd party registrations fail the user of the RegistrationSender may
  /// need to take action to deregister some associated identities. This class
  /// defines the interface that the user of the RegistrationSender must
  /// implement in order to receive this notification.
  class DeregistrationEventConsumer
  {
  public:
    /// Called to notify the consumer that a subscriber must be de-registered.
    ///
    /// @param[in] public_id      The public identity to deregister. This is
    ///                           not necessarily a primary IMPU.
    /// @param[in] trail          SAS trail ID to use for logging.
    ///
    /// @return  HTTPCode indicating the success or failure of the
    ///          deregistration operation.
    virtual HTTPCode deregister_subscriber(const std::string& public_id,
                                           SAS::TrailId trail) = 0;

    virtual ~DeregistrationEventConsumer() {}
  };

  /// Registration sender constructor
  ///
  /// @param  ifc_configuration iFC configuration for fallback and dummy iFCs
  /// @param  fifc_service      Service to lookup fallback iFCs
  /// @param  third_party_reg_stats_tbls
  ///                           Statistics for thrid party registers
  /// @param  force_third_party_register_body
  ///                           Whether the thrid party register body should
  ///                           contain the received register and its response
  RegistrationSender(IFCConfiguration ifc_configuration,
                     FIFCService* fifc_service,
                     SNMP::RegistrationStatsTables* third_party_reg_stats_tbls,
                     bool force_third_party_register_body);

  /// Registration sender destructor
  virtual ~RegistrationSender();

  /// Initializes the registration sender with a reference to the consumer of
  /// dregistration events
  ///
  /// @param[in]  dereg_event_consumer
  ///                           The consumer of deregistration events
  void register_dereg_event_consumer(DeregistrationEventConsumer* dereg_event_consumer);

  /// Registers a subscriber with its application servers
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
  /// @param[in]  expires       The expiry of the received register. An expiry
  ///                           of 0 results in a deregistration
  /// @param[in]  is_initial_registration
  ///                           Whether or not the received register is an
  ///                           initial registration
  /// @param[out] deregister_subscriber
  ///                           Whether to deregister the subscriber after this
  ///                           call.
  /// @param[in]  trail         The SAS trail ID
  virtual void register_with_application_servers(pjsip_msg* received_register_message,
                                                 pjsip_msg* ok_response_msg,
                                                 const std::string& served_user,
                                                 const Ifcs& ifcs,
                                                 int expires,
                                                 bool is_initial_registration,
                                                 bool& deregister_subscriber,
                                                 SAS::TrailId trail);

  /// Deregister a subscriber with its application servers
  ///
  /// @param[in]  served_user   The IMPU we are sending 3rd party deregisters for
  /// @param[in]  ifcs          The iFCs to parse to determine the 3rd party
  ///                           application servers.
  /// @param[in]  trail         The SAS trail ID
  virtual void deregister_with_application_servers(const std::string& served_user,
                                                   const Ifcs& ifcs,
                                                   SAS::TrailId trail);

private:
  DeregistrationEventConsumer* _dereg_event_consumer;
  IFCConfiguration _ifc_configuration;
  FIFCService* _fifc_service;
  SNMP::RegistrationStatsTables* _third_party_reg_stats_tbls;
  bool _force_third_party_register_body;

  /// Works out which iFCs apply to the received register message and returns a
  /// list of matched application servers
  ///
  /// @param[in]  received_register_message
  ///                           The received register message
  /// @param[in]  ifcs          The iFCs to parse to determine the 3rd party
  ///                           application servers
  /// @param[in]  fallback_ifcs Any fallbakc iFCs that may apply to this
  ///                           register
  /// @param[in]  is_initial_registration
  ///                           Whether or not the received register is an
  ///                           initial registration
  /// @param[out] application_servers
  ///                           The matched application servers. Does not
  ///                           include any dummy application servers
  /// @param[out] matched_dummy_as
  ///                           Whether we mathed a dummy application server
  /// @param[in]  trail         The SAS trail ID
  void match_application_servers(pjsip_msg* received_register_msg,
                                 const Ifcs& ifcs,
                                 const std::vector<Ifc>& fallback_ifcs,
                                 bool is_initial_registration,
                                 std::vector<AsInvocation>& application_servers,
                                 bool& matched_dummy_as,
                                 SAS::TrailId trail);

  /// Sends a 3rd party register to an application server
  ///
  /// @param[in]  received_register_message
  ///                           The received register message. This may be
  ///                           included in the body of 3rd party registers
  /// @param[in]  ok_response_msg
  ///                           The response to the REGISTER message. This may
  ///                           be included in the body of 3rd party registers
  /// @param[in]  served_user   The IMPU we are sending 3rd party registers for
  /// @param[in]  as            The application server we are sending a 3rd
  ///                           party register to
  /// @param[in]  expires       The expiry of the received register
  /// @param[in]  is_initial_registration
  ///                           Whether or not the received register is an
  ///                           initial registration
  /// @param[in]  trail         The SAS trail ID
  void send_register_to_as(pjsip_msg* received_register_msg,
                           pjsip_msg* ok_response_msg,
                           const std::string& served_user,
                           const AsInvocation& as,
                           int expires,
                           bool is_initial_registration,
                           SAS::TrailId trail);


  /// Builds a PJSIP callback for when the 3rd party register completes
  ///
  /// @param[in]  token         Token containing the stored ThirdPartyRegData
  /// @param[in]  event         The SIP event that triggered the callback.
  static PJUtils::Callback* build_register_cb(void* token,
                                              pjsip_event* event);

  /// Data structure used to store data that is needed on a third party
  /// register callack
  struct ThirdPartyRegData
  {
    RegistrationSender* registration_sender;
    DeregistrationEventConsumer* dereg_event_consumer;
    std::string served_user;
    DefaultHandling default_handling;
    int expires;
    bool is_initial_registration;
    SAS::TrailId trail;
  };

  /// The PJSIP callback that is run when a 3rd party register completes.
  class RegisterCallback : public PJUtils::Callback
  {
    int _status_code;
    ThirdPartyRegData* _reg_data;
    std::function<void(ThirdPartyRegData*, int)> _send_register_callback;

  public:
    /// The PJSIP callback for when a 3rd party register completes
    ///
    /// @param[in]  token         Token containing the stored ThirdPartyRegData
    /// @param[in]  event         The SIP event that triggered the callback.
    RegisterCallback(void* token, pjsip_event* event);

    /// Callback destructor
    ~RegisterCallback() override;

    /// Run the callback
    void run() override;
  };
};

#endif
