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
#include "subscriber_manager.h"
#include "pjutils.h"
#include "snmp_success_fail_count_table.h"

// TODO Doxygen comments.

class RegistrationSender
{
public:
  RegistrationSender(SubscriberManager* subscriber_manager,
                     IFCConfiguration ifc_configuration,
                     FIFCService* fifc_service,
                     SNMP::RegistrationStatsTables* third_party_reg_stats_tbls,
                     bool force_third_party_register_body);

  virtual ~RegistrationSender();

  /// TODO - is this the right interface?
  ///      - Should we pass the IRS info?
  ///      - Do we need to pass back whether to deregister the subscriber?
  ///        e.g. if the _reject_if_no_matching_ifcs flag is set.
  ///
  /// Registers a subscriber with its application servers.
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
  /// @param[in]  expires       The expiry of the received register TODO should
  ///                           this be the max or min expiry?
  /// @param[in]  is_initial_registration
  ///                           Whether or not the received registraion is an
  ///                           initial registration
  /// @param[in]  trail         The SAS trail ID
  void register_with_application_servers(pjsip_msg* received_register_message,
                                         pjsip_msg* ok_response_msg,
                                         const std::string& served_user,
                                         const Ifcs& ifcs,
                                         int expires,
                                         bool is_initial_registration,
                                         SAS::TrailId trail);

  void deregister_with_application_servers(const std::string& served_user,
                                           const Ifcs& ifcs,
                                           SAS::TrailId trail);

private:
  SubscriberManager* _subscriber_manager;
  IFCConfiguration _ifc_configuration;
  FIFCService* _fifc_service;
  SNMP::RegistrationStatsTables* _third_party_reg_stats_tbls;
  bool _force_third_party_register_body;

  /// TODO better method name.
  ///
  /// Works out which iFCs apply to the received register message and returns a
  /// list of matched application servers.
  ///
  /// @param[in]  received_register_message
  ///                           The received register message
  /// @param[in]  ifcs          The iFCs to parse to determine the 3rd party
  ///                           application servers
  /// @param[in]  fallback_ifcs Any fallbakc iFCs that may appply to this
  ///                           register
  /// @param[in]  is_initial_registration
  ///                           Whether or not the received registraion is an
  ///                           initial registration
  /// @param[out] application_servers
  ///                           The matched application servers. Does not
  ///                           include any dummy application servers.
  /// @param[out] found_match   Whether we found any matching application
  ///                           servers. TODO is this needed? This is actually
  ///                           talking about dummy iFCs - rename to reflect that.
  /// @param[in]  trail         The SAS trail ID
  void interpret_ifcs(pjsip_msg* received_register_msg,
                      const Ifcs& ifcs,
                      const std::vector<Ifc>& fallback_ifcs,
                      bool is_initial_registration,
                      std::vector<AsInvocation>& application_servers,
                      bool& found_match,
                      SAS::TrailId trail);

  /// Sends a 3rd party register to an application server.
  ///
  /// @param[in]  received_register_message
  ///                           The received register message. This may be
  ///                           included in the body of 3rd party registers
  /// @param[in]  ok_response_msg
  ///                           The response to the REGISTER message. This may
  ///                           be included in teh body of 3rd party registers
  /// @param[in]  served_user   The IMPU we are sending 3rd party registers for
  /// @param[in]  as            The application server we are sending a 3rd
  ///                           party register to
  /// @param[in]  expires       The expiry of the received register TODO should
  ///                           this be the max or min expiry?
  /// @param[in]  is_initial_registration
  ///                           Whether or not the received registraion is an
  ///                           initial registration
  /// @param[in]  trail         The SAS trail ID
  void send_register_to_as(pjsip_msg* received_register_msg,
                           pjsip_msg* ok_response_msg,
                           const std::string& served_user,
                           const AsInvocation& as,
                           int expires,
                           bool is_initial_registration,
                           SAS::TrailId trail);

  static PJUtils::Callback* build_register_cb(void* token,
                                              pjsip_event* event);

  /// TODO update comment.
  /// Temporary data structure maintained while transmitting a third-party
  /// REGISTER to an application server.
  struct ThirdPartyRegData
  {
    RegistrationSender* registration_sender;
    SubscriberManager* subscriber_manager;
    std::string public_id; // TODO rename to served_user?
    DefaultHandling default_handling;
    int expires;
    bool is_initial_registration;
    SAS::TrailId trail;
  };

  class RegisterCallback : public PJUtils::Callback
  {
    int _status_code;
    ThirdPartyRegData* _reg_data;
    std::function<void(ThirdPartyRegData*, int)> _send_register_callback;

  public:
    RegisterCallback(void* token, pjsip_event* event);

    ~RegisterCallback() override;

    void run() override;
  };
};

#endif
