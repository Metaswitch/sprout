/**
 * @file registrarsproutlet.h Initialization/Termination functions for
 *                            Sprout's Registrar sproutlet.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef REGISTRARSPROUTLET_H__
#define REGISTRARSPROUTLET_H__

#include <vector>
#include <unordered_map>

#include "enumservice.h"
#include "subscriber_manager.h"
#include "stack.h"
#include "ifchandler.h"
#include "hssconnection.h"
#include "aschain.h"
#include "acr.h"
#include "sproutlet.h"
#include "snmp_success_fail_count_table.h"
#include "session_expires_helper.h"
#include "as_communication_tracker.h"
#include "compositesproutlet.h"

class RegistrarSproutletTsx;

/// Enum to determine what type of request a register is. If the request is
/// removing any bindings then it's a deregister request, otherwise if the
/// subscriber has no current bindings then it's any initial request,
/// otherwise it's a register request.
///
/// Ideally there would also be an UNKNOWN type to cover the cases where the
/// register fails too early for us to be able to determine what type of
/// register it really was. Instead, all unknown requests are treated as
/// deregister requests.
enum RegisterType
{
  INITIAL = 0,
  REREGISTER,
  DEREGISTER,
  FETCH_INITIAL,
  FETCH,
};

class RegistrarSproutlet : public Sproutlet
{
public:
  RegistrarSproutlet(const std::string& name,
                     int port,
                     const std::string& uri,
                     const std::list<std::string>& aliases,
                     const std::string& network_function,
                     const std::string& next_hop_service,
                     SubscriberManager* sm,
                     ACRFactory* rfacr_factory,
                     int cfg_max_expires,
                     bool force_original_register_inclusion,
                     SNMP::RegistrationStatsTables* reg_stats_tbls,
                     SNMP::RegistrationStatsTables* third_party_reg_stats_tbls);
  ~RegistrarSproutlet();

  bool init();

  SproutletTsx* get_tsx(SproutletHelper* helper,
                        const std::string& alias,
                        pjsip_msg* req,
                        pjsip_sip_uri*& next_hop,
                        pj_pool_t* pool,
                        SAS::TrailId trail) override;

  int expiry_for_binding(pjsip_contact_hdr* contact,
                         pjsip_expires_hdr* expires);

private:
  friend class RegistrarSproutletTsx;

  SubscriberManager* _sm;

  // Factory for create ACR messages for Rf billing flows.
  ACRFactory* _acr_factory;

  int _max_expires;
  bool _force_original_register_inclusion;

  // Pre-constructed Service Route header added to REGISTER responses.
  pjsip_routing_hdr* _service_route;

  // SNMP tables that count the number of attempts, successes and failures of
  // registration attempts.
  SNMP::RegistrationStatsTables* _reg_stats_tbls;
  SNMP::RegistrationStatsTables* _third_party_reg_stats_tbls;

  // The next service to route requests onto if the sproutlet does not handle
  // them itself.
  std::string _next_hop_service;
};


class RegistrarSproutletTsx : public CompositeSproutletTsx
{
public:
  RegistrarSproutletTsx(RegistrarSproutlet* registrar,
                        const std::string& next_hop_service);
  ~RegistrarSproutletTsx();

  virtual void on_rx_initial_request(pjsip_msg* req);

protected:
  void process_register_request(pjsip_msg* req);

  /// Perform basic validation of the register. We can reject the request
  /// early which saves contacting the HSS/memcached.
  ///
  /// @param req[in]                     - The request to validate.
  /// @param num_contact_headers[out]    - How many contact headers there were
  ///                                      in the request.
  /// @param emergency_registration[out] - Whether this register adds/updates
  ///                                      an emergency registration.
  ///
  /// @return Whether the request is valid. The cases are:
  ///   PJSIP_OK - The request is valid
  ///   PJSIP_SC_NOT_FOUND - The request has an invalid scheme
  ///   PJSIP_SC_BAD_REQUEST - The request has an invalid contact URI
  ///   PJSIP_SC_NOT_IMPLEMENTED - The request is attempting to deregister
  ///                              emergency registrations
  pjsip_status_code basic_validation_of_register(pjsip_msg* req,
                                                 int& num_contact_headers,
                                                 bool& emergency_registration);

  void get_bindings_from_req(pjsip_msg* req,         ///<REGISTER request containing new binding information
                             const std::string& private_id, ///<private ID that the request refers to
                             const std::string& aor_id,
                             const int& now,
                             const Bindings& current_bindings,
                             Bindings& updated_bindings,
                             std::vector<std::string>& binding_ids_to_remove);

  bool get_private_id(pjsip_msg* req, std::string& id);
  std::string get_binding_id(pjsip_contact_hdr* contact);

  void add_contact_headers(pjsip_msg* rsp,
                           pjsip_msg* req,
                           const Bindings& all_bindings,
                           int now,
                           const std::string& public_id,
                           SAS::TrailId trail);
  void handle_path_headers(pjsip_msg* rsp,
                           pjsip_msg* req,
                           const Bindings& bindings);
  void add_service_route_header(pjsip_msg* rsp,
                                pjsip_msg* req);
  void add_p_associated_uri_headers(pjsip_msg* rsp,
                                    HSSConnection::irs_info& irs_info,
                                    const std::string& aor,
                                    SAS::TrailId trail);

  /// Get what type of registration this is.
  RegisterType get_register_type(
                         const int& contact_headers,
                         const Bindings& current_bindings,
                         const Bindings& bindings_to_update,
                         const std::vector<std::string>& binding_ids_to_remove);

  /// Track the register statistics
  void track_register_attempts_statistics(const RegisterType& rt);
  void track_register_successes_statistics(const RegisterType& rt);
  void track_register_failures_statistics(const RegisterType& rt);

  RegistrarSproutlet* _registrar;

  // The S-CSCF URI for this transaction. This is used on any SAR that is sent
  // to the HSS. This field should not be changed once it has been set by the
  // on_rx_intial_request() call.
  std::string _scscf_uri;
};

#endif
