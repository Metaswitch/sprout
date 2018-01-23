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
  void get_bindings_from_req(pjsip_msg* req,         ///<REGISTER request containing new binding information
                             std::string private_id, ///<private ID that the request refers to
                             const int& now,
                             Bindings& updated_bindings,
                             std::vector<std::string>& binding_ids_to_remove);

  bool get_private_id(pjsip_msg* req, std::string& id);
  std::string get_binding_id(pjsip_contact_hdr *contact);
  void add_contact_headers(pjsip_msg* rsp,
                           pjsip_msg* req,
                           Bindings all_bindings,
                           int now,
                           std::string public_id,
                           SAS::TrailId trail);
  void handle_path_headers(pjsip_msg* rsp,
                           pjsip_msg* req,
                           Bindings bindings);
  void add_service_route_header(pjsip_msg* rsp,
                                pjsip_msg* req);
  void add_p_associated_uri_headers(pjsip_msg* rsp,
                                    HSSConnection::irs_info& irs_info,
                                    std::string aor,
                                    SAS::TrailId trail);

  RegistrarSproutlet* _registrar;

  // The S-CSCF URI for this transaction. This is used on any SAR that is sent
  // to the HSS. This field should not be changed once it has been set by the
  // on_rx_intial_request() call.
  std::string _scscf_uri;
};

#endif
