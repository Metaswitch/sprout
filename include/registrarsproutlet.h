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
#include "subscriber_data_manager.h"
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
                     SubscriberDataManager* reg_sdm,
                     std::vector<SubscriberDataManager*> reg_remote_sdms,
                     HSSConnection* hss_connection,
                     ACRFactory* rfacr_factory,
                     int cfg_max_expires,
                     bool force_original_register_inclusion,
                     SNMP::RegistrationStatsTables* reg_stats_tbls,
                     SNMP::RegistrationStatsTables* third_party_reg_stats_tbls,
                     FIFCService* fifcservice,
                     IFCConfiguration ifc_configuration);
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

  SubscriberDataManager* _sdm;
  std::vector<SubscriberDataManager*> _remote_sdms;

  // Connection to the HSS service for retrieving associated public URIs.
  HSSConnection* _hss;

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

  // Fallback IFCs service
  FIFCService* _fifc_service;
  IFCConfiguration _ifc_configuration;

  // The next service to route requests onto if the sproutlet does not handle
  // them itself.
  std::string _next_hop_service;
};


class RegistrarSproutletTsx : public CompositeSproutletTsx
{
public:
  RegistrarSproutletTsx(RegistrarSproutlet* registrar,
                        const std::string& next_hop_service,
                        FIFCService* fifc_service,
                        IFCConfiguration ifc_configuration);
  ~RegistrarSproutletTsx();

  virtual void on_rx_initial_request(pjsip_msg* req);

protected:
  void process_register_request(pjsip_msg* req);
  void update_bindings_from_req(AoRPair* aor_pair,      ///<AoR pair containing any existing bindings
                                pjsip_msg* req,         ///<REGISTER request containing new binding information
                                int now,                ///<the time now.
                                std::string private_id, ///<private ID that the request refers to
                                int& changed_bindings,  ///<[out] the number of bindings in the request
                                int& max_expiry);       ///<[out] the max_expiry time of bindings in the request

  AoRPair* write_to_store(SubscriberDataManager* primary_sdm,         ///<store to write to
                          std::string aor,                            ///<address of record to write to
                          AssociatedURIs* associated_uris,            ///<Associated IMPUs in Implicit Registration Set
                          pjsip_msg* req,                             ///<received request to read headers from
                          int now,                                    ///<time now
                          int& max_expiry,                            ///<[out] longest expiry time
                          bool is_initial_registration,               ///<Does the caller believe that this is an initial registration?
                          bool& out_no_bindings_found,                ///<[out] true if no previous bindings were found
                          AoRPair* backup_aor,                        ///<backup data if no entry in store
                          std::vector<SubscriberDataManager*> backup_sdms,
                                                                      ///<backup stores to read from if no entry in store and no backup data
                          std::string private_id,                     ///<private id that the binding was registered with
                          bool& out_all_bindings_expired,             ///<[out] whether all bindings have now expired.
                          int& initial_notify_cseq);                  ///<[out] The CSeq value on the AoR pair before it is written to the store

  bool get_private_id(pjsip_msg* req, std::string& id);
  std::string get_binding_id(pjsip_contact_hdr *contact);
  void log_bindings(const std::string& aor_name, AoR* aor_data);

  RegistrarSproutlet* _registrar;

  // The S-CSCF URI for this transaction. This is used on any SAR that is sent
  // to the HSS. This field should not be changed once it has been set by the
  // on_rx_intial_request() call.
  std::string _scscf_uri;

  /// Member variables covering the IFCs.
  FIFCService* _fifc_service;
  IFCConfiguration _ifc_configuration;
};

#endif
