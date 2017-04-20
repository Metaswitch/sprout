/**
 * @file registrarsproutlet.h Initialization/Termination functions for
 *                            Sprout's Registrar sproutlet.
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
#include "forwardingsproutlet.h"

class RegistrarSproutletTsx;

class RegistrarSproutlet : public Sproutlet
{
public:
  RegistrarSproutlet(const std::string& name,
                     int port,
                     const std::string& uri,
                     const std::string& next_hop_service,
                     SubscriberDataManager* reg_sdm,
                     std::vector<SubscriberDataManager*> reg_remote_sdms,
                     HSSConnection* hss_connection,
                     ACRFactory* rfacr_factory,
                     int cfg_max_expires,
                     bool force_original_register_inclusion,
                     SNMP::RegistrationStatsTables* reg_stats_tbls,
                     SNMP::RegistrationStatsTables* third_party_reg_stats_tbls);
  ~RegistrarSproutlet();

  bool init();

  SproutletTsx* get_tsx(SproutletProxy* proxy,
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

  // The next service to route requests onto if the sproutlet does not handle
  // them itself.
  std::string _next_hop_service;
};


class RegistrarSproutletTsx : public ForwardingSproutletTsx
{
public:
  RegistrarSproutletTsx(const std::string& next_hop_service,
                        RegistrarSproutlet* sproutlet);
  ~RegistrarSproutletTsx();

  virtual void on_rx_initial_request(pjsip_msg* req);

protected:
  void process_register_request(pjsip_msg* req);

  SubscriberDataManager::AoRPair* write_to_store(
                     SubscriberDataManager* primary_sdm,         ///<store to write to
                     std::string aor,                            ///<address of record to write to
                     std::vector<std::string> irs_impus,         ///<IMPUs in Implicit Registration Set
                     pjsip_msg* req,                             ///<received request to read headers from
                     int now,                                    ///<time now
                     int& expiry,                                ///<[out] longest expiry time
                     bool& out_is_initial_registration,
                     SubscriberDataManager::AoRPair* backup_aor, ///<backup data if no entry in store
                     std::vector<SubscriberDataManager*> backup_sdms,
                                                                 ///<backup stores to read from if no entry in store and no backup data
                     std::string private_id,                     ///<private id that the binding was registered with
                     bool& out_all_bindings_expired);

  bool get_private_id(pjsip_msg* req, std::string& id);
  std::string get_binding_id(pjsip_contact_hdr *contact);
  void log_bindings(const std::string& aor_name, SubscriberDataManager::AoR* aor_data);

  RegistrarSproutlet* _sproutlet;
};

#endif
