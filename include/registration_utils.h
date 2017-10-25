/**
 * @file registration_utils.h
 *
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef REGISTRATION_UTILS_H__
#define REGISTRATION_UTILS_H__

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}

#include <string>
#include "subscriber_data_manager.h"
#include "ifchandler.h"
#include "hssconnection.h"
#include "snmp_success_fail_count_table.h"
#include "fifcservice.h"

namespace RegistrationUtils {

void init(SNMP::RegistrationStatsTables* third_party_reg_stats_tables_arg,
          bool force_third_party_register_body_arg);

bool remove_bindings(SubscriberDataManager* sdm,
                     std::vector<SubscriberDataManager*> remote_sdms,
                     HSSConnection* hss,
                     FIFCService* fifc_service,
                     IFCConfiguration ifc_configuration,
                     const std::string& aor,
                     const std::string& binding_id,
                     const std::string& dereg_type,
                     const SubscriberDataManager::EventTrigger& event_trigger,
                     SAS::TrailId trail,
                     HTTPCode* hss_status_code = nullptr);

bool get_aor_data(AoRPair** aor_pair,
                  std::string aor_id,
                  SubscriberDataManager* primary_sdm,
                  std::vector<SubscriberDataManager*> backup_sdms,
                  AoRPair* backup_aor_pair,
                  SAS::TrailId trail);

int expiry_for_binding(pjsip_contact_hdr* contact,
                       pjsip_expires_hdr* expires,
                       int max_expires);

void deregister_with_application_servers(Ifcs& ifcs,
                                         FIFCService* fifc_service,
                                         IFCConfiguration ifc_configuration,
                                         SubscriberDataManager* sdm,
                                         std::vector<SubscriberDataManager*> remote_sdms,
                                         HSSConnection* hss,
                                         const std::string& served_user,
                                         SAS::TrailId trail);
void register_with_application_servers(Ifcs& ifcs,
                                       FIFCService* fifc_service,
                                       IFCConfiguration ifc_configuration,
                                       SubscriberDataManager* sdm,
                                       std::vector<SubscriberDataManager*> remote_sdms,
                                       HSSConnection* hss,
                                       pjsip_msg *received_register_msg,
                                       pjsip_msg *ok_response_msg,
                                       int expires,
                                       bool is_initial_registration,
                                       const std::string& served_user,
                                       SAS::TrailId trail);

void interpret_ifcs(Ifcs& ifcs,
                    std::vector<Ifc> fallback_ifcs,
                    IFCConfiguration ifc_configuration,
                    const SessionCase& session_case,
                    bool is_registered,
                    bool is_initial_registration,
                    pjsip_msg* msg,
                    std::vector<AsInvocation>& application_servers,
                    bool& found_match,
                    SAS::TrailId trail);
}

#endif
