/**
 * @file registration_utils.cpp Registration and deregistration functions
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}


#include <string>
#include <cassert>
#include "constants.h"
#include "ifchandler.h"
#include "pjutils.h"
#include "stack.h"
#include "registrarsproutlet.h"
#include "registration_utils.h"
#include "log.h"
#include <boost/lexical_cast.hpp>
#include "sproutsasevent.h"
#include "snmp_success_fail_count_table.h"
#include "hssconnection.h"

#define MAX_SIP_MSG_SIZE 65535

static SNMP::RegistrationStatsTables* third_party_reg_stats_tables;

// Should we always send the access-side REGISTER and 200 OK in the body
// of third-party REGISTER messages to application servers, even if the
// iFCs don't tell us to?
static bool force_third_party_register_body;

/// Temporary data structure maintained while transmitting a third-party
/// REGISTER to an application server.
struct ThirdPartyRegData
{
  SubscriberDataManager* sdm;
  std::vector<SubscriberDataManager*> remote_sdms;
  HSSConnection* hss;
  FIFCService* fifc_service;
  IFCConfiguration ifc_configuration;
  std::string public_id;
  DefaultHandling default_handling;
  SAS::TrailId trail;
  int expires;
  bool is_initial_registration;
};

class RegisterCallback : public PJUtils::Callback
{
  int _status_code;
  ThirdPartyRegData* _reg_data;
  std::function<void(ThirdPartyRegData*, int)> _send_register_callback;

public:
  ~RegisterCallback() override
  {
    delete _reg_data; _reg_data = NULL;
  }

  void run() override
  {
    if ((_reg_data->default_handling == SESSION_TERMINATED) &&
        ((_status_code == 408) ||
         (PJSIP_IS_STATUS_IN_CLASS(_status_code, 500))))
    {
      std::string error_msg = "Third-party REGISTER transaction failed with code " + std::to_string(_status_code);
      TRC_INFO(error_msg.c_str());

      SAS::Event event(_reg_data->trail, SASEvent::REGISTER_AS_FAILED, 0);
      event.add_var_param(error_msg);
      SAS::report_event(event);

      // 3GPP TS 24.229 V12.0.0 (2013-03) 5.4.1.7 specifies that an AS failure
      // where SESSION_TERMINATED is set means that we should deregister "the
      // currently registered public user identity" - i.e. all bindings
      RegistrationUtils::remove_bindings(_reg_data->sdm,
                                         _reg_data->remote_sdms,
                                         _reg_data->hss,
                                         _reg_data->fifc_service,
                                         _reg_data->ifc_configuration,
                                         _reg_data->public_id,
                                         "*",
                                         HSSConnection::DEREG_ADMIN,
                                         SubscriberDataManager::EventTrigger::ADMIN,
                                         _reg_data->trail);
    }

    if (third_party_reg_stats_tables != NULL)
    {
      if (_status_code == 200)
      {
        if (_reg_data->expires == 0)
        {
          third_party_reg_stats_tables->de_reg_tbl->increment_successes();
        }
        else if (_reg_data->is_initial_registration)
        {
          third_party_reg_stats_tables->init_reg_tbl->increment_successes();
        }
        else
        {
          third_party_reg_stats_tables->re_reg_tbl->increment_successes();
        }
      }
      else
      {
        // Count all failed registration attempts, not just ones that result in
        // user being unsubscribed.
        if (_reg_data->expires == 0)
        {
          third_party_reg_stats_tables->de_reg_tbl->increment_failures();
        }
        else if (_reg_data->is_initial_registration)
        {
          third_party_reg_stats_tables->init_reg_tbl->increment_failures();
        }
        else
        {
          third_party_reg_stats_tables->re_reg_tbl->increment_failures();
        }
      }
    }
  }

  RegisterCallback(void* token, pjsip_event* event)
  {
    // Save the regdata from the token, and the status code from the event
    _reg_data = (ThirdPartyRegData*)token;
    _status_code = event->body.tsx_state.tsx->status_code;
  }
};

static void send_register_to_as(SubscriberDataManager* sdm,
                                std::vector<SubscriberDataManager*> remote_sdms,
                                HSSConnection* hss,
                                FIFCService* fifc_service,
                                IFCConfiguration ifc_configuration,
                                pjsip_msg* received_register_msg,
                                pjsip_msg* ok_response_msg,
                                AsInvocation& as,
                                int expires,
                                bool is_initial_registration,
                                const std::string&,
                                SAS::TrailId);

void RegistrationUtils::init(SNMP::RegistrationStatsTables* third_party_reg_stats_tables_arg,
                             bool force_third_party_register_body_arg)
{
  third_party_reg_stats_tables = third_party_reg_stats_tables_arg;
  force_third_party_register_body = force_third_party_register_body_arg;
}

void RegistrationUtils::interpret_ifcs(Ifcs& ifcs,
                                       std::vector<Ifc> fallback_ifcs,
                                       IFCConfiguration ifc_configuration,
                                       const SessionCase& session_case,
                                       bool is_registered,
                                       bool is_initial_registration,
                                       pjsip_msg* msg,
                                       std::vector<AsInvocation>& application_servers,
                                       bool& found_match,
                                       SAS::TrailId trail)
{
  found_match = false;

  for (Ifc ifc : ifcs.ifcs_list())
  {
    // As per TS 24.229, section 5.4.1.7, note 1, we don't fill in any
    // P-Associated-URI details.
    if (ifc.filter_matches(session_case,
                           is_registered,
                           is_initial_registration,
                           msg,
                           trail))
    {
      if ((ifc.as_invocation().server_name) ==
          (ifc_configuration._dummy_as))
      {
        TRC_DEBUG("Ignoring this iFC as it matches a dummy AS (%s)",
                  ifc_configuration._dummy_as.c_str());
        SAS::Event event(trail, SASEvent::IFC_MATCHED_DUMMY_AS, 1);
        event.add_var_param(ifc_configuration._dummy_as);
        SAS::report_event(event);
        found_match = true;
      }
      else
      {
        application_servers.push_back(ifc.as_invocation());
      }
    }
  }

  // Check if we should apply any fallback iFCs. We do this if:
  //   - We haven't found any matching iFC (true if application_servers
  //      is empty and we didn't find a dummy AS
  //   - The config option to apply fallback iFCs is set.
  // should be using them.
  if (((application_servers.empty()) && (!found_match)) &&
      (ifc_configuration._apply_fallback_ifcs))
  {
    TRC_DEBUG("No iFCs apply to this message; looking up fallback iFCs");
    SAS::Event event(trail, SASEvent::STARTING_FALLBACK_IFCS_LOOKUP, 1);
    SAS::report_event(event);

    for (Ifc ifc : fallback_ifcs)
    {
      if (ifc.filter_matches(SessionCase::Originating,
                             true,
                             is_initial_registration,
                             msg,
                             trail))
      {
        if ((ifc.as_invocation().server_name) ==
             (ifc_configuration._dummy_as))
        {
          TRC_DEBUG("Ignoring this fallback iFC as it matches a dummy AS (%s)",
                    ifc_configuration._dummy_as.c_str());
          SAS::Event event(trail, SASEvent::IFC_MATCHED_DUMMY_AS, 2);
          event.add_var_param(ifc_configuration._dummy_as);
          SAS::report_event(event);
          found_match = true;
        }
        else
        {
          // SAS log if we're going to apply fallback iFCs - we only log this
          // the first time through.
          if (application_servers.empty())
          {
            TRC_DEBUG("We've found a matching fallback iFC - applying it");
            SAS::Event event(trail, SASEvent::FIRST_FALLBACK_IFC, 1);
            SAS::report_event(event);
          }

          application_servers.push_back(ifc.as_invocation());
        }
      }
    }

    // Check if we should have applied fallback iFCs, but didn't find any. We
    // SAS log this, and increment a statistic.
    //   - We haven't found any matching iFC (true if application_servers
    //      is empty and we didn't find a dummy AS
    //   - The config option to apply fallback iFCs is set.
    if (((application_servers.empty()) && (!found_match)) &&
        (ifc_configuration._apply_fallback_ifcs))
    {
      if (ifc_configuration._no_matching_fallback_ifcs_tbl)
      {
        ifc_configuration._no_matching_fallback_ifcs_tbl->increment();
      }

      TRC_DEBUG("Unable to apply fallback iFCs as no matching iFCs available");
      SAS::Event event(trail, SASEvent::NO_FALLBACK_IFCS, 1);
      SAS::report_event(event);
    }
  }
}

void RegistrationUtils::deregister_with_application_servers(Ifcs& ifcs,
                                                            FIFCService* fifc_service,
                                                            IFCConfiguration ifc_configuration,
                                                            SubscriberDataManager* sdm,
                                                            std::vector<SubscriberDataManager*> remote_sdms,
                                                            HSSConnection* hss,
                                                            const std::string& served_user,
                                                            SAS::TrailId trail)
{
  pj_status_t status;
  pjsip_method method;
  pjsip_method_set(&method, PJSIP_REGISTER_METHOD);
  pjsip_tx_data *tdata;

  std::string served_user_uri_string = "<"+served_user+">";
  const pj_str_t served_user_uri = pj_str(const_cast<char *>(served_user_uri_string.c_str()));

  TRC_INFO("Generating a fake REGISTER to send to IfcHandler using AOR %s", served_user.c_str());

  SAS::Event event(trail, SASEvent::REGISTER_AS_START, 0);
  event.add_var_param(served_user);
  SAS::report_event(event);

  status = pjsip_endpt_create_request(stack_data.endpt,
                                      &method,                   // Method
                                      &stack_data.scscf_uri_str, // Target
                                      &served_user_uri,          // From
                                      &served_user_uri,          // To
                                      &served_user_uri,          // Contact
                                      NULL,                      // Auto-generate Call-ID
                                      1,                         // CSeq
                                      NULL,                      // No body
                                      &tdata);                   // OUT

  if (status != PJ_SUCCESS)
  {
    TRC_DEBUG("Unable to create third party registration for %s",
              served_user.c_str());
    SAS::Event event(trail, SASEvent::DEREGISTER_AS_FAILED, 0);
    event.add_var_param(served_user);
    SAS::report_event(event);
  }
  else
  {
    TRC_DEBUG("Creating third party deregistration for %s", served_user.c_str());
    RegistrationUtils::register_with_application_servers(ifcs,
                                                         fifc_service,
                                                         ifc_configuration,
                                                         sdm,
                                                         remote_sdms,
                                                         hss,
                                                         tdata->msg,
                                                         NULL,
                                                         0,
                                                         false,
                                                         served_user,
                                                         trail);
  }
}

void RegistrationUtils::register_with_application_servers(Ifcs& ifcs,
                                                          FIFCService* fifc_service,
                                                          IFCConfiguration ifc_configuration,
                                                          SubscriberDataManager* sdm,
                                                          std::vector<SubscriberDataManager*> remote_sdms,
                                                          HSSConnection* hss,
                                                          pjsip_msg* register_msg,
                                                          pjsip_msg* response_msg,
                                                          int expires,
                                                          bool is_initial_registration,
                                                          const std::string& served_user,
                                                          SAS::TrailId trail)
{
  bool found_match;

  std::vector<Ifc> fallback_ifcs;
  rapidxml::xml_document<>* root = NULL;

  if ((fifc_service) && (ifc_configuration._apply_fallback_ifcs))
  {
    root = new rapidxml::xml_document<>;
    fallback_ifcs = fifc_service->get_fallback_ifcs(root);
  }

  std::vector<AsInvocation> as_list;
  interpret_ifcs(ifcs,
                 fallback_ifcs,
                 ifc_configuration,
                 SessionCase::Originating,
                 true,
                 is_initial_registration,
                 register_msg,
                 as_list,
                 found_match,
                 trail);

  // Loop through the application servers and send the registers.
  for (AsInvocation as : as_list)
  {
    if (third_party_reg_stats_tables != NULL)
    {
      if (expires == 0)
      {
        third_party_reg_stats_tables->de_reg_tbl->increment_attempts();
      }
      else if (is_initial_registration)
      {
        third_party_reg_stats_tables->init_reg_tbl->increment_attempts();
      }
      else
      {
        third_party_reg_stats_tables->re_reg_tbl->increment_attempts();
      }
    }
    send_register_to_as(sdm,
                        remote_sdms,
                        hss,
                        fifc_service,
                        ifc_configuration,
                        register_msg,
                        response_msg,
                        as,
                        expires,
                        is_initial_registration,
                        served_user,
                        trail);
  }

  // Check if we found any iFCs at all. We didn't find any if:
  //   - We haven't found any matching iFC (true if application_servers
  //      is empty and we didn't find a dummy AS
  //   - It's an initial registration
  if (((as_list.empty()) && (!found_match)) &&
      (is_initial_registration))
  {
    if (ifc_configuration._no_matching_ifcs_tbl)
    {
      ifc_configuration._no_matching_ifcs_tbl->increment();
    }

    if (ifc_configuration._reject_if_no_matching_ifcs)
    {
      TRC_DEBUG("Deregistering the subscriber as no matching iFCs were found");
      RegistrationUtils::remove_bindings(sdm,
                                         remote_sdms,
                                         hss,
                                         fifc_service,
                                         ifc_configuration,
                                         served_user,
                                         "*",
                                         HSSConnection::DEREG_ADMIN,
                                         SubscriberDataManager::EventTrigger::ADMIN,
                                         trail);
    }
  }

  delete root; root = NULL;
}

static PJUtils::Callback* build_register_cb(void* token,
                                            pjsip_event* event)
{
  RegisterCallback* cb = new RegisterCallback(token, event);
  return cb;
}

static void send_register_to_as(SubscriberDataManager* sdm,
                                std::vector<SubscriberDataManager*> remote_sdms,
                                HSSConnection* hss,
                                FIFCService* fifc_service,
                                IFCConfiguration ifc_configuration,
                                pjsip_msg *received_register_msg,
                                pjsip_msg *ok_response_msg,
                                AsInvocation& as,
                                int expires,
                                bool is_initial_registration,
                                const std::string& served_user,
                                SAS::TrailId trail)
{
  pj_status_t status;
  pjsip_tx_data *tdata;
  pjsip_method method;
  pjsip_method_set(&method, PJSIP_REGISTER_METHOD);

  pj_str_t user_uri;
  pj_cstr(&user_uri, served_user.c_str());
  pj_str_t as_uri;
  pj_cstr(&as_uri, as.server_name.c_str());

  status = pjsip_endpt_create_request(stack_data.endpt,
                                      &method,                   // Method
                                      &as_uri,                   // Target
                                      &stack_data.scscf_uri_str, // From
                                      &user_uri,                 // To
                                      &stack_data.scscf_contact, // Contact
                                      NULL,                      // Auto-generate Call-ID
                                      1,                         // CSeq
                                      NULL,                      // No body
                                      &tdata);                   // OUT

  if (status != PJ_SUCCESS)
  {
    //LCOV_EXCL_START
    TRC_DEBUG("Failed to build third-party REGISTER request for server %s",
              as.server_name.c_str());
    return;
    //LCOV_EXCL_STOP
  }

  // Expires header based on 200 OK response
  pjsip_expires_hdr_create(tdata->pool, expires);
  pjsip_expires_hdr* expires_hdr = pjsip_expires_hdr_create(tdata->pool, expires);
  pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)expires_hdr);

  // TODO: modify orig-ioi of P-Charging-Vector and remove term-ioi

  if (received_register_msg && ok_response_msg)
  {
    // Copy P-Access-Network-Info, P-Visited-Network-Id and P-Charging-Vector
    // from original message
    PJUtils::clone_header(&STR_P_A_N_I, received_register_msg, tdata->msg, tdata->pool);
    PJUtils::clone_header(&STR_P_V_N_I, received_register_msg, tdata->msg, tdata->pool);
    PJUtils::clone_header(&STR_P_C_V, received_register_msg, tdata->msg, tdata->pool);

    // Copy P-Charging-Function-Addresses from the OK response.
    PJUtils::clone_header(&STR_P_C_F_A, ok_response_msg, tdata->msg, tdata->pool);

    // Generate a message body based on Filter Criteria values
    char buf[MAX_SIP_MSG_SIZE];
    pj_str_t sip_type = pj_str("message");
    pj_str_t sip_subtype = pj_str("sip");
    pj_str_t xml_type = pj_str("application");
    pj_str_t xml_subtype = pj_str("3gpp-ims+xml");

    // Build up this multipart body incrementally, based on the ServiceInfo, IncludeRegisterRequest and IncludeRegisterResponse fields
    pjsip_msg_body *final_body = pjsip_multipart_create(tdata->pool, NULL, NULL);

    // If we only have one part, we don't want a multipart MIME body - store the reference to each one here to use instead
    pjsip_msg_body *possible_final_body = NULL;
    int multipart_parts = 0;

    if (!as.service_info.empty())
    {
      pjsip_multipart_part *xml_part = pjsip_multipart_create_part(tdata->pool);
      std::string xml_str = "<ims-3gpp><service-info>"+as.service_info+"</service-info></ims-3gpp>";
      pj_str_t xml_pj_str;
      pj_cstr(&xml_pj_str, xml_str.c_str());
      xml_part->body = pjsip_msg_body_create(tdata->pool, &xml_type, &xml_subtype, &xml_pj_str),
      possible_final_body = xml_part->body;
      multipart_parts++;
      pjsip_multipart_add_part(tdata->pool,
                               final_body,
                               xml_part);
    }

    if (as.include_register_request || force_third_party_register_body)
    {
      pjsip_multipart_part *request_part = pjsip_multipart_create_part(tdata->pool);
      pjsip_msg_print(received_register_msg, buf, sizeof(buf));
      pj_str_t request_str = pj_str(buf);
      request_part->body = pjsip_msg_body_create(tdata->pool, &sip_type, &sip_subtype, &request_str),
      possible_final_body = request_part->body;
      multipart_parts++;
      pjsip_multipart_add_part(tdata->pool,
                               final_body,
                               request_part);
    }

    if (as.include_register_response || force_third_party_register_body)
    {
      pjsip_multipart_part *response_part = pjsip_multipart_create_part(tdata->pool);
      pjsip_msg_print(ok_response_msg, buf, sizeof(buf));
      pj_str_t response_str = pj_str(buf);
      response_part->body = pjsip_msg_body_create(tdata->pool, &sip_type, &sip_subtype, &response_str),
      possible_final_body = response_part->body;
      multipart_parts++;
      pjsip_multipart_add_part(tdata->pool,
                               final_body,
                               response_part);
    }

    if (multipart_parts == 0)
    {
      final_body = NULL;
    }
    else if (multipart_parts == 1)
    {
      final_body = possible_final_body;
    }
    else
    {
      // Just use the multipart MIME body you've built up
    }

    tdata->msg->body = final_body;
  }

  // Set the SAS trail on the request.
  set_trail(tdata, trail);

  if (Log::enabled(Log::VERBOSE_LEVEL))
  {
    char buf[PJSIP_MAX_PKT_LEN];
    pj_ssize_t size;

    // Serialise the message in a separate buffer using the function
    // exposed by PJSIP.  In principle we could use tdata's own
    // serialisation buffer structure for this, but then we'd need to
    // explicitly invalidate it afterwards to avoid accidentally sending
    // the wrong data over SIP at some future point.  Safer to use a local
    // buffer.
    size = pjsip_msg_print(tdata->msg, buf, sizeof(buf));

    // Defensively set size to zero if pjsip_msg_print failed
    size = std::max(0L, size);

    TRC_VERBOSE("Routing %s (%d bytes) to 3rd party AS %s:\n"
                "--start msg--\n\n"
                "%.*s\n"
                "--end msg--",
                pjsip_tx_data_get_info(tdata),
                size,
                as.server_name.c_str(),
                (int)size,
                buf);
  }

  // Allocate a temporary structure to record the default handling for this
  // REGISTER, and send it statefully.
  ThirdPartyRegData* tsxdata = new ThirdPartyRegData;
  tsxdata->sdm = sdm;
  tsxdata->remote_sdms = remote_sdms;
  tsxdata->hss = hss;
  tsxdata->fifc_service = fifc_service;
  tsxdata->ifc_configuration = ifc_configuration;
  tsxdata->default_handling = as.default_handling;
  tsxdata->trail = trail;
  tsxdata->public_id = served_user;
  tsxdata->expires = expires;
  tsxdata->is_initial_registration = is_initial_registration;
  pj_status_t resolv_status = PJUtils::send_request(tdata, 0, tsxdata, &build_register_cb);

  if (resolv_status != PJ_SUCCESS)
  {
    delete tsxdata; tsxdata = NULL;                  // LCOV_EXCL_LINE
  }
}

static void notify_application_servers()
{
  TRC_DEBUG("In dummy notify_application_servers function");
  // TODO: implement as part of reg events package
}

static bool expire_bindings(SubscriberDataManager *sdm,
                            const std::string& aor,
                            const SubscriberDataManager::EventTrigger& event_trigger,
                            AssociatedURIs* associated_uris,
                            const std::string& binding_id,
                            std::string& scscf_uri,
                            SAS::TrailId trail)
{
  // We need the retry loop to handle the store's compare-and-swap.
  bool all_bindings_expired = false;
  Store::Status set_rc;

  do
  {
    AoRPair* aor_pair = sdm->get_aor_data(aor, trail);

    if ((aor_pair == NULL) || (aor_pair->get_current() == NULL))
    {
      break;  // LCOV_EXCL_LINE No UT for lookup failure.
    }

    // Get the S-CSCF URI off the AoR to put on the SAR to the HSS.
    AoR* aor_data = aor_pair->get_current();
    scscf_uri = aor_data->_scscf_uri;

    if (binding_id == "*")
    {
      // We only use this when doing some network-initiated deregistrations;
      // when the user deregisters all bindings another code path clears them
      TRC_INFO("Clearing all bindings!");
      aor_pair->get_current()->clear(false);
    }
    else
    {
      aor_pair->get_current()->remove_binding(binding_id); // LCOV_EXCL_LINE No UT for network
                                                           // initiated deregistration of a
                                                           // single binding (flow failed).
    }

    aor_pair->get_current()->_associated_uris = *associated_uris;
    set_rc = sdm->set_aor_data(aor, 
                               event_trigger,
                               aor_pair, 
                               trail, 
                               all_bindings_expired);
    delete aor_pair; aor_pair = NULL;

    // We can only say for sure that the bindings were expired if we were able
    // to update the store.
    all_bindings_expired = (all_bindings_expired && (set_rc == Store::OK));

  }
  while (set_rc == Store::DATA_CONTENTION);

  return all_bindings_expired;
}

bool RegistrationUtils::remove_bindings(SubscriberDataManager* sdm,
                                        std::vector<SubscriberDataManager*> remote_sdms,
                                        HSSConnection* hss,
                                        FIFCService* fifc_service,
                                        IFCConfiguration ifc_configuration,
                                        const std::string& aor,
                                        const std::string& binding_id,
                                        const std::string& dereg_type,
                                        const SubscriberDataManager::EventTrigger& event_trigger,
                                        SAS::TrailId trail,
                                        HTTPCode* hss_status_code)
{
  TRC_INFO("Remove binding(s) %s from IMPU %s", binding_id.c_str(), aor.c_str());
  bool all_bindings_expired = false;

  // Determine the set of IMPUs in the Implicit Registration Set
  std::vector<std::string> unbarred_irs_impus;
  HSSConnection::irs_info irs_info;

  HTTPCode http_code = hss->get_registration_data(aor,
                                                  irs_info,
                                                  trail);

  // We only want to send NOTIFYs for unbarred IMPUs.
  unbarred_irs_impus = irs_info._associated_uris.get_unbarred_uris();

  if ((http_code != HTTP_OK) || unbarred_irs_impus.empty())
  {
    // We were unable to determine the set of IMPUs for this AoR. Push the AoR
    // we have into the Associated URIs list so that we have at least one IMPU
    // we can issue NOTIFYs for. We should only do this if that IMPU is not barred.
    TRC_WARNING("Unable to get Implicit Registration Set for %s: %d", aor.c_str(), http_code);
    if (!irs_info._associated_uris.is_impu_barred(aor))
    {
      irs_info._associated_uris.clear_uris();
      irs_info._associated_uris.add_uri(aor, false);
    }
  }

  std::string scscf_uri;

  if (expire_bindings(sdm, aor, event_trigger, &(irs_info._associated_uris), binding_id, scscf_uri, trail))
  {
    // All bindings have been expired, so do deregistration processing for the
    // IMPU.
    TRC_INFO("All bindings for %s expired, so deregister at HSS and ASs", aor.c_str());
    all_bindings_expired = true;

    HSSConnection::irs_query irs_query;
    irs_query._public_id = aor;
    irs_query._req_type = dereg_type;
    irs_query._server_name = scscf_uri;

    HTTPCode http_code = hss->update_registration_state(irs_query,
                                                        irs_info,
                                                        trail);

    if (http_code == HTTP_OK)
    {
      // Note that 3GPP TS 24.229 V12.0.0 (2013-03) 5.4.1.7 doesn't specify that any binding information
      // should be passed on the REGISTER message, so we don't need the binding ID.
      deregister_with_application_servers(irs_info._service_profiles[aor],
                                          fifc_service,
                                          ifc_configuration,
                                          sdm,
                                          remote_sdms,
                                          hss,
                                          aor,
                                          trail);
      notify_application_servers();
    }

    if (hss_status_code)
    {
      *hss_status_code = http_code;
    }
  }

  // Now go through the remote SDMs and remove bindings there too.  We don't
  // make any effort to check whether the local and remote stores are in sync --
  // we'll do this next time we get the data from the store and before we do
  // anything with it.
  for (std::vector<SubscriberDataManager*>::const_iterator remote_sdm =
       remote_sdms.begin();
       remote_sdm != remote_sdms.end();
       ++remote_sdm)
  {
    (void) expire_bindings(*remote_sdm, aor, event_trigger, &(irs_info._associated_uris), binding_id, scscf_uri, trail);
  }

  return all_bindings_expired;
}

/// Retrieve information from the Subscriber Data Manager for a specified AoR.
/// This function will look in the following places and stop as soon as it finds
/// a record for the specified AoR that has > 0 bindings.
/// -- the primary_sdm
/// -- the provided backup_aor_pair (if not null)
/// -- the specified backup_sdms (if any have been provided).
///
/// On success (return code true) it returns an AoRPair (as aor_pair) where the
/// original copy of the AoR contains all bindings and subscriptions found, and
/// the current copy contains all bindings and subscriptions that have not
/// expired.  On failure (return code false) no aor_pair is returned. This
/// function only returns false if there is an error and the data cannot be
/// queried (see below); If the query is successful but no data was found it
/// returns true and a blank AoRPair.
///
/// This function allocates additional importance to the primary_sdm: if the
/// primary_sdm is unable to successfully query its store then (irrespective of
/// whether we might have been able to get data from the backup_sdms) we return
/// false and no AoR data. On the other hand, if the primary_sdm is able to
/// successfully query its store then we return success and our best view of
/// the data (across primary and backup sources) -- irrespective of whether the
/// backup stores were successfully queried.
bool RegistrationUtils::get_aor_data(AoRPair** aor_pair,
                                     std::string aor_id,
                                     SubscriberDataManager* primary_sdm,
                                     std::vector<SubscriberDataManager*> backup_sdms,
                                     AoRPair* backup_aor_pair,
                                     SAS::TrailId trail)
{
  // Find the current bindings for the AoR.
  delete *aor_pair;
  *aor_pair = primary_sdm->get_aor_data(aor_id, trail);
  TRC_DEBUG("Retrieved AoR data %p", *aor_pair);

  if ((*aor_pair == NULL) ||
      ((*aor_pair)->get_current() == NULL))
  {
    // Failed to get data for the AoR because there is no connection
    // to the store. This will already have been SAS logged by the AoR store.
    TRC_DEBUG("Store connection error.  Failed to get AoR binding for %s from store",
              aor_id.c_str());
    return false;
  }

  // If we don't have any bindings, try the backup AoR and/or stores.
  if ((*aor_pair)->get_current()->bindings().empty())
  {
    bool found_binding = false;
    bool backup_aor_pair_alloced = false;

    if ((backup_aor_pair != NULL) &&
        (backup_aor_pair->current_contains_bindings()))
    {
      found_binding = true;
    }
    else
    {
      std::vector<SubscriberDataManager*>::iterator it = backup_sdms.begin();
      AoRPair* local_backup_aor_pair = NULL;

      TRC_INFO("Failed to find binding for %s in local store - checking remote stores",
               aor_id.c_str());

      while ((it != backup_sdms.end()) && (!found_binding))
      {
        if ((*it)->has_servers())
        {
          local_backup_aor_pair = (*it)->get_aor_data(aor_id, trail);

          if ((local_backup_aor_pair != NULL) &&
              (local_backup_aor_pair->current_contains_bindings()))
          {
            found_binding = true;
            backup_aor_pair = local_backup_aor_pair;

            // Flag that we have allocated the memory for the backup pair so
            // that we can tidy it up later.
            backup_aor_pair_alloced = true;
          }
        }

        if (!found_binding)
        {
          ++it;

          if (local_backup_aor_pair != NULL)
          {
            delete local_backup_aor_pair;
            local_backup_aor_pair = NULL;
          }
        }
      }
    }

    if (found_binding)
    {
      (*aor_pair)->get_current()->copy_aor(backup_aor_pair->get_current());
    }

    if (backup_aor_pair_alloced)
    {
      delete backup_aor_pair;
      backup_aor_pair = NULL;
    }
  }

  return true;
}

int RegistrationUtils::expiry_for_binding(pjsip_contact_hdr* contact,
                                          pjsip_expires_hdr* expires,
                                          int max_expires)
{
  int expiry = (contact->expires != -1) ? contact->expires :
               (expires != NULL) ? expires->ivalue :
               max_expires;
  if (expiry > max_expires)
  {
    // Expiry is too long, set it to the maximum.
    expiry = max_expires;
  }

  return expiry;
}
