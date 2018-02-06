/**
 * @file registration_sender.cpp
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "constants.h"
#include "sproutsasevent.h"
#include "registration_sender.h"
#include "stack.h"

#define MAX_SIP_MSG_SIZE 65535 // TODO move to constants.h

RegistrationSender::RegistrationSender(SubscriberManager* subscriber_manager,
                                       IFCConfiguration ifc_configuration,
                                       FIFCService* fifc_service,
                                       SNMP::RegistrationStatsTables* third_party_reg_stats_tbls,
                                       bool force_third_party_register_body) :
  _subscriber_manager(subscriber_manager),
  _ifc_configuration(ifc_configuration),
  _fifc_service(fifc_service),
  _third_party_reg_stats_tbls(third_party_reg_stats_tbls),
  _force_third_party_register_body(force_third_party_register_body)
{
}

RegistrationSender::~RegistrationSender()
{
}

void RegistrationSender::register_with_application_servers(pjsip_msg* received_register_message,
                                                           pjsip_msg* ok_response_msg,
                                                           const std::string& served_user,
                                                           const Ifcs& ifcs,
                                                           int expires,
                                                           bool is_initial_registration,
                                                           SAS::TrailId trail)
{
  TRC_DEBUG("Registering %s with application servers", served_user.c_str());

  bool matched_dummy_as;

  std::vector<Ifc> fallback_ifcs;
  rapidxml::xml_document<>* root = NULL;

  if ((_fifc_service) && (_ifc_configuration._apply_fallback_ifcs))
  {
    root = new rapidxml::xml_document<>;
    fallback_ifcs = _fifc_service->get_fallback_ifcs(root);
  }

  std::vector<AsInvocation> as_list;
  match_application_servers(received_register_message,
                            ifcs,
                            fallback_ifcs,
                            is_initial_registration,
                            as_list,
                            matched_dummy_as,
                            trail);

  // Loop through the application servers and send the registers.
  for (AsInvocation as : as_list)
  {
    if (_third_party_reg_stats_tbls != NULL)
    {
      if (expires == 0)
      {
        _third_party_reg_stats_tbls->de_reg_tbl->increment_attempts();
      }
      else if (is_initial_registration)
      {
        _third_party_reg_stats_tbls->init_reg_tbl->increment_attempts();
      }
      else
      {
        _third_party_reg_stats_tbls->re_reg_tbl->increment_attempts();
      }
    }

    send_register_to_as(received_register_message,
                        ok_response_msg,
                        served_user,
                        as,
                        expires,
                        is_initial_registration,
                        trail);
  }

  // If we didn't match any application servers (dummy or otherwise) and this is
  // an initial registration, we:
  //  - Update a statistic.
  //  - May trigger the subscriber to be dereigstered if we should reject if
  //    there are no matching application servers.
  if (((as_list.empty()) && (!matched_dummy_as)) &&
      (is_initial_registration))
  {
    if (_ifc_configuration._no_matching_ifcs_tbl)
    {
      _ifc_configuration._no_matching_ifcs_tbl->increment();
    }

    if (_ifc_configuration._reject_if_no_matching_ifcs)
    {
      TRC_DEBUG("Deregistering the subscriber as no matching iFCs were found");
      // TODO Deal with deregistration. Probably by passing back a boolean back
      // to SM.
      /*RegistrationUtils::remove_bindings(sdm,
                                         remote_sdms,
                                         hss,
                                         fifc_service,
                                         ifc_configuration,
                                         served_user,
                                         "*",
                                         HSSConnection::DEREG_ADMIN,
                                         SubscriberDataManager::EventTrigger::ADMIN,
                                         trail);*/
    }
  }

  delete root; root = NULL;
}

void RegistrationSender::deregister_with_application_servers(const std::string& served_user,
                                                             const Ifcs& ifcs,
                                                             SAS::TrailId trail)
{
  pj_status_t status;
  pjsip_method method;
  pjsip_method_set(&method, PJSIP_REGISTER_METHOD);
  pjsip_tx_data *tdata;

  std::string served_user_uri_string = "<"+served_user+">";
  const pj_str_t served_user_uri = pj_str(const_cast<char *>(served_user_uri_string.c_str()));

  SAS::Event event(trail, SASEvent::REGISTER_AS_START, 0);
  event.add_var_param(served_user);
  SAS::report_event(event);

  // Create a fake register to use as a base for the 3rd party deregisters.
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
    register_with_application_servers(tdata->msg,
                                      NULL,
                                      served_user,
                                      ifcs,
                                      0,
                                      false,
                                      trail);
  }
}

void RegistrationSender::match_application_servers(pjsip_msg* received_register_msg,
                                                   const Ifcs& ifcs,
                                                   const std::vector<Ifc>& fallback_ifcs,
                                                   bool is_initial_registration,
                                                   std::vector<AsInvocation>& application_servers,
                                                   bool& matched_dummy_as,
                                                   SAS::TrailId trail)
{
  matched_dummy_as = false;

  // Go through the list of iFCs and find which application servers should be
  // invoked for this request. Save off any application servers that do not
  // match a dummy AS.
  for (Ifc ifc : ifcs.ifcs_list())
  {
    if (ifc.filter_matches(SessionCase::Originating,
                           true,
                           is_initial_registration,
                           received_register_msg,
                           trail))
    {
      if ((ifc.as_invocation().server_name) ==
          (_ifc_configuration._dummy_as))
      {
        TRC_DEBUG("Ignoring this iFC as it matches a dummy AS (%s)",
                  _ifc_configuration._dummy_as.c_str());
        SAS::Event event(trail, SASEvent::IFC_MATCHED_DUMMY_AS, 1);
        event.add_var_param(_ifc_configuration._dummy_as);
        SAS::report_event(event);
        matched_dummy_as = true;
      }
      else
      {
        application_servers.push_back(ifc.as_invocation());
      }
    }
  }

  // Check if we should apply any fallback iFCs. We do this if:
  //  - The config option to apply fallback iFCs is set.
  //  - We haven't found any matching iFCs (true if application_servers is empty
  //    and we didn't find a dummy AS).
  if ((_ifc_configuration._apply_fallback_ifcs) &&
      ((application_servers.empty()) && (!matched_dummy_as)))
  {
    TRC_DEBUG("No iFCs apply to this message; looking up fallback iFCs");
    SAS::Event event(trail, SASEvent::STARTING_FALLBACK_IFCS_LOOKUP, 1);
    SAS::report_event(event);

    // Go though the list of fallback iFCs and find which application servers
    // should be invoked for this request. Save off any application servers that
    // do match a dummy AS.
    for (Ifc ifc : fallback_ifcs)
    {
      if (ifc.filter_matches(SessionCase::Originating,
                             true,
                             is_initial_registration,
                             received_register_msg,
                             trail))
      {
        if (ifc.as_invocation().server_name == _ifc_configuration._dummy_as)
        {
          TRC_DEBUG("Ignoring this fallback iFC as it matches a dummy AS (%s)",
                    _ifc_configuration._dummy_as.c_str());
          SAS::Event event(trail, SASEvent::IFC_MATCHED_DUMMY_AS, 2);
          event.add_var_param(_ifc_configuration._dummy_as);
          SAS::report_event(event);
          matched_dummy_as = true;
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

    // Check if we didn't find any fallback iFCs. This is true if we haven't
    // found any matching iFCs (true if application_servers is empty and we
    // didn't find a dummy AS). We SAS log this, and increment a statistic.
    if ((application_servers.empty()) && (!matched_dummy_as))
    {
      if (_ifc_configuration._no_matching_fallback_ifcs_tbl)
      {
        _ifc_configuration._no_matching_fallback_ifcs_tbl->increment();
      }

      TRC_DEBUG("Unable to apply fallback iFCs as no matching iFCs available");
      SAS::Event event(trail, SASEvent::NO_FALLBACK_IFCS, 1);
      SAS::report_event(event);
    }
  }
}

void RegistrationSender::send_register_to_as(pjsip_msg* received_register_msg,
                                             pjsip_msg* ok_response_msg,
                                             const std::string& served_user,
                                             const AsInvocation& as,
                                             int expires,
                                             bool is_initial_registration,
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

    if (as.include_register_request || _force_third_party_register_body)
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

    if (as.include_register_response || _force_third_party_register_body)
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

  // Save off the third party registration data that we may need when we the
  // register callback is triggered.
  ThirdPartyRegData* tsxdata = new ThirdPartyRegData;
  tsxdata->registration_sender = this;
  tsxdata->subscriber_manager = _subscriber_manager;
  tsxdata->default_handling = as.default_handling;
  tsxdata->trail = trail;
  tsxdata->public_id = served_user;
  tsxdata->expires = expires;
  tsxdata->is_initial_registration = is_initial_registration;

  // Build the register callback and send the request statefully.
  status = PJUtils::send_request(tdata, 0, tsxdata, &build_register_cb);

  if (status != PJ_SUCCESS)
  {
    delete tsxdata; tsxdata = NULL; // LCOV_EXCL_LINE
  }
}

PJUtils::Callback* RegistrationSender::build_register_cb(void* token,
                                                         pjsip_event* event)
{
  RegistrationSender::RegisterCallback* cb = new RegistrationSender::RegisterCallback(token, event);
  return cb;
}

///
/// RegisterCallback methods.
///

RegistrationSender::RegisterCallback::RegisterCallback(void* token, pjsip_event* event)
{
  // Save the regdata from the token, and the status code from the event
  _reg_data = (ThirdPartyRegData*)token;
  _status_code = event->body.tsx_state.tsx->status_code;
}

RegistrationSender::RegisterCallback::~RegisterCallback()
{
  delete _reg_data; _reg_data = NULL;
}

void RegistrationSender::RegisterCallback::run()
{
  TRC_DEBUG("Handling 3rd party register callback for %s", _reg_data->public_id.c_str());

  if ((_reg_data->default_handling == SESSION_TERMINATED) &&
      ((_status_code == 408) ||
       (PJSIP_IS_STATUS_IN_CLASS(_status_code, 500))))
  {
    TRC_INFO("Third-party REGISTER transaction failed with code %d", _status_code);

    SAS::Event event(_reg_data->trail, SASEvent::REGISTER_AS_FAILED, 0);
    event.add_var_param(""); // TODO fix this up to send a status code only.
    SAS::report_event(event);

    // TODO can this call result in a loop of 3rdPartyReg callbacks if the AS
    // is unreachable? Should we deregister the sub if this is a 3rd party
    // deregister since they will already be deregisterd??
    //
    // 3GPP TS 24.229 V12.0.0 (2013-03) 5.4.1.7 specifies that an AS failure
    // where SESSION_TERMINATED is set means that we should deregister "the
    // currently registered public user identity" - i.e. all bindings
    _reg_data->subscriber_manager->deregister_subscriber(_reg_data->public_id,
                                                         SubscriberDataUtils::EventTrigger::ADMIN,
                                                         _reg_data->trail);
  }

  if (_reg_data->registration_sender->_third_party_reg_stats_tbls != NULL)
  {
    SNMP::RegistrationStatsTables* third_party_reg_stats_tbls =
                                     _reg_data->registration_sender->_third_party_reg_stats_tbls;

    if (_status_code == 200)
    {
      if (_reg_data->expires == 0)
      {
        third_party_reg_stats_tbls->de_reg_tbl->increment_successes();
      }
      else if (_reg_data->is_initial_registration)
      {
        third_party_reg_stats_tbls->init_reg_tbl->increment_successes();
      }
      else
      {
        third_party_reg_stats_tbls->re_reg_tbl->increment_successes();
      }
    }
    else
    {
      // Count all failed registration attempts, not just ones that result in
      // user being unsubscribed.
      if (_reg_data->expires == 0)
      {
        third_party_reg_stats_tbls->de_reg_tbl->increment_failures();
      }
      else if (_reg_data->is_initial_registration)
      {
        third_party_reg_stats_tbls->init_reg_tbl->increment_failures();
      }
      else
      {
        third_party_reg_stats_tbls->re_reg_tbl->increment_failures();
      }
    }
  }
}
