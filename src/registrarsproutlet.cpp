/**
 *
 * @file registrarproutlet.cpp
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <time.h>

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}

// Common STL includes.
#include <cassert>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <queue>
#include <string>

#include "pjutils.h"
#include "utils.h"
#include "wildcard_utils.h"
#include "sproutsasevent.h"
#include "sm_sip_mapping.h"
#include "registrarsproutlet.h"
#include "constants.h"
#include "custom_headers.h"
#include "log.h"
#include "uri_classifier.h"
#include "associated_uris.h"
#include "scscf_utils.h"
#include "aor_utils.h"
#include "subscriber_data_utils.h"

// RegistrarSproutlet constructor.
RegistrarSproutlet::RegistrarSproutlet(const std::string& name,
                                       int port,
                                       const std::string& uri,
                                       const std::list<std::string>& aliases,
                                       const std::string& network_function,
                                       const std::string& next_hop_service,
                                       SubscriberManager* sm,
                                       ACRFactory* rfacr_factory,
                                       int cfg_max_expires,
                                       SNMP::RegistrationStatsTables* reg_stats_tbls) :
  Sproutlet(name, port, uri, "", aliases, NULL, NULL, network_function),
  _sm(sm),
  _acr_factory(rfacr_factory),
  _max_expires(cfg_max_expires),
  _reg_stats_tbls(reg_stats_tbls),
  _next_hop_service(next_hop_service)
{
}

//RegistrarSproutlet destructor.
RegistrarSproutlet::~RegistrarSproutlet()
{
}

bool RegistrarSproutlet::init()
{
  bool init_success = true;

  // Construct a Service-Route header pointing at the S-CSCF ready to be added
  // to REGISTER 200 OK response.
  pjsip_sip_uri* service_route_uri = NULL;

  if (stack_data.scscf_uri != NULL)
  {
    service_route_uri = (pjsip_sip_uri*)pjsip_uri_clone(stack_data.pool,
                                                        stack_data.scscf_uri);
  }

  if (service_route_uri != NULL)
  {
    service_route_uri->lr_param = 1;

    // Add the orig parameter.  The UE must provide this back on future messages
    // to ensure we perform originating processing.
    pjsip_param *orig_param = PJ_POOL_ALLOC_T(stack_data.pool, pjsip_param);
    pj_strdup(stack_data.pool, &orig_param->name, &STR_ORIG);
    pj_strdup2(stack_data.pool, &orig_param->value, "");
    pj_list_insert_after(&service_route_uri->other_param, orig_param);

    _service_route = pjsip_route_hdr_create(stack_data.pool);
    _service_route->name = STR_SERVICE_ROUTE;
    _service_route->sname = pj_str((char *)"");
    _service_route->name_addr.uri = (pjsip_uri*)service_route_uri;
  }
  else
  {
    // LCOV_EXCL_START - Start up failures not tested in UT
    TRC_ERROR("Unable to set up Service-Route header for the registrar from %.*s",
              stack_data.scscf_uri_str.slen, stack_data.scscf_uri_str.ptr);
    init_success = false;
    // LCOV_EXCL_STOP
  }

  return init_success;
}

SproutletTsx* RegistrarSproutlet::get_tsx(SproutletHelper* helper,
                                          const std::string& alias,
                                          pjsip_msg* req,
                                          pjsip_sip_uri*& next_hop,
                                          pj_pool_t* pool,
                                          SAS::TrailId trail)
{
  URIClass uri_class = URIClassifier::classify_uri(req->line.req.uri);
  if ((req->line.req.method.id == PJSIP_REGISTER_METHOD) &&
      ((uri_class == NODE_LOCAL_SIP_URI) ||
       (uri_class == HOME_DOMAIN_SIP_URI)) &&
      (PJUtils::check_route_headers(req)))
  {
    return (SproutletTsx*)new RegistrarSproutletTsx(this,
                                                    _next_hop_service);
  }

  // We're not interested in the message so create a next hop URI.
  pjsip_sip_uri* base_uri = helper->get_routing_uri(req, this);
  next_hop = helper->next_hop_uri(_next_hop_service,
                                  base_uri,
                                  pool);
  return NULL;
}

RegistrarSproutletTsx::RegistrarSproutletTsx(RegistrarSproutlet* registrar,
                                             const std::string& next_hop_service) :
  CompositeSproutletTsx(registrar, next_hop_service),
  _registrar(registrar),
  _scscf_uri()
{
  TRC_DEBUG("Registrar Transaction (%p) created", this);
}

RegistrarSproutletTsx::~RegistrarSproutletTsx()
{
  TRC_DEBUG("Registrar Transaction (%p) destroyed", this);
}

void RegistrarSproutletTsx::on_rx_initial_request(pjsip_msg *req)
{
  TRC_INFO("Registrar sproutlet received initial request");

  process_register_request(req);
}

// This function processes the register. There are six steps:
// 1. Perform basic validation of the register. This step covers validating
//    the register request without making any calls out to the HSS/memcached.
//    If the validation fails we can bail out early.
// 2. Get the subscriber data from the HSS. This allows the registrar to get
//    the default IMPU. If this fails, reject the register with a return
//    code based on the HSS error.
// 3. Get the existing bindings for the subscriber from the SM (using the
//    default IMPU). If this fails, reject the register with a return code
//    based on the memcached error.
// 4. Work out what changes we want to make, based on the register request
//    and the set of current bindings. Any invalid change is logged and then
//    ignored.
// 5. Write the changes to SM.
// 6. Respond to the register. The return code is based on the SM response.
//    Add any appropriate headers to the response.
// 7. Send the register/response to any third party application servers.
void RegistrarSproutletTsx::process_register_request(pjsip_msg *req)
{
  // Get the system time in seconds for calculating absolute expiry times.
  int now = time(NULL);

  // 1. Perform basic validation of the register.
  int num_contact_headers = 0;
  bool emergency_registration = false;
  bool contains_id = false;
  pjsip_status_code st_code = basic_validation_of_register(
                                                        req,
                                                        num_contact_headers,
                                                        emergency_registration,
                                                        contains_id,
                                                        trail());

  if (st_code != PJSIP_SC_OK)
  {
    if (num_contact_headers != 0)
    {
      // We've no idea what type of registration request this was. Assume
      // deregistration (as we want to record it somehow). If this was
      // just a fetch bindings register then don't increment any statistics.
      _registrar->_reg_stats_tbls->de_reg_tbl->increment_attempts();
      _registrar->_reg_stats_tbls->de_reg_tbl->increment_failures();
    }

    pjsip_msg* rsp = create_response(req, st_code);
    send_response(rsp);
    free_msg(req);

    return;
  }

  // 2. The register has passed basic validation - so we can now start the
  //    actual register processing. SAS log the request, and get the
  //    subscriber information from the HSS.

  // Allocate an ACR for this transaction and pass the request to it. Node
  // role is always considered originating for REGISTER requests.
  ACR* acr = _registrar->_acr_factory->get_acr(trail(),
                                               ACR::CALLING_PARTY,
                                               ACR::NODE_ROLE_ORIGINATING);
  acr->rx_request(req);

  // Canonicalize the public ID from the URI in the To header.
  pjsip_uri* uri = (pjsip_uri*)pjsip_uri_get_uri(PJSIP_MSG_TO_HDR(req)->uri);
  std::string public_id = PJUtils::public_id_from_uri(uri);
  TRC_DEBUG("Process REGISTER for public ID %s", public_id.c_str());

  std::string private_id;
  std::string private_id_for_binding;

  if (!get_private_id(req, private_id))
  {
    // There are legitimate cases where we don't have a private ID
    // here (for example, on a re-registration where Bono has set the
    // Integrity-Protected header), so this is *not* a failure
    // condition.

    // We want the private ID here so that Homestead can use it to
    // subscribe for updates from the HSS - but on a re-registration,
    // Homestead should already have subscribed for updates during the
    // initial registration, so we can just make a request using our
    // public ID.
    private_id = "";

    // IMS compliant clients will always have the Auth header on all REGISTERs,
    // including reREGISTERS. Non-IMS clients won't, but their private ID
    // will always be the public ID with the sip: removed.
    private_id_for_binding = PJUtils::default_private_id_from_uri(uri);
  }
  else
  {
    private_id_for_binding = private_id;
  }

  SAS::Event event(trail(), SASEvent::REGISTER_START, 0);
  event.add_var_param(public_id);
  event.add_var_param(private_id);
  SAS::report_event(event);

  if (num_contact_headers == 0)
  {
    SAS::Event event(trail(), SASEvent::REGISTER_NO_CONTACTS, 0);
    event.add_var_param(public_id);
    SAS::report_event(event);
  }

  if (emergency_registration)
  {
    SAS::Event event(trail(), SASEvent::REGISTER_EMERGENCY, 0);
    SAS::report_event(event);
  }

  // Construct the S-CSCF URI for this transaction. Use the configured S-CSCF
  // URI as a starting point.
  pjsip_sip_uri* scscf_uri =
           (pjsip_sip_uri*)pjsip_uri_clone(get_pool(req), stack_data.scscf_uri);
  pjsip_sip_uri* routing_uri = get_routing_uri(req);

  // If the URI that routed to this Sproutlet isn't reflexive, just ignore it
  // and use the configured scscf uri
  if ((routing_uri != nullptr) && is_uri_reflexive((pjsip_uri*)routing_uri))
  {
    SCSCFUtils::get_scscf_uri(get_pool(req),
                              get_local_hostname(routing_uri),
                              get_local_hostname(scscf_uri),
                              scscf_uri);
  }

  _scscf_uri = PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                      (pjsip_uri*)scscf_uri);


  // Get the subscriber state.
  HSSConnection::irs_query irs_query;
  irs_query._public_id = public_id;
  irs_query._private_id = private_id;
  irs_query._req_type = HSSConnection::REG;
  irs_query._server_name = _scscf_uri;
  HSSConnection::irs_info irs_info;
  std::string default_impu;

  HTTPCode rc = _registrar->_sm->get_subscriber_state(irs_query, irs_info, trail());
  st_code = determine_sm_sip_response(rc, irs_info._regstate, "REGISTER");

  if (st_code != PJSIP_SC_OK)
  {
    // Getting the subscriber information failed. SAS log and reject the request
    TRC_DEBUG("Failed to get subscriber information for %s - error is %d",
              public_id.c_str(), st_code);
    SAS::Event event(trail(), SASEvent::REGISTER_FAILED_INVALIDPUBPRIV, 0);
    event.add_var_param(public_id);
    event.add_var_param(private_id);
    SAS::report_event(event);

    acr->send();
    delete acr;

    if (num_contact_headers != 0)
    {
      // We've no idea what type of registration request this was. Assume
      // deregistration (as we want to record it somehow). If this was
      // just a fetch bindings register then don't increment any statistics.
      _registrar->_reg_stats_tbls->de_reg_tbl->increment_attempts();
      _registrar->_reg_stats_tbls->de_reg_tbl->increment_failures();
    }

    pjsip_msg* rsp = create_response(req, st_code);
    send_response(rsp);
    free_msg(req);

    return;
  }

  if (!irs_info._associated_uris.get_default_impu(default_impu,
                                                  emergency_registration))
  {
    // Getting the subscriber information failed. SAS log and reject the request
    TRC_DEBUG("Failed to get subscriber information for %s - error is %d",
              public_id.c_str(), st_code);

    SAS::Event event(trail(), SASEvent::REGISTER_IRS_INVALID, 0);
    event.add_var_param(public_id);
    SAS::report_event(event);

    acr->send();
    delete acr;

    if (num_contact_headers != 0)
    {
      // We've no idea what type of registration request this was. Assume
      // deregistration (as we want to record it somehow). If this was
      // just a fetch bindings register then don't increment any statistics.
      _registrar->_reg_stats_tbls->de_reg_tbl->increment_attempts();
      _registrar->_reg_stats_tbls->de_reg_tbl->increment_failures();
    }

    pjsip_msg* rsp = create_response(req, PJSIP_SC_BAD_REQUEST);
    send_response(rsp);
    free_msg(req);

    return;
  }

  // 3. We've now got the subscriber information - in particular the default
  //    public ID. Use this to get the current bindings for the subscriber.
  //    Despite getting the previous registration state of the subscriber, we
  //    still don't have enough information to be able to tell what type of
  //    registration request we have.
  Bindings current_bindings;
  rc = _registrar->_sm->get_bindings(default_impu, current_bindings, trail());

  if ((rc != HTTP_OK) && (rc != HTTP_NOT_FOUND))
  {
    // Getting the current bindings failed. SAS log and reject the request.
    st_code = determine_sm_sip_response(rc, irs_info._regstate, "REGISTER");
    TRC_DEBUG("Failed to get current bindings for %s  - error is %d",
              default_impu.c_str(), rc);

    SAS::Event event(trail(), SASEvent::REGISTER_FAILED_GET_BINDINGS, 0);
    event.add_var_param(default_impu);
    event.add_static_param(rc);
    SAS::report_event(event);

    acr->send();
    delete acr;

    if (num_contact_headers != 0)
    {
      // We've no idea what type of registration request this was. Assume
      // deregistration (as we want to record it somehow). If this was
      // just a fetch bindings register then don't increment any statistics.
      _registrar->_reg_stats_tbls->de_reg_tbl->increment_attempts();
      _registrar->_reg_stats_tbls->de_reg_tbl->increment_failures();
    }

    pjsip_msg* rsp = create_response(req, st_code);
    send_response(rsp);
    free_msg(req);

    return;
  }

  // 4. We've successfully got the current bindings. Parse the register to work
  //    out what changes we want to make. We can also work out what type of
  //    register this is.
  Bindings update_bindings;
  std::vector<std::string> binding_ids_to_remove = {};
  get_bindings_from_req(req,
                        private_id_for_binding,
                        default_impu,
                        now,
                        current_bindings,
                        update_bindings,
                        binding_ids_to_remove);
  RegisterType rt = get_register_type(num_contact_headers,
                                      current_bindings,
                                      update_bindings,
                                      binding_ids_to_remove);
  track_register_attempts_statistics(rt);

  // 5. We know what changes we want to make - contact the SM to do so.
  Bindings all_bindings;

  if ((rt == RegisterType::INITIAL) ||
      (rt == RegisterType::FETCH_INITIAL))
  {
    TRC_DEBUG("Processing an initial register for %s", default_impu.c_str());
    rc = _registrar->_sm->register_subscriber(default_impu,
                                              _scscf_uri,
                                              irs_info._associated_uris,
                                              update_bindings,
                                              all_bindings,
                                              irs_info,
                                              trail());
  }
  else
  {
    TRC_DEBUG("Processing a register for %s", default_impu.c_str());
    rc = _registrar->_sm->reregister_subscriber(default_impu,
                                                _scscf_uri,
                                                irs_info._associated_uris,
                                                update_bindings,
                                                binding_ids_to_remove,
                                                all_bindings,
                                                irs_info,
                                                trail());
  }

  if (rc == HTTP_OK)
  {
    st_code = PJSIP_SC_OK;
  }
  else
  {
    st_code = determine_sm_sip_response(rc, irs_info._regstate, "REGISTER");
  }

  // 6. Build and send the response.
  pjsip_msg* rsp = create_response(req, st_code);
  pjsip_generic_string_hdr* gen_hdr;

  if (st_code == PJSIP_SC_OK)
  {
    // Create Supported and Require headers for RFC5626.
    gen_hdr = pjsip_generic_string_hdr_create(get_pool(rsp),
                                              &STR_SUPPORTED,
                                              &STR_OUTBOUND);
    if (gen_hdr == NULL)
    {
      // LCOV_EXCL_START - Shouldn't be hittable
      TRC_DEBUG("Failed to add RFC 5626 headers");

      SAS::Event event(trail(), SASEvent::REGISTER_FAILED_5636, 0);
      event.add_var_param(public_id);
      SAS::report_event(event);

      st_code = PJSIP_SC_INTERNAL_SERVER_ERROR;
      rsp->line.status.code = PJSIP_SC_INTERNAL_SERVER_ERROR;
      // LCOV_EXCL_STOP
    }
  }

  if (st_code != PJSIP_SC_OK)
  {
    // The REGISTER failed.
    TRC_DEBUG("Register failed for %s with %d", public_id.c_str(), st_code);

    SAS::Event event(trail(), SASEvent::REGISTER_FAILED, 0);
    event.add_var_param(public_id);
    event.add_static_param(st_code);
    SAS::report_event(event);

    track_register_failures_statistics(rt);
  }
  else
  {
    // At this point we're definitely going to accept the register. Write a SAS
    // log. The rest of this processing is adding the correct headers to the
    // 200 OK.
    SAS::Event reg_accepted(trail(), SASEvent::REGISTER_ACCEPTED, 0);
    SAS::report_event(reg_accepted);

    track_register_successes_statistics(rt);

    pjsip_msg_add_hdr(rsp, (pjsip_hdr*)gen_hdr);
    add_contact_headers(rsp, req, all_bindings, now, default_impu, trail());
    handle_path_headers(rsp, req, contains_id, all_bindings);
    add_service_route_header(rsp, req);

    // Add P-Associated-URI headers for all of the associated URIs that are real
    // URIs, ignoring wildcard URIs and logging any URIs that aren't wildcards
    // but are still unparseable as URIs.
    add_p_associated_uri_headers(rsp, irs_info, public_id, trail());

    // Add a PCFA header.
    PJUtils::add_pcfa_header(rsp, get_pool(rsp), irs_info._ccfs, irs_info._ecfs, true);
  }

  // Send the register request/response to the register sender, in case there's
  // any third party registers to send.
  if ((!SubscriberDataUtils::contains_emergency_binding(all_bindings)) &&
      (rt != RegisterType::FETCH) &&
      (rt != RegisterType::FETCH_INITIAL))
  {
    int max_expiry = SubscriberDataUtils::get_max_expiry(all_bindings, now);

    std::string as_id = public_id;

    if (irs_info._associated_uris.is_impu_barred(public_id))
    {
      as_id = default_impu;
    }

    _registrar->_sm->register_with_application_servers(req,
                                                       rsp,
                                                       as_id,
                                                       irs_info._service_profiles[public_id],
                                                       max_expiry,
                                                       (rt == RegisterType::INITIAL),
                                                       trail());
  }

  // Finally, tidy up. Send the ACR, send the response, and free up the memory.

  // Pass the response to the ACR.
  acr->tx_response(rsp);

  // Send the ACR and delete it.
  acr->send();
  delete acr; acr = NULL;

  // Send the response
  send_response(rsp);

  // Tidy up memory.
  SubscriberDataUtils::delete_bindings(all_bindings);
  SubscriberDataUtils::delete_bindings(current_bindings);
  SubscriberDataUtils::delete_bindings(update_bindings);

  free_msg(req);
}

pjsip_status_code RegistrarSproutletTsx::basic_validation_of_register(
                                                   pjsip_msg* req,
                                                   int& num_contact_headers,
                                                   bool& emergency_registration,
                                                   bool& contains_id,
                                                   SAS::TrailId trail)
{
  // Perform basic validation of the register. We can reject the request
  // early which saves contacting the HSS/memcached (although we do have to
  // loop through the contact headers twice in the success case).
  //
  // The error cases are:
  // - Register with a contact header containing * but where the expiry isn't
  //   0 - reject with a 400
  // - Register only contains attempts to remove emergency bindings - reject
  //   with a 501. It's invalid to shorten the time of an emergency
  //   registration, so if this is all the register is doing then it's
  //   definitely invalid. If a register is doing this along with some valid
  //   changes, then we'll continue. Later on, we'll remove the invalid
  //   emergency register changes, but allow the valid changes to be made.
  // - Invalid scheme - reject with a 404

  pjsip_status_code st_code = PJSIP_SC_OK;

  // Get the URI from the To header and check it is a SIP or TEL URI.
  pjsip_uri* uri = (pjsip_uri*)pjsip_uri_get_uri(PJSIP_MSG_TO_HDR(req)->uri);

  if ((!PJSIP_URI_SCHEME_IS_SIP(uri)) && (!PJSIP_URI_SCHEME_IS_TEL(uri)))
  {
    // Reject a non-SIP/TEL URI with 404 Not Found (RFC3261 isn't clear
    // whether 404 is the right status code - it says 404 should be used if
    // the AoR isn't valid for the domain in the RequestURI).
    TRC_DEBUG("Rejecting register request using invalid URI scheme");

    SAS::Event event(trail, SASEvent::REGISTER_FAILED_INVALIDURISCHEME, 0);
    SAS::report_event(event);

    st_code = PJSIP_SC_NOT_FOUND;
  }

  int num_emergency_deregisters = 0;

  // Loop through the contact headers. This allows us to detect if there's an
  // invalid wildcard contact URI, and if we're only attempting to deregister
  // emergency deregistrations
  pjsip_contact_hdr* contact_hdr =
             (pjsip_contact_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_CONTACT, NULL);

  while (contact_hdr != NULL)
  {
    num_contact_headers++;

    pjsip_expires_hdr* expires =
             (pjsip_expires_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_EXPIRES, NULL);
    int expiry = PJUtils::expiry_for_binding(contact_hdr,
                                             expires,
                                             _registrar->_max_expires);

    bool contains_instance_id = false;
    bool contains_reg_id = false;

    // Check for the presence of sip-instance and reg-id parameters
    pjsip_param* p = contact_hdr->other_param.next;

    while ((p != NULL) && (p != &contact_hdr->other_param))
    {
      if (pj_stricmp(&p->name, &STR_SIP_INSTANCE) == 0)
      {
        contains_instance_id = true;
      }

      if (pj_stricmp(&p->name, &STR_REG_ID) == 0)
      {
        contains_reg_id = true;
      }

      p = p->next;
    }

    contains_id = contains_id ? contains_id :
                                      (contains_instance_id && contains_reg_id);

    if ((contact_hdr->star) && (expiry != 0))
    {
      TRC_DEBUG("Attempted to deregister all bindings, but expiry "
                "value wasn't 0");

      SAS::Event event(trail, SASEvent::REGISTER_FAILED_INVALIDCONTACT, 0);
      SAS::report_event(event);

      st_code = PJSIP_SC_BAD_REQUEST;
      break;
    }

    if (PJUtils::is_emergency_registration(contact_hdr))
    {
      if (expiry == 0)
      {
        TRC_DEBUG("Attempting to deregister an emergency registration");
        num_emergency_deregisters++;
      }
      else
      {
        emergency_registration = true;
      }
    }

    contact_hdr = (pjsip_contact_hdr*) pjsip_msg_find_hdr(req,
                                                          PJSIP_H_CONTACT,
                                                          contact_hdr->next);
  }

  if ((num_contact_headers != 0) &&
      (num_contact_headers == num_emergency_deregisters))
  {
    TRC_DEBUG("Register request is solely attempting to deregister emergency "
              "registrations");

    SAS::Event event(trail, SASEvent::DEREGISTER_FAILED_EMERGENCY, 0);
    SAS::report_event(event);

    st_code = PJSIP_SC_NOT_IMPLEMENTED;
  }

  return st_code;
}

/// Updates an existing set of binding data (typically just retrieved from the
/// AoR store), with updated binding information from a REGISTER request.
void RegistrarSproutletTsx::get_bindings_from_req(
                             pjsip_msg* req,
                             const std::string& private_id,
                             const std::string& aor_id,
                             const int& now,
                             const Bindings& current_bindings,
                             Bindings& updated_bindings,
                             std::vector<std::string>& binding_ids_to_remove)
{
  // Get the call identifier and the cseq number from the respective headers.
  std::string cid = PJUtils::pj_str_to_string(&PJSIP_MSG_CID_HDR(req)->id);
  int cseq =
           ((pjsip_cseq_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_CSEQ, NULL))->cseq;

  // Find the expire headers in the message.
  pjsip_expires_hdr* expires =
             (pjsip_expires_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_EXPIRES, NULL);
  int expiry;

  // Now loop through all the contacts. If there are multiple contacts in the
  // contact header in the SIP message, pjsip parses them to separate contact
  // header structures.
  pjsip_contact_hdr* contact =
             (pjsip_contact_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_CONTACT, NULL);

  while (contact != NULL)
  {
    if (contact->star)
    {
      // The REGISTER has a Contact header that looks something like
      // "Contact: *". This means that we should remove all existing bindings.
      // (We've already checked for invalid use of the wildcard contact
      // header in the basic validation).
      SubscriberDataUtils::delete_bindings(updated_bindings);

      for (BindingPair binding : current_bindings)
      {
        binding_ids_to_remove.push_back(binding.first);
      }
    }

    expiry = PJUtils::expiry_for_binding(contact,
                                         expires,
                                         _registrar->_max_expires);

    pjsip_uri* uri = (contact->uri != NULL) ?
                      (pjsip_uri*)pjsip_uri_get_uri(contact->uri) :
                      NULL;

    if ((uri != NULL) &&
        (PJSIP_URI_SCHEME_IS_SIP(uri)))
    {
      // The binding identifier is based on the +sip.instance parameter if
      // it is present.  If not the contact URI is used instead.
      std::string contact_uri =
                          PJUtils::uri_to_string(PJSIP_URI_IN_CONTACT_HDR, uri);
      std::string binding_id = get_binding_id(contact);

      if (binding_id == "")
      {
        binding_id = contact_uri;
      }

      TRC_DEBUG("Binding identifier for contact = %s", binding_id.c_str());

      if (expiry == 0)
      {
        binding_ids_to_remove.push_back(binding_id);
      }
      else
      {
        Binding* binding = new Binding(aor_id);

        // Either this is a new binding, has come from a restarted device, or
        // is an update to an existing binding.
        binding->_uri = contact_uri;

        TRC_DEBUG("Updating binding %s for contact %s",
                  binding_id.c_str(), contact_uri.c_str());

        // Get the Path headers, if present.  RFC 3327 allows us the option of
        // rejecting a request with a Path header if there is no corresponding
        // "path" entry in the Supported header but we don't do so on the
        // assumption that the edge proxy knows what it's doing.
        //
        // We store the full path header in the _path_headers field.
        binding->_path_headers.clear();
        pjsip_routing_hdr* path_hdr = (pjsip_routing_hdr*)
                            pjsip_msg_find_hdr_by_name(req, &STR_PATH, NULL);

        while (path_hdr)
        {
          std::string path = PJUtils::get_header_value((pjsip_hdr*)path_hdr);
          TRC_DEBUG("Path header %s", path.c_str());

          // Extract all the paths from this header.
          binding->_path_headers.push_back(path);

          // Look for the next header.
          path_hdr = (pjsip_routing_hdr*)
                  pjsip_msg_find_hdr_by_name(req, &STR_PATH, path_hdr->next);
        }

        binding->_cid = cid;
        binding->_cseq = cseq;
        binding->_priority = contact->q1000;
        binding->_params.clear();
        pjsip_param* p = contact->other_param.next;

        while ((p != NULL) && (p != &contact->other_param))
        {
          std::string pname = PJUtils::pj_str_to_string(&p->name);
          std::string pvalue = PJUtils::pj_str_to_string(&p->value);

          // Skip parameters that must not be user-specified
          if (pname != "pub-gruu")
          {
            binding->_params[pname] = pvalue;
          }

          p = p->next;
        }

        binding->_private_id = private_id;
        binding->_emergency_registration =
                                    PJUtils::is_emergency_registration(contact);

        // If the new expiry is less than the current expiry, and it's an
        // emergency registration, don't update the expiry time
        int new_expiry = now + expiry;
        int old_expiry = 0;

        if (current_bindings.find(binding_id) != current_bindings.end())
        {
          old_expiry = current_bindings.at(binding_id)->_expires;
        }

        if ((binding->_emergency_registration) &&
            (new_expiry < old_expiry))
        {
          TRC_DEBUG("Unable to reduce the expiry time of an emergency binding");
          new_expiry = old_expiry;
        }

        binding->_expires = new_expiry;

        updated_bindings.insert(std::make_pair(binding_id, binding));
      }
    }

    contact = (pjsip_contact_hdr*)pjsip_msg_find_hdr(req,
                                                     PJSIP_H_CONTACT,
                                                     contact->next);
  }
}

/// Get private ID from a received message by checking the Authorization
/// header. If that uses the Digest scheme and contains a non-empty
/// username, it puts that username into id and returns true;
/// otherwise returns false.
bool RegistrarSproutletTsx::get_private_id(pjsip_msg* req, std::string& id)
{
  bool success = false;

  pjsip_authorization_hdr* auth_hdr = (pjsip_authorization_hdr*)
                           pjsip_msg_find_hdr(req, PJSIP_H_AUTHORIZATION, NULL);

  if (auth_hdr != NULL)
  {
    if (pj_stricmp2(&auth_hdr->scheme, "digest") == 0)
    {
      id = PJUtils::pj_str_to_string(&auth_hdr->credential.digest.username);
      if (!id.empty())
      {
        success = true;
      }
    }
    else
    {
      // LCOV_EXCL_START
      TRC_WARNING("Unsupported scheme \"%.*s\" in Authorization header when "
                  "determining private ID - ignoring",
                  auth_hdr->scheme.slen, auth_hdr->scheme.ptr);
      // LCOV_EXCL_STOP
    }
  }
  return success;
}

std::string RegistrarSproutletTsx::get_binding_id(pjsip_contact_hdr* contact)
{
  // Get a suitable binding string from +sip.instance and reg_id parameters
  // if they are supplied.
  std::string id = "";
  pj_str_t *instance = NULL;
  pj_str_t *reg_id = NULL;

  pjsip_param *p = contact->other_param.next;

  while ((p != NULL) && (p != &contact->other_param))
  {
    if (pj_stricmp(&p->name, &STR_SIP_INSTANCE) == 0)
    {
      instance = &p->value;
    }
    else if (pj_stricmp(&p->name, &STR_REG_ID) == 0)
    {
      reg_id = &p->value;
    }
    p = p->next;
  }

  if ((instance != NULL) && (pj_strlen(instance) >= 2))
  {
    // The contact a +sip.instance parameters, so form a suitable binding string.
    id = PJUtils::pj_str_to_string(instance);
    id = id.substr(1, id.size() - 2); // Strip quotes

    if (reg_id != NULL)
    {
      id = id + ":" + PJUtils::pj_str_to_string(reg_id);
    }

    if (PJUtils::is_emergency_registration(contact))
    {
      id = "sos" + id;
    }

  }

  return id;
}

RegisterType RegistrarSproutletTsx::get_register_type(
                          const int& contact_headers,
                          const Bindings& current_bindings,
                          const Bindings& update_bindings,
                          const std::vector<std::string>& binding_ids_to_remove)
{
  RegisterType rt = RegisterType::REREGISTER;

  if (contact_headers == 0)
  {
    rt = RegisterType::FETCH;

    if (current_bindings.empty())
    {
      rt = RegisterType::FETCH_INITIAL;
    }
  }
  else if (!binding_ids_to_remove.empty())
  {
    rt = RegisterType::DEREGISTER;
  }
  else if (current_bindings.empty())
  {
    rt = RegisterType::INITIAL;
  }

  return rt;
}

void RegistrarSproutletTsx::track_register_attempts_statistics(const RegisterType& rt)
{
  if (rt == RegisterType::INITIAL)
  {
    _registrar->_reg_stats_tbls->init_reg_tbl->increment_attempts();
  }
  else if (rt == RegisterType::REREGISTER)
  {
    _registrar->_reg_stats_tbls->re_reg_tbl->increment_attempts();
  }
  else if (rt == RegisterType::DEREGISTER)
  {
    _registrar->_reg_stats_tbls->de_reg_tbl->increment_attempts();
  }
}

void RegistrarSproutletTsx::track_register_successes_statistics(const RegisterType& rt)
{
  if (rt == RegisterType::INITIAL)
  {
    _registrar->_reg_stats_tbls->init_reg_tbl->increment_successes();
  }
  else if (rt == RegisterType::REREGISTER)
  {
    _registrar->_reg_stats_tbls->re_reg_tbl->increment_successes();
  }
  else if (rt == RegisterType::DEREGISTER)
  {
    _registrar->_reg_stats_tbls->de_reg_tbl->increment_successes();
  }
}

void RegistrarSproutletTsx::track_register_failures_statistics(const RegisterType& rt)
{
  if (rt == RegisterType::INITIAL)
  {
    _registrar->_reg_stats_tbls->init_reg_tbl->increment_failures();
  }
  else if (rt == RegisterType::REREGISTER)
  {
    _registrar->_reg_stats_tbls->re_reg_tbl->increment_failures();
  }
  else if (rt == RegisterType::DEREGISTER)
  {
    _registrar->_reg_stats_tbls->de_reg_tbl->increment_failures();
  }
}

void RegistrarSproutletTsx::add_contact_headers(pjsip_msg* rsp,
                                                pjsip_msg* req,
                                                const Bindings& all_bindings,
                                                int now,
                                                const std::string& public_id,
                                                SAS::TrailId trail)
{
  // Add contact headers for all active bindings.
  for (BindingPair b : all_bindings)
  {
    Binding* binding = b.second;

    // Parse the Contact URI from the store, making sure it is formatted as a
    // name-address.
    pjsip_uri* uri = PJUtils::uri_from_string(binding->_uri,
                                              get_pool(rsp),
                                              PJ_TRUE);

    if (uri != NULL)
    {
      // Contact URI is well formed, so include this in the response.
      pjsip_contact_hdr* contact = pjsip_contact_hdr_create(get_pool(rsp));
      contact->star = 0;
      contact->uri = uri;
      contact->q1000 = binding->_priority;
      contact->expires = binding->_expires - now;
      pj_list_init(&contact->other_param);

      for (std::pair<std::string, std::string> param : binding->_params)
      {
        pjsip_param *new_param = PJ_POOL_ALLOC_T(get_pool(rsp), pjsip_param);
        pj_strdup2(get_pool(rsp), &new_param->name, param.first.c_str());
        pj_strdup2(get_pool(rsp), &new_param->value, param.second.c_str());
        pj_list_insert_before(&contact->other_param, new_param);
      }

      // Add a GRUU if the UE supports GRUUs and the contact header contains
      // a +sip.instance parameter.
      if (PJUtils::msg_supports_extension(req, "gruu"))
      {
        // The pub-gruu parameter on the Contact header is calculated
        // from the instance-id, to avoid unnecessary storage in
        // memcached.
        std::string gruu = AoRUtils::pub_gruu_quoted_string(binding,
                                                            get_pool(rsp));

        if (!gruu.empty())
        {
          pjsip_param *new_param = PJ_POOL_ALLOC_T(get_pool(rsp), pjsip_param);
          pj_strdup2(get_pool(rsp), &new_param->name, "pub-gruu");
          pj_strdup2(get_pool(rsp), &new_param->value, gruu.c_str());
          pj_list_insert_before(&contact->other_param, new_param);
        }
      }

      pjsip_msg_add_hdr(rsp, (pjsip_hdr*)contact);
    }
    else
    {
      // Contact URI is malformed. We don't expect to hit this, as it requires
      // the data in the store to be corrupt.

      // LCOV_EXCL_START - No UTs for unhittable code.
      TRC_WARNING("Badly formed contact URI %s for address of record %s",
                  binding->_uri.c_str(), public_id.c_str());
      // LCOV_EXCL_STOP
    }
  }
}

void RegistrarSproutletTsx::handle_path_headers(
                                       pjsip_msg* rsp,
                                       pjsip_msg* req,
                                       const bool& contains_id,
                                       const Bindings& bindings)
{
  // We check if the UE that sent this REGISTER supports "outbound" (RFC5626)
  bool supported_outbound = PJUtils::is_param_in_generic_array_hdr(
                                                              req,
                                                              PJSIP_H_SUPPORTED,
                                                              &STR_OUTBOUND);

  // Deal with path header related fields in the response.
  // Find the first path header as added to the message. We do this using the
  // function msg_get_last_routing_hdr_by_name which itterates through the
  // headers of the message and returns the last one (which will be the first
  // one added).
  pjsip_routing_hdr* first_path_hdr =
                     PJUtils::msg_get_last_routing_hdr_by_name(req, &STR_PATH);


  if (first_path_hdr != NULL)
  {
    // Check for the presence of an "ob" parameter in the URI of the first path header
    pjsip_sip_uri* uri =
             (first_path_hdr->name_addr.uri != NULL) ?
              (pjsip_sip_uri*)pjsip_uri_get_uri(first_path_hdr->name_addr.uri) :
              NULL;

    bool contains_ob = ((uri != NULL) &&
                        (pjsip_param_find(&uri->other_param, &STR_OB) != NULL));

    // We include the outbound option tag in the Require header if and only if:
    // 1. We have bindings
    // 2. The first path header contains the "ob" parameter
    // 3. At least one contact header contains the instance-id and reg-id header
    //    parameters
    // 4. The UE supports "outbound" (RFC5626)
    //
    // The above behaviour is described in RFC5626 section 6. See also
    // TS24.229, 5.4.1.2.2F, step h).
    if ((!bindings.empty()) &&
        (contains_ob) &&
        (contains_id) &&
        (supported_outbound))
    {
      pjsip_require_hdr* require_hdr = pjsip_require_hdr_create(get_pool(rsp));
      require_hdr->count = 1;
      require_hdr->values[0] = STR_OUTBOUND;
      pjsip_msg_add_hdr(rsp, (pjsip_hdr*)require_hdr);
    }
  }

  // Echo back any Path headers as per RFC 3327, section 5.3.  We take these
  // from the request as they may not exist in the bindings anymore if the
  // bindings have expired.
  pjsip_routing_hdr* path_hdr =
           (pjsip_routing_hdr*)pjsip_msg_find_hdr_by_name(req, &STR_PATH, NULL);

  while (path_hdr)
  {
    pjsip_msg_add_hdr(rsp,
                      (pjsip_hdr*)pjsip_hdr_clone(get_pool(rsp), path_hdr));
    path_hdr = (pjsip_routing_hdr*)
                    pjsip_msg_find_hdr_by_name(req, &STR_PATH, path_hdr->next);
  }
}

void RegistrarSproutletTsx::add_service_route_header(pjsip_msg* rsp,
                                                     pjsip_msg* req)
{
  // Add the Service-Route header. We may modify this so need to do a full clone
  // of the header. Annoyingly this overwrites the custom name we set during
  // module initialization, so reset it.
  pjsip_routing_hdr* sr_hdr = (pjsip_routing_hdr*)
    pjsip_hdr_clone(get_pool(rsp), _registrar->_service_route);
  sr_hdr->name = STR_SERVICE_ROUTE;
  sr_hdr->sname = pj_str((char*)"");

  // Replace the local hostname part of the Service route URI with the local
  // hostname part of the URI that routed to this sproutlet.
  pjsip_sip_uri* sr_uri = (pjsip_sip_uri*)sr_hdr->name_addr.uri;
  pjsip_sip_uri* routing_uri = get_routing_uri(req);

  // If the URI that routed to this Sproutlet isn't reflexive, just ignore it
  // and use the configured scscf uri
  if ((routing_uri != nullptr) && is_uri_reflexive((pjsip_uri*)routing_uri))
  {
    SCSCFUtils::get_scscf_uri(get_pool(rsp),
                              get_local_hostname(routing_uri),
                              get_local_hostname(sr_uri),
                              sr_uri);
  }

  pjsip_msg_insert_first_hdr(rsp, (pjsip_hdr*)sr_hdr);
}

void RegistrarSproutletTsx::add_p_associated_uri_headers(
                                        pjsip_msg* rsp,
                                        HSSConnection::irs_info& irs_info,
                                        const std::string& aor,
                                        SAS::TrailId trail)
{
  // Log any URIs that have been left out of the P-Associated-URI because they
  // are barred.
  std::vector<std::string> barred_uris =
                                    irs_info._associated_uris.get_barred_uris();

  if (!barred_uris.empty())
  {
    std::stringstream ss;
    std::copy(barred_uris.begin(),
              barred_uris.end(),
              std::ostream_iterator<std::string>(ss, ","));
    std::string list = ss.str();

    if (!list.empty())
    {
      // Strip the trailing comma.
      list = list.substr(0, list.length() - 1);
    }

    SAS::Event event(trail, SASEvent::OMIT_BARRED_ID_FROM_P_ASSOC_URI, 0);
    event.add_var_param(list);
    SAS::report_event(event);
  }

  // Add P-Associated-URI headers for all of the associated URIs that are real
  // URIs, ignoring wildcard URIs and logging any URIs that aren't wildcards
  // but are still unparseable as URIs.
  std::vector<std::string> unbarred_uris =
                                  irs_info._associated_uris.get_unbarred_uris();

  if (!unbarred_uris.empty())
  {
    for (std::string uri : unbarred_uris)
    {
      if (!WildcardUtils::is_wildcard_uri(uri))
      {
        pjsip_uri* this_uri = PJUtils::uri_from_string(uri, get_pool(rsp));

        if (this_uri != NULL)
        {
          pjsip_routing_hdr* pau =
                       identity_hdr_create(get_pool(rsp), STR_P_ASSOCIATED_URI);
          pau->name_addr.uri = this_uri;
          pjsip_msg_add_hdr(rsp, (pjsip_hdr*)pau);
        }
        else
        {
          TRC_DEBUG("Bad associated URI %s", uri.c_str());

          SAS::Event event(trail, SASEvent::HTTP_HOMESTEAD_BAD_IDENTITY, 0);
          event.add_var_param(uri);
          SAS::report_event(event);
        }
      }
    }
  }
  else
  {
    // There aren't any associated URIs so just add the AoR in the P-Associated
    // URI header. We should only have to do this for emergency registrations.
    if (!WildcardUtils::is_wildcard_uri(aor))
    {
      pjsip_uri* aor_uri = PJUtils::uri_from_string(aor, get_pool(rsp));

      if (aor_uri != NULL)
      {
        pjsip_routing_hdr* pau =
                        identity_hdr_create(get_pool(rsp), STR_P_ASSOCIATED_URI);
        pau->name_addr.uri = aor_uri;
        pjsip_msg_add_hdr(rsp, (pjsip_hdr*)pau);
      }
    }
  }
}
