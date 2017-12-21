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
#include "memcachedstore.h"
#include "hss_sip_mapping.h"
#include "registrarsproutlet.h"
#include "registration_utils.h"
#include "constants.h"
#include "custom_headers.h"
#include "log.h"
#include "notify_utils.h"
#include "uri_classifier.h"
#include "associated_uris.h"
#include "scscf_utils.h"

// RegistrarSproutlet constructor.
RegistrarSproutlet::RegistrarSproutlet(const std::string& name,
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
                                       FIFCService* fifc_service,
                                       IFCConfiguration ifc_configuration) :
  Sproutlet(name, port, uri, "", aliases, NULL, NULL, network_function),
  _sdm(reg_sdm),
  _remote_sdms(reg_remote_sdms),
  _hss(hss_connection),
  _acr_factory(rfacr_factory),
  _max_expires(cfg_max_expires),
  _force_original_register_inclusion(force_original_register_inclusion),
  _reg_stats_tbls(reg_stats_tbls),
  _third_party_reg_stats_tbls(third_party_reg_stats_tbls),
  _fifc_service(fifc_service),
  _ifc_configuration(ifc_configuration),
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

  RegistrationUtils::init(_third_party_reg_stats_tbls, _force_original_register_inclusion);

  // Construct a Service-Route header pointing at the S-CSCF ready to be added
  // to REGISTER 200 OK response.
  pjsip_sip_uri* service_route_uri = NULL;

  if (stack_data.scscf_uri != NULL)
  {
    service_route_uri = (pjsip_sip_uri*)pjsip_uri_clone(stack_data.pool, stack_data.scscf_uri);
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
                                                    _next_hop_service,
                                                    _fifc_service,
                                                    _ifc_configuration);
  }

  // We're not interested in the message so create a next hop URI.
  pjsip_sip_uri* base_uri = helper->get_routing_uri(req, this);
  next_hop = helper->next_hop_uri(_next_hop_service,
                                  base_uri,
                                  pool);
  return NULL;
}

RegistrarSproutletTsx::RegistrarSproutletTsx(RegistrarSproutlet* registrar,
                                             const std::string& next_hop_service,
                                             FIFCService* fifc_service,
                                             IFCConfiguration ifc_configuration) :
  CompositeSproutletTsx(registrar, next_hop_service),
  _registrar(registrar),
  _scscf_uri(),
  _fifc_service(fifc_service),
  _ifc_configuration(ifc_configuration)
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

void RegistrarSproutletTsx::process_register_request(pjsip_msg *req)
{
  pjsip_status_code st_code = PJSIP_SC_OK;

  // Get the system time in seconds for calculating absolute expiry times.
  int now = time(NULL);
  int expiry = 0;

  // Loop through headers as early as possible so that we know the expiry time
  // and which registration statistics to update.
  // Loop through each contact header. If every registration is an emergency
  // registration and its expiry is 0 then reject with a 501.
  // If there are valid registration updates to make then attempt to write to
  // store, which also stops emergency registrations from being deregistered.
  int num_contacts = 0;
  int num_emergency_bindings = 0;
  int num_emergency_deregisters = 0;
  bool reject_with_400 = false;
  pjsip_contact_hdr* contact_hdr = (pjsip_contact_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_CONTACT, NULL);

  while (contact_hdr != NULL)
  {
    num_contacts++;
    pjsip_expires_hdr* expires = (pjsip_expires_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_EXPIRES, NULL);
    expiry = RegistrationUtils::expiry_for_binding(contact_hdr, expires, _registrar->_max_expires);

    if ((contact_hdr->star) && (expiry != 0))
    {
      // Wildcard contact, which can only be used if the expiry is 0
      TRC_ERROR("Attempted to deregister all bindings, but expiry value wasn't 0");
      reject_with_400 = true;
      break;
    }

    if (PJUtils::is_emergency_registration(contact_hdr))
    {
      num_emergency_bindings++;
      if (expiry == 0)
      {
        num_emergency_deregisters++;
      }
    }

    contact_hdr = (pjsip_contact_hdr*) pjsip_msg_find_hdr(req,
                                                          PJSIP_H_CONTACT,
                                                          contact_hdr->next);
  }

  // Get the URI from the To header and check it is a SIP or SIPS URI.
  pjsip_uri* uri = (pjsip_uri*)pjsip_uri_get_uri(PJSIP_MSG_TO_HDR(req)->uri);

  if ((!PJSIP_URI_SCHEME_IS_SIP(uri)) && (!PJSIP_URI_SCHEME_IS_TEL(uri)))
  {
    // Reject a non-SIP/TEL URI with 404 Not Found (RFC3261 isn't clear
    // whether 404 is the right status code - it says 404 should be used if
    // the AoR isn't valid for the domain in the RequestURI).
    TRC_ERROR("Rejecting register request using invalid URI scheme");

    SAS::Event event(trail(), SASEvent::REGISTER_FAILED_INVALIDURISCHEME, 0);
    SAS::report_event(event);

    pjsip_msg* rsp = create_response(req, PJSIP_SC_NOT_FOUND);
    send_response(rsp);
    free_msg(req);

    // Only update statistics if this is going to change the state of the
    // IRS (i.e. if the number of contact headers is non-zero)
    if (num_contacts > 0)
    {
      if (expiry == 0)
      {
        _registrar->_reg_stats_tbls->de_reg_tbl->increment_attempts();
        _registrar->_reg_stats_tbls->de_reg_tbl->increment_failures();
      }
      else
      // Invalid URI means this cannot be a re-register request, so if not
      // a de-register request, then treat as an initial register request.
      {
        _registrar->_reg_stats_tbls->init_reg_tbl->increment_attempts();
        _registrar->_reg_stats_tbls->init_reg_tbl->increment_failures();
      }
    }
    return;
  }

  // Allocate an ACR for this transaction and pass the request to it.  Node
  // role is always considered originating for REGISTER requests.
  ACR* acr = _registrar->_acr_factory->get_acr(trail(),
                                               ACR::CALLING_PARTY,
                                               ACR::NODE_ROLE_ORIGINATING);
  acr->rx_request(req);

  // Canonicalize the public ID from the URI in the To header.
  std::string public_id = PJUtils::public_id_from_uri(uri);
  TRC_DEBUG("Process REGISTER for public ID %s", public_id.c_str());

  // Get the call identifier and the cseq number from the respective headers.
  std::string cid = PJUtils::pj_str_to_string(&PJSIP_MSG_CID_HDR(req)->id);;

  // Query the HSS for the associated URIs.
  std::string private_id;
  std::string private_id_for_binding;
  bool success = get_private_id(req, private_id);
  if (!success)
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

  if (num_contacts == 0)
  {
    SAS::Event event(trail(), SASEvent::REGISTER_NO_CONTACTS, 0);
    event.add_var_param(public_id);
    SAS::report_event(event);
  }

  // Construct the S-CSCF URI for this transaction. Use the configured S-CSCF
  // URI as a starting point.
  pjsip_sip_uri* scscf_uri = (pjsip_sip_uri*)pjsip_uri_clone(get_pool(req), stack_data.scscf_uri);
  pjsip_sip_uri* routing_uri = get_routing_uri(req);
  if (routing_uri != NULL)
  {
    SCSCFUtils::get_scscf_uri(get_pool(req),
                              get_local_hostname(routing_uri),
                              get_local_hostname(scscf_uri),
                              scscf_uri);
  }

  _scscf_uri = PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR, (pjsip_uri*)scscf_uri);

  HSSConnection::irs_query irs_query;
  irs_query._public_id = public_id;
  irs_query._private_id = private_id;
  irs_query._req_type = HSSConnection::REG;
  irs_query._server_name = _scscf_uri;

  HSSConnection::irs_info irs_info;
  HTTPCode http_code = _registrar->_hss->update_registration_state(irs_query,
                                                                   irs_info,
                                                                   trail());

  st_code = determine_hss_sip_response(http_code, irs_info._regstate, "REGISTER");

  if (st_code != PJSIP_SC_OK)
  {
    pjsip_msg* rsp = create_response(req, st_code);
    send_response(rsp);
    free_msg(req);

    SAS::Event event(trail(), SASEvent::REGISTER_FAILED_INVALIDPUBPRIV, 0);
    event.add_var_param(public_id);
    event.add_var_param(private_id);
    SAS::report_event(event);

    acr->send();
    delete acr;

    if (num_contacts > 0)
    {
      if (expiry == 0)
      {
        _registrar->_reg_stats_tbls->de_reg_tbl->increment_attempts();
        _registrar->_reg_stats_tbls->de_reg_tbl->increment_failures();
      }
      else
      // Invalid public/private identity means this cannot be a re-register request,
      // so if not a de-register request, then treat as an initial register request.
      {
        _registrar->_reg_stats_tbls->init_reg_tbl->increment_attempts();
        _registrar->_reg_stats_tbls->init_reg_tbl->increment_failures();
      }
    }
    return;
  }

  // Get the default URI to use as a key in the binding store.
  std::string aor;
  success = irs_info._associated_uris.get_default_impu(aor,
                                                       num_emergency_bindings > 0);
  if (!success)
  {
    // Don't have a default IMPU so send an error response. We only hit this
    // if the subscriber is misconfigured at the HSS.
    reject_with_400 = true;
  }

  // Use the unbarred URIs for when we send NOTIFYs.
  std::vector<std::string> unbarred_uris = irs_info._associated_uris.get_unbarred_uris();
  TRC_DEBUG("REGISTER for public ID %s uses AOR %s", public_id.c_str(), aor.c_str());

  if (reject_with_400)
  {
    SAS::Event event(trail(), SASEvent::REGISTER_FAILED_INVALIDCONTACT, 0);
    event.add_var_param(public_id);
    SAS::report_event(event);

    pjsip_msg* rsp = create_response(req, PJSIP_SC_BAD_REQUEST);
    send_response(rsp);
    free_msg(req);

    acr->send();
    delete acr;

    if (num_contacts > 0)
    {
      _registrar->_reg_stats_tbls->de_reg_tbl->increment_attempts();
      _registrar->_reg_stats_tbls->de_reg_tbl->increment_failures();
    }

    return;
  }

  if ((num_emergency_deregisters > 0) && (num_emergency_deregisters == num_contacts))
  {
    TRC_ERROR("Rejecting register request as attempting to deregister an emergency registration");

    SAS::Event event(trail(), SASEvent::DEREGISTER_FAILED_EMERGENCY, 0);
    event.add_var_param(public_id);
    SAS::report_event(event);

    pjsip_msg* rsp = create_response(req, PJSIP_SC_NOT_IMPLEMENTED);
    send_response(rsp);
    free_msg(req);

    acr->send();
    delete acr;

    if (num_contacts > 0)
    {
      _registrar->_reg_stats_tbls->de_reg_tbl->increment_attempts();
      _registrar->_reg_stats_tbls->de_reg_tbl->increment_failures();
    }

    return;
  }

  // Write to the local store, checking the remote stores if there is no entry locally.
  bool all_bindings_expired;
  int max_expiry;

  // Figure out whether we think this is an intial registration, based on
  // what Homestead thought the previous regstate was.
  bool is_initial_registration = (irs_info._prev_regstate == RegDataXMLUtils::STATE_NOT_REGISTERED);
  bool no_existing_bindings_found = false;
  int initial_notify_cseq = 0;
  AoRPair* aor_pair = write_to_store(_registrar->_sdm,
                                     aor,
                                     &(irs_info._associated_uris),
                                     req,
                                     now,
                                     max_expiry,
                                     is_initial_registration,
                                     no_existing_bindings_found,
                                     NULL,
                                     _registrar->_remote_sdms,
                                     private_id_for_binding,
                                     all_bindings_expired,
                                     initial_notify_cseq);

  // Update our view of whether this was in fact an initial registration based
  // on whether we found any bindings. There are race conditions where
  // at the time that Homestead processed the request this looked like an
  // initial registration, but where another request has subsequently created
  // bindings. If we got it wrong in the call to write_to_store that's fine --
  // we'll just have been slightly less efficient.
  is_initial_registration = no_existing_bindings_found;

  if (all_bindings_expired)
  {
    TRC_DEBUG("All bindings have expired - triggering deregistration at the HSS");

    HSSConnection::irs_query irs_query;
    irs_query._public_id = aor;
    irs_query._req_type = HSSConnection::DEREG_USER;
    irs_query._server_name = _scscf_uri;

    HSSConnection::irs_info irs_info;

    _registrar->_hss->update_registration_state(irs_query,
                                                irs_info,
                                                trail());
  }

  if ((aor_pair != NULL) && (aor_pair->get_current() != NULL))
  {
    // Log the bindings.
    log_bindings(aor, aor_pair->get_current());

    // If we have any remote stores, try to store this in them too. We don't worry
    // about failures in this case.
    for (std::vector<SubscriberDataManager*>::iterator it = _registrar->_remote_sdms.begin();
         it != _registrar->_remote_sdms.end();
         ++it)
    {
      if ((*it)->has_servers())
      {
        int tmp_expiry = 0;
        bool ignored;
        int ignored_cseq;

        if (aor_pair->get_current()->_notify_cseq != initial_notify_cseq)
        {
          TRC_DEBUG("Correcting incremented CSeq %d to %d",
                    aor_pair->get_current()->_notify_cseq,
                    initial_notify_cseq);
          aor_pair->get_current()->_notify_cseq = initial_notify_cseq;
        }

        AoRPair* remote_aor_pair = write_to_store(*it,
                                                  aor,
                                                  &(irs_info._associated_uris),
                                                  req,
                                                  now,
                                                  tmp_expiry,
                                                  false,
                                                  ignored,
                                                  aor_pair,
                                                  {},
                                                  private_id_for_binding,
                                                  ignored,
                                                  ignored_cseq);
        delete remote_aor_pair;
      }
    }
  }
  else
  {
    // Failed to connect to the local store.  Reject the register with a 500
    // response.
    // LCOV_EXCL_START - the can't fail to connect to the store we use for UT
    st_code = PJSIP_SC_INTERNAL_SERVER_ERROR;

    SAS::Event event(trail(), SASEvent::REGISTER_FAILED_REGSTORE, 0);
    event.add_var_param(public_id);
    SAS::report_event(event);

    // LCOV_EXCL_STOP
  }

  if (num_contacts > 0)
  {
    if (expiry == 0)
    {
      _registrar->_reg_stats_tbls->de_reg_tbl->increment_attempts();
    }
    else if (is_initial_registration)
    {
      _registrar->_reg_stats_tbls->init_reg_tbl->increment_attempts();
    }
    else
    {
      _registrar->_reg_stats_tbls->re_reg_tbl->increment_attempts();
    }
  }

  // Build and send the reply.
  pjsip_msg* rsp = create_response(req, st_code);

  if (st_code != PJSIP_SC_OK)
  {
    // LCOV_EXCL_START - we only reject REGISTER if something goes wrong, and
    // we aren't covering any of those paths so we can't hit this either
    acr->tx_response(rsp);

    send_response(rsp);
    free_msg(req);

    SAS::Event event(trail(), SASEvent::REGISTER_FAILED, 0);
    event.add_var_param(public_id);
    std::string error_msg = "REGISTER failed with status code: " + std::to_string(st_code);
    event.add_var_param(error_msg);
    SAS::report_event(event);

    acr->send();
    delete acr;
    delete aor_pair;

    if (num_contacts > 0)
    {
      if (is_initial_registration)
      {
        _registrar->_reg_stats_tbls->init_reg_tbl->increment_failures();
      }
      else if (expiry == 0)
      {
        _registrar->_reg_stats_tbls->de_reg_tbl->increment_failures();
      }
      else
      {
        _registrar->_reg_stats_tbls->re_reg_tbl->increment_failures();
      }
    }

    return;
    // LCOV_EXCL_STOP
  }

  // Add supported and require headers for RFC5626.
  pjsip_generic_string_hdr* gen_hdr;
  gen_hdr = pjsip_generic_string_hdr_create(get_pool(rsp),
                                            &STR_SUPPORTED,
                                            &STR_OUTBOUND);
  if (gen_hdr == NULL)
  {
    // LCOV_EXCL_START - can't see how this could ever happen
    TRC_ERROR("Failed to add RFC 5626 headers");

    SAS::Event event(trail(), SASEvent::REGISTER_FAILED_5636, 0);
    event.add_var_param(public_id);
    SAS::report_event(event);

    rsp->line.status.code = PJSIP_SC_INTERNAL_SERVER_ERROR;

    acr->tx_response(rsp);

    send_response(rsp);
    free_msg(req);

    acr->send();
    delete acr;
    delete aor_pair;

    if (num_contacts > 0)
    {
      if (is_initial_registration)
      {
        _registrar->_reg_stats_tbls->init_reg_tbl->increment_failures();
      }
      else if (expiry == 0)
      {
        _registrar->_reg_stats_tbls->de_reg_tbl->increment_failures();
      }
      else
      {
        _registrar->_reg_stats_tbls->re_reg_tbl->increment_failures();
      }
    }

    return;
    // LCOV_EXCL_STOP
  }

  pjsip_msg_add_hdr(rsp, (pjsip_hdr*)gen_hdr);

  // Add contact headers for all active bindings.
  for (AoR::Bindings::const_iterator i = aor_pair->get_current()->bindings().begin();
       i != aor_pair->get_current()->bindings().end();
       ++i)
  {
    AoR::Binding* binding = i->second;
    if (binding->_expires > now)
    {
      // The binding hasn't expired.  Parse the Contact URI from the store,
      // making sure it is formatted as a name-address.
      pjsip_uri* uri = PJUtils::uri_from_string(binding->_uri, get_pool(rsp), PJ_TRUE);
      if (uri != NULL)
      {
        // Contact URI is well formed, so include this in the response.
        pjsip_contact_hdr* contact = pjsip_contact_hdr_create(get_pool(rsp));
        contact->star = 0;
        contact->uri = uri;
        contact->q1000 = binding->_priority;
        contact->expires = binding->_expires - now;
        pj_list_init(&contact->other_param);
        for (std::map<std::string, std::string>::iterator j = binding->_params.begin();
             j != binding->_params.end();
             ++j)
        {
          pjsip_param *new_param = PJ_POOL_ALLOC_T(get_pool(rsp), pjsip_param);
          pj_strdup2(get_pool(rsp), &new_param->name, j->first.c_str());
          pj_strdup2(get_pool(rsp), &new_param->value, j->second.c_str());
          pj_list_insert_before(&contact->other_param, new_param);
        }

        // Add a GRUU if the UE supports GRUUs and the contact header contains
        // a +sip.instance parameter.
        if (PJUtils::msg_supports_extension(req, "gruu"))
        {
          // The pub-gruu parameter on the Contact header is calculated
          // from the instance-id, to avoid unnecessary storage in
          // memcached.
          std::string gruu = binding->pub_gruu_quoted_string(get_pool(rsp));
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
        // Contact URI is malformed.  Log an error, but otherwise don't try and
        // fix it.
        // LCOV_EXCL_START hard to hit - needs bad data in the store
        TRC_WARNING("Badly formed contact URI %s for address of record %s",
                    binding->_uri.c_str(), aor.c_str());

        SAS::Event event(trail(), SASEvent::REGISTER_FAILED, 0);
        event.add_var_param(public_id);
        std::string error_msg = "Badly formed contact URI - " + binding->_uri;
        event.add_var_param(error_msg);
        SAS::report_event(event);
        // LCOV_EXCL_STOP
      }
    }
  }

  SAS::Event reg_Accepted(trail(), SASEvent::REGISTER_ACCEPTED, 0);
  SAS::report_event(reg_Accepted);

  if (num_contacts > 0)
  {
    if (expiry == 0)
    {
      _registrar->_reg_stats_tbls->de_reg_tbl->increment_successes();
    }
    else if (is_initial_registration)
    {
      _registrar->_reg_stats_tbls->init_reg_tbl->increment_successes();
    }
    else
    {
      _registrar->_reg_stats_tbls->re_reg_tbl->increment_successes();
    }
  }

  // Deal with path header related fields in the response.
  pjsip_routing_hdr* path_hdr = (pjsip_routing_hdr*)
                              pjsip_msg_find_hdr_by_name(req, &STR_PATH, NULL);
  if ((path_hdr != NULL) &&
      (!aor_pair->get_current()->bindings().empty()))
  {
    // We have bindings with path headers so we must require outbound.
    pjsip_require_hdr* require_hdr = pjsip_require_hdr_create(get_pool(rsp));
    require_hdr->count = 1;
    require_hdr->values[0] = STR_OUTBOUND;
    pjsip_msg_add_hdr(rsp, (pjsip_hdr*)require_hdr);
  }

  // Echo back any Path headers as per RFC 3327, section 5.3.  We take these
  // from the request as they may not exist in the bindings any more if the
  // bindings have expired.
  while (path_hdr)
  {
    pjsip_msg_add_hdr(rsp,
                      (pjsip_hdr*)pjsip_hdr_clone(get_pool(rsp), path_hdr));
    path_hdr = (pjsip_routing_hdr*)
                    pjsip_msg_find_hdr_by_name(req, &STR_PATH, path_hdr->next);
  }

  // Add the Service-Route header. We may modify this so need to do a full clone
  // of the header.  Annoyingly this overwrites the custom name we set during
  // module initialization, so reset it.
  pjsip_routing_hdr* sr_hdr = (pjsip_routing_hdr*)
    pjsip_hdr_clone(get_pool(rsp), _registrar->_service_route);
  sr_hdr->name = STR_SERVICE_ROUTE;
  sr_hdr->sname = pj_str((char*)"");

  // Replace the local hostname part of the Service route URI with the local
  // hostname part of the URI that routed to this sproutlet.
  pjsip_sip_uri* sr_uri = (pjsip_sip_uri*)sr_hdr->name_addr.uri;
  if (routing_uri != NULL)
  {
    SCSCFUtils::get_scscf_uri(get_pool(rsp),
                              get_local_hostname(routing_uri),
                              get_local_hostname(sr_uri),
                              sr_uri);
  }

  pjsip_msg_insert_first_hdr(rsp, (pjsip_hdr*)sr_hdr);

  // Log any URIs that have been left out of the P-Associated-URI because they
  // are barred.
  std::vector<std::string> barred_uris = irs_info._associated_uris.get_barred_uris();
  if (!barred_uris.empty())
  {
    std::stringstream ss;
    std::copy(barred_uris.begin(), barred_uris.end(), std::ostream_iterator<std::string>(ss, ","));
    std::string list = ss.str();
    if (!list.empty())
    {
      // Strip the trailing comma.
      list = list.substr(0, list.length() - 1);
    }

    SAS::Event event(trail(), SASEvent::OMIT_BARRED_ID_FROM_P_ASSOC_URI, 0);
    event.add_var_param(list);
    SAS::report_event(event);
  }

  // Add P-Associated-URI headers for all of the associated URIs that are real
  // URIs, ignoring wildcard URIs and logging any URIs that aren't wildcards
  // but are still unparseable as URIs.
  if (!unbarred_uris.empty())
  {
    for (std::vector<std::string>::iterator it = unbarred_uris.begin();
         it != unbarred_uris.end();
         it++)
    {
      if (!WildcardUtils::is_wildcard_uri(*it))
      {
        pjsip_uri* this_uri = PJUtils::uri_from_string(*it, get_pool(rsp));
        if (this_uri != NULL)
        {
          pjsip_routing_hdr* pau =
                           identity_hdr_create(get_pool(rsp), STR_P_ASSOCIATED_URI);
          pau->name_addr.uri = this_uri;
          pjsip_msg_add_hdr(rsp, (pjsip_hdr*)pau);
        }
        else
        {
          TRC_DEBUG("Bad associated URI %s", it->c_str());
          SAS::Event event(trail(), SASEvent::HTTP_HOMESTEAD_BAD_IDENTITY, 0);
          event.add_var_param(*it);
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
      else
      {
        TRC_DEBUG("Bad associated URI %s", aor.c_str());
        SAS::Event event(trail(), SASEvent::HTTP_HOMESTEAD_BAD_IDENTITY, 1);
        event.add_var_param(aor);
        SAS::report_event(event);
      }
    }
  }

  // Add a PCFA header.
  PJUtils::add_pcfa_header(rsp, get_pool(rsp), irs_info._ccfs, irs_info._ecfs, true);

  // Pass the response to the ACR.
  acr->tx_response(rsp);

  // Clone the response so that we can use it to inform ASes of the 200 OK response we send.
  pjsip_msg* clone_rsp = clone_msg(rsp);
  send_response(rsp);

  // Send the ACR and delete it.
  acr->send();
  delete acr;

  // TODO in sto397: we should do third-party registration once per
  // service profile (i.e. once per iFC, using an arbitrary public
  // ID). hss->get_subscription_data should be enhanced to provide an
  // appropriate data structure (representing the ServiceProfile
  // nodes) and we should loop through that. Don't send any register that
  // contained emergency registrations to the application servers.

  if (num_emergency_bindings == 0)
  {
    // If the public ID is unbarred, we use that for third party registers. If
    // it is barred, we use the default URI.
    std::string as_reg_id = public_id;
    if (irs_info._associated_uris.is_impu_barred(public_id))
    {
      as_reg_id = aor;
    }

    RegistrationUtils::register_with_application_servers(irs_info._service_profiles[public_id],
                                                         _registrar->_fifc_service,
                                                         _registrar->_ifc_configuration,
                                                         _registrar->_sdm,
                                                         _registrar->_remote_sdms,
                                                         _registrar->_hss,
                                                         req,
                                                         clone_rsp,
                                                         expiry,
                                                         is_initial_registration,
                                                         as_reg_id,
                                                         trail());
  }

  // Now we can free the messages.
  free_msg(clone_rsp);
  free_msg(req);

  delete aor_pair;
}

/// Updates an existing set of binding data (typically just retrieved from the
/// AoR store), with updated binding information from a REGISTER request.
void RegistrarSproutletTsx::update_bindings_from_req(AoRPair* aor_pair,      ///<AoR pair containing any existing bindings
                                                     pjsip_msg* req,         ///<REGISTER request containing new binding information
                                                     int now,                ///<the time now.
                                                     std::string private_id, ///<private ID that the request refers to
                                                     int& changed_bindings,  ///<[out] the number of bindings in the request
                                                     int& max_expiry)        ///<[out] the max_expiry time of bindings in the request
{
  // Find the expire headers in the message.
  pjsip_expires_hdr* expires = (pjsip_expires_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_EXPIRES, NULL);

  // Get the call identifier and the cseq number from the respective headers.
  std::string cid = PJUtils::pj_str_to_string(&PJSIP_MSG_CID_HDR(req)->id);
  int cseq = ((pjsip_cseq_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_CSEQ, NULL))->cseq;

  changed_bindings = 0;
  int expiry;
  max_expiry = 0;

  // Now loop through all the contacts.  If there are multiple contacts in
  // the contact header in the SIP message, pjsip parses them to separate
  // contact header structures.
  pjsip_contact_hdr* contact = (pjsip_contact_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_CONTACT, NULL);

  while (contact != NULL)
  {
    changed_bindings++;
    expiry = RegistrationUtils::expiry_for_binding(contact, expires, _registrar->_max_expires);
    max_expiry = (expiry > max_expiry) ? expiry : max_expiry;

    if (contact->star)
    {
      // Wildcard contact, which can only be used to clear all bindings for
      // the AoR (and only if the expiry is 0). It won't clear any emergency
      // bindings
      TRC_DEBUG("Clearing all non-emergency bindings");
      aor_pair->get_current()->clear(false);
      break;
    }

    pjsip_uri* uri = (contact->uri != NULL) ?
                         (pjsip_uri*)pjsip_uri_get_uri(contact->uri) :
                         NULL;

    if ((uri != NULL) &&
        (PJSIP_URI_SCHEME_IS_SIP(uri)))
    {
      // The binding identifier is based on the +sip.instance parameter if
      // it is present.  If not the contact URI is used instead.
      std::string contact_uri = PJUtils::uri_to_string(PJSIP_URI_IN_CONTACT_HDR, uri);
      std::string binding_id = get_binding_id(contact);

      if (binding_id == "")
      {
        binding_id = contact_uri;
      }

      TRC_DEBUG("Binding identifier for contact = %s", binding_id.c_str());

      // Find the appropriate binding in the bindings list for this AoR.
      AoR::Binding* binding = aor_pair->get_current()->get_binding(binding_id);

      if ((cid != binding->_cid) ||
          (cseq > binding->_cseq))
      {
        // Either this is a new binding, has come from a restarted device, or
        // is an update to an existing binding.
        binding->_uri = contact_uri;

        TRC_DEBUG("Updating binding %s for contact %s",
                  binding_id.c_str(), contact_uri.c_str());

        // TODO Examine Via header to see if we're the first hop
        // TODO Only if we're not the first hop, check that the top path header has "ob" parameter

        // Get the Path headers, if present.  RFC 3327 allows us the option of
        // rejecting a request with a Path header if there is no corresponding
        // "path" entry in the Supported header but we don't do so on the assumption
        // that the edge proxy knows what it's doing.
        //
        // We store the full path header in the _path_headers field. For
        // backwards compatibility, we also store the URI part of the path
        // header in the _path_uris field.
        binding->_path_headers.clear();
        binding->_path_uris.clear();
        pjsip_routing_hdr* path_hdr = (pjsip_routing_hdr*)
                            pjsip_msg_find_hdr_by_name(req, &STR_PATH, NULL);

        while (path_hdr)
        {
          std::string path = PJUtils::get_header_value((pjsip_hdr*)path_hdr);
          std::string path_uri = PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                                        path_hdr->name_addr.uri);
          TRC_DEBUG("Path header %s", path.c_str());

          // Extract all the paths from this header.
          binding->_path_headers.push_back(path);
          binding->_path_uris.push_back(path_uri);

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
        binding->_emergency_registration = PJUtils::is_emergency_registration(contact);

        // If the new expiry is less than the current expiry, and it's an emergency registration,
        // don't update the expiry time
        int new_expiry = now + expiry;

        if ((binding->_expires >= new_expiry) && (binding->_emergency_registration))
        {
          TRC_DEBUG("Don't reduce expiry time for an emergency registration");
        }
        else
        {
          TRC_DEBUG("Setting new expiry for %s to %d", binding_id.c_str(), new_expiry);
          binding->_expires = new_expiry;
        }
      }
      else
      {
        TRC_DEBUG("Skipping binding %s for contact %s - (CSeq: %d v %d, CID: %s == %s)",
                  binding_id.c_str(), contact_uri.c_str(),
                  cseq, binding->_cseq,
                  cid.c_str(), binding->_cid.c_str());
      }
    }
    contact = (pjsip_contact_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_CONTACT, contact->next);
  }
}

/// Write to the registration store. If we can't find the AoR pair in the
/// primary SDM, we will either use the backup_aor or we will try and look up
/// the AoR pair in the backup SDMs. Therefore either the backup_aor should be
/// NULL, or backup_sdms should be empty.
AoRPair* RegistrarSproutletTsx::write_to_store(
                   SubscriberDataManager* primary_sdm,         ///<store to write to
                   std::string aor,                            ///<address of record to write to
                   AssociatedURIs* associated_uris,
                                                               ///<Associated IMPUs in Implicit Registration Set
                   pjsip_msg* req,                             ///<received request to read headers from
                   int now,                                    ///<time now
                   int& max_expiry,                            ///<[out] longest expiry time
                   bool is_initial_registration,               ///<Does the caller believe that this is an initial registration?
                   bool& out_no_existing_bindings_found,       ///<[out] true if no existing bindings were found in the store
                   AoRPair* backup_aor,                        ///<backup data if no entry in store
                   std::vector<SubscriberDataManager*> backup_sdms,
                                                               ///<backup stores to read from if no entry in store and no backup data
                   std::string private_id,                     ///<private id that the binding was registered with
                   bool& out_all_bindings_expired,
                   int& initial_notify_cseq)
{

  // The registration service uses optimistic locking to avoid concurrent
  // updates to the same AoR conflicting.  This means we have to loop
  // reading, updating and writing the AoR until the write is successful.
  AoRPair* aor_pair = NULL;
  bool all_bindings_expired = false;
  Store::Status set_rc;

  out_no_existing_bindings_found = true;

  do // While the operations fail due to data contention
  {
    if (is_initial_registration)
    {
      // We think this is an initial registration so there won't be any
      // bindings already in the store unless we've hit a race condition.
      // Optimize for the mainline:
      // -- don't try and GET bindings from the store (without this
      // optimization we'll look in the local store and not finding any
      // bindings there we'll then look in each remote store too -- that's
      // expensive).
      // -- instead just create a blank aor_pair.  We'll try to add the new
      // bindings to this and then, when we try to write it to the store it will
      // get processed as an ADD because the AoRPair will have a CAS of zero.
      // -- if we're wrong and there are actually bindings already in the store
      // (possible in race conditions) then the ADD will fail and the write
      // will return a DATA_CONTENTION error.  In that case we'll loop back and
      // do all this processing again.  Set is_initial_registration to false now
      // so that on second / subsequent attempts we always do the full GET and
      // update processing.
      TRC_DEBUG("This is an initial registration -- attempt to ADD the data");
      aor_pair = new AoRPair(aor);
      is_initial_registration = false;
    }
    else
    {
      bool store_access_ok = RegistrationUtils::get_aor_data(&aor_pair,
                                                             aor,
                                                             primary_sdm,
                                                             backup_sdms,
                                                             backup_aor,
                                                             trail());
      if (!store_access_ok)
      {
        // This means that there was an error accessing the store. We don't hit
        // this if we just fail to find any bindings. This is already SAS logged
        // at a lower level, so just drop a debug log.
        TRC_DEBUG("Store access error: Failed to get AoR binding for %s", aor.c_str());
        break;
      }
      out_no_existing_bindings_found = out_no_existing_bindings_found && aor_pair->get_current()->bindings().empty();
    }

    int changed_bindings = 0;
    update_bindings_from_req(aor_pair,
                             req,
                             now,
                             private_id,
                             changed_bindings,
                             max_expiry);

    // Set the S-CSCF URI on the AoR.
    AoR* aor_data = aor_pair->get_current();
    initial_notify_cseq = aor_data->_notify_cseq;
    aor_data->_scscf_uri = _scscf_uri;

    if (changed_bindings > 0)
    {
      aor_pair->get_current()->_associated_uris = *associated_uris;
      set_rc = primary_sdm->set_aor_data(aor,
                                         SubscriberDataManager::EventTrigger::USER,
                                         aor_pair,
                                         trail(),
                                         all_bindings_expired);
    }
    else
    {
      // No bindings changed (because we had no contact headers).  However, we
      // may need to deregister the subscriber (because we will have registered
      // the sub in the calling routine), so set all_bindings_expired based on
      // whether we found any bindings to report.
      set_rc = Store::OK;
      all_bindings_expired = aor_pair->get_current()->bindings().empty();
    }

    if (set_rc != Store::OK)
    {
      delete aor_pair; aor_pair = NULL;
    }
  }
  while (set_rc == Store::DATA_CONTENTION);

  out_all_bindings_expired = all_bindings_expired;

  return aor_pair;
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
      TRC_WARNING("Unsupported scheme \"%.*s\" in Authorization header when determining private ID - ignoring",
                  auth_hdr->scheme.slen, auth_hdr->scheme.ptr);
      // LCOV_EXCL_STOP
    }
  }
  return success;
}

std::string RegistrarSproutletTsx::get_binding_id(pjsip_contact_hdr *contact)
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
    // The contact a +sip.instance parameters, so form a suitable binding
    // string.
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

void RegistrarSproutletTsx::log_bindings(const std::string& aor_name,
                                         AoR* aor_data)
{
  TRC_DEBUG("Bindings for %s, timer ID %s", aor_name.c_str(), aor_data->_timer_id.c_str());
  for (AoR::Bindings::const_iterator i = aor_data->bindings().begin();
       i != aor_data->bindings().end();
       ++i)
  {
    AoR::Binding* binding = i->second;
    TRC_DEBUG("  %s URI=%s expires=%d q=%d from=%s cseq=%d private_id=%s emergency_registration=%s",
              i->first.c_str(),
              binding->_uri.c_str(),
              binding->_expires, binding->_priority,
              binding->_cid.c_str(), binding->_cseq,
              binding->_private_id.c_str(),
              (binding->_emergency_registration ? "true" : "false"));
  }
}

