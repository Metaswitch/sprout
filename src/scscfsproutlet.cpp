/**
 * @file scscfsproutlet.cpp S-CSCF Sproutlet classes, implementing S-CSCF
 *                          specific SIP proxy functions.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "log.h"
#include "sprout_pd_definitions.h"
#include "sproutsasevent.h"
#include "constants.h"
#include "custom_headers.h"
#include "stack.h"
#include "contact_filtering.h"
#include "registration_utils.h"
#include "scscfsproutlet.h"
#include "uri_classifier.h"
#include "wildcard_utils.h"
#include "associated_uris.h"
#include "scscf_utils.h"

// Constant indicating there is no served user for a request.
const char* NO_SERVED_USER = "";

/// SCSCFSproutlet constructor.
SCSCFSproutlet::SCSCFSproutlet(const std::string& name,
                               const std::string& scscf_name,
                               const std::string& scscf_cluster_uri,
                               const std::string& scscf_node_uri,
                               const std::string& icscf_uri,
                               const std::string& bgcf_uri,
                               int port,
                               const std::string& uri,
                               const std::string& network_function,
                               const std::string& next_hop_service,
                               SubscriberDataManager* sdm,
                               std::vector<SubscriberDataManager*> remote_sdms,
                               HSSConnection* hss,
                               EnumService* enum_service,
                               ACRFactory* acr_factory,
                               SNMP::SuccessFailCountByRequestTypeTable* incoming_sip_transactions_tbl,
                               SNMP::SuccessFailCountByRequestTypeTable* outgoing_sip_transactions_tbl,
                               bool override_npdi,
                               FIFCService* fifcservice,
                               IFCConfiguration ifc_configuration,
                               int session_continued_timeout_ms,
                               int session_terminated_timeout_ms,
                               AsCommunicationTracker* sess_term_as_tracker,
                               AsCommunicationTracker* sess_cont_as_tracker) :
  Sproutlet(name,
            port,
            uri,
            "",
            {},
            incoming_sip_transactions_tbl,
            outgoing_sip_transactions_tbl,
            network_function),
  _scscf_name(scscf_name),
  _scscf_cluster_uri(NULL),
  _scscf_node_uri(NULL),
  _icscf_uri(NULL),
  _bgcf_uri(NULL),
  _next_hop_service(next_hop_service),
  _sdm(sdm),
  _remote_sdms(remote_sdms),
  _hss(hss),
  _enum_service(enum_service),
  _acr_factory(acr_factory),
  _override_npdi(override_npdi),
  _fifcservice(fifcservice),
  _ifc_configuration(ifc_configuration),
  _session_continued_timeout_ms(session_continued_timeout_ms),
  _session_terminated_timeout_ms(session_terminated_timeout_ms),
  _scscf_cluster_uri_str(scscf_cluster_uri),
  _scscf_node_uri_str(scscf_node_uri),
  _icscf_uri_str(icscf_uri),
  _bgcf_uri_str(bgcf_uri),
  _sess_term_as_tracker(sess_term_as_tracker),
  _sess_cont_as_tracker(sess_cont_as_tracker)
{
  _routed_by_preloaded_route_tbl = SNMP::CounterTable::create("scscf_routed_by_preloaded_route",
                                                              "1.2.826.0.1.1578918.9.3.26");
  _invites_cancelled_before_1xx_tbl = SNMP::CounterTable::create("invites_cancelled_before_1xx",
                                                                 "1.2.826.0.1.1578918.9.3.32");
  _invites_cancelled_after_1xx_tbl = SNMP::CounterTable::create("invites_cancelled_after_1xx",
                                                                "1.2.826.0.1.1578918.9.3.33");
  _audio_session_setup_time_tbl = SNMP::EventAccumulatorTable::create("scscf_audio_session_setup_time",
                                                                      "1.2.826.0.1.1578918.9.3.34");
  _video_session_setup_time_tbl = SNMP::EventAccumulatorTable::create("scscf_video_session_setup_time",
                                                                      "1.2.826.0.1.1578918.9.3.35");
  _forked_invite_tbl = SNMP::CounterTable::create("scscf_forked_invites",
                                                  "1.2.826.0.1.1578918.9.3.38");
  _barred_calls_tbl = SNMP::CounterTable::create("scscf_barred_calls",
                                                 "1.2.826.0.1.1578918.9.3.42");
}


/// SCSCFSproutlet destructor.
SCSCFSproutlet::~SCSCFSproutlet()
{
  delete _as_chain_table;
  delete _routed_by_preloaded_route_tbl;
  delete _invites_cancelled_before_1xx_tbl;
  delete _invites_cancelled_after_1xx_tbl;
  delete _forked_invite_tbl;
  delete _barred_calls_tbl;
  delete _audio_session_setup_time_tbl;
  delete _video_session_setup_time_tbl;
}

bool SCSCFSproutlet::init()
{
  TRC_DEBUG("Creating S-CSCF Sproutlet");
  TRC_DEBUG("  S-CSCF cluster URI = %s", _scscf_cluster_uri_str.c_str());
  TRC_DEBUG("  S-CSCF node URI    = %s", _scscf_node_uri_str.c_str());
  TRC_DEBUG("  I-CSCF URI         = %s", _icscf_uri_str.c_str());
  TRC_DEBUG("  BGCF URI           = %s", _bgcf_uri_str.c_str());

  bool init_success = true;

  // Convert the routing URIs to a form suitable for PJSIP, so we're
  // not continually converting from strings.
  _scscf_cluster_uri = PJUtils::uri_from_string(_scscf_cluster_uri_str, stack_data.pool, false);

  if (_scscf_cluster_uri == NULL)
  {
    // LCOV_EXCL_START - Don't test pjsip URI failures in the S-CSCF UTs
    TRC_ERROR("Invalid S-CSCF cluster %s", _scscf_cluster_uri_str.c_str());
    init_success = false;
    // LCOV_EXCL_STOP
  }

  _scscf_node_uri = PJUtils::uri_from_string(_scscf_node_uri_str, stack_data.pool, false);

  if (_scscf_node_uri == NULL)
  {
    // LCOV_EXCL_START - Don't test pjsip URI failures in the S-CSCF UTs
    TRC_ERROR("Invalid S-CSCF node URI %s", _scscf_node_uri_str.c_str());
    init_success = false;
    // LCOV_EXCL_STOP
  }

  _bgcf_uri = PJUtils::uri_from_string(_bgcf_uri_str, stack_data.pool, false);

  if (_bgcf_uri == NULL)
  {
    // LCOV_EXCL_START - Don't test pjsip URI failures in the S-CSCF UTs
    TRC_ERROR("Invalid BGCF URI %s", _bgcf_uri_str.c_str());
    init_success = false;
    // LCOV_EXCL_STOP
  }

  if (_icscf_uri_str != "")
  {
    _icscf_uri = PJUtils::uri_from_string(_icscf_uri_str, stack_data.pool, false);

    if (_icscf_uri == NULL)
    {
      // LCOV_EXCL_START - Don't test pjsip URI failures in the S-CSCF UTs
      TRC_ERROR("Invalid I-CSCF URI %s", _icscf_uri_str.c_str());
      init_success = false;
      // LCOV_EXCL_STOP
    }
  }

  // Create an AS Chain table for maintaining the mapping from ODI tokens to
  // AS chains (and links in those chains).
  _as_chain_table = new AsChainTable;

  return init_success;
}

/// Creates a SCSCFSproutletTsx instance for performing S-CSCF service processing
/// on a request.
SproutletTsx* SCSCFSproutlet::get_tsx(SproutletHelper* helper,
                                      const std::string& alias,
                                      pjsip_msg* req,
                                      pjsip_sip_uri*& next_hop,
                                      pj_pool_t* pool,
                                      SAS::TrailId trail)
{
  pjsip_method_e req_type = req->line.req.method.id;
  return (SproutletTsx*)new SCSCFSproutletTsx(this, _next_hop_service, req_type);
}


/// Returns the service name of the entire S-CSCF.
const std::string SCSCFSproutlet::scscf_service_name() const
{
  return _scscf_name;
}


/// Returns the configured S-CSCF cluster URI for this system.
const pjsip_uri* SCSCFSproutlet::scscf_cluster_uri() const
{
  return _scscf_cluster_uri;
}


/// Returns the configured S-CSCF node URI for this system.
const pjsip_uri* SCSCFSproutlet::scscf_node_uri() const
{
  return _scscf_node_uri;
}


/// Returns the configured I-CSCF URI for this system.
const pjsip_uri* SCSCFSproutlet::icscf_uri() const
{
  return _icscf_uri;
}


/// Returns the configured BGCF URI for this system.
const pjsip_uri* SCSCFSproutlet::bgcf_uri() const
{
  return _bgcf_uri;
}


/// Returns the AS chain table object used to manage AS chains and the
/// associated ODI tokens.
AsChainTable* SCSCFSproutlet::as_chain_table() const
{
  return _as_chain_table;
}

FIFCService* SCSCFSproutlet::fifcservice() const
{
  return _fifcservice;
}

IFCConfiguration SCSCFSproutlet::ifc_configuration() const
{
  return _ifc_configuration;
}

/// Gets all bindings for the specified Address of Record from the local or
/// remote registration stores.
void SCSCFSproutlet::get_bindings(const std::string& aor,
                                  AoRPair** aor_pair,
                                  SAS::TrailId trail)
{
  // Look up the target in the registration data store.
  TRC_INFO("Look up targets in registration store: %s", aor.c_str());
  *aor_pair = _sdm->get_aor_data(aor, trail);

  // If we didn't get bindings from the local store and we have any remote
  // stores, try them.
  if ((*aor_pair == NULL) ||
      (!(*aor_pair)->current_contains_bindings()))
  {
    // scan-build currently detects this loop as double freeing memory, as it
    // doesn't recognise that the value of aor_pair changes each loop iteration.
    // Excluding from analysis while this bug is present
    // (https://bugs.llvm.org/show_bug.cgi?id=18222).
    #ifndef __clang_analyzer__
    std::vector<SubscriberDataManager*>::iterator it = _remote_sdms.begin();

    while ((it != _remote_sdms.end()) &&
           ((*aor_pair == NULL) || !(*aor_pair)->current_contains_bindings()))
    {
      delete *aor_pair;

      if ((*it)->has_servers())
      {
        *aor_pair = (*it)->get_aor_data(aor, trail);
      }

      ++it;
    }
    #endif
  }

  // TODO - Log bindings to SAS
}


/// Removes the specified binding for the specified Address of Record from
/// the local or remote registration stores.
void SCSCFSproutlet::remove_binding(const std::string& aor,
                                    const std::string& binding_id,
                                    SAS::TrailId trail)
{
  RegistrationUtils::remove_bindings(_sdm,
                                     _remote_sdms,
                                     _hss,
                                     _fifcservice,
                                     _ifc_configuration,
                                     aor,
                                     binding_id,
                                     HSSConnection::DEREG_TIMEOUT,
                                     SubscriberDataManager::EventTrigger::TIMEOUT,
                                     trail);
}


/// Read data from the HSS and store in member fields for sproutlet.
long SCSCFSproutletTsx::read_hss_data(const HSSConnection::irs_query& irs_query,
                                      HSSConnection::irs_info& irs_info,
                                      SAS::TrailId trail)
{
  long http_code = _scscf->_hss->update_registration_state(irs_query,
                                                           irs_info,
                                                           trail);

  if (http_code == HTTP_OK)
  {
    _ifcs = irs_info._service_profiles[irs_query._public_id];

    // Get the default URI. This should always succeed.
    irs_info._associated_uris.get_default_impu(_default_uri, true);

    // We may want to route to bindings that are barred (in case of an
    // emergency), so get all the URIs.
    _registered = (irs_info._regstate == RegDataXMLUtils::STATE_REGISTERED);
    _barred = irs_info._associated_uris.is_impu_barred(irs_query._public_id);
  }

  return http_code;
}


/// Attempt ENUM lookup if appropriate.
void SCSCFSproutlet::translate_request_uri(pjsip_msg* req,
                                           pj_pool_t* pool,
                                           SAS::TrailId trail)
{
  return PJUtils::translate_request_uri(req,
                                        pool,
                                        _enum_service,
                                        should_override_npdi(),
                                        trail);
}


/// Get an ACR instance from the factory.
/// @param trail                SAS trail identifier to use for the ACR.
/// @param initiator            The initiator of the SIP transaction (calling
///                             or called party).
ACR* SCSCFSproutlet::get_acr(SAS::TrailId trail,
                             ACR::Initiator initiator,
                             ACR::NodeRole role)
{
  return _acr_factory->get_acr(trail, initiator, role);
}


void SCSCFSproutlet::track_app_serv_comm_failure(const std::string& uri,
                                                 const std::string& reason,
                                                 DefaultHandling default_handling)
{
  AsCommunicationTracker* as_tracker = (default_handling == SESSION_CONTINUED) ?
                                       _sess_cont_as_tracker :
                                       _sess_term_as_tracker;
  if (as_tracker != NULL)
  {
    as_tracker->on_failure(uri, reason);
  }
}


void SCSCFSproutlet::track_app_serv_comm_success(const std::string& uri,
                                                 DefaultHandling default_handling)
{
  AsCommunicationTracker* as_tracker = (default_handling == SESSION_CONTINUED) ?
                                       _sess_cont_as_tracker :
                                       _sess_term_as_tracker;
  if (as_tracker != NULL)
  {
    as_tracker->on_success(uri);
  }
}

void SCSCFSproutlet::track_session_setup_time(uint64_t tsx_start_time_usec,
                                              bool video_call)
{
  // Calculate how long it has taken to setup the session.
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
  uint64_t ringing_usec = ((uint64_t)ts.tv_sec * 1000000) + (ts.tv_nsec / 1000) - tsx_start_time_usec;

  if (video_call)
  {
    _video_session_setup_time_tbl->accumulate(ringing_usec);
  }
  else
  {
    _audio_session_setup_time_tbl->accumulate(ringing_usec);
  }
}

SCSCFSproutletTsx::SCSCFSproutletTsx(SCSCFSproutlet* scscf,
                                     const std::string& next_hop_service,
                                     pjsip_method_e req_type) :
  CompositeSproutletTsx(scscf, next_hop_service),
  _scscf(scscf),
  _cancelled(false),
  _session_case(NULL),
  _as_chain_link(),
  _hss_data_cached(false),
  _registered(false),
  _barred(false),
  _default_uri(""),
  _ifcs(),
  _in_dialog_acr(NULL),
  _failed_ood_acr(NULL),
  _target_aor(),
  _target_bindings(),
  _liveness_timer(0),
  _record_routed(false),
  _req_type(req_type),
  _seen_1xx(false),
  _record_session_setup_time(false),
  _tsx_start_time_usec(0),
  _video_call(false),
  _impi(),
  _auto_reg(false),
  _wildcard(""),
  _se_helper(stack_data.default_session_expires),
  _base_req(nullptr),
  _scscf_uri()
{
  TRC_DEBUG("S-CSCF Transaction (%p) created", this);
}


SCSCFSproutletTsx::~SCSCFSproutletTsx()
{
  TRC_DEBUG("S-CSCF Transaction (%p) destroyed", this);
  if (!_as_chain_link.is_set())
  {
    ACR* acr = get_acr();
    if (acr)
    {
      acr->send();
    }
  }

  if (_as_chain_link.is_set())
  {
    _as_chain_link.release();
  }

  if (_liveness_timer != 0)
  {
    cancel_timer(_liveness_timer); //LCOV_EXCL_LINE - can't be hit in production
  }

  // If the ACR was stored locally, destroy it now.
  if (_failed_ood_acr)
  {
    delete _failed_ood_acr;
  }
  if (_in_dialog_acr)
  {
    delete _in_dialog_acr;
  }

  _target_bindings.clear();

  if (_base_req != nullptr)
  {
    free_msg(_base_req);
  }
}


void SCSCFSproutletTsx::on_rx_initial_request(pjsip_msg* req)
{
  TRC_INFO("S-CSCF received initial request");

  pjsip_status_code status_code = PJSIP_SC_OK;

  // Work out if we should be auto-registering the user based on this
  // request and if we are, also work out the IMPI to register them with.
  const pjsip_route_hdr* top_route = route_hdr();
  if (top_route != NULL)
  {
    pjsip_sip_uri* uri = (pjsip_sip_uri*)top_route->name_addr.uri;

    if ((pjsip_param_find(&uri->other_param, &STR_ORIG) != NULL) &&
        (pjsip_param_find(&uri->other_param, &STR_AUTO_REG) != NULL))
    {
      _auto_reg = true;

      pjsip_proxy_authorization_hdr* proxy_auth_hdr =
        (pjsip_proxy_authorization_hdr*)pjsip_msg_find_hdr(req,
                                                           PJSIP_H_PROXY_AUTHORIZATION,
                                                           NULL);
      _impi = PJUtils::extract_username(proxy_auth_hdr,
                                        PJUtils::orig_served_user(req,
                                                                  get_pool(req),
                                                                  trail()));
    }
  }

  // Pull out the P-Profile-Key header if it exists. We must do this before
  // sending any requests to the HSS.
  pjsip_routing_hdr* ppk_hdr = (pjsip_routing_hdr*)pjsip_msg_find_hdr_by_name(
                                                   req,
                                                   &STR_P_PROFILE_KEY,
                                                   NULL);

  if (ppk_hdr != NULL)
  {
    std::string escaped_wildcard = PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                                          (pjsip_uri*)(&ppk_hdr->name_addr));
    _wildcard = PJUtils::unescape_string_for_uri(std::string(escaped_wildcard),
                                                 get_pool(req));

    // If the URI is surrounded with angle brackets remove them.
    if ((boost::starts_with(_wildcard, "<")) &&
        (boost::ends_with(_wildcard, ">")))
    {
      _wildcard = _wildcard.substr(1, _wildcard.size() - 2);
    }
  }

  // Determine the session case and the served user.  This will link to
  // an AsChain object (creating it if necessary), if we need to provide
  // services.
  // It will also set the S-CSCF URI
  status_code = determine_served_user(req);

  // Pass the received request to the ACR.
  // @TODO - request timestamp???
  ACR* acr = get_acr();
  if (acr)
  {
    acr->lock();
    acr->rx_request(req);
    acr->unlock();
  }

  if (status_code != PJSIP_SC_OK)
  {
    // Failed to determine the served user for a request we should provide
    // services on, so reject the request.
    TRC_INFO("Failed to determine served user for request, reject with %d status code",
             status_code);
    pjsip_msg* rsp = create_response(req, status_code);
    send_response(rsp);
    free_msg(req);
    return;
  }
  else
  {
    // Check if the served user is barred. If it is barred, we reject the request
    // unless it is a terminating request to a binding that is using an
    // emergency registration in which case we let it through.
    if (_barred)
    {
      bool emergency = false;

      if (_session_case->is_terminating())
      {
        // The bindings are keyed off the default IMPU.
        std::string aor = _default_uri;
        AoRPair* aor_pair = NULL;
        _scscf->get_bindings(aor, &aor_pair, trail());

        if ((aor_pair != NULL) &&
            (aor_pair->get_current() != NULL))
        {
          if (!aor_pair->get_current()->bindings().empty())
          {
            const AoR::Bindings bindings = aor_pair->get_current()->bindings();

            // Loop over the bindings. If any binding has an emergency registration,
            // let the request through. When routing to UEs, we will make sure we
            // only route the request to the bindings that have an emergency registration.
            for (AoR::Bindings::const_iterator binding = bindings.begin();
                 binding != bindings.end();
                 ++binding)
            {
              if (binding->second->_emergency_registration)
              {
                emergency = true;
                break;
              }
            }
          }

          delete aor_pair; aor_pair = NULL;
        }
      }

      if (!emergency)
      {
        TRC_INFO("Served user is barred so reject the request");
        status_code = _session_case->is_originating() ? PJSIP_SC_FORBIDDEN : PJSIP_SC_NOT_FOUND;
        pjsip_msg* rsp = create_response(req, status_code);

        if (_session_case->is_originating())
        {
          SAS::Event event(trail(), SASEvent::REJECT_CALL_FROM_BARRED_USER, 0);
          std::string served_user = served_user_from_msg(req);
          event.add_var_param(served_user);
          SAS::report_event(event);
          CL_SPROUT_ORIG_PARTY_BARRED.log(served_user.c_str());
        }
        else
        {
          SAS::Event event(trail(), SASEvent::REJECT_CALL_TO_BARRED_USER, 0);
          std::string served_user = served_user_from_msg(req);
          event.add_var_param(served_user);
          SAS::report_event(event);
          CL_SPROUT_TERM_PARTY_BARRED.log(served_user.c_str());
        }

        _scscf->_barred_calls_tbl->increment();

        send_response(rsp);
        free_msg(req);
        return;
      }
    }

    // Add a P-Charging-Function-Addresses header if one is not already present
    // for some reason. We only do this if we have the charging addresses cached
    // (which we should do).
    PJUtils::add_pcfa_header(req, get_pool(req), _irs_info._ccfs, _irs_info._ecfs, false);

    // Add a second P-Asserted-Identity header if required on originating calls.
    // See 3GPP TS24.229, 5.4.3.2.
    if (_session_case->is_originating())
    {
      add_second_p_a_i_hdr(req);
    }

    if (_as_chain_link.is_set())
    {
      // AS chain is set up, so must apply services to the request.
      TRC_INFO("Found served user, so apply services");

      if (_session_case->is_originating())
      {
        apply_originating_services(req);
      }
      else
      {
        apply_terminating_services(req);
      }
    }
    else
    {
      // No AS chain set, so don't apply services to the request.
      // Check whether the next hop is a routeable URI
      pjsip_uri_context_e context;
      pjsip_uri* next_uri = PJUtils::get_next_routing_uri(req, &context);
      URIClass uri_class = URIClassifier::classify_uri(next_uri);

      if (uri_class != UNKNOWN)
      {
        TRC_INFO("Route request without applying services");
        SAS::Event no_as_route(trail(), SASEvent::NO_AS_CHAIN_ROUTE, 0);
        SAS::report_event(no_as_route);
        send_request(req);
      }
      else
      {
        // Invalid URI, so just reject the request
        std::string uri_str = PJUtils::uri_to_string(context, next_uri);
        reject_invalid_uri(req, uri_str);
      }
    }
  }
}


void SCSCFSproutletTsx::on_rx_in_dialog_request(pjsip_msg* req)
{
  TRC_INFO("S-CSCF received in-dialog request");

  // We must be record-routed to be in the dialog
  _record_routed = true;
  _se_helper.process_request(req, get_pool(req), trail());

  // Determine whether we should be generating an ACR for this transaction,
  // and if so what our role should be? (originaing or terminating).
  ACR::NodeRole billing_role;
  bool bill_request = get_billing_role(billing_role);

  if (bill_request)
  {
    // Create an ACR for this request and pass the request to it.
    _in_dialog_acr = _scscf->get_acr(trail(),
                                     ACR::CALLING_PARTY,
                                     billing_role);

    // @TODO - request timestamp???
    ACR* acr = get_acr();
    if (acr != NULL)
    {
      acr->lock();
      acr->rx_request(req);
      acr->unlock();
    }
  }
  else
  {
    // We don't want to bill this transaction. in_dialog_acr should already
    // be NULL.  NULL it just in case though.
    _in_dialog_acr = NULL;
  }

  send_request(req);
}


void SCSCFSproutletTsx::on_tx_request(pjsip_msg* req, int fork_id)
{
  ACR* acr = get_acr();
  if (acr)
  {
    // Pass the transmitted request to the ACR to update the accounting
    // information.
    acr->lock();
    acr->tx_request(req);
    acr->unlock();
  }
}


void SCSCFSproutletTsx::on_rx_response(pjsip_msg* rsp, int fork_id)
{
  TRC_INFO("S-CSCF received response");

  if (_record_routed)
  {
    _se_helper.process_response(rsp, get_pool(rsp), trail());
  }

  // Pass the received response to the ACR.
  // @TODO - timestamp from response???
  ACR* acr = get_acr();
  if (acr != NULL)
  {
    acr->lock();
    acr->rx_response(rsp);
    acr->unlock();
  }

  if (_liveness_timer != 0)
  {
    // The liveness timer is running on this request, so cancel it.
    cancel_timer(_liveness_timer);
    _liveness_timer = 0;
  }

  int st_code = rsp->line.status.code;

  if (st_code == SIP_STATUS_FLOW_FAILED)
  {
    // The edge proxy / P-CSCF has reported that this flow has failed.
    // We should remove the binding from the registration store so we don't
    // try it again.
    std::unordered_map<int, std::string>::iterator i = _target_bindings.find(fork_id);

    if (i != _target_bindings.end())
    {
      // We're the auth proxy and the flow we used failed, so delete the binding
      // corresponding to this flow.
      _scscf->remove_binding(_target_aor, i->second, trail());
    }
  }

  if ((st_code >= PJSIP_SC_OK) && (_hss_data_cached))
  {
    // Final response. Add a P-Charging-Function-Addresses header if one is
    // not already present for some reason. We only do this if we have
    // the charging addresses cached (which we should do).
    PJUtils::add_pcfa_header(rsp, get_pool(rsp), _irs_info._ccfs, _irs_info._ecfs, false);
  }

  if ((st_code < 300) && (_session_case->is_terminating()))
  {
    // Add a second P-Asserted-Identity header if required. See 3GPP TS24.229,
    // 5.4.3.3.
    add_second_p_a_i_hdr(rsp);
  }

  if (_as_chain_link.is_set())
  {
    // Pass the response code to the controlling AsChain for accounting.
    _as_chain_link.on_response(st_code);

    if (!_as_chain_link.complete())
    {
      // The AS chain isn't complete, so the response must be from an
      // application server.  Check to see if we need to trigger default
      // handling.
      if ((!_as_chain_link.responsive()) &&
          (!_cancelled) &&
          ((st_code == PJSIP_SC_REQUEST_TIMEOUT) ||
           (PJSIP_IS_STATUS_IN_CLASS(st_code, 500))))
      {
        // Default handling will be triggered. Track this as a failed
        // communication.
        _scscf->track_app_serv_comm_failure(_as_chain_link.uri(),
                                            fork_failure_reason_as_string(fork_id, st_code),
                                            _as_chain_link.default_handling());

        if (_as_chain_link.default_handling() == SESSION_CONTINUED)
        {
          // The AS either timed out or returned a 5xx error, and default
          // handling is set to continue.
          TRC_DEBUG("Trigger default_handling=CONTINUE processing");
          SAS::Event bypass_As(trail(), SASEvent::BYPASS_AS, 1);
          bypass_As.add_var_param(st_code == PJSIP_SC_REQUEST_TIMEOUT ?
                                  "Timed out waiting for response to INVITE request from AS" :
                                  "AS returned 5xx response");
          SAS::report_event(bypass_As);

          _as_chain_link = _as_chain_link.next();
          pjsip_msg* req = get_base_request();
          _record_routed = false;
          if (_session_case->is_originating())
          {
            apply_originating_services(req);
          }
          else
          {
            apply_terminating_services(req);
          }

          // Free off the response as we no longer need it.
          free_msg(rsp);
        }
      }
      else
      {
        // Default handling will not be triggered. If this is the first non-100
        // response we've seen from an AS track it as a successful
        // communication. This means that no matter how many 1xx responses we
        // receive we only track one success.
        if ((st_code > PJSIP_SC_TRYING) && (!_seen_1xx))
        {
          _scscf->track_app_serv_comm_success(_as_chain_link.uri(),
                                              _as_chain_link.default_handling());
        }
      }
    }
  }

  if (st_code > PJSIP_SC_TRYING)
  {
    _seen_1xx = true;
  }

  if (rsp != NULL)
  {
    // Forward the response upstream.  The proxy layer will aggregate responses
    // if required.
    send_response(rsp);
  }
}


void SCSCFSproutletTsx::on_tx_response(pjsip_msg* rsp)
{
  ACR* acr = get_acr();
  if (acr != NULL)
  {
    // Pass the transmitted response to the ACR to update the accounting
    // information.
    acr->lock();
    acr->tx_response(rsp);
    acr->unlock();
  }

  // If this is a transaction where we are supposed to be tracking session
  // setup stats then check to see if it is now set up.  We consider it to be
  // setup when we receive either a 180 Ringing or 2xx (per TS 32.409).
  pjsip_status_code st_code = (pjsip_status_code)rsp->line.status.code;
  if (_record_session_setup_time &&
      ((st_code == PJSIP_SC_RINGING) ||
       PJSIP_IS_STATUS_IN_CLASS(st_code, 200)))
  {
    _scscf->track_session_setup_time(_tsx_start_time_usec, _video_call);
    _record_session_setup_time = false;
  }
}


void SCSCFSproutletTsx::on_rx_cancel(int status_code, pjsip_msg* cancel_req)
{
  TRC_INFO("S-CSCF received CANCEL");

  if (_req_type == PJSIP_INVITE_METHOD)
  // If an INVITE is being cancelled, then update INVITE cancellation stats.
  {
    if (_seen_1xx)
    {
      _scscf->_invites_cancelled_after_1xx_tbl->increment();
    }
    else
    {
      _scscf->_invites_cancelled_before_1xx_tbl->increment();
    }
  }

  _cancelled = true;

  if ((status_code == PJSIP_SC_REQUEST_TERMINATED) &&
      (cancel_req != NULL))
  {
    // Create and send an ACR for the CANCEL request.
    ACR::NodeRole role = ACR::NODE_ROLE_ORIGINATING;
    if ((_session_case != NULL) &&
        (_session_case->is_terminating()))
    {
      role = ACR::NODE_ROLE_TERMINATING;
    }
    ACR* cancel_acr = _scscf->get_acr(trail(), ACR::CALLING_PARTY, role);

    // @TODO - timestamp from request.
    cancel_acr->rx_request(cancel_req);
    cancel_acr->send();

    delete cancel_acr;
  }
}

void SCSCFSproutletTsx::retrieve_odi_and_sesscase(pjsip_msg* req)
{
  // Get the top route header.
  const pjsip_route_hdr* hroute = route_hdr();
  URIClass uri_class;
  if (hroute != NULL)
  {
    uri_class = URIClassifier::classify_uri(hroute->name_addr.uri);
  }

  if ((hroute != NULL) &&
      ((uri_class == NODE_LOCAL_SIP_URI) ||
       (uri_class == HOME_DOMAIN_SIP_URI)))
  {
    // This is our own Route header, containing a SIP URI.  Check for an
    // ODI token.  We need to determine the session case: is
    // this an originating request or not - see 3GPP TS 24.229
    // s5.4.3.1, s5.4.1.2.2F and the behaviour of
    // proxy_calculate_targets as an access proxy.
    TRC_DEBUG("Route header references this system");
    pjsip_sip_uri* uri = (pjsip_sip_uri*)hroute->name_addr.uri;
    pjsip_param* orig_param = pjsip_param_find(&uri->other_param, &STR_ORIG);

    _session_case = (orig_param != NULL) ? &SessionCase::Originating :
                                           &SessionCase::Terminating;

    if (pj_strncmp(&uri->user, &STR_ODI_PREFIX, STR_ODI_PREFIX.slen) == 0)
    {
      // This is one of our original dialog identifier (ODI) tokens.
      // See 3GPP TS 24.229 s5.4.3.4.
      std::string odi_token = std::string(uri->user.ptr + STR_ODI_PREFIX.slen,
                                          uri->user.slen - STR_ODI_PREFIX.slen);
      TRC_DEBUG("Found ODI token %s", odi_token.c_str());
      _as_chain_link = _scscf->as_chain_table()->lookup(odi_token);

      if (_as_chain_link.is_set())
      {
        TRC_INFO("Original dialog for %.*s found: %s",
                 uri->user.slen, uri->user.ptr,
                 _as_chain_link.to_string().c_str());
        _session_case = &_as_chain_link.session_case();
      }
      else
      {
        // The ODI token is invalid or expired.  Treat call as OOTB.
        TRC_INFO("Expired ODI token %s so handle as OOTB request", odi_token.c_str());
        SAS::Event event(trail(), SASEvent::SCSCF_ODI_INVALID, 0);
        event.add_var_param(PJUtils::pj_str_to_string(&uri->user));
        SAS::report_event(event);
      }
    }

    // If an application server is a B2BUA and so changes the Call-ID,
    // we'll normally correlate that in SAS through the AS chain
    // (directly correlating the new trail and the trail of the
    // original dialog). If it strips the ODI token for any reason,
    // that won't work - so as a fallback, if we have no ODI token,
    // we'll log an ICID marker to correlate the trails.
    if (!_as_chain_link.is_set())
    {
      TRC_DEBUG("No ODI token, or invalid ODI token, on request");
      PJUtils::mark_icid(trail(), req);
    }

    TRC_DEBUG("Got our Route header, session case %s, OD=%s",
              _session_case->to_string().c_str(),
              _as_chain_link.to_string().c_str());
  }
  else
  {
    // No Route header on the request or top Route header does not correspond to
    // the S-CSCF.  This probably shouldn't happen, but if it does we will
    // treat it as a terminating request.
    TRC_DEBUG("No S-CSCF Route header, so treat as terminating request");
    _session_case = &SessionCase::Terminating;
  }
}

bool SCSCFSproutletTsx::is_retarget(std::string new_served_user)
{
  std::string old_served_user = _as_chain_link.served_user();

  // TS 24.229 section 5.4.3.3 says that changing the Request-URI to an alias of the original URI
  // doesn't count as a retarget, so get the aliases ready to check
  std::vector<std::string> aliases;
  get_aliases(old_served_user, aliases);

  if (new_served_user == old_served_user)
  {
    // URIs match exactly - this is not a retarget
    return false;
  }
  else if (std::find(aliases.begin(), aliases.end(), new_served_user) != aliases.end())
  {
    TRC_DEBUG("Application server has changed URI %s to the aliased URI %s - "
              "not treating as a retarget, not invoking originating-cdiv processing",
              old_served_user.c_str(),
              new_served_user.c_str());
    SAS::Event event(trail(), SASEvent::AS_RETARGETED_TO_ALIAS, 1);
    event.add_var_param(old_served_user);
    event.add_var_param(new_served_user);
    SAS::report_event(event);
    return false;
  }
  else
  {
    // The new URI is not identical to the old one and is not an aliased URI - the request has been retargeted
    SAS::Event event(trail(), SASEvent::AS_RETARGETED_CDIV, 1);
    event.add_var_param(old_served_user);
    event.add_var_param(new_served_user);
    SAS::report_event(event);
    return true;
  }
}

pjsip_status_code SCSCFSproutletTsx::determine_served_user(pjsip_msg* req)
{
  pjsip_status_code status_code = PJSIP_SC_OK;

  retrieve_odi_and_sesscase(req);

  if (_as_chain_link.is_set())
  {
    // Set the S-CSCF URI to the one we stored in the AsChain
    _scscf_uri = _as_chain_link.scscf_uri();

    bool retargeted = false;
    std::string served_user = served_user_from_msg(req);

    if ((_session_case->is_terminating()) &&
        is_retarget(served_user))
    {
      if (pjsip_msg_find_hdr(req, PJSIP_H_ROUTE, NULL) != NULL)
      {
        // The AS has supplied a pre-loaded route, which means it is routing
        // directly to the target. Interrupt the AS chain link to prevent any
        // more app servers from being triggered.
        TRC_INFO("Preloaded route - interrupt AS processing");
        _scscf->_routed_by_preloaded_route_tbl->increment(); // Update SNMP statistics.
        SAS::Event preloaded_route(trail(), SASEvent::AS_SUPPLIED_PRELOADED_ROUTE, 0);
        SAS::report_event(preloaded_route);
        _as_chain_link.interrupt();
      }
      else
      {
        // AS is retargeting per 3GPP TS 24.229 s5.4.3.3 step 3, so
        // create new AS chain with session case orig-cdiv and the
        // terminating user as served user.
        TRC_INFO("AS is retargeting the request");
        retargeted = true;

        _session_case = &SessionCase::OriginatingCdiv;
        served_user = _as_chain_link.served_user();

        sas_log_start_of_sesion_case(req, _session_case, served_user);

        // We might not be the terminating server any more, so we
        // should blank out the term_ioi parameter. If we are still
        // the terminating server, we'll fill it back in when we go
        // through handle_terminating.

        // Note that there's no need to change orig_ioi - we don't
        // actually become the originating server when we do this redirect.
        pjsip_p_c_v_hdr* pcv = (pjsip_p_c_v_hdr*)
                               pjsip_msg_find_hdr_by_name(req, &STR_P_C_V, NULL);
        if (pcv)
        {
          TRC_DEBUG("Blanking out term_ioi parameter due to redirect");
          pcv->term_ioi = pj_str(const_cast<char*>(""));
        }

        // Abandon the `term` ACR we're building up as we're about to perform CDIV.
        ACR* acr = _as_chain_link.acr();
        if (acr != NULL)
        {
          acr->lock();
          acr->cancel();
          acr->unlock();
        }

        Ifcs ifcs;
        long http_code = lookup_ifcs(served_user, ifcs);
        if (http_code == HTTP_OK)
        {
          TRC_DEBUG("Creating originating CDIV AS chain");

          // Preserve the SAS trail ID of the AS chain, to allow us to correlate even when a B2BUA
          // retargets the call
          SAS::TrailId old_chain_trail = _as_chain_link.trail();
          _as_chain_link.release();

          // Don't provide an ACR for the CDIV orig processing.
          ACR* cdiv_acr = NULL;
          _as_chain_link = create_as_chain(ifcs, served_user, cdiv_acr, old_chain_trail);

          if (stack_data.record_route_on_diversion)
          {
            TRC_DEBUG("Add service to dialog - originating Cdiv");
            add_to_dialog(req, false, ACR::NODE_ROLE_ORIGINATING);
          }
        }
        else
        {
          TRC_DEBUG("Failed to retrieve ServiceProfile for %s", served_user.c_str());

          if ((http_code == HTTP_SERVER_UNAVAILABLE) || (http_code == HTTP_GATEWAY_TIMEOUT))
          {
            // Send a SIP 504 response if we got a 500/503 HTTP response.
            status_code = PJSIP_SC_SERVER_TIMEOUT;
          }
          else
          {
            status_code = PJSIP_SC_NOT_FOUND;
          }

          SAS::Event no_ifcs(trail(), SASEvent::IFC_GET_FAILURE, 0);
          SAS::report_event(no_ifcs);
        }
      }
    }

    if (!retargeted)
    {
      if (stack_data.record_route_on_every_hop)
      {
        TRC_DEBUG("Add service to dialog - AS hop");
        if (_session_case->is_terminating())
        {
          add_to_dialog(req, false, ACR::NODE_ROLE_TERMINATING);
        }
        else
        {
          add_to_dialog(req, false, ACR::NODE_ROLE_ORIGINATING);
        }
      }
    }
  }
  else
  {
    // No existing AS chain - create new.
    std::string served_user = served_user_from_msg(req);

    // Create a new ACR for this request.
    ACR* acr = _scscf->get_acr(trail(),
                               ACR::CALLING_PARTY,
                               _session_case->is_originating() ?
                                 ACR::NODE_ROLE_ORIGINATING : ACR::NODE_ROLE_TERMINATING);

    if (!served_user.empty())
    {
      // SAS log the start of originating or terminating processing.
      sas_log_start_of_sesion_case(req, _session_case, served_user);

      if (_session_case->is_terminating())
      {
        if (stack_data.record_route_on_initiation_of_terminating)
        {
          TRC_DEBUG("Single Record-Route - initiation of terminating handling");
          add_to_dialog(req, false, ACR::NODE_ROLE_TERMINATING);
        }
      }
      else if (_session_case->is_originating())
      {
        if (stack_data.record_route_on_initiation_of_originating)
        {
          TRC_DEBUG("Single Record-Route - initiation of originating handling");
          add_to_dialog(req, true, ACR::NODE_ROLE_ORIGINATING);
          acr->lock();
          acr->override_session_id(PJUtils::pj_str_to_string(&PJSIP_MSG_CID_HDR(req)->id));
          acr->unlock();
        }

        // This is an initial originating request -- not a request coming back
        // from an AS.  If it's an INVITE and is actually originating (rather
        // than than an originating call that has been diverted) we need to
        // track the session setup time for our stats.
        if ((_req_type == PJSIP_INVITE_METHOD) && (_session_case == &SessionCase::Originating))
        {
          _record_session_setup_time = true;

          // Store off the time we received this request.
          struct timespec ts;
          clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
          _tsx_start_time_usec = ((uint64_t)ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);

          // Check whether this is a video call.
          std::set<pjmedia_type> media_types = PJUtils::get_media_types(req);
          if (media_types.find(PJMEDIA_TYPE_VIDEO) != media_types.end())
          {
            _video_call = true;
          }
        }
      }

      // Before looking up the iFCs, calculate the S-CSCF URI to use for this
      // transaction, using the configured S-CSCF URI as a starting point.
      pjsip_sip_uri* scscf_uri = (pjsip_sip_uri*)pjsip_uri_clone(get_pool(req), _scscf->_scscf_cluster_uri);
      pjsip_sip_uri* routing_uri = get_routing_uri(req);
      if (routing_uri != NULL)
      {
        SCSCFUtils::get_scscf_uri(get_pool(req),
                                  get_local_hostname(routing_uri),
                                  get_local_hostname(scscf_uri),
                                  scscf_uri);
      }

      _scscf_uri = PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR, (pjsip_uri*)scscf_uri);

      TRC_DEBUG("Looking up iFCs for %s for new AS chain", served_user.c_str());

      Ifcs ifcs;
      long http_code = lookup_ifcs(served_user, ifcs);
      if (http_code == HTTP_OK)
      {
        TRC_DEBUG("Successfully looked up iFCs");
        _as_chain_link = create_as_chain(ifcs, served_user, acr, trail());
      }
      else
      {
        TRC_DEBUG("Failed to retrieve ServiceProfile for %s", served_user.c_str());

        if ((http_code == HTTP_SERVER_UNAVAILABLE) || (http_code == HTTP_GATEWAY_TIMEOUT))
        {
          // Send a SIP 504 response if we got a 500/503 HTTP response.
          status_code = PJSIP_SC_SERVER_TIMEOUT;
        }
        else
        {
          status_code = PJSIP_SC_NOT_FOUND;
        }

        SAS::Event no_ifcs(trail(), SASEvent::IFC_GET_FAILURE, 1);
        SAS::report_event(no_ifcs);

        // No iFC, so no AsChain, store the ACR locally.
        _failed_ood_acr = acr;
      }
    }
    else
    {
      delete acr;
    }
  }

  return status_code;
}


std::string SCSCFSproutletTsx::served_user_from_msg(pjsip_msg* msg)
{
  // For originating:
  //
  // We determine the served user as described in 3GPP TS 24.229 s5.4.3.2,
  // step 1. This first relies on P-Served-User (RFC5502), if present
  // (step 1a). If not (step 1b), we then look at P-Asserted-Identity.
  // For compliance with non-IMS devices (and contrary to the IMS spec),
  // if there is no P-Asserted-Identity we then look at the From header
  // or the request URI as appropriate for the session case.  Per 24.229,
  // we ignore the session case and registration state parameters of
  // P-Served-User; these are intended for the AS, not the S-CSCF (which
  // has other means of determining these).

  // For terminating:
  //
  // We determine the served user as described in 3GPP TS 24.229
  // s5.4.3.3, step 1, i.e., purely on the Request-URI.

  // For originating after retargeting (orig-cdiv), we normally don't
  // call this method at all, because we can pick up the served user
  // from the existing AsChain. If this method is called, however, the
  // following logic applies:
  //
  // We could determine the served user as described in 3GPP TS
  // 24.229 s5.4.3.3 step 3b. This relies on History-Info (RFC4244)
  // and P-Served-User (RFC5502) in step 3b. We should never respect
  // P-Asserted-Identity.
  //
  // We implement P-Served-User, and fall back on the From
  // header. However, the History-Info mechanism has fundamental
  // problems as outlined in RFC5502 appendix A, and we do not
  // implement it.
  pjsip_uri* uri = NULL;
  std::string user;

  if (_session_case->is_originating())  // (includes orig-cdiv)
  {
    uri = PJUtils::orig_served_user(msg, get_pool(msg), trail());
  }
  else
  {
    // We only consider a terminating request to be destined for a served user
    // if it doesn't have a route header.
    if (pjsip_msg_find_hdr(msg, PJSIP_H_ROUTE, NULL) == NULL)
    {
      uri = PJUtils::term_served_user(msg);
    }
  }

  if (uri != NULL)
  {
    URIClass uri_class = URIClassifier::classify_uri(uri);

    if (((PJSIP_URI_SCHEME_IS_SIP(uri)) &&
        ((uri_class == NODE_LOCAL_SIP_URI) ||
         (uri_class == HOME_DOMAIN_SIP_URI) ||
         (uri_class == LOCAL_PHONE_NUMBER) ||
         (uri_class == GLOBAL_PHONE_NUMBER)
         ))
        || (PJSIP_URI_SCHEME_IS_TEL(uri)))
    {
      user = PJUtils::public_id_from_uri(uri);
    }
    else
    {
      TRC_DEBUG("URI is not locally hosted");
    }
  }

  return user;
}


/// Factory method: create AsChain by looking up iFCs.
AsChainLink SCSCFSproutletTsx::create_as_chain(Ifcs ifcs,
                                               std::string served_user,
                                               ACR*& acr,
                                               SAS::TrailId chain_trail)
{
  bool is_registered = is_user_registered(served_user);

  AsChainLink ret = AsChainLink::create_as_chain(_scscf->as_chain_table(),
                                                 *_session_case,
                                                 served_user,
                                                 is_registered,
                                                 chain_trail,
                                                 ifcs,
                                                 acr,
                                                 _scscf->fifcservice(),
                                                 _scscf->ifc_configuration(),
                                                 _scscf_uri);
  acr = NULL;
  TRC_DEBUG("S-CSCF sproutlet transaction %p linked to AsChain %s",
            this, ret.to_string().c_str());
  return ret;
}


/// Apply originating services for this request.
void SCSCFSproutletTsx::apply_originating_services(pjsip_msg* req)
{
  TRC_DEBUG("Performing originating initiating request processing");

  // Add ourselves as orig-IOI.
  pjsip_p_c_v_hdr* pcv = (pjsip_p_c_v_hdr*)
                             pjsip_msg_find_hdr_by_name(req, &STR_P_C_V, NULL);
  if (pcv)
  {
    pcv->orig_ioi = PJUtils::domain_from_uri(_as_chain_link.served_user(),
                                             get_pool(req));
  }

  // Find the next application server to invoke.
  std::string server_name;
  pjsip_status_code status_code =
                   _as_chain_link.on_initial_request(req, server_name, trail());

  if (status_code != PJSIP_SC_OK)
  {
    TRC_ERROR("Rejecting a request as there were no matching iFCs");
    SAS::Event event(trail(), SASEvent::REJECT_AS_NO_MATCHING_IFC, 0);
    SAS::report_event(event);

    pjsip_msg* rsp = create_response(req, status_code);
    send_response(rsp);
    free_msg(req);
  }
  else if (!server_name.empty())
  {
    // We've should have identified an application server to be invoked, so
    // encode the app server hop and the return hop in Route headers.
    route_to_as(req, server_name);
  }
  else
  {
    // No more application servers, so perform processing at the end of
    // originating call processing.
    TRC_INFO("Completed applying originating services");

    if (stack_data.record_route_on_completion_of_originating)
    {
      TRC_DEBUG("Add service to dialog - end of originating handling");
      add_to_dialog(req, false, ACR::NODE_ROLE_ORIGINATING);
    }

    if (_scscf->_enum_service)
    {
      // Attempt to translate the RequestURI using ENUM or an alternative
      // database.
      _scscf->translate_request_uri(req, get_pool(req), trail());

      URIClass uri_class = URIClassifier::classify_uri(req->line.req.uri, true, true);
      std::string new_uri_str = PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, req->line.req.uri);
      TRC_INFO("New URI string is %s", new_uri_str.c_str());

      if ((uri_class == LOCAL_PHONE_NUMBER) ||
          (uri_class == GLOBAL_PHONE_NUMBER) ||
          (uri_class == NP_DATA) ||
          (uri_class == FINAL_NP_DATA))
      {
        TRC_DEBUG("Routing to BGCF");
        SAS::Event event(trail(), SASEvent::PHONE_ROUTING_TO_BGCF, 0);
        event.add_var_param(new_uri_str);
        SAS::report_event(event);
        route_to_bgcf(req);
      }
      else if (uri_class == OFFNET_SIP_URI)
      {
        // Destination is off-net, so route to the BGCF.
        TRC_DEBUG("Routing to BGCF");
        SAS::Event event(trail(), SASEvent::OFFNET_ROUTING_TO_BGCF, 0);
        event.add_var_param(new_uri_str);
        SAS::report_event(event);
        route_to_bgcf(req);
      }
      else if (uri_class != UNKNOWN)
      {
        // Destination is on-net so route to the I-CSCF.
        route_to_icscf(req);
      }
      else
      {
        // Non-sip: or -tel: URI is invalid at this point, so just reject the request
        reject_invalid_uri(req, new_uri_str);
      }
    }
    else
    {
      // ENUM is not configured so we have no way to tell if this request is
      // on-net or off-net. If it's to a valid sip: or tel: URI, route it to the
      // I-CSCF, which should be able to look it up in the HSS.
      URIClass uri_class = URIClassifier::classify_uri(req->line.req.uri, true, false);

      if (uri_class != UNKNOWN)
      {
        TRC_DEBUG("No ENUM lookup available - routing to I-CSCF");
        route_to_icscf(req);
      }
      else
      {
        // Invalid URI, so just reject the request
        std::string uri_str = PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, req->line.req.uri);
        reject_invalid_uri(req, uri_str);
      }
    }
  }
}


/// Apply terminating services for this request.
void SCSCFSproutletTsx::apply_terminating_services(pjsip_msg* req)
{
  // Include ourselves as the terminating operator for billing.
  pjsip_p_c_v_hdr* pcv = (pjsip_p_c_v_hdr*)
                             pjsip_msg_find_hdr_by_name(req, &STR_P_C_V, NULL);
  if (pcv)
  {
    pcv->term_ioi = PJUtils::domain_from_uri(_as_chain_link.served_user(),
                                             get_pool(req));
  }

  // Find the next application server to invoke.
  std::string server_name;
  pjsip_status_code status_code =
                   _as_chain_link.on_initial_request(req, server_name, trail());

  if (status_code != PJSIP_SC_OK)
  {
    TRC_ERROR("Rejecting a request as there were no matching iFCs");
    SAS::Event event(trail(), SASEvent::REJECT_AS_NO_MATCHING_IFC, 1);
    SAS::report_event(event);

    pjsip_msg* rsp = create_response(req, status_code);
    send_response(rsp);
    free_msg(req);
  }
  else if (!server_name.empty())
  {
    // We've should have identified an application server to be invoked, so
    // encode the app server hop and the return hop in Route headers.
    route_to_as(req, server_name);
  }
  else
  {
    // No more application servers to invoke, so perform end of terminating
    // request processing.
    TRC_INFO("Completed applying terminating services");

    if (stack_data.record_route_on_completion_of_terminating)
    {
      TRC_DEBUG("Add service to dialog - end of terminating handling");
      add_to_dialog(req, true, ACR::NODE_ROLE_TERMINATING);

      ACR* acr = _as_chain_link.acr();
      if (acr != NULL)
      {
        acr->lock();
        acr->override_session_id(PJUtils::pj_str_to_string(&PJSIP_MSG_CID_HDR(req)->id));
        acr->unlock();
      }
    }

    if (pjsip_msg_find_hdr(req, PJSIP_H_ROUTE, NULL) != NULL)
    {
      // Route according to normal SIP routing.
      send_request(req);
    }
    else
    {
      // Route the call to the appropriate target.
      route_to_target(req);
    }
  }
}


/// Attempt to route the request to an application server.
void SCSCFSproutletTsx::route_to_as(pjsip_msg* req, const std::string& server_name)
{
  SAS::Event invoke_as(trail(), SASEvent::SCSCF_INVOKING_AS, 0);
  invoke_as.add_var_param(server_name);
  SAS::report_event(invoke_as);

  // Check that the AS URI is well-formed.
  pjsip_sip_uri* as_uri = (pjsip_sip_uri*)
                        PJUtils::uri_from_string(server_name, get_pool(req));

  if ((as_uri != NULL) &&
      (PJSIP_URI_SCHEME_IS_SIP(as_uri)))
  {
    // AS URI is valid, so encode the AS hop and the return hop in Route headers.
    std::string odi_value = PJUtils::pj_str_to_string(&STR_ODI_PREFIX) +
                            _as_chain_link.next_odi_token();
    TRC_INFO("Routing to Application Server %s with ODI token %s for %s",
             server_name.c_str(),
             odi_value.c_str(),
             _as_chain_link.to_string().c_str());

    // Insert route header below it with an ODI in it.  This must use the
    // URI for this S-CSCF node (not the cluster) to ensure any forwarded
    // requests are routed to this node.
    pjsip_sip_uri* odi_uri = (pjsip_sip_uri*)
                             pjsip_uri_clone(get_pool(req), _scscf->scscf_node_uri());
    pj_strdup2(get_pool(req), &odi_uri->user, odi_value.c_str());
    odi_uri->transport_param = as_uri->transport_param;  // Use same transport as AS, in case it can only cope with one.

    PJUtils::add_parameter_to_sip_uri(odi_uri,
                                      STR_SERVICE,
                                      _scscf->scscf_service_name().c_str(),
                                      get_pool(req));

    if (_session_case->is_originating())
    {
      pjsip_param *orig_param = PJ_POOL_ALLOC_T(get_pool(req), pjsip_param);
      pj_strdup(get_pool(req), &orig_param->name, &STR_ORIG);
      pj_strdup2(get_pool(req), &orig_param->value, "");
      pj_list_insert_after(&odi_uri->other_param, orig_param);
    }

    PJUtils::add_top_route_header(req, odi_uri, get_pool(req));

    // Add the application server URI as the top Route header, per TS 24.229.
    PJUtils::add_top_route_header(req, as_uri, get_pool(req));

    // Set P-Served-User, including session case and registration
    // state, per RFC5502 and the extension in 3GPP TS 24.229
    // s7.2A.15, following the description in 3GPP TS 24.229 5.4.3.2
    // step 5 s5.4.3.3 step 4c.
    PJUtils::remove_hdr(req, &STR_P_SERVED_USER);
    pj_pool_t* pool = get_pool(req);
    pjsip_routing_hdr* psu_hdr = identity_hdr_create(pool, STR_P_SERVED_USER);
    psu_hdr->name_addr.uri =
                PJUtils::uri_from_string(_as_chain_link.served_user(), pool);
    pjsip_param* p = PJ_POOL_ALLOC_T(pool, pjsip_param);
    if (_session_case == &SessionCase::OriginatingCdiv)
    {
      // If the session case is "Originating_CDIV" we include the
      // "orig-div" header field parameter with just a name and no value.
      // As per 3GPP TS 24.229 this creates a header that looks like:
      // P-Served-User: <sip:6505551234@homedomain>;orig-cdiv
      pj_strdup2(pool, &p->name, _session_case->to_string().c_str());
      pj_strdup2(pool, &p->value, "");
      pj_list_insert_before(&psu_hdr->other_param, p);
    }
    else
    {
      // If the session case is not "Originating_CDIV" we include the
      // sescase header field parameter and the regstate header field
      // parameter both set to their corresponding values, for example:
      // P-Served-User: <sip:6505551234@homedomain>;sescase=term;regstate=reg
      pj_strdup2(pool, &p->name, "sescase");
      pj_strdup2(pool, &p->value, _session_case->to_string().c_str());
      pj_list_insert_before(&psu_hdr->other_param, p);

      p = PJ_POOL_ALLOC_T(pool, pjsip_param);
      pj_strdup2(pool, &p->name, "regstate");
      if (_as_chain_link.is_registered())
      {
        pj_strdup2(pool, &p->value, "reg");
      }
      else
      {
        pj_strdup2(pool, &p->value, "unreg");
      }
      pj_list_insert_before(&psu_hdr->other_param, p);
    }
    pjsip_msg_add_hdr(req, (pjsip_hdr*)psu_hdr);

    // Forward the request.
    send_request(req);

    // Start the liveness timer for the AS.
    int timeout = ((_as_chain_link.default_handling() == SESSION_CONTINUED) ?
                   _scscf->_session_continued_timeout_ms :
                   _scscf->_session_terminated_timeout_ms);

    if (timeout != 0)
    {
      if (!schedule_timer(NULL, _liveness_timer, timeout))
      {
        // LCOV_EXCL_START - Don't test pjsip failures in the S-CSCF UTs
        TRC_WARNING("Failed to start liveness timer");
        // LCOV_EXCL_STOP
      }
    }
  }
  else
  {
    // The AS URI is badly formed, so reject the request.  (We could choose
    // to continue processing here with the next AS if the default handling
    // is set to allow it, but it feels better to fail the request for a
    // misconfiguration.)
    TRC_ERROR("Badly formed AS URI %s", server_name.c_str());
    SAS::Event bad_uri(trail(), SASEvent::BAD_AS_URI, 0);
    SAS::report_event(bad_uri);

    pjsip_msg* rsp = create_response(req, PJSIP_SC_BAD_GATEWAY);
    send_response(rsp);
    free_msg(req);
  }
}


/// Route the request to the I-CSCF.
void SCSCFSproutletTsx::route_to_icscf(pjsip_msg* req)
{
  const pjsip_uri* icscf_uri = _scscf->icscf_uri();

  if (icscf_uri != NULL)
  {
    // I-CSCF is enabled, so route to it.
    TRC_INFO("Routing to I-CSCF %s",
             PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR, icscf_uri).c_str());
    PJUtils::add_route_header(req,
                              (pjsip_sip_uri*)pjsip_uri_clone(get_pool(req), icscf_uri),
                              get_pool(req));
  }
  else
  {
    // I-CSCF is disabled, so route directly to the local S-CSCF.
    const pjsip_uri* scscf_uri = _scscf->scscf_cluster_uri();
    TRC_INFO("Routing directly to S-CSCF %s",
             PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR, scscf_uri).c_str());
    PJUtils::add_route_header(req,
                              (pjsip_sip_uri*)pjsip_uri_clone(get_pool(req), scscf_uri),
                              get_pool(req));
  }
  send_request(req);
}


/// Route the request to the BGCF.
void SCSCFSproutletTsx::route_to_bgcf(pjsip_msg* req)
{
  TRC_INFO("Routing to BGCF %s",
           PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                  _scscf->bgcf_uri()).c_str());
  PJUtils::add_route_header(req,
                            (pjsip_sip_uri*)pjsip_uri_clone(get_pool(req),
                                                            _scscf->bgcf_uri()),
                            get_pool(req));
  send_request(req);
}

/// Route the request to the appropriate onward target.
void SCSCFSproutletTsx::route_to_target(pjsip_msg* req)
{
  pjsip_uri* req_uri = req->line.req.uri;

  if ((PJSIP_URI_SCHEME_IS_SIP(req_uri) &&
      ((pjsip_sip_uri*)req_uri)->maddr_param.slen))
  {
    // The Request-URI of the request contains an maddr parameter, so forward
    // the request to the Request-URI.
    TRC_INFO("Route request to maddr %.*s",
             ((pjsip_sip_uri*)req_uri)->maddr_param.slen,
             ((pjsip_sip_uri*)req_uri)->maddr_param.ptr);
    send_request(req);
  }
  else
  {
    // The Request-URI is a SIP URI local to us, or a tel: URI that would only
    // have reached this point if it was owned by us, so look it up in the
    // registration store.
    TRC_INFO("Route request to registered UE bindings");
    route_to_ue_bindings(req);
  }
}


/// Route the request to UE bindings retrieved from the registration store.
void SCSCFSproutletTsx::route_to_ue_bindings(pjsip_msg* req)
{
  // Get the public user identity corresponding to the RequestURI.
  pjsip_uri* req_uri = req->line.req.uri;
  std::string public_id = PJUtils::public_id_from_uri(req_uri);

  // Add a P-Called-Party-ID header containing the public user identity,
  // replacing any existing header.
  pj_pool_t* pool = get_pool(req);
  PJUtils::remove_hdr(req, &STR_P_CALLED_PARTY_ID);
  std::string name_addr_str("<" + public_id + ">");
  pj_str_t called_party_id;
  pj_strdup2(pool, &called_party_id, name_addr_str.c_str());
  pjsip_hdr* hdr = (pjsip_hdr*)
                        pjsip_generic_string_hdr_create(pool,
                                                        &STR_P_CALLED_PARTY_ID,
                                                        &called_party_id);
  pjsip_msg_add_hdr(req, hdr);

  TargetList targets;
  std::string aor;

  if (is_user_registered(public_id))
  {
    // User is registered, so look up bindings.  Determine the canonical public
    // ID, and look up the set of associated URIs on the HSS.
    std::vector<std::string> uris;
    bool success = get_associated_uris(public_id, uris);

    if ((success) && (uris.size() > 0))
    {
      for (std::string uri : uris)
      {
        if (WildcardUtils::check_users_equivalent(uri, public_id))
        {
          aor = _default_uri;
          break;
        }
      }
    }

    if (aor == "")
    {
      // Failed to get the associated URIs from Homestead.  We'll try to
      // do the registration look-up with the specified target URI - this may
      // fail, but we'll never misroute the call.
      TRC_WARNING("Invalid Homestead response - a user is registered but has no list of "
                  "associated URIs, or is not in its own list of associated URIs");
      aor = public_id;
    }

    // Get the bindings from the store and filter/sort them for the request.
    AoRPair* aor_pair = NULL;
    _scscf->get_bindings(aor, &aor_pair, trail());

    if ((aor_pair != NULL) &&
        (aor_pair->get_current() != NULL) &&
        (!aor_pair->get_current()->bindings().empty()))
    {
      // Retrieved bindings from the store so filter them to an ordered list
      // of targets.
      filter_bindings_to_targets(aor,
                                 aor_pair->get_current(),
                                 req,
                                 pool,
                                 MAX_FORKING,
                                 targets,
                                 _barred,
                                 trail());
    }
    else
    {
      // Subscriber is registered, but there are no bindings in the store.
      // This indicates an error case - it is likely that de-registration
      // has failed.  Make a SAS log, the call will be rejected with a 480.
      TRC_DEBUG("Public ID %s registered, but 0 bindings in store",
                public_id.c_str());
      SAS::Event event(trail(), SASEvent::SCSCF_NO_BINDINGS, 0);
      event.add_var_param(public_id);
      SAS::report_event(event);
    }

    delete aor_pair; aor_pair = NULL;
  }
  else
  {
    // Subscriber is not registered.  This is not necessarily an error case,
    // but make a SAS log for clarity.  The call will be rejected with a 480.
    TRC_DEBUG("Public ID %s not registered", public_id.c_str());
    SAS::Event event(trail(), SASEvent::SCSCF_NOT_REGISTERED, 0);
    event.add_var_param(public_id);
    SAS::report_event(event);
  }

  if (targets.empty())
  {
    // No valid target bindings for this request, so reject it.
    pjsip_msg* rsp = create_response(req, PJSIP_SC_TEMPORARILY_UNAVAILABLE);
    send_response(rsp);
    free_msg(req);
  }
  else
  {
    SAS::Event route_to_ues(trail(), SASEvent::SCSCF_ROUTING_TO_UES, 0);
    route_to_ues.add_static_param(targets.size());
    SAS::report_event(route_to_ues);

    // Fork the request to the bindings, and remember the AoR used to query
    // the registration store and the binding identifier for each fork.
    _target_aor = aor;
    for (size_t ii = 0; ii < targets.size(); ++ii)
    {
      // Clone for all but the last request.
      pjsip_msg* to_send = (ii == targets.size() - 1) ? req : clone_request(req);
      pool = get_pool(to_send);

      // Set up the Request URI.
      to_send->line.req.uri = (pjsip_uri*)
                                        pjsip_uri_clone(pool, targets[ii].uri);

      // Copy across the path headers into Route headers.
      for (std::list<pjsip_route_hdr*>::const_iterator j = targets[ii].paths.begin();
           j != targets[ii].paths.end();
           ++j)
      {
        pjsip_msg_add_hdr(to_send,
                          (pjsip_hdr*)pjsip_hdr_clone(pool, *j));
      }

      // Forward the request and remember the binding identifier used for this
      // in case we get a 430 Flow Failed response.
      int fork_id = send_request(to_send);
      _target_bindings.insert(std::make_pair(fork_id, targets[ii].binding_id));

      if ((_req_type == PJSIP_INVITE_METHOD) && (ii != 0))
      {
        // Increment stat tracking the number of additional INVITEs generated
        // due to there being multiple registered targets.
        _scscf->_forked_invite_tbl->increment();
      }
    }
  }
}

/// Gets the subscriber's associated URIs and iFCs for each URI from
/// the HSS and stores cached values. Returns the HTTP result code obtained from
/// homestead.
long SCSCFSproutletTsx::get_data_from_hss(std::string public_id)
{
  long http_code = HTTP_OK;

  // Read IRS information from HSS if not previously cached.
  if (!_hss_data_cached)
  {
    HSSConnection::irs_query irs_query;
    irs_query._public_id = public_id;
    irs_query._private_id =_impi;
    irs_query._req_type = _auto_reg ? HSSConnection::REG : HSSConnection::CALL;
    irs_query._server_name = _scscf_uri;
    irs_query._wildcard = _wildcard;
    irs_query._cache_allowed = !_auto_reg;

    http_code = read_hss_data(irs_query,
                              _irs_info,
                              trail());

    if (http_code == HTTP_OK)
    {
      _hss_data_cached = true;
    }
  }

  return http_code;
}


/// Look up the registration state for the given public ID, using the
/// per-transaction cache, which will be present at this point
bool SCSCFSproutletTsx::is_user_registered(std::string public_id)
{
  return _registered;
}


/// Look up the associated URIs for the given public ID, using the cache if
/// possible (and caching them and the iFC otherwise).
/// The uris parameter is only filled in correctly if this function
/// returns true.
bool SCSCFSproutletTsx::get_associated_uris(std::string public_id,
                                            std::vector<std::string>& uris)
{
  long http_code = get_data_from_hss(public_id);
  if (http_code == HTTP_OK)
  {
    uris = _irs_info._associated_uris.get_all_uris();
  }
  return (http_code == HTTP_OK);
}

/// Look up the aliases for the given public ID, using the cache if
/// possible (and caching them and the iFC otherwise).
/// The aliases parameter is only filled in correctly if this function
/// returns true.
bool SCSCFSproutletTsx::get_aliases(std::string public_id,
                                    std::vector<std::string>& aliases)
{
  long http_code = get_data_from_hss(public_id);
  if (http_code == HTTP_OK)
  {
    aliases = _irs_info._aliases;
  }
  return (http_code == HTTP_OK);
}



/// Look up the Ifcs for the given public ID, using the cache if possible
/// (and caching them and the associated URIs otherwise).
/// Returns the HTTP result code obtained from homestead.
/// The ifcs parameter is only filled in correctly if this function
/// returns HTTP_OK.
long SCSCFSproutletTsx::lookup_ifcs(std::string public_id, Ifcs& ifcs)
{
  long http_code = get_data_from_hss(public_id);
  if (http_code == HTTP_OK)
  {
    ifcs = _ifcs;
  }
  return http_code;
}


/// Add the S-CSCF sproutlet into a dialog by adding an appropriate record-route
/// to the current message (if we haven't already done this previously).  In
/// order to ensure that we correctly bill or don't bill this hop on subsequent
/// in-dialog transactions we also add a billing-role parameter to the
/// record-route indicating either that we shouldn't bill the hop, that we
/// should bill it (as an originating party) or that we should bill it (as a
/// terminating party).
///
/// Params:
/// - msg:         the message that we are currently processing and that we
///                want to add a record-route header to
/// - bill_this_hop:
///                set to true if this is a hop where future in-dialog requests
///                should generate an ACR
/// - acr_billing_role:
///                if billing_rr is set to true then this is the ACR::NodeRole
///                that should be used when generating said future ACRs
void SCSCFSproutletTsx::add_to_dialog(pjsip_msg* msg,
                                      bool bill_this_hop,
                                      ACR::NodeRole acr_billing_role)
{
  pj_pool_t* pool = get_pool(msg);
  _se_helper.process_request(msg, pool, trail());

  pjsip_route_hdr* rr = NULL;
  if (!_record_routed)
  {
    // Get the cluster URI. Don't use `get_reflexive_uri` here as we want to
    // record route the entire S-CSCF service, not just this sproutlet.
    pjsip_sip_uri* uri = (pjsip_sip_uri*)pjsip_uri_clone(pool, _scscf->scscf_cluster_uri());
    uri->lr_param = 1;

    rr = pjsip_rr_hdr_create(pool);
    rr->name_addr.uri = (pjsip_uri*)uri;

    pjsip_msg_insert_first_hdr(msg, (pjsip_hdr*)rr);

    _record_routed = true;
  }
  else
  {
    rr = (pjsip_route_hdr*)pjsip_msg_find_hdr(msg,
                                              PJSIP_H_RECORD_ROUTE,
                                              NULL);
  }

  // Ensure the billing scope flag is set on the RR header.
  // We've record-routed before (either earlier in this function or in a
  // previous call to this function within this transaction).  Therefore the
  // Record-Route header we added then must be present (and must be the top
  // such header).
  assert(rr != NULL);

  pjsip_sip_uri* uri = (pjsip_sip_uri*)rr->name_addr.uri;
  pjsip_param* param = pjsip_param_find(&uri->other_param,
                                        &STR_BILLING_ROLE);

  // Work out what our billing-role should be set to for this hop.
  pj_str_t const* pjsip_billing_role;
  if (!bill_this_hop)
  {
    // This isn't a hop that we want to generate a billing record for.
    pjsip_billing_role = &STR_CHARGE_NONE;
  }
  else if (acr_billing_role == ACR::NODE_ROLE_ORIGINATING)
  {
    pjsip_billing_role = &STR_CHARGE_ORIG;
  }
  else if (acr_billing_role == ACR::NODE_ROLE_TERMINATING)
  {
    pjsip_billing_role = &STR_CHARGE_TERM;
  }
  else
  {
    // LCOV_EXCL_START
    // This should never happen.  Log an error and treat as a hop that we won't
    // generate a billing record for.
    TRC_ERROR("Unrecognised billing_role: %d", acr_billing_role);
    pjsip_billing_role = &STR_CHARGE_NONE;
    // LCOV_EXCL_STOP
  }

  if (!param)
  {
    // There wasn't a billing role previously.  Set it now.
    param = PJ_POOL_ALLOC_T(pool, pjsip_param);
    pj_strdup(pool, &param->name, &STR_BILLING_ROLE);

    pj_strdup(pool, &param->value, pjsip_billing_role);
    pj_list_insert_before(&uri->other_param, param);
  }
  else if ((bill_this_hop) && !pj_strcmp(&param->value, &STR_CHARGE_NONE))
  {
    // We had previously set the billing-role for this hop to NONE but have now
    // decided that we should be billing it. E.g. we first treated this as
    // just a standard AS hop, but have now decided that it is the final
    // terminating hop.  Update the billing role.
    pj_strdup(pool, &param->value, pjsip_billing_role);
  }

  // Store off the modified message - we may need it later if we need to invoke
  // default handling for an AS.
  if (_base_req != nullptr)
  {
    free_msg(_base_req);
  }
  _base_req = clone_msg(msg);
}


/// Retrieve the billing role for an in-dialog message.
bool SCSCFSproutletTsx::get_billing_role(ACR::NodeRole &role)
{
  const pjsip_route_hdr* route = route_hdr();

  if (route != NULL)
  {
    pjsip_sip_uri* uri = (pjsip_sip_uri*)route->name_addr.uri;
    pjsip_param* param = pjsip_param_find(&uri->other_param,
                                          &STR_BILLING_ROLE);

    if (param != NULL)
    {
      if (!pj_strcmp(&param->value, &STR_CHARGE_NONE))
      {
        TRC_INFO("Charging role is none");
        return false;
      }
      else if (!pj_strcmp(&param->value, &STR_CHARGE_ORIG))
      {
        TRC_INFO("Charging role is originating");
        role = ACR::NODE_ROLE_ORIGINATING;
      }
      else if (!pj_strcmp(&param->value, &STR_CHARGE_TERM))
      {
        TRC_INFO("Charging role is terminating");
        role = ACR::NODE_ROLE_TERMINATING;
      }
      else
      {
        TRC_INFO("Unknown charging role %.*s, assume originating",
                 param->value.slen, param->value.ptr);
        role = ACR::NODE_ROLE_ORIGINATING;
      }
    }
    else
    {
      TRC_INFO("No charging role in Route header, assume originating");
      role = ACR::NODE_ROLE_ORIGINATING;
    }
  }
  else
  {
    TRC_INFO("Cannot determine charging role as no Route header, assume originating");
    role = ACR::NODE_ROLE_ORIGINATING;
  }

  return true;
}


/// Handles liveness timer expiry.
void SCSCFSproutletTsx::on_timer_expiry(void* context)
{
  _liveness_timer = 0;

  if (_as_chain_link.is_set())
  {
    // The AS has timed out so track this as a communication failure.
    _scscf->track_app_serv_comm_failure(_as_chain_link.uri(),
                                        "Default handling timeout",
                                        _as_chain_link.default_handling());

    // The request was routed to a downstream AS, so cancel any outstanding
    // forks.
    cancel_pending_forks(PJSIP_SC_REQUEST_TIMEOUT, "AS liveness timer expired");
    mark_pending_forks_as_abandoned();

    if (_as_chain_link.default_handling() == SESSION_CONTINUED)
    {
      // The AS either timed out or returned a 5xx error, and default
      // handling is set to continue.
      TRC_DEBUG("Trigger default_handling=CONTINUED processing");
      SAS::Event bypass_as(trail(), SASEvent::BYPASS_AS, 0);
      bypass_as.add_var_param("AS liveness timer expired");
      SAS::report_event(bypass_as);

      _as_chain_link = _as_chain_link.next();
      pjsip_msg* req = get_base_request();
      _record_routed = false;
      if (_session_case->is_originating())
      {
        apply_originating_services(req);
      }
      else
      {
        apply_terminating_services(req);
      }
    }
    else
    {
      TRC_DEBUG("Trigger default_handling=TERMINATED processing");
      SAS::Event as_failed(trail(), SASEvent::AS_FAILED, 0);
      SAS::report_event(as_failed);

      // Build and send a timeout response upstream.
      pjsip_msg* req = get_base_request();
      pjsip_msg* rsp = create_response(req,
                                       PJSIP_SC_REQUEST_TIMEOUT);
      free_msg(req);
      send_response(rsp);
    }
  }
}

/// Adds a second P-Asserted-Identity header to a message when required.
///
/// We only add the header to messages for which all of the following is true:
/// - We can't find our Route header or our Route header doesn't contain an
///   ODI token.
/// - There is exactly one P-Asserted-Identity header on the message already.
/// - If that header contains a SIP URI sip:user@example.com, that SIP URI is
///   an alias of the tel URI tel:user. That tel URI is used in the new header.
///   If that header contains a tel URI tel:user, we use the SIP URI
///   sip:user@<homedomain> in the new header.
void SCSCFSproutletTsx::add_second_p_a_i_hdr(pjsip_msg* msg)
{
  const pjsip_route_hdr* hroute = route_hdr();

  if ((hroute != NULL) &&
      (!pj_strncmp(&((pjsip_sip_uri*)hroute->name_addr.uri)->user,
                   &STR_ODI_PREFIX,
                   STR_ODI_PREFIX.slen)))
  {
    // Found our Route header and it contains one of our original dialog
    // identifier (ODI) tokens. No need to add a second P-Asserted-Identity
    // header.
    return;
  }

  // Look for P-Asserted-Identity header.
  pjsip_routing_hdr* asserted_id =
    (pjsip_routing_hdr*)pjsip_msg_find_hdr_by_name(msg,
                                                   &STR_P_ASSERTED_IDENTITY,
                                                   NULL);

  // If we have one and only one P-Asserted-Identity header we may need to add
  // a second one.
  if ((asserted_id != NULL) &&
      (pjsip_msg_find_hdr_by_name(msg,
                                  &STR_P_ASSERTED_IDENTITY,
                                  asserted_id->next) == NULL))
  {
    std::string new_p_a_i_str;
    pjsip_uri* uri = (pjsip_uri*)pjsip_uri_get_uri(&asserted_id->name_addr);

    if (PJSIP_URI_SCHEME_IS_SIP(uri))
    {
      // If we have a SIP URI, we add a second P-Asserted-Identity containing a
      // tel URI if this SIP URI has a tel URI alias.
      new_p_a_i_str = "tel:";
      new_p_a_i_str += PJUtils::pj_str_to_string(&((pjsip_sip_uri*)uri)->user);

      // If the SIP URI has a alias tel URI with the same username we add this
      // tel URI to the P-Asserted-Identity header. If not we select the first
      // tel URI in the alias list to add to the P-Asserted-Identity header.
      if (find(_irs_info._aliases.begin(),
               _irs_info._aliases.end(),
               new_p_a_i_str) != _irs_info._aliases.end())
      {
        TRC_DEBUG("Add second P-Asserted-Identity for %s", new_p_a_i_str.c_str());
        PJUtils::add_asserted_identity(msg,
                                       get_pool(msg),
                                       new_p_a_i_str,
                                       asserted_id->name_addr.display);
      }
      else
      {
        for (std::string alias : _irs_info._aliases)
        {
          std::string tel_URI_prefix = "tel:";
          bool has_tel_prefix = (alias.rfind(tel_URI_prefix.c_str(), 4) != std::string::npos);
          if (has_tel_prefix)
          {
            TRC_DEBUG("Add second P-Asserted Identity for %s", alias.c_str());
            PJUtils::add_asserted_identity(msg,
                                           get_pool(msg),
                                           alias,
                                           asserted_id->name_addr.display);
            break;
          }
        }
      }
    }
    else if (PJSIP_URI_SCHEME_IS_TEL(uri))
    {
      // If we have a tel URI, we add a second P-Asserted-Identity containg the
      // corresponding SIP URI.
      new_p_a_i_str = "sip:";
      new_p_a_i_str += PJUtils::pj_str_to_string(&((pjsip_tel_uri*)uri)->number);
      new_p_a_i_str += "@";
      new_p_a_i_str += PJUtils::pj_str_to_string(&stack_data.default_home_domain);
      new_p_a_i_str += ";user=phone";
      TRC_DEBUG("Add second P-Asserted-Identity for %s", new_p_a_i_str.c_str());
      PJUtils::add_asserted_identity(msg,
                                     get_pool(msg),
                                     new_p_a_i_str,
                                     asserted_id->name_addr.display);
    }
  }
}

void SCSCFSproutletTsx::sas_log_start_of_sesion_case(pjsip_msg* req,
                                                     const SessionCase* session_case,
                                                     const std::string& served_user)
{
  int event_id;

  if (session_case == &SessionCase::Originating)
  {
    event_id = SASEvent::SCSCF_STARTED_ORIG_PROC;
  }
  else if (session_case == &SessionCase::Terminating)
  {
    event_id = SASEvent::SCSCF_STARTED_TERM_PROC;
  }
  else
  {
    event_id = SASEvent::SCSCF_STARTED_ORIG_CDIV_PROC;
  }

  SAS::Event event(trail(), event_id, 0);
  event.add_var_param(served_user);
  event.add_var_param(req->line.req.method.name.slen,
                      req->line.req.method.name.ptr);
  SAS::report_event(event);
}

ACR* SCSCFSproutletTsx::get_acr()
{
  if (_as_chain_link.is_set())
  {
    return _as_chain_link.acr();
  }
  else if (_in_dialog_acr)
  {
    return _in_dialog_acr;
  }
  else
  {
    return _failed_ood_acr;
  }
}

std::string SCSCFSproutletTsx::fork_failure_reason_as_string(int fork_id, int sip_code)
{
  ForkState fs = fork_state(fork_id);
  std::string reason;

  switch (fs.error_state)
  {
  case TIMEOUT:
    reason = "SIP timeout";
    break;

  case TRANSPORT_ERROR:
    reason = "Transport error";
    break;

  case NO_ADDRESSES:
    reason = "No valid address";
    break;

  case NONE:
    reason = "SIP " + std::to_string(sip_code) + " response received";
    break;

  default:
    // LCOV_EXCL_START - hitting this branch implies a logic error which we
    // don't expect to hit in UT.
    TRC_ERROR("Unknown ForkErrorState: %d", fs.error_state);
    reason = "Unknown";
    break;
    // LCOV_EXCL_STOP
  }

  return reason;
}

pjsip_msg* SCSCFSproutletTsx::get_base_request()
{
  if (_base_req != nullptr)
  {
    return clone_msg(_base_req);
  }
  else
  {
    return original_request();
  }
}

void SCSCFSproutletTsx::reject_invalid_uri(pjsip_msg* req, const std::string& uri_str)
{
  TRC_DEBUG("Rejecting request to invalid URI %s", uri_str.c_str());
  SAS::Event event(trail(), SASEvent::SCSCF_INVALID_URI, 0);
  event.add_var_param(uri_str);
  SAS::report_event(event);
  pjsip_msg* rsp = create_response(req, PJSIP_SC_BAD_REQUEST);
  send_response(rsp);
  free_msg(req);
}
