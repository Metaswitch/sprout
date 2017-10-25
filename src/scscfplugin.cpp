/**
 * @file scscfplugin.cpp  Plug-in wrapper for the S-CSCF Sproutlet.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <functional>

#include "cfgoptions.h"
#include "sproutletplugin.h"
#include "impistore.h"
#include "scscfsproutlet.h"
#include "subscriptionsproutlet.h"
#include "registrarsproutlet.h"
#include "authenticationsproutlet.h"
#include "sprout_alarmdefinition.h"
#include "sprout_pd_definitions.h"
#include "log.h"

const std::string PROXY_SERVICE_NAME = "scscf-proxy";
const std::string AUTHENTICATION_SERVICE_NAME = "authentication";
const std::string REGISTRAR_SERVICE_NAME = "registrar";
const std::string SUBSCRIPTION_SERVICE_NAME = "subscription";

class SCSCFPlugin : public SproutletPlugin
{
public:
  SCSCFPlugin();
  ~SCSCFPlugin();

  bool load(struct options& opt, std::list<Sproutlet*>&);
  void unload();

private:
  SCSCFSproutlet* _scscf_sproutlet;
  SubscriptionSproutlet* _subscription_sproutlet;
  RegistrarSproutlet* _registrar_sproutlet;
  AuthenticationSproutlet* _auth_sproutlet;
  Alarm* _sess_cont_as_alarm;
  Alarm* _sess_term_as_alarm;

  SNMP::SuccessFailCountByRequestTypeTable* _incoming_sip_transactions_tbl;
  SNMP::SuccessFailCountByRequestTypeTable* _outgoing_sip_transactions_tbl;
  SNMP::RegistrationStatsTables reg_stats_tbls = {nullptr, nullptr, nullptr};
  SNMP::RegistrationStatsTables third_party_reg_stats_tbls = {nullptr, nullptr, nullptr};
  SNMP::AuthenticationStatsTables auth_stats_tbls = {nullptr, nullptr, nullptr};
  SNMP::CounterTable* _no_matching_ifcs_tbl;
  SNMP::CounterTable* _no_matching_fallback_ifcs_tbl;
};

/// Export the plug-in using the magic symbol "sproutlet_plugin"
extern "C" {
SCSCFPlugin sproutlet_plugin;
}

SCSCFPlugin::SCSCFPlugin() :
  _scscf_sproutlet(NULL),
  _subscription_sproutlet(NULL),
  _registrar_sproutlet(NULL),
  _incoming_sip_transactions_tbl(NULL),
  _outgoing_sip_transactions_tbl(NULL),
  _no_matching_ifcs_tbl(NULL),
  _no_matching_fallback_ifcs_tbl(NULL)
{
}

SCSCFPlugin::~SCSCFPlugin()
{
  delete _incoming_sip_transactions_tbl;
  delete _outgoing_sip_transactions_tbl;
  delete _no_matching_ifcs_tbl;
  delete _no_matching_fallback_ifcs_tbl;
}

/// Loads the S-CSCF plug-in, returning the supported Sproutlets.
bool SCSCFPlugin::load(struct options& opt, std::list<Sproutlet*>& sproutlets)
{
  bool ok = true;

  // Create the SNMP tables here - they should exist based on whether the
  // plugin is loaded, not whether the Sproutlet is enabled, in order to
  // simplify SNMP polling of multiple differently-configured Sprout nodes.
  _incoming_sip_transactions_tbl = SNMP::SuccessFailCountByRequestTypeTable::create("scscf_incoming_sip_transactions",
                                                                                    "1.2.826.0.1.1578918.9.3.20");
  _outgoing_sip_transactions_tbl = SNMP::SuccessFailCountByRequestTypeTable::create("scscf_outgoing_sip_transactions",
                                                                                    "1.2.826.0.1.1578918.9.3.21");
  _no_matching_fallback_ifcs_tbl = SNMP::CounterTable::create("no_matching_fallback_ifcs",
                                                              "1.2.826.0.1.1578918.9.3.39");
  _no_matching_ifcs_tbl = SNMP::CounterTable::create("no_matching_ifcs",
                                                     "1.2.826.0.1.1578918.9.3.41");

  if (opt.enabled_scscf)
  {
    TRC_STATUS("S-CSCF plugin enabled");

    // Determine the S-CSCF node URI and then S-SCSCF, BGCF and I-CSCF cluster URIs.
    std::string scscf_node_uri;

    if (opt.scscf_node_uri != "")
    {
      scscf_node_uri = opt.scscf_node_uri;
    }
    else
    {
      std::string node_host(stack_data.local_host.ptr, stack_data.local_host.slen);

      if (Utils::parse_ip_address(node_host) == Utils::IPV6_ADDRESS)
      {
        node_host = "[" + node_host + "]";
      }

      scscf_node_uri = "sip:" + node_host + ":" + std::to_string(opt.port_scscf);
    }

    std::string icscf_uri;

    if (opt.enabled_icscf)
    {
      icscf_uri = opt.uri_icscf;
    }
    else
    {
      icscf_uri = opt.external_icscf_uri;
    }

    // Create Application Server communication trackers.
    _sess_term_as_alarm = new Alarm(alarm_manager,
                                    "sprout",
                                    AlarmDef::SPROUT_SESS_TERMINATED_AS_COMM_ERROR,
                                    AlarmDef::MAJOR);
    AsCommunicationTracker* sess_term_as_tracker =
        new AsCommunicationTracker(_sess_term_as_alarm,
                                   &CL_SPROUT_SESS_TERM_AS_COMM_FAILURE,
                                   &CL_SPROUT_SESS_TERM_AS_COMM_SUCCESS);

    _sess_cont_as_alarm =  new Alarm(alarm_manager,
                                     "sprout",
                                     AlarmDef::SPROUT_SESS_CONTINUED_AS_COMM_ERROR,
                                     AlarmDef::MINOR);
    AsCommunicationTracker* sess_cont_as_tracker =
        new AsCommunicationTracker(_sess_cont_as_alarm,
                                   &CL_SPROUT_SESS_CONT_AS_COMM_FAILURE,
                                   &CL_SPROUT_SESS_CONT_AS_COMM_SUCCESS);

    _scscf_sproutlet = new SCSCFSproutlet(PROXY_SERVICE_NAME,
                                          opt.prefix_scscf,
                                          opt.uri_scscf,
                                          scscf_node_uri,
                                          icscf_uri,
                                          opt.uri_bgcf,
                                          0,
                                          "",
                                          opt.prefix_scscf,
                                          "",
                                          local_sdm,
                                          remote_sdms,
                                          hss_connection,
                                          enum_service,
                                          scscf_acr_factory,
                                          _incoming_sip_transactions_tbl,
                                          _outgoing_sip_transactions_tbl,
                                          opt.override_npdi,
                                          fifc_service,
                                          IFCConfiguration(opt.apply_fallback_ifcs,
                                                           opt.reject_if_no_matching_ifcs,
                                                           opt.dummy_app_server,
                                                           _no_matching_ifcs_tbl,
                                                           _no_matching_fallback_ifcs_tbl),
                                          opt.session_continued_timeout_ms,
                                          opt.session_terminated_timeout_ms,
                                          sess_term_as_tracker,
                                          sess_cont_as_tracker);
    ok = ok && _scscf_sproutlet->init();
    sproutlets.push_front(_scscf_sproutlet);

    _subscription_sproutlet = new SubscriptionSproutlet(SUBSCRIPTION_SERVICE_NAME,
                                                        0,
                                                        "",
                                                        opt.prefix_scscf,
                                                        PROXY_SERVICE_NAME,
                                                        local_sdm,
                                                        remote_sdms,
                                                        hss_connection,
                                                        scscf_acr_factory,
                                                        analytics_logger,
                                                        opt.sub_max_expires);
    ok = ok && _subscription_sproutlet->init();
    sproutlets.push_front(_subscription_sproutlet);

    reg_stats_tbls.init_reg_tbl = SNMP::SuccessFailCountTable::create("initial_reg_success_fail_count",
                                                                       ".1.2.826.0.1.1578918.9.3.9");
    reg_stats_tbls.re_reg_tbl = SNMP::SuccessFailCountTable::create("re_reg_success_fail_count",
                                                                     ".1.2.826.0.1.1578918.9.3.10");
    reg_stats_tbls.de_reg_tbl = SNMP::SuccessFailCountTable::create("de_reg_success_fail_count",
                                                                      ".1.2.826.0.1.1578918.9.3.11");

    third_party_reg_stats_tbls.init_reg_tbl = SNMP::SuccessFailCountTable::create("third_party_initial_reg_success_fail_count",
                                                                                   ".1.2.826.0.1.1578918.9.3.12");
    third_party_reg_stats_tbls.re_reg_tbl = SNMP::SuccessFailCountTable::create("third_party_re_reg_success_fail_count",
                                                                                 ".1.2.826.0.1.1578918.9.3.13");
    third_party_reg_stats_tbls.de_reg_tbl = SNMP::SuccessFailCountTable::create("third_party_de_reg_success_fail_count",
                                                                                 ".1.2.826.0.1.1578918.9.3.14");

    _registrar_sproutlet = new RegistrarSproutlet(REGISTRAR_SERVICE_NAME,
                                                  0,
                                                  "",
                                                  {},
                                                  opt.prefix_scscf,
                                                  SUBSCRIPTION_SERVICE_NAME,
                                                  local_sdm,
                                                  remote_sdms,
                                                  hss_connection,
                                                  scscf_acr_factory,
                                                  opt.reg_max_expires,
                                                  opt.force_third_party_register_body,
                                                  &reg_stats_tbls,
                                                  &third_party_reg_stats_tbls,
                                                  fifc_service,
                                                  IFCConfiguration(opt.apply_fallback_ifcs,
                                                                   opt.reject_if_no_matching_ifcs,
                                                                   opt.dummy_app_server,
                                                                   _no_matching_ifcs_tbl,
                                                                   _no_matching_fallback_ifcs_tbl));


    ok = ok && _registrar_sproutlet->init();
    sproutlets.push_front(_registrar_sproutlet);

    if (opt.auth_enabled)
    {
      auth_stats_tbls.sip_digest_auth_tbl =
        SNMP::SuccessFailCountTable::create("sip_digest_auth_success_fail_count",
                                            ".1.2.826.0.1.1578918.9.3.15");
      auth_stats_tbls.ims_aka_auth_tbl =
        SNMP::SuccessFailCountTable::create("ims_aka_auth_success_fail_count",
                                            ".1.2.826.0.1.1578918.9.3.16");
      auth_stats_tbls.non_register_auth_tbl =
        SNMP::SuccessFailCountTable::create("non_register_auth_success_fail_count",
                                            ".1.2.826.0.1.1578918.9.3.17");

      _auth_sproutlet =
        new AuthenticationSproutlet(AUTHENTICATION_SERVICE_NAME,
                                    opt.port_scscf,
                                    "",
                                    {opt.prefix_scscf},
                                    opt.prefix_scscf,
                                    REGISTRAR_SERVICE_NAME,
                                    opt.auth_realm,
                                    local_impi_store,
                                    remote_impi_stores,
                                    hss_connection,
                                    chronos_connection,
                                    scscf_acr_factory,
                                    opt.non_register_auth_mode,
                                    analytics_logger,
                                    &auth_stats_tbls,
                                    opt.nonce_count_supported,
                                    opt.sub_max_expires);
      ok = ok && _auth_sproutlet->init();
      sproutlets.push_front(_auth_sproutlet);
    }
  }

  return ok;
}


/// Unloads the S-CSCF plug-in.
void SCSCFPlugin::unload()
{
  delete _scscf_sproutlet;
  delete _subscription_sproutlet;
  delete _registrar_sproutlet;
  delete _auth_sproutlet; _auth_sproutlet = NULL;
  delete _sess_term_as_alarm; _sess_term_as_alarm = NULL;
  delete _sess_cont_as_alarm; _sess_cont_as_alarm = NULL;
  delete reg_stats_tbls.init_reg_tbl;
  delete reg_stats_tbls.re_reg_tbl;
  delete reg_stats_tbls.de_reg_tbl;
  delete third_party_reg_stats_tbls.init_reg_tbl;
  delete third_party_reg_stats_tbls.re_reg_tbl;
  delete third_party_reg_stats_tbls.de_reg_tbl;
  delete auth_stats_tbls.sip_digest_auth_tbl;
  delete auth_stats_tbls.ims_aka_auth_tbl;
  delete auth_stats_tbls.non_register_auth_tbl;
}
