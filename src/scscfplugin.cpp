/**
 * @file scscfplugin.cpp  Plug-in wrapper for the S-CSCF Sproutlet.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2014  Metaswitch Networks Ltd
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
  _outgoing_sip_transactions_tbl(NULL)
{
}

SCSCFPlugin::~SCSCFPlugin()
{
  delete _incoming_sip_transactions_tbl;
  delete _outgoing_sip_transactions_tbl;
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
      std::string node_host(stack_data.local_host.ptr, stack_data.public_host.slen);

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
                                          opt.uri_scscf,
                                          scscf_node_uri,
                                          icscf_uri,
                                          opt.uri_bgcf,
                                          0,
                                          "",
                                          local_sdm,
                                          remote_sdms,
                                          hss_connection,
                                          enum_service,
                                          scscf_acr_factory,
                                          _incoming_sip_transactions_tbl,
                                          _outgoing_sip_transactions_tbl,
                                          opt.override_npdi,
                                          opt.session_continued_timeout_ms,
                                          opt.session_terminated_timeout_ms,
                                          sess_term_as_tracker,
                                          sess_cont_as_tracker);
    ok = ok && _scscf_sproutlet->init();
    sproutlets.push_front(_scscf_sproutlet);

    _subscription_sproutlet = new SubscriptionSproutlet(SUBSCRIPTION_SERVICE_NAME,
                                                        0,
                                                        "",
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
                                                  SUBSCRIPTION_SERVICE_NAME,
                                                  local_sdm,
                                                  remote_sdms,
                                                  hss_connection,
                                                  scscf_acr_factory,
                                                  opt.reg_max_expires,
                                                  opt.force_third_party_register_body,
                                                  &reg_stats_tbls,
                                                  &third_party_reg_stats_tbls);

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
                                    REGISTRAR_SERVICE_NAME,
                                    {opt.prefix_scscf},
                                    opt.auth_realm,
                                    impi_store,
                                    hss_connection,
                                    chronos_connection,
                                    scscf_acr_factory,
                                    opt.non_register_auth_mode,
                                    analytics_logger,
                                    &auth_stats_tbls,
                                    opt.nonce_count_supported,
                                    std::bind(&RegistrarSproutlet::expiry_for_binding,
                                              _registrar_sproutlet,
                                              std::placeholders::_1,
                                              std::placeholders::_2));
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
