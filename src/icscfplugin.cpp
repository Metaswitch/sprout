/**
 * @file icscfplugin.cpp  Plug-in wrapper for the I-CSCF Sproutlet.
 *
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "cfgoptions.h"
#include "sproutletplugin.h"
#include "stack.h"
#include "scscfselector.h"
#include "icscfsproutlet.h"
#include "log.h"

class ICSCFPlugin : public SproutletPlugin
{
public:
  ICSCFPlugin();
  ~ICSCFPlugin();

  bool load(struct options& opt, std::list<Sproutlet*>&);
  void unload();

private:
  ICSCFSproutlet* _icscf_sproutlet;
  ACRFactory* _acr_factory;
  SCSCFSelector* _scscf_selector;
  SNMP::SuccessFailCountByRequestTypeTable* _incoming_sip_transactions_tbl;
  SNMP::SuccessFailCountByRequestTypeTable* _outgoing_sip_transactions_tbl;
};

/// Export the plug-in using the magic symbol "sproutlet_plugin"
extern "C" {
ICSCFPlugin sproutlet_plugin;
}

ICSCFPlugin::ICSCFPlugin() :
  _icscf_sproutlet(NULL),
  _acr_factory(NULL),
  _scscf_selector(NULL)
{
}

ICSCFPlugin::~ICSCFPlugin()
{
}

/// Loads the I-CSCF plug-in, returning the supported Sproutlets.
bool ICSCFPlugin::load(struct options& opt, std::list<Sproutlet*>& sproutlets)
{
  bool plugin_loaded = true;

  // Create the SNMP tables here - they should exist based on whether the
  // plugin is loaded, not whether the Sproutlet is enabled, in order to
  // simplify SNMP polling of multiple differently-configured Sprout nodes.
  _incoming_sip_transactions_tbl = SNMP::SuccessFailCountByRequestTypeTable::create("icscf_incoming_sip_transactions",
                                                                                    "1.2.826.0.1.1578918.9.3.18");
  _outgoing_sip_transactions_tbl = SNMP::SuccessFailCountByRequestTypeTable::create("icscf_outgoing_sip_transactions",
                                                                                    "1.2.826.0.1.1578918.9.3.19");

  if (opt.enabled_icscf)
  {
    TRC_STATUS("I-CSCF plugin enabled");

    // Create the S-CSCF selector.
    _scscf_selector = new SCSCFSelector(opt.uri_scscf);

    // Create the I-CSCF ACR factory.
    _acr_factory = (ralf_processor != NULL) ?
                        (ACRFactory*)new RalfACRFactory(ralf_processor, ACR::ICSCF) :
                        new ACRFactory();

    // Create the I-CSCF sproutlet.
    _icscf_sproutlet = new ICSCFSproutlet(opt.prefix_icscf,
                                          opt.uri_bgcf,
                                          opt.port_icscf,
                                          opt.uri_icscf,
                                          opt.prefix_icscf,
                                          "",
                                          hss_connection,
                                          _acr_factory,
                                          _scscf_selector,
                                          enum_service,
                                          _incoming_sip_transactions_tbl,
                                          _outgoing_sip_transactions_tbl,
                                          opt.override_npdi,
                                          opt.port_icscf,
                                          opt.blacklisted_scscfs);
    _icscf_sproutlet->init();

    sproutlets.push_back(_icscf_sproutlet);
  }

  return plugin_loaded;
}

/// Unloads the I-CSCF plug-in.
void ICSCFPlugin::unload()
{
  delete _icscf_sproutlet;
  delete _acr_factory;
  delete _scscf_selector;
  delete _incoming_sip_transactions_tbl;
  delete _outgoing_sip_transactions_tbl;
}
