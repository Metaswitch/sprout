/**
 * @file bgcfplugin.cpp  Plug-in wrapper for the BGCF Sproutlet.
 *
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "cfgoptions.h"
#include "acr.h"
#include "sproutletplugin.h"
#include "bgcfservice.h"
#include "bgcfsproutlet.h"
#include "log.h"

class BGCFPlugin : public SproutletPlugin
{
public:
  BGCFPlugin();
  ~BGCFPlugin();

  bool load(struct options& opt, std::list<Sproutlet*>& sproutlets);
  void unload();

private:
  BGCFSproutlet* _bgcf_sproutlet;
  ACRFactory* _acr_factory;
  BgcfService* _bgcf_service;
  SNMP::SuccessFailCountByRequestTypeTable* _incoming_sip_transactions_tbl;
  SNMP::SuccessFailCountByRequestTypeTable* _outgoing_sip_transactions_tbl;
};

/// Export the plug-in using the magic symbol "sproutlet_plugin"
extern "C" {
BGCFPlugin sproutlet_plugin;
}


BGCFPlugin::BGCFPlugin() :
  _bgcf_sproutlet(NULL),
  _acr_factory(NULL),
  _bgcf_service(NULL),
  _incoming_sip_transactions_tbl(NULL),
  _outgoing_sip_transactions_tbl(NULL)
{
}

BGCFPlugin::~BGCFPlugin()
{
  delete _incoming_sip_transactions_tbl;
  delete _outgoing_sip_transactions_tbl;
}

/// Loads the BGCF plug-in, returning the supported Sproutlets.
bool BGCFPlugin::load(struct options& opt, std::list<Sproutlet*>& sproutlets)
{
  bool plugin_loaded = true;

  // Create the SNMP tables here - they should exist based on whether the
  // plugin is loaded, not whether the Sproutlet is enabled, in order to
  // simplify SNMP polling of multiple differently-configured Sprout nodes.
  _incoming_sip_transactions_tbl = SNMP::SuccessFailCountByRequestTypeTable::create("bgcf_incoming_sip_transactions",
                                                                                    "1.2.826.0.1.1578918.9.3.22");
  _outgoing_sip_transactions_tbl = SNMP::SuccessFailCountByRequestTypeTable::create("bgcf_outgoing_sip_transactions",
                                                                                    "1.2.826.0.1.1578918.9.3.23");
  if (opt.enabled_bgcf)
  {
    TRC_STATUS("BGCF plugin enabled");

    // Create BGCF service required for the BGCF Sproutlet.
    _bgcf_service = new BgcfService();

    // Create the BGCF ACR factory.
    _acr_factory = (ralf_processor != NULL) ?
                       (ACRFactory*)new RalfACRFactory(ralf_processor, ACR::BGCF) :
                       new ACRFactory();

    // Create the Sproutlet.
    _bgcf_sproutlet = new BGCFSproutlet(opt.prefix_bgcf,
                                        opt.port_bgcf,
                                        opt.uri_bgcf,
                                        _bgcf_service,
                                        enum_service,
                                        _acr_factory,
                                        _incoming_sip_transactions_tbl,
                                        _outgoing_sip_transactions_tbl,
                                        opt.override_npdi);

    sproutlets.push_back(_bgcf_sproutlet);
  }

  return plugin_loaded;
}

/// Unloads the BGCF plug-in.
void BGCFPlugin::unload()
{
  delete _bgcf_sproutlet;
  delete _acr_factory;
  delete _bgcf_service;
}
