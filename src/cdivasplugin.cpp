/**
 * @file cdivasplugin.cpp  Plug-in wrapper for the CDiv AS Sproutlet.
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
#include "sproutletappserver.h"
#include "mmtel.h"
#include "log.h"

class CDivASPlugin : public SproutletPlugin
{
public:
  CDivASPlugin();
  ~CDivASPlugin();

  bool load(struct options& opt, std::list<Sproutlet*>& sproutlets);
  void unload();

private:
  SproutletAppServerShim* _cdiv_sproutlet;
  CallDiversionAS* _cdiv;
};

/// Export the plug-in using the magic symbol "sproutlet_plugin"
extern "C" {
CDivASPlugin sproutlet_plugin;
}


CDivASPlugin::CDivASPlugin() :
  _cdiv_sproutlet(NULL),
  _cdiv(NULL)
{
}

CDivASPlugin::~CDivASPlugin()
{
}

/// Loads the CDiv AS plug-in, returning the supported Sproutlets.
bool CDivASPlugin::load(struct options& opt, std::list<Sproutlet*>& sproutlets)
{
  bool plugin_loaded = true;

  if (opt.enabled_cdiv)
  {
    TRC_STATUS("CDIV plugin enabled");

    SNMP::SuccessFailCountByRequestTypeTable* incoming_sip_transactions = SNMP::SuccessFailCountByRequestTypeTable::create("cdiv_as_incoming_sip_transactions",
                                                                                                                           "1.2.826.0.1.1578918.9.7.2");
    SNMP::SuccessFailCountByRequestTypeTable* outgoing_sip_transactions = SNMP::SuccessFailCountByRequestTypeTable::create("cdiv_as_outgoing_sip_transactions",
                                                                                                                         "1.2.826.0.1.1578918.9.7.3");
    // Load the CDiv AppServer
    _cdiv = new CallDiversionAS(opt.prefix_cdiv);
    _cdiv_sproutlet = new SproutletAppServerShim(_cdiv,
                                                 opt.port_cdiv,
                                                 opt.uri_cdiv,
                                                 incoming_sip_transactions,
                                                 outgoing_sip_transactions);
    sproutlets.push_back(_cdiv_sproutlet);
  }

  return plugin_loaded;
}

/// Unloads the CDiv AS plug-in.
void CDivASPlugin::unload()
{
  delete _cdiv_sproutlet;
  delete _cdiv;
}
