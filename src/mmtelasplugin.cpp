/**
 * @file mmtelasplugin.cpp  Plug-in wrapper for the MMTEL AS Sproutlet.
 *
 * Copyright (C) Metaswitch Networks 2017
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

class MMTELASPlugin : public SproutletPlugin
{
public:
  MMTELASPlugin();
  ~MMTELASPlugin();

  bool load(struct options& opt, std::list<Sproutlet*>& sproutlets);
  void unload();

private:
  SproutletAppServerShim* _mmtel_sproutlet;
  Mmtel* _mmtel;
  SNMP::IPCountTable* _xdm_cxn_count_tbl;
  SNMP::EventAccumulatorTable* _xdm_latency_tbl;
  XDMConnection* _xdm_connection;
};

/// Export the plug-in using the magic symbol "sproutlet_plugin"
extern "C" {
MMTELASPlugin sproutlet_plugin;
}


MMTELASPlugin::MMTELASPlugin() :
  _mmtel_sproutlet(NULL),
  _mmtel(NULL),
  _xdm_connection(NULL)
{
}

MMTELASPlugin::~MMTELASPlugin()
{
}

/// Loads the MMTEL AS plug-in, returning the supported Sproutlets.
bool MMTELASPlugin::load(struct options& opt, std::list<Sproutlet*>& sproutlets)
{
  bool plugin_loaded = true;

  if (opt.enabled_mmtel)
  {
    TRC_STATUS("MMTel AS plugin enabled");

    SNMP::SuccessFailCountByRequestTypeTable* incoming_sip_transactions = SNMP::SuccessFailCountByRequestTypeTable::create("mmtel_as_incoming_sip_transactions",
                                                                                                                           "1.2.826.0.1.1578918.9.3.24");
    SNMP::SuccessFailCountByRequestTypeTable* outgoing_sip_transactions = SNMP::SuccessFailCountByRequestTypeTable::create("mmtel_as_outgoing_sip_transactions",
                                                                                                                           "1.2.826.0.1.1578918.9.3.25");
    if (opt.xdm_server != "")
    {
      // Create a connection to the XDMS.
      TRC_STATUS("Creating connection to XDMS %s", opt.xdm_server.c_str());
      _xdm_cxn_count_tbl = SNMP::IPCountTable::create("homer-ip-count",
                                                          ".1.2.826.0.1.1578918.9.3.2.1");
      _xdm_latency_tbl = SNMP::EventAccumulatorTable::create("homer-latency",
                                                          ".1.2.826.0.1.1578918.9.3.2.2");
      _xdm_connection = new XDMConnection(opt.xdm_server,
                                          http_resolver,
                                          load_monitor,
                                          _xdm_cxn_count_tbl,
                                          _xdm_latency_tbl);

      // Load the MMTEL AppServer
      _mmtel = new Mmtel(opt.prefix_mmtel, _xdm_connection);
      _mmtel_sproutlet = new SproutletAppServerShim(_mmtel,
                                                    opt.port_mmtel,
                                                    opt.uri_mmtel,
                                                    incoming_sip_transactions,
                                                    outgoing_sip_transactions,
                                                    "mmtel." + opt.home_domain);
      sproutlets.push_back(_mmtel_sproutlet);
    }
  }
  return plugin_loaded;
}

/// Unloads the MMTEL AS plug-in.
void MMTELASPlugin::unload()
{
  delete _mmtel_sproutlet;
  delete _mmtel;
  delete _xdm_connection;
  delete _xdm_cxn_count_tbl;
  delete _xdm_latency_tbl;
}
