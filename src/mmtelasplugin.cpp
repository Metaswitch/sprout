/**
 * @file mmtelasplugin.cpp  Plug-in wrapper for the MMTEL AS Sproutlet.
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
