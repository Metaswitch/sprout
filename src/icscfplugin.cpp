/**
 * @file icscfplugin.cpp  Plug-in wrapper for the I-CSCF Sproutlet.
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
#include "stack.h"
#include "scscfselector.h"
#include "icscfsproutlet.h"

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
                                          hss_connection,
                                          _acr_factory,
                                          _scscf_selector,
                                          enum_service,
                                          _incoming_sip_transactions_tbl,
                                          _outgoing_sip_transactions_tbl,
                                          opt.override_npdi);
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
