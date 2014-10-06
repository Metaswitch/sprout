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

class MMTELASPlugin : public SproutletPlugin
{
public:
  MMTELASPlugin();
  ~MMTELASPlugin();

  std::list<Sproutlet*> load(struct options& opt);
  void unload();

private:
  SproutletAppServerShim* _mmtel_sproutlet;
  Mmtel* _mmtel;
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
std::list<Sproutlet*> MMTELASPlugin::load(struct options& opt)
{
  std::list<Sproutlet*> sproutlets;

  if (opt.xdm_server != "")
  {
    // Create a connection to the XDMS.
    LOG_STATUS("Creating connection to XDMS %s", opt.xdm_server.c_str());
    _xdm_connection = new XDMConnection(opt.xdm_server,
                                        http_resolver,
                                        load_monitor,
                                        stack_data.stats_aggregator);

    // Load the MMTEL AppServer
    _mmtel = new Mmtel("mmtel", _xdm_connection);
    _mmtel_sproutlet = new SproutletAppServerShim(_mmtel, "mmtel." + opt.home_domain);
    sproutlets.push_back(_mmtel_sproutlet);
  }

  return sproutlets;
}

/// Unloads the MMTEL AS plug-in.
void MMTELASPlugin::unload()
{
  delete _mmtel_sproutlet;
  delete _mmtel;
  delete _xdm_connection;
}
