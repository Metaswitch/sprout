/**
 * @file pbxas.cpp  Plug-in wrapper for an example PBX TAS.
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
//#include "sproutletappserver.h"
#include "log.h"
#include "pjutils.h"
#include "custom_headers.h"
#include "constants.h"
extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <pjsip-simple/evsub.h>
}

#include "sproutlet.h"

const std::string TARGET = "sip:54.175.67.146:5060;transport=TCP";
const std::vector<std::string> PATH = {
  "sip:10.239.139.116:5058;transport=TCP;lr",
};

class PbxAppServer;
class PbxAppServerTsx;

class PbxAppServer : public Sproutlet
{
public:
  PbxAppServer(const std::string& _service_name) : Sproutlet(_service_name) {}

  virtual SproutletTsx* get_tsx(SproutletTsxHelper* helper,
                                const std::string& service_name,
                                pjsip_msg* req);
};

class PbxAppServerTsx : public SproutletTsx
{
public:
  PbxAppServerTsx(SproutletTsxHelper* helper);
  virtual ~PbxAppServerTsx();

  virtual void on_rx_initial_request(pjsip_msg* req);
};

class PbxPlugin : public SproutletPlugin
{
public:
  PbxPlugin() {};
  ~PbxPlugin() {};

  bool load(struct options& opt, std::list<Sproutlet*>& sproutlets);
  void unload();

private:
  PbxAppServer* _sproutlet;
};

/// Export the plug-in using the magic symbol "sproutlet_plugin"
extern "C" {
PbxPlugin sproutlet_plugin;
}

/// Loads the Pbx plug-in, returning the supported Sproutlets.
bool PbxPlugin::load(struct options& opt, std::list<Sproutlet*>& sproutlets)
{
  bool plugin_loaded = true;

  TRC_STATUS("Loading PBX AS sproutlet");

  // Create the Sproutlet.
  _sproutlet = new PbxAppServer("pbxas");
  sproutlets.push_back(_sproutlet);

  return plugin_loaded;
}

/// Unloads the Pbx plug-in.
void PbxPlugin::unload()
{
  delete _sproutlet; _sproutlet = NULL;
}

SproutletTsx* PbxAppServer::get_tsx(SproutletTsxHelper* helper,
                                    const std::string& service_name,
                                    pjsip_msg* req)
{
  return new PbxAppServerTsx(helper);
}

PbxAppServerTsx::PbxAppServerTsx(SproutletTsxHelper* helper) :
  SproutletTsx(helper)
{
}

/// Destructor
PbxAppServerTsx::~PbxAppServerTsx()
{
}

void PbxAppServerTsx::on_rx_initial_request(pjsip_msg* req)
{
  TRC_DEBUG("PbxAS - process request %p", req);

  req->line.req.uri = PJUtils::uri_from_string(TARGET, get_pool(req));

  for(std::vector<std::string>::const_iterator p = PATH.begin();
      p != PATH.end();
      ++p)
  {
    pjsip_route_hdr* route_hdr = pjsip_route_hdr_create(get_pool(req));
    route_hdr->name_addr.uri = PJUtils::uri_from_string(*p, get_pool(req));
    pjsip_msg_add_hdr(req, (pjsip_hdr*)route_hdr); route_hdr = NULL;
  }

  send_request(req);
}


