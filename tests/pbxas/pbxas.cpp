/**
 * @file pbxas.cpp  Plug-in wrapper for an example PBX TAS.
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


