/**
 * @file mangelwurzelplugin.cpp Plug-in wrapper for the mangelwurzel sproutlet.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "cfgoptions.h"
#include "acr.h"
#include "sproutletplugin.h"
#include "mangelwurzel.h"

class MangelwurzelPlugin : public SproutletPlugin
{
public:
  MangelwurzelPlugin();
  ~MangelwurzelPlugin();

  bool load(struct options& opt, std::list<Sproutlet*>& sproutlets);
  void unload();

private:
  Mangelwurzel* _mangelwurzel;
};

/// Export the plug-in using the magic symbol "sproutlet_plugin"
extern "C" {
MangelwurzelPlugin sproutlet_plugin;
}

MangelwurzelPlugin::MangelwurzelPlugin() :
  _mangelwurzel(NULL)
{
}

MangelwurzelPlugin::~MangelwurzelPlugin()
{
}

/// Loads the mangelwurzel plug-in, returning the supported Sproutlets.
bool MangelwurzelPlugin::load(struct options& opt, std::list<Sproutlet*>& sproutlets)
{
  bool plugin_loaded = true;

  if (opt.enabled_mangelwurzel)
  {
    // Create the Sproutlet.
    _mangelwurzel = new Mangelwurzel(opt.prefix_mangelwurzel,
                                     opt.port_mangelwurzel,
                                     opt.uri_mangelwurzel);

    sproutlets.push_back(_mangelwurzel);
  }

  return plugin_loaded;
}

/// Unloads the mangelwurzel plug-in.
void MangelwurzelPlugin::unload()
{
  delete _mangelwurzel;
}
