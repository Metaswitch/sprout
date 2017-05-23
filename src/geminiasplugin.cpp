/**
 * @file geminiasplugin.cpp  Plug-in wrapper for the Gemini Sproutlet.
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
#include "mobiletwinned.h"
#include "sproutletappserver.h"
#include "log.h"

class GeminiPlugin : public SproutletPlugin
{
public:
  GeminiPlugin();
  ~GeminiPlugin();

  bool load(struct options& opt, std::list<Sproutlet*>& sproutlets);
  void unload();

private:
  MobileTwinnedAppServer* _gemini;
  SproutletAppServerShim* _gemini_sproutlet;
};

/// Export the plug-in using the magic symbol "sproutlet_plugin"
extern "C" {
GeminiPlugin sproutlet_plugin;
}


GeminiPlugin::GeminiPlugin() :
  _gemini(NULL),
  _gemini_sproutlet(NULL)
{
}

GeminiPlugin::~GeminiPlugin()
{
}

/// Loads the Gemini plug-in, returning the supported Sproutlets.
bool GeminiPlugin::load(struct options& opt, std::list<Sproutlet*>& sproutlets)
{
  bool plugin_loaded = true;

  if (opt.enabled_gemini)
  {
    TRC_STATUS("Gemini plugin enabled");

    SNMP::SuccessFailCountByRequestTypeTable* incoming_sip_transactions = SNMP::SuccessFailCountByRequestTypeTable::create("gemini_as_incoming_sip_transactions",
                                                                                                                           "1.2.826.0.1.1578918.9.11.1");
    SNMP::SuccessFailCountByRequestTypeTable* outgoing_sip_transactions = SNMP::SuccessFailCountByRequestTypeTable::create("gemini_as_outgoing_sip_transactions",
                                                                                                                           "1.2.826.0.1.1578918.9.11.2");
    // Create the Sproutlet.
    _gemini = new MobileTwinnedAppServer(opt.prefix_gemini);
    _gemini_sproutlet = new SproutletAppServerShim(_gemini,
                                                   opt.port_gemini,
                                                   opt.uri_gemini,
                                                   incoming_sip_transactions,
                                                   outgoing_sip_transactions);

    sproutlets.push_back(_gemini_sproutlet);
  }

  return plugin_loaded;
}

/// Unloads the Gemini plug-in.
void GeminiPlugin::unload()
{
  delete _gemini_sproutlet;
  delete _gemini;
}
