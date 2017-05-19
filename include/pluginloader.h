/**
 * @file pluginloader.h  Sproutlet plug-in loader.
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef PLUGINLOADER_H__
#define PLUGINLOADER_H__

#include "cfgoptions.h"
#include "sproutlet.h"
#include "sproutletplugin.h"

class PluginLoader
{
public:
  PluginLoader(const std::string& path, struct options& opt);
  ~PluginLoader();

  /// Loads the plug-ins and populates the resulting list of Sproutlets
  /// Returns whether we hit issues loading the plugins and should 
  /// therefore exit
  bool load(std::list<Sproutlet*>& sproutlets);

  /// Unloads all plug-ins that have been successfully loaded.
  void unload();

private:
  /// Checks whether the API version is supported by this system.
  bool api_supported(int version);

  /// Path to load plug-ins from.
  std::string _path;

  /// Command line options.
  struct options& _opt;

  /// Structure maintained for each plugin that is successfully loaded.
  typedef struct
  {
    std::string name;
    void* handle;
    SproutletPlugin* plugin;
  } Plugin;

  /// List of successfully loaded plugins.
  std::list<Plugin> _loaded;
};

#endif
