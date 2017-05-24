/**
 * @file pluginloader.cpp  Class responsible for loading and unloading
 *                         Sproutlet plug-ins.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


#include <dirent.h>
#include <dlfcn.h>

#include "log.h"
#include "pluginloader.h"

/// Create a PluginLoader to load plugins from the specified path with the
/// supplied configuration options.
PluginLoader::PluginLoader(const std::string& path, struct options& opt) :
  _path(path),
  _opt(opt),
  _loaded()
{
}

/// Destroy the PluginLoader.
PluginLoader::~PluginLoader()
{
  unload();
}

/// Load the plug-ins, returning the resulting list of Sproutlets.
bool PluginLoader::load(std::list<Sproutlet*>& sproutlets)
{
  TRC_STATUS("Loading plug-ins from %s", _path.c_str());
  bool plugins_loaded = true;

  DIR* d = opendir(_path.c_str());

  if (d != NULL)
  {
    struct dirent *de;
    while ((de = readdir(d)) != NULL)
    {
      // The file name isn't a reliable indication that the file is a shared
      // object, but checking for a ".so" extension filters out files like "."
      // and ".." and prevents spurious error logs. If a file isn't a valid
      // shared object, dlopen will return NULL and we'll log an error.

      // We don't check the file type as given by de->d_type - this would also
      // filter out directories like "." and "..", but some filesystems like
      // XFS don't support this.
      Plugin p;
      p.name = _path + "/";
      p.name.append(de->d_name);
      p.handle = NULL;
      p.plugin = NULL;

      if (p.name.compare(p.name.length() - 3, 3, ".so") != 0)
      {
        TRC_DEBUG("Skipping %s - doesn't have .so extension", p.name.c_str());
        continue;
      }

      TRC_STATUS("Attempt to load plug-in %s", p.name.c_str());

      // Clear any dynamic load errors
      dlerror();

      p.handle = dlopen(p.name.c_str(), RTLD_NOW);

      if (p.handle == NULL)
      {
        TRC_ERROR("Error loading Sproutlet plug-in %s - %s",
                  p.name.c_str(), dlerror());
        plugins_loaded = false;
        break;
      }

      // Clear any dynamic load errors. It's safest to simply call dlerror
      // prior to any dl*() call. In theory, we could have succesfully
      // loaded a shared object, which itself had an optional dependency on
      // another shared object that failed to load. In order to prevent us
      // seeing any spurious errors unrelated to the dsym call, clear out
      // any dynamic load errors which have been stored off.
      dlerror();

      p.plugin = static_cast<SproutletPlugin*>(dlsym(p.handle, "sproutlet_plugin"));

      if (p.plugin == NULL)
      {
        TRC_ERROR("Failed to load Sproutlet plug-in %s - %s",
                  p.name.c_str(), dlerror());
        plugins_loaded = false;
        break;
      }

      std::list<Sproutlet*> plugin_sproutlets;
      plugins_loaded = p.plugin->load(_opt, plugin_sproutlets);

      if (!plugins_loaded)
      {
        // There was an error loading one of the plugins. Return an error
        // now so that Sprout is killed, rather than running with
        // unexpected plugins.
        TRC_ERROR("Failed to successfully load plug-in %s", p.name.c_str());
        break;
      }

      for (std::list<Sproutlet*>::const_iterator i = plugin_sproutlets.begin();
           i != plugin_sproutlets.end();
           ++i)
      {
        Sproutlet* s = *i;
        TRC_DEBUG("Sproutlet %s using API version %d",
                  s->service_name().c_str(), s->api_version());

        if (api_supported(s->api_version()))
        {
          // The API version required by the sproutlet is supported.
          sproutlets.push_back(s);
          TRC_STATUS("Loaded sproutlet %s using API version %d",
                     s->service_name().c_str(), s->api_version());
        }
        else
        {
          // The API version required by the sproutlet is not supported.
          TRC_ERROR("Sproutlet %s requires unsupported API version %d",
                    s->service_name().c_str(), s->api_version());
          plugins_loaded = false;
          break;
        }
      }

      if (!plugins_loaded)
      {
        break;
      }

      // Add shared object to the list of loaded plugins.
      _loaded.push_back(p);
    }

    closedir(d);
  }

  TRC_STATUS("Finished loading plug-ins");
  return plugins_loaded;
}

/// Unload all the loaded plug-ins.
void PluginLoader::unload()
{
  while (!_loaded.empty())
  {
    Plugin p = _loaded.front();
    p.plugin->unload();
    dlclose(p.handle);
    _loaded.pop_front();
  }
}

/// Check whether the specified API version is supported.
bool PluginLoader::api_supported(int version)
{
  if (version == 1)
  {
    // Only version 1 of the API is currently supported.
    return true;
  }
  return false;
}
