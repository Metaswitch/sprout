/**
 * @file pluginloader.cpp  Class responsible for loading and unloading
 *                         Sproutlet plug-ins.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
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

      // Clear any dynamic load errors
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
