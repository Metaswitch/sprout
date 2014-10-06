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
void PluginLoader::load(std::list<Sproutlet*>& sproutlets)
{
  LOG_STATUS("Loading plug-ins from %s", _path.c_str());

  DIR* d = opendir(_path.c_str());

  if (d != NULL)
  {
    struct dirent *de;
    while ((de = readdir(d)) != NULL)
    {
      if (de->d_type == DT_REG)
      {
        // Regular file, so attempt to load any sproutlets in it.
        // (We don't bother checking the file name as this isn't a reliable
        // indication that the file is a shared object.)
        Plugin p;
        p.name = _path + "/";
        p.name.append(de->d_name);
        p.handle = NULL;
        p.plugin = NULL;
        LOG_STATUS("Attempt to load plug-in %s", p.name.c_str());

        dlerror();
        p.handle = dlopen(p.name.c_str(), RTLD_NOW);
        if (p.handle != NULL)
        {
          p.plugin = static_cast<SproutletPlugin*>(dlsym(p.handle, "sproutlet_plugin"));

          if (p.plugin != NULL)
          {
            std::list<Sproutlet*> plugin_sproutlets = p.plugin->load(_opt);

            for (std::list<Sproutlet*>::const_iterator i = plugin_sproutlets.begin();
                 i != plugin_sproutlets.end();
                 ++i)
            {
              Sproutlet* s = *i;
              LOG_DEBUG("Sproutlet %s using API version %d",
                         s->service_name().c_str(), s->api_version());
              if (api_supported(s->api_version()))
              {
                // The API version required by the sproutlet is supported.
                sproutlets.push_back(s);
                LOG_STATUS("Loaded sproutlet %s using API version %d",
                           s->service_name().c_str(), s->api_version());
              }
              else
              {
                // The API version required by the sproutlet is not supported.
                LOG_ERROR("Sproutlet %s requires unsupported API version %d",
                          s->service_name().c_str(), s->api_version());
              }
            }
          }
        }

        if (p.plugin != NULL)
        {
          // Add shared object to the list of loaded plugins.
          _loaded.push_back(p);
        }
        else
        {
          LOG_ERROR("Error loading Sproutlet plug-in %s - %s",
                    p.name.c_str(), dlerror());
          if (p.handle != NULL)
          {
            dlclose(p.handle);
          }
        }
      }
    }
    closedir(d);
  }

  LOG_STATUS("Finished loading plug-ins");
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
