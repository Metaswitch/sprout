/**
 * @file pluginloader.h  Sproutlet plug-in loader.
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
