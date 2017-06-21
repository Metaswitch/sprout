/**
 * @file mmfservice.h Support for MMF function.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <string>
#include <boost/thread.hpp>
#include "rapidjson/document.h"

#include "mmftargets.h"
#include "updater.h"
#include "alarm.h"


#ifndef MMFSERVICE_H__
#define MMFSERVICE_H__

class MMFService
{
public:
  MMFService(Alarm* alarm,
             std::string configuration = "/etc/clearwater/mmf_targets.json");
  ~MMFService();

  /// Shared pointer to a piece of config in the mmf_targets.json file
  typedef std::shared_ptr<MMFTarget> MMFTargetPtr;

  /// A map from Application Server addresses, to the MMF configuration
  /// associated with the address
  typedef std::map<std::string, MMFTargetPtr> MMFMap;

  /// Updates the MMF Config
  void update_config();

  /// Read the rapidjson representation of the mmf_targets.json file, and
  /// return an MMFMap representation of the config file.
  ///
  /// Raises an error if the passed in configuration is invalid
  std::shared_ptr<MMFService::MMFMap> read_config(rapidjson::Document& config);

  /// Return a shared_ptr to the MMFTarget object for the passed in server.
  /// Returns a nullptr if we don't have config for the server.
  MMFTargetPtr get_config_for_server(std::string server_domain);

private:
  MMFService(const MMFService&) = delete;  // Prevent implicit copying

  Alarm* _alarm;
  std::string _configuration;
  Updater<void, MMFService>* _updater;

  /// Locking of the mmf_config relies on the atomic nature of shared pointers.
  /// The updater method replaces the config with an entire new map, and the
  /// accessor methods take a shared_ptr to the MMFMap.

  /// This is never modified dynamically, nor read incrementally.  If you wish
  /// to do either of the above, you must think about the locking consequences
  std::shared_ptr<MMFService::MMFMap> _mmf_config;

  /// Helper functions to set/clear the alarm.
  void set_alarm();
  void clear_alarm();
};

#endif
