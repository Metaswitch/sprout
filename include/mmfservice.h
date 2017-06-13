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

  /// Return whether we should invoke MMF prior to routing a message to the
  /// passed in Application Server
  const bool apply_mmf_pre_as(std::string address);

  /// Return whether we should invoke MMF after routing a message to the
  /// passed in Application Server
  const bool apply_mmf_post_as(std::string address);

private:
  MMFService(const MMFService&) = delete;  // Prevent implicit copying

  /// These methods are private as they are not part of the API.  You should
  /// access the mmf config via the public 'apply_mmf_*' methods.
  inline const bool has_config_for_address(std::string address)
  {
    return (_mmf_config->find(address) != _mmf_config->end());
  }

  /// This raises an exception is the passed in address is not present in the
  /// mmf_config map.  Any function calling this must handle this exception.
  inline const MMFTargetPtr get_address_config(std::string address)
  {
    return _mmf_config->at(address);
  }

  Alarm* _alarm;
  std::string _configuration;
  Updater<void, MMFService>* _updater;

  /// The atomic properties of shared_ptr values prevent the need for locking
  std::shared_ptr<MMFService::MMFMap> _mmf_config;

  /// Helper functions to set/clear the alarm.
  void set_alarm();
  void clear_alarm();
};

#endif
