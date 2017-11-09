/**
 * @file rphservice.h - Service for loading and managaing RPH configuration
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef RPHSERVICE_H__
#define RPHSERVICE_H__

#include <map>
#include <string>
#include <boost/thread.hpp>

#include "updater.h"
#include "sas.h"
#include "alarm.h"

class RPHService
{
public:
  RPHService(Alarm* alarm,
              std::string configuration = "./rph.json");
  virtual ~RPHService();

  /// Updates the RPH configuration.
  void update_rph();

  /// Lookup the priority of an RPH value.
  int lookup_priority(std::string rph_value);

private:
  Alarm* _alarm;
  std::string _configuration;
  std::map<std::string, int> _rph_map;
  Updater<void, RPHService>* _updater;

  // Mark as mutable to flag that this can be modified without affecting the
  // external behaviour of the class, allowing for locking in 'const' methods.
  mutable boost::shared_mutex _sets_rw_lock;

  // Helper functions to set/clear the alarm.
  void set_alarm();
  void clear_alarm();
};

#endif
