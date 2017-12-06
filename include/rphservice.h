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
#include <boost/algorithm/string.hpp>

#include "updater.h"
#include "sip_event_priority.h"
#include "sas.h"
#include "alarm.h"

/// These vector contains the 5 IANA namespaces which are defined in RFC 4412
/// section 12.6.
static std::vector<std::vector<std::string>> RPH_NAMESPACES =
{
  {"wps.4", "wps.3", "wps.2", "wps.1", "wps.0"},
  {"ets.4", "ets.3", "ets.2", "ets.1", "ets.0"},
  {"q735.4", "q735.3", "q735.2", "q735.1", "q735.0"},
  {"dsn.routine", "dsn.priority", "dsn.immediate", "dsn.flash", "dsn.flash-override"},
  {"drsn.routine", "drsn.priority", "drsn.immediate", "drsn.flash", "drsn.flash-override", "drsn.flash-override-override"}
};

class RPHService
{
public:
  RPHService(Alarm* alarm,
             std::string configuration = "./rph.json");
  virtual ~RPHService();

  /// Updates the RPH configuration.
  void update_rph();

  /// Lookup the priority of an RPH value.
  virtual SIPEventPriorityLevel lookup_priority(std::string rph_value,
                                                SAS::TrailId trail);

private:
  Alarm* _alarm;
  std::string _configuration;

  // RFC 4412 section 3.1 states that RPH values are case-insensitive, so write
  // a case-insensitive compare function to pass to the map.
  struct str_cmp_ci
  {
    bool operator() (std::string k1, std::string k2) const
    {
      boost::algorithm::to_lower(k1);
      boost::algorithm::to_lower(k2);
      return k1 < k2;
    }
  };
  std::map<std::string, SIPEventPriorityLevel, str_cmp_ci> _rph_map;
  Updater<void, RPHService>* _updater;

  // Mark as mutable to flag that this can be modified without affecting the
  // external behaviour of the class, allowing for locking in 'const' methods.
  mutable boost::shared_mutex _sets_rw_lock;

  // Helper functions to set/clear the alarm.
  void set_alarm();
  void clear_alarm();
};

#endif
