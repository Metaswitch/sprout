/**
 * @file difcservice.h Support for Default iFCs.
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <string>
#include <boost/thread.hpp>
#include "rapidjson/document.h"

#include "mmf.h"
#include "updater.h"
#include "alarm.h"


#ifndef MMFSERVICE_H__
#define MMFSERVICE_H__

class MMFService
{
public:
  MMFService(Alarm* alarm,
             std::string configuration = "/etc/clearwater/mmf.json");
  ~MMFService();

  /// Updates the MMF AS Config
  void update_config();

  void read_config(std::map<std::string, MMFCfg::ptr>& mmf_config,
                   rapidjson::Document&);

  const MMFCfg::ptr get_mmf_config(std::string address)
  {
    return _mmf_config.at(address);
  }

  bool have_mmf_config(std::string address)
  {
    return _mmf_config.count(address);
  }

  boost::shared_mutex& get_mmf_rw_lock() {return _mmf_rw_lock;};

private:
  MMFService(const MMFService&) = delete;  // Prevent implicit copying

  Alarm* _alarm;
  std::map<std::string, MMFCfg::ptr> _mmf_config;
  std::string _configuration;
  Updater<void, MMFService>* _updater;

  // Mark as mutable to flag that this can be modified without affecting the
  // external behaviour of the calss, allowing for locking in 'const' methods.
  mutable boost::shared_mutex _mmf_rw_lock;

  // Helper functions to set/clear the alarm.
  void set_alarm();
  void clear_alarm();
};

#endif

