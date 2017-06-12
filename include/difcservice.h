/**
 * @file difcservice.h Support for Default iFCs.
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
#include "rapidxml/rapidxml.hpp"

#include "updater.h"
#include "ifc.h"
#include "alarm.h"

#ifndef DIFCSERVICE_H__
#define DIFCSERVICE_H__

class DIFCService
{
public:
  DIFCService(Alarm* alarm,
              std::string configuration = "/etc/clearwater/default_ifcs.xml");
  ~DIFCService();

  // Node names within the Default iFC configuration file.
  const char* const DEFAULT_IFCS_SET = "DefaultIFCsSet";

  /// Updates the default iFCs.
  void update_difcs();

  /// Get the default IFCs
  std::vector<Ifc> get_default_ifcs(rapidxml::xml_document<>* ifc_doc) const;

private:
  Alarm* _alarm;
  std::vector<std::string> _default_ifcs;
  std::string _configuration;
  Updater<void, DIFCService>* _updater;

  // Mark as mutable to flag that this can be modified without affecting the
  // external behaviour of the calss, allowing for locking in 'const' methods.
  mutable boost::shared_mutex _sets_rw_lock;

  // Helper functions to set/clear the alarm.
  void set_alarm();
  void clear_alarm();
};

#endif

