/**
 * @file fifcservice.h Support for fallback iFCs.
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
#include "rapidxml/rapidxml.hpp"

#include "updater.h"
#include "ifc.h"
#include "alarm.h"

#ifndef FIFCSERVICE_H__
#define FIFCSERVICE_H__

class FIFCService
{
public:
  FIFCService(Alarm* alarm,
              std::string configuration = "/etc/clearwater/fallback_ifcs.xml");
  ~FIFCService();

  // Node names within the fallback iFC configuration file.
  const char* const FALLBACK_IFCS_SET = "FallbackIFCsSet";

  /// Updates the fallback iFCs.
  void update_fifcs();

  /// Get the fallback IFCs
  std::vector<Ifc> get_fallback_ifcs(rapidxml::xml_document<>* ifc_doc) const;

private:
  Alarm* _alarm;
  std::vector<std::string> _fallback_ifcs;
  std::string _configuration;
  Updater<void, FIFCService>* _updater;

  // Mark as mutable to flag that this can be modified without affecting the
  // external behaviour of the calss, allowing for locking in 'const' methods.
  mutable boost::shared_mutex _sets_rw_lock;

  // Helper functions to set/clear the alarm.
  void set_alarm();
  void clear_alarm();
};

#endif

