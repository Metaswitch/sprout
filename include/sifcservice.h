/**
 * @file sifcservice.h
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef SIFCSERVICE_H__
#define SIFCSERVICE_H__

#include <map>
#include <string>
#include <boost/thread.hpp>
#include "rapidxml/rapidxml.hpp"
#include <functional>

#include "updater.h"
#include "sas.h"
#include "ifc.h"
#include "alarm.h"
#include "snmp_counter_table.h"

class SIFCService
{
public:
  SIFCService(Alarm* alarm,
              SNMP::CounterTable* no_shared_ifcs_set_tbl,
              std::string configuration = "./shared_ifcs.xml");
  virtual ~SIFCService();

  // Node names within the Shared IFC configuration file.
  const char* const SHARED_IFCS_SETS = "SharedIFCsSets";
  const char* const SHARED_IFCS_SET = "SharedIFCsSet";
  const char* const SET_ID = "SetID";

  /// Updates the shared IFC sets
  void update_sets();

  /// Get the IFCs that belong to a set of IDs
  virtual void get_ifcs_from_id(std::multimap<int32_t, Ifc>& ifc_map,
                                const std::set<int32_t>& id,
                                std::shared_ptr<xml_document<> > ifc_doc,
                                SAS::TrailId trail) const;

private:
  Alarm* _alarm;
  SNMP::CounterTable* _no_shared_ifcs_set_tbl;
  std::map<int32_t, std::vector<std::pair<int32_t, std::string>>> _shared_ifc_sets;
  std::string _configuration;
  Updater<void, SIFCService>* _updater;

  // Mark as mutable to flag that this can be modified without affecting the
  // external behaviour of the class, allowing for locking in 'const' methods.
  mutable boost::shared_mutex _sets_rw_lock;

  // Helper functions to set/clear the alarm.
  void set_alarm();
  void clear_alarm();
};

#endif
