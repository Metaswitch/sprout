/**
 * @file sifcservice.cpp class
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <sys/stat.h>
#include <fstream>
#include <stdlib.h>

#include "sifcservice.h"
#include "log.h"
#include "sas.h"
#include "sproutsasevent.h"
#include "sprout_pd_definitions.h"
#include "utils.h"
#include "rapidxml/rapidxml_print.hpp"

SIFCService::SIFCService(Alarm* alarm,
                         SNMP::CounterTable* no_shared_ifcs_set_tbl,
                         std::string configuration) :
  _alarm(alarm),
  _no_shared_ifcs_set_tbl(no_shared_ifcs_set_tbl),
  _configuration(configuration),
  _updater(NULL)
{
  // Create an updater to keep the shared iFC sets configured appropriately.
  _updater = new Updater<void, SIFCService>
                                (this, std::mem_fun(&SIFCService::update_sets));
}

void SIFCService::update_sets()
{
  // Check whether the file exists.
  struct stat s;
  TRC_DEBUG("stat(%s) returns %d", _configuration.c_str(), stat(_configuration.c_str(), &s));
  if ((stat(_configuration.c_str(), &s) != 0) &&
      (errno == ENOENT))
  {
    TRC_STATUS("No shared iFCs configuration (file %s does not exist)",
               _configuration.c_str());
    CL_SPROUT_SIFC_FILE_MISSING.log();
    set_alarm();
    return;
  }

  TRC_STATUS("Loading shared iFCs configuration from %s", _configuration.c_str());

  // Read from the file
  std::ifstream fs(_configuration.c_str());
  std::string sifc_str((std::istreambuf_iterator<char>(fs)),
                        std::istreambuf_iterator<char>());

  if (sifc_str == "")
  {
    TRC_ERROR("Failed to read shared iFCs configuration data from %s",
              _configuration.c_str());
    CL_SPROUT_SIFC_FILE_EMPTY.log();
    set_alarm();
    return;
  }

  // Now parse the document
  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;

  try
  {
    root->parse<0>(root->allocate_string(sifc_str.c_str()));
  }
  catch (rapidxml::parse_error& err)
  {
    TRC_ERROR("Failed to parse the shared iFCs configuration data:\n %s\n %s",
              sifc_str.c_str(),
              err.what());
    CL_SPROUT_SIFC_FILE_INVALID_XML.log();
    set_alarm();
    delete root; root = NULL;
    return;
  }

  if (!root->first_node(SIFCService::SHARED_IFCS_SETS))
  {
    TRC_ERROR("Invalid shared iFCs configuration file - missing SharedIFCsSets block");
    CL_SPROUT_SIFC_FILE_MISSING_SHARED_IFCS_SETS.log();
    set_alarm();
    delete root; root = NULL;
    return;
  }

  // At this point, we're definitely going to override the iFCs we've got.
  // Update our map, taking a lock while we do so.
  boost::lock_guard<boost::shared_mutex> write_lock(_sets_rw_lock);
  _shared_ifc_sets.clear();
  bool any_errors = false;

  rapidxml::xml_node<>* sets = root->first_node(SIFCService::SHARED_IFCS_SETS);
  rapidxml::xml_node<>* set = NULL;

  for (set = sets->first_node(SIFCService::SHARED_IFCS_SET);
       set != NULL;
       set = set->next_sibling(SIFCService::SHARED_IFCS_SET))
  {
    rapidxml::xml_node<>* set_id_node = set->first_node(SIFCService::SET_ID);

    if (!set_id_node)
    {
      TRC_ERROR("Invalid shared iFC block - missing SetID. Skipping this entry");
      CL_SPROUT_SIFC_FILE_MISSING_SET_ID.log();
      any_errors = true;
      continue;
    }

    std::string set_id_str = std::string(set_id_node->value());
    Utils::trim(set_id_str);
    int32_t set_id = std::atoi(set_id_str.c_str());

    if (set_id_str != std::to_string(set_id))
    {
      TRC_ERROR("Invalid shared iFC block - SetID (%s) isn't an int. Skipping this entry",
                set_id_str.c_str());
      CL_SPROUT_SIFC_FILE_INVALID_SET_ID.log(set_id_str.c_str());
      any_errors = true;
      continue;
    }

    if (_shared_ifc_sets.count(set_id) != 0)
    {
      TRC_ERROR("Invalid shared iFC block - SetID (%d) is repeated. Skipping this entry",
                set_id);
      CL_SPROUT_SIFC_FILE_REPEATED_SET_ID.log(set_id_str.c_str());
      any_errors = true;
      continue;
    }

    std::vector<std::pair<int32_t, std::string>> ifc_set;

    for (rapidxml::xml_node<>* ifc = set->first_node(RegDataXMLUtils::IFC);
         ifc != NULL;
         ifc = ifc->next_sibling(RegDataXMLUtils::IFC))
    {
      int32_t priority = 0;
      rapidxml::xml_node<>* priority_node = ifc->first_node(RegDataXMLUtils::PRIORITY);

      if (priority_node)
      {
        std::string priority_str = std::string(priority_node->value());
        Utils::trim(priority_str);
        priority = std::atoi(priority_str.c_str());

        if (priority_str != std::to_string(priority))
        {
          TRC_ERROR("Invalid shared iFC block - Priority (%s) isn't an int. Skipping this entry",
                    priority_str.c_str());
          CL_SPROUT_SIFC_FILE_INVALID_PRIORITY.log(priority_str.c_str());
          any_errors = true;
          continue;
        }
      }

      // Creating the iFC always passes; we don't validate the iFC any further
      // at this stage. We've validated this against a schema before allowing
      // any upload though.
      std::string ifc_str;
      rapidxml::print(std::back_inserter(ifc_str), *ifc, 0);
      ifc_set.push_back(std::make_pair(priority, ifc_str));
    }

    TRC_STATUS("Adding %lu iFCs for ID %d", ifc_set.size(), set_id);
    _shared_ifc_sets.insert(std::make_pair(set_id, ifc_set));
  }

  if (any_errors)
  {
    set_alarm();
  }
  else
  {
    clear_alarm();
  }

  delete root; root = NULL;
}

SIFCService::~SIFCService()
{
  delete _updater; _updater = NULL;
  _shared_ifc_sets.clear();
  delete _alarm; _alarm = NULL;
}

void SIFCService::get_ifcs_from_id(std::multimap<int32_t, Ifc>& ifc_map,
                                   const std::set<int32_t>& ids,
                                   std::shared_ptr<xml_document<> > ifc_doc,
                                   SAS::TrailId trail) const
{
  // Take a read lock on the mutex in RAII style
  boost::shared_lock<boost::shared_mutex> read_lock(_sets_rw_lock);

  for (int id : ids)
  {
    TRC_DEBUG("Getting the shared iFCs for ID %d", id);
    std::map<int, std::vector<std::pair<int32_t, std::string>>>::const_iterator i =
                                                      _shared_ifc_sets.find(id);

    if (i != _shared_ifc_sets.end())
    {
      TRC_DEBUG("Found iFC set for ID %d", id);

      for (std::pair<int32_t, std::string> ifc : i->second)
      {
        ifc_map.insert(std::make_pair(ifc.first, Ifc(ifc.second, ifc_doc.get())));
      }
    }
    else
    {
      TRC_WARNING("No iFCs stored for ID %d", id);

      if (_no_shared_ifcs_set_tbl)
      {
        _no_shared_ifcs_set_tbl->increment();
      }

      SAS::Event event(trail, SASEvent::SIFC_NO_SET_FOR_ID, 0);
      event.add_static_param(id);
      SAS::report_event(event);
    }
  }
}

void SIFCService::set_alarm()
{
  if (_alarm)
  {
    _alarm->set();
  }
}

void SIFCService::clear_alarm()
{
  if (_alarm)
  {
    _alarm->clear();
  }
}
