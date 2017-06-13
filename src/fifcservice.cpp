/**
 * @file fifcservice.cpp The fallback iFC handler.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <sys/stat.h>
#include <fstream>

#include "fifcservice.h"
#include "sprout_pd_definitions.h"
#include "utils.h"
#include "xml_utils.h"
#include "rapidxml/rapidxml_print.hpp"

FIFCService::FIFCService(Alarm* alarm,
                         std::string configuration):
  _alarm(alarm),
  _configuration(configuration),
  _updater(NULL)
{
  // Create an updater to keep the fallback iFCs configured correctly.
  _updater = new Updater<void, FIFCService>
                               (this, std::mem_fun(&FIFCService::update_fifcs));
}

FIFCService::~FIFCService()
{
  delete _updater; _updater = NULL;
  _fallback_ifcs.clear();
  delete _alarm; _alarm = NULL;
}

void FIFCService::update_fifcs()
{
  // Check whether the file exists.
  struct stat s;
  TRC_DEBUG("stat (%s) returns %d", _configuration.c_str(),
            stat(_configuration.c_str(), &s));
  if ((stat(_configuration.c_str(), &s) != 0) &&
      (errno == ENOENT))
  {
    TRC_STATUS("No fallback IFC configuration found (file %s does not exist)",
               _configuration.c_str());
    CL_SPROUT_FIFC_FILE_MISSING.log();
    set_alarm();
    return;
  }

  TRC_STATUS("Loading fallback IFC configuration from %s",
             _configuration.c_str());

  // Check whether the file is empty.
  std::ifstream fs(_configuration.c_str());
  std::string fifc_str((std::istreambuf_iterator<char>(fs)),
                        std::istreambuf_iterator<char>());
  if (fifc_str == "")
  {
    TRC_ERROR("Failed to read fallback IFC configuration data from %s",
              _configuration.c_str());
    CL_SPROUT_FIFC_FILE_EMPTY.log();
    set_alarm();
    return;
  }

  // Now parse the document.
  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;

  // Check the file contains valid xml.
  try
  {
    root->parse<0>(root->allocate_string(fifc_str.c_str()));
  }
  catch (rapidxml::parse_error& err)
  {
    TRC_ERROR("Failed to parse the fallback IFC configuration data:\n %s\n %s",
              fifc_str.c_str(),
              err.what());
    CL_SPROUT_FIFC_FILE_INVALID_XML.log();
    set_alarm();
    delete root; root = NULL;
    return;
  }

  // Finally, check the "FallbackIFCsSet" node is present.
  if (!root->first_node(FIFCService::FALLBACK_IFCS_SET))
  {
    TRC_ERROR("Failed to parse the fallback IFC configuration file as it is "
              "invalid (missing FallbackIFCsSet block)");
    CL_SPROUT_FIFC_FILE_MISSING_FALLBACK_IFCS_SET.log();
    set_alarm();
    delete root; root = NULL;
    return;
  }

  // If we have reached this point, we are definitely going to update the current
  // fallback ifc list.
  // Take a lock while we do so.
  boost::lock_guard<boost::shared_mutex> write_lock(_sets_rw_lock);
  bool any_errors = false;
  _fallback_ifcs.clear();

  // Parse any iFCs that are present.
  std::multimap<int32_t, std::string> ifc_map;
  rapidxml::xml_node<>* fifc_set = root->first_node(FIFCService::FALLBACK_IFCS_SET);
  rapidxml::xml_node<>* ifc = NULL;
  for (ifc = fifc_set->first_node(RegDataXMLUtils::IFC);
       ifc != NULL;
       ifc = ifc->next_sibling(RegDataXMLUtils::IFC))
  {
    // Parse the priority.
    int32_t priority = 0;
    rapidxml::xml_node<>* priority_node = ifc->first_node(RegDataXMLUtils::PRIORITY);
    if (priority_node)
    {
      std::string priority_str = priority_node->value();
      Utils::trim(priority_str);
      priority = std::atoi(priority_str.c_str());

      if (priority_str != std::to_string(priority))
      {
        TRC_ERROR("Failed to parse one fallback IFC, as its Priority (%s) isn't an "
                  "int. This IFC will not be included in the fallback IFC list",
                  priority_str.c_str());
        CL_SPROUT_FIFC_FILE_INVALID_PRIORITY.log(priority_str.c_str());
        any_errors = true;
        continue;
      }
    }
    // Creating the iFC always passes, and the iFC isn't validated any
    // further at this stage.
    std::string ifc_str;
    rapidxml::print(std::back_inserter(ifc_str), *ifc, 0);
    ifc_map.insert(std::make_pair(priority, ifc_str));
  }

  std::vector<std::string> ifcs_vec;
  for (std::pair<int32_t, std::string> ifc_pair : ifc_map)
  {
    ifcs_vec.push_back(ifc_pair.second);
  }

  TRC_DEBUG("Adding %lu fallback IFC(s)", ifcs_vec.size());
  _fallback_ifcs = ifcs_vec;

  if (any_errors)
  {
    set_alarm();
  }
  else
  {
    clear_alarm();
  }

  delete root; root = NULL;
  return;
}

std::vector<Ifc> FIFCService::get_fallback_ifcs(rapidxml::xml_document<>* ifc_doc) const
{
  // Take a read lock on the mutex in RAII style
  boost::shared_lock<boost::shared_mutex> read_lock(_sets_rw_lock);

  std::vector<Ifc> ifc_vec;
  for (std::string ifc : _fallback_ifcs)
  {
    ifc_vec.push_back(Ifc(ifc, ifc_doc));
  }

  return ifc_vec;
}

void FIFCService::set_alarm()
{
  if (_alarm)
  {
    _alarm->set();
  }
}

void FIFCService::clear_alarm()
{
  if (_alarm)
  {
    _alarm->clear();
  }
}
