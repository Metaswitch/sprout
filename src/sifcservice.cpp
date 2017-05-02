/**
 * @file sifcservice.cpp class
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2017  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version, along with the "Special Exception" for use of
 * the program along with SSL, set forth below. This program is distributed
 * in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details. You should have received a copy of the GNU General Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by
 * post at Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 *
 * Special Exception
 * Metaswitch Networks Ltd  grants you permission to copy, modify,
 * propagate, and distribute a work formed by combining OpenSSL with The
 * Software, or a work derivative of such a combination, even if such
 * copying, modification, propagation, or distribution would otherwise
 * violate the terms of the GPL. You must comply with the GPL in all
 * respects for all of the code used other than OpenSSL.
 * "OpenSSL" means OpenSSL toolkit software distributed by the OpenSSL
 * Project and licensed under the OpenSSL Licenses, or a work based on such
 * software and licensed under the OpenSSL Licenses.
 * "OpenSSL Licenses" means the OpenSSL License and Original SSLeay License
 * under which the OpenSSL Project distributes the OpenSSL toolkit software,
 * as those licenses appear in the file LICENSE-OPENSSL.
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

SIFCService::SIFCService(std::string configuration) :
  _configuration(configuration),
  _updater(NULL),
  _root(NULL)
{
  // Create an updater to keep the shared IFC sets configured appropriately.
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
    TRC_STATUS("No shared IFCs configuration (file %s does not exist)",
               _configuration.c_str());
    CL_SPROUT_SIFC_FILE_MISSING.log();
    return;
  }

  TRC_STATUS("Loading shared IFCs configuration from %s", _configuration.c_str());

  // Read from the file
  std::ifstream fs(_configuration.c_str());
  std::string sifc_str((std::istreambuf_iterator<char>(fs)),
                        std::istreambuf_iterator<char>());

  if (sifc_str == "")
  {
    TRC_ERROR("Failed to read shared IFCs configuration data from %s",
              _configuration.c_str());
    CL_SPROUT_SIFC_FILE_EMPTY.log();
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
    TRC_ERROR("Failed to parse the shared IFCs configuration data:\n %s\n %s",
              sifc_str.c_str(),
              err.what());
    CL_SPROUT_SIFC_FILE_INVALID_XML.log();
    delete root; root = NULL;
    return;
  }

  if (!root->first_node(SIFCService::SHARED_IFCS_SETS))
  {
    TRC_ERROR("Invalid shared IFCs configuration file - missing SharedIFCsSets block");
    CL_SPROUT_SIFC_FILE_MISSING_SHARED_IFCS_SETS.log();
    delete root; root = NULL;
    return;
  }

  // At this point, we're definitely going to override the IFCs we've got.
  // Update our map, taking a lock while we do so.
  boost::lock_guard<boost::shared_mutex> write_lock(_sets_rw_lock);
  _shared_ifc_sets.clear();
  delete _root; _root = root;

  rapidxml::xml_node<>* sets = _root->first_node(SIFCService::SHARED_IFCS_SETS);
  rapidxml::xml_node<>* set = NULL;

  for (set = sets->first_node(SIFCService::SHARED_IFCS_SET);
       set != NULL;
       set = set->next_sibling(SIFCService::SHARED_IFCS_SET))
  {
    rapidxml::xml_node<>* set_id_node = set->first_node(SIFCService::SET_ID);

    if (!set_id_node)
    {
      TRC_ERROR("Invalid shared IFC block - missing SetID. Skipping this entry");
      CL_SPROUT_SIFC_FILE_MISSING_SET_ID.log();
      continue;
    }

    std::string set_id_str = std::string(set_id_node->value());
    Utils::trim(set_id_str);
    int32_t set_id = std::atoi(set_id_str.c_str());

    if (set_id_str != std::to_string(set_id))
    {
      TRC_ERROR("Invalid shared IFC block - SetID (%s) isn't an int. Skipping this entry",
                set_id_str.c_str());
      CL_SPROUT_SIFC_FILE_INVALID_SET_ID.log(set_id_str.c_str());
      continue;
    }

    if (_shared_ifc_sets.count(set_id) != 0)
    {
      TRC_ERROR("Invalid shared IFC block - SetID (%d) is repeated. Skipping this entry",
                set_id);
      CL_SPROUT_SIFC_FILE_REPEATED_SET_ID.log(set_id_str.c_str());
      continue;
    }

    std::vector<std::pair<int32_t, Ifc>> ifc_set;

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
          TRC_ERROR("Invalid shared IFC block - Priority (%s) isn't an int. Skipping this entry",
                    priority_str.c_str());
          CL_SPROUT_SIFC_FILE_INVALID_PRIORITY.log(priority_str.c_str());
          continue;
        }
      }

      // Creating the IFC always passes; we don't validate the IFC any further
      // at this stage. This is a fairly complicated thing to do however.
      ifc_set.push_back(std::make_pair(priority, Ifc(ifc)));
    }

    TRC_DEBUG("Adding %lu IFCs for ID %d", ifc_set.size(), set_id);
    _shared_ifc_sets.insert(std::make_pair(set_id, ifc_set));
  }
}

SIFCService::~SIFCService()
{
  // Destroy the updater (if it was created).
  delete _updater; _updater = NULL;

  _shared_ifc_sets.clear();
  delete _root; _root = NULL;
}

void SIFCService::get_ifcs_from_id(std::multimap<int32_t, Ifc>& ifc_map,
                                   const std::set<int32_t>& ids,
                                   SAS::TrailId trail) const
{
  // Take a read lock on the mutex in RAII style
  boost::shared_lock<boost::shared_mutex> read_lock(_sets_rw_lock);

  for (int id : ids)
  {
    TRC_DEBUG("Getting the shared IFCs for ID %d", id);
    std::map<int, std::vector<std::pair<int32_t, Ifc>>>::const_iterator i =
                                                      _shared_ifc_sets.find(id);

    if (i != _shared_ifc_sets.end())
    {
      TRC_DEBUG("Found IFC set for ID %d", id);

      for (std::pair<int32_t, Ifc> ifc : i->second)
      {
        ifc_map.insert(ifc);
      }
    }
    else
    {
      TRC_WARNING("No IFCs stored for ID %d", id);
      SAS::Event event(trail, SASEvent::SIFC_NO_SET_FOR_ID, 0);
      event.add_static_param(id);
      SAS::report_event(event);
    }
  }
}
