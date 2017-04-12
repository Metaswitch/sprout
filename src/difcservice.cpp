/**
 * @file difcservice.cpp The iFC handler data type.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
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

#include "difcservice.h"
#include "sprout_pd_definitions.h"
#include "utils.h"

DIFCService::DIFCService(std::string configuration):
  _configuration(configuration),
  _updater(NULL),
  _root(NULL)
{
  // Create an updater to keep the defuault iFCs configured correctly.
  _updater = new Updater<void, DIFCService>
                               (this, std::mem_fun(&DIFCService::update_difcs));
}

DIFCService::~DIFCService()
{
  delete _updater; _updater = NULL;
  _default_ifcs.clear();
  delete _root; _root = NULL;
}

void DIFCService::update_difcs()
{
  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;
  bool file_valid = check_difc_file(root);

  if (file_valid)
  {
    // Now we are going to update the current default ifc list.
    // Take a lock while we do so.
    boost::lock_guard<boost::shared_mutex> write_lock(_sets_rw_lock);
    _default_ifcs.clear();
    delete _root; _root = root;

    std::vector<std::pair<int32_t, Ifc>> ifc_list;
    ifc_list = create_difc_list();

    TRC_DEBUG("Adding %lu default IFC(s)", ifc_list.size());
    _default_ifcs = ifc_list;
  }

  return;
}

bool DIFCService::check_difc_file(rapidxml::xml_document<>* root)
{
  // Check whether the file exists.
  struct stat s;
  TRC_DEBUG("stat (%s) returns %d", _configuration.c_str(),
            stat(_configuration.c_str(), &s));
  if ((stat(_configuration.c_str(), &s) != 0) &&
      (errno == ENOENT))
  {
    TRC_STATUS("No default IFC configuration found (file %s does not exist)",
               _configuration.c_str());
    CL_SPROUT_DIFC_FILE_MISSING.log();
    delete root; root = NULL;
    return false;
  }

  TRC_STATUS("Loading default IFC configuration from %s",
             _configuration.c_str());

  // Check whether the file is empty.
  std::ifstream fs(_configuration.c_str());
  std::string difc_str((std::istreambuf_iterator<char>(fs)),
                        std::istreambuf_iterator<char>());
  if (difc_str == "")
  {
    TRC_ERROR("Failed to read default IFC configuration data from %s",
              _configuration.c_str());
    CL_SPROUT_DIFC_FILE_EMPTY.log();
    delete root; root = NULL;
    return false;
  }

  // Check the file contains valid xml.
  try
  {
    root->parse<0>(root->allocate_string(difc_str.c_str()));
  }
  catch (rapidxml::parse_error& err)
  {
    TRC_ERROR("Failed to parse the default IFC configuration data:\n %s\n %s",
              difc_str.c_str(),
              err.what());
    CL_SPROUT_DIFC_FILE_INVALID_XML.log();
    delete root; root = NULL;
    return false;
  }

  // Finally, check the "DefaultIfcSet" node is present.
  if (!root->first_node(DIFCService::DEFAULT_IFC_SET))
  {
    TRC_ERROR("Invalid default IFC configuration file - missing DefaultIfcSet block");
    CL_SPROUT_DIFC_FILE_MISSING_DEFAULTIFCSET.log();
    delete root; root = NULL;
    return false;
  }

  // If we've reached this point, the DiFC config file is valid.
  return true;
}

std::vector<std::pair<int32_t, Ifc>> DIFCService::create_difc_list()
{
  rapidxml::xml_node<>* difc_set = _root->first_node(DIFCService::DEFAULT_IFC_SET);

  // Parse any iFCs that are present.
  std::vector<std::pair<int32_t, Ifc>> ifc_set;
  rapidxml::xml_node<>* ifc = NULL;
  for (ifc = difc_set->first_node(DIFCService::INITIAL_FILTER_CRITERIA);
       ifc != NULL;
       ifc = ifc->next_sibling(DIFCService::INITIAL_FILTER_CRITERIA))
  {
    // Parse the priority.
    int32_t priority = 0;
    rapidxml::xml_node<>* priority_node = ifc->first_node(DIFCService::PRIORITY);
    if (priority_node)
    {
      std::string priority_str = priority_node->value();
      Utils::trim(priority_str);
      priority = std::atoi(priority_str.c_str());

      if (priority_str != std::to_string(priority))
      {
        TRC_ERROR("Invalid default iFC - Priority (%s) isn't an int. This iFC "
                  "will not be included in the default iFC list.",
                  priority_str.c_str());
        CL_SPROUT_DIFC_FILE_INVALID_PRIORITY.log(priority_str.c_str());
        continue;
      }
    }
    // Creating the iFC always passes, and the iFC isn't validated any
    // further at this stage.
    ifc_set.push_back(std::make_pair(priority, Ifc(ifc)));
  }

  return ifc_set;
}


