/**
* @file scscfselector.cpp
*
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
*/

#include <sys/stat.h>
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "json_parse_utils.h"
#include <fstream>
#include <stdlib.h>
#include <algorithm>

#include "scscfselector.h"
#include "log.h"
#include "sas.h"
#include "sproutsasevent.h"
#include "sprout_pd_definitions.h"

SCSCFSelector::SCSCFSelector(const std::string& fallback_scscf_uri,
                             std::string configuration) :
  _fallback_scscf_uri(fallback_scscf_uri),
  _configuration(configuration),
  _updater(NULL)
{
  // create an updater
  _updater = new Updater<void, SCSCFSelector>(this, std::mem_fun(&SCSCFSelector::update_scscf));
}

void SCSCFSelector::update_scscf()
{
  std::vector<scscf_t> new_scscfs;

  struct stat s;
  if ((stat(_configuration.c_str(), &s) != 0) &&
      (errno == ENOENT))
  {
    // Check whether the file exists. If it doesn't exist at all, then
    // we'll fall back to a default value for a single S-CSCF
    TRC_STATUS("No S-CSCF configuration data (file %s does not exist)",
               _configuration.c_str());
    CL_SPROUT_SCSCF_FILE_MISSING.log();
  }
  else
  {
    TRC_STATUS("Loading S-CSCF configuration from %s", _configuration.c_str());

    // Read from the file
    std::ifstream fs(_configuration.c_str());
    std::string scscf_str((std::istreambuf_iterator<char>(fs)),
                           std::istreambuf_iterator<char>());

    if (scscf_str == "")
    {
      // LCOV_EXCL_START
      TRC_ERROR("Failed to read S-CSCF configuration data from %s",
                _configuration.c_str());
      CL_SPROUT_SCSCF_FILE_EMPTY.log();
      // LCOV_EXCL_STOP
    }
    else
    {
      // Now parse the document
      rapidjson::Document doc;
      doc.Parse<0>(scscf_str.c_str());

      if (doc.HasParseError())
      {
        TRC_ERROR("Failed to read S-CSCF configuration data: %s\nError: %s",
                  scscf_str.c_str(),
                  rapidjson::GetParseError_En(doc.GetParseError()));
        CL_SPROUT_SCSCF_FILE_INVALID.log();
      }
      else
      {
        try
        {
          JSON_ASSERT_CONTAINS(doc, "s-cscfs");
          JSON_ASSERT_ARRAY(doc["s-cscfs"]);
          const rapidjson::Value& scscfs_arr = doc["s-cscfs"];

          for (rapidjson::Value::ConstValueIterator scscfs_it = scscfs_arr.Begin();
               scscfs_it != scscfs_arr.End();
               ++scscfs_it)
          {
            try
            {
              scscf_t new_scscf;
              JSON_GET_STRING_MEMBER(*scscfs_it, "server", new_scscf.server);
              JSON_GET_INT_MEMBER(*scscfs_it, "priority", new_scscf.priority);
              JSON_GET_INT_MEMBER(*scscfs_it, "weight", new_scscf.weight);

              JSON_ASSERT_CONTAINS(*scscfs_it, "capabilities");
              JSON_ASSERT_ARRAY((*scscfs_it)["capabilities"]);
              const rapidjson::Value& cap_arr = (*scscfs_it)["capabilities"];
              std::vector<int> capabilities_vec;

              for (rapidjson::Value::ConstValueIterator cap_it = cap_arr.Begin();
                   cap_it != cap_arr.End();
                   ++cap_it)
              {
                capabilities_vec.push_back((*cap_it).GetInt());
              }

              // Sort the capabilities and remove duplicates
              std::sort(capabilities_vec.begin(), capabilities_vec.end());
              capabilities_vec.erase(unique(capabilities_vec.begin(),
                                            capabilities_vec.end()),
                                     capabilities_vec.end() );
              new_scscf.capabilities = capabilities_vec;
              new_scscfs.push_back(new_scscf);
              capabilities_vec.clear();
            }
            catch (JsonFormatError err)
            {
              // Badly formed S-CSCF entry.
              TRC_WARNING("Badly formed S-CSCF entry (hit error at %s:%d)",
                          err._file, err._line);
              CL_SPROUT_SCSCF_FILE_INVALID.log();
            }
          }
        }
        catch (JsonFormatError err)
        {
          TRC_ERROR("Badly formed S-CSCF configuration file - missing s-cscfs object");
          CL_SPROUT_SCSCF_FILE_INVALID.log();
        }
      }
    }
  }

  if (new_scscfs.empty())
  {
    // Add a default option that is our S-CSCF
    TRC_WARNING("The S-CSCF json file is empty/invalid. Using default values");
    scscf_t new_scscf;
    new_scscf.server = _fallback_scscf_uri;
    new_scscf.priority = 0;
    new_scscf.weight = 100;
    new_scscfs.push_back(new_scscf);
  }

  // Take a write lock on the mutex in RAII style
  boost::lock_guard<boost::shared_mutex> write_lock(_scscfs_rw_lock);
  _scscfs = new_scscfs;
}

SCSCFSelector::~SCSCFSelector()
{
  // Destroy the updater
  delete _updater;
  _updater = NULL;
}

std::string SCSCFSelector::get_scscf(const std::vector<int> &mandatory,
                                     const std::vector<int> &optional,
                                     const std::vector<std::string> &rejects,
                                     SAS::TrailId trail)
{
  // Take a read lock on the mutex in RAII style. See
  // http://www.boost.org/doc/libs/1_41_0/doc/html/thread/synchronization.html
  // for documentation.
  boost::shared_lock<boost::shared_mutex> read_lock(_scscfs_rw_lock);

  // There's at least one S-CSCF, so check if any match the capabilities requested
  std::string reject_str;
  for (std::vector<std::string>::const_iterator ii = rejects.begin(); ii != rejects.end(); ++ii)
  {
    reject_str = reject_str + *ii + ";";
  }

  // Sort the mandatory capabilities, and remove duplicates.
  std::vector<int> mandatory_cap = mandatory;
  std::sort(mandatory_cap.begin(), mandatory_cap.end());
  mandatory_cap.erase(unique(mandatory_cap.begin(), mandatory_cap.end()), mandatory_cap.end());
  std::string mandatory_str;
  for (std::vector<int>::const_iterator ii = mandatory_cap.begin(); ii != mandatory_cap.end(); ++ii)
  {
    mandatory_str = mandatory_str + std::to_string(*ii) + ";";
  }

  // Sort the optional capabilities, and remove duplicates.
  std::vector<int> optional_cap = optional;
  std::sort(optional_cap.begin(), optional_cap.end());
  optional_cap.erase(unique(optional_cap.begin(), optional_cap.end()), optional_cap.end());
  std::string optional_str;
  for (std::vector<int>::const_iterator ii = optional_cap.begin(); ii != optional_cap.end(); ++ii)
  {
    optional_str = optional_str + std::to_string(*ii) + ";";
  }

  // Find all S-CSCFs that have all the mandatory capabilities, the highest possible number
  // of optional capabilities, and the highest priority (closest to 0).
  // Also sum up the weights of the valid S-CSCFs as part of the iteration
  std::vector<scscf> matches;
  u_int max_size = 0;
  int priority = 0;
  int sum = 0;

  for (std::vector<scscf>::iterator it=_scscfs.begin(); it!=_scscfs.end(); ++it)
  {
    // Only include the S-CSCF if its name isn't in the list of S-CSCFs to reject and it has all of
    // the mandatory capabilities
    if ((std::find(rejects.begin(), rejects.end(), it->server) == rejects.end()) &&
        (std::includes(it->capabilities.begin(), it->capabilities.end(), mandatory_cap.begin(), mandatory_cap.end())))
    {
      std::vector<int> intersection;
      std::set_intersection(it->capabilities.begin(), it->capabilities.end(),
                            optional_cap.begin(), optional_cap.end(),
                            std::back_inserter(intersection));

      if (intersection.size() > max_size ||
          matches.size() == 0)
      {
        matches.clear();
        matches.push_back(*it);
        max_size = intersection.size();
        priority = it->priority;
        sum = it->weight;
      }
      else if (intersection.size() == max_size)
      {
        if (it->priority == priority)
        {
          matches.push_back(*it);
          sum += it->weight;
        }
        else if (it->priority < priority)
        {
          matches.clear();
          matches.push_back(*it);
          priority = it->priority;
          sum = it->weight;
        }
      }
    }
  }

  // If there are no matches, return an empty string (there will only be no matches
  // if no S-CSCFs had all the requested mandatory capabilities).
  // If there's only one match, then return its name.
  if (matches.empty())
  {
    TRC_WARNING("There are no configured S-CSCFs that have the requested mandatory capabilities (%s)",
                mandatory_str.c_str());

    SAS::Event event(trail, SASEvent::SCSCF_NONE_VALID, 0);
    event.add_var_param(mandatory_str);
    event.add_var_param(optional_str);
    event.add_var_param(reject_str);
    SAS::report_event(event);

    return std::string();
  }
  else if (matches.size() == 1)
  {
    TRC_DEBUG("Selected S-CSCF is %s",  matches[0].server.c_str());

    SAS::Event event(trail, SASEvent::SCSCF_SELECTED, 0);
    event.add_var_param(matches[0].server);
    event.add_var_param(mandatory_str);
    event.add_var_param(optional_str);
    std::string priority_str = std::to_string(matches[0].priority);
    std::string weight_str = std::to_string(matches[0].weight);
    event.add_var_param(priority_str);
    event.add_var_param(weight_str);
    event.add_var_param(reject_str);
    SAS::report_event(event);

    return matches[0].server.c_str();
  }

  // There are multiple S-CSCFs that match on all mandatory capabilities, the highest number of optional
  // capabilities, and the highest priority. Select one using a weighted random choice.
  srand(time(NULL));
  int random = (sum != 0) ? rand() % sum : 0;

  int index = 0;
  int accumulator = matches[index].weight;

  while (accumulator <= random)
  {
    index++;
    accumulator +=  matches[index].weight;
  }

  TRC_DEBUG("Selected S-CSCF is %s",  matches[index].server.c_str());

  SAS::Event event(trail, SASEvent::SCSCF_SELECTED, 0);
  event.add_var_param(matches[index].server);
  event.add_var_param(mandatory_str);
  event.add_var_param(optional_str);
  std::string priority_str = std::to_string(matches[index].priority);
  std::string weight_str = std::to_string(matches[index].weight);
  event.add_var_param(priority_str);
  event.add_var_param(weight_str);
  event.add_var_param(reject_str);
  SAS::report_event(event);

  return matches[index].server;
}
