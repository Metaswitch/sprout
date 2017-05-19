/**
 * @file bgcfservice.cpp class implementation for an BGCF service provider
 *
 * Copyright (C) Metaswitch Networks
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

#include "bgcfservice.h"
#include "log.h"
#include "sas.h"
#include "sproutsasevent.h"
#include "pjutils.h"
#include "sprout_pd_definitions.h"

BgcfService::BgcfService(std::string configuration) :
  _configuration(configuration),
  _updater(NULL)
{
  // Create an updater to keep the bgcf routes configured appropriately.
  _updater = new Updater<void, BgcfService>(this, std::mem_fun(&BgcfService::update_routes));
}

void BgcfService::update_routes()
{
  // Check whether the file exists.
  struct stat s;
  TRC_DEBUG("stat(%s) returns %d", _configuration.c_str(), stat(_configuration.c_str(), &s));
  if ((stat(_configuration.c_str(), &s) != 0) &&
      (errno == ENOENT))
  {
    TRC_STATUS("No BGCF configuration (file %s does not exist)",
               _configuration.c_str());
    CL_SPROUT_BGCF_FILE_MISSING.log();
    return;
  }

  TRC_STATUS("Loading BGCF configuration from %s", _configuration.c_str());

  // Read from the file
  std::ifstream fs(_configuration.c_str());
  std::string bgcf_str((std::istreambuf_iterator<char>(fs)),
                        std::istreambuf_iterator<char>());

  if (bgcf_str == "")
  {
    // LCOV_EXCL_START
    TRC_ERROR("Failed to read BGCF configuration data from %s",
              _configuration.c_str());
    CL_SPROUT_BGCF_FILE_EMPTY.log();
    return;
    // LCOV_EXCL_STOP
  }

  // Now parse the document
  rapidjson::Document doc;
  doc.Parse<0>(bgcf_str.c_str());

  if (doc.HasParseError())
  {
    TRC_ERROR("Failed to read BGCF configuration data: %s\nError: %s",
              bgcf_str.c_str(),
              rapidjson::GetParseError_En(doc.GetParseError()));
    CL_SPROUT_BGCF_FILE_INVALID.log();
    return;
  }

  try
  {
    std::map<std::string, std::vector<std::string>> new_domain_routes;
    std::map<std::string, std::vector<std::string>> new_number_routes;

    JSON_ASSERT_CONTAINS(doc, "routes");
    JSON_ASSERT_ARRAY(doc["routes"]);
    const rapidjson::Value& routes_arr = doc["routes"];

    for (rapidjson::Value::ConstValueIterator routes_it = routes_arr.Begin();
         routes_it != routes_arr.End();
         ++routes_it)
    {
      // An entry is valid if it has either a domain (string) OR a
      // number (string) AND an array of routes
      if ((((((*routes_it).HasMember("domain")) &&
             ((*routes_it)["domain"].IsString()))   &&
            (!(*routes_it).HasMember("number"))) ||
           ((!(*routes_it).HasMember("domain"))  &&
            (((*routes_it).HasMember("number")) &&
             ((*routes_it)["number"].IsString())))) &&
          ((*routes_it).HasMember("route") &&
           (*routes_it)["route"].IsArray()))
      {
        std::vector<std::string> route_vec;
        const rapidjson::Value& route_arr = (*routes_it)["route"];

        for (rapidjson::Value::ConstValueIterator route_it = route_arr.Begin();
             route_it != route_arr.End();
            ++route_it)
        {
          std::string route_uri = (*route_it).GetString();
          TRC_DEBUG("  %s", route_uri.c_str());
          route_vec.push_back(route_uri);
        }

        std::string routing_value;

        if ((*routes_it).HasMember("domain"))
        {
          routing_value = (*routes_it)["domain"].GetString();
          new_domain_routes.insert(std::make_pair(routing_value, route_vec));
        }
        else
        {
          routing_value = (*routes_it)["number"].GetString();
          new_number_routes.insert(
                    std::make_pair(PJUtils::remove_visual_separators(routing_value),
                                   route_vec));
        }

        route_vec.clear();

        TRC_DEBUG("Add route for %s", routing_value.c_str());
      }
      else
      {
        TRC_WARNING("Badly formed BGCF route entry");
        CL_SPROUT_BGCF_FILE_INVALID.log();
      }
    }

    // Take a write lock on the mutex in RAII style
    boost::lock_guard<boost::shared_mutex> write_lock(_routes_rw_lock);
    _domain_routes = new_domain_routes;
    _number_routes = new_number_routes;
  }
  catch (JsonFormatError err)
  {
    TRC_ERROR("Badly formed BGCF configuration file - missing routes object");
    CL_SPROUT_BGCF_FILE_INVALID.log();
  }
}

BgcfService::~BgcfService()
{
  // Destroy the updater (if it was created).
  delete _updater;
  _updater = NULL;
}

std::vector<std::string> BgcfService::get_route_from_domain(
                                                const std::string &domain,
                                                SAS::TrailId trail) const
{
  TRC_DEBUG("Getting route for URI domain %s via BGCF lookup", domain.c_str());

  // Take a read lock on the mutex in RAII style
  boost::shared_lock<boost::shared_mutex> read_lock(_routes_rw_lock);

  // First try the specified domain.
  std::map<std::string, std::vector<std::string>>::const_iterator i =
                                                    _domain_routes.find(domain);
  if (i != _domain_routes.end())
  {
    TRC_INFO("Found route to domain %s", domain.c_str());

    SAS::Event event(trail, SASEvent::BGCF_FOUND_ROUTE_DOMAIN, 0);
    event.add_var_param(domain);
    std::string route_string;

    for (std::vector<std::string>::const_iterator ii = i->second.begin(); ii != i->second.end(); ++ii)
    {
      route_string = route_string + *ii + ";";
    }

    event.add_var_param(route_string);
    SAS::report_event(event);

    return i->second;
  }

  // Then try the default domain (*).
  i = _domain_routes.find("*");
  if (i != _domain_routes.end())
  {
    TRC_INFO("Found default route");

    SAS::Event event(trail, SASEvent::BGCF_DEFAULT_ROUTE_DOMAIN, 0);
    event.add_var_param(domain);
    std::string route_string;

    for (std::vector<std::string>::const_iterator ii = i->second.begin(); ii != i->second.end(); ++ii)
    {
      route_string = route_string + *ii + ";";
    }

    event.add_var_param(route_string);
    SAS::report_event(event);

    return i->second;
  }

  SAS::Event event(trail, SASEvent::BGCF_NO_ROUTE_DOMAIN, 0);
  event.add_var_param(domain);
  SAS::report_event(event);

  return std::vector<std::string>();
}

std::vector<std::string> BgcfService::get_route_from_number(
                                                const std::string &number,
                                                SAS::TrailId trail) const
{
  // Take a read lock on the mutex in RAII style
  boost::shared_lock<boost::shared_mutex> read_lock(_routes_rw_lock);

  // The number routes map is ordered by length of key. Start from the end of
  // the map to get the longest prefixes first.
  for (std::map<std::string, std::vector<std::string>>::const_reverse_iterator it =
        _number_routes.rbegin();
       it != _number_routes.rend();
       it++)
  {
    int len = std::min(number.size(), (*it).first.size());

    if (PJUtils::remove_visual_separators(number).compare(0,
                                                          len,
                                                          (*it).first,
                                                          0,
                                                          len) == 0)
    {
      // Found a match, so return it
      TRC_DEBUG("Match found. Number: %s, prefix: %s",
                number.c_str(), (*it).first.c_str());

      SAS::Event event(trail, SASEvent::BGCF_FOUND_ROUTE_NUMBER, 0);
      event.add_var_param(number);
      std::string route_string;

      for (std::vector<std::string>::const_iterator ii = (*it).second.begin();
                                                    ii != (*it).second.end();
                                                    ++ii)
      {
        route_string = route_string + *ii + ";";
      }

      event.add_var_param(route_string);
      SAS::report_event(event);

      return (*it).second;
    }
  }

  SAS::Event event(trail, SASEvent::BGCF_NO_ROUTE_NUMBER, 0);
  event.add_var_param(number);
  SAS::report_event(event);

  return std::vector<std::string>();
}
