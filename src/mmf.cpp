/**
 * @file mmf.cpp  class representing MMF Target configuration options
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "mmf.h"


MMFTarget::MMFTarget(const rapidjson::Value& config)
{
  TRC_DEBUG("Creating MMFTarget");
  parse_name(config);
  parse_pre_as(config);
  parse_post_as(config);
  parse_addresses(config);
}

void MMFTarget::parse_addresses(const rapidjson::Value& config)
{
  if (config.HasMember("addresses") && config["addresses"].IsArray())
  {
    TRC_DEBUG("Reading addresses");
    const rapidjson::Value& addresses = config["addresses"];

    for (rapidjson::Value::ConstValueIterator address_it = addresses.Begin();
         address_it != addresses.End();
         ++address_it)
    {
      if ((*address_it).IsString())
      {
        TRC_DEBUG("Read address: %s", (*address_it).GetString());
        _addresses.push_back((*address_it).GetString());
      }
      else
      {
        TRC_ERROR("Invalid 'addresses' field in MMF configuration.  The "
                  "'addresses' field be an array of strings.");
        JSON_FORMAT_ERROR();
      }
    }
  }
  else
  {
    TRC_ERROR("Invalid 'addresses' field in MMF configuration.  The "
              "'addresses' field must be present, and must be an array of strings.");
    JSON_FORMAT_ERROR();
  }
}

void MMFTarget::parse_name(const rapidjson::Value& config)
{
  TRC_DEBUG("Reading name");
  if (config.HasMember("name") && config["name"].IsString())
  {
    TRC_DEBUG("Read name: %s", config["name"].GetString());
    _name = config["name"].GetString();
  }
  else
  {
    TRC_ERROR("Invalid 'name' field in MMF configuration.  The 'name' "
              "field must be present, and must be a string");
    JSON_FORMAT_ERROR();
  }
}

void MMFTarget::parse_pre_as(const rapidjson::Value& config)
{
  TRC_DEBUG("Reading pre-AS");
  if (config.HasMember("pre-AS") && config["pre-AS"].IsBool())
  {
    TRC_DEBUG("Read pre-AS: %d", config["pre-AS"].GetBool());
    _pre_as = config["pre-AS"].GetBool();
  }
  else
  {
    TRC_ERROR("Invalid 'pre-AS' field in MMF configuration.  The 'pre-AS' "
              "field must be present, and must be a boolean");
    JSON_FORMAT_ERROR();
  }
}

void MMFTarget::parse_post_as(const rapidjson::Value& config)
{
  TRC_DEBUG("Reading post-AS");
  if (config.HasMember("post-AS") && config["post-AS"].IsBool())
  {
    TRC_DEBUG("Read post-AS: %d", config["post-AS"].GetBool());
    _post_as = config["post-AS"].GetBool();
  }
  else
  {
    TRC_ERROR("Invalid 'post-AS' field in MMF configuration.  The 'post-AS' "
              "field must be present, and must be a boolean");
    JSON_FORMAT_ERROR();
  }
}
