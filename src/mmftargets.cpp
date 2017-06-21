/**
 * @file mmftargets.cpp  class representing MMF Target configuration options
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "mmftargets.h"
#include <regex>
#include <iostream>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/regex.hpp>

MMFTarget::MMFTarget(const rapidjson::Value& config):
  _pre_as(false),
  _post_as(false)
{
  TRC_DEBUG("Creating MMFTarget");
  parse_name(config);
  parse_addresses(config);
  parse_pre_as(config);
  parse_post_as(config);
}
void MMFTarget::parse_name(const rapidjson::Value& config)
{
  TRC_DEBUG("Reading name");

  if (config.HasMember("name") && config["name"].IsString())
  {
    std::string name = config["name"].GetString();
    TRC_DEBUG("Read name: %s", name.c_str());

    if (name.empty())
    {
      TRC_ERROR("Invalid 'name' field in MMF configuration.  The 'name' "
                "must be a non-empty string");
      JSON_FORMAT_ERROR();
    }

    const boost::regex allowed_chars = boost::regex("^[A-Za-z0-9_-]+$");

    // The _name is used as the mmfcontext URI parameter in requests sent for
    // MMF processing.  We only allow A-Z, a-z, 0-9, - and _.
    if (!boost::regex_match(name, allowed_chars))
    {
      TRC_ERROR("Invalid 'name' field: '%s' in MMF configuration.  The 'name' "
                "contains an invalid character.  It can only contain Alphanumerical"
                " characters, '-' and '_'", name.c_str());
      JSON_FORMAT_ERROR();
    }

    _name = name;
  }
  else
  {
    TRC_ERROR("Invalid 'name' field in MMF configuration.  The 'name' "
              "field must be present, and must be a string");
    JSON_FORMAT_ERROR();
  }
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

void MMFTarget::parse_pre_as(const rapidjson::Value& config)
{
  TRC_DEBUG("Reading pre-as");
  if (config.HasMember("pre-as"))
  {
    if (config["pre-as"].IsBool())
    {
      _pre_as = config["pre-as"].GetBool();
      TRC_DEBUG("Read pre-as: %s", _pre_as ? "true" : "false");
    }
    else
    {
      TRC_ERROR("Invalid 'pre-as' field in MMF configuration.  The 'pre-as' "
                "field must be present, and must be a boolean");
      JSON_FORMAT_ERROR();
    }
  }
  else
  {
    TRC_DEBUG("No 'pre-as' field present for the MMF target '%s'.  Defaulting "
              "to 'false'", _name.c_str());
  }
}

void MMFTarget::parse_post_as(const rapidjson::Value& config)
{
  TRC_DEBUG("Reading post-as");
  if (config.HasMember("post-as"))
  {
    if (config["post-as"].IsBool())
    {
      _post_as = config["post-as"].GetBool();
      TRC_DEBUG("Read post-as: %s", _post_as ? "true" : "false");
    }
    else
    {
      TRC_ERROR("Invalid 'post-as' field in MMF configuration.  The 'post-as' "
                "field must be present, and must be a boolean");
      JSON_FORMAT_ERROR();
    }
  }
  else
  {
    TRC_DEBUG("No 'post-as' field present for the MMF target '%s'.  Defaulting "
              "to 'false'", _name.c_str());
  }
}
