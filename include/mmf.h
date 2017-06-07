/**
 * @file mmf.h The MMF Config data type.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef MMF_H__
#define MMF_H__

#include "utils.h"
#include "json_parse_utils.h"

/// A representation of an entry in the mmf.json file
class MMFCfg
{
public:
  MMFCfg(const rapidjson::Value& config)
  {
    parse_context(config);
    parse_pre_as(config);
    parse_post_as(config);
    parse_addresses(config);
  }

  void parse_addresses(const rapidjson::Value& config)
  {
    if (config.HasMember("addresses") && config["addresses"].IsArray())
    {
      const rapidjson::Value& addresses = config["addresses"];

      for (rapidjson::Value::ConstValueIterator address_it = addresses.Begin();
           address_it != addresses.End();
           ++address_it)
      {
        if ((*address_it).IsString())
        {
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

  void parse_context(const rapidjson::Value& config)
  {
    if (config.HasMember("context") && config["context"].IsString())
    {
      _context = config["context"].GetString();
    }
    else
    {
      TRC_ERROR("Invalid 'context' field in MMF configuration.  The 'context' "
                "field must be present, and must be a string");
      JSON_FORMAT_ERROR();
    }
  }

  void parse_pre_as(const rapidjson::Value& config)
  {
    if (config.HasMember("pre-AS") && config["pre-AS"].IsBool())
    {
      _pre_as = config["pre-AS"].GetBool();
    }
    else
    {
      TRC_ERROR("Invalid 'pre-AS' field in MMF configuration.  The 'pre-AS' "
                "field must be present, and must be a boolean");
      JSON_FORMAT_ERROR();
    }
  }

  void parse_post_as(const rapidjson::Value& config)
  {
    if (config.HasMember("post-AS") && config["post-AS"].IsBool())
    {
      _post_as = config["post-AS"].GetBool();
    }
    else
    {
      TRC_ERROR("Invalid 'post-AS' field in MMF configuration.  The 'post-AS' "
                "field must be present, and must be a boolean");
      JSON_FORMAT_ERROR();
    }
  }

  typedef std::shared_ptr<MMFCfg> ptr;

  const bool apply_pre_as() const {return _pre_as;};
  const bool apply_post_as() const {return _post_as;};
  const std::vector<std::string>& get_addresses() {return _addresses;};

private:
  MMFCfg(const MMFCfg&) = delete;  // Prevent implicit copying

  std::vector<std::string> _addresses;
  std::string _context;
  bool _pre_as;
  bool _post_as;
};

#endif