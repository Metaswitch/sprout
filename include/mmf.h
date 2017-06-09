/**
 * @file mmf.h  MMF target configuration options
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

#include <iostream>
#include <memory>
#include "utils.h"
#include "json_parse_utils.h"

/// A representation of an entry in the mmf_targets.json file
class MMFTarget
{
public:
  typedef std::shared_ptr<MMFTarget> ptr;

  MMFTarget(const rapidjson::Value& config);

  void parse_addresses(const rapidjson::Value& config);

  void parse_name(const rapidjson::Value& config);

  void parse_pre_as(const rapidjson::Value& config);

  void parse_post_as(const rapidjson::Value& config);

  inline const bool apply_pre_as() const {return _pre_as;};
  inline const bool apply_post_as() const {return _post_as;};
  inline const std::vector<std::string>& get_addresses() {return _addresses;};

private:
  MMFTarget(const MMFTarget&) = delete;  // Prevent implicit copying

  std::vector<std::string> _addresses;
  std::string _name;
  bool _pre_as;
  bool _post_as;
};

#endif
