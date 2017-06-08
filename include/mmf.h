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

#include <iostream>
#include <memory>
#include "utils.h"
#include "json_parse_utils.h"

/// A representation of an entry in the mmf.json file
class MMFCfg
{
public:
  typedef std::shared_ptr<MMFCfg> ptr;

  MMFCfg(const rapidjson::Value& config);

  void parse_addresses(const rapidjson::Value& config);

  void parse_context(const rapidjson::Value& config);

  void parse_pre_as(const rapidjson::Value& config);

  void parse_post_as(const rapidjson::Value& config);

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