/*
 * @file cfgoptions_helper.h
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

// Common STL includes.
#include <cassert>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <queue>
#include <string>
#include "log.h"

/// Validate the result we get when using atoi
bool validated_atoi(const char* char_to_int,
                    int& char_as_int)
{
  char_as_int = atoi(char_to_int);
  return (char_to_int == std::to_string(char_as_int));
}

/// Parse a string representing a port.
/// @returns The port number as an int, or zero if the port is invalid.
int parse_port(const std::string& port_str)
{
  int port;
  bool rc = validated_atoi(port_str.c_str(), port);

  if ((!rc) || (port < 0) || (port > 0xFFFF))
  {
    port = 0;
  }

  return port;
}

/// Parse a string representing a port.
/// @returns whether the port is invalid and sets the port
bool parse_port(const std::string& port_str, int& port)
{
  bool rc = validated_atoi(port_str.c_str(), port);

  if ((!rc) || (port < 0) || (port > 0xFFFF))
  {
    return false;
  }

  return true;
}

void set_plugin_opt_str(std::multimap<std::string, std::string>& plugin_opts,
                        const std::string& opt_name,
                        const std::string& plugin_name,
                        const bool& required_opt,
                        std::string& opt,
                        bool& plugin_enabled)
{
  if (!plugin_enabled)
  {
    // If the plugin is already disabled, don't attempt to parse another option
    return;
  }

  std::multimap<std::string, std::string>::iterator
                                            opt_it = plugin_opts.find(opt_name);

  if (opt_it != plugin_opts.end())
  {
    opt = opt_it->second;
    TRC_INFO("%s %s option '%s': '%s'",
             required_opt ? "Set" : "Overwrote",
             plugin_name.c_str(),
             opt_name.c_str(),
             opt.c_str());
  }
  else if (required_opt)
  {
    TRC_STATUS("Required %s option '%s' not set. Disabling %s.",
               plugin_name.c_str(),
               opt_name.c_str(),
               plugin_name.c_str());
    plugin_enabled = false;
  }
  else
  {
    TRC_INFO("%s option '%s' not set. Defaulting to: '%s'",
             plugin_name.c_str(),
             opt_name.c_str(),
             opt.c_str());
  }
}

void set_plugin_opt_int(std::multimap<std::string, std::string>& plugin_opts,
                        const std::string& opt_name,
                        const std::string& plugin_name,
                        const bool& required_opt,
                        int& opt,
                        bool& plugin_enabled)
{
  if (!plugin_enabled)
  {
    // If the plugin is already disabled, don't attempt to parse another option
    return;
  }

  std::multimap<std::string, std::string>::iterator opt_it =
                                                     plugin_opts.find(opt_name);
  bool option_read_success = false;
  int as_int = 0;

  if (opt_it != plugin_opts.end())
  {
    if (validated_atoi(opt_it->second.c_str(), as_int))
    {
      option_read_success = true;
    }
    else
    {
      TRC_WARNING("Failed to parse value for %s option %s",
                  plugin_name.c_str(),
                  opt_name.c_str());
      option_read_success = false;
    }
  }

  if (option_read_success)
  {
    opt = as_int;
    TRC_INFO("%s %s option '%s': %d",
             required_opt ? "Set" : "Overwrote",
             plugin_name.c_str(),
             opt_name.c_str(),
             opt);
  }
  else if (required_opt)
  {
    TRC_STATUS("Required %s option '%s' not set. Disabling %s.",
               plugin_name.c_str(),
               opt_name.c_str(),
               plugin_name.c_str());
    plugin_enabled = false;
  }
  else
  {
    TRC_INFO("%s option '%s' not set. Defaulting to: %d",
             plugin_name.c_str(),
             opt_name.c_str(),
             opt);
  }
}

void parse_minimum_plugin_options(std::multimap<std::string, std::string>& plugin_opts,
                                  std::string plugin_name,
                                  std::pair<std::string, int>& plugin_port,
                                  std::pair<std::string, std::string>& plugin_prefix,
                                  std::pair<std::string, std::string>& plugin_uri,
                                  bool& plugin_enabled,
                                  const std::string& sprout_hostname)
{
  set_plugin_opt_int(plugin_opts,
                     plugin_port.first,
                     plugin_name,
                     true,
                     plugin_port.second,
                     plugin_enabled);

  if (plugin_port.second <= 0)
  {
    TRC_STATUS("Plugin port (%d) set to 0 (or less). Disabling %s.",
               plugin_port.second,
               plugin_name.c_str());
    plugin_enabled = false;
  }

  set_plugin_opt_str(plugin_opts,
                     plugin_prefix.first,
                     plugin_name,
                     false,
                     plugin_prefix.second,
                     plugin_enabled);

  // Given the prefix, set the default uri
  plugin_uri.second = "sip:" + plugin_prefix.second + "." + sprout_hostname + ";transport=TCP";

  set_plugin_opt_str(plugin_opts,
                     plugin_uri.first,
                     plugin_name,
                     false,
                     plugin_uri.second,
                     plugin_enabled);
}

// Macros for validating an integer parameter
#define VALIDATE_INT_PARAM(PARAMETER, PARAMETER_NAME, TRC_STATEMENT)           \
  int parameter;                                                               \
  bool rc = validated_atoi(pj_optarg, parameter);                              \
                                                                               \
  if (rc)                                                                      \
  {                                                                            \
    PARAMETER = parameter;                                                     \
    TRC_INFO(""#TRC_STATEMENT" set to %d", parameter);                         \
  }                                                                            \
  else                                                                         \
  {                                                                            \
    TRC_ERROR("Invalid value for "#PARAMETER_NAME": %s", pj_optarg);           \
    return -1;                                                                 \
  }

#define VALIDATE_INT_PARAM_NON_ZERO(PARAMETER, PARAMETER_NAME, TRC_STATEMENT)  \
  int parameter;                                                               \
  bool rc = validated_atoi(pj_optarg, parameter);                              \
                                                                               \
  if ((rc) && (parameter > 0))                                                 \
  {                                                                            \
    PARAMETER = parameter;                                                     \
    TRC_INFO(""#TRC_STATEMENT" set to %d", parameter);                         \
  }                                                                            \
  else                                                                         \
  {                                                                            \
    TRC_ERROR("Invalid value for "#PARAMETER_NAME": %s", pj_optarg);           \
    return -1;                                                                 \
  }


