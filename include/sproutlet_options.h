/**
 * @file sproutlet_options.h  Sproutlet configuration options.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2016  Metaswitch Networks Ltd
 *
 * Parts of this module were derived from GPL licensed PJSIP sample code
 * with the following copyrights.
 *   Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 *   Copyright (C) 2003-2008 Benny Prijono <benny@prijono.org>
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

#ifndef SPROUTLETOPTIONS_H__
#define SPROUTLETOPTIONS_H__

#include <string>
#include <set>

// Set up a macro that calls the passed in macro for all Sproutlets. To add
// a new sproutlet just add it to the list here
#define SPROUTLET_MACRO(FUNCTION_NAME)                                         \
  FUNCTION_NAME(SCSCF, scscf, "scscf")                                         \
  FUNCTION_NAME(ICSCF, icscf, "icscf")                                         \
  FUNCTION_NAME(MEMENTO, memento, "memento")                                   \
  FUNCTION_NAME(MANGELWURZEL, mangelwurzel, "mangelwurzel")                    \
  FUNCTION_NAME(GEMINI, gemini, "gemini")                                      \
  FUNCTION_NAME(CDIV, cdiv, "cdiv")                                            \
  FUNCTION_NAME(MMTEL, mmtel, "mmtel")                                         \
  FUNCTION_NAME(BGCF, bgcf, "bgcf")

// Set up the options types for each Sproutlet. This goes into the OptionTypes
// ENUM.
#define SPROUTLET_OPTION_TYPES(NAME, NAME_LOWER, NAME_AS_STR)                  \
  OPT_PREFIX_##NAME,                                                           \
  OPT_PORT_##NAME,                                                             \
  OPT_URI_##NAME,

// Set up the mapping between parameters and ENUM types
#define SPROUTLET_CFG_PJ_STRUCT(NAME, NAME_LOWER, NAME_AS_STR)                 \
  { NAME_AS_STR,                required_argument, 0, OPT_PORT_##NAME},        \
  { "prefix-"#NAME_LOWER"",        required_argument, 0, OPT_PREFIX_##NAME},   \
  { "uri-"#NAME_LOWER"",           required_argument, 0, OPT_URI_##NAME},

// Each sproutlet can have its URI, prefix and port defined through config.
#define SPROUTLET_CFG_OPTIONS(NAME, NAME_LOWER, NAME_AS_STR)                   \
  std::string                          uri_##NAME_LOWER;                       \
  std::string                          prefix_##NAME_LOWER;                    \
  int                                  port_##NAME_LOWER;                      \
  bool                                 set_uri_##NAME_LOWER;                   \
  bool                                 set_prefix_##NAME_LOWER;                \
  bool                                 set_port_##NAME_LOWER;                  \
  bool                                 enabled_##NAME_LOWER;

// Set up the default config values
#define SPROUTLET_CFG_OPTIONS_DEFAULT_VALUES(NAME, NAME_LOWER, NAME_AS_STR)    \
  opt.uri_##NAME_LOWER = "";                                                   \
  opt.prefix_##NAME_LOWER = "";                                                \
  opt.port_##NAME_LOWER = 0;                                                   \
  opt.set_uri_##NAME_LOWER = false;                                            \
  opt.set_prefix_##NAME_LOWER = false;                                         \
  opt.set_port_##NAME_LOWER = false;                                           \
  opt.enabled_##NAME_LOWER = false;

// Parse the options
#define SPROUTLET_OPTIONS(NAME, NAME_LOWER, NAME_AS_STR)                       \
    case OPT_PORT_##NAME:                                                      \
      {                                                                        \
        int sproutlet_port;                                                    \
        bool parse_port_success =                                              \
           parse_port(std::string(pj_optarg), sproutlet_port);                 \
                                                                               \
        if (parse_port_success)                                                \
        {                                                                      \
          options->port_##NAME_LOWER = sproutlet_port;                         \
          options->set_port_##NAME_LOWER = true;                               \
          TRC_INFO(""#NAME_LOWER" port set to %d", sproutlet_port);            \
        }                                                                      \
        else                                                                   \
        {                                                                      \
          CL_SPROUT_INVALID_PORT_SPROUTLET.log(NAME_AS_STR, pj_optarg);        \
          TRC_ERROR(""#NAME_LOWER" port %s is invalid\n", pj_optarg);          \
          return -1;                                                           \
        }                                                                      \
        break;                                                                 \
      }                                                                        \
                                                                               \
    case OPT_PREFIX_##NAME:                                                    \
      {                                                                        \
        options->prefix_##NAME_LOWER = std::string(pj_optarg);                 \
        options->set_prefix_##NAME_LOWER = true;                               \
        TRC_INFO(""#NAME_LOWER" prefix set to %s", pj_optarg);                 \
        break;                                                                 \
      }                                                                        \
                                                                               \
    case OPT_URI_##NAME:                                                       \
      {                                                                        \
        options->uri_##NAME_LOWER = std::string(pj_optarg);                    \
        options->set_uri_##NAME_LOWER = true;                                  \
        TRC_INFO(""#NAME_LOWER" URI set to %s", pj_optarg);                    \
        break;                                                                 \
      }

// Verify the options
#define SPROUTLET_VERIFY_OPTIONS(NAME, NAME_LOWER, NAME_AS_STR)                \
  if (opt.set_port_##NAME_LOWER)                                               \
  {                                                                            \
    if (opt.port_##NAME_LOWER == 0)                                            \
    {                                                                          \
      TRC_INFO(""#NAME_LOWER" disabled");                                      \
      opt.enabled_##NAME_LOWER = false;                                        \
    }                                                                          \
    else                                                                       \
    {                                                                          \
      TRC_INFO(""#NAME_LOWER" enabled on %d", opt.port_##NAME_LOWER);          \
      opt.enabled_##NAME_LOWER = true;                                         \
      opt.sproutlet_ports.insert(opt.port_##NAME_LOWER);                       \
    }                                                                          \
  }                                                                            \
  else if (opt.port_##NAME_LOWER != 0)                                         \
  {                                                                            \
    TRC_INFO(""#NAME_LOWER" enabled on %d", opt.port_##NAME_LOWER);            \
    opt.enabled_##NAME_LOWER = true;                                           \
    opt.sproutlet_ports.insert(opt.port_##NAME_LOWER);                         \
  }                                                                            \
                                                                               \
  if (!opt.set_prefix_##NAME_LOWER)                                            \
  {                                                                            \
    opt.prefix_##NAME_LOWER = NAME_AS_STR;                                     \
  }                                                                            \
                                                                               \
  TRC_INFO(""#NAME_LOWER" prefix set to %s", opt.prefix_##NAME_LOWER.c_str()); \
                                                                               \
  if (!opt.set_uri_##NAME_LOWER)                                               \
  {                                                                            \
    opt.uri_##NAME_LOWER = "sip:" +                                            \
                           opt.prefix_##NAME_LOWER +                           \
                           "." +                                               \
                           opt.sprout_hostname +                               \
                           ":" + std::to_string(opt.port_##NAME_LOWER) +       \
                           ";transport=TCP";                                   \
  }                                                                            \
                                                                               \
  TRC_INFO(""#NAME_LOWER" uri set to %s", opt.uri_##NAME_LOWER.c_str());       \
                                                                               \
  if (opt.enabled_##NAME_LOWER)                                                \
  {                                                                            \
    if (opt.uri_##NAME_LOWER == "")                                            \
    {                                                                          \
      TRC_ERROR(""#NAME_LOWER" enabled, but no "#NAME_LOWER" URI specified");  \
      return 1;                                                                \
    }                                                                          \
    else                                                                       \
    {                                                                          \
      sproutlet_uris.push_back(opt.uri_##NAME_LOWER);                          \
    }                                                                          \
  }

#endif
