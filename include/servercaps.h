/**
 * @file servercaps.h  Server Capabilities as returned by HSS.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef __SERVERCAPS_H__
#define __SERVERCAPS_H__

#include <string>
#include <vector>

/// Structure storing server capabilities as returned by the HSS
struct ServerCapabilities
{
  /// The S-CSCF returned by the HSS.
  std::string scscf;

  /// The list of mandatory capabilities returned by the HSS.
  std::vector<int> mandatory_caps;

  /// The list of optional capabilities returned by the HSS.
  std::vector<int> optional_caps;

  /// The wildcarded identity returned by the HSS.
  std::string wildcard;
};

#endif
