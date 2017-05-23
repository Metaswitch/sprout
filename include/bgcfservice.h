/**
 * @file bgcfservice.h class definition for an BGCF service provider
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

///
///

#ifndef BGCFSERVICE_H__
#define BGCFSERVICE_H__

#include <map>
#include <string>
#include <boost/regex.hpp>
#include <boost/thread.hpp>

#include <functional>
#include "updater.h"
#include "sas.h"

class BgcfService
{
public:
  BgcfService(std::string configuration = "./bgcf.json");
  ~BgcfService();

  /// Updates the bgcf routes
  void update_routes();

  std::vector<std::string> get_route_from_domain(const std::string &domain,
                                                 SAS::TrailId trail) const;
  std::vector<std::string> get_route_from_number(const std::string &number,
                                                 SAS::TrailId trail) const;

private:
  std::map<std::string, std::vector<std::string>> _domain_routes;
  std::map<std::string, std::vector<std::string>> _number_routes;
  std::string _configuration;
  Updater<void, BgcfService>* _updater;

  // Mark as mutable to flag that this can be modified without affecting the
  // external behaviour of the class, allowing for locking in 'const' methods.
  mutable boost::shared_mutex _routes_rw_lock;
};

#endif
