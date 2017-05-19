/**
* @file scscfselector.h
*
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
*/

#ifndef SCSCFSELECTOR_H__
#define SCSCFSELECTOR_H__

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <boost/thread.hpp>
#include "updater.h"
#include "sas.h"

class SCSCFSelector
{
public:
  SCSCFSelector(const std::string& fallback_scscf_uri,
                std::string configuration = "./s-cscf.json");
  ~SCSCFSelector();

  // Updates the scscf configuration
  void update_scscf();

  // returns name of s-cscf with matching capabilities
  std::string get_scscf(const std::vector<int> &mandatory,
                        const std::vector<int> &optional,
                        const std::vector<std::string> &rejects,
                        SAS::TrailId trail);
private:
  typedef struct scscf
  {
    std::string server;
    int priority;
    int weight;
    std::vector<int> capabilities;
  } scscf_t;

  std::string _fallback_scscf_uri;
  std::string _configuration;
  std::vector<scscf> _scscfs;
  Updater<void, SCSCFSelector>* _updater;
  boost::shared_mutex _scscfs_rw_lock;
};

#endif

