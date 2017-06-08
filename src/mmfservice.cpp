/**
 * @file mmfservice.cpp The MMF Config handler.
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <sys/stat.h>
#include <fstream>

#include "mmfservice.h"
#include "sprout_pd_definitions.h"
#include "utils.h"
#include "rapidjson/error/en.h"

MMFService::MMFService(Alarm* alarm,
                       std::string configuration):
  _alarm(alarm),
  _configuration(configuration),
  _updater(NULL)
{
  // Create an updater to keep the invoking of MMF configured correctly.
  _updater = new Updater<void, MMFService>
                              (this, std::mem_fun(&MMFService::update_config));
}

MMFService::~MMFService()
{
  delete _updater; _updater = NULL;
  _mmf_config.clear();
  delete _alarm; _alarm = NULL;
}

void MMFService::update_config()
{
  // Check whether the file exists.
  struct stat s;
  rapidjson::Document doc;

  TRC_DEBUG("stat (%s) returns %d", _configuration.c_str(),
            stat(_configuration.c_str(), &s));
  if ((stat(_configuration.c_str(), &s) != 0) &&
      (errno == ENOENT))
  {
    TRC_STATUS("No MMF configuration found (file %s does not exist)",
               _configuration.c_str());
    CL_SPROUT_MMF_FILE_MISSING.log();
    set_alarm();
    return;
  }

  TRC_STATUS("Loading MMF configuration from %s", _configuration.c_str());

  // Check whether the file is empty.
  std::ifstream fs(_configuration.c_str());
  std::string mmf_str((std::istreambuf_iterator<char>(fs)),
                        std::istreambuf_iterator<char>());
  if (mmf_str == "")
  {
    TRC_ERROR("Failed to read MMF configuration data from %s",
              _configuration.c_str());
    CL_SPROUT_MMF_FILE_EMPTY.log();
    set_alarm();
    return;
  }

  TRC_DEBUG("Read MMF config file from stream successfully.");

  // Check the file contains valid JSON
  try
  {
    doc.Parse<0>(mmf_str.c_str());
    TRC_DEBUG("Parsed into JSON Doc.");

    if (doc.HasParseError())
    {
      TRC_ERROR("Failed to read the MMF configuration data from %s "
                "due to a JSON parse error.", _configuration.c_str());
      TRC_DEBUG("Badly formed configuration data: %s", mmf_str.c_str());
      TRC_ERROR("Error: %s", rapidjson::GetParseError_En(doc.GetParseError()));
      JSON_FORMAT_ERROR();
    }

    std::map<std::string, MMFCfg::ptr> mmf_config;
    read_config(mmf_config, doc);

    TRC_DEBUG("Taking write lock on mmf config");

    // Take a write lock on the houdini config, in RAII style.
    boost::lock_guard<boost::shared_mutex> write_lock(get_mmf_rw_lock());

    // Now that we have the mmf config lock, free the memory from the old
    // mmf config objects, and start pointing at the new ones.
    TRC_DEBUG("Delete old MMF config.");
    _mmf_config = mmf_config;

    clear_alarm();
    TRC_DEBUG("Updated MMF config.");
  }
  catch (JsonFormatError err)
  {
    TRC_ERROR("Badly formed MMF configuration file - keep current config");
    CL_SPROUT_MMF_FILE_INVALID.log();
    set_alarm();
  }
}

void MMFService::read_config(std::map<std::string, MMFCfg::ptr>& mmf_config,
                             rapidjson::Document& doc)
{
  TRC_DEBUG("Reading MMF Config");

  if (!doc.HasMember("mmf_nodes"))
  {
    TRC_STATUS("No MMF config present in the %s file.  Sprout will not apply "
               "MMF to any calls.", _configuration.c_str());
    return;
  }

  const rapidjson::Value& mmf_nodes = doc["mmf_nodes"];

  // Iterate over MMF config in the config file
  for (rapidjson::Value::ConstValueIterator mmf_it = mmf_nodes.Begin();
       mmf_it != mmf_nodes.End();
       ++mmf_it)
  {
    // Throws a JsonFormatError if the config is invalid
    MMFCfg::ptr config(new MMFCfg(*mmf_it));

    for (std::string address : config->get_addresses())
    {
      if (has_config_for_address(address))
      {
        // This is a duplicate entry
        TRC_ERROR("Duplicate config present in the %s configuration file for"
                  "the address: '%s'", _configuration.c_str(), address.c_str());
        JSON_FORMAT_ERROR();
      }

      mmf_config.insert(std::make_pair(address, config));
    }
  }
}

void MMFService::set_alarm()
{
  if (_alarm)
  {
    _alarm->set();
  }
}

void MMFService::clear_alarm()
{
  if (_alarm)
  {
    _alarm->clear();
  }
}
