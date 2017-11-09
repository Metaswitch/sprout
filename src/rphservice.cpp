/**
 * @file rphservice.cpp - Service for loading and managing RPH configuration
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <sys/stat.h>
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "json_parse_utils.h"
#include <fstream>

#include "rphservice.h"
#include "log.h"
#include "sas.h"
#include "sproutsasevent.h"
#include "sprout_pd_definitions.h"
#include "utils.h"

// JSON constants
static const char * const JSON_PRIORITY_BLOCKS = "priority_blocks";
static const char * const JSON_PRIORITY = "priority";
static const char * const JSON_RPH_VALUES = "rph_values";

RPHService::RPHService(Alarm* alarm,
                       std::string configuration) :
  _alarm(alarm),
  _configuration(configuration),
  _updater(NULL)
{
  // Create an updater to keep the shared iFC sets configured appropriately.
  _updater = new Updater<void, RPHService>
                                (this, std::mem_fun(&RPHService::update_rph));
}

RPHService::~RPHService()
{
  delete _updater; _updater = NULL;
  delete _alarm; _alarm = NULL;
}

void RPHService::update_rph()
{
  // Check whether the file exists.
  struct stat s;
  if ((stat(_configuration.c_str(), &s) != 0) &&
      (errno == ENOENT))
  {
    TRC_STATUS("No RPH configuration (file %s does not exist)",
               _configuration.c_str());
    CL_SPROUT_RPH_FILE_MISSING.log();
    set_alarm();
    return;
  }

  TRC_STATUS("Loading RPH configuration from %s", _configuration.c_str());

  // Read from the file
  std::ifstream fs(_configuration.c_str());
  std::string rph_str((std::istreambuf_iterator<char>(fs)),
                       std::istreambuf_iterator<char>());

  if (rph_str == "")
  {
    TRC_ERROR("Failed to read RPH configuration data from %s",
              _configuration.c_str());
    CL_SPROUT_RPH_FILE_EMPTY.log();
    set_alarm();
    return;
  }

  // Now parse the document
  rapidjson::Document doc;
  doc.Parse<0>(rph_str.c_str());

  std::map<std::string, int> new_rph_map;

  if (doc.HasParseError())
  {
    TRC_ERROR("Failed to read RPH configuration data: %s\nError: %s",
              rph_str.c_str(),
              rapidjson::GetParseError_En(doc.GetParseError()));
    CL_SPROUT_RPH_FILE_INVALID.log();
    set_alarm();
    return;
  }

  try
  {
    JSON_ASSERT_CONTAINS(doc, JSON_PRIORITY_BLOCKS);
    JSON_ASSERT_ARRAY(doc[JSON_PRIORITY_BLOCKS]);
    rapidjson::Value& pb_arr = doc[JSON_PRIORITY_BLOCKS];

    for (rapidjson::Value::ValueIterator pb_it = pb_arr.Begin();
         pb_it != pb_arr.End();
         ++pb_it)
    {
      try
      {
        int priority;
        JSON_GET_INT_MEMBER(*pb_it, JSON_PRIORITY, priority);

        if ((priority < 1) || (priority > 15))
        {
          TRC_ERROR("RPH value block contains a priority not in the range 1-15");
          CL_SPROUT_RPH_FILE_INVALID_CONFIG.log();
          set_alarm();
          return;
        }

        std::vector<std::string> rph_values;
        extract_json_string_array(*pb_it, JSON_RPH_VALUES, rph_values);
        for (std::string rph_value: rph_values)
        {
          if (new_rph_map.insert(std::make_pair(rph_value, priority)).second == false)
          {
            TRC_ERROR("Attempted to insert an RPH value into the map that already exists");
            CL_SPROUT_RPH_FILE_INVALID.log();
            set_alarm();
            return;
          }
        }
      }
      catch (JsonFormatError err)
      {
        // Badly formed priority block.
        TRC_ERROR("Badly formed RPH priority block (hit error at %s:%d)",
                    err._file, err._line);
        CL_SPROUT_RPH_FILE_INVALID.log();
        set_alarm();
        return;
      }
    }
  }
  catch (JsonFormatError err)
  {
    TRC_ERROR("Badly formed RPH configuration data - missing priority_blocks array");
    CL_SPROUT_RPH_FILE_INVALID.log();
    set_alarm();
    return;
  }

  // TODO: More checking of temporary map, including:
  //  - Check that RPH values are well ordered.
  //  - There are no unknown RPH values.

  // At this point, we're definitely going to override the RPH map we currently have so,
  // take the lock and update the map.
  boost::lock_guard<boost::shared_mutex> write_lock(_sets_rw_lock);
  _rph_map = new_rph_map;


  // We've successfully uploaded RPH configuration so clear the alarm.
  clear_alarm();
}

int RPHService::lookup_priority(std::string rph_value)
{
  int priority = 0;

  // Take a read lock on the mutex in RAII style
  boost::shared_lock<boost::shared_mutex> read_lock(_sets_rw_lock);

  // Lookup the key in the map. If it doesn't exist, we will return the default
  // priority of 0.
  std::map<std::string, int>::iterator result = _rph_map.find(rph_value);
  if (result != _rph_map.end())
  {
    priority = result->second;
  }

  return priority;
}

void RPHService::set_alarm()
{
  if (_alarm)
  {
    _alarm->set();
  }
}

void RPHService::clear_alarm()
{
  if (_alarm)
  {
    _alarm->clear();
  }
}
