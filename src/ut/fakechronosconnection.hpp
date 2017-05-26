/**
 * @file fakehssconnection.hpp Header file for fake HSS connection (for testing).
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#pragma once

#include <string>
#include "log.h"
#include "sas.h"
#include "chronosconnection.h"

/// ChronosConnection that writes to/reads from a local map rather than the HSS.
class FakeChronosConnection : public ChronosConnection
{
public:
  FakeChronosConnection();
  ~FakeChronosConnection();

  void flush_all();
  void set_result(const std::string& url, const HTTPCode& result);
  void delete_result(const std::string& url);

private:
  std::map<std::string, HTTPCode> _results;
  HTTPCode send_delete(const std::string& delete_identity,
                       SAS::TrailId trail);
  HTTPCode send_post(std::string& post_identity,
                     uint32_t timer_interval,
                     const std::string& callback_uri,
                     const std::string& opaque_data,
                     SAS::TrailId trail,
                     const std::map<std::string, uint32_t>& tags);
  HTTPCode send_put(std::string& put_identity,
                    uint32_t timer_interval,
                    const std::string& callback_uri,
                    const std::string& opaque_data,
                    SAS::TrailId trail,
                    const std::map<std::string, uint32_t>& tags);
  HTTPCode get_result(std::string identity);
};
