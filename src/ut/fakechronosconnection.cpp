/**
 * @file fakehssconnection.cpp Fake HSS Connection (for testing).
 *
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <cstdio>
#include "fakechronosconnection.hpp"
#include "gtest/gtest.h"
#include "sas.h"

FakeChronosConnection::FakeChronosConnection() : ChronosConnection("localhost", "localhost:9888", NULL, NULL)
{
}

FakeChronosConnection::~FakeChronosConnection()
{
  flush_all();
}


void FakeChronosConnection::flush_all()
{
  _results.clear();
}


void FakeChronosConnection::set_result(const std::string& url,
                                       const HTTPCode& result)
{
  _results[url] = result;
}


void FakeChronosConnection::delete_result(const std::string& url)
{
  _results.erase(url);
}

HTTPCode FakeChronosConnection::send_delete(const std::string& delete_identity,
                                            SAS::TrailId trail)
{
  return get_result(delete_identity);
}

HTTPCode FakeChronosConnection::send_post(std::string& post_identity,
                                          uint32_t timer_interval,
                                          const std::string& callback_uri,
                                          const std::string& opaque_data,
                                          SAS::TrailId trail,
                                          const std::map<std::string, uint32_t>& tags)
{
  HTTPCode status = get_result(post_identity);

  post_identity = "post_identity";
  return status;
}

HTTPCode FakeChronosConnection::send_put(std::string& put_identity,
                                         uint32_t timer_interval,
                                         const std::string& callback_uri,
                                         const std::string& opaque_data,
                                         SAS::TrailId trail,
                                         const std::map<std::string, uint32_t>& tags)
{
  HTTPCode status = get_result(put_identity);

  put_identity = "put_identity";
  return status;
}

HTTPCode FakeChronosConnection::get_result(std::string identity)
{
  std::map<std::string, HTTPCode>::const_iterator i = _results.find(identity);

  if (i != _results.end())
  {
    return i->second;
  }
  else
  {
    TRC_DEBUG("Failed to find Chronos result for %s", identity.c_str());
    return HTTP_BAD_REQUEST;
  }
}
