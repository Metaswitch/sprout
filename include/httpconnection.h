/**
 * @file httpconnection.h Definitions for HttpConnection class.
 *
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by post at
 * Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 */

///
///

#pragma once

#include <map>

#include <curl/curl.h>
#include <sas.h>

#include "statistic.h"

/// Provides managed access to data on a single HTTP server. Properly
/// supports round-robin DNS load balancing.
///
class HttpConnection
{
public:
  HttpConnection(const std::string& server, bool assertUser, int sasEventBase, const std::string& statName);
  ~HttpConnection();

  virtual bool get(const std::string& path, std::string& doc, const std::string& username, SAS::TrailId trail);

private:
  CURL* get_curl_handle();

  const std::string _server;
  const bool _assertUser;
  const int _sasEventBase;
  pthread_key_t _thread_local;

  Statistic _statistic;

  pthread_mutex_t _lock;
  std::map<std::string, int> _serverCount;  // must access under _lock

  friend class PoolEntry; // so it can update stats
};

