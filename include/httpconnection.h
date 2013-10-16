/**
 * @file httpconnection.h Definitions for HttpConnection class.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
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

#pragma once

#include <map>

#include <curl/curl.h>
#include <sas.h>

#include "utils.h"
#include "statistic.h"

typedef long HTTPCode;
#define HTTP_OK 200
#define HTTP_BAD_RESULT 400
#define HTTP_NOT_FOUND 404
#define HTTP_TEMP_UNAVAILABLE 480
#define HTTP_SERVER_ERROR 500

/// Provides managed access to data on a single HTTP server. Properly
/// supports round-robin DNS load balancing.
///
class HttpConnection
{
public:
  HttpConnection(const std::string& server, bool assert_user, int sas_event_base, const std::string& stat_name);
  virtual ~HttpConnection();

  virtual long get(const std::string& path, std::string& doc, const std::string& username, SAS::TrailId trail);

  static size_t string_store(void* ptr, size_t size, size_t nmemb, void* stream);
  static void cleanup_curl(void* curlptr);

private:

  /// A single entry in the connection pool. Stored inside a cURL handle.
  class PoolEntry
  {
  public:
    PoolEntry(HttpConnection* parent);
    ~PoolEntry();

    void set_remote_ip(const std::string& value);
    const std::string& get_remote_ip() const { return _remote_ip; };

    bool is_connection_expired(unsigned long now_ms);
    void update_deadline(unsigned long now_ms);

  private:
    /// Parent HttpConnection object.
    HttpConnection* _parent;

    /// Time beyond which this connection should be recycled, in
    // CLOCK_MONOTONIC milliseconds, or 0 for ASAP.
    unsigned long _deadline_ms;

    /// Random distribution to use for determining connection lifetimes.
    /// Use an exponential distribution because it is memoryless. This
    /// gives us a Poisson distribution of recycle events, both for
    /// individual threads and for the overall application.
    Utils::ExponentialDistribution _rand;

    /// Server IP we're connected to, if any.
    std::string _remote_ip;
  };

  CURL* get_curl_handle();
  HTTPCode curl_code_to_http_code(CURL* curl, CURLcode code);

  const std::string _server;
  const bool _assert_user;
  const int _sas_event_base;
  pthread_key_t _thread_local;

  Statistic _statistic;

  pthread_mutex_t _lock;
  std::map<std::string, int> _server_count;  // must access under _lock

  friend class PoolEntry; // so it can update stats
};

