/**
 * @file httpconnection.cpp HttpConnection class methods.
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

#include <curl/curl.h>
#include <cassert>
#include <iostream>

#include "utils.h"
#include "log.h"
#include "sas.h"
#include "sasevent.h"
#include "httpconnection.h"
#include "load_monitor.h"

/// Total time to wait for a response from the server before giving
/// up.  This is the value that affects the user experience, so should
/// be set to what we consider acceptable.  Covers lookup, possibly
/// multiple connection attempts, request, and response.  In
/// milliseconds.
static const long TOTAL_TIMEOUT_MS = 500;

/// Approximate length of time to wait before giving up on a
/// connection attempt to a single address (in milliseconds).  cURL
/// may wait more or less than this depending on the number of
/// addresses to be tested and where this address falls in the
/// sequence. A connection will take longer than this to establish if
/// multiple addresses must be tried. This includes only the time to
/// perform the DNS lookup and establish the connection, not to send
/// the request or receive the response.
///
/// We set this quite short to ensure we quickly move on to another
/// server. A connection should be very fast to establish (a few
/// milliseconds) in the success case.
static const long SINGLE_CONNECT_TIMEOUT_MS = 50;

/// Mean age of a connection before we recycle it. Ensures we respect
/// DNS changes, and that we rebalance load when servers come back up
/// after failure. Actual connection recycle events are
/// Poisson-distributed with this mean inter-arrival time.
static const double CONNECTION_AGE_MS = 60 * 1000.0;


HttpConnection::HttpConnection(const std::string& server,      //< Server to send HTTP requests to.
                               bool assert_user,               //< Assert user in header?
                               int sas_event_base,             //< SAS events: sas_event_base - will have  SASEvent::HTTP_REQ / RSP / ERR added to it.
                               const std::string& stat_name,   //< Name of statistic to report connection info to.
                               LoadMonitor* load_monitor) :    //< Load Monitor.
  _server(server),
  _assert_user(assert_user),
  _sas_event_base(sas_event_base),
  _statistic(stat_name)
{
  pthread_key_create(&_thread_local, cleanup_curl);
  pthread_mutex_init(&_lock, NULL);
  curl_global_init(CURL_GLOBAL_DEFAULT);
  std::vector<std::string> no_stats;
  _statistic.report_change(no_stats);
  _load_monitor = load_monitor;
}


HttpConnection::~HttpConnection()
{
  // Clean up this thread's connection now, rather than waiting for
  // pthread_exit.  This is to support use by single-threaded code
  // (e.g., UTs), where pthread_exit is never called.
  CURL* curl = pthread_getspecific(_thread_local);
  if (curl != NULL)
  {
    pthread_setspecific(_thread_local, NULL);
    cleanup_curl(curl);
  }
}


/// Get the thread-local curl handle if it exists, and create it if not.
CURL* HttpConnection::get_curl_handle()
{
  CURL* curl = pthread_getspecific(_thread_local);
  if (curl == NULL)
  {
    curl = curl_easy_init();
    LOG_DEBUG("Allocated CURL handle %p", curl);
    pthread_setspecific(_thread_local, curl);

    // Create our private data
    PoolEntry* entry = new PoolEntry(this);
    curl_easy_setopt(curl, CURLOPT_PRIVATE, entry);

    // Retrieved data will always be written to a string.
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &string_store);

    // Tell cURL to fail on 400+ response codes.
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);

    // We always talk to the same server, unless we intentionally want
    // to rotate our requests. So a connection pool makes no sense.
    curl_easy_setopt(curl, CURLOPT_MAXCONNECTS, 1L);

    // Maximum time to wait for a response.
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TOTAL_TIMEOUT_MS);

    // Time to wait until we establish a TCP connection to one of the
    // available addresses.  We will try the first address for half of
    // this time.
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 2 * SINGLE_CONNECT_TIMEOUT_MS);

    // We mustn't reuse DNS responses, because cURL does no shuffling
    // of DNS entries and we rely on this for load balancing.
    curl_easy_setopt(curl, CURLOPT_DNS_CACHE_TIMEOUT, 0L);

    // Nagle is not required. Probably won't bite us, but can't hurt
    // to turn it off.
    curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1L);

    // We are a multithreaded app using C-Ares. This is the
    // recommended setting.
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  }
  return curl;
}

// Map the CURLcode into a sensible HTTP return code.
HTTPCode HttpConnection::curl_code_to_http_code(CURL* curl, CURLcode code)
{
  switch (code)
  {
  case CURLE_OK:
    return HTTP_OK;
  // LCOV_EXCL_START
  case CURLE_URL_MALFORMAT:
  case CURLE_NOT_BUILT_IN:
    return HTTP_BAD_RESULT;
  // LCOV_EXCL_STOP
  case CURLE_REMOTE_FILE_NOT_FOUND:
    return HTTP_NOT_FOUND;
  // LCOV_EXCL_START
  case CURLE_COULDNT_RESOLVE_PROXY:
  case CURLE_COULDNT_RESOLVE_HOST:
  case CURLE_COULDNT_CONNECT:
  case CURLE_AGAIN:
    return HTTP_NOT_FOUND;
  case CURLE_HTTP_RETURNED_ERROR:
    // We have an actual HTTP error available, so use that.
  {
    long http_code = 0;
    CURLcode rc = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    assert(rc == CURLE_OK);
    return http_code;
  }
  default:
    return HTTP_SERVER_ERROR;
  // LCOV_EXCL_STOP
  }
}

/// Get data; return a HTTP return code
HTTPCode HttpConnection::get(const std::string& path,       //< Absolute path to request from server - must start with "/"
                             std::string& doc,             //< OUT: Retrieved document
                             const std::string& username,  //< Username to assert (if assertUser was true, else ignored).
                             SAS::TrailId trail)          //< SAS trail to use
{
  std::string url = "http://" + _server + path;
  struct curl_slist *extra_headers = NULL;
  CURL *curl = get_curl_handle();

  PoolEntry* entry;
  CURLcode rc = curl_easy_getinfo(curl, CURLINFO_PRIVATE, (char**)&entry);
  assert(rc == CURLE_OK);

  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &doc);
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

  if (_assert_user)
  {
    extra_headers = curl_slist_append(extra_headers, ("X-XCAP-Asserted-Identity: " + username).c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, extra_headers);
  }

  // Determine whether to recycle the connection, based on
  // previously-calculated deadline.
  struct timespec tp;
  int rv = clock_gettime(CLOCK_MONOTONIC, &tp);
  assert(rv == 0);
  unsigned long now_ms = tp.tv_sec * 1000 + (tp.tv_nsec / 1000000);
  bool recycle_conn = entry->is_connection_expired(now_ms);
  bool first_error_503 = false;
  
  // Try to get a decent connection. We may need to retry, but only
  // once - cURL itself does most of the retrying for us.
  for (int attempt = 0; attempt < 2; attempt++)
  {
    curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, recycle_conn ? 1L : 0L);

    // Report the request to SAS.
    SAS::Event http_req_event(trail, _sas_event_base + SASEvent::HTTP_REQ, 1u);
    http_req_event.add_var_param(url);
    SAS::report_event(http_req_event);

    // Send the request.
    doc.clear();
    LOG_DEBUG("Sending HTTP request : GET %s (try %d) %s", url.c_str(), attempt, (recycle_conn) ? "on new connection" : "");
    rc = curl_easy_perform(curl);

    if (rc == CURLE_OK)
    {
      LOG_DEBUG("Received HTTP response : %s", doc.c_str());

      // Report the response to SAS.
      SAS::Event http_rsp_event(trail, _sas_event_base + SASEvent::HTTP_RSP, 1u);
      http_rsp_event.add_var_param(url);
      http_rsp_event.add_var_param(doc);
      SAS::report_event(http_rsp_event);

      if (recycle_conn)
      {
        entry->update_deadline(now_ms);
      }

      // Success!
      break;
    }
    else
    {
      LOG_DEBUG("Received HTTP error response : GET %s : %s", url.c_str(), curl_easy_strerror(rc));

      // Report the error to SAS
      SAS::Event http_err_event(trail, _sas_event_base + SASEvent::HTTP_ERR, 1u);
      http_err_event.add_static_param(rc);
      http_err_event.add_var_param(url);
      http_err_event.add_var_param(curl_easy_strerror(rc));
      SAS::report_event(http_err_event);

      long http_rc = 0;
      if (rc == CURLE_HTTP_RETURNED_ERROR)
      {
        // Get the HTTP error code returned from the server.
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_rc);
      }

      bool error_is_503 = ((rc == CURLE_HTTP_RETURNED_ERROR) && (http_rc == 503));

      // Is this an error we should retry? If cURL itself has already
      // retried (e.g., CURLE_COULDNT_CONNECT) then there is no point
      // in us retrying. But if the remote application has hung
      // (CURLE_OPERATION_TIMEDOUT) or a previously-up connection has
      // failed (CURLE_SEND|RECV_ERROR) then we must retry once
      // ourselves.
      bool non_fatal = ((rc == CURLE_OPERATION_TIMEDOUT) ||
                        (rc == CURLE_SEND_ERROR) ||
                        (rc == CURLE_RECV_ERROR) ||
                        (error_is_503));

      char* remote_ip;
      curl_easy_getinfo(curl, CURLINFO_PRIMARY_IP, &remote_ip);

      if ((non_fatal) && (attempt == 0))
      {
        // Loop around and try again.  Always request a fresh connection.
        LOG_ERROR("GET %s failed at server %s : %s (%d %d) : retrying",
                  url.c_str(), remote_ip, curl_easy_strerror(rc), rc, http_rc);
        recycle_conn = true;
        
        // Record that the first error was a 503 error. 
        if (error_is_503)
        {
          first_error_503 = true;
        }
      }
      else
      {
        // Fatal error or we've already retried once - we're done!
        LOG_ERROR("GET %s failed at server %s : %s (%d %d) : fatal",
                  url.c_str(), remote_ip, curl_easy_strerror(rc), rc, http_rc);

        // Check whether both attempts returned 503 errors, or the error was 
        // a 502 (where the HSS is overloaded)  and raise a penalty if so. 
        if ((error_is_503 && first_error_503) ||
            ((rc == CURLE_HTTP_RETURNED_ERROR) && (http_rc == 502)))
        {
          _load_monitor->incr_penalties();
        }

        break;
      }
    }
  }

  curl_slist_free_all(extra_headers);

  if ((rc == CURLE_OK) || (rc == CURLE_HTTP_RETURNED_ERROR))
  {
    char* remote_ip;
    CURLcode rc = curl_easy_getinfo(curl, CURLINFO_PRIMARY_IP, &remote_ip);

    if (rc == CURLE_OK)
    {
      entry->set_remote_ip(remote_ip);
    }
    else
    {
      entry->set_remote_ip("UNKNOWN");  // LCOV_EXCL_LINE Can't happen.
    }
  }
  else
  {
    entry->set_remote_ip("");
  }

  HTTPCode http_code = curl_code_to_http_code(curl, rc);
  if ((rc != CURLE_OK) && (rc != CURLE_REMOTE_FILE_NOT_FOUND))
  {
    LOG_ERROR("cURL failure with cURL error code %d (see man 3 libcurl-errors) and HTTP error code %ld", (int)rc, http_code);  // LCOV_EXCL_LINE
  }
  return http_code;
}


/// cURL helper - write data into string.
size_t HttpConnection::string_store(void* ptr, size_t size, size_t nmemb, void* stream)
{
  ((std::string*)stream)->append((char*)ptr, size * nmemb);
  return (size * nmemb);
}


/// Called to clean up the cURL handle.
void HttpConnection::cleanup_curl(void* curlptr)
{
  CURL* curl = (CURL*)curlptr;

  PoolEntry* entry;
  CURLcode rc = curl_easy_getinfo(curl, CURLINFO_PRIVATE, (char**)&entry);
  if (rc == CURLE_OK)
  {
    // Connection has closed.
    entry->set_remote_ip("");
    delete entry;
  }

  curl_easy_cleanup(curl);
}


/// PoolEntry constructor
HttpConnection::PoolEntry::PoolEntry(HttpConnection* parent) :
  _parent(parent),
  _deadline_ms(0L),
  _rand(1.0 / CONNECTION_AGE_MS)
{
}


/// PoolEntry destructor
HttpConnection::PoolEntry::~PoolEntry()
{
}


/// Is it time to recycle the connection? Expects CLOCK_MONOTONIC
/// current time, in milliseconds.
bool HttpConnection::PoolEntry::is_connection_expired(unsigned long now_ms)
{
  return (now_ms > _deadline_ms);
}


/// Update deadline to next appropriate value. Expects
/// CLOCK_MONOTONIC current time, in milliseconds.  Call on
/// successful connection.
void HttpConnection::PoolEntry::update_deadline(unsigned long now_ms)
{
  // Get the next desired inter-arrival time. Choose this
  // randomly so as to avoid spikes.
  unsigned long interval_ms = (unsigned long)_rand();

  if ((_deadline_ms == 0L) ||
      ((_deadline_ms + interval_ms) < now_ms))
  {
    // This is the first request, or the next arrival has
    // already passed (in which case things must be pretty
    // quiet). Just bump the next deadline into the future.
    _deadline_ms = now_ms + interval_ms;
  }
  else
  {
    // The next arrival is yet to come. Schedule it relative to
    // the last intended time, so as not to skew the mean
    // upwards.
    _deadline_ms += interval_ms;
  }
}


/// Set the remote IP, and update statistics.
void HttpConnection::PoolEntry::set_remote_ip(const std::string& value)  //< Remote IP, or "" if no connection.
{
  if (value == _remote_ip)
  {
    return;
  }

  pthread_mutex_lock(&_parent->_lock);

  if (!_remote_ip.empty())
  {
    // Decrement the number of connections to this address.
    if (--_parent->_server_count[_remote_ip] <= 0)
    {
      // No more connections to this address, so remove it from the map.
      _parent->_server_count.erase(_remote_ip);
    }
  }

  if (!value.empty())
  {
    // Increment the count of connections to this address.  (Note this is
    // safe even if this is the first connection as the [] operator will
    // insert an entry initialised to 0.)
    ++_parent->_server_count[value];
  }

  _remote_ip = value;

  // Now build the statistics to report.
  std::vector<std::string> new_value;

  for (std::map<std::string, int>::iterator iter = _parent->_server_count.begin();
       iter != _parent->_server_count.end();
       ++iter)
  {
    new_value.push_back(iter->first);
    new_value.push_back(std::to_string(iter->second));
  }

  pthread_mutex_unlock(&_parent->_lock);

  // Actually report outside the mutex to avoid any risk of deadlock.
  _parent->_statistic.report_change(new_value);
}


