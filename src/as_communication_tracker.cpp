/**
 * @file as_communication_tracker.cpp
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2016  Metaswitch Networks Ltd
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

#include "as_communication_tracker.h"

AsCommunicationTracker::AsCommunicationTracker(Alarm* alarm,
                                               const PDLog2<const char*, const char*>* as_failed_log,
                                               const PDLog1<const char*>* as_ok_log) :
  _next_check_time_ms(current_time_ms() + NEXT_CHECK_INTERVAL_MS),
  _alarm(alarm),
  _as_failed_log(as_failed_log),
  _as_ok_log(as_ok_log)
{
  pthread_mutex_init(&_lock, NULL);
}


AsCommunicationTracker::~AsCommunicationTracker()
{
  pthread_mutex_destroy(&_lock);
}


void AsCommunicationTracker::on_success(const std::string& as_uri)
{
  TRC_DEBUG("Communication with AS %s successful", as_uri.c_str());
  check_for_healthy_app_servers();
}


void AsCommunicationTracker::on_failure(const std::string& as_uri,
                                        const std::string& reason)
{
  TRC_DEBUG("Communication with AS %s failed", as_uri.c_str());

  pthread_mutex_lock(&_lock);

  // If we didn't know of any failed ASs, we do now so we should raise the
  // alarm.
  if (_as_failures.empty())
  {
    TRC_DEBUG("First failure - raise the alarm");
    _alarm->set();
  }

  // Add an entry to the failed ASs map (incrementing the count of failures if
  // it has already failed).
  std::map<std::string, int>::iterator as_iter = _as_failures.find(as_uri);

  if (as_iter != _as_failures.end())
  {
    as_iter->second++;
  }
  else
  {
    // This is the first time we've spotted that the AS has failed, so log this
    // fact.
    TRC_DEBUG("First failure for this AS - generate log");
    _as_failed_log->log(as_uri.c_str(), reason.c_str());
    _as_failures[as_uri] = 1;
  }
  pthread_mutex_unlock(&_lock);

  // Even though communication to this AS has failed, other ASs may have become
  // healthy recently so we still need to check them.
  check_for_healthy_app_servers();
}


void AsCommunicationTracker::check_for_healthy_app_servers()
{
  uint64_t now = current_time_ms();
  TRC_DEBUG("Current time is %ld, next AS check at %ld",
            now, _next_check_time_ms.load());

  if (now > _next_check_time_ms)
  {
    pthread_mutex_lock(&_lock);

    if (now > _next_check_time_ms)
    {
      TRC_DEBUG("Check for ASs that have become healthy again");

      // Don't check again for a while.
      _next_check_time_ms = current_time_ms() + NEXT_CHECK_INTERVAL_MS;

      // Iterate through all the AS in our map. If any of them have not had
      // any failures in the last time period we will log they are now working
      // correctly and remove them from the map.
      //
      // We mutate the map as we iterate over it. The non-standard loop
      // construct avoids iterator invalidation.
      std::map<std::string, int>::iterator curr_as = _as_failures.begin();
      std::map<std::string, int>::iterator next_as;

      while (curr_as != _as_failures.end())
      {
        next_as = std::next(curr_as);

        if (curr_as->second == 0)
        {
          TRC_DEBUG("AS %s has become healthy", curr_as->first.c_str());
          _as_ok_log->log(curr_as->first.c_str());
          _as_failures.erase(curr_as);
        }
        else
        {
          curr_as->second = 0;
        }

        curr_as = next_as;
      }

      if (_as_failures.empty())
      {
        TRC_DEBUG("All ASs OK - clear the alarm");
        // No ASs are currently failed. Clear the alarm.
        _alarm->clear();
      }
    }

    pthread_mutex_unlock(&_lock);
  }
}


uint64_t AsCommunicationTracker::current_time_ms()
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000 + (ts.tv_nsec / 1000000);
}
