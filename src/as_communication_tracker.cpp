/**
 * @file as_communication_tracker.cpp
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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
