/**
 * @file test_interposer.hpp Unit test interposer - hooks various calls that are useful for UT.
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


#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <dlfcn.h>
#include <pthread.h>

#include <map>
#include <string>

#include "test_interposer.hpp"

/// The map we use.
static std::map<std::string, std::string> host_map;

/// The current time offset, and the lock which guards it.
static struct timespec time_offset = { 0, 0 };
static pthread_mutex_t time_offset_lock = PTHREAD_MUTEX_INITIALIZER;

/// The real functions we are interposing.
static int (*real_getaddrinfo)(const char*, const char*, const struct addrinfo*, struct addrinfo**);
static struct hostent* (*real_gethostbyname)(const char*);
static int (*real_clock_gettime)(clockid_t, struct timespec *);
static time_t (*real_time)(time_t*);

// Whether time is completely controlled by the test script.
bool completely_control_time = false;

/// Helper: add two timespecs. Arbitrary aliasing is fine.
static inline void ts_add(struct timespec& a, struct timespec& b, struct timespec& res)
{
  long nsec = a.tv_nsec + b.tv_nsec;
  res.tv_nsec = nsec % (1000L * 1000L * 1000L);
  res.tv_sec = (time_t)(nsec / (1000L * 1000L * 1000L)) + a.tv_sec + b.tv_sec;
}

/// Add a new mapping: lookup for host will actually lookup target.
void cwtest_add_host_mapping(std::string host, std::string target)
{
  host_map[host] = target;
}

/// Clear all mappings.
void cwtest_clear_host_mapping()
{
  host_map.clear();
}

/// Alter the fabric of space-time.
void cwtest_advance_time_ms(long delta_ms)  ///< Delta to add to the current offset applied to returned times (in ms).
{
  struct timespec delta = { delta_ms / 1000, (delta_ms % 1000) * 1000L * 1000L };
  pthread_mutex_lock(&time_offset_lock);
  ts_add(time_offset, delta, time_offset);
  pthread_mutex_unlock(&time_offset_lock);
}

/// Restore the fabric of space-time.
void cwtest_reset_time()
{
  pthread_mutex_lock(&time_offset_lock);
  time_offset.tv_sec = 0;
  time_offset.tv_nsec = 0;
  completely_control_time = false;
  pthread_mutex_unlock(&time_offset_lock);
}

void cwtest_completely_control_time(bool control)
{
  pthread_mutex_lock(&time_offset_lock);
  completely_control_time = control;
  pthread_mutex_unlock(&time_offset_lock);
}

bool cwtest_completely_controlling_time()
{
  bool control;
  pthread_mutex_lock(&time_offset_lock);
  control = completely_control_time;
  pthread_mutex_unlock(&time_offset_lock);
  return control;
}

/// Lookup helper.  If there is a mapping of this host in host_mapping
/// apply it, otherwise just return the host requested.
static inline std::string host_lookup(const char* node)
{
  std::string host(node);
  std::map<std::string,std::string>::iterator iter = host_map.find(host);
  if (iter != host_map.end())
  {
    // We have a mapping which says "turn a lookup for node into a
    // lookup for iter->second".  Apply it.
    host = iter->second;
  }

  return host;
}

/// Replacement getaddrinfo.
int getaddrinfo(const char *node,
                const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res)
{
  if (!real_getaddrinfo)
  {
    real_getaddrinfo = (int(*)(const char*, const char*, const struct addrinfo*, struct addrinfo**))dlsym(RTLD_NEXT, "getaddrinfo");
  }

  return real_getaddrinfo(host_lookup(node).c_str(), service, (const struct addrinfo*)hints, (struct addrinfo**)res);
}

/// Replacement gethostbyname.
struct hostent* gethostbyname(const char *name)
{
  if (!real_gethostbyname)
  {
    real_gethostbyname = (struct hostent*(*)(const char*))dlsym(RTLD_NEXT, "gethostbyname");
  }

  return real_gethostbyname(host_lookup(name).c_str());
}

/// Replacement clock_gettime.
int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
  int rc = 0;

  if (!real_clock_gettime)
  {
    real_clock_gettime = (int (*)(clockid_t, struct timespec *))dlsym(RTLD_NEXT, "clock_gettime");
  }

  if (cwtest_completely_controlling_time())
  {
    tp->tv_sec = 0;
    tp->tv_nsec = 0;
  }
  else
  {
    rc = real_clock_gettime(clk_id, tp);
  }

  if (!rc)
  {
    pthread_mutex_lock(&time_offset_lock);
    ts_add(*tp, time_offset, *tp);
    pthread_mutex_unlock(&time_offset_lock);
  }

  return rc;
}


/// Replacement time().
time_t time(time_t* v)
{
  time_t rt = 0;

  if (!real_time)
  {
    real_time = (time_t (*)(time_t*))dlsym(RTLD_NEXT, "time");
  }

  if (cwtest_completely_controlling_time())
  {
    rt = 0;
  }
  else
  {
    // Get the real time in seconds since the epoch.
    rt = real_time(NULL);
  }

  // Add the seconds portion of the time offset.
  pthread_mutex_lock(&time_offset_lock);
  rt += time_offset.tv_sec;
  pthread_mutex_unlock(&time_offset_lock);

  if (v != NULL)
  {
    // Pointer supplied, so set it to the returned value.
    *v = rt;
  }

  return rt;
}


