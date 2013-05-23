/**
 * @file zmq_lvc.h
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

#ifndef STATISTIC_H__
#define STATISTIC_H__

extern "C" {
#include <pjlib.h>
}
#include <map>
#include <vector>
#include <string>
#include <zmq.h>

#define ZMQ_NEW_SUBSCRIPTION_MARKER 1

class LastValueCache
{
public:
  LastValueCache(int statcount, std::string *statnames, long poll_timeout);
  ~LastValueCache();
  void* get_internal_publisher(std::string statname);
  void run();

private:
  void clear_cache(void *entry);
  void replay_cache(void *entry);

  void **_subscriber;
  void *_publisher;
  std::map<void *, std::vector<zmq_msg_t *>> _cache;
  pthread_t _cache_thread;
  void *_context;
  int _statcount;
  std::string *_statnames;
  const long _poll_timeout;
  volatile bool _terminate;

  /// A bound 0MQ socket per statistic, for use by the internal
  // publishers. At most one thread may use each socket at
  // a time.
  std::map<std::string, void*> _internal_publishers;

  static void* last_value_cache_entry_func(void *);
};

#endif
