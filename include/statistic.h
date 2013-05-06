/**
 * @file statistic.h
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

#ifndef STATISTICS_H__
#define STATISTICS_H__

#include <string>
#include <zmq.h>
#include <vector>

#include <pthread.h>

#include "eventq.h"

class Statistic
{
public:
  Statistic(std::string statname);
  ~Statistic();

  void report_change(std::vector<std::string> new_value);

  static int known_stats_count();
  static std::string *known_stats();

  // Thread entry point for reporting thread.
  static void* reporter_thread(void* p);

private:
  void reporter();

  std::string _statname;
  void *_publisher;
  pthread_t _reporter;
  eventq<std::vector<std::string> > _stat_q;  // input queue

  static const int MAX_Q_DEPTH = 100;
};

#endif
