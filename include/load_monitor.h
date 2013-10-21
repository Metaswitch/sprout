/**
 * @file load_monitor.h Definitions for LoadMonitor class.
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

#ifndef LOAD_MONITOR_H__
#define LOAD_MONITOR_H__

#include <time.h>
#include <pthread.h>
 
class TokenBucket
{
  public:
    TokenBucket(int s, float r);
    float rate;
    int max_size;
    bool get_token();
    void update_rate(float new_rate); 
  private:
    timespec replenish_time;
    float tokens;
    void replenish_bucket();
};

class LoadMonitor
{
  public:
    LoadMonitor(int init_target_latency, int max_bucket_size,
                float init_token_rate, float init_min_token_rate);
    ~LoadMonitor();
    bool admit_request();
    void incr_penalties();
    void request_complete(int latency);

  private:
    // This must be held when accessing any of this object's member variables.
     pthread_mutex_t _lock;
   
    // Number of requests processed before each adjustment of token bucket rate
    int ADJUST_PERIOD;

    // Adjustment parameters for token bucket
    float DECREASE_THRESHOLD;
    float DECREASE_FACTOR;
    float INCREASE_THRESHOLD;
    float INCREASE_FACTOR;
  
    int accepted;
    int rejected;
    int penalties;
    int pending_count;
    int max_pending_count;
    int target_latency;
    int smoothed_latency;
    int adjust_count;
    float min_token_rate;
    TokenBucket bucket;
};

#endif
