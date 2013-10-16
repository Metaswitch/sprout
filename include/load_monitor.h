//#include <iostream>
//#include <cstdio>
//#include <cstdlib>
#ifndef LOAD_MONITOR_H__
#define LOAD_MONITOR_H__

#include <time.h>
#include <mutex>
//#include <cmath>

//#include "log.h" // a MS header, then replace printf with LOG_DEBUG
//using namespace std;
class TokenBucket
{
  public:
    TokenBucket(int s, float r);
    float rate;
    int max_size;
    int tokens;  
    time_t replenish_time;
    std::mutex m;  
    bool get_token();
    void update_rate(float new_rate); 
    void update_max_size(int new_max_size);
//    private:
//        int max_size;
  //      int tokens;
    //    time_t replenish_time;

    void replenish_bucket();
};

class PenaltyCounter
{
  public:
    PenaltyCounter();
    int penalties;
    void reset_penalties();
    int get_penalties();
    void incr_penalties();
};

class LoadMonitor
{
  public:
    LoadMonitor(int init_target_latency, int max_bucket_size,
                float init_token_rate, float init_min_token_rate);
//            : bucket(max_bucket_size, init_token_rate);
    bool admit_request();
    void incr_penalties();
//private:
    void request_complete(int latency);
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
    PenaltyCounter penalty_counter;

    // MAKE THESE CONSTS?
    // Number of requests processed before each adjustment of leacky bucket rate
    int ADJUST_PERIOD;

    // Adjustment parameters for leaky bucket
    float DECREASE_THRESHOLD;// = 0.0;
    float DECREASE_FACTOR;// = 1.2;
    float INCREASE_THRESHOLD;// = -0.005;
    float INCREASE_FACTOR;// = 0.5;
};

#endif
