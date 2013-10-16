#include "load_monitor.h"
#include <time.h>
#include <mutex>
#include "log.h" 

// a MS header, then replace printf with LOG_DEBUG
//using namespace std;
TokenBucket::TokenBucket(int s, float r)
{
  max_size = s;
  tokens = max_size;
  rate = r;
  replenish_time = time(0);
}

bool TokenBucket::get_token()
{
  m.lock();
  time_t new_replenish_time = time(0);
  tokens += (int) (rate * (new_replenish_time - replenish_time));
  replenish_time = new_replenish_time;
        
  if (tokens > max_size)
  {
    tokens = max_size;
  }
 
  bool rc = (tokens >= 1);
  
  if (rc)
  {
    tokens -= 1;
  }

  m.unlock();

  return rc;
}

void TokenBucket::update_rate(float new_rate)
{
  rate = new_rate;
}

void TokenBucket::update_max_size(int new_max_size)
{
  max_size = new_max_size;
}
    
void TokenBucket::replenish_bucket()
{
  time_t new_replenish_time = time(0);
  tokens += (int) (rate * (new_replenish_time - replenish_time));
  replenish_time = new_replenish_time;

  if (tokens > max_size)
  {
    tokens = max_size;
  }
}

PenaltyCounter::PenaltyCounter()
{
  penalties = 0;
}

void PenaltyCounter::reset_penalties()
{
  penalties = 0;
}

int PenaltyCounter::get_penalties()
{
  return penalties;
}

void PenaltyCounter::incr_penalties()
{
  penalties += 1;
}

    // I believe the magic colon syntax is what you need to initialise bucket
LoadMonitor::LoadMonitor(int init_target_latency, int max_bucket_size,
                         float init_token_rate, float init_min_token_rate)
                         : bucket(max_bucket_size, init_token_rate), penalty_counter()
{
  ADJUST_PERIOD = 20;
  DECREASE_THRESHOLD = 0.0;
  DECREASE_FACTOR = 1.2;
  INCREASE_THRESHOLD = -0.005;
  INCREASE_FACTOR = 0.5;       
    
  accepted = 0;
  rejected = 0;
  penalties = 0;
  pending_count = 0;
  max_pending_count = 0;
  target_latency = init_target_latency;
  smoothed_latency = 0;
  adjust_count = ADJUST_PERIOD;
  min_token_rate = init_min_token_rate;
}
    
bool LoadMonitor::admit_request()
{
  if (bucket.get_token())
  {
    // Got a token from the bucket, so admit the request
    accepted += 1;
    pending_count += 1;
           
    if (pending_count > max_pending_count)
    {
      max_pending_count = pending_count;
    }
    
    return true;
  }
  else
  {
    rejected += 1;
    return false;
  }        
}

void LoadMonitor::incr_penalties()
{
  penalties += 1;
}

    
void LoadMonitor::request_complete(int latency)
{
  pending_count -= 1;
  smoothed_latency = (7 * smoothed_latency + latency) / 8;
  adjust_count -= 1;
        
  if (adjust_count <= 0)
  {
    // This algorithm is based on the Welsh and Culler "Adaptive Overload
    // Control for Busy Internet Servers" paper, although based on a smoothed
    // mean latency, rather than the 90th percentile as per the paper.
    // Also, the additive increase is scaled as a proportion of the maximum
    // bucket size, rather than an absolute number as per the paper.
    float err = ((float) (smoothed_latency - target_latency)) / target_latency;

    // Work out the percentage of accepted requests (for logs)
    float accepted_percent = 100 * (((float) accepted) / (accepted + rejected));

    //int overload_penalties = penalty_counter.get_penalties();

    LOG_DEBUG("Accepted %f%% of requests, latency error = %f, overload responses = %d", 
               accepted_percent, err, penalties);

    // latency is above where we want it to be, or we are getting overload responses from 
    // Homer/Homestead, so adjust the rate downwards by a multiplicative factor
    if (err > DECREASE_THRESHOLD || penalties > 0)
    {
      float new_rate = bucket.rate / DECREASE_FACTOR;

      if (new_rate < min_token_rate)
      {
        new_rate = min_token_rate;
      }

      bucket.update_rate(new_rate);

      LOG_DEBUG("Decrease rate to %f", bucket.rate);
    }
    else if (err < INCREASE_THRESHOLD)
    {
      float new_rate = bucket.rate + 
                        (-1 * err * bucket.max_size * INCREASE_FACTOR);
      bucket.update_rate(new_rate);

      LOG_DEBUG("Increase rate to %f", bucket.rate);
    }
    else
    {
      LOG_DEBUG("Rate unchanged at %f", bucket.rate);
    }

    // Reset counts
    adjust_count = ADJUST_PERIOD;
    accepted = 0;
    rejected = 0;
    penalties = 0;
  }
}
