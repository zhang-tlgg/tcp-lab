#ifndef __TIMERS_H__
#define __TIMERS_H__

#include <functional>
#include <queue>
#include <stdint.h>
#include <vector>

// return -1 means break
// return >=0 means schedule in res ms
typedef std::function<int()> timer_fn;

// Return monotonic timestamp in msecs
uint64_t current_ts_msec();

// Return monotonic timestamp in usecs
uint64_t current_ts_usec();

class Timer {
public:
  Timer(timer_fn fn, uint64_t ts_msec);

  // Callback function
  timer_fn fn;
  // Timestamp in msecs
  uint64_t ts_msec;

  bool operator<(const Timer &other) const;
};

class Timers {
private:
  std::priority_queue<Timer> timers;

public:
  // Trigger timers
  void trigger();

  // Add job to timers
  void add_job(timer_fn fn, uint64_t ts_msec);

  // Schedule job to timers in msecs later
  void schedule_job(timer_fn fn, uint64_t delay_msec);
};

extern Timers TIMERS;

#endif