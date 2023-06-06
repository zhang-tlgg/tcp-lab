#include "timers.h"
#include <sys/time.h>
#include <time.h>

Timers TIMERS;

uint64_t current_ts_msec() {
  struct timespec tp;
  clock_gettime(CLOCK_MONOTONIC, &tp);
  return tp.tv_sec * 1000 + tp.tv_nsec / 1000 / 1000;
}

uint64_t current_ts_usec() {
  struct timespec tp;
  clock_gettime(CLOCK_MONOTONIC, &tp);
  return tp.tv_sec * 1000 * 1000 + tp.tv_nsec / 1000;
}

Timer::Timer(timer_fn fn, uint64_t ts_msec) {
  this->fn = fn;
  this->ts_msec = ts_msec;
}

bool Timer::operator<(const Timer &other) const {
  // smallest ts first
  return this->ts_msec > other.ts_msec;
}

void Timers::trigger() {
  uint64_t cur_ts = current_ts_msec();
  while (!timers.empty()) {
    auto timer = timers.top();
    if (timer.ts_msec > cur_ts) {
      break;
    }
    int res = timer.fn();
    if (res >= 0) {
      schedule_job(timer.fn, res);
    }
    timers.pop();
  }
}

void Timers::add_job(timer_fn fn, uint64_t ts_msec) {
  timers.emplace(fn, ts_msec);
}

void Timers::schedule_job(timer_fn fn, uint64_t delay_msec) {
  timers.emplace(fn, delay_msec + current_ts_msec());
}