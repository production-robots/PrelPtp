#pragma once

#include "Util.h"

/*
Moving-average filter of offset samples (ns).

- Once the window is full, samples further than the outlier limit from the mean are dropped.
  If too many consecutive samples are dropped the filter assumes the offset really has changed
  (for example a different grandmaster, or w32time slewing the clock) and starts again.
- If no sample has been added for longer than the maximum gap, the existing samples are
  out of date (the host clock has been free-running): the filter starts again with the
  new sample rather than averaging it with old ones.
- GetMean reports the age of the newest sample so the caller can refuse to use stale data.
*/
class CFilter {
public:
  static const int MAX_LENGTH = 20;

  enum class EAddResult {
    Accepted,
    Rejected,     //outlier
    Reacquired,   //too many consecutive outliers: filter restarted with this sample
    Restarted     //previous samples were too old: filter restarted with this sample
  };

  static const int REACQUIRE_AFTER = 10;

  //millisecond tick used for sample age and the maximum gap
  using TTickSource = ULONGLONG(WINAPI*)();

private:
  TTickSource _tick;

  int64_t _filter[MAX_LENGTH];
  TSRWLock _lock;
  int64_t _total;
  int64_t _mean;
  int64_t _outlier;
  int _length;
  bool _full;
  int _ptr;
  int _consecutive_rejects;
  ULONGLONG _last_sample_tick;
  ULONGLONG _max_gap_ms;

  void ResetLocked();
  void AddLocked(int64_t Value);
public:
  uint64_t DroppedOutliers;
  void Reset();

  //Length is clamped to 1..MAX_LENGTH. Resets the filter.
  void SetLength(int Length);

  void SetMaxGap(ULONGLONG MaxGapMs);

  //GetTickCount64 by default. Unit tests replace it to control time.
  void SetTickSource(TTickSource Tick);

  EAddResult AddSample(int64_t Value);

  bool Empty() const;

  //out_AgeMs (optional) receives the time since the newest sample was added
  bool GetMean(int64_t& out_Mean, ULONGLONG* out_AgeMs = nullptr) const;

  CFilter(int64_t AOutlier);
};
