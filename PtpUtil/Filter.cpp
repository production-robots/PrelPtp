#include "Filter.h"
#include <strsafe.h>

CFilter::CFilter(int64_t AOutlier) : _tick(GetTickCount64), _total(0), _mean(0), _outlier(AOutlier), _length(MAX_LENGTH), _full(false), _ptr(0),
  _consecutive_rejects(0), _last_sample_tick(0), _max_gap_ms(0), DroppedOutliers(0) {}

void CFilter::ResetLocked() {
  _ptr = 0;
  _full = false;
  _total = 0;
  _mean = 0;
  _consecutive_rejects = 0;
}

void CFilter::Reset() {
  TSRWExclusiveLock lock(_lock);
  ResetLocked();
}

void CFilter::SetLength(int Length) {
  if (Length < 1)
    Length = 1;
  if (Length > MAX_LENGTH)
    Length = MAX_LENGTH;
  TSRWExclusiveLock lock(_lock);
  _length = Length;
  ResetLocked();
}

void CFilter::SetMaxGap(ULONGLONG MaxGapMs) {
  TSRWExclusiveLock lock(_lock);
  _max_gap_ms = MaxGapMs;
}

void CFilter::SetTickSource(TTickSource Tick) {
  TSRWExclusiveLock lock(_lock);
  _tick = Tick;
}

void CFilter::AddLocked(int64_t Value) {
  if (!_full) {  //rare case
    _filter[_ptr] = Value;
    _total += Value;
    ++_ptr;
    _mean = _total / _ptr;
    if (_ptr == _length) {
      _ptr = 0;
      _full = true;
    }
  }
  else { //full. Common case
    _total += Value;
    _total -= _filter[_ptr];
    _filter[_ptr] = Value;
    _mean = _total / _length;
    _ptr = (_ptr + 1) % _length;
  }
  _last_sample_tick = _tick();
}

CFilter::EAddResult CFilter::AddSample(int64_t Value) {
  TSRWExclusiveLock lock(_lock);

  bool empty(!_full && !_ptr);
  if (!empty && _max_gap_ms && ((_tick() - _last_sample_tick) > _max_gap_ms)) {
    ResetLocked();
    AddLocked(Value);
    return EAddResult::Restarted;
  }

  if (_full && _outlier) {
    int64_t dev = Value - _mean;
    if (dev < 0)
      dev = -dev;
    if (dev > _outlier) {
      ++DroppedOutliers;
      if (++_consecutive_rejects < REACQUIRE_AFTER) {
#ifdef ODS_DEBUG
        wchar_t buf[0x40];
        StringCchPrintf(buf, ARRAYSIZE(buf), L"Dropped outliers %llu\n", DroppedOutliers);
        OutputDebugString(buf);
#endif
        return EAddResult::Rejected;
      }
      ResetLocked();
      AddLocked(Value);
      return EAddResult::Reacquired;
    }
  }
  _consecutive_rejects = 0;
  AddLocked(Value);
  return EAddResult::Accepted;
}


bool CFilter::Empty() const {
  TSRWSharedLock lock(_lock);
  return !_full && !_ptr;
}

bool CFilter::GetMean(int64_t& out_Mean, ULONGLONG* out_AgeMs) const {
  TSRWSharedLock lock(_lock);
  if (!_full && !_ptr)
    return false;
  out_Mean = _mean;
  if (out_AgeMs != nullptr)
    *out_AgeMs = _tick() - _last_sample_tick;
  return true;
}
