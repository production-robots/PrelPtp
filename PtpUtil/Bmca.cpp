#include "Bmca.h"
#include <strsafe.h>

int CompareClockIdentity(TClockIdentity A, TClockIdentity B) {
  //wire order in memory: swap so the first octet is the most significant
  uint64_t a = _byteswap_uint64(A);
  uint64_t b = _byteswap_uint64(B);
  return (a < b) ? -1 : ((a > b) ? 1 : 0);
}

void FormatClockIdentity(TClockIdentity Identity, wchar_t* Buf, size_t Chars) {
  const uint8_t* b = (const uint8_t*)&Identity;  //wire order
  StringCchPrintf(Buf, Chars, L"%02X%02X%02X.%02X%02X.%02X%02X%02X", b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
}

int ComparePortIdentity(const PortIdentity& A, const PortIdentity& B) {
  int c = CompareClockIdentity(A.clockIdentity, B.clockIdentity);
  if (c != 0)
    return c;
  return (A.portNumber < B.portNumber) ? -1 : ((A.portNumber > B.portNumber) ? 1 : 0);
}

/*
IEEE 1588-2008 9.3.4.

Figure 27: if the grandmasters differ, compare the grandmaster attributes in this order,
lower is better:
  priority1, clockClass, clockAccuracy, offsetScaledLogVariance, priority2, grandmasterIdentity

Figure 28: if the grandmaster is the same, compare the paths to it.
*/
EBmcaResult BmcaCompare(const SBmcaDataset& A, const SBmcaDataset& B) {
  int gm = CompareClockIdentity(A.GrandmasterIdentity, B.GrandmasterIdentity);

  if (gm != 0) {
    //figure 27
    if (A.Priority1 != B.Priority1)
      return (A.Priority1 < B.Priority1) ? EBmcaResult::ABetter : EBmcaResult::BBetter;
    if (A.ClockClass != B.ClockClass)
      return (A.ClockClass < B.ClockClass) ? EBmcaResult::ABetter : EBmcaResult::BBetter;
    if (A.ClockAccuracy != B.ClockAccuracy)
      return (A.ClockAccuracy < B.ClockAccuracy) ? EBmcaResult::ABetter : EBmcaResult::BBetter;
    if (A.OffsetScaledLogVariance != B.OffsetScaledLogVariance)
      return (A.OffsetScaledLogVariance < B.OffsetScaledLogVariance) ? EBmcaResult::ABetter : EBmcaResult::BBetter;
    if (A.Priority2 != B.Priority2)
      return (A.Priority2 < B.Priority2) ? EBmcaResult::ABetter : EBmcaResult::BBetter;
    return (gm < 0) ? EBmcaResult::ABetter : EBmcaResult::BBetter;
  }

  //figure 28: same grandmaster
  uint32_t steps_a = A.StepsRemoved;
  uint32_t steps_b = B.StepsRemoved;

  if (steps_a > steps_b + 1)
    return EBmcaResult::BBetter;
  if (steps_a + 1 < steps_b)
    return EBmcaResult::ABetter;

  if (steps_a > steps_b) {
    //A is one step further from the grandmaster
    int c = ComparePortIdentity(A.Receiver, A.Sender);
    if (c < 0)
      return EBmcaResult::BBetter;
    if (c > 0)
      return EBmcaResult::BBetterByTopology;
    return EBmcaResult::Error1;
  }

  if (steps_a < steps_b) {
    //B is one step further from the grandmaster
    int c = ComparePortIdentity(B.Receiver, B.Sender);
    if (c < 0)
      return EBmcaResult::ABetter;
    if (c > 0)
      return EBmcaResult::ABetterByTopology;
    return EBmcaResult::Error1;
  }

  //same number of steps: compare the senders, then the receiving port numbers
  int c = ComparePortIdentity(A.Sender, B.Sender);
  if (c < 0)
    return EBmcaResult::ABetterByTopology;
  if (c > 0)
    return EBmcaResult::BBetterByTopology;
  if (A.Receiver.portNumber < B.Receiver.portNumber)
    return EBmcaResult::ABetterByTopology;
  if (A.Receiver.portNumber > B.Receiver.portNumber)
    return EBmcaResult::BBetterByTopology;
  return EBmcaResult::Error2;
}

ULONGLONG AnnounceIntervalMs(uint8_t LogMessageInterval) {
  int log_interval = (int8_t)LogMessageInterval;
  if (log_interval < -4)
    log_interval = -4;
  if (log_interval > 4)
    log_interval = 4;
  return (log_interval >= 0) ? (1000ULL << log_interval) : (1000ULL >> -log_interval);
}

static bool SamePort(const PortIdentity& A, const PortIdentity& B) {
  return (A.clockIdentity == B.clockIdentity) && (A.portNumber == B.portNumber);
}

CBmca::CBmca() : _tick(GetTickCount64), _domain(PTP_DOMAIN_ANY), _local({ 0 }), _count(0),
  _have_selected(false), _selected_port({ 0 }), _selected_domain(0) {
  ZeroMemory(_masters, sizeof(_masters));
}

void CBmca::SetTickSource(TTickSource Tick) {
  TSRWExclusiveLock l(_lock);
  _tick = Tick;
}

void CBmca::SetDomain(DWORD Domain) {
  TSRWExclusiveLock l(_lock);
  _domain = Domain;
}

void CBmca::SetLocalPort(const PortIdentity& Port) {
  TSRWExclusiveLock l(_lock);
  _local = Port;
  for (int i = 0; i < _count; ++i)
    _masters[i].Dataset.Receiver = Port;
}

void CBmca::Reset() {
  TSRWExclusiveLock l(_lock);
  _count = 0;
  _have_selected = false;
}

bool CBmca::IsQualified(const SForeignMaster& M, ULONGLONG Now) const {
  //FOREIGN_MASTER_THRESHOLD distinct Announce messages within the last FOREIGN_MASTER_TIME_WINDOW
  return (M.Count >= FOREIGN_MASTER_THRESHOLD) &&
         ((Now - M.PreviousTick) <= FOREIGN_MASTER_TIME_WINDOW * M.IntervalMs);
}

void CBmca::RemoveLocked(int Index) {
  _masters[Index] = _masters[_count - 1];
  --_count;
}

void CBmca::ExpireLocked(ULONGLONG Now) {
  for (int i = _count - 1; i >= 0; --i) {
    if ((Now - _masters[i].LastTick) > ANNOUNCE_RECEIPT_TIMEOUT * _masters[i].IntervalMs)
      RemoveLocked(i);
  }
}

int CBmca::FindLocked(const PortIdentity& Port, uint8_t Domain) const {
  for (int i = 0; i < _count; ++i) {
    if (SamePort(_masters[i].Dataset.Sender, Port) && (_masters[i].Domain == Domain))
      return i;
  }
  return -1;
}

bool CBmca::SelectLocked(ULONGLONG Now) {
  int best = -1;
  for (int i = 0; i < _count; ++i) {
    if (!IsQualified(_masters[i], Now))
      continue;
    if (best < 0) {
      best = i;
      continue;
    }
    EBmcaResult r = BmcaCompare(_masters[i].Dataset, _masters[best].Dataset);
    if ((r == EBmcaResult::ABetter) || (r == EBmcaResult::ABetterByTopology))
      best = i;
  }

  bool changed;
  if (best < 0) {
    changed = _have_selected;
    _have_selected = false;
  }
  else {
    changed = !_have_selected || !SamePort(_selected_port, _masters[best].Dataset.Sender) || (_selected_domain != _masters[best].Domain);
    _have_selected = true;
    _selected_port = _masters[best].Dataset.Sender;
    _selected_domain = _masters[best].Domain;
  }
  return changed;
}

CBmca::EAnnounceResult CBmca::OnAnnounce(const CommonMsgHeader& Header, const AnnounceMessage& Announce, DWORD Address, bool* out_Changed) {
  if (out_Changed != nullptr)
    *out_Changed = false;

  TSRWExclusiveLock l(_lock);
  ULONGLONG now = _tick();

  if ((_local.clockIdentity != 0) && (Header.sourcePortIdentity.clockIdentity == _local.clockIdentity))
    return EAnnounceResult::IgnoredOwn;
  if (!DomainAccepted(_domain, Header.domainNumber))
    return EAnnounceResult::IgnoredDomain;
  if (Header.alternateMasterFlag)
    return EAnnounceResult::IgnoredAlternate;
  if (Announce.stepsRemoved >= 255)
    return EAnnounceResult::IgnoredSteps;

  ExpireLocked(now);

  int i = FindLocked(Header.sourcePortIdentity, Header.domainNumber);
  if (i < 0) {
    if (_count >= MAX_FOREIGN_MASTERS) {
      bool changed = SelectLocked(now);
      if (out_Changed != nullptr)
        *out_Changed = changed;
      return EAnnounceResult::IgnoredFull;
    }
    i = _count++;
    ZeroMemory(&_masters[i], sizeof(_masters[i]));
    _masters[i].Dataset.Sender = Header.sourcePortIdentity;
    _masters[i].Domain = Header.domainNumber;
    _masters[i].Count = 1;
    _masters[i].LastTick = now;
    _masters[i].PreviousTick = now;
  }
  else {
    SForeignMaster& m = _masters[i];
    if (Header.sequenceId == m.LastSequenceId) {
      bool changed = SelectLocked(now);
      if (out_Changed != nullptr)
        *out_Changed = changed;
      return EAnnounceResult::IgnoredDuplicate;
    }
    m.PreviousTick = m.LastTick;
    m.LastTick = now;
    if (m.Count < FOREIGN_MASTER_THRESHOLD)
      ++m.Count;
  }

  SForeignMaster& m = _masters[i];
  m.LastSequenceId = Header.sequenceId;
  m.Address = Address;
  m.TimeSource = Announce.timeSource;
  m.IntervalMs = AnnounceIntervalMs(Header.logMessageInterval);
  m.Dataset.Priority1 = Announce.grandmasterPriority1;
  m.Dataset.ClockClass = Announce.grandmasterClockQuality.clockClass;
  m.Dataset.ClockAccuracy = Announce.grandmasterClockQuality.clockAccuracy;
  m.Dataset.OffsetScaledLogVariance = Announce.grandmasterClockQuality.offsetScaledLogVariance;
  m.Dataset.Priority2 = Announce.grandmasterPriority2;
  CopyMemory(&m.Dataset.GrandmasterIdentity, Announce.grandmasterIdentity, sizeof(m.Dataset.GrandmasterIdentity));
  m.Dataset.StepsRemoved = Announce.stepsRemoved;
  m.Dataset.Receiver = _local;

  bool changed = SelectLocked(now);
  if (out_Changed != nullptr)
    *out_Changed = changed;
  return EAnnounceResult::Used;
}

bool CBmca::OnTick() {
  TSRWExclusiveLock l(_lock);
  ULONGLONG now = _tick();
  ExpireLocked(now);
  return SelectLocked(now);
}

bool CBmca::GetSelected(SForeignMaster& out_Master) const {
  TSRWSharedLock l(_lock);
  if (!_have_selected)
    return false;
  int i = FindLocked(_selected_port, _selected_domain);
  if (i < 0)
    return false;
  out_Master = _masters[i];
  return true;
}

bool CBmca::IsSelected(const PortIdentity& Port, uint8_t Domain) const {
  TSRWSharedLock l(_lock);
  return _have_selected && SamePort(_selected_port, Port) && (_selected_domain == Domain);
}

int CBmca::ForeignMasterCount() const {
  TSRWSharedLock l(_lock);
  return _count;
}

bool CBmca::HasForeignMasterAt(DWORD Address) const {
  TSRWSharedLock l(_lock);
  for (int i = 0; i < _count; ++i)
    if (_masters[i].Address == Address)
      return true;
  return false;
}
