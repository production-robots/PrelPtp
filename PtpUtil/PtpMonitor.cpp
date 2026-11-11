#include "PtpMonitor.h"

#pragma comment(lib, "ws2_32")

//---------------------------------------------------------------------------- CPtpSurvey

CPtpSurvey::CPtpSurvey() : _tick(GetTickCount64), _slots(new SSlot[MAX_SLOTS]), _reported(new SSummary[MAX_ADAPTERS]) {
  for (int i = 0; i < MAX_SLOTS; ++i)
    _slots[i].Used = false;
  ZeroMemory(_reported, sizeof(SSummary) * MAX_ADAPTERS);
}

CPtpSurvey::~CPtpSurvey() {
  delete[] _slots;
  delete[] _reported;
}

void CPtpSurvey::SetTickSource(TTickSource Tick) {
  TSRWExclusiveLock l(_lock);
  _tick = Tick;
  for (int i = 0; i < MAX_SLOTS; ++i)
    _slots[i].Bmca.SetTickSource(Tick);
}

void CPtpSurvey::SummariseLocked(int Adapter, SSummary& out_Summary) const {
  ZeroMemory(&out_Summary, sizeof(out_Summary));
  //lowest domain first
  for (int domain = 0; (domain < 256) && (out_Summary.DomainCount < MAX_DOMAINS); ++domain) {
    for (int i = 0; i < MAX_SLOTS; ++i) {
      const SSlot& s = _slots[i];
      if (!s.Used || (s.Adapter != Adapter) || (s.Domain != domain))
        continue;
      if (s.Bmca.ForeignMasterCount() == 0)
        continue;
      SDomain& d = out_Summary.Domains[out_Summary.DomainCount++];
      d.Domain = (uint8_t)domain;
      d.HaveMaster = s.Bmca.GetSelected(d.Master);
    }
  }
}

//what the user sees: domains, and for each the master and its grandmaster's quality
static bool SameSummary(const CPtpSurvey::SSummary& A, const CPtpSurvey::SSummary& B) {
  if (A.DomainCount != B.DomainCount)
    return false;
  for (int i = 0; i < A.DomainCount; ++i) {
    const CPtpSurvey::SDomain& a = A.Domains[i];
    const CPtpSurvey::SDomain& b = B.Domains[i];
    if ((a.Domain != b.Domain) || (a.HaveMaster != b.HaveMaster))
      return false;
    if (!a.HaveMaster)
      continue;
    const SBmcaDataset& da = a.Master.Dataset;
    const SBmcaDataset& db = b.Master.Dataset;
    if ((da.Sender != db.Sender) || (da.GrandmasterIdentity != db.GrandmasterIdentity) ||
        (da.Priority1 != db.Priority1) || (da.ClockClass != db.ClockClass) || (da.ClockAccuracy != db.ClockAccuracy) ||
        (da.OffsetScaledLogVariance != db.OffsetScaledLogVariance) || (da.Priority2 != db.Priority2) ||
        (da.StepsRemoved != db.StepsRemoved) || (a.Master.Address != b.Master.Address))
      return false;
  }
  return true;
}

bool CPtpSurvey::UpdateLocked(int Adapter) {
  SSummary now;
  SummariseLocked(Adapter, now);
  if (SameSummary(now, _reported[Adapter]))
    return false;
  _reported[Adapter] = now;
  return true;
}

bool CPtpSurvey::OnMessage(int Adapter, const void* Bytes, int Size, DWORD FromAddress) {
  if ((Adapter < 0) || (Adapter >= MAX_ADAPTERS))
    return false;
  if (Size < (int)(sizeof(CommonMsgHeader) + sizeof(AnnounceMessage)))
    return false;

  PtpMessage m;
  ZeroMemory(&m, sizeof(m));
  CopyMemory(&m, Bytes, (Size < (int)sizeof(m)) ? Size : sizeof(m));
  m.Header._ByteSwap();
  if (m.Header.messageType != EMessageType::Announce)
    return false;
  m.Message.Announce._ByteSwap();

  TSRWExclusiveLock l(_lock);
  int slot = -1;
  int free_slot = -1;
  for (int i = 0; i < MAX_SLOTS; ++i) {
    if (_slots[i].Used) {
      if ((_slots[i].Adapter == Adapter) && (_slots[i].Domain == m.Header.domainNumber)) {
        slot = i;
        break;
      }
    }
    else if (free_slot < 0) {
      free_slot = i;
    }
  }
  if (slot < 0) {
    if (free_slot < 0)
      return false;
    slot = free_slot;
    SSlot& s = _slots[slot];
    s.Used = true;
    s.Adapter = Adapter;
    s.Domain = m.Header.domainNumber;
    s.Bmca.Reset();
    s.Bmca.SetTickSource(_tick);
    s.Bmca.SetDomain(m.Header.domainNumber);
  }
  _slots[slot].Bmca.OnAnnounce(m.Header, m.Message.Announce, FromAddress);
  return UpdateLocked(Adapter);
}

bool CPtpSurvey::Tick() {
  TSRWExclusiveLock l(_lock);
  for (int i = 0; i < MAX_SLOTS; ++i) {
    SSlot& s = _slots[i];
    if (!s.Used)
      continue;
    s.Bmca.OnTick();
    if (s.Bmca.ForeignMasterCount() == 0)
      s.Used = false;
  }
  bool changed = false;
  for (int a = 0; a < MAX_ADAPTERS; ++a)
    changed |= UpdateLocked(a);
  return changed;
}

void CPtpSurvey::GetSummary(int Adapter, SSummary& out_Summary) const {
  if ((Adapter < 0) || (Adapter >= MAX_ADAPTERS)) {
    ZeroMemory(&out_Summary, sizeof(out_Summary));
    return;
  }
  TSRWSharedLock l(_lock);
  SummariseLocked(Adapter, out_Summary);
}

static bool Better(const CBmca::SForeignMaster& A, const CBmca::SForeignMaster& B) {
  EBmcaResult r = BmcaCompare(A.Dataset, B.Dataset);
  return (r == EBmcaResult::ABetter) || (r == EBmcaResult::ABetterByTopology);
}

bool CPtpSurvey::HeardFrom(int Adapter, DWORD Address) const {
  TSRWSharedLock l(_lock);
  for (int i = 0; i < MAX_SLOTS; ++i) {
    const SSlot& s = _slots[i];
    if (s.Used && (s.Adapter == Adapter) && s.Bmca.HasForeignMasterAt(Address))
      return true;
  }
  return false;
}

int CPtpSurvey::BestAdapter() const {
  TSRWSharedLock l(_lock);
  int best_adapter = -1;
  CBmca::SForeignMaster best;
  for (int a = 0; a < MAX_ADAPTERS; ++a) {
    SSummary s;
    SummariseLocked(a, s);
    for (int i = 0; i < s.DomainCount; ++i) {
      if (!s.Domains[i].HaveMaster)
        continue;
      if ((best_adapter < 0) || Better(s.Domains[i].Master, best)) {
        best_adapter = a;
        best = s.Domains[i].Master;
      }
    }
  }
  return best_adapter;
}

//---------------------------------------------------------------------------- CPtpMonitor

CPtpMonitor::CPtpMonitor() : _thread(NULL), _stop(0), _notify(NULL), _message(0), _count(0), _started(0), _wsa(false) {
  ZeroMemory(_addresses, sizeof(_addresses));
  ZeroMemory(_listening, sizeof(_listening));
}

CPtpMonitor::~CPtpMonitor() {
  Stop();
}

bool CPtpMonitor::Start(HWND Notify, UINT Message, const DWORD* Addresses, int Count) {
  Stop();
  WSADATA wsa;
  _wsa = WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
  if (!_wsa)
    return false;
  _notify = Notify;
  _message = Message;
  _count = (Count < CPtpSurvey::MAX_ADAPTERS) ? Count : CPtpSurvey::MAX_ADAPTERS;
  for (int i = 0; i < _count; ++i)
    _addresses[i] = Addresses[i];
  _stop = 0;
  _started = GetTickCount64();
  _thread = CreateThread(nullptr, 0, GThread, this, 0, nullptr);
  return _thread != NULL;
}

void CPtpMonitor::Stop() {
  if (_thread != NULL) {
    InterlockedExchange(&_stop, 1);
    WaitForSingleObject(_thread, 5000);
    CloseHandle(_thread);
    _thread = NULL;
  }
  if (_wsa) {
    WSACleanup();
    _wsa = false;
  }
}

bool CPtpMonitor::Listening(int Adapter) const {
  return (Adapter >= 0) && (Adapter < _count) && _listening[Adapter];
}

bool CPtpMonitor::Checking() const {
  return (_thread != NULL) && ((GetTickCount64() - _started) < CHECKING_MS);
}

static SOCKET OpenListener(DWORD Address) {
  SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (s == INVALID_SOCKET)
    return s;
  int one = 1;
  sockaddr_in local;
  ZeroMemory(&local, sizeof(local));
  local.sin_family = AF_INET;
  local.sin_addr.s_addr = Address;
  local.sin_port = htons(PTP_GENERAL_PORT);
  IP_MREQ mreq;
  mreq.imr_multiaddr.s_addr = htonl(PTP_IP_ADDRESS);
  mreq.imr_interface.s_addr = Address;
  if ((setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one)) == SOCKET_ERROR) ||
      (bind(s, (const sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) ||
      (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char*)&mreq, sizeof(mreq)) == SOCKET_ERROR)) {
    closesocket(s);
    return INVALID_SOCKET;
  }
  return s;
}

void CPtpMonitor::Run() {
  SOCKET sockets[CPtpSurvey::MAX_ADAPTERS];
  for (int i = 0; i < _count; ++i) {
    sockets[i] = (_addresses[i] != 0) ? OpenListener(_addresses[i]) : INVALID_SOCKET;
    _listening[i] = sockets[i] != INVALID_SOCKET;
  }
  //the "listening" state is now known
  PostMessage(_notify, _message, 0, 0);

  ULONGLONG last_tick = GetTickCount64();
  bool checking_over = false;
  char buf[MAX_PTP_PACKET_SIZE];

  while (InterlockedCompareExchange(&_stop, 0, 0) == 0) {
    fd_set readable;
    FD_ZERO(&readable);
    for (int i = 0; i < _count; ++i)
      if (sockets[i] != INVALID_SOCKET)
        FD_SET(sockets[i], &readable);

    bool changed = false;
    if (readable.fd_count == 0) {
      Sleep(250);
    }
    else {
      timeval timeout = { 0, 250000 };
      if (select(0, &readable, nullptr, nullptr, &timeout) > 0) {
        for (int i = 0; i < _count; ++i) {
          if ((sockets[i] == INVALID_SOCKET) || !FD_ISSET(sockets[i], &readable))
            continue;
          sockaddr_in from;
          int from_size = sizeof(from);
          int n = recvfrom(sockets[i], buf, sizeof(buf), 0, (sockaddr*)&from, &from_size);
          if (n > 0)
            changed |= _survey.OnMessage(i, buf, n, from.sin_addr.s_addr);
        }
      }
    }

    ULONGLONG now = GetTickCount64();
    if ((now - last_tick) >= TICK_MS) {
      last_tick = now;
      changed |= _survey.Tick();
      //lets the dialog change "checking" to "none" even if nothing arrives
      if (!checking_over && ((now - _started) >= CHECKING_MS)) {
        checking_over = true;
        changed = true;
      }
    }
    if (changed)
      PostMessage(_notify, _message, 0, 0);
  }

  for (int i = 0; i < _count; ++i)
    if (sockets[i] != INVALID_SOCKET)
      closesocket(sockets[i]);
}
