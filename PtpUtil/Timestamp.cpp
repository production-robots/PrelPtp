#include "Timestamp.h"
#include <math.h>

//receive and transmit latencies outside this range mean the timestamp or the clock mapping is wrong
static const double MIN_LATENCY_NS = -100000.0;
static const double MAX_LATENCY_NS = 100000000.0;

STimePair STimePair::Now() {
  STimePair p;
  GetSystemTimePreciseAsFileTime((LPFILETIME)&p.SystemTime);
  LARGE_INTEGER q;
  QueryPerformanceCounter(&q);
  p.Qpc = q.QuadPart;
  return p;
}

// --- software ---

bool CSoftwareTimestamps::RxTime(const STimePair& Wake, const WSAMSG& Msg, uint64_t& out_Time) {
  UNREFERENCED_PARAMETER(Msg);
  out_Time = Wake.SystemTime;
  return true;
}

ULONG CSoftwareTimestamps::TxControl(uint32_t Id, char* Buf, ULONG Size) {
  UNREFERENCED_PARAMETER(Id);
  UNREFERENCED_PARAMETER(Buf);
  UNREFERENCED_PARAMETER(Size);
  return 0;
}

ETxResult CSoftwareTimestamps::TxTime(uint32_t Id, const STimePair& Before, uint64_t& out_Time) {
  UNREFERENCED_PARAMETER(Id);
  out_Time = Before.SystemTime;
  return ETxResult::Ready;
}

// --- NIC clock ---

CNicClock::CNicClock() : _count(0), _newest(0), _rate(0.0), _qpf(1), _ready(false) {
  ZeroMemory(_hist, sizeof(_hist));
}

void CNicClock::Reset(int64_t QpcFrequency) {
  _qpf = QpcFrequency;
  _newest = 0;
  Restart();
}

void CNicClock::Restart() {
  _count = 0;
  _ready = false;
  _rate = 0.0;
}

const SCrossTimestamp& CNicClock::Oldest() const {
  return _hist[(_newest - _count + 1 + HISTORY) % HISTORY];
}

CNicClock::EAdd CNicClock::Add(const SCrossTimestamp& X) {
  if ((X.Qpc2 < X.Qpc1) || ((double)(X.Qpc2 - X.Qpc1) * 1e9 / (double)_qpf > MAX_WINDOW_NS))
    return EAdd::Rejected;

  EAdd result = EAdd::Added;
  if (_count > 0) {
    const SCrossTimestamp& last = _hist[_newest];
    double dq = Mid(X) - Mid(last);
    bool restart = (dq <= 0);
    if (!restart) {
      //the rate since the last reading, against the rate seen so far: measured once Ready, otherwise
      //between the readings since the measurement (re)started
      double rate = (double)(int64_t)(X.Hw - last.Hw) / dq;
      double seen(0.0);
      if (_ready) {
        seen = _rate;
      }
      else if (_count >= 2) {
        const SCrossTimestamp& oldest = Oldest();
        seen = (double)(int64_t)(last.Hw - oldest.Hw) / (Mid(last) - Mid(oldest));
      }
      if (seen > 0.0)
        restart = fabs(rate / seen - 1.0) * 1e6 > MAX_RATE_PPM;
      else
        restart = (rate <= 0.0) || ((_count >= 2) && (seen <= 0.0));  //stopped or going backwards
      //a step smaller than that, but more than 100 us off the measured rate
      if (!restart && _ready)
        restart = fabs(((double)(int64_t)(X.Hw - last.Hw) - dq * _rate) / _rate) * 1e9 / (double)_qpf > 100000.0;
    }
    if (restart) {
      Restart();
      result = EAdd::Restarted;
    }
  }

  _newest = (_count == 0) ? 0 : (_newest + 1) % HISTORY;
  _hist[_newest] = X;
  if (_count < HISTORY)
    ++_count;

  const SCrossTimestamp& oldest = Oldest();
  double span = Mid(X) - Mid(oldest);
  if (span >= (double)MIN_SPAN_S * (double)_qpf) {
    _rate = (double)(int64_t)(X.Hw - oldest.Hw) / span;
    _ready = _rate * (double)_qpf >= (double)MIN_HZ;
  }
  return result;
}

double CNicClock::ToQpc(uint64_t Hw) const {
  const SCrossTimestamp& last = _hist[_newest];
  return Mid(last) + (double)(int64_t)(Hw - last.Hw) / _rate;
}

double CNicClock::MeasuredHz() const {
  return _ready ? _rate * (double)_qpf : 0.0;
}

// --- hardware ---

CHardwareTimestamps::CHardwareTimestamps() :
  _active_fn(nullptr), _supported_fn(nullptr), _cross_fn(nullptr), _socket(INVALID_SOCKET), _qpf(1), _last_cross_tick(0), _hw_hz(0),
  _active_error(NO_ERROR) {
  ZeroMemory(&_luid, sizeof(_luid));
  LARGE_INTEGER f;
  QueryPerformanceFrequency(&f);
  _qpf = f.QuadPart;
}

DWORD CHardwareTimestamps::Open(SOCKET Socket, DWORD IfIndex, const wchar_t*& out_Reason) {
  _socket = INVALID_SOCKET;
  _active_error = NO_ERROR;
  if (_active_fn == nullptr) {
    HMODULE iphlpapi = GetModuleHandleW(L"iphlpapi.dll");
    if (iphlpapi != NULL) {
      _active_fn = (TCapsFn)GetProcAddress(iphlpapi, "GetInterfaceActiveTimestampCapabilities");
      _supported_fn = (TCapsFn)GetProcAddress(iphlpapi, "GetInterfaceSupportedTimestampCapabilities");
      _cross_fn = (TCrossFn)GetProcAddress(iphlpapi, "CaptureInterfaceHardwareCrossTimestamp");
    }
  }
  if ((_active_fn == nullptr) || (_supported_fn == nullptr) || (_cross_fn == nullptr)) {
    out_Reason = L"this version of Windows has no timestamping support (Windows Server 2022 or Windows 11 is needed)";
    return ERROR_NOT_SUPPORTED;
  }

  DWORD result = ConvertInterfaceIndexToLuid(IfIndex, &_luid);
  if (result != NO_ERROR) {
    out_Reason = L"the adapter could not be identified";
    return result;
  }

  WinsockTs::InterfaceCaps caps;
  ZeroMemory(&caps, sizeof(caps));
  _active_error = _active_fn(&_luid, &caps);
  if (_active_error != NO_ERROR) {
    //the driver doesn't say what is active (Intel: ERROR_BAD_DRIVER): go by what it supports, and
    //let use show whether the timestamps arrive
    ZeroMemory(&caps, sizeof(caps));
    result = _supported_fn(&_luid, &caps);
    if (result != NO_ERROR) {
      out_Reason = L"the adapter's timestamp capabilities could not be read";
      return result;
    }
  }
  const WinsockTs::HardwareCaps& hw = caps.Hardware;
  bool rx = hw.PtpV2OverUdpIPv4EventMessageReceive || hw.PtpV2OverUdpIPv4AllMessageReceive || hw.AllReceive;
  bool tx = hw.PtpV2OverUdpIPv4EventMessageTransmit || hw.PtpV2OverUdpIPv4AllMessageTransmit || hw.AllTransmit || hw.TaggedTransmit;
  if (!rx || !tx) {
    out_Reason = (_active_error == NO_ERROR) ?
      L"hardware timestamping is not active on the adapter (set the advanced property PtpHardwareTimestamp to Enabled)" :
      L"the adapter has no hardware timestamps for PTP";
    return ERROR_NOT_SUPPORTED;
  }
  if (!caps.SupportsCrossTimestamp || (caps.HardwareClockFrequencyHz == 0)) {
    out_Reason = L"the adapter cannot relate its clock to the system clock (no cross-timestamp support)";
    return ERROR_NOT_SUPPORTED;
  }

  WinsockTs::TIMESTAMPING_CONFIG_ config;
  ZeroMemory(&config, sizeof(config));
  config.Flags = WinsockTs::FLAG_RX | WinsockTs::FLAG_TX;
  config.TxTimestampsBuffered = 8;
  DWORD bytes(0);
  if (WSAIoctl(Socket, WinsockTs::SIO_TIMESTAMPING_, &config, sizeof(config), nullptr, 0, &bytes, nullptr, nullptr) == SOCKET_ERROR) {
    out_Reason = L"timestamping could not be turned on for the socket";
    return WSAGetLastError();
  }

  _hw_hz = caps.HardwareClockFrequencyHz;
  _clock.Reset(_qpf);
  _socket = Socket;
  _last_cross_tick = 0;
  Refresh();
  out_Reason = nullptr;
  return NOERROR;
}

void CHardwareTimestamps::Restart() {
  _clock.Reset(_qpf);
  _last_cross_tick = 0;
  if (_socket != INVALID_SOCKET)
    Refresh();
}

void CHardwareTimestamps::Refresh() {
  _last_cross_tick = GetTickCount64();
  WinsockTs::CrossTimestamp c;
  ZeroMemory(&c, sizeof(c));
  if (_cross_fn(&_luid, &c) != NO_ERROR)
    return;
  SCrossTimestamp x = { c.SystemTimestamp1, c.HardwareClockTimestamp, c.SystemTimestamp2 };
  _clock.Add(x);
}

void CHardwareTimestamps::Poll() {
  if ((_socket != INVALID_SOCKET) && (GetTickCount64() - _last_cross_tick >= 1000))
    Refresh();
}

uint64_t CHardwareTimestamps::QpcToSystemTime(double Qpc, const STimePair& Pair) const {
  //ns100 = QPC ticks * 1e7 / QPC frequency; the difference is small, so a double is exact enough
  double delta = (Qpc - (double)Pair.Qpc) * 1e7 / (double)_qpf;
  return (uint64_t)((int64_t)Pair.SystemTime + (int64_t)floor(delta + 0.5));
}

bool CHardwareTimestamps::RxTime(const STimePair& Wake, const WSAMSG& Msg, uint64_t& out_Time) {
  uint64_t ts = WinsockTs::RxTimestamp(Msg);
  if ((ts == 0) || !_clock.Ready())
    return false;
  double qpc = _clock.ToQpc(ts);
  double latency_ns = ((double)Wake.Qpc - qpc) * 1e9 / (double)_qpf;
  if ((latency_ns < MIN_LATENCY_NS) || (latency_ns > MAX_LATENCY_NS))
    return false;
  out_Time = QpcToSystemTime(qpc, Wake);
  return true;
}

ULONG CHardwareTimestamps::TxControl(uint32_t Id, char* Buf, ULONG Size) {
  ULONG needed = (ULONG)WSA_CMSG_SPACE(sizeof(uint32_t));
  if (Size < needed)
    return 0;
  ZeroMemory(Buf, needed);
  WSACMSGHDR* cm = (WSACMSGHDR*)Buf;
  cm->cmsg_len = WSA_CMSG_LEN(sizeof(uint32_t));
  cm->cmsg_level = SOL_SOCKET;
  cm->cmsg_type = WinsockTs::SO_TIMESTAMP_ID_;
  CopyMemory(WSA_CMSG_DATA(cm), &Id, sizeof(Id));
  return needed;
}

ETxResult CHardwareTimestamps::TxTime(uint32_t Id, const STimePair& Before, uint64_t& out_Time) {
  uint64_t ts(0);
  DWORD bytes(0);
  if (WSAIoctl(_socket, WinsockTs::SIO_GET_TX_TIMESTAMP_, &Id, sizeof(Id), &ts, sizeof(ts), &bytes, nullptr, nullptr) == SOCKET_ERROR)
    return (WSAGetLastError() == WSAEWOULDBLOCK) ? ETxResult::NotYet : ETxResult::Failed;
  if ((ts == 0) || !_clock.Ready())
    return ETxResult::Failed;
  double qpc = _clock.ToQpc(ts);
  double latency_ns = (qpc - (double)Before.Qpc) * 1e9 / (double)_qpf;
  if ((latency_ns < MIN_LATENCY_NS) || (latency_ns > MAX_LATENCY_NS))
    return ETxResult::Failed;
  out_Time = QpcToSystemTime(qpc, Before);
  return ETxResult::Ready;
}

// --- recheck after a fallback ---

CHardwareRecheck::CHardwareRecheck() : _nic_hz(0.0), _qpf(1), _interval(RECHECK_MS), _next(0), _returned(false),
  _run(0), _first_ts(0), _first_qpc(0), _plausible(false) {
}

void CHardwareRecheck::Reset() {
  _nic_hz = 0.0;
  _interval = RECHECK_MS;
  _returned = false;
  _run = 0;
}

void CHardwareRecheck::OnFallback(double NicHz, int64_t QpcFrequency, ULONGLONG Now) {
  //a return that didn't hold: wait longer before the next one
  if (_returned && (_interval < MAX_RECHECK_MS))
    _interval = (_interval * 2 < MAX_RECHECK_MS) ? _interval * 2 : MAX_RECHECK_MS;
  _returned = false;
  _nic_hz = NicHz;
  _qpf = QpcFrequency;
  _next = Now + _interval;
  _run = 0;
}

void CHardwareRecheck::OnSync(uint64_t RxTimestamp, int64_t WakeQpc) {
  if (!Watching())
    return;
  if (RxTimestamp == 0) {
    _run = 0;
    return;
  }
  if (_run == 0) {
    _first_ts = RxTimestamp;
    _first_qpc = WakeQpc;
    _plausible = false;
    _run = 1;
    return;
  }
  ++_run;
  double span_s = (double)(WakeQpc - _first_qpc) / (double)_qpf;
  if (span_s < MIN_RUN_SPAN_S) {
    _plausible = false;
    return;
  }
  double hz = (double)(int64_t)(RxTimestamp - _first_ts) / span_s;
  _plausible = fabs(hz / _nic_hz - 1.0) <= RATE_TOLERANCE;
  if (!_plausible) {
    //start a new run from this Sync
    _first_ts = RxTimestamp;
    _first_qpc = WakeQpc;
    _run = 1;
  }
}

bool CHardwareRecheck::Due(ULONGLONG Now) const {
  return Watching() && (Now >= _next) && (_run >= MIN_RUN) && _plausible;
}

void CHardwareRecheck::OnReturn() {
  _nic_hz = 0.0;
  _returned = true;
  _run = 0;
}

// --- Winsock helpers ---

uint64_t WinsockTs::RxTimestamp(const WSAMSG& Msg) {
  //the WSA_CMSG macros take a non-const message
  WSAMSG& m = const_cast<WSAMSG&>(Msg);
  if ((m.Control.buf == nullptr) || (m.Control.len < sizeof(WSACMSGHDR)))
    return 0;
  for (WSACMSGHDR* cm = WSA_CMSG_FIRSTHDR(&m); cm != nullptr; cm = WSA_CMSG_NXTHDR(&m, cm)) {
    if ((cm->cmsg_level == SOL_SOCKET) && (cm->cmsg_type == SO_TIMESTAMP_) && (cm->cmsg_len >= WSA_CMSG_LEN(sizeof(uint64_t)))) {
      uint64_t ts;
      CopyMemory(&ts, WSA_CMSG_DATA(cm), sizeof(ts));
      return ts;
    }
  }
  return 0;
}
