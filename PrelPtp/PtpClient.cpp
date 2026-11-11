#include "PtpClient.h"
#include "Exception.h"
#include "..\PtpUtil\Ptp.h"
#include "..\PrelPtpVersion.h"
#include <strsafe.h>
#include <math.h>

#pragma comment(lib, "ws2_32")
#pragma comment(lib, "iphlpapi")

struct SocketHandle {
  SOCKET skt;
  operator SOCKET() const { return skt; }
  operator bool() const { return skt != INVALID_SOCKET; }
  void Release(SOCKET& out_Socket) { out_Socket = skt; skt = INVALID_SOCKET; }
  void Close() {
    if (skt != INVALID_SOCKET)
      closesocket(skt);
    skt = INVALID_SOCKET;
  }
  SocketHandle() : skt(INVALID_SOCKET) {}
  SocketHandle(SOCKET ASocket) : skt(ASocket) {}
  ~SocketHandle() { Close(); }
};

struct EventHandle {
  WSAEVENT evt;
  operator WSAEVENT() const { return evt; }
  operator bool() const { return evt != WSA_INVALID_EVENT; }
  EventHandle() : evt(WSACreateEvent()) {}
  ~EventHandle() {
    if (evt != WSA_INVALID_EVENT)
      WSACloseEvent(evt);
  }
};

//5 ms, in ns. Samples further than this from the filter mean are dropped (see CFilter).
static const int64_t OUTLIER = 5000000LL;

//retry back-off while the adapter is not ready or the socket keeps failing
static const DWORD BACKOFF_MIN_MS = 1000;
static const DWORD BACKOFF_MAX_MS = 30000;

//message loops wake at least this often to check for silence
static const DWORD LOOP_TICK_MS = 5000;

//reopen a socket that has not received a PTP message from a master for this long.
//Must be longer than the slowest plausible Announce interval (16 s).
static const ULONGLONG RX_SILENCE_MS = 60000;

//after this many consecutive send failures the socket is reopened even if the error is not a network error
static const int MAX_CONSECUTIVE_SEND_ERRORS = 3;

//Hardware timestamps fall back to software after this many consecutive Syncs without a receive
//timestamp (1 s at 8 Syncs a second), this many consecutive Delay_Req without a transmit timestamp, or
//if the NIC clock is not related to the system clock this long after opening. They are used again when
//the socket is reopened, or when CHardwareRecheck sees the receive timestamps come back.
static const int MAX_SYNC_MISSES = 8;
static const int MAX_TX_FAILURES = 5;
static const ULONGLONG NIC_CLOCK_READY_MS = 15000;

//errors that mean the socket is no longer usable (address removed, adapter down or restarted...)
static bool IsNetworkError(int Error) {
  switch (Error) {
  case WSAENETDOWN:
  case WSAENETUNREACH:
  case WSAEHOSTUNREACH:
  case WSAEADDRNOTAVAIL:
  case WSAENETRESET:
  case WSAENOTSOCK:
  case WSAESHUTDOWN:
  case WSAENOTCONN:
    return true;
  default:
    return false;
  }
}

static DWORD NextBackoff(DWORD BackoffMs) {
  return (BackoffMs >= BACKOFF_MAX_MS / 2) ? BACKOFF_MAX_MS : BackoffMs * 2;
}

static void FormatAddress(DWORD NetAddress, wchar_t* Buf, size_t Chars) {
  IN_ADDR addr;
  addr.S_un.S_addr = NetAddress;
  if (InetNtopW(AF_INET, &addr, Buf, Chars) == nullptr)
    StringCchCopy(Buf, Chars, L"?");
}

static const wchar_t* LoopName(WORD Port) {
  return Port == PTP_EVENT_PORT ? L"event" : L"general";
}

CPtpClient::CPtpClient(const TimeProvSysCallbacks* ATpCallbacks):
  _event_thread(NULL), _general_thread(NULL),
  _close_event(WSACreateEvent()), _delay_request_event(WSACreateEvent()),
  _delay_request_timer(nullptr),
  _address_notification(NULL), _interface_notification(NULL), _if_index(0),
  _source((((DWORD)'P') << 0)| (((DWORD)'R') << 8) | (((DWORD)'E') << 16) | ((DWORD)'L') << 24),
  _tp_callbacks(*ATpCallbacks), _disable_delay_request(false), _filter(OUTLIER), _stale_limit_ms(10000),
  _stale_logged(false), _alert_pending(1), _poll_interval(0),
  _message_path(_sync_request, _bmca), _timestamp_mode(ETimestampMode::Auto), _timestamps(&_software_timestamps),
  _logged_source(nullptr), _logged_reason(nullptr) {
  _net_change_event[0] = WSACreateEvent();
  _net_change_event[1] = WSACreateEvent();
  ZeroMemory(&_config, sizeof(_config));
  ZeroMemory(&_delay_request, sizeof(_delay_request));
  ZeroMemory(&_delay_request_addr, sizeof(_delay_request_addr));
  StringCchCopy(_source_name, ARRAYSIZE(_source_name), L"Prel PTP Client");
  WSADATA wsa;
  WSAStartup(MAKEWORD(2, 2), &wsa);
}

CPtpClient::~CPtpClient() {
  WSACloseEvent(_close_event);
  WSACloseEvent(_delay_request_event);
  WSACloseEvent(_net_change_event[0]);
  WSACloseEvent(_net_change_event[1]);
  WSACleanup();
}


void CPtpClient::ScheduleDelayRequest() {
  /*
  There are some very complicated rules in the standard about DR interval. I got a bit lost reading through them
  but I think a slightly randomised interval about a configured mean should do. In a multicast environment it is
  important that the grandmaster is not dealing with multiple delay requests at the same time. That is why it is
  not allowed to send a DR immediately after a sync unless you are using unicast.

  +/- 10% variation
  */

  uint32_t r = Uniform();
  int variation = _config.DelayRequestInterval * 20 / 100;
  int64_t interval = (_config.DelayRequestInterval - variation/2) + (r * variation) / 0xFFFF;

  interval *= -10000;
  SetThreadpoolTimer(_delay_request_timer, (PFILETIME)&interval, 0, 0);
}

void CPtpClient::DelayRequestCallback() {
  WSASetEvent(_delay_request_event);
  ScheduleDelayRequest();
}

//Sets this port's identity and builds the Delay_Req message. Called by the event thread each
//time its socket is opened, because the clock identity is derived from the adapter's MAC address.
void CPtpClient::InitDelayRequest(const TMacAddress& MacAddress) {
  PortIdentity local;
  local.clockIdentity = ClockIdentityFromMac(MacAddress);
  local.portNumber = 1;

  //the BMCA needs our identity even when we send no delay requests
  _bmca.SetLocalPort(local);

  if (_disable_delay_request)
    return;

  ZeroMemory(&_delay_request, sizeof(_delay_request));
  _delay_request.Header.messageType = EMessageType::Delay_Req;
  _delay_request.Header.versionPTP = 0x02;
  _delay_request.Header.messageLength = _delay_request.Size();
  _delay_request.Header.sourcePortIdentity = local;

  //before swap, because it will be returned after swap.
  _sync_request.SetPortIdentity(local);

  _delay_request.Header.controlField = EControlField::Delay_Req;
  _delay_request.Header.logMessageInterval = 0x7F; //table 24

  _delay_request.Header._ByteSwap();
  _delay_request.Message.Delay_Req._ByteSwap();  //zero so doesn't matter
}

DWORD CPtpClient::OpenSocket(WORD Port, DWORD LocalAddress, SOCKET& out_Socket) {

  SocketHandle sock(socket(AF_INET, SOCK_DGRAM, 0));

  if (!sock)
    return WSAGetLastError();

  SOCKADDR_IN local;
  ZeroMemory(&local, sizeof(local));
  local.sin_family = AF_INET;
  local.sin_addr.s_addr = LocalAddress;
  local.sin_port = htons(Port);
  char TTL = 64;
  if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &TTL, sizeof(TTL)) == SOCKET_ERROR)
    return WSAGetLastError();

  char DF = 1;
  if (setsockopt(sock, IPPROTO_IP, IP_DONTFRAGMENT, &DF, sizeof(DF)) == SOCKET_ERROR)
    return WSAGetLastError();

  int one = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one)) == SOCKET_ERROR)
    return WSAGetLastError();
  if (bind(sock, (const sockaddr*)&local, sizeof(local)) == SOCKET_ERROR)
    return WSAGetLastError();

  IP_MREQ mreq;
  mreq.imr_multiaddr.s_addr = htonl(PTP_IP_ADDRESS);
  mreq.imr_interface = local.sin_addr;
  if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char*)&mreq, sizeof(mreq)) == SOCKET_ERROR)
    return WSAGetLastError();
  if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, (const char*)&one, sizeof(one)) == SOCKET_ERROR)
    return WSAGetLastError();

  //send multicast (delay requests) out of the PTP adapter rather than the default route
  if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, (const char*)&local.sin_addr, sizeof(local.sin_addr)) == SOCKET_ERROR)
    return WSAGetLastError();

  sock.Release(out_Socket);

  return NOERROR;
}

VOID NETIOAPI_API_ CPtpClient::GAddressChange(PVOID Context, PMIB_UNICASTIPADDRESS_ROW Row, MIB_NOTIFICATION_TYPE NotificationType) {
  if (NotificationType == MibInitialNotification)
    return;
  ((CPtpClient*)Context)->OnNetworkChange(Row != nullptr ? Row->InterfaceIndex : 0);
}

VOID NETIOAPI_API_ CPtpClient::GInterfaceChange(PVOID Context, PMIB_IPINTERFACE_ROW Row, MIB_NOTIFICATION_TYPE NotificationType) {
  if (NotificationType == MibInitialNotification)
    return;
  ((CPtpClient*)Context)->OnNetworkChange(Row != nullptr ? Row->InterfaceIndex : 0);
}

void CPtpClient::OnNetworkChange(DWORD IfIndex) {
  //until the adapter has been found, any change might be the one we are waiting for
  DWORD ours = (DWORD)InterlockedCompareExchange(&_if_index, 0, 0);
  if ((ours == 0) || (IfIndex == 0) || (IfIndex == ours))
    SignalNetworkChange();
}

void CPtpClient::SignalNetworkChange() {
  WSASetEvent(_net_change_event[0]);
  WSASetEvent(_net_change_event[1]);
}

void CPtpClient::RegisterNetworkNotifications() {
  //failure is not fatal: send errors and the silence timeout still trigger a reopen
  DWORD result = NotifyUnicastIpAddressChange(AF_INET, GAddressChange, this, FALSE, &_address_notification);
  if (result != NO_ERROR) {
    _address_notification = NULL;
    LogResult(result, L"Register for IP address change notifications");
  }
  result = NotifyIpInterfaceChange(AF_INET, GInterfaceChange, this, FALSE, &_interface_notification);
  if (result != NO_ERROR) {
    _interface_notification = NULL;
    LogResult(result, L"Register for network interface change notifications");
  }
}

void CPtpClient::CancelNetworkNotifications() {
  //CancelMibChangeNotify2 waits for running callbacks to complete
  if (_address_notification != NULL) {
    CancelMibChangeNotify2(_address_notification);
    _address_notification = NULL;
  }
  if (_interface_notification != NULL) {
    CancelMibChangeNotify2(_interface_notification);
    _interface_notification = NULL;
  }
}

//"2.0.0", or "2.0.0.5" with a build number: the same form as the setup program and Apps show
static void FormatVersion(wchar_t* Buf, size_t Chars) {
  static const int v[] = { PRODUCT_VER };
  if (v[3] != 0)
    StringCchPrintf(Buf, Chars, L"%d.%d.%d.%d", v[0], v[1], v[2], v[3]);
  else
    StringCchPrintf(Buf, Chars, L"%d.%d.%d", v[0], v[1], v[2]);
}

DWORD CPtpClient::Start() {

  if (!LoadConfiguration(_config)) {
    LogError(L"Prel PTP provider cannot start: its configuration registry key is missing. Run the PrelPtp setup program.");
    return PR_E_CANNOT_LOAD_CONFIGURATION;
  }
  _disable_delay_request = LoadDisableDelayRequestSetting();
  _timestamp_mode = LoadTimestampModeSetting();
  _timestamps = &_software_timestamps;
  _logged_source = nullptr;
  _logged_reason = nullptr;

  //FilterLength values outside 1..MAX_LENGTH (including the 0 written by older setup programs) keep the default
  if ((_config.FilterLength >= 1) && (_config.FilterLength <= CFilter::MAX_LENGTH))
    _filter.SetLength((int)_config.FilterLength);

  //samples older than this are not given to w32time
  if (_disable_delay_request)
    _stale_limit_ms = 10000;
  else {
    _stale_limit_ms = 5ULL * _config.DelayRequestInterval;
    if (_stale_limit_ms < 10000)
      _stale_limit_ms = 10000;
  }
  _filter.SetMaxGap(_stale_limit_ms);

  _bmca.Reset();
  _sync_request.Reset();
  _rx_diagnosis.Reset();
  _message_path.Configure(_config.GrandmasterAddress, _config.DomainNumber, _disable_delay_request);
  wchar_t domain[0x10];
  if (_config.DomainNumber <= 255)
    StringCchPrintf(domain, ARRAYSIZE(domain), L"domain %u", _config.DomainNumber);
  else
    StringCchCopy(domain, ARRAYSIZE(domain), L"any domain");
  if (_config.GrandmasterAddress != 0) {
    wchar_t address[0x20];
    FormatAddress(_config.GrandmasterAddress, address, ARRAYSIZE(address));
    LogFormat(EVENTLOG_INFORMATION_TYPE, L"Prel PTP provider: using only the PTP master at %s (GrandmasterAddress is set), %s", address, domain);
  }
  else {
    LogFormat(EVENTLOG_INFORMATION_TYPE, L"Prel PTP provider: selecting the PTP master automatically (IEEE 1588 best master clock algorithm), %s", domain);
  }

  _delay_request_addr.sin_family = AF_INET;
  _delay_request_addr.sin_port = htons(PTP_EVENT_PORT);
  _delay_request_addr.sin_addr.S_un.S_addr = htonl(PTP_IP_ADDRESS);

  WSAResetEvent(_close_event);
  WSAResetEvent(_delay_request_event);
  WSAResetEvent(_net_change_event[0]);
  WSAResetEvent(_net_change_event[1]);

  RegisterNetworkNotifications();

  if (!_disable_delay_request) {
    _delay_request_timer = CreateThreadpoolTimer(GDrCallback, this, nullptr);
    if (_delay_request_timer == nullptr) {
      DWORD result = GetLastError();
      LogResult(result, L"Create delay request timer");
      Stop();
      return result;
    }
  }

  _event_thread = CreateThread(nullptr, 0, GEventHandler, this, 0, nullptr);
  if (_event_thread == NULL) {
    DWORD result = GetLastError();
    LogResult(result, L"Create event thread");
    Stop();
    return result;
  }

  SetThreadPriority(_event_thread, THREAD_PRIORITY_TIME_CRITICAL);

  _general_thread = CreateThread(nullptr, 0, GGeneralHandler, this, 0, nullptr);
  if (_general_thread == NULL) {
    DWORD result = GetLastError();
    LogResult(result, L"Create general thread");
    Stop();
    return result;
  }

  wchar_t version[0x20];
  FormatVersion(version, ARRAYSIZE(version));
  if (!_disable_delay_request) {
    ScheduleDelayRequest();
    LogFormat(EVENTLOG_INFORMATION_TYPE, L"Prel PTP provider %s started", version);
  }
  else {
    LogFormat(EVENTLOG_WARNING_TYPE, L"Prel PTP provider %s started with delay requests disabled", version);
  }

  return NOERROR;
}


//safe to call more than once, and after a partial Start()
void CPtpClient::Stop() {

  //stop timer callbacks
  if (_delay_request_timer != nullptr) {
    SetThreadpoolTimer(_delay_request_timer, nullptr, 0, 0);
    WaitForThreadpoolTimerCallbacks(_delay_request_timer, TRUE);
    CloseThreadpoolTimer(_delay_request_timer);
    _delay_request_timer = nullptr;
  }

  CancelNetworkNotifications();

  static const DWORD CLOSE_TIMEOUT = 5000;

  WSASetEvent(_close_event);

  HANDLE threads[2];
  DWORD thread_count(0);
  if (_event_thread != NULL)
    threads[thread_count++] = _event_thread;
  if (_general_thread != NULL)
    threads[thread_count++] = _general_thread;

  if (thread_count) {
    if (WaitForMultipleObjects(thread_count, threads, TRUE, CLOSE_TIMEOUT) != WAIT_OBJECT_0)
      LogWarning(L"Prel PTP provider message threads did not stop in time");
    for (DWORD i = 0; i < thread_count; ++i)
      CloseHandle(threads[i]);
    _event_thread = NULL;
    _general_thread = NULL;
    LogInformation(L"Prel PTP provider stopped");
  }
}


/*
Reference ID (refid): 32-bit code identifying the particular server
or reference clock.  The interpretation depends on the value in the
stratum field.  For packet stratum 0 (unspecified or invalid), this
is a four-character ASCII [RFC1345] string, called the "kiss code",
used for debugging and monitoring purposes.  For stratum 1 (reference
clock), this is a four-octet, left-justified, zero-padded ASCII
string assigned to the reference clock.  The authoritative list of
Reference Identifiers is maintained by IANA; however, any string
beginning with the ASCII character "X" is reserved for unregistered
experimentation and development.  The identifiers in Figure 12 have
been used as ASCII identifiers:


+------+----------------------------------------------------------+
| ID   | Clock Source                                             |
+------+----------------------------------------------------------+
| GOES | Geosynchronous Orbit Environment Satellite               |
| GPS  | Global Position System                                   |
| GAL  | Galileo Positioning System                               |
| PPS  | Generic pulse-per-second                                 |
| IRIG | Inter-Range Instrumentation Group                        |
| WWVB | LF Radio WWVB Ft. Collins, CO 60 kHz                     |
| DCF  | LF Radio DCF77 Mainflingen, DE 77.5 kHz                  |
| HBG  | LF Radio HBG Prangins, HB 75 kHz                         |
| MSF  | LF Radio MSF Anthorn, UK 60 kHz                          |
| JJY  | LF Radio JJY Fukushima, JP 40 kHz, Saga, JP 60 kHz       |
| LORC | MF Radio LORAN C station, 100 kHz                        |
| TDF  | MF Radio Allouis, FR 162 kHz                             |
| CHU  | HF Radio CHU Ottawa, Ontario                             |
| WWV  | HF Radio WWV Ft. Collins, CO                             |
| WWVH | HF Radio WWVH Kauai, HI                                  |
| NIST | NIST telephone modem                                     |
| ACTS | NIST telephone modem                                     |
| USNO | USNO telephone modem                                     |
| PTB  | European telephone modem                                 |
+------+----------------------------------------------------------+

*/


HRESULT CPtpClient::GetSamples(TpcGetSamplesArgs* Samples) {
  //only return one sample
  if (Samples->cbSampleBuf < sizeof(TimeSample))
    return ERROR_INSUFFICIENT_BUFFER;

  TimeSample* sample = (TimeSample*)Samples->pbSampleBuf;
  ZeroMemory(sample, sizeof(TimeSample));
  sample->dwSize = sizeof(TimeSample);
  Samples->dwSamplesAvailable = 0;
  Samples->dwSamplesReturned = 0;

  //toDelay not sure
  //toDispersion not sure

  _tp_callbacks.pfnGetTimeSysInfo(TSI_TickCount, &(sample->nSysTickCount));
  _tp_callbacks.pfnGetTimeSysInfo(TSI_PhaseOffset, &(sample->nSysPhaseOffset));

  //nLeapFlags 0

  sample->nStratum = 1; //important. See note above: if this is changed then intepretation of RefId changes.
  sample->dwRefid = _source;

  //nStratum 0
  //dwTSFlags 0  this is what NTP client does

  StringCchCopy(sample->wszUniqueName, ARRAYSIZE(sample->wszUniqueName), _source_name);

  int64_t mean_offset;
  ULONGLONG age_ms(0);
  bool have_mean = _filter.GetMean(mean_offset, &age_ms);

  if (have_mean && (age_ms <= _stale_limit_ms)) {
    mean_offset /= 100;
    sample->toOffset = mean_offset;
    Samples->dwSamplesAvailable = 1;
    Samples->dwSamplesReturned = 1;
    if (_stale_logged) {
      _stale_logged = false;
      LogInformation(L"Prel PTP provider: PTP measurements have resumed");
    }
  }
  else {
    InterlockedExchange(&_alert_pending, 1);
    if (have_mean && !_stale_logged) {
      //do not let w32time keep steering the clock with an out of date correction
      _stale_logged = true;
      LogFormat(EVENTLOG_WARNING_TYPE, L"Prel PTP provider: no PTP measurement for %llu s. Samples are withheld until measurements resume.", age_ms / 1000);
    }
  }


#ifdef ODS_DEBUG
  if (Samples->dwSamplesReturned) {
    wchar_t buf[0x100];
    StringCbPrintfW(buf, sizeof(buf), L"GetSamples: toOffset=%lld SysTickCount=%llu SysPhaseOffset=%lld Age=%llums Name=%s\n",
      sample->toOffset / 10, sample->nSysTickCount, sample->nSysPhaseOffset, age_ms, sample->wszUniqueName);
    OutputDebugString(buf);
  }
  else {
    wchar_t buf[80];
    StringCbPrintfW(buf, sizeof(buf), L"GetSamples: no samples available\n");
    OutputDebugString(buf);
  }
#endif


  return S_OK;
}

void CPtpClient::AddSample(int64_t Offset) {
  switch (_filter.AddSample(Offset)) {
  case CFilter::EAddResult::Rejected:
    return;
  case CFilter::EAddResult::Reacquired:
    LogWarning(L"Prel PTP provider: offset changed suddenly; measurement filter restarted");
    break;
  default:
    break;
  }
  //tell w32time as soon as there is something to collect again
  if (InterlockedExchange(&_alert_pending, 0) != 0)
    AlertSamplesAvailable();
}

//I don't think we use poll interval. Maybe we should use this to set up frequency of sending DR.
//The problem with this is that the DR frequency has a (not very clear) relationship with Sync frequency
//(which is a property of the clock). It seems clear to me that DR interval should be <= Sync frequency.
//Elaborate?
void CPtpClient::UpdatePollInterval() {
  __int32 pi;
  _tp_callbacks.pfnGetTimeSysInfo(TSI_PollInterval, &pi);
  {
    TSRWExclusiveLock lock(_lock);
    _poll_interval = 1 << pi;
  }
}

HRESULT CPtpClient::Command(TimeProvCmd eCmd, PVOID pvArgs) {

  switch (eCmd) {
    case TPC_GetSamples:
      return GetSamples((TpcGetSamplesArgs*)pvArgs);
    case TPC_PollIntervalChanged:
#ifdef ODS_DEBUG
      OutputDebugString(L"Cmd TPC_PollIntervalChanged\n");
#endif
      UpdatePollInterval();
      break;
    case TPC_TimeJumped:
#ifdef ODS_DEBUG
      OutputDebugString(L"Cmd TPC_TimeJumped\n");
#endif
      _filter.Reset();
      break;
    case TPC_UpdateConfig:
#ifdef ODS_DEBUG
      OutputDebugString(L"Cmd TPC_UpdateConfig\n");
#endif
      //_cmd = cmdInitialise;
      break;
    case TPC_NetTopoChange:
      //(TpcNetTopoChangeArgs *)pvArgs;
#ifdef ODS_DEBUG
      OutputDebugString(L"Cmd TPC_NetTopoChange\n");
#endif
      SignalNetworkChange();
      break;
#ifdef ODS_DEBUG
    case TPC_Query:            // (W32TIME_PROVIDER_STATUS *)pvArgs
      OutputDebugString(L"Cmd TPC_Query\n");
      break;

    case TPC_Shutdown:           // (void)pvArgs
      OutputDebugString(L"Cmd TPC_Shutdown\n");
      break;
#endif

  }
  return S_OK;
}

void CPtpClient::DoLog(int Level, const wchar_t* Message) const {
  if (_tp_callbacks.pfnLogTimeProvEvent)
    _tp_callbacks.pfnLogTimeProvEvent(Level, (WCHAR*)ProviderName, (WCHAR*)Message);

#ifdef ODS_DEBUG
  wchar_t buf[0x200];
  StringCbPrintfW(buf,sizeof(buf),L"MTP: %d %s\n", Level, Message);
  OutputDebugString(buf);
#endif

}

void CPtpClient::LogFormat(int Level, const wchar_t* Format, ...) const {
  wchar_t buf[0x200];
  va_list args;
  va_start(args, Format);
  StringCchVPrintfW(buf, ARRAYSIZE(buf), Format, args);
  va_end(args);
  DoLog(Level, buf);
}

void CPtpClient::LogResult(DWORD Result, const TCHAR* Hint) {
  if (Result) {
    TCHAR buf[0x100];
    ErrorMessage(Result, buf, sizeof(buf)/sizeof(TCHAR));
    if (!Hint) {
      LogError(buf);
    } else {
      TCHAR long_buf[0x200];
      StringCbPrintfW(long_buf, sizeof(long_buf), L"%s failed. %s", Hint, buf);
      LogError(long_buf);
    }
  }
}

void CPtpClient::AlertSamplesAvailable() {
  if (_tp_callbacks.pfnAlertSamplesAvail)
    _tp_callbacks.pfnAlertSamplesAvail();
}

bool CPtpClient::WaitForCloseOrNetworkChange(WSAEVENT NetChangeEvent, DWORD TimeoutMs) {
  WSAEVENT events[2] = { _close_event, NetChangeEvent };
  DWORD wait_result = WSAWaitForMultipleEvents(2, events, FALSE, TimeoutMs, FALSE);
  if (wait_result == WSA_WAIT_FAILED) {
    //should never happen; avoid spinning
    Sleep(TimeoutMs);
    return WSAWaitForMultipleEvents(1, events, FALSE, 0, FALSE) == WSA_WAIT_EVENT_0;
  }
  return wait_result == WSA_WAIT_EVENT_0;
}

//Thread entry point. MessageLoop only returns when the provider is stopping;
//anything unexpected is logged and the loop restarted so the thread never just disappears.
DWORD CPtpClient::ThreadProc(WORD Port, EMessageLoop Loop) {
  while (true) {
    try {
      MessageLoop(Port, Loop);
      return 0;
    }
    catch (...) {
      LogFormat(EVENTLOG_ERROR_TYPE, L"Prel PTP provider: unexpected error in the %s message loop. Restarting it.", LoopName(Port));
    }
    if (WaitForCloseOrNetworkChange(_net_change_event[(int)Loop], BACKOFF_MIN_MS))
      return 0;
  }
}

void CPtpClient::MessageLoop(WORD Port, EMessageLoop Loop) {

  WSAEVENT net_change_event = _net_change_event[(int)Loop];
  DWORD backoff_ms(BACKOFF_MIN_MS);
  EAdapterState logged_state(EAdapterState::Ready);
  bool waiting_logged(false);
  DWORD logged_open_error(NOERROR);
  DWORD bound_address(0);
  bool silence_logged(false);

  while (true) {
    //any network change from here on causes another pass
    WSAResetEvent(net_change_event);

    SAdapterInfo adapter;
    EAdapterState state = ResolveAdapter(_config.AdapterName, adapter);
    if (state != EAdapterState::Ready) {
      //IfIndex is 0 if the adapter was not found, which lets notifications for any interface through
      InterlockedExchange(&_if_index, (LONG)adapter.IfIndex);
      if (!waiting_logged || (state != logged_state)) {
        LogFormat(EVENTLOG_WARNING_TYPE, L"Prel PTP provider (%s port %d) is waiting: %s. It will start automatically when the adapter is ready.",
          LoopName(Port), Port, AdapterStateText(state));
        waiting_logged = true;
        logged_state = state;
      }
      if (WaitForCloseOrNetworkChange(net_change_event, backoff_ms))
        return;
      backoff_ms = NextBackoff(backoff_ms);
      continue;
    }

    InterlockedExchange(&_if_index, (LONG)adapter.IfIndex);

    SocketHandle sock;
    DWORD result = OpenSocket(Port, adapter.LocalAddress, sock.skt);
    if (result != NOERROR) {
      if (result != logged_open_error) {
        wchar_t hint[0x80];
        wchar_t address[0x20];
        FormatAddress(adapter.LocalAddress, address, ARRAYSIZE(address));
        StringCchPrintf(hint, ARRAYSIZE(hint), L"Open %s socket on %s port %d (will retry)", LoopName(Port), address, Port);
        LogResult(result, hint);
        logged_open_error = result;
      }
      if (WaitForCloseOrNetworkChange(net_change_event, backoff_ms))
        return;
      backoff_ms = NextBackoff(backoff_ms);
      continue;
    }

    //log recovery, or an address change, but not routine reopens
    if (waiting_logged || (logged_open_error != NOERROR) || (adapter.LocalAddress != bound_address)) {
      wchar_t address[0x20];
      FormatAddress(adapter.LocalAddress, address, ARRAYSIZE(address));
      LogFormat(EVENTLOG_INFORMATION_TYPE, L"Prel PTP provider listening on %s port %d", address, Port);
    }
    waiting_logged = false;
    logged_open_error = NOERROR;
    bound_address = adapter.LocalAddress;

    if (Loop == EMessageLoop::Event) {
      InitDelayRequest(adapter.MacAddress);
      SelectTimestampSource(sock, adapter.IfIndex);
    }

    switch (RunSocket(sock, Port, Loop, silence_logged)) {
      case ESocketResult::Closed:
        return;
      case ESocketResult::NetworkChanged:
        backoff_ms = BACKOFF_MIN_MS;
        break;
      case ESocketResult::Fault:
        sock.Close();
        if (WaitForCloseOrNetworkChange(net_change_event, backoff_ms))
          return;
        backoff_ms = NextBackoff(backoff_ms);
        break;
    }
  }
}

void CPtpClient::SelectTimestampSource(SOCKET Socket, DWORD IfIndex) {
  ITimestampSource* previous = _timestamps;
  const wchar_t* reason = nullptr;
  _hw_recheck.Reset();
  if (_timestamp_mode == ETimestampMode::Software) {
    _timestamps = &_software_timestamps;
    reason = L"TimestampMode is set to 1 (software)";
  }
  else if (_hardware_timestamps.Open(Socket, IfIndex, reason) == NOERROR) {
    _timestamps = &_hardware_timestamps;
  }
  else {
    _timestamps = &_software_timestamps;
  }

  //samples timed one way must not be averaged with samples timed the other
  if (_timestamps != previous) {
    _filter.Reset();
    _sync_request.Reset();
  }

  if ((_timestamps == _logged_source) && (reason == _logged_reason))
    return;
  _logged_source = _timestamps;
  _logged_reason = reason;
  if ((_timestamps == &_hardware_timestamps) && (_hardware_timestamps.ActiveQueryError() != NO_ERROR))
    LogFormat(EVENTLOG_INFORMATION_TYPE, L"Prel PTP provider: trying hardware timestamps from the adapter. Its driver does not say whether they are active (error %lu), so they are checked as they arrive, and software timestamps are used if they don't. Delay requests start when the NIC clock rate has been measured, after about 5 s.",
      _hardware_timestamps.ActiveQueryError());
  else if (_timestamps == &_hardware_timestamps)
    LogInformation(L"Prel PTP provider: using hardware timestamps from the adapter. Delay requests start when the NIC clock rate has been measured, after about 5 s.");
  else
    LogFormat(EVENTLOG_INFORMATION_TYPE, L"Prel PTP provider: using software timestamps: %s.", reason);
}

void CPtpClient::FallBackToSoftware(const wchar_t* Why, double NicHz) {
  LARGE_INTEGER qpf;
  QueryPerformanceFrequency(&qpf);
  _hw_recheck.OnFallback(NicHz, qpf.QuadPart, GetTickCount64());
  if (_hw_recheck.Watching())
    LogFormat(EVENTLOG_WARNING_TYPE, L"Prel PTP provider: switching to software timestamps: %s. If hardware receive timestamps come back, hardware timestamps are used again (checked every %llu minutes, or when the socket is reopened).",
      Why, _hw_recheck.Interval() / 60000);
  else
    LogFormat(EVENTLOG_WARNING_TYPE, L"Prel PTP provider: switching to software timestamps: %s. Hardware timestamps are tried again when the socket is reopened.", Why);
  _timestamps = &_software_timestamps;
  _logged_source = _timestamps;
  _logged_reason = Why;
  _filter.Reset();
  _sync_request.Reset();
}

void CPtpClient::ReturnToHardware() {
  _hw_recheck.OnReturn();
  _hardware_timestamps.Restart();
  _timestamps = &_hardware_timestamps;
  _logged_source = _timestamps;
  _logged_reason = nullptr;
  _filter.Reset();
  _sync_request.Reset();
  LogInformation(L"Prel PTP provider: hardware receive timestamps are arriving again; switching back to hardware timestamps. Delay requests resume when the NIC clock rate has been measured, after about 5 s.");
}

void CPtpClient::CollectTxTime(STxPending& inout_Pending, int& inout_Failures) {
  uint64_t t3(0);
  switch (_timestamps->TxTime(inout_Pending.Seq, inout_Pending.Before, t3)) {
  case ETxResult::Ready: {
    inout_Pending.Active = false;
    inout_Failures = 0;
    int64_t offset(0);
    //true if the Delay_Resp arrived first
    if (_sync_request.DelayRequestTx(inout_Pending.Seq, t3, offset))
      AddSample(offset);
    break;
  }
  case ETxResult::NotYet:
    //A timestamp that turns up after this stays in the socket's buffer (8 entries); the failures
    //that cause it also lead to the fallback long before the buffer could fill.
    if (GetTickCount64() - inout_Pending.SentTick > (ULONGLONG)CHardwareTimestamps::TX_TIMEOUT_MS) {
      inout_Pending.Active = false;
      ++inout_Failures;
    }
    break;
  case ETxResult::Failed:
    inout_Pending.Active = false;
    ++inout_Failures;
    break;
  }
}

CPtpClient::ESocketResult CPtpClient::RunSocket(SOCKET Socket, WORD Port, EMessageLoop Loop, bool& inout_SilenceLogged) {

  EventHandle select_event;
  if (!select_event) {
    LogResult(WSAGetLastError(), L"Create socket event");
    return ESocketResult::Fault;
  }

  //WSARecvMsg returns the control data a timestamp source needs. It is an extension function,
  //looked up for each socket.
  LPFN_WSARECVMSG recv_msg(nullptr);
  GUID recv_msg_id = WSAID_WSARECVMSG;
  DWORD bytes(0);
  if (WSAIoctl(Socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &recv_msg_id, sizeof(recv_msg_id),
    &recv_msg, sizeof(recv_msg), &bytes, nullptr, nullptr) == SOCKET_ERROR) {
    LogResult(WSAGetLastError(), L"Get WSARecvMsg");
    return ESocketResult::Fault;
  }

  WSAEVENT events[4] = { select_event, _close_event, _net_change_event[(int)Loop], _delay_request_event };
  //do not handle delay request event on general loop. It is time sensitive.
  DWORD event_count(Loop == EMessageLoop::Event ? 4 : 3);

  ULONGLONG last_rx(GetTickCount64());
  int consecutive_send_errors(0);
  int last_send_error(0);
  bool healthy(false);

  //event loop only: the Delay_Req whose transmit time is still to be collected, and the health of
  //hardware timestamps (see FallBackToSoftware)
  STxPending tx_pending;
  ZeroMemory(&tx_pending, sizeof(tx_pending));
  int sync_misses(0);
  int tx_failures(0);
  ULONGLONG opened_tick(GetTickCount64());
  bool rate_logged(false);
  double nic_hz(0.0);   //NIC clock rate last measured on this socket

  while (true) {
    if (WSAEventSelect(Socket, select_event, FD_READ) == SOCKET_ERROR) {
      LogResult(WSAGetLastError(), L"Select socket events");
      return ESocketResult::Fault;
    }

    //while a transmit timestamp is outstanding, wake often to collect it
    DWORD wait_result = WSAWaitForMultipleEvents(event_count, events, FALSE, tx_pending.Active ? 1 : LOOP_TICK_MS, FALSE);

    //software receive time (t2), then QPC: the pair maps hardware times to system time
    STimePair wake = STimePair::Now();
    uint64_t timestamp = wake.SystemTime;

    if (wait_result == WSA_WAIT_EVENT_0 + 1) {
      return ESocketResult::Closed;
    }
    else if (wait_result == WSA_WAIT_EVENT_0 + 2) {
      //network change on (or possibly on) the PTP adapter: reopen against the current address
      return ESocketResult::NetworkChanged;
    }
    else if (wait_result == WSA_WAIT_EVENT_0 + 3) {  //never happens on general loop
      WSAResetEvent(_delay_request_event);
      //no Delay_Req until the timestamp source can time it (hardware: NIC clock rate being measured)
      if (!_disable_delay_request && _timestamps->Ready()) {
        uint16_t wire_seq = _sync_request.GetDelayRequestSequenceId();
        _delay_request.Header.sequenceId = wire_seq;
        uint16_t seq = _byteswap_ushort(wire_seq);
        char control[0x40];
        ULONG control_len = _timestamps->TxControl(seq, control, sizeof(control));
        WSABUF data = { (ULONG)(sizeof(CommonMsgHeader) + sizeof(Delay_ReqMessage)), (char*)&_delay_request };
        WSAMSG msg;
        ZeroMemory(&msg, sizeof(msg));
        msg.name = (sockaddr*)&_delay_request_addr;
        msg.namelen = sizeof(_delay_request_addr);
        msg.lpBuffers = &data;
        msg.dwBufferCount = 1;
        if (control_len != 0) {
          msg.Control.buf = control;
          msg.Control.len = control_len;
        }
        DWORD sent(0);
        STimePair before = STimePair::Now();  //software t3
        int result = WSASendMsg(Socket, &msg, 0, &sent, nullptr, nullptr);
        if (result == SOCKET_ERROR) {
          int err(WSAGetLastError());
          if (err != last_send_error)  //one message per burst of identical errors
            LogResult(err, L"send delay request");
          last_send_error = err;
          if (IsNetworkError(err) || (++consecutive_send_errors >= MAX_CONSECUTIVE_SEND_ERRORS)) {
            LogFormat(EVENTLOG_WARNING_TYPE, L"Prel PTP provider: reopening the %s socket after send errors", LoopName(Port));
            return ESocketResult::Fault;
          }
        }
        else {
          consecutive_send_errors = 0;
          last_send_error = 0;
          //replaces any transmit time still outstanding: the previous Delay_Req can no longer complete
          tx_pending.Active = true;
          tx_pending.Seq = seq;
          tx_pending.Before = before;
          tx_pending.SentTick = GetTickCount64();
          CollectTxTime(tx_pending, tx_failures);
        }
      }
    }
    else if (wait_result == WSA_WAIT_EVENT_0) {
      WSAResetEvent(select_event);

      PtpMessage message;
      SOCKADDR_IN from;
      ZeroMemory(&from, sizeof(from));
      char control[0x80];
      WSABUF data = { sizeof(message), (char*)&message };
      WSAMSG msg;
      ZeroMemory(&msg, sizeof(msg));
      msg.name = (sockaddr*)&from;
      msg.namelen = sizeof(from);
      msg.lpBuffers = &data;
      msg.dwBufferCount = 1;
      msg.Control.buf = control;
      msg.Control.len = sizeof(control);
      DWORD received(0);
      int result = recv_msg(Socket, &msg, &received, nullptr, nullptr);
      if (result != SOCKET_ERROR)
        result = (int)received;

      if (result == SOCKET_ERROR) {
        int err(WSAGetLastError());
        //WSAEMSGSIZE: management message, don't care. WSAEWOULDBLOCK: spurious wake.
        //WSAECONNRESET: ICMP port unreachable from an earlier send.
        if ((err != WSAEMSGSIZE) && (err != WSAEWOULDBLOCK) && (err != WSAECONNRESET)) {
          LogResult(err, L"WSARecvMsg");
          if (IsNetworkError(err))
            return ESocketResult::Fault;
        }
      }
      else if (result == 0) {
        LogError(L"WSARecvMsg connection closed"); //should never happen on UDP socket
      }
      else {
        /*
        Event messages (port 319): Sync Rx, Delay_Req Tx (looped back to us), Pdelay_Req, Pdelay_Resp
        General messages (port 320): Announce Rx, Follow_Up Rx, Delay_Resp Rx, Pdelay_Resp_Follow_Up,
        Management, Signalling
        */
        //only event messages (Sync) need a receive time
        uint64_t rx_time = timestamp;
        bool usable(true);
        if (Loop == EMessageLoop::Event) {
          bool is_sync = (*(const uint8_t*)&message & 0x0F) == (uint8_t)EMessageType::Sync;
          //on software after a fallback: are hardware receive timestamps back? (costs nothing: the control data is here)
          if (is_sync && (_timestamps != &_hardware_timestamps))
            _hw_recheck.OnSync(WinsockTs::RxTimestamp(msg), wake.Qpc);
          if (_timestamps->RxTime(wake, msg, rx_time)) {
            if (is_sync)
              sync_misses = 0;
          }
          else if (is_sync) {
            //a Sync without a receive time cannot be used: a software time would bias the offset
            usable = false;
            if (_timestamps->Ready() && (++sync_misses >= MAX_SYNC_MISSES))
              FallBackToSoftware(L"Sync messages are arriving without hardware receive timestamps", nic_hz);
          }
          else {
            rx_time = timestamp;  //only Sync needs a receive time
          }
        }
        if (usable) {
          CMessagePath::SOutcome outcome = _message_path.Handle(message, result, from.sin_addr.S_un.S_addr, rx_time);
          _rx_diagnosis.OnOutcome(outcome, from.sin_addr.S_un.S_addr);

          //any PTP message from the network shows the socket is working, even one in another domain
          //or from another master: whether it can be used is CheckRxDiagnosis's business
          if (outcome.Result != CMessagePath::EResult::Ignored) {
            last_rx = GetTickCount64();
            healthy = true;
            if (inout_SilenceLogged) {
              inout_SilenceLogged = false;
              LogFormat(EVENTLOG_INFORMATION_TYPE, L"Prel PTP provider: receiving PTP messages on port %d again", Port);
            }
          }
          HandleOutcome(outcome, Loop);
          if (Loop == EMessageLoop::General)
            CheckRxDiagnosis();
        }
      }
    }
    else if (wait_result == WSA_WAIT_TIMEOUT) {
      //nothing received for a while: the selected master's Announce messages may have stopped
      if (Loop == EMessageLoop::General) {
        if (_message_path.Tick())
          OnMasterChanged();
        CheckRxDiagnosis();
      }
    }
    else {
      LogResult(WSAGetLastError(), L"Wait in message loop");
      return ESocketResult::Fault;
    }

    if (Loop == EMessageLoop::Event) {
      _timestamps->Poll();
      if (tx_pending.Active)
        CollectTxTime(tx_pending, tx_failures);
      if (_timestamps == &_hardware_timestamps) {
        if (_timestamps->Ready()) {
          nic_hz = _hardware_timestamps.MeasuredHz();
          if (!rate_logged) {
            rate_logged = true;
            //the reported frequency is only for comparison: some adapters report a wrong one
            double measured = _hardware_timestamps.MeasuredHz();
            uint64_t reported = _hardware_timestamps.ReportedHz();
            double ppm = (reported != 0) ? (measured / (double)reported - 1.0) * 1e6 : 0.0;
            if ((reported != 0) && (fabs(ppm) < 1000.0))
              LogFormat(EVENTLOG_INFORMATION_TYPE, L"Prel PTP provider: hardware timestamps ready. NIC clock %llu Hz nominal, running %+.2f ppm against the system counter.",
                reported, ppm);
            else
              LogFormat(EVENTLOG_INFORMATION_TYPE, L"Prel PTP provider: hardware timestamps ready. The NIC clock runs at %.0f Hz against the system counter (the adapter reports %llu Hz).",
                measured, reported);
          }
          //the recheck only sees receive timestamps, so it can't tell when transmit timestamps are back
          if (tx_failures >= MAX_TX_FAILURES)
            FallBackToSoftware(L"Delay_Req messages are being sent without hardware transmit timestamps", 0.0);
        }
        else if (GetTickCount64() - opened_tick > NIC_CLOCK_READY_MS) {
          //nic_hz is 0 unless the clock was measured earlier on this socket (a return that didn't hold)
          FallBackToSoftware(L"the NIC clock could not be related to the system clock", nic_hz);
        }
      }
      else if (_hw_recheck.Due(GetTickCount64())) {
        ReturnToHardware();
        sync_misses = 0;
        tx_failures = 0;
        tx_pending.Active = false;
        opened_tick = GetTickCount64();
        rate_logged = false;
      }
    }

    if ((GetTickCount64() - last_rx) > RX_SILENCE_MS) {
      //the master may be down, or the socket may have silently lost its multicast membership
      if (!inout_SilenceLogged) {
        inout_SilenceLogged = true;
        LogFormat(EVENTLOG_WARNING_TYPE, L"Prel PTP provider: no PTP messages on port %d for %llu s. Reopening the socket.", Port, RX_SILENCE_MS / 1000);
      }
      return healthy ? ESocketResult::NetworkChanged : ESocketResult::Fault;
    }
  }
}

void CPtpClient::HandleOutcome(const CMessagePath::SOutcome& Outcome, EMessageLoop Loop) {
  if (Outcome.MasterChanged)
    OnMasterChanged();

  if (Outcome.Result != CMessagePath::EResult::Accepted)
    return;

  //Delay_Req goes to the domain of the master whose Sync we are using
  if ((Outcome.Type == EMessageType::Sync) && (Loop == EMessageLoop::Event))
    _delay_request.Header.domainNumber = Outcome.Domain;

  if (Outcome.HaveOffset)
    AddSample(Outcome.Offset);
}

void CPtpClient::CheckRxDiagnosis() {
  CRxDiagnosis::SDetail detail;
  switch (_rx_diagnosis.Check(detail)) {
  case CRxDiagnosis::EReport::WrongDomain: {
    wchar_t seen[0x80] = { 0 };
    int listed = 0;
    for (int d = 0; d < 256; ++d) {
      if (!detail.Domains[d])
        continue;
      wchar_t one[0x10];
      if (++listed > 8) {
        StringCchCat(seen, ARRAYSIZE(seen), L", ...");
        break;
      }
      StringCchPrintf(one, ARRAYSIZE(one), listed == 1 ? L"%d" : L", %d", d);
      StringCchCat(seen, ARRAYSIZE(seen), one);
    }
    LogFormat(EVENTLOG_WARNING_TYPE,
      L"Prel PTP provider: PTP messages are arriving, but none in domain %u, the configured domain (DomainNumber). Domains seen: %s. No samples until messages arrive in domain %u.",
      _config.DomainNumber, seen, _config.DomainNumber);
    break;
  }
  case CRxDiagnosis::EReport::WrongSource: {
    wchar_t configured[0x20], seen[0x20];
    FormatAddress(_config.GrandmasterAddress, configured, ARRAYSIZE(configured));
    FormatAddress(detail.OtherAddress, seen, ARRAYSIZE(seen));
    LogFormat(EVENTLOG_WARNING_TYPE,
      L"Prel PTP provider: PTP messages are arriving, but none from %s, the configured master (GrandmasterAddress). Messages seen from %s, for example. No samples until %s is heard.",
      configured, seen, configured);
    break;
  }
  case CRxDiagnosis::EReport::Resumed:
    LogInformation(L"Prel PTP provider: PTP messages from the configured domain and master are arriving again");
    break;
  default:
    break;
  }
}

void CPtpClient::OnMasterChanged() {
  //samples from different masters must not be averaged together
  if (!_message_path.Pinned())
    _filter.Reset();

  CBmca::SForeignMaster master;
  if (_bmca.GetSelected(master)) {
    wchar_t address[0x20];
    wchar_t gm[0x20];
    wchar_t port[0x20];
    FormatAddress(master.Address, address, ARRAYSIZE(address));
    FormatClockIdentity(master.Dataset.GrandmasterIdentity, gm, ARRAYSIZE(gm));
    FormatClockIdentity(master.Dataset.Sender.clockIdentity, port, ARRAYSIZE(port));
    LogFormat(EVENTLOG_INFORMATION_TYPE,
      L"Prel PTP provider: PTP master is %s (port %s-%u, domain %u). Grandmaster %s: priority1 %u, clock class %u, accuracy 0x%02X, variance 0x%04X, priority2 %u, steps removed %u.",
      address, port, master.Dataset.Sender.portNumber, master.Domain, gm,
      master.Dataset.Priority1, master.Dataset.ClockClass, master.Dataset.ClockAccuracy,
      master.Dataset.OffsetScaledLogVariance, master.Dataset.Priority2, master.Dataset.StepsRemoved);
  }
  else {
    LogWarning(_message_path.Pinned()
      ? L"Prel PTP provider: Announce messages from the configured PTP master have stopped"
      : L"Prel PTP provider: no PTP master. Announce messages from the selected master have stopped and no other master qualifies.");
  }
}