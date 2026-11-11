#pragma once

#include "..\PtpUtil\Util.h"
#include "..\PtpUtil\Filter.h"
#include "..\PtpUtil\Ptp.h"
#include "..\PtpUtil\SyncRequest.h"
#include "..\PtpUtil\Bmca.h"
#include "..\PtpUtil\MessagePath.h"
#include "..\PtpUtil\Timestamp.h"
#include <mswsock.h>
#include <timeprov.h>


/*
First implementation sent delay request immediately on getting sync message

This is not allowed with multicast because it means that all clients will be 
sending simultaneous DR. 

The delay between a sync/follow_up and DR is irrelevant because the delay is the
same on gmc and client. So DR can be issued at any frequency then matched to the most
recent sync.

DR should not be sent at a regular frequency - there should be some random variation.
I think this is specified in the standard as +/- 10% but it hardly matters.

Don't use Sync sequence id for DR. We want to be able to easily work out which responses
are ours. We will get Delay response for all clients on the LAN and must filter these 
out. Sequence ID first then Client id.

*/

/*
Robustness

Start() only fails if the configuration cannot be loaded or threads cannot be created. 
Each message loop (event port 319, general port 320) runs an outer retry loop:

  resolve adapter -> not ready: log (once per state), wait for a network change or back off, retry
                  -> ready: open socket -> fails: log, back off, retry
                                        -> ok: process messages until
                                             close event              -> exit thread
                                             network change event     -> reopen immediately
                                             fatal socket error       -> back off, reopen
                                             no PTP traffic for a minute -> reopen

Network changes come from NotifyUnicastIpAddressChange / NotifyIpInterfaceChange (filtered to
the PTP adapter's interface once it is known) and from w32time's TPC_NetTopoChange.

Reopening a socket does not discard measurements. Instead, GetSamples withholds the offset
when the newest sample is too old, so w32time free-runs rather than following a stale
correction, and the filter restarts when samples resume after a gap.
*/

class CPtpClient {
private:
  typedef wchar_t String40[40];
  TSRWLock _lock;

  enum class EMessageLoop {
    Event = 0,
    General = 1
  };

  enum class ESocketResult {
    Closed,           //provider is stopping
    NetworkChanged,   //reopen immediately
    Fault             //socket error or silence: back off then reopen
  };

  HANDLE _event_thread;
  HANDLE _general_thread;

  WSAEVENT _close_event;
  WSAEVENT _delay_request_event;
  WSAEVENT _net_change_event[2];  //one per message loop, manual reset
  PTP_TIMER _delay_request_timer;

  HANDLE _address_notification;
  HANDLE _interface_notification;
  volatile LONG _if_index;        //interface index of the PTP adapter, 0 if not known

  DWORD _source;
  String40 _source_name;
  TimeProvSysCallbacks _tp_callbacks;
  SConfiguration _config;
  bool _disable_delay_request; //emergency fallback from the provider registry value
  CFilter _filter;
  ULONGLONG _stale_limit_ms;

  //GetSamples state, only touched on the w32time thread
  bool _stale_logged;
  //set when GetSamples had nothing to return, so the next good sample alerts w32time
  volatile LONG _alert_pending;

  //we do not use this. It is part of the TimeProv contract.
  //presumably it has something to do with the corresponding value in w32time config
  //&&& Look into it.
  DWORD _poll_interval;

  SSyncRequest _sync_request;
  CBmca _bmca;
  CMessagePath _message_path;     //after _sync_request and _bmca: it holds references to them
  CRxDiagnosis _rx_diagnosis;
  //Timestamp source for the event socket, chosen each time it is opened (SelectTimestampSource).
  //Only used by the event thread.
  ETimestampMode _timestamp_mode;
  CSoftwareTimestamps _software_timestamps;
  CHardwareTimestamps _hardware_timestamps;
  ITimestampSource* _timestamps;
  //after a fallback: whether hardware receive timestamps have come back
  CHardwareRecheck _hw_recheck;
  //what was last logged about the choice, so a routine reopen does not log it again
  const ITimestampSource* _logged_source;
  const wchar_t* _logged_reason;

  //a Delay_Req whose transmit time has not been collected yet
  struct STxPending {
    bool Active;
    uint16_t Seq;         //host order; also the transmit timestamp id
    STimePair Before;     //read just before the send
    ULONGLONG SentTick;
  };
  PtpMessage _delay_request;      //only used by the event thread after Start()
  sockaddr_in _delay_request_addr;

  void DelayRequestCallback();

  static void CALLBACK GDrCallback(
    PTP_CALLBACK_INSTANCE Instance,
    PVOID Context,
    PTP_TIMER Timer
  ) {
    ((CPtpClient*)Context)->DelayRequestCallback();
  }

  static VOID NETIOAPI_API_ GAddressChange(PVOID Context, PMIB_UNICASTIPADDRESS_ROW Row, MIB_NOTIFICATION_TYPE NotificationType);
  static VOID NETIOAPI_API_ GInterfaceChange(PVOID Context, PMIB_IPINTERFACE_ROW Row, MIB_NOTIFICATION_TYPE NotificationType);
  void OnNetworkChange(DWORD IfIndex);
  void SignalNetworkChange();
  void RegisterNetworkNotifications();
  void CancelNetworkNotifications();

  void AlertSamplesAvailable();
  void AddSample(int64_t Offset);

  //called by Time service W32Time
  HRESULT GetSamples(TpcGetSamplesArgs* Samples);

  //not sure we even use this. See above.
  void UpdatePollInterval();

  void ScheduleDelayRequest();
  void InitDelayRequest(const TMacAddress& MacAddress);

  //hardware timestamps if TimestampMode allows and the adapter has them, otherwise software
  void SelectTimestampSource(SOCKET Socket, DWORD IfIndex);
  //Hardware timestamps stopped working on this socket: software until it is reopened, or until
  //_hw_recheck sees the receive timestamps come back. NicHz: the NIC clock rate measured on this
  //socket (0 if it never was, or if the failure isn't one the recheck can see).
  void FallBackToSoftware(const wchar_t* Why, double NicHz);
  //_hw_recheck says the receive timestamps are back
  void ReturnToHardware();
  //asks the timestamp source for the outstanding Delay_Req's t3 and completes the exchange if it can
  void CollectTxTime(STxPending& inout_Pending, int& inout_Failures);

  //acts on what CMessagePath decided about a received message
  void HandleOutcome(const CMessagePath::SOutcome& Outcome, EMessageLoop Loop);
  //the BMCA's selected master changed: restart the filter (automatic mode) and log it
  void OnMasterChanged();
  //logs once if PTP traffic arrives but none of it is usable (wrong domain or address), and when it recovers
  void CheckRxDiagnosis();

  //returns true if the provider is stopping
  bool WaitForCloseOrNetworkChange(WSAEVENT NetChangeEvent, DWORD TimeoutMs);

  void MessageLoop(WORD Port, EMessageLoop Loop);
  ESocketResult RunSocket(SOCKET Socket, WORD Port, EMessageLoop Loop, bool& inout_SilenceLogged);
  DWORD ThreadProc(WORD Port, EMessageLoop Loop);

  static DWORD WINAPI GEventHandler(LPVOID This) {
    return ((CPtpClient*)This)->ThreadProc(PTP_EVENT_PORT, EMessageLoop::Event);
  }

  static DWORD WINAPI GGeneralHandler(LPVOID This) { 
    return ((CPtpClient*)This)->ThreadProc(PTP_GENERAL_PORT, EMessageLoop::General);
  }
  
  void DoLog(int Level, const wchar_t* Message) const;
  void LogFormat(int Level, const wchar_t* Format, ...) const;
  void LogError(const TCHAR* Msg) { DoLog(EVENTLOG_ERROR_TYPE, Msg); }
  void LogWarning(const TCHAR* Msg) { DoLog(EVENTLOG_WARNING_TYPE, Msg); }
  void LogInformation(const TCHAR* Msg) { DoLog(EVENTLOG_INFORMATION_TYPE, Msg); }

  void LogResult(DWORD Result, const TCHAR* Hint);
  DWORD OpenSocket(WORD Port, DWORD LocalAddress, SOCKET& out_Socket);

public:
  void Stop();
  DWORD Start();
  HRESULT Command(TimeProvCmd eCmd, PVOID pvArgs);
  CPtpClient(const TimeProvSysCallbacks* ATpCallbacks);
  ~CPtpClient();
};


extern const wchar_t* ProviderName;
