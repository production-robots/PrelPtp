#pragma once

#include "Util.h"

/*
Where the provider's receive (t2) and transmit (t3) times come from.

Software (the method used since the first version): t2 is the system time read when the wait for
the socket returns, before the message is read; t3 is the system time read just before the send.
Both include the time the stack and the scheduler take: measured on a ConnectX-5 on Windows Server
2022, about 30 us on receive and 54 us on send, so the offset is biased by about -12 us with an sd of
6 us per sample.

Hardware: the NIC's own receive and transmit timestamps (Windows Server 2022 / Windows 11 and an
adapter with hardware timestamping active). They are in NIC clock ticks. CNicClock maps them to QPC
using cross-timestamps, and a QPC / system time pair read together maps QPC to system time.

All times are system time, ns100 since 1601, as the rest of the provider uses.

The event message loop (one thread) is the only user of a source after it is opened.
*/

//System time and QPC read one after the other.
struct STimePair {
  uint64_t SystemTime;  //ns100 since 1601
  int64_t Qpc;

  static STimePair Now();
};

enum class ETxResult {
  Ready,    //out_Time is valid
  NotYet,   //ask again later
  Failed    //no transmit time for this message
};

class ITimestampSource {
public:
  virtual ~ITimestampSource() {}

  //for the event log
  virtual const wchar_t* Name() const = 0;

  //False while the source cannot produce times yet (the NIC clock rate is still being measured).
  //No Delay_Req should be sent then.
  virtual bool Ready() const { return true; }

  //Called on every pass of the event loop.
  virtual void Poll() {}

  //Receive time of the message in Msg. Wake: read when the wait for the socket returned.
  //Returns false if there is no time for this message.
  virtual bool RxTime(const STimePair& Wake, const WSAMSG& Msg, uint64_t& out_Time) = 0;

  //Control data to send with the message whose transmit time will be asked for with Id.
  //Returns the number of bytes written to Buf (0: none needed).
  virtual ULONG TxControl(uint32_t Id, char* Buf, ULONG Size) = 0;

  //Transmit time of the message sent with Id. Before: read just before the send.
  virtual ETxResult TxTime(uint32_t Id, const STimePair& Before, uint64_t& out_Time) = 0;
};

//Today's method: the wake time and the time just before the send.
class CSoftwareTimestamps : public ITimestampSource {
public:
  const wchar_t* Name() const override { return L"software"; }
  bool RxTime(const STimePair& Wake, const WSAMSG& Msg, uint64_t& out_Time) override;
  ULONG TxControl(uint32_t Id, char* Buf, ULONG Size) override;
  ETxResult TxTime(uint32_t Id, const STimePair& Before, uint64_t& out_Time) override;
};

//A NIC clock reading taken between two QPC readings (CaptureInterfaceHardwareCrossTimestamp).
struct SCrossTimestamp {
  uint64_t Qpc1;
  uint64_t Hw;
  uint64_t Qpc2;
};

/*
Maps NIC clock ticks to QPC ticks.

Add a cross-timestamp about once a second. The NIC clock rate is measured against QPC between the
oldest and newest of the last HISTORY cross-timestamps; until they span MIN_SPAN_S seconds the
clock is not Ready. The frequency the adapter reports is not used, for two reasons:
- it is not exact enough: each ppm of error is 1 us over the second between cross-timestamps (the
  ConnectX-5 tested reports 156,260,416 Hz and runs -0.14 ppm from that against QPC);
- it can be plain wrong: the Intel I219-LM tested reports 125 MHz, but its timestamps and
  cross-timestamps count at 1.008 GHz.

A cross-timestamp read slowly (wide QPC window) is a poor anchor and is rejected. A reading that
does not fit the rate seen so far (the NIC clock was stepped, or the adapter restarted) restarts the
measurement. A clock that does not advance (MIN_HZ) is never Ready.
*/
class CNicClock {
public:
  static const int HISTORY = 16;
  static const int MIN_SPAN_S = 5;
  static const int MAX_WINDOW_NS = 5000;    //read window above which a cross-timestamp is rejected
  static const int MAX_RATE_PPM = 1000;     //a rate between two readings this far from the rate seen so far restarts the measurement
  static const int MIN_HZ = 1000000;        //a NIC clock slower than this (or stopped) is not usable

private:
  SCrossTimestamp _hist[HISTORY];
  int _count;
  int _newest;
  double _rate;       //NIC ticks per QPC tick, measured
  int64_t _qpf;
  bool _ready;

  const SCrossTimestamp& Oldest() const;
  static double Mid(const SCrossTimestamp& X) { return ((double)X.Qpc1 + (double)X.Qpc2) / 2.0; }
  void Restart();

public:
  CNicClock();

  void Reset(int64_t QpcFrequency);

  enum class EAdd { Added, Rejected, Restarted };
  EAdd Add(const SCrossTimestamp& X);

  bool Ready() const { return _ready; }

  //QPC tick (fractional) at which the NIC clock read Hw. Only valid when Ready.
  double ToQpc(uint64_t Hw) const;

  //measured frequency of the NIC clock against QPC, Hz (0 until Ready)
  double MeasuredHz() const;
};

/*
Hardware timestamps on one socket.

Open checks that the adapter has hardware receive and transmit timestamps and cross-timestamps
active, and turns timestamping on for the socket. The timestamp functions are looked up at run time,
so the DLL still loads on Windows 10 (where Open fails).

Some drivers don't answer the "active" query: the Intel I219-LM and I350 tested
return ERROR_BAD_DRIVER (2001), although the I219-LM delivers hardware timestamps. Open then goes by
the supported capabilities, and ActiveQueryError() returns the error. Whether the timestamps really arrive is
then only known from use: the NIC clock must become Ready, every timestamp must fall within a
plausible latency of the software time, and the provider falls back to software if they don't.
*/
class CHardwareTimestamps : public ITimestampSource {
public:
  //SIO_GET_TX_TIMESTAMP gives up on a transmit timestamp after this long
  static const int TX_TIMEOUT_MS = 200;

private:
  typedef DWORD(WINAPI* TCapsFn)(const NET_LUID*, void*);
  typedef DWORD(WINAPI* TCrossFn)(const NET_LUID*, void*);

  TCapsFn _active_fn;
  TCapsFn _supported_fn;
  TCrossFn _cross_fn;
  SOCKET _socket;
  NET_LUID _luid;
  CNicClock _clock;
  int64_t _qpf;
  ULONGLONG _last_cross_tick;
  uint64_t _hw_hz;
  DWORD _active_error;

  void Refresh();
  uint64_t QpcToSystemTime(double Qpc, const STimePair& Pair) const;

public:
  CHardwareTimestamps();

  //Returns NOERROR, or an error with out_Reason saying why hardware timestamps cannot be used.
  DWORD Open(SOCKET Socket, DWORD IfIndex, const wchar_t*& out_Reason);

  //After a fallback to software, when the timestamps have come back: measure the NIC clock again,
  //on the socket Open succeeded on. Not Ready until that is done.
  void Restart();

  //frequency the adapter reports, and the frequency measured against QPC (0 until Ready)
  uint64_t ReportedHz() const { return _hw_hz; }
  double MeasuredHz() const { return _clock.MeasuredHz(); }

  //After a successful Open: the adapter didn't say which timestamping is active (the error it
  //returned), so the supported capabilities were used. 0 if it did.
  DWORD ActiveQueryError() const { return _active_error; }

  const wchar_t* Name() const override { return L"hardware"; }
  bool Ready() const override { return _clock.Ready(); }
  void Poll() override;
  bool RxTime(const STimePair& Wake, const WSAMSG& Msg, uint64_t& out_Time) override;
  ULONG TxControl(uint32_t Id, char* Buf, ULONG Size) override;
  ETxResult TxTime(uint32_t Id, const STimePair& Before, uint64_t& out_Time) override;
};

/*
After a fallback from hardware to software timestamps on a socket, whether hardware receive
timestamps have come back (an Intel I219-LM on Windows 11 stopped delivering them until the adapter
was restarted; they might also come back by themselves). The adapter is never touched.

It costs almost nothing: the socket still has timestamping on and the event loop reads each
message's control data anyway, so OnSync only looks at the value. A run of MIN_RUN Syncs in a row
with a timestamp, advancing at the NIC clock rate measured before the fallback (within
RATE_TOLERANCE, which tells NIC ticks from other units such as QPC), makes Due true, at most every
RECHECK_MS. If a return to hardware doesn't hold (another fallback), the interval doubles, up to
MAX_RECHECK_MS.

Times are GetTickCount64 milliseconds; QPC is the wake QPC of each Sync.
*/
class CHardwareRecheck {
public:
  static const ULONGLONG RECHECK_MS = 5 * 60 * 1000;
  static const ULONGLONG MAX_RECHECK_MS = 60 * 60 * 1000;
  static const int MIN_RUN = 8;
  static constexpr double RATE_TOLERANCE = 0.1;
  static constexpr double MIN_RUN_SPAN_S = 0.5;

private:
  double _nic_hz;       //measured before the fallback; 0: not watching
  int64_t _qpf;
  ULONGLONG _interval;
  ULONGLONG _next;      //tick from which Due can be true
  bool _returned;       //hardware was resumed since Start: a further fallback means it didn't hold
  int _run;
  uint64_t _first_ts;
  int64_t _first_qpc;
  bool _plausible;      //the run so far advances at the NIC clock rate

public:
  CHardwareRecheck();

  //a new socket: nothing to watch, and the interval starts again
  void Reset();

  //Hardware timestamps have just been dropped. NicHz: the NIC clock rate measured before (0 if it
  //never was: then there is nothing to check against and nothing is watched).
  void OnFallback(double NicHz, int64_t QpcFrequency, ULONGLONG Now);

  bool Watching() const { return _nic_hz > 0.0; }

  //every Sync received while on software timestamps: its socket timestamp (0 if none)
  void OnSync(uint64_t RxTimestamp, int64_t WakeQpc);

  //time to go back to hardware
  bool Due(ULONGLONG Now) const;

  //the caller has gone back to hardware: stop watching until the next fallback
  void OnReturn();

  ULONGLONG Interval() const { return _interval; }
};

/*
Winsock and IP Helper timestamping declarations (mstcpip.h, iphlpapi.h; Windows SDK 10.0.20348 and
later). The SDK declares them only for NTDDI_WIN10_FE (build 20348, Server 2022) and later, and the
projects target Windows 10 (WinTarget.h) so that the DLL still loads there, so these are private
copies. They are part of the Windows ABI.
*/
namespace WinsockTs {
  static const DWORD SIO_TIMESTAMPING_ = _WSAIOW(IOC_VENDOR, 235);
  static const DWORD SIO_GET_TX_TIMESTAMP_ = _WSAIOW(IOC_VENDOR, 234);
  static const int SO_TIMESTAMP_ = 0x300A;     //control message: receive timestamp, UINT64
  static const int SO_TIMESTAMP_ID_ = 0x300B;  //control message: transmit timestamp id, UINT32
  static const ULONG FLAG_RX = 0x1;
  static const ULONG FLAG_TX = 0x2;

  struct TIMESTAMPING_CONFIG_ {
    ULONG Flags;
    USHORT TxTimestampsBuffered;
  };

  //INTERFACE_TIMESTAMP_CAPABILITIES
  struct HardwareCaps {
    BOOLEAN PtpV2OverUdpIPv4EventMessageReceive;
    BOOLEAN PtpV2OverUdpIPv4AllMessageReceive;
    BOOLEAN PtpV2OverUdpIPv4EventMessageTransmit;
    BOOLEAN PtpV2OverUdpIPv4AllMessageTransmit;
    BOOLEAN PtpV2OverUdpIPv6EventMessageReceive;
    BOOLEAN PtpV2OverUdpIPv6AllMessageReceive;
    BOOLEAN PtpV2OverUdpIPv6EventMessageTransmit;
    BOOLEAN PtpV2OverUdpIPv6AllMessageTransmit;
    BOOLEAN AllReceive;
    BOOLEAN AllTransmit;
    BOOLEAN TaggedTransmit;
  };
  struct SoftwareCaps {
    BOOLEAN AllReceive;
    BOOLEAN AllTransmit;
    BOOLEAN TaggedTransmit;
  };
  struct InterfaceCaps {
    ULONG64 HardwareClockFrequencyHz;
    BOOLEAN SupportsCrossTimestamp;
    HardwareCaps Hardware;
    SoftwareCaps Software;
  };
  //INTERFACE_HARDWARE_CROSSTIMESTAMP
  struct CrossTimestamp {
    ULONG64 SystemTimestamp1;
    ULONG64 HardwareClockTimestamp;
    ULONG64 SystemTimestamp2;
  };

  //The SO_TIMESTAMP value attached to a received message, or 0 if there is none.
  //Server 2022 attaches the control message with the value 0 when no timestamping is active.
  uint64_t RxTimestamp(const WSAMSG& Msg);
}
