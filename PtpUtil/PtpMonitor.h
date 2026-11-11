#pragma once

#include "Util.h"
#include "Ptp.h"
#include "Bmca.h"

/*
PTP traffic on each network adapter, for the setup program's adapter list.

CPtpSurvey   what has been heard: for each adapter, the domains in which Announce messages
             arrive and the best master in each (chosen by CBmca, exactly as the provider would).
             Pure logic with an injectable tick source, so it can be unit tested.
CPtpMonitor  a background thread that listens passively on port 320 (224.0.1.129) on each
             adapter's IPv4 address and feeds a CPtpSurvey. It never sends anything. It uses
             SO_REUSEADDR, so it works alongside a running w32time.

Adapters are identified by the caller's index (0 .. MAX_ADAPTERS-1).
*/
class CPtpSurvey {
public:
  static const int MAX_ADAPTERS = 32;
  static const int MAX_DOMAINS = 8;     //per adapter
  static const int MAX_SLOTS = 64;      //adapter and domain pairs, in total

  using TTickSource = ULONGLONG(WINAPI*)();

  struct SDomain {
    uint8_t Domain;
    bool HaveMaster;                    //a master has qualified (2 Announces)
    CBmca::SForeignMaster Master;       //valid if HaveMaster
  };

  struct SSummary {
    int DomainCount;                    //domains with Announce messages, lowest first
    SDomain Domains[MAX_DOMAINS];
  };

private:
  struct SSlot {
    bool Used;
    int Adapter;
    uint8_t Domain;
    CBmca Bmca;
  };

  mutable TSRWLock _lock;
  TTickSource _tick;
  SSlot* _slots;                        //MAX_SLOTS, on the heap: CBmca is large
  SSummary* _reported;                  //MAX_ADAPTERS: the summary as last reported, to detect changes

  void SummariseLocked(int Adapter, SSummary& out_Summary) const;
  //updates _reported; true if it changed
  bool UpdateLocked(int Adapter);

public:
  CPtpSurvey();
  ~CPtpSurvey();
  CPtpSurvey(const CPtpSurvey&) = delete;
  CPtpSurvey& operator=(const CPtpSurvey&) = delete;

  //GetTickCount64 by default
  void SetTickSource(TTickSource Tick);

  //Bytes: a message as received on port 320 (network byte order). Only Announce messages count.
  //Returns true if what is known about the adapter changed.
  bool OnMessage(int Adapter, const void* Bytes, int Size, DWORD FromAddress);

  //expires masters whose Announce messages have stopped. Returns true if anything changed.
  bool Tick();

  void GetSummary(int Adapter, SSummary& out_Summary) const;

  //true if Announce messages from Address (network byte order) are being heard on the adapter,
  //in any domain, whether or not that master is the best one
  bool HeardFrom(int Adapter, DWORD Address) const;

  //the adapter whose best master is best by the BMCA comparison, or -1 if no adapter has a master.
  //This is the adapter the provider would do best on.
  int BestAdapter() const;
};

class CPtpMonitor {
public:
  static const DWORD TICK_MS = 500;
  //until then an adapter with nothing heard is "checking" rather than "none". Covers masters
  //that announce every 2 s (logAnnounceInterval 1); slower ones appear when they are heard.
  static const ULONGLONG CHECKING_MS = 3000;

private:
  CPtpSurvey _survey;
  HANDLE _thread;
  volatile LONG _stop;
  HWND _notify;
  UINT _message;
  int _count;
  DWORD _addresses[CPtpSurvey::MAX_ADAPTERS];
  bool _listening[CPtpSurvey::MAX_ADAPTERS];
  ULONGLONG _started;
  bool _wsa;

  void Run();
  static DWORD WINAPI GThread(LPVOID This) {
    ((CPtpMonitor*)This)->Run();
    return 0;
  }

public:
  CPtpMonitor();
  ~CPtpMonitor();
  CPtpMonitor(const CPtpMonitor&) = delete;
  CPtpMonitor& operator=(const CPtpMonitor&) = delete;

  //Addresses[i]: IPv4 address of adapter i (network byte order), 0 to skip it.
  //Message is posted to Notify (wParam 0, lParam 0) whenever the survey changes.
  bool Start(HWND Notify, UINT Message, const DWORD* Addresses, int Count);
  void Stop();

  const CPtpSurvey& Survey() const { return _survey; }

  //a socket could be opened for this adapter
  bool Listening(int Adapter) const;

  //true for CHECKING_MS after Start: say "checking" rather than "none"
  bool Checking() const;
};
