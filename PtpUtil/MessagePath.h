#pragma once

#include "Util.h"
#include "Ptp.h"
#include "SyncRequest.h"
#include "Bmca.h"

/*
Decides what to do with each PTP message received, and passes it on. Both message loops
(event port 319 and general port 320) call Handle with the bytes as received.

Which master is used
- Pinned (GrandmasterAddress set): only messages from that IPv4 address are used, as in
  earlier versions. Announce messages from it still go to the BMCA, so the grandmaster can be
  reported, but the BMCA does not filter anything.
- Automatic (GrandmasterAddress 0): Announce messages from every master go to the BMCA.
  Sync, Follow_Up and Delay_Resp are used only from the master it selects. When the selected
  master changes, the Sync/Delay_Req state is reset and the caller is told, so it can reset
  its filter.

Result tells the caller two things:
- anything but Ignored is PTP traffic from the network, so the socket is working;
- WrongSource and WrongDomain are traffic the configuration excludes. If that is all that arrives,
  CRxDiagnosis says so, so the user is not left guessing why there are no samples.

Thread safety: Configure must be called before the message loops start. Handle and Tick can
then be called from both loops at once; SSyncRequest and CBmca do their own locking.
*/
class CMessagePath {
public:
  enum class EResult {
    Ignored,      //not a PTP message from the network: too short, or our own Delay_Req looped back
    WrongSource,  //from an address other than the pinned master (GrandmasterAddress)
    WrongDomain,  //in a domain other than the configured one
    NotSelected,  //Sync, Follow_Up or Delay_Resp from a master the BMCA has not selected
    Accepted      //from an acceptable source (it may still have been of no use, e.g. an unmatched Follow_Up)
  };

  struct SOutcome {
    EResult Result;
    EMessageType Type;    //valid unless the message was too short
    uint8_t Domain;
    bool HaveOffset;      //Offset is a new sample (ns, master - local)
    int64_t Offset;
    bool MasterChanged;   //the BMCA's selected master changed while handling this message
  };

private:
  SSyncRequest& _sync;
  CBmca& _bmca;
  DWORD _pinned_address;
  DWORD _domain;
  bool _disable_delay_request;

  void OnMasterChanged(SOutcome& out_Outcome);

public:
  CMessagePath(SSyncRequest& Sync, CBmca& Bmca);

  //PinnedAddress: IPv4 network byte order, 0 for automatic selection.
  //DomainNumber: 0-255 or PTP_DOMAIN_ANY.
  void Configure(DWORD PinnedAddress, DWORD DomainNumber, bool DisableDelayRequest);

  bool Pinned() const { return _pinned_address != 0; }

  //Message holds Size bytes as received (network byte order); it is byte swapped in place.
  //FromAddress: sender IPv4 address, network byte order. RxSystemTime: receive time, ns100 since 1601.
  SOutcome Handle(PtpMessage& Message, int Size, DWORD FromAddress, uint64_t RxSystemTime);

  //call when no message has arrived for a while: expires masters whose Announce messages have
  //stopped. Returns true if the selected master changed.
  bool Tick();
};

/*
Notices when PTP messages arrive but none of them can be used, because they are all in another
domain or all from addresses other than the pinned master, and says so once.

Every outcome from CMessagePath::Handle is passed to OnOutcome (from either message loop).
Check is called regularly (from one loop) and returns a report when the state changes:
  WrongDomain  nothing usable for UNUSABLE_AFTER_MS, but messages in other domains
  WrongSource  nothing usable for UNUSABLE_AFTER_MS, but messages from other addresses
  Resumed      usable messages again after one of the above was reported
With no PTP traffic at all nothing is reported here: the message loops report silence.
*/
class CRxDiagnosis {
public:
  static const ULONGLONG UNUSABLE_AFTER_MS = 10000;

  using TTickSource = ULONGLONG(WINAPI*)();

  enum class EReport { None, WrongDomain, WrongSource, Resumed };

  struct SDetail {
    bool Domains[256];      //WrongDomain: domains seen in the last UNUSABLE_AFTER_MS
    DWORD OtherAddress;     //WrongSource: the most recent other sender, network byte order
  };

private:
  enum class EState { Ok, WrongDomain, WrongSource };

  mutable TSRWLock _lock;
  TTickSource _tick;
  EState _state;
  ULONGLONG _last_usable;
  ULONGLONG _last_domain_seen[256];   //0 = never
  ULONGLONG _last_wrong_source;
  DWORD _wrong_source_address;

public:
  CRxDiagnosis();

  //GetTickCount64 by default. Unit tests replace it to control time.
  void SetTickSource(TTickSource Tick);

  //forgets everything; the next UNUSABLE_AFTER_MS is a grace period
  void Reset();

  void OnOutcome(const CMessagePath::SOutcome& Outcome, DWORD FromAddress);

  //out_Detail is filled in for WrongDomain and WrongSource
  EReport Check(SDetail& out_Detail);
};