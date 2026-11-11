#pragma once

#include "Util.h"
#include "Ptp.h"

/*
Best master clock algorithm (BMCA), IEEE 1588-2008 clause 9.3 (unchanged in 1588-2019).

The provider is a slave-only ordinary clock with one port, so the state decision algorithm
(9.3.3) reduces to: follow the best qualified foreign master (Erbest), or no master if there
is none. This file implements:

  BmcaCompare   the data set comparison algorithm, 9.3.4, figures 27 and 28
  CBmca         the foreign master data set and Announce qualification (9.3.2.4, 9.3.2.5),
                the announce receipt timeout, and selection of Erbest

Conventions
- Clock identities are kept as they are on the wire: the 8 octets copied into a uint64_t.
  They are compared as unsigned octet strings, first octet most significant.
- Port numbers are in host byte order (after _ByteSwap).
- Lower values are better for every field.

Not implemented
- The optional acceptable master table. Pin a master with GrandmasterAddress instead.
- The optional alternate master feature: Announce messages with alternateMasterFlag set are ignored.
*/

//the fields used by the data set comparison (9.3.4)
struct SBmcaDataset {
  uint8_t Priority1;
  uint8_t ClockClass;
  uint8_t ClockAccuracy;
  uint16_t OffsetScaledLogVariance;
  uint8_t Priority2;
  TClockIdentity GrandmasterIdentity;   //wire byte order
  uint16_t StepsRemoved;
  PortIdentity Sender;                  //sourcePortIdentity of the Announce
  PortIdentity Receiver;                //the port that received it (this provider)
};

enum class EBmcaResult {
  ABetter,
  BBetter,
  ABetterByTopology,
  BBetterByTopology,
  Error1,   //a message received from the receiving port itself
  Error2    //A and B came from the same port: duplicates
};

//compares two clock identities as octet strings: <0, 0, >0
int CompareClockIdentity(TClockIdentity A, TClockIdentity B);

//"0C42A1.FFFE.800A54"
void FormatClockIdentity(TClockIdentity Identity, wchar_t* Buf, size_t Chars);

//compares two port identities: clock identity, then port number
int ComparePortIdentity(const PortIdentity& A, const PortIdentity& B);

//IEEE 1588-2008 9.3.4, figures 27 and 28
EBmcaResult BmcaCompare(const SBmcaDataset& A, const SBmcaDataset& B);

//announce interval from an Announce header's logMessageInterval, in ms. Clamped to 2^-4 .. 2^4 s.
ULONGLONG AnnounceIntervalMs(uint8_t LogMessageInterval);

class CBmca {
public:
  static const int FOREIGN_MASTER_THRESHOLD = 2;       //9.3.2.4
  static const int FOREIGN_MASTER_TIME_WINDOW = 4;     //announce intervals, 9.3.2.4
  static const int ANNOUNCE_RECEIPT_TIMEOUT = 3;       //announce intervals: the default profiles' default (Annex J)
  static const int MAX_FOREIGN_MASTERS = 16;           //the standard requires room for at least 5

  using TTickSource = ULONGLONG(WINAPI*)();

  struct SForeignMaster {
    SBmcaDataset Dataset;
    uint8_t Domain;
    DWORD Address;            //IPv4, network byte order
    uint8_t TimeSource;
    uint16_t LastSequenceId;
    ULONGLONG IntervalMs;     //from the most recent Announce
    ULONGLONG LastTick;       //receipt time of the most recent Announce
    ULONGLONG PreviousTick;   //receipt time of the one before it
    int Count;                //distinct Announce messages received, capped at FOREIGN_MASTER_THRESHOLD
  };

  enum class EAnnounceResult {
    Used,             //added to or updated the foreign master data set
    IgnoredOwn,       //sent by this clock (9.3.2.5)
    IgnoredDomain,    //different domain from the configured one
    IgnoredSteps,     //stepsRemoved 255 or more (9.3.2.5)
    IgnoredAlternate, //alternateMasterFlag set
    IgnoredDuplicate, //same sequenceId as the previous Announce from that port
    IgnoredFull       //foreign master data set is full
  };

private:
  mutable TSRWLock _lock;
  TTickSource _tick;
  DWORD _domain;              //configured domain or PTP_DOMAIN_ANY
  PortIdentity _local;        //this port, to recognise our own messages and for the topology comparison
  SForeignMaster _masters[MAX_FOREIGN_MASTERS];
  int _count;
  //the selected master (Erbest), by key. Entries move within _masters when others are removed.
  bool _have_selected;
  PortIdentity _selected_port;
  uint8_t _selected_domain;

  bool IsQualified(const SForeignMaster& M, ULONGLONG Now) const;
  void ExpireLocked(ULONGLONG Now);
  void RemoveLocked(int Index);
  int FindLocked(const PortIdentity& Port, uint8_t Domain) const;
  //re-runs the selection. Returns true if the selected master changed.
  bool SelectLocked(ULONGLONG Now);

public:
  //GetTickCount64 by default. Unit tests replace it to control time.
  void SetTickSource(TTickSource Tick);

  //only Announce messages in this domain are considered (PTP_DOMAIN_ANY: all domains)
  void SetDomain(DWORD Domain);

  //this provider's port identity (clock identity in wire order, port number in host order)
  void SetLocalPort(const PortIdentity& Port);

  //forgets all foreign masters
  void Reset();

  //Header and Announce in host byte order (after _ByteSwap). Address is the sender's IPv4 address.
  //out_Changed (optional) is set to true if the selected master changed.
  EAnnounceResult OnAnnounce(const CommonMsgHeader& Header, const AnnounceMessage& Announce, DWORD Address, bool* out_Changed = nullptr);

  //removes foreign masters whose Announce messages have timed out. Returns true if the selected master changed.
  bool OnTick();

  //the selected master (Erbest), if there is one
  bool GetSelected(SForeignMaster& out_Master) const;

  //true if Port in Domain is the selected master
  bool IsSelected(const PortIdentity& Port, uint8_t Domain) const;

  //number of entries in the foreign master data set (qualified or not)
  int ForeignMasterCount() const;

  //true if any entry in the foreign master data set (qualified or not) was sent from Address
  bool HasForeignMasterAt(DWORD Address) const;

  CBmca();
};
