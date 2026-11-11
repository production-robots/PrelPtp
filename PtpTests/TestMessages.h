#pragma once

#include "..\PtpUtil\MessagePath.h"
#include "CppUnitTest.h"
#include <vector>
#include <string>

/*
Builders for PTP messages in network byte order, exactly as the socket delivers them.
*/

namespace Microsoft { namespace VisualStudio { namespace CppUnitTestFramework {
template<> inline std::wstring ToString<EBmcaResult>(const EBmcaResult& R) {
  switch (R) {
  case EBmcaResult::ABetter: return L"ABetter";
  case EBmcaResult::BBetter: return L"BBetter";
  case EBmcaResult::ABetterByTopology: return L"ABetterByTopology";
  case EBmcaResult::BBetterByTopology: return L"BBetterByTopology";
  case EBmcaResult::Error1: return L"Error1";
  case EBmcaResult::Error2: return L"Error2";
  }
  return L"?";
}
template<> inline std::wstring ToString<CBmca::EAnnounceResult>(const CBmca::EAnnounceResult& R) {
  return std::to_wstring((int)R);
}
template<> inline std::wstring ToString<CMessagePath::EResult>(const CMessagePath::EResult& R) {
  switch (R) {
  case CMessagePath::EResult::Ignored: return L"Ignored";
  case CMessagePath::EResult::WrongSource: return L"WrongSource";
  case CMessagePath::EResult::WrongDomain: return L"WrongDomain";
  case CMessagePath::EResult::NotSelected: return L"NotSelected";
  case CMessagePath::EResult::Accepted: return L"Accepted";
  }
  return L"?";
}
template<> inline std::wstring ToString<CRxDiagnosis::EReport>(const CRxDiagnosis::EReport& R) {
  switch (R) {
  case CRxDiagnosis::EReport::None: return L"None";
  case CRxDiagnosis::EReport::WrongDomain: return L"WrongDomain";
  case CRxDiagnosis::EReport::WrongSource: return L"WrongSource";
  case CRxDiagnosis::EReport::Resumed: return L"Resumed";
  }
  return L"?";
}
}}}
namespace PtpTests {

//builds a message in network byte order, as received from the socket
class WireBuilder {
  std::vector<uint8_t> _bytes;
public:
  WireBuilder& U8(uint8_t V) { _bytes.push_back(V); return *this; }
  WireBuilder& U16(uint16_t V) { U8((uint8_t)(V >> 8)); return U8((uint8_t)V); }
  WireBuilder& U32(uint32_t V) { U16((uint16_t)(V >> 16)); return U16((uint16_t)V); }
  WireBuilder& U64(uint64_t V) { U32((uint32_t)(V >> 32)); return U32((uint32_t)V); }
  WireBuilder& Bytes(const uint8_t* P, size_t N) { _bytes.insert(_bytes.end(), P, P + N); return *this; }
  WireBuilder& Timestamp48(uint64_t Seconds, uint32_t Ns) {
    U16((uint16_t)(Seconds >> 32));
    U32((uint32_t)Seconds);
    return U32(Ns);
  }
  //timestamp from PTP nanoseconds
  WireBuilder& TimestampNs(uint64_t Ns) {
    return Timestamp48(Ns / 1000000000ULL, (uint32_t)(Ns % 1000000000ULL));
  }

  //IEEE 1588-2008 table 18 common header
  WireBuilder& Header(uint8_t MessageType, uint16_t Length, uint8_t Domain, uint8_t Flags0, uint8_t Flags1,
                      int64_t Correction, const uint8_t ClockIdentity[8], uint16_t Port, uint16_t Sequence,
                      uint8_t LogMessageInterval = 0xFD) {
    U8(0x10 | MessageType);  //transportSpecific 1, messageType
    U8(0x02);                //versionPTP 2
    U16(Length);
    U8(Domain);
    U8(0);
    U8(Flags0);
    U8(Flags1);
    U64((uint64_t)Correction);
    U32(0);
    Bytes(ClockIdentity, 8);
    U16(Port);
    U16(Sequence);
    U8(0);                   //controlField
    return U8(LogMessageInterval);
  }

  PtpMessage Message() const {
    PtpMessage m;
    ZeroMemory(&m, sizeof(m));
    Assert(_bytes.size() <= sizeof(m));
    CopyMemory(&m, _bytes.data(), _bytes.size());
    return m;
  }
  size_t Size() const { return _bytes.size(); }
  const std::vector<uint8_t>& Data() const { return _bytes; }

private:
  static void Assert(bool Condition) {
    Microsoft::VisualStudio::CppUnitTestFramework::Assert::IsTrue(Condition);
  }
};

//a clock identity written as a number, first octet most significant, as it would be printed
inline void IdOctets(uint64_t Id, uint8_t out_Octets[8]) {
  for (int i = 0; i < 8; ++i)
    out_Octets[i] = (uint8_t)(Id >> (56 - 8 * i));
}

//the same clock identity as it is held in memory by the provider (wire byte order)
inline TClockIdentity WireId(uint64_t Id) {
  return _byteswap_uint64(Id);
}

inline PortIdentity Pid(uint64_t Id, uint16_t Port) {
  PortIdentity p;
  p.clockIdentity = WireId(Id);
  p.portNumber = Port;
  return p;
}

inline DWORD Ip(uint8_t A, uint8_t B, uint8_t C, uint8_t D) {
  return (DWORD)A | ((DWORD)B << 8) | ((DWORD)C << 16) | ((DWORD)D << 24);  //network byte order
}

//a received message: bytes as from the socket, and how many
struct Received {
  PtpMessage Msg;
  int Size;
};

inline Received FromWire(const WireBuilder& W) {
  return Received{ W.Message(), (int)W.Size() };
}

//a PTP master port, for building the messages it sends
struct TestMaster {
  uint64_t Id;                  //clock identity of the port that sends (sourcePortIdentity)
  uint16_t Port = 1;
  DWORD Address = 0;
  uint8_t Domain = 0;
  uint8_t LogAnnounceInterval = 0;  //1 s

  //grandmaster described by the Announce messages. Gm 0 means "this clock is the grandmaster".
  uint64_t Gm = 0;
  uint8_t Priority1 = 128;
  uint8_t ClockClass = 6;
  uint8_t ClockAccuracy = 0x21;
  uint16_t Variance = 0x4E5D;
  uint8_t Priority2 = 128;
  uint16_t StepsRemoved = 0;
  bool AlternateMaster = false;

  uint16_t AnnounceSequence = 0;

  TestMaster(uint64_t AId, DWORD AAddress) : Id(AId), Address(AAddress) {}

  PortIdentity Identity() const { return Pid(Id, Port); }

  //the next Announce (sequence number increments each call)
  Received Announce() {
    uint8_t id[8], gm[8];
    IdOctets(Id, id);
    IdOctets(Gm ? Gm : Id, gm);
    WireBuilder w;
    w.Header(0xB, 64, Domain, AlternateMaster ? 0x01 : 0x00, 0x08, 0, id, Port, AnnounceSequence++, LogAnnounceInterval)
      .Timestamp48(0, 0)
      .U16(37)               //currentUtcOffset
      .U8(0)
      .U8(Priority1)
      .U8(ClockClass).U8(ClockAccuracy).U16(Variance)
      .U8(Priority2)
      .Bytes(gm, 8)
      .U16(StepsRemoved)
      .U8(0x20);             //timeSource GPS
    return FromWire(w);
  }

  Received Sync(uint16_t Sequence, bool TwoStep, uint64_t OriginNs = 0) const {
    uint8_t id[8];
    IdOctets(Id, id);
    WireBuilder w;
    w.Header(0x0, 44, Domain, TwoStep ? 0x02 : 0x00, 0x08, 0, id, Port, Sequence, 0).TimestampNs(OriginNs);
    return FromWire(w);
  }

  Received FollowUp(uint16_t Sequence, uint64_t OriginNs) const {
    uint8_t id[8];
    IdOctets(Id, id);
    WireBuilder w;
    w.Header(0x8, 44, Domain, 0x00, 0x08, 0, id, Port, Sequence, 0).TimestampNs(OriginNs);
    return FromWire(w);
  }

  //Requester: the requesting port identity as the provider holds it (clock identity in wire order)
  Received DelayResp(uint16_t Sequence, uint64_t ReceiveNs, const PortIdentity& Requester) const {
    uint8_t id[8];
    IdOctets(Id, id);
    WireBuilder w;
    w.Header(0x9, 54, Domain, 0x00, 0x08, 0, id, Port, Sequence, 0)
      .TimestampNs(ReceiveNs)
      .Bytes((const uint8_t*)&Requester.clockIdentity, 8)
      .U16(Requester.portNumber);
    return FromWire(w);
  }
};

}
