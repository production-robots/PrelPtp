#pragma once

#include "WinTarget.h"
#include <intrin.h>


static const DWORD PTP_IP_ADDRESS = (DWORD)((224 << 24) | (1 << 8) | 129);
static const WORD PTP_GENERAL_PORT = 320;
static const WORD PTP_EVENT_PORT = 319;

inline void ByteSwap(uint16_t& V) {
  V = _byteswap_ushort(V);
}

inline void ByteSwap(int16_t& V) {
  V = (int16_t)_byteswap_ushort((uint16_t)V);
}


inline void ByteSwap(uint32_t& V) {
  V = _byteswap_ulong(V);
}

inline void ByteSwap(uint64_t& V) {
  V = _byteswap_uint64(V);
}

inline void ByteSwap(int64_t& V) {
  V = (int64_t)_byteswap_uint64((uint64_t)V);
}


//for compile time only enumerations
constexpr uint16_t BYTE_SWAP_U16(uint16_t V) {
  return ((V & 0xFF00) >> 8) | ((V & 0x00FF) << 8);
}

constexpr uint32_t BYTE_SWAP_U32(uint32_t V) {
  return ((V & 0xFF000000) >> 24) | ((V & 0x00FF0000) >> 8) | ((V & 0x0000FF00) << 8) | ((V & 0x000000FF) << 24);
}

#define MAX_PTP_PACKET_SIZE 384

#define PTP_PRESENT 0x002
#define V2_ANNOUNCE_MESSAGE 0xB
#define V2_ANNOUNCE_LENGTH 64
#define V2_MESSAGE_TYPE 2


#pragma pack(push, 1)

struct TimeInterval {
  int64_t scaledNanoseconds;
  void _ByteSwap() {
    ByteSwap(scaledNanoseconds);
  }
  //TimeInterval() : scaledNanoseconds(0) {}
};


//IEEE 1588 timestamp: 48-bit seconds (sent as a 16-bit high part then a 32-bit low part)
//followed by 32-bit nanoseconds. secondsHigh is zero until 2106.
//Nanoseconds() fits in 64 bits until about 2554.
struct Timestamp {
  uint16_t secondsHigh;
  uint32_t secondsField;
  uint32_t  nanosecondsField;
  uint64_t Nanoseconds() const {
    uint64_t seconds = ((uint64_t)secondsHigh << 32) | secondsField;
    return seconds * 1000000000ULL + nanosecondsField;
  }
  void _ByteSwap() {
    ByteSwap(secondsHigh);
    ByteSwap(secondsField);
    ByteSwap(nanosecondsField);
  }
};

using TClockIdentity = uint64_t;

//IEEE 1588-2008 7.5.2.2.2: clock identity from a 48-bit MAC address (EUI-48 to EUI-64),
//MAC octets 0-2, FF, FE, MAC octets 3-5. Returned in wire byte order, as TClockIdentity is held.
inline TClockIdentity ClockIdentityFromMac(const uint8_t Mac[6]) {
  const uint8_t octets[8] = { Mac[0], Mac[1], Mac[2], 0xFF, 0xFE, Mac[3], Mac[4], Mac[5] };
  TClockIdentity id;
  memcpy(&id, octets, sizeof(id));
  return id;
}

struct PortIdentity {
  TClockIdentity clockIdentity;
  uint16_t portNumber;
  void _ByteSwap() {
    ByteSwap(portNumber);
  }
  bool operator==(const PortIdentity& Other) const {
    return (clockIdentity == Other.clockIdentity) && (portNumber == Other.portNumber);
  }
  bool operator!=(const PortIdentity& Other) const {
    return !(*this == Other);
  }
};

enum class ENetworkProtocol : uint16_t {
  Reserved1 = BYTE_SWAP_U16(0x0000),
  UDPv4 = BYTE_SWAP_U16(0x0001),
  UDPv6 = BYTE_SWAP_U16(0x0002),
  IEEE_802_3 = BYTE_SWAP_U16(0x0003),
  DeviceNet = BYTE_SWAP_U16(0x0004),
  ControlNet = BYTE_SWAP_U16(0x0005),
  Profinet = BYTE_SWAP_U16(0x0006),
  Unknown = BYTE_SWAP_U16(0xFFFE),
  Reserved2 = BYTE_SWAP_U16(0xFFFF)
};

//note will need a "manual" byte swap on input
//but is initialised in wire format for output
template<int ADDR_LENGTH>
struct PortAddress {
  ENetworkProtocol networkProtocol;
  uint16_t addressLength;
  uint8_t addressField[ADDR_LENGTH];
  void _ByteSwap() {
    ByteSwap(addressLength);
  }
};

struct ClockQuality {
  uint8_t clockClass;
  uint8_t clockAccuracy;
  uint16_t offsetScaledLogVariance;
  void _ByteSwap() {
    ByteSwap(offsetScaledLogVariance);
  }
};

//dynamic &&&
struct TLV {
  uint16_t tlvType;
  uint16_t lengthField;
  uint8_t* valueField;
  void _ByteSwap() {
    ByteSwap(tlvType);
    ByteSwap(lengthField);
  }
  TLV& operator=(const TLV&) = delete;
  TLV(const TLV&) = delete;
  TLV() : tlvType(0), lengthField(0), valueField(nullptr) {}
  TLV(uint16_t AtlvType, uint16_t AlengthField) : tlvType(AtlvType), lengthField(AlengthField), valueField(AlengthField ? new uint8_t[AlengthField] : nullptr) {}
  ~TLV() {
    delete[] valueField;
  }
};

//dynamic &&& 
struct PTPText {
  uint8_t lengthField;
  char* textField;
  void _ByteSwap() {}
  uint16_t Length() const { return lengthField + sizeof(lengthField); }
  PTPText& operator=(const PTPText&) = delete;
  PTPText(const PTPText&) = delete;
  PTPText(uint8_t AlengthField) : lengthField(AlengthField), textField(AlengthField ? new char[AlengthField] : nullptr) {}
  PTPText() : lengthField(0), textField(nullptr) {}
  ~PTPText() {
    delete[] textField;
  }
};

//dynamic &&& 
struct FaultRecord {
  uint16_t faultRecordLength;
  Timestamp faultTime;
  int8_t severityCode;
  PTPText faultName;
  PTPText faultValue;
  PTPText faultDescription;
  void _ByteSwap() {
    ByteSwap(faultRecordLength);
  }
};

enum class EMessageType: uint8_t {
  Sync = 0x0,
  Delay_Req = 0x1,
  Pdelay_Req = 0x2,
  Pdelay_Resp = 0x3,
  Follow_Up = 0x8,
  Delay_Resp = 0x9,
  Pdelay_Resp_Follow_Up = 0xA,
  Announce = 0xB,
  Signalling = 0xC,
  Management = 0xD
};

//deprecated
enum class EControlField : uint8_t {
  Sync = 0x00,
  Delay_Req = 0x01,
  Follow_Up = 0x02,
  Delay_Resp = 0x03,
  Management = 0x04,
  Others = 0x5
};

static const int64_t CORRECTION_TOO_BIG = (int64_t)(0x7FFFFFFFFFFFFFFFULL);

struct CommonMsgHeader {
  // Offset  Length (bytes)
  EMessageType messageType : 4;
  uint8_t transportSpecific : 4;
  uint8_t versionPTP : 4;
  uint8_t Reserved1 : 4;
  uint16_t messageLength;
  uint8_t domainNumber;
  uint8_t Reserved2;
  bool alternateMasterFlag : 1;  //bit0 byte 0
  bool twoStepFlag : 1;
  bool unicastFlag : 1;
  uint8_t Reserved3 : 2;
  bool PTPProfileSpecific1 : 1;
  bool PTPProfileSpecific2 : 1;
  bool Reserved4 : 1;            //bit7 byte 0
  bool leap61 : 1;               //bit0 byte 1
  bool leap59 : 1;
  bool currentUtcOffsetValid : 1;
  bool ptpTimescale : 1;
  bool timeTraceable : 1;
  bool frequencyTraceable : 1;
  uint8_t Reserved5 : 2;           //bit0 byte 1
  int64_t correctionField;
  uint32_t Reserved6;
  PortIdentity sourcePortIdentity;
  uint16_t sequenceId;
  EControlField controlField;
  uint8_t logMessageInterval;
  void _ByteSwap() {
    ByteSwap(messageLength);
    ByteSwap(correctionField);
    sourcePortIdentity._ByteSwap();
    ByteSwap(sequenceId);
  }
};

struct AnnounceMessage {
  // Offset  Length (bytes)
  Timestamp originTimestamp;
  int16_t currentUTCOffset;
  uint8_t Reserved;
  uint8_t grandmasterPriority1;
  ClockQuality grandmasterClockQuality;
  uint8_t grandmasterPriority2;
  char grandmasterIdentity[8];
  uint16_t stepsRemoved;
  uint8_t timeSource;
  void _ByteSwap() {
    originTimestamp._ByteSwap();
    ByteSwap(currentUTCOffset);
    grandmasterClockQuality._ByteSwap();
    ByteSwap(stepsRemoved);
  }
};


struct SyncMessage {
  Timestamp originTimestamp;
  void _ByteSwap() {
    originTimestamp._ByteSwap();
  }
};

using Delay_ReqMessage = SyncMessage;

using Follow_UpMessage = SyncMessage;

struct Delay_RespMessage {
  Timestamp receiveTimestamp;
  PortIdentity requestingPortIdentity;
  void _ByteSwap() {
    receiveTimestamp._ByteSwap();
    requestingPortIdentity._ByteSwap();
  }
};

struct Pdelay_RespMessage {
  Timestamp originTimestamp;
  uint8_t Reserved[10];
  void _ByteSwap() {
    originTimestamp._ByteSwap();
  }
};

struct Pdelay_Resp_Follow_UpMessage {
  Timestamp responseOriginTimestamp;
  PortIdentity requestingPortIdentity;
  void _ByteSwap() {
    responseOriginTimestamp._ByteSwap();
    requestingPortIdentity._ByteSwap();
  }
};


struct PtpMessage {
  CommonMsgHeader Header;
  union _message {
    AnnounceMessage Announce;
    SyncMessage Sync;
    Delay_ReqMessage Delay_Req;
    Follow_UpMessage Follow_Up;
    Delay_RespMessage Delay_Resp;
    Pdelay_RespMessage Pdelay_Resp;
    Pdelay_Resp_Follow_UpMessage Pdelay_Resp_Follow_Up;
  } Message;
  uint32_t Size() const;
};

#pragma pack(pop)

typedef uint64_t ptp_timestamp;        //ns100 relative to 2059 epoch with "historical leap seconds"
typedef uint64_t system_time;          //ns100 relative to nt system epoch

//map system time to Ptp. Account for epoch offset and leap seconds not included in system timeline
ptp_timestamp SystemTimeToPtp(system_time SystemTime);
system_time PtpToSystemTime(ptp_timestamp SystemTime);

