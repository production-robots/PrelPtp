#include "..\PtpUtil\Ptp.h"
#include "..\PtpUtil\Util.h"
#include "CppUnitTest.h"

#include "TestMessages.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace PtpTests {

static const uint8_t CLOCK_ID[8] = { 0x00, 0x20, 0xFC, 0xFF, 0xFE, 0x12, 0x34, 0x56 };

TEST_CLASS(PtpMessageLayout) {
public:
  TEST_METHOD(WireSizes) {
    Assert::AreEqual((size_t)34, sizeof(CommonMsgHeader));
    Assert::AreEqual((size_t)10, sizeof(Timestamp));
    Assert::AreEqual((size_t)10, sizeof(PortIdentity));
    Assert::AreEqual((size_t)30, sizeof(AnnounceMessage));
    Assert::AreEqual((size_t)20, sizeof(Delay_RespMessage));
  }

  TEST_METHOD(SizeByMessageType) {
    PtpMessage m;
    ZeroMemory(&m, sizeof(m));
    m.Header.messageType = EMessageType::Sync;
    Assert::AreEqual(44u, m.Size());
    m.Header.messageType = EMessageType::Delay_Req;
    Assert::AreEqual(44u, m.Size());
    m.Header.messageType = EMessageType::Follow_Up;
    Assert::AreEqual(44u, m.Size());
    m.Header.messageType = EMessageType::Delay_Resp;
    Assert::AreEqual(54u, m.Size());
    m.Header.messageType = EMessageType::Announce;
    Assert::AreEqual((uint32_t)V2_ANNOUNCE_LENGTH, m.Size());
  }

  TEST_METHOD(ByteSwapHelpers) {
    uint16_t u16 = 0x1234; ByteSwap(u16);
    Assert::AreEqual((uint16_t)0x3412, u16);
    int16_t i16 = -2; ByteSwap(i16);
    Assert::AreEqual((int16_t)0xFEFF, i16);
    uint32_t u32 = 0x11223344; ByteSwap(u32);
    Assert::AreEqual(0x44332211u, u32);
    int64_t i64 = 0x0102030405060708LL; ByteSwap(i64);
    Assert::AreEqual(0x0807060504030201LL, i64);
  }

  TEST_METHOD(CompileTimeByteSwap) {
    static_assert(BYTE_SWAP_U16(0x1234) == 0x3412, "BYTE_SWAP_U16");
    static_assert(BYTE_SWAP_U32(0x11223344) == 0x44332211, "BYTE_SWAP_U32");
    Assert::AreEqual(0x44332211u, BYTE_SWAP_U32(0x11223344));
  }
};

TEST_CLASS(PtpMessageParsing) {
public:
  TEST_METHOD(HeaderFields) {
    WireBuilder w;
    w.Header(0x8, 44, 3, 0x02, 0x08, 0x0000000012345678LL, CLOCK_ID, 1, 0xABCD).Timestamp48(1700000037, 123456789);
    PtpMessage m = w.Message();
    m.Header._ByteSwap();

    Assert::IsTrue(m.Header.messageType == EMessageType::Follow_Up);
    Assert::AreEqual((uint8_t)1, m.Header.transportSpecific);
    Assert::AreEqual((uint8_t)2, m.Header.versionPTP);
    Assert::AreEqual((uint16_t)44, m.Header.messageLength);
    Assert::AreEqual((uint8_t)3, m.Header.domainNumber);
    Assert::IsTrue(m.Header.twoStepFlag);
    Assert::IsFalse(m.Header.unicastFlag);
    Assert::IsTrue(m.Header.ptpTimescale);
    Assert::IsFalse(m.Header.leap61);
    Assert::AreEqual(0x12345678LL, m.Header.correctionField);
    Assert::AreEqual((uint16_t)1, m.Header.sourcePortIdentity.portNumber);
    Assert::AreEqual(0, memcmp(&m.Header.sourcePortIdentity.clockIdentity, CLOCK_ID, 8));
    Assert::AreEqual((uint16_t)0xABCD, m.Header.sequenceId);
  }

  TEST_METHOD(OneStepFlagIsClear) {
    WireBuilder w;
    w.Header(0x0, 44, 0, 0x00, 0x00, 0, CLOCK_ID, 1, 1).Timestamp48(0, 0);
    PtpMessage m = w.Message();
    m.Header._ByteSwap();
    Assert::IsTrue(m.Header.messageType == EMessageType::Sync);
    Assert::IsFalse(m.Header.twoStepFlag);
  }

  TEST_METHOD(NegativeCorrection) {
    WireBuilder w;
    w.Header(0x0, 44, 0, 0, 0, -65536LL, CLOCK_ID, 1, 1).Timestamp48(0, 0);
    PtpMessage m = w.Message();
    m.Header._ByteSwap();
    Assert::AreEqual(-65536LL, m.Header.correctionField);
  }

  TEST_METHOD(OriginTimestamp) {
    WireBuilder w;
    w.Header(0x8, 44, 0, 0x02, 0, 0, CLOCK_ID, 1, 7).Timestamp48(1700000037, 123456789);
    PtpMessage m = w.Message();
    m.Header._ByteSwap();
    m.Message.Follow_Up._ByteSwap();
    Assert::AreEqual(1700000037ULL * 1000000000ULL + 123456789ULL, m.Message.Follow_Up.originTimestamp.Nanoseconds());
  }

  TEST_METHOD(TimestampUsesSecondsHigh) {
    //seconds beyond 32 bits (after 2106)
    WireBuilder w;
    w.Header(0x8, 44, 0, 0x02, 0, 0, CLOCK_ID, 1, 7).Timestamp48(0x100000005ULL, 6);
    PtpMessage m = w.Message();
    m.Header._ByteSwap();
    m.Message.Follow_Up._ByteSwap();
    Assert::AreEqual((uint16_t)1, m.Message.Follow_Up.originTimestamp.secondsHigh);
    Assert::AreEqual(0x100000005ULL * 1000000000ULL + 6ULL, m.Message.Follow_Up.originTimestamp.Nanoseconds());
  }

  TEST_METHOD(DelayResponse) {
    const uint8_t requester[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    WireBuilder w;
    w.Header(0x9, 54, 0, 0, 0, 0, CLOCK_ID, 1, 0x0102).Timestamp48(1700000037, 999999999).Bytes(requester, 8).U16(0x0203);
    Assert::AreEqual((size_t)54, w.Size());
    PtpMessage m = w.Message();
    m.Header._ByteSwap();
    m.Message.Delay_Resp._ByteSwap();
    Assert::IsTrue(m.Header.messageType == EMessageType::Delay_Resp);
    Assert::AreEqual((uint16_t)0x0102, m.Header.sequenceId);
    Assert::AreEqual(1700000037ULL * 1000000000ULL + 999999999ULL, m.Message.Delay_Resp.receiveTimestamp.Nanoseconds());
    Assert::AreEqual((uint16_t)0x0203, m.Message.Delay_Resp.requestingPortIdentity.portNumber);
    Assert::AreEqual(0, memcmp(&m.Message.Delay_Resp.requestingPortIdentity.clockIdentity, requester, 8));
  }

  TEST_METHOD(Announce) {
    WireBuilder w;
    w.Header(0xB, 64, 0, 0, 0x08, 0, CLOCK_ID, 1, 9)
      .Timestamp48(0, 0)
      .U16(37)                    //currentUtcOffset
      .U8(0)
      .U8(128)                    //priority1
      .U8(6).U8(0x21).U16(0x4E5D) //clock quality
      .U8(129)                    //priority2
      .Bytes(CLOCK_ID, 8)
      .U16(1)                     //stepsRemoved
      .U8(0x20);                  //timeSource GPS
    Assert::AreEqual((size_t)V2_ANNOUNCE_LENGTH, w.Size());
    PtpMessage m = w.Message();
    m.Header._ByteSwap();
    m.Message.Announce._ByteSwap();
    Assert::AreEqual((int16_t)37, m.Message.Announce.currentUTCOffset);
    Assert::AreEqual((uint8_t)128, m.Message.Announce.grandmasterPriority1);
    Assert::AreEqual((uint8_t)6, m.Message.Announce.grandmasterClockQuality.clockClass);
    Assert::AreEqual((uint16_t)0x4E5D, m.Message.Announce.grandmasterClockQuality.offsetScaledLogVariance);
    Assert::AreEqual((uint8_t)129, m.Message.Announce.grandmasterPriority2);
    Assert::AreEqual((uint16_t)1, m.Message.Announce.stepsRemoved);
    Assert::AreEqual((uint8_t)0x20, m.Message.Announce.timeSource);
  }

  TEST_METHOD(ClockIdentityFromMacIsEui64) {
    //a ConnectX-5: 0C-42-A1-80-0A-54 -> 0C42A1.FFFE.800A54
    const uint8_t mac[6] = { 0x0C, 0x42, 0xA1, 0x80, 0x0A, 0x54 };
    TClockIdentity id = ClockIdentityFromMac(mac);
    const uint8_t expected[8] = { 0x0C, 0x42, 0xA1, 0xFF, 0xFE, 0x80, 0x0A, 0x54 };
    Assert::AreEqual(0, memcmp(&id, expected, 8));
    //and that is what goes on the wire in sourcePortIdentity
    PtpMessage m;
    ZeroMemory(&m, sizeof(m));
    m.Header.sourcePortIdentity.clockIdentity = id;
    m.Header.sourcePortIdentity.portNumber = 1;
    m.Header._ByteSwap();
    const uint8_t* b = (const uint8_t*)&m;
    Assert::AreEqual(0, memcmp(b + 20, expected, 8));
    Assert::AreEqual((uint8_t)0x00, b[28]);
    Assert::AreEqual((uint8_t)0x01, b[29]);
  }

  TEST_METHOD(SwapIsItsOwnInverse) {
    //the provider builds Delay_Req in host order and swaps it to wire order before sending
    PtpMessage m;
    ZeroMemory(&m, sizeof(m));
    m.Header.messageType = EMessageType::Delay_Req;
    m.Header.messageLength = 44;
    m.Header.sequenceId = 0x1234;
    m.Header.sourcePortIdentity.portNumber = 1;
    m.Header.correctionField = 0x0102030405060708LL;
    PtpMessage wire = m;
    wire.Header._ByteSwap();
    const uint8_t* b = (const uint8_t*)&wire;
    Assert::AreEqual((uint8_t)0x00, b[2]);
    Assert::AreEqual((uint8_t)44, b[3]);
    Assert::AreEqual((uint8_t)0x12, b[30]);
    Assert::AreEqual((uint8_t)0x34, b[31]);
    Assert::AreEqual((uint8_t)0x01, b[8]);
    wire.Header._ByteSwap();
    Assert::AreEqual(0, memcmp(&m.Header, &wire.Header, sizeof(m.Header)));
  }
};

}
