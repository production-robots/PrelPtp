#include "..\PtpUtil\MessagePath.h"
#include "CppUnitTest.h"

#include "TestMessages.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

/*
Messages captured from the test lab network (passive listen on ports 319/320).

  Grandmaster  D0A4B1.FFFE.00058A, clock class 6, priority1/2 128, domain 127
  Heard through a boundary clock 506B4B.FFFE.9D5DC8 (stepsRemoved 1):
    port 34 (0x22) at 10.218.1.2   on the 10.218.1.x network
    port 19 (0x13) at 10.218.10.2  on the 10.218.10.x network
  Announce interval 2^-2 s (250 ms), two-step Sync.

These check the parsing and the BMCA against what a real master sends, not what we think it sends.
*/

namespace PtpTests {

static Received Hex(const char* Bytes) {
  WireBuilder w;
  const char* p = Bytes;
  while (*p) {
    while (*p == ' ')
      ++p;
    if (!*p)
      break;
    unsigned v = 0;
    Assert::AreEqual(1, sscanf_s(p, "%2x", &v));
    w.U8((uint8_t)v);
    p += 2;
  }
  return FromWire(w);
}

//Announce from port 34, sequence 0xF157 and 0xF158
static const char* LAB_ANNOUNCE_34_A = "0B 02 00 40 7F 00 00 3C 00 00 00 00 00 00 00 00 00 00 00 00 50 6B 4B FF FE 9D 5D C8 00 22 F1 57 05 FE 00 00 00 00 00 00 00 00 00 00 00 25 00 80 06 21 FF FF 80 D0 A4 B1 FF FE 00 05 8A 00 01 20";
static const char* LAB_ANNOUNCE_34_B = "0B 02 00 40 7F 00 00 3C 00 00 00 00 00 00 00 00 00 00 00 00 50 6B 4B FF FE 9D 5D C8 00 22 F1 58 05 FE 00 00 00 00 00 00 00 00 00 00 00 25 00 80 06 21 FF FF 80 D0 A4 B1 FF FE 00 05 8A 00 01 20";
//Announce from port 19, sequence 0xF121 and 0xF122
static const char* LAB_ANNOUNCE_19_A = "0B 02 00 40 7F 00 00 3C 00 00 00 00 00 00 00 00 00 00 00 00 50 6B 4B FF FE 9D 5D C8 00 13 F1 21 05 FE 00 00 00 00 00 00 00 00 00 00 00 25 00 80 06 21 FF FF 80 D0 A4 B1 FF FE 00 05 8A 00 01 20";
static const char* LAB_ANNOUNCE_19_B = "0B 02 00 40 7F 00 00 3C 00 00 00 00 00 00 00 00 00 00 00 00 50 6B 4B FF FE 9D 5D C8 00 13 F1 22 05 FE 00 00 00 00 00 00 00 00 00 00 00 25 00 80 06 21 FF FF 80 D0 A4 B1 FF FE 00 05 8A 00 01 20";
//two-step Sync and its Follow_Up from port 34, sequence 0xCEE5
static const char* LAB_SYNC_34 = "00 02 00 2C 7F 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 50 6B 4B FF FE 9D 5D C8 00 22 CE E5 00 FD 00 00 00 00 00 00 00 00 00 00";
static const char* LAB_FOLLOW_UP_34 = "08 02 00 2C 7F 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 50 6B 4B FF FE 9D 5D C8 00 22 CE E5 02 FD 00 00 6A EE 1A AF 1D A3 68 B0";
//Delay_Resp from port 34 to another client (44B7D0.FFFE.DED041 port 1), sequence 0x73A3
static const char* LAB_DELAY_RESP_OTHER = "09 02 00 36 7F 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 50 6B 4B FF FE 9D 5D C8 00 22 73 A3 03 FD 00 00 6A EE 1A AF 19 EA CA C6 44 B7 D0 FF FE DE D0 41 00 01";

static const DWORD LAB_IP_34 = Ip(10, 218, 1, 2);
static const DWORD LAB_IP_19 = Ip(10, 218, 10, 2);
static const uint64_t LAB_BC = 0x506B4BFFFE9D5DC8ULL;
static const uint64_t LAB_GM = 0xD0A4B1FFFE00058AULL;
static const uint64_t LAB_FOLLOW_UP_T1 = 0x6AEE1AAFULL * 1000000000ULL + 0x1DA368B0ULL;

static ULONGLONG g_lab_now;
static ULONGLONG WINAPI LabTick() { return g_lab_now; }

TEST_CLASS(LabCapture) {
  SSyncRequest sync;
  CBmca bmca;
  CMessagePath path{ sync, bmca };

  CMessagePath::SOutcome Feed(const char* Bytes, DWORD From, uint64_t RxSystemTime = 0) {
    Received r = Hex(Bytes);
    return path.Handle(r.Msg, r.Size, From, RxSystemTime);
  }

  void SelectPort34() {
    Feed(LAB_ANNOUNCE_34_A, LAB_IP_34);
    g_lab_now += 250;
    Assert::IsTrue(Feed(LAB_ANNOUNCE_34_B, LAB_IP_34).MasterChanged);
  }

public:
  TEST_METHOD_INITIALIZE(Init) {
    g_lab_now = 1000000;
    bmca.SetTickSource(LabTick);
    bmca.SetLocalPort(Pid(0x50, 1));
    sync.SetPortIdentity(Pid(0x50, 1));
    path.Configure(0, 127, false);
  }

  TEST_METHOD(AnnounceFields) {
    Received r = Hex(LAB_ANNOUNCE_34_A);
    Assert::AreEqual(64, r.Size);
    r.Msg.Header._ByteSwap();
    r.Msg.Message.Announce._ByteSwap();
    const CommonMsgHeader& h = r.Msg.Header;
    const AnnounceMessage& a = r.Msg.Message.Announce;
    Assert::IsTrue(h.messageType == EMessageType::Announce);
    Assert::AreEqual((uint8_t)127, h.domainNumber);
    Assert::IsTrue(h.sourcePortIdentity == Pid(LAB_BC, 34));
    Assert::AreEqual((uint16_t)0xF157, h.sequenceId);
    Assert::AreEqual(250ULL, AnnounceIntervalMs(h.logMessageInterval));
    Assert::IsTrue(h.ptpTimescale);
    Assert::IsTrue(h.currentUtcOffsetValid);
    Assert::IsTrue(h.timeTraceable);
    Assert::IsTrue(h.frequencyTraceable);
    Assert::IsFalse(h.alternateMasterFlag);
    Assert::AreEqual((int16_t)37, a.currentUTCOffset);
    Assert::AreEqual((uint8_t)128, a.grandmasterPriority1);
    Assert::AreEqual((uint8_t)6, a.grandmasterClockQuality.clockClass);
    Assert::AreEqual((uint8_t)0x21, a.grandmasterClockQuality.clockAccuracy);
    Assert::AreEqual((uint16_t)0xFFFF, a.grandmasterClockQuality.offsetScaledLogVariance);
    Assert::AreEqual((uint8_t)128, a.grandmasterPriority2);
    TClockIdentity gm;
    CopyMemory(&gm, a.grandmasterIdentity, sizeof(gm));
    Assert::AreEqual(WireId(LAB_GM), gm);
    Assert::AreEqual((uint16_t)1, a.stepsRemoved);
    Assert::AreEqual((uint8_t)0x20, a.timeSource);
  }

  TEST_METHOD(MasterSelectedAfterTwoAnnounces) {
    Feed(LAB_ANNOUNCE_34_A, LAB_IP_34);
    g_lab_now += 250;
    auto o = Feed(LAB_ANNOUNCE_34_B, LAB_IP_34);
    Assert::IsTrue(o.MasterChanged);
    CBmca::SForeignMaster m;
    Assert::IsTrue(bmca.GetSelected(m));
    Assert::IsTrue(m.Dataset.Sender == Pid(LAB_BC, 34));
    Assert::AreEqual(WireId(LAB_GM), m.Dataset.GrandmasterIdentity);
    Assert::AreEqual((unsigned int)LAB_IP_34, (unsigned int)m.Address);
    Assert::AreEqual((uint8_t)127, m.Domain);
    Assert::AreEqual(250ULL, m.IntervalMs);
  }

  TEST_METHOD(MasterTimesOutAfterThreeAnnounceIntervals) {
    SelectPort34();
    g_lab_now += 750;
    Assert::IsFalse(path.Tick());
    g_lab_now += 1;
    Assert::IsTrue(path.Tick());
  }

  TEST_METHOD(DomainZeroConfiguredIgnoresLab) {
    path.Configure(0, 0, false);
    Assert::AreEqual(CMessagePath::EResult::WrongDomain, Feed(LAB_ANNOUNCE_34_A, LAB_IP_34).Result);
  }

  TEST_METHOD(SyncAndFollowUpGiveOffset) {
    path.Configure(0, 127, true);  //offset from Sync alone, so no Delay_Req is needed
    SelectPort34();
    const uint64_t t2_ns = ((LAB_FOLLOW_UP_T1 + 5000) / 100) * 100;  //received 5 us later, in 100 ns units
    Assert::AreEqual(CMessagePath::EResult::Accepted, Feed(LAB_SYNC_34, LAB_IP_34, PtpToSystemTime(t2_ns / 100)).Result);
    auto o = Feed(LAB_FOLLOW_UP_34, LAB_IP_34);
    Assert::IsTrue(o.HaveOffset);
    Assert::AreEqual((int64_t)LAB_FOLLOW_UP_T1 - (int64_t)t2_ns, o.Offset);
  }

  TEST_METHOD(DelayResponseToAnotherClientIgnored) {
    SelectPort34();
    Feed(LAB_SYNC_34, LAB_IP_34, PtpToSystemTime(LAB_FOLLOW_UP_T1 / 100));
    Feed(LAB_FOLLOW_UP_34, LAB_IP_34);
    //even with the same sequence number, the requesting port is someone else's
    sync.dr_seq_id = 0x73A2;
    uint16_t seq = _byteswap_ushort(sync.GetDelayRequestSequenceId());
    Assert::AreEqual((uint16_t)0x73A3, seq);
    int64_t no_offset; sync.DelayRequestTx(seq, PtpToSystemTime(LAB_FOLLOW_UP_T1 / 100) + 100000, no_offset);
    auto o = Feed(LAB_DELAY_RESP_OTHER, LAB_IP_34);
    Assert::AreEqual(CMessagePath::EResult::Accepted, o.Result);
    Assert::IsFalse(o.HaveOffset);
  }

  TEST_METHOD(OtherPortOfBoundaryClockNotSelected) {
    SelectPort34();
    //port 19 of the same boundary clock, as if both networks were joined
    Feed(LAB_ANNOUNCE_19_A, LAB_IP_19);
    auto o = Feed(LAB_SYNC_34, LAB_IP_34, PtpToSystemTime(LAB_FOLLOW_UP_T1 / 100));
    Assert::AreEqual(CMessagePath::EResult::Accepted, o.Result);
  }

  TEST_METHOD(SameGrandmasterSameStepsLowerPortWins) {
    //figure 28 with real data: same grandmaster, same stepsRemoved, same sender clock:
    //port 19 is better by topology than port 34
    Feed(LAB_ANNOUNCE_34_A, LAB_IP_34);
    Feed(LAB_ANNOUNCE_19_A, LAB_IP_19);
    g_lab_now += 250;
    Feed(LAB_ANNOUNCE_34_B, LAB_IP_34);
    Feed(LAB_ANNOUNCE_19_B, LAB_IP_19);
    Assert::IsTrue(bmca.IsSelected(Pid(LAB_BC, 19), 127));
    Assert::AreEqual(CMessagePath::EResult::NotSelected, Feed(LAB_SYNC_34, LAB_IP_34).Result);
  }

  TEST_METHOD(PinnedToPort34) {
    path.Configure(LAB_IP_34, 127, true);
    Assert::AreEqual(CMessagePath::EResult::WrongSource, Feed(LAB_ANNOUNCE_19_A, LAB_IP_19).Result);
    const uint64_t t2_ns = ((LAB_FOLLOW_UP_T1 + 5000) / 100) * 100;
    Feed(LAB_SYNC_34, LAB_IP_34, PtpToSystemTime(t2_ns / 100));
    auto o = Feed(LAB_FOLLOW_UP_34, LAB_IP_34);
    Assert::IsTrue(o.HaveOffset);
    Assert::AreEqual((int64_t)LAB_FOLLOW_UP_T1 - (int64_t)t2_ns, o.Offset);
  }
};

}
