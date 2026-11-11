#include "..\PtpUtil\Bmca.h"
#include "CppUnitTest.h"

#include "TestMessages.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;


/*
CBmca over time: foreign master qualification, announce receipt timeout, and selection.
Masters announce once a second (logMessageInterval 0) unless a test says otherwise.
*/

namespace PtpTests {

static ULONGLONG g_bmca_now;
static ULONGLONG WINAPI BmcaTick() { return g_bmca_now; }

static const uint64_t LOCAL_ID = 0x0000000000000050ULL;

TEST_CLASS(BmcaSelect) {
  CBmca b;

  CBmca::EAnnounceResult Announce(TestMaster& M, bool* out_Changed = nullptr) {
    Received r = M.Announce();
    r.Msg.Header._ByteSwap();
    r.Msg.Message.Announce._ByteSwap();
    return b.OnAnnounce(r.Msg.Header, r.Msg.Message.Announce, M.Address, out_Changed);
  }

  //announces twice, a second apart, so the master qualifies
  void Qualify(TestMaster& M) {
    Announce(M);
    g_bmca_now += 1000;
    Announce(M);
  }

  bool Selected(const TestMaster& M) {
    return b.IsSelected(M.Identity(), M.Domain);
  }

  bool NoneSelected() {
    CBmca::SForeignMaster m;
    return !b.GetSelected(m);
  }

public:
  TEST_METHOD_INITIALIZE(Init) {
    g_bmca_now = 1000000;
    b.SetTickSource(BmcaTick);
    b.SetLocalPort(Pid(LOCAL_ID, 1));
  }

  //qualification (9.3.2.4, 9.3.2.5)

  TEST_METHOD(SingleAnnounceDoesNotQualify) {
    TestMaster a(0x10, Ip(10, 0, 0, 1));
    bool changed = true;
    Assert::AreEqual(CBmca::EAnnounceResult::Used, Announce(a, &changed));
    Assert::IsFalse(changed);
    Assert::IsTrue(NoneSelected());
    Assert::AreEqual(1, b.ForeignMasterCount());
  }

  TEST_METHOD(TwoAnnouncesQualify) {
    TestMaster a(0x10, Ip(10, 0, 0, 1));
    Announce(a);
    g_bmca_now += 1000;
    bool changed = false;
    Announce(a, &changed);
    Assert::IsTrue(changed);
    Assert::IsTrue(Selected(a));
  }

  TEST_METHOD(SelectedMasterDetails) {
    TestMaster a(0x10, Ip(10, 0, 0, 1));
    a.Gm = 0x77;
    a.StepsRemoved = 1;
    a.ClockClass = 7;
    Qualify(a);
    CBmca::SForeignMaster m;
    Assert::IsTrue(b.GetSelected(m));
    Assert::AreEqual((unsigned int)Ip(10, 0, 0, 1), (unsigned int)m.Address);
    Assert::AreEqual(WireId(0x77), m.Dataset.GrandmasterIdentity);
    Assert::AreEqual((uint16_t)1, m.Dataset.StepsRemoved);
    Assert::AreEqual((uint8_t)7, m.Dataset.ClockClass);
    Assert::IsTrue(m.Dataset.Sender == Pid(0x10, 1));
    Assert::IsTrue(m.Dataset.Receiver == Pid(LOCAL_ID, 1));
  }

  TEST_METHOD(AnnouncesTooFarApartDoNotQualify) {
    //window is 4 intervals; the first entry has also timed out (3 intervals) by then
    TestMaster a(0x10, Ip(10, 0, 0, 1));
    Announce(a);
    g_bmca_now += 4001;
    Announce(a);
    Assert::IsTrue(NoneSelected());
    g_bmca_now += 1000;
    Announce(a);
    Assert::IsTrue(Selected(a));
  }

  TEST_METHOD(AnnouncesWithinTimeoutQualify) {
    TestMaster a(0x10, Ip(10, 0, 0, 1));
    Announce(a);
    g_bmca_now += 3000;
    Announce(a);
    Assert::IsTrue(Selected(a));
  }

  TEST_METHOD(RepeatedSequenceIdDoesNotCount) {
    TestMaster a(0x10, Ip(10, 0, 0, 1));
    Announce(a);
    a.AnnounceSequence--;   //send the same sequence number again
    g_bmca_now += 1000;
    Assert::AreEqual(CBmca::EAnnounceResult::IgnoredDuplicate, Announce(a));
    Assert::IsTrue(NoneSelected());
    g_bmca_now += 1000;
    Announce(a);
    Assert::IsTrue(Selected(a));
  }

  TEST_METHOD(OwnAnnounceIgnored) {
    TestMaster self(LOCAL_ID, Ip(10, 0, 0, 9));
    Assert::AreEqual(CBmca::EAnnounceResult::IgnoredOwn, Announce(self));
    g_bmca_now += 1000;
    Announce(self);
    Assert::IsTrue(NoneSelected());
    Assert::AreEqual(0, b.ForeignMasterCount());
  }

  TEST_METHOD(StepsRemoved255Ignored) {
    TestMaster a(0x10, Ip(10, 0, 0, 1));
    a.StepsRemoved = 255;
    Assert::AreEqual(CBmca::EAnnounceResult::IgnoredSteps, Announce(a));
    a.StepsRemoved = 254;
    Assert::AreEqual(CBmca::EAnnounceResult::Used, Announce(a));
  }

  TEST_METHOD(AlternateMasterIgnored) {
    TestMaster a(0x10, Ip(10, 0, 0, 1));
    a.AlternateMaster = true;
    Assert::AreEqual(CBmca::EAnnounceResult::IgnoredAlternate, Announce(a));
    g_bmca_now += 1000;
    Announce(a);
    Assert::IsTrue(NoneSelected());
  }

  TEST_METHOD(OtherDomainIgnored) {
    b.SetDomain(0);
    TestMaster a(0x10, Ip(10, 0, 0, 1));
    a.Domain = 1;
    Assert::AreEqual(CBmca::EAnnounceResult::IgnoredDomain, Announce(a));
  }

  TEST_METHOD(AnyDomainKeepsDomainsApart) {
    //the same port (a boundary clock) announcing a different grandmaster in each domain
    //is two foreign masters
    TestMaster d0(0x10, Ip(10, 0, 0, 1));
    TestMaster d1(0x10, Ip(10, 0, 0, 1));
    d0.Gm = 0x70;
    d1.Gm = 0x71;
    d1.Domain = 1;
    d1.Priority1 = 100;
    Announce(d0);
    Announce(d1);
    Assert::AreEqual(2, b.ForeignMasterCount());
    g_bmca_now += 1000;
    Announce(d0);
    Announce(d1);
    Assert::IsTrue(Selected(d1));
    Assert::IsFalse(b.IsSelected(d0.Identity(), 0));
  }

  //timeout (announceReceiptTimeout = 3 intervals)

  TEST_METHOD(SelectedMasterTimesOut) {
    TestMaster a(0x10, Ip(10, 0, 0, 1));
    Qualify(a);
    g_bmca_now += 3000;
    Assert::IsFalse(b.OnTick());
    Assert::IsTrue(Selected(a));
    g_bmca_now += 1;
    Assert::IsTrue(b.OnTick());
    Assert::IsTrue(NoneSelected());
    Assert::AreEqual(0, b.ForeignMasterCount());
  }

  TEST_METHOD(TimeoutUsesAnnouncedInterval) {
    TestMaster a(0x10, Ip(10, 0, 0, 1));
    a.LogAnnounceInterval = (uint8_t)-2;   //250 ms
    Announce(a);
    g_bmca_now += 250;
    Announce(a);
    Assert::IsTrue(Selected(a));
    g_bmca_now += 750;
    Assert::IsFalse(b.OnTick());
    g_bmca_now += 1;
    Assert::IsTrue(b.OnTick());
  }

  TEST_METHOD(SlowAnnounceInterval) {
    TestMaster a(0x10, Ip(10, 0, 0, 1));
    a.LogAnnounceInterval = 2;   //4 s
    Announce(a);
    g_bmca_now += 4000;
    Announce(a);
    Assert::IsTrue(Selected(a));
    g_bmca_now += 12000;
    Assert::IsFalse(b.OnTick());
    g_bmca_now += 1;
    Assert::IsTrue(b.OnTick());
  }

  TEST_METHOD(AnnounceIntervalConversion) {
    Assert::AreEqual(1000ULL, AnnounceIntervalMs(0));
    Assert::AreEqual(2000ULL, AnnounceIntervalMs(1));
    Assert::AreEqual(16000ULL, AnnounceIntervalMs(4));
    Assert::AreEqual(500ULL, AnnounceIntervalMs((uint8_t)-1));
    Assert::AreEqual(62ULL, AnnounceIntervalMs((uint8_t)-4));
    //out of range values are clamped
    Assert::AreEqual(62ULL, AnnounceIntervalMs((uint8_t)-10));
    Assert::AreEqual(16000ULL, AnnounceIntervalMs(10));
    Assert::AreEqual(16000ULL, AnnounceIntervalMs(0x7F));
  }

  TEST_METHOD(FailoverToNextQualifiedMaster) {
    TestMaster a(0x10, Ip(10, 0, 0, 1));
    TestMaster c(0x20, Ip(10, 0, 0, 2));
    a.Priority1 = 100;
    Announce(a); Announce(c);
    g_bmca_now += 1000;
    Announce(a); Announce(c);
    Assert::IsTrue(Selected(a));
    //a stops; c keeps announcing
    for (int i = 0; i < 3; ++i) {
      g_bmca_now += 1000;
      bool changed = true;
      Announce(c, &changed);
      Assert::IsFalse(changed);
      Assert::IsTrue(Selected(a));
    }
    g_bmca_now += 1000;
    bool changed = false;
    Announce(c, &changed);
    Assert::IsTrue(changed);
    Assert::IsTrue(Selected(c));
  }

  TEST_METHOD(NoMasterWhenAllStop) {
    TestMaster a(0x10, Ip(10, 0, 0, 1));
    Qualify(a);
    g_bmca_now += 60000;
    Assert::IsTrue(b.OnTick());
    Assert::IsTrue(NoneSelected());
    Assert::IsFalse(b.OnTick());
  }

  //selection

  TEST_METHOD(BetterMasterTakesOverOnceQualified) {
    TestMaster a(0x10, Ip(10, 0, 0, 1));
    TestMaster c(0x20, Ip(10, 0, 0, 2));
    c.Priority1 = 100;
    Qualify(a);
    bool changed = true;
    Announce(c, &changed);
    Assert::IsFalse(changed);
    Assert::IsTrue(Selected(a));
    g_bmca_now += 1000;
    Announce(a);
    Announce(c, &changed);
    Assert::IsTrue(changed);
    Assert::IsTrue(Selected(c));
  }

  TEST_METHOD(WorseMasterDoesNotTakeOver) {
    TestMaster a(0x10, Ip(10, 0, 0, 1));
    TestMaster c(0x20, Ip(10, 0, 0, 2));
    c.ClockClass = 7;
    Qualify(a);
    for (int i = 0; i < 5; ++i) {
      g_bmca_now += 1000;
      Announce(a);
      bool changed = true;
      Announce(c, &changed);
      Assert::IsFalse(changed);
    }
    Assert::IsTrue(Selected(a));
  }

  TEST_METHOD(DegradedMasterLosesToBetterOne) {
    TestMaster a(0x10, Ip(10, 0, 0, 1));
    TestMaster c(0x20, Ip(10, 0, 0, 2));
    c.ClockClass = 7;
    Announce(a); Announce(c);
    g_bmca_now += 1000;
    Announce(a); Announce(c);
    Assert::IsTrue(Selected(a));
    //a loses its reference: class 6 -> 52 (degraded)
    a.ClockClass = 52;
    g_bmca_now += 1000;
    bool changed = false;
    Announce(a, &changed);
    Assert::IsTrue(changed);
    Assert::IsTrue(Selected(c));
  }

  TEST_METHOD(BetterMasterReturnsAndIsSelectedAgain) {
    //the standard has no hold-off: a better master that comes back is used again once qualified
    TestMaster a(0x10, Ip(10, 0, 0, 1));
    TestMaster c(0x20, Ip(10, 0, 0, 2));
    a.Priority2 = 100;
    Announce(a); Announce(c);
    g_bmca_now += 1000;
    Announce(a); Announce(c);
    Assert::IsTrue(Selected(a));
    for (int i = 0; i < 4; ++i) {
      g_bmca_now += 1000;
      Announce(c);
    }
    Assert::IsTrue(Selected(c));
    g_bmca_now += 1000;
    Announce(a); Announce(c);
    Assert::IsTrue(Selected(c));
    g_bmca_now += 1000;
    Announce(a);
    Assert::IsTrue(Selected(a));
  }

  TEST_METHOD(RogueMasterTakesOverWhenNotPinned) {
    //the reason GrandmasterAddress exists: the BMCA believes what Announce messages say
    TestMaster good(0x10, Ip(10, 0, 0, 1));
    TestMaster rogue(0x99, Ip(10, 0, 0, 66));
    rogue.Priority1 = 0;
    rogue.ClockClass = 6;
    Qualify(good);
    Announce(rogue);
    g_bmca_now += 1000;
    Announce(good);
    Announce(rogue);
    Assert::IsTrue(Selected(rogue));
  }

  TEST_METHOD(TieOnQualityLowerGrandmasterIdentityWins) {
    TestMaster a(0x20, Ip(10, 0, 0, 1));
    TestMaster c(0x10, Ip(10, 0, 0, 2));
    Announce(a); Announce(c);
    g_bmca_now += 1000;
    Announce(a); Announce(c);
    Assert::IsTrue(Selected(c));
  }

  TEST_METHOD(SameGrandmasterFewerStepsWins) {
    //grandmaster 0x77 through two boundary clocks
    TestMaster near_bc(0x30, Ip(10, 0, 0, 3));
    TestMaster far_bc(0x20, Ip(10, 0, 0, 2));
    near_bc.Gm = far_bc.Gm = 0x77;
    near_bc.StepsRemoved = 1;
    far_bc.StepsRemoved = 2;
    Announce(far_bc); Announce(near_bc);
    g_bmca_now += 1000;
    Announce(far_bc); Announce(near_bc);
    Assert::IsTrue(Selected(near_bc));
  }

  TEST_METHOD(SameGrandmasterSameStepsLowerSenderWins) {
    TestMaster bc1(0x30, Ip(10, 0, 0, 3));
    TestMaster bc2(0x20, Ip(10, 0, 0, 2));
    bc1.Gm = bc2.Gm = 0x77;
    bc1.StepsRemoved = bc2.StepsRemoved = 1;
    Announce(bc1); Announce(bc2);
    g_bmca_now += 1000;
    Announce(bc1); Announce(bc2);
    Assert::IsTrue(Selected(bc2));
  }

  TEST_METHOD(UnqualifiedBetterMasterNotSelected) {
    TestMaster a(0x10, Ip(10, 0, 0, 1));
    TestMaster c(0x20, Ip(10, 0, 0, 2));
    c.Priority1 = 1;
    Qualify(a);
    Announce(c);
    Assert::IsTrue(Selected(a));
  }

  //table management

  TEST_METHOD(FullTableIgnoresNewMasters) {
    for (int i = 0; i < CBmca::MAX_FOREIGN_MASTERS; ++i) {
      TestMaster m(0x100 + i, Ip(10, 0, 1, (uint8_t)i));
      Assert::AreEqual(CBmca::EAnnounceResult::Used, Announce(m));
    }
    TestMaster extra(0x10, Ip(10, 0, 0, 1));
    Assert::AreEqual(CBmca::EAnnounceResult::IgnoredFull, Announce(extra));
    //the others time out and make room
    g_bmca_now += 3001;
    Assert::AreEqual(CBmca::EAnnounceResult::Used, Announce(extra));
    Assert::AreEqual(1, b.ForeignMasterCount());
  }

  TEST_METHOD(ResetForgetsEverything) {
    TestMaster a(0x10, Ip(10, 0, 0, 1));
    Qualify(a);
    b.Reset();
    Assert::IsTrue(NoneSelected());
    Assert::AreEqual(0, b.ForeignMasterCount());
  }
};

}
