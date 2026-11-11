#include "..\PtpUtil\MessagePath.h"
#include "..\PtpUtil\Filter.h"
#include "CppUnitTest.h"

#include "TestMessages.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;


/*
CMessagePath: what happens to each message the sockets receive, given as bytes in network
byte order. Two masters are on the network unless a test says otherwise:
  A (10.0.0.1): the better master
  B (10.0.0.2): priority1 200, so worse
Times follow the scenario in SyncRequestTests: master A is OFFSET ns ahead of the local clock
and the path delay is DELAY ns. B's timestamps are deliberately wrong by a large amount, so
any B message that reached the offset calculation would show in the result.
*/

namespace PtpTests {

static ULONGLONG g_path_now;
static ULONGLONG WINAPI PathTick() { return g_path_now; }

static const int64_t MP_OFFSET = -2000;
static const int64_t MP_DELAY = 1500;
static const uint64_t MP_T1 = 1700000037ULL * 1000000000ULL;
static const uint64_t MP_T2 = (uint64_t)((int64_t)MP_T1 + MP_DELAY - MP_OFFSET);
static const uint64_t MP_T3 = MP_T2 + 10000000;
static const uint64_t MP_T4 = (uint64_t)((int64_t)MP_T3 + MP_OFFSET + MP_DELAY);
static const uint64_t B_ERROR = 7000000;   //7 ms

static uint64_t SysTime(uint64_t PtpNs) {
  return PtpToSystemTime(PtpNs / 100);
}

static const PortIdentity LOCAL_PORT = Pid(0x50, 1);

TEST_CLASS(MessagePath) {
  SSyncRequest sync;
  CBmca bmca;
  CMessagePath path{ sync, bmca };
  TestMaster A{ 0x10, Ip(10, 0, 0, 1) };
  TestMaster B{ 0x20, Ip(10, 0, 0, 2) };

  CMessagePath::SOutcome Feed(Received R, DWORD From, uint64_t RxSystemTime = 0) {
    return path.Handle(R.Msg, R.Size, From, RxSystemTime);
  }

  void Qualify(TestMaster& M) {
    Feed(M.Announce(), M.Address);
    g_path_now += 1000;
    Feed(M.Announce(), M.Address);
  }

  //sends a Delay_Req and returns its sequence number (host order)
  uint16_t SendDelayRequest(uint64_t T3) {
    uint16_t seq = _byteswap_ushort(sync.GetDelayRequestSequenceId());
    int64_t no_offset; sync.DelayRequestTx(seq, SysTime(T3), no_offset);
    return seq;
  }

  //a complete two-step exchange with M. Returns the outcome of the Delay_Resp.
  CMessagePath::SOutcome Exchange(TestMaster& M, uint16_t Seq, uint64_t Error = 0) {
    Feed(M.Sync(Seq, true), M.Address, SysTime(MP_T2));
    Feed(M.FollowUp(Seq, MP_T1 + Error), M.Address);
    uint16_t dr = SendDelayRequest(MP_T3);
    return Feed(M.DelayResp(dr, MP_T4 + Error, LOCAL_PORT), M.Address);
  }

public:
  TEST_METHOD_INITIALIZE(Init) {
    g_path_now = 1000000;
    bmca.SetTickSource(PathTick);
    bmca.SetLocalPort(LOCAL_PORT);
    sync.SetPortIdentity(LOCAL_PORT);
    path.Configure(0, PTP_DOMAIN_ANY, false);
    B.Priority1 = 200;
  }

  //automatic selection

  TEST_METHOD(AnnounceIsAccepted) {
    Assert::AreEqual(CMessagePath::EResult::Accepted, Feed(A.Announce(), A.Address).Result);
  }

  TEST_METHOD(NothingUsedBeforeAMasterIsSelected) {
    auto o = Feed(A.Sync(1, false, MP_T1), A.Address, SysTime(MP_T2));
    Assert::AreEqual(CMessagePath::EResult::NotSelected, o.Result);
    Assert::IsFalse(o.HaveOffset);
  }

  TEST_METHOD(SelectionReported) {
    Feed(A.Announce(), A.Address);
    g_path_now += 1000;
    auto o = Feed(A.Announce(), A.Address);
    Assert::IsTrue(o.MasterChanged);
    Assert::IsTrue(bmca.IsSelected(A.Identity(), 0));
  }

  TEST_METHOD(SelectedMasterGivesOffset) {
    Qualify(A);
    auto o = Exchange(A, 1);
    Assert::AreEqual(CMessagePath::EResult::Accepted, o.Result);
    Assert::IsTrue(o.HaveOffset);
    Assert::AreEqual(MP_OFFSET, o.Offset);
  }

  TEST_METHOD(InterleavedMastersOnlySelectedOneUsed) {
    Feed(A.Announce(), A.Address); Feed(B.Announce(), B.Address);
    g_path_now += 1000;
    Feed(B.Announce(), B.Address); Feed(A.Announce(), A.Address);
    Assert::IsTrue(bmca.IsSelected(A.Identity(), 0));

    //both masters use sequence number 1 and both answer our Delay_Req
    Feed(A.Sync(1, true), A.Address, SysTime(MP_T2));
    Assert::AreEqual(CMessagePath::EResult::NotSelected, Feed(B.Sync(1, true), B.Address, SysTime(MP_T2 + B_ERROR)).Result);
    Assert::AreEqual(CMessagePath::EResult::NotSelected, Feed(B.FollowUp(1, MP_T1 + B_ERROR), B.Address).Result);
    Feed(A.FollowUp(1, MP_T1), A.Address);
    uint16_t dr = SendDelayRequest(MP_T3);
    auto ob = Feed(B.DelayResp(dr, MP_T4 + B_ERROR, LOCAL_PORT), B.Address);
    Assert::AreEqual(CMessagePath::EResult::NotSelected, ob.Result);
    Assert::IsFalse(ob.HaveOffset);
    auto oa = Feed(A.DelayResp(dr, MP_T4, LOCAL_PORT), A.Address);
    Assert::IsTrue(oa.HaveOffset);
    Assert::AreEqual(MP_OFFSET, oa.Offset);
  }

  TEST_METHOD(SwitchResetsSyncState) {
    Qualify(A);
    //A's Sync arrives; then B becomes the better master before A's Follow_Up
    Feed(A.Sync(5, true), A.Address, SysTime(MP_T2));
    B.Priority1 = 1;
    Feed(B.Announce(), B.Address);
    g_path_now += 1000;
    auto changed = Feed(B.Announce(), B.Address);
    Assert::IsTrue(changed.MasterChanged);
    Assert::IsTrue(bmca.IsSelected(B.Identity(), 0));

    Assert::AreEqual(CMessagePath::EResult::NotSelected, Feed(A.FollowUp(5, MP_T1), A.Address).Result);
    //B's Follow_Up with the same sequence number must not complete A's Sync
    Assert::AreEqual(CMessagePath::EResult::Accepted, Feed(B.FollowUp(5, MP_T1 + B_ERROR), B.Address).Result);
    uint16_t dr = SendDelayRequest(MP_T3);
    Assert::IsFalse(Feed(B.DelayResp(dr, MP_T4 + B_ERROR, LOCAL_PORT), B.Address).HaveOffset);

    //a complete exchange with B works
    auto o = Exchange(B, 6);
    Assert::IsTrue(o.HaveOffset);
    Assert::AreEqual(MP_OFFSET, o.Offset);
  }

  TEST_METHOD(TimeoutFoundByTick) {
    Qualify(A);
    g_path_now += 3001;
    Assert::IsTrue(path.Tick());
    Assert::IsFalse(path.Tick());
    Assert::AreEqual(CMessagePath::EResult::NotSelected, Feed(A.Sync(1, false, MP_T1), A.Address).Result);
  }

  TEST_METHOD(TimeoutFoundByAnyMessage) {
    Qualify(A);
    g_path_now += 3001;
    auto o = Feed(A.Sync(1, false, MP_T1), A.Address);
    Assert::IsTrue(o.MasterChanged);
    Assert::AreEqual(CMessagePath::EResult::NotSelected, o.Result);
  }

  TEST_METHOD(TimeoutResetsSyncState) {
    Qualify(A);
    Feed(A.Sync(1, true), A.Address, SysTime(MP_T2));
    Feed(A.FollowUp(1, MP_T1), A.Address);
    g_path_now += 3001;
    Assert::IsTrue(path.Tick());
    Assert::AreEqual((uint64_t)0, sync.sync_rx_t2);
  }

  TEST_METHOD(DelayRequestsDisabledOffsetFromSync) {
    path.Configure(0, PTP_DOMAIN_ANY, true);
    Qualify(A);
    Qualify(B);
    auto ob = Feed(B.Sync(1, false, MP_T1 + B_ERROR), B.Address, SysTime(MP_T2));
    Assert::AreEqual(CMessagePath::EResult::NotSelected, ob.Result);
    Assert::IsFalse(ob.HaveOffset);
    auto oa = Feed(A.Sync(1, false, MP_T1), A.Address, SysTime(MP_T2));
    Assert::IsTrue(oa.HaveOffset);
    Assert::AreEqual(MP_OFFSET - MP_DELAY, oa.Offset);
    //Delay_Resp messages are for someone else's Delay_Req
    uint16_t dr = SendDelayRequest(MP_T3);
    Assert::IsFalse(Feed(A.DelayResp(dr, MP_T4, LOCAL_PORT), A.Address).HaveOffset);
  }

  TEST_METHOD(SyncDomainReported) {
    A.Domain = 4;
    Qualify(A);
    auto o = Feed(A.Sync(1, true), A.Address, SysTime(MP_T2));
    Assert::AreEqual(CMessagePath::EResult::Accepted, o.Result);
    Assert::IsTrue(o.Type == EMessageType::Sync);
    Assert::AreEqual((uint8_t)4, o.Domain);
  }

  //pinned master (GrandmasterAddress set)

  TEST_METHOD(PinnedUsesMasterWithoutAnnounce) {
    path.Configure(A.Address, PTP_DOMAIN_ANY, false);
    auto o = Exchange(A, 1);
    Assert::IsTrue(o.HaveOffset);
    Assert::AreEqual(MP_OFFSET, o.Offset);
  }

  TEST_METHOD(PinnedIgnoresOtherAddresses) {
    path.Configure(A.Address, PTP_DOMAIN_ANY, false);
    Assert::AreEqual(CMessagePath::EResult::WrongSource, Feed(B.Announce(), B.Address).Result);
    Assert::AreEqual(CMessagePath::EResult::WrongSource, Feed(B.Sync(1, false, MP_T1), B.Address).Result);
  }

  TEST_METHOD(PinnedIgnoresRogueMaster) {
    path.Configure(A.Address, PTP_DOMAIN_ANY, false);
    TestMaster rogue(0x01, Ip(10, 0, 0, 66));
    rogue.Priority1 = 0;
    for (int i = 0; i < 3; ++i) {
      auto o = Feed(rogue.Announce(), rogue.Address);
      Assert::AreEqual(CMessagePath::EResult::WrongSource, o.Result);
      Assert::IsFalse(o.MasterChanged);
      g_path_now += 1000;
    }
    auto o = Exchange(A, 1);
    Assert::IsTrue(o.HaveOffset);
    Assert::AreEqual(MP_OFFSET, o.Offset);
  }

  TEST_METHOD(PinnedReportsMasterButDoesNotResetSync) {
    path.Configure(A.Address, PTP_DOMAIN_ANY, false);
    Feed(A.Sync(1, true), A.Address, SysTime(MP_T2));
    Feed(A.Announce(), A.Address);
    g_path_now += 1000;
    Assert::IsTrue(Feed(A.Announce(), A.Address).MasterChanged);
    Feed(A.FollowUp(1, MP_T1), A.Address);
    uint16_t dr = SendDelayRequest(MP_T3);
    auto o = Feed(A.DelayResp(dr, MP_T4, LOCAL_PORT), A.Address);
    Assert::IsTrue(o.HaveOffset);
    Assert::AreEqual(MP_OFFSET, o.Offset);
  }

  //filtering that applies in both modes

  TEST_METHOD(OtherDomainIgnored) {
    path.Configure(0, 0, false);
    A.Domain = 1;
    Assert::AreEqual(CMessagePath::EResult::WrongDomain, Feed(A.Announce(), A.Address).Result);
    Assert::AreEqual(CMessagePath::EResult::WrongDomain, Feed(A.Sync(1, true), A.Address).Result);
  }

  TEST_METHOD(OtherSlavesDelayRequestIgnoredWhenPinned) {
    //another slave's Delay_Req is not evidence of anything, even from another address
    path.Configure(A.Address, PTP_DOMAIN_ANY, false);
    uint8_t id[8];
    IdOctets(0x60, id);
    WireBuilder w;
    w.Header(0x1, 44, 0, 0, 0, 0, id, 1, 7, 0x7F).Timestamp48(0, 0);
    Assert::AreEqual(CMessagePath::EResult::Ignored, Feed(FromWire(w), Ip(10, 0, 0, 60)).Result);
  }

  TEST_METHOD(WrongDomainReportsTheDomain) {
    path.Configure(0, 0, false);
    A.Domain = 127;
    auto o = Feed(A.Sync(1, true), A.Address);
    Assert::AreEqual(CMessagePath::EResult::WrongDomain, o.Result);
    Assert::AreEqual((uint8_t)127, o.Domain);
  }

  TEST_METHOD(OwnDelayRequestIgnored) {
    uint8_t id[8];
    IdOctets(0x50, id);
    WireBuilder w;
    w.Header(0x1, 44, 0, 0, 0, 0, id, 1, 7, 0x7F).Timestamp48(0, 0);
    Assert::AreEqual(CMessagePath::EResult::Ignored, Feed(FromWire(w), Ip(10, 0, 0, 9)).Result);
  }

  TEST_METHOD(ShortMessageIgnored) {
    Received r = A.Announce();
    r.Size = (int)sizeof(CommonMsgHeader) - 1;
    Assert::AreEqual(CMessagePath::EResult::Ignored, Feed(r, A.Address).Result);
  }

  TEST_METHOD(TruncatedAnnounceNotUsed) {
    Received r = A.Announce();
    r.Size = (int)sizeof(CommonMsgHeader) + 10;
    Feed(r, A.Address);
    g_path_now += 1000;
    r = A.Announce();
    r.Size = (int)sizeof(CommonMsgHeader) + 10;
    Feed(r, A.Address);
    Assert::AreEqual(0, bmca.ForeignMasterCount());
  }
};

}
