#include "..\PtpUtil\SyncRequest.h"
#include "CppUnitTest.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace PtpTests {

/*
The handlers receive messages that have already been byte swapped to host order,
and local timestamps as Windows system time (ns100 since 1601).

Scenario used throughout: the master is OFFSET ns ahead of the local clock and the
one-way path delay is DELAY ns. Times are PTP nanoseconds, all multiples of 100 so
they convert exactly to and from system time.
*/
static const int64_t OFFSET = -2000;    //master - local
static const int64_t DELAY = 1500;
static const uint64_t T1 = 1700000037ULL * 1000000000ULL;   //master sends Sync (PTP ns)
static const uint64_t T2 = (uint64_t)((int64_t)T1 + DELAY - OFFSET);  //local receives Sync
static const uint64_t T3 = T2 + 10000000;                              //local sends Delay_Req 10 ms later
static const uint64_t T4 = (uint64_t)((int64_t)T3 + OFFSET + DELAY);  //master receives Delay_Req

static uint64_t LocalSystemTime(uint64_t PtpNs) {
  return PtpToSystemTime(PtpNs / 100);
}

static Timestamp Ts(uint64_t Ns) {
  Timestamp t;
  t.secondsHigh = 0;
  t.secondsField = (uint32_t)(Ns / 1000000000ULL);
  t.nanosecondsField = (uint32_t)(Ns % 1000000000ULL);
  return t;
}

static PtpMessage Msg(EMessageType Type, uint16_t Sequence, bool TwoStep = false) {
  PtpMessage m;
  ZeroMemory(&m, sizeof(m));
  m.Header.messageType = Type;
  m.Header.sequenceId = Sequence;
  m.Header.twoStepFlag = TwoStep;
  return m;
}

static PtpMessage SyncMsg(uint16_t Sequence, bool TwoStep, uint64_t OriginNs = 0) {
  PtpMessage m = Msg(EMessageType::Sync, Sequence, TwoStep);
  m.Message.Sync.originTimestamp = Ts(OriginNs);
  return m;
}

static PtpMessage FollowUpMsg(uint16_t Sequence, uint64_t OriginNs) {
  PtpMessage m = Msg(EMessageType::Follow_Up, Sequence);
  m.Message.Follow_Up.originTimestamp = Ts(OriginNs);
  return m;
}

static PortIdentity Port(uint16_t Number) {
  PortIdentity p;
  p.clockIdentity = 0x5634121EFEFF2000ULL;
  p.portNumber = Number;
  return p;
}

TEST_CLASS(SyncRequest) {
  SSyncRequest s;

  //sends a Delay_Req and returns the matching response (host order)
  PtpMessage DelayRequest(uint64_t T3Ns, uint64_t T4Ns) {
    uint16_t seq = _byteswap_ushort(s.GetDelayRequestSequenceId());  //returned in wire order
    int64_t no_offset; s.DelayRequestTx(seq, LocalSystemTime(T3Ns), no_offset);
    PtpMessage r = Msg(EMessageType::Delay_Resp, seq);
    r.Message.Delay_Resp.receiveTimestamp = Ts(T4Ns);
    r.Message.Delay_Resp.requestingPortIdentity = Port(1);
    return r;
  }

public:
  TEST_METHOD_INITIALIZE(Init) {
    s.SetPortIdentity(Port(1));
  }

  //delay request disabled: offset from Sync alone (includes the path delay)

  TEST_METHOD(OneStepSyncGivesOffset) {
    int64_t offset = 0;
    Assert::IsTrue(s.Sync(SyncMsg(1, false, T1), LocalSystemTime(T2), &offset));
    Assert::AreEqual(OFFSET - DELAY, offset);
  }

  TEST_METHOD(TwoStepSyncWaitsForFollowUp) {
    int64_t offset = 12345;
    Assert::IsFalse(s.Sync(SyncMsg(1, true), LocalSystemTime(T2), &offset));
    Assert::AreEqual(12345LL, offset);
    Assert::IsTrue(s.SyncFollowUp(FollowUpMsg(1, T1), &offset));
    Assert::AreEqual(OFFSET - DELAY, offset);
  }

  TEST_METHOD(FollowUpForOtherSyncIsIgnored) {
    int64_t offset = 0;
    s.Sync(SyncMsg(5, true), LocalSystemTime(T2), nullptr);
    Assert::IsFalse(s.SyncFollowUp(FollowUpMsg(4, T1), &offset));
    Assert::IsFalse(s.SyncFollowUp(FollowUpMsg(6, T1), &offset));
  }

  TEST_METHOD(FollowUpOfReplacedSyncIsIgnored) {
    int64_t offset = 0;
    s.Sync(SyncMsg(5, true), LocalSystemTime(T2), nullptr);
    s.Sync(SyncMsg(6, true), LocalSystemTime(T2 + 1000000000), nullptr);
    Assert::IsFalse(s.SyncFollowUp(FollowUpMsg(5, T1), &offset));
  }

  TEST_METHOD(RepeatedFollowUpIsIgnored) {
    int64_t offset = 0;
    s.Sync(SyncMsg(5, true), LocalSystemTime(T2), nullptr);
    Assert::IsTrue(s.SyncFollowUp(FollowUpMsg(5, T1), &offset));
    Assert::IsFalse(s.SyncFollowUp(FollowUpMsg(5, T1), &offset));
  }

  TEST_METHOD(FollowUpWithoutSyncIsIgnored) {
    int64_t offset = 0;
    Assert::IsFalse(s.SyncFollowUp(FollowUpMsg(0, T1), &offset));
  }

  //delay request-response: offset = ((t1 - t2) + (t4 - t3)) / 2, path delay cancels

  TEST_METHOD(DelayResponseAfterOneStepSync) {
    s.Sync(SyncMsg(1, false, T1), LocalSystemTime(T2), nullptr);
    int64_t offset = 0;
    Assert::IsTrue(s.DelayRequestRx(DelayRequest(T3, T4), offset));
    Assert::AreEqual(OFFSET, offset);
  }

  TEST_METHOD(DelayResponseAfterTwoStepSync) {
    s.Sync(SyncMsg(1, true), LocalSystemTime(T2), nullptr);
    s.SyncFollowUp(FollowUpMsg(1, T1), nullptr);
    int64_t offset = 0;
    Assert::IsTrue(s.DelayRequestRx(DelayRequest(T3, T4), offset));
    Assert::AreEqual(OFFSET, offset);
  }

  TEST_METHOD(PositiveOffset) {
    const int64_t offset_true = 7300;
    uint64_t t2 = T1 + DELAY - offset_true;
    uint64_t t3 = t2 + 5000000;
    uint64_t t4 = t3 + offset_true + DELAY;
    s.Sync(SyncMsg(1, false, T1), LocalSystemTime(t2), nullptr);
    int64_t offset = 0;
    Assert::IsTrue(s.DelayRequestRx(DelayRequest(t3, t4), offset));
    Assert::AreEqual(offset_true, offset);
  }

  TEST_METHOD(SyncCanServeSeveralDelayResponses) {
    s.Sync(SyncMsg(1, false, T1), LocalSystemTime(T2), nullptr);
    int64_t offset = 0;
    Assert::IsTrue(s.DelayRequestRx(DelayRequest(T3, T4), offset));
    Assert::IsTrue(s.DelayRequestRx(DelayRequest(T3 + 1000000, T4 + 1000000), offset));
    Assert::AreEqual(OFFSET, offset);
  }

  TEST_METHOD(DelayResponseWithoutSyncIsIgnored) {
    int64_t offset = 0;
    Assert::IsFalse(s.DelayRequestRx(DelayRequest(T3, T4), offset));
  }

  TEST_METHOD(DelayResponseWhileWaitingForFollowUpIsIgnored) {
    s.Sync(SyncMsg(1, true), LocalSystemTime(T2), nullptr);
    int64_t offset = 0;
    Assert::IsFalse(s.DelayRequestRx(DelayRequest(T3, T4), offset));
  }

  TEST_METHOD(DelayResponseWithoutRequestIsIgnored) {
    s.Sync(SyncMsg(1, false, T1), LocalSystemTime(T2), nullptr);
    PtpMessage r = Msg(EMessageType::Delay_Resp, s.dr_seq_id);
    r.Message.Delay_Resp.receiveTimestamp = Ts(T4);
    r.Message.Delay_Resp.requestingPortIdentity = Port(1);
    int64_t offset = 0;
    Assert::IsFalse(s.DelayRequestRx(r, offset));
  }

  TEST_METHOD(DelayResponseWithWrongSequenceIsIgnored) {
    s.Sync(SyncMsg(1, false, T1), LocalSystemTime(T2), nullptr);
    PtpMessage r = DelayRequest(T3, T4);
    r.Header.sequenceId++;
    int64_t offset = 0;
    Assert::IsFalse(s.DelayRequestRx(r, offset));
  }

  TEST_METHOD(DelayResponseForAnotherPortIsIgnored) {
    s.Sync(SyncMsg(1, false, T1), LocalSystemTime(T2), nullptr);
    PtpMessage r = DelayRequest(T3, T4);
    r.Message.Delay_Resp.requestingPortIdentity.portNumber = 2;
    int64_t offset = 0;
    Assert::IsFalse(s.DelayRequestRx(r, offset));
  }

  TEST_METHOD(DelayResponseForAnotherClockIsIgnored) {
    //for example the reply to a Delay_Req from another client on the same multicast group
    s.Sync(SyncMsg(1, false, T1), LocalSystemTime(T2), nullptr);
    PtpMessage r = DelayRequest(T3, T4);
    r.Message.Delay_Resp.requestingPortIdentity.clockIdentity ^= 1;
    int64_t offset = 0;
    Assert::IsFalse(s.DelayRequestRx(r, offset));
  }

  //messages from two masters are never combined

  TEST_METHOD(FollowUpFromAnotherMasterIsIgnored) {
    PtpMessage sync = SyncMsg(1, true);
    sync.Header.sourcePortIdentity = Port(1);
    s.Sync(sync, LocalSystemTime(T2), nullptr);
    PtpMessage fu = FollowUpMsg(1, T1);
    fu.Header.sourcePortIdentity = Port(2);
    int64_t offset = 0;
    Assert::IsFalse(s.SyncFollowUp(fu, &offset));
    fu.Header.sourcePortIdentity = Port(1);
    Assert::IsTrue(s.SyncFollowUp(fu, &offset));
  }

  TEST_METHOD(DelayResponseFromAnotherMasterIsIgnored) {
    PtpMessage sync = SyncMsg(1, false, T1);
    sync.Header.sourcePortIdentity = Port(7);
    s.Sync(sync, LocalSystemTime(T2), nullptr);
    PtpMessage r = DelayRequest(T3, T4);
    r.Header.sourcePortIdentity = Port(8);
    int64_t offset = 0;
    Assert::IsFalse(s.DelayRequestRx(r, offset));
    r.Header.sourcePortIdentity = Port(7);
    Assert::IsTrue(s.DelayRequestRx(r, offset));
    Assert::AreEqual(OFFSET, offset);
  }

  TEST_METHOD(ResetForgetsSync) {
    s.Sync(SyncMsg(1, false, T1), LocalSystemTime(T2), nullptr);
    s.Reset();
    int64_t offset = 0;
    Assert::IsFalse(s.DelayRequestRx(DelayRequest(T3, T4), offset));
    Assert::IsFalse(s.SyncFollowUp(FollowUpMsg(0, T1), &offset));
  }

  TEST_METHOD(SequenceIdIncrementsAndWraps) {
    s.dr_seq_id = 0xFFFE;
    Assert::AreEqual((uint16_t)0xFFFF, _byteswap_ushort(s.GetDelayRequestSequenceId()));
    Assert::AreEqual((uint16_t)0x0000, _byteswap_ushort(s.GetDelayRequestSequenceId()));
    Assert::AreEqual((uint16_t)0x0001, _byteswap_ushort(s.GetDelayRequestSequenceId()));
  }

  //hardware transmit timestamps: t3 can arrive after the Delay_Resp

  //sends a Delay_Req without giving t3 and returns its sequence id and response
  uint16_t DelayRequestNoT3(uint64_t T4Ns, PtpMessage& out_Response) {
    uint16_t seq = _byteswap_ushort(s.GetDelayRequestSequenceId());
    out_Response = Msg(EMessageType::Delay_Resp, seq);
    out_Response.Message.Delay_Resp.receiveTimestamp = Ts(T4Ns);
    out_Response.Message.Delay_Resp.requestingPortIdentity = Port(1);
    return seq;
  }

  TEST_METHOD(LateT3CompletesExchange) {
    s.Sync(SyncMsg(1, false, T1), LocalSystemTime(T2), nullptr);
    PtpMessage r;
    uint16_t seq = DelayRequestNoT3(T4, r);
    int64_t offset = 0;
    Assert::IsFalse(s.DelayRequestRx(r, offset));
    Assert::IsTrue(s.DelayRequestTx(seq, LocalSystemTime(T3), offset));
    Assert::AreEqual(OFFSET, offset);
  }

  TEST_METHOD(T3BeforeResponseDoesNotComplete) {
    s.Sync(SyncMsg(1, false, T1), LocalSystemTime(T2), nullptr);
    PtpMessage r;
    uint16_t seq = DelayRequestNoT3(T4, r);
    int64_t offset = 0;
    Assert::IsFalse(s.DelayRequestTx(seq, LocalSystemTime(T3), offset));
    Assert::IsTrue(s.DelayRequestRx(r, offset));
    Assert::AreEqual(OFFSET, offset);
  }

  TEST_METHOD(LateT3OfOlderRequestIsIgnored) {
    s.Sync(SyncMsg(1, false, T1), LocalSystemTime(T2), nullptr);
    PtpMessage r1, r2;
    uint16_t seq1 = DelayRequestNoT3(T4, r1);
    int64_t offset = 0;
    Assert::IsFalse(s.DelayRequestRx(r1, offset));
    DelayRequestNoT3(T4 + 1000000, r2);   //the next Delay_Req is sent before t3 of the first arrives
    Assert::IsFalse(s.DelayRequestTx(seq1, LocalSystemTime(T3), offset));
    Assert::IsFalse(s.DelayRequestRx(r1, offset));
  }

  TEST_METHOD(NewRequestForgetsT3) {
    //a response must never be combined with the t3 of an earlier request
    s.Sync(SyncMsg(1, false, T1), LocalSystemTime(T2), nullptr);
    DelayRequest(T3, T4);
    PtpMessage r;
    DelayRequestNoT3(T4 + 1000000, r);
    int64_t offset = 0;
    Assert::IsFalse(s.DelayRequestRx(r, offset));
  }

  TEST_METHOD(LateT3WaitsForFollowUp) {
    //the response is kept, but a Sync still waiting for its Follow_Up cannot complete it
    s.Sync(SyncMsg(1, true), LocalSystemTime(T2), nullptr);
    PtpMessage r;
    uint16_t seq = DelayRequestNoT3(T4, r);
    int64_t offset = 0;
    Assert::IsFalse(s.DelayRequestRx(r, offset));
    Assert::IsFalse(s.DelayRequestTx(seq, LocalSystemTime(T3), offset));
  }
};

}
