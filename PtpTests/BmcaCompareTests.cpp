#include "..\PtpUtil\Bmca.h"
#include "CppUnitTest.h"

#include "TestMessages.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;


/*
Data set comparison, IEEE 1588-2008 9.3.4.

Figure 27 (part 1) is used when the grandmaster identities differ: priority1, clockClass,
clockAccuracy, offsetScaledLogVariance, priority2, grandmasterIdentity, lower is better,
the first difference decides.

Figure 28 (part 2) is used when the grandmaster identity is the same: stepsRemoved, then
the identities of the receivers and senders.

The test names say which branch of which figure they cover.
*/

namespace PtpTests {

static const uint64_t LOCAL = 0x0000000000000050ULL;   //this provider's clock identity (receiver)

//a typical data set: grandmaster 0x10 announcing itself directly
static SBmcaDataset Ds(uint64_t Gm = 0x10) {
  SBmcaDataset d;
  ZeroMemory(&d, sizeof(d));
  d.Priority1 = 128;
  d.ClockClass = 248;
  d.ClockAccuracy = 0xFE;
  d.OffsetScaledLogVariance = 0xFFFF;
  d.Priority2 = 128;
  d.GrandmasterIdentity = WireId(Gm);
  d.StepsRemoved = 0;
  d.Sender = Pid(Gm, 1);
  d.Receiver = Pid(LOCAL, 1);
  return d;
}

static EBmcaResult Mirror(EBmcaResult R) {
  switch (R) {
  case EBmcaResult::ABetter: return EBmcaResult::BBetter;
  case EBmcaResult::BBetter: return EBmcaResult::ABetter;
  case EBmcaResult::ABetterByTopology: return EBmcaResult::BBetterByTopology;
  case EBmcaResult::BBetterByTopology: return EBmcaResult::ABetterByTopology;
  default: return R;
  }
}

static bool ABetterAtAll(EBmcaResult R) {
  return (R == EBmcaResult::ABetter) || (R == EBmcaResult::ABetterByTopology);
}

//checks Compare(A, B) == Expected and Compare(B, A) is its mirror image
static void Check(EBmcaResult Expected, const SBmcaDataset& A, const SBmcaDataset& B) {
  Assert::AreEqual(Expected, BmcaCompare(A, B));
  Assert::AreEqual(Mirror(Expected), BmcaCompare(B, A));
}

TEST_CLASS(BmcaIdentityOrder) {
public:
  TEST_METHOD(ClockIdentityComparedAsOctetsFirstMostSignificant) {
    //0x01 00.. is greater than 0x00 FF.. although its last octets are smaller
    Assert::IsTrue(CompareClockIdentity(WireId(0x0100000000000000ULL), WireId(0x00FFFFFFFFFFFFFFULL)) > 0);
    Assert::IsTrue(CompareClockIdentity(WireId(0x00000000000000FFULL), WireId(0x0000000000000100ULL)) < 0);
    Assert::AreEqual(0, CompareClockIdentity(WireId(0x1234), WireId(0x1234)));
  }

  TEST_METHOD(PortIdentityClockThenPortNumber) {
    Assert::IsTrue(ComparePortIdentity(Pid(1, 9), Pid(2, 1)) < 0);
    Assert::IsTrue(ComparePortIdentity(Pid(2, 1), Pid(2, 9)) < 0);
    Assert::IsTrue(ComparePortIdentity(Pid(2, 0x0100), Pid(2, 0x00FF)) > 0);
    Assert::AreEqual(0, ComparePortIdentity(Pid(2, 3), Pid(2, 3)));
  }
};

TEST_CLASS(BmcaFigure27) {
public:
  TEST_METHOD(Priority1LowerIsBetter) {
    SBmcaDataset a = Ds(0x10), b = Ds(0x20);
    a.Priority1 = 127;
    Check(EBmcaResult::ABetter, a, b);
  }

  TEST_METHOD(Priority1DecidesBeforeEverythingElse) {
    //A is worse on every later field, and has the higher grandmaster identity
    SBmcaDataset a = Ds(0x20), b = Ds(0x10);
    a.Priority1 = 127;
    a.ClockClass = 255; b.ClockClass = 6;
    a.ClockAccuracy = 0xFE; b.ClockAccuracy = 0x20;
    a.OffsetScaledLogVariance = 0xFFFF; b.OffsetScaledLogVariance = 0x0000;
    a.Priority2 = 255; b.Priority2 = 0;
    Check(EBmcaResult::ABetter, a, b);
  }

  TEST_METHOD(Priority1Extremes) {
    SBmcaDataset a = Ds(0x10), b = Ds(0x20);
    a.Priority1 = 0; b.Priority1 = 255;
    Check(EBmcaResult::ABetter, a, b);
  }

  TEST_METHOD(ClockClassDecidesWhenPriority1Equal) {
    SBmcaDataset a = Ds(0x20), b = Ds(0x10);
    a.ClockClass = 6; b.ClockClass = 7;
    a.ClockAccuracy = 0xFE; b.ClockAccuracy = 0x20;
    a.OffsetScaledLogVariance = 0xFFFF; b.OffsetScaledLogVariance = 0;
    a.Priority2 = 255; b.Priority2 = 0;
    Check(EBmcaResult::ABetter, a, b);
  }

  TEST_METHOD(ClockClassExtremes) {
    SBmcaDataset a = Ds(0x10), b = Ds(0x20);
    a.ClockClass = 0; b.ClockClass = 255;
    Check(EBmcaResult::ABetter, a, b);
  }

  TEST_METHOD(ClockAccuracyDecidesWhenClassEqual) {
    SBmcaDataset a = Ds(0x20), b = Ds(0x10);
    a.ClockClass = b.ClockClass = 6;
    a.ClockAccuracy = 0x21; b.ClockAccuracy = 0x22;
    a.OffsetScaledLogVariance = 0xFFFF; b.OffsetScaledLogVariance = 0;
    a.Priority2 = 255; b.Priority2 = 0;
    Check(EBmcaResult::ABetter, a, b);
  }

  TEST_METHOD(VarianceDecidesWhenAccuracyEqual) {
    SBmcaDataset a = Ds(0x20), b = Ds(0x10);
    a.OffsetScaledLogVariance = 0x4E5D; b.OffsetScaledLogVariance = 0x4E5E;
    a.Priority2 = 255; b.Priority2 = 0;
    Check(EBmcaResult::ABetter, a, b);
  }

  TEST_METHOD(VarianceComparedAsSixteenBits) {
    //a byte-wise comparison of the low octet would get this wrong
    SBmcaDataset a = Ds(0x10), b = Ds(0x20);
    a.OffsetScaledLogVariance = 0x00FF; b.OffsetScaledLogVariance = 0x0100;
    Check(EBmcaResult::ABetter, a, b);
    a.OffsetScaledLogVariance = 0xFFFF; b.OffsetScaledLogVariance = 0xFFFE;
    Check(EBmcaResult::BBetter, a, b);
  }

  TEST_METHOD(Priority2DecidesWhenVarianceEqual) {
    SBmcaDataset a = Ds(0x20), b = Ds(0x10);
    a.Priority2 = 127; b.Priority2 = 128;
    Check(EBmcaResult::ABetter, a, b);
  }

  TEST_METHOD(GrandmasterIdentityIsTheLastTieBreak) {
    SBmcaDataset a = Ds(0x10), b = Ds(0x20);
    Check(EBmcaResult::ABetter, a, b);
  }

  TEST_METHOD(GrandmasterIdentityOctetOrder) {
    SBmcaDataset a = Ds(0x00FFFFFFFFFFFFFFULL), b = Ds(0x0100000000000000ULL);
    Check(EBmcaResult::ABetter, a, b);
  }

  TEST_METHOD(StepsRemovedIgnoredWhenGrandmastersDiffer) {
    //A is many steps away but its grandmaster is better
    SBmcaDataset a = Ds(0x10), b = Ds(0x20);
    a.Priority2 = 127;
    a.StepsRemoved = 10;
    a.Sender = Pid(0x99, 1);
    Check(EBmcaResult::ABetter, a, b);
  }

  TEST_METHOD(SenderIgnoredWhenGrandmastersDiffer) {
    SBmcaDataset a = Ds(0x10), b = Ds(0x20);
    a.Sender = Pid(0xFFFF, 0xFFFF);
    b.Sender = Pid(0x0001, 1);
    Check(EBmcaResult::ABetter, a, b);
  }
};

TEST_CLASS(BmcaFigure28) {
  //the same grandmaster 0x10 heard through two different senders
  static SBmcaDataset Path(uint16_t Steps, uint64_t Sender, uint16_t SenderPort = 1) {
    SBmcaDataset d = Ds(0x10);
    d.StepsRemoved = Steps;
    d.Sender = Pid(Sender, SenderPort);
    return d;
  }

public:
  TEST_METHOD(AMoreThanOneStepFurtherBBetter) {
    Check(EBmcaResult::BBetter, Path(3, 0x30), Path(1, 0x40));
  }

  TEST_METHOD(BMoreThanOneStepFurtherABetter) {
    Check(EBmcaResult::ABetter, Path(1, 0x40), Path(3, 0x30));
  }

  TEST_METHOD(AOneStepFurtherReceiverBelowSenderBBetter) {
    //receiver of A (LOCAL 0x50) < sender of A (0x60)
    Check(EBmcaResult::BBetter, Path(2, 0x60), Path(1, 0x40));
  }

  TEST_METHOD(AOneStepFurtherReceiverAboveSenderBBetterByTopology) {
    //receiver of A (LOCAL 0x50) > sender of A (0x30)
    Check(EBmcaResult::BBetterByTopology, Path(2, 0x30), Path(1, 0x40));
  }

  TEST_METHOD(AOneStepFurtherSentByReceiverError1) {
    //A was sent by the port that received it
    SBmcaDataset a = Path(2, LOCAL, 1);
    Assert::AreEqual(EBmcaResult::Error1, BmcaCompare(a, Path(1, 0x40)));
  }

  TEST_METHOD(BOneStepFurtherReceiverBelowSenderABetter) {
    Assert::AreEqual(EBmcaResult::ABetter, BmcaCompare(Path(1, 0x40), Path(2, 0x60)));
  }

  TEST_METHOD(BOneStepFurtherReceiverAboveSenderABetterByTopology) {
    Assert::AreEqual(EBmcaResult::ABetterByTopology, BmcaCompare(Path(1, 0x40), Path(2, 0x30)));
  }

  TEST_METHOD(BOneStepFurtherSentByReceiverError1) {
    Assert::AreEqual(EBmcaResult::Error1, BmcaCompare(Path(1, 0x40), Path(2, LOCAL, 1)));
  }

  TEST_METHOD(ReceiverComparedWithSenderUsingPortNumber) {
    //sender has our clock identity but another port number: not an error
    Assert::AreEqual(EBmcaResult::BBetterByTopology, BmcaCompare(Path(2, LOCAL, 0), Path(1, 0x40)));
    Assert::AreEqual(EBmcaResult::BBetter, BmcaCompare(Path(2, LOCAL, 2), Path(1, 0x40)));
  }

  TEST_METHOD(EqualStepsLowerSenderBetterByTopology) {
    Check(EBmcaResult::ABetterByTopology, Path(1, 0x30), Path(1, 0x40));
  }

  TEST_METHOD(EqualStepsSameSenderClockLowerPortBetterByTopology) {
    Check(EBmcaResult::ABetterByTopology, Path(1, 0x30, 1), Path(1, 0x30, 2));
  }

  TEST_METHOD(EqualStepsSameSenderLowerReceiverPortBetterByTopology) {
    SBmcaDataset a = Path(1, 0x30), b = Path(1, 0x30);
    a.Receiver.portNumber = 1;
    b.Receiver.portNumber = 2;
    Check(EBmcaResult::ABetterByTopology, a, b);
  }

  TEST_METHOD(SameSenderSameReceiverError2) {
    Assert::AreEqual(EBmcaResult::Error2, BmcaCompare(Path(1, 0x30), Path(1, 0x30)));
  }

  TEST_METHOD(StepsCompareWithoutOverflowAt65535) {
    Check(EBmcaResult::BBetter, Path(0xFFFF, 0x30), Path(0xFFFD, 0x40));
    Check(EBmcaResult::BBetterByTopology, Path(0xFFFF, 0x30), Path(0xFFFE, 0x40));
  }

  TEST_METHOD(QualityFieldsNotComparedWhenGrandmasterSame) {
    //the standard goes straight to figure 28 when the grandmaster identity is the same.
    //(In practice the fields are the same: they describe the same clock.)
    SBmcaDataset a = Path(2, 0x30), b = Path(0, 0x10);
    a.Priority1 = 0;
    Check(EBmcaResult::BBetter, a, b);
  }
};

/*
Properties over a generated set of data sets. The grandmaster attributes are a function of the
grandmaster identity, as they are in a real network (they describe that clock).
*/
TEST_CLASS(BmcaProperties) {
  static std::vector<SBmcaDataset> Generate() {
    struct Gm { uint64_t Id; uint8_t P1; uint8_t Class; uint8_t Acc; uint16_t Var; uint8_t P2; };
    const Gm gms[] = {
      { 0x10, 128, 6,   0x21, 0x4E5D, 128 },
      { 0x20, 128, 6,   0x21, 0x4E5D, 128 },   //ties with 0x10 on everything but identity
      { 0x08, 128, 6,   0x21, 0x4E5D, 129 },   //loses to both on priority2
      { 0x30, 128, 7,   0x21, 0x4E5D, 0 },     //holdover
      { 0x40, 127, 248, 0xFE, 0xFFFF, 255 },   //free-running but priority1 127
    };
    const uint64_t senders[] = { 0x01, 0x60, LOCAL };
    std::vector<SBmcaDataset> out;
    for (const Gm& g : gms)
      for (uint16_t steps : { 0, 1, 2, 3 })
        for (uint64_t sender : senders)
          for (uint16_t port : { 1, 2 }) {
            SBmcaDataset d;
            ZeroMemory(&d, sizeof(d));
            d.Priority1 = g.P1; d.ClockClass = g.Class; d.ClockAccuracy = g.Acc;
            d.OffsetScaledLogVariance = g.Var; d.Priority2 = g.P2;
            d.GrandmasterIdentity = WireId(g.Id);
            d.StepsRemoved = steps;
            d.Sender = Pid(sender, port);
            d.Receiver = Pid(LOCAL, 1);
            out.push_back(d);
          }
    return out;
  }

  static bool IsError(EBmcaResult R) {
    return (R == EBmcaResult::Error1) || (R == EBmcaResult::Error2);
  }

  //Error1 means the message came from our own port: such messages never reach the comparison
  static bool FromSelf(const SBmcaDataset& D) {
    return D.Sender.clockIdentity == D.Receiver.clockIdentity;
  }

public:
  TEST_METHOD(Antisymmetric) {
    auto all = Generate();
    for (const auto& a : all)
      for (const auto& b : all)
        Assert::AreEqual(Mirror(BmcaCompare(a, b)), BmcaCompare(b, a));
  }

  TEST_METHOD(Error2OnlyForIdenticalSenderAndReceiver) {
    auto all = Generate();
    for (const auto& a : all)
      for (const auto& b : all) {
        bool same = (a.Sender == b.Sender) && (a.Receiver == b.Receiver) &&
                    (a.GrandmasterIdentity == b.GrandmasterIdentity) && (a.StepsRemoved == b.StepsRemoved);
        Assert::AreEqual(same, BmcaCompare(a, b) == EBmcaResult::Error2);
      }
  }

  TEST_METHOD(Transitive) {
    //"better" must be a strict order for the selection of the best master to be well defined
    std::vector<SBmcaDataset> all;
    for (const auto& d : Generate())
      if (!FromSelf(d))
        all.push_back(d);
    for (const auto& a : all)
      for (const auto& b : all) {
        EBmcaResult ab = BmcaCompare(a, b);
        if (IsError(ab) || !ABetterAtAll(ab))
          continue;
        for (const auto& c : all) {
          EBmcaResult bc = BmcaCompare(b, c);
          if (IsError(bc) || !ABetterAtAll(bc))
            continue;
          Assert::IsTrue(ABetterAtAll(BmcaCompare(a, c)));
        }
      }
  }
};

}
