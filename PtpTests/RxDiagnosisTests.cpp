#include "..\PtpUtil\MessagePath.h"
#include "CppUnitTest.h"

#include "TestMessages.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

/*
CRxDiagnosis: telling the user that PTP traffic is arriving but none of it can be used.
Found in testing: with domain 0 configured on a domain 127 network, the provider
reopened its sockets every minute with "no PTP messages" and never said why.
*/

namespace PtpTests {

static ULONGLONG g_diag_now;
static ULONGLONG WINAPI DiagTick() { return g_diag_now; }

static CMessagePath::SOutcome Outcome(CMessagePath::EResult Result, uint8_t Domain = 0) {
  CMessagePath::SOutcome o;
  ZeroMemory(&o, sizeof(o));
  o.Result = Result;
  o.Domain = Domain;
  return o;
}

TEST_CLASS(RxDiagnosis) {
  CRxDiagnosis d;
  CRxDiagnosis::SDetail detail;

  CRxDiagnosis::EReport Check() { return d.Check(detail); }

  //feeds an outcome every 250 ms for Ms milliseconds
  void Run(CMessagePath::EResult Result, ULONGLONG Ms, uint8_t Domain = 0, DWORD From = 0) {
    for (ULONGLONG t = 0; t < Ms; t += 250) {
      g_diag_now += 250;
      d.OnOutcome(Outcome(Result, Domain), From);
    }
  }

public:
  TEST_METHOD_INITIALIZE(Init) {
    g_diag_now = 1000000;
    d.SetTickSource(DiagTick);
    d.Reset();
  }

  TEST_METHOD(UsableTrafficReportsNothing) {
    for (int i = 0; i < 10; ++i) {
      Run(CMessagePath::EResult::Accepted, 5000);
      Assert::AreEqual(CRxDiagnosis::EReport::None, Check());
    }
  }

  TEST_METHOD(NotSelectedCountsAsUsable) {
    //right domain and address, master not (yet) selected: the BMCA log covers that
    Run(CMessagePath::EResult::NotSelected, 30000);
    Assert::AreEqual(CRxDiagnosis::EReport::None, Check());
  }

  TEST_METHOD(WrongDomainReportedAfterGracePeriod) {
    Run(CMessagePath::EResult::WrongDomain, 9750, 127);
    Assert::AreEqual(CRxDiagnosis::EReport::None, Check());
    Run(CMessagePath::EResult::WrongDomain, 500, 127);
    Assert::AreEqual(CRxDiagnosis::EReport::WrongDomain, Check());
    Assert::IsTrue(detail.Domains[127]);
    Assert::IsFalse(detail.Domains[0]);
  }

  TEST_METHOD(WrongDomainReportedOnce) {
    Run(CMessagePath::EResult::WrongDomain, 11000, 127);
    Assert::AreEqual(CRxDiagnosis::EReport::WrongDomain, Check());
    for (int i = 0; i < 20; ++i) {
      Run(CMessagePath::EResult::WrongDomain, 5000, 127);
      Assert::AreEqual(CRxDiagnosis::EReport::None, Check());
    }
  }

  TEST_METHOD(AllDomainsSeenAreListed) {
    for (int i = 0; i < 50; ++i) {
      g_diag_now += 250;
      d.OnOutcome(Outcome(CMessagePath::EResult::WrongDomain, 127), 0);
      d.OnOutcome(Outcome(CMessagePath::EResult::WrongDomain, 24), 0);
    }
    Assert::AreEqual(CRxDiagnosis::EReport::WrongDomain, Check());
    Assert::IsTrue(detail.Domains[24]);
    Assert::IsTrue(detail.Domains[127]);
    int count = 0;
    for (bool b : detail.Domains)
      count += b ? 1 : 0;
    Assert::AreEqual(2, count);
  }

  TEST_METHOD(OldDomainsNotListed) {
    Run(CMessagePath::EResult::WrongDomain, 1000, 5);
    Run(CMessagePath::EResult::WrongDomain, 11000, 127);
    Assert::AreEqual(CRxDiagnosis::EReport::WrongDomain, Check());
    Assert::IsTrue(detail.Domains[127]);
    Assert::IsFalse(detail.Domains[5]);
  }

  TEST_METHOD(ResumedReportedAfterAProblem) {
    Run(CMessagePath::EResult::WrongDomain, 11000, 127);
    Assert::AreEqual(CRxDiagnosis::EReport::WrongDomain, Check());
    Run(CMessagePath::EResult::Accepted, 250);
    Assert::AreEqual(CRxDiagnosis::EReport::Resumed, Check());
    Assert::AreEqual(CRxDiagnosis::EReport::None, Check());
  }

  TEST_METHOD(UsableTrafficAmongWrongDomainIsFine) {
    //two domains on the network, one of them ours
    for (int i = 0; i < 200; ++i) {
      g_diag_now += 250;
      d.OnOutcome(Outcome(CMessagePath::EResult::WrongDomain, 127), 0);
      d.OnOutcome(Outcome(CMessagePath::EResult::Accepted, 0), 0);
      Assert::AreEqual(CRxDiagnosis::EReport::None, Check());
    }
  }

  TEST_METHOD(WrongSourceReported) {
    Run(CMessagePath::EResult::WrongSource, 11000, 0, Ip(10, 218, 10, 2));
    Assert::AreEqual(CRxDiagnosis::EReport::WrongSource, Check());
    Assert::AreEqual((unsigned int)Ip(10, 218, 10, 2), (unsigned int)detail.OtherAddress);
    Assert::AreEqual(CRxDiagnosis::EReport::None, Check());
  }

  TEST_METHOD(WrongDomainTakesPrecedenceOverWrongSource) {
    //the pinned master is there but in another domain: the domain is the thing to fix
    for (int i = 0; i < 50; ++i) {
      g_diag_now += 250;
      d.OnOutcome(Outcome(CMessagePath::EResult::WrongSource), Ip(10, 0, 0, 9));
      d.OnOutcome(Outcome(CMessagePath::EResult::WrongDomain, 127), Ip(10, 0, 0, 1));
    }
    Assert::AreEqual(CRxDiagnosis::EReport::WrongDomain, Check());
  }

  TEST_METHOD(SilenceReportsNothing) {
    //no traffic at all is reported by the message loops, not here
    g_diag_now += 60000;
    Assert::AreEqual(CRxDiagnosis::EReport::None, Check());
  }

  TEST_METHOD(ResumedAfterSilenceFollowingAProblem) {
    Run(CMessagePath::EResult::WrongDomain, 11000, 127);
    Assert::AreEqual(CRxDiagnosis::EReport::WrongDomain, Check());
    g_diag_now += 60000;
    Assert::AreEqual(CRxDiagnosis::EReport::None, Check());
    Run(CMessagePath::EResult::Accepted, 250);
    Assert::AreEqual(CRxDiagnosis::EReport::Resumed, Check());
  }

  TEST_METHOD(IgnoredMessagesDoNotCount) {
    Run(CMessagePath::EResult::Ignored, 30000);
    Assert::AreEqual(CRxDiagnosis::EReport::None, Check());
  }

  TEST_METHOD(ResetStartsAGracePeriod) {
    Run(CMessagePath::EResult::WrongDomain, 11000, 127);
    d.Reset();
    Assert::AreEqual(CRxDiagnosis::EReport::None, Check());
    Run(CMessagePath::EResult::WrongDomain, 11000, 127);
    Assert::AreEqual(CRxDiagnosis::EReport::WrongDomain, Check());
  }
};

}
