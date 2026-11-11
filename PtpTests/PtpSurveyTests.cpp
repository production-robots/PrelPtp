#include "..\PtpUtil\PtpMonitor.h"
#include "CppUnitTest.h"

#include "TestMessages.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

/*
CPtpSurvey: what the setup program's adapter list shows. Masters announce once a second
unless a test says otherwise.
*/

namespace PtpTests {

static ULONGLONG g_survey_now;
static ULONGLONG WINAPI SurveyTick() { return g_survey_now; }

TEST_CLASS(PtpSurvey) {
  CPtpSurvey s;

  bool Hear(int Adapter, TestMaster& M) {
    Received r = M.Announce();
    return s.OnMessage(Adapter, &r.Msg, r.Size, M.Address);
  }

  CPtpSurvey::SSummary Summary(int Adapter) {
    CPtpSurvey::SSummary out;
    s.GetSummary(Adapter, out);
    return out;
  }

public:
  TEST_METHOD_INITIALIZE(Init) {
    g_survey_now = 1000000;
    s.SetTickSource(SurveyTick);
  }

  TEST_METHOD(NothingHeard) {
    Assert::AreEqual(0, Summary(0).DomainCount);
    Assert::AreEqual(-1, s.BestAdapter());
  }

  TEST_METHOD(FirstAnnounceShowsDomain) {
    TestMaster m(0x10, Ip(10, 0, 0, 1));
    m.Domain = 127;
    Assert::IsTrue(Hear(0, m));
    auto sum = Summary(0);
    Assert::AreEqual(1, sum.DomainCount);
    Assert::AreEqual((uint8_t)127, sum.Domains[0].Domain);
    Assert::IsFalse(sum.Domains[0].HaveMaster);
  }

  TEST_METHOD(SecondAnnounceSelectsMaster) {
    TestMaster m(0x10, Ip(10, 0, 0, 1));
    Hear(0, m);
    g_survey_now += 1000;
    Assert::IsTrue(Hear(0, m));
    auto sum = Summary(0);
    Assert::IsTrue(sum.Domains[0].HaveMaster);
    Assert::IsTrue(sum.Domains[0].Master.Dataset.Sender == Pid(0x10, 1));
    Assert::AreEqual((unsigned int)Ip(10, 0, 0, 1), (unsigned int)sum.Domains[0].Master.Address);
  }

  TEST_METHOD(RepeatedAnnounceIsNoChange) {
    TestMaster m(0x10, Ip(10, 0, 0, 1));
    Hear(0, m);
    g_survey_now += 1000;
    Hear(0, m);
    for (int i = 0; i < 5; ++i) {
      g_survey_now += 1000;
      Assert::IsFalse(Hear(0, m));
      Assert::IsFalse(s.Tick());
    }
  }

  TEST_METHOD(ChangeOfClassIsAChange) {
    TestMaster m(0x10, Ip(10, 0, 0, 1));
    Hear(0, m);
    g_survey_now += 1000;
    Hear(0, m);
    m.ClockClass = 7;
    g_survey_now += 1000;
    Assert::IsTrue(Hear(0, m));
  }

  TEST_METHOD(OnlyAnnounceCounts) {
    TestMaster m(0x10, Ip(10, 0, 0, 1));
    Received sync = m.Sync(1, true);
    Received follow_up = m.FollowUp(1, 0);
    Assert::IsFalse(s.OnMessage(0, &sync.Msg, sync.Size, m.Address));
    Assert::IsFalse(s.OnMessage(0, &follow_up.Msg, follow_up.Size, m.Address));
    Assert::AreEqual(0, Summary(0).DomainCount);
  }

  TEST_METHOD(ShortMessageIgnored) {
    TestMaster m(0x10, Ip(10, 0, 0, 1));
    Received r = m.Announce();
    Assert::IsFalse(s.OnMessage(0, &r.Msg, r.Size - 1, m.Address));
    Assert::AreEqual(0, Summary(0).DomainCount);
  }

  TEST_METHOD(BadAdapterIndexIgnored) {
    TestMaster m(0x10, Ip(10, 0, 0, 1));
    Assert::IsFalse(Hear(-1, m));
    Assert::IsFalse(Hear(CPtpSurvey::MAX_ADAPTERS, m));
  }

  TEST_METHOD(DomainsListedLowestFirst) {
    TestMaster a(0x10, Ip(10, 0, 0, 1));
    TestMaster b(0x20, Ip(10, 0, 0, 2));
    a.Domain = 127;
    b.Domain = 0;
    Hear(0, a);
    Hear(0, b);
    auto sum = Summary(0);
    Assert::AreEqual(2, sum.DomainCount);
    Assert::AreEqual((uint8_t)0, sum.Domains[0].Domain);
    Assert::AreEqual((uint8_t)127, sum.Domains[1].Domain);
  }

  TEST_METHOD(BestMasterPerDomain) {
    TestMaster a(0x10, Ip(10, 0, 0, 1));
    TestMaster b(0x20, Ip(10, 0, 0, 2));
    b.Priority1 = 100;
    Hear(0, a); Hear(0, b);
    g_survey_now += 1000;
    Hear(0, a); Hear(0, b);
    auto sum = Summary(0);
    Assert::AreEqual(1, sum.DomainCount);
    Assert::IsTrue(sum.Domains[0].Master.Dataset.Sender == Pid(0x20, 1));
  }

  TEST_METHOD(AdaptersKeptApart) {
    TestMaster a(0x10, Ip(10, 0, 0, 1));
    TestMaster b(0x20, Ip(10, 0, 1, 1));
    b.Domain = 5;
    Hear(0, a);
    Hear(3, b);
    Assert::AreEqual((uint8_t)0, Summary(0).Domains[0].Domain);
    Assert::AreEqual((uint8_t)5, Summary(3).Domains[0].Domain);
    Assert::AreEqual(0, Summary(1).DomainCount);
  }

  TEST_METHOD(SilentMasterExpires) {
    TestMaster m(0x10, Ip(10, 0, 0, 1));
    Hear(0, m);
    g_survey_now += 1000;
    Hear(0, m);
    g_survey_now += 3000;
    Assert::IsFalse(s.Tick());
    g_survey_now += 1;
    Assert::IsTrue(s.Tick());
    Assert::AreEqual(0, Summary(0).DomainCount);
    Assert::IsFalse(s.Tick());
  }

  TEST_METHOD(ExpiredSlotsAreReused) {
    //more adapter/domain pairs over time than there are slots
    for (int round = 0; round < 3; ++round) {
      for (int d = 0; d < CPtpSurvey::MAX_SLOTS; ++d) {
        TestMaster m(0x100 + d, Ip(10, 0, 0, 1));
        m.Domain = (uint8_t)d;
        Hear(d % CPtpSurvey::MAX_ADAPTERS, m);
      }
      g_survey_now += 10000;
      s.Tick();
    }
    TestMaster m(0x10, Ip(10, 0, 0, 1));
    Assert::IsTrue(Hear(0, m));
  }

  TEST_METHOD(AtMostMaxDomainsListed) {
    for (int d = 0; d < CPtpSurvey::MAX_DOMAINS + 2; ++d) {
      TestMaster m(0x100 + d, Ip(10, 0, 0, 1));
      m.Domain = (uint8_t)d;
      Hear(0, m);
    }
    Assert::AreEqual(CPtpSurvey::MAX_DOMAINS, Summary(0).DomainCount);
  }

  //which adapter to pre-select

  TEST_METHOD(BestAdapterNeedsAQualifiedMaster) {
    TestMaster m(0x10, Ip(10, 0, 0, 1));
    Hear(2, m);
    Assert::AreEqual(-1, s.BestAdapter());
    g_survey_now += 1000;
    Hear(2, m);
    Assert::AreEqual(2, s.BestAdapter());
  }

  TEST_METHOD(BestAdapterHasTheBestMaster) {
    TestMaster ordinary(0x10, Ip(10, 0, 0, 1));
    TestMaster better(0x20, Ip(10, 0, 1, 1));
    better.Priority1 = 100;
    Hear(0, ordinary); Hear(1, better);
    g_survey_now += 1000;
    Hear(0, ordinary); Hear(1, better);
    Assert::AreEqual(1, s.BestAdapter());
  }

  TEST_METHOD(BestAdapterInTheLab) {
    //the test lab: the same boundary clock and grandmaster on both networks, port 34 on one
    //adapter and port 19 on the other. Equal on everything but the port: the lower port wins.
    TestMaster port34(0x506B4BFFFE9D5DC8ULL, Ip(10, 218, 1, 2));
    TestMaster port19(0x506B4BFFFE9D5DC8ULL, Ip(10, 218, 10, 2));
    port34.Port = 34;
    port19.Port = 19;
    for (TestMaster* m : { &port34, &port19 }) {
      m->Gm = 0xD0A4B1FFFE00058AULL;
      m->StepsRemoved = 1;
      m->Domain = 127;
      m->LogAnnounceInterval = (uint8_t)-2;
    }
    Hear(0, port34); Hear(1, port19);
    g_survey_now += 250;
    Hear(0, port34); Hear(1, port19);
    Assert::AreEqual(1, s.BestAdapter());
  }

  TEST_METHOD(HeardFromAnyMasterNotOnlyTheBest) {
    //a pinned master is checked by address: it need not be the one the BMCA prefers
    TestMaster best(0x10, Ip(10, 0, 0, 1));
    TestMaster other(0x20, Ip(10, 0, 0, 2));
    best.Priority1 = 100;
    Hear(0, best); Hear(0, other);
    Assert::IsTrue(s.HeardFrom(0, Ip(10, 0, 0, 1)));
    Assert::IsTrue(s.HeardFrom(0, Ip(10, 0, 0, 2)), L"after one Announce, before it qualifies");
    Assert::IsFalse(s.HeardFrom(0, Ip(10, 0, 0, 3)));
    Assert::IsFalse(s.HeardFrom(1, Ip(10, 0, 0, 1)), L"another adapter");
  }

  TEST_METHOD(HeardFromInAnyDomain) {
    TestMaster m(0x10, Ip(10, 0, 0, 1));
    m.Domain = 44;
    Hear(2, m);
    Assert::IsTrue(s.HeardFrom(2, Ip(10, 0, 0, 1)));
  }

  TEST_METHOD(HeardFromEndsWhenAnnouncesStop) {
    TestMaster m(0x10, Ip(10, 0, 0, 1));
    Hear(0, m);
    g_survey_now += 1000;
    Hear(0, m);
    g_survey_now += 10000;
    s.Tick();
    Assert::IsFalse(s.HeardFrom(0, Ip(10, 0, 0, 1)));
  }
};

}
