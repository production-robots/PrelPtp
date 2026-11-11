#include "..\PtpUtil\Validation.h"
#include "CppUnitTest.h"
#include <strsafe.h>

#include "TestMessages.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

/*
ValidateConfiguration: the setup program's checks before anything is saved.
Each test starts from a configuration that passes with no issues at all and changes one thing.
*/

namespace Microsoft { namespace VisualStudio { namespace CppUnitTestFramework {
template<> inline std::wstring ToString<EValidationField>(const EValidationField& F) {
  switch (F) {
  case EValidationField::Provider: return L"Provider";
  case EValidationField::AnnounceInterval: return L"AnnounceInterval";
  case EValidationField::MulticastRx: return L"MulticastRx";
  case EValidationField::Adapter: return L"Adapter";
  case EValidationField::Domain: return L"Domain";
  case EValidationField::Grandmaster: return L"Grandmaster";
  case EValidationField::DelayRequestInterval: return L"DelayRequestInterval";
  }
  return L"?";
}
template<> inline std::wstring ToString<EValidationSeverity>(const EValidationSeverity& S) {
  return (S == EValidationSeverity::Error) ? L"Error" : L"Warning";
}
}}}

namespace PtpTests {

TEST_CLASS(DelayRequestIntervalText) {
public:
  TEST_METHOD(AcceptsRange) {
    DWORD v = 0;
    Assert::IsTrue(ParseDelayRequestInterval(L"1200", v));
    Assert::AreEqual((DWORD)1200, v);
    Assert::IsTrue(ParseDelayRequestInterval(L"200", v));
    Assert::AreEqual((DWORD)200, v);
    Assert::IsTrue(ParseDelayRequestInterval(L"10000", v));
    Assert::AreEqual((DWORD)10000, v);
    Assert::IsTrue(ParseDelayRequestInterval(L"  500  ", v));
    Assert::AreEqual((DWORD)500, v);
    Assert::IsTrue(ParseDelayRequestInterval(L"0500", v));
    Assert::AreEqual((DWORD)500, v);
  }

  TEST_METHOD(RejectsOutOfRange) {
    DWORD v = 77;
    Assert::IsFalse(ParseDelayRequestInterval(L"199", v));
    Assert::IsFalse(ParseDelayRequestInterval(L"10001", v));
    Assert::IsFalse(ParseDelayRequestInterval(L"0", v));
    Assert::IsFalse(ParseDelayRequestInterval(L"99999999999999999999", v));
    Assert::AreEqual((DWORD)77, v, L"unchanged on failure");
  }

  TEST_METHOD(RejectsNonNumbers) {
    DWORD v;
    Assert::IsFalse(ParseDelayRequestInterval(nullptr, v));
    Assert::IsFalse(ParseDelayRequestInterval(L"", v));
    Assert::IsFalse(ParseDelayRequestInterval(L"   ", v));
    Assert::IsFalse(ParseDelayRequestInterval(L"1,200", v));
    Assert::IsFalse(ParseDelayRequestInterval(L"1200ms", v));
    Assert::IsFalse(ParseDelayRequestInterval(L"-500", v));
    Assert::IsFalse(ParseDelayRequestInterval(L"12 00", v));
  }
};

TEST_CLASS(GrandmasterAddress) {
public:
  TEST_METHOD(AutomaticAndUnicastAreFine) {
    Assert::IsNull(GrandmasterAddressProblem(0));
    Assert::IsNull(GrandmasterAddressProblem(Ip(10, 218, 10, 2)));
    Assert::IsNull(GrandmasterAddressProblem(Ip(192, 168, 1, 1)));
    Assert::IsNull(GrandmasterAddressProblem(Ip(169, 254, 3, 4)));
    Assert::IsNull(GrandmasterAddressProblem(Ip(223, 255, 255, 254)));
    Assert::IsNull(GrandmasterAddressProblem(Ip(1, 0, 0, 0)));
  }

  TEST_METHOD(RejectsWhatCannotBeAMaster) {
    Assert::IsNotNull(GrandmasterAddressProblem(Ip(0, 0, 0, 1)));
    Assert::IsNotNull(GrandmasterAddressProblem(Ip(0, 255, 255, 255)));
    Assert::IsNotNull(GrandmasterAddressProblem(Ip(127, 0, 0, 1)));
    Assert::IsNotNull(GrandmasterAddressProblem(Ip(224, 0, 1, 129)));   //the PTP multicast group itself
    Assert::IsNotNull(GrandmasterAddressProblem(Ip(239, 255, 255, 255)));
    Assert::IsNotNull(GrandmasterAddressProblem(Ip(240, 0, 0, 1)));
    Assert::IsNotNull(GrandmasterAddressProblem(Ip(255, 255, 255, 255)));
  }
};

TEST_CLASS(Validation) {
  IpAddressEntry adapter;
  SValidationInput in;
  SValidationResult r;

  bool Validate() { return ValidateConfiguration(in, r); }

  void HearDomains(std::initializer_list<uint8_t> Domains) {
    in.Traffic.Known = true;
    in.Traffic.DomainCount = 0;
    for (uint8_t d : Domains)
      in.Traffic.Domains[in.Traffic.DomainCount++] = d;
  }

  //exactly one issue, with this severity and field
  void AssertOnly(EValidationSeverity Severity, EValidationField Field) {
    Assert::AreEqual(1, r.Count, r.Count ? r.Issues[0].Message : L"no issues");
    Assert::AreEqual(Severity, r.Issues[0].Severity, r.Issues[0].Message);
    Assert::AreEqual(Field, r.Issues[0].Field, r.Issues[0].Message);
    Logger::WriteMessage(r.Issues[0].Message);
  }

  bool HasIssue(EValidationSeverity Severity, EValidationField Field) {
    for (int i = 0; i < r.Count; ++i)
      if ((r.Issues[i].Severity == Severity) && (r.Issues[i].Field == Field))
        return true;
    return false;
  }

public:
  TEST_METHOD_INITIALIZE(Init) {
    ZeroMemory(&adapter, sizeof(adapter));
    StringCchCopy(adapter.FriendlyName, ARRAYSIZE(adapter.FriendlyName), L"CX5-Port1");
    adapter.LocalAddress = Ip(10, 218, 10, 11);
    adapter.Present = true;
    adapter.Up = true;
    adapter.Ethernet = true;
    adapter.ConnectorPresent = true;

    ZeroMemory(&in, sizeof(in));
    in.Provider = ETimeProvider::PrelPtp;
    in.Adapter = &adapter;
    in.DomainText = L"127 - SMPTE ST 2059-2";
    in.IntervalText = L"1200";
    in.GrandmasterAddress = 0;
    HearDomains({ 127 });
  }

  TEST_METHOD(GoodConfigurationHasNoIssues) {
    Assert::IsTrue(Validate());
    Assert::AreEqual(0, r.Count, r.Count ? r.Issues[0].Message : L"");
  }

  TEST_METHOD(PinnedGrandmasterHeardHasNoIssues) {
    in.GrandmasterAddress = Ip(10, 218, 10, 2);
    in.Traffic.GrandmasterHeard = true;
    Assert::IsTrue(Validate());
    Assert::AreEqual(0, r.Count);
  }

  // ---- errors

  TEST_METHOD(PtpEnabledWithoutAdapterIsAnError) {
    in.Adapter = nullptr;
    Assert::IsFalse(Validate());
    AssertOnly(EValidationSeverity::Error, EValidationField::Adapter);
  }

  TEST_METHOD(PtpDisabledNeedsNoAdapter) {
    in.Provider = ETimeProvider::Ntp;
    in.Adapter = nullptr;
    Assert::IsTrue(Validate());
    Assert::AreEqual(0, r.Count);
  }

  TEST_METHOD(NtpIgnoresThePtpSettings) {
    //the dialog disables them: a value that can't be used must not stop the save
    in.Provider = ETimeProvider::Ntp;
    in.DomainText = L"300";
    in.GrandmasterAddress = Ip(224, 0, 1, 129);
    in.IntervalText = L"x";
    Assert::IsTrue(Validate());
    Assert::AreEqual(0, r.Count);
  }

  TEST_METHOD(InvalidDomainIsAnError) {
    in.DomainText = L"256";
    Assert::IsFalse(Validate());
    AssertOnly(EValidationSeverity::Error, EValidationField::Domain);
    in.DomainText = L"default";
    Assert::IsFalse(Validate());
    AssertOnly(EValidationSeverity::Error, EValidationField::Domain);
  }

  TEST_METHOD(AnyDomainIsFine) {
    in.DomainText = L"Any";
    HearDomains({ 0, 127 });
    Assert::IsTrue(Validate());
    Assert::AreEqual(0, r.Count);
  }

  TEST_METHOD(BadGrandmasterAddressIsAnError) {
    in.GrandmasterAddress = Ip(224, 0, 1, 129);
    Assert::IsFalse(Validate());
    AssertOnly(EValidationSeverity::Error, EValidationField::Grandmaster);
    Assert::IsNotNull(wcsstr(r.Issues[0].Message, L"224.0.1.129"));
    Assert::IsNotNull(wcsstr(r.Issues[0].Message, L"multicast"));
  }

  TEST_METHOD(BadIntervalIsAnError) {
    in.IntervalText = L"50";
    Assert::IsFalse(Validate());
    AssertOnly(EValidationSeverity::Error, EValidationField::DelayRequestInterval);
  }

  TEST_METHOD(ErrorsComeBeforeWarnings) {
    HearDomains({});               //warning
    in.IntervalText = L"x";        //error
    Assert::IsFalse(Validate());
    Assert::AreEqual(2, r.Count);
    Assert::AreEqual(EValidationSeverity::Error, r.Issues[0].Severity);
    Assert::AreEqual(EValidationSeverity::Warning, r.Issues[1].Severity);
    Assert::AreEqual(1, r.ErrorCount());
    Assert::AreEqual(1, r.WarningCount());
    Assert::IsTrue(r.First(EValidationSeverity::Warning) == &r.Issues[1]);
  }

  TEST_METHOD(EveryErrorIsReported) {
    in.Adapter = nullptr;
    in.DomainText = L"300";
    in.GrandmasterAddress = Ip(127, 0, 0, 1);
    in.IntervalText = L"";
    Assert::IsFalse(Validate());
    Assert::AreEqual(4, r.ErrorCount());
    Assert::AreEqual(EValidationField::Adapter, r.First(EValidationSeverity::Error)->Field);
  }

  // ---- warnings: time sources

  TEST_METHOD(NoTimeSourceIsAWarning) {
    in.Provider = ETimeProvider::None;
    Assert::IsTrue(Validate(), L"a warning, not an error: another provider may be in use");
    AssertOnly(EValidationSeverity::Warning, EValidationField::Provider);
  }

  // ---- warnings: the adapter

  TEST_METHOD(AdapterNotPresentIsAWarning) {
    adapter.Present = false;
    adapter.Up = false;
    adapter.LocalAddress = 0;
    Assert::IsTrue(Validate());
    AssertOnly(EValidationSeverity::Warning, EValidationField::Adapter);
    Assert::IsNotNull(wcsstr(r.Issues[0].Message, L"not present"));
  }

  TEST_METHOD(AdapterNotConnectedIsAWarning) {
    adapter.Up = false;
    Assert::IsTrue(Validate());
    AssertOnly(EValidationSeverity::Warning, EValidationField::Adapter);
    Assert::IsNotNull(wcsstr(r.Issues[0].Message, L"not connected"));
  }

  TEST_METHOD(AdapterWithoutAddressIsAWarning) {
    adapter.LocalAddress = 0;
    Assert::IsTrue(Validate());
    AssertOnly(EValidationSeverity::Warning, EValidationField::Adapter);
    Assert::IsNotNull(wcsstr(r.Issues[0].Message, L"no IPv4 address"));
  }

  TEST_METHOD(AdapterWarningsAreSkippedWhenPtpIsDisabled) {
    in.Provider = ETimeProvider::Ntp;
    adapter.Up = false;
    Assert::IsTrue(Validate());
    Assert::AreEqual(0, r.Count);
  }

  // ---- warnings: traffic

  TEST_METHOD(NoTrafficIsAWarning) {
    HearDomains({});
    Assert::IsTrue(Validate());
    AssertOnly(EValidationSeverity::Warning, EValidationField::Adapter);
    Assert::IsNotNull(wcsstr(r.Issues[0].Message, L"CX5-Port1"));
  }

  TEST_METHOD(UnknownTrafficIsNotChecked) {
    HearDomains({});
    in.Traffic.Known = false;
    in.DomainText = L"0";
    in.GrandmasterAddress = Ip(10, 218, 10, 2);
    Assert::IsTrue(Validate());
    Assert::AreEqual(0, r.Count);
  }

  TEST_METHOD(TrafficInOtherDomainsIsAWarning) {
    in.DomainText = L"0";
    HearDomains({ 44, 127 });
    Assert::IsTrue(Validate());
    AssertOnly(EValidationSeverity::Warning, EValidationField::Domain);
    Assert::IsNotNull(wcsstr(r.Issues[0].Message, L"domains 44, 127"), r.Issues[0].Message);
    Assert::IsNotNull(wcsstr(r.Issues[0].Message, L"not in domain 0"), r.Issues[0].Message);
  }

  TEST_METHOD(TrafficInOneOfSeveralDomainsIsFine) {
    in.DomainText = L"127";
    HearDomains({ 0, 127 });
    Assert::IsTrue(Validate());
    Assert::AreEqual(0, r.Count);
  }

  TEST_METHOD(NoTrafficGivesOneWarningNotThree) {
    HearDomains({});
    in.DomainText = L"0";
    in.GrandmasterAddress = Ip(10, 218, 10, 2);
    Assert::IsTrue(Validate());
    AssertOnly(EValidationSeverity::Warning, EValidationField::Adapter);
  }

  TEST_METHOD(PinnedGrandmasterNotHeardIsAWarning) {
    in.GrandmasterAddress = Ip(10, 218, 10, 2);
    in.Traffic.GrandmasterHeard = false;
    Assert::IsTrue(Validate());
    AssertOnly(EValidationSeverity::Warning, EValidationField::Grandmaster);
    Assert::IsNotNull(wcsstr(r.Issues[0].Message, L"10.218.10.2"));
  }

  TEST_METHOD(BadGrandmasterAddressIsNotAlsoAWarning) {
    in.GrandmasterAddress = Ip(255, 255, 255, 255);
    in.Traffic.GrandmasterHeard = false;
    Assert::IsFalse(Validate());
    AssertOnly(EValidationSeverity::Error, EValidationField::Grandmaster);
  }

  TEST_METHOD(InvalidDomainSkipsTheDomainTrafficCheck) {
    in.DomainText = L"999";
    HearDomains({ 127 });
    Assert::IsFalse(Validate());
    AssertOnly(EValidationSeverity::Error, EValidationField::Domain);
  }

  // ---- the case seen on 2026-11-06 at 18:57:21: an empty AdapterName was saved

  TEST_METHOD(EmptyAdapterCannotBeSaved) {
    in.Adapter = nullptr;
    Assert::IsFalse(Validate());
    Assert::AreEqual(EValidationField::Adapter, r.First(EValidationSeverity::Error)->Field);
  }
};

TEST_CLASS(AnnounceIntervalText) {
public:
  TEST_METHOD(AcceptsRange) {
    DWORD v = 0;
    Assert::IsTrue(ParseAnnounceInterval(L"4000", v));
    Assert::AreEqual((DWORD)4000, v);
    Assert::IsTrue(ParseAnnounceInterval(L"125", v));
    Assert::AreEqual((DWORD)125, v);
    Assert::IsTrue(ParseAnnounceInterval(L" 16000 ", v));
    Assert::AreEqual((DWORD)16000, v);
  }

  TEST_METHOD(Rejects) {
    DWORD v = 77;
    Assert::IsFalse(ParseAnnounceInterval(L"124", v));
    Assert::IsFalse(ParseAnnounceInterval(L"16001", v));
    Assert::IsFalse(ParseAnnounceInterval(L"", v));
    Assert::IsFalse(ParseAnnounceInterval(nullptr, v));
    Assert::IsFalse(ParseAnnounceInterval(L"4 s", v));
    Assert::AreEqual((DWORD)77, v, L"unchanged on failure");
  }
};

/*
The Microsoft PTP client. It chooses its own adapter, so the selected adapter doesn't matter and
the traffic checks look at every adapter the monitor listens on (in the test lab one adapter
hears 10.218.10.2 and another 10.218.1.2, both domain 127).
*/
TEST_CLASS(MsPtpValidation) {
  SValidationInput in;
  SValidationResult r;
  SSurveyedAdapter surveyed[3];

  bool Validate() { return ValidateConfiguration(in, r); }

  void Hear(int Adapter, std::initializer_list<uint8_t> Domains, bool GrandmasterHeard = false) {
    STraffic& t = surveyed[Adapter].Traffic;
    t.Known = true;
    t.DomainCount = 0;
    for (uint8_t d : Domains)
      t.Domains[t.DomainCount++] = d;
    t.GrandmasterHeard = GrandmasterHeard;
  }

  void AssertOnly(EValidationSeverity Severity, EValidationField Field) {
    Assert::AreEqual(1, r.Count, r.Count ? r.Issues[0].Message : L"no issues");
    Assert::AreEqual(Severity, r.Issues[0].Severity, r.Issues[0].Message);
    Assert::AreEqual(Field, r.Issues[0].Field, r.Issues[0].Message);
    Logger::WriteMessage(r.Issues[0].Message);
  }

public:
  TEST_METHOD_INITIALIZE(Init) {
    ZeroMemory(surveyed, sizeof(surveyed));
    surveyed[0].Name = L"CX5-Port1";
    surveyed[1].Name = L"NIC1";
    surveyed[2].Name = L"NIC2";

    ZeroMemory(&in, sizeof(in));
    in.Provider = ETimeProvider::MsPtp;
    in.MsPtpAvailability = EMsPtpAvailability::Available;
    in.Adapter = nullptr;                 //not needed
    in.DomainText = L"127";
    in.IntervalText = L"1000";
    in.AnnounceIntervalText = L"4000";
    in.MulticastRx = true;
    in.GrandmasterAddress = Ip(10, 218, 10, 2);
    in.Surveyed = surveyed;
    in.SurveyedCount = 3;
    Hear(0, { 127 }, true);
    Hear(1, { 127 });
    Hear(2, {});
  }

  TEST_METHOD(GoodConfigurationHasNoIssues) {
    Assert::IsTrue(Validate());
    Assert::AreEqual(0, r.Count, r.Count ? r.Issues[0].Message : L"");
  }

  TEST_METHOD(NoAdapterNeeded) {
    //and the selected adapter's state doesn't matter
    IpAddressEntry a;
    ZeroMemory(&a, sizeof(a));
    StringCchCopy(a.FriendlyName, ARRAYSIZE(a.FriendlyName), L"Unplugged");
    in.Adapter = &a;
    Assert::IsTrue(Validate());
    Assert::AreEqual(0, r.Count, r.Count ? r.Issues[0].Message : L"");
  }

  // ---- errors

  TEST_METHOD(NotAvailableIsAnError) {
    in.MsPtpAvailability = EMsPtpAvailability::WindowsTooOld;
    Assert::IsFalse(Validate());
    AssertOnly(EValidationSeverity::Error, EValidationField::Provider);
    Assert::AreEqual(MsPtpAvailabilityText(EMsPtpAvailability::WindowsTooOld), r.Issues[0].Message);
    in.MsPtpAvailability = EMsPtpAvailability::NoDll;
    Assert::IsFalse(Validate());
    AssertOnly(EValidationSeverity::Error, EValidationField::Provider);
  }

  TEST_METHOD(AnyDomainIsAnError) {
    in.DomainText = L"Any";
    Assert::IsFalse(Validate());
    AssertOnly(EValidationSeverity::Error, EValidationField::Domain);
    in.DomainText = L"";
    Assert::IsFalse(Validate());
    AssertOnly(EValidationSeverity::Error, EValidationField::Domain);
  }

  TEST_METHOD(InvalidDomainDoesNotOfferAny) {
    in.DomainText = L"256";
    Assert::IsFalse(Validate());
    AssertOnly(EValidationSeverity::Error, EValidationField::Domain);
    Assert::IsNull(wcsstr(r.Issues[0].Message, L"Any"), r.Issues[0].Message);
  }

  TEST_METHOD(BadAnnounceIntervalIsAnError) {
    in.AnnounceIntervalText = L"20000";
    Assert::IsFalse(Validate());
    AssertOnly(EValidationSeverity::Error, EValidationField::AnnounceInterval);
  }

  TEST_METHOD(BadDelayRequestIntervalIsAnError) {
    in.IntervalText = L"100";
    Assert::IsFalse(Validate());
    AssertOnly(EValidationSeverity::Error, EValidationField::DelayRequestInterval);
  }

  TEST_METHOD(BadGrandmasterSaysAnyMaster) {
    in.GrandmasterAddress = Ip(127, 0, 0, 1);
    Assert::IsFalse(Validate());
    AssertOnly(EValidationSeverity::Error, EValidationField::Grandmaster);
    Assert::IsNotNull(wcsstr(r.Issues[0].Message, L"to accept any master"), r.Issues[0].Message);
  }

  TEST_METHOD(PrelPtpOnlyAnnounceIntervalIsIgnored) {
    //the Microsoft client's settings aren't checked for PrelPtp
    IpAddressEntry a;
    ZeroMemory(&a, sizeof(a));
    a.Present = a.Up = true;
    a.LocalAddress = Ip(10, 218, 10, 11);
    in.Provider = ETimeProvider::PrelPtp;
    in.Adapter = &a;
    in.AnnounceIntervalText = L"x";
    in.MulticastRx = false;
    in.MsPtpAvailability = EMsPtpAvailability::NoDll;
    Assert::IsTrue(Validate());
    Assert::AreEqual(0, r.Count, r.Count ? r.Issues[0].Message : L"");
  }

  // ---- warnings

  TEST_METHOD(MulticastRxOffIsAWarning) {
    in.MulticastRx = false;
    Assert::IsTrue(Validate());
    AssertOnly(EValidationSeverity::Warning, EValidationField::MulticastRx);
  }

  TEST_METHOD(AnyMasterOnSeveralAdaptersIsAWarning) {
    in.GrandmasterAddress = 0;
    Assert::IsTrue(Validate());
    AssertOnly(EValidationSeverity::Warning, EValidationField::Grandmaster);
    Assert::IsNotNull(wcsstr(r.Issues[0].Message, L"2 adapters (CX5-Port1, NIC1)"), r.Issues[0].Message);
  }

  TEST_METHOD(AnyMasterOnOneAdapterIsFine) {
    in.GrandmasterAddress = 0;
    Hear(1, { 0 });   //another domain doesn't count
    Assert::IsTrue(Validate());
    Assert::AreEqual(0, r.Count, r.Count ? r.Issues[0].Message : L"");
  }

  TEST_METHOD(GrandmasterHeardOnAnyAdapterIsFine) {
    Hear(0, { 127 }, false);
    Hear(1, { 127 }, true);
    Assert::IsTrue(Validate());
    Assert::AreEqual(0, r.Count, r.Count ? r.Issues[0].Message : L"");
  }

  TEST_METHOD(GrandmasterNotHeardIsAWarning) {
    Hear(0, { 127 }, false);
    Assert::IsTrue(Validate());
    AssertOnly(EValidationSeverity::Warning, EValidationField::Grandmaster);
    Assert::IsNotNull(wcsstr(r.Issues[0].Message, L"any adapter"), r.Issues[0].Message);
  }

  TEST_METHOD(DomainNotHeardAnywhereIsAWarning) {
    in.DomainText = L"0";
    Assert::IsTrue(Validate());
    AssertOnly(EValidationSeverity::Warning, EValidationField::Domain);
    Assert::IsNotNull(wcsstr(r.Issues[0].Message, L"domain 0"), r.Issues[0].Message);
  }

  TEST_METHOD(UnknownTrafficIsNotChecked) {
    for (auto& s : surveyed)
      s.Traffic.Known = false;
    in.GrandmasterAddress = 0;
    in.DomainText = L"0";
    Assert::IsTrue(Validate());
    Assert::AreEqual(0, r.Count, r.Count ? r.Issues[0].Message : L"");
    in.Surveyed = nullptr;
    in.SurveyedCount = 0;
    Assert::IsTrue(Validate());
    Assert::AreEqual(0, r.Count, r.Count ? r.Issues[0].Message : L"");
  }
};

}
