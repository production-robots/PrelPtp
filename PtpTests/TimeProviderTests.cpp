#include "..\PtpUtil\TimeProviders.h"
#include "CppUnitTest.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

/*
TimeProviders: choosing among PrelPtp, the Microsoft PTP client and NTP; the PtpClient values
the setup program writes; availability; uninstall. Only the parts that don't touch the registry.
The expected values are what ptpprov.dll was found to need (see TimeProviders.h).
*/

namespace Microsoft { namespace VisualStudio { namespace CppUnitTestFramework {
template<> inline std::wstring ToString<ETimeProvider>(const ETimeProvider& P) {
  return TimeProviderName(P);
}
template<> inline std::wstring ToString<EMsPtpAvailability>(const EMsPtpAvailability& A) {
  switch (A) {
  case EMsPtpAvailability::Available: return L"Available";
  case EMsPtpAvailability::WindowsTooOld: return L"WindowsTooOld";
  case EMsPtpAvailability::NoDll: return L"NoDll";
  }
  return L"?";
}
}}}

namespace PtpTests {

//IPv4 address in network byte order
static DWORD Ip(BYTE A, BYTE B, BYTE C, BYTE D) {
  return (DWORD)A | ((DWORD)B << 8) | ((DWORD)C << 16) | ((DWORD)D << 24);
}

static SProvidersEnabled Enabled(bool PrelPtp, bool MsPtp, bool Ntp) {
  SProvidersEnabled e;
  e.PrelPtp = PrelPtp;
  e.MsPtp = MsPtp;
  e.Ntp = Ntp;
  return e;
}

TEST_CLASS(ChooseTimeProviderTests) {
public:
  TEST_METHOD(OneEnabled) {
    Assert::AreEqual(ETimeProvider::PrelPtp, ChooseTimeProvider(Enabled(true, false, false)));
    Assert::AreEqual(ETimeProvider::MsPtp, ChooseTimeProvider(Enabled(false, true, false)));
    Assert::AreEqual(ETimeProvider::Ntp, ChooseTimeProvider(Enabled(false, false, true)));
  }

  TEST_METHOD(NoneEnabled) {
    Assert::AreEqual(ETimeProvider::None, ChooseTimeProvider(Enabled(false, false, false)));
  }

  TEST_METHOD(SeveralEnabled_PrelPtpThenMsPtpThenNtp) {
    Assert::AreEqual(ETimeProvider::PrelPtp, ChooseTimeProvider(Enabled(true, true, true)));
    Assert::AreEqual(ETimeProvider::PrelPtp, ChooseTimeProvider(Enabled(true, false, true)));
    Assert::AreEqual(ETimeProvider::PrelPtp, ChooseTimeProvider(Enabled(true, true, false)));
    Assert::AreEqual(ETimeProvider::MsPtp, ChooseTimeProvider(Enabled(false, true, true)));
  }
};

TEST_CLASS(MsPtpValuesTests) {
  static SMsPtpConfiguration Config() {
    SMsPtpConfiguration c;
    DefaultMsPtpConfiguration(c);
    c.DomainNumber = 127;
    c.GrandmasterAddress = Ip(10, 218, 10, 2);
    return c;
  }

  static const SRegValue& Get(const SRegPlan& Plan, const wchar_t* Name) {
    const SRegValue* v = Plan.Find(Name);
    Assert::IsNotNull(v, Name);
    return *v;
  }

  static void AssertDword(const SRegPlan& Plan, const wchar_t* Name, DWORD Expected) {
    const SRegValue& v = Get(Plan, Name);
    Assert::AreEqual((int)SRegValue::Dword, (int)v.Kind, Name);
    Assert::AreEqual(Expected, v.Number, Name);
  }

  static void AssertString(const SRegPlan& Plan, const wchar_t* Name, const wchar_t* Expected) {
    const SRegValue& v = Get(Plan, Name);
    Assert::AreEqual((int)SRegValue::String, (int)v.Kind, Name);
    Assert::AreEqual(Expected, v.Text, Name);
  }

  static void AssertDeleted(const SRegPlan& Plan, const wchar_t* Name) {
    Assert::AreEqual((int)SRegValue::Delete, (int)Get(Plan, Name).Kind, Name);
  }

public:
  TEST_METHOD(Defaults) {
    SMsPtpConfiguration c;
    DefaultMsPtpConfiguration(c);
    Assert::AreEqual((DWORD)0, c.DomainNumber);
    Assert::AreEqual((DWORD)0, c.GrandmasterAddress);
    Assert::AreEqual((DWORD)1000, c.DelayPollInterval);
    Assert::AreEqual((DWORD)4000, c.AnnounceInterval);
    Assert::IsTrue(c.MulticastRx);
    Assert::IsFalse(c.MulticastTx);
  }

  TEST_METHOD(DllNameIsExpandString) {
    SRegPlan p;
    PlanMsPtpValues(Config(), p);
    const SRegValue& v = Get(p, L"DllName");
    Assert::AreEqual((int)SRegValue::ExpandString, (int)v.Kind);
    Assert::AreEqual(L"%SystemRoot%\\System32\\ptpprov.dll", v.Text);
  }

  TEST_METHOD(SettingsWritten) {
    SMsPtpConfiguration c = Config();
    c.DelayPollInterval = 2000;
    c.AnnounceInterval = 8000;
    SRegPlan p;
    PlanMsPtpValues(c, p);
    AssertDword(p, L"InputProvider", 1);
    AssertDword(p, L"DomainNumber", 127);
    AssertDword(p, L"DelayPollInterval", 2000);
    AssertDword(p, L"AnnounceInterval", 8000);
    AssertDword(p, L"EnableMulticastRx", 1);
  }

  TEST_METHOD(EnabledIsNotWritten) {
    //SelectTimeProvider sets it
    SRegPlan p;
    PlanMsPtpValues(Config(), p);
    Assert::IsNull(p.Find(L"Enabled"));
  }

  TEST_METHOD(UnusedValuesAreNotWritten) {
    //no visible effect in the tests; values the setup doesn't manage are left alone
    SRegPlan p;
    PlanMsPtpValues(Config(), p);
    Assert::IsNull(p.Find(L"MulticastIfIndex"));
    Assert::IsNull(p.Find(L"MulticastOnlyTxEnabled"));
  }

  TEST_METHOD(FixedMaster_ListedAndAllowAnyMasterRemoved) {
    //AllowAnyMaster = 1 overrides PtpMasters
    SRegPlan p;
    PlanMsPtpValues(Config(), p);
    AssertString(p, L"PtpMasters", L"10.218.10.2");
    AssertDeleted(p, L"AllowAnyMaster");
  }

  TEST_METHOD(AnyMaster_EmptyListAndAllowAnyMaster) {
    SMsPtpConfiguration c = Config();
    c.GrandmasterAddress = 0;
    SRegPlan p;
    PlanMsPtpValues(c, p);
    AssertString(p, L"PtpMasters", L"");
    AssertDword(p, L"AllowAnyMaster", 1);
  }

  TEST_METHOD(MulticastTxOn_Written) {
    SMsPtpConfiguration c = Config();
    c.MulticastTx = true;
    SRegPlan p;
    PlanMsPtpValues(c, p);
    AssertDword(p, L"EnableMulticastTx", 1);
  }

  TEST_METHOD(MulticastTxOff_Removed) {
    //absent is the tested unicast case; 0 was not tested
    SRegPlan p;
    PlanMsPtpValues(Config(), p);
    AssertDeleted(p, L"EnableMulticastTx");
  }

  TEST_METHOD(MulticastRxOff_WrittenAsZero) {
    SMsPtpConfiguration c = Config();
    c.MulticastRx = false;
    SRegPlan p;
    PlanMsPtpValues(c, p);
    AssertDword(p, L"EnableMulticastRx", 0);
  }

  TEST_METHOD(FitsThePlan) {
    SRegPlan p;
    PlanMsPtpValues(Config(), p);
    Assert::IsTrue(p.Count > 0 && p.Count <= SRegPlan::MAX_VALUES);
  }
};

TEST_CLASS(PtpMastersTests) {
public:
  TEST_METHOD(SingleAddress) {
    DWORD a = 0;
    Assert::IsTrue(ParsePtpMasters(L"10.218.1.2", a));
    Assert::AreEqual(Ip(10, 218, 1, 2), a);
  }

  TEST_METHOD(FirstOfSeveral) {
    DWORD a = 0;
    Assert::IsTrue(ParsePtpMasters(L"10.218.10.2 10.218.1.2", a));
    Assert::AreEqual(Ip(10, 218, 10, 2), a);
    Assert::IsTrue(ParsePtpMasters(L"10.218.1.2,10.218.10.2", a));
    Assert::AreEqual(Ip(10, 218, 1, 2), a);
    Assert::IsTrue(ParsePtpMasters(L" ; 192.168.1.10;10.0.0.1", a));
    Assert::AreEqual(Ip(192, 168, 1, 10), a);
  }

  TEST_METHOD(NothingUsable) {
    DWORD a = 77;
    Assert::IsFalse(ParsePtpMasters(nullptr, a));
    Assert::IsFalse(ParsePtpMasters(L"", a));
    Assert::IsFalse(ParsePtpMasters(L"  ", a));
    Assert::IsFalse(ParsePtpMasters(L"master.example.com", a));
    Assert::IsFalse(ParsePtpMasters(L"10.218.1", a));
    Assert::IsFalse(ParsePtpMasters(L"10.218.1.2.3.4.5.6.7.8.9.10.11.12", a));
    Assert::AreEqual((DWORD)77, a, L"unchanged on failure");
  }
};

TEST_CLASS(MsPtpAvailabilityTests) {
public:
  TEST_METHOD(Server2022AndLater) {
    Assert::AreEqual(EMsPtpAvailability::Available, MsPtpAvailability(20348, true));   //Server 2022
    Assert::AreEqual(EMsPtpAvailability::Available, MsPtpAvailability(26100, true));   //Windows 11 24H2
  }

  TEST_METHOD(OlderWindows) {
    Assert::AreEqual(EMsPtpAvailability::WindowsTooOld, MsPtpAvailability(17763, true)); //Server 2019, Windows 10 1809
    Assert::AreEqual(EMsPtpAvailability::WindowsTooOld, MsPtpAvailability(19045, true)); //Windows 10 22H2
    Assert::AreEqual(EMsPtpAvailability::WindowsTooOld, MsPtpAvailability(20347, true));
  }

  TEST_METHOD(NoDll) {
    Assert::AreEqual(EMsPtpAvailability::NoDll, MsPtpAvailability(20348, false));
    //an old Windows is the reason given, DLL or not
    Assert::AreEqual(EMsPtpAvailability::WindowsTooOld, MsPtpAvailability(17763, false));
  }

  TEST_METHOD(ReasonText) {
    Assert::AreEqual(L"", MsPtpAvailabilityText(EMsPtpAvailability::Available));
    Assert::AreNotEqual(L"", MsPtpAvailabilityText(EMsPtpAvailability::WindowsTooOld));
    Assert::AreNotEqual(L"", MsPtpAvailabilityText(EMsPtpAvailability::NoDll));
  }
};

TEST_CLASS(UninstallPlanTests) {
public:
  TEST_METHOD(PrelPtpOnly_AskAboutNtp) {
    SUninstallPlan p = PlanUninstall(Enabled(true, false, false));
    Assert::IsTrue(p.AskToEnableNtp);
    Assert::IsFalse(p.KeepFirewallRule);
  }

  TEST_METHOD(PrelPtpAndNtp_NtpAlreadyOn) {
    SUninstallPlan p = PlanUninstall(Enabled(true, false, true));
    Assert::IsFalse(p.AskToEnableNtp);
    Assert::IsFalse(p.KeepFirewallRule);
  }

  TEST_METHOD(MsPtp_KeepRuleDontAsk) {
    SUninstallPlan p = PlanUninstall(Enabled(false, true, false));
    Assert::IsFalse(p.AskToEnableNtp);
    Assert::IsTrue(p.KeepFirewallRule);
  }

  TEST_METHOD(PrelPtpAndMsPtp_MsPtpKeepsRunning) {
    SUninstallPlan p = PlanUninstall(Enabled(true, true, false));
    Assert::IsFalse(p.AskToEnableNtp);
    Assert::IsTrue(p.KeepFirewallRule);
  }

  TEST_METHOD(NtpOrNothing_LeftAlone) {
    SUninstallPlan p = PlanUninstall(Enabled(false, false, true));
    Assert::IsFalse(p.AskToEnableNtp);
    Assert::IsFalse(p.KeepFirewallRule);
    p = PlanUninstall(Enabled(false, false, false));
    Assert::IsFalse(p.AskToEnableNtp);
    Assert::IsFalse(p.KeepFirewallRule);
  }
};

TEST_CLASS(InitialPtpSettingsTests) {
  SConfiguration prel;
  SMsPtpConfiguration ms;
  SPtpSettings out_prel, out_ms;

  static void AssertSettings(DWORD Domain, DWORD Grandmaster, DWORD Interval, const SPtpSettings& S, const wchar_t* Which) {
    Assert::AreEqual(Domain, S.DomainNumber, Which);
    Assert::AreEqual(Grandmaster, S.GrandmasterAddress, Which);
    Assert::AreEqual(Interval, S.DelayRequestInterval, Which);
  }

public:
  TEST_METHOD_INITIALIZE(Init) {
    ZeroMemory(&prel, sizeof(prel));
    prel.DomainNumber = 127;
    prel.GrandmasterAddress = Ip(10, 218, 1, 2);
    prel.DelayRequestInterval = 200;
    DefaultMsPtpConfiguration(ms);
    ms.DomainNumber = 24;
    ms.GrandmasterAddress = Ip(10, 218, 10, 2);
    ms.DelayPollInterval = 2000;
    memset(&out_prel, 0xCC, sizeof(out_prel));
    memset(&out_ms, 0xCC, sizeof(out_ms));
  }

  TEST_METHOD(BothKeys_EachKeepsItsOwn) {
    InitialPtpSettings(&prel, &ms, out_prel, out_ms);
    AssertSettings(127, Ip(10, 218, 1, 2), 200, out_prel, L"PrelPtp");
    AssertSettings(24, Ip(10, 218, 10, 2), 2000, out_ms, L"MsPtp");
  }

  TEST_METHOD(NoPtpClientKey_MsPtpFromPrelPtp) {
    InitialPtpSettings(&prel, nullptr, out_prel, out_ms);
    AssertSettings(127, Ip(10, 218, 1, 2), 200, out_prel, L"PrelPtp");
    AssertSettings(127, Ip(10, 218, 1, 2), DEFAULT_MS_PTP_DELAY_POLL_INTERVAL, out_ms, L"MsPtp");
  }

  TEST_METHOD(NoPtpClientKey_PrelPtpAnyDomainGivesZero) {
    //never seeded with a value ptpprov can't use
    prel.DomainNumber = PTP_DOMAIN_ANY;
    prel.GrandmasterAddress = 0;
    InitialPtpSettings(&prel, nullptr, out_prel, out_ms);
    AssertSettings(PTP_DOMAIN_ANY, 0, 200, out_prel, L"PrelPtp");
    AssertSettings(0, 0, DEFAULT_MS_PTP_DELAY_POLL_INTERVAL, out_ms, L"MsPtp");
  }

  TEST_METHOD(NoPrelPtpKey_PrelPtpFromMsPtp) {
    InitialPtpSettings(nullptr, &ms, out_prel, out_ms);
    AssertSettings(24, Ip(10, 218, 10, 2), DEFAULT_PREL_PTP_DELAY_REQUEST_INTERVAL, out_prel, L"PrelPtp");
    AssertSettings(24, Ip(10, 218, 10, 2), 2000, out_ms, L"MsPtp");
  }

  TEST_METHOD(NeitherKey_Defaults) {
    InitialPtpSettings(nullptr, nullptr, out_prel, out_ms);
    AssertSettings(PTP_DOMAIN_ANY, 0, 1200, out_prel, L"PrelPtp");
    AssertSettings(0, 0, 1000, out_ms, L"MsPtp");
  }
};

}
