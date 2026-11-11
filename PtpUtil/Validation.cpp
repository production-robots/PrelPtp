#include "Validation.h"
#include <stdlib.h>   //_byteswap_ulong
#include <strsafe.h>

int SValidationResult::ErrorCount() const {
  int n = 0;
  for (int i = 0; i < Count; ++i)
    n += (Issues[i].Severity == EValidationSeverity::Error) ? 1 : 0;
  return n;
}

int SValidationResult::WarningCount() const {
  return Count - ErrorCount();
}

const SValidationIssue* SValidationResult::First(EValidationSeverity Severity) const {
  for (int i = 0; i < Count; ++i)
    if (Issues[i].Severity == Severity)
      return &Issues[i];
  return nullptr;
}

//decimal digits with optional surrounding spaces, Min..Max
static bool ParseMilliseconds(const wchar_t* Text, DWORD Min, DWORD Max, DWORD& out_Value) {
  if (Text == nullptr)
    return false;
  const wchar_t* p = Text;
  while (*p == L' ')
    ++p;
  DWORD value = 0;
  int digits = 0;
  while ((*p >= L'0') && (*p <= L'9')) {
    if (value > Max)   //already out of range: stop before it can overflow
      return false;
    value = value * 10 + (DWORD)(*p - L'0');
    ++p;
    ++digits;
  }
  while (*p == L' ')
    ++p;
  if ((digits == 0) || (*p != 0))
    return false;
  if ((value < Min) || (value > Max))
    return false;
  out_Value = value;
  return true;
}

bool ParseDelayRequestInterval(const wchar_t* Text, DWORD& out_Interval) {
  return ParseMilliseconds(Text, MIN_DELAY_REQUEST_INTERVAL, MAX_DELAY_REQUEST_INTERVAL, out_Interval);
}

bool ParseAnnounceInterval(const wchar_t* Text, DWORD& out_Interval) {
  return ParseMilliseconds(Text, MIN_ANNOUNCE_INTERVAL, MAX_ANNOUNCE_INTERVAL, out_Interval);
}

const wchar_t* GrandmasterAddressProblem(DWORD Address) {
  if (Address == 0)
    return nullptr;
  DWORD a = _byteswap_ulong(Address);   //host order: the first octet is the most significant
  BYTE first = (BYTE)(a >> 24);
  if (a == 0xFFFFFFFF)
    return L"the broadcast address";
  if (first == 0)
    return L"not a host address (0.x.x.x)";
  if (first == 127)
    return L"a loopback address";
  if ((first >= 224) && (first <= 239))
    return L"a multicast address";
  if (first >= 240)
    return L"a reserved address (240.0.0.0 and above)";
  return nullptr;
}

static void Add(SValidationResult& R, EValidationSeverity Severity, EValidationField Field, const wchar_t* Format, ...) {
  if (R.Count >= SValidationResult::MAX_ISSUES)
    return;
  SValidationIssue& issue = R.Issues[R.Count++];
  issue.Severity = Severity;
  issue.Field = Field;
  va_list args;
  va_start(args, Format);
  StringCchVPrintf(issue.Message, ARRAYSIZE(issue.Message), Format, args);
  va_end(args);
}

static void FormatAddress(DWORD Address, wchar_t* Buf, size_t Chars) {
  IN_ADDR addr;
  addr.s_addr = Address;
  if (InetNtop(AF_INET, &addr, Buf, Chars) == nullptr)
    StringCchCopy(Buf, Chars, L"?");
}

static bool HeardInDomain(const STraffic& T, DWORD Domain) {
  int count = (T.DomainCount < ARRAYSIZE(T.Domains)) ? T.DomainCount : ARRAYSIZE(T.Domains);
  for (int i = 0; i < count; ++i)
    if (T.Domains[i] == Domain)
      return true;
  return false;
}

//PrelPtp: the selected adapter and what is heard on it
static void CheckPrelPtpAdapter(const SValidationInput& In, bool DomainValid, DWORD Domain,
  const wchar_t* Gm, const wchar_t* GmProblem, SValidationResult& r) {
  const EValidationSeverity W = EValidationSeverity::Warning;
  if (In.Adapter == nullptr)
    return;   //an error already

  const IpAddressEntry& a = *In.Adapter;
  if (!a.Present) {
    Add(r, W, EValidationField::Adapter, L"The adapter \"%s\" is not present on this computer.", a.FriendlyName);
    return;
  }
  if (!a.Up) {
    Add(r, W, EValidationField::Adapter, L"The adapter \"%s\" is not connected.", a.FriendlyName);
    return;
  }
  if (a.LocalAddress == 0) {
    Add(r, W, EValidationField::Adapter, L"The adapter \"%s\" has no IPv4 address.", a.FriendlyName);
    return;
  }

  const STraffic& t = In.Traffic;
  if (!t.Known)
    return;

  if (t.DomainCount <= 0) {
    Add(r, W, EValidationField::Adapter, L"No PTP traffic (Announce messages) is being received on \"%s\".", a.FriendlyName);
    return;
  }

  if (DomainValid && (Domain != PTP_DOMAIN_ANY) && !HeardInDomain(t, Domain)) {
    wchar_t list[0x100] = { 0 };
    int count = (t.DomainCount < ARRAYSIZE(t.Domains)) ? t.DomainCount : ARRAYSIZE(t.Domains);
    for (int i = 0; i < count; ++i) {
      wchar_t d[0x10];
      StringCchPrintf(d, ARRAYSIZE(d), i ? L", %u" : L"%u", t.Domains[i]);
      StringCchCat(list, ARRAYSIZE(list), d);
    }
    Add(r, W, EValidationField::Domain, L"PTP traffic on \"%s\" is in %s %s, not in domain %u.",
      a.FriendlyName, (count == 1) ? L"domain" : L"domains", list, Domain);
  }

  if ((In.GrandmasterAddress != 0) && (GmProblem == nullptr) && !t.GrandmasterHeard)
    Add(r, W, EValidationField::Grandmaster,
      L"No Announce messages from the grandmaster address %s are being received on \"%s\".", Gm, a.FriendlyName);
}

//Microsoft PTP client: it chooses its own adapter, so what is heard on every adapter counts
static void CheckMsPtpTraffic(const SValidationInput& In, bool DomainValid, DWORD Domain,
  const wchar_t* Gm, const wchar_t* GmProblem, SValidationResult& r) {
  const EValidationSeverity W = EValidationSeverity::Warning;
  if (!DomainValid || (Domain == PTP_DOMAIN_ANY) || (In.Surveyed == nullptr))
    return;

  int known = 0, in_domain = 0;
  bool gm_heard = false;
  wchar_t names[0x80] = { 0 };
  for (int i = 0; i < In.SurveyedCount; ++i) {
    const SSurveyedAdapter& s = In.Surveyed[i];
    if (!s.Traffic.Known)
      continue;
    ++known;
    gm_heard |= s.Traffic.GrandmasterHeard;
    if (!HeardInDomain(s.Traffic, Domain))
      continue;
    if (in_domain++ > 0)
      StringCchCat(names, ARRAYSIZE(names), L", ");
    StringCchCat(names, ARRAYSIZE(names), s.Name ? s.Name : L"?");
  }
  if (known == 0)
    return;

  if (in_domain == 0) {
    Add(r, W, EValidationField::Domain, L"No PTP traffic (Announce messages) in domain %u is being received on any adapter.", Domain);
    return;
  }

  if (In.GrandmasterAddress == 0) {
    //seen in testing: it chose an Intel I350 over a ConnectX-5 with hardware timestamps
    if (in_domain > 1)
      Add(r, W, EValidationField::Grandmaster,
        L"Masters in domain %u are heard on %d adapters (%s). With grandmaster 0.0.0.0 the Microsoft PTP client "
        L"may use any of them, not necessarily the best. Enter the grandmaster address to choose one.",
        Domain, in_domain, names);
  } else if ((GmProblem == nullptr) && !gm_heard) {
    Add(r, W, EValidationField::Grandmaster,
      L"No Announce messages from the grandmaster address %s are being received on any adapter.", Gm);
  }
}

bool ValidateConfiguration(const SValidationInput& In, SValidationResult& out_Result) {
  ZeroMemory(&out_Result, sizeof(out_Result));
  SValidationResult& r = out_Result;
  const EValidationSeverity E = EValidationSeverity::Error;
  const EValidationSeverity W = EValidationSeverity::Warning;
  const bool prel_ptp = (In.Provider == ETimeProvider::PrelPtp);
  const bool ms_ptp = (In.Provider == ETimeProvider::MsPtp);

  if (!prel_ptp && !ms_ptp) {
    //NTP or nothing: the PTP settings are disabled and not checked
    if (In.Provider == ETimeProvider::None)
      Add(r, W, EValidationField::Provider,
        L"No time provider is selected. Windows Time will have no time source unless another provider is configured.");
    return true;
  }

  //---- errors: entries that cannot be saved, or a provider that cannot work

  if (ms_ptp && (In.MsPtpAvailability != EMsPtpAvailability::Available))
    Add(r, E, EValidationField::Provider, L"%s", MsPtpAvailabilityText(In.MsPtpAvailability));

  if (prel_ptp && (In.Adapter == nullptr))
    Add(r, E, EValidationField::Adapter, L"Select the network adapter that receives PTP.");

  DWORD domain = PTP_DOMAIN_ANY;
  bool domain_valid = ParseDomain(In.DomainText, domain);
  if (!domain_valid)
    Add(r, E, EValidationField::Domain, ms_ptp
      ? L"The PTP domain must be a number from 0 to 255."
      : L"The PTP domain must be a number from 0 to 255, or Any.");
  else if (ms_ptp && (domain == PTP_DOMAIN_ANY)) {
    Add(r, E, EValidationField::Domain, L"The Microsoft PTP client needs a PTP domain number from 0 to 255: it can't accept any domain.");
    domain_valid = false;
  }

  wchar_t gm[0x20];
  FormatAddress(In.GrandmasterAddress, gm, ARRAYSIZE(gm));
  const wchar_t* gm_problem = GrandmasterAddressProblem(In.GrandmasterAddress);
  if (gm_problem != nullptr)
    Add(r, E, EValidationField::Grandmaster,
      L"The grandmaster address %s is %s. Enter the master's own address, or 0.0.0.0 %s.",
      gm, gm_problem, ms_ptp ? L"to accept any master" : L"to select the master automatically");

  DWORD interval;
  if (!ParseDelayRequestInterval(In.IntervalText, interval))
    Add(r, E, EValidationField::DelayRequestInterval,
      L"The delay request interval must be a whole number of milliseconds from %u to %u.",
      MIN_DELAY_REQUEST_INTERVAL, MAX_DELAY_REQUEST_INTERVAL);

  if (ms_ptp && !ParseAnnounceInterval(In.AnnounceIntervalText, interval))
    Add(r, E, EValidationField::AnnounceInterval,
      L"The announce interval must be a whole number of milliseconds from %u to %u.",
      MIN_ANNOUNCE_INTERVAL, MAX_ANNOUNCE_INTERVAL);

  //---- warnings: the configuration can be saved, but probably won't work as intended

  if (ms_ptp) {
    if (!In.MulticastRx)
      Add(r, W, EValidationField::MulticastRx,
        L"Multicast receive is off. The Microsoft PTP client then hears a master only if it sends to this computer "
        L"by unicast. This has not been tested.");
    CheckMsPtpTraffic(In, domain_valid, domain, gm, gm_problem, r);
  } else {
    CheckPrelPtpAdapter(In, domain_valid, domain, gm, gm_problem, r);
  }

  return r.ErrorCount() == 0;
}
