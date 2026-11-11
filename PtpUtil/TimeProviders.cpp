#include "TimeProviders.h"
#include <TimeProv.h>
#include <strsafe.h>

const wchar_t* MsPtpProviderName = L"PtpClient";
static const wchar_t* NtpProviderName = L"NtpClient";

const wchar_t* TimeProviderName(ETimeProvider Provider) {
  switch (Provider) {
  case ETimeProvider::PrelPtp: return L"PREL PTP";
  case ETimeProvider::MsPtp:   return L"Microsoft PTP client";
  case ETimeProvider::Ntp:     return L"Windows NTP client";
  default:                     return L"None";
  }
}

ETimeProvider ChooseTimeProvider(const SProvidersEnabled& Enabled) {
  if (Enabled.PrelPtp)
    return ETimeProvider::PrelPtp;
  if (Enabled.MsPtp)
    return ETimeProvider::MsPtp;
  if (Enabled.Ntp)
    return ETimeProvider::Ntp;
  return ETimeProvider::None;
}

static bool OpenProviderKey(const wchar_t* Provider, REGSAM Access, HKEY& out_Key) {
  wchar_t key_name[0x80];
  GetProviderKeyName(key_name, Provider, ARRAYSIZE(key_name));
  return RegOpenKeyEx(HKEY_LOCAL_MACHINE, key_name, 0, Access, &out_Key) == ERROR_SUCCESS;
}

static bool ProviderEnabled(const wchar_t* Provider) {
  HKEY key;
  if (!OpenProviderKey(Provider, KEY_QUERY_VALUE, key))
    return false;
  DWORD enabled = 0;
  bool result = RegRead(key, wszW32TimeRegValueEnabled, enabled) && (enabled != 0);
  RegCloseKey(key);
  return result;
}

void LoadProvidersEnabled(SProvidersEnabled& out_Enabled) {
  out_Enabled.PrelPtp = ProviderEnabled(ProviderName);
  out_Enabled.MsPtp = ProviderEnabled(MsPtpProviderName);
  out_Enabled.Ntp = ProviderEnabled(NtpProviderName);
}

//false if the key doesn't exist (and Must) or can't be written
static bool SetEnabled(const wchar_t* Provider, bool Enabled, bool Must) {
  HKEY key;
  if (!OpenProviderKey(Provider, KEY_SET_VALUE | KEY_QUERY_VALUE, key))
    return !Must;
  bool result = RegWrite(key, wszW32TimeRegValueEnabled, Enabled ? 1 : 0);
  RegCloseKey(key);
  return result;
}

bool SelectTimeProvider(ETimeProvider Selected) {
  //the others first, so that two are never enabled at once
  bool ok = true;
  if (Selected != ETimeProvider::PrelPtp)
    ok &= SetEnabled(ProviderName, false, false);
  if (Selected != ETimeProvider::MsPtp)
    ok &= SetEnabled(MsPtpProviderName, false, false);
  if (Selected != ETimeProvider::Ntp)
    ok &= SetEnabled(NtpProviderName, false, false);

  switch (Selected) {
  case ETimeProvider::PrelPtp: ok &= SetEnabled(ProviderName, true, true); break;
  case ETimeProvider::MsPtp:   ok &= SetEnabled(MsPtpProviderName, true, true); break;
  case ETimeProvider::Ntp:     ok &= SetEnabled(NtpProviderName, true, true); break;
  default: break;
  }
  return ok;
}

bool SaveTimeProviders(ETimeProvider Selected, const SConfiguration& PrelPtpConfig, const SMsPtpConfiguration* MsPtpConfig) {
  if (!SaveConfiguration(PrelPtpConfig))
    return false;
  if (Selected == ETimeProvider::MsPtp)
    if ((MsPtpConfig == nullptr) || !SaveMsPtpConfiguration(*MsPtpConfig))
      return false;
  return SelectTimeProvider(Selected);
}


//---- Microsoft PTP client

void DefaultMsPtpConfiguration(SMsPtpConfiguration& out_Config) {
  out_Config.DomainNumber = 0;
  out_Config.GrandmasterAddress = 0;
  out_Config.DelayPollInterval = DEFAULT_MS_PTP_DELAY_POLL_INTERVAL;
  out_Config.AnnounceInterval = DEFAULT_MS_PTP_ANNOUNCE_INTERVAL;
  out_Config.MulticastRx = true;
  out_Config.MulticastTx = false;
}

const SRegValue* SRegPlan::Find(const wchar_t* Name) const {
  for (int i = 0; i < Count; ++i)
    if (_wcsicmp(Values[i].Name, Name) == 0)
      return &Values[i];
  return nullptr;
}

static SRegValue& AddValue(SRegPlan& Plan, const wchar_t* Name, SRegValue::EKind Kind) {
  SRegValue& v = Plan.Values[Plan.Count++];   //PlanMsPtpValues adds fewer than MAX_VALUES
  ZeroMemory(&v, sizeof(v));
  v.Name = Name;
  v.Kind = Kind;
  return v;
}

static void AddDword(SRegPlan& Plan, const wchar_t* Name, DWORD Value) {
  AddValue(Plan, Name, SRegValue::Dword).Number = Value;
}

static void AddText(SRegPlan& Plan, const wchar_t* Name, SRegValue::EKind Kind, const wchar_t* Text) {
  SRegValue& v = AddValue(Plan, Name, Kind);
  StringCchCopy(v.Text, ARRAYSIZE(v.Text), Text);
}

void PlanMsPtpValues(const SMsPtpConfiguration& Config, SRegPlan& out_Plan) {
  out_Plan.Count = 0;
  //REG_EXPAND_SZ: w32time expands it only if typed as such (as for PrelPtp.dll)
  AddText(out_Plan, wszW32TimeRegValueDllName, SRegValue::ExpandString, L"%SystemRoot%\\System32\\ptpprov.dll");
  AddDword(out_Plan, wszW32TimeRegValueInputProvider, 1);
  AddDword(out_Plan, L"DomainNumber", Config.DomainNumber & 0xFF);
  AddDword(out_Plan, L"DelayPollInterval", Config.DelayPollInterval);
  AddDword(out_Plan, L"AnnounceInterval", Config.AnnounceInterval);
  AddDword(out_Plan, L"EnableMulticastRx", Config.MulticastRx ? 1 : 0);
  if (Config.MulticastTx)
    AddDword(out_Plan, L"EnableMulticastTx", 1);
  else
    AddValue(out_Plan, L"EnableMulticastTx", SRegValue::Delete);

  if (Config.GrandmasterAddress == 0) {
    //any master: an empty or absent PtpMasters both worked; empty says what is meant
    AddText(out_Plan, L"PtpMasters", SRegValue::String, L"");
    AddDword(out_Plan, L"AllowAnyMaster", 1);
  } else {
    wchar_t address[0x20] = { 0 };
    IN_ADDR addr;
    addr.S_un.S_addr = Config.GrandmasterAddress;
    InetNtop(AF_INET, &addr, address, ARRAYSIZE(address));
    AddText(out_Plan, L"PtpMasters", SRegValue::String, address);
    //AllowAnyMaster = 1 would override the list
    AddValue(out_Plan, L"AllowAnyMaster", SRegValue::Delete);
  }
}

bool ParsePtpMasters(const wchar_t* Text, DWORD& out_Address) {
  if (Text == nullptr)
    return false;
  while ((*Text == L' ') || (*Text == L',') || (*Text == L';') || (*Text == L'\t'))
    ++Text;
  wchar_t first[0x20];
  size_t n = 0;
  while ((Text[n] != 0) && (Text[n] != L' ') && (Text[n] != L',') && (Text[n] != L';') && (Text[n] != L'\t')) {
    if (n + 1 >= ARRAYSIZE(first))
      return false;
    first[n] = Text[n];
    ++n;
  }
  first[n] = 0;
  if (n == 0)
    return false;
  IN_ADDR addr;
  if (InetPton(AF_INET, first, &addr) != 1)
    return false;
  out_Address = addr.S_un.S_addr;
  return true;
}

static bool ApplyPlan(HKEY Key, const SRegPlan& Plan) {
  bool ok = true;
  for (int i = 0; i < Plan.Count; ++i) {
    const SRegValue& v = Plan.Values[i];
    LSTATUS status = ERROR_SUCCESS;
    switch (v.Kind) {
    case SRegValue::Delete:
      status = RegDeleteValue(Key, v.Name);
      if (status == ERROR_FILE_NOT_FOUND)
        status = ERROR_SUCCESS;
      break;
    case SRegValue::Dword:
      status = RegSetValueEx(Key, v.Name, 0, REG_DWORD, (const BYTE*)&v.Number, sizeof(v.Number));
      break;
    case SRegValue::String:
    case SRegValue::ExpandString:
      status = RegSetValueEx(Key, v.Name, 0, (v.Kind == SRegValue::String) ? REG_SZ : REG_EXPAND_SZ,
        (const BYTE*)v.Text, ((DWORD)wcslen(v.Text) + 1) * sizeof(wchar_t));
      break;
    }
    ok &= (status == ERROR_SUCCESS);
  }
  return ok;
}

bool SaveMsPtpConfiguration(const SMsPtpConfiguration& Config) {
  wchar_t key_name[0x80];
  GetProviderKeyName(key_name, MsPtpProviderName, ARRAYSIZE(key_name));
  HKEY key;
  if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, key_name, 0, nullptr, 0, KEY_SET_VALUE | KEY_QUERY_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS)
    return false;
  SRegPlan plan;
  PlanMsPtpValues(Config, plan);
  bool ok = ApplyPlan(key, plan);
  RegCloseKey(key);
  return ok;
}

bool LoadMsPtpConfiguration(SMsPtpConfiguration& out_Config) {
  DefaultMsPtpConfiguration(out_Config);
  HKEY key;
  if (!OpenProviderKey(MsPtpProviderName, KEY_QUERY_VALUE, key))
    return false;

  DWORD value;
  if (RegRead(key, L"DomainNumber", value) && (value <= 255))
    out_Config.DomainNumber = value;
  if (RegRead(key, L"DelayPollInterval", value))
    out_Config.DelayPollInterval = value;
  if (RegRead(key, L"AnnounceInterval", value))
    out_Config.AnnounceInterval = value;
  if (RegRead(key, L"EnableMulticastRx", value))
    out_Config.MulticastRx = (value != 0);
  if (RegRead(key, L"EnableMulticastTx", value))
    out_Config.MulticastTx = (value != 0);

  bool any_master = RegRead(key, L"AllowAnyMaster", value) && (value != 0);
  if (!any_master) {
    //REG_SZ or REG_MULTI_SZ (the first string); RegGetValue terminates it
    wchar_t masters[0x100] = { 0 };
    DWORD size = sizeof(masters);
    DWORD address;
    if ((RegGetValue(key, nullptr, L"PtpMasters", RRF_RT_REG_SZ | RRF_RT_REG_MULTI_SZ, nullptr, masters, &size) == ERROR_SUCCESS)
      && ParsePtpMasters(masters, address))
      out_Config.GrandmasterAddress = address;
  }

  RegCloseKey(key);
  return true;
}


//---- the settings both PTP providers have

void InitialPtpSettings(const SConfiguration* PrelPtp, const SMsPtpConfiguration* MsPtp,
  SPtpSettings& out_PrelPtp, SPtpSettings& out_MsPtp) {
  SMsPtpConfiguration ms_defaults;
  DefaultMsPtpConfiguration(ms_defaults);

  if (PrelPtp != nullptr)
    out_PrelPtp = { PrelPtp->DomainNumber, PrelPtp->GrandmasterAddress, PrelPtp->DelayRequestInterval };
  else if (MsPtp != nullptr)
    out_PrelPtp = { MsPtp->DomainNumber, MsPtp->GrandmasterAddress, DEFAULT_PREL_PTP_DELAY_REQUEST_INTERVAL };
  else
    out_PrelPtp = { PTP_DOMAIN_ANY, 0, DEFAULT_PREL_PTP_DELAY_REQUEST_INTERVAL };

  if (MsPtp != nullptr)
    out_MsPtp = { MsPtp->DomainNumber, MsPtp->GrandmasterAddress, MsPtp->DelayPollInterval };
  else if (PrelPtp != nullptr)
    out_MsPtp = { (PrelPtp->DomainNumber <= 255) ? PrelPtp->DomainNumber : 0, PrelPtp->GrandmasterAddress, ms_defaults.DelayPollInterval };
  else
    out_MsPtp = { ms_defaults.DomainNumber, ms_defaults.GrandmasterAddress, ms_defaults.DelayPollInterval };
}


//---- availability

EMsPtpAvailability MsPtpAvailability(DWORD WindowsBuild, bool DllPresent) {
  if (WindowsBuild < MS_PTP_MIN_BUILD)
    return EMsPtpAvailability::WindowsTooOld;
  if (!DllPresent)
    return EMsPtpAvailability::NoDll;
  return EMsPtpAvailability::Available;
}

//GetVersionEx reports what the program's manifest claims to support; RtlGetVersion the real build
static DWORD WindowsBuild() {
  typedef LONG(WINAPI* TRtlGetVersion)(OSVERSIONINFOW*);
  HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
  TRtlGetVersion rtl_get_version = ntdll ? (TRtlGetVersion)GetProcAddress(ntdll, "RtlGetVersion") : nullptr;
  if (rtl_get_version == nullptr)
    return 0;
  OSVERSIONINFOW info;
  ZeroMemory(&info, sizeof(info));
  info.dwOSVersionInfoSize = sizeof(info);
  return (rtl_get_version(&info) == 0) ? info.dwBuildNumber : 0;
}

EMsPtpAvailability CheckMsPtpAvailability() {
  wchar_t path[MAX_PATH];
  UINT n = GetSystemDirectory(path, ARRAYSIZE(path));
  bool present = (n > 0) && (n < ARRAYSIZE(path)) &&
    SUCCEEDED(StringCchCat(path, ARRAYSIZE(path), L"\\ptpprov.dll")) &&
    (GetFileAttributes(path) != INVALID_FILE_ATTRIBUTES);
  return MsPtpAvailability(WindowsBuild(), present);
}

const wchar_t* MsPtpAvailabilityText(EMsPtpAvailability Availability) {
  switch (Availability) {
  case EMsPtpAvailability::WindowsTooOld:
    return L"The Microsoft PTP client needs Windows Server 2022 or Windows 11, or later.";
  case EMsPtpAvailability::NoDll:
    return L"The Microsoft PTP client (ptpprov.dll) is not installed on this computer.";
  default:
    return L"";
  }
}


//---- uninstall

SUninstallPlan PlanUninstall(const SProvidersEnabled& Enabled) {
  SUninstallPlan plan;
  plan.AskToEnableNtp = Enabled.PrelPtp && !Enabled.MsPtp && !Enabled.Ntp;
  plan.KeepFirewallRule = Enabled.MsPtp;
  return plan;
}
