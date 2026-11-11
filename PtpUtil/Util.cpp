#include "Util.h"
#include <TimeProv.h>
#include <strsafe.h>

#pragma comment(lib, "iphlpapi")

const WORD DEFAULT_MULTICAST_PORT = 28523;

const wchar_t* ProviderName = L"PrelPtpProvider";
const wchar_t* HarnessName = L"TestHarness";

//not linked to RTL
template<typename T> 
class auto_buf {
private:
  T* _buf;
public:
  void reset(T* NewBuf) {
    delete[] _buf;
    _buf = NewBuf;
  }
  T* get() { return _buf; }
  const T* get() const { return _buf;  }
  auto_buf(T* ABuf) : _buf(ABuf) {}
  ~auto_buf() { delete[] _buf; }
};


const wchar_t* AdapterStateText(EAdapterState State) {
  switch (State) {
  case EAdapterState::Ready:           return L"adapter is ready";
  case EAdapterState::NotConfigured:   return L"no adapter is configured (AdapterName registry value is empty)";
  case EAdapterState::NotFound:        return L"the configured adapter was not found (it may be disabled or not yet started)";
  case EAdapterState::NotOperational:  return L"the configured adapter is not connected or is restarting";
  case EAdapterState::NoAddress:       return L"the configured adapter has no IPv4 address";
  case EAdapterState::AddressNotReady: return L"the configured adapter's IPv4 address is not usable yet (duplicate address detection in progress)";
  default:                             return L"network adapters could not be enumerated";
  }
}

static bool IsLinkLocal(DWORD NetAddress) {
  return (ntohl(NetAddress) & 0xFFFF0000) == 0xA9FE0000; //169.254.0.0/16
}

//the first IPv4 address that has completed duplicate address detection, preferring a
//routable address over an APIPA (169.254.x.x) one. 0 if none.
static DWORD ChooseAddress(PIP_ADAPTER_ADDRESSES Adapter, bool& out_AnyAddress) {
  out_AnyAddress = false;
  DWORD chosen(0);
  bool chosen_is_link_local(false);
  for (PIP_ADAPTER_UNICAST_ADDRESS unicast = Adapter->FirstUnicastAddress; unicast != nullptr; unicast = unicast->Next) {
    const sockaddr* sa = unicast->Address.lpSockaddr;
    if ((sa == nullptr) || (sa->sa_family != AF_INET))
      continue;
    out_AnyAddress = true;
    if (unicast->DadState != IpDadStatePreferred)
      continue;
    DWORD address = ((const sockaddr_in*)sa)->sin_addr.s_addr;
    bool link_local = IsLinkLocal(address);
    if ((chosen == 0) || (chosen_is_link_local && !link_local)) {
      chosen = address;
      chosen_is_link_local = link_local;
    }
  }
  return chosen;
}

EAdapterState ResolveAdapter(const wchar_t* AdapterName, SAdapterInfo& out_Info) {
  ZeroMemory(&out_Info, sizeof(out_Info));

  if ((AdapterName == nullptr) || (AdapterName[0] == 0))
    return EAdapterState::NotConfigured;

  //AdapterName is the adapter GUID string, which GetAdaptersAddresses returns as narrow chars
  char narrow_name[(sizeof(TAdapterName) / sizeof(wchar_t)) * 3];
  if (WideCharToMultiByte(CP_UTF8, 0, AdapterName, -1, narrow_name, (int)sizeof(narrow_name), nullptr, nullptr) == 0)
    return EAdapterState::NotFound;

  const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
  ULONG size = 1024 * 16;
  auto_buf<char> buf(new char[size]);
  ULONG result = GetAdaptersAddresses(AF_INET, flags, nullptr, (PIP_ADAPTER_ADDRESSES)buf.get(), &size);
  //the adapter list can grow between calls, so allow a few attempts
  for (int attempt = 0; (result == ERROR_BUFFER_OVERFLOW) && (attempt < 3); ++attempt) {
    buf.reset(new char[size]);
    result = GetAdaptersAddresses(AF_INET, flags, nullptr, (PIP_ADAPTER_ADDRESSES)buf.get(), &size);
  }
  if (result == ERROR_NO_DATA)
    return EAdapterState::NotFound;
  if (result != ERROR_SUCCESS)
    return EAdapterState::Error;

  for (PIP_ADAPTER_ADDRESSES adapter = (PIP_ADAPTER_ADDRESSES)buf.get(); adapter != nullptr; adapter = adapter->Next) {
    if (_stricmp(adapter->AdapterName, narrow_name) != 0)
      continue;

    out_Info.IfIndex = adapter->IfIndex;
    uint32_t mac_addr_length(adapter->PhysicalAddressLength);
    if (mac_addr_length > sizeof(TMacAddress))
      mac_addr_length = sizeof(TMacAddress);
    CopyMemory(out_Info.MacAddress, adapter->PhysicalAddress, mac_addr_length);

    if (adapter->OperStatus != IfOperStatusUp)
      return EAdapterState::NotOperational;

    bool any_address(false);
    DWORD chosen = ChooseAddress(adapter, any_address);

    if (chosen != 0) {
      out_Info.LocalAddress = chosen;
      return EAdapterState::Ready;
    }
    return any_address ? EAdapterState::AddressNotReady : EAdapterState::NoAddress;
  }
  return EAdapterState::NotFound;
}

bool GetAdapterList(IpAddressEntry* out_AddressList, DWORD& inout_Count) {
  DWORD max_count(inout_Count);
  inout_Count = 0;

  const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
  ULONG size = 1024 * 56;
  auto_buf<char> buf(new char[size]);
  ULONG result = GetAdaptersAddresses(AF_INET, flags, nullptr, (PIP_ADAPTER_ADDRESSES)buf.get(), &size);
  for (int attempt = 0; (result == ERROR_BUFFER_OVERFLOW) && (attempt < 3); ++attempt) {
    buf.reset(new char[size]);
    result = GetAdaptersAddresses(AF_INET, flags, nullptr, (PIP_ADAPTER_ADDRESSES)buf.get(), &size);
  }
  if (result == ERROR_NO_DATA)
    return true;
  if (result != ERROR_SUCCESS)
    return false;

  DWORD count(0);
  for (PIP_ADAPTER_ADDRESSES adapter = (PIP_ADAPTER_ADDRESSES)buf.get(); (adapter != nullptr) && (count < max_count); adapter = adapter->Next) {
    IpAddressEntry* entry = out_AddressList + count;
    ZeroMemory(entry, sizeof(*entry));
    MultiByteToWideChar(CP_UTF8, 0, adapter->AdapterName, -1, entry->AdapterName, ARRAYSIZE(entry->AdapterName));
    StringCchCopyW(entry->FriendlyName, ARRAYSIZE(entry->FriendlyName), adapter->FriendlyName);
    uint32_t mac_addr_length(adapter->PhysicalAddressLength);
    if (mac_addr_length > sizeof(TMacAddress))
      mac_addr_length = sizeof(TMacAddress);
    CopyMemory(entry->MacAddress, adapter->PhysicalAddress, mac_addr_length);
    entry->IfIndex = adapter->IfIndex;
    entry->Up = adapter->OperStatus == IfOperStatusUp;
    entry->Ethernet = adapter->IfType == IF_TYPE_ETHERNET_CSMACD;
    entry->Present = true;
    bool any_address;
    entry->LocalAddress = entry->Up ? ChooseAddress(adapter, any_address) : 0;

    MIB_IF_ROW2 row;
    ZeroMemory(&row, sizeof(row));
    row.InterfaceLuid = adapter->Luid;
    if (GetIfEntry2(&row) == NO_ERROR)
      entry->ConnectorPresent = row.InterfaceAndOperStatusFlags.ConnectorPresent != FALSE;

    ++count;
  }
  inout_Count = count;
  return true;
}

void GetProviderKeyName(wchar_t* KeyName, const wchar_t* Provider, size_t Chars) {
  STRSAFE_LPWSTR next;
  size_t next_chars;
  StringCchCopyEx(KeyName, Chars, wszW32TimeRegKeyTimeProviders, &next, &next_chars, 0);
  StringCchCopyEx(next, next_chars, L"\\", &next, &next_chars, 0);
  StringCchCopy(next, next_chars, Provider);
}

static void GetConfigurationKeyName(wchar_t* KeyName, size_t Chars) {
  GetProviderKeyName(KeyName, ProviderName, Chars);
}

static void GetNtpClientKeyName(wchar_t* KeyName, size_t Chars) {
  GetProviderKeyName(KeyName, L"NtpClient", Chars);
}

bool SetNtpClientEnabled(bool Enabled) {
  HKEY key;
  wchar_t key_name[0x80];
  GetNtpClientKeyName(key_name, ARRAYSIZE(key_name));
  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, key_name, 0, KEY_SET_VALUE | KEY_QUERY_VALUE, &key) != ERROR_SUCCESS)
    return false;
  bool result = RegWrite(key, wszW32TimeRegValueEnabled, Enabled ? 1 : 0);
  RegCloseKey(key);
  return result;
}

bool SaveConfiguration(const SConfiguration& Config) {
  HKEY key;
  wchar_t key_name[0x80];

  GetConfigurationKeyName(key_name, ARRAYSIZE(key_name));
  if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, key_name, 0, nullptr, 0, KEY_SET_VALUE | KEY_QUERY_VALUE, nullptr, &key, nullptr) == ERROR_SUCCESS) {
    // Must be REG_EXPAND_SZ: W32Time passes DllName to LoadLibrary after expanding it only if typed as such;
    // a REG_SZ containing %SystemRoot% fails with ERROR_FILE_NOT_FOUND and the service won't start.
    static const wchar_t dll_name[] = L"%SystemRoot%\\System32\\PrelPtp.dll";
    RegSetValueEx(key, wszW32TimeRegValueDllName, 0, REG_EXPAND_SZ, (const BYTE*)dll_name, sizeof(dll_name));
    RegWrite(key, wszW32TimeRegValueInputProvider, 1);
    RegWrite(key, L"AdapterName", Config.AdapterName);
    RegWrite(key, L"FilterLength", Config.FilterLength);
    RegWrite(key, L"DelayRequestInterval", Config.DelayRequestInterval);

    //values whose absence means something must be deleted, not left with an old setting

    //absent: accept any domain
    if (Config.DomainNumber <= 255)
      RegWrite(key, L"DomainNumber", Config.DomainNumber);
    else
      RegDeleteValue(key, L"DomainNumber");

    //absent: select the master automatically (BMCA)
    wchar_t grandmaster_address[0x20] = { 0 };
    IN_ADDR addr;
    addr.S_un.S_addr = Config.GrandmasterAddress;
    if ((Config.GrandmasterAddress != 0) && (InetNtop(AF_INET, &addr, grandmaster_address, ARRAYSIZE(grandmaster_address)) != nullptr))
      RegWrite(key, L"GrandmasterAddress", grandmaster_address);
    else
      RegDeleteValue(key, L"GrandmasterAddress");

    //legacy value, always 0 and never used: DomainNumber replaces it
    RegDeleteValue(key, L"SubDomain");

    //emergency override, set only by hand in the registry. Older setup programs wrote 1 for
    //Matrox adapters; saving from the dialog clears it so those installations use delay requests again.
    RegDeleteValue(key, L"DisableDelayRequest");

    RegCloseKey(key);
    return true;
  }

  return false;
}


bool DeleteConfiguration() {
  wchar_t key_name[0x80];
  GetConfigurationKeyName(key_name, ARRAYSIZE(key_name));
  return (RegDeleteKey(HKEY_LOCAL_MACHINE, key_name) == ERROR_SUCCESS);
}

bool LoadConfiguration(SConfiguration& out_Config) {
  HKEY key;
  bool result(false);
  ZeroMemory(&out_Config, sizeof(out_Config));
  wchar_t key_name[0x80];

  GetConfigurationKeyName(key_name, ARRAYSIZE(key_name));
  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, key_name, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS)
    return false;

  RegRead(key, L"AdapterName", out_Config.AdapterName, ARRAYSIZE(out_Config.AdapterName));

  out_Config.FilterLength = 50;
  RegRead(key, L"FilterLength", out_Config.FilterLength);

  out_Config.DelayRequestInterval = 1200;
  RegRead(key, L"DelayRequestInterval", out_Config.DelayRequestInterval);

  //domain filter: absent means any domain, as in installations from before this value existed.
  //(The legacy "SubDomain" value could not be used: older setup programs always wrote 0 there.)
  out_Config.DomainNumber = PTP_DOMAIN_ANY;
  DWORD domain_number;
  if (RegRead(key, L"DomainNumber", domain_number) && (domain_number <= 255))
    out_Config.DomainNumber = domain_number;

  wchar_t grandmaster_address[0x20];
  if (RegRead(key, L"GrandmasterAddress", grandmaster_address, ARRAYSIZE(grandmaster_address))) {
    IN_ADDR addr;
    if (InetPton(AF_INET, grandmaster_address, &addr) == 1) 
      out_Config.GrandmasterAddress = addr.S_un.S_addr;
  }

  RegCloseKey(key);
  return true;
}

bool LoadDisableDelayRequestSetting() {
  HKEY key;
  wchar_t key_name[0x80];
  GetConfigurationKeyName(key_name, ARRAYSIZE(key_name));
  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, key_name, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS)
    return false;

  DWORD disable_dr = 0;
  RegRead(key, L"DisableDelayRequest", disable_dr);
  RegCloseKey(key);
  return disable_dr != 0;
}

ETimestampMode LoadTimestampModeSetting() {
  HKEY key;
  wchar_t key_name[0x80];
  GetConfigurationKeyName(key_name, ARRAYSIZE(key_name));
  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, key_name, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS)
    return ETimestampMode::Auto;

  DWORD mode = 0;
  RegRead(key, L"TimestampMode", mode);
  RegCloseKey(key);
  return (mode == 1) ? ETimestampMode::Software : ETimestampMode::Auto;
}

bool ParseDomain(const wchar_t* Text, DWORD& out_Domain) {
  if (Text == nullptr)
    return false;
  while (*Text == L' ')
    ++Text;
  if ((*Text == 0) || (_wcsnicmp(Text, L"any", 3) == 0)) {
    out_Domain = PTP_DOMAIN_ANY;
    return true;
  }
  DWORD value = 0;
  int digits = 0;
  while ((*Text >= L'0') && (*Text <= L'9')) {
    value = value * 10 + (*Text - L'0');
    ++Text;
    ++digits;
    if (value > 255)   //also stops overflow on long input
      return false;
  }
  if (digits == 0)
    return false;
  //only a description may follow, separated by white space
  if ((*Text != 0) && (*Text != L' ') && (*Text != L'\t'))
    return false;
  out_Domain = value;
  return true;
}

void FormatDomain(DWORD Domain, wchar_t* Buf, size_t Chars) {
  if (Domain > 255)
    StringCchCopy(Buf, Chars, L"Any");
  else
    StringCchPrintf(Buf, Chars, L"%u", Domain);
}

void SysErrorMessage(DWORD Error, LPTSTR Buf, DWORD Chars) {
  if (!FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, Error, 0, Buf, Chars, 0))
    StringCchPrintf(Buf, Chars, L"Unknown error code 0x%.8X", Error);
}

bool RegRead(HKEY Key, const wchar_t* Name, wchar_t* out_Value, DWORD Length) {
  DWORD reg_type;
  DWORD size(Length * sizeof(wchar_t));
  return (RegQueryValueEx(Key, Name, nullptr, &reg_type, (LPBYTE)out_Value, &size) == ERROR_SUCCESS) && (reg_type == REG_SZ);
}

bool RegRead(HKEY Key, const wchar_t* Name, DWORD& out_Value) {
  DWORD reg_type;
  DWORD size(sizeof(out_Value));
  return (RegQueryValueEx(Key, Name, nullptr, &reg_type, (LPBYTE)&out_Value, &size) == ERROR_SUCCESS) && (reg_type == REG_DWORD);
}

bool RegWrite(HKEY Key, const wchar_t* Name, const wchar_t* Value) {
  return RegSetValueEx(Key, Name, 0, REG_SZ, (const BYTE*)Value, ((DWORD)wcslen(Value) + 1) * sizeof(wchar_t)) == ERROR_SUCCESS;
}

bool RegWrite(HKEY Key, const wchar_t* Name, DWORD Value) {
  return RegSetValueEx(Key, Name, 0, REG_DWORD, (const BYTE*)&Value, sizeof(DWORD)) == ERROR_SUCCESS;
}

//I have no idea if/how this works

static uint16_t lfsr = 0xACE1u;
uint16_t Uniform() {
  static unsigned bit;
  bit = ((lfsr >> 0) ^ (lfsr >> 2) ^ (lfsr >> 3) ^ (lfsr >> 5)) & 1;
  return lfsr = (lfsr >> 1) | (bit << 15);
}

void SeedUniform() {
  lfsr = (uint16_t)GetTickCount() ^ lfsr;
}

