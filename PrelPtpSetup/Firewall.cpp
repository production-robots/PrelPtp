#include "Firewall.h"

#include <netfw.h>
#include <oleauto.h>
#include <wrl/client.h>

#pragma comment(lib, "Ole32")
#pragma comment(lib, "OleAut32")

using Microsoft::WRL::ComPtr;


struct UsingCom {
  HRESULT hr;
  operator bool() const { return SUCCEEDED(hr) || (hr == RPC_E_CHANGED_MODE); }
  UsingCom() : hr(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED)) {}
  ~UsingCom() { if (SUCCEEDED(hr)) CoUninitialize(); }
};

/*
Owns a BSTR for the length of a call. The INetFw* methods take BSTR arguments, and a plain
wchar_t string is not a BSTR: it has no length prefix, so the callee may read garbage.
*/
struct Bstr {
  BSTR str;
  operator BSTR() const { return str; }
  explicit Bstr(const wchar_t* Text) : str(SysAllocString(Text)) {}
  ~Bstr() { SysFreeString(str); }
  Bstr(const Bstr&) = delete;
  Bstr& operator=(const Bstr&) = delete;
};


static void SetPortInfo(INetFwRule* Rule) {
  Rule->put_Description(Bstr(L"Precision Time Protocol"));
  Rule->put_LocalPorts(Bstr(L"319,320"));
}

HRESULT RemoveFirewallRule() {
  UsingCom com;

  if (!com)
    return com.hr;

  ComPtr<INetFwPolicy2> fw_policy;

  HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&fw_policy));

  if (!SUCCEEDED(hr))
    return hr;

  ComPtr<INetFwRules> rules;
  hr = fw_policy->get_Rules(&rules);

  if (!SUCCEEDED(hr))
    return hr;

  hr = rules->Remove(Bstr(L"PTP"));

  return hr;

}


HRESULT AddFirewallRule() {
  UsingCom com;

  if (!com)
    return com.hr;

  ComPtr<INetFwPolicy2> fw_policy;

  HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&fw_policy));

  if (FAILED(hr))
    return hr;

  long current_profiles;

  hr = fw_policy->get_CurrentProfileTypes(&current_profiles);
  if (FAILED(hr))
    return hr;

  // When possible we avoid adding firewall rules to the Public profile.
  // If Public is currently active and it is not the only active profile, we remove it from the bitmask
  if ((current_profiles & NET_FW_PROFILE2_PUBLIC) && (current_profiles != NET_FW_PROFILE2_PUBLIC))
    current_profiles ^= NET_FW_PROFILE2_PUBLIC;


  ComPtr<INetFwRules> rules;

  //search for existing rule
  hr = fw_policy->get_Rules(&rules);

  if (!SUCCEEDED(hr))
    return hr;

  ComPtr<INetFwRule> mct_rule;

  Bstr rule_name(L"PTP");

  hr = rules->Item(rule_name, &mct_rule);

  if (SUCCEEDED(hr)) {
    //update exising rule
    SetPortInfo(mct_rule.Get());
  } else if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) { //rule does not exist
    hr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&mct_rule));

    if (!SUCCEEDED(hr))
      return hr;

    mct_rule->put_Name(rule_name);

    mct_rule->put_ApplicationName(Bstr(L"%systemroot%\\system32\\svchost.exe"));

    mct_rule->put_ServiceName(Bstr(L"W32Time"));

    mct_rule->put_Protocol(NET_FW_IP_PROTOCOL_UDP);

    mct_rule->put_Grouping(Bstr(L"PREL PTP Provider Group"));

    mct_rule->put_Action(NET_FW_ACTION_ALLOW);

    mct_rule->put_Profiles(current_profiles);

    mct_rule->put_Enabled(VARIANT_TRUE);

    SetPortInfo(mct_rule.Get());

    hr = rules->Add(mct_rule.Get());

    if (FAILED(hr))
      return hr;

  } else {
    return hr;
  }

  return S_OK;
}

/*
Temporary rule that lets the setup program itself receive PTP General messages (UDP 320) while
its dialog is open, so the adapter list can show where PTP traffic is. Added when the dialog
opens and removed when it closes. A rule left behind by a crash is replaced the next time.
*/
static const wchar_t* LISTEN_RULE_NAME = L"PREL PTP setup - detect PTP traffic (temporary)";

static HRESULT GetRules(ComPtr<INetFwPolicy2>& out_Policy, ComPtr<INetFwRules>& out_Rules) {
  HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&out_Policy));
  if (FAILED(hr))
    return hr;
  return out_Policy->get_Rules(&out_Rules);
}

HRESULT RemoveListenFirewallRule() {
  UsingCom com;
  if (!com)
    return com.hr;
  ComPtr<INetFwPolicy2> policy;
  ComPtr<INetFwRules> rules;
  HRESULT hr = GetRules(policy, rules);
  if (FAILED(hr))
    return hr;
  return rules->Remove(Bstr(LISTEN_RULE_NAME));
}

HRESULT AddListenFirewallRule() {
  UsingCom com;
  if (!com)
    return com.hr;
  ComPtr<INetFwPolicy2> policy;
  ComPtr<INetFwRules> rules;
  HRESULT hr = GetRules(policy, rules);
  if (FAILED(hr))
    return hr;
  rules->Remove(Bstr(LISTEN_RULE_NAME));  //a stale copy, if any

  wchar_t exe[MAX_PATH];
  if (GetModuleFileName(nullptr, exe, ARRAYSIZE(exe)) == 0)
    return HRESULT_FROM_WIN32(GetLastError());

  ComPtr<INetFwRule> rule;
  hr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&rule));
  if (FAILED(hr))
    return hr;
  rule->put_Name(Bstr(LISTEN_RULE_NAME));
  rule->put_Description(Bstr(L"Lets the PREL PTP setup program see PTP traffic on each adapter. Removed when the setup program closes."));
  rule->put_ApplicationName(Bstr(exe));
  rule->put_Protocol(NET_FW_IP_PROTOCOL_UDP);
  rule->put_LocalPorts(Bstr(L"320"));
  rule->put_Direction(NET_FW_RULE_DIR_IN);
  rule->put_Grouping(Bstr(L"PREL PTP Provider Group"));
  rule->put_Profiles(NET_FW_PROFILE2_ALL);
  rule->put_Action(NET_FW_ACTION_ALLOW);
  rule->put_Enabled(VARIANT_TRUE);
  return rules->Add(rule.Get());
}
