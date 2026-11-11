#pragma once

#include "Util.h"

/*
Time providers: which of PrelPtp, Microsoft's PTP client (ptpprov.dll) and the Windows NTP
client w32time uses, and the Microsoft PTP client's settings. For the setup program.

Only one provider is enabled at a time. Two PTP providers can't run together (ptpprov binds UDP
319/320 exclusively), and w32time would combine PTP and NTP. If the registry has more than one
enabled (set by hand, or by an older setup program), ChooseTimeProvider picks one, and saving
from the setup program leaves only that one enabled.

The registry logic that decides what to write is kept apart from the registry calls
(PlanMsPtpValues, ParsePtpMasters, PlanUninstall, MsPtpAvailability) so that it can be unit tested.

The Microsoft PTP client's values are undocumented; what they do was found by experiment (each
case written to the registry, w32time restarted, the PTP traffic captured and the events read), with
ptpprov.dll 10.0.20348.1 (Server 2022) and 10.0.26100.1 (Windows 11):
  - PtpMasters is an allow-list: masters not in it are ignored (PTP-Operational event 516).
  - AllowAnyMaster = 1 accepts any master and overrides PtpMasters. So it is removed, not set
    to 0 (which was not tested), whenever a fixed master is configured.
  - EnableMulticastTx = 1 sends Delay_Req by multicast; otherwise they are unicast to the master.
    It is removed, not set to 0, when off: absent is the tested unicast case.
  - MulticastIfIndex and MulticastOnlyTxEnabled had no visible effect and are not written.
  - Values are read only when w32time starts the provider.
Values this module doesn't manage are left as they are.
*/

enum class ETimeProvider { None, PrelPtp, MsPtp, Ntp };

const wchar_t* TimeProviderName(ETimeProvider Provider);

//the registry keys' Enabled values; a missing key or value counts as not enabled
struct SProvidersEnabled {
  bool PrelPtp;
  bool MsPtp;
  bool Ntp;
};

//the first enabled one of PrelPtp, MsPtp, Ntp; None if none is enabled
ETimeProvider ChooseTimeProvider(const SProvidersEnabled& Enabled);

void LoadProvidersEnabled(SProvidersEnabled& out_Enabled);

//Sets Enabled to 1 for Selected and to 0 for the other two. Keys that don't exist are not created:
//the selected provider's key must have been written first (SaveConfiguration, SaveMsPtpConfiguration).
//Returns false if the selected provider's key is missing or can't be written.
bool SelectTimeProvider(ETimeProvider Selected);

struct SMsPtpConfiguration;

//What the setup program's OK saves, in this order:
//  1. PrelPtp's settings (SaveConfiguration). PrelPtp stays installed whichever provider is
//     selected, and its settings are kept for switching back.
//  2. If the Microsoft PTP client is selected, its settings (SaveMsPtpConfiguration), creating
//     the PtpClient key if it doesn't exist. MsPtpConfig is not used otherwise and may be nullptr.
//  3. SelectTimeProvider.
//If a step fails the later ones are skipped, so a provider is never enabled with its settings
//half written. Returns false if any step failed.
bool SaveTimeProviders(ETimeProvider Selected, const SConfiguration& PrelPtpConfig, const SMsPtpConfiguration* MsPtpConfig);


//---- Microsoft PTP client (TimeProviders\PtpClient)

extern const wchar_t* MsPtpProviderName;   //"PtpClient"

struct SMsPtpConfiguration {
  DWORD DomainNumber;         //0-255; ptpprov has no "any domain"
  DWORD GrandmasterAddress;   //IPv4, network byte order. 0: any master (AllowAnyMaster)
  DWORD DelayPollInterval;    //ms
  DWORD AnnounceInterval;     //ms
  bool MulticastRx;           //EnableMulticastRx
  bool MulticastTx;           //EnableMulticastTx
};

static const DWORD DEFAULT_MS_PTP_DELAY_POLL_INTERVAL = 1000;
static const DWORD DEFAULT_MS_PTP_ANNOUNCE_INTERVAL = 4000;

//domain 0, any master, the default intervals, multicast receive on and transmit off
void DefaultMsPtpConfiguration(SMsPtpConfiguration& out_Config);

//one registry value to write, or to delete
struct SRegValue {
  enum EKind { Delete, Dword, String, ExpandString };
  const wchar_t* Name;
  EKind Kind;
  DWORD Number;       //Dword
  wchar_t Text[0x40];
};

struct SRegPlan {
  static const int MAX_VALUES = 12;
  int Count;
  SRegValue Values[MAX_VALUES];
  //the entry for Name, or nullptr
  const SRegValue* Find(const wchar_t* Name) const;
};

//What SaveMsPtpConfiguration writes: DllName, InputProvider and the settings. Not Enabled,
//which SelectTimeProvider sets.
void PlanMsPtpValues(const SMsPtpConfiguration& Config, SRegPlan& out_Plan);

//The first address in a PtpMasters value (separated by spaces, commas or semicolons), in network
//byte order. False if there is none or it isn't an IPv4 address.
bool ParsePtpMasters(const wchar_t* Text, DWORD& out_Address);

//Writes the values (creating the key). Returns false if the key can't be created or a value
//can't be written.
bool SaveMsPtpConfiguration(const SMsPtpConfiguration& Config);

//Defaults for anything missing. Grandmaster: 0 if AllowAnyMaster is set, otherwise the first
//PtpMasters address (0 if there is none). Returns false if the key doesn't exist.
bool LoadMsPtpConfiguration(SMsPtpConfiguration& out_Config);


//---- the settings both PTP providers have

//The setup dialog keeps one of these for each PTP provider: they share the controls, and
//switching between the providers shows each one's own settings.
struct SPtpSettings {
  DWORD DomainNumber;           //0-255, or PTP_DOMAIN_ANY (PrelPtp only)
  DWORD GrandmasterAddress;     //IPv4, network byte order. 0: BMCA (PrelPtp), any master (MsPtp)
  DWORD DelayRequestInterval;   //ms: PrelPtp's DelayRequestInterval, MsPtp's DelayPollInterval
};

static const DWORD DEFAULT_PREL_PTP_DELAY_REQUEST_INTERVAL = 1200;

//Each PTP provider's settings when the dialog opens. PrelPtp, MsPtp: the registry's, or nullptr
//if the provider's key doesn't exist. A provider without a key starts from the other one's domain
//and grandmaster, with its own default interval, so that switching to it needs no retyping. The
//Microsoft PTP client has no "any domain": PrelPtp's "any" gives it domain 0. With neither key,
//the defaults: PrelPtp any domain, BMCA, 1200 ms; MsPtp domain 0, any master, 1000 ms.
void InitialPtpSettings(const SConfiguration* PrelPtp, const SMsPtpConfiguration* MsPtp,
  SPtpSettings& out_PrelPtp, SPtpSettings& out_MsPtp);


//---- whether the Microsoft PTP client can be offered

//ptpprov.dll from Windows 10 1809 / Server 2019 is not usable; Server 2022 (20348) and Windows 11 are
static const DWORD MS_PTP_MIN_BUILD = 20348;

enum class EMsPtpAvailability { Available, WindowsTooOld, NoDll };

EMsPtpAvailability MsPtpAvailability(DWORD WindowsBuild, bool DllPresent);

//for this computer: the real build number (RtlGetVersion) and System32\ptpprov.dll
EMsPtpAvailability CheckMsPtpAvailability();

//why it isn't available, for the dialog; empty for Available
const wchar_t* MsPtpAvailabilityText(EMsPtpAvailability Availability);


//---- uninstall

struct SUninstallPlan {
  //PrelPtp was the only time source: ask whether to enable the Windows NTP client
  bool AskToEnableNtp;
  //the Microsoft PTP client stays running and needs the "PTP" firewall rule (UDP 319/320 for W32Time)
  bool KeepFirewallRule;
};

//Uninstall never switches to the Microsoft PTP client: that may need configuring.
SUninstallPlan PlanUninstall(const SProvidersEnabled& Enabled);
