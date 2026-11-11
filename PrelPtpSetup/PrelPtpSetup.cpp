#include "..\PtpUtil\WinTarget.h"
#include "resource.h"
#include <ShellAPI.h>
#include <CommCtrl.h>
#include <tchar.h>

#include "..\PtpUtil\Util.h"
#include "..\PtpUtil\PtpMonitor.h"
#include "..\PtpUtil\Validation.h"
#include "..\PtpUtil\TimeProviders.h"


#include "Firewall.h"
#include "Install.h"
#include <vector>
#include <memory>
#include <strsafe.h>


#pragma comment(lib, "ComCtl32")
#pragma comment(lib, "Ws2_32")
#pragma comment(lib, "Advapi32") //for SCM
#pragma comment(lib, "Shell32")
#pragma comment(lib, "mincore")


#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")


static const DWORD TIMER_ID = 123;

//set when an uninstall has run: once the dialog has closed, the program's folder is deleted
static bool g_uninstalled = false;

//DRI = "Delay Request Interval" (PrelPtp's default; the Microsoft PTP client's is DEFAULT_MS_PTP_DELAY_POLL_INTERVAL)
static const DWORD DEFAULT_DRI = DEFAULT_PREL_PTP_DELAY_REQUEST_INTERVAL;


void ErrorBox(HWND Dlg, const TCHAR* Message) {
  MessageBox(Dlg, Message, L"Error", MB_OK | MB_ICONEXCLAMATION);
}

void W32TimeRestartError(HWND Dlg) {
  KillTimer(Dlg, TIMER_ID);
  ErrorBox(Dlg, L"Error restarting W32Time service");
  SendMessage(Dlg, WM_CLOSE, 0, 0);
}

static const wchar_t* ServiceState(DWORD State) {
  switch (State) {
  case SERVICE_CONTINUE_PENDING: return L"continuing";
  case SERVICE_PAUSE_PENDING: return L"pausing";
  case SERVICE_PAUSED: return L"paused";
  case SERVICE_RUNNING: return L"running";
  case SERVICE_START_PENDING: return L"starting";
  case SERVICE_STOP_PENDING: return L"stopping";
  case SERVICE_STOPPED: return L"stopped";
  default: return L"unknown";
  }
}

bool FileExists(const TCHAR* Filename) {
  return GetFileAttributes(Filename) != INVALID_FILE_ATTRIBUTES;
}


//a PTP provider's domain, grandmaster and delay request interval as entered (see PtpFields)
struct SPtpFields {
  wchar_t Domain[0x40];
  wchar_t Interval[0x20];
  DWORD GrandmasterAddress;
};

struct SDlgContext {

  HWND Dlg;

  SConfiguration InitialConfig;
  ETimeProvider InitialProvider;
  SMsPtpConfiguration InitialMsPtp;       //defaults if the PtpClient key doesn't exist

  //[0] PrelPtp, [1] the Microsoft PTP client (see PtpFields)
  SPtpSettings InitialPtp[2];
  SPtpFields PtpFields[2];
  ETimeProvider FieldsShown;              //PrelPtp or MsPtp: whose fields the controls show
  EMsPtpAvailability MsPtpAvailability;
  DWORD AdapterCount;
  IpAddressEntry AdapterList[CPtpSurvey::MAX_ADAPTERS];

  //adapter list and PTP detection (see "Adapter list" below)
  CPtpMonitor* Monitor;           //created after the context is zeroed
  bool ListenRuleAdded;           //temporary firewall rule, removed on close
  bool ProgrammaticSelection;     //the selection is being changed by code, not the user
  bool AdapterChosenByUser;       //stop choosing an adapter automatically

  bool Installed;   //a configuration exists

  bool Uninstall;   //uninstalling, from the Uninstall button or --uninstall (Apps)

  //what OK will install (see Install.h); shown in the status line
  Install::SProviderState Provider;
  bool SelfNeedsInstalling;

  SC_HANDLE _w32_time_service;
  SC_HANDLE _scm;
  DWORD _service_restart_ticks;
  HWND _service_status_control;

  //service control state machine
  enum _ServiceState {
    ssDone,
    ssStopping,
    ssStarting
  } _service_state;

  void UpdateStatus(DWORD State) {
    if (!State) {
      SetWindowText(_service_status_control, L"");
    } else {
      wchar_t buf[80];
      StringCchPrintf(buf, ARRAYSIZE(buf), L"Win32 time service is %s", ServiceState(State));
      SetWindowText(_service_status_control, buf);
    }
  }

  void CloseServiceHandles() {
    if (_w32_time_service) {
      CloseServiceHandle(_w32_time_service);
      _w32_time_service = nullptr;
    }    
    if (_scm) {
      CloseServiceHandle(_scm);
      _scm = nullptr;
    }
  }

  //called very 300ms while stopping W32Time until it returns true
  //is is possible to stop a paused service? Internet does not know.
  bool TryW32TimeStop() {
    SERVICE_STATUS status;
    bool result(false);
    if (QueryServiceStatus(_w32_time_service, &status)) {
      switch (status.dwCurrentState) {
      case SERVICE_CONTINUE_PENDING:
      case SERVICE_PAUSE_PENDING:
      case SERVICE_START_PENDING:
      case SERVICE_STOP_PENDING:
        break;
      case SERVICE_PAUSED:
      case SERVICE_RUNNING:
        ControlService(_w32_time_service, SERVICE_CONTROL_STOP, &status);
        break;
      case SERVICE_STOPPED:
        result = true;
        break;
      }
    }
    UpdateStatus(status.dwCurrentState);
    return result;
  }

  //called while W32Time is stopped: it has PrelPtp.dll loaded the rest of the time
  void UpdatePrelPtpDll() {
    if (Uninstall)
      Install::DeleteProvider();
    else
      Install::ApplyPendingProvider();
  }

  void CheckServiceConfiguration() {
    static const DWORD MAX_SERVICE_CONFIG = 0x2000;
    LPQUERY_SERVICE_CONFIG config((LPQUERY_SERVICE_CONFIG)malloc(MAX_SERVICE_CONFIG));
    DWORD needed_bytes;
    if (QueryServiceConfig(_w32_time_service, config, MAX_SERVICE_CONFIG, &needed_bytes)) {
      if (config->dwStartType == SERVICE_DEMAND_START) { //manual start. Switch to auto
        ChangeServiceConfig(_w32_time_service,
          SERVICE_NO_CHANGE,
          SERVICE_AUTO_START,
          SERVICE_NO_CHANGE,
          nullptr,
          nullptr,
          nullptr,
          nullptr,
          nullptr,
          nullptr,
          nullptr);
      }
    }
    else {
      int err = GetLastError();
      wchar_t buf[0x100];
      SysErrorMessage(err, buf, 0x100);
      OutputDebugString(buf);
    }
    free(config);
  }


  //called every 300ms while starting W32Time until it returns true
  bool TryW32TimeStart() {
    SERVICE_STATUS status;
    bool result(false);
    if (QueryServiceStatus(_w32_time_service, &status)) {
      switch (status.dwCurrentState) {
      case SERVICE_CONTINUE_PENDING:
      case SERVICE_PAUSE_PENDING:
      case SERVICE_START_PENDING:
      case SERVICE_STOP_PENDING:
        break;
      case SERVICE_PAUSED:
      case SERVICE_RUNNING:
        CheckServiceConfiguration();
        result = true;
        break;
      case SERVICE_STOPPED:
        UpdatePrelPtpDll();
        if (StartService(_w32_time_service, 0, nullptr))
          status.dwCurrentState = SERVICE_START_PENDING;
        break;
      }
    }
    UpdateStatus(status.dwCurrentState);
    return result;
  }

  //called from tick
  bool CommenceRestartW32Time(HWND Dlg) {
    _scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!_scm)
      return false;

    _w32_time_service = OpenService(_scm, L"W32Time", SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG );
    if (!_w32_time_service) {
      CloseServiceHandles();
      return false;
    }

    if (TryW32TimeStop()) {
      _service_state = ssStarting;
      TryW32TimeStart();
    } else {
      _service_state = ssStopping;
    }

    _service_restart_ticks = 0;
    SetTimer(Dlg, TIMER_ID, 300, nullptr);
    return true;
  }

  bool ContinueRestartW32Time(HWND Dlg) {
    //30 s: W32Time has been seen to take 11 s to start when ptpprov failed to bind
    if (++_service_restart_ticks > 100) {
      CloseServiceHandles();
      W32TimeRestartError(Dlg);
      return false;
    }
    switch (_service_state) {
    case ssStopping:
      if (TryW32TimeStop()) {
        UpdatePrelPtpDll();
        if (!StartService(_w32_time_service, 0, nullptr)) {
          CloseServiceHandles();
          W32TimeRestartError(Dlg);
        } else {
          _service_state = ssStarting;
        }
      }
      break;

    case ssStarting:
      if (TryW32TimeStart()) {
        CloseServiceHandles();
        _service_state = ssDone;
        return true;
      }
      break;
    }
    return false;
  }
};

SDlgContext* GetContext(HWND Dlg) {
  return (SDlgContext*)GetWindowLongPtr(Dlg, GWLP_USERDATA);
}

static void EnableWindows(HWND Dlg, const std::vector<int>& Idcs, bool Enabled) {
  for (auto i : Idcs)
    EnableWindow(GetDlgItem(Dlg, i), Enabled?TRUE:FALSE);
}

/*
Time provider

One of PrelPtp, the Microsoft PTP client (ptpprov.dll), the Windows NTP client or none, chosen
with radio buttons: two PTP providers can't run together, and w32time would combine PTP and NTP.
The PTP settings are enabled for either PTP provider, the "MS ptpprov parameters" group only for
the Microsoft PTP client. The adapter list stays enabled throughout: it shows what is heard.
The Microsoft PTP client is offered only where it works (CheckMsPtpAvailability); otherwise its
button is disabled and the group says why.
*/
static int ProviderButton(ETimeProvider Provider) {
  switch (Provider) {
  case ETimeProvider::PrelPtp: return IDC_PROVIDER_PRELPTP;
  case ETimeProvider::MsPtp:   return IDC_PROVIDER_MSPTP;
  case ETimeProvider::Ntp:     return IDC_PROVIDER_NTP;
  default:                     return IDC_PROVIDER_NONE;
  }
}

static ETimeProvider SelectedProvider(HWND Dlg) {
  if (IsDlgButtonChecked(Dlg, IDC_PROVIDER_PRELPTP) == BST_CHECKED)
    return ETimeProvider::PrelPtp;
  if (IsDlgButtonChecked(Dlg, IDC_PROVIDER_MSPTP) == BST_CHECKED)
    return ETimeProvider::MsPtp;
  if (IsDlgButtonChecked(Dlg, IDC_PROVIDER_NTP) == BST_CHECKED)
    return ETimeProvider::Ntp;
  return ETimeProvider::None;
}

static void UpdateProviderControls(HWND Dlg) {
  ETimeProvider provider = SelectedProvider(Dlg);
  bool ms_ptp = (provider == ETimeProvider::MsPtp);
  bool ptp = ms_ptp || (provider == ETimeProvider::PrelPtp);
  EnableWindows(Dlg,
    { IDC_DOMAIN_LABEL, IDC_DOMAIN,
      IDC_GRANDMASTER_LABEL, IDC_GRANDMASTER, IDC_BMCA_BUTTON, IDC_GRANDMASTER_HINT,
      IDC_DRINTERVAL_LABEL, IDC_DRINTERVAL_EDIT, IDC_DRINTERVAL, IDC_DRINTERVAL_UNITS, IDC_DEFAULT_DRINTERVAL_BUTTON }, ptp);
  EnableWindows(Dlg,
    { IDC_MSPTP_GROUP, IDC_MULTICAST_RX, IDC_MULTICAST_TX, IDC_ANNOUNCE_LABEL, IDC_ANNOUNCE_EDIT, IDC_ANNOUNCE_UNITS }, ms_ptp);
  //ptpprov's choice among the masters it accepts is not the IEEE 1588 BMCA (seen in testing)
  SetDlgItemText(Dlg, IDC_BMCA_BUTTON, ms_ptp ? L"&Any master" : L"&BMCA");
  SetDlgItemText(Dlg, IDC_GRANDMASTER_HINT, ms_ptp ? L"0.0.0.0 = any master" : L"0.0.0.0 = automatic (BMCA)");
}

void SetDefaultDri(HWND Dlg) {
  DWORD dri = (SelectedProvider(Dlg) == ETimeProvider::MsPtp) ? DEFAULT_MS_PTP_DELAY_POLL_INTERVAL : DEFAULT_DRI;
  SendMessage(GetDlgItem(Dlg, IDC_DRINTERVAL), UDM_SETPOS32, 0, dri);
}

/*
Installation (see Install.h)

The status line says what OK will install before it is pressed, so nothing happens unannounced.
OK installs or updates PrelPtp.dll and this program (in Program Files), then saves the
configuration. Uninstall removes everything; the folder in Program Files goes after the dialog
has closed (Install::StartSelfDelete, from _tWinMain).
*/

//the installed copy only configures; it never installs or updates (see InstallFiles)
static void FormatMismatch(const Install::SProviderState& P, wchar_t* Text, size_t Chars) {
  wchar_t ours[0x20], installed[0x20];
  P.Ours.Format(ours, ARRAYSIZE(ours));
  P.Installed.Format(installed, ARRAYSIZE(installed));
  if (P.Action == Install::EProviderAction::Install)
    StringCchCopy(Text, Chars, L"The provider is not installed. Run the setup program you downloaded to install it.");
  else
    StringCchPrintf(Text, Chars, L"The installed provider (%s) does not match this setup program (%s). Run the setup program you downloaded to update it.",
      installed, ours);
}

static void ShowInstallStatus(HWND Dlg) {
  SDlgContext* context = GetContext(Dlg);
  const Install::SProviderState& p = context->Provider;
  wchar_t ours[0x20], installed[0x20], text[0x100] = { 0 };
  p.Ours.Format(ours, ARRAYSIZE(ours));
  p.Installed.Format(installed, ARRAYSIZE(installed));
  if (Install::RunningFromInstallDir()) {
    if (p.Action != Install::EProviderAction::None)
      FormatMismatch(p, text, ARRAYSIZE(text));
    SetWindowText(GetDlgItem(Dlg, IDC_STATUSTEXT), text);
    return;
  }
  switch (p.Action) {
  case Install::EProviderAction::Install:
    StringCchPrintf(text, ARRAYSIZE(text), L"OK will install the PREL PTP time provider %s.", ours);
    break;
  case Install::EProviderAction::Update:
    if (p.Installed.Compare(p.Ours) == 0)
      StringCchPrintf(text, ARRAYSIZE(text), L"OK will replace the provider with this build of %s.", ours);
    else
      StringCchPrintf(text, ARRAYSIZE(text), L"OK will update the provider from %s to %s.", installed, ours);
    break;
  case Install::EProviderAction::Downgrade:
    StringCchPrintf(text, ARRAYSIZE(text), L"A newer provider (%s) is installed. OK will ask before replacing it with %s.", installed, ours);
    break;
  case Install::EProviderAction::None:
    if (context->SelfNeedsInstalling)
      StringCchCopy(text, ARRAYSIZE(text), L"OK will update the setup program in Program Files.");
    break;
  }
  SetWindowText(GetDlgItem(Dlg, IDC_STATUSTEXT), text);
}

//false if nothing may be changed (the user declined a downgrade, or something failed and was reported)
static bool InstallFiles(HWND Dlg) {
  SDlgContext* context = GetContext(Dlg);
  //look again: another copy may have installed something while this dialog was open
  Install::CheckProvider(context->Provider);
  context->SelfNeedsInstalling = Install::SelfNeedsInstalling();

  //The installed copy (Start menu, Apps) reconfigures only. Installed together, it matches the
  //DLL; if it doesn't, something odd has happened, and updates come from a downloaded copy.
  if (Install::RunningFromInstallDir()) {
    if (context->Provider.Action == Install::EProviderAction::None)
      return true;
    wchar_t text[0x100];
    FormatMismatch(context->Provider, text, ARRAYSIZE(text));
    ErrorBox(Dlg, text);
    return false;
  }

  if (context->Provider.Action == Install::EProviderAction::Downgrade) {
    wchar_t ours[0x20], installed[0x20], text[0x180];
    context->Provider.Ours.Format(ours, ARRAYSIZE(ours));
    context->Provider.Installed.Format(installed, ARRAYSIZE(installed));
    StringCchPrintf(text, ARRAYSIZE(text),
      L"A newer version of the PREL PTP time provider (%s) is installed.\n\nReplace it with this older version (%s)?", installed, ours);
    if (MessageBox(Dlg, text, L"PREL PTP setup", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES)
      return false;
  }

  bool install_provider = context->Provider.Action != Install::EProviderAction::None;
  if (!install_provider && !context->SelfNeedsInstalling)
    return true;   //everything is up to date: configuration only

  wchar_t message[0x200] = { 0 };
  //this program first: if the installed copy is in use, stop before anything else has changed
  if (context->SelfNeedsInstalling && !Install::InstallSelf(message, ARRAYSIZE(message))) {
    ErrorBox(Dlg, message);
    return false;
  }
  //written now as PrelPtp.dll.pending if W32Time has the DLL loaded, so a failure shows before
  //anything is stopped; swapped in while W32Time is stopped for the restart (UpdatePrelPtpDll)
  if (install_provider && !Install::InstallProvider(message, ARRAYSIZE(message))) {
    ErrorBox(Dlg, message);
    return false;
  }
  //new installation or update: the Apps entry shows the version, and an update over 1.3
  //replaces its entry (which pointed elsewhere) and adds the shortcut it never had
  Install::CreateShortcut();
  Install::AddUninstallEntry();
  return true;
}

//shows a built-in document as a page in the default browser, which renders the markdown; or,
//where there is no browser (Server Core), as plain text in Notepad
static void ShowDocument(HWND Dlg, Install::Document Doc) {
  wchar_t path[MAX_PATH];
  for (bool html : { true, false }) {
    if (Install::WriteDocument(Doc, html, path) && ((INT_PTR)ShellExecute(Dlg, L"open", path, nullptr, nullptr, SW_SHOWNORMAL) > 32))
      return;
  }
  ErrorBox(Dlg, Doc == Install::Document::Readme ? L"The README could not be opened." : L"The release notes could not be opened.");
}

void DoUninstall(HWND Dlg) {
  EnableWindows(Dlg,
    { IDC_UNINSTALL,
    IDC_RELEASE_NOTES,
    IDC_README,
    IDC_PROVIDER_PRELPTP,
    IDC_PROVIDER_MSPTP,
    IDC_PROVIDER_NTP,
    IDC_PROVIDER_NONE,
    IDC_MULTICAST_RX,
    IDC_MULTICAST_TX,
    IDC_ANNOUNCE_EDIT,
    IDC_LOCALADAPTER,
    IDC_DOMAIN,
    IDC_DRINTERVAL,
    IDC_DRINTERVAL_EDIT,
    IDC_DRINTERVAL_LABEL,
     IDC_GRANDMASTER,
     IDC_GRANDMASTER_LABEL,
     IDC_BMCA_BUTTON,
     IDOK }, false);
  PostMessage(Dlg, WM_COMMAND, IDOK, 0);
}

/*
Adapter list

A report-view list of the physical Ethernet adapters, plus the configured adapter even if it is
missing or virtual. A background CPtpMonitor listens on each one, and the PTP column shows the
domains in which Announce messages are heard ("domain 0", or "domain 0, domain 24"). Hovering
over an adapter shows the best master in each domain.

- With no adapter configured, the adapter whose best master the BMCA prefers is selected
  automatically, until the user picks one.
- The domain is never changed automatically: the list shows the domains heard, and only the
  user sets the domain field.

Rows hold the index of their adapter in SDlgContext::AdapterList as their lParam; the same index
identifies the adapter to the monitor.
*/
static const UINT WM_APP_SURVEY = WM_APP + 1;

static const wchar_t* const ELLIPSIS = L"\x2026";

enum EAdapterColumn { COL_ADAPTER = 0, COL_ADDRESS = 1, COL_PTP = 2 };

static HWND AdapterListView(HWND Dlg) {
  return GetDlgItem(Dlg, IDC_LOCALADAPTER);
}

//index into AdapterList of the selected row, or -1
static int SelectedAdapter(HWND Dlg) {
  HWND lv = AdapterListView(Dlg);
  int row = ListView_GetNextItem(lv, -1, LVNI_SELECTED);
  if (row < 0)
    return -1;
  LVITEM item;
  ZeroMemory(&item, sizeof(item));
  item.mask = LVIF_PARAM;
  item.iItem = row;
  if (!ListView_GetItem(lv, &item))
    return -1;
  return (int)item.lParam;
}

static int RowOfAdapter(HWND Dlg, int Adapter) {
  LVFINDINFO find;
  ZeroMemory(&find, sizeof(find));
  find.flags = LVFI_PARAM;
  find.lParam = Adapter;
  return ListView_FindItem(AdapterListView(Dlg), -1, &find);
}

static void GetSurvey(SDlgContext* Context, int Adapter, CPtpSurvey::SSummary& out_Summary) {
  if (Context->Monitor != nullptr)
    Context->Monitor->Survey().GetSummary(Adapter, out_Summary);
  else
    ZeroMemory(&out_Summary, sizeof(out_Summary));
}

static void FormatAddressColumn(const IpAddressEntry& Entry, wchar_t* Buf, size_t Chars) {
  if (!Entry.Present)
    StringCchCopy(Buf, Chars, L"(not present)");
  else if (!Entry.Up)
    StringCchCopy(Buf, Chars, L"(not connected)");
  else if (Entry.LocalAddress == 0)
    StringCchCopy(Buf, Chars, L"(no address)");
  else {
    IN_ADDR addr;
    addr.s_addr = Entry.LocalAddress;
    if (InetNtop(AF_INET, &addr, Buf, Chars) == nullptr)
      StringCchCopy(Buf, Chars, L"?");
  }
}

//out_Traffic: Announce messages are heard (the text lists the domains and is drawn in the normal
//text colour; the other states are drawn grey)
static void FormatPtpColumn(SDlgContext* Context, int Adapter, wchar_t* Buf, size_t Chars, bool* out_Traffic = nullptr) {
  if (out_Traffic)
    *out_Traffic = false;
  Buf[0] = 0;
  const IpAddressEntry& entry = Context->AdapterList[Adapter];
  if (!entry.Present || !entry.Up || (entry.LocalAddress == 0) || (Context->Monitor == nullptr))
    return;

  CPtpSurvey::SSummary s;
  GetSurvey(Context, Adapter, s);
  if (s.DomainCount > 0) {
    for (int i = 0; i < s.DomainCount; ++i) {
      wchar_t d[0x14];
      StringCchPrintf(d, ARRAYSIZE(d), i ? L", domain %u" : L"domain %u", s.Domains[i].Domain);
      StringCchCat(Buf, Chars, d);
    }
    if (out_Traffic)
      *out_Traffic = true;
  }
  else if (Context->Monitor->Checking()) {
    StringCchCopy(Buf, Chars, L"checking");
    StringCchCat(Buf, Chars, ELLIPSIS);
  }
  else if (!Context->Monitor->Listening(Adapter)) {
    StringCchCopy(Buf, Chars, L"cannot listen");
  }
  else {
    StringCchCopy(Buf, Chars, L"none");
  }
}

//the tooltip for an adapter: what was heard, master by master
static void FormatAdapterTip(SDlgContext* Context, int Adapter, wchar_t* Buf, size_t Chars) {
  const IpAddressEntry& entry = Context->AdapterList[Adapter];
  StringCchCopy(Buf, Chars, entry.FriendlyName);
  if (!entry.Present) {
    StringCchCat(Buf, Chars, L"\nThe configured adapter was not found. It may be disabled or removed.");
    return;
  }
  if (!entry.Up || (entry.LocalAddress == 0)) {
    StringCchCat(Buf, Chars, L"\nPTP traffic can only be detected on a connected adapter with an IPv4 address.");
    return;
  }
  CPtpSurvey::SSummary s;
  GetSurvey(Context, Adapter, s);
  if (s.DomainCount == 0) {
    StringCchCat(Buf, Chars, (Context->Monitor && Context->Monitor->Listening(Adapter))
      ? L"\nNo PTP Announce messages heard."
      : L"\nNot listening for PTP on this adapter. Port 320 may be in use by a program that doesn't share it, such as the Microsoft PTP client.");
    return;
  }
  for (int i = 0; i < s.DomainCount; ++i) {
    const CPtpSurvey::SDomain& d = s.Domains[i];
    wchar_t line[0x100];
    if (!d.HaveMaster) {
      StringCchPrintf(line, ARRAYSIZE(line), L"\nDomain %u: Announce messages heard, no master selected yet", d.Domain);
    }
    else {
      wchar_t address[0x20], gm[0x20];
      IN_ADDR addr;
      addr.s_addr = d.Master.Address;
      if (InetNtop(AF_INET, &addr, address, ARRAYSIZE(address)) == nullptr)
        StringCchCopy(address, ARRAYSIZE(address), L"?");
      FormatClockIdentity(d.Master.Dataset.GrandmasterIdentity, gm, ARRAYSIZE(gm));
      StringCchPrintf(line, ARRAYSIZE(line), L"\nDomain %u: master %s, grandmaster %s, clock class %u, priority1 %u, steps removed %u",
        d.Domain, address, gm, d.Master.Dataset.ClockClass, d.Master.Dataset.Priority1, d.Master.Dataset.StepsRemoved);
    }
    StringCchCat(Buf, Chars, line);
  }
}

static void SelectAdapterRow(SDlgContext* Context, int Adapter) {
  int row = RowOfAdapter(Context->Dlg, Adapter);
  if (row < 0)
    return;
  HWND lv = AdapterListView(Context->Dlg);
  Context->ProgrammaticSelection = true;
  ListView_SetItemState(lv, row, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
  ListView_EnsureVisible(lv, row, FALSE);
  Context->ProgrammaticSelection = false;
}

//WM_APP_SURVEY: the monitor heard something new, or something expired
static void OnSurveyChanged(HWND Dlg) {
  SDlgContext* context = GetContext(Dlg);
  if ((context == nullptr) || (context->Monitor == nullptr))
    return;
  HWND lv = AdapterListView(Dlg);
  int rows = ListView_GetItemCount(lv);
  for (int row = 0; row < rows; ++row) {
    LVITEM item;
    ZeroMemory(&item, sizeof(item));
    item.mask = LVIF_PARAM;
    item.iItem = row;
    ListView_GetItem(lv, &item);
    wchar_t text[0x80];
    FormatPtpColumn(context, (int)item.lParam, text, ARRAYSIZE(text));
    ListView_SetItemText(lv, row, COL_PTP, text);
  }

  //no adapter configured: offer the one with the best master, until the user picks one
  if ((context->InitialConfig.AdapterName[0] == 0) && !context->AdapterChosenByUser) {
    int best = context->Monitor->Survey().BestAdapter();
    if ((best >= 0) && (best != SelectedAdapter(Dlg)))
      SelectAdapterRow(context, best);
  }
}

//LVN_ITEMCHANGED
static void OnAdapterSelectionChanged(HWND Dlg, const NMLISTVIEW* Change) {
  SDlgContext* context = GetContext(Dlg);
  if ((context == nullptr) || !(Change->uChanged & LVIF_STATE))
    return;
  if (!(Change->uNewState & LVIS_SELECTED) || (Change->uOldState & LVIS_SELECTED))
    return;
  if (!context->ProgrammaticSelection)
    context->AdapterChosenByUser = true;
}

//NM_CUSTOMDRAW: PTP column in the normal text colour where there is traffic, grey otherwise
static LRESULT OnAdapterListCustomDraw(HWND Dlg, NMLVCUSTOMDRAW* Draw) {
  switch (Draw->nmcd.dwDrawStage) {
  case CDDS_PREPAINT:
    return CDRF_NOTIFYITEMDRAW;
  case CDDS_ITEMPREPAINT:
    return CDRF_NOTIFYSUBITEMDRAW;
  case CDDS_ITEMPREPAINT | CDDS_SUBITEM: {
    SDlgContext* context = GetContext(Dlg);
    int adapter = (int)Draw->nmcd.lItemlParam;
    if (Draw->iSubItem == COL_PTP && context != nullptr) {
      wchar_t text[0x80];
      bool traffic;
      FormatPtpColumn(context, adapter, text, ARRAYSIZE(text), &traffic);
      Draw->clrText = GetSysColor(traffic ? COLOR_WINDOWTEXT : COLOR_GRAYTEXT);
    }
    else if (Draw->iSubItem == COL_ADDRESS && context != nullptr && !context->AdapterList[adapter].Present) {
      Draw->clrText = GetSysColor(COLOR_GRAYTEXT);
    }
    else {
      Draw->clrText = GetSysColor(COLOR_WINDOWTEXT);
    }
    return CDRF_NEWFONT;
  }
  default:
    return CDRF_DODEFAULT;
  }
}

static void OnAdapterListGetInfoTip(HWND Dlg, NMLVGETINFOTIP* Tip) {
  SDlgContext* context = GetContext(Dlg);
  if ((context == nullptr) || (Tip->cchTextMax <= 0))
    return;
  LVITEM item;
  ZeroMemory(&item, sizeof(item));
  item.mask = LVIF_PARAM;
  item.iItem = Tip->iItem;
  if (!ListView_GetItem(AdapterListView(Dlg), &item))
    return;
  //the list view offers the label text when it is truncated: replace it
  FormatAdapterTip(context, (int)item.lParam, Tip->pszText, Tip->cchTextMax);
}

static void InitialiseAdapterList(HWND Dlg) {
  SDlgContext* context = GetContext(Dlg);
  HWND lv = AdapterListView(Dlg);
  ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT | LVS_EX_INFOTIP | LVS_EX_DOUBLEBUFFER);

  RECT client;
  GetClientRect(lv, &client);
  int width = client.right - GetSystemMetrics(SM_CXVSCROLL);
  struct { const wchar_t* Name; int Width; } columns[] = {
    { L"Adapter", width * 40 / 100 },
    { L"IP address", width * 24 / 100 },
    { L"PTP", width - (width * 40 / 100) - (width * 24 / 100) },
  };
  for (int i = 0; i < ARRAYSIZE(columns); ++i) {
    LVCOLUMN col;
    ZeroMemory(&col, sizeof(col));
    col.mask = LVCF_TEXT | LVCF_WIDTH;
    col.pszText = (LPWSTR)columns[i].Name;
    col.cx = columns[i].Width;
    ListView_InsertColumn(lv, i, &col);
  }

  //the configured adapter is always listed, even if it is missing: the setting is never dropped silently
  int configured = -1;
  for (DWORD i = 0; i < context->AdapterCount; ++i)
    if ((context->InitialConfig.AdapterName[0] != 0) && (_wcsicmp(context->InitialConfig.AdapterName, context->AdapterList[i].AdapterName) == 0))
      configured = (int)i;
  if ((context->InitialConfig.AdapterName[0] != 0) && (configured < 0) && (context->AdapterCount < ARRAYSIZE(context->AdapterList))) {
    IpAddressEntry& missing = context->AdapterList[context->AdapterCount];
    ZeroMemory(&missing, sizeof(missing));
    StringCchCopy(missing.AdapterName, ARRAYSIZE(missing.AdapterName), context->InitialConfig.AdapterName);
    StringCchCopy(missing.FriendlyName, ARRAYSIZE(missing.FriendlyName), L"Configured adapter");
    configured = (int)context->AdapterCount++;
  }

  DWORD addresses[CPtpSurvey::MAX_ADAPTERS] = { 0 };
  int row = 0;
  for (DWORD i = 0; (i < context->AdapterCount) && (i < CPtpSurvey::MAX_ADAPTERS); ++i) {
    const IpAddressEntry& entry = context->AdapterList[i];
    if (!entry.IsCandidate() && ((int)i != configured))
      continue;
    LVITEM item;
    ZeroMemory(&item, sizeof(item));
    //Matrox cards (MAC 00:20:FC) are labelled for identification only.
    wchar_t name[ARRAYSIZE(entry.FriendlyName) + 16];
    StringCchCopy(name, ARRAYSIZE(name), entry.FriendlyName);
    if (entry.IsMatroxCard())
      StringCchCat(name, ARRAYSIZE(name), L" (Matrox)");
    item.mask = LVIF_TEXT | LVIF_PARAM;
    item.iItem = row;
    item.pszText = name;
    item.lParam = (LPARAM)i;
    int inserted = ListView_InsertItem(lv, &item);
    wchar_t text[0x40];
    FormatAddressColumn(entry, text, ARRAYSIZE(text));
    ListView_SetItemText(lv, inserted, COL_ADDRESS, text);
    ++row;
    if (entry.Present && entry.Up)
      addresses[i] = entry.LocalAddress;
  }

  if (configured >= 0)
    SelectAdapterRow(context, configured);

  //listen for PTP traffic. The setup program needs its own firewall rule for that.
  context->ListenRuleAdded = SUCCEEDED(AddListenFirewallRule());
  context->Monitor = new CPtpMonitor();
  if (!context->Monitor->Start(Dlg, WM_APP_SURVEY, addresses, (int)context->AdapterCount)) {
    delete context->Monitor;
    context->Monitor = nullptr;
  }
  OnSurveyChanged(Dlg);
}

//domain choices offered in the drop-down. The user can also type any number 0-255.
static const wchar_t* const DOMAIN_CHOICES[] = {
  L"Any",
  L"0 - default profile",
  L"127 - SMPTE ST 2059-2",
  L"24 - ITU-T G.8275.1",
  L"44 - ITU-T G.8275.2",
};

//shows Domain in the domain field: the matching choice if there is one, otherwise the number
void SetDomainField(HWND Dlg, DWORD Domain) {
  HWND combo(GetDlgItem(Dlg, IDC_DOMAIN));
  for (int i = 0; i < ARRAYSIZE(DOMAIN_CHOICES); ++i) {
    DWORD choice;
    if (ParseDomain(DOMAIN_CHOICES[i], choice) && (choice == Domain)) {
      SendMessage(combo, CB_SETCURSEL, i, 0);
      return;
    }
  }
  SendMessage(combo, CB_SETCURSEL, (WPARAM)-1, 0);
  wchar_t text[0x10];
  FormatDomain(Domain, text, ARRAYSIZE(text));
  SetWindowText(combo, text);
}

void InitialiseDomain(HWND Dlg, DWORD Domain) {
  HWND combo(GetDlgItem(Dlg, IDC_DOMAIN));
  SendMessage(combo, CB_LIMITTEXT, 40, 0);
  for (int i = 0; i < ARRAYSIZE(DOMAIN_CHOICES); ++i)
    SendMessage(combo, CB_ADDSTRING, 0, (LPARAM)DOMAIN_CHOICES[i]);
  SetDomainField(Dlg, Domain);
}

/*
Configuration validation

On OK the entries are checked by ValidateConfiguration (PtpUtil/Validation.h) before anything
is written: errors are listed and the dialog stays open; warnings are listed and the user may
save anyway. Either way the field of the first issue is focused.
*/

//the text the user sees in the domain combo box (a chosen item or what was typed),
//and in the delay request interval edit box
struct SEnteredText {
  wchar_t Domain[0x40];
  wchar_t Interval[0x20];
  wchar_t AnnounceInterval[0x20];
};

static void GetEnteredText(HWND Dlg, SEnteredText& out_Text) {
  ZeroMemory(&out_Text, sizeof(out_Text));
  GetWindowText(GetDlgItem(Dlg, IDC_DOMAIN), out_Text.Domain, ARRAYSIZE(out_Text.Domain));
  GetWindowText(GetDlgItem(Dlg, IDC_DRINTERVAL_EDIT), out_Text.Interval, ARRAYSIZE(out_Text.Interval));
  GetWindowText(GetDlgItem(Dlg, IDC_ANNOUNCE_EDIT), out_Text.AnnounceInterval, ARRAYSIZE(out_Text.AnnounceInterval));
}

static DWORD GetGrandmasterAddress(HWND Dlg) {
  DWORD gma = 0;
  SendMessage(GetDlgItem(Dlg, IDC_GRANDMASTER), IPM_GETADDRESS, 0, (LPARAM)&gma);
  return _byteswap_ulong(gma);   //IPM_GETADDRESS gives host order
}

/*
PTP fields

The two PTP providers each have their own domain, grandmaster and delay request interval, which
share the controls. The context keeps both sets as entered, including text that isn't valid yet.
The controls show the set of the selected PTP provider, or, while NTP or none is selected (and
the controls are disabled), of the PTP provider last selected. Choosing the other PTP provider
keeps what is shown and shows that provider's set. OK saves each provider's key with its own set.
Only the dialog's copies change here: the registry is read when the dialog opens and written on OK.
*/
static SPtpFields& PtpFields(SDlgContext* Context, ETimeProvider Provider) {
  return Context->PtpFields[(Provider == ETimeProvider::MsPtp) ? 1 : 0];
}

static const SPtpSettings& InitialPtpSettings(SDlgContext* Context, ETimeProvider Provider) {
  return Context->InitialPtp[(Provider == ETimeProvider::MsPtp) ? 1 : 0];
}

//keeps what the controls show as the fields of the provider they show
static void StorePtpFields(HWND Dlg) {
  SDlgContext* context = GetContext(Dlg);
  SPtpFields& f = PtpFields(context, context->FieldsShown);
  GetWindowText(GetDlgItem(Dlg, IDC_DOMAIN), f.Domain, ARRAYSIZE(f.Domain));
  GetWindowText(GetDlgItem(Dlg, IDC_DRINTERVAL_EDIT), f.Interval, ARRAYSIZE(f.Interval));
  f.GrandmasterAddress = GetGrandmasterAddress(Dlg);
}

static void ShowPtpFields(HWND Dlg, ETimeProvider Provider) {
  SDlgContext* context = GetContext(Dlg);
  const SPtpFields& f = PtpFields(context, Provider);
  HWND combo = GetDlgItem(Dlg, IDC_DOMAIN);
  LRESULT item = SendMessage(combo, CB_FINDSTRINGEXACT, (WPARAM)-1, (LPARAM)f.Domain);
  SendMessage(combo, CB_SETCURSEL, (WPARAM)item, 0);   //CB_ERR (-1) clears the selection
  if (item == CB_ERR)
    SetWindowText(combo, f.Domain);
  SetDlgItemText(Dlg, IDC_DRINTERVAL_EDIT, f.Interval);
  SendMessage(GetDlgItem(Dlg, IDC_GRANDMASTER), IPM_SETADDRESS, 0, _byteswap_ulong(f.GrandmasterAddress));
  context->FieldsShown = Provider;
}

//when the dialog opens: Provider's fields from its settings, formatted as the controls show them
static void InitialisePtpFields(HWND Dlg, ETimeProvider Provider) {
  SDlgContext* context = GetContext(Dlg);
  const SPtpSettings& s = InitialPtpSettings(context, Provider);
  SetDomainField(Dlg, s.DomainNumber);
  SendMessage(GetDlgItem(Dlg, IDC_DRINTERVAL), UDM_SETPOS32, 0, s.DelayRequestInterval);
  SendMessage(GetDlgItem(Dlg, IDC_GRANDMASTER), IPM_SETADDRESS, 0, _byteswap_ulong(s.GrandmasterAddress));
  context->FieldsShown = Provider;
  StorePtpFields(Dlg);
}

static void OnProviderClicked(HWND Dlg) {
  SDlgContext* context = GetContext(Dlg);
  ETimeProvider provider = SelectedProvider(Dlg);
  bool ptp = (provider == ETimeProvider::PrelPtp) || (provider == ETimeProvider::MsPtp);
  if (ptp && (provider != context->FieldsShown)) {
    StorePtpFields(Dlg);
    ShowPtpFields(Dlg, provider);
  }
  UpdateProviderControls(Dlg);
}

//Provider's fields as saved: what was entered, or, where that isn't valid (only possible for the
//provider not selected; CheckConfiguration checks the selected one's), what the dialog opened with
static SPtpSettings PtpSettingsToSave(SDlgContext* Context, ETimeProvider Provider) {
  const SPtpFields& f = PtpFields(Context, Provider);
  SPtpSettings s = InitialPtpSettings(Context, Provider);
  ParseDomain(f.Domain, s.DomainNumber);
  ParseDelayRequestInterval(f.Interval, s.DelayRequestInterval);
  s.GrandmasterAddress = f.GrandmasterAddress;
  return s;
}

static void FocusField(HWND Dlg, EValidationField Field) {
  int id = 0;
  switch (Field) {
  case EValidationField::Provider: id = ProviderButton(SelectedProvider(Dlg)); break;
  case EValidationField::Adapter: id = IDC_LOCALADAPTER; break;
  case EValidationField::Domain: id = IDC_DOMAIN; break;
  case EValidationField::Grandmaster: id = IDC_GRANDMASTER; break;
  case EValidationField::DelayRequestInterval: id = IDC_DRINTERVAL_EDIT; break;
  case EValidationField::AnnounceInterval: id = IDC_ANNOUNCE_EDIT; break;
  case EValidationField::MulticastRx: id = IDC_MULTICAST_RX; break;
  }
  HWND control = GetDlgItem(Dlg, id);
  if (control == NULL)
    return;
  SendMessage(Dlg, WM_NEXTDLGCTL, (WPARAM)control, TRUE);
  if (id == IDC_DOMAIN)
    SendMessage(control, CB_SETEDITSEL, 0, MAKELPARAM(0, -1));
}

static void AppendIssues(const SValidationResult& Result, EValidationSeverity Severity, wchar_t* Buf, size_t Chars) {
  for (int i = 0; i < Result.Count; ++i) {
    if (Result.Issues[i].Severity != Severity)
      continue;
    StringCchCat(Buf, Chars, L"\x2022 ");   //bullet
    StringCchCat(Buf, Chars, Result.Issues[i].Message);
    StringCchCat(Buf, Chars, L"\n\n");
  }
}

//true if the configuration may be saved: no errors, and either no warnings or the user accepted them
static bool CheckConfiguration(HWND Dlg, const SEnteredText& Text) {
  SDlgContext* context(GetContext(Dlg));

  SValidationInput in;
  ZeroMemory(&in, sizeof(in));
  in.Provider = SelectedProvider(Dlg);
  in.DomainText = Text.Domain;
  in.IntervalText = Text.Interval;
  in.GrandmasterAddress = GetGrandmasterAddress(Dlg);

  int adapter = SelectedAdapter(Dlg);
  if (adapter >= 0) {
    in.Adapter = &context->AdapterList[adapter];
    CPtpMonitor* monitor = context->Monitor;
    //nothing is known about traffic until the monitor has listened for a few seconds
    if ((monitor != nullptr) && monitor->Listening(adapter) && !monitor->Checking()) {
      CPtpSurvey::SSummary s;
      monitor->Survey().GetSummary(adapter, s);
      in.Traffic.Known = true;
      in.Traffic.DomainCount = s.DomainCount;
      for (int i = 0; i < s.DomainCount; ++i)
        in.Traffic.Domains[i] = s.Domains[i].Domain;
      in.Traffic.GrandmasterHeard = (in.GrandmasterAddress != 0) && monitor->Survey().HeardFrom(adapter, in.GrandmasterAddress);
    }
  }

  //the Microsoft PTP client chooses its own adapter: what every adapter hears counts
  in.MsPtpAvailability = context->MsPtpAvailability;
  in.AnnounceIntervalText = Text.AnnounceInterval;
  in.MulticastRx = (IsDlgButtonChecked(Dlg, IDC_MULTICAST_RX) == BST_CHECKED);
  std::unique_ptr<SSurveyedAdapter[]> surveyed(new SSurveyedAdapter[ARRAYSIZE(context->AdapterList)]);
  CPtpMonitor* monitor = context->Monitor;
  if ((monitor != nullptr) && !monitor->Checking()) {
    for (DWORD i = 0; i < context->AdapterCount; ++i) {
      if (!monitor->Listening((int)i))
        continue;
      SSurveyedAdapter& a = surveyed[in.SurveyedCount++];
      ZeroMemory(&a, sizeof(a));
      a.Name = context->AdapterList[i].FriendlyName;
      CPtpSurvey::SSummary s;
      monitor->Survey().GetSummary((int)i, s);
      a.Traffic.Known = true;
      a.Traffic.DomainCount = s.DomainCount;
      for (int d = 0; d < s.DomainCount; ++d)
        a.Traffic.Domains[d] = s.Domains[d].Domain;
      a.Traffic.GrandmasterHeard = (in.GrandmasterAddress != 0) && monitor->Survey().HeardFrom((int)i, in.GrandmasterAddress);
    }
  }
  in.Surveyed = surveyed.get();

  //large: on the heap rather than the stack
  std::unique_ptr<SValidationResult> result(new SValidationResult);
  ValidateConfiguration(in, *result);
  if (result->Count == 0)
    return true;

  std::unique_ptr<wchar_t[]> text(new wchar_t[0x1000]);
  const size_t chars = 0x1000;
  text[0] = 0;

  if (result->ErrorCount() > 0) {
    StringCchCopy(text.get(), chars, L"The configuration cannot be saved:\n\n");
    AppendIssues(*result, EValidationSeverity::Error, text.get(), chars);
    MessageBox(Dlg, text.get(), L"PREL PTP setup", MB_OK | MB_ICONEXCLAMATION);
    FocusField(Dlg, result->First(EValidationSeverity::Error)->Field);
    return false;
  }

  StringCchCopy(text.get(), chars, L"Please check:\n\n");
  AppendIssues(*result, EValidationSeverity::Warning, text.get(), chars);
  StringCchCat(text.get(), chars, L"Save this configuration anyway?");
  if (MessageBox(Dlg, text.get(), L"PREL PTP setup", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES)
    return true;
  FocusField(Dlg, result->First(EValidationSeverity::Warning)->Field);
  return false;
}

void InitialiseDialog(HWND Dlg) {
  SDlgContext* context = new SDlgContext();

  SetWindowLongPtr(Dlg, GWLP_USERDATA, (LONG_PTR)context);

  ZeroMemory(context, sizeof(SDlgContext));
  context->Dlg = Dlg;

  //--uninstall: from the Apps entry. (-uninstall: the entry written by the 1.3 setup program.)
  int argc = 0;
  LPWSTR* argv(CommandLineToArgvW(GetCommandLine(), &argc));
  context->Uninstall = (argv != nullptr) && (argc > 1) &&
    ((_wcsicmp(argv[1], L"--uninstall") == 0) || (_wcsicmp(argv[1], L"-uninstall") == 0));
  if (argv != nullptr)
    LocalFree(argv);

  //leave room for the configured adapter if it is not present
  context->AdapterCount = ARRAYSIZE(context->AdapterList) - 1;

  context->_service_status_control = GetDlgItem(Dlg, IDC_STATUSTEXT);

  SVersion version;
  GetFileVersion(nullptr, version);
  wchar_t version_text[0x20], caption[0x60];
  version.Format(version_text, ARRAYSIZE(version_text));
  StringCchPrintf(caption, ARRAYSIZE(caption), L"PREL PTP time provider %s", version_text);
  SetWindowText(Dlg, caption);

  if (context->Uninstall) {
    DoUninstall(Dlg);
    return;
  }

  context->Installed = LoadConfiguration(context->InitialConfig);
  SProvidersEnabled enabled;
  LoadProvidersEnabled(enabled);
  context->InitialProvider = ChooseTimeProvider(enabled);
  context->MsPtpAvailability = CheckMsPtpAvailability();
  bool ms_ptp_configured = LoadMsPtpConfiguration(context->InitialMsPtp);
  const SMsPtpConfiguration& ms = context->InitialMsPtp;

  //each PTP provider's domain, grandmaster and interval (see "PTP fields")
  InitialPtpSettings(context->Installed ? &context->InitialConfig : nullptr, ms_ptp_configured ? &ms : nullptr,
    context->InitialPtp[0], context->InitialPtp[1]);

  Install::CheckProvider(context->Provider);
  context->SelfNeedsInstalling = Install::SelfNeedsInstalling();
  ShowInstallStatus(Dlg);

  EnableWindow(GetDlgItem(Dlg, IDC_UNINSTALL), (context->Installed || context->Provider.HaveInstalled) ? TRUE : FALSE);

  GetAdapterList(context->AdapterList, context->AdapterCount);

  UDACCEL accel[2] = {
    {0, 100},
    {2, 500}
  };

  HWND up_down(GetDlgItem(Dlg, IDC_DRINTERVAL));
  SendMessage(up_down, UDM_SETRANGE32, 200, 10000);
  SendMessage(up_down, UDM_SETACCEL, 1, (LPARAM)accel);

  InitialiseDomain(Dlg, PTP_DOMAIN_ANY);
  InitialisePtpFields(Dlg, ETimeProvider::MsPtp);
  InitialisePtpFields(Dlg, ETimeProvider::PrelPtp);
  //the Microsoft PTP client's if it is the provider, otherwise PrelPtp's
  if (context->InitialProvider == ETimeProvider::MsPtp)
    ShowPtpFields(Dlg, ETimeProvider::MsPtp);

  CheckRadioButton(Dlg, IDC_PROVIDER_PRELPTP, IDC_PROVIDER_NONE, ProviderButton(context->InitialProvider));
  CheckDlgButton(Dlg, IDC_MULTICAST_RX, ms.MulticastRx ? BST_CHECKED : BST_UNCHECKED);
  CheckDlgButton(Dlg, IDC_MULTICAST_TX, ms.MulticastTx ? BST_CHECKED : BST_UNCHECKED);
  SetDlgItemInt(Dlg, IDC_ANNOUNCE_EDIT, ms.AnnounceInterval, FALSE);
  SendMessage(GetDlgItem(Dlg, IDC_ANNOUNCE_EDIT), EM_LIMITTEXT, 5, 0);
  if (context->MsPtpAvailability != EMsPtpAvailability::Available) {
    //still shown as selected if it is the current provider; OK then says why it can't be saved
    EnableWindow(GetDlgItem(Dlg, IDC_PROVIDER_MSPTP), FALSE);
    SetDlgItemText(Dlg, IDC_MSPTP_NOTE, MsPtpAvailabilityText(context->MsPtpAvailability));
  }
  UpdateProviderControls(Dlg);

  InitialiseAdapterList(Dlg);

}

//Closes the adapter list's sockets: its survey stops. Before W32Time is restarted it must be:
//the Microsoft PTP client binds ports 319/320 exclusively and fails to start (WSAEADDRINUSE)
//while this program listens on port 320.
static void StopMonitor(SDlgContext* Context) {
  if (Context->Monitor) {
    Context->Monitor->Stop();
    delete Context->Monitor;
    Context->Monitor = nullptr;
  }
}

static bool RestartW32Time(HWND Dlg) {
  SDlgContext* context = GetContext(Dlg);
  StopMonitor(context);
  return context->CommenceRestartW32Time(Dlg);
}

void FinaliseDialog(HWND Dlg) {
  SDlgContext* context = GetContext(Dlg);
  if (context) {
    StopMonitor(context);
    if (context->ListenRuleAdded)
      RemoveListenFirewallRule();
    SetWindowLongPtr(Dlg, GWLP_USERDATA, 0);
    delete context;
  }
}


void DlgSaveConfiguration(HWND Dlg) {

  SDlgContext* context(GetContext(Dlg));
  if (context->Uninstall) {
    //NTP is the user's choice: leave it alone, unless PrelPtp was the only time source. Then ask,
    //rather than leave the clock running freely without saying so. If the Microsoft PTP client
    //is enabled it keeps running, with the firewall rule it needs. (The registry counts, not the
    //dialog: an uninstall from Apps never loads it into the dialog.)
    SProvidersEnabled enabled;
    LoadProvidersEnabled(enabled);
    SUninstallPlan plan = PlanUninstall(enabled);
    bool enable_ntp = false;
    if (plan.AskToEnableNtp)
      enable_ntp = MessageBox(Dlg,
        L"PTP is this computer's only time source: the Windows NTP client is disabled. "
        L"After uninstalling, the clock will run freely.\n\nEnable the Windows NTP client?",
        L"PREL PTP setup", MB_YESNO | MB_ICONQUESTION) == IDYES;

    DeleteConfiguration();
    if (!plan.KeepFirewallRule)
      RemoveFirewallRule();
    Install::RemoveShortcut();
    Install::RemoveUninstallEntry();
    if (enable_ntp)
      SetNtpClientEnabled(true);
    //PrelPtp.dll is deleted while W32Time is stopped for the restart (UpdatePrelPtpDll), and
    //the folder in Program Files once the dialog has closed (_tWinMain)
    g_uninstalled = true;
    if (!RestartW32Time(Dlg))
      SendMessage(Dlg, WM_CLOSE, 0, 0);
    return;
  }

  //check the user's entries before anything is changed
  SEnteredText entered;
  GetEnteredText(Dlg, entered);
  if (!CheckConfiguration(Dlg, entered))
    return;
  //each PTP provider's key gets its own fields (see "PTP fields")
  StorePtpFields(Dlg);
  SPtpSettings prel_ptp = PtpSettingsToSave(context, ETimeProvider::PrelPtp);
  SPtpSettings ms_ptp_fields = PtpSettingsToSave(context, ETimeProvider::MsPtp);

  //install or update the DLL and this program, as the status line said
  if (!InstallFiles(Dlg))
    return;

  SConfiguration config;
  ZeroMemory(&config, sizeof(config));
  config.DelayRequestInterval = DEFAULT_DRI;

  ETimeProvider provider = SelectedProvider(Dlg);
  int adapter = SelectedAdapter(Dlg);
  if (adapter >= 0)
    StringCchCopy(config.AdapterName, ARRAYSIZE(config.AdapterName), context->AdapterList[adapter].AdapterName);

  config.DelayRequestInterval = prel_ptp.DelayRequestInterval;
  config.GrandmasterAddress = prel_ptp.GrandmasterAddress;
  config.DomainNumber = prel_ptp.DomainNumber;

  HRESULT hr = AddFirewallRule();
  if (FAILED(hr)) {
    wchar_t msg[120];
    wchar_t* error_msg;
    size_t remaining_chars;
    StringCchCopyEx(msg, ARRAYSIZE(msg),
      L"Error setting firewall rule: ", &error_msg, &remaining_chars, 0);

    SysErrorMessage(hr, error_msg, (DWORD)remaining_chars);
    ErrorBox(Dlg, msg);
  }

  //used only if the Microsoft PTP client is selected; then CheckConfiguration has found the
  //domain to be a number and the announce interval valid
  SMsPtpConfiguration ms_ptp;
  DefaultMsPtpConfiguration(ms_ptp);
  ms_ptp.DomainNumber = (ms_ptp_fields.DomainNumber <= 255) ? ms_ptp_fields.DomainNumber : 0;
  ms_ptp.GrandmasterAddress = ms_ptp_fields.GrandmasterAddress;
  ms_ptp.DelayPollInterval = ms_ptp_fields.DelayRequestInterval;
  ParseAnnounceInterval(entered.AnnounceInterval, ms_ptp.AnnounceInterval);
  ms_ptp.MulticastRx = (IsDlgButtonChecked(Dlg, IDC_MULTICAST_RX) == BST_CHECKED);
  ms_ptp.MulticastTx = (IsDlgButtonChecked(Dlg, IDC_MULTICAST_TX) == BST_CHECKED);
  if (!SaveTimeProviders(provider, config, &ms_ptp)) {
    ErrorBox(Dlg, L"The configuration could not be saved in the registry. Windows Time has not been restarted.");
    return;
  }

  if (!RestartW32Time(Dlg))
    W32TimeRestartError(Dlg);
}

INT_PTR CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
  switch (uMsg)
  {
  case WM_TIMER:
    if (wParam == TIMER_ID) {
      if (GetContext(hDlg)->ContinueRestartW32Time(hDlg))
        SendMessage(hDlg, WM_CLOSE, 0, 0);
      return TRUE;
    }
    break;  //(this used to fall through into WM_INITDIALOG)

  case WM_INITDIALOG:
    InitialiseDialog(hDlg);
    return true;

  case WM_APP_SURVEY:
    OnSurveyChanged(hDlg);
    return TRUE;

  case WM_NOTIFY: {
    const NMHDR* hdr = (const NMHDR*)lParam;
    if (hdr->idFrom != IDC_LOCALADAPTER)
      break;
    switch (hdr->code) {
    case LVN_ITEMCHANGED:
      OnAdapterSelectionChanged(hDlg, (const NMLISTVIEW*)lParam);
      return TRUE;
    case LVN_GETINFOTIP:
      OnAdapterListGetInfoTip(hDlg, (NMLVGETINFOTIP*)lParam);
      return TRUE;
    case NM_CUSTOMDRAW:
      SetWindowLongPtr(hDlg, DWLP_MSGRESULT, OnAdapterListCustomDraw(hDlg, (NMLVCUSTOMDRAW*)lParam));
      return TRUE;
    }
    break;
  }
  case WM_COMMAND:
    switch (LOWORD(wParam))
    {
    case IDC_UNINSTALL:
      if (MessageBox(hDlg, L"Are you sure you want to uninstall PREL PTP time provider?", L"Confirm",
        MB_ICONQUESTION | MB_YESNO) == IDYES) {
        GetContext(hDlg)->Uninstall = true;
        DoUninstall(hDlg);
      }
      return TRUE;

    case IDC_RELEASE_NOTES:
      ShowDocument(hDlg, Install::Document::ReleaseNotes);
      return TRUE;

    case IDC_README:
      ShowDocument(hDlg, Install::Document::Readme);
      return TRUE;

    case IDC_BMCA_BUTTON:
      //0.0.0.0: no grandmaster address, so PrelPtp selects the master by the BMCA, and the
      //Microsoft PTP client accepts any master
      SendMessage(GetDlgItem(hDlg, IDC_GRANDMASTER), IPM_SETADDRESS, 0, 0);
      return TRUE;

    case IDC_PROVIDER_PRELPTP:
    case IDC_PROVIDER_MSPTP:
    case IDC_PROVIDER_NTP:
    case IDC_PROVIDER_NONE:
      if (HIWORD(wParam) == BN_CLICKED)
        OnProviderClicked(hDlg);
      return TRUE;

    case IDC_DEFAULT_DRINTERVAL_BUTTON:
      SetDefaultDri(hDlg);
      return TRUE;

    case IDCANCEL:
      SendMessage(hDlg, WM_CLOSE, 0, 0);
      return TRUE;

    case IDOK:
      DlgSaveConfiguration(hDlg);
      return TRUE;
    }

    break;

  case WM_CLOSE:
    DestroyWindow(hDlg);
    return TRUE;

  case WM_DESTROY:
    FinaliseDialog(hDlg);
    PostQuitMessage(0);
    return TRUE;
  }

  return FALSE;
}


int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
  _In_opt_ HINSTANCE hPrevInstance,
  _In_ LPTSTR    lpCmdLine,
  _In_ int       nCmdShow) {

  HWND dlg;
  MSG msg;
  BOOL ret;

  //the temporary copy that deletes the installed one after an uninstall (Install::StartSelfDelete)
  int argc = 0;
  LPWSTR* argv = CommandLineToArgvW(GetCommandLine(), &argc);
  if ((argv != nullptr) && (argc > 2) && (_wcsicmp(argv[1], L"--finish-uninstall") == 0)) {
    DWORD parent = wcstoul(argv[2], nullptr, 10);
    LocalFree(argv);
    return Install::FinishUninstall(parent);
  }
  //--uninstall (from Apps): the dialog still runs, for the W32Time restart, but is never shown.
  //Its message boxes (the NTP question, errors) still appear.
  bool hidden = (argv != nullptr) && (argc > 1) &&
    ((_wcsicmp(argv[1], L"--uninstall") == 0) || (_wcsicmp(argv[1], L"-uninstall") == 0));
  if (argv != nullptr)
    LocalFree(argv);

  Install::CleanUpTemporaryCopies();

  InitCommonControls();

  // this window is only used to find CW_USEDEFAULT 
  // see http://stackoverflow.com/questions/11812931/how-to-make-a-win32-dialog-appear-at-the-default-position-cw-usedefault
  // answered by Raymond Chen!

  HWND host_wnd(CreateWindow(L"STATIC", L"HOST", WS_OVERLAPPED, CW_USEDEFAULT, CW_USEDEFAULT, 10, 10, 0, 0, 0, 0));

  dlg = CreateDialogParam(hInstance, MAKEINTRESOURCE(IDD_MAIN), host_wnd, DialogProc, 0);

  if (!hidden)
    ShowWindow(dlg, nCmdShow);

  while ((ret = GetMessage(&msg, 0, 0, 0)) != 0) {
    if (ret == -1)
      return -1;

    if (!IsDialogMessage(dlg, &msg)) {
      TranslateMessage(&msg);
      DispatchMessage(&msg);
    }
  }

  DestroyWindow(host_wnd);

  if (g_uninstalled) {
    //if W32Time could not be stopped, the DLL is deleted at the next reboot
    Install::DeleteProvider();
    Install::StartSelfDelete();
  }

  return 0;

}
