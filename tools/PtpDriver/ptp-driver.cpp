// ptp-driver: runs PrelPtp.dll outside the Windows Time service, for testing and debugging.
//
// It loads the DLL, opens it as a time provider named "TestHarness" and plays the part of w32time:
// it polls for samples every 2 s and prints them, prints what the provider logs, sends one
// TPC_NetTopoChange (a network change) at a chosen second, then closes the provider and times the
// shutdown. It doesn't steer the clock.
//
// Usage:
//   ptp-driver.exe [<path\to\PrelPtp.dll>] [seconds] [netchange-second]
//     PrelPtp.dll  default: PrelPtp.dll in the same folder as ptp-driver.exe
//     seconds      how long to run, default 30
//     netchange-second  when to send TPC_NetTopoChange, default half way; 0 for never
//
// The provider reads its configuration from the registry, as it does under w32time
// (HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\PrelPtpProvider), so run
// PrelPtpSetup first. It can run alongside w32time with PrelPtp installed (both listen with
// SO_REUSEADDR), but not alongside Microsoft's PTP client, which holds the PTP ports exclusively.
// To debug the provider, run ptp-driver under the debugger with a Debug build of PrelPtp.dll.

#include <windows.h>
#include <timeprov.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

typedef HRESULT (CALLBACK *PFOpen)(WCHAR*, TimeProvSysCallbacks*, TimeProvHandle*);
typedef HRESULT (CALLBACK *PFCommand)(TimeProvHandle, TimeProvCmd, PVOID);
typedef HRESULT (CALLBACK *PFClose)(TimeProvHandle);

static ULONGLONG t0;
static double Now() { return (GetTickCount64() - t0) / 1000.0; }

HRESULT __stdcall GetTimeSysInfo(TimeSysInfo eInfo, void* pvInfo) {
  switch (eInfo) {
  case TSI_TickCount: *(unsigned __int64*)pvInfo = GetTickCount64(); break;
  case TSI_PhaseOffset: *(signed __int64*)pvInfo = 0; break;
  case TSI_PollInterval: *(signed __int32*)pvInfo = 0; break;
  case TSI_CurrentTime: GetSystemTimeAsFileTime((FILETIME*)pvInfo); break;
  default: *(unsigned __int64*)pvInfo = 0; break;
  }
  return S_OK;
}
HRESULT __stdcall LogTimeProvEvent(WORD wType, WCHAR*, WCHAR* wszMessage) {
  wprintf(L"[%6.1f] LOG %d %s\n", Now(), wType, wszMessage);
  return S_OK;
}
HRESULT __stdcall AlertSamplesAvail() { wprintf(L"[%6.1f] AlertSamplesAvail\n", Now()); return S_OK; }
HRESULT __stdcall SetProviderStatus(SetProviderStatusInfo*) { return S_OK; }

static bool IsNumber(const wchar_t* s) {
  if (*s == 0)
    return false;
  for (; *s; ++s)
    if ((*s < L'0') || (*s > L'9'))
      return false;
  return true;
}

int wmain(int argc, wchar_t** argv) {
  setvbuf(stdout, nullptr, _IONBF, 0);

  //the DLL path is optional: the first argument is the path unless it is a number
  int arg = 1;
  wchar_t dll_path[MAX_PATH];
  if ((argc > arg) && !IsNumber(argv[arg])) {
    if ((wcscmp(argv[arg], L"/?") == 0) || (wcscmp(argv[arg], L"-h") == 0) || (wcscmp(argv[arg], L"--help") == 0)) {
      wprintf(L"Usage: ptp-driver.exe [<path\\to\\PrelPtp.dll>] [seconds] [netchange-second]\n");
      return 0;
    }
    wcsncpy_s(dll_path, argv[arg++], _TRUNCATE);
  } else {
    DWORD n = GetModuleFileNameW(nullptr, dll_path, MAX_PATH);
    if ((n == 0) || (n >= MAX_PATH)) { wprintf(L"GetModuleFileName failed %lu\n", GetLastError()); return 1; }
    wchar_t* slash = wcsrchr(dll_path, L'\\');
    if (slash != nullptr)
      slash[1] = 0;
    wcsncat_s(dll_path, L"PrelPtp.dll", _TRUNCATE);
  }
  int seconds = (argc > arg) ? _wtoi(argv[arg]) : 30;
  if (seconds <= 0)
    seconds = 30;
  int netchange_at = (argc > arg + 1) ? _wtoi(argv[arg + 1]) : seconds / 2;

  HMODULE dll = LoadLibraryW(dll_path);
  if (!dll) { wprintf(L"LoadLibrary(%s) failed %lu\n", dll_path, GetLastError()); return 1; }
  PFOpen open = (PFOpen)GetProcAddress(dll, "TimeProvOpen");
  PFCommand cmd = (PFCommand)GetProcAddress(dll, "TimeProvCommand");
  PFClose close = (PFClose)GetProcAddress(dll, "TimeProvClose");
  if (!open || !cmd || !close) { wprintf(L"%s is not a time provider\n", dll_path); return 1; }
  wprintf(L"%s, %d s, network change at %d s\n", dll_path, seconds, netchange_at);

  TimeProvSysCallbacks cb = { sizeof(cb), GetTimeSysInfo, LogTimeProvEvent, AlertSamplesAvail, SetProviderStatus };
  t0 = GetTickCount64();
  TimeProvHandle h;
  HRESULT hr = open((WCHAR*)L"TestHarness", &cb, &h);
  wprintf(L"[%6.1f] TimeProvOpen hr=0x%08lX\n", Now(), hr);
  if (FAILED(hr)) return 2;

  for (int s = 1; s <= seconds; ++s) {
    Sleep(1000);
    if (s == netchange_at) {
      wprintf(L"[%6.1f] >>> TPC_NetTopoChange\n", Now());
      cmd(h, TPC_NetTopoChange, nullptr);
    }
    if (s % 2 == 0) {
      TimeSample sample = {};
      TpcGetSamplesArgs args = {};
      args.cbSampleBuf = sizeof(sample);
      args.pbSampleBuf = (BYTE*)&sample;
      cmd(h, TPC_GetSamples, &args);
      if (args.dwSamplesReturned)
        wprintf(L"[%6.1f] sample offset=%lld us\n", Now(), sample.toOffset / 10);
      else
        wprintf(L"[%6.1f] no sample\n", Now());
    }
  }
  ULONGLONG c0 = GetTickCount64();
  close(h);
  wprintf(L"[%6.1f] TimeProvClose took %llu ms\n", Now(), GetTickCount64() - c0);
  return 0;
}
