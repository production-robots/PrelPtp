#include "PtpClient.h"
#include <strsafe.h>

/* NOTES 

The sample provider at https://msdn.microsoft.com/en-us/library/windows/desktop/ms724929(v=vs.85).aspx 

is incomplete and has serious errors. The documentation at 

https://msdn.microsoft.com/en-us/library/windows/desktop/ms725475(v=vs.85).aspx

is pretty sketchy but it is all I have had to go on: I have not found anything else on the internet.




On windows 7, W32Time will only run if in the "Date and Time" dialog box, "Internet time" is enabled.

This starts W32Time service that will load all configured providers. If you want to use only ptp then
you should disable NTPClient


HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\W32Time\TimeProviders\NtpClient\Enabled = 0


There is some useful information about W32Time and the w32tm command line tool here:

https://technet.microsoft.com/en-us/library/cc773263(v=ws.10).aspx


*/


#define EXPORT extern "C"

EXPORT HRESULT CALLBACK TimeProvOpen(
   WCHAR *wszName,
   TimeProvSysCallbacks *pSysCallback,
   TimeProvHandle *phTimeProv) {
#ifdef ODS_DEBUG
  wchar_t buf[100];
  StringCbPrintfW(buf,sizeof(buf),L"TimeProvOpen %s\n", wszName);
  //wsprintf(buf, L"TimeProvOpen %s\n", wszName);
  OutputDebugString(buf);
#endif

  bool test_mode(_wcsicmp(wszName, HarnessName) == 0);

   if (test_mode || (_wcsicmp(wszName, ProviderName) == 0)) {
     CPtpClient* ptp = new CPtpClient(pSysCallback);

     DWORD result = ptp->Start();
     if (result == S_OK) {
       *phTimeProv = ptp;
       return S_OK;
     }
     delete ptp;
   }
   return E_FAIL;
}

EXPORT HRESULT CALLBACK TimeProvCommand(
   TimeProvHandle hTimeProv,
   TimeProvCmd eCmd,
   PVOID pvArgs) {
  CPtpClient* ptp((CPtpClient*)hTimeProv);
  return ptp->Command(eCmd, pvArgs);
}

EXPORT HRESULT CALLBACK TimeProvClose(
   TimeProvHandle hTimeProv) {
  CPtpClient* ptp((CPtpClient*)hTimeProv);
  ptp->Stop();
  delete ptp;
  return S_OK;
}

