#include "Install.h"
#include "resource.h"

#include "..\PtpUtil\Util.h"
#include <ShlObj.h>
#include <ShObjIdl.h>
#include <wrl/client.h>
#include <strsafe.h>

#pragma comment(lib, "Version")
#pragma comment(lib, "Ole32")

//---------------------------------------------------------------------------- SVersion

int SVersion::Compare(const SVersion& Other) const {
  const int a[] = { Major, Minor, Release, Build };
  const int b[] = { Other.Major, Other.Minor, Other.Release, Other.Build };
  for (int i = 0; i < 4; ++i)
    if (a[i] != b[i])
      return (a[i] < b[i]) ? -1 : 1;
  return 0;
}

void SVersion::Format(wchar_t* Buf, size_t Chars) const {
  if (Build != 0)
    StringCchPrintf(Buf, Chars, L"%d.%d.%d.%d", Major, Minor, Release, Build);
  else
    StringCchPrintf(Buf, Chars, L"%d.%d.%d", Major, Minor, Release);
}

bool GetFileVersion(const wchar_t* Filename, SVersion& out_Version) {
  out_Version = SVersion();
  wchar_t self[MAX_PATH];
  if (Filename == nullptr) {
    if (GetModuleFileName(nullptr, self, ARRAYSIZE(self)) == 0)
      return false;
    Filename = self;
  }
  DWORD zero;
  DWORD size = GetFileVersionInfoSizeEx(FILE_VER_GET_NEUTRAL, Filename, &zero);
  if (size == 0)
    return false;
  std::vector<uint8_t> info(size);
  if (!GetFileVersionInfoEx(FILE_VER_GET_NEUTRAL, Filename, 0, size, info.data()))
    return false;
  VS_FIXEDFILEINFO* ffi;
  UINT length;
  if (!VerQueryValue(info.data(), L"\\", (LPVOID*)&ffi, &length) || (length < sizeof(VS_FIXEDFILEINFO)))
    return false;
  out_Version.Major = HIWORD(ffi->dwFileVersionMS);
  out_Version.Minor = LOWORD(ffi->dwFileVersionMS);
  out_Version.Release = HIWORD(ffi->dwFileVersionLS);
  out_Version.Build = LOWORD(ffi->dwFileVersionLS);
  return true;
}

namespace Install {

static const wchar_t* INSTALL_FOLDER = L"PrelPtp";
static const wchar_t* EXE_NAME = L"PrelPtpSetup.exe";
static const wchar_t* SHORTCUT_NAME = L"PREL PTP setup.lnk";
//the same key as the setup program of 1.3, so an update replaces its entry
static const wchar_t* UNINSTALL_KEY = LR"(SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PrelPtp)";

//---------------------------------------------------------------------------- helpers

static bool FileExists(const wchar_t* Path) {
  return GetFileAttributes(Path) != INVALID_FILE_ATTRIBUTES;
}

static bool KnownFolder(REFKNOWNFOLDERID Id, const wchar_t* Child, wchar_t* Path) {
  PWSTR folder = nullptr;
  if (FAILED(SHGetKnownFolderPath(Id, 0, nullptr, &folder)))
    return false;
  HRESULT hr = StringCchCopy(Path, MAX_PATH, folder);
  CoTaskMemFree(folder);
  if (SUCCEEDED(hr) && Child) {
    hr = StringCchCat(Path, MAX_PATH, L"\\");
    if (SUCCEEDED(hr))
      hr = StringCchCat(Path, MAX_PATH, Child);
  }
  return SUCCEEDED(hr);
}

static bool SelfPath(wchar_t* Path) {
  DWORD n = GetModuleFileName(nullptr, Path, MAX_PATH);
  return (n > 0) && (n < MAX_PATH);
}

static bool ReadWholeFile(const wchar_t* Path, std::vector<uint8_t>& out_Bytes) {
  out_Bytes.clear();
  HANDLE file = CreateFile(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
  if (file == INVALID_HANDLE_VALUE)
    return false;
  LARGE_INTEGER size;
  bool ok = GetFileSizeEx(file, &size) && (size.QuadPart < 64 * 1024 * 1024);
  if (ok) {
    out_Bytes.resize((size_t)size.QuadPart);
    DWORD read = 0;
    ok = out_Bytes.empty() || (ReadFile(file, out_Bytes.data(), (DWORD)out_Bytes.size(), &read, nullptr) && (read == out_Bytes.size()));
  }
  CloseHandle(file);
  return ok;
}

static bool WriteWholeFile(const wchar_t* Path, const void* Bytes, DWORD Size) {
  HANDLE file = CreateFile(Path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE)
    return false;
  DWORD written = 0;
  bool ok = WriteFile(file, Bytes, Size, &written, nullptr) && (written == Size);
  DWORD error = ok ? ERROR_SUCCESS : ((GetLastError() != ERROR_SUCCESS) ? GetLastError() : ERROR_WRITE_FAULT);
  CloseHandle(file);
  if (!ok) {
    DeleteFile(Path);
    SetLastError(error);   //for the caller's message
  }
  return ok;
}

//a resource of this program
static bool GetResource(int Id, const wchar_t* Type, const void*& out_Bytes, DWORD& out_Size) {
  HRSRC resource = FindResource(nullptr, MAKEINTRESOURCE(Id), Type);
  if (resource == nullptr)
    return false;
  HGLOBAL loaded = LoadResource(nullptr, resource);
  if (loaded == nullptr)
    return false;
  out_Bytes = LockResource(loaded);
  out_Size = SizeofResource(nullptr, resource);
  return out_Bytes != nullptr;
}

static bool GetBuiltInDll(const void*& out_Bytes, DWORD& out_Size) {
  return GetResource(IDR_PPTP_DLL, L"BIN", out_Bytes, out_Size);
}

static bool SameBytes(const std::vector<uint8_t>& File, const void* Bytes, DWORD Size) {
  return (File.size() == Size) && (memcmp(File.data(), Bytes, Size) == 0);
}

static void AppendError(wchar_t* Message, size_t Chars, const wchar_t* What, const wchar_t* Path, DWORD Error) {
  wchar_t reason[0x100];
  SysErrorMessage(Error, reason, ARRAYSIZE(reason));
  StringCchPrintf(Message, Chars, L"%s %s: %s", What, Path, reason);
}

//---------------------------------------------------------------------------- paths

bool GetInstallDir(wchar_t* Path) {
  return KnownFolder(FOLDERID_ProgramFiles, INSTALL_FOLDER, Path);
}

bool GetInstalledExe(wchar_t* Path) {
  return GetInstallDir(Path) && SUCCEEDED(StringCchCat(Path, MAX_PATH, L"\\")) && SUCCEEDED(StringCchCat(Path, MAX_PATH, EXE_NAME));
}

void GetProviderDll(wchar_t* Path) {
  GetSystemDirectory(Path, MAX_PATH);
  StringCchCat(Path, MAX_PATH, L"\\PrelPtp.dll");
}

void GetPendingDll(wchar_t* Path) {
  GetProviderDll(Path);
  StringCchCat(Path, MAX_PATH, L".pending");
}

bool RunningFromInstallDir() {
  wchar_t self[MAX_PATH];
  wchar_t installed[MAX_PATH];
  return SelfPath(self) && GetInstalledExe(installed) && (_wcsicmp(self, installed) == 0);
}

//---------------------------------------------------------------------------- install and update

void CheckProvider(SProviderState& out_State) {
  out_State = SProviderState();
  out_State.Action = EProviderAction::Install;
  GetFileVersion(nullptr, out_State.Ours);   //PrelPtp.dll and this program share PrelPtpVersion.h

  wchar_t dll[MAX_PATH];
  GetProviderDll(dll);
  out_State.HaveInstalled = FileExists(dll);
  if (!out_State.HaveInstalled)
    return;
  GetFileVersion(dll, out_State.Installed);

  const void* ours;
  DWORD ours_size;
  if (!GetBuiltInDll(ours, ours_size)) {
    out_State.Action = EProviderAction::None;   //nothing to install (a broken build); leave the DLL alone
    return;
  }

  //an update already waiting for W32Time to stop counts as installed
  wchar_t pending[MAX_PATH];
  GetPendingDll(pending);
  std::vector<uint8_t> bytes;
  if (ReadWholeFile(pending, bytes) && SameBytes(bytes, ours, ours_size)) {
    out_State.Action = EProviderAction::None;
    return;
  }

  int order = out_State.Installed.Compare(out_State.Ours);
  if (order > 0)
    out_State.Action = EProviderAction::Downgrade;
  else if ((order == 0) && ReadWholeFile(dll, bytes) && SameBytes(bytes, ours, ours_size))
    out_State.Action = EProviderAction::None;
  else
    out_State.Action = EProviderAction::Update;   //older, or the same version but a different build
}

bool SelfNeedsInstalling() {
  if (RunningFromInstallDir())
    return false;
  wchar_t self[MAX_PATH];
  wchar_t installed[MAX_PATH];
  if (!SelfPath(self) || !GetInstalledExe(installed))
    return false;
  std::vector<uint8_t> a, b;
  if (!ReadWholeFile(installed, b))
    return true;
  return !ReadWholeFile(self, a) || (a != b);
}

bool InstallProvider(wchar_t* Message, size_t Chars) {
  const void* bytes;
  DWORD size;
  if (!GetBuiltInDll(bytes, size)) {
    StringCchCopy(Message, Chars, L"This program does not contain PrelPtp.dll (a broken build).");
    return false;
  }
  wchar_t dll[MAX_PATH];
  wchar_t pending[MAX_PATH];
  GetProviderDll(dll);
  GetPendingDll(pending);
  DeleteFile(pending);   //an older pending update, if any

  //W32Time normally has the DLL loaded: then it can't be replaced now. Write the new one beside
  //it; it is moved into place while W32Time is stopped for the restart.
  if (!FileExists(dll) || DeleteFile(dll)) {
    if (WriteWholeFile(dll, bytes, size))
      return true;
    AppendError(Message, Chars, L"Cannot write", dll, GetLastError());
    return false;
  }
  if (WriteWholeFile(pending, bytes, size))
    return true;
  AppendError(Message, Chars, L"Cannot write", pending, GetLastError());
  return false;
}

bool InstallSelf(wchar_t* Message, size_t Chars) {
  wchar_t self[MAX_PATH];
  wchar_t dir[MAX_PATH];
  wchar_t installed[MAX_PATH];
  if (!SelfPath(self) || !GetInstallDir(dir) || !GetInstalledExe(installed)) {
    StringCchCopy(Message, Chars, L"Cannot find the Program Files folder.");
    return false;
  }
  if (!CreateDirectory(dir, nullptr) && (GetLastError() != ERROR_ALREADY_EXISTS)) {
    AppendError(Message, Chars, L"Cannot create", dir, GetLastError());
    return false;
  }
  if (CopyFile(self, installed, FALSE))
    return true;
  DWORD error = GetLastError();
  if ((error == ERROR_SHARING_VIOLATION) || (error == ERROR_ACCESS_DENIED))
    StringCchPrintf(Message, Chars, L"%s cannot be replaced: it may be running. Close it and press OK again.", installed);
  else
    AppendError(Message, Chars, L"Cannot write", installed, error);
  return false;
}

struct UsingCom {
  HRESULT hr;
  operator bool() const { return SUCCEEDED(hr) || (hr == RPC_E_CHANGED_MODE); }
  UsingCom() : hr(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED)) {}
  ~UsingCom() { if (SUCCEEDED(hr)) CoUninitialize(); }
};

bool CreateShortcut() {
  wchar_t link[MAX_PATH];
  wchar_t target[MAX_PATH];
  wchar_t dir[MAX_PATH];
  if (!KnownFolder(FOLDERID_CommonPrograms, SHORTCUT_NAME, link) || !GetInstalledExe(target) || !GetInstallDir(dir))
    return false;
  UsingCom com;
  if (!com)
    return false;
  Microsoft::WRL::ComPtr<IShellLink> shell_link;
  if (FAILED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&shell_link))))
    return false;
  shell_link->SetPath(target);
  shell_link->SetWorkingDirectory(dir);
  shell_link->SetDescription(L"Configure the PREL PTP time provider");
  Microsoft::WRL::ComPtr<IPersistFile> file;
  if (FAILED(shell_link->QueryInterface(IID_PPV_ARGS(&file))))
    return false;
  return SUCCEEDED(file->Save(link, TRUE));
}

bool RemoveShortcut() {
  wchar_t link[MAX_PATH];
  return KnownFolder(FOLDERID_CommonPrograms, SHORTCUT_NAME, link) && (DeleteFile(link) || (GetLastError() == ERROR_FILE_NOT_FOUND));
}

static DWORD FileSizeKb(const wchar_t* Path) {
  WIN32_FILE_ATTRIBUTE_DATA data;
  if (!GetFileAttributesEx(Path, GetFileExInfoStandard, &data))
    return 0;
  return (DWORD)((((ULONGLONG)data.nFileSizeHigh << 32) | data.nFileSizeLow) / 1024);
}

bool AddUninstallEntry() {
  wchar_t exe[MAX_PATH];
  wchar_t dir[MAX_PATH];
  wchar_t dll[MAX_PATH];
  if (!GetInstalledExe(exe) || !GetInstallDir(dir))
    return false;
  GetProviderDll(dll);

  HKEY key;
  if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, UNINSTALL_KEY, 0, nullptr, 0, KEY_SET_VALUE | KEY_QUERY_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS)
    return false;

  //InstallDate: when it was first installed here; kept on updates
  wchar_t old_location[MAX_PATH];
  if (!RegRead(key, L"InstallLocation", old_location, ARRAYSIZE(old_location)) || (_wcsicmp(old_location, dir) != 0)) {
    wchar_t today[0x20];
    SYSTEMTIME now;
    GetLocalTime(&now);
    StringCchPrintf(today, ARRAYSIZE(today), L"%04d%02d%02d", now.wYear, now.wMonth, now.wDay);
    RegWrite(key, L"InstallDate", today);
  }

  SVersion version;
  GetFileVersion(nullptr, version);
  wchar_t display_version[0x20];
  version.Format(display_version, ARRAYSIZE(display_version));

  wchar_t command[MAX_PATH + 0x20];
  RegWrite(key, L"DisplayName", L"PREL PTP time provider");
  RegWrite(key, L"Publisher", L"Production Robots Engineering Ltd");
  RegWrite(key, L"DisplayVersion", display_version);
  RegWrite(key, L"DisplayIcon", exe);
  RegWrite(key, L"InstallLocation", dir);
  StringCchPrintf(command, ARRAYSIZE(command), L"\"%s\" --uninstall", exe);
  RegWrite(key, L"UninstallString", command);
  RegWrite(key, L"NoModify", 1);
  RegWrite(key, L"NoRepair", 1);
  RegWrite(key, L"EstimatedSize", FileSizeKb(exe) + FileSizeKb(dll));
  RegDeleteValue(key, L"Comments");   //1.3 put the install folder there
  RegCloseKey(key);
  return true;
}

bool RemoveUninstallEntry() {
  LSTATUS status = RegDeleteKey(HKEY_LOCAL_MACHINE, UNINSTALL_KEY);
  return (status == ERROR_SUCCESS) || (status == ERROR_FILE_NOT_FOUND);
}

void ApplyPendingProvider() {
  wchar_t dll[MAX_PATH];
  wchar_t pending[MAX_PATH];
  GetProviderDll(dll);
  GetPendingDll(pending);
  if (!FileExists(pending))
    return;
  if (FileExists(dll) && !DeleteFile(dll))
    return;   //still in use: try again at the next restart
  MoveFile(pending, dll);
}

void DeleteProvider() {
  wchar_t dll[MAX_PATH];
  wchar_t pending[MAX_PATH];
  GetProviderDll(dll);
  GetPendingDll(pending);
  if (!DeleteFile(pending) && FileExists(pending))
    MoveFileEx(pending, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
  if (!DeleteFile(dll) && FileExists(dll))
    MoveFileEx(dll, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
}

//---------------------------------------------------------------------------- uninstall: deleting the installed copy

//deletes the installed copy and its folder; anything still locked after Patience is deleted at the next reboot
static void DeleteInstallDir(DWORD PatienceMs) {
  wchar_t dir[MAX_PATH];
  wchar_t exe[MAX_PATH];
  if (!GetInstallDir(dir) || !GetInstalledExe(exe))
    return;
  ULONGLONG give_up = GetTickCount64() + PatienceMs;
  while (FileExists(exe) && !DeleteFile(exe) && (GetTickCount64() < give_up))
    Sleep(250);
  if (FileExists(exe))
    MoveFileEx(exe, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
  //only our own file is deleted; the folder goes if nothing else is in it
  if (!RemoveDirectory(dir) && FileExists(dir))
    MoveFileEx(dir, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
}

void StartSelfDelete() {
  if (!RunningFromInstallDir()) {
    DeleteInstallDir(2000);
    return;
  }
  //Windows won't delete a running exe: a temporary copy waits for this one to exit, then deletes it
  wchar_t self[MAX_PATH];
  wchar_t temp_dir[MAX_PATH];
  wchar_t temp[MAX_PATH];
  if (SelfPath(self) && GetTempPath(ARRAYSIZE(temp_dir), temp_dir) &&
    SUCCEEDED(StringCchPrintf(temp, ARRAYSIZE(temp), L"%sPrelPtpUninstall-%u.exe", temp_dir, GetCurrentProcessId())) &&
    CopyFile(self, temp, FALSE)) {
    wchar_t command[MAX_PATH + 0x40];
    StringCchPrintf(command, ARRAYSIZE(command), L"\"%s\" --finish-uninstall %u", temp, GetCurrentProcessId());
    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    if (CreateProcess(temp, command, nullptr, nullptr, FALSE, 0, nullptr, temp_dir, &si, &pi)) {
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      return;
    }
    DeleteFile(temp);
  }
  //no hand-over: delete at the next reboot instead
  DeleteInstallDir(0);
}

int FinishUninstall(DWORD ParentPid) {
  HANDLE parent = OpenProcess(SYNCHRONIZE, FALSE, ParentPid);
  if (parent != nullptr) {
    WaitForSingleObject(parent, 30000);
    CloseHandle(parent);
  }
  DeleteInstallDir(10000);
  wchar_t self[MAX_PATH];
  if (SelfPath(self))
    MoveFileEx(self, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
  return 0;
}

void CleanUpTemporaryCopies() {
  wchar_t temp_dir[MAX_PATH];
  wchar_t pattern[MAX_PATH];
  if (!GetTempPath(ARRAYSIZE(temp_dir), temp_dir) ||
    FAILED(StringCchPrintf(pattern, ARRAYSIZE(pattern), L"%sPrelPtpUninstall-*.exe", temp_dir)))
    return;
  WIN32_FIND_DATA found;
  HANDLE find = FindFirstFile(pattern, &found);
  if (find == INVALID_HANDLE_VALUE)
    return;
  do {
    wchar_t path[MAX_PATH];
    //a copy still finishing an uninstall is running and can't be deleted: it is skipped
    if (SUCCEEDED(StringCchPrintf(path, ARRAYSIZE(path), L"%s%s", temp_dir, found.cFileName)))
      DeleteFile(path);
  } while (FindNextFile(find, &found));
  FindClose(find);
}

bool WriteDocument(Document Doc, wchar_t* Path) {
  const bool readme = Doc == Document::Readme;
  const void* bytes;
  DWORD size;
  wchar_t temp_dir[MAX_PATH];
  if (!GetResource(readme ? IDR_README : IDR_RELEASE_NOTES, L"TEXT", bytes, size) || !GetTempPath(ARRAYSIZE(temp_dir), temp_dir))
    return false;
  if (FAILED(StringCchPrintf(Path, MAX_PATH, L"%sPREL PTP %s.html", temp_dir, readme ? L"README" : L"release notes")))
    return false;
  return WriteWholeFile(Path, bytes, size);
}

}
