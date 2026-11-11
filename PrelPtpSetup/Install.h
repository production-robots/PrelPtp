#pragma once

#include "..\PtpUtil\WinTarget.h"
#include <vector>

/*
Self-installation

PrelPtpSetup.exe carries PrelPtp.dll as a resource. When the user presses OK it installs or
updates the DLL in System32 and itself in C:\Program Files\PrelPtp, with a Start menu shortcut
and an Apps entry that points at the installed copy. Uninstalling removes all of it; the running
copy in Program Files hands over to a temporary copy to delete itself (see StartSelfDelete).

Nothing here shows UI: the dialog decides and reports.
*/

struct SVersion {
  int Major;
  int Minor;
  int Release;
  int Build;
  SVersion() : Major(0), Minor(0), Release(0), Build(0) {}
  //-1, 0, 1
  int Compare(const SVersion& Other) const;
  //"2.0.0", or "2.0.0.5" when there is a build number
  void Format(wchar_t* Buf, size_t Chars) const;
};

//Filename nullptr: this program
bool GetFileVersion(const wchar_t* Filename, SVersion& out_Version);

namespace Install {

//paths; buffers of MAX_PATH characters
bool GetInstallDir(wchar_t* Path);        //C:\Program Files\PrelPtp
bool GetInstalledExe(wchar_t* Path);      //C:\Program Files\PrelPtp\PrelPtpSetup.exe
void GetProviderDll(wchar_t* Path);       //System32\PrelPtp.dll
void GetPendingDll(wchar_t* Path);        //System32\PrelPtp.dll.pending: waits for W32Time to stop

//this program is the installed copy
bool RunningFromInstallDir();

enum class EProviderAction {
  None,       //the installed DLL (or the one waiting to replace it) is this program's
  Install,    //no DLL installed
  Update,     //an older version, or the same version but a different build
  Downgrade   //a newer version is installed: ask first
};

struct SProviderState {
  EProviderAction Action;
  bool HaveInstalled;
  SVersion Installed;     //valid if HaveInstalled
  SVersion Ours;          //the version of this program and of the DLL it carries
};

void CheckProvider(SProviderState& out_State);

//the copy in Program Files is missing or differs from this program (never true for the installed copy itself)
bool SelfNeedsInstalling();

//Each returns false with a reason in Message on failure.

//writes the built-in DLL to System32, or to the .pending file if the installed one is in use
//(it then replaces it while W32Time is stopped: ApplyPendingProvider)
bool InstallProvider(wchar_t* Message, size_t Chars);

//copies this program to Program Files (creating the folder)
bool InstallSelf(wchar_t* Message, size_t Chars);

//Start menu shortcut (all users) to the installed copy
bool CreateShortcut();
bool RemoveShortcut();

//the Apps entry, pointing at the installed copy
bool AddUninstallEntry();
bool RemoveUninstallEntry();

//while W32Time is stopped: move a pending DLL into place
void ApplyPendingProvider();

//while W32Time is stopped, on uninstall: delete the DLL (at the next reboot if it is still in use)
void DeleteProvider();

//after the dialog has closed, on uninstall: delete C:\Program Files\PrelPtp. If this is the
//installed copy, hand over to a temporary copy run with --finish-uninstall.
void StartSelfDelete();

//the temporary copy: waits for ParentPid to exit, deletes the installed copy and its folder,
//and marks itself for deletion at the next reboot. Returns the exit code.
int FinishUninstall(DWORD ParentPid);

//deletes temporary copies left by earlier uninstalls (they are otherwise deleted at the next
//reboot, which on a server may be a long way off). Called whenever the setup program starts.
void CleanUpTemporaryCopies();

enum class Document { ReleaseNotes, Readme };

//writes a built-in document, a web page made from the markdown at build time, to a temporary
//.html file. Path: MAX_PATH characters
bool WriteDocument(Document Doc, wchar_t* Path);

}
