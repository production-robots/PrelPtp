#pragma once

#include "WinTarget.h"

bool RegRead(HKEY Key, const wchar_t* Name, wchar_t* out_Value, DWORD Length);
bool RegRead(HKEY Key, const wchar_t* Name, DWORD& out_Value);
bool RegWrite(HKEY Key, const wchar_t* Name, const wchar_t* Value);
bool RegWrite(HKEY Key, const wchar_t* Name, DWORD Value);

class TSRWLock {
	friend class TSRWSharedLock;
	friend class TSRWExclusiveLock;
	friend class TSRWTrySharedLock;
	friend class TSRWTryExclusiveLock;
private:
	mutable SRWLOCK _lock;
public:
	TSRWLock() {
		InitializeSRWLock(&_lock);
	}
};


class TSRWSharedLock {
private:
	SRWLOCK* _lock;
public:
	TSRWSharedLock(const TSRWLock& ALock) : _lock(&(ALock._lock)) {
		AcquireSRWLockShared(_lock);
	}
	~TSRWSharedLock() {
		ReleaseSRWLockShared(_lock);
	}
};

class TSRWExclusiveLock {
private:
	SRWLOCK* _lock;
public:
	TSRWExclusiveLock(const TSRWLock& ALock) : _lock(&(ALock._lock)) {
		AcquireSRWLockExclusive(_lock);
	}
	~TSRWExclusiveLock() {
		ReleaseSRWLockExclusive(_lock);
	}
};

class TSRWTrySharedLock {
private:
	SRWLOCK* _lock;
	BOOLEAN _locked;
public:
	TSRWTrySharedLock(const TSRWLock& ALock) : _lock(&(ALock._lock)) {
		_locked = TryAcquireSRWLockShared(_lock);
	}
	~TSRWTrySharedLock() {
		if (_locked)
			ReleaseSRWLockShared(_lock);
	}
	operator bool() const { return _locked != 0; }
};


class TSRWTryExclusiveLock {
private:
	SRWLOCK* _lock;
	BOOLEAN _locked;
public:
	TSRWTryExclusiveLock(const TSRWLock& ALock) : _lock(&(ALock._lock)) {
		_locked = TryAcquireSRWLockExclusive(_lock);
	}
	~TSRWTryExclusiveLock() {
		if (_locked)
			ReleaseSRWLockExclusive(_lock);
	}
	operator bool() const { return _locked != 0; }
};

void SysErrorMessage(DWORD Error, LPTSTR Buf, DWORD Chars);


typedef wchar_t TAdapterName[0x80];
typedef uint8_t TMacAddress[6];

struct IpAddressEntry {
	TAdapterName AdapterName;   //GUID string, as stored in the AdapterName registry value
	TAdapterName FriendlyName;
	DWORD LocalAddress;         //usable IPv4 address (network byte order), 0 if none
	TMacAddress MacAddress;
	DWORD IfIndex;
	bool Up;                    //operational status up
	bool Ethernet;              //IF_TYPE_ETHERNET_CSMACD
	bool ConnectorPresent;      //a physical adapter, not virtual, tunnel or loopback
	bool Present;               //false for a configured adapter that was not found
   bool IsMatroxCard() const {
      return MacAddress[0] == 0x00 && MacAddress[1] == 0x20 && MacAddress[2] == 0xFC;
   }
   //worth offering as a PTP adapter
   bool IsCandidate() const { return Present && Ethernet && ConnectorPresent; }
};

enum class EAdapterState {
  Ready,            //adapter is up and has a usable (DAD preferred) IPv4 address
  NotConfigured,    //no adapter name in the configuration
  NotFound,         //no adapter with the configured name (disabled, removed, or not yet enumerated)
  NotOperational,   //adapter exists but is not up (cable unplugged, restarting...)
  NoAddress,        //adapter is up but has no IPv4 address
  AddressNotReady,  //adapter has an IPv4 address but it is not yet usable (tentative/duplicate)
  Error             //adapter enumeration failed
};

struct SAdapterInfo {
  DWORD LocalAddress;   //network byte order
  TMacAddress MacAddress;
  DWORD IfIndex;        //IPv4 interface index, 0 if not known
};

//Finds the configured adapter and checks that it can be used for PTP right now.
//out_Info.IfIndex and out_Info.MacAddress are filled in whenever the adapter is found,
//out_Info.LocalAddress only when the result is EAdapterState::Ready.
EAdapterState ResolveAdapter(const wchar_t* AdapterName, SAdapterInfo& out_Info);

const wchar_t* AdapterStateText(EAdapterState State);

//All adapters with IPv4 enabled, up or not. inout_Count: capacity in, entries out.
//Returns false if adapters could not be enumerated; extra adapters beyond the capacity are left out.
bool GetAdapterList(IpAddressEntry* out_AddressList, DWORD& inout_Count);


//PrelPtp's own settings (TimeProviders\PrelPtpProvider). Whether it is enabled is set with
//SelectTimeProvider (TimeProviders.h), which also enables or disables the other providers.
struct SConfiguration {
  TAdapterName AdapterName;
  DWORD GrandmasterAddress;   //IPv4, network byte order. 0: select the master automatically (BMCA)
  DWORD FilterLength;
  DWORD DelayRequestInterval; //1200ms default
  DWORD DomainNumber;   //PTP domain to accept (0-255), or PTP_DOMAIN_ANY. Registry value "DomainNumber", absent = any.
};

static const DWORD PTP_DOMAIN_ANY = 0xFFFFFFFF;

//true if a message from PTP domain MessageDomain should be used, given the configured DomainNumber
inline bool DomainAccepted(DWORD ConfiguredDomain, uint8_t MessageDomain) {
  return (ConfiguredDomain == PTP_DOMAIN_ANY) || (MessageDomain == ConfiguredDomain);
}

//Parses a domain as typed or chosen in the setup program:
//  empty, or starting with "any" (any case)   -> PTP_DOMAIN_ANY
//  0-255, optionally followed by a space and a description ("127 - SMPTE ST 2059-2")
//Leading spaces are ignored. Returns false for anything else.
bool ParseDomain(const wchar_t* Text, DWORD& out_Domain);

//"Any" or the number
void FormatDomain(DWORD Domain, wchar_t* Buf, size_t Chars);

extern const WORD DEFAULT_MULTICAST_PORT;

extern const wchar_t* ProviderName;
extern const wchar_t* HarnessName;

//TimeProviders\<Provider>. Chars: at least 0x80
void GetProviderKeyName(wchar_t* KeyName, const wchar_t* Provider, size_t Chars);

//creates the key if need be; doesn't change Enabled (see SelectTimeProvider)
bool SaveConfiguration(const SConfiguration& Config);

//NtpClient\Enabled
bool SetNtpClientEnabled(bool Enabled);

bool LoadConfiguration(SConfiguration& out_Config);

//Provider-only emergency fallback. A missing registry value means delay requests are enabled.
bool LoadDisableDelayRequestSetting();

//Registry value TimestampMode (provider key): 0 or absent = Auto (hardware timestamps when the adapter
//has them active, otherwise software), 1 = Software (never try hardware).
enum class ETimestampMode { Auto = 0, Software = 1 };
ETimestampMode LoadTimestampModeSetting();

bool DeleteConfiguration();

uint16_t Uniform();

void SeedUniform();
