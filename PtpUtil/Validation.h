#pragma once

#include "Util.h"
#include "TimeProviders.h"

/*
Configuration validation: the setup program checks the user's entries before
anything is written. Pure logic, no window or network access, so it can be unit tested.

Errors stop the save. Warnings are shown and the user may save anyway.
The checks that depend on PTP traffic use what the setup program's monitor has heard (STraffic);
they are skipped while that is not known. For PrelPtp that is the selected adapter. The Microsoft
PTP client chooses its own adapter, so for it every adapter the monitor listens on counts.

The PTP settings are checked only when a PTP provider is selected: with NTP or None the dialog
disables them, so a value there that can't be used must not stop the save.
*/

enum class EValidationSeverity { Error, Warning };

//the dialog field an issue is about, so the dialog can focus it
enum class EValidationField { Provider, Adapter, Domain, Grandmaster, DelayRequestInterval, AnnounceInterval, MulticastRx };

struct SValidationIssue {
  EValidationSeverity Severity;
  EValidationField Field;
  wchar_t Message[0x100];
};

struct SValidationResult {
  static const int MAX_ISSUES = 12;
  int Count;
  SValidationIssue Issues[MAX_ISSUES];

  int ErrorCount() const;
  int WarningCount() const;
  //the first issue of that severity, or nullptr
  const SValidationIssue* First(EValidationSeverity Severity) const;
};

//what the monitor has heard on an adapter
struct STraffic {
  bool Known;               //the monitor is listening on the adapter and its first few seconds are over
  int DomainCount;          //domains in which Announce messages are heard
  uint8_t Domains[256];
  bool GrandmasterHeard;    //Announce messages from SValidationInput::GrandmasterAddress are heard
};

//an adapter the monitor listens on, and what it has heard there
struct SSurveyedAdapter {
  const wchar_t* Name;
  STraffic Traffic;
};

struct SValidationInput {
  ETimeProvider Provider;
  const IpAddressEntry* Adapter;    //the selected adapter, nullptr if none
  const wchar_t* DomainText;        //as typed or chosen; see ParseDomain
  const wchar_t* IntervalText;      //delay request interval in ms, as typed
  DWORD GrandmasterAddress;         //IPv4, network byte order. 0 = automatic (PrelPtp: BMCA; Microsoft client: any master)
  STraffic Traffic;                 //on the selected adapter (PrelPtp)

  //the Microsoft PTP client
  EMsPtpAvailability MsPtpAvailability;
  const wchar_t* AnnounceIntervalText;    //ms, as typed
  bool MulticastRx;
  const SSurveyedAdapter* Surveyed;       //every adapter the monitor listens on; nullptr if none
  int SurveyedCount;
};

//the same range for PrelPtp's DelayRequestInterval and the Microsoft client's DelayPollInterval.
//ptpprov's own limits are not known.
static const DWORD MIN_DELAY_REQUEST_INTERVAL = 200;
static const DWORD MAX_DELAY_REQUEST_INTERVAL = 10000;

//Microsoft PTP client. ptpprov's own limits are not known: this is IEEE 1588's usual range of
//announce intervals, 2^-3 to 2^4 s.
static const DWORD MIN_ANNOUNCE_INTERVAL = 125;
static const DWORD MAX_ANNOUNCE_INTERVAL = 16000;

//decimal digits with optional surrounding spaces, MIN_DELAY_REQUEST_INTERVAL..MAX_DELAY_REQUEST_INTERVAL
bool ParseDelayRequestInterval(const wchar_t* Text, DWORD& out_Interval);

//the same, MIN_ANNOUNCE_INTERVAL..MAX_ANNOUNCE_INTERVAL
bool ParseAnnounceInterval(const wchar_t* Text, DWORD& out_Interval);

//nullptr if Address (network byte order) can be a PTP master's unicast address, or is 0 (automatic).
//Otherwise why not: "a multicast address", "a loopback address"...
const wchar_t* GrandmasterAddressProblem(DWORD Address);

//all issues, errors first. Returns true if there are no errors.
bool ValidateConfiguration(const SValidationInput& Input, SValidationResult& out_Result);
