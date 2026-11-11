#pragma once

/*
The Windows version every project targets, and the Windows and Winsock headers in the order they
must be included. Include this (directly or through another header) before any other Windows header.

Windows 10 / Server 2016 is the oldest supported version. Declarations for later versions (such as
the timestamping functions in Timestamp.h) must be looked up at run time, so that the provider DLL
still loads on Windows 10.

The provider DLL does not link to the C++ runtime library: it is loaded by w32time and should be
lightweight. Don't use the STL in PtpUtil or PrelPtp.
*/

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00   //_WIN32_WINNT_WIN10 (sdkddkver.h is not included yet)
#endif
#ifndef WINVER
#define WINVER _WIN32_WINNT
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <iphlpapi.h>

#include <inttypes.h>
