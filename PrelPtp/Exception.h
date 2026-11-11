
#pragma once

#include "..\PtpUtil\WinTarget.h"

#define _FACPREL 0x99A

#define MAKE_APPLICATION_ERROR(code) MAKE_HRESULT( 1, _FACPREL, code )

#define PR_E_APPLICATION_ERROR                   MAKE_APPLICATION_ERROR(0x5001)
#define PR_E_CANNOT_FIND_ADAPTER                 MAKE_APPLICATION_ERROR(0x5002)
#define PR_E_CANNOT_LOAD_CONFIGURATION           MAKE_APPLICATION_ERROR(0x5003)
#define PR_E_NO_TIME_AVAILABLE                   MAKE_APPLICATION_ERROR(0x5004) //not really an error
#define PR_E_SHUTDOWN                            MAKE_APPLICATION_ERROR(0x5005) //not really an error

void ErrorMessage(DWORD Error, wchar_t* Buf, DWORD Chars);
