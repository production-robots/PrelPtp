#include "Exception.h"

#include "..\PtpUtil\Util.h"
#include <strsafe.h>

#define _ERROR_(e) case e: StringCchCopy(Buf, Chars, L#e); break;


void ErrorMessage(DWORD Error, wchar_t* Buf, DWORD Chars) {
  switch (Error) {
    _ERROR_(PR_E_APPLICATION_ERROR)
    _ERROR_(PR_E_CANNOT_FIND_ADAPTER)
    _ERROR_(PR_E_CANNOT_LOAD_CONFIGURATION)
    _ERROR_(PR_E_NO_TIME_AVAILABLE)
    _ERROR_(PR_E_SHUTDOWN)
  default:
    SysErrorMessage(Error, Buf, Chars);
    break;
  }
}
