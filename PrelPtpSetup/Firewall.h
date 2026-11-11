#pragma once

#include "..\PtpUtil\WinTarget.h"

HRESULT AddFirewallRule();

HRESULT RemoveFirewallRule();

//temporary rule for the setup program's own PTP traffic detection (UDP 320 in)
HRESULT AddListenFirewallRule();

HRESULT RemoveListenFirewallRule();
