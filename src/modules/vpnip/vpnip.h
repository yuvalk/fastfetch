#pragma once

#include "fastfetch.h"
#include "modules/vpnip/option.h"

#define FF_VPNIP_MODULE_NAME "VpnIP"

bool ffPrintVpnIp(FFVpnIpOptions* options);
void ffInitVpnIpOptions(FFVpnIpOptions* options);
void ffDestroyVpnIpOptions(FFVpnIpOptions* options);

extern FFModuleBaseInfo ffVpnIpModuleInfo;

