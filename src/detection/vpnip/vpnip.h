#pragma once

#include "fastfetch.h"
#include "modules/vpnip/option.h"

typedef struct FFVpnIpResult
{
    FFstrbuf name;
    FFstrbuf ipv4;
    FFstrbuf ipv6;
} FFVpnIpResult;

const char* ffDetectVpnIps(const FFVpnIpOptions* options, FFlist* results);
