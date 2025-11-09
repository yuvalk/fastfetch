#pragma once

#include "common/option.h"

typedef enum __attribute__((__packed__)) FFVpnIpType
{
    FF_VPNIP_TYPE_NONE,
    FF_VPNIP_TYPE_IPV4_BIT        = 1 << 1,
    FF_VPNIP_TYPE_IPV6_BIT        = 1 << 2,
    FF_VPNIP_TYPE_PREFIX_LEN_BIT  = 1 << 4,

    FF_VPNIP_TYPE_FORCE_UNSIGNED         = UINT16_MAX,
} FFVpnIpType;
static_assert(sizeof(FFVpnIpType) == sizeof(uint16_t), "");

typedef struct FFVpnIpOptions
{
    FFModuleArgs moduleArgs;

    FFVpnIpType showType;
    FFstrbuf namePrefix;
} FFVpnIpOptions;

static_assert(sizeof(FFVpnIpOptions) <= FF_OPTION_MAX_SIZE, "FFVpnIpOptions size exceeds maximum allowed size");
